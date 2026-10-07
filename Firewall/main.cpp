#include "packet_sniffer.h"
#include "packet_parser.h"
#include "rule_engine.h"
#include "logger.h"
#include "firewall_enforcer.h"
#include "port_scan_detector.h"    // ← NEW

#include <csignal>
#include <cstdlib>
#include <iostream>

// ─────────────────────────────────────────────────────────────────────────────
// Globals — accessed by signal handler
// ─────────────────────────────────────────────────────────────────────────────
static PacketSniffer*    g_sniffer  = nullptr;
static FirewallEnforcer* g_enforcer = nullptr;

static void onSignal(int /*sig*/)
{
    std::cout << "\n[main] Interrupt received – stopping capture…\n";
    if (g_sniffer)
        g_sniffer->stopCapture();
}

// ─────────────────────────────────────────────────────────────────────────────
// main
// ─────────────────────────────────────────────────────────────────────────────
int main(int argc, char* argv[])
{
    const std::string iface = (argc > 1) ? argv[1] : "any";

    std::cout << "[main] Starting firewall on interface : " << iface        << '\n';
    std::cout << "[main] Logging blocked packets to     : " << LOG_FILE_PATH << '\n';

    // ── Initialise all subsystems ────────────────────────────────────────
    RuleEngine        engine("rules.json");
    FirewallEnforcer  enforcer;
    PortScanDetector  scanner;              // ← NEW

    g_enforcer = &enforcer;

    PacketSniffer sniffer(iface);
    g_sniffer = &sniffer;

    if (!sniffer.lastError().empty()) {
        std::cerr << "[main] Sniffer init failed. Are you running as root?\n";
        return EXIT_FAILURE;
    }

    std::signal(SIGINT,  onSignal);
    std::signal(SIGTERM, onSignal);

    std::cout << "[main] IDS active — port scan threshold : "
              << PORTSCAN_PORT_THRESHOLD << " ports / "
              << PORTSCAN_TIME_WINDOW_SEC << " sec\n";
    std::cout << "[main] Press Ctrl+C to stop.\n\n";

    // ── Per-packet handler ────────────────────────────────────────────────
    auto handler = [&engine, &enforcer, &scanner](const RawPacket& raw) {

        ParsedPacket pkt = PacketParser::parse(raw);
        if (!pkt.valid) return;

        // ── STEP 1: Port scan detection (IDS) — checked FIRST ─────────────
        if (scanner.inspect(pkt)) {
            std::cout << "[ALERT] Port scan detected from " << pkt.src_ip
                      << "  (" << PORTSCAN_PORT_THRESHOLD << "+ ports in "
                      << PORTSCAN_TIME_WINDOW_SEC << "s)\n";

            Logger::logAlert(pkt.src_ip, "Port scan detected");
            enforcer.blockIP(pkt.src_ip);   // auto-block the scanner
            return;                          // no further processing needed
        }

        // ── STEP 2: Rule engine (static JSON rules) ────────────────────────
        if (engine.isBlocked(pkt)) {
            Logger::logBlocked(pkt);
            enforcer.blockIP(pkt.src_ip);

            std::cout << "[BLOCKED & DROPPED] "
                      << pkt.src_ip  << " → " << pkt.dst_ip
                      << "  port="   << pkt.dst_port
                      << "  proto="  << pkt.proto_str
                      << '\n';
            return;
        }

        // ── STEP 3: Allowed — print normally ──────────────────────────────
        PacketParser::print(pkt);
    };

    sniffer.startCapture(handler, /*packet_count=*/-1);

    std::cout << "[main] Capture stopped. Exiting cleanly.\n";
    return EXIT_SUCCESS;
}
