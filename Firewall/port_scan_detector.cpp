#include "port_scan_detector.h"

#include <iostream>
#include <netinet/in.h>    // IPPROTO_TCP, IPPROTO_UDP

// ─────────────────────────────────────────────────────────────────────────────
// inspect
//
//   Called for every parsed packet.  Flow:
//
//   1. Ignore non-TCP/UDP packets (ICMP etc. don't have ports)
//   2. Ignore already-confirmed scanners (alert was already fired)
//   3. First packet from this IP → create a fresh ScanRecord
//   4. Packet within the time window → add dst_port to the set
//   5. Time window expired → reset the record, start fresh
//   6. If unique port count > threshold → flag as port scan, return true
// ─────────────────────────────────────────────────────────────────────────────
bool PortScanDetector::inspect(const ParsedPacket& pkt)
{
    // ── Only track TCP and UDP — they carry meaningful port numbers ────────
    if (pkt.protocol != IPPROTO_TCP && pkt.protocol != IPPROTO_UDP)
        return false;

    // ── Skip IPs we have already confirmed and reported ───────────────────
    if (confirmed_scanners_.count(pkt.src_ip) > 0)
        return false;

    auto  now = std::chrono::steady_clock::now();
    auto& rec = tracker_[pkt.src_ip];   // creates entry if first time seen

    // ── Initialise record on first sight of this IP ───────────────────────
    if (rec.ports.empty()) {
        rec.first_seen = now;
    }

    // ── Check if the time window has expired ──────────────────────────────
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                       now - rec.first_seen).count();

    if (elapsed > PORTSCAN_TIME_WINDOW_SEC) {
        // Window expired — reset and start counting fresh from this packet
        rec.first_seen = now;
        rec.ports.clear();
    }

    // ── Record this destination port ──────────────────────────────────────
    rec.ports.insert(pkt.dst_port);

    // ── Check threshold ───────────────────────────────────────────────────
    if (static_cast<int>(rec.ports.size()) > PORTSCAN_PORT_THRESHOLD) {
        // Mark as confirmed so we don't fire duplicate alerts
        confirmed_scanners_.insert(pkt.src_ip);
        tracker_.erase(pkt.src_ip);   // free memory — no longer needed
        return true;                   // ← ALERT: port scan detected
    }

    return false;
}
