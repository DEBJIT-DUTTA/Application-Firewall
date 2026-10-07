#include "firewall_enforcer.h"

#include <iostream>
#include <cstdlib>
#include <regex>

// ─────────────────────────────────────────────────────────────────────────────
// isValidIPv4 - prevent shell injection before passing to system()
// ─────────────────────────────────────────────────────────────────────────────
bool FirewallEnforcer::isValidIPv4(const std::string& ip)
{
    static const std::regex ipv4_re(
        R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)"
    );

    std::smatch m;
    if (!std::regex_match(ip, m, ipv4_re))
        return false;

    for (int i = 1; i <= 4; ++i) {
        if (std::stoi(m[i].str()) > 255)
            return false;
    }
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// addRule - blocks traffic in BOTH directions for the given IP
// ─────────────────────────────────────────────────────────────────────────────
void FirewallEnforcer::addRule(const std::string& src_ip)
{
    // Block incoming packets FROM this IP
    std::string cmd1 = "iptables -A INPUT -s " + src_ip
                     + " -j DROP > /dev/null 2>&1";

    // Block outgoing packets TO this IP
    std::string cmd2 = "iptables -A OUTPUT -d " + src_ip
                     + " -j DROP > /dev/null 2>&1";

    int ret1 = system(cmd1.c_str());
    int ret2 = system(cmd2.c_str());

    if (ret1 != 0 || ret2 != 0) {
        std::cerr << "[Enforcer] WARNING: iptables rule failed for "
                  << src_ip << " — are you running as root?\n";
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// removeRule - removes both INPUT and OUTPUT rules on cleanup
// ─────────────────────────────────────────────────────────────────────────────
void FirewallEnforcer::removeRule(const std::string& src_ip)
{
    system(("iptables -D INPUT -s "  + src_ip + " -j DROP > /dev/null 2>&1").c_str());
    system(("iptables -D OUTPUT -d " + src_ip + " -j DROP > /dev/null 2>&1").c_str());
}

// ─────────────────────────────────────────────────────────────────────────────
// blockIP - public entry point with validation + deduplication
// ─────────────────────────────────────────────────────────────────────────────
void FirewallEnforcer::blockIP(const std::string& src_ip)
{
    if (!isValidIPv4(src_ip)) {
        std::cerr << "[Enforcer] Invalid IP rejected: '" << src_ip << "'\n";
        return;
    }

    if (blocked_ips_.count(src_ip) > 0)
        return;   // already blocked — skip duplicate iptables call

    addRule(src_ip);
    blocked_ips_.insert(src_ip);

    std::cout << "[Enforcer] iptables DROP rule added for: " << src_ip << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// Destructor - auto cleanup all rules on exit / Ctrl+C
// ─────────────────────────────────────────────────────────────────────────────
FirewallEnforcer::~FirewallEnforcer()
{
    if (blocked_ips_.empty()) return;

    std::cout << "\n[Enforcer] Cleaning up " << blocked_ips_.size()
              << " iptables rule(s)…\n";

    for (const auto& ip : blocked_ips_) {
        removeRule(ip);
        std::cout << "[Enforcer] Removed DROP rule for: " << ip << '\n';
    }
}
