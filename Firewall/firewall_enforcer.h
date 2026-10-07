#pragma once

#include <string>
#include <set>

// ─────────────────────────────────────────────────────────────────────────────
// FirewallEnforcer
//
//   Translates firewall decisions into real iptables DROP rules.
//
//   Design goals:
//     • One iptables rule per unique source IP — never duplicated
//     • All previously blocked IPs are flushed on clean shutdown
//     • system() is used for simplicity; each call is sanitized first
//
//   Usage:
//       FirewallEnforcer enforcer;
//       enforcer.blockIP("10.0.0.99");   // adds iptables rule once
//       enforcer.blockIP("10.0.0.99");   // silently ignored (already blocked)
// ─────────────────────────────────────────────────────────────────────────────
class FirewallEnforcer {
public:
    FirewallEnforcer()  = default;

    // Destructor automatically removes every rule this session added.
    ~FirewallEnforcer();

    // Prevent copying — the blocked_ips_ set must have one owner.
    FirewallEnforcer(const FirewallEnforcer&)            = delete;
    FirewallEnforcer& operator=(const FirewallEnforcer&) = delete;

    // Block a source IP via iptables. No-op if already blocked this session.
    void blockIP(const std::string& src_ip);

    // How many unique IPs have been blocked this session
    std::size_t blockedCount() const { return blocked_ips_.size(); }

private:
    // IPs blocked during this session — prevents duplicate iptables rules
    std::set<std::string> blocked_ips_;

    // Validate IP string before passing it to shell (basic safety check)
    static bool isValidIPv4(const std::string& ip);

    // Thin wrappers around system() calls
    static void addRule   (const std::string& src_ip);
    static void removeRule(const std::string& src_ip);
};
