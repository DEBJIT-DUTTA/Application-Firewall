#include "rule_engine.h"

#include <fstream>
#include <iostream>
#include <netinet/in.h>        // IPPROTO_TCP, IPPROTO_UDP
#include "include/json.hpp"    // nlohmann/json single-header

using json = nlohmann::json;

// ─────────────────────────────────────────────────────────────────────────────
// Constructor – parse rules.json and populate the two lookup sets
// ─────────────────────────────────────────────────────────────────────────────
RuleEngine::RuleEngine(const std::string& rules_file)
{
    std::ifstream f(rules_file);

    if (!f.is_open()) {
        std::cerr << "[RuleEngine] WARNING: could not open '"
                  << rules_file << "'. Running with NO rules.\n";
        return;
    }

    // Let nlohmann parse the entire file in one shot.
    // If the JSON is malformed, catch and warn rather than crash.
    json data;
    try {
        f >> data;
    } catch (const json::parse_error& e) {
        std::cerr << "[RuleEngine] JSON parse error: " << e.what() << '\n';
        return;
    }

    // ── blocked_ips ──────────────────────────────────────────────────────
    if (data.contains("blocked_ips") && data["blocked_ips"].is_array()) {
        for (const auto& ip : data["blocked_ips"]) {
            if (ip.is_string())
                blocked_ips_.insert(ip.get<std::string>());
        }
    }

    // ── blocked_ports ────────────────────────────────────────────────────
    if (data.contains("blocked_ports") && data["blocked_ports"].is_array()) {
        for (const auto& port : data["blocked_ports"]) {
            if (port.is_number_unsigned())
                blocked_ports_.insert(port.get<uint16_t>());
        }
    }

    printLoadedRules();   // always confirm what was loaded at startup
}

// ─────────────────────────────────────────────────────────────────────────────
// printLoadedRules – startup diagnostic
// ─────────────────────────────────────────────────────────────────────────────
void RuleEngine::printLoadedRules() const
{
    std::cout << "[RuleEngine] Loaded "
              << blocked_ips_.size()   << " blocked IP(s), "
              << blocked_ports_.size() << " blocked port(s).\n";

    for (const auto& ip   : blocked_ips_)    std::cout << "  BLOCK IP:   " << ip   << '\n';
    for (const auto& port : blocked_ports_)  std::cout << "  BLOCK PORT: " << port << '\n';
    std::cout << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// Private rule evaluators
// ─────────────────────────────────────────────────────────────────────────────
bool RuleEngine::isBlockedBySourceIP(const ParsedPacket& pkt) const
{
    // std::set::count() is O(log n) — safe even with hundreds of rules
    return blocked_ips_.count(pkt.src_ip) > 0;
}

bool RuleEngine::isBlockedByDestPort(const ParsedPacket& pkt) const
{
    if (pkt.protocol != IPPROTO_TCP && pkt.protocol != IPPROTO_UDP)
        return false;

    return blocked_ports_.count(pkt.dst_port) > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// isBlocked – public entry point; short-circuit OR across all rules
// ─────────────────────────────────────────────────────────────────────────────
bool RuleEngine::isBlocked(const ParsedPacket& pkt) const
{
    if (!pkt.valid) return false;

    if (isBlockedBySourceIP(pkt))  return true;
    if (isBlockedByDestPort(pkt))  return true;

    return false;
}
