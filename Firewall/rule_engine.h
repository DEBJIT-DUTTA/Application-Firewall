#pragma once

#include "packet_parser.h"   // ParsedPacket
#include <string>
#include <set>

// ─────────────────────────────────────────────────────────────────────────────
// RuleEngine
//
//   Loads firewall rules from a JSON file at startup and evaluates every
//   parsed packet against those rules.
//
//   Usage:
//       RuleEngine engine("rules.json");   // load once
//       if (engine.isBlocked(pkt)) { ... }
//
//   std::set is used for O(log n) lookups — faster than linear vector search
//   when the rule list grows large.
// ─────────────────────────────────────────────────────────────────────────────
class RuleEngine {
public:
    // Load rules from the given JSON file path.
    // Prints a warning and continues with empty rules if the file is missing.
    explicit RuleEngine(const std::string& rules_file = "rules.json");

    // Returns true if the packet matches any loaded rule (should be blocked).
    bool isBlocked(const ParsedPacket& pkt) const;

    // Diagnostics – useful for verifying rules loaded correctly at startup
    void printLoadedRules() const;

private:
    std::set<std::string> blocked_ips_;    // source IPs to block
    std::set<uint16_t>    blocked_ports_;  // destination ports to block

    // Individual rule checkers
    bool isBlockedBySourceIP (const ParsedPacket& pkt) const;
    bool isBlockedByDestPort (const ParsedPacket& pkt) const;
};
