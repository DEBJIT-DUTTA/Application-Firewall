#pragma once

#include "packet_parser.h"    // ParsedPacket
#include <string>
#include <set>
#include <unordered_map>
#include <chrono>

// ─────────────────────────────────────────────────────────────────────────────
// Detection thresholds — tweak these to tune sensitivity
// ─────────────────────────────────────────────────────────────────────────────
inline constexpr int    PORTSCAN_PORT_THRESHOLD  = 10;   // unique ports
inline constexpr int    PORTSCAN_TIME_WINDOW_SEC = 10;   // seconds

// ─────────────────────────────────────────────────────────────────────────────
// ScanRecord
//   Everything we track per source IP:
//     first_seen  – timestamp of the first packet in current window
//     ports       – unique destination ports seen in that window
// ─────────────────────────────────────────────────────────────────────────────
struct ScanRecord {
    std::chrono::steady_clock::time_point first_seen;
    std::set<uint16_t>                    ports;
};

// ─────────────────────────────────────────────────────────────────────────────
// PortScanDetector
//
//   Watches each source IP and counts how many unique destination ports it
//   probes within a rolling time window.  When the count exceeds the threshold
//   the IP is flagged as a port scanner.
//
//   Usage:
//       PortScanDetector detector;
//       if (detector.inspect(pkt)) {
//           // port scan confirmed — block + log
//       }
// ─────────────────────────────────────────────────────────────────────────────
class PortScanDetector {
public:
    PortScanDetector()  = default;
    ~PortScanDetector() = default;

    // Inspect one packet.
    // Returns true the FIRST time a source IP crosses the port threshold.
    // Subsequent packets from the same confirmed scanner return false
    // (already reported — no duplicate alerts).
    bool inspect(const ParsedPacket& pkt);

private:
    // Per-IP tracking table
    std::unordered_map<std::string, ScanRecord> tracker_;

    // IPs already confirmed as scanners this session — suppresses re-alerting
    std::set<std::string> confirmed_scanners_;
};
