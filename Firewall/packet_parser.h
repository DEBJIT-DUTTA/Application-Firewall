#pragma once

#include "packet_sniffer.h"   // for RawPacket
#include <cstdint>
#include <string>

// ─────────────────────────────────────────────────────────────────────────────
// ParsedPacket – a flat, human-readable summary of a captured frame.
//   Populated fields depend on which protocol layers are present.
// ─────────────────────────────────────────────────────────────────────────────
struct ParsedPacket {
    // --- Ethernet ---
    std::string src_mac;
    std::string dst_mac;
    uint16_t    ether_type = 0;   // e.g. 0x0800 = IPv4, 0x86DD = IPv6

    // --- IP (v4) ---
    std::string src_ip;
    std::string dst_ip;
    uint8_t     protocol  = 0;    // 6 = TCP, 17 = UDP, 1 = ICMP …
    uint8_t     ttl       = 0;

    // --- TCP / UDP ---
    uint16_t    src_port  = 0;
    uint16_t    dst_port  = 0;

    // --- Meta ---
    bool        valid     = false; // false if frame was too short / malformed
    std::string proto_str;         // human label: "TCP", "UDP", "ICMP", …
};

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser
//   Stateless helper: converts a RawPacket into a ParsedPacket.
// ─────────────────────────────────────────────────────────────────────────────
class PacketParser {
public:
    // Parse raw bytes; returns a populated ParsedPacket.
    static ParsedPacket parse(const RawPacket& raw);

    // Pretty-print a ParsedPacket to stdout
    static void print(const ParsedPacket& pkt);
};
