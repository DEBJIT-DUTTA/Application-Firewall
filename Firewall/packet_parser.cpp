#include "packet_parser.h"

#include <netinet/in.h>       // ntohs / ntohl
#include <arpa/inet.h>        // inet_ntoa
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format structs  (no padding – use __attribute__((packed)) for safety)
// ─────────────────────────────────────────────────────────────────────────────

// Ethernet II header (14 bytes)
struct EtherHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ether_type;   // big-endian on wire
} __attribute__((packed));

// IPv4 header (20 bytes minimum, IHL field gives actual size)
struct IPv4Header {
    uint8_t  version_ihl;   // upper 4 bits = version, lower 4 = IHL (×4 = bytes)
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
} __attribute__((packed));

// TCP header (20 bytes minimum, data_offset field gives actual size)
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;  // upper 4 bits = offset in 32-bit words
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
} __attribute__((packed));

// UDP header (8 bytes, fixed)
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

static std::string macToString(const uint8_t* mac)
{
    std::ostringstream oss;
    for (int i = 0; i < 6; ++i) {
        if (i) oss << ':';
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(mac[i]);
    }
    return oss.str();
}

static std::string ipv4ToString(uint32_t addr_net)
{
    struct in_addr a;
    a.s_addr = addr_net;   // already in network byte order
    return inet_ntoa(a);
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser::parse
// ─────────────────────────────────────────────────────────────────────────────
ParsedPacket PacketParser::parse(const RawPacket& raw)
{
    ParsedPacket pkt;

    // ── Layer 2: Ethernet ──────────────────────────────────────────────────
    constexpr uint32_t ETHER_HDR_LEN = 14;
    if (raw.len < ETHER_HDR_LEN) return pkt;  // too short

    const auto* eth = reinterpret_cast<const EtherHeader*>(raw.data);
    pkt.src_mac    = macToString(eth->src);
    pkt.dst_mac    = macToString(eth->dst);
    pkt.ether_type = ntohs(eth->ether_type);

    // We only handle IPv4 (0x0800) for now; silently drop ARP, IPv6, etc.
    if (pkt.ether_type != 0x0800) {
        pkt.proto_str = "non-IPv4";
        pkt.valid     = true;  // frame is valid, just not IPv4
        return pkt;
    }

    // ── Layer 3: IPv4 ──────────────────────────────────────────────────────
    if (raw.len < ETHER_HDR_LEN + sizeof(IPv4Header)) return pkt;

    const auto* ip =
        reinterpret_cast<const IPv4Header*>(raw.data + ETHER_HDR_LEN);

    uint8_t ihl = (ip->version_ihl & 0x0F) * 4;   // IHL in bytes
    if (ihl < 20) return pkt;                        // malformed

    pkt.src_ip   = ipv4ToString(ip->src_addr);
    pkt.dst_ip   = ipv4ToString(ip->dst_addr);
    pkt.protocol = ip->protocol;
    pkt.ttl      = ip->ttl;

    uint32_t ip_offset = ETHER_HDR_LEN + ihl;       // start of transport layer

    // ── Layer 4: TCP / UDP ────────────────────────────────────────────────
    switch (ip->protocol) {

        case IPPROTO_TCP: {
            pkt.proto_str = "TCP";
            if (raw.len < ip_offset + sizeof(TCPHeader)) break;
            const auto* tcp =
                reinterpret_cast<const TCPHeader*>(raw.data + ip_offset);
            pkt.src_port = ntohs(tcp->src_port);
            pkt.dst_port = ntohs(tcp->dst_port);
            break;
        }

        case IPPROTO_UDP: {
            pkt.proto_str = "UDP";
            if (raw.len < ip_offset + sizeof(UDPHeader)) break;
            const auto* udp =
                reinterpret_cast<const UDPHeader*>(raw.data + ip_offset);
            pkt.src_port = ntohs(udp->src_port);
            pkt.dst_port = ntohs(udp->dst_port);
            break;
        }

        case IPPROTO_ICMP:
            pkt.proto_str = "ICMP";
            break;

        default:
            pkt.proto_str = "IP/" + std::to_string(ip->protocol);
            break;
    }

    pkt.valid = true;
    return pkt;
}

// ─────────────────────────────────────────────────────────────────────────────
// PacketParser::print
// ─────────────────────────────────────────────────────────────────────────────
void PacketParser::print(const ParsedPacket& pkt)
{
    if (!pkt.valid) {
        std::cout << "[PARSER] Malformed / unsupported frame\n";
        return;
    }
    if (pkt.ether_type != 0x0800) {
        std::cout << "[PARSER] EtherType=0x"
                  << std::hex << pkt.ether_type << std::dec
                  << " (non-IPv4, skipped)\n";
        return;
    }

    std::cout << "[PACKET] "
              << pkt.proto_str
              << "  "
              << pkt.src_ip;
    if (pkt.src_port)
        std::cout << ':' << pkt.src_port;

    std::cout << "  →  "
              << pkt.dst_ip;
    if (pkt.dst_port)
        std::cout << ':' << pkt.dst_port;

    std::cout << "  TTL=" << static_cast<int>(pkt.ttl)
              << '\n';
}
