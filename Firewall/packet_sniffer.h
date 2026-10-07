#pragma once

#include <pcap.h>
#include <string>
#include <functional>

// Forward declaration of the raw packet data passed to the callback
struct RawPacket {
    const u_char* data;
    uint32_t      len;
    struct timeval ts;
};

// Signature of the user-supplied per-packet handler
using PacketHandler = std::function<void(const RawPacket&)>;

// ─────────────────────────────────────────────────────────────────────────────
// PacketSniffer
//   Wraps libpcap lifecycle: open device → set filter → capture loop → close.
// ─────────────────────────────────────────────────────────────────────────────
class PacketSniffer {
public:
    explicit PacketSniffer(const std::string& device,
                           int                snaplen    = 65535,
                           int                timeout_ms = 1000);
    ~PacketSniffer();

    // Prevent copying – pcap handles are not copyable
    PacketSniffer(const PacketSniffer&)            = delete;
    PacketSniffer& operator=(const PacketSniffer&) = delete;

    // Optional BPF filter string, e.g. "tcp port 80"
    bool setFilter(const std::string& filter_expr);

    // Start the capture loop; calls |handler| for every packet.
    // Pass packet_count = -1 to loop indefinitely.
    bool startCapture(PacketHandler handler, int packet_count = -1);

    // Signal the capture loop to stop (safe to call from a signal handler)
    void stopCapture();

    const std::string& lastError() const { return last_error_; }

private:
    std::string device_;
    pcap_t*     handle_     = nullptr;
    std::string last_error_;

    // libpcap C-style callback trampoline
    static void pcapCallback(u_char* user,
                             const struct pcap_pkthdr* hdr,
                             const u_char* pkt);

    PacketHandler active_handler_;   // stored during capture loop
};
