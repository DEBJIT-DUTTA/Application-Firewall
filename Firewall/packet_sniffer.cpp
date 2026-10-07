#include "packet_sniffer.h"

#include <iostream>
#include <cstring>

// ─────────────────────────────────────────────────────────────────────────────
// Constructor – opens the live capture device
// ─────────────────────────────────────────────────────────────────────────────
PacketSniffer::PacketSniffer(const std::string& device,
                             int                snaplen,
                             int                timeout_ms)
    : device_(device)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap_open_live:
    //   device     – network interface name (e.g. "eth0", "enp3s0")
    //   snaplen    – max bytes captured per packet
    //   promisc    – 1 = promiscuous mode (capture all frames, not just ours)
    //   timeout_ms – read timeout in milliseconds
    handle_ = pcap_open_live(device_.c_str(), snaplen, /*promisc=*/1,
                             timeout_ms, errbuf);

    if (!handle_) {
        last_error_ = errbuf;
        std::cerr << "[PacketSniffer] Failed to open device '"
                  << device_ << "': " << last_error_ << '\n';
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Destructor – always close the handle
// ─────────────────────────────────────────────────────────────────────────────
PacketSniffer::~PacketSniffer()
{
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// setFilter – compile and install a BPF filter on the capture handle
// ─────────────────────────────────────────────────────────────────────────────
bool PacketSniffer::setFilter(const std::string& filter_expr)
{
    if (!handle_) return false;

    struct bpf_program fp{};
    // net mask 0 = don't optimize for a specific subnet
    if (pcap_compile(handle_, &fp, filter_expr.c_str(),
                     /*optimize=*/1, PCAP_NETMASK_UNKNOWN) == -1) {
        last_error_ = pcap_geterr(handle_);
        std::cerr << "[PacketSniffer] Filter compile error: "
                  << last_error_ << '\n';
        return false;
    }

    if (pcap_setfilter(handle_, &fp) == -1) {
        last_error_ = pcap_geterr(handle_);
        std::cerr << "[PacketSniffer] Filter install error: "
                  << last_error_ << '\n';
        pcap_freecode(&fp);
        return false;
    }

    pcap_freecode(&fp);
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// pcapCallback – static trampoline; libpcap calls this per packet.
//   user  = pointer we passed to pcap_loop (→ the PacketSniffer instance)
// ─────────────────────────────────────────────────────────────────────────────
void PacketSniffer::pcapCallback(u_char*                   user,
                                 const struct pcap_pkthdr* hdr,
                                 const u_char*             pkt)
{
    auto* self = reinterpret_cast<PacketSniffer*>(user);

    RawPacket rp;
    rp.data = pkt;
    rp.len  = hdr->caplen;   // actual captured bytes (may be < hdr->len)
    rp.ts   = hdr->ts;

    self->active_handler_(rp);
}

// ─────────────────────────────────────────────────────────────────────────────
// startCapture – enter libpcap's blocking dispatch loop
// ─────────────────────────────────────────────────────────────────────────────
bool PacketSniffer::startCapture(PacketHandler handler, int packet_count)
{
    if (!handle_) {
        std::cerr << "[PacketSniffer] Cannot start capture: device not open.\n";
        return false;
    }

    active_handler_ = std::move(handler);

    // pcap_loop returns 0 when packet_count is satisfied,
    //                   -1 on error,
    //                   -2 if pcap_breakloop() was called.
    int ret = pcap_loop(handle_, packet_count,
                        &PacketSniffer::pcapCallback,
                        reinterpret_cast<u_char*>(this));

    if (ret == -1) {
        last_error_ = pcap_geterr(handle_);
        std::cerr << "[PacketSniffer] pcap_loop error: " << last_error_ << '\n';
        return false;
    }
    return true;   // ret == 0 or -2 (stopped cleanly)
}

// ─────────────────────────────────────────────────────────────────────────────
// stopCapture – break out of pcap_loop from another thread / signal handler
// ─────────────────────────────────────────────────────────────────────────────
void PacketSniffer::stopCapture()
{
    if (handle_)
        pcap_breakloop(handle_);
}
