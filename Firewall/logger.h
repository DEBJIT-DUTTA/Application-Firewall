#pragma once

#include "packet_parser.h"
#include <string>

inline constexpr const char* LOG_FILE_PATH = "firewall.log";

class Logger {
public:
    // Log a blocked packet
    static void logBlocked(const ParsedPacket& pkt);

    // Log a port scan alert
    static void logAlert(const std::string& src_ip, const std::string& reason);

private:
    static std::string currentTimestamp();
};
