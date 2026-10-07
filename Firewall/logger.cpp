#include "logger.h"

#include <fstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <sstream>

// ─────────────────────────────────────────────────────────────────────────────
// currentTimestamp - "2025-05-03 14:22:01"
// ─────────────────────────────────────────────────────────────────────────────
std::string Logger::currentTimestamp()
{
    std::time_t now = std::time(nullptr);
    std::tm*    lt  = std::localtime(&now);
    std::ostringstream oss;
    oss << std::put_time(lt, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
// logBlocked - one line per blocked packet
// ─────────────────────────────────────────────────────────────────────────────
void Logger::logBlocked(const ParsedPacket& pkt)
{
    std::ofstream log(LOG_FILE_PATH, std::ios::app);
    if (!log.is_open()) {
        std::cerr << "[Logger] WARNING: could not open '"
                  << LOG_FILE_PATH << "'\n";
        return;
    }

    log << '[' << currentTimestamp() << "] "
        << "[ALERT] Blocked: "
        << pkt.src_ip  << " → " << pkt.dst_ip
        << "  PROTO="    << pkt.proto_str
        << "  SRC_PORT=" << pkt.src_port
        << "  DST_PORT=" << pkt.dst_port
        << '\n';
}

// ─────────────────────────────────────────────────────────────────────────────
// logAlert - generic alert line (used for port scan detection)
// ─────────────────────────────────────────────────────────────────────────────
void Logger::logAlert(const std::string& src_ip, const std::string& reason)
{
    std::ofstream log(LOG_FILE_PATH, std::ios::app);
    if (!log.is_open()) {
        std::cerr << "[Logger] WARNING: could not open '"
                  << LOG_FILE_PATH << "'\n";
        return;
    }

    log << '[' << currentTimestamp() << "] "
        << "[ALERT] " << reason
        << " — Source IP: " << src_ip
        << '\n';
}
