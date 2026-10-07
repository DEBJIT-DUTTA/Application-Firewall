# ─────────────────────────────────────────────────────────────────────────────
# Modular Firewall – Makefile
# Build: make          Run: sudo ./firewall [interface]
# ─────────────────────────────────────────────────────────────────────────────

CXX      := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -Iinclude
LDFLAGS  := -lpcap

TARGET   := firewall
SRCS     := main.cpp \
             packet_sniffer.cpp \
             packet_parser.cpp \
             rule_engine.cpp \
             logger.cpp \
             firewall_enforcer.cpp \
             port_scan_detector.cpp

OBJS     := $(SRCS:.cpp=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "✓ Build successful → ./$(TARGET)"

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
