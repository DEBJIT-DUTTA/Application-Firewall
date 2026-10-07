# Application-Firewall
# Firewall Application

A lightweight **network firewall application** designed to monitor and control network traffic based on predefined security rules.

The application demonstrates the core concepts behind firewalls by inspecting network traffic and applying rules to **allow or block connections** based on parameters such as IP addresses, ports, protocols, and traffic direction.

## Objective

The main objective of this project is to understand how network firewalls work and how security rules can be used to control network communication.

The project provides a practical implementation of concepts such as **packet filtering, access control, network monitoring, and traffic blocking**.

## Key Features

- Network traffic monitoring
- Rule-based traffic filtering
- Allow/block network connections
- IP address-based filtering
- Port-based filtering
- Protocol-based filtering
- Inbound and outbound traffic control
- Logging of network events
- Configurable firewall rules
- Detection of blocked network activity

## How It Works

The firewall sits between network traffic and the protected system and evaluates traffic against configured security rules.

```text
              Incoming / Outgoing Traffic
                         │
                         ▼
                ┌─────────────────┐
                │ Traffic Capture │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Packet Analysis │
                └────────┬────────┘
                         │
                         ▼
                ┌─────────────────┐
                │ Firewall Rules  │
                │   Evaluation    │
                └────────┬────────┘
                         │
                  ┌──────┴──────┐
                  │             │
                ALLOW          BLOCK
                  │             │
                  ▼             ▼
              Forward       Drop Traffic
              Traffic       + Log Event
```

## Firewall Rule Concept

Rules can be used to define which traffic should be permitted or denied.

Example:

| Source IP | Destination Port | Protocol | Action |
|---|---:|---|---|
| `192.168.1.10` | `80` | TCP | ALLOW |
| `192.168.1.20` | `22` | TCP | BLOCK |
| `10.0.0.0/24` | `443` | TCP | ALLOW |

The firewall evaluates network traffic against these rules and takes the corresponding action.

## 📊 Monitoring & Logging

The application can record relevant network events, including:

- Allowed connections
- Blocked connections
- Source and destination information
- Ports and protocols
- Firewall rule responsible for the decision
- Timestamp of the event

This makes the project useful for understanding how firewall logs can contribute to **network monitoring and security operations**.

## Concepts Demonstrated

This project helped me understand and implement concepts related to:

- Firewalls
- Packet filtering
- TCP/IP
- IP addressing
- TCP and UDP
- Network ports
- Inbound and outbound traffic
- Access Control Lists (ACLs)
- Network security
- Traffic monitoring
- Security event logging

## Future Improvements

Planned improvements include:

- Advanced rule management
- CIDR/subnet-based rules
- Stateful packet inspection
- Real-time traffic dashboard
- Rule priority and ordering
- Automatic suspicious-traffic detection
- Centralized logging
- SIEM integration
- Alert notifications
- More detailed packet inspection
- Traffic statistics and visualization

## Learning Purpose

This project was developed as a **hands-on network security project** to understand the fundamental architecture and working principles of firewalls.

It is particularly focused on learning how network traffic can be **inspected, filtered, controlled, and logged** using security policies.

## ⚠️ Disclaimer

This project is intended for **educational and defensive security purposes**. Use it only on systems and networks where you have proper authorization.
