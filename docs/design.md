# IDS Design Document

## Architecture
- Packet capture module
- Detection engine
- Alerting/logging system

## Detection Strategy
- Rule-based detection (port scans, suspicious IPs)
- Threshold alerts

## IDS Modes

This IDS supports two operating modes:

1. Offline Mode (PCAP Analysis)
- Reads captured network traffic from .pcap files
- Performs detection on historical traffic
- Useful for forensics and testing

2. Live Mode (Real-time Sniffing)
- Monitors network packets in real time
- Generates alerts as suspicious activity is detected
- Simulates SOC-style network monitoring


(To be expanded)
