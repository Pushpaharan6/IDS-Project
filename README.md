# Intrusion Detection System (IDS)

This project implements a basic IDS in Python using Scapy.  
It supports offline PCAP analysis and will later support live traffic monitoring.

## Features
- Offline packet analysis from PCAP
- Top source IP detection
- Suspicious traffic identification (future)

## How to Run
```bash
py scripts/ids_basic.py offline captures/sample_traffic.pcap
