# Intrusion Detection System (IDS)

This project implements a basic IDS in Python using Scapy.  
It supports offline PCAP analysis and will later support live traffic monitoring.

## Features
- Offline packet analysis from PCAP
- Top source IP detection
- Suspicious traffic identification (future)
- Categorizing Data use numpy (future)
- Interface to interact via GUI (future)

## How to Run
```bash
py scripts/ids_basic.py offline captures/sample_traffic.pcap

## Suspicious Traffic Identification

This IDS implements multiple detection rules:

- Port scan detection: detects IPs contacting many unique destination ports
- SYN activity detection: detects abnormal SYN packet activity
- Alerts are printed to console and saved to logs/alerts.log

Thresholds can be configured in ids_basic.py.
