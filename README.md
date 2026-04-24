# Python Intrusion Detection System (IDS)

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Scapy](https://img.shields.io/badge/Scapy-Packet%20Analysis-green)
![Flask](https://img.shields.io/badge/Flask-Dashboard-black)
![NumPy](https://img.shields.io/badge/NumPy-Traffic%20Analysis-orange)
![Status](https://img.shields.io/badge/Project-Semester%20Final-success)

## Overview

This project is a lightweight Intrusion Detection System (IDS) built in Python for a cybersecurity semester project. It analyzes network traffic from saved packet capture files and detects suspicious behavior using rule-based logic.

The IDS supports:

- **Offline PCAP analysis**
- **Live packet capture**
- **Flask dashboard visualization**
- **TXT and CSV report export**

This project demonstrates key cybersecurity concepts such as packet inspection, network monitoring, anomaly detection, alert logging, and dashboard-based reporting.

---

## Project Goals

The main goals of this project are to:

- analyze `.pcap` and `.pcapng` files
- detect suspicious traffic patterns
- identify top traffic sources
- classify traffic activity levels
- log alerts in text and JSON formats
- present results in a dashboard
- support controlled live testing in a lab environment

---

## Features

- Offline PCAP analysis
- Live packet capture support
- Port scan detection
- SYN activity detection
- High traffic anomaly detection
- Traffic categorization using NumPy percentiles
- Alert severity levels
- Text and JSON alert logging
- Flask dashboard for PCAP upload and result review
- Top source IP activity visualization
- Downloadable TXT report export
- Downloadable CSV report export

---

## Detection Rules

The IDS currently uses three main detection rules:

### 1. Port Scan Detection
Counts how many unique destination TCP ports are contacted by each source IP.  
If the count exceeds the configured threshold, the IDS generates a `PORT_SCAN` alert.

### 2. SYN Activity Detection
Counts TCP SYN packets without ACK for each source IP.  
If the count exceeds the configured threshold, the IDS generates a `SYN_ACTIVITY` alert.

### 3. High Traffic Detection
Counts how many packets are sent by each source IP.  
If the count exceeds the configured threshold, the IDS generates a `HIGH_TRAFFIC` alert.

---

## Future Improvements
Possible future improvements include:
- machine learning anomaly detection
- real-time network visualization
- SIEM integration
- improved live capture reliability on Windows virtual adapters
- additional dashboard charts and analytics
- downloadable CSV and advanced report formats
- more detection rules
- more advanced alert prioritization

## How to Run

# Offline Mode
Use offline mode to analyze a saved PCAP file: py scripts/ids_basic.py offline captures/kali_portscan.pcapng

# Live Mode
py scripts/ids_basic.py live
Or specify interface, packet limit, and timeout: py scripts/ids_basic.py live 3 500 60

# Run the Web Dashboard
py app.py
Then open this in your browser: http://127.0.0.1:5000

## Alert Severity

To improve readability and prioritization, alerts are displayed with severity levels:

- `LOW`
- `MEDIUM`
- `HIGH`

Severity is shown in:

- dashboard alert cards
- text logs
- JSON logs
- exported TXT reports

---

## Dashboard Features

The Flask dashboard provides a simple interface for reviewing IDS results.

### Dashboard Capabilities

- Upload `.pcap` or `.pcapng` files
- View total packet count
- View unique source IP count
- Review traffic category counts
- View highest alert severity
- Review alert summary by type
- View detected alerts with severity badges
- View top source IP activity bars
- Review top source IP table
- Review recent alert log entries
- Download a TXT report after analysis
- Download a CSV report after analysis

---
## Output Files
The IDS generates several output files:

- logs/alerts.log → text-based alert log
- logs/alerts.jsonl → JSON alert log
- logs/ids_results.txt → latest results summary
- downloadable TXT report from dashboard
- downloadable CSV report from dashboard

## Latest Updates
Recent improvements to the project include:

- improved Flask dashboard layout and styling
- added alert summary display by rule type
- added severity badges for alert visualization
- added downloadable TXT report export
- added downloadable CSV report export
- improved README documentation and run instructions
- improved logging structure with text and JSON output
- added better support for dashboard-based review of suspicious traffic

## Known Limitations
- Live capture reliability on Windows may vary depending on the selected interface and adapter configuration.
- Offline PCAP analysis is currently the most reliable workflow for demonstrating the IDS.
- ICMP detection logic was explored, but still requires additional refinement depending on capture format and interface behavior.

  ## Demonstration Summary
  The project was successfully demonstrated using:

- normal traffic analysis with no alerts
- suspicious traffic analysis with alert generation
- dashboard visualization of alert results
- TXT and CSV report export
- logging to text and JSON formats

## Conclusion
This project demonstrates a rule-based Python IDS that can analyze PCAP traffic, detect suspicious behavior, log alerts, and present results in a user-friendly dashboard.
It provides a strong foundation for future improvements such as expanded detection rules, stronger live capture support, SIEM-ready logging, and intelligent anomaly detection.
  
## Project Structure

```text
IDS-Project/
│
├── app.py                     # Flask dashboard application
├── README.md                  # Project documentation
│
├── captures/                  # Sample PCAP / PCAPNG files
├── docs/                      # Project documents and report files
├── logs/                      # alerts.log, alerts.jsonl, ids_results.txt
├── proposal/                  # Proposal and presentation files
├── static/                    # CSS for dashboard
├── templates/                 # HTML templates for dashboard
├── uploads/                   # Uploaded PCAP files from dashboard
│
└── scripts/
    ├── ids_basic.py           # Main IDS engine
    └── packet_capture.py      # Packet capture helper

## Project Structure

```text
IDS-Project/
│
├── app.py                     # Flask dashboard application
├── README.md                  # Project documentation
│
├── captures/                  # Sample PCAP / PCAPNG files
├── docs/                      # Project documents and report files
├── logs/                      # alerts.log, alerts.jsonl, ids_results.txt
├── proposal/                  # Proposal and presentation files
├── static/                    # CSS for dashboard
├── templates/                 # HTML templates for dashboard
├── uploads/                   # Uploaded PCAP files from dashboard
│
└── scripts/
    ├── ids_basic.py           # Main IDS engine
    └── packet_capture.py      # Packet capture helper


