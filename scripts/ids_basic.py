"""
ids_basic.py
Offline IDS (PCAP analysis) with detection rules + logging
Author: Pushpaharan
"""

import os
import sys
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, IP, TCP


# -----------------------
# SETTINGS / THRESHOLDS
# -----------------------
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 1    # if an IP touches >= 15 different ports -> alert
SYN_COUNT_THRESHOLD = 1              # if an IP sends >= 100 SYN packets -> alert


# -----------------------
# LOGGING
# -----------------------
def log_alert(message: str, log_path="logs/alerts.log"):
    """Append one alert line to logs/alerts.log (creates folder if missing)."""
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")


# -----------------------
# DETECTION RULES
# -----------------------
def detect_port_scan(src_to_ports: dict):
    """
    Rule A: Port scan detection
    If a source IP attempts connections to many unique destination ports -> suspicious.
    """
    print("\n[+] Port Scan Check (unique destination ports per source):")
    detected = False

    for src_ip, port_set in src_to_ports.items():
        unique_ports = len(port_set)
        if unique_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
            detected = True
            alert_msg = (
                f"ALERT PORT_SCAN Source={src_ip} UniquePorts={unique_ports} "
                f"Threshold={PORTSCAN_UNIQUE_PORTS_THRESHOLD}"
            )
            print("[!]", alert_msg)
            log_alert(alert_msg)

    if not detected:
        print("[+] No port scan behavior detected (based on threshold).")


def detect_syn_activity(src_syn_counts: dict):
    """
    Rule B: SYN scan / SYN flood indicator
    If a source IP sends many TCP SYN packets -> suspicious.
    """
    print("\n[+] SYN Activity Check (SYN packets per source):")
    detected = False

    for src_ip, syn_count in src_syn_counts.items():
        if syn_count >= SYN_COUNT_THRESHOLD:
            detected = True
            alert_msg = (
                f"ALERT SYN_ACTIVITY Source={src_ip} SYNs={syn_count} "
                f"Threshold={SYN_COUNT_THRESHOLD}"
            )
            print("[!]", alert_msg)
            log_alert(alert_msg)

    if not detected:
        print("[+] No suspicious SYN activity detected (based on threshold).")


# -----------------------
# OFFLINE MODE
# -----------------------
def run_offline_mode(pcap_file: str):
    if not os.path.exists(pcap_file):
        print(f"[!] ERROR: File not found: {pcap_file}")
        return

    print(f"[+] Running IDS in OFFLINE mode on {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[+] Loaded {len(packets)} packets from {pcap_file}")

    # Top talkers
    src_counts = defaultdict(int)

    # For Rule A: port scan detection
    src_to_ports = defaultdict(set)     # src_ip -> set of destination ports

    # For Rule B: SYN activity
    src_syn_counts = defaultdict(int)   # src_ip -> syn packet count

    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            src_counts[src_ip] += 1

            # Only check TCP packets for port scan and SYN rules
            if pkt.haslayer(TCP):
                dport = int(pkt[TCP].dport)
                src_to_ports[src_ip].add(dport)

                flags = pkt[TCP].flags
                # SYN packet is usually flag "S" (SYN) without ACK
                # Scapy flags: 'S' for SYN. You can check by: if flags & 0x02
                if flags & 0x02:  # SYN bit
                    src_syn_counts[src_ip] += 1

    # Print top 5
    print("\n[+] Top 5 source IPs by packet count:")
    top5 = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top5:
        print(f"    {ip} -> {count} packets")

    # Run detection rules
    detect_port_scan(src_to_ports)
    detect_syn_activity(src_syn_counts)

    print("\n[+] Alerts saved to: logs/alerts.log")


# -----------------------
# MAIN
# -----------------------
def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  py scripts/ids_basic.py offline <pcap_file>")
        return

    mode = sys.argv[1].lower()

    if mode == "offline":
        if len(sys.argv) < 3:
            print("[!] ERROR: Please provide a pcap file path.")
            print("Example:")
            print("  py scripts/ids_basic.py offline captures/sample_traffic.pcap")
            return

        pcap_file = sys.argv[2]
        run_offline_mode(pcap_file)
    else:
        print("[!] Unknown mode. Use 'offline'.")


if __name__ == "__main__":
    main()