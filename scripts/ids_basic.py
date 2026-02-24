"""
ids_basic.py
Offline IDS (PCAP analysis) with detection rules + logging + NumPy categorization
Author: Pushpaharan
"""

import os
import sys
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, IP, TCP
import numpy as np


# -----------------------
# SETTINGS / THRESHOLDS
# -----------------------
PORTSCAN_UNIQUE_PORTS_THRESHOLD = 1  # >= 15 unique destination ports -> alert
SYN_COUNT_THRESHOLD = 1             # >= 100 SYN packets -> alert


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
# NUMPY CATEGORIZATION
# -----------------------
def categorize_traffic_numpy(src_counts: dict):
    """
    Categorize source IPs into Low / Medium / High traffic using NumPy percentiles.
    Returns: (low_list, medium_list, high_list, p50, p90)
    """
    if not src_counts:
        return [], [], [], 0, 0

    counts = np.array(list(src_counts.values()), dtype=int)

    p50 = int(np.percentile(counts, 50))  # median
    p90 = int(np.percentile(counts, 90))  # top 10%

    low, medium, high = [], [], []

    for ip, count in src_counts.items():
        if count <= p50:
            low.append((ip, count))
        elif count <= p90:
            medium.append((ip, count))
        else:
            high.append((ip, count))

    low.sort(key=lambda x: x[1], reverse=True)
    medium.sort(key=lambda x: x[1], reverse=True)
    high.sort(key=lambda x: x[1], reverse=True)

    return low, medium, high, p50, p90


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

    src_counts = defaultdict(int)

    # Rule A
    src_to_ports = defaultdict(set)     # src_ip -> set of destination ports

    # Rule B
    src_syn_counts = defaultdict(int)   # src_ip -> syn packet count

    for pkt in packets:
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            src_counts[src_ip] += 1

            if pkt.haslayer(TCP):
                dport = int(pkt[TCP].dport)
                src_to_ports[src_ip].add(dport)

                flags = int(pkt[TCP].flags)

                # SYN without ACK (more accurate than SYN alone)
                SYN = 0x02
                ACK = 0x10
                if (flags & SYN) and not (flags & ACK):
                    src_syn_counts[src_ip] += 1

    # Top 5 talkers
    print("\n[+] Top 5 source IPs by packet count:")
    top5 = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    for ip, count in top5:
        print(f"    {ip} -> {count} packets")

    # NumPy categorization
    low, medium, high, p50, p90 = categorize_traffic_numpy(src_counts)

    print("\n[+] Traffic Categories (NumPy percentile-based):")
    print(f"    Thresholds: Low <= {p50}, Medium <= {p90}, High > {p90}")
    print(f"    Low Traffic IPs: {len(low)}")
    print(f"    Medium Traffic IPs: {len(medium)}")
    print(f"    High Traffic IPs: {len(high)}")

    print("\n    Top Low Traffic (max 3):")
    for ip, count in low[:3]:
        print(f"      {ip} -> {count}")

    print("\n    Top Medium Traffic (max 3):")
    for ip, count in medium[:3]:
        print(f"      {ip} -> {count}")

    print("\n    Top High Traffic (max 3):")
    for ip, count in high[:3]:
        print(f"      {ip} -> {count}")

    # Detection rules
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
            print("  py scripts/ids_basic.py offline captures/geotest.pcap")
            return

        pcap_file = sys.argv[2]
        run_offline_mode(pcap_file)
    else:
        print("[!] Unknown mode. Use 'offline'.")


if __name__ == "__main__":
    main()