"""
ids_basic.py
Offline + Live Intrusion Detection System (IDS)
PCAP analysis + live packet sniffing with detection rules, logging, and NumPy traffic categorization

Author: Pushpaharan
"""

import os
import sys
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, sniff, IP, TCP
import numpy as np


# -----------------------
# SETTINGS / THRESHOLDS
# -----------------------

PORTSCAN_UNIQUE_PORTS_THRESHOLD = 10   # >= 10 unique ports -> possible scan
SYN_COUNT_THRESHOLD = 20               # >= 20 SYN packets -> suspicious


# -----------------------
# LOGGING
# -----------------------

def log_alert(message: str, log_path="logs/alerts.log"):
    """Write alerts to logs/alerts.log"""

    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")


# -----------------------
# DETECTION RULES
# -----------------------

def detect_port_scan(src_to_ports: dict):

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
        print("[+] No port scan behavior detected.")


def detect_syn_activity(src_syn_counts: dict):

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
        print("[+] No suspicious SYN activity detected.")


# -----------------------
# NUMPY TRAFFIC ANALYSIS
# -----------------------

def categorize_traffic_numpy(src_counts: dict):

    if not src_counts:
        return [], [], [], 0, 0

    counts = np.array(list(src_counts.values()), dtype=int)

    p50 = int(np.percentile(counts, 50))
    p90 = int(np.percentile(counts, 90))

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

def run_offline_mode(pcap_file):

    if not os.path.exists(pcap_file):

        print(f"[!] ERROR: File not found: {pcap_file}")
        return

    print(f"[+] Running IDS in OFFLINE mode on {pcap_file}")

    packets = rdpcap(pcap_file)

    print(f"[+] Loaded {len(packets)} packets")

    src_counts = defaultdict(int)
    src_to_ports = defaultdict(set)
    src_syn_counts = defaultdict(int)

    for pkt in packets:

        if pkt.haslayer(IP):

            src_ip = pkt[IP].src

            src_counts[src_ip] += 1

            if pkt.haslayer(TCP):

                dport = int(pkt[TCP].dport)

                src_to_ports[src_ip].add(dport)

                flags = int(pkt[TCP].flags)

                SYN = 0x02
                ACK = 0x10

                if (flags & SYN) and not (flags & ACK):

                    src_syn_counts[src_ip] += 1

    # Top talkers

    print("\n[+] Top 5 source IPs:")

    top5 = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    for ip, count in top5:
        print(f"    {ip} -> {count} packets")

    # NumPy analysis

    low, medium, high, p50, p90 = categorize_traffic_numpy(src_counts)

    print("\n[+] Traffic Categories:")

    print(f"    Low <= {p50}")
    print(f"    Medium <= {p90}")
    print(f"    High > {p90}")

    # Detection rules

    detect_port_scan(src_to_ports)

    detect_syn_activity(src_syn_counts)

    print("\n[+] Alerts saved to logs/alerts.log")


# -----------------------
# LIVE MODE
# -----------------------

def run_live_mode(interface=None, packet_limit=200, timeout=30):

    print("[+] Running IDS in LIVE mode")

    print(f"    Interface: {interface if interface else 'default'}")

    print(f"    Packet limit: {packet_limit}")

    print(f"    Timeout: {timeout} seconds")

    packets = sniff(iface=interface, count=packet_limit, timeout=timeout)

    print(f"[+] Captured {len(packets)} packets")

    src_counts = defaultdict(int)
    src_to_ports = defaultdict(set)
    src_syn_counts = defaultdict(int)

    for pkt in packets:

        if pkt.haslayer(IP):

            src_ip = pkt[IP].src

            src_counts[src_ip] += 1

            if pkt.haslayer(TCP):

                dport = int(pkt[TCP].dport)

                src_to_ports[src_ip].add(dport)

                flags = int(pkt[TCP].flags)

                SYN = 0x02
                ACK = 0x10

                if (flags & SYN) and not (flags & ACK):

                    src_syn_counts[src_ip] += 1

    print("\n[+] Top 5 source IPs:")

    top5 = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    for ip, count in top5:
        print(f"    {ip} -> {count} packets")

    detect_port_scan(src_to_ports)

    detect_syn_activity(src_syn_counts)

    print("\n[+] Alerts saved to logs/alerts.log")


# -----------------------
# MAIN PROGRAM
# -----------------------

def main():

    if len(sys.argv) < 2:

        print("\nUsage:")

        print("Offline mode:")
        print("  py scripts/ids_basic.py offline captures/file.pcap")

        print("\nLive mode:")
        print("  py scripts/ids_basic.py live")

        print("  py scripts/ids_basic.py live <interface>")

        print("  py scripts/ids_basic.py live <interface> <packet_limit> <timeout>")

        return

    mode = sys.argv[1].lower()

    if mode == "offline":

        if len(sys.argv) < 3:

            print("[!] ERROR: Please provide a PCAP file")

            return

        pcap_file = sys.argv[2]

        run_offline_mode(pcap_file)

    elif mode == "live":

        interface = sys.argv[2] if len(sys.argv) >= 3 else None

        packet_limit = int(sys.argv[3]) if len(sys.argv) >= 4 else 200

        timeout = int(sys.argv[4]) if len(sys.argv) >= 5 else 30

        run_live_mode(interface, packet_limit, timeout)

    else:

        print("[!] Unknown mode. Use 'offline' or 'live'")


if __name__ == "__main__":
    main()