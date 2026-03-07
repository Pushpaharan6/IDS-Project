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

from scapy.all import rdpcap, sniff, IP, TCP, IFACES
import numpy as np


# -----------------------
# SETTINGS / CONSTANTS
# -----------------------

PORTSCAN_UNIQUE_PORTS_THRESHOLD = 10   # >= 10 unique ports -> possible scan
SYN_COUNT_THRESHOLD = 20               # >= 20 SYN packets -> suspicious
TOP_TALKERS_COUNT = 5                  # show top 5 source IPs
TOP_CATEGORY_DISPLAY_COUNT = 3         # show top 3 IPs in each traffic category
DEFAULT_PACKET_LIMIT = 200
DEFAULT_TIMEOUT = 30
DEFAULT_LOG_PATH = "logs/alerts.log"


# -----------------------
# LOGGING
# -----------------------

def log_alert(message: str, log_path: str = DEFAULT_LOG_PATH):
    """Write alerts to logs/alerts.log with timestamp."""
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{timestamp} {message}\n")

    except Exception as e:
        print(f"[!] ERROR writing to log file: {e}")


# -----------------------
# DETECTION RULES
# -----------------------

def detect_port_scan(src_to_ports: dict):
    """
    Rule A: Port scan detection
    Detects source IPs contacting many unique destination ports.
    """
    print("\n[+] Port Scan Check (unique destination ports per source):")
    detected = False

    for src_ip, port_set in src_to_ports.items():
        unique_ports = len(port_set)

        if unique_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
            detected = True
            sorted_ports = sorted(port_set)

            alert_msg = (
                f"ALERT PORT_SCAN "
                f"Source={src_ip} "
                f"UniquePorts={unique_ports} "
                f"Ports={sorted_ports} "
                f"Threshold={PORTSCAN_UNIQUE_PORTS_THRESHOLD} "
                f"Detection=Possible_Port_Scan"
            )

            print("[!]", alert_msg)
            log_alert(alert_msg)

    if not detected:
        print("[+] No port scan behavior detected.")


def detect_syn_activity(src_syn_counts: dict):
    """
    Rule B: SYN activity detection
    Detects unusually high TCP SYN packet counts per source IP.
    """
    print("\n[+] SYN Activity Check (SYN packets per source):")
    detected = False

    for src_ip, syn_count in src_syn_counts.items():
        if syn_count >= SYN_COUNT_THRESHOLD:
            detected = True

            alert_msg = (
                f"ALERT SYN_ACTIVITY "
                f"Source={src_ip} "
                f"SYNs={syn_count} "
                f"Threshold={SYN_COUNT_THRESHOLD} "
                f"Detection=Possible_SYN_Scan_or_Flood"
            )

            print("[!]", alert_msg)
            log_alert(alert_msg)

    if not detected:
        print("[+] No suspicious SYN activity detected.")


# -----------------------
# NUMPY TRAFFIC ANALYSIS
# -----------------------

def categorize_traffic_numpy(src_counts: dict):
    """
    Categorize source IPs into Low / Medium / High traffic using NumPy percentiles.
    Returns: (low_list, medium_list, high_list, p50, p90)
    """
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


def print_traffic_categories(src_counts: dict):
    """Display NumPy-based traffic categories."""
    low, medium, high, p50, p90 = categorize_traffic_numpy(src_counts)

    print("\n[+] Traffic Categories:")
    print(f"    Low <= {p50}")
    print(f"    Medium <= {p90}")
    print(f"    High > {p90}")

    print(f"\n    Top Low Traffic (max {TOP_CATEGORY_DISPLAY_COUNT}):")
    for ip, count in low[:TOP_CATEGORY_DISPLAY_COUNT]:
        print(f"      {ip} -> {count}")

    print(f"\n    Top Medium Traffic (max {TOP_CATEGORY_DISPLAY_COUNT}):")
    for ip, count in medium[:TOP_CATEGORY_DISPLAY_COUNT]:
        print(f"      {ip} -> {count}")

    print(f"\n    Top High Traffic (max {TOP_CATEGORY_DISPLAY_COUNT}):")
    for ip, count in high[:TOP_CATEGORY_DISPLAY_COUNT]:
        print(f"      {ip} -> {count}")


# -----------------------
# SHARED PACKET ANALYSIS
# -----------------------

def analyze_packets(packets):
    """
    Analyze packets and build traffic statistics used by both offline and live modes.
    Returns:
        src_counts, src_to_ports, src_syn_counts
    """
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

                # Count SYN packets without ACK
                if (flags & SYN) and not (flags & ACK):
                    src_syn_counts[src_ip] += 1

    return src_counts, src_to_ports, src_syn_counts


def print_top_talkers(src_counts: dict):
    """Print top source IPs by packet count."""
    print(f"\n[+] Top {TOP_TALKERS_COUNT} source IPs:")

    top_talkers = sorted(
        src_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:TOP_TALKERS_COUNT]

    for ip, count in top_talkers:
        print(f"    {ip} -> {count} packets")


# -----------------------
# OFFLINE MODE
# -----------------------

def run_offline_mode(pcap_file: str):
    """Analyze packets from a saved PCAP/PCAPNG file."""
    if not os.path.exists(pcap_file):
        print(f"[!] ERROR: File not found: {pcap_file}")
        return

    print(f"[+] Running IDS in OFFLINE mode on {pcap_file}")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] ERROR reading PCAP file: {e}")
        return

    print(f"[+] Loaded {len(packets)} packets")

    src_counts, src_to_ports, src_syn_counts = analyze_packets(packets)

    print_top_talkers(src_counts)
    print_traffic_categories(src_counts)

    detect_port_scan(src_to_ports)
    detect_syn_activity(src_syn_counts)

    print(f"\n[+] Alerts saved to {DEFAULT_LOG_PATH}")


# -----------------------
# LIVE MODE
# -----------------------

def run_live_mode(interface=None, packet_limit=DEFAULT_PACKET_LIMIT, timeout=DEFAULT_TIMEOUT):
    """Capture and analyze live network traffic."""

    # If the user passes an interface index like 3, resolve it to the
    # actual interface object Scapy can use on Windows.
    if isinstance(interface, int):
        try:
            interface = IFACES.dev_from_index(interface)
        except Exception as e:
            print(f"[!] ERROR resolving interface index: {e}")
            return

    print("[+] Running IDS in LIVE mode")
    print(f"    Interface: {interface if interface else 'default'}")
    print(f"    Packet limit: {packet_limit}")
    print(f"    Timeout: {timeout} seconds")

    try:
        packets = sniff(iface=interface, count=packet_limit, timeout=timeout)
    except Exception as e:
        print(f"[!] ERROR capturing live traffic: {e}")
        return

    print(f"[+] Captured {len(packets)} packets")

    src_counts, src_to_ports, src_syn_counts = analyze_packets(packets)

    print_top_talkers(src_counts)
    print_traffic_categories(src_counts)

    detect_port_scan(src_to_ports)
    detect_syn_activity(src_syn_counts)

    print(f"\n[+] Alerts saved to {DEFAULT_LOG_PATH}")


# -----------------------
# MAIN PROGRAM
# -----------------------

def main():
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Offline mode:")
        print("    py scripts/ids_basic.py offline captures/file.pcap")
        print("    py scripts/ids_basic.py offline captures/file.pcapng")
        print("\n  Live mode:")
        print("    py scripts/ids_basic.py live")
        print("    py scripts/ids_basic.py live <interface>")
        print("    py scripts/ids_basic.py live <interface> <packet_limit> <timeout>")
        print("    py scripts/ids_basic.py live 3 500 60")
        return

    mode = sys.argv[1].lower()

    if mode == "offline":
        if len(sys.argv) < 3:
            print("[!] ERROR: Please provide a PCAP file.")
            return

        pcap_file = sys.argv[2]
        run_offline_mode(pcap_file)

    elif mode == "live":
        interface = (
            int(sys.argv[2])
            if len(sys.argv) >= 3 and sys.argv[2].isdigit()
            else (sys.argv[2] if len(sys.argv) >= 3 else None)
        )

        try:
            packet_limit = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_PACKET_LIMIT
            timeout = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_TIMEOUT
        except ValueError:
            print("[!] ERROR: packet_limit and timeout must be integers.")
            return

        run_live_mode(interface, packet_limit, timeout)

    else:
        print("[!] Unknown mode. Use 'offline' or 'live'.")


if __name__ == "__main__":
    main()