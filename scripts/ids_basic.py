"""
ids_basic.py
Dual-mode IDS: PCAP analysis + live sniffing
Author: Pushpaharan
"""

import sys
import os
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, sniff


ALERT_THRESHOLD = 20000  # change this number if you want stricter/looser alerts


def ensure_logs_dir():
    """Make sure the logs/ folder exists so writing alerts won't fail."""
    os.makedirs("logs", exist_ok=True)


def log_alert(message: str):
    """Append an alert line to logs/alerts.log with a timestamp."""
    ensure_logs_dir()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open("logs/alerts.log", "a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")


def run_offline_mode(pcap_file: str):
    print(f"[+] Running IDS in OFFLINE mode on {pcap_file}")

    if not os.path.exists(pcap_file):
        print(f"[!] File not found: {pcap_file}")
        print("[!] Example: py -3.14 scripts/ids_basic.py offline .\\captures\\sample_traffic.pcap")
        return

    packets = rdpcap(pcap_file)
    print(f"[+] Loaded {len(packets)} packets from {pcap_file}")

    src_counts = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            src_counts[src_ip] += 1

    print("[+] Top 5 source IPs by packet count:")
    top5 = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    for ip, count in top5:
        print(f"    {ip} -> {count} packets")

        # ✅ ALERT RULE GOES HERE (inside the loop)
        if count > ALERT_THRESHOLD:
            alert_msg = f"ALERT HighTraffic Source={ip} Packets={count} File={pcap_file}"
            print("[!]", alert_msg)
            log_alert(alert_msg)


def run_live_mode(interface: str | None = None):
    """
    Live sniffing (basic skeleton).
    NOTE: On Windows, live sniffing may require running VS Code/Terminal as Administrator,
    and Npcap must be installed.
    """
    print("[+] Running IDS in LIVE mode")
    print("[i] Press Ctrl+C to stop.\n")

    src_counts = defaultdict(int)

    def handle_packet(pkt):
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            src_counts[src_ip] += 1
            count = src_counts[src_ip]

            # Simple example alert
            if count % 5000 == 0:  # prints every 5000 packets per IP
                msg = f"INFO LiveCount Source={src_ip} Packets={count}"
                print("[*]", msg)

            if count > ALERT_THRESHOLD:
                alert_msg = f"ALERT HighTraffic (LIVE) Source={src_ip} Packets={count}"
                print("[!]", alert_msg)
                log_alert(alert_msg)

    sniff(iface=interface, prn=handle_packet, store=False)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  py -3.14 scripts/ids_basic.py offline <pcap_file>")
        print("  py -3.14 scripts/ids_basic.py live [interface]")
        return

    mode = sys.argv[1].lower()

    if mode == "offline":
        if len(sys.argv) < 3:
            print("[!] Missing pcap file.")
            print("Example:")
            print("  py -3.14 scripts/ids_basic.py offline .\\captures\\sample_traffic.pcap")
            return
        pcap_file = sys.argv[2]
        run_offline_mode(pcap_file)

    elif mode == "live":
        # optional interface argument
        interface = sys.argv[2] if len(sys.argv) >= 3 else None
        run_live_mode(interface)

    else:
        print("Unknown mode. Use 'offline' or 'live'.")


if __name__ == "__main__":
    main()
