"""
ids_basic.py
Dual-mode IDS: PCAP analysis + live sniffing
Author: Pushpaharan
"""

import sys
from scapy.all import rdpcap
from collections import defaultdict


def run_offline_mode(pcap_file):
    print(f"[+] Running IDS in OFFLINE mode on {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[+] Loaded {len(packets)} packets from {pcap_file}")


    src_counts = defaultdict(int)

    for pkt in packets:
        if pkt.haslayer("IP"):
            src_ip = pkt["IP"].src
            src_counts[src_ip] += 1

    print("[+] Top 5 source IPs by packet count:")
    for ip, count in sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
        print(f"    {ip} -> {count} packets")


def run_live_mode(interface=None):
    print("[+] Running IDS in LIVE mode")
    # TODO: sniff packets in real time

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ids_basic.py offline <pcap_file>")
        print("  python ids_basic.py live")
        return

    mode = sys.argv[1]

    if mode == "offline":
        pcap_file = sys.argv[2]
        run_offline_mode(pcap_file)
    elif mode == "live":
        run_live_mode()
    else:
        print("Unknown mode. Use 'offline' or 'live'.")

if __name__ == "__main__":
    main()
