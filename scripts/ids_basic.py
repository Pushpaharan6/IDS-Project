"""
ids_basic.py
Offline + Live Intrusion Detection System (IDS)
PCAP analysis + live packet sniffing with detection rules, logging,
NumPy traffic categorization, and SIEM-friendly JSON logging

Author: Pushpaharan
"""

import os
import sys
import json
from datetime import datetime
from collections import defaultdict

from scapy.all import rdpcap, sniff, wrpcap, IP, TCP, IFACES
import numpy as np



# SETTINGS / CONSTANTS


PORTSCAN_UNIQUE_PORTS_THRESHOLD = 1   # >= 1 unique port -> test alert generation
SYN_COUNT_THRESHOLD = 1               # >= 1 SYN packet -> test alert generation
TOP_TALKERS_COUNT = 5                 # show top 5 source IPs
TOP_CATEGORY_DISPLAY_COUNT = 3        # show top 3 IPs in each traffic category
DEFAULT_PACKET_LIMIT = 200
DEFAULT_TIMEOUT = 30
DEFAULT_LOG_PATH = "logs/alerts.log"
DEFAULT_JSON_LOG_PATH = "logs/alerts.jsonl"
DEFAULT_RESULTS_PATH = "logs/ids_results.txt"

# Set to None for easier Windows/VirtualBox live testing
LIVE_SNIFF_FILTER = None



# LOGGING


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_alert(message: str, log_path: str = DEFAULT_LOG_PATH):
    """Write message to text log with timestamp."""
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{current_timestamp()} {message}\n")
    except Exception as e:
        print(f"[!] ERROR writing to log file: {e}")


def log_alert_json(record: dict, log_path: str = DEFAULT_JSON_LOG_PATH):
    """Write structured alert/info data as one JSON object per line."""
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        payload = record.copy()
        payload["timestamp"] = current_timestamp()

        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")
    except Exception as e:
        print(f"[!] ERROR writing JSON alert log: {e}")


def log_info_event(event_type: str, details: dict):
    """Write non-alert informational events so logs are not empty."""
    text_parts = [f"INFO {event_type}"]
    for key, value in details.items():
        text_parts.append(f"{key}={value}")
    text_message = " ".join(text_parts)

    log_alert(text_message)
    log_alert_json({
        "record_type": "INFO",
        "event_type": event_type,
        **details
    })


def write_results_summary(lines, results_path: str = DEFAULT_RESULTS_PATH):
    """Write a plain text summary report for the latest run."""
    try:
        os.makedirs(os.path.dirname(results_path), exist_ok=True)
        with open(results_path, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
    except Exception as e:
        print(f"[!] ERROR writing results summary: {e}")



# INTERFACES


def list_interfaces():
    """Show interfaces that Scapy can capture from."""
    print("\n[+] Available capture interfaces:")
    for iface in IFACES.values():
        try:
            print(
                f"    Index={iface.index} "
                f"Name={iface.name} "
                f"Description={getattr(iface, 'description', 'N/A')}"
            )
        except Exception:
            print(f"    {iface}")


def resolve_interface(interface):
    """Convert an interface index to a Scapy interface object if needed."""
    if interface is None:
        return None

    if isinstance(interface, int):
        try:
            return IFACES.dev_from_index(interface)
        except Exception as e:
            raise RuntimeError(f"Could not resolve interface index {interface}: {e}") from e

    return interface



# DETECTION RULES


def detect_port_scan(src_to_ports: dict):
    """
    Rule A: Port scan detection
    Detects source IPs contacting many unique destination ports.
    Returns a list of alert dictionaries.
    """
    print("\n[+] Port Scan Check (unique destination ports per source):")
    alerts = []

    for src_ip, port_set in src_to_ports.items():
        unique_ports = len(port_set)

        if unique_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
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

            alert_record = {
                "record_type": "ALERT",
                "alert_type": "PORT_SCAN",
                "source_ip": src_ip,
                "unique_ports": unique_ports,
                "ports": sorted_ports,
                "threshold": PORTSCAN_UNIQUE_PORTS_THRESHOLD,
                "severity": "medium",
                "detection": "Possible_Port_Scan"
            }
            log_alert_json(alert_record)
            alerts.append(alert_record)

    if not alerts:
        print("[+] No port scan behavior detected.")

    return alerts


def detect_syn_activity(src_syn_counts: dict):
    """
    Rule B: SYN activity detection
    Detects unusually high TCP SYN packet counts per source IP.
    Returns a list of alert dictionaries.
    """
    print("\n[+] SYN Activity Check (SYN packets per source):")
    alerts = []

    for src_ip, syn_count in src_syn_counts.items():
        if syn_count >= SYN_COUNT_THRESHOLD:
            alert_msg = (
                f"ALERT SYN_ACTIVITY "
                f"Source={src_ip} "
                f"SYNs={syn_count} "
                f"Threshold={SYN_COUNT_THRESHOLD} "
                f"Detection=Possible_SYN_Scan_or_Flood"
            )

            print("[!]", alert_msg)
            log_alert(alert_msg)

            alert_record = {
                "record_type": "ALERT",
                "alert_type": "SYN_ACTIVITY",
                "source_ip": src_ip,
                "syn_count": syn_count,
                "threshold": SYN_COUNT_THRESHOLD,
                "severity": "medium",
                "detection": "Possible_SYN_Scan_or_Flood"
            }
            log_alert_json(alert_record)
            alerts.append(alert_record)

    if not alerts:
        print("[+] No suspicious SYN activity detected.")

    return alerts



# NUMPY TRAFFIC ANALYSIS


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
    """Display NumPy-based traffic categories and return summary info."""
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

    return {
        "low": low,
        "medium": medium,
        "high": high,
        "p50": p50,
        "p90": p90
    }



# SHARED PACKET ANALYSIS


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
        try:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                src_counts[src_ip] += 1

                if pkt.haslayer(TCP):
                    dport = int(pkt[TCP].dport)
                    src_to_ports[src_ip].add(dport)

                    flags = int(pkt[TCP].flags)
                    syn_flag = 0x02
                    ack_flag = 0x10

                    if (flags & syn_flag) and not (flags & ack_flag):
                        src_syn_counts[src_ip] += 1
        except Exception:
            continue

    return src_counts, src_to_ports, src_syn_counts


def print_top_talkers(src_counts: dict):
    """Print top source IPs by packet count and return top talkers list."""
    print(f"\n[+] Top {TOP_TALKERS_COUNT} source IPs:")

    top_talkers = sorted(
        src_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:TOP_TALKERS_COUNT]

    if not top_talkers:
        print("    No IP traffic found.")

    for ip, count in top_talkers:
        print(f"    {ip} -> {count} packets")

    return top_talkers


def summarize_run(mode_name: str, packet_count: int, src_counts: dict):
    """Write a general run summary to logs."""
    log_info_event(
        event_type=f"{mode_name}_RUN",
        details={
            "packet_count": packet_count,
            "unique_source_ips": len(src_counts)
        }
    )



# OFFLINE MODE


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

    if len(packets) == 0:
        print("[!] PCAP file loaded but contains 0 packets.")
        log_info_event("OFFLINE_EMPTY_FILE", {"pcap_file": pcap_file})
        return

    src_counts, src_to_ports, src_syn_counts = analyze_packets(packets)

    top_talkers = print_top_talkers(src_counts)
    traffic_summary = print_traffic_categories(src_counts)

    port_alerts = detect_port_scan(src_to_ports)
    syn_alerts = detect_syn_activity(src_syn_counts)
    all_alerts = port_alerts + syn_alerts

    summarize_run("OFFLINE", len(packets), src_counts)

    if not all_alerts:
        log_info_event(
            "OFFLINE_NO_ALERTS",
            {
                "pcap_file": pcap_file,
                "packet_count": len(packets),
                "unique_source_ips": len(src_counts)
            }
        )

    results_lines = [
        f"IDS OFFLINE RESULTS - {current_timestamp()}",
        f"PCAP File: {pcap_file}",
        f"Total Packets: {len(packets)}",
        f"Unique Source IPs: {len(src_counts)}",
        f"Top Talkers: {top_talkers}",
        f"Traffic Thresholds: p50={traffic_summary['p50']}, p90={traffic_summary['p90']}",
        f"Alert Count: {len(all_alerts)}"
    ]
    write_results_summary(results_lines)

    print(f"\n[+] Alerts saved to {DEFAULT_LOG_PATH}")
    print(f"[+] JSON alerts saved to {DEFAULT_JSON_LOG_PATH}")
    print(f"[+] Results summary saved to {DEFAULT_RESULTS_PATH}")



# LIVE MODE


def run_live_mode(interface=None, packet_limit=DEFAULT_PACKET_LIMIT, timeout=DEFAULT_TIMEOUT):
    """Capture and analyze live network traffic."""
    try:
        resolved_interface = resolve_interface(interface)
    except Exception as e:
        print(f"[!] ERROR resolving interface: {e}")
        return

    print("[+] Running IDS in LIVE mode")
    print(f"    Interface: {interface if interface else 'default'}")
    print(f"    Resolved interface: {resolved_interface}")
    print(f"    Packet limit: {packet_limit}")
    print(f"    Timeout: {timeout} seconds")
    print(f"    Filter: {LIVE_SNIFF_FILTER}")

    packets = []

    try:
        if LIVE_SNIFF_FILTER:
            packets = sniff(
                iface=resolved_interface,
                filter=LIVE_SNIFF_FILTER,
                count=packet_limit,
                timeout=timeout,
                store=True
            )
        else:
            packets = sniff(
                iface=resolved_interface,
                count=packet_limit,
                timeout=timeout,
                store=True
            )
    except Exception as e:
        print(f"[!] ERROR capturing live traffic: {e}")
        return

    print(f"[+] Captured {len(packets)} packets")

    if len(packets) > 0:
        os.makedirs("captures", exist_ok=True)
        wrpcap("captures/live_debug_capture.pcapng", packets)
        print("[+] Saved live debug capture to captures/live_debug_capture.pcapng")

    if len(packets) == 0:
        print("[!] No packets captured.")
        print("[!] Try a different interface or generate traffic during the timeout window.")
        print("[!] You can run: py scripts/ids_basic.py interfaces")
        log_info_event(
            "LIVE_NO_PACKETS",
            {
                "interface": str(resolved_interface),
                "packet_limit": packet_limit,
                "timeout": timeout
            }
        )
        return

    src_counts, src_to_ports, src_syn_counts = analyze_packets(packets)

    print(f"[+] Unique source IPs found: {len(src_counts)}")
    print(f"[+] TCP source entries found: {len(src_to_ports)}")
    print(f"[+] SYN source entries found: {len(src_syn_counts)}")

    top_talkers = print_top_talkers(src_counts)
    traffic_summary = print_traffic_categories(src_counts)

    port_alerts = detect_port_scan(src_to_ports)
    syn_alerts = detect_syn_activity(src_syn_counts)
    all_alerts = port_alerts + syn_alerts

    summarize_run("LIVE", len(packets), src_counts)

    if not all_alerts:
        log_info_event(
            "LIVE_NO_ALERTS",
            {
                "interface": str(resolved_interface),
                "packet_count": len(packets),
                "unique_source_ips": len(src_counts)
            }
        )

    results_lines = [
        f"IDS LIVE RESULTS - {current_timestamp()}",
        f"Interface: {resolved_interface}",
        f"Total Packets: {len(packets)}",
        f"Unique Source IPs: {len(src_counts)}",
        f"Top Talkers: {top_talkers}",
        f"Traffic Thresholds: p50={traffic_summary['p50']}, p90={traffic_summary['p90']}",
        f"Alert Count: {len(all_alerts)}"
    ]
    write_results_summary(results_lines)

    print(f"\n[+] Alerts saved to {DEFAULT_LOG_PATH}")
    print(f"[+] JSON alerts saved to {DEFAULT_JSON_LOG_PATH}")
    print(f"[+] Results summary saved to {DEFAULT_RESULTS_PATH}")



# DASHBOARD SUPPORT


def analyze_pcap_for_dashboard(pcap_file: str):
    """Return IDS results as a dictionary for Flask dashboard."""
    if not os.path.exists(pcap_file):
        return {"error": f"File not found: {pcap_file}"}

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        return {"error": f"Error reading PCAP file: {e}"}

    if len(packets) == 0:
        return {"error": "PCAP file contains 0 packets."}

    src_counts, src_to_ports, src_syn_counts = analyze_packets(packets)

    top_talkers = sorted(
        src_counts.items(),
        key=lambda x: x[1],
        reverse=True
    )[:TOP_TALKERS_COUNT]

    low, medium, high, p50, p90 = categorize_traffic_numpy(src_counts)

    alerts = []

    for src_ip, port_set in src_to_ports.items():
        unique_ports = len(port_set)

        if unique_ports >= PORTSCAN_UNIQUE_PORTS_THRESHOLD:
            sorted_ports = sorted(port_set)
            alert_data = {
                "type": "PORT_SCAN",
                "source": src_ip,
                "details": f"UniquePorts={unique_ports}, Ports={sorted_ports}"
            }
            alerts.append(alert_data)

    for src_ip, syn_count in src_syn_counts.items():
        if syn_count >= SYN_COUNT_THRESHOLD:
            alert_data = {
                "type": "SYN_ACTIVITY",
                "source": src_ip,
                "details": f"SYNs={syn_count}"
            }
            alerts.append(alert_data)

    return {
        "pcap_file": pcap_file,
        "total_packets": len(packets),
        "top_talkers": top_talkers,
        "traffic_categories": {
            "low_count": len(low),
            "medium_count": len(medium),
            "high_count": len(high),
            "p50": p50,
            "p90": p90
        },
        "alerts": alerts
    }



# MAIN PROGRAM


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
        print("\n  Interface list:")
        print("    py scripts/ids_basic.py interfaces")
        return

    mode = sys.argv[1].lower()

    if mode == "interfaces":
        list_interfaces()
        return

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
        print("[!] Unknown mode. Use 'offline', 'live', or 'interfaces'.")


if __name__ == "__main__":
    main()