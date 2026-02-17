import os
from datetime import datetime
from collections import defaultdict

from flask import Flask, request, redirect, url_for, render_template, flash
from scapy.all import rdpcap

# ----- Paths -----
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
UPLOAD_DIR = os.path.join(BASE_DIR, "dashboard", "uploads")
LOG_DIR = os.path.join(BASE_DIR, "logs")
ALERT_LOG = os.path.join(LOG_DIR, "alerts.log")

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ----- Settings -----
ALERT_THRESHOLD = 20000
TOP_N = 10

app = Flask(__name__)
app.secret_key = "change-this-string"


def log_alert(message: str):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{ts} {message}\n")


def read_recent_alerts(limit=50):
    if not os.path.exists(ALERT_LOG):
        return []
    with open(ALERT_LOG, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    return lines[-limit:]


def analyze_pcap(pcap_path: str):
    packets = rdpcap(pcap_path)

    src_counts = defaultdict(int)
    for pkt in packets:
        if pkt.haslayer("IP"):
            src_counts[pkt["IP"].src] += 1

    top = sorted(src_counts.items(), key=lambda x: x[1], reverse=True)[:TOP_N]

    alerts = []
    for ip, count in top:
        if count > ALERT_THRESHOLD:
            msg = f"ALERT HighTraffic Source={ip} Packets={count} File={os.path.basename(pcap_path)}"
            alerts.append(msg)
            log_alert(msg)

    # Prepare chart data
    labels = [ip for ip, _ in top]
    values = [count for _, count in top]

    return {
        "pcap_file": os.path.basename(pcap_path),
        "total_packets": len(packets),
        "top_talkers": top,
        "alerts": alerts,
        "chart_labels": labels,
        "chart_values": values,
    }


LAST_RESULT = None


@app.route("/", methods=["GET"])
def index():
    global LAST_RESULT
    recent = read_recent_alerts(limit=50)
    return render_template("index.html", result=LAST_RESULT, recent_alerts=recent)


@app.route("/upload", methods=["POST"])
def upload():
    global LAST_RESULT

    if "pcap" not in request.files:
        flash("No file uploaded.")
        return redirect(url_for("index"))

    f = request.files["pcap"]
    if not f.filename:
        flash("Empty filename.")
        return redirect(url_for("index"))

    # basic filename sanitization
    filename = f.filename.replace("..", "").replace("/", "").replace("\\", "")
    save_path = os.path.join(UPLOAD_DIR, filename)
    f.save(save_path)

    try:
        LAST_RESULT = analyze_pcap(save_path)
        flash(f"Analyzed: {filename}")
    except Exception as e:
        LAST_RESULT = None
        flash(f"Error analyzing PCAP: {e}")

    return redirect(url_for("index"))


if __name__ == "__main__":
    # Open: http://127.0.0.1:5000
    app.run(debug=True)

