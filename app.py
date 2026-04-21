import os
import io
import csv
from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from werkzeug.utils import secure_filename

from scripts.ids_basic import analyze_pcap_for_dashboard

app = Flask(__name__)
app.secret_key = "ids-dashboard-secret"

UPLOAD_FOLDER = "uploads"
LOG_FILE = "logs/alerts.log"
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs("logs", exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def read_recent_alerts():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()[-20:]

    lines.reverse()
    return lines


def build_txt_report(result):
    lines = []
    lines.append("INTRUSION DETECTION SYSTEM REPORT")
    lines.append("=" * 40)
    lines.append(f"PCAP File: {result.get('pcap_file', 'N/A')}")
    lines.append(f"Total Packets: {result.get('total_packets', 0)}")
    lines.append(f"Unique Source IPs: {result.get('unique_source_ips', 0)}")
    lines.append(f"Total Alerts: {result['alert_summary'].get('total', 0)}")
    lines.append(f"Highest Severity: {result['alert_summary'].get('highest_severity', 'NONE')}")
    lines.append("")

    lines.append("ALERT SUMMARY")
    lines.append("-" * 40)
    lines.append(f"PORT_SCAN: {result['alert_summary'].get('port_scan_count', 0)}")
    lines.append(f"SYN_ACTIVITY: {result['alert_summary'].get('syn_count', 0)}")
    lines.append(f"HIGH_TRAFFIC: {result['alert_summary'].get('high_traffic_count', 0)}")
    lines.append(f"ICMP_FLOOD: {result['alert_summary'].get('icmp_count', 0)}")
    lines.append("")

    lines.append("TRAFFIC CATEGORIES")
    lines.append("-" * 40)
    lines.append(f"Low Traffic IPs: {result['traffic_categories'].get('low_count', 0)}")
    lines.append(f"Medium Traffic IPs: {result['traffic_categories'].get('medium_count', 0)}")
    lines.append(f"High Traffic IPs: {result['traffic_categories'].get('high_count', 0)}")
    lines.append(f"p50 Threshold: {result['traffic_categories'].get('p50', 0)}")
    lines.append(f"p90 Threshold: {result['traffic_categories'].get('p90', 0)}")
    lines.append("")

    lines.append("DETECTED ALERTS")
    lines.append("-" * 40)
    if result.get("alerts"):
        for i, alert in enumerate(result["alerts"], start=1):
            lines.append(f"{i}. Type: {alert.get('type', 'N/A')}")
            lines.append(f"   Severity: {alert.get('severity', 'N/A')}")
            lines.append(f"   Source: {alert.get('source', 'N/A')}")
            lines.append(f"   Details: {alert.get('details', 'N/A')}")
            lines.append("")
    else:
        lines.append("No suspicious activity detected.")
        lines.append("")

    lines.append("TOP SOURCE IPS")
    lines.append("-" * 40)
    if result.get("top_talkers"):
        for ip, count in result["top_talkers"]:
            lines.append(f"{ip} -> {count} packets")
    else:
        lines.append("No source IP activity found.")

    lines.append("")
    return "\n".join(lines)


def build_csv_report(result):
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["PCAP File", result.get("pcap_file", "N/A")])
    writer.writerow(["Total Packets", result.get("total_packets", 0)])
    writer.writerow(["Unique Source IPs", result.get("unique_source_ips", 0)])
    writer.writerow(["Total Alerts", result["alert_summary"].get("total", 0)])
    writer.writerow(["Highest Severity", result["alert_summary"].get("highest_severity", "NONE")])
    writer.writerow([])

    writer.writerow(["Alert Summary"])
    writer.writerow(["PORT_SCAN", result["alert_summary"].get("port_scan_count", 0)])
    writer.writerow(["SYN_ACTIVITY", result["alert_summary"].get("syn_count", 0)])
    writer.writerow(["HIGH_TRAFFIC", result["alert_summary"].get("high_traffic_count", 0)])
    writer.writerow(["ICMP_FLOOD", result["alert_summary"].get("icmp_count", 0)])
    writer.writerow([])

    writer.writerow(["Detected Alerts"])
    writer.writerow(["Type", "Severity", "Source IP", "Details"])

    if result.get("alerts"):
        for alert in result["alerts"]:
            writer.writerow([
                alert.get("type", "N/A"),
                alert.get("severity", "N/A"),
                alert.get("source", "N/A"),
                alert.get("details", "N/A")
            ])
    else:
        writer.writerow(["NO_ALERTS", "NONE", "N/A", "No suspicious activity detected"])

    writer.writerow([])
    writer.writerow(["Top Source IPs"])
    writer.writerow(["Source IP", "Packets"])

    if result.get("top_talkers"):
        for ip, count in result["top_talkers"]:
            writer.writerow([ip, count])
    else:
        writer.writerow(["N/A", 0])

    return output.getvalue()


@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        if "pcap_file" not in request.files:
            flash("No file selected.")
            return redirect(url_for("index"))

        file = request.files["pcap_file"]

        if file.filename == "":
            flash("Please choose a PCAP file.")
            return redirect(url_for("index"))

        if not allowed_file(file.filename):
            flash("Only .pcap and .pcapng files are allowed.")
            return redirect(url_for("index"))

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(filepath)

        result = analyze_pcap_for_dashboard(filepath)

        if "error" in result:
            flash(result["error"])
            result = None
        else:
            flash(f"Analysis completed for {filename}")
            session["last_result"] = result
            session["last_filename"] = filename

    alerts_log = read_recent_alerts()
    return render_template("index.html", result=result, alerts_log=alerts_log)


@app.route("/download-report")
def download_report():
    result = session.get("last_result")

    if not result:
        flash("No analysis result available yet. Please upload and analyze a PCAP first.")
        return redirect(url_for("index"))

    report_text = build_txt_report(result)
    filename = session.get("last_filename", "ids_report")
    report_filename = f"{os.path.splitext(filename)[0]}_report.txt"

    return Response(
        report_text,
        mimetype="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename={report_filename}"
        }
    )


@app.route("/download-csv")
def download_csv():
    result = session.get("last_result")

    if not result:
        flash("No analysis result available yet. Please upload and analyze a PCAP first.")
        return redirect(url_for("index"))

    csv_text = build_csv_report(result)
    filename = session.get("last_filename", "ids_report")
    csv_filename = f"{os.path.splitext(filename)[0]}_report.csv"

    return Response(
        csv_text,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename={csv_filename}"
        }
    )


if __name__ == "__main__":
    app.run(debug=True)