import os
from flask import Flask, render_template, request, redirect, url_for, flash
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
        return f.readlines()[-20:]


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

    alerts_log = read_recent_alerts()
    return render_template("index.html", result=result, alerts_log=alerts_log)


if __name__ == "__main__":
    app.run(debug=True)
