from pathlib import Path
import sys
import tempfile
from flask import Flask, render_template, request, jsonify, send_file
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.analyzer import analyze_file
from reports.report_generator import save_html

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/analyze")
def analyze():
    uploaded = request.files.get("email")
    if not uploaded or not uploaded.filename.lower().endswith(".eml"):
        return jsonify({"error": "Please upload a .eml file."}), 400
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as tmp:
        uploaded.save(tmp.name)
        result = analyze_file(tmp.name)
    return jsonify(result)

@app.post("/analyze-raw")
def analyze_raw():
    raw = request.get_data(as_text=True)
    if not raw.strip():
        return jsonify({"error": "No raw email supplied."}), 400
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write(raw)
        result = analyze_file(tmp.name)
    return jsonify(result)

@app.post("/report-raw")
def report_raw():
    raw = request.get_data(as_text=True)
    if not raw.strip():
        return jsonify({"error": "No raw email supplied."}), 400
    with tempfile.NamedTemporaryFile(suffix=".eml", mode="w", encoding="utf-8", delete=False) as tmp:
        tmp.write(raw)
        result = analyze_file(tmp.name)
    out = tempfile.NamedTemporaryFile(suffix=".html", delete=False)
    out.close()
    save_html(result, out.name)
    return send_file(out.name, as_attachment=True, download_name="phishing_analysis_report.html")

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
