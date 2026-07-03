"""
Flask web server for the Fake URL Detector.

Serves the static frontend (index.html) and exposes a JSON API that runs
the heuristic checks from detector.py.

Run with:
    python app.py
Then open:
    http://127.0.0.1:5000
"""

from flask import Flask, request, jsonify, send_from_directory
import os

from detector import scan_url

app = Flask(__name__, static_folder="static", static_url_path="")


@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "Please enter a URL to scan."}), 400
    if len(url) > 2048:
        return jsonify({"error": "That URL is too long to scan."}), 400

    result = scan_url(url)
    return jsonify(result.to_dict())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)
