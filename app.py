import os, socket, datetime
from urllib.parse import urlparse
from flask import Flask, request, render_template, jsonify

from analyzer.ssl_checker import check_ssl
from analyzer.dns_checker import check_dns
from analyzer.whois_checker import check_whois
from analyzer.blacklist_checker import check_blacklist
from analyzer.reputation_checker import check_ip_reputation

app = Flask(__name__)

def extract_domain(url):
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None
    return hostname

def score_report(data):
    score = 0
    max_score = 100

    # HTTPS (max 10)
    if data["ssl"]["valid"]:
        score += 10
    elif data["ssl"].get("error"):
        score += 0

    # SSL valid + not expired (max 10)
    if data["ssl"]["valid"] and not data["ssl"].get("expired", True):
        score += 10

    # DNS resolves (max 10)
    if data["dns"]["success"]:
        score += 10

    # Domain age (max 25)
    age = data.get("whois", {}).get("age_days", 0)
    if age > 365:
        score += 25
    elif age > 180:
        score += 20
    elif age > 30:
        score += 10
    elif age > 7:
        score += 5

    # Blacklist (max 30)
    if data["blacklist"]["threats_found"] == 0:
        score += 30
    else:
        score += max(0, 30 - data["blacklist"]["threats_found"] * 15)

    # IP reputation (max 15)
    if data["reputation"].get("available"):
        if not data["reputation"].get("flags"):
            score += 15
        else:
            score += 5

    score = min(score, max_score)

    if score >= 80:
        verdict = "Trusted"
        level = "low"
    elif score >= 50:
        verdict = "Suspicious"
        level = "medium"
    else:
        verdict = "High Risk"
        level = "high"

    return {"score": score, "max": max_score, "verdict": verdict, "level": level}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "No URL provided"}), 400

    raw_url = data["url"].strip()
    domain = extract_domain(raw_url)
    if not domain:
        return jsonify({"error": "Invalid URL. Please enter a full URL (e.g. https://example.com)"}), 400

    result = {
        "url": raw_url,
        "domain": domain,
        "ssl": check_ssl(domain),
        "dns": check_dns(domain),
        "whois": check_whois(domain),
        "blacklist": check_blacklist(domain),
        "reputation": check_ip_reputation(domain),
    }

    result["report"] = score_report(result)
    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
