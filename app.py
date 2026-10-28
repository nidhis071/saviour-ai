from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import re
from urllib.parse import urlparse
from datetime import datetime, timezone

app = Flask(__name__)
CORS(app)  # For local development. Restrict origins before production.

DB_PATH = "saviour_ai.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                reasons TEXT NOT NULL,
                scanned_at TEXT NOT NULL
            )
        """)


def analyze_url(raw_url):
    """Basic heuristic analysis only; not a live reputation or malware check."""
    url = raw_url.strip()
    if not url:
        raise ValueError("Please enter a URL.")

    # Accept URLs with or without a scheme, then normalize.
    candidate = url if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) else "https://" + url
    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported.")
    if not parsed.hostname:
        raise ValueError("Please enter a valid URL, such as https://example.com.")

    host = parsed.hostname.lower()
    full_lower = candidate.lower()
    score = 0
    reasons = []

    # These signals are heuristics, not proof of malicious activity.
    if parsed.scheme.lower() == "http":
        score += 10
        reasons.append("Uses HTTP instead of HTTPS")

    if "@" in parsed.netloc:
        score += 20
        reasons.append("Contains an @ symbol in the URL authority")

    if host.startswith("xn--") or ".xn--" in host:
        score += 15
        reasons.append("Contains an internationalized/punycode domain")

    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        score += 20
        reasons.append("Uses an IP address instead of a typical domain name")

    if len(candidate) > 120:
        score += 10
        reasons.append("Unusually long URL")

    if len(host.split(".")) >= 5:
        score += 10
        reasons.append("Contains many subdomains")

    suspicious_words = (
        "login", "verify", "update", "secure", "account", "password",
        "wallet", "banking", "signin", "free-gift", "gift", "confirm"
    )
    matched_words = [word for word in suspicious_words if word in full_lower]
    if matched_words:
        score += min(25, 5 * len(matched_words))
        reasons.append("Contains potentially sensitive or lure-related keywords: " + ", ".join(matched_words))

    if host.count("-") >= 3:
        score += 10
        reasons.append("Domain contains several hyphens")

    if parsed.port and parsed.port not in (80, 443):
        score += 10
        reasons.append("Uses a non-standard port")

    score = min(score, 100)

    if score >= 50:
        risk_level = "High"
        verdict = "Suspicious"
    elif score >= 20:
        risk_level = "Medium"
        verdict = "Needs Caution"
    else:
        risk_level = "Low"
        verdict = "No obvious warning signs detected"

    if not reasons:
        reasons = ["No configured suspicious patterns were detected"]

    return {
        "normalized_url": candidate,
        "host": host,
        "risk_score": score,
        "risk_level": risk_level,
        "verdict": verdict,
        "reasons": reasons,
        "disclaimer": "Heuristic result only. This is not a live threat-intelligence check and does not guarantee that a URL is safe."
    }


def save_scan(result):
    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO scans (url, risk_score, risk_level, verdict, reasons, scanned_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            result["normalized_url"],
            result["risk_score"],
            result["risk_level"],
            result["verdict"],
            " | ".join(result["reasons"]),
            scanned_at
        ))
        scan_id = cursor.lastrowid
    result["id"] = scan_id
    result["scanned_at"] = scanned_at
    return result


@app.get("/")
def home():
    return jsonify({
        "name": "Saviour AI URL Intelligence API",
        "status": "running",
        "endpoints": ["/api/health", "/api/scan", "/api/history", "/api/stats"]
    })


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "message": "Saviour AI backend is running"})


@app.post("/api/scan")
def scan():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")
    try:
        result = analyze_url(raw_url)
        saved_result = save_scan(result)
        return jsonify({"success": True, "scan": saved_result}), 200
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        app.logger.exception("Unexpected error while scanning URL")
        return jsonify({"success": False, "error": "An internal server error occurred."}), 500


@app.get("/api/history")
def history():
    try:
        limit = request.args.get("limit", default=100, type=int)
        limit = max(1, min(limit or 100, 500))
        with get_db() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        scans = []
        for row in rows:
            scans.append({
                "id": row["id"],
                "url": row["url"],
                "risk_score": row["risk_score"],
                "risk_level": row["risk_level"],
                "verdict": row["verdict"],
                "reasons": row["reasons"].split(" | "),
                "scanned_at": row["scanned_at"]
            })
        return jsonify({"success": True, "count": len(scans), "scans": scans})
    except Exception:
        app.logger.exception("Could not load scan history")
        return jsonify({"success": False, "error": "Could not load scan history."}), 500


@app.get("/api/stats")
def stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'High'").fetchone()[0]
        medium = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Medium'").fetchone()[0]
        low = conn.execute("SELECT COUNT(*) FROM scans WHERE risk_level = 'Low'").fetchone()[0]
    return jsonify({
        "success": True,
        "total_scans": total,
        "high_risk_scans": high,
        "medium_risk_scans": medium,
        "low_risk_scans": low,
        "threats_flagged": high + medium
    })


@app.delete("/api/history")
def clear_history():
    # Clear only scan history in this app's local SQLite database.
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
        # Reset the displayed sequence for a clean demo, where supported.
        conn.execute("DELETE FROM sqlite_sequence WHERE name = 'scans'")
    return jsonify({"success": True, "message": "Scan history cleared."})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
