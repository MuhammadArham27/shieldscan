"""
ShieldScan — Flask Backend
Provides: Auth, URL scanning, and Groq AI chatbot proxy
"""

import os
import re
import time
import hashlib
import ipaddress
from urllib.parse import urlparse
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from groq import Groq

# ─── App setup ────────────────────────────────────────────────────────────────

app = Flask(__name__, static_folder=".", static_url_path="")

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None

SYSTEM_PROMPT = """You are ShieldBot, an AI security assistant embedded in ShieldScan — a URL threat analysis platform.

You specialize in:
- URL and domain safety analysis
- Phishing, malware, and social engineering threats
- Cybersecurity best practices
- Explaining scan results and security scores

Be concise, technically precise, and use practical examples.
Format responses with clear structure using short paragraphs.
If a user pastes a URL, analyze it for red flags and explain your reasoning.
Always recommend caution and safe browsing habits."""

_users: dict[str, dict] = {}
_sessions: dict[str, str] = {}
_scan_history: dict[str, list] = {}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_token(email: str) -> str:
    raw = f"{email}{time.time()}{os.urandom(16).hex()}"
    return hashlib.sha256(raw.encode()).hexdigest()

def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if token not in _sessions:
            return jsonify({"error": "Unauthorized"}), 401
        request.user_email = _sessions[token]
        return f(*args, **kwargs)
    return decorated

# ─── URL Scanner ───────────────────────────────────────────────────────────────

RISKY_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club",
    ".work", ".link", ".click", ".download", ".zip", ".review",
    ".country", ".kim", ".science", ".stream", ".racing",
}

PHISHING_KEYWORDS = {
    "verify", "update", "secure", "login", "signin", "account",
    "banking", "paypal", "amazon", "apple", "google", "microsoft",
    "netflix", "support", "confirm", "password", "credential",
    "wallet", "urgent", "suspended", "limited", "validate",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "rb.gy", "short.io", "cutt.ly",
}

SUSPICIOUS_PATH_WORDS = {
    "wp-admin", "phishing", "malware", "login", "update",
    "verify", "suspend", "confirm", "account", "secure",
}


def analyze_url(raw_url: str) -> dict:
    checks = []
    risk_score = 0

    url = raw_url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return {"error": "Invalid URL"}

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    # 1. HTTPS
    is_https = parsed.scheme == "https"
    checks.append({"name": "HTTPS Protocol", "icon": "🔒", "pass": is_https,
        "detail": "Uses secure HTTPS" if is_https else "Unencrypted HTTP — data can be intercepted",
        "severity": "medium"})
    if not is_https: risk_score += 15

    # 2. IP address
    is_ip = False
    try:
        ipaddress.ip_address(hostname); is_ip = True
    except ValueError:
        pass
    checks.append({"name": "IP Address Check", "icon": "🔢", "pass": not is_ip,
        "detail": "Uses a proper domain name" if not is_ip else f"Raw IP address ({hostname}) — avoids DNS traceability",
        "severity": "high"})
    if is_ip: risk_score += 25

    # 3. Risky TLD
    tld = "." + hostname.rsplit(".", 1)[-1] if "." in hostname else ""
    bad_tld = tld.lower() in RISKY_TLDS
    checks.append({"name": "TLD Reputation", "icon": "🌐", "pass": not bad_tld,
        "detail": f"TLD '{tld}' is commonly used in attacks" if bad_tld else f"TLD '{tld}' appears reputable",
        "severity": "medium"})
    if bad_tld: risk_score += 20

    # 4. Phishing keywords
    domain_lower = hostname.lower()
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in domain_lower]
    checks.append({"name": "Phishing Keywords", "icon": "🎣", "pass": len(found_kw) == 0,
        "detail": f"Suspicious keywords found: {', '.join(found_kw)}" if found_kw else "No phishing keywords detected in domain",
        "severity": "high"})
    if found_kw: risk_score += min(10 * len(found_kw), 30)

    # 5. URL shortener
    apex = ".".join(hostname.split(".")[-2:]) if hostname.count(".") >= 1 else hostname
    is_short = apex in SHORTENER_DOMAINS
    checks.append({"name": "URL Shortener", "icon": "✂️", "pass": not is_short,
        "detail": f"Short URL service ({apex}) — destination is hidden" if is_short else "Not a URL shortener",
        "severity": "medium"})
    if is_short: risk_score += 15

    # 6. Subdomain depth
    parts = hostname.split(".")
    subdomain_count = max(0, len(parts) - 2)
    deep = subdomain_count > 2
    checks.append({"name": "Subdomain Depth", "icon": "🧩", "pass": not deep,
        "detail": f"{subdomain_count} subdomain levels — unusually deep" if deep else f"{subdomain_count} subdomain levels — normal",
        "severity": "medium"})
    if deep: risk_score += 10 * (subdomain_count - 2)

    # 7. Punycode
    has_puny = "xn--" in hostname.lower()
    checks.append({"name": "Punycode / Homograph", "icon": "🎭", "pass": not has_puny,
        "detail": "Punycode encoding detected — possible lookalike domain" if has_puny else "No punycode encoding found",
        "severity": "high"})
    if has_puny: risk_score += 30

    # 8. URL length
    url_len = len(url)
    too_long = url_len > 100
    checks.append({"name": "URL Length", "icon": "📏", "pass": not too_long,
        "detail": f"URL length {url_len} chars — abnormally long" if too_long else f"URL length {url_len} chars — acceptable",
        "severity": "low"})
    if too_long: risk_score += min((url_len - 100) // 20 * 5, 15)

    # 9. Special chars
    has_special = bool(re.search(r"[^a-zA-Z0-9.\-]", hostname))
    checks.append({"name": "Special Characters", "icon": "⚠️", "pass": not has_special,
        "detail": "Unusual characters found in domain" if has_special else "Domain uses standard characters only",
        "severity": "medium"})
    if has_special: risk_score += 20

    # 10. Path keywords
    path_lower = path.lower()
    path_hits = [w for w in SUSPICIOUS_PATH_WORDS if w in path_lower]
    checks.append({"name": "Path Keywords", "icon": "📁", "pass": len(path_hits) == 0,
        "detail": f"Suspicious path words: {', '.join(path_hits)}" if path_hits else "Path looks clean",
        "severity": "low"})
    if path_hits: risk_score += min(10 * len(path_hits), 20)

    score = max(0, 100 - risk_score)
    if score >= 75:
        verdict, verdict_label, verdict_msg = "safe", "Safe", "No significant threats detected."
    elif score >= 45:
        verdict, verdict_label, verdict_msg = "warning", "Suspicious", "Proceed with caution — several risk signals found."
    else:
        verdict, verdict_label, verdict_msg = "danger", "Dangerous", "High risk — do not visit this URL."

    return {
        "url": raw_url, "normalized_url": url, "score": score,
        "verdict": verdict, "verdict_label": verdict_label,
        "verdict_msg": verdict_msg, "checks": checks,
        "timestamp": int(time.time()),
    }


# ─── Auth routes ───────────────────────────────────────────────────────────────

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data  = request.get_json() or {}
    name  = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    pw    = data.get("password") or ""

    if not name or not email or not pw:
        return jsonify({"error": "All fields are required"}), 400
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return jsonify({"error": "Invalid email address"}), 400
    if len(pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if email in _users:
        return jsonify({"error": "An account with that email already exists"}), 409

    _users[email] = {"name": name, "email": email, "pw_hash": _hash_pw(pw)}
    _scan_history[email] = []
    token = _make_token(email)
    _sessions[token] = email
    return jsonify({"token": token, "name": name, "email": email}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data  = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    pw    = data.get("password") or ""

    user = _users.get(email)
    if not user or user["pw_hash"] != _hash_pw(pw):
        return jsonify({"error": "Invalid email or password"}), 401

    token = _make_token(email)
    _sessions[token] = email
    return jsonify({"token": token, "name": user["name"], "email": email})


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    _sessions.pop(token, None)
    return jsonify({"ok": True})


# ─── Scan routes ───────────────────────────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
@require_auth
def scan():
    data = request.get_json() or {}
    url  = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    result = analyze_url(url)
    if "error" in result:
        return jsonify(result), 400

    email = request.user_email
    _scan_history.setdefault(email, []).insert(0, result)
    _scan_history[email] = _scan_history[email][:50]
    return jsonify(result)


@app.route("/api/scan/history", methods=["GET"])
@require_auth
def scan_history():
    email = request.user_email
    return jsonify(_scan_history.get(email, []))


# ─── Chatbot route (Groq — free & fast) ───────────────────────────────────────

@app.route("/api/chat", methods=["POST"])
@require_auth
def chat():
    if not groq_client:
        return jsonify({
            "error": "Groq API key not configured. Set GROQ_API_KEY environment variable."
        }), 503

    data     = request.get_json() or {}
    messages = data.get("messages", [])

    if not messages:
        return jsonify({"error": "No messages provided"}), 400

    for m in messages:
        if m.get("role") not in ("user", "assistant"):
            return jsonify({"error": f"Invalid role: {m.get('role')}"}), 400

    try:
        response = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": SYSTEM_PROMPT}] + messages,
            max_tokens=1024,
            temperature=0.7,
        )
        reply = response.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "invalid_api_key" in error_msg.lower():
            return jsonify({"error": "Invalid Groq API key"}), 401
        if "429" in error_msg or "rate" in error_msg.lower():
            return jsonify({"error": "Rate limit reached. Please wait a moment."}), 429
        return jsonify({"error": f"API error: {error_msg}"}), 500


# ─── Static pages ──────────────────────────────────────────────────────────────

@app.route("/")
def root():
    return send_from_directory(".", "index.html")

@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)


if __name__ == "__main__":
    app.run()