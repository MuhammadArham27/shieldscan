from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import sqlite3
import joblib
import numpy as np
import re
import hashlib
import secrets
from urllib.parse import urlparse
from datetime import datetime
import os

app = FastAPI(title="PhishGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "phishing_detection.db"

# ─── Pydantic Models ──────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    url: str

class PredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float
    features: list
    is_phishing: bool

class SignupRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

# ─── Helpers ──────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = "phishguard_salt_2024"
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def generate_token() -> str:
    return secrets.token_hex(32)

# ─── Database Setup ───────────────────────────────────────────────────────────

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT NOT NULL UNIQUE,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            token         TEXT,
            created_at    TEXT NOT NULL,
            last_login    TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS predictions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            url         TEXT NOT NULL,
            prediction  TEXT NOT NULL,
            confidence  REAL,
            features    TEXT,
            user_id     INTEGER,
            created_at  TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS model_stats (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            model_name  TEXT NOT NULL,
            accuracy    REAL,
            auc_score   REAL,
            cv_score    REAL,
            trained_at  TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            details     TEXT,
            ip_address  TEXT,
            timestamp   TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def get_current_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized — no token provided")
    token = auth[7:]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE token = ?", (token,)).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized — invalid or expired token")
    return dict(user)

# ─── Feature Extraction ───────────────────────────────────────────────────────

def extract_features(url: str) -> list:
    parsed = urlparse(url)
    return [
        len(url),
        1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0,
        1 if "@" in url else 0,
        1 if "//" in url[7:] else 0,
        1 if "-" in parsed.netloc else 0,
        parsed.netloc.count('.'),
        1 if url.startswith("https") else 0,
        30,  # domain_age placeholder
        5,   # page_rank placeholder
        1 if "#" in url else 0,
        len(url),
        sum(c.isdigit() for c in url),
        1 if any(s in url for s in ["bit.ly", "tinyurl"]) else 0,
        1 if "iframe" in url.lower() else 0,
    ]

# ─── Startup ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
def startup():
    init_db()
    print("✅  Database initialised →", DB_PATH)

# ─── Auth Routes ─────────────────────────────────────────────────────────────

@app.post("/api/auth/signup")
def signup(body: SignupRequest, request: Request):
    username = body.username.strip()
    email    = body.email.strip().lower()
    password = body.password

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")

    pw_hash = hash_password(password)
    token   = generate_token()
    conn    = get_db()

    try:
        conn.execute(
            "INSERT INTO users (username, email, password_hash, token, created_at) VALUES (?,?,?,?,?)",
            (username, email, pw_hash, token, datetime.now().isoformat())
        )
        conn.execute(
            "INSERT INTO audit_log (action, details, ip_address, timestamp) VALUES (?,?,?,?)",
            ("SIGNUP", f"New user: {username}", request.client.host if request.client else "unknown", datetime.now().isoformat())
        )
        conn.commit()
        user = conn.execute("SELECT id, username, email, created_at FROM users WHERE username=?", (username,)).fetchone()
    except sqlite3.IntegrityError as e:
        if "username" in str(e):
            raise HTTPException(status_code=409, detail="Username already taken")
        raise HTTPException(status_code=409, detail="Email already registered")
    finally:
        conn.close()

    return {
        "success": True,
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"]}
    }

@app.post("/api/auth/login")
def login(body: LoginRequest, request: Request):
    username = body.username.strip()
    pw_hash  = hash_password(body.password)

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password_hash=?", (username, pw_hash)
    ).fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = generate_token()
    conn.execute(
        "UPDATE users SET token=?, last_login=? WHERE id=?",
        (token, datetime.now().isoformat(), user["id"])
    )
    conn.execute(
        "INSERT INTO audit_log (action, details, ip_address, timestamp) VALUES (?,?,?,?)",
        ("LOGIN", f"User logged in: {username}", request.client.host if request.client else "unknown", datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return {
        "success": True,
        "token": token,
        "user": {"id": user["id"], "username": user["username"], "email": user["email"]}
    }

@app.post("/api/auth/logout")
def logout(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    conn.execute("UPDATE users SET token=NULL WHERE id=?", (current_user["id"],))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/auth/me")
def me(current_user: dict = Depends(get_current_user)):
    return {
        "id": current_user["id"], "username": current_user["username"],
        "email": current_user["email"], "created_at": current_user["created_at"],
        "last_login": current_user["last_login"],
    }

# ─── App Routes ───────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index():
    try:
        with open("index.html", encoding="utf-8") as f:
            html = f.read()
        return HTMLResponse(content=html, media_type="text/html; charset=utf-8")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="index.html not found")

@app.post("/api/predict", response_model=PredictResponse)
def predict(body: PredictRequest, request: Request, current_user: dict = Depends(get_current_user)):
    url = body.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        model = joblib.load("phishing_model.pkl")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="Model not found. Please train the model first.")

    features     = extract_features(url)
    features_arr = np.array([features])
    pred         = model.predict(features_arr)[0]
    confidence   = float(max(model.predict_proba(features_arr)[0])) * 100
    label        = "Phishing" if pred == 1 else "Legit"
    client_ip    = request.client.host if request.client else "unknown"

    conn = get_db()
    conn.execute(
        "INSERT INTO predictions (url, prediction, confidence, features, user_id, created_at) VALUES (?,?,?,?,?,?)",
        (url, label, round(confidence, 2), str(features), current_user["id"], datetime.now().isoformat())
    )
    conn.execute(
        "INSERT INTO audit_log (action, details, ip_address, timestamp) VALUES (?,?,?,?)",
        ("PREDICTION", f"{label} – {url} [user:{current_user['username']}]", client_ip, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    return PredictResponse(
        url=url, prediction=label, confidence=round(confidence, 2),
        features=features, is_phishing=bool(pred == 1),
    )

@app.get("/api/history")
def history(limit: int = 20, current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM predictions WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
        (current_user["id"], limit)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/stats")
def stats(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    uid  = current_user["id"]
    total    = conn.execute("SELECT COUNT(*) FROM predictions WHERE user_id=?", (uid,)).fetchone()[0]
    phishing = conn.execute("SELECT COUNT(*) FROM predictions WHERE prediction='Phishing' AND user_id=?", (uid,)).fetchone()[0]
    legit    = conn.execute("SELECT COUNT(*) FROM predictions WHERE prediction='Legit' AND user_id=?", (uid,)).fetchone()[0]
    avg_conf = conn.execute("SELECT AVG(confidence) FROM predictions WHERE user_id=?", (uid,)).fetchone()[0] or 0
    conn.close()
    return {
        "total_scanned": total, "phishing_detected": phishing, "legit_detected": legit,
        "avg_confidence": round(avg_conf, 2),
        "phishing_rate": round((phishing / total * 100) if total else 0, 1),
    }

@app.delete("/api/history/{record_id}")
def delete_record(record_id: int, request: Request, current_user: dict = Depends(get_current_user)):
    client_ip = request.client.host if request.client else "unknown"
    conn = get_db()
    conn.execute("DELETE FROM predictions WHERE id=? AND user_id=?", (record_id, current_user["id"]))
    conn.execute(
        "INSERT INTO audit_log (action, details, ip_address, timestamp) VALUES (?,?,?,?)",
        ("DELETE", f"Deleted prediction ID {record_id} by {current_user['username']}", client_ip, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/audit")
def audit(current_user: dict = Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
