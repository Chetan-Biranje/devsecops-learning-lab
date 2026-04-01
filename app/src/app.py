"""
DevSecOps Learning Lab – Sample Web Application
A deliberately vulnerable-then-fixed Flask app for security practice.
"""

import os
import sqlite3
import hashlib
import logging
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ── Logging ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-me-in-production")
app.config["DATABASE"]   = os.environ.get("DATABASE_URL", ":memory:")

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# ── DB helpers ───────────────────────────────────────────

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(app.config["DATABASE"])
        db.row_factory = sqlite3.Row
        _init_db(db)
    return db


def _init_db(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role     TEXT DEFAULT 'user'
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS notes (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT NOT NULL
        )
    """)
    db.commit()


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# ── Auth helper ──────────────────────────────────────────

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with salt (secure)."""
    salt = os.urandom(32)
    key  = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + key.hex()


def verify_password(stored: str, provided: str) -> bool:
    salt_hex, key_hex = stored.split(":")
    salt = bytes.fromhex(salt_hex)
    key  = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 100_000)
    return key.hex() == key_hex


def require_json(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type must be application/json"}), 415
        return f(*args, **kwargs)
    return decorated


# ── Routes ───────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "devsecops-lab-app"})


@app.route("/api/register", methods=["POST"])
@require_json
@limiter.limit("5 per minute")
def register():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
        logger.info("User registered: %s", username)
        return jsonify({"message": "registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "username already exists"}), 409


@app.route("/api/login", methods=["POST"])
@require_json
@limiter.limit("10 per minute")
def login():
    data     = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    db   = get_db()
    # ✅ Parameterised query – safe from SQL injection
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user and verify_password(user["password"], password):
        logger.info("Login success: %s", username)
        return jsonify({"message": "login successful", "user_id": user["id"]})

    logger.warning("Login failed: %s", username)
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/notes", methods=["GET"])
def get_notes():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"error": "user_id required"}), 400
    db    = get_db()
    notes = db.execute(
        "SELECT id, content FROM notes WHERE user_id = ?", (user_id,)
    ).fetchall()
    return jsonify([dict(n) for n in notes])


@app.route("/api/notes", methods=["POST"])
@require_json
def create_note():
    data    = request.get_json()
    user_id = data.get("user_id")
    content = data.get("content", "").strip()
    if not user_id or not content:
        return jsonify({"error": "user_id and content required"}), 400
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, content) VALUES (?, ?)", (user_id, content)
    )
    db.commit()
    return jsonify({"message": "note created"}), 201


# ── Security headers middleware ───────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"]   = "default-src 'self'"
    response.headers["Referrer-Policy"]           = "no-referrer-when-downgrade"
    # Remove server fingerprint
    response.headers.pop("Server", None)
    return response


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)
