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
from flask_wtf.csrf import CSRFProtect

# ── Logging ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App setup ────────────────────────────────────────────
app = Flask(__name__)

# ⚠️ Security: Check SECRET_KEY in production
secret_key = os.environ.get("SECRET_KEY")
if not secret_key or secret_key == "change-me-in-production":
    logger.error("🔴 CRITICAL: SECRET_KEY not set or using default value!")
    logger.error("Set the SECRET_KEY environment variable in production!")
    if not secret_key:
        raise RuntimeError("SECRET_KEY environment variable is required in production")

app.config["SECRET_KEY"] = secret_key
app.config["DATABASE"] = os.environ.get("DATABASE_URL", ":memory:")

# ── Security Configuration ───────────────────────────────
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 1800  # 30 minutes
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1MB max request size
app.config["JSON_SORT_KEYS"] = False

# ── Rate Limiter ─────────────────────────────────────────
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# ── CSRF Protection ──────────────────────────────────────
csrf = CSRFProtect(app)

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


# ── Input Validation ─────────────────────────────────────

def sanitize_input(data, max_length=255):
    """Sanitize user input - prevent injection attacks."""
    if not isinstance(data, str):
        raise ValueError("Input must be a string")
    if len(data) > max_length:
        raise ValueError(f"Input exceeds {max_length} characters")
    return data.strip()


# ── Auth helper ──────────────────────────────────────────

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with salt (secure)."""
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return salt.hex() + ":" + key.hex()


def verify_password(stored: str, provided: str) -> bool:
    """Verify hashed password safely."""
    try:
        salt_hex, key_hex = stored.split(":")
        salt = bytes.fromhex(salt_hex)
        key = hashlib.pbkdf2_hmac("sha256", provided.encode(), salt, 100_000)
        return key.hex() == key_hex
    except (ValueError, IndexError):
        return False


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
    """Health check endpoint."""
    return jsonify({"status": "ok", "service": "devsecops-lab-app"}), 200


@app.route("/api/register", methods=["POST"])
@require_json
@limiter.limit("5 per minute")
def register():
    """Register a new user."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # ✅ Input validation
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    try:
        username = sanitize_input(username, max_length=128)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400
    if len(password) > 128:
        return jsonify({"error": "password is too long"}), 400

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
        logger.warning("Registration failed - username exists: %s", username)
        return jsonify({"error": "username already exists"}), 409


@app.route("/api/login", methods=["POST"])
@require_json
@limiter.limit("10 per minute")
def login():
    """Authenticate user and return session."""
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    # ✅ Input validation
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    db = get_db()
    # ✅ Parameterised query – safe from SQL injection
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user and verify_password(user["password"], password):
        logger.info("Login success: %s", username)
        return jsonify({"message": "login successful", "user_id": user["id"]}), 200

    logger.warning("Login failed for username: %s", username)
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/notes", methods=["GET"])
def get_notes():
    """Retrieve user notes."""
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    db = get_db()
    # ✅ Parameterised query
    notes = db.execute(
        "SELECT id, content FROM notes WHERE user_id = ?", (user_id,)
    ).fetchall()
    return jsonify([dict(n) for n in notes]), 200


@app.route("/api/notes", methods=["POST"])
@require_json
@limiter.limit("20 per minute")
def create_note():
    """Create a new note."""
    data = request.get_json()
    user_id = data.get("user_id")
    content = data.get("content", "").strip()

    if not user_id or not content:
        return jsonify({"error": "user_id and content required"}), 400

    # ✅ Input validation
    try:
        content = sanitize_input(content, max_length=5000)
    except ValueError as e:
        logger.warning("Input validation failed in create_note: %s", e)
        return jsonify({"error": "invalid input"}), 400

    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, content) VALUES (?, ?)", (user_id, content)
    )
    db.commit()
    logger.info("Note created for user: %s", user_id)
    return jsonify({"message": "note created"}), 201


# ── Security headers middleware ───────────────────────────

@app.after_request
def set_security_headers(response):
    """Set security headers on all responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Remove server fingerprint
    response.headers.pop("Server", None)
    return response


# ── Error handlers ───────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):
    """Handle bad request."""
    logger.warning("Bad request: %s", e)
    return jsonify({"error": "bad request"}), 400


@app.errorhandler(403)
def forbidden(e):
    """Handle forbidden access."""
    logger.warning("Forbidden access attempt")
    return jsonify({"error": "forbidden"}), 403


@app.errorhandler(404)
def not_found(e):
    """Handle not found."""
    return jsonify({"error": "not found"}), 404


@app.errorhandler(500)
def server_error(e):
    """Handle server error."""
    logger.error("Server error: %s", e)
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=5000, debug=debug)
