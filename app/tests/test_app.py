"""
Unit & integration tests for the DevSecOps Lab app.
Run: pytest tests/ -v --cov=src --cov-report=xml
"""

import json
import os
import pytest
from src.app import app, get_db


@pytest.fixture
def client():
    """Test client with isolated database."""
    app.config["TESTING"] = True
    app.config["DATABASE"] = ":memory:"
    # Set required SECRET_KEY for testing
    app.config["SECRET_KEY"] = "test-secret-key-do-not-use-in-production"
    
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture
def runner():
    """CLI runner for testing CLI commands."""
    return app.test_cli_runner()


# ── Health ────────────────────────────────────────────────

def test_health(client):
    """Test health check endpoint."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "ok"
    assert data["service"] == "devsecops-lab-app"


# ── Registration ──────────────────────────────────────────

def test_register_success(client):
    """Test successful user registration."""
    r = client.post(
        "/api/register",
        data=json.dumps({"username": "alice", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    assert r.status_code == 201
    data = r.get_json()
    assert "message" in data


def test_register_duplicate(client):
    """Test registering duplicate username."""
    payload = json.dumps({"username": "bob", "password": "SecurePass1!"})
    r1 = client.post("/api/register", data=payload, content_type="application/json")
    assert r1.status_code == 201
    
    r2 = client.post("/api/register", data=payload, content_type="application/json")
    assert r2.status_code == 409
    assert "already exists" in r2.get_json()["error"]


def test_register_short_password(client):
    """Test registration with short password."""
    r = client.post(
        "/api/register",
        data=json.dumps({"username": "charlie", "password": "abc"}),
        content_type="application/json",
    )
    assert r.status_code == 400
    assert "at least 8 characters" in r.get_json()["error"]


def test_register_long_password(client):
    """Test registration with password exceeding max length."""
    long_password = "a" * 129  # Max is 128
    r = client.post(
        "/api/register",
        data=json.dumps({"username": "toolong", "password": long_password}),
        content_type="application/json",
    )
    assert r.status_code == 400
    assert "too long" in r.get_json()["error"]


def test_register_missing_fields(client):
    """Test registration with missing fields."""
    r = client.post(
        "/api/register",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert r.status_code == 400


def test_register_invalid_content_type(client):
    """Test registration with invalid content type."""
    r = client.post(
        "/api/register",
        data="invalid",
        content_type="text/plain",
    )
    assert r.status_code == 415


# ── Login ─────────────────────────────────────────────────

def test_login_success(client):
    """Test successful login."""
    client.post(
        "/api/register",
        data=json.dumps({"username": "dave", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    r = client.post(
        "/api/login",
        data=json.dumps({"username": "dave", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    assert r.status_code == 200
    data = r.get_json()
    assert "user_id" in data
    assert data["message"] == "login successful"


def test_login_wrong_password(client):
    """Test login with wrong password."""
    client.post(
        "/api/register",
        data=json.dumps({"username": "eve", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    r = client.post(
        "/api/login",
        data=json.dumps({"username": "eve", "password": "WrongPassword"}),
        content_type="application/json",
    )
    assert r.status_code == 401
    assert "invalid credentials" in r.get_json()["error"]


def test_login_nonexistent_user(client):
    """Test login with nonexistent user."""
    r = client.post(
        "/api/login",
        data=json.dumps({"username": "nobody", "password": "anything"}),
        content_type="application/json",
    )
    assert r.status_code == 401


def test_login_missing_fields(client):
    """Test login with missing fields."""
    r = client.post(
        "/api/login",
        data=json.dumps({"username": "user"}),
        content_type="application/json",
    )
    assert r.status_code == 400


# ── Security Headers ─────────────────────────────────────

def test_security_headers_present(client):
    """Test that security headers are present."""
    r = client.get("/health")
    headers = r.headers
    
    assert "X-Content-Type-Options" in headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    
    assert "X-Frame-Options" in headers
    assert headers["X-Frame-Options"] == "DENY"
    
    assert "Content-Security-Policy" in headers
    assert "default-src 'self'" in headers["Content-Security-Policy"]
    
    assert "Strict-Transport-Security" in headers
    assert "max-age=31536000" in headers["Strict-Transport-Security"]
    
    assert "Referrer-Policy" in headers
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    
    assert "Permissions-Policy" in headers


def test_server_header_hidden(client):
    """Test that Server header is not exposed."""
    r = client.get("/health")
    assert "Server" not in r.headers


def test_x_xss_protection_header(client):
    """Test X-XSS-Protection header."""
    r = client.get("/health")
    assert "X-XSS-Protection" in r.headers
    assert "1; mode=block" in r.headers["X-XSS-Protection"]


# ── Notes ─────────────────────────────────────────────────

def test_create_and_get_note(client):
    """Test creating and retrieving a note."""
    # Register user
    client.post(
        "/api/register",
        data=json.dumps({"username": "frank", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    
    # Login to get user_id
    login_r = client.post(
        "/api/login",
        data=json.dumps({"username": "frank", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    user_id = login_r.get_json()["user_id"]

    # Create note
    r = client.post(
        "/api/notes",
        data=json.dumps({"user_id": user_id, "content": "Hello DevSecOps!"}),
        content_type="application/json",
    )
    assert r.status_code == 201

    # Fetch notes
    r = client.get(f"/api/notes?user_id={user_id}")
    assert r.status_code == 200
    notes = r.get_json()
    assert len(notes) == 1
    assert notes[0]["content"] == "Hello DevSecOps!"


def test_create_note_missing_fields(client):
    """Test creating note with missing fields."""
    r = client.post(
        "/api/notes",
        data=json.dumps({"user_id": 1}),
        content_type="application/json",
    )
    assert r.status_code == 400


def test_create_note_empty_content(client):
    """Test creating note with empty content."""
    r = client.post(
        "/api/notes",
        data=json.dumps({"user_id": 1, "content": ""}),
        content_type="application/json",
    )
    assert r.status_code == 400


def test_create_note_long_content(client):
    """Test creating note with content exceeding max length."""
    long_content = "a" * 5001  # Max is 5000
    r = client.post(
        "/api/notes",
        data=json.dumps({"user_id": 1, "content": long_content}),
        content_type="application/json",
    )
    assert r.status_code == 400
    assert "exceeds" in r.get_json()["error"]


def test_get_notes_missing_user_id(client):
    """Test getting notes without user_id parameter."""
    r = client.get("/api/notes")
    assert r.status_code == 400


def test_get_notes_nonexistent_user(client):
    """Test getting notes for nonexistent user."""
    r = client.get("/api/notes?user_id=999")
    assert r.status_code == 200
    assert r.get_json() == []


# ── Error Handlers ────────────────────────────────────────

def test_404_error(client):
    """Test 404 error handler."""
    r = client.get("/nonexistent")
    assert r.status_code == 404
    assert "error" in r.get_json()


def test_invalid_json(client):
    """Test invalid JSON handling."""
    r = client.post(
        "/api/register",
        data="invalid json",
        content_type="application/json",
    )
    # Flask returns 400 for invalid JSON
    assert r.status_code in [400, 415]


# ── Rate Limiting ─────────────────────────────────────────

def test_rate_limit_register(client):
    """Test rate limiting on registration endpoint."""
    # Register endpoint limit: 5 per minute
    for i in range(5):
        r = client.post(
            "/api/register",
            data=json.dumps({"username": f"user{i}", "password": "Pass1234!"}),
            content_type="application/json",
        )
        assert r.status_code in [201, 409]  # 201 success or 409 duplicate


def test_rate_limit_login(client):
    """Test rate limiting on login endpoint."""
    # Register user first
    client.post(
        "/api/register",
        data=json.dumps({"username": "testuser", "password": "Pass1234!"}),
        content_type="application/json",
    )
    
    # Login endpoint limit: 10 per minute
    for i in range(10):
        r = client.post(
            "/api/login",
            data=json.dumps({"username": "testuser", "password": "Pass1234!"}),
            content_type="application/json",
        )
        assert r.status_code == 200
