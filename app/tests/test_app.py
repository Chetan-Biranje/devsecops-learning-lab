"""
Unit & integration tests for the DevSecOps Lab app.
Run: pytest tests/ -v --cov=src --cov-report=xml
"""

import json
import pytest
from src.app import app, get_db


@pytest.fixture
def client():
    app.config["TESTING"] = True
    app.config["DATABASE"] = ":memory:"
    with app.test_client() as client:
        with app.app_context():
            yield client


# ── Health ────────────────────────────────────────────────

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


# ── Registration ──────────────────────────────────────────

def test_register_success(client):
    r = client.post(
        "/api/register",
        data=json.dumps({"username": "alice", "password": "SecurePass1!"}),
        content_type="application/json",
    )
    assert r.status_code == 201


def test_register_duplicate(client):
    payload = json.dumps({"username": "bob", "password": "SecurePass1!"})
    client.post("/api/register", data=payload, content_type="application/json")
    r = client.post("/api/register", data=payload, content_type="application/json")
    assert r.status_code == 409


def test_register_short_password(client):
    r = client.post(
        "/api/register",
        data=json.dumps({"username": "charlie", "password": "abc"}),
        content_type="application/json",
    )
    assert r.status_code == 400


def test_register_missing_fields(client):
    r = client.post(
        "/api/register",
        data=json.dumps({}),
        content_type="application/json",
    )
    assert r.status_code == 400


# ── Login ─────────────────────────────────────────────────

def test_login_success(client):
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
    assert "user_id" in r.get_json()


def test_login_wrong_password(client):
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


def test_login_nonexistent_user(client):
    r = client.post(
        "/api/login",
        data=json.dumps({"username": "nobody", "password": "anything"}),
        content_type="application/json",
    )
    assert r.status_code == 401


# ── Security Headers ─────────────────────────────────────

def test_security_headers(client):
    r = client.get("/health")
    assert "X-Content-Type-Options" in r.headers
    assert "X-Frame-Options" in r.headers
    assert "Content-Security-Policy" in r.headers
    assert "Strict-Transport-Security" in r.headers


def test_server_header_hidden(client):
    r = client.get("/health")
    assert "Server" not in r.headers


# ── Notes ─────────────────────────────────────────────────

def test_create_and_get_note(client):
    # Register + get user_id
    client.post(
        "/api/register",
        data=json.dumps({"username": "frank", "password": "SecurePass1!"}),
        content_type="application/json",
    )
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
