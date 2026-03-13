"""
ShieldScan — pytest test suite
Tests URL analysis logic and all API endpoints.

Run with:  pytest tests/ -v
"""

import sys
import os
import json
import time
import pytest

# Make sure app module is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app import app as flask_app, analyze_url, _users, _sessions, _scan_history


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_state():
    """Reset in-memory stores before every test."""
    _users.clear()
    _sessions.clear()
    _scan_history.clear()
    yield
    _users.clear()
    _sessions.clear()
    _scan_history.clear()


@pytest.fixture
def client():
    flask_app.config["TESTING"] = True
    with flask_app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """Returns (test_client, auth_token) for an already-registered user."""
    res = client.post("/api/auth/signup", json={
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123",
    })
    data = res.get_json()
    return client, data["token"]


def auth_header(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════════
#  1. URL ANALYSIS UNIT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAnalyzeUrl:

    # --- happy path ---

    def test_safe_https_url(self):
        result = analyze_url("https://google.com")
        assert result["verdict"] == "safe"
        assert result["score"] >= 75

    def test_safe_url_has_required_keys(self):
        result = analyze_url("https://github.com")
        for key in ("url", "score", "verdict", "verdict_label", "verdict_msg", "checks", "timestamp"):
            assert key in result, f"Missing key: {key}"

    def test_returns_ten_checks(self):
        result = analyze_url("https://example.com")
        assert len(result["checks"]) == 10

    def test_check_has_required_fields(self):
        result = analyze_url("https://example.com")
        for check in result["checks"]:
            for field in ("name", "icon", "pass", "detail", "severity"):
                assert field in check, f"Check missing field: {field}"

    # --- HTTPS check ---

    def test_http_url_fails_https_check(self):
        result = analyze_url("http://example.com")
        https_check = next(c for c in result["checks"] if c["name"] == "HTTPS Protocol")
        assert https_check["pass"] is False

    def test_https_url_passes_https_check(self):
        result = analyze_url("https://example.com")
        https_check = next(c for c in result["checks"] if c["name"] == "HTTPS Protocol")
        assert https_check["pass"] is True

    # --- IP address check ---

    def test_ip_address_detected(self):
        result = analyze_url("http://192.168.1.1/login")
        ip_check = next(c for c in result["checks"] if c["name"] == "IP Address Check")
        assert ip_check["pass"] is False

    def test_domain_passes_ip_check(self):
        result = analyze_url("https://example.com")
        ip_check = next(c for c in result["checks"] if c["name"] == "IP Address Check")
        assert ip_check["pass"] is True

    # --- Phishing keywords ---

    def test_phishing_keyword_in_domain(self):
        result = analyze_url("https://secure-login-amazon.xyz/verify")
        kw_check = next(c for c in result["checks"] if c["name"] == "Phishing Keywords")
        assert kw_check["pass"] is False

    def test_clean_domain_no_phishing_keywords(self):
        result = analyze_url("https://github.com")
        kw_check = next(c for c in result["checks"] if c["name"] == "Phishing Keywords")
        assert kw_check["pass"] is True

    # --- TLD reputation ---

    def test_risky_tld_flagged(self):
        result = analyze_url("https://totally-safe.xyz")
        tld_check = next(c for c in result["checks"] if c["name"] == "TLD Reputation")
        assert tld_check["pass"] is False

    def test_com_tld_passes(self):
        result = analyze_url("https://example.com")
        tld_check = next(c for c in result["checks"] if c["name"] == "TLD Reputation")
        assert tld_check["pass"] is True

    # --- URL shortener ---

    def test_shortener_detected(self):
        result = analyze_url("https://bit.ly/3xK9mPQ")
        short_check = next(c for c in result["checks"] if c["name"] == "URL Shortener")
        assert short_check["pass"] is False

    def test_tinyurl_detected(self):
        result = analyze_url("https://tinyurl.com/abc123")
        short_check = next(c for c in result["checks"] if c["name"] == "URL Shortener")
        assert short_check["pass"] is False

    # --- Subdomain depth ---

    def test_deep_subdomains_flagged(self):
        result = analyze_url("https://a.b.c.evil.com")
        sub_check = next(c for c in result["checks"] if c["name"] == "Subdomain Depth")
        assert sub_check["pass"] is False

    def test_normal_subdomain_passes(self):
        result = analyze_url("https://www.github.com")
        sub_check = next(c for c in result["checks"] if c["name"] == "Subdomain Depth")
        assert sub_check["pass"] is True

    # --- Punycode ---

    def test_punycode_detected(self):
        result = analyze_url("https://xn--pple-43d.com")
        puny_check = next(c for c in result["checks"] if c["name"] == "Punycode / Homograph")
        assert puny_check["pass"] is False

    # --- URL length ---

    def test_very_long_url_flagged(self):
        long_url = "https://example.com/" + "a" * 200
        result = analyze_url(long_url)
        len_check = next(c for c in result["checks"] if c["name"] == "URL Length")
        assert len_check["pass"] is False

    def test_normal_length_url_passes(self):
        result = analyze_url("https://example.com/page")
        len_check = next(c for c in result["checks"] if c["name"] == "URL Length")
        assert len_check["pass"] is True

    # --- Score & verdict thresholds ---

    def test_score_between_0_and_100(self):
        for url in ["https://google.com", "http://192.168.1.1", "https://bit.ly/xyz"]:
            result = analyze_url(url)
            assert 0 <= result["score"] <= 100

    def test_malicious_url_gets_danger_verdict(self):
        result = analyze_url("http://192.168.1.1/secure-login-verify-paypal.xyz")
        assert result["verdict"] in ("danger", "warning")

    def test_url_without_scheme_auto_prefixed(self):
        result = analyze_url("example.com")
        assert "error" not in result
        assert result["normalized_url"].startswith("https://")

    def test_timestamp_is_recent(self):
        result = analyze_url("https://example.com")
        assert abs(result["timestamp"] - int(time.time())) < 5


# ══════════════════════════════════════════════════════════════════════════════
#  2. AUTH API TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthSignup:

    def test_signup_success(self, client):
        res = client.post("/api/auth/signup", json={
            "name": "Alice",
            "email": "alice@example.com",
            "password": "securepass",
        })
        assert res.status_code == 201
        data = res.get_json()
        assert "token" in data
        assert data["name"] == "Alice"
        assert data["email"] == "alice@example.com"

    def test_signup_missing_fields(self, client):
        res = client.post("/api/auth/signup", json={"email": "x@x.com"})
        assert res.status_code == 400

    def test_signup_invalid_email(self, client):
        res = client.post("/api/auth/signup", json={
            "name": "Bob",
            "email": "not-an-email",
            "password": "password123",
        })
        assert res.status_code == 400

    def test_signup_short_password(self, client):
        res = client.post("/api/auth/signup", json={
            "name": "Bob",
            "email": "bob@example.com",
            "password": "short",
        })
        assert res.status_code == 400

    def test_signup_duplicate_email(self, client):
        payload = {"name": "Bob", "email": "bob@example.com", "password": "pass1234"}
        client.post("/api/auth/signup", json=payload)
        res = client.post("/api/auth/signup", json=payload)
        assert res.status_code == 409

    def test_signup_email_case_insensitive(self, client):
        client.post("/api/auth/signup", json={
            "name": "Carol",
            "email": "CAROL@EXAMPLE.COM",
            "password": "password123",
        })
        res = client.post("/api/auth/signup", json={
            "name": "Carol2",
            "email": "carol@example.com",
            "password": "password456",
        })
        assert res.status_code == 409


class TestAuthLogin:

    def test_login_success(self, client):
        client.post("/api/auth/signup", json={
            "name": "Dave",
            "email": "dave@example.com",
            "password": "mypassword",
        })
        res = client.post("/api/auth/login", json={
            "email": "dave@example.com",
            "password": "mypassword",
        })
        assert res.status_code == 200
        assert "token" in res.get_json()

    def test_login_wrong_password(self, client):
        client.post("/api/auth/signup", json={
            "name": "Eve",
            "email": "eve@example.com",
            "password": "correctpass",
        })
        res = client.post("/api/auth/login", json={
            "email": "eve@example.com",
            "password": "wrongpass",
        })
        assert res.status_code == 401

    def test_login_nonexistent_user(self, client):
        res = client.post("/api/auth/login", json={
            "email": "ghost@example.com",
            "password": "anything",
        })
        assert res.status_code == 401

    def test_login_returns_name_and_email(self, client):
        client.post("/api/auth/signup", json={
            "name": "Frank",
            "email": "frank@example.com",
            "password": "frank1234",
        })
        res = client.post("/api/auth/login", json={
            "email": "frank@example.com",
            "password": "frank1234",
        })
        data = res.get_json()
        assert data["name"] == "Frank"
        assert data["email"] == "frank@example.com"


class TestAuthLogout:

    def test_logout_success(self, auth_client):
        client, token = auth_client
        res = client.post("/api/auth/logout", headers=auth_header(token))
        assert res.status_code == 200

    def test_logout_invalidates_token(self, auth_client):
        client, token = auth_client
        client.post("/api/auth/logout", headers=auth_header(token))
        # Token should now be invalid
        res = client.get("/api/scan/history", headers=auth_header(token))
        assert res.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
#  3. SCAN API TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestScanEndpoint:

    def test_scan_requires_auth(self, client):
        res = client.post("/api/scan", json={"url": "https://example.com"})
        assert res.status_code == 401

    def test_scan_returns_result(self, auth_client):
        client, token = auth_client
        res = client.post("/api/scan",
                          json={"url": "https://google.com"},
                          headers=auth_header(token))
        assert res.status_code == 200
        data = res.get_json()
        assert "score" in data
        assert "verdict" in data
        assert "checks" in data

    def test_scan_missing_url(self, auth_client):
        client, token = auth_client
        res = client.post("/api/scan", json={}, headers=auth_header(token))
        assert res.status_code == 400

    def test_scan_stores_in_history(self, auth_client):
        client, token = auth_client
        client.post("/api/scan", json={"url": "https://github.com"},
                    headers=auth_header(token))
        res = client.get("/api/scan/history", headers=auth_header(token))
        history = res.get_json()
        assert len(history) == 1
        assert history[0]["url"] == "https://github.com"

    def test_scan_history_max_50(self, auth_client):
        client, token = auth_client
        for i in range(55):
            client.post("/api/scan",
                        json={"url": f"https://example{i}.com"},
                        headers=auth_header(token))
        res = client.get("/api/scan/history", headers=auth_header(token))
        assert len(res.get_json()) <= 50

    def test_history_newest_first(self, auth_client):
        client, token = auth_client
        for url in ["https://first.com", "https://second.com", "https://third.com"]:
            client.post("/api/scan", json={"url": url}, headers=auth_header(token))
        history = client.get("/api/scan/history", headers=auth_header(token)).get_json()
        assert history[0]["url"] == "https://third.com"

    def test_history_requires_auth(self, client):
        res = client.get("/api/scan/history")
        assert res.status_code == 401

    def test_scan_verdict_field_valid(self, auth_client):
        client, token = auth_client
        res = client.post("/api/scan",
                          json={"url": "https://example.com"},
                          headers=auth_header(token))
        assert res.get_json()["verdict"] in ("safe", "warning", "danger")


# ══════════════════════════════════════════════════════════════════════════════
#  4. CHAT API TESTS  (stub — no real API key required)
# ══════════════════════════════════════════════════════════════════════════════

class TestChatEndpoint:

    def test_chat_requires_auth(self, client):
        res = client.post("/api/chat", json={"messages": [{"role": "user", "content": "hi"}]})
        assert res.status_code == 401

    def test_chat_no_messages(self, auth_client):
        client, token = auth_client
        res = client.post("/api/chat", json={}, headers=auth_header(token))
        assert res.status_code == 400

    def test_chat_no_api_key_returns_503(self, auth_client, monkeypatch):
        """When no API key is configured, returns 503."""
        import app as app_module
        monkeypatch.setattr(app_module, "client", None)
        c, token = auth_client
        res = c.post("/api/chat",
                     json={"messages": [{"role": "user", "content": "hello"}]},
                     headers=auth_header(token))
        assert res.status_code == 503

    def test_chat_invalid_role(self, auth_client):
        client, token = auth_client
        res = client.post("/api/chat",
                          json={"messages": [{"role": "system", "content": "hi"}]},
                          headers=auth_header(token))
        assert res.status_code == 400
