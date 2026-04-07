"""
test_firefox.py
---------------
Regression tests for cookie_extractor.py — Firefox extraction path.

Tests:
  1. Module imports cleanly (catches syntax errors, bad imports)
  2. extract_firefox returns the correct cookies for the seeded domain
  3. Domain filtering excludes cookies from other domains
  4. Cookie fields are correctly typed and populated
  5. Session cookies (expiry=0) are handled without error
  6. All five output writers run without raising exceptions
  7. --list CLI flag exits 0 on the seeded domain
  8. --domain CLI flag with no matches exits 0 gracefully
"""

import json
import os
import pickle
import subprocess
import sys
import tempfile

import pytest

# ── Make sure the repo root is on the path ──────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cookie_extractor as ce  # noqa: E402  (import after path manipulation)

TARGET_DOMAIN = "test.example.com"
OTHER_DOMAIN  = "other.com"


# ── 1. Import smoke test ─────────────────────────────────────────────────────

def test_module_imports():
    """The module must import without error."""
    assert hasattr(ce, "extract_firefox")
    assert hasattr(ce, "extract_chrome")
    assert hasattr(ce, "extract_safari")
    assert hasattr(ce, "Cookie")


# ── 2. Firefox returns expected cookies ──────────────────────────────────────

@pytest.fixture(scope="module")
def firefox_cookies():
    """Extract Firefox cookies for TARGET_DOMAIN once for all tests."""
    cookies = ce.extract_firefox(TARGET_DOMAIN)
    return cookies


def test_firefox_finds_cookies(firefox_cookies):
    """At least one cookie should be found for the seeded domain."""
    assert len(firefox_cookies) > 0, (
        "extract_firefox returned 0 cookies — check seed_firefox_cookies.py ran first"
    )


def test_firefox_expected_count(firefox_cookies):
    """Exactly 3 cookies belong to test.example.com in the seed data."""
    assert len(firefox_cookies) == 3, (
        f"Expected 3 cookies, got {len(firefox_cookies)}: "
        f"{[c.name for c in firefox_cookies]}"
    )


def test_firefox_known_cookie_names(firefox_cookies):
    """session_id and csrf_token must be present."""
    names = {c.name for c in firefox_cookies}
    assert "session_id" in names
    assert "csrf_token" in names
    assert "session_only" in names


# ── 3. Domain filtering ──────────────────────────────────────────────────────

def test_firefox_excludes_other_domain():
    """Cookies for other.com must NOT appear when querying test.example.com."""
    cookies = ce.extract_firefox(TARGET_DOMAIN)
    domains = {c.domain for c in cookies}
    assert not any("other.com" in d for d in domains), (
        f"other.com leaked into results: {domains}"
    )


def test_firefox_other_domain_isolated():
    """Querying other.com should return exactly 1 cookie."""
    cookies = ce.extract_firefox(OTHER_DOMAIN)
    assert len(cookies) == 1
    assert cookies[0].name == "tracker"


# ── 4. Cookie field types and values ─────────────────────────────────────────

def test_cookie_fields_typed(firefox_cookies):
    """All Cookie fields must have correct types."""
    for c in firefox_cookies:
        assert isinstance(c.name,     str),  f"name not str: {c.name!r}"
        assert isinstance(c.value,    str),  f"value not str: {c.value!r}"
        assert isinstance(c.domain,   str),  f"domain not str: {c.domain!r}"
        assert isinstance(c.path,     str),  f"path not str: {c.path!r}"
        assert isinstance(c.secure,   bool), f"secure not bool: {c.secure!r}"
        assert isinstance(c.http_only,bool), f"http_only not bool: {c.http_only!r}"


def test_session_id_values(firefox_cookies):
    """session_id cookie must have correct seeded value and flags."""
    s = next((c for c in firefox_cookies if c.name == "session_id"), None)
    assert s is not None
    assert s.value == "abc123"
    assert s.secure is True
    assert s.http_only is True
    assert s.same_site == "lax"


def test_csrf_token_values(firefox_cookies):
    """csrf_token must be not-secure and not-httponly as seeded."""
    c = next((x for x in firefox_cookies if x.name == "csrf_token"), None)
    assert c is not None
    assert c.value == "xyz789"
    assert c.secure is False
    assert c.http_only is False
    assert c.path == "/api"


# ── 5. Session cookie (expiry=0) ──────────────────────────────────────────────

def test_session_cookie_handled(firefox_cookies):
    """A cookie with expiry=0 must not cause errors and expires should be falsy."""
    s = next((c for c in firefox_cookies if c.name == "session_only"), None)
    assert s is not None
    # expiry=0 → stored as 0.0, which is falsy
    assert not s.expires or s.expires == 0


# ── 6. All output writers run cleanly ────────────────────────────────────────

@pytest.fixture(scope="module")
def tmp_out(tmp_path_factory):
    return tmp_path_factory.mktemp("output")


def test_write_json(firefox_cookies, tmp_out):
    path = str(tmp_out / "cookies.json")
    ce.write_json(firefox_cookies, path)
    assert os.path.exists(path)
    data = json.loads(open(path).read())
    assert isinstance(data, list)
    assert len(data) == len(firefox_cookies)
    # Validate keys present
    assert "name" in data[0] and "value" in data[0]


def test_write_netscape(firefox_cookies, tmp_out):
    path = str(tmp_out / "cookies.txt")
    ce.write_netscape(firefox_cookies, path)
    content = open(path).read()
    assert "# Netscape HTTP Cookie File" in content
    # Each cookie should produce a tab-delimited line
    lines = [l for l in content.splitlines() if not l.startswith("#") and l.strip()]
    assert len(lines) == len(firefox_cookies)
    # Each line must have 7 tab-separated fields
    for line in lines:
        assert line.count("\t") == 6, f"Malformed Netscape line: {line!r}"


def test_write_header(firefox_cookies, tmp_out):
    path = str(tmp_out / "cookies.hdr")
    ce.write_header(firefox_cookies, path)
    content = open(path).read()
    assert content.startswith("Cookie: ")
    # All cookie names should appear in the header
    for c in firefox_cookies:
        assert c.name in content


def test_write_pickle(firefox_cookies, tmp_out):
    path = str(tmp_out / "cookies.pkl")
    ce.write_pickle(firefox_cookies, path)
    assert os.path.exists(path)
    with open(path, "rb") as f:
        loaded = pickle.load(f)
    # Should be a requests.Session or a list of dicts
    import requests
    assert isinstance(loaded, (requests.Session, list))


def test_write_playwright(firefox_cookies, tmp_out):
    path = str(tmp_out / "cookies.playwright.json")
    ce.write_playwright(firefox_cookies, path)
    data = json.loads(open(path).read())
    assert "cookies" in data and "origins" in data
    assert isinstance(data["cookies"], list)
    assert len(data["cookies"]) == len(firefox_cookies)
    # sameSite values must be Playwright-valid strings
    valid_samesite = {"None", "Lax", "Strict"}
    for c in data["cookies"]:
        assert c["sameSite"] in valid_samesite, f"Bad sameSite: {c['sameSite']}"


# ── 7. CLI --list flag ────────────────────────────────────────────────────────

def test_cli_list_flag():
    """--list should exit 0 and print cookie names to stdout."""
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", TARGET_DOMAIN, "--browser", "firefox", "--list"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"CLI exited non-zero:\n{result.stderr}"
    assert "session_id" in result.stdout


# ── 8. CLI graceful no-match ─────────────────────────────────────────────────

def test_cli_no_cookies_found():
    """Querying a domain with no cookies should exit 0, not crash."""
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", "nonexistent-domain-xyz.io",
         "--browser", "firefox", "--list"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"CLI crashed on no-match:\n{result.stderr}"
    assert "No cookies found" in result.stdout
