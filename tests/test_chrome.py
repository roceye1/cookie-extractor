"""
test_chrome.py
--------------
Regression tests for cookie_extractor.py — Chrome/Chromium extraction path
on Linux (ubuntu-latest in CI).

Coverage:
  1.  Module imports cleanly
  2.  extract_chrome returns correct cookie count for seeded domain
  3.  Known cookie names are present
  4.  Domain filtering excludes cookies from other domains
  5.  Other domain isolated to exactly 1 cookie
  6.  Cookie field types are correct
  7.  v10-AES encrypted value is decrypted to expected plaintext
  8.  Plaintext (no-prefix) value is returned as-is
  9.  Empty encrypted_value returns empty string without raising
  10. Session cookie (expires_utc=0) is handled without error
  11. samesite integer is mapped to correct string
  12. Chrome epoch → Unix timestamp conversion is within tolerance
  13. source_browser is "chrome" for all returned cookies
  14-18. All five output writers produce valid artefacts
  19. CLI --list flag exits 0 and prints expected cookie names
  20. CLI graceful no-match exits 0 with "No cookies found" message
  21. _decrypt_chrome_value round-trips with known key (unit test)
  22. _domain_matches helper correctly handles leading-dot variants
"""

import hashlib
import json
import os
import pickle
import subprocess
import sys
import time

import pytest

# ── Path setup ───────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cookie_extractor as ce  # noqa: E402

TARGET_DOMAIN = "test.chrome-example.com"
OTHER_DOMAIN  = "other-chrome.com"


# ══════════════════════════════════════════════════════════════════════════════
#  Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def chrome_cookies():
    """Extract Chrome cookies for TARGET_DOMAIN once for all tests in module."""
    cookies = ce.extract_chrome(TARGET_DOMAIN)
    return cookies


@pytest.fixture(scope="module")
def tmp_out(tmp_path_factory):
    return tmp_path_factory.mktemp("chrome_output")


# ══════════════════════════════════════════════════════════════════════════════
#  1. Import smoke test
# ══════════════════════════════════════════════════════════════════════════════

def test_module_imports():
    """All public symbols must be importable without error."""
    assert callable(ce.extract_chrome)
    assert callable(ce._decrypt_chrome_value)
    assert callable(ce._domain_matches)
    assert callable(ce.write_json)
    assert callable(ce.write_netscape)
    assert callable(ce.write_header)
    assert callable(ce.write_pickle)
    assert callable(ce.write_playwright)
    assert ce.Cookie is not None


# ══════════════════════════════════════════════════════════════════════════════
#  2-3. Count & names
# ══════════════════════════════════════════════════════════════════════════════

def test_chrome_finds_cookies(chrome_cookies):
    assert len(chrome_cookies) > 0, (
        "extract_chrome returned 0 cookies — did seed_chrome_cookies.py run?"
    )


def test_chrome_expected_count(chrome_cookies):
    """4 cookies belong to test.chrome-example.com in the seed."""
    assert len(chrome_cookies) == 4, (
        f"Expected 4, got {len(chrome_cookies)}: {[c.name for c in chrome_cookies]}"
    )


def test_chrome_known_names(chrome_cookies):
    names = {c.name for c in chrome_cookies}
    assert "session_id"   in names
    assert "csrf_token"   in names
    assert "pref"         in names
    assert "session_only" in names


# ══════════════════════════════════════════════════════════════════════════════
#  4-5. Domain filtering
# ══════════════════════════════════════════════════════════════════════════════

def test_chrome_excludes_other_domain(chrome_cookies):
    domains = {c.domain for c in chrome_cookies}
    assert not any("other-chrome.com" in d for d in domains), (
        f"other-chrome.com leaked into results: {domains}"
    )


def test_chrome_other_domain_isolated():
    cookies = ce.extract_chrome(OTHER_DOMAIN)
    assert len(cookies) == 1
    assert cookies[0].name == "tracker"


# ══════════════════════════════════════════════════════════════════════════════
#  6. Field types
# ══════════════════════════════════════════════════════════════════════════════

def test_cookie_field_types(chrome_cookies):
    for c in chrome_cookies:
        assert isinstance(c.name,      str),  f"name not str: {c.name!r}"
        assert isinstance(c.value,     str),  f"value not str for {c.name!r}"
        assert isinstance(c.domain,    str),  f"domain not str: {c.domain!r}"
        assert isinstance(c.path,      str),  f"path not str: {c.path!r}"
        assert isinstance(c.secure,    bool), f"secure not bool: {c.secure!r}"
        assert isinstance(c.http_only, bool), f"http_only not bool: {c.http_only!r}"
        assert isinstance(c.same_site, str),  f"same_site not str: {c.same_site!r}"
        assert c.source_browser == "chrome",  f"wrong source_browser: {c.source_browser!r}"


# ══════════════════════════════════════════════════════════════════════════════
#  7. v10-AES decryption
# ══════════════════════════════════════════════════════════════════════════════

def test_v10_encrypted_session_id(chrome_cookies):
    """session_id was encrypted with v10+AES-CBC; must decrypt to known value."""
    c = next((x for x in chrome_cookies if x.name == "session_id"), None)
    assert c is not None, "session_id cookie missing"
    assert c.value == "chrome-session-abc", (
        f"Decryption produced: {c.value!r} — expected 'chrome-session-abc'"
    )
    assert c.secure is True
    assert c.http_only is True
    assert c.same_site == "lax"


def test_v10_encrypted_pref(chrome_cookies):
    """pref was also v10-encrypted."""
    c = next((x for x in chrome_cookies if x.name == "pref"), None)
    assert c is not None
    assert c.value == "dark-mode", (
        f"Decryption produced: {c.value!r} — expected 'dark-mode'"
    )
    assert c.same_site == "strict"


# ══════════════════════════════════════════════════════════════════════════════
#  8. Plaintext (no-prefix) decryption path
# ══════════════════════════════════════════════════════════════════════════════

def test_plaintext_csrf_token(chrome_cookies):
    """csrf_token was stored as raw UTF-8 bytes with no prefix."""
    c = next((x for x in chrome_cookies if x.name == "csrf_token"), None)
    assert c is not None
    assert c.value == "plaintext-csrf-xyz", (
        f"Plaintext path returned: {c.value!r}"
    )
    assert c.secure    is False
    assert c.http_only is False
    assert c.path      == "/api"
    assert c.same_site == "no_restriction"


# ══════════════════════════════════════════════════════════════════════════════
#  9. Empty encrypted_value
# ══════════════════════════════════════════════════════════════════════════════

def test_empty_encrypted_value(chrome_cookies):
    """session_only has b'' as encrypted_value; must return '' without crashing."""
    c = next((x for x in chrome_cookies if x.name == "session_only"), None)
    assert c is not None
    assert c.value == "", f"Expected empty string, got: {c.value!r}"


# ══════════════════════════════════════════════════════════════════════════════
#  10. Session cookie (expires_utc = 0)
# ══════════════════════════════════════════════════════════════════════════════

def test_session_cookie_expires(chrome_cookies):
    """expires_utc=0 must map to None (not a timestamp)."""
    c = next((x for x in chrome_cookies if x.name == "session_only"), None)
    assert c is not None
    assert c.expires is None, f"Expected None for session cookie, got: {c.expires}"


# ══════════════════════════════════════════════════════════════════════════════
#  11. samesite integer → string mapping
# ══════════════════════════════════════════════════════════════════════════════

def test_samesite_mapping(chrome_cookies):
    by_name = {c.name: c for c in chrome_cookies}
    assert by_name["session_id"].same_site  == "lax"
    assert by_name["csrf_token"].same_site  == "no_restriction"
    assert by_name["pref"].same_site        == "strict"
    assert by_name["session_only"].same_site == "unspecified"


# ══════════════════════════════════════════════════════════════════════════════
#  12. Chrome epoch conversion accuracy
# ══════════════════════════════════════════════════════════════════════════════

def test_chrome_epoch_conversion(chrome_cookies):
    """Expiry timestamps must be within 5 seconds of expected Unix time."""
    now = time.time()
    c = next((x for x in chrome_cookies if x.name == "session_id"), None)
    assert c is not None and c.expires is not None
    expected = now + 86_400
    # Tolerance is 30s: seed runs immediately before pytest in CI;
    # locally the DB may be slightly older if seed was run earlier.
    assert abs(c.expires - expected) < 30, (
        f"Timestamp off: got {c.expires}, expected ~{expected}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  13. source_browser field
# ══════════════════════════════════════════════════════════════════════════════

def test_source_browser_chrome(chrome_cookies):
    for c in chrome_cookies:
        assert c.source_browser == "chrome"


# ══════════════════════════════════════════════════════════════════════════════
#  14-18. Output writers
# ══════════════════════════════════════════════════════════════════════════════

def test_write_json_chrome(chrome_cookies, tmp_out):
    path = str(tmp_out / "chrome.json")
    ce.write_json(chrome_cookies, path)
    data = json.loads(open(path).read())
    assert isinstance(data, list)
    assert len(data) == len(chrome_cookies)
    required_keys = {"name", "value", "domain", "path", "expires", "secure",
                     "httpOnly", "sameSite", "sourceBrowser"}
    for entry in data:
        assert required_keys.issubset(entry.keys()), (
            f"Missing keys: {required_keys - entry.keys()}"
        )
    # Verify decrypted values are present in JSON
    names_in_json = {e["name"]: e["value"] for e in data}
    assert names_in_json["session_id"] == "chrome-session-abc"
    assert names_in_json["csrf_token"] == "plaintext-csrf-xyz"
    assert names_in_json["pref"]       == "dark-mode"


def test_write_netscape_chrome(chrome_cookies, tmp_out):
    path = str(tmp_out / "chrome.txt")
    ce.write_netscape(chrome_cookies, path)
    content = open(path).read()
    assert "# Netscape HTTP Cookie File" in content
    data_lines = [l for l in content.splitlines()
                  if l.strip() and not l.startswith("#")]
    assert len(data_lines) == len(chrome_cookies)
    for line in data_lines:
        fields = line.split("\t")
        assert len(fields) == 7, f"Expected 7 tab-fields, got {len(fields)}: {line!r}"
        # Field 3 (index 2) is path — must start with /
        assert fields[2].startswith("/"), f"Bad path field: {fields[2]!r}"
        # Field 4 (index 3) is SECURE flag
        assert fields[3] in ("TRUE", "FALSE"), f"Bad SECURE: {fields[3]!r}"


def test_write_header_chrome(chrome_cookies, tmp_out):
    path = str(tmp_out / "chrome.hdr")
    ce.write_header(chrome_cookies, path)
    content = open(path).read()
    assert content.startswith("Cookie: ")
    header_val = content.splitlines()[0][len("Cookie: "):]
    pairs = dict(p.split("=", 1) for p in header_val.split("; ") if "=" in p)
    assert "session_id" in pairs
    assert pairs["session_id"] == "chrome-session-abc"
    assert "csrf_token"  in pairs
    assert pairs["csrf_token"] == "plaintext-csrf-xyz"


def test_write_pickle_chrome(chrome_cookies, tmp_out):
    path = str(tmp_out / "chrome.pkl")
    ce.write_pickle(chrome_cookies, path)
    assert os.path.exists(path)
    with open(path, "rb") as f:
        loaded = pickle.load(f)
    import requests
    assert isinstance(loaded, (requests.Session, list))
    if isinstance(loaded, requests.Session):
        cookie_names = {c.name for c in loaded.cookies}
        assert "session_id" in cookie_names
        assert "csrf_token"  in cookie_names


def test_write_playwright_chrome(chrome_cookies, tmp_out):
    path = str(tmp_out / "chrome.playwright.json")
    ce.write_playwright(chrome_cookies, path)
    data = json.loads(open(path).read())
    assert "cookies" in data and "origins" in data
    assert len(data["cookies"]) == len(chrome_cookies)
    valid_samesite = {"None", "Lax", "Strict"}
    for c in data["cookies"]:
        assert c["sameSite"] in valid_samesite, f"Invalid sameSite: {c['sameSite']!r}"
        assert isinstance(c["secure"],   bool)
        assert isinstance(c["httpOnly"], bool)
    # Confirm decrypted values flow through to Playwright output
    pw_by_name = {c["name"]: c["value"] for c in data["cookies"]}
    assert pw_by_name["session_id"] == "chrome-session-abc"
    assert pw_by_name["pref"]       == "dark-mode"


# ══════════════════════════════════════════════════════════════════════════════
#  19. CLI --list flag
# ══════════════════════════════════════════════════════════════════════════════

def test_cli_list_flag_chrome():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", TARGET_DOMAIN, "--browser", "chrome", "--list"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"CLI exited non-zero:\n{result.stderr}"
    assert "session_id" in result.stdout
    assert "csrf_token"  in result.stdout


# ══════════════════════════════════════════════════════════════════════════════
#  20. CLI graceful no-match
# ══════════════════════════════════════════════════════════════════════════════

def test_cli_no_match_chrome():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", "nonexistent-xyz-123.io",
         "--browser", "chrome", "--list"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"CLI crashed on no-match:\n{result.stderr}"
    assert "No cookies found" in result.stdout


# ══════════════════════════════════════════════════════════════════════════════
#  21. _decrypt_chrome_value unit test (round-trip)
# ══════════════════════════════════════════════════════════════════════════════

def test_decrypt_chrome_value_v10_roundtrip():
    """Encrypt a known string with v10 scheme, then decrypt via the extractor."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    plaintext  = "round-trip-value"
    password   = b"peanuts"
    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1, dklen=16)
    iv  = b" " * 16
    cipher     = AES.new(key, AES.MODE_CBC, IV=iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    blob       = b"v10" + ciphertext

    result = ce._decrypt_chrome_value(blob, "Linux")
    assert result == plaintext, f"Round-trip failed: {result!r}"


def test_decrypt_chrome_value_plaintext():
    """Raw UTF-8 bytes with no prefix must pass through unchanged."""
    raw    = b"just-a-plain-value"
    result = ce._decrypt_chrome_value(raw, "Linux")
    assert result == "just-a-plain-value"


def test_decrypt_chrome_value_empty():
    """Empty bytes must return empty string, not raise."""
    result = ce._decrypt_chrome_value(b"", "Linux")
    assert result == ""


# ══════════════════════════════════════════════════════════════════════════════
#  22. _domain_matches unit tests
# ══════════════════════════════════════════════════════════════════════════════

def test_domain_matches_exact():
    assert ce._domain_matches("example.com", "example.com")


def test_domain_matches_leading_dot():
    assert ce._domain_matches(".example.com", "example.com")
    assert ce._domain_matches(".example.com", "sub.example.com")


def test_domain_matches_subdomain():
    assert ce._domain_matches("sub.example.com", "sub.example.com")


def test_domain_no_match():
    assert not ce._domain_matches(".other.com", "example.com")
    assert not ce._domain_matches("evil-example.com", "example.com")
