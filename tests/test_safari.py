"""
test_safari.py
--------------
Regression tests for cookie_extractor.py — Safari BinaryCookies parsing path.
Runs only on macOS (macos-latest in CI).

Coverage:
  1.  Module imports cleanly; Safari symbols present
  2.  _parse_binary_cookies returns all seeded records from file
  3.  extract_safari returns correct count for target domain
  4.  Known cookie names present
  5.  Domain filtering excludes cookies from other-safari.com
  6.  Other domain isolated to exactly 1 cookie
  7.  Cookie field types correct (str/bool)
  8.  session_id: value, secure=True, http_only=True
  9.  csrf_token: value, secure=False, http_only=False, path=/api
  10. pref: value, flags both False
  11. Apple epoch → Unix timestamp conversion within tolerance
  12. source_browser is "safari" for all returned cookies
  13. Multi-page BinaryCookies file parsed correctly
  14. _parse_binary_cookies raises ValueError on invalid magic
  15. _parse_binary_cookies handles page with wrong page-magic gracefully
  16-20. All five output writers produce valid artefacts
  21. CLI --list flag exits 0 and prints known cookie names
  22. CLI graceful no-match exits 0 with 'No cookies found'
  23. extract_safari returns [] on non-macOS (mocked via monkeypatch)
  24. extract_safari returns [] when binarycookies file absent
"""

import io
import json
import os
import pickle
import platform
import struct
import subprocess
import sys
import time

import pytest

# ── Skip entire module on non-macOS ──────────────────────────────────────────
pytestmark = pytest.mark.skipif(
    platform.system() != "Darwin",
    reason="Safari BinaryCookies tests only run on macOS"
)

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import cookie_extractor as ce  # noqa: E402

TARGET_DOMAIN = "test.safari-example.com"
OTHER_DOMAIN  = "other-safari.com"
APPLE_EPOCH_OFFSET = 978_307_200


# ══════════════════════════════════════════════════════════════════════════════
#  Fixtures
# ══════════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def safari_cookies():
    cookies = ce.extract_safari(TARGET_DOMAIN)
    return cookies


@pytest.fixture(scope="module")
def all_raw_records():
    """All records from the seeded file, unfiltered."""
    path = os.path.expanduser("~/Library/Cookies/Cookies.binarycookies")
    return ce._parse_binary_cookies(path)


@pytest.fixture(scope="module")
def tmp_out(tmp_path_factory):
    return tmp_path_factory.mktemp("safari_output")


# ══════════════════════════════════════════════════════════════════════════════
#  1. Import smoke
# ══════════════════════════════════════════════════════════════════════════════

def test_module_imports():
    assert callable(ce.extract_safari)
    assert callable(ce._parse_binary_cookies)
    assert callable(ce._domain_matches)
    assert ce.Cookie is not None


# ══════════════════════════════════════════════════════════════════════════════
#  2. Raw parser returns all seeded records
# ══════════════════════════════════════════════════════════════════════════════

def test_parse_binary_cookies_total_count(all_raw_records):
    """Parser must return all 4 seeded cookies (3 + 1 excluded domain)."""
    assert len(all_raw_records) == 4, (
        f"Expected 4 raw records, got {len(all_raw_records)}: "
        f"{[r['name'] for r in all_raw_records]}"
    )


def test_parse_binary_cookies_all_names(all_raw_records):
    names = {r["name"] for r in all_raw_records}
    assert names == {"session_id", "csrf_token", "pref", "tracker"}


def test_parse_binary_cookies_fields_present(all_raw_records):
    required = {"name", "value", "domain", "path", "expires", "secure", "http_only"}
    for r in all_raw_records:
        assert required.issubset(r.keys()), f"Missing keys in: {r}"


# ══════════════════════════════════════════════════════════════════════════════
#  3–4. extract_safari count and names
# ══════════════════════════════════════════════════════════════════════════════

def test_safari_finds_cookies(safari_cookies):
    assert len(safari_cookies) > 0, (
        "extract_safari returned 0 — did seed_safari_cookies.py run?"
    )


def test_safari_expected_count(safari_cookies):
    assert len(safari_cookies) == 3, (
        f"Expected 3, got {len(safari_cookies)}: {[c.name for c in safari_cookies]}"
    )


def test_safari_known_names(safari_cookies):
    names = {c.name for c in safari_cookies}
    assert {"session_id", "csrf_token", "pref"} == names


# ══════════════════════════════════════════════════════════════════════════════
#  5–6. Domain filtering
# ══════════════════════════════════════════════════════════════════════════════

def test_safari_excludes_other_domain(safari_cookies):
    domains = {c.domain for c in safari_cookies}
    assert not any("other-safari.com" in d for d in domains), (
        f"other-safari.com leaked into results: {domains}"
    )


def test_safari_other_domain_isolated():
    cookies = ce.extract_safari(OTHER_DOMAIN)
    assert len(cookies) == 1
    assert cookies[0].name == "tracker"


# ══════════════════════════════════════════════════════════════════════════════
#  7. Field types
# ══════════════════════════════════════════════════════════════════════════════

def test_cookie_field_types(safari_cookies):
    for c in safari_cookies:
        assert isinstance(c.name,      str),  f"name not str: {c.name!r}"
        assert isinstance(c.value,     str),  f"value not str for {c.name!r}"
        assert isinstance(c.domain,    str),  f"domain not str"
        assert isinstance(c.path,      str),  f"path not str"
        assert isinstance(c.secure,    bool), f"secure not bool: {c.secure!r}"
        assert isinstance(c.http_only, bool), f"http_only not bool: {c.http_only!r}"
        assert c.source_browser == "safari",  f"wrong source_browser: {c.source_browser!r}"


# ══════════════════════════════════════════════════════════════════════════════
#  8. session_id cookie
# ══════════════════════════════════════════════════════════════════════════════

def test_session_id_values(safari_cookies):
    c = next((x for x in safari_cookies if x.name == "session_id"), None)
    assert c is not None
    assert c.value     == "safari-session-abc"
    assert c.secure    is True
    assert c.http_only is True
    assert c.path      == "/"
    assert c.domain    == "test.safari-example.com"


# ══════════════════════════════════════════════════════════════════════════════
#  9. csrf_token cookie
# ══════════════════════════════════════════════════════════════════════════════

def test_csrf_token_values(safari_cookies):
    c = next((x for x in safari_cookies if x.name == "csrf_token"), None)
    assert c is not None
    assert c.value     == "safari-csrf-xyz"
    assert c.secure    is False
    assert c.http_only is False
    assert c.path      == "/api"


# ══════════════════════════════════════════════════════════════════════════════
#  10. pref cookie
# ══════════════════════════════════════════════════════════════════════════════

def test_pref_values(safari_cookies):
    c = next((x for x in safari_cookies if x.name == "pref"), None)
    assert c is not None
    assert c.value     == "light-mode"
    assert c.secure    is False
    assert c.http_only is False


# ══════════════════════════════════════════════════════════════════════════════
#  11. Apple epoch → Unix timestamp conversion
# ══════════════════════════════════════════════════════════════════════════════

def test_apple_epoch_conversion(safari_cookies):
    """session_id has 1-day expiry; Unix timestamp must be within 30s of expected."""
    c = next((x for x in safari_cookies if x.name == "session_id"), None)
    assert c is not None and c.expires is not None
    expected = time.time() + 86_400
    assert abs(c.expires - expected) < 30, (
        f"Timestamp off: got {c.expires:.1f}, expected ~{expected:.1f}"
    )


def test_1hr_expiry_cookie(safari_cookies):
    """csrf_token has 1-hour expiry."""
    c = next((x for x in safari_cookies if x.name == "csrf_token"), None)
    assert c is not None and c.expires is not None
    expected = time.time() + 3_600
    assert abs(c.expires - expected) < 30


# ══════════════════════════════════════════════════════════════════════════════
#  12. source_browser field
# ══════════════════════════════════════════════════════════════════════════════

def test_source_browser_safari(safari_cookies):
    for c in safari_cookies:
        assert c.source_browser == "safari"


# ══════════════════════════════════════════════════════════════════════════════
#  13. Multi-page parsing
# ══════════════════════════════════════════════════════════════════════════════

def test_multipage_parsing(all_raw_records):
    """
    The seed puts 3 cookies in page 1 and 1 in page 2.
    All 4 must be returned, proving multi-page iteration works.
    """
    assert len(all_raw_records) == 4
    names = {r["name"] for r in all_raw_records}
    assert "tracker" in names   # from page 2


# ══════════════════════════════════════════════════════════════════════════════
#  14. Invalid magic raises ValueError
# ══════════════════════════════════════════════════════════════════════════════

def test_invalid_magic_raises(tmp_path):
    bad_file = tmp_path / "bad.binarycookies"
    bad_file.write_bytes(b"NOPE" + b"\x00" * 100)
    with pytest.raises(ValueError, match="Not a valid BinaryCookies file"):
        ce._parse_binary_cookies(str(bad_file))


# ══════════════════════════════════════════════════════════════════════════════
#  15. Wrong page magic skipped gracefully
# ══════════════════════════════════════════════════════════════════════════════

def test_wrong_page_magic_skipped(tmp_path):
    """
    A page with incorrect page-magic (not \\x00\\x00\\x01\\x00) must be
    skipped without raising, returning an empty list.
    """
    import struct as _s
    # Build a minimal file: valid file header, 1 page, wrong page magic
    bad_page = b"\xFF\xFF\xFF\xFF" + b"\x00" * 100   # wrong page magic
    data = (
        b"cook"
        + _s.pack(">I", 1)              # 1 page
        + _s.pack(">I", len(bad_page))  # page size
        + bad_page
    )
    f = tmp_path / "wrong_page.binarycookies"
    f.write_bytes(data)
    result = ce._parse_binary_cookies(str(f))
    assert result == [], f"Expected [], got {result}"


# ══════════════════════════════════════════════════════════════════════════════
#  16-20. Output writers
# ══════════════════════════════════════════════════════════════════════════════

def test_write_json_safari(safari_cookies, tmp_out):
    path = str(tmp_out / "safari.json")
    ce.write_json(safari_cookies, path)
    data = json.loads(open(path).read())
    assert len(data) == len(safari_cookies)
    required = {"name", "value", "domain", "path", "expires", "secure",
                "httpOnly", "sourceBrowser"}
    for entry in data:
        assert required.issubset(entry.keys())
    by_name = {e["name"]: e for e in data}
    assert by_name["session_id"]["value"]        == "safari-session-abc"
    assert by_name["session_id"]["secure"]       is True
    assert by_name["session_id"]["httpOnly"]     is True
    assert by_name["csrf_token"]["value"]        == "safari-csrf-xyz"
    assert by_name["csrf_token"]["secure"]       is False
    assert by_name["session_id"]["sourceBrowser"] == "safari"


def test_write_netscape_safari(safari_cookies, tmp_out):
    path = str(tmp_out / "safari.txt")
    ce.write_netscape(safari_cookies, path)
    content = open(path).read()
    assert "# Netscape HTTP Cookie File" in content
    lines = [l for l in content.splitlines() if l.strip() and not l.startswith("#")]
    assert len(lines) == len(safari_cookies)
    for line in lines:
        fields = line.split("\t")
        assert len(fields) == 7, f"Expected 7 fields: {line!r}"
        assert fields[2].startswith("/"),      f"Bad path: {fields[2]!r}"
        assert fields[3] in ("TRUE", "FALSE"), f"Bad SECURE: {fields[3]!r}"


def test_write_header_safari(safari_cookies, tmp_out):
    path = str(tmp_out / "safari.hdr")
    ce.write_header(safari_cookies, path)
    content = open(path).read()
    assert content.startswith("Cookie: ")
    header_val = content.splitlines()[0][len("Cookie: "):]
    pairs = dict(p.split("=", 1) for p in header_val.split("; ") if "=" in p)
    assert "session_id" in pairs
    assert pairs["session_id"] == "safari-session-abc"
    assert "csrf_token"  in pairs


def test_write_pickle_safari(safari_cookies, tmp_out):
    path = str(tmp_out / "safari.pkl")
    ce.write_pickle(safari_cookies, path)
    assert os.path.exists(path)
    with open(path, "rb") as f:
        loaded = pickle.load(f)
    import requests
    assert isinstance(loaded, (requests.Session, list))
    if isinstance(loaded, requests.Session):
        names = {c.name for c in loaded.cookies}
        assert "session_id" in names


def test_write_playwright_safari(safari_cookies, tmp_out):
    path = str(tmp_out / "safari.playwright.json")
    ce.write_playwright(safari_cookies, path)
    data = json.loads(open(path).read())
    assert "cookies" in data and "origins" in data
    assert len(data["cookies"]) == len(safari_cookies)
    valid_samesite = {"None", "Lax", "Strict"}
    for c in data["cookies"]:
        assert c["sameSite"] in valid_samesite
        assert isinstance(c["secure"],   bool)
        assert isinstance(c["httpOnly"], bool)
    pw = {c["name"]: c for c in data["cookies"]}
    assert pw["session_id"]["secure"]   is True
    assert pw["session_id"]["httpOnly"] is True
    assert pw["csrf_token"]["secure"]   is False


# ══════════════════════════════════════════════════════════════════════════════
#  21. CLI --list flag
# ══════════════════════════════════════════════════════════════════════════════

def test_cli_list_flag_safari():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", TARGET_DOMAIN, "--browser", "safari", "--list"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"Non-zero exit:\n{result.stderr}"
    assert "session_id" in result.stdout
    assert "csrf_token"  in result.stdout


# ══════════════════════════════════════════════════════════════════════════════
#  22. CLI graceful no-match
# ══════════════════════════════════════════════════════════════════════════════

def test_cli_no_match_safari():
    result = subprocess.run(
        [sys.executable, os.path.join(ROOT, "cookie_extractor.py"),
         "--domain", "nonexistent-xyz-123.io",
         "--browser", "safari", "--list"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, f"CLI crashed:\n{result.stderr}"
    assert "No cookies found" in result.stdout


# ══════════════════════════════════════════════════════════════════════════════
#  23. extract_safari returns [] on non-macOS (monkeypatched)
# ══════════════════════════════════════════════════════════════════════════════

def test_extract_safari_non_macos(monkeypatch, capsys):
    monkeypatch.setattr(ce.platform, "system", lambda: "Linux")
    result = ce.extract_safari(TARGET_DOMAIN)
    assert result == []
    captured = capsys.readouterr()
    assert "only available on macOS" in captured.err


# ══════════════════════════════════════════════════════════════════════════════
#  24. extract_safari returns [] when file absent
# ══════════════════════════════════════════════════════════════════════════════

def test_extract_safari_missing_file(monkeypatch, capsys):
    monkeypatch.setattr(ce, "SAFARI_COOKIE_PATH", "~/nonexistent/path/Cookies.binarycookies")
    result = ce.extract_safari(TARGET_DOMAIN)
    assert result == []
    captured = capsys.readouterr()
    assert "not found" in captured.err
