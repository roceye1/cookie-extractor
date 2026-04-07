#!/usr/bin/env python3
"""
seed_chrome_cookies.py
----------------------
Creates a Chromium-style Cookies SQLite DB at the Linux profile path
(~/.config/chromium/Default/Cookies) with deterministic test data.

Three value types are seeded to exercise every decryption branch:

  1. Plaintext          — raw UTF-8 bytes, no prefix     → decoded as-is
  2. v10-AES encrypted  — "v10" + AES-CBC ciphertext     → decrypted with
                          PBKDF2(peanuts/saltysalt, 1 iter) on Linux
  3. Empty              — b""                             → returns ""

Timestamps use the Chrome epoch: microseconds since 1601-01-01 UTC.
  Unix ts → Chrome ts:  (unix + 11644473600) * 1_000_000

Run before pytest:
    python tests/seed_chrome_cookies.py
"""

import hashlib
import os
import sqlite3
import struct
import time

# ── Encryption helper (mirrors _decrypt_chrome_value Linux branch) ────────────

def _encrypt_v10(plaintext: str) -> bytes:
    """Produce a v10-prefixed AES-CBC blob, matching Chrome's Linux scheme."""
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad

    password   = b"peanuts"
    salt       = b"saltysalt"
    iterations = 1
    key = hashlib.pbkdf2_hmac("sha1", password, salt, iterations, dklen=16)
    iv  = b" " * 16

    cipher     = AES.new(key, AES.MODE_CBC, IV=iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), AES.block_size))
    return b"v10" + ciphertext


# ── Chrome epoch conversion ───────────────────────────────────────────────────

def _unix_to_chrome(unix_ts: int) -> int:
    return (unix_ts + 11_644_473_600) * 1_000_000


NOW        = int(time.time())
CHROME_NOW = _unix_to_chrome(NOW + 86_400)   # 1 day from now
CHROME_EXP = _unix_to_chrome(NOW + 3_600)    # 1 hour from now

# ── Profile / DB path ─────────────────────────────────────────────────────────

PROFILE_DIR = os.path.expanduser("~/.config/chromium/Default")
os.makedirs(PROFILE_DIR, exist_ok=True)
DB_PATH = os.path.join(PROFILE_DIR, "Cookies")

# ── Seed rows ─────────────────────────────────────────────────────────────────
#
# Schema matches both Chrome column-name variants; we use is_secure/is_httponly
# (newer Chrome). The extractor falls back to secure/httponly if needed.
#
# Columns: name, encrypted_value, host_key, path, expires_utc,
#          is_secure, is_httponly, samesite
#
# samesite: -1=unspecified  0=no_restriction  1=lax  2=strict

ROWS = [
    # ── test.chrome-example.com cookies ──────────────────────────────────────
    (
        "session_id",
        _encrypt_v10("chrome-session-abc"),   # v10 encrypted
        ".test.chrome-example.com",
        "/",
        CHROME_NOW,
        1, 1, 1,                              # secure, httpOnly, samesite=lax
    ),
    (
        "csrf_token",
        b"plaintext-csrf-xyz",               # plaintext (no prefix)
        ".test.chrome-example.com",
        "/api",
        CHROME_EXP,
        0, 0, 0,                              # not secure, not httpOnly, no_restriction
    ),
    (
        "pref",
        _encrypt_v10("dark-mode"),            # v10 encrypted
        ".test.chrome-example.com",
        "/",
        CHROME_NOW,
        0, 0, 2,                              # samesite=strict
    ),
    (
        "session_only",
        b"",                                  # empty value edge-case
        ".test.chrome-example.com",
        "/",
        0,                                    # session cookie (no expiry)
        1, 0, -1,
    ),
    # ── other.com cookie — must be excluded from test.chrome-example.com query
    (
        "tracker",
        b"should-be-excluded",
        ".other-chrome.com",
        "/",
        CHROME_NOW,
        0, 0, 0,
    ),
]

conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS cookies (
        name            TEXT,
        encrypted_value BLOB,
        host_key        TEXT,
        path            TEXT,
        expires_utc     INTEGER,
        is_secure       INTEGER,
        is_httponly     INTEGER,
        samesite        INTEGER
    )
""")
conn.execute("DELETE FROM cookies")
conn.executemany(
    "INSERT INTO cookies "
    "(name, encrypted_value, host_key, path, expires_utc, is_secure, is_httponly, samesite) "
    "VALUES (?,?,?,?,?,?,?,?)",
    ROWS,
)
conn.commit()
conn.close()

print(f"[seed-chrome] Profile dir : {PROFILE_DIR}")
print(f"[seed-chrome] DB          : {DB_PATH}")
print(f"[seed-chrome] Rows seeded : {len(ROWS)} ({len(ROWS)-1} for test.chrome-example.com, 1 excluded)")
print(f"[seed-chrome]   session_id  → v10-AES encrypted")
print(f"[seed-chrome]   csrf_token  → plaintext bytes")
print(f"[seed-chrome]   pref        → v10-AES encrypted")
print(f"[seed-chrome]   session_only→ empty value / session cookie")
print(f"[seed-chrome]   tracker     → excluded domain (other-chrome.com)")
