#!/usr/bin/env python3
"""
seed_firefox_cookies.py
-----------------------
Creates a minimal Firefox profile with a pre-populated cookies.sqlite
so the CI test has real data to parse without needing a running browser.

Run before pytest:
    python tests/seed_firefox_cookies.py
"""

import os
import sqlite3
import time

PROFILE_DIR = os.path.expanduser("~/.mozilla/firefox/ci-test.default")
os.makedirs(PROFILE_DIR, exist_ok=True)

DB_PATH = os.path.join(PROFILE_DIR, "cookies.sqlite")

# Seed data: two cookies for test.example.com, one for other.com (should be excluded)
NOW = int(time.time())
COOKIES = [
    # (name, value, host, path, expiry, isSecure, isHttpOnly, sameSite)
    ("session_id",   "abc123",         ".test.example.com", "/",       NOW + 86400, 1, 1, 1),
    ("csrf_token",   "xyz789",         ".test.example.com", "/api",    NOW + 3600,  0, 0, 0),
    ("tracker",      "should-exclude", ".other.com",        "/",       NOW + 86400, 0, 0, 0),
    ("session_only", "no-expiry",      ".test.example.com", "/",       0,           1, 0, 2),
]

conn = sqlite3.connect(DB_PATH)
conn.execute("""
    CREATE TABLE IF NOT EXISTS moz_cookies (
        id          INTEGER PRIMARY KEY,
        name        TEXT,
        value       TEXT,
        host        TEXT,
        path        TEXT,
        expiry      INTEGER,
        isSecure    INTEGER,
        isHttpOnly  INTEGER,
        sameSite    INTEGER
    )
""")
conn.execute("DELETE FROM moz_cookies")  # clean slate on re-run
conn.executemany(
    "INSERT INTO moz_cookies (name, value, host, path, expiry, isSecure, isHttpOnly, sameSite) "
    "VALUES (?,?,?,?,?,?,?,?)",
    COOKIES,
)
conn.commit()
conn.close()

print(f"[seed] Firefox test profile created at: {PROFILE_DIR}")
print(f"[seed] Seeded {len(COOKIES)} cookies ({len(COOKIES)-1} for test.example.com, 1 excluded)")
