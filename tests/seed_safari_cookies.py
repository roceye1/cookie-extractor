#!/usr/bin/env python3
"""
seed_safari_cookies.py
----------------------
Generates a syntactically valid Apple BinaryCookies file at
~/Library/Cookies/Cookies.binarycookies so that CI tests have
real binary data to parse without needing a running Safari instance.

Format reference (reverse-engineered):
  File header
    [0:4]   b"cook"           magic
    [4:8]   >I               number of pages
    [8:8+4*N] >I * N         page sizes (big-endian)

  Per page
    [0:4]   b"\x00\x00\x01\x00"  page magic
    [4:8]   <I               number of cookies
    [8:8+4*N] <I * N         cookie offsets from page start (little-endian)
    [data]  cookie records

  Per cookie record (offsets from record start, little-endian)
    [0:4]   <I  record size
    [4:8]   <I  unknown (0)
    [8:12]  <I  flags  (0x1=Secure, 0x4=HttpOnly)
    [12:16] <I  unknown (0)
    [16:20] <I  url_offset    (offset of domain string from record start)
    [20:24] <I  name_offset
    [24:28] <I  path_offset
    [28:32] <I  value_offset
    [32:40] 8 bytes padding/unknown
    [40:48] <d  expiry  (seconds since 2001-01-01 as float64)
    [48:56] <d  creation (seconds since 2001-01-01 as float64)
    [56+]   NUL-terminated UTF-8 strings: domain, name, path, value
            in the order url→name→path→value (offsets define order)

Run before pytest:
    python tests/seed_safari_cookies.py
"""

import os
import struct
import time

APPLE_EPOCH_OFFSET = 978_307_200  # seconds between 1970-01-01 and 2001-01-01
NOW_APPLE = time.time() - APPLE_EPOCH_OFFSET


def _build_cookie_record(
    domain: str,
    name: str,
    path: str,
    value: str,
    expiry_apple: float,  # seconds since 2001-01-01
    secure: bool = False,
    http_only: bool = False,
) -> bytes:
    """
    Build a single cookie record as raw bytes matching the BinaryCookies layout
    expected by _parse_binary_cookies().
    """
    flags = 0
    if secure:
        flags |= 0x1
    if http_only:
        flags |= 0x4

    # Strings follow the fixed 56-byte header, in this order: domain name path value
    # Each is NUL-terminated UTF-8.
    domain_b = domain.encode("utf-8") + b"\x00"
    name_b   = name.encode("utf-8")   + b"\x00"
    path_b   = path.encode("utf-8")   + b"\x00"
    value_b  = value.encode("utf-8")  + b"\x00"

    # Fixed header is 56 bytes; strings start immediately after.
    header_size = 56
    url_off   = header_size                            # domain first
    name_off  = url_off  + len(domain_b)
    path_off  = name_off + len(name_b)
    value_off = path_off + len(path_b)

    total_size = header_size + len(domain_b) + len(name_b) + len(path_b) + len(value_b)

    header = struct.pack(
        "<IIII IIII 8x dd",
        total_size,       # [0:4]   record size
        0,                # [4:8]   unknown
        flags,            # [8:12]  flags
        0,                # [12:16] unknown
        url_off,          # [16:20] domain offset
        name_off,         # [20:24] name offset
        path_off,         # [24:28] path offset
        value_off,        # [28:32] value offset
        # [32:40] 8 bytes of padding handled by "8x"
        expiry_apple,     # [40:48] expiry float64
        NOW_APPLE,        # [48:56] creation float64
    )

    return header + domain_b + name_b + path_b + value_b


def _build_page(cookie_records: list[bytes]) -> bytes:
    """
    Wrap a list of cookie record bytes into a BinaryCookies page.
    """
    page_magic   = b"\x00\x00\x01\x00"
    num_cookies  = len(cookie_records)

    # Offset table: each entry is 4 bytes, starts after magic(4) + count(4) + offsets(4*N)
    offset_table_size = 4 * num_cookies
    header_size = 4 + 4 + offset_table_size   # magic + count + offset table

    offsets = []
    pos = header_size
    for rec in cookie_records:
        offsets.append(pos)
        pos += len(rec)

    page = page_magic
    page += struct.pack("<I", num_cookies)
    for off in offsets:
        page += struct.pack("<I", off)
    for rec in cookie_records:
        page += rec

    return page


def build_binary_cookies(pages: list[bytes]) -> bytes:
    """
    Assemble the full BinaryCookies file from a list of page blobs.
    """
    file_magic = b"cook"
    num_pages  = len(pages)

    header = file_magic + struct.pack(">I", num_pages)
    for page in pages:
        header += struct.pack(">I", len(page))

    return header + b"".join(pages)


# ── Seed data ─────────────────────────────────────────────────────────────────
#
# Three cookies for test.safari-example.com, one for excluded other-safari.com.
# Expiry is Apple-epoch float (seconds since 2001-01-01).

EXPIRY_1DAY  = NOW_APPLE + 86_400
EXPIRY_1HR   = NOW_APPLE + 3_600
EXPIRY_FAR   = NOW_APPLE + 86_400 * 30

SEED_COOKIES = [
    # (domain, name, path, value, expiry_apple, secure, http_only)
    ("test.safari-example.com", "session_id",   "/",    "safari-session-abc", EXPIRY_1DAY, True,  True),
    ("test.safari-example.com", "csrf_token",   "/api", "safari-csrf-xyz",    EXPIRY_1HR,  False, False),
    ("test.safari-example.com", "pref",         "/",    "light-mode",         EXPIRY_FAR,  False, False),
    # excluded domain — must not appear in test.safari-example.com queries
    ("other-safari.com",        "tracker",      "/",    "should-be-excluded", EXPIRY_1DAY, False, False),
]

records = [_build_cookie_record(*c) for c in SEED_COOKIES]

# Put the first three in page 1, the excluded one in page 2
# to exercise multi-page parsing.
page1 = _build_page(records[:3])
page2 = _build_page(records[3:])
binary = build_binary_cookies([page1, page2])

# ── Write file ────────────────────────────────────────────────────────────────

COOKIE_DIR  = os.path.expanduser("~/Library/Cookies")
COOKIE_PATH = os.path.join(COOKIE_DIR, "Cookies.binarycookies")

os.makedirs(COOKIE_DIR, exist_ok=True)
with open(COOKIE_PATH, "wb") as f:
    f.write(binary)

print(f"[seed-safari] Written : {COOKIE_PATH}")
print(f"[seed-safari] Pages   : 2")
print(f"[seed-safari] Cookies : {len(SEED_COOKIES)} total")
print(f"[seed-safari]   session_id → secure + httpOnly, 1-day expiry")
print(f"[seed-safari]   csrf_token → not-secure, /api path, 1-hour expiry")
print(f"[seed-safari]   pref       → not-secure, 30-day expiry")
print(f"[seed-safari]   tracker    → excluded domain (other-safari.com, page 2)")
