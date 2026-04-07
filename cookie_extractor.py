#!/usr/bin/env python3
"""
cookie_extractor.py
-------------------
Extract cookies from Chrome, Firefox, and Safari for a specific domain.

Outputs:
  - JSON           (.json)
  - Netscape/curl  (.txt)  — compatible with wget --load-cookies, curl -b
  - HTTP Header    (.hdr)  — raw Cookie: header string
  - Requests dict  (.pkl)  — Python requests-compatible pickle

Usage:
  python cookie_extractor.py --domain example.com
  python cookie_extractor.py --domain example.com --browser chrome
  python cookie_extractor.py --domain example.com --browser all --format json netscape header
  python cookie_extractor.py --domain example.com --output ./my_cookies
"""

import os
import sys
import glob
import json
import copy
import shutil
import struct
import sqlite3
import pickle
import argparse
import platform
import tempfile
import datetime
from pathlib import Path
from typing import List, Dict, Optional, Any


# ─────────────────────────────────────────────
#  Data model
# ─────────────────────────────────────────────

class Cookie:
    def __init__(self, name: str, value: str, domain: str, path: str,
                 expires: Optional[float], secure: bool, http_only: bool,
                 same_site: str = "", source_browser: str = ""):
        self.name = name
        self.value = value
        self.domain = domain
        self.path = path
        self.expires = expires          # Unix timestamp or None
        self.secure = secure
        self.http_only = http_only
        self.same_site = same_site
        self.source_browser = source_browser

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "domain": self.domain,
            "path": self.path,
            "expires": self.expires,
            "expires_human": (
                datetime.datetime.utcfromtimestamp(self.expires).isoformat() + "Z"
                if self.expires and self.expires > 0 else "session"
            ),
            "secure": self.secure,
            "httpOnly": self.http_only,
            "sameSite": self.same_site,
            "sourceBrowser": self.source_browser,
        }


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _safe_copy_db(src: str) -> str:
    """Copy a locked SQLite DB to a temp file so we can read it."""
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
    tmp.close()
    shutil.copy2(src, tmp.name)
    return tmp.name


def _domain_matches(cookie_domain: str, target: str) -> bool:
    """Check if cookie_domain covers the target domain."""
    cd = cookie_domain.lstrip(".")
    return cd == target or target.endswith("." + cd) or cd.endswith("." + target)


# ─────────────────────────────────────────────
#  Chrome / Chromium / Edge / Brave  (SQLite + optional AES decrypt)
# ─────────────────────────────────────────────

CHROME_PROFILES = {
    "Darwin": [
        "~/Library/Application Support/Google/Chrome/Default/Cookies",
        "~/Library/Application Support/Google/Chrome/Profile */Cookies",
        "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
        "~/Library/Application Support/Microsoft Edge/Default/Cookies",
        "~/Library/Application Support/Chromium/Default/Cookies",
    ],
    "Linux": [
        "~/.config/google-chrome/Default/Cookies",
        "~/.config/google-chrome/Profile */Cookies",
        "~/.config/chromium/Default/Cookies",
        "~/.config/BraveSoftware/Brave-Browser/Default/Cookies",
        "~/.config/microsoft-edge/Default/Cookies",
    ],
    "Windows": [
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Cookies",
        r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Network\Cookies",
        r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Cookies",
        r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Cookies",
        r"%LOCALAPPDATA%\Chromium\User Data\Default\Cookies",
    ],
}


def _decrypt_chrome_value(encrypted_value: bytes, os_name: str) -> str:
    """Decrypt Chrome's encrypted cookie value. Falls back to empty string on failure."""
    if not encrypted_value:
        return ""

    # v10/v11 prefix on macOS/Linux → AES-CBC with PBKDF2 key
    if os_name in ("Darwin", "Linux") and encrypted_value[:3] in (b"v10", b"v11"):
        try:
            from Crypto.Cipher import AES
            import hashlib, hmac as _hmac

            if os_name == "Darwin":
                # macOS Keychain
                try:
                    import subprocess
                    result = subprocess.run(
                        ["security", "find-generic-password",
                         "-w", "-a", "Chrome", "-s", "Chrome Safe Storage"],
                        capture_output=True, text=True, timeout=5
                    )
                    password = result.stdout.strip().encode()
                except Exception:
                    password = b"peanuts"
                iterations = 1003
            else:
                password = b"peanuts"
                iterations = 1

            key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", iterations, dklen=16)
            iv = b" " * 16
            cipher = AES.new(key, AES.MODE_CBC, IV=iv)
            decrypted = cipher.decrypt(encrypted_value[3:])
            # Remove PKCS7 padding
            pad_len = decrypted[-1]
            return decrypted[:-pad_len].decode("utf-8", errors="replace")
        except ImportError:
            return "<encrypted — install pycryptodome to decrypt>"
        except Exception:
            return "<decryption_failed>"

    # Windows DPAPI / v10 prefix
    if os_name == "Windows" and encrypted_value[:3] == b"v10":
        try:
            import win32crypt  # type: ignore
            import json as _json, base64 as _b64

            # Try app-bound encryption key first
            local_state_path = Path(os.environ.get("LOCALAPPDATA", "")) / \
                "Google/Chrome/User Data/Local State"
            if local_state_path.exists():
                with open(local_state_path, encoding="utf-8") as f:
                    local_state = _json.load(f)
                enc_key = _b64.b64decode(
                    local_state["os_crypt"]["encrypted_key"])[5:]
                key = win32crypt.CryptUnprotectData(enc_key, None, None, None, 0)[1]
                from Crypto.Cipher import AES
                nonce = encrypted_value[3:15]
                ciphertext = encrypted_value[15:-16]
                tag = encrypted_value[-16:]
                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                return cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            import win32crypt  # type: ignore
            return win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)[1].decode("utf-8")
        except Exception:
            return "<encrypted — run as same Windows user>"

    # Unencrypted
    try:
        return encrypted_value.decode("utf-8", errors="replace")
    except Exception:
        return ""


def extract_chrome(domain: str) -> List[Cookie]:
    os_name = platform.system()
    patterns = CHROME_PROFILES.get(os_name, [])
    cookies: List[Cookie] = []
    seen_paths = set()

    for pattern in patterns:
        expanded = os.path.expandvars(os.path.expanduser(pattern))
        for db_path in glob.glob(expanded):
            if db_path in seen_paths or not os.path.exists(db_path):
                continue
            seen_paths.add(db_path)

            tmp = _safe_copy_db(db_path)
            try:
                conn = sqlite3.connect(tmp)
                conn.row_factory = sqlite3.Row
                cur = conn.cursor()

                # Schema differs between older and newer Chrome
                try:
                    cur.execute("""
                        SELECT name, encrypted_value, host_key, path,
                               expires_utc, is_secure, is_httponly, samesite
                        FROM cookies
                    """)
                except sqlite3.OperationalError:
                    cur.execute("""
                        SELECT name, encrypted_value, host_key, path,
                               expires_utc, secure, httponly, samesite
                        FROM cookies
                    """)

                for row in cur.fetchall():
                    if not _domain_matches(row["host_key"], domain):
                        continue
                    value = _decrypt_chrome_value(bytes(row["encrypted_value"]), os_name)
                    # Chrome stores time as microseconds since 1601-01-01
                    exp_us = row["expires_utc"]
                    if exp_us and exp_us > 0:
                        exp_unix = (exp_us / 1_000_000) - 11644473600
                    else:
                        exp_unix = None

                    samesite_map = {-1: "unspecified", 0: "no_restriction", 1: "lax", 2: "strict"}
                    ss_val = row["samesite"] if row["samesite"] is not None else -1
                    samesite = samesite_map.get(ss_val, str(ss_val))

                    cookies.append(Cookie(
                        name=row["name"],
                        value=value,
                        domain=row["host_key"],
                        path=row["path"],
                        expires=exp_unix,
                        secure=bool(row[5]),
                        http_only=bool(row[6]),
                        same_site=samesite,
                        source_browser="chrome",
                    ))
                conn.close()
            except Exception as e:
                print(f"  [!] Chrome DB error ({db_path}): {e}", file=sys.stderr)
            finally:
                os.unlink(tmp)

    return cookies


# ─────────────────────────────────────────────
#  Firefox
# ─────────────────────────────────────────────

FIREFOX_PROFILES = {
    "Darwin": "~/Library/Application Support/Firefox/Profiles",
    "Linux":  "~/.mozilla/firefox",
    "Windows": r"%APPDATA%\Mozilla\Firefox\Profiles",
}


def extract_firefox(domain: str) -> List[Cookie]:
    os_name = platform.system()
    base = os.path.expandvars(os.path.expanduser(
        FIREFOX_PROFILES.get(os_name, "~/.mozilla/firefox")
    ))
    cookies: List[Cookie] = []

    cookie_dbs = glob.glob(os.path.join(base, "*/cookies.sqlite"))
    if not cookie_dbs:
        print("  [!] No Firefox cookies.sqlite found.", file=sys.stderr)
        return cookies

    for db_path in cookie_dbs:
        tmp = _safe_copy_db(db_path)
        try:
            conn = sqlite3.connect(tmp)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""
                SELECT name, value, host, path,
                       expiry, isSecure, isHttpOnly, sameSite
                FROM moz_cookies
            """)
            for row in cur.fetchall():
                if not _domain_matches(row["host"], domain):
                    continue
                samesite_map = {0: "no_restriction", 1: "lax", 2: "strict"}
                ss_val = row["sameSite"] if row["sameSite"] is not None else 0
                cookies.append(Cookie(
                    name=row["name"],
                    value=row["value"],
                    domain=row["host"],
                    path=row["path"],
                    expires=float(row["expiry"]) if row["expiry"] else None,
                    secure=bool(row["isSecure"]),
                    http_only=bool(row["isHttpOnly"]),
                    same_site=samesite_map.get(ss_val, str(ss_val)),
                    source_browser="firefox",
                ))
            conn.close()
        except Exception as e:
            print(f"  [!] Firefox DB error ({db_path}): {e}", file=sys.stderr)
        finally:
            os.unlink(tmp)

    return cookies


# ─────────────────────────────────────────────
#  Safari (macOS only — BinaryCookies format)
# ─────────────────────────────────────────────

SAFARI_COOKIE_PATH = "~/Library/Cookies/Cookies.binarycookies"


def _parse_binary_cookies(path: str) -> List[Dict]:
    """Parse Apple's BinaryCookies format."""
    results = []
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != b"cook":
            raise ValueError("Not a valid BinaryCookies file")

        num_pages = struct.unpack(">I", f.read(4))[0]
        page_sizes = [struct.unpack(">I", f.read(4))[0] for _ in range(num_pages)]

        for page_size in page_sizes:
            page = f.read(page_size)
            if page[:4] != b"\x00\x00\x01\x00":
                continue
            num_cookies = struct.unpack("<I", page[4:8])[0]
            offsets = [struct.unpack("<I", page[8 + i*4: 12 + i*4])[0]
                       for i in range(num_cookies)]

            for offset in offsets:
                try:
                    cookie_size = struct.unpack("<I", page[offset:offset+4])[0]
                    flags = struct.unpack("<I", page[offset+8:offset+12])[0]
                    url_offset   = struct.unpack("<I", page[offset+16:offset+20])[0]
                    name_offset  = struct.unpack("<I", page[offset+20:offset+24])[0]
                    path_offset  = struct.unpack("<I", page[offset+24:offset+28])[0]
                    value_offset = struct.unpack("<I", page[offset+28:offset+32])[0]
                    # Expiry: 8-byte float, Apple epoch (Jan 1 2001)
                    expiry_raw = struct.unpack("<d", page[offset+40:offset+48])[0]
                    expiry_unix = expiry_raw + 978307200  # seconds from 2001 to 1970

                    def read_str(base_offset):
                        start = offset + base_offset
                        end = page.index(b"\x00", start)
                        return page[start:end].decode("utf-8", errors="replace")

                    domain = read_str(url_offset)
                    name   = read_str(name_offset)
                    path   = read_str(path_offset)
                    value  = read_str(value_offset)
                    secure    = bool(flags & 0x1)
                    http_only = bool(flags & 0x4)

                    results.append({
                        "name": name, "value": value, "domain": domain,
                        "path": path, "expires": expiry_unix,
                        "secure": secure, "http_only": http_only,
                    })
                except Exception:
                    continue
    return results


def extract_safari(domain: str) -> List[Cookie]:
    if platform.system() != "Darwin":
        print("  [!] Safari cookies are only available on macOS.", file=sys.stderr)
        return []

    path = os.path.expanduser(SAFARI_COOKIE_PATH)
    if not os.path.exists(path):
        print(f"  [!] Safari cookie file not found: {path}", file=sys.stderr)
        return []

    cookies: List[Cookie] = []
    try:
        raw = _parse_binary_cookies(path)
        for r in raw:
            if not _domain_matches(r["domain"], domain):
                continue
            cookies.append(Cookie(
                name=r["name"],
                value=r["value"],
                domain=r["domain"],
                path=r["path"],
                expires=r["expires"],
                secure=r["secure"],
                http_only=r["http_only"],
                source_browser="safari",
            ))
    except Exception as e:
        print(f"  [!] Safari parse error: {e}", file=sys.stderr)

    return cookies


# ─────────────────────────────────────────────
#  Output formatters
# ─────────────────────────────────────────────

def write_json(cookies: List[Cookie], out_path: str):
    data = [c.to_dict() for c in cookies]
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  ✔  JSON          → {out_path}")


def write_netscape(cookies: List[Cookie], out_path: str):
    """
    Netscape/Mozilla format — compatible with:
      curl -b cookies.txt
      wget --load-cookies cookies.txt
      requests with http.cookiejar
    """
    lines = ["# Netscape HTTP Cookie File",
             "# Generated by cookie_extractor.py",
             "# https://curl.se/docs/http-cookies.html",
             ""]
    for c in cookies:
        domain = c.domain if c.domain.startswith(".") else "." + c.domain
        include_subdomains = "TRUE" if c.domain.startswith(".") else "FALSE"
        secure = "TRUE" if c.secure else "FALSE"
        exp = int(c.expires) if c.expires and c.expires > 0 else 0
        lines.append(
            f"{domain}\t{include_subdomains}\t{c.path}\t{secure}\t{exp}\t{c.name}\t{c.value}"
        )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"  ✔  Netscape/curl → {out_path}")


def write_header(cookies: List[Cookie], out_path: str):
    """
    Raw HTTP Cookie header — paste directly into curl -H, Postman, etc.
    Also writes a curl command example.
    """
    header_value = "; ".join(f"{c.name}={c.value}" for c in cookies)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("Cookie: " + header_value + "\n\n")
        f.write("# curl example:\n")
        f.write(f'# curl -H "Cookie: {header_value}" https://YOURDOMAIN.com\n\n')
        f.write("# Python requests example:\n")
        f.write('# headers = {"Cookie": "' + header_value.replace('"', '\\"') + '"}\n')
        f.write('# response = requests.get("https://YOURDOMAIN.com", headers=headers)\n')
    print(f"  ✔  HTTP header   → {out_path}")


def write_pickle(cookies: List[Cookie], out_path: str):
    """
    Python requests.Session-compatible cookie jar (pickle).
    Load with:
        import pickle, requests
        with open("cookies.pkl", "rb") as f:
            session = pickle.load(f)
        response = session.get("https://example.com")
    """
    try:
        import requests
        from requests.cookies import RequestsCookieJar
        jar = RequestsCookieJar()
        for c in cookies:
            jar.set(
                c.name, c.value,
                domain=c.domain.lstrip("."),
                path=c.path,
            )
        session = requests.Session()
        session.cookies = jar
        with open(out_path, "wb") as f:
            pickle.dump(session, f)
        print(f"  ✔  Requests pkl  → {out_path}")
    except ImportError:
        # Fallback: just pickle the list of dicts
        data = [c.to_dict() for c in cookies]
        with open(out_path, "wb") as f:
            pickle.dump(data, f)
        print(f"  ✔  Dict pkl      → {out_path}  (requests not installed; saved as list of dicts)")


def write_playwright(cookies: List[Cookie], out_path: str):
    """
    Playwright storageState format — use with:
        page.context().add_cookies(cookies)
        or pass storage_state= to browser.new_context()
    """
    pw_cookies = []
    for c in cookies:
        entry = {
            "name": c.name,
            "value": c.value,
            "domain": c.domain.lstrip("."),
            "path": c.path,
            "secure": c.secure,
            "httpOnly": c.http_only,
            "sameSite": {
                "no_restriction": "None",
                "lax": "Lax",
                "strict": "Strict",
            }.get(c.same_site, "None"),
        }
        if c.expires and c.expires > 0:
            entry["expires"] = c.expires
        pw_cookies.append(entry)

    storage_state = {"cookies": pw_cookies, "origins": []}
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(storage_state, f, indent=2)
    print(f"  ✔  Playwright    → {out_path}")


# ─────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────

FORMAT_WRITERS = {
    "json":       (write_json,       ".json"),
    "netscape":   (write_netscape,   ".txt"),
    "header":     (write_header,     ".hdr"),
    "pickle":     (write_pickle,     ".pkl"),
    "playwright": (write_playwright, ".playwright.json"),
}

BROWSER_EXTRACTORS = {
    "chrome":  extract_chrome,
    "firefox": extract_firefox,
    "safari":  extract_safari,
}


def main():
    parser = argparse.ArgumentParser(
        description="Extract browser cookies for a domain and export in multiple formats.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cookie_extractor.py --domain github.com
  python cookie_extractor.py --domain google.com --browser chrome firefox
  python cookie_extractor.py --domain example.com --format json netscape header playwright
  python cookie_extractor.py --domain example.com --output ./exported_cookies
        """
    )
    parser.add_argument("--domain", "-d", required=True,
                        help="Target domain (e.g. github.com or .github.com)")
    parser.add_argument("--browser", "-b", nargs="+",
                        choices=["chrome", "firefox", "safari", "all"],
                        default=["all"],
                        help="Browser(s) to extract from (default: all)")
    parser.add_argument("--format", "-f", nargs="+",
                        choices=list(FORMAT_WRITERS.keys()),
                        default=list(FORMAT_WRITERS.keys()),
                        help="Output format(s) (default: all)")
    parser.add_argument("--output", "-o", default=".",
                        help="Output directory (default: current directory)")
    parser.add_argument("--list", "-l", action="store_true",
                        help="List found cookies without writing files")
    args = parser.parse_args()

    domain = args.domain.lstrip(".")
    os.makedirs(args.output, exist_ok=True)

    browsers = (list(BROWSER_EXTRACTORS.keys())
                if "all" in args.browser else args.browser)

    print(f"\n🍪  Cookie Extractor")
    print(f"    Domain  : {domain}")
    print(f"    Browsers: {', '.join(browsers)}")
    print(f"    Formats : {', '.join(args.format)}")
    print(f"    Output  : {os.path.abspath(args.output)}\n")

    all_cookies: List[Cookie] = []
    for browser in browsers:
        print(f"[*] Scanning {browser}...")
        extractor = BROWSER_EXTRACTORS[browser]
        found = extractor(domain)
        print(f"    Found {len(found)} cookie(s)")
        all_cookies.extend(found)

    # Deduplicate by (name, domain, path) — prefer later browser if duplicate
    seen = {}
    for c in all_cookies:
        key = (c.name, c.domain, c.path)
        seen[key] = c
    cookies = list(seen.values())

    print(f"\n[*] Total unique cookies: {len(cookies)}")

    if not cookies:
        print("\n  ⚠  No cookies found for this domain.")
        print("  Make sure the browser is closed (or use --browser firefox which")
        print("  doesn't lock the DB), and that you've visited the domain recently.\n")
        return

    if args.list:
        print("\nCookies found:\n")
        for c in cookies:
            exp = (datetime.datetime.utcfromtimestamp(c.expires).strftime("%Y-%m-%d")
                   if c.expires and c.expires > 0 else "session")
            print(f"  [{c.source_browser:8s}] {c.name:40s} = {c.value[:40]}{'...' if len(c.value) > 40 else ''}")
            print(f"             domain={c.domain}  path={c.path}  expires={exp}  secure={c.secure}")
        print()
        return

    # Write output files
    safe_domain = domain.replace(".", "_")
    print("\n[*] Writing output files...\n")
    for fmt in args.format:
        writer, ext = FORMAT_WRITERS[fmt]
        out_path = os.path.join(args.output, f"cookies_{safe_domain}{ext}")
        try:
            writer(cookies, out_path)
        except Exception as e:
            print(f"  [!] Failed to write {fmt}: {e}", file=sys.stderr)

    print(f"\n✅  Done. {len(cookies)} cookie(s) exported to: {os.path.abspath(args.output)}\n")

    # Usage tips
    safe_domain_hdr = domain
    print("─" * 60)
    print("Quick usage tips:\n")
    print(f"  curl (Netscape):  curl -b cookies_{safe_domain}.txt https://{domain}")
    print(f"  curl (header):    curl -H \"$(head -1 cookies_{safe_domain}.hdr)\" https://{domain}")
    print(f"  wget:             wget --load-cookies cookies_{safe_domain}.txt https://{domain}")
    print(f"  Python requests:")
    print(f"      import pickle, requests")
    print(f"      session = pickle.load(open('cookies_{safe_domain}.pkl','rb'))")
    print(f"      r = session.get('https://{domain}')")
    print(f"  Playwright:")
    print(f"      context = browser.new_context(storage_state='cookies_{safe_domain}.playwright.json')")
    print("─" * 60 + "\n")


if __name__ == "__main__":
    main()
