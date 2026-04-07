# 🍪 cookie_extractor

A cross-platform Python script to extract cookies from **Chrome**, **Firefox**, and **Safari** for any domain you choose — and export them in **5 formats** ready for automation pipelines.

---

## Features

- Supports **Chrome**, **Brave**, **Edge**, **Chromium**, **Firefox**, and **Safari**
- Runs on **macOS**, **Linux**, and **Windows**
- Decrypts Chrome's AES-encrypted cookie values automatically
- Parses Safari's binary `.binarycookies` format natively
- Deduplicates across browsers
- Exports in **5 formats**: JSON, Netscape/curl, HTTP header, Requests pickle, Playwright storageState

---

## Installation

**Requirements:** Python 3.8+

```bash
git clone https://github.com/YOUR_USERNAME/cookie-extractor.git
cd cookie-extractor
```

Install optional dependencies (recommended for Chrome cookie decryption):

```bash
pip install pycryptodome requests
```

> Without `pycryptodome`, Chrome cookie values stored in encrypted form will be flagged as `<encrypted>` but the script will still run and export all other data.

---

## Browser Support

| Browser | Platform | Cookie Storage | Encryption |
|---------|----------|----------------|------------|
| Chrome | macOS, Linux, Windows | SQLite (`Cookies`) | AES-CBC (macOS/Linux), AES-GCM DPAPI (Windows) |
| Brave | macOS, Linux, Windows | SQLite (`Cookies`) | Same as Chrome |
| Microsoft Edge | macOS, Linux, Windows | SQLite (`Cookies`) | Same as Chrome |
| Chromium | macOS, Linux, Windows | SQLite (`Cookies`) | Same as Chrome |
| Firefox | macOS, Linux, Windows | SQLite (`cookies.sqlite`) | None (plaintext) |
| Safari | macOS only | `Cookies.binarycookies` | None (plaintext) |

> **Tip:** Close Chrome/Edge/Brave before running — they lock the SQLite DB. Firefox and Safari can be open.

---

## Usage

```bash
python cookie_extractor.py --domain <domain> [options]
```

### Options

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--domain` | `-d` | *(required)* | Target domain, e.g. `github.com` |
| `--browser` | `-b` | `all` | `chrome`, `firefox`, `safari`, or `all` |
| `--format` | `-f` | all formats | `json`, `netscape`, `header`, `pickle`, `playwright` |
| `--output` | `-o` | `.` (current dir) | Output directory |
| `--list` | `-l` | — | Preview cookies without writing files |

### Examples

```bash
# Extract from all browsers for github.com (all formats)
python cookie_extractor.py --domain github.com

# Chrome and Firefox only
python cookie_extractor.py --domain google.com --browser chrome firefox

# Specific formats only
python cookie_extractor.py --domain example.com --format json playwright

# Preview without writing
python cookie_extractor.py --domain example.com --list

# Custom output directory
python cookie_extractor.py --domain example.com --output ./pipeline/cookies
```

---

## Output Formats

All files are named `cookies_<domain>.<ext>`. Running against `github.com` produces:

```
cookies_github_com.json
cookies_github_com.txt
cookies_github_com.hdr
cookies_github_com.pkl
cookies_github_com.playwright.json
```

---

### 1. JSON (`.json`)

Full structured data — best for inspection, logging, or custom pipeline ingestion.

```json
[
  {
    "name": "user_session",
    "value": "abc123xyz",
    "domain": ".github.com",
    "path": "/",
    "expires": 1780000000,
    "expires_human": "2026-05-01T00:00:00Z",
    "secure": true,
    "httpOnly": true,
    "sameSite": "lax",
    "sourceBrowser": "chrome"
  }
]
```

**Use in Python:**
```python
import json

with open("cookies_github_com.json") as f:
    cookies = json.load(f)

for c in cookies:
    print(c["name"], "=", c["value"])
```

---

### 2. Netscape/curl format (`.txt`)

Standard Netscape cookie file — compatible with `curl`, `wget`, and Python's `http.cookiejar`.

```
# Netscape HTTP Cookie File
.github.com    TRUE    /    TRUE    1780000000    user_session    abc123xyz
.github.com    TRUE    /    FALSE   1780000000    _octo           GH1.1.123456789
```

**Use with curl:**
```bash
curl -b cookies_github_com.txt https://github.com/settings
```

**Use with wget:**
```bash
wget --load-cookies cookies_github_com.txt https://github.com/settings
```

**Use with Python http.cookiejar:**
```python
import requests
from http.cookiejar import MozillaCookieJar

jar = MozillaCookieJar("cookies_github_com.txt")
jar.load(ignore_discard=True, ignore_expires=True)

session = requests.Session()
session.cookies = jar
r = session.get("https://github.com/settings")
```

---

### 3. HTTP Header (`.hdr`)

Raw `Cookie:` header string — paste directly into Postman, Insomnia, or any HTTP client.

```
Cookie: user_session=abc123xyz; _octo=GH1.1.123456789; logged_in=yes
```

**Use with curl:**
```bash
curl -H "Cookie: user_session=abc123xyz; _octo=GH1.1.123456789" https://github.com/settings
```

**Use with Python requests:**
```python
import requests

with open("cookies_github_com.hdr") as f:
    header_line = f.readline().strip()  # "Cookie: ..."

headers = {"Cookie": header_line.split(": ", 1)[1]}
r = requests.get("https://github.com/settings", headers=headers)
```

---

### 4. Requests Session Pickle (`.pkl`)

A serialized `requests.Session` with the cookie jar pre-loaded — zero setup required.

**Use:**
```python
import pickle
import requests

with open("cookies_github_com.pkl", "rb") as f:
    session = pickle.load(f)

# Authenticated session — cookies are already attached
r = session.get("https://github.com/settings")
print(r.status_code)
```

> Requires `requests` to be installed: `pip install requests`

---

### 5. Playwright storageState (`.playwright.json`)

Playwright's native `storageState` format — pass directly to `new_context()` or `add_cookies()`.

```json
{
  "cookies": [
    {
      "name": "user_session",
      "value": "abc123xyz",
      "domain": "github.com",
      "path": "/",
      "secure": true,
      "httpOnly": true,
      "sameSite": "Lax",
      "expires": 1780000000
    }
  ],
  "origins": []
}
```

**Use with Playwright (Python):**
```python
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch()

    # Option A: pass at context creation
    context = browser.new_context(
        storage_state="cookies_github_com.playwright.json"
    )

    # Option B: add cookies to existing context
    with open("cookies_github_com.playwright.json") as f:
        import json
        state = json.load(f)
    context.add_cookies(state["cookies"])

    page = context.new_page()
    page.goto("https://github.com/settings")
    print(page.title())
```

**Use with Playwright (JavaScript/Node):**
```javascript
const { chromium } = require('playwright');

const browser = await chromium.launch();
const context = await browser.newContext({
  storageState: 'cookies_github_com.playwright.json'
});
const page = await context.newPage();
await page.goto('https://github.com/settings');
```

---

## Platform Notes

### macOS — Chrome decryption
The script reads the AES key from your macOS Keychain (`Chrome Safe Storage`). You may see a Keychain permission prompt — click **Allow**. This is needed to decrypt cookie values in Chrome 80+.

### Windows — Chrome decryption
Decryption uses Windows DPAPI and the `Local State` app-bound key automatically. Must run as the same Windows user account that owns the browser profile.

### Linux — Chrome decryption
Uses a fixed PBKDF2 key derivation (`peanuts` / `saltysalt`), which works for standard Chromium installs. Snap/Flatpak Chrome variants may use different key storage — install `secretstorage` (`pip install secretstorage`) if values come up empty.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `<encrypted — install pycryptodome>` | Run `pip install pycryptodome` |
| `0 cookies found` for Chrome | Close Chrome before running |
| `No Firefox cookies.sqlite found` | Ensure Firefox has been launched at least once |
| Safari returns no cookies | Run on macOS; grant Full Disk Access to Terminal in System Preferences |
| Windows: `<decryption_failed>` | Run the script as the same user account that uses Chrome |

---

## License

MIT
