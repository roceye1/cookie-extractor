# 🍪 Cookie Extractor — Browser Extension

A Manifest V3 browser extension that extracts all cookies for the current tab and exports them in **5 formats** ready for automation pipelines. Works in Chrome, Brave, Edge, Chromium, and Firefox.

---

## One-line install

```bash
bash install.sh
```

That's it. The script auto-detects your browser, launches it with the extension loaded, and opens the extensions page so you can see it's active.

---

## Manual install (Chrome / Brave / Edge / Chromium)

1. Open `chrome://extensions/`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked**
4. Select this folder

## Manual install (Firefox)

```bash
npm install -g web-ext
web-ext run --source-dir=.
```

---

## Usage

1. Navigate to any website
2. Click the 🍪 icon in your toolbar (pin it via the puzzle-piece menu if needed)
3. All cookies for the current domain load instantly

### Tabs

| Tab | What it does |
|-----|-------------|
| **Cookies** | Browse all cookies, search by name/value, click any row to copy its value |
| **Export** | One-click copy or download in all 5 formats |
| **Raw JSON** | Full structured JSON — copy or download |

---

## Export Formats

| Format | File | Use with |
|--------|------|---------|
| JSON | `cookies_domain.json` | Any pipeline / inspection |
| Netscape/curl | `cookies_domain.txt` | `curl -b`, `wget --load-cookies` |
| HTTP Header | `cookies_domain.hdr` | Postman, `curl -H`, raw HTTP |
| Playwright storageState | `cookies_domain.playwright.json` | `browser.new_context(storage_state=…)` |
| Puppeteer / CDP | `cookies_domain.puppeteer.json` | `page.setCookie(…cookies)` |

---

## Files

```
manifest.json       Manifest V3 declaration
background.js       Service worker — chrome.cookies API
popup.html          Extension popup UI
popup.js            UI logic, formatters, export handlers
icons/              Extension icons (16, 32, 48, 128px)
install.sh          Automated installer for all browsers
```
