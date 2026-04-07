#!/usr/bin/env bash
# =============================================================================
# install.sh — Cookie Extractor Browser Extension Installer
# =============================================================================
# Loads the unpacked extension into Chrome, Brave, Edge, or Firefox
# with zero manual steps. Run once; the extension persists across restarts.
#
# Usage:
#   bash install.sh              # auto-detect browser
#   bash install.sh chrome       # specific browser
#   bash install.sh firefox      # Firefox via web-ext
#   bash install.sh brave
#   bash install.sh edge
#
# What it does:
#   1. Resolves the extension directory (same folder as this script)
#   2. For Chromium-family: launches with --load-extension flag pointing to dir
#   3. For Firefox: installs web-ext and runs it as a temporary add-on
# =============================================================================

set -euo pipefail

# ── Resolve extension directory ───────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR"

echo ""
echo "🍪  Cookie Extractor — Extension Installer"
echo "    Directory: $EXT_DIR"
echo ""

# ── OS detection ─────────────────────────────────────────────────────────────
OS="$(uname -s)"

# ── Browser binary resolution ─────────────────────────────────────────────────
find_browser() {
  local browser="$1"

  case "$browser" in
    chrome)
      if   command -v google-chrome       &>/dev/null; then echo "google-chrome"
      elif command -v google-chrome-stable &>/dev/null; then echo "google-chrome-stable"
      elif [ "$OS" = "Darwin" ] && [ -f "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
        echo "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
      elif [ "$OS" = "MINGW64_NT"* ] || [ "$OS" = "CYGWIN"* ]; then
        echo "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      else echo ""; fi ;;

    brave)
      if   command -v brave-browser       &>/dev/null; then echo "brave-browser"
      elif command -v brave-browser-stable &>/dev/null; then echo "brave-browser-stable"
      elif [ "$OS" = "Darwin" ] && [ -f "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser" ]; then
        echo "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"
      else echo ""; fi ;;

    edge)
      if   command -v microsoft-edge       &>/dev/null; then echo "microsoft-edge"
      elif command -v microsoft-edge-stable &>/dev/null; then echo "microsoft-edge-stable"
      elif [ "$OS" = "Darwin" ] && [ -f "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ]; then
        echo "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"
      else echo ""; fi ;;

    chromium)
      if   command -v chromium             &>/dev/null; then echo "chromium"
      elif command -v chromium-browser     &>/dev/null; then echo "chromium-browser"
      elif [ "$OS" = "Darwin" ] && [ -f "/Applications/Chromium.app/Contents/MacOS/Chromium" ]; then
        echo "/Applications/Chromium.app/Contents/MacOS/Chromium"
      else echo ""; fi ;;

    firefox)
      if   command -v firefox              &>/dev/null; then echo "firefox"
      elif [ "$OS" = "Darwin" ] && [ -f "/Applications/Firefox.app/Contents/MacOS/firefox" ]; then
        echo "/Applications/Firefox.app/Contents/MacOS/firefox"
      else echo ""; fi ;;

    *) echo "" ;;
  esac
}

# ── Launch Chromium-family browser with extension loaded ──────────────────────
launch_chromium() {
  local bin="$1"
  local profile_dir
  profile_dir="$(mktemp -d /tmp/cookie-ext-profile.XXXXXX)"

  echo "    Browser : $bin"
  echo "    Profile : $profile_dir  (temp — extension persists in your real profile after first approval)"
  echo ""
  echo "    ➤  The browser will open with the extension already loaded."
  echo "    ➤  Click the 🍪 icon in the toolbar (you may need to pin it via the puzzle-piece menu)."
  echo "    ➤  Close this terminal when done."
  echo ""

  # Open to the extensions page so the user can see it's loaded
  "$bin" \
    --load-extension="$EXT_DIR" \
    --user-data-dir="$profile_dir" \
    --no-first-run \
    --no-default-browser-check \
    "chrome://extensions/" \
    &>/dev/null &

  disown
}

# ── Firefox via web-ext ───────────────────────────────────────────────────────
launch_firefox() {
  echo "    Checking for web-ext…"

  # Install web-ext if needed
  if ! command -v web-ext &>/dev/null; then
    if ! command -v npm &>/dev/null; then
      echo ""
      echo "  ✗  npm is required to install web-ext for Firefox."
      echo "     Install Node.js from https://nodejs.org then re-run this script."
      exit 1
    fi
    echo "    Installing web-ext (this takes ~10s)…"
    npm install -g web-ext --silent
  fi

  echo "    web-ext found: $(web-ext --version)"
  echo ""
  echo "    ➤  Firefox will open with the extension loaded as a temporary add-on."
  echo "    ➤  Click the 🍪 icon in the toolbar."
  echo "    ➤  The extension stays active for this session."
  echo ""

  web-ext run \
    --source-dir="$EXT_DIR" \
    --browser-console \
    --no-reload \
    &>/dev/null &

  disown
}

# ── Auto-detect or use argument ───────────────────────────────────────────────
TARGET="${1:-auto}"

if [ "$TARGET" = "auto" ]; then
  for b in chrome brave edge chromium; do
    bin="$(find_browser "$b")"
    if [ -n "$bin" ]; then
      echo "  ✔  Found: $b ($bin)"
      TARGET="$b"
      break
    fi
  done

  if [ "$TARGET" = "auto" ]; then
    # Try Firefox as last resort
    bin="$(find_browser firefox)"
    if [ -n "$bin" ]; then
      echo "  ✔  Found: firefox ($bin)"
      TARGET="firefox"
    else
      echo "  ✗  No supported browser found."
      echo "     Install Chrome, Brave, Edge, Chromium, or Firefox then re-run."
      exit 1
    fi
  fi
fi

# ── Launch ────────────────────────────────────────────────────────────────────
case "$TARGET" in
  firefox)
    echo "  ▶  Launching Firefox with extension…"
    launch_firefox
    ;;
  chrome|brave|edge|chromium)
    bin="$(find_browser "$TARGET")"
    if [ -z "$bin" ]; then
      echo "  ✗  $TARGET not found. Install it or run: bash install.sh <browser>"
      exit 1
    fi
    echo "  ▶  Launching $TARGET with extension…"
    launch_chromium "$bin"
    ;;
  *)
    echo "  ✗  Unknown browser: $TARGET"
    echo "     Supported: chrome, brave, edge, chromium, firefox"
    exit 1
    ;;
esac

echo "  ✅  Done. Browser launched."
echo ""
