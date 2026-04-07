// background.js — Service Worker
// Handles cookie queries from the popup via chrome.runtime.onMessage

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "getCookies") {
    const { url, domain } = request;

    // Get all cookies matching the full URL (respects HttpOnly, secure, etc.)
    chrome.cookies.getAll({ url }, (urlCookies) => {
      // Also get cookies by domain to catch parent-domain cookies
      chrome.cookies.getAll({ domain }, (domainCookies) => {
        // Merge and deduplicate by name+domain+path
        const seen = new Map();
        [...urlCookies, ...domainCookies].forEach((c) => {
          const key = `${c.name}||${c.domain}||${c.path}`;
          if (!seen.has(key)) seen.set(key, c);
        });

        const cookies = Array.from(seen.values()).map((c) => ({
          name:         c.name,
          value:        c.value,
          domain:       c.domain,
          path:         c.path,
          expires:      c.expirationDate || null,
          expiresHuman: c.expirationDate
            ? new Date(c.expirationDate * 1000).toISOString()
            : "session",
          secure:       c.secure,
          httpOnly:     c.httpOnly,
          sameSite:     c.sameSite || "unspecified",
          session:      c.session,
        }));

        sendResponse({ cookies });
      });
    });

    return true; // keep channel open for async response
  }
});
