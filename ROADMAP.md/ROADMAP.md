# MTProto Proxy Store — Roadmap & Feature Proposals

This document records the bugs and security issues fixed in v2025.2 and proposes the
next steps for the project.

---

## 1. Bugs fixed in this release

| # | Bug | Impact | Fix |
|---|-----|--------|-----|
| 1 | `stream_select()` was called with `$read = null`. PHP requires a variable for the read set; the old code fatally errored or silently mis-detected every proxy. | Connectivity results were wrong. | Correct `stream_select($read, $write, $except, ...)` call. |
| 2 | `socket_get_option($sock, ...)` used a stream resource, not a `Socket` object (PHP 8). | Fatal `TypeError` mid-scan, JSON never written. | Replaced with a `fread()` probe: `false` = refused, anything else = online. |
| 3 | `dd` secret check required length 32, but a real `dd` secret is 34 hex chars. | All valid `dd` (Secure/FakeTLS) proxies were silently dropped. | Correct validation: plain = 32, `dd` = 34, `ee` = ≥34 and even. |
| 4 | Type detection compared the secret against `'dd'`/`'ee'` after it was already lowercased, but the template matched `'Secured'`/`'TLS'` while the scanner emitted `'MTProto Secure'`/`'MTProto TLS'`. | Every card rendered with the wrong badge colour/type. | Single `detectType()` returning `MTProto` / `Secure` / `TLS`, matched in the template. |
| 5 | `fread()` was used to decide online/offline; a TLS endpoint that accepts but sends nothing returns `''`, which is truthy but the old `!== false` check was inconsistent. | Flapping online/offline status. | Explicit `fread(...) !== false` semantics, documented in code. |
| 6 | `usort()` with a non-total comparator (`-1/1/0` only) plus `?? 9999` | Inconsistent ordering. | Total-order comparator with `PHP_INT_MAX`. |
| 7 | `file_put_contents` wrote directly to the served file. | GitHub Pages could serve a truncated file during a push. | Atomic write via temp file + `rename()`. |
| 8 | No cap on the number of proxies checked. | A channel spamming links could make the scan run for many minutes. | `max_per_scan` cap (400). |
| 9 | `fetchChannels` never checked the HTTP status code. | A 404/rate-limit page was parsed as if it were content. | Response code checked, failures logged as warnings. |
| 10 | Server names kept a trailing dot (`Rudmoain.co.uk.`) and control chars. | Broken links and inconsistent de-duplication. | `sanitizeServer()` strips them and lowercases. |
| 11 | `?scan=1` triggered a full rescan on every request with no limit. | Trivial DoS / GitHub Actions abuse. | 60-second minimum gap between web-triggered scans. |
| 12 | Scan failure threw and left `extracted_proxies.json` unwritten. | Site went stale/blank. | `try/catch`, falls back to the last good JSON. |

## 2. Security issues fixed

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| S1 | **Reflected XSS** — `$proxy['server']`, `type` and `tg_url` were echoed into HTML attributes and text without escaping. A channel could publish a proxy whose "server" is `"><script>…</script>` and execute JS in every visitor's browser. | High | Every echo uses `htmlspecialchars(..., ENT_QUOTES, 'UTF-8')`; the JSON island is encoded with `JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT`. |
| S2 | **SSRF** — the scanner opened TCP connections to whatever host a channel supplied, including `127.0.0.1`, `169.254.169.254` (cloud metadata) and private ranges. | High | `isPublicHost()` / `isPublicIp()` reject private and reserved ranges (`FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE`) before connecting. |
| S3 | **TLS verification disabled** — `CURLOPT_SSL_VERIFYPEER => false` allowed a MITM to inject proxies. | High | Verification enabled (`VERIFYPEER=true`, `VERIFYHOST=2`). |
| S4 | **No Content-Security-Policy** — any injected script ran unrestricted. | Medium | CSP added: no `default-src`, scripts/styles limited to self + jsDelivr, `connect-src 'none'`, `base-uri 'none'`, `form-action 'none'`. |
| S5 | **Unvalidated input** — usernames, ports and secrets were passed through with loose checks. | Medium | Usernames must match `^[A-Za-z0-9_]{3,64}$`; ports must be 1–65535; secrets must be hex with a valid length. |
| S6 | **Supply chain** — `cdn.tailwindcss.com` (unpinned "latest") and a deprecated QR library. | Medium | Pinned Tailwind `@tailwindcss/browser@4.1.12` and `qrcode-generator@1.4.4` on jsDelivr; workflow actions pinned to major versions with a PHP syntax gate. |
| S7 | **Missing HTTP hardening** — no `referrer` policy, channel content fetched over an unconstrained protocol. | Low | `referrer: no-referrer` meta tag; cURL restricted to `CURLPROTO_HTTPS`. |
| S8 | **Workflow races** — scheduled and push runs could force-push over each other. | Low | Added `concurrency` group and a generated-output sanity check. |

> Note: the proxy secrets themselves are public by design (they come from public
> Telegram channels), so they are not treated as credentials.

---

## 3. Proposed next features

### Near term (small, high value)
1. **Real MTProto handshake health check** — the current check only proves a TCP
   connect. Sending a valid `req_pq_multi` and reading the `resPQ` response would
   prove the endpoint is actually a working MTProto proxy, not a web server on
   port 443.
2. **Historical uptime** — append each scan result to a rolling 24h/7d history and
   show an uptime percentage per proxy. Cheap: one JSON file per day.
3. **Sponsor / country flags** — geo-locate each server IP and show a flag plus
   the round-trip latency from multiple regions.
4. **Favourites & sort options** — let visitors pin proxies in `localStorage` and
   sort by latency / uptime / type.
5. **Dark/light toggle** and a proper `manifest.json` + service worker so the page
   installs as a PWA and works offline with the last-known list.

### Medium term
6. **Move the scan out of the page request path** — keep the GitHub Action as the
   only scanner and make `index.html` a static asset that fetches
   `extracted_proxies.json`. This removes PHP execution from the web tier entirely
   and removes the `?scan=1` attack surface.
7. **Structured source registry** — a `sources.json` with channel URL, trust
   score, and last-success timestamp, so unreliable channels can be disabled
   without editing code.
8. **Deduplication across channels with conflict resolution** — when the same
   `server:port` appears with different secrets, prefer the one from the
   higher-trust channel and record both.
9. **Automated tests** — PHPUnit cases for `cleanSecret()`, `sanitizeServer()`,
   `detectType()` and `extractProxies()` using fixture HTML; a GitHub Action that
   runs them on every push.
10. **Alerts** — post to a Telegram channel or GitHub Issue when the online count
    drops below a threshold (a signal that scraping broke or channels went dark).

### Long term
11. **Multi-region scanning** — run the connectivity check from 3–4 GitHub runners
    in different regions and publish the best latency per region.
12. **API endpoint** — publish `api.json` with CORS enabled so other apps can
    consume the list, with a documented schema and rate-limit guidance.
13. **Reputation scoring** — combine uptime, latency stability and channel trust
    into a single score, and warn users about proxies that have appeared only
    recently.
14. **Privacy note / disclaimer page** — MTProto proxies can see metadata; a clear
    explanation builds trust and reduces misuse.

---

## 4. Suggested file layout after the refactor

```
extract_proxies.php      # scanner (CLI + optional web trigger)
template.html            # view template (escaped output only)
usernames.json           # channel list
sources.json             # (new) channel metadata + trust scores
extracted_proxies.json   # generated data (served)
index.html               # generated page (served)
history/YYYY-MM-DD.json  # (new) rolling uptime history
tests/                   # (new) PHPUnit fixtures
.github/workflows/       # scan + test workflows
```
