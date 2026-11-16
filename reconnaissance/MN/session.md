# MN session

Source: `mn/REPORT.md` §Transport & Bot Posture + §Tier Ladder, `mn/scripts/probe_*.py`, `mn/samples/t0_feed_page0_20261026T191021Z.headers`, `mn/samples/t0_403_limitparam_20261026T200500Z.html`.

- **Session = none.** Stateless-per-request `GET`; no cookie, token, handshake, or priming required. A cookie-less first request returns full content.
- **One required header: browser-like `User-Agent`.** Full Chrome 131 UA → 200 on ~40/40 requests. Bare `curl` UA → 403 + 118 B empty body; truncated `Mozilla/5.0 Chrome/131` UA → 403 + 520 B on some requests. `Accept: text/html` optional.
- **403s are transient and UA-correlated, not an IP ban:** the identical URL re-fetched 20 s later with a full UA returned 200 in the same session. On 403: fix the UA, back off 30 s, never retry-storm.
- **AWS ALB stickiness:** origin sets `AWSALB`/`AWSALBCORS` (issued, not demanded). Keep one cookie jar per crawl for sticky-target consistency; measured content identical either way.
- **Not required:** `X-Requested-With`, `Referer`, `Origin`, CSRF, login. No JA3/header-order sensitivity observed (HTTP/2 negotiated; `fpcheck` not run).
- **Request prep:** full Chrome UA, timeout 30 s, follow redirects, 1.5 s spacing, ≤60 requests/domain discipline. Safe concurrency 2–3 workers on distinct cities, 1 s delay each.
- **No throttling observed:** ~48 sequential requests, zero 429s. Latency 0.15–0.35 s/page; 105–170 KB/page.
- **Response headers of interest:** `cache-control: max-age=300, public`; `x-drupal-dynamic-cache: UNCACHEABLE`; `vary: Cookie,Accept-Encoding,User-Agent`; `x-generator: Drupal 11`; `server: Apache`.
- **Robots:** `Disallow: /job-search` and `/job-search/` for `User-agent: *` — the feed itself is off-limits. No ToS/automated-access statement exists on the host (footer nav + full site index searched). Compliance, not technical posture, is the blocker.
