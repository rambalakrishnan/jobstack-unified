# IL session

Source: `il/REPORT.md` §Transport, `il/scripts/t1_dummy_cookie.py`, `t2_cookie_replay.py`, `t3_browser_probe.py`.

- **Session = one `_session_id` cookie, any 32-hex value** (verified incl. all-zeros; `foo=bar` still 202s). No state carried — looks like WAF misconfiguration.
- **Server rotation:** fresh dummy values get answered with a real `Set-Cookie: _session_id=<32 hex>; path=/; secure; httponly`. Keep a jar; dummy keeps working regardless.
- **`aws-waf-token` is NOT decisive** (token alone → 202; session alone → 200). Don't bother harvesting it.
- **No UA/TLS binding:** token replays across Chrome 120↔141, HTTP/1.1 vs browser stacks. HTTP/2 untested (no h2 lib) — site doesn't care about 1.1.
- **202 handling:** no-cookie or wrong-cookie requests get 202 + `x-amzn-waf-action: challenge` (0-byte curl body, 2,011-byte challenge HTML with `Accept:`). Re-prime with `GET /`, retry once, then escalate to browser harvest (proven: headless Chromium self-solves in 1.19 s, cookies replay from httpx).
- **Request prep:** `User-Agent: Chrome/141…`, `Accept-Language: en-US,en;q=0.9`, timeout 25 s, no redirects, 1.5 s spacing, ≤60 requests/domain discipline.
- **Lifetime unknown:** single ~15-min session; one 4-day token expiry observed (`[uncertain: session lifetime unmeasured]`). No throttling/429s/bans seen.
- **Scope:** challenge applies ONLY to `/search/*` (root, robots, detail, privacy all 200 unchallenged). No login anywhere in the crawl path.
- **Robots:** `Disallow: /search/jobs` + `/search/resumes` — the feed itself. No ToS anti-scraping clause found. Rate-limit + identify in production.
