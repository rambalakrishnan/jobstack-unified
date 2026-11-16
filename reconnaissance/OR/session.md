# OR session

Source: `or/REPORT.md` §Transport & Bot Posture + §Tier Ladder, `or/scripts/t3_browser_bootstrap.py`,
`t4_stealth_probe.py`, `t4_uaoverride_probe.py`, `t2_bootstrap_and_replay.py`,
`t1_session_crawl.py`, `t2_cookie_replay.py`, `or/samples/session_20261026T191747Z/`,
`or/samples/t4*.json`.

- **Model: T3 bootstrap once → T1 crawl.** One headless-Chromium pass (UA + UA-CH
  consistent, Chrome/151) clears the F5 volt-adc challenge and mints the jar; all crawl
  traffic is plain `httpx` over HTTP/1.1 with that jar in ONE stateful client.
- **The jar (5 cookies, from `or/samples/session_20261026T191747Z/00_cookies.json`):**
  `CFID` (6 chars, HttpOnly Secure Lax, +1 day, ColdFusion session), `CFTOKEN`
  (52 chars, same flags/expiry), `TS01dc4fc6` (106 chars, HttpOnly Secure Strict,
  session, F5 BIG-IP ASM), `Lyp1CWKh` (88 chars, volt-adc, ~1 yr),
  `OClmoOot` (481 chars, volt-adc, ~1 yr nominal — **rotated via Set-Cookie on EVERY
  response**). No tokens, no viewstate, no CSRF field. Single `httpx.Client`, never a
  per-request copy of a frozen dict.
- **Snapshot vs session (decisive):** frozen-cookie replay fails — 4/4 variants
  (cookie only / +UA / +CH / +ISTL headers) re-challenged, and a snapshot died after
  ~3 requests. A stateful client persisting `Set-Cookie` rotation survived 4–6
  consecutive requests. `[uncertain: long-run jar lifetime unmeasured — longest chain
  6 requests / ~1 min.]`
- **The gate is UA/CH consistency:** default headless (`sec-ch-ua:
  "HeadlessChrome";v="151"` vs `user-agent: … Chrome/131`) → 1,581 B block notice;
  `channel="chromium"` alone (still HeadlessChrome UA) → BLOCKED; CDP
  `Emulation.setUserAgentOverride` with UA + `userAgentMetadata` (`"Google
  Chrome";v="151"`) → app, no other change. Header order, HTTP/2-vs-1.1, and TLS
  fingerprint were NOT decisive (crawl ran HTTP/1.1 from httpx).
- **Challenge shape (for detectors):** 244–250 KB obfuscated JS (`<title></title>`,
  `fromCharCode`, `Uint8Array`, 0 links); computes a browser signature into
  `localStorage['yT5fcM@4GfJ$Dum358SM8hW^ffLBgJ']` (1 h expiry), re-requests with
  `ISTL-INFINITE-LOOP: 1` + dynamic `xa4vrhyp3q-*` headers. All statuses are 200 —
  **judge by body**: 244–250 KB = challenge, 1,581 B starting `Please advise your
  users` = WAF block, 15–30 KB+ = app, ~15 KB `search criteria was not valid` = bad
  partition (do not retry).
- **Failure handling:** body >200 KB with `Uint8Array` → re-bootstrap (cheap: 1 Chromium
  launch ≈ 8–10 s + ~10 asset requests); `Please advise your users` → WAF block, back
  off + re-bootstrap with a fresh UA/CH pair; `Reached limit:` → split partition (see
  `pagination.md`), never retry as-is. One jar = one rotation chain: parallelise via N
  bootstrap+client pairs (3–4 safe), 1.2–1.5 s jitter between requests. No 429/403 seen
  in 22 instrumented GETs (~40 s wall); fragility is state-based, not rate-based.
- **Request prep:** Chrome/151 UA + matching `sec-ch-ua`/`sec-ch-ua-mobile`/
  `sec-ch-ua-platform`, `Accept-Language: en-US,en;q=0.9`, timeout 30 s, follow
  redirects. Single-IP testing only (`[uncertain: IP/UA binding of the jar untested]`).
- **Robots:** `User-agent: * → Disallow: /` + block-page CFAA language — prohibited by
  policy (see `README.md`). No login anywhere in the legitimate crawl path; the only
  credential-adjacent surface (SSN fields) belongs to the prohibited write and is out
  of scope.
