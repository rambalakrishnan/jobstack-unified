# MI session

Source: `mi/REPORT.md` §Transport + §Feed Discovery, `mi/scripts/probe_t1_replay.py`,
`mi/samples/t1_searchresults_headers_20261026.txt`, `mi/mi_cookies.txt`.

- **Session = cookie jar + server-side search state.** First `GET /job-search/` (cookieless OK, no
  JS challenge) issues three cookies: `ASP.NET_SessionId` (the semantically required one — holds
  the search criteria), `BIGipServer~TED~HCV186TIAWPWA03_04_05_443_Pool` (F5 node pinning),
  `__cf_bm` (Cloudflare bot management). A fourth cookie, `__RequestVerificationToken`, is issued
  but the winning replay never sends it back — no endpoint observed requiring it.
- **Search state lives server-side.** R2 stores criteria in the session; nothing is passed in the
  URL, query strings on the results route are ignored, and a fresh session `GET` of the results
  URL 302s to `/job-search/` even with primed cookies (probes 6–7,
  `mi/samples/t1replay_fresh_results_20261026T1920Z.html`).
- **`__VIEWSTATE` is single-use and MAC-protected.** Always carry the newest blob forward; replaying
  an old one fails and naive parallel page fetching will 500. Every paging/sort/page-size postback
  must echo the full hidden field set from the immediately previous response.
- **F5 stickiness unisolated.** The F5 cookie was present in every successful replay; dropping it
  mid-crawl could silently move the session to a stateless node — keep the jar intact
  (`[uncertain: necessity not tested in isolation]`).
- **Idle timeout unmeasured.** Page exposes `Header1$lblSecconds` / `$IdleTimeForUser` hinting
  ~20 min; a 60-minute serial walk risks mid-crawl expiry — design assumption is re-prime +
  restart, never resume (`[uncertain: actual timeout value]`).
- **Request prep:** browser UA (Chrome/131 in the winning scripts), `Accept-Language:
  en-US,en;q=0.9`, `Referer` + `Origin` on POSTs, timeout 30 s, `follow_redirects=false`
  (assert the 302 explicitly), 1.5 s spacing, sequential only (concurrency 1 per session).
- **Fingerprint sensitivity low.** curl (HTTP/2), httpx (HTTP/1.1), Chromium all get identical
  200s with only a UA header; no JA3/JS challenge, no header-order sensitivity. No 429/403/503
  across ~55 sequential requests (one later bare detail attempt did hit a Cloudflare block page —
  `mi/samples/detail_mi_one_20261026T195230Z.html`).
- **302 handling:** 302 → `/job-search/` at any point = session lost → re-prime from R1 and treat
  as a fresh full pass (new session, new order). 200 with 0 cards = end of results or too-narrow
  filter. `cache-control: private,no-cache, no-store` — nothing is cacheable.
- **Robots:** `Disallow: /job-seeker/job-details/` (+ "irresponsible" warning) and `/bot-trap/`;
  several UA-specific `Disallow: /` + `Crawl-Delay: 1–30`. Search routes not disallowed. No ToS
  anti-scraping clause (`mi/samples/t0_tos_terms_20261026.html`). Detail captures exist despite
  the disallow (see `requests/detail.txt`) — counsel sign-off required before shipping them.
