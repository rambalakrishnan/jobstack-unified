# MI (Pure Michigan Talent Connect) — reconnaissance findings

## What was found

- **Tier T1 wins.** `GET /job-search/` (form + `__VIEWSTATE` + cookies) → `POST /job-search/`
  (41-field WebForms postback, `submitBtn2=Search`) → 302 → `GET /job-seeker/jobsearch-results/`
  returns 200 + 25 server-rendered cards + total count. No browser, no JS, no antiforgery token.
  Source: `mi/REPORT.md` §Verdict + §Request Contract, `mi/scripts/probe_t1_replay.py`,
  `mi/samples/t1replay_results_page1_20261026T1920Z.html` (179,485 B, 25 cards, `txtJobCount`=61152).
- **No JSON/XHR feed exists.** Headless-Chromium netlog (105 records) shows zero data XHRs —
  only analytics beacons and one empty `FilterProfanity` ASMX call. The 331 KB JS bundle has no
  job-feed endpoint (`AutoComplete.asmx` / `JobDetails.aspx` web-methods only). HTML postback is
  the only tier; T2 does not exist. Source: `mi/samples/t3_netlog_20261026T191204Z.jsonl`,
  `mi/samples/t1_bundles_scripts_20261026.js`, `mi/scripts/probe_t3_intercept.py`.
- **`/search-results` is a dead end.** It is a Google Programmable Search wrapper
  (`cx=012737484712748150863:xgxosvm5d3i`, `.GSAResults`, `cse.google.com`), 87,209 B with zero job
  links — site search, not the job feed. Source: `mi/samples/t1_searchresults_20261026.html`.
- **Feed is session-stateful.** Fresh-session `GET /job-seeker/jobsearch-results/` → 302 back to
  `/job-search/` (114,585 B stub); query strings are ignored, criteria live server-side in
  `ASP.NET_SessionId`. Source: `mi/samples/t1replay_fresh_results_20261026T1920Z.html`,
  `mi/samples/t1replay_log_20261026T1920Z.txt` (probes 6–7).
- **Hard 25/page server cap.** `PageSizeTop=100` and `PageSizeBtm=100` postbacks both return exactly
  25 cards; the 50/100 `<select>` options are cosmetic. Full crawl ≈ 2,449 requests at 25/page.
  Source: `mi/samples/t1replay_pagesize_top100_20261026T1935Z.html`,
  `mi/samples/t1replay_pagesize100_20261026T1920Z.html`, `mi/scripts/probe_pagesize.py`.
- **Pager slots are a sliding window, not page numbers.** Five slots `pageTop1..5`; posting slot 5
  ("advance") moves `startIndexNum` 1→5→7 with rendered texts `1 2 3 4 »` → `« 4 5 6 »` →
  `« 6 7 8 »`. Read displayed text to know the target page. Source:
  `mi/samples/t1replay_pager_*.html`, `mi/scripts/probe_pager.py`.
- **Detail pages are cookie-bootstrapped HTML.** `GET /job-seeker/job-details/JobCode/{id}` with a
  primed jar returns ~150 KB full pages (verified: 414569021/22/24, fetched 19:59Z in the same
  session-block as the 19:58Z results page whose page-1 codes they are). A bare/direct attempt
  returned a Cloudflare "Sorry, you have been blocked" page (4,553 B). No fetching script exists
  in `scripts/` — provenance by timestamp correspondence only.
  Source: `mi/samples/detail_mi_httpx_*`, `mi/samples/detail_mi_one_20261026T195230Z.html`,
  `mi/samples/detail_mi_net_20261026T195729Z.json` (browser 200 for JobCode/389043045),
  `mi/samples/fresh_results_20261026T195827Z.html` (page-1 first codes 414569021/22/24).
  Tension: `mi/REPORT.md` §Transport states detail URLs were never fetched (robots) — these
  captures postdate that claim and are kept as evidence.
- **Ordering/counts observed (no verdict rendered — separate task).** Six 25-card captures:
  page-1 first codes t3/19:12Z 389043045, httpx/19:20Z 417418550, httpx/19:35Z 401481412...,
  httpx/19:45Z 413865470, httpx/19:58Z 414569021; pairwise page-1 overlaps all 0/25 except
  `page2_1920 × pager1_1945` = 2 codes. Totals drifted 61154 → 61152 → 61151 → 61149 → 61150
  across 19:12–19:58Z. Within-session page 1 × page 2 = 0 overlap. Computed from
  `mi/samples/t1replay_results_page{1,2}_*`, `t1replay_resultstop_*`, `t1replay_pager_page1_*`,
  `fresh_results_20261026T195827Z.html`, `t3_after_submit_20261026T191204Z.html`.
- **Bot posture**: Cloudflare + F5 BIG-IP + ASP.NET 4.0.30319; no JS challenge, no UA/TLS binding
  (curl/httpx/Chromium identical 200s), no throttling over ~55 requests at 1.5 s. `robots.txt`
  disallows `/job-seeker/job-details/` (+ "irresponsible" warning) and `/bot-trap/`; search routes
  not disallowed. ToS has no anti-automation clause. Source:
  `mi/samples/t0_robots_20261026.txt`, `mi/samples/t0_tos_terms_20261026.html`,
  `mi/samples/t1_searchresults_headers_20261026.txt`.
- Corpus ~61,150 live postings; full walk ≈ 2,449 sequential requests (~61 min at 1.5 s);
  concurrency 1 per session (`__VIEWSTATE` single-use, MAC-protected). `job_time_range` ∈
  {1,7,14,30} days is the incremental-crawl hook (unexercised). Source: `mi/REPORT.md`
  §Enumeration Strategy + §Module Design Notes.

## Sourced from

- `mi/REPORT.md` (contract), `mi/MANIFEST.md` (inventory; stale — omits `detail_mi_*` and
  `fresh_results_*` captures), `mi/data/probe.sqlite` (`postings` 75 rows from 3 source files,
  `meta` total_count=61154 — dumped, schema verified)
- `mi/scripts/`: `probe_t1_replay.py`, `probe_pagesize.py`, `probe_pager.py`, `mi_parse.py`,
  `parse_saved.py`, `probe_t3_intercept.py`
- `mi/samples/`: t0 discovery + false leads, t1replay winning path, pager semantics, t3 netlogs,
  unscripted `detail_mi_*` / `fresh_results_*` captures (19:52–19:59Z)
- `mi/mi_cookies.txt` (brittle curl jar — evidence only, expired)

## Still open

- Sort-postback (`PageSortTop` ∈ Posted/Title/OrgName/City) unexercised — cheapest next experiment.
  (`mi/REPORT.md` §Risks.4)
- Ordering stability beyond two consecutive pages unverified; deep-walk duplication risk is the top
  risk — verdict owned by a separate task, not rendered here. (`mi/REPORT.md` §Risks.1)
- Session idle timeout (~20 min hinted by `lblSecconds`/`IdleTimeForUser`) unmeasured; assume
  re-prime + restart, not resume. (`mi/REPORT.md` §Risks.2)
- F5 cookie necessity for sticky-session consistency untested in isolation. (`mi/REPORT.md` §Transport)
- `job_time_range` semantics (posted vs modified date; keyword interaction) untested. (`mi/REPORT.md` §Enumeration)
- `__RequestVerificationToken` cookie is *issued* but the working replay never sends it back —
  no endpoint observed requiring it. (`mi/samples/t1_searchresults_headers_20261026.txt`)
- Detail-fetch provenance: no script in `scripts/` performs the `detail_mi_*` fetches; exact
  request/cookie requirements reconstructed from samples only
  (`[uncertain: no fetching script; timestamp correspondence 19:58Z→19:59Z]`).
- Orphan citations: code `411083899` appears in `mi/REPORT.md` ordering table and the
  `scripts/mi_parse.py` docstring "verbatim excerpt" but in **no** `samples/*.html`;
  `414569018` appears only in `samples/t1replay_pagesize_top100_20261026T1935Z.html`, not in the
  19:35Z page-1 file the REPORT table implies.
- `t1replay_post_page1_20261026T1920Z.txt` contains 40 `k=v` lines vs the 41 fields claimed in
  `mi/REPORT.md` §R2 and the replay log (`[uncertain: one field indistinguishable — file is ground truth]`).
- No official partner/API or bulk feed checked. (`mi/REPORT.md` §Risks.8)
