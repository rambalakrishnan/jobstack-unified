# MI pagination

Source: `mi/REPORT.md` §Request Contract (R4) + §Enumeration Strategy, `mi/scripts/probe_pager.py`,
`mi/scripts/probe_pagesize.py`, `mi/samples/t1replay_pager_*.html`,
`mi/samples/t1replay_pagesize{,_top}100_*.html`, `mi/samples/t1replay_results_page2_*.html`.

- **Mechanism:** WebForms postback, not URL offsets. `POST /job-seeker/jobsearch-results/` with the
  full hidden-field echo from the previous response and `__EVENTTARGET` set to a pager slot
  (`ctl00$MainContent$pageTop2..5` or `$pageBtm2..5` — top/bottom identical, verified by
  `probe_t1_replay.py` step 4 using `pageBtm2` → 200, 25 fresh cards, 0 overlap with page 1).
- **Page size: hard 25.** `PageSizeTop=100` and `PageSizeBtm=100` both return exactly 25 cards;
  the 50/100 `<select>` options are cosmetic. Full crawl = `ceil(total/25)` page postbacks.
- **Pager slots are a sliding window.** Five slots per pager; slot number ≠ page number. Measured
  chain (`startIndexNum` from `input#MainContent_startIndexNum`): page 1 → `1` (slots render
  `1 2 3 4 »`); post slot 5 → `5` (renders `« 4 5 6 »`); post slot 5 again → `7` (renders
  `« 6 7 8 »`). Verified programmatically against the three pager captures (numeric slot texts
  {2,3,4} → {4,6} → {6,8}). Rule: parse `ul.pagination` anchors, post the slot whose displayed
  text == `startIndexNum+1`; if no slot shows it, post slot 5 ("advance") and re-read.
- **Ordering (observed, no verdict):** within-session page 1 × page 2 = 0/25 overlap (coherent
  first hop); across independent sessions page-1 overlap is 0/25 in 14 of 15 computed pairs
  (one pair shares 2 codes); totals drifted live (61154→61149 over ~45 min). See README.
- **No partitioning proven.** No facet/count endpoint exists (see `requests/facet.txt`); the only
  narrowing hooks are unexercised R2 filter fields (`job_time_range`, keyword). A full crawl is a
  single ~2,447-page sequential walk — `[uncertain: deep-walk (25+) stability unmeasured]`.
- **Stop rule:** stop when `page * 25 >= txtJobCount`, or a page returns 0 cards, or a page's job
  codes are a subset of already-held codes (`mi/REPORT.md` §Enumeration).
- **Resume:** persist `(ASP.NET_SessionId, __VIEWSTATE, startIndexNum)`; the session IS the cursor.
  If the session dies (302 → `/job-search/`), re-prime from R1 — but the new session orders
  differently, so treat it as a fresh full pass, never a mid-walk resume.
- **Incremental:** `job_time_range` ∈ {1,7,14,30} days (posted-within) is the recommended production
  shape (daily `time_range=1` instead of a 2,447-page walk) — `[uncertain: filter semantics
  untested; posted-vs-modified unknown]`.
- **Cost:** 3 priming + `ceil(61152/25)-1 = 2446` page postbacks ≈ **2,449 requests**, strictly
  sequential (each page's `__VIEWSTATE` comes from the previous response), ~61 min at 1.5 s.
