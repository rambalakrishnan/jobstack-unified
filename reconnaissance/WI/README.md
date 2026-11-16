# WI (Job Center of Wisconsin) — reconnaissance findings

## What was found

- **Tier T0 wins for page 1; T1 postback chain for pages 2..N.** `GET /Presentation/JobSeekers/JobOrderList.aspx` with **no query string, no cookies** returns 200 + 20 rows of the unfiltered statewide list. Paging is a WebForms `__EVENTTARGET`/`__EVENTARGUMENT=Page$N` POST carrying the previous page's `__VIEWSTATE`. Source: `wi/REPORT.md` §Verdict + §Tier Ladder, `wi/scripts/14_minimal_qs.py`, `wi/samples/t0_page1_verified_*`, `wi/samples/t0_minimal_qs_*`.
- **Viewstate is NOT session-bound.** The same paging POST from a fresh cookie-less client returns page 2 with rows/pager/viewstate identical to the in-session POST (only the `WebResource.axd?...&t=` render timestamp differs). Source: `wi/scripts/04_postback_page.py`, `wi/samples/t1_page2_session_*` vs `t1_page2_stateless_*` (diffed during extraction).
- **Chained paging proven:** page 11's harvested viewstate POSTs page 12 from a fresh client (`Page 12` marker, new IDs `004063xxx`). Only pager-advertised pages are accepted; anything else (13/15/17/20/24/25/26 probed) returns **HTTP 200 + 39,459 B "System Error" page**. Source: `wi/scripts/10_chained_paging.py`, `wi/samples/t1_chain_from11_p12_*`, `wi/samples/t1_page11_*`, `wi/scripts/07_paging_depth.py`, `08_page_blocks_and_detail.py`, `09_page_breakpoint.py`.
- **Hard 500-row / 25-page cap per query**, announced by `500+ Jobs Found` + the `Label_TooManyResults` banner. Partitioning works per-axis (`onet=45` → 101 jobs, `loctyp=Home` → 25 jobs, `Appr=True` → 266 jobs) but full cross-product coverage is unproven. Source: `wi/REPORT.md` §Feed Discovery + §Enumeration, `wi/scripts/05_partition_probe.py`, `06_qs_filter_test.py`, `wi/samples/t1_partitions_*`, `t1_qsfilter_*`.
- **Details are login-gated, not bot-walled.** Anonymous `GET EnhancedJobs-det.aspx?OrderNumber=` → `302 /Login.aspx` (4/4 URL shapes). Login is reCAPTCHA Enterprise-gated: plain POST and headless Chromium fail; **headed Thorium under Xvfb passes**, sets `.ADAuthCookie`, lands on `/Default.aspx` — then **httpx replay fetches details directly (3/3, ~0.35 s, 71–74 KB each)**. Source: `wi/REPORT.md` Addendum, `DETAILS.md` §3 (WI), `wi/scripts/20_login_detail.py`, `21_browser_login.py`, `22_replay_details.py`, `wi/samples/auth2_detail_004073143_20261026T234903Z.html` (82,284 B, 48 `Label_*` ids, `DutiesText` 2,576 chars, `aplitrak.com` apply URL).
- **Detail field contract is stable element ids** `span#ctl00_ContentPlaceHolder_MainBase_Label_<Name>` (`JobTitle`, `PayValue`, `DutiesText`, …) + `table.applyInstructions` for the external apply URL. Source: `wi/scripts/22_replay_details.py` (`parse()`), `DETAILS.md` §3 table.
- **Result-set instability across backends:** one of ~12 identical GETs returned different page-1 rows and `(622+ openings)` vs `(525+ openings)` — dedupe by job number, never trust offset/total as cursor. Source: `wi/REPORT.md` §Feed Discovery, `wi/samples/t1_getlist_direct_*`.
- **Bot posture:** ~60 requests at 1.5–2 s + an 8-request burst at 1.2 s → all 200, no 403/1020/challenge; `robots.txt` allows the feed paths (`Disallow: /*.axd$` only); ToS has no anti-scraping clause. Source: `wi/scripts/11_bot_posture.py`, `wi/data/bot_posture.jsonl`, `wi/samples/t0_robots_*`, `t1_termsofuse_*`.
- Corpus ≈ 525 postings; full list sweep ≈ 150–400 requests; full detail pass ≈ 525 requests / ~38 MB. Source: `wi/REPORT.md` §Enumeration + Addendum, `DETAILS.md` §2.

## Sourced from

- `wi/REPORT.md` (contract + authenticated-detail addendum), `wi/MANIFEST.md` (inventory), `wi/BRIEF.md` (seed observations), `wi/data/probe.sqlite` (`captures` 17 rows, `jobs` 326 row-instances / 201 distinct keys — dumped, schema verified)
- `wi/scripts/`: `01_enum_form.py`, `02_post_search.py`, `03_get_list_direct.py`, `04_postback_page.py`, `05_partition_probe.py`, `06_qs_filter_test.py`, `07_paging_depth.py`, `08_page_blocks_and_detail.py`, `09_page_breakpoint.py`, `10_chained_paging.py`, `11_bot_posture.py`, `12_detail_after_post.py`, `13_parse_rows.py`, `14_minimal_qs.py`, `20_login_detail.py`, `21_browser_login.py`, `22_replay_details.py`
- `wi/samples/`: t0 verified page-1 + minimal-QS + robots, t1 form/post/paging/partition/filter/detail captures, auth/auth2 login + detail captures
- Cross-state: `DETAILS.md` §3 (WI Phase B contract) + §5 (adapter fields), `SYNTHESIS.md`, `BRIEF.md` (tier ladder)

## Still open

- Partition cross-product (`onet` × `wd`, 115 queries) proven per-axis but **not proven to drive every partition under 500**; SOC overlap means partitions double-count (dedupe mandatory). (`wi/REPORT.md` §Enumeration.6)
- `loc`, `dist`, `city`, `edu`, `shft`, `ww`, `tbsel`, `MOSCode`, `VetsReadyEmployer` semantics UNKNOWN — never driven. (`wi/REPORT.md` §Feed Discovery + §Risks)
- **Session lifetime UNKNOWN** — site expires access "due to inactivity"; treat any detail-fetch `302 → /Login.aspx` as session-expired, re-login, resume. (`wi/REPORT.md` Addendum, `DETAILS.md` §3)
- Saved successful detail capture is the **browser** body (82,284 B); httpx-replay bodies (71–74 KB) verified field-identical at runtime but not saved to `samples/`. (`wi/scripts/22_replay_details.py` prints only)
- Single-IP testing only; no TLS/JA3 experiment (no evidence it is needed).
- Partner rows (`USNLX`, `wisc.jobs`) link straight to `Login.aspx` and carry composite ids from the anchor `title` only.

## Fixture map (verbatim `cp` of captures)

- `responses/search_sample.html` = `fixtures/WI/search_page_1.html` = `wi/samples/t0_page1_verified_20261026T191741Z.html` (82,231 B, canonical query string page 1)
- `responses/detail_sample.html` = `fixtures/WI/detail_1.html` = `wi/samples/auth2_detail_004073143_20261026T234903Z.html` (82,284 B, authenticated browser capture, OrderNumber 004073143)
- `responses/facet_onet_sample.html` = `fixtures/WI/facet_onet.html` = `wi/samples/t1_part_occarea_29_healthcare_20261026T191156Z.html` (85,226 B, pure `onet=29` filter page 1)
