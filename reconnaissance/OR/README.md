# OR (WorkSource Oregon / iMatchSkills) — reconnaissance findings

Target: `https://secure.emp.state.or.us/jobs/index.cfm` (Oregon Employment Department,
custom in-house ColdFusion app; no ATS vendor signature).
Recon date: 2026-10-26 UTC. Corpus at capture: **26,699** live postings.

> **POLICY — PROHIBITED BY POLICY, NOT GREY.** `robots.txt` says
> `User-agent: * → Disallow: /`, and the WAF block page (served in place of content to
> clients classified as automated) explicitly forbids "automated tools such as robots,
> spiders" and cites the **Computer Fraud and Abuse Act of 1986** and the National
> Information Infrastructure Protection Act of 1996. Source: `or/REPORT.md`
> §Transport & Bot Posture, `or/samples/t3_flow_20261026T191146Z/02_200_xhr.body`
> (1,581 B, verbatim), cross-state `SYNTHESIS.md` §4 ("Prohibited by policy. Not grey.
> Do not ship without written permission.") and §7 ("OR — do not build until the
> robots/CFAA question is resolved with the state"). Any module must be gated behind an
> explicit licence/partner agreement with OED. `[uncertain: no verbatim robots.txt
> capture exists in or/samples/; the 108 B text above is quoted in or/REPORT.md — a
> one-request re-fetch would resolve it.]`

## What was found

- **Tier T3-once → T1 for the crawl.** One headless-Chromium bootstrap with consistent
  UA + UA-CH passes the F5 volt-adc (`server: volt-adc`) JS challenge and mints a
  5-cookie jar; every subsequent request is plain `httpx` over HTTP/1.1 with that live
  jar. The decisive replay experiment is yes-with-a-stateful-jar. Source: `or/REPORT.md`
  §Verdict + §Tier Ladder, `or/scripts/t2_bootstrap_and_replay.py`,
  `or/samples/bootstrap_20261026T191507Z/B_index_cookie.body` (21,884 B app from httpx).
- **The gate is UA/client-hint consistency, not fingerprinting.** Default headless
  Chromium leaks `HeadlessChrome` in `sec-ch-ua` → block notice; CDP
  `Emulation.setUserAgentOverride` (UA **and** `userAgentMetadata`) → app, with no other
  change. HTTP/1.1, default header order, and a plain Python TLS stack all pass once
  cookies are valid. Source: `or/REPORT.md` §Transport, `or/scripts/t4_stealth_probe.py`
  (BLOCKED) vs `or/scripts/t4_uaoverride_probe.py` (PASSED),
  `or/samples/t4_chromium_20261026T191320Z.json` vs
  `or/samples/t4ua_chromium_20261026T191348Z.{html,json}`.
- **Server-rendered ColdFusion HTML; no JSON/XHR API exists.** The only XHR observed
  site-wide is the WAF interstitial itself. `location_content=<page>.cfm` dispatches
  list/detail/advanced views of one script. Source: `or/REPORT.md` §Request Contract,
  `or/samples/bootstrap_20261026T191507Z/netlog.jsonl` (35 requests, 0 JSON).
- **Hard 1,000-row cap per result set; `start` is a no-op.** `start=1001` returns
  byte-identical content and the identical 1,373 `ord` values as `start=1`. Past the cap
  the page carries a `Reached limit: 1000 of N Jobs matching …` banner — the split
  signal. There is no `maxrows`/`page` param. Source: `or/REPORT.md` §Feed Discovery,
  `or/scripts/t1_paging_probe.py`,
  `or/samples/paging_20261026T192128Z/B_sales_start1001.body`.
- **Full corpus measured via all-54-location comma list: 26,699 postings** (`Reached
  limit: 1000 of 26699 Jobs`). `loc` accepts comma-separated 3-digit codes (proven:
  `loc=008,019` → 654 = 281 + 373 rows). Ordering is ascending by `ord`, so a capped
  partition silently drops the **newest** postings. Source: `or/scripts/t1_total_probe.py`,
  `or/samples/total_20261026T192247Z/all_locations.{body,json}`,
  `or/samples/paging_20261026T192128Z/A_multi_loc_008_019.{body,json}`.
- **Every result page re-appends 373 statewide recruitments** (`#tbl_jobSearch2`,
  "included in all search results as required by USDOL Regulations"), disjoint from the
  query set — carry once, dedupe by `ord`. Source: `or/REPORT.md` §Feed Discovery,
  `or/data/probe.sqlite` → `listing_row` (373 `statewide` rows in all four captures).
- **Detail pages are anonymous and complete except employer contact.** Label/value pairs
  (`div.fw-bold` + sibling, `span.fw-bold.me-1` + `span.text_jobdetail`), sections
  (`Job Summary`, `Compensation`, SOC title). Employer name/contact/How-to-Apply sit
  behind a **state-changing self-referral handshake — prohibited; see below, never
  crawled**. Source: `or/scripts/t1_detail_probe.py`,
  `or/samples/detail_20261026T192030Z/02_detail_4594067.body`,
  `or/scripts/t5_selfrefer_contact.py` (evidence only).
- **No export/partner feed.** Zero `.xml`/`.rss`/`.csv`/`format=xml` references and no
  "download jobs" link across index, advanced, listing, and detail captures. Source:
  `or/REPORT.md` §Feed Discovery (regex sweep over all captures; re-verified: grep over
  `or/samples/{feed,detail,bootstrap,total,selfrefer,paging}_*` returns nothing).
- **Full crawl ≈ 27,000 GETs** (26,699 details + ~150–400 list partitions), ~1 GB,
  ~11 h single-threaded at 1.5 s/request; 3–4 independent bootstrap+jar pairs, never
  one jar shared across threads. Source: `or/REPORT.md` §Enumeration Strategy.
- **Session fragility is the main engineering risk.** `OClmoOot` rotates on *every*
  response; a frozen snapshot dies after ~3 requests; a stateful `httpx.Client`
  survived 4–6 consecutive requests. `[uncertain: long-run jar lifetime unmeasured —
  longest chain observed was 6 requests / ~1 min; whether the chain survives 27,000
  requests or needs re-bootstrap every N pages is unknown.]` Source: `or/REPORT.md`
  §Risks, `or/scripts/t1_session_crawl.py`, `or/scripts/t2_cookie_replay.py`,
  `or/samples/session_20261026T191747Z/`.

## Prohibition evidence — the self-referral POST (READ-ONLY DOCUMENTATION)

> This section is the **only** place in Phase 3.5 where the self-referral write is
> documented. It MUST NOT appear as an executable operation in `configs/adapters/OR.yaml`,
> in any fixture, in `endpoints.md`, in `extraction.json`, or in crawl code. A Phase 5
> test MUST verify the endpoint is never called (including via redirect — the completion
> page auto-redirects to `jobdisplay` with an `sr` token; only pre-authored GET URLs may
> be fetched).

**Why prohibited.** Each "Obtain Contact Information" submission files a self-referral
record in the state's system (labelled a referral, carries a `transid`/`sr` token).
Repeating it across 26,699 postings would file 26,699 referrals — far beyond any
plausible use and squarely inside the site's own harvesting prohibition (robots
`Disallow: /`, block notice citing CFAA). Recon exercised the opt-out path exactly once,
for one posting, to document the contract. Source: `or/REPORT.md` §Risks ("NEW RISK —
the contact reveal is a write, not a read") and §Reproduction (WARNING label on
`or/scripts/t5_selfrefer_contact.py`).

**Step 1 — referral page (GET, observed).**
`GET /jobs/selfrefer/index.cfm?ord={ord}&lang=E` → 200, 24,124 B,
`<title>Job Listing Self Referral</title>`. PRISM/WIOA SSN yes/no choice. Source:
`or/samples/selfrefer_20261027T014530Z/02_selfrefer.body`,
`or/scripts/t5_selfrefer_contact.py`.

**Step 2 — form structure (verbatim from the capture; DO NOT SUBMIT).**

```html
<form action="self-refer-step1-validate.cfm?ord=4594067&rtnto=%2Fjobs%2F&atpt=1&transid=39441502"
      method="POST" autocomplete="off">
  <input type="password" name="ssn"  id="ssn" maxlength="11">        <!-- stays EMPTY on opt-out -->
  <input type="password" name="ssn2" id="confirmSsn" maxlength="11"> <!-- stays EMPTY on opt-out -->
  <input type="checkbox" name="usemyssn" value="No" id="chk_usemyssn">
  <!-- label: "No. You may not have my Social Security Number, but I would still
       like help in finding a job." -->
  <button type="submit" name="submitbtn" value="Continue">Continue</button>
</form>
```

Endpoint: `POST /jobs/selfrefer/self-refer-step1-validate.cfm` (relative action above;
query: `ord` int, `rtnto=/jobs/`, `atpt=1`, `transid` per-session int; body:
`ssn`/`ssn2` empty, `usemyssn=No` checkbox, `submitbtn=Continue`). The opt-out control is
a **checkbox**, not a radio; the submit control is a `<button type="submit">`, not an
input. Source: `or/samples/selfrefer_20261027T014530Z/02_selfrefer.body` (form HTML),
`or/samples/selfrefer_20261027T014530Z/02_selfrefer_form.json` (machine form contract:
action/method/inputs), `or/scripts/t5_selfrefer_contact.py` (opt-out identification +
empty-SSN assertions).

**Step 3 — response shapes (observed).** The POST returns
`self-refer-completed.cfm?ord={ord}&sr={n}`, which auto-redirects to the job display
after ~3 s (or via its "Continue to Job Display" control):
`GET /jobs/index.cfm?location_content=jobdisplay.cfm&ord={ord}&sr={n}` → 200, 35,855 B
(vs 28,455 B anonymous). The **`sr` query param is the unlock**: re-fetching the same
`ord` with that `sr` renders the contact block. Source: `or/REPORT.md` §Response Schema,
`or/scripts/t5_selfrefer_contact.py` (completion-page handling),
`or/samples/selfrefer_20261027T014530Z/03_after_continue.body`.

**Revealed block (response shape; selectors live here ONLY, not in extraction.json).**
Delimited by `<!--  _format_self_refer_contact.cfm  start -->` /
`<!--  _format_self_refer_contact.cfm  end -->` (double spaces — match with `\s+`).
Robust anchor: `span.fw-bold` label text → `find_next_sibling("span",
class_="text_jobdetail")`. Fields observed for ord 4594067: `How to Apply:` (free text —
email + phone; extract `mailto:`/`http(s)`/phone by regex; **no apply `<a href>`
element exists**), `Employer Name:` (`Serenity Vapors, LLC`), `Employer Contact:`
(`Owner`). Source: `or/samples/selfrefer_20261027T014530Z/03_after_continue.body`,
`or/samples/selfrefer_20261027T014530Z/03_contact_census.json`.

**Anonymous placeholder (what the crawl legitimately sees).** Anonymous detail carries
`<!--  _format_self_refer_instr  start -->` … `<b>You may contact this employer
directly.</b>` … `<button onclick="window.location.href=
'selfrefer/index.cfm?ord=4594067&lang=E'">Obtain Contact Information</button>` … end
marker. The crawler MUST treat this button as absent (never follow, never submit).
Source: `or/samples/detail_20261026T192030Z/02_detail_4594067.body`.

**Phase 4 test gap (module-test verdict: DIVERGENT).** `crawler_readonly` conformance
tests reject a sheriff's-sketch URL (`https://jobs.oregon.gov/self-refer-step1-validate.cfm?usemyssn=No`)
that provably differs from the capture in host (`jobs.oregon.gov` vs
`secure.emp.state.or.us`), path (root vs `/jobs/selfrefer/…`), and shape (`usemyssn` as
query param vs POST-body checkbox; real query is `ord&rtnto&atpt&transid`). Mitigation:
the guard matches lowercase substring `self-refer`, which IS present in the real path,
so the safety property holds — but no test exercises the verbatim real shape. Phase 5
MUST add a never-called test with the exact endpoint above (method + path + params).
`crawler_acquisition` has no per-state extractor code (grep-clean for OR markers), so the
gate-4 probe is NOT-RUNNABLE there; shape is documented in `extraction.json` and verified
by the mechanical selector check below.

## OR-solver marker status (NOT CLOSED — documented, not designed)

`[INCOMPLETE: §4.OR-solver]` stays open. Per assignment, no solver was designed here.
What recon shows:

- **Bootstrap outcome:** `scripts/t3_browser_bootstrap.py` (default headless Chromium,
  Playwright UA) → challenge resolves into the 1,581 B block notice, not the app.
  Source: `or/samples/t3_flow_20261026T191146Z/`, `or/samples/t3_cookies_20261026T191039Z.json`.
- **Stealth outcome:** `scripts/t4_stealth_probe.py` (`channel="chromium"` + JS stealth
  shim, still `HeadlessChrome/151` UA) → BLOCKED (1,607 B notice DOM). Source:
  `or/samples/t4_chromium_20261026T191320Z.{html,json}` (`ua_sent` contains
  `HeadlessChrome/151`, `sec_ch_ua_sent` lacks `Google Chrome`).
- **UA-override outcome:** `scripts/t4_uaoverride_probe.py` (CDP
  `Emulation.setUserAgentOverride` with UA + `userAgentMetadata`, Chrome/151) → PASSED
  (26,297 B app DOM, "Jobs Listed with WorkSource Oregon", 5-cookie jar incl.
  `TS01dc4fc6`). Source: `or/samples/t4ua_chromium_20261026T191348Z.{html,json}`.
- **Fingerprint posture:** UA/client-hint-consistency sensitive; NOT JA3-sensitive;
  HTTP/1.1 + default header order + plain httpx TLS pass once the jar is valid. The
  challenge script stores a signature in
  `localStorage['yT5fcM@4GfJ$Dum358SM8hW^ffLBgJ']` (1 h expiry) and re-requests with
  `ISTL-INFINITE-LOOP: 1` + dynamic `xa4vrhyp3q-*` headers. Source: `or/REPORT.md`
  §Transport, `or/samples/t3_flow_20261026T191146Z/01_200_document.body` (246,078 B).
- `[uncertain: re-challenge cadence / cookie TTL beyond the 1-day CFID/CFTOKEN expiry
  and 1-hour localStorage payload — unmeasured; resolve with a long-run jar-lifetime
  experiment.]`
- `[uncertain: IP/UA binding of the minted jar — untested; single-IP testing only.]`

## Mechanical check (gate-4 analog; IL-style cargo probe N/A — see below)

Python selector verification of `extraction.json` against the verbatim fixtures
(`fixtures/OR/*.html`), run 2026-11-16: **PASS**.

- `search_page_1.html`: `table#tbl_jobSearch` + `table#tbl_jobSearch2` present; `thead`
  carries all 8 headings (`Job ID … Types`); `#tbl_jobSearch tbody` = 654 rows,
  `#tbl_jobSearch2 tbody` = 373 rows (matches `A_multi_loc_008_019.json`: `n_rows`
  1027); first query row cells verify (`4597867`, `a[href*=jobdisplay]&ord=`,
  `Albany`, `span.hide` `20261026`, wage text, `40`, `At least 6 years`, `.badge`);
  no `Reached limit` banner (uncapped, correct for 654 < 1000).
- `facet_loc.html`: `#tbl_jobSearch tbody` = 281 rows, all in the Albany area (262
  `Albany` + Jefferson/Tangent/Millersburg/Scio — loc codes are zones, not cities);
  `#tbl_jobSearch2 tbody` = 373 rows; statewide label `There are currently 373
  statewide recruitments` present.
- `detail_1.html`: title `Jobs Listed with WorkSource Oregon`; all 16 detail labels
  present (`Job Listing ID:` … `Employer Will Perform:`); `Job Listing ID:` sibling =
  `4594067`; anonymous placeholder `_format_self_refer_instr` + `Obtain Contact
  Information` button present; `_format_self_refer_contact` ABSENT (anonymous, as
  required); sections `Job Summary` / `Compensation` present.
- Prohibition hygiene: `self-refer-step1-validate` and `usemyssn` occur NOWHERE in
  `configs/adapters/OR.yaml`, `fixtures/OR/`, `endpoints.md`, or `extraction.json`
  (this README is the sole holder).

IL-style `cargo test -p crawler_acquisition` temp probe: **N/A**. Oregon exposes no
JSON/XHR API surface (REPORT §Tier Ladder T2: none exists — the adaptation target of
IL's probe does not exist here), and `crawler_acquisition` src+tests contain no
per-state extractor code or declaration to adapt (grep-clean for
`oregon|OR-A|tbl_jobSearch|volt`). The python selector check above is the gate-4 analog.

## Sourced from

- `or/REPORT.md` (contract), `or/MANIFEST.md` (inventory), `or/data/probe.sqlite`
  (`listing_row` 4,427 rows / 8 source×block groups verified, `detail_job` 1 row ord
  4594067, `http_log` 24 rows — dumped via python sqlite3, schema verified)
- `or/scripts/`: `t1_total_probe.py`, `t1_feed_probe.py`, `t1_paging_probe.py`,
  `t1_detail_probe.py`, `t1_session_crawl.py`, `t1_httpx_explore.py`,
  `t2_bootstrap_and_replay.py`, `t2_cookie_replay.py`, `t2_replay_probe.py`,
  `t3_browser_bootstrap.py`, `t3_body_capture.py`, `t4_stealth_probe.py`,
  `t4_uaoverride_probe.py`, `t5_selfrefer_contact.py` (headers + flow skimmed),
  `parse_samples.py`
- `or/samples/`: t0 challenge, t3 flow + block notice, t4/t4ua verdicts, replay
  failures, bootstrap decisive replay, session chain, feed grammar, paging no-op proof,
  total 26,699, detail contract, selfrefer handshake (evidence only)
- Cross-state: `SYNTHESIS.md` §§1–2,4,7 (caps table, legal posture, build order),
  `BRIEF.md` (tier ladder — OR starts at T3 per `or/BRIEF.md` correction)

## Still open

- `[uncertain: long-run jar lifetime]` — longest stateful chain observed: 6 requests /
  ~1 min. Re-bootstrap cadence for 27,000 requests unmeasured. (`or/REPORT.md` §Risks)
- `[uncertain: since/datePosted filter semantics]` — `#datePosted` select observed
  (`Today`, `Last 24 hours`, `Last 3 days`, … → `YYYYMMDD`), never exercised; no
  verified incremental path — fall back to full re-walk + `ord` diff. (`or/REPORT.md`
  §Feed Discovery; `or/samples/bootstrap_20261026T191507Z_explore/adv.body`)
- `[uncertain: system=WIOA vs system=new universe]` — both returned the same 26,699 in
  probes; only `new` used for listings. (`or/REPORT.md` §Request Contract)
- `[uncertain: wage-unit normalisation]` — free-text `wage` cell only. (`or/REPORT.md` §Risks)
- `[uncertain: cookie TTL / UA-or-IP binding]` beyond CFID/CFTOKEN +1 day and the 1 h
  localStorage payload. (`or/REPORT.md` §Transport)
- Postings back to 2021 still listed (`ord 2845592`, posted 2021-05-25) — `posted` is
  not a freshness signal; expect stale rows. (`or/REPORT.md` §Risks)
- `CFID`/`CFTOKEN` expire +1 day — any cached jar is dead by tomorrow. (`or/REPORT.md` §Risks)
