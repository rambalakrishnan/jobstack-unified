# IL (Illinois JobLink) — reconnaissance findings

## What was found

- **Tier T1 wins.** `GET /search/jobs` with any `_session_id` cookie value (verified incl. all-zeros) returns 200 + full results. No browser, no JS, no `aws-waf-token` needed. Source: `il/REPORT.md` §Verdict + §Tier Ladder, `il/scripts/t1_dummy_cookie.py`, `il/samples/t1c_*`.
- **Same URL serves JSON** via `Accept: application/json` (or `.json` suffix): `{jobs[10], pages, total}`. JSON ignores `per_page` (fixed 10/page). Source: `il/scripts/t1_params_probe.py`, `il/samples/p1_json_variant_*`, `il/samples/p2_json_*`.
- **Hard 10,000-match window per query**, silent tail clamp (pages past the end repeat the last window instead of erroring). Partition state → county → work_type using facet counts; AND-combination proven. Source: `il/REPORT.md` §Feed Discovery + §Enumeration, `il/samples/p4_*`, `p5_*`, `p6_*`.
- **Detail page needs no cookie**: `GET /jobs/{id}` → 22.9 KB HTML, full description (identical to JSON field). No JSON representation (406). Apply endpoint account-gated. Source: `il/scripts/t1_params_probe.py` (`detail_job` probe), `il/samples/p1_detail_job_*`.
- **Deterministic ordering** (repeated page 2 → identical id sequence), keyed resume on job id. Source: `il/samples/p4_json_page2_repeat_*`.
- **Bot posture**: AWS WAF challenges only `/search/*` without `_session_id`; no UA/TLS binding (token replays across UAs/HTTP versions); no throttling seen at 1.5 s spacing. `robots.txt` disallows `/search/jobs`; no ToS anti-scraping clause. Source: `il/scripts/t2_cookie_replay.py`, `t3_browser_probe.py`, `il/samples/t0_robots_body.txt`.
- Corpus 78,528; full crawl ≈ 1,600–1,800 GETs at 2–3 concurrency. Source: `il/REPORT.md` §Enumeration, `SYNTHESIS.md` §1.

## Sourced from

- `il/REPORT.md` (contract), `il/MANIFEST.md` (inventory), `il/data/probe.sqlite` (`probes`, `jobs_json`, `cards_html` tables — dumped, schema verified)
- `il/scripts/`: `t1_dummy_cookie.py`, `t1_params_probe.py`, `t2_cookie_replay.py`, `t3_browser_probe.py`, `build_dataset.py`
- `il/samples/`: t0 wall/challenge captures, t1 bypass + JSON, t2 replay, t3 browser, p1–p6 sweep bins
- Cross-state: `SYNTHESIS.md` §§1–7, `DETAILS.md` §3 (IL detail contract), `BRIEF.md` (tier ladder)

## Still open

- Cookie bypass looks like WAF misconfiguration — fallback chain documented, not exercised beyond browser harvest. (`il/REPORT.md` §Risks)
- `aws-waf-token` role unpinned; `_session_id` lifetime unknown (~4-day token expiry observed once).
- `last_update=Today` filter effect unverified (returned unfiltered-looking results); `date_posted` verified. (`il/REPORT.md` §Enumeration.5)
- Facet counts drift from live query totals (Du Page 6,682 vs 6,667) — partition planner must read live counts.
- Single-IP testing only; no second-IP or long-session data. T4/T5 never attempted.
- No salary field; wage/education/hours sparse in HTML only (4/50 cards for wage).
