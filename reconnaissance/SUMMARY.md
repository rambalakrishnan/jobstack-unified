# Phase 3.5 Reconnaissance Summary

Sole source: `/home/whipsthellamasass/workspace/state-bank-research/` (translation, not discovery).
No seam/DAG edits. No invented values. OR self-referral documented as prohibition only.

## Source of each extraction

| State | What was found | Recon files/folders |
|---|---|---|
| IL | T1 wins (any `_session_id`); same-URL JSON feed; 10k window + silent clamp; partition ladder state→county→work_type; cookieless detail; deterministic order | REPORT.md, t1/t2/t3 scripts, t0/t1/t2/t3/p1–p6 samples, probe.sqlite (probes/jobs_json/cards_html) |
| MN | T0 + UA; HTML only; cosmetic 500 label, real 10k cap sliced by 500-city `loc` facet; detail = same route + `?jvid`; churn-shifted offsets | REPORT.md, probe_*.py scripts, t0_* samples, probe.sqlite (jobs/detail_fields) |
| WI | T0 page 1, T1 `Page$N` postbacks (viewstate not session-bound); 500-cap; login-gated details via headed Thorium, replayable to httpx; backend flips 525↔622 | REPORT.md + Addendum, scripts 01–22, t0/t1/auth/auth2 samples, probe.sqlite |
| MI | T1 41-field postback → 302 → results; no JSON/XHR; hard 25/page; sliding-window pager slots; cookie-bootstrapped 150 KB details; session-random order | REPORT.md, probe_*.py + mi_parse.py, t1replay/t3 samples, probe.sqlite (postings/meta) |
| OR | T3-once → T1 stateful; UA/CH-consistency gate (not JA3); 1k cap, no-op `start`, loc-comma-lists; 26,699 via 54-code query; self-referral POST is a prohibited write | REPORT.md, t1/t2/t3/t4/t5 scripts, session/bootstrap/total/detail/selfrefer samples, probe.sqlite |

Cross-state: `BRIEF.md` (ladder), `SYNTHESIS.md` (caps, robots, adapter interface), `DETAILS.md` (Phase A/B contracts), `_shared/baseline.py` (T0 conventions; `env.sh` holds only `FIRECRAWL_API_KEY`, unread).

## Coverage table

| State | URLs captured | Response schema | Extraction bindings | Pagination | Session | Fixtures |
|---|---|---|---|---|---|---|
| IL | search×2 rep, detail, county, robots | JSON 9 keys + HTML card/DOM ids | extraction.json (verified keys) | offset+50, 10k clamp, partitions | any-value cookie, 202 re-prime | search_page_1.json, detail_1.html, facet_county.json |
| MN | feed, detail `?jvid`, filters | HTML cards + detail div | extraction.json (16/16 mechanical) | `?page` 0-idx, 10k cap, loc slices | UA-only, sticky ignored | search/detail/facet_loc HTML |
| WI | list, 4 detail shapes, postback chain | GridView rows + 48 Label_* ids | extraction.json (28/28 mechanical) | `Page$N` postback, 500-cap, onet×wd | stateless paging; login jar for details | search/detail(On!)/facet_onet HTML |
| MI | search POST, results, detail, pager | 25-card rows + label/value detail | extraction.json (mechanical PASS) | slot postbacks, hard 25/page | session-stateful, cookie jar | search/detail/facet HTML |
| OR | list/detail/advanced/total, selfrefer (evidence) | tables + label/value detail | extraction.json (17/17, contact excluded) | 1k cap, no-op start, loc lists | T3 jar, per-response rotation | search/detail/facet_loc HTML |

## Seam mapping [uncertain]/[INCOMPLETE] marker resolution

Spec §3 labels (§4.OR-solver etc.) do not exist verbatim in `crawler-seam-mapping.md`; the four gaps live as §23.2 prose + §§17–18 rows. Assessed against recon:

| Marker | Status | Evidence |
|---|---|---|
| OR solver (`f5_volt_adc` placeholder) | **Still open** (bootstrap config documented) | Default headless → block notice; stealth shim → BLOCKED; CDP UA+metadata override → PASSED + 5-cookie jar (`or/samples/t4*`, `t4ua_*`). Gate is UA/CH consistency, not JA3. Working bootstrap configuration captured; no conforming solver implementation exists (out of scope per §6.4). See `reconnaissance/OR/README.md` |
| MI/OR proof sources | **Partially resolved** | MI: `txtJobCount` per-session stable, invariant to permutation, churn-scale drift; usable as `session_reported_aggregate` under 7 conditions — but no completed eligible walk, so the proof is unproven (DeepSeek `MI/aggregate_assessment.md`: CONDITIONAL). OR: single-request 26,699 all-locations total is a usable count, not a session aggregate. Extractor verified (10/10 parses); `probe.sqlite` meta is a last-write artifact, not the aggregate |
| MN/WI/MI non-offset cursors | **Still open** | All three STILL POSITIONAL (DeepSeek `WI/cursor_assessment.md`): WI `Page$N` is an absolute ordinal with a pager-relative admissibility gate (chained paging proves reusable form-state echo, not continuation); MN pure offset with churn overlap; MI page-number slots + session cursor. Decisive follow-up probes specified in the assessment |
| Veto projections | **Still open** | Requires measurement data, not reconnaissance (per spec — no recon bears on it) |

## Adapter module test impact

- **IL: PASS.** Temp `crawler_acquisition` probe fed real `search_page_1.json` (declaration adapted to real `jobs`/`id` shape): accepted, `posting_count` 10, first id 13816272. Probe created, run green, deleted; no test code modified.
- **MN/WI/MI: NOT-RUNNABLE.** No per-state extractor code exists (grep-verified); shapes documented + mechanically verified against fixtures (16/16, 28/28, full PASS). Nothing to fail.
- **OR: DIVERGENT (fidelity, not failure).** `crawler_readonly` stub URLs (`jobs.oregon.gov`, root self-refer path, `usemyssn`-as-query) provably differ from captures (`secure.emp.state.or.us`, `/jobs/selfrefer/…`, POST-body checkbox). Safety holds (substring guard matches real path) but verbatim shape is untested → **Phase 5 must add a never-called test** with the exact endpoint.
- No Phase 4 test was modified. No test that passed on stubs fails on real data (IL passes; others have no runnable per-state path).

## Remaining open evidence

- **Per-marker:** OR solver implementation + jar-lifetime/re-challenge cadence experiments; MI completed eligible walk + `PageSortTop` determinism test; WI/MN/MI decisive cursor probes (listed in `WI/cursor_assessment.md`); veto measurement data (out of recon scope entirely).
- **Per-state:** IL: WAF-rule tightening fallback, token/session lifetimes, `last_update` semantics, second IP. MN: sub-500-city tail, Saint Paul 71%-of-cap monitoring, prose salary precision. WI: partition cross-product proof, 8 undriven filter params, session lifetime, httpx-replay bodies unsaved. MI: sort postback, deep-walk duplication, idle timeout, F5 necessity, `job_time_range`, detail-fetch provenance (no script). OR: 27k-request jar survival, `since` filter semantics, WIOA/new universe, wage normalization, cookie TTL/binding, stale rows.
- **Recon self-corrections found:** WI "byte-identical" overstatement (REPORT:38), MN "deterministic continuation" mislabel (MANIFEST:36), MI orphan code `411083899` + 40-vs-41 POST fields, MI REPORT never-fetched claim vs 19:59Z captures.

## DAG regeneration recommendation

1. **DAG gaps surfaced: 0.** Every recon-implied capability has a DAG home: cookie/headed bootstrap → `crawler_browser` (+ WI-B/MI-B seam targets); jar topology → `crawler_sessions`; positional/continuation → `crawler_cursors`; OR solver → existing `f5_volt_adc` placeholder; prohibition guard → `crawler_readonly` (already implements self-refer rejection). Per-state behavior lives in §13.A config artifacts (produced), not new modules. Open markers are capability/certification states, not missing structure.
2. **Phase 4 module tests failing on real fixtures: 0.** IL acquisition passes on real JSON; no other per-state path is runnable (by design — no extractor code exists); OR readonly diverges in stub fidelity without failing.
3. **Recommendation: Proceed to Phase 5.** No structural regen warranted (0/0). Carry as certification constraints, not DAG work: OR blocked (policy + solver), cursors uncertified (positional-only walks + job-id dedupe), veto unmeasured, WI login-gated details need credentials, MI needs dedupe-safe design. Required Phase 5 tests: OR never-called self-refer test; WI session-expiry re-login resume.

## Outputs index

- `reconnaissance/{IL,MN,WI,MI,OR}/` — per-state bundles (README/endpoints/requests/responses/extraction/pagination/session) + `WI/cursor_assessment.md` + `MI/aggregate_assessment.md`
- `configs/adapters/{IL,MN,WI,MI,OR}.yaml` — §13.A declarations (evidenced `# from:` or `null # [uncertain:]`)
- `fixtures/{IL,MN,WI,MI,OR}/` — verbatim capture copies (IL JSON+HTML; others HTML)
