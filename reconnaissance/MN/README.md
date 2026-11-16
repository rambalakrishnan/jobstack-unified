# MN (Minnesota CareerForce) — reconnaissance findings

## What was found

- **Tier T0 wins (with T1 header hygiene).** `GET /job-search` is server-rendered Drupal 11 HTML with all 10 cards inline. No browser, no JS, no API, no cookies. The only requirement is a full browser-like `User-Agent` (bare `curl`/truncated UAs get transient 403s). Source: `mn/REPORT.md` §Verdict + §Tier Ladder, `mn/scripts/probe_filters.py`, `mn/samples/t0_feed_page0_20261026T191021Z.html`, `mn/samples/t0_403_limitparam_20261026T200500Z.html`.
- **No JSON anywhere.** `/jsonapi` → 404; the `/api/` string in the page is Google Maps Places JS. Source: `mn/REPORT.md` §Platform & Stack, `mn/BRIEF.md`.
- **"Showing 500 jobs" is a cosmetic label** (`min(true_count, 500)`), not a row cap. The real cap is **10,000 rows per query** (1,000 pages × 10): `?page=999` returns the 10,000th row, `?page=1000` returns a byte-identical 63,805 B empty state. Source: `mn/scripts/probe_depth.py`, `mn/scripts/probe_bisect_total.py`, `mn/samples/t0_unfiltered_p999_20261026T194000Z.html`, `mn/samples/t0_depth_p1000_20261026T193000Z.html`.
- **True corpus ≈45,000 postings** (lower bound 44,971 = sum of the 500 city-facet counts). The unfiltered feed exposes only ~22 %. Source: `mn/REPORT.md` §Feed Discovery, `mn/samples/t0_feed_page0_20261026T191021Z.html` (`select[name=loc]` options).
- **Beat the cap by slicing on `loc` (city).** Largest slice (Minneapolis 7,114 measured / Saint Paul 7,137 facet) is under 10,000, so every city slice is fully enumerable; `loc` + `company` AND-compose. Source: `mn/scripts/probe_slice_cap.py`, `mn/samples/t0_mpls_p711_20261026T194000Z.html` (4 cards), `mn/samples/t0_mpls_p712_20261026T194000Z.html` (0 cards), `mn/samples/t0_compose_woodbury_walmart_20261026T195800Z.html`.
- **Page size fixed at 10.** `?items_per_page=100` silently ignored. Source: `mn/samples/t0_items_per_page100_20261026T200900Z.html`.
- **Detail = same route + `?jvid=<36 chars>`** (32 hex + literal `8003` suffix, the stable dedupe key). Returns one card with `job-description__full`; adds no structured fields — salary/type live in prose only. Source: `mn/scripts/probe_order_detail.py`, `mn/samples/t0_detail_8eb1059c476c4ed5b62d5dd0dfd5198c8003_20261026T192000Z.html`, `mn/data/probe.sqlite:detail_fields`.
- **Deterministic ordering** (re-fetch → identical jvid sequences) but **churn-shifts offsets** (page-0/page-1 overlap observed 1.5 s apart): dedupe on `jvid`. No absolute dates anywhere (relative "Posted N days ago" only); no date filter. Source: `mn/scripts/probe_order_detail.py`, `mn/samples/t0_sort_dd_p0_again_20261026T192000Z.html`, `mn/data/probe.sqlite:jobs` (19 rows from 20 cards).
- **Bot posture**: Apache + AWS ALB (sticky cookies issued, not required); no WAF challenge, no 429s in ~48 requests at 1.5 s spacing. `robots.txt` **explicitly disallows `/job-search`** — the feed itself; no ToS page exists on the host. Source: `mn/samples/t0_robots_20261026T191021Z.txt`, `mn/samples/t0_siteindex_20261026T194500Z.html`.
- Full crawl ≈ 4,500–5,500 GETs (~2 h at 1.5 s spacing, ~700 MB). Source: `mn/REPORT.md` §Enumeration Strategy.

## Sourced from

- `mn/REPORT.md` (contract), `mn/MANIFEST.md` (inventory), `mn/BRIEF.md` (seed observations), `mn/data/probe.sqlite` (`jobs` 19 rows, `detail_fields` 1 row, `request_log` empty — dumped, schema verified)
- `mn/scripts/`: `probe_filters.py`, `probe_order_detail.py`, `probe_depth.py`, `probe_bisect_total.py`, `probe_slice_cap.py`, `extract_probe.py` (reference extractor: selectors verified against captures)
- `mn/samples/`: t0 feed/filter/sort/paging/depth/compose captures listed in `mn/MANIFEST.md`

## Still open

- Tail coverage gap: facets truncate at top-500 cities/companies; residual uncovered set magnitude UNKNOWN (`mn/REPORT.md` §Risks).
- Card location nullability: no card lacking a location observed — parser must still tolerate `None` (`mn/REPORT.md` §Risks).
- `~X~` escape table mapped for 7 escapes only; copy `<option value>` byte-for-byte (`mn/REPORT.md` §Request Contract).
- Saint Paul (7,137) at 71 % of the 10,000 per-query ceiling — monitor per-slice truncation (`mn/REPORT.md` §Risks).
- Salary/type extraction is prose text-mining, low precision (`mn/data/probe.sqlite:detail_fields.salary_snippet`).
- Single-IP testing only; T3–T5 never attempted (unnecessary). `robots.txt` denial is a compliance blocker, not technical.
