# MN pagination

Source: `mn/REPORT.md` §Feed Discovery + §Enumeration Strategy, `mn/scripts/probe_depth.py`, `probe_bisect_total.py`, `probe_slice_cap.py`, `mn/samples/t0_depth_*`, `t0_mpls_*`, `t0_unfiltered_p999_*`.

- **Mechanism:** offset query param. `page` (0-indexed) × fixed 10 rows. Offset = `page*10`, confirmed (Minneapolis page 711 = last page of 7,114 rows with 4 cards).
- **Page size:** fixed at 10. `?items_per_page=100` returns 200 but still 10 cards (`mn/samples/t0_items_per_page100_20261026T200900Z.html`).
- **Hard cap: 10,000 rows per query.** `?page=999` has the 10,000th row; `?page=1000/2000/4000/8000` all return HTTP 200 with a byte-identical 63,805 B empty body (`No results found.`, no cards, no `Showing` header). The cap is **per-query, not global**: the Minneapolis slice ends at its own 7,114th row (`page=712` → 0 cards).
- **"Showing 500 jobs" is cosmetic** (`min(true_count, 500)`): unfiltered and Minneapolis both read 500 while true counts are 10,000+ and 7,114; Ada reads 21 (true count below 500). Never use it for end detection or totals.
- **Pager widget lies:** past page 8 it renders `…41 42 … 48 49` with no "next" even on `?page=499`/`?page=999`. Never trust it — trust an empty page.
- **Ordering:** deterministic per run (re-fetched pages → identical jvid sequences) but **churn-shifts offsets** (page-0 tail reappeared as page-1 head 1.5 s apart). Dedupe on `jvid`; never compute totals from card counts.
- **Partition (mandatory for ≈45,000 corpus):** city slices via `select[name=loc] > option[value]` (500 cities + placeholder, true counts in labels, sum 44,971). Every observed slice < 10,000 rows (largest: Minneapolis 7,114 measured). Sentinel: a slice reading `Showing 500` whose last page sits at 10,000 rows is truncated — sub-slice by `company`.
- **Residual gap:** facets truncate at top-500 cities/companies; union a `company` tail pass with `jvid` dedupe. Residual uncovered magnitude UNKNOWN.
- **Stop rule:** 0 `data-jvid` cards AND absence of the `Showing N jobs` header. Confirmed at Minneapolis `?page=712` and unfiltered `?page=1000/2000/4000/8000`.
- **Incremental:** no date-posted filter exists (filter form has no date-like `name=`); no absolute dates anywhere (relative "Posted N days ago" only). Sort-based delta: `sort=date-posted-desc` from `page=0`, stop at a run of known jvids past the delta window — best-effort; full city sweep weekly. Cheap daily delta: each city's `page=0` = 500 requests for the state's newest ~5,000 postings.
- **Cost:** unfiltered-only 1,000 GETs (22 % coverage); full city sweep ≈4,500 + company tail ≈5,000–5,500; daily delta 500. ~2 h full / ~13 min delta at 1.5 s spacing; ~700 MB bandwidth per full crawl.
