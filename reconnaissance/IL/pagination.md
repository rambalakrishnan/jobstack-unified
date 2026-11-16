# IL pagination

Source: `il/REPORT.md` §Feed Discovery + §Enumeration, `il/scripts/t1_params_probe.py`, `il/samples/p1_*`, `p3_*`, `p4_*`, `p5_*`, `p6_*`.

- **Mechanism:** offset query params. `page` (1-based) × `per_page` (10/20/50). Offset = `(page-1)*per_page`, confirmed (`per_page=50&page=2` → "51 - 100").
- **Page size:** HTML honors 10/20/50 (`per_page=100` → clamped to 50 cards). JSON ignores `per_page` entirely (fixed 10/page, `pages` = ceil(window/10)).
- **Hard cap: 10,000 matches per query.** Past-the-end pages **silently clamp to the final window** (`page=1001..1572` all return "9951 - 10000") instead of erroring — a naive `while cards:` loop spins forever on duplicates.
- **Ordering:** deterministic per run (repeated page 2 → identical id sequence `11194261,…`), stable but opaque (not numeric by id). Resume keyed on job id, not position.
- **Partition (mandatory for 78,528 corpus):** state → county (20 published facets) → work_type → source → date_posted. Sentinel: `total == 10000` (JSON) or header "of 10,000 matches" means "capped, split me". Proven splits: Cook-Chicago+full_time = 8,238; Du Page+date_posted=1 week = 1,072.
- **Residual gap:** ~9.5k jobs outside the 20 county facets + 3,631 non-Illinois rows need their own pass; verify union sums to the true total.
- **Stop rule:** stop at `ceil(total/50)` AND when a page returns <50 cards AND when the header start offset stops advancing.
- **Incremental:** `date_posted=1 week` verified filtering; `last_update=Today` looked unfiltered — **unverified, validate before relying** (`[uncertain: filter semantics unconfirmed in recon]`).
- **Cost:** ≈1,571 page GETs + 40–120 partition probes ⇒ ~1,600–1,800 requests at 2–3 concurrency, ~1 s spacing.
