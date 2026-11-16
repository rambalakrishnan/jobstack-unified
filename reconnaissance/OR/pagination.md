# OR pagination

Source: `or/REPORT.md` §Feed Discovery + §Enumeration Strategy, `or/scripts/t1_paging_probe.py`,
`or/scripts/t1_total_probe.py`, `or/samples/paging_20261026T192128Z/`,
`or/samples/total_20261026T192247Z/all_locations.{body,json}`,
`or/samples/feed_20261026T191839Z/c2_home_sales.body`.

- **Mechanism: none — there is no pagination.** `start` is echoed in the form markup and
  `list_url` but is a **no-op**: `start=1001` returns byte-identical content and the
  identical 1,373 `ord` values as `start=1`. There is no `maxrows`/`page`/`perpage`
  param. A naive `start += 1000` loop silently re-fetches the first 1,000 rows forever.
- **Hard cap: 1,000 rows per result set.** Capped pages carry the banner `Reached limit:
  1000 of N Jobs matching <criteria>` (verbatim forms: `1000 of 26699 Jobs matching .`,
  `1000 of 5182 Jobs matching Keyword: SALES`). Uncapped pages carry NO total — count rows.
- **Ordering: ascending by `ord`** (all-locations capture runs 2845592 → 4597628
  monotonically, posted 2021-05-25 … 2026-10-26). Consequence: a capped partition drops
  the **newest** postings — the opposite of the usual failure mode, invisible unless the
  banner is checked on EVERY response.
- **Partition (mandatory for the 26,699 corpus):** single `loc` (54 codes) → on
  `Reached limit`, split `loc` × `cat` (36 occupational groups). `cat=34` alone is valid
  criteria (`1000 of 2150 … Architecture and Engineering`); `cat=00` alone is rejected
  (`The search criteria was not valid.`, 15,373 B). Comma `loc` lists are accepted, so
  coarse partitions can be re-merged once measured under the cap.
- **End detection:** absence of `Reached limit:` AND `len(rows) < 1000` (belt and
  braces). A capped page is DISCARDED and re-requested with a narrower partition — never paged.
- **Statewide duplicate:** every page appends the same 373 `#tbl_jobSearch2` rows;
  dedupe by `ord` or counts inflate ~7% per page fetched.
- **Resume:** persist `(partition_key, complete?)` plus `max(ord)` seen; ascending order
  lets a resumed run skip `ord <= max_seen` per unchanged partition. Re-check partition
  sizes every run (overflow eats newest first).
- **Incremental:** no verified date filter — `since`/`#datePosted` observed but never
  exercised (**`[uncertain: filter semantics unconfirmed in recon]`**). Fall back to full
  re-walk + diff on monotonic max `ord`.
- **Stop rule:** every queued partition returns uncapped (no banner, <1000 query rows);
  union of query `ord`s + one statewide set = corpus. Empty criteria → ~15 KB
  no-criteria page (bad partition, do not retry).
- **Cost:** ~150–400 list GETs at ~1.2–1.7 MB each (≈0.3–0.6 GB) + 26,699 detail GETs
  (≈780 MB) ⇒ ~1 GB total, ~11 h single-threaded at 1.5 s/request.
