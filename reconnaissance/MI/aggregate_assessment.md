# MI — aggregate stability assessment (`session_reported_aggregate`)

**Status:** assessment only. No bundle, config, or fixture changes.
**Question:** Do `mi/samples/t1replay_*` + `mi/data/probe.sqlite` constitute a **stable aggregate count**
usable as `session_reported_aggregate` under MI's session-randomized ordering?
**Verdict:** **CONDITIONAL** — stable as a *per-session, per-predicate, per-run* advertised count
(invariant to the ordering permutation, drifting only at live-churn scale). **Not** stable as a
frozen global constant, and the sqlite scalar alone does **not** constitute the aggregate.

---

## 1. Verdict in one table

| Proposition | Result | Basis |
|---|---|---|
| Same total across every replay/session | **NO** — 61,149 … 61,154 observed | §4 |
| Same total within one session, including after a full row reshuffle | **YES** | §5 |
| Bounded drift at live-churn scale | **YES** — range 5, 0.0082 % over the documented window | §4 |
| Count is invariant to the session-randomized ordering | **YES** for every ordering control exercised | §5 |
| Usable as per-session `session_reported_aggregate` (max-RHS for the lower-bound proof) | **YES, conditional** (§7) | §2, §7 |
| Usable as a frozen corpus constant or an equality target | **NO** | §2, §4 |
| `mi/data/probe.sqlite` by itself constitutes the aggregate | **NO** — scalar is a last-write artifact; 75 rows cannot validate 61 k | §6 |
| MI lower-bound coverage proof currently computable | **NO** — no completed eligible walks (`session_min_count=2`) | §6–§8 |
| Extract MI aggregate deterministically from the payload | **YES** — verified, 10/10 results captures | §3 |

---

## 2. What “stable” has to mean for this field

The spec does **not** define stability as identity across sessions. `coverage_ledger` stores:

> `session_reported_aggregates` | Count evidence | `json` | `NOT NULL` | **Per-session** reported
> aggregates for `payload_field_union`
> — `feature-inventories/crawler-feature-inventory.md:494`

and the MI proof is a lower-bound union:

\[
\left|\bigcup_{\text{sessions}} job\_ids\right| \;\ge\; \max(session\_reported\_aggregate),
\qquad session\_count \ge session\_min\_count
\]

with the MI allocation `payload_field_union`, `session_min_count = 2`
(`feature-inventories/crawler-feature-inventory.md:1824,1944`). The spec forbids averaging:
“Backend aggregate changes without compatible cohort evidence → Separate count evidence; do not
average totals” (`crawler-feature-inventory.md` §8.5, mirrored in
`seam-mappings/crawler-seam-mapping.md` §17.4).

Three candidate definitions therefore exist. Only the second is the operative one:

| Definition | Test | Result |
|---|---|---|
| **A. Exact replay identity** — every session reports the same integer | compare all captures | **Fails**: a live board churns (61,154 → 61,149 over ~6.6 min). This is the wrong test; the spec's `max` + cohort rules explicitly anticipate changing totals. |
| **B. Bounded drift + ordering invariance** — each session's value is the full-result cardinality, unaffected by the permutation, varying only at catalogue-churn scale | same-session repeats; deliberate row reshuffle; cross-session spread | **Passes** the supplied evidence (§4–§5). |
| **C. Union semantics** — the count is a count of the whole predicate result set, not the number of rows a session happens to expose, so it can serve as the RHS while the ID union is the LHS | magnitude vs page size; invariance under reshuffle; no floor/saturation marker | **Supported**, but not provable to the catalogue boundary without completed walks (§8). |

Consequence: the right artifact is a **list of per-session values with timestamps and predicate
identity**, consumed by `max()`. A single scalar labelled “the MI total” is the wrong shape even if
its value happens to be close.

---

## 3. The extractor is verified

The count is server-rendered in the results HTML in **two** places in the same payload:

```html
<p id="txtJobCount">61152 Job(s) that matched your search.</p>
```
`mi/samples/t1replay_results_page1_20261026T1920Z.html`

```js
var count = '61152 Job(s) that matched your search.';
$("#txtJobCount").attr("aria-label", count);
```
same file

`mi/scripts/mi_parse.py:43-46` extracts it with:

```python
def total_count(html):
    """Total matching postings, from <p id="txtJobCount">NNNNN Job(s) that matched your search.</p>"""
    m = re.search(r'id=["\']txtJobCount["\'][^>]*>\s*([\d,]+)\s*Job', html)
    return int(m.group(1).replace(",", "")) if m else None
```

Verification run for this assessment (Python, no network):

- **10/10** results captures parse to a non-null integer. Non-results captures (the search form,
  the Google CSE shell, and the 302 stub `mi/samples/t1replay_fresh_results_20261026T1920Z.html`)
  have no count, as expected.
- The `<p>` value and the JS `var count` value **agree in all 10/10** captures, including the
  browser-serialized `mi/samples/t3_after_submit_20261026T191204Z.html` where the `<p>` carries an
  extra `aria-label` and uses different serialization. The regex accepts both.
- The value is an **exact integer**: no `+`, no “at least”, no “Reached limit” language. That is the
  `reported_total_unit='postings'`, `header_label_is_floor=false` case, not a floor or saturation
  marker.
- The sample values are **not rounded page counts**: `61152 % 25 = 2`, `61151 % 25 = 1`,
  `61149 % 25 = 24`, `61154 % 25 = 4`. A `ceil(rows/25)` page count would be a multiple of 25.

---

## 4. Measurements

Capture times below are **file mtimes**. The `T1920Z` / `T1935Z` / `T1945Z` suffixes in the t1replay
filenames are hard-coded `TS` constants in the probe scripts, not clock times
(`mi/scripts/probe_t1_replay.py:29`, `TS = "20261026T1920Z"`); the actual runs landed at 19:14,
19:16, and 19:19 UTC. The t3 filename timestamp is its run-start label (19:12:04); its mtime is
19:12:24.

| Capture (session) | mtime (UTC) | `startIndexNum` | control | `txtJobCount` | cards |
|---|---|---:|---|---:|---:|
| `mi/samples/t3_after_submit_20261026T191204Z.html` (browser) | 19:12:24 | 1 | form submit, default size | **61,154** | 25 |
| `mi/samples/t1replay_results_page1_20261026T1920Z.html` (A) | 19:14:35 | 1 | default 25 | **61,152** | 25 |
| `mi/samples/t1replay_results_page2_20261026T1920Z.html` (A) | 19:14:44 | 2 | `pageBtm2` | **61,152** | 25 |
| `mi/samples/t1replay_pagesize100_20261026T1920Z.html` (A) | 19:14:52 | 2 | `PageSizeBtm=100` (ignored) | **61,152** | 25 |
| `mi/samples/t1replay_resultstop_20261026T1935Z.html` (B) | 19:16:09 | 1 | default 25 | **61,151** | 25 |
| `mi/samples/t1replay_pagesize_top100_20261026T1935Z.html` (B) | 19:16:19 | 1 | `PageSizeTop=100` (ignored) | **61,151** | 25 |
| `mi/samples/t1replay_pager_page1_20261026T1945Z.html` (C) | 19:19:03 | 1 | default 25 | **61,149** | 25 |
| `mi/samples/t1replay_pager_adv1_20261026T1945Z.html` (C) | 19:19:10 | 5 | `pageTop5` | **61,149** | 25 |
| `mi/samples/t1replay_pager_adv2_20261026T1945Z.html` (C) | 19:19:18 | 7 | `pageTop5` | **61,149** | 25 |

Documented t1replay sessions A→C: **61,152 → 61,151 → 61,149** over 4 min 27 s, range **3**
(0.0049 %). Including the T3 browser capture: **61,154 → 61,149** over 6 min 39 s, range **5**
(0.0082 %). This is the entire documented spread.

The unscripted capture `mi/samples/fresh_results_20261026T195827Z.html` (mtime 19:58:34) reports
**61,150** — one above the 19:19 value after a 39-min gap, consistent with two-way churn rather than
a one-way session effect. It has **no producing script** and is not in `mi/MANIFEST.md`
(`[uncertain: provenance — README flags `fresh_results_*` and `detail_mi_*` as unscripted captures]`);
it is corroboration only, not part of the core verdict.

**Cross-tier agreement:** the browser (T3) and httpx (T1) captures report 61,154 and 61,152 within
~2 min of each other, so the count is not a transport/browser artifact.

---

## 5. Why the randomized ordering does not move the count

The strongest evidence is **within one session**, where the predicate and session state are fixed
and only the row selection/ordering changes.

### 5.1 Same session, same `startIndexNum`, completely different rows, identical count

`mi/scripts/probe_pagesize.py` uses one `httpx.Client` for all four requests. It fetches results
page 1, then posts the page-size control:

```python
b["__EVENTTARGET"] = "ctl00$MainContent$PageSizeTop"
b["ctl00$MainContent$PageSizeTop"] = "100"
```
`mi/scripts/probe_pagesize.py:59-64`

Both responses carry:

```html
<input type="hidden" name="ctl00$MainContent$startIndexNum" id="MainContent_startIndexNum" value="1" />
```

and

```html
<p id="txtJobCount">61151 Job(s) that matched your search.</p>
```

Yet the 25 job codes are **0/25 overlapping**:

- first code `401481406…` in `mi/samples/t1replay_resultstop_20261026T1935Z.html`
- first code `414569018…` in `mi/samples/t1replay_pagesize_top100_20261026T1935Z.html`

So a control that shuffled which rows occupy page 1 did not change the reported total at all. The
count is a property of the search predicate, not of the current page slice or its ordering.

### 5.2 Same session, same position, same rows, identical count

In session A, the `PageSizeBtm=100` postback (`mi/scripts/probe_t1_replay.py:193-200`) returned
`startIndexNum=2` with the **same 25 codes** as page 2 (25/25 overlap) and the same total 61,152
(`mi/samples/t1replay_pagesize100_20261026T1920Z.html` vs
`mi/samples/t1replay_results_page2_20261026T1920Z.html`). The page-size control is ignored, but the
count remains identical.

### 5.3 Paging across multiple positions, identical count

Session C walked `startIndexNum` 1 → 5 → 7 via `pageTop5`
(`mi/scripts/probe_pager.py:60-70`). All three responses report 61,149
(`mi/samples/t1replay_pager_{page1,adv1,adv2}_20261026T1945Z.html`), while the three 25-code sets
are **pairwise disjoint** (union 75 distinct IDs). The count did not drift with position, and the
pages did not repeat rows.

**Conclusion:** the randomized ordering permutes (or reselects) the rows that fill the page
positions; it does not recompute the cardinality. Therefore `txtJobCount` is exactly the value the
lower-bound formula needs on the RHS. This conclusion does not depend on the cross-session
“independence” claim in `mi/REPORT.md`, which is weaker evidence than the within-session control.

---

## 6. What the sqlite file does and does not establish

Schema and contents (dumped with `sqlite3` for this assessment):

```
postings(job_code TEXT PRIMARY KEY, title, employer, city, state, zip, onet, posted, url,
         snippet, src_file, page, source_tier)          -- 75 rows, 75 distinct job_code
meta(k TEXT PRIMARY KEY, v TEXT)                        -- [('rows','75'), ('total_count','61154')]
```

Sources: 25 rows from `t1replay_results_page1_20261026T1920Z.html`, 25 from
`t1replay_results_page2_20261026T1920Z.html`, 25 from `t3_after_submit_20261026T191204Z.html`
(`mi/scripts/parse_saved.py:21-25`). 75 = 3 × 25; the three sources are pairwise disjoint, so the
PK dedupe has nothing to collapse.

**What it establishes:** `job_code` is a usable dedupe key; the parser handles both card variants;
the union-of-observations accounting in the spec's LHS has a working representation.

**What it does not establish:**

1. **The scalar is a last-write artifact, not “the” aggregate.** `parse_saved.py` overwrites one row
   per source file:
   ```python
   con.execute("INSERT OR REPLACE INTO meta VALUES('total_count',?)", (str(total_count(html)),))
   ```
   `mi/scripts/parse_saved.py:48-49`
   Its `SRC` order is page 1 (61,152), page 2 (61,152), then **t3 (61,154)**. The stored 61,154 is
   therefore the *earliest* capture (19:12), not the latest (19:19 = 61,149) and not a stable value.
   Anything that reads `meta.total_count` as “the MI corpus size” gets a time-skewed scalar.
2. **75 rows cannot validate a 61 k count.** That is 0.12 % of the reported total. The sqlite file is
   a recon union of first pages, not a completed walk; it cannot support or refute
   `|∪ job_ids| ≥ max(aggregate)`.
3. **The required shape is a per-session JSON array.** One scalar `total_count` row cannot represent
   61,154 / 61,152 / 61,151 / 61,149 with session identity, predicate hash, and evidence. The
   samples contain that information; the sqlite file collapses it.

Bottom line: the **samples plus the verified extractor** constitute the aggregate evidence. The
sqlite file is a convenience snapshot and must not be promoted to the ledger's single truth.

---

## 7. Conditions for using it as `session_reported_aggregate`

**C1 — Per-session recording.** Store one entry per session walk in
`coverage_ledger.session_reported_aggregates`, e.g.
`{session_id, session_epoch, captured_at, start_index, raw_string, normalized_count,
partition_predicate_hash, response_hash, evidence_path}`. Never collapse to one scalar; the schema
says “per-session reported aggregates” (`crawler-feature-inventory.md:494`).

**C2 — Max rule, no averaging.** The proof RHS is `max(session_reported_aggregate)`
(`crawler-feature-inventory.md:1944`). Do not average and do not silently reconcile a changed total:
§8.5/§17.4 require separate coherent cohorts when the aggregate changes without compatible cohort
evidence. A spread beyond the observed churn band (5 postings, 0.008 %) should trigger cohort
separation/incomplete status rather than normalization. (A 1 % operational guard is reasonable; the
normative rule is cohort compatibility, not a magic tolerance.)

**C3 — Predicate identity.** The value is valid only for the empty-keyword, unfiltered search that
all three sessions used (`job_keywords=""`, `submitBtn2="Search"`; `mi/scripts/probe_t1_replay.py`
steps 1–2, `mi/scripts/probe_pagesize.py:36-37`, `mi/scripts/probe_pager.py:44-45`). The three
session result pages expose identical input-name sets (52/52, no missing/extra, checked for this
assessment), so the exposed predicate is the same. Any filter/default difference invalidates
cross-session comparability.

**C4 — Unit and flags.** `reported_total_unit='postings'`, exact integer, no `+`/floor/saturation
marker; `header_label_is_floor=false`; source `payload_field_union` for the MI allocation.
This is an **advertised count**, not a union of observed rows.

**C5 — Recompute per run; never hard-code.** The value must come from each run's sessions. Use it
for planning and end detection (`ceil(count/25)` pages; last page has `count mod 25` cards — 2 for
61,152, 24 for 61,149 — not always 25). Do not freeze 61,151/61,152 into config or documentation;
the existing docs already disagree: `mi/REPORT.md` §Tier Ladder quotes “61,151” against
`mi/samples/t1replay_results_page1_20261026T1920Z.html`, which actually says **61,152**, and
`SYNTHESIS.md` §1 carries 61,151.

**C6 — `session_min_count=2` completed walks still owed.** The aggregate is usable now, but the
lower-bound proof is not computable from these captures: no session was walked to completion (max
75 IDs, three pages). The spec requires at least two eligible completed session walks
(`crawler-feature-inventory.md:1944`; `seam-mappings/crawler-seam-mapping.md:1053`). The count is a
trustworthy RHS; the LHS does not yet exist at the required scale.

**C7 — Cheap integrity check.** Parse both in-payload representations (`var count` and
`p#txtJobCount`) and fail the extraction if they disagree. They agree 10/10 today; this guards against
a future template change that leaves one stale.

---

## 8. What would strengthen or invalidate the verdict

### Strengthen

1. **Two complete eligible walks in different sessions**, exact-ID union ≥ `max(aggregate)`. This is
   the actual proof, and it simultaneously tests the count's relationship to the enumerable set.
2. **Concurrent sessions** (same predicate, overlapping minute) returning the same total. That
   isolates session/backend effects from time churn; the current captures are sequential, so the
   61,154→61,149 decline is *consistent with* churn but not proven to be churn
   `[uncertain: concurrent same-predicate comparison not present in recon]`.
3. **A sort-pinned replay** (`PageSortTop=Posted`, two sessions). This is the one ordering control
   not exercised (`mi/REPORT.md` §Risks.4). If the total stays ~61 k while the row order becomes
   stable, it confirms the count is orthogonal to ordering and is the cheapest future experiment.
4. **A count-vs-time series** (e.g., 10 primed sessions over an hour) to fit the churn band and set
   the cohort/tolerance window in the ledger.
5. **An idle-session re-fetch** (hold one primed session ~30 min, re-query results). If the total is
   frozen at search time, `captured_at` means “search time”; if it tracks the live catalogue, it
   means “response time”. Either value works under the max rule, but the ledger semantics differ
   `[uncertain: session snapshot vs live query not tested]`.
6. **A last-page check in a full walk**: the final page should have `count mod 25` cards and the
   distinct-ID total should equal the reported count for a single permutation session. For 61,149
   that is 24 cards on page 2,446, not 25.

### Invalidate

1. **The total changes under a pure sort change** (`PageSortTop=Title` vs `Posted`) with predicate
   and session held fixed. Then the count is a property of the randomized *view*, not the predicate,
   and must not be used as the predicate aggregate.
2. **Concurrent same-predicate sessions differ by more than the churn band** (e.g., >1 %). That
   indicates per-session sampling/partitioning or F5 backend incoherence; `max()` would be poisoned
   and §8.5 cohort separation would be mandatory.
3. **A completed walk cannot reach the reported total**: distinct IDs systematically below the
   count, pager terminates early, or pages repeat before `ceil(count/25)`. Then the advertised count
   overstates the enumerable set and the lower-bound proof is unattainable.
4. **The count is a floor/estimate** (`+`, “500+”, “Reached limit: 1000 of …”). The supplied MI
   samples show exact integers, so this is not currently the case.
5. **Predicate contamination**: a session's hidden defaults differ (e.g., `IncludeStateWideJobs`,
   time-range), so the totals are not the same predicate. The 52-input-name check is only a partial
   guard.

---

## 9. Effect on the seam §7 marker

The marker reads:

> `[INCOMPLETE: §7.proof-sources — the supplied material does not identify a verifiable independent
> MI aggregate extractor or an independent OR total/floor source; MI’s lower-bound allocation and OR
> partition completion remain uncertified until those evidence sources are supplied.]`
> — `feature-inventories/crawler-feature-inventory.md:1829`

For MI, split the marker into two claims:

- **“verifiable … aggregate extractor” — now demonstrated.** `p#txtJobCount` via
  `mi_parse.total_count()` parses 10/10 results captures across T1 and T3, with a second in-payload
  representation agreeing 10/10. The count is exact, per-session, and invariant to the ordering
  permutation. That part of the evidence gap is closed by the recon.
- **“independent” / “allocation remains uncertified” — still open.** The count is server-reported in
  the same HTML as the rows; it is independent of *row enumeration* (which is what
  `payload_field_union` designates), not an external count source. More importantly, no eligible
  completed walks exist, so `session_count ≥ 2` and `|∪ IDs| ≥ max(aggregate)` are unproven. The
  marker should become “extractor verified; coverage proof pending completed session walks”, not
  “closed”.

This is consistent with `seam-mappings/crawler-seam-mapping.md:1053` (“Session union, minimum two
eligible completed walks; aggregate extractor and non-offset continuation unverified”) and with
§8.3's MI cursor verdict, which is about continuation capability and is unaffected by this
assessment.

---

## 10. OR note (non-comparable; left to the OR extractor)

`or/scripts/t1_total_probe.py` sends all 54 `loc` codes and reads a single
`Reached limit: 1000 of <N> Jobs` banner; `or/samples/total_20261026T192247Z/all_locations.json`
records `limit_text = "Reached limit: 1000 of 26699 Jobs matching …"`, `tbl1_rows=1000`,
`tbl2_rows=373`. That is a **single-request corpus total with an explicit 1,000-row cap**, not a
per-session aggregate, and OR's ordering problem is the no-op `start` rather than session
randomization (`SYNTHESIS.md` §2). It is therefore not directly comparable to the MI stability
question and does not affect this verdict; OR's count/floor decision belongs to its extractor.

---

## 11. Evidence hygiene (affects how the numbers should be quoted)

1. **Filename timestamps are script labels, not capture times.** `probe_t1_replay.py` hard-codes
   `TS = "20261026T1920Z"`, `probe_pagesize.py` uses `1935Z`, and `probe_pager.py` uses `1945Z`;
   file mtimes show the runs at 19:14, 19:16, and 19:19 UTC. Use mtimes for ordering/drift claims.
2. **`mi/REPORT.md`'s ordering table is not a reliable session inventory.** It lists first code
   `411083899` for the 19:20 session, but a grep of `mi/samples/*.html` finds that code in no
   capture, and its “19:36Z” first code `414569018` is the `PageSizeTop` postback result
   (`mi/samples/t1replay_pagesize_top100_20261026T1935Z.html`), not that session's page-1 first code
   (`401481406`, `mi/samples/t1replay_resultstop_20261026T1935Z.html`). The counts table in §4 above
   was computed directly from the files, not copied from the table.
3. **`fresh_results_20261026T195827Z.html`** (61,150) has no script; it is kept out of the core
   range. `mi/MANIFEST.md` does not list the 19:52–19:59 `detail_mi_*` / `fresh_results_*` captures
   (it inventories only `t1replay_fresh_results_20261026T1920Z.html`).
4. **No external/independent MI count exists in the recon.** The only count is the payload field
   itself; that is acceptable for `payload_field_union`, but it is not a facet or third-party
   source. `[uncertain: an independent MI total/floor source — not present in recon; would require
   a count on a different surface or an official feed.]`

---

## 12. Checks run for this assessment

All read-only; no network, no writes outside this file.

- Parsed `txtJobCount` from every `mi/samples/*.html`; verified the two in-payload representations
  agree 10/10 on results captures.
- Recomputed card counts and pairwise job-code overlaps for every successful `t1replay_*` capture and
  the T3 capture: session A page 1 × page 2 = 0/25; session B page 1 × `PageSizeTop` postback = 0/25
  with identical `startIndexNum=1` and total 61,151; session C page 1/adv1/adv2 pairwise 0/25,
  union 75; pagesize postback in A = 25/25 with page 2.
- Dumped `mi/data/probe.sqlite`: 75 `postings` rows, 75 distinct `job_code`, 3 sources × 25;
  `meta` = `[('rows','75'), ('total_count','61154')]`; traced 61,154 to the last `SRC` entry in
  `mi/scripts/parse_saved.py` (the oldest capture).
- Compared input-name sets of the three session result pages: identical 52/52.
- Checked `txtJobCount` remainders modulo 25 (2, 1, 24, 4) to rule out a rounded page count.
- Read `mi/REPORT.md`, `mi/MANIFEST.md`, `SYNTHESIS.md` §1–§2, the spec §8.3/§8.5, and the seam §7/§17
  allocations. No Stage 1/M0 artifacts, seam-mappings edits, crawler DAG, or Phase 4 module tests
  were touched.
