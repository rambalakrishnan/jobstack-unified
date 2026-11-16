# Cursor assessment — WI, MN, MI: continuation or positional navigation?

**Scope.** This file answers one Phase 3.5 question for the three states named in seam §17.5: does the
reconnaissance establish that the paging mechanism produces a **response-bound continuation** (a
server-issued handle to the next slice) rather than **positional navigation** (a client-visible
ordinal into an ordering)? It is an assessment of the existing recon only. No new requests were
issued, no recon files were modified, and the only file written is this one.

**Verdicts**

| State | Verdict | One-line basis |
|---|---|---|
| WI | **STILL POSITIONAL** | `Page$<N>` is an absolute 1-based page ordinal; the response only gates which ordinals the current form snapshot may post. No token is issued. |
| MN | **STILL POSITIONAL** | Plain `?page=N`, 0-indexed, 10 rows/page. A one-row boundary shift was observed between two page fetches 1.5 s apart. |
| MI | **STILL POSITIONAL** | `startIndexNum` is a session-held **page number** (1-based), and pager slots are window-relative aliases for page numbers. The only non-numeric control (`»`) is a block jump (1→5→7), not a next-slice continuation. |

None of the three has a response-issued continuation handle anywhere in the wire format. The recon
therefore does **not** establish a continuation for any of them. The residual uncertainties are about
*coverage* (whether the positional walk is complete/stable), not about the mechanism; those are called
out per state and in §5.

Confidence split, to avoid over-reading the labels:

* WI mechanism: positional, high confidence. The exact admissibility rule for a posted ordinal is
  **INCONCLUSIVE** (see §2.4).
* MN mechanism: positional, high confidence. Whether a numeric walk can be certified for coverage is
  **INCONCLUSIVE** and, on the recon evidence, unlikely under live churn.
* MI mechanism: positional, high confidence. Whether the session walk is coherent/complete beyond two
  hops, and whether a pinned sort makes it deterministic, is **INCONCLUSIVE** (§4.3).

---

## 1. What is being tested

For this assessment a continuation must satisfy three operational conditions:

* **C1 — response-supplied position.** The response contains the handle that addresses the next slice.
* **C2 — non-ordinal handle.** The handle is not a small integer into the same ordering; it cannot be
  computed by a client that never saw the response (e.g. an opaque token, a last-seen key, a signed
  state blob whose meaning is not `rows[(N-1)*page_size : N*page_size]`).
* **C3 — next-slice / snapshot semantics.** Following the handle yields the next unseen slice and the
  handle pins the ordering or snapshot the slice belongs to.

The seam contract is stricter than "the next value appears in the response":

> `Offset is allowed only for ordering_model=Deterministic and coverage_scope=per_run.`
> — `seam-mappings/crawler-seam-mapping.md:1056`

and the three target rows under assessment are (verbatim excerpts; `seam-mappings/crawler-seam-mapping.md:1050-1053`; the IL row at line 1051 is omitted):

```text
| MN | Snippet+B / 30,000 ms | 10,000 cap; exact loc-facet equality; cosmetic 500 ignored; churn-shifted numeric page walk uncertified |
| WI | B only / 45,000 ms | 500 cap; jobs floor, never openings; saturation `+`; onet×wd splits; positional `Page$N` uncertified |
| MI | Snippet+B / 60,000 ms | Session union, minimum two eligible completed walks; aggregate extractor and non-offset continuation unverified |
```

A **response-gated ordinal** — an ordinal that must appear in the previous response's pager before the
server will accept it — satisfies a weak reading of C1 but fails C2 and C3. It is treated below as
positional, with the gate documented explicitly so the distinction is not lost.

The governing acceptance rule is spec §8.1:

> "Offset pagination is permitted only when:
> `ordering_model='Deterministic' AND coverage_scope='per_run'`.
>
> A numeric `page=N`, `start=N`, or equivalent positional postback does not become a non-offset cursor
> merely because the adapter stores the last value or follows a “Next” link.
>
> A permissible continuation cursor must be a verified response-bound continuation capability, not an
> arithmetic substitute for a page offset."
> — `full-featured-blueprints/2-state-bank-crawler-blueprint.md:767-775`
> (mirrored at `feature-inventories/crawler-feature-inventory.md:3525-3533`)

The starting certification for these targets is therefore already "not certified", and the question is
whether the recon evidence changes it:

```text
| MN | Numeric `page` parameter | Not certified for a churn-shifted walk |
| WI | `Page$N` stateless postback chains | Numeric positional semantics are not certified as a non-offset continuation |
| MI | Session-local serial postbacks | Session affinity is established, but a genuinely non-offset continuation capability is not established by the supplied description |
```

> — spec §8.3, `full-featured-blueprints/2-state-bank-crawler-blueprint.md:793-796`
> (mirrored at `feature-inventories/crawler-feature-inventory.md:3551-3554`)

C1–C3 above are the operational form of §8.1: a handle that is merely the last ordinal, or the next
rendered link, does not qualify. The recon's chained-paging probe is exactly the "adapter stores the
last value / follows a Next link" pattern §8.1 rejects, which is why the verdicts below stay
**STILL POSITIONAL** and the §8.nonoffset-cursors marker stays open.

---

## 2. WI — `__EVENTTARGET` postbacks

### 2.1 The wire mechanism is an absolute page ordinal

> "**Pagination model: `__EVENTTARGET` postback, not a query param.** There is no `page=`/`start=`
> parameter anywhere in the markup or URLs. The pager renders
> `javascript:__doPostBack('ctl00$ContentPlaceHolder_MainBase$GridViewJobs','Page$2')` (etc.), and the
> pager row also carries a `[ ... ]` link that jumps to the next 10-page block (`Page$11` from page 1,
> `Page$21` from page 11). Pages are 1-based, page size **20 (fixed — no page-size control exists on
> the results page; the only dropdown there is "Listed Within")**."
> — `wi/REPORT.md:104-110`

Measured pager contents (programmatic parse of the captures):

* Page 1 (`wi/samples/t0_page1_verified_20261026T191741Z.html`, `.../t1_post_Button_Search_20261026T191047Z.html`,
  `.../t1_getlist_direct_20261026T191118Z.html`): `tr.pad span` = `Page 1`; links =
  `Page$2` … `Page$10`, then `Page$11` with anchor text `[ ... ]`. Exactly 10 links; no "next" control
  other than the block-jump ellipsis.
* Page 11 (`wi/samples/t1_page11_20261026T191411Z.html`): span `Page 11`; links =
  `Page$10`, `Page$12` … `Page$20`, plus `Page$21` (`[ ... ]`).
* Page 12 (`wi/samples/t1_chain_from11_p12_20261026T191513Z.html`): span `Page 12`; links =
  `Page$10`, `Page$11`, `Page$13` … `Page$20`, plus `Page$21`.

So the request payload is `__EVENTTARGET=ctl00$ContentPlaceHolder_MainBase$GridViewJobs` plus
`__EVENTARGUMENT=Page$<N>`, where `<N>` is the absolute page index. Page size is 20, so
`Page$N` deterministically means rows `(N-1)*20+1 … N*20` of the current ordering.

### 2.2 `10_chained_paging.py` — the request/response sequence, step by step

The script header states the question it was built to answer:

> "is paging a *stateful chain* (must reuse the viewstate returned by the previous page) rather than a
> stateless jump? Takes the page-11 capture, harvests its `__VIEWSTATE`, POSTs Page$12 from it with a
> brand-new client (no cookies)."
> — `wi/scripts/10_chained_paging.py:2-7`

The sequence actually executed:

1. Input: the page-11 capture (`wi/samples/t1_page11_20261026T191411Z.html`, produced by
   `08_page_blocks_and_detail.py` at 19:14:11Z). That page was itself reached by posting `Page$11`
   from **page 1's** form snapshot, not by walking pages 2–10 (see §2.3).
2. Harvest every input/select/textarea on the form (`wi/scripts/10_chained_paging.py:23-39`). The
   page-11 sample contains `__VIEWSTATE` of 14,152 base64 chars.
3. Open a **brand-new** `httpx.Client`:
   > `with httpx.Client(headers=H, timeout=30, follow_redirects=True) as c:  # fresh: no cookies`
   > — `wi/scripts/10_chained_paging.py:44`
4. POST to the same URL (including the query string) with:
   > `data["__EVENTTARGET"] = "ctl00$ContentPlaceHolder_MainBase$GridViewJobs"`
   > `data["__EVENTARGUMENT"] = f"Page${p}"; data["__LASTFOCUS"] = ""`
   > — `wi/scripts/10_chained_paging.py:42-43`
   with `Referer`, `Origin`, and `Content-Type: application/x-www-form-urlencoded` (lines 46-47).
5. Response `200`, 84,480 B, grid present, 20 rows, pager span `Page 12`, first job numbers
   `004063762`, `004063765`, `004063776`; new `__VIEWSTATE` is 14,044 base64 chars; pager advertises
   `Page$10`, `Page$11`, `Page$13` … `Page$21`.
   Sample: `wi/samples/t1_chain_from11_p12_20261026T191513Z.html`.

The boundary is at least locally coherent: page 11's last five job numbers are
`004063718, 004063742, 004063744, 004063747, 004063748`; page 12 starts at `004063762`, with no
duplicate across the boundary. (Job numbers are not globally contiguous, so the 14-wide gap is not
evidence of missing rows; it is only evidence of no visible overlap at this boundary.)

**Answer to the probe's own question.** The sequence is a *stateful form chain* — the response's
`__VIEWSTATE` is what the next hop echoes — but not a response-bound cursor chain: the response does not
issue the next position. `Page$12` is derivable from page 11's HTML and the documented page size, and
the same page-11 snapshot also advertises `Page$10` and `Page$13`–`Page$21`. The state is in the form
envelope, not in the data position.

### 2.3 What this proves, and what it does not

**Proved by the sequence**

* The page-11 form snapshot is sufficient to obtain page 12. No cookie jar, no session continuity,
  and no prior hop from this client are required. This matches `04_postback_page.py` Test B, which
  posted `Page$2` from a cookie-less client using page-1's form and got the same 20 job numbers as the
  session request (`wi/scripts/04_postback_page.py:77-84`;
  `wi/samples/t1_page2_stateless_20261026T191137Z.html` vs `..._session_...html`).
* The server accepts a client-chosen absolute ordinal and renders that ordinal's 20-row slice. The
  target `Page$12` is derivable from page 11's rendered pager; it is not opaque.
* The response re-mints form state: page 11's submitted viewstate is 14,152 chars; page 12's is 14,044
  chars. Each hop therefore yields a new form snapshot, which the next hop would echo.

**Not proved**

* **No snapshot binding is demonstrated.** A single 11→12 boundary with no overlap is consistent with
  both a pinned snapshot and a live re-query on a quiet feed. The viewstate is not readable as plaintext
  (base64 payloads do not contain plaintext job numbers or titles, and they do not start with the
  standard unencrypted ASP.NET marker `0xFF 0x01`), so offline inspection cannot settle whether the
  slice is embedded. [INFERENCE: the viewstate is encrypted with a random IV — the same logical `Page$2`
  request yields different viewstate ciphertext in §6 — which is why decoded content is opaque.] No
  replay-under-churn test exists.
* **It is not a strict "previous response only" chain.** `08_page_blocks_and_detail.py` harvested
  **page 1's** form once and posted `Page$11` from it successfully:

  > `r1 = c.get(URL); time.sleep(1.5)` / `d = fields(r1.text)` / …
  > `data = dict(d); data["__EVENTARGUMENT"] = f"Page${p}"`
  > — `wi/scripts/08_page_blocks_and_detail.py:49-56`

  That is a 10-page jump from a page-1 snapshot. The recon's prose says the new viewstate "must be
  used for the following hop" (`wi/REPORT.md:203`), but that specific claim was not tested. The 08
  result shows a page-1 snapshot can reach at least `Page$2` and `Page$11` in one hop, including the
  block-jump target; whether pages 3–10 behave identically is untested (the pager renders them, so it
  is likely, but it is not evidence in hand).
* **The admissibility rule is not isolated.** See §2.4.

### 2.4 The pager-window gate — real, but not a cursor

Every observed request from a page-1 form snapshot, and the one from a page-11 snapshot:

| Source form | Requested | Rows | Result | Evidence |
|---|---|---|---|---|
| page 1 | `Page$2` | 20 | 200, span `Page 2` | `wi/samples/t1_page2_session_20261026T191137Z.html`, `..._stateless_...html` |
| page 1 | `Page$11` (the `[ ... ]` block jump) | 20 | 200, span `Page 11` | `wi/samples/t1_page11_20261026T191411Z.html`; `wi/samples/t1_blocks_20261026T191411Z.json` |
| page 1 | `Page$13` | 0 | 200, 39,459 B "System Error" | `wi/samples/t1_break_p13_20261026T191446Z.html`; `t1_breakpoint_...json` |
| page 1 | `Page$15` | 0 | 200, "System Error" | `t1_break_p15_...html`; `t1_breakpoint_...json` |
| page 1 | `Page$17` | 0 | 200, "System Error" | `t1_break_p17_...html`; `t1_breakpoint_...json` |
| page 1 | `Page$20` | 0 | 200, "System Error" | `wi/samples/t1_blocks_...json` (blocks `"20"`) |
| page 1 | `Page$24` | 0 | 200, "System Error" | `wi/samples/t1_blocks_...json` (blocks `"24"`) |
| page 1 | `Page$25` / `Page$26` | 0 | 200, "System Error" | `wi/samples/t1_paging_report_20261026T191337Z.json` |
| page 11 | `Page$12` | 20 | 200, span `Page 12` | `wi/samples/t1_chain_from11_p12_20261026T191513Z.html` |

Page 1's rendered pager is exactly `{2..10, 11}`. For the page-1 snapshot rows in the table, the two
successes (`Page$2`, `Page$11`) are inside that set and every failure is outside it. The page-11
snapshot then accepts `Page$12`, which is inside *its* advertised set. Crucially, the page-1 failures
are not simply past the end of the grid: page 11's pager renders
`Page$13` … `Page$20` (and a `Page$21` block jump), so those pages exist [INFERENCE: ASP.NET renders
pager links only up to the grid's page count]. Yet `Page$13` posted from page 1's form is rejected
while the same `Page$13` is a rendered target on page 11. The gate is therefore not a plain
`1 ≤ N ≤ PageCount` range check; it is relative to the **pager/form snapshot being used**. The
best-fit description is:

> "Only pages advertised in the current pager are accepted."
> — `wi/REPORT.md:339` (Tier ladder, T1 row)
>
> "Do **not** attempt to jump to a page number that is not present in the current pager — it returns
> the 39,459 B "System Error" page with HTTP 200. Prefer following the pager's own links (including
> the `[ ... ]` block jump) rather than incrementing blindly."
> — `wi/REPORT.md:305-307`

Why this still fails the continuation test:

* **C2 fails.** The handle is the literal small integer in `Page$12`. It is fully computable from the
  documented page size and current page; there is no opaque component.
* **C3 fails.** A single snapshot can address several pages (page 11's form advertises 10 and 12–21;
  page 1's advertises 2–11). The response does not issue "the next" position; it renders a set of
  positional links. The gate is a low-cardinality validity check, not a pointer to data.
* **The gate's scope is under-determined.** The untested cells are the ones that would isolate it:
  `Page$12` from page 1 (not advertised there, but the ordinal immediately after the block jump) and
  `Page$13` from page 11 (advertised there). The current evidence cannot distinguish "must be a
  rendered pager target" from "within the current block + one" — both predict the observed
  success/failure table. That is an INCONCLUSIVE sub-question inside a positional mechanism.

The recon itself refuses to treat the ordinal as a cursor:

> "Consequence: **dedupe by job number; never trust the total label or page offset as a stable
> cursor.**"
> — `wi/REPORT.md:129-130`
>
> "Use job number as the only cursor; re-crawl rather than resume by offset."
> — `wi/REPORT.md:352-353`

### 2.5 WI verdict

**STILL POSITIONAL.** `Page$N` is an absolute page-index coordinate in a 20-rows-per-page ordering.
The viewstate/form snapshot is a stateful envelope that constrains which ordinals the server will
accept, but it is client-carried, replayable without cookies, and re-minted per response; it is not a
server-issued continuation. The recon explicitly treats page offset as an unstable cursor and job
number as the only key. No `VERIFIED continuation` is available from this evidence.

What would decide the open points is in §5 (WI-P1…WI-P4).

---

## 3. MN — Drupal views offset paging

### 3.1 The mechanism is a URL ordinal, by construction

> "Drupal views pager, classic offset paging:
>
> * `?page=N`, **0-indexed**, 10 rows per page."
> — `mn/REPORT.md:135-137`

The depth probe issues exactly that shape:

> `r = c.get(BASE, params={"sort": "date-posted-desc", "page": p})`
> — `mn/scripts/probe_depth.py:29`

and the slice-cap probe does the same with the location filter:

> `("mpls_p711", {"loc": "Minneapolis~D~ MN", "sort": "date-posted-desc", "page": 711}),`
> `("mpls_p712", {"loc": "Minneapolis~D~ MN", "sort": "date-posted-desc", "page": 712}),`
> — `mn/scripts/probe_slice_cap.py:25-26`

Measured captures:

* `mn/samples/t0_mpls_p711_20261026T194000Z.html` — 4 cards, `Showing 500 jobs` (the label is
  clamped to 500; the facet count for Minneapolis is 7,113, so 7110 + 4 = 7,114 rows measured).
* `mn/samples/t0_mpls_p712_20261026T194000Z.html` — 0 cards, `No results found.`, no `Showing`
  header, 64,356 B.
* `mn/samples/t0_depth_p1000_...html`, `..._p4000_...`, `..._p8000_...` — 0 cards, byte-identical
  63,805 B empty-state bodies.

The p711/p712 pair is the cleanest possible proof of offset arithmetic: the last page of a 7,114-row
slice contains the 4 rows at offset 7,110. There is no token, no `last_key`, no cursor field anywhere
in the URL or pager links; the only coordinate is `page`. The compose captures behave the same way:
`t0_compose_woodbury_walmart_20261026T195800Z.html` (10 cards, `Showing 31 jobs`) and
`t0_compose_mpls_walmart_20261026T195500Z.html` (0 cards, empty state) are reached by adding `loc=` and
`company=` query parameters to the same `?page=N` interface; their pager links carry the same query
parameters and no continuation value.

### 3.2 Churn shifts the ordinal — observed, not merely suspected

The recon recorded the shift, and the capture pair confirms it at the jvid level. `probe_filters.py`
fetched page 0 and page 1, 1.5 s apart, for both `sort=date-posted-desc` and the Minneapolis location
filter (the `7998948c…` jvid quoted in `mn/REPORT.md:148` is from a different capture run; the pair
below is an independent confirmation):

> `("loc_Minneapolis", {"loc": "Minneapolis~D~ MN"}, "f_loc_minneapolis"),`
> `("loc_Mpls_page1", {"loc": "Minneapolis~D~ MN", "page": "1"}, "f_loc_minneapolis_p1"),`
> `("sort_date_desc", {"sort": "date-posted-desc"}, "f_sort_date_desc"),`
> `("sort_date_desc_p1", {"sort": "date-posted-desc", "page": "1"}, "f_sort_date_desc_p1"),`
> — `mn/scripts/probe_filters.py:24-29`

Programmatic comparison of the captures:

| Pair | Page 0 last jvid | Page 1 first jvid | Overlap |
|---|---|---|---|
| date-posted-desc, page 0 vs page 1 | `e9899db0175c408ebe065c4c1aae88f18003` | `e9899db0175c408ebe065c4c1aae88f18003` | 1 of 10 |
| Minneapolis, page 0 vs page 1 | `5c9884e19efe49ab9e49547d013986818003` | `5c9884e19efe49ab9e49547d013986818003` | 1 of 10 |

That is exactly the churn signature: a posting inserted at the top between the two fetches pushes the
old last row of page 0 into page 1. The pages are otherwise disjoint and the order differs. The recon
states the same finding in prose:

> "So page offsets are stable *while the underlying feed is unchanged*. They are **not** stable across
> posting churn: a posting inserted between two page fetches shifts everything by one. Observed: page
> 0's last card (`7998948c…`) reappeared as page 1's first card when the two pages were fetched 1.5 s
> apart on a live feed. **Dedupe on `jvid`; never assume 10-per-page × N.**"
> — `mn/REPORT.md:148`
>
> "**Dedupe** accumulated rows on `jvid` — posting churn shifts offsets between pages (observed
> page-0/page-1 overlap), so expect 1–3 % duplicate rows and never compute totals from card counts."
> — `mn/REPORT.md:275`
>
> "Midnight rollover and new-posting churn shift offsets mid-crawl: always dedupe, never trust
> totals."
> — `mn/REPORT.md:329`

### 3.3 MN verdict

**STILL POSITIONAL.** The mechanism is a 0-indexed row offset in the URL, with no continuation handle of
any kind. The recon additionally observed the offset move under live churn (one-row boundary duplicate
in two independent pairs), so a numeric page walk is not a stable cursor and the seam's "churn-shifted
numeric page walk uncertified" row is confirmed at the mechanism level. What remains uncertified is
coverage completeness under churn, which is a different (and harder) question.

No probe can promote `?page=N` to a continuation short of a site change; the certification question is
only whether a per-run offset walk can be accepted, which §17.5 permits only for
`ordering_model=Deterministic` + `coverage_scope=per_run`. The observed shift is evidence against the
former unless the walk is explicitly scoped as a noisy per-run snapshot with dedupe.

---

## 4. MI — session page index and window slots

### 4.1 The mechanism

MI is session-stateful: a fresh `GET /job-seeker/jobsearch-results/` 302s to `/job-search/` unless a
search POST has primed the session (`mi/REPORT.md:119-121`; `mi/samples/t1replay_fresh_results_...html`).
Paging is a POST to the results URL:

> "every hidden field from the *previous* results response (`__VIEWSTATE`, `__VIEWSTATEGENERATOR`,
> `__EVENTTARGET`, `__EVENTARGUMENT`, `ctl00$MainContent$hdMiTalentViewType=JOBSEEKERSEARCHJOB`,
> `ctl00$MainContent$startIndexNum`, `PageSizeTop/Btm`, `PageSortTop/Btm`, …) with `__EVENTTARGET`
> set to the pager slot"
> — `mi/REPORT.md:205`
>
> "| Response | 200, ~176 KB HTML, 25 cards, new `startIndexNum` |"
> — `mi/REPORT.md:207`

`startIndexNum` is documented in the field contract as:

> "| page number | `input#MainContent_startIndexNum` `value` | int | no | `7` | current page (1-based)
> — use for resume |"
> — `mi/REPORT.md:259`

The samples confirm it is a **page number**, not a row offset: page 1 has `startIndexNum=1`; page 2
(reached by posting `pageBtm2` from page-1 hidden fields) has `startIndexNum=2`; page size is 25
(`t1replay_results_page2_...html`). If it were a row offset, page 2 would read 26. It is a 1-based page
index.

### 4.2 The pager slots are window-relative aliases for page numbers

> "**Pager slot semantics (measured, `samples/t1replay_pager_*.html`):** five slots `pageTop1..5`.
> They are *positions in a sliding window over page numbers*, not fixed page numbers — and their href
> is `javascript:__doPostBack('ctl00$MainContent$pageTop<slot>','')`:
>
> | response | `startIndexNum` | slot text rendering |
> |---|---|---|
> | page 1 | `1` | `1`, `2`, `3`, `4`, `»`(slot5) |
> | after posting slot5 | `5` | `«`(slot1), `4`, `5`, `6`, `»`(slot5) |
> | after posting slot5 again | `7` | `«`(slot1), `6`, `7`, `8`, `»`(slot5) |
>
> So slot 5 is "advance the window", and reading the **displayed** text is the only safe way to know
> which page a slot goes to. `startIndexNum` in the response tells you where you landed."
> — `mi/REPORT.md:212-223`

Measured details from the three captures (programmatic parse):

* `mi/samples/t1replay_pager_page1_20261026T1945Z.html`: `startIndexNum=1`; slots `1 2 3 4 »`; slot 1
  is the current page (rendered as a non-postback `<a>`/span), slots 2–4 are numbered postbacks, slot 5
  is the unlabeled `»`.
* `mi/samples/t1replay_pager_adv1_20261026T1945Z.html`: `startIndexNum=5`; slots `« 4 5 6 »`; slot 3
  (`5`) is the current page. 25 cards, 0/25 job-code overlap with page 1.
* `mi/samples/t1replay_pager_adv2_20261026T1945Z.html`: `startIndexNum=7`; slots `« 6 7 8 »`; slot 3
  (`7`) is current. 25 cards, 0/25 overlap with adv1.

The probe sequence that produced these is:

> `for hop in (1, 2):`
> `    f = dict(hidden_fields(html))`
> `    f["__EVENTTARGET"] = "ctl00$MainContent$pageTop5"   # the '>>' / "Advance Pages" slot`
> `    f["__EVENTARGUMENT"] = ""`
> `    r = c.post(URL, data=f, headers=HDR)`
> — `mi/scripts/probe_pager.py:60-65`

**Interpretation.** Posting the `»` slot from page 1 landed on page **5**, not page 2: pages 2–4 were
skipped. Posting it again from page 5 landed on page 7. Whatever the intended UI semantics, the only
non-numeric control is a positional **window/block jump**, not a handle to the next unseen slice. A true
continuation would have returned page 2's 25 rows after page 1; it returned page 5's. Page-by-page
navigation does exist, but only by posting the numbered slot whose displayed text equals the target
page (`pageBtm2` from page 1 → page 2, `startIndexNum=2`, 0/25 overlap; `mi/scripts/probe_t1_replay.py:170-187`).

### 4.3 Why this is positional, and what remains unknown

* The coordinate the client selects is a **page number**. The slot is a window-relative alias for that
  number; the number is displayed in the HTML, and `startIndexNum` echoes the landed page.
* There is no opaque handle. The state is the session cookie plus the submitted hidden fields; the recon
  is explicit that "the session is the cursor":

  > "**Resume:** persist `(ASP.NET_SessionId, __VIEWSTATE, startIndexNum)`; the session is the cursor."
  > — `mi/REPORT.md:310-311`

* The ordering is **randomised per session**: four sessions returned page 1 with 0/25 overlap
  (`mi/REPORT.md:132-140`). So a page index is meaningful only inside one session; across sessions it
  addresses different rows. This is per-session positional page navigation, not a response-bound
  continuation, and not a deterministic offset either.
* Whether a pinned sort makes the order globally stable is untested: "whether pinning a sort key makes
  the order globally stable is `UNKNOWN — the sort postback was not exercised (request budget)`"
  (`mi/REPORT.md:143-145`). Beyond two consecutive pages is also untested
  (`mi/REPORT.md:158-162`). Those gaps concern coverage/determinism, not the mechanism.
* Requests are strictly sequential because each page's hidden fields come from the previous response
  (`mi/REPORT.md:319-321`). That is a response-derived **form state** dependency, not a continuation
  token; the next position is still a page number.

### 4.4 MI verdict

**STILL POSITIONAL** — specifically, a session-scoped page-index walk. The recon found no non-offset
continuation; the only candidate (`»`) is a positional block advance that demonstrably skips pages. The
seam's "non-offset continuation unverified" is therefore confirmed in the negative: nothing in the
captures issues or consumes an opaque continuation.

Residual INCONCLUSIVE points: whether the session walk is complete/duplicate-free beyond two hops, and
whether pinning `PageSortTop/Btm` yields a deterministic order. Those need §5's MI probes.

---

## 5. What further evidence would certify (or finally refute) each mechanism

These are the probes that would decide the open cells. They are listed so the next recon pass can be
scoped tightly; none is required to support the current verdicts.

### WI

| Probe | Request shape | Decision rule |
|---|---|---|
| **WI-P1** — isolate the gate | From a page-1 form snapshot, POST `Page$12` and `Page$19`. From a page-11 snapshot, POST `Page$12` and `Page$13`. | If page-1 rejects `Page$12` while page-11 accepts it, the gate is the rendered pager/window. If page-1 accepts `Page$12`, the report's "only advertised" rule is too strong (the gate is at most "current block + block jump"). Either outcome leaves the coordinate positional. |
| **WI-P2** — snapshot vs live re-query | POST `Page$12` twice from the *same* page-11 form snapshot, ≥2 min apart (ideally during a 525↔622 backend flip; the anomaly is documented at `wi/REPORT.md:124-130`). Compare all 20 order numbers and the total label. | Identical rows ⇒ the response/viewstate pins the slice (a weak continuation-like property). Differing rows ⇒ each POST re-queries live data, so the ordinal is a live offset. This is the single most important WI probe. |
| **WI-P3** — is the "chain" necessary? | Reuse the *same* page-1 form snapshot for `Page$2`, then `Page$3`, then `Page$4` (do not refresh the viewstate). | If all are accepted, the "new viewstate must be used for the following hop" claim (`wi/REPORT.md:203`) is false; the snapshot is a reusable form, and the only constraint is its advertised set. |
| **WI-P4** — ordinal tamper | POST `Page$999`, and separately `Sort$job_ttl`, from a page-1 snapshot. | Confirms the failure mode is a generic "System Error" body with HTTP 200, and that non-page event arguments are the sort channel. Already partly documented; include only if WI-P1/P3 are ambiguous. |
| **WI-P5** — deep reachability | From a page-11 form, POST `Page$21` (the block jump), then from the resulting page walk to the last advertisement. | Establishes whether the 25-page cap is reachable through chained window moves; the current recon only verified 11 and 12. |

If WI-P2 shows identical rows on replay, that is evidence of **snapshot-pinned slices**, but not yet a
continuation: the handle is still `Page$N`. To call it a continuation you would additionally need the
server to issue a value that is not an ordinal; no such value exists in any WI capture.

### MN

| Probe | Request shape | Decision rule |
|---|---|---|
| **MN-P1** — boundary drift rate | Walk one full slice (Minneapolis, `page=0..712`) logging every `data-jvid` and the boundary rows; repeat the walk. Compute duplicate rate and, against the facet count, the residual. | The recon already observed a one-row shift in 1.5 s. This quantifies whether dedupe + overlap closes the slice or whether keys are silently skipped. No outcome turns `?page=N` into a continuation. |
| **MN-P2** — sort/tiebreaker stability | Exercise the available sort options, and any `order=` parameter the pager exposes (not probed), under repeated fetches; compare full page fingerprints. | If a unique-key sort is exposed and offsets stay stable under churn, a per-run offset walk becomes arguable under §17.5. If not (the recon found no date filter and only four sorts), the offset walk remains noisy. |
| **MN-P3** — controlled insertion | Capture page 0; poll page 0 under `date-posted-desc` until a new jvid appears; immediately fetch page 1. | Reproduces the shift deterministically and shows whether the displaced key is a duplicate (insert) or a skip (delete/expiry). This is the cleanest evidence for the "churn-shifted" label. |
| **MN-P4** — deep-page pager lie | Fetch `page=499` and `page=999` and inspect the rendered pager links. | Confirms the pager widget is not a cursor and cannot be used for end detection (the recon says the widget lies past page 8, `mn/REPORT.md:139-141`). |

Because the wire format is literally `?page=N`, no MN probe can produce a response-bound continuation.
The only certification question is whether the numeric walk is acceptable as a per-run offset.

### MI

| Probe | Request shape | Decision rule |
|---|---|---|
| **MI-P1** — full slot map | From page 1, walk pages 1→10 by posting the slot whose displayed text equals `startIndexNum+1`; record `startIndexNum`, slot labels, and all 25 job codes per hop. | Verifies the numbered slots are a coherent page walk (increment by 1, disjoint consecutive pages) rather than a window-relative approximation. If pages 1..10 are reachable and disjoint, the mechanism is a clean positional walk *within* the session. |
| **MI-P2** — stale-form slot semantics | Hold the page-1 hidden fields; advance the session to page 5 via slots; then post `pageTop2` from the **old** page-1 form. | If it lands on page 2, the submitted form's `startIndexNum`/slot is authoritative. If it lands on page 6 or errors, the slot resolves against the session's current window. This tells the adapter whether it must refresh the form every hop (the recon's assumption). |
| **MI-P3** — offset tamper | Post a valid slot while setting `ctl00$MainContent$startIndexNum` to a different value (e.g. 100). | If honored, the server accepts a direct page index (still positional, client-addressable). If ignored, the position is server/session-decided (still positional, but not directly addressable). |
| **MI-P4** — determinism under pinned sort | Post `PageSortTop=Posted` (and `OrgName`) on page 1, then compare page 1/page 2/page 3 orderings across two fresh sessions with the same sort. | If the order becomes identical across sessions, numeric page walks become deterministic and the coverage risk shrinks. If it stays randomised, the session union is the only viable coverage strategy and no cursor exists. |
| **MI-P5** — enumerate all postback controls | Extract every `__doPostBack` target and hidden field from the raw results HTML (not only `pageTop/Btm1..5`); look for a `next`/`more`/token control and for any non-numeric event argument. | If a control exists whose target is not a page number, test it before concluding; the current samples show only five top and five bottom slots. |

If MI-P4 succeeds and MI-P1 shows a clean sequence, MI becomes a deterministic positional walk within a
session; it still does not become a continuation. If MI-P4 fails, the seam's "session union" requirement
is the only coverage story, and the "non-offset continuation" blocker remains.

---

## 6. Evidence-integrity notes (recon claims that do not survive sample-level checks)

These are recorded because they affect how much weight the seam can put on the recon's prose. None
overturns a verdict, but several are stated in the recon as if they were stronger than the captures
support.

1. **WI "byte-identical" is inaccurate.** `wi/REPORT.md:38` and `wi/MANIFEST.md:64` say the session and
   stateless `Page$2` responses are byte-identical. They are not: MD5
   `651b5832688596412d3c13a658cef83e` vs `8551264e4d54f84243a2172444e3b180`. The 20 job numbers, pager
   and visible text are identical; the differences are `__VIEWSTATE`, `__EVENTVALIDATION`, a
   stylesheet cache-buster timestamp, Cloudflare email-obfuscation strings, and Cloudflare challenge
   parameters. The conclusion the claim supports — "viewstate is not session-bound" — survives,
   because the stateless client returned the same 20 job numbers; the word "byte-identical" does not.

2. **MN "deterministic continuation" is contradicted by its own capture pair.**
   `mn/MANIFEST.md:36` labels `t0_f_sort_date_desc_p1_...html` a "Date sort page 1 (deterministic
   continuation)". The sample comparison shows page 0's last jvid is also page 1's first jvid (1 of 10
   overlap) for both date-sort and Minneapolis pairs. `mn/REPORT.md:148` correctly records the shift;
   the manifest label is the outlier.

3. **WI's "new `__VIEWSTATE` must be used for the following hop" is untested.**
   `wi/REPORT.md:203`. `08_page_blocks_and_detail.py:49-56` posts `Page$11` from page 1's snapshot in
   one hop, which already disproves a strict adjacency requirement within the advertised window. A
   same-snapshot `Page$2`→`Page$3`→`Page$4` sequence (WI-P3) would settle whether old snapshots are
   reusable beyond their first post.

4. **WI's "only pages advertised in the current pager are accepted" is a best-fit rule, not an
   isolated one.** The success/failure table is consistent with it, but the off-diagonal cells
   (`Page$12` from page 1; `Page$13` from page 11) were never requested. The recon does not distinguish
   "must be a rendered link" from "within the current block + block jump". This matters only to the
   exact failure predicate; both readings are positional.

5. **WI's viewstate is not inspectable offline.** The base64-decoded payloads (12,464; 14,152; 14,044
   chars) contain no plaintext job numbers or titles and do not begin with the standard unencrypted
   ASP.NET viewstate marker `0xFF 0x01`; the same logical request yields different viewstate bytes.
   [INFERENCE] This is consistent with encrypted viewstate and a random IV. The absence of row data
   from the decoded bytes therefore cannot be used to argue that the result set is not embedded; only
   the replay probe (WI-P2) can settle snapshot binding.

6. **MI's `startIndexNum` is a page number, not a row index.** The name suggests a row offset; the
   measured values are 1, 2, 5, 7 at 25 cards/page, and page 2 is `startIndexNum=2`. Any adapter or
   seam note that treats it as `rows[0:25]`-style offset will be off by a factor of 25.

---

## 7. Implications for the seam rows

* **WI — `positional Page$N uncertified` is correct and should stay.** The mechanism is an absolute
  page ordinal. The pager-window gate is a response-derived admissibility check, not a continuation;
  it does not make the coordinate opaque, and the recon explicitly says not to trust the page offset as
  a cursor. The open sub-question is only the gate's exact predicate (WI-P1) and whether slices are
  snapshot-pinned (WI-P2).
* **MN — `churn-shifted numeric page walk uncertified` is correct; the shift is now observed, not
  hypothetical.** `?page=N` has no handle. The uncertified part is coverage (duplicates/skips) under
  live churn, which is a per-run offset/dedupe question, not a continuation question.
* **MI — `non-offset continuation unverified` is correct; the recon found no non-offset control.** The
  only non-numeric pager control is a window/block jump; `startIndexNum` is a session page number; the
  ordering is randomised per session, so the session itself is the cursor (recon's own words). The
  "session union" strategy follows from that, but it is a coverage strategy, not a continuation.

**Spec §8.3 and the §8.nonoffset-cursors marker are unchanged.** The spec's starting rows — MN "Not
certified for a churn-shifted walk", WI "Numeric positional semantics are not certified as a non-offset
continuation", MI "a genuinely non-offset continuation capability is not established by the supplied
description" — are exactly what the samples show. Nothing in the recon is a *verified response-bound
continuation capability* in the §8.1 sense. The seam mapping treats this as an evidence gap, not a
naming problem:

> "The mapping preserves four source evidence gaps: Oregon solver implementation, MI/OR independent
> proof sources, MN/WI/MI permitted non-offset traversal, and empirical veto projections."
> — `seam-mappings/crawler-seam-mapping.md:1500`
>
> "None is resolved by scheduling, policy approval, renaming a cursor, accepting a memory exception,
> receiving a connector acknowledgement, or validating this document. Evidence or an explicitly
> versioned contract revision is required."
> — `seam-mappings/crawler-seam-mapping.md:1504`

The marker therefore stays open; closing it requires a mechanism that issues something other than an
ordinal, or a versioned change to the offset Floor — not a reinterpretation of these captures. In
particular, relabelling any of the three as `ordering_model='Deterministic'` to admit offsets would
contradict the observed churn (MN), the 622-vs-525 backend variance (WI), and per-session
randomisation (MI), and is not supported by this evidence.

No state in this assessment can be moved to **VERIFIED continuation**. The word "chain" in the WI
recon is accurate only in the sense of a client-carried form-state chain (each hop's viewstate is
harvested from the previous response); it is not a server-issued cursor chain, and the response's
pager is a set of positional links that the next request must stay inside.

---

## 8. Verification performed for this assessment

* Read-only: no new network requests were issued; the recon root was not modified.
* Programmatic re-checks against the captures: WI MD5s, `__VIEWSTATE` lengths, page-11/page-12 ID sets
  (empty intersection), pager link sets and spans, and the 39,459 B error-page size; MN boundary jvid
  equality and 1/10 overlap for both page-0/page-1 pairs, p711/p712 card counts and byte sizes; MI
  `startIndexNum` values, slot labels/current markers, 25-card counts, and 0/25 overlaps.
* No `crawler_acquisition` module test applies: this is an assessment-only deliverable and no
  extractor, fixture, config, or module test was touched.
