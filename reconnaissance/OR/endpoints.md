# OR endpoints (all `GET` on `https://secure.emp.state.or.us`)

Source: `or/REPORT.md` §Request Contract + `or/scripts/t1_*.py` + per-request `*.json`
metadata in `or/samples/`. Verified working 2026-10-26. One script, `location_content`
switch; `GET` only.

| Method + path | Purpose | Auth/session |
|---|---|---|
| `GET /jobs/index.cfm` | Landing / search home (form + `#location1` vocab) | live 5-cookie jar + consistent UA/CH (see `session.md`) |
| `GET /jobs/index.cfm` + `location_content=joblist.cfm` | **Job list** (HTML tables `#tbl_jobSearch` + `#tbl_jobSearch2`) | same jar |
| `GET /jobs/index.cfm` + `location_content=jobdisplay.cfm&ord={ord}` | **Job detail** (anonymous; full fields except employer contact) | same jar |
| `GET /jobs/index.cfm` + `location_content=adv.cfm&system=WIOA` | Advanced form (`#occupationalGroup`, `#location1..3`, `#datePosted`, wage, `jnum`) | same jar |
| `GET /jobs/index.cfm` + `location_content=no-criteria.cfm` | No-criteria error page (~15 KB; redirect target, not a request to author) | same jar |
| `GET /robots.txt` | Policy (108 B; `User-agent: * → Disallow: /`, quoted in `or/REPORT.md`) | none |

Not endpoints: bare `joblist.cfm` with empty criteria (→ no-criteria error, 15,373–15,489 B:
`or/samples/feed_20261026T191839Z/c1_adv_cat00.body`, `c4_bare_joblist.body`); any
`.xml`/`.rss`/`.csv`/`format=xml` export (none found — zero refs across all captures);
any JSON/XHR feed (none exists — `or/samples/bootstrap_20261026T191507Z/netlog.jsonl`).

One observed URL is deliberately absent from this table: the self-referral submit is a
state-changing write, not a crawl operation. It is documented ONLY as prohibition
evidence in `README.md` ("Prohibition evidence" section) and MUST NEVER appear in
configs, fixtures, or crawl code. A Phase 5 test must verify it is never called.

## List params (`location_content=joblist.cfm`)

Source: `or/REPORT.md` §Request Contract, `or/samples/paging_20261026T192128Z/A_multi_loc_008_019.json`
(`params`), `or/samples/total_20261026T192247Z/all_locations.json`,
`or/samples/bootstrap_20261026T191507Z_explore/adv.body` (advanced form controls).

`location_content=joblist.cfm` (str, req), `cat` (str — `00` rejected alone, pair with
`loc`), `keytype` (`Title|Description|Both`), `keyword` (str, may be empty), `loc` (csv
of 3-digit codes, e.g. `008,019`; advanced variant: `loc`/`loc2`/`loc3` one code each),
`wage` (num), `since` (`YYYYMMDD` from `#datePosted` — `[uncertain: never exercised]`),
`rad_ftpt` (`F|P|E`), `chk_ld`/`chk_pw`/`chk_jb` (`Y`), `jnum` (order-number lookup),
`calling_pg` (`search_home|adv`), `showcounts=Y`, `system` (`new|WIOA` —
`[uncertain: universe difference unmeasured; only new used for listings]`),
`type=N`, `lang=E`, `start` (**IGNORED by the server — never paginate with it**).

Verified working list URL (verbatim params from `or/scripts/t1_paging_probe.py`, request A):
`https://secure.emp.state.or.us/jobs/index.cfm?cat=00&keytype=Both&calling_pg=search_home&location_content=joblist.cfm&showcounts=Y&system=new&type=N&lang=E&keyword=&loc=008%2C019&start=1`
→ 200, 1,255,301 B, 654 + 373 rows, no truncation banner.

## Detail params (`location_content=jobdisplay.cfm`)

`location_content=jobdisplay.cfm` (req), `ord` (int, req — the stable job id),
`system=new`, `type=N`, `lang=E`. Canonical:
`https://secure.emp.state.or.us/jobs/index.cfm?location_content=jobdisplay.cfm&ord={ord}&system=new&type=N&lang=E`
(e.g. `ord=4594067` → 200, 29,411 B anonymous detail —
`or/samples/detail_20261026T192030Z/02_detail.json`).

The `sr` param (self-referral token) unlocks the employer contact block but is minted
ONLY by the prohibited write above — it is not a crawl parameter and MUST NOT be
pursued. Anonymous detail is the complete legitimate representation.
