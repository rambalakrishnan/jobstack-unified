# MI endpoints (all on `https://jobs.mitalent.org`)

Source: `mi/REPORT.md` §Request Contract + §Tier Ladder, `mi/scripts/probe_t1_replay.py`,
`mi/scripts/probe_pager.py`, `mi/scripts/probe_pagesize.py`. Verified working 2026-10-26.

| Method + path | Purpose | Auth/session |
|---|---|---|
| `GET /job-search/` | R1 form prime: `__VIEWSTATE` + 41-field form + session cookies (125,989 B) | none (first request works cookieless) |
| `POST /job-search/` | R2 execute search: empty keyword = whole feed → 302 to results | cookie jar from R1; `Referer` + `Origin` sent |
| `GET /job-seeker/jobsearch-results/` | R3 read page 1 of the session's result set (174–183 KB, 25 cards + `txtJobCount`) | same jar; 302s without a prior R2 |
| `POST /job-seeker/jobsearch-results/` | R4 paging/sort/page-size postbacks (`__EVENTTARGET` = pager slot) | same jar + freshest `__VIEWSTATE` from previous response |
| `GET /job-seeker/job-details/JobCode/{id}` | Detail page, full posting HTML (~150 KB) | primed jar (cookie-bootstrapped); **robots-disallowed** — see note |
| `GET /robots.txt` | Policy (2,016 B) | none |
| `GET /search-results?keyword=&location=` | DEAD END: Google CSE site-search shell, 0 postings | n/a |

Not endpoints: `/job-seeker/jobsearch-results` (no trailing slash → 302 to `/job-search/`,
`mi/samples/t1_jobseeker_results_headers_20261026.txt`); any `/api/*` or XHR job feed (proven
absent by `mi/samples/t3_netlog_20261026T191204Z.jsonl`); `/search-results` with `page=`/`skip=`
params (Google shell, ignores them).

## R2 filter fields (`POST /job-search/`, `...$` = `ctl00$ctl00$MainContent$MainContentSub$`)

Free text: `...$job_keywords` (empty = whole feed), `...$job_title`, `...$job_company`
(`...$RepeaterComps$ctl00$job_company`), `...$job_city`, `...$job_state`, `...$job_zip`,
`...$job_exclude1`, `...$job_exclude3`, `...$job_code_number`, `...$job_rate_amount`.
Selects: `...$job_radius` (0/5/10/15/25/50/100 miles), `...$job_time_range` (**1/7/14/30 days —
posted-within filter, the incremental-crawl hook**), `...$job_rate_time` (Hourly/Salary),
`...$PayRange$ddlPayRangeCategories`. Checkbox lists: `...$chlCharacteristics$0..7`,
`...$chlEducationLevel$0..6`, `...$chlPositionLevel$0..4`, `...$IncludeStateWideJobs`.
O*NET: `...$UcONetOccp$txtOccupations` / `$Occupations` (+ `hdn*` helpers).
All values read from the form's own markup in `mi/samples/t0_index_20261026T190805Z.html`;
default `job_time_range=30`, `job_radius=0` per `mi/samples/t1replay_post_page1_20261026T1920Z.txt`.

## R4 postback targets (`POST /job-seeker/jobsearch-results/`)

Pager: `__EVENTTARGET=ctl00$MainContent$pageTop2..5` or `$pageBtm2..5` (top/bottom identical).
Sort: `ctl00$MainContent$PageSortTop/Btm` ∈ Posted/Title/OrgName/City (unexercised).
Page size: `ctl00$MainContent$PageSizeTop/Btm` ∈ 25/50/100 — **all ignored, always 25**
(`mi/samples/t1replay_pagesize100_*`, `t1replay_pagesize_top100_*`).
Required companions: full hidden-field echo (`__VIEWSTATE`, `__VIEWSTATEGENERATOR`,
`ctl00$MainContent$hdMiTalentViewType=JOBSEEKERSEARCHJOB`, `startIndexNum`, …) harvested from
the immediately previous response; `__EVENTARGUMENT=""`.

## Detail-page note

`robots.txt` (`mi/samples/t0_robots_20261026.txt`) carries
`# Added to block bots from crawling the job details` + `Disallow: /job-seeker/job-details/`,
and `mi/REPORT.md` states detail URLs were never fetched — yet `mi/samples/detail_mi_httpx_*`
(19:59Z, full ~150 KB pages) and `mi/samples/detail_mi_net_*.json` (browser 200) exist with no
fetching script in `mi/scripts/`. Both facts are kept as evidence; confirm with counsel before
shipping detail fetches (`[uncertain: fetch requirements reconstructed from samples only]`).
