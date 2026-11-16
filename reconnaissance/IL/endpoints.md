# IL endpoints (all `GET` on `https://ijl.illinois.gov`)

Source: `il/REPORT.md` §Request Contract + `il/scripts/t1_params_probe.py` + `il/scripts/t1_dummy_cookie.py`. Verified working 2026-10-26.

| Method + path | Purpose | Auth/session |
|---|---|---|
| `GET /` | Optional priming: obtains real Rails session cookie | none |
| `GET /search/jobs` | List feed (HTML, 10/20/50 per page) | `Cookie: _session_id=<any 32 hex>` |
| `GET /search/jobs` + `Accept: application/json` | List feed (JSON, fixed 10/page) | same cookie |
| `GET /search/jobs.json` | Identical JSON feed (format suffix) | same cookie |
| `GET /jobs/{id}` | Detail page, full description HTML | **none** (unchallenged) |
| `GET /robots.txt` | Policy (162 B, nginx-direct) | none |

Not endpoints: `/jobs` (404), `/sitemap.xml` (404), `/jobs/{id}` + `Accept: json` (406).

## List params (`/search/jobs`)

`page` (int 1-based, default 1), `per_page` (10/20/50; 100 → 50; ignored by JSON).
`search_job_search[...]` filters: `keywords`, `location`, `radius`, `job_location_city`, `job_location_state`, `county` (e.g. `Cook - Chicago`), `company`, `industry`, `education_level` (3–14), `wage` (`15.0-*`), `work_type` (full_time/part_time/full_time_or_part_time/see_job_description), `source` (External/Internal), `date_posted` (`1 week`/`2 weeks`/`1 month`), `last_update` (Today/Yesterday/`1 week`/`2 weeks`/`1 month`), booleans `offers_remote_work`, `driving_required`, `federal_contractor`, `green`, `hires_under_18`, `internship_externship`, `apprenticeship`, `on_the_job_training`.

County filter encoding (verbatim from `il/scripts/t1_params_probe.py`):
`/search/jobs?per_page=10&search_job_search%5Bcounty%5D=Cook+-+Chicago`
