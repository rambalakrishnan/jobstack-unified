# MN endpoints (all `GET` on `https://careerforce.mn.gov`)

Source: `mn/REPORT.md` §Feed Discovery + §Request Contract + `mn/scripts/probe_filters.py` + `mn/scripts/probe_slice_cap.py`. Verified working 2026-10-26.

| Method + path | Purpose | Auth/session |
|---|---|---|
| `GET /job-search` | Unfiltered list feed (HTML, 10/page) | none (browser-like UA required) |
| `GET /job-search?page=N` | Paged feed, 0-indexed | same |
| `GET /job-search?loc=<value>&sort=<sort>&page=N` | City-sliced + sorted + paged feed | same |
| `GET /job-search?jvid=<36 chars>` | Detail page (same route, single-job mode) | same |
| `GET /robots.txt` | Policy (1,879 B, disallows `/job-search`) | none |

Not endpoints: `/jsonapi` (404), `/api/` (Google Maps Places JS, not first-party), `/search?k=` (Drupal content search, 0 job cards), `/careerforce/forms/job_search_anonymous_modal` (bookmark modal AJAX, not probed — write-adjacent).

## List params (`/job-search`)

All optional strings. `page` (int, 0-indexed, default 0; verified 0…999). `loc` (city facet value, Drupal-encoded, e.g. `Ada~D~ MN` = `Ada, MN`). `company` (company facet value, e.g. `Walmart`). `sort`: `best-match` (default, "Relevance") | `date-posted-desc` | `job-title-asc` | `company-asc`. `title` (free-text keyword; the page's `k` input belongs to `/search`, not the feed). `location[text]` + `radius` (5…100 miles; geocoded client-side by Google Places). `jvid` (36 chars = 32 hex + `8003`; switches route to detail mode).

`items_per_page` / `limit` are **ignored** (page size fixed at 10). Filters AND-compose (`loc` + `company` proven).

`~X~` escapes observed in `<option value>`: `~D~` = `,` · `~A~` = `.` · `~F~` = `&` · `~B~` = `-` · `~J~` = `'` · `~C~` = `+` · `~G~`/`~H~` = `(`/`)`. Copy values byte-for-byte (`mn/REPORT.md` §Request Contract).

City-slice encoding (verbatim from `mn/scripts/probe_slice_cap.py`):

`/job-search?loc=Minneapolis~D~%20MN&sort=date-posted-desc&page=711`
