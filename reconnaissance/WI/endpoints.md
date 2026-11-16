# WI endpoints (all on `https://jobcenterofwisconsin.com`)

Source: `wi/REPORT.md` §Request Contract + `wi/REPORT.md` Addendum + `DETAILS.md` §3 (WI). Verified working 2026-10-26.

| Method + path | Purpose | Auth/session |
|---|---|---|
| `GET /Presentation/JobSeekers/JobOrderList.aspx` | List feed page 1 (bare URL = unfiltered; 20 rows) | **none** (no cookies, UA only) |
| `GET /Presentation/JobSeekers/JobOrderList.aspx?<query>` | Filtered list page 1 (`onet`, `wd`, `loctyp`, `Appr`, …) | **none** |
| `POST /Presentation/JobSeekers/JobOrderList.aspx?<same query>` | Paging (`__EVENTTARGET`=`…$GridViewJobs`, `__EVENTARGUMENT`=`Page$N`) / sort (`Sort$…`) | **none** (viewstate carries state, not cookies) |
| `GET /Presentation/JobSeekers/JobSearch.aspx` | Search form (22 controls); only needed to mint the list URL via POST | none (sets `ASP.NET_SessionId` + CF cookies, unused) |
| `POST /Presentation/JobSeekers/JobSearch.aspx` | Optional: submit search → 302 to `JobOrderList.aspx?<query>` | same client (cookies unused downstream) |
| `GET /Presentation/JobSeekers/EnhancedJobs-det.aspx?OrderNumber=<9-digit>` | Detail page (full description, pay, apply URL) | **login session** (`.ADAuthCookie` + `ASP.NET_SessionId` + `cf_clearance`); anonymous → 302 `/Login.aspx` |
| `POST /Login.aspx` | WebForms login (reCAPTCHA Enterprise) — **headed browser only** | account credentials; success → 302 `/Default.aspx` + `.ADAuthCookie` |
| `GET /robots.txt` | Policy (2,709 B; allows feed paths, `Disallow: /*.axd$`) | none |
| `GET /Presentation/TermsofUse.aspx` | 302 → `www.wisconsinjobcenter.org/legal/terms.htm`; no anti-scraping clause | none |

Not endpoints: `JobOrderDetail.aspx`, `JobOrder.aspx`, `PrintJobOrder.aspx` (all 302 to `/Login.aspx` anonymously — `DETAILS.md` §3); no `*.asmx`/`*.svc`/`/api/` JSON layer exists in the delivered HTML (`wi/REPORT.md` §Tier Ladder T2 FAIL).

## List query params (`JobOrderList.aspx`)

Canonical query string (verbatim, `wi/REPORT.md` §Feed Discovery, `wi/scripts/05_partition_probe.py`):

```
?kwords=&onet=&loctyp=&loc=&dist=&city=&edu=&shft=&ww=&wd=&tbsel=N&STCode=&src=JCW,PARTNERS&MOSCode=&Appr=False&VetsReadyEmployer=
```

Verified filters: `kwords` (free text), `onet` (SOC major `11`…`55`), `loctyp` (`City`/`County`/`Zip`/`Home`/`Varies`), `wd` (`2`/`3`/`7`/`15`/`30`), `Appr` (`True`/`False`); constants `tbsel=N`, `src=JCW,PARTNERS`. Unverified (`[uncertain: never driven]`): `loc`, `dist`, `city`, `edu`, `shft`, `ww`, `STCode`, `MOSCode`, `VetsReadyEmployer`.

## Paging POST body (verbatim shape, `wi/scripts/10_chained_paging.py`)

POST to the **same URL including its query string**, `Content-Type: application/x-www-form-urlencoded`, with every non-submit input/select/textarea harvested from the *current* page (`__EVENTTARGET`, `__EVENTARGUMENT`, `__LASTFOCUS`, `__VIEWSTATE` ~12.8–14.2 KB, `__VIEWSTATEGENERATOR`, `__EVENTVALIDATION`, `ctl00$hdnGoogleLanguageCode`, both `DropDownList_*Language`, `…$DropDownList_ListedWithin`), then `__EVENTTARGET=ctl00$ContentPlaceHolder_MainBase$GridViewJobs` + `__EVENTARGUMENT=Page$<N>`. Sort variants: `Sort$job_ttl` / `Sort$work_site_city_nam` / `Sort$job_ord_dt_sort` (header links in `responses/search_sample.html`).
