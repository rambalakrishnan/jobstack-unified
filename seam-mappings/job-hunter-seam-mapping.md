# Track 2.5: Job Hunter Boundary Seam Mapping Specification

## 1. Status, authority, and interpretation

| Property | Specification |
|---|---|
| Identifier | `job-hunter-seam-mapping/0.1.0` |
| Status | Proposed mapping specification; not deployment certification |
| Component | Job Hunter, the portfolio orchestrator |
| Governing source | `full-featured-blueprints/1-handoff-brief.txt` |
| Product source | `feature-inventories/job-hunter-feature-inventory.md` |
| Evidence contract | `contracts/00-evidence-kernel.yaml` |
| Attempt contract | `contracts/01-application-attempt-lifecycle.yaml` |
| Connector contract | `contracts/02-external-connector.yaml` |
| Write-domain contract | `contracts/04-owner-separated-write-domains.yaml` |
| Verification status | Specified, not executed |
| Language and primary store | Deliberately unselected |

### 1.1 Precedence

The handoff’s invariants govern. The supplied versioned contracts implement those invariants. This document maps Job Hunter onto those contracts without changing their record shapes or ownership rules. The feature inventory supplies product capabilities, legacy fields, candidate inputs, search concepts, and implementation history.

The following legacy choices are not current portfolio requirements:

- TypeScript, Python, Firebase, or Restate as Job Hunter’s required runtime.
- Firestore as the orchestrator’s authoritative store.
- Direct browser control by Job Hunter.
- A shared internal browser primitive abstraction.
- A scalar tracker status as the authoritative application outcome.
- Company/title hashes as posting or attempt identities.
- Practice success as production evidence or dispatch authorization.

Firebase may remain a dashboard-local cache. Restate may remain a private durable-execution implementation. Neither becomes the cross-component exchange.

### 1.2 Normative terminology and schema notation

**MUST** and **MUST NOT** identify conformance requirements.

Type prefixes identify exact supplied definitions:

- `K`: Evidence Kernel, `evidence-kernel/0.1.0`.
- `L`: Application Attempt Lifecycle, `application-attempt-lifecycle/0.1.0`.
- `E`: External Connector, `external-connector/0.1.0`.
- `W`: Owner-Separated Write Domains, `owner-separated-write-domains/0.1.0`.
- `JH`: Proposed Job Hunter-local records defined here.

A qualified type imports its complete supplied schema and semantic rules. This avoids creating incompatible copies of shared types.

For every local schema table:

1. Every listed field is required unless explicitly identified as optional.
2. Objects are closed; undeclared properties are rejected.
3. An identifier is a nonempty opaque string.
4. `T[]` means an array of `T`.
5. `T | Missing` means an explicit union, not field omission.
6. Empty arrays establish an empty collection; they do not mean unknown.
7. Numeric values are finite. Integer bounds follow the kernel’s safe-integer bounds.
8. Artifact references require retained, validated bytes.
9. Version pins identify immutable schema, code, policy, or catalog artifacts.
10. Proposed local record names are not claims that implementations already exist.

### 1.3 Scope

The specification covers candidate inputs, queries, crawler consumption, evaluation, selection, materials, commissioning, manual recording, connector orchestration, origin verification, reconciliation, private persistence, correspondence, scheduling, costs, dashboard access, retention, recovery, and conformance.

It does not supply absent business thresholds, employer receipt mappings, native endpoints, or deployment guarantees. Missing source semantics block only operations requiring those semantics.

---

## 2. Boundary and ownership map

### 2.1 Semantic boundaries

| Boundary | Owns | Explicit exclusion |
|---|---|---|
| Contracts | Schemas, invariants, conformance requirements | Candidate-specific decisions |
| Crawler | Acquisition, extraction, render evidence, coverage, crawler classification | Candidate suitability and applications |
| Job Hunter product writer | Evaluations, materials, selection, priority, work ownership, attempt links | Crawler fields and employer facts |
| Commissioner | Immutable attempt intent and owner bindings | Any outcome axis |
| Executor connector | Preparation, dispatch observations, observation window, local controls | Application facts and reconciliation |
| Subject | Native execution claims | Independent assessment of those claims |
| Origin fact recorder | Verified normalization and publication of origin facts | Becoming the employer or inventing facts |
| Reconciler | Comparisons over pinned source revisions | Editing claims or facts |
| Hellscape | Practice fixture truth and diagnostics | Production commitment or origin representation |
| Dashboard | Presentation and authorized command submission | Direct owner-domain writes |
| Development tools | Specifications, code generation, verification, clarification | Runtime application authority |

A deployment may host several roles, but their grants, owner domains, revision authorities, and durability boundaries remain distinct.

### 2.2 Seam register

| ID | Producer → consumer | Boundary object |
|---|---|---|
| JH-01 | Candidate custodian → evaluator | Versioned restricted profile artifact |
| JH-02 | Query policy → discovery requester | Versioned query and veto-policy artifacts |
| JH-03 | Crawler publisher → Job Hunter | Verified `W.LogicalRow` |
| JH-04 | Evaluator → product writer | Evaluation artifact and `W.EvaluationReference` |
| JH-05 | Operator/policy → product writer | `W.ProductSelection` |
| JH-06 | Material generator → product writer | Material artifact and `W.MaterialReference` |
| JH-07 | Product worker → lease authority | Owner-fenced kernel lease operations |
| JH-08 | Commissioner → kernel | `K.Manifest`, then `L.AttemptCommission` |
| JH-09 | Job Hunter → connector | `Describe`, `Prepare`, `Start` |
| JH-10 | Connector → Job Hunter | `Observe` pages and immutable publications |
| JH-11 | Job Hunter → connector | Four separately authorized control verbs |
| JH-12 | Connector → artifact consumer | Inventory and verified chunks |
| JH-13 | Manual recorder → kernel | Manual observations |
| JH-14 | Employer receipt → fact recorder | Restricted raw receipt and verification evidence |
| JH-15 | Fact recorder → application domain | Cumulative `L.OriginFact` history |
| JH-16 | Source domains → reconciler | Pinned revisions; report-only output |
| JH-17 | Owners → read-view publisher | Complete revisions, publication receipts, seals |
| JH-18 | Read API → dashboard | Derived views with evidence and freshness |
| JH-19 | Mail/calendar adapters → private services | Provider observations and authorized effects |
| JH-20 | Model provider → cost accountant | Usage evidence and priced derivations |
| JH-21 | Runtime → secret provider | Scoped access references |
| JH-22 | Hellscape → Job Hunter | Practice evidence only |

### 2.3 Write grants

| Actor | Permitted authoritative writes |
|---|---|
| Crawler writer | Job `crawler` domain |
| Product writer | Job `downstream` domain |
| Connector | Attempt `dispatch` and `observation`, when bound |
| Delegated subject adapter | Attempt `execution`, faithfully preserving subject authorship |
| Manual recorder | Attempt `observation`; never dispatch or execution |
| Origin fact recorder | Attempt `application`, under the bound origin policy |
| Reconciler | Attempt `report` |
| Read-view publisher | Derived publication pointers and seals only |
| Dashboard | None; submits commands to authorized gateways |

Every write checks authenticated identity. Serialized `writer_id`, provenance, hashes, or role labels do not grant authority.

---

## 3. Shared evidence requirements

### 3.1 Missing values

`K.Missing` contains required `value: null`, required `reason`, and optional nonempty `detail`.

The six permitted reasons are:

| Reason | Meaning |
|---|---|
| `not_enabled` | Deliberately disabled facility |
| `not_applicable` | No meaning in the declared scope |
| `not_observed` | Value not established |
| `observation_lost` | Expected or previously available observation lost |
| `unsupported_by_subject` | Evidenced scoped subject limitation prevents supply |
| `manual_override` | Authenticated journaled operator decision withheld or superseded a local value |

A manual override cannot rewrite an immutable commission, source claim, origin fact, or prior publication.

Forbidden conversions include missing salary to zero, missing tokens to zero, absent confirmation to noncommitment, unknown lists to empty arrays, and missing native time to exact zero.

Raw vendor bodies may contain bare nulls only while retained as raw artifacts. Normalized records use kernel missingness.

### 3.2 TimePoint

Every `K.TimePoint` contains:

| Field | Type and rule |
|---|---|
| `clock_id` | Registered identifier |
| `boot_id` | Registered clock lifetime |
| `origin` | `engine_measured`, `browser_measured`, `subject_reported`, or `manual_reference` |
| `monotonic_offset_ms` | Nonnegative finite coordinate |
| `utc_annotation` | Date-time string or `Missing` |

Clocks are registered before use or atomically by an allowed clock-registration event. No subtraction crosses clocks, boots, or origins. UTC is annotation, not elapsed-time authority.

Employer dates, employment dates, email source dates, and future interview times retain their business semantics in source artifacts. They do not acquire invented monotonic coordinates. Their ingestion receives an actual recorder `TimePoint`.

### 3.3 Measurement

Every observed metric or duration uses `K.Measurement`:

| Field | Required meaning |
|---|---|
| `measurement_id` | Unique scoped identity |
| `name` | Explicit metric name |
| `scope` | Kernel scope |
| `quantity` | `duration` or `scalar` |
| `unit` | `ms` for duration; explicit scalar unit |
| `origin` | Actual measurement/report origin |
| `clock_id`, `boot_id` | Registered source lifetime |
| `method` | `endpoint_difference`, `source_value`, `evidence_bound`, or `unavailable` |
| `start`, `end` | `TimePoint` or reasoned missingness |
| `estimate` | Exact, bounded, or unavailable |
| `resolution` | Nonnegative granularity or `Missing` |
| `censoring` | `none`, `left`, `right`, `both`, or `unavailable` |
| `comparability_group` | Identifier or `Missing` |

Estimate forms are closed:

- Exact: `kind: exact`, numeric `value`.
- Bounded: `kind: bounded`, `lower_bound`, `upper_bound`; each bound is numeric or `Missing`, and at least one is numeric.
- Unavailable: `kind: unavailable`, `value: Missing`.

Endpoint differences require matching clock, boot, and origin, ordered endpoints, and arithmetic equality. Duration values and bounds are nonnegative. Exact values use no censoring. Bounded values use `evidence_bound`; unavailable values use unavailable method and censoring.

Reported zero remains a reported zero. Aggregate runtime is not divided into invented step durations. A comparability-group label does not itself establish equivalent semantic boundaries.

Configured limits use `DurationLimit`, not `Measurement`.

### 3.4 References and hashes

| Type | Complete field set |
|---|---|
| `K.ArtifactReference` | `digest`, `size_bytes`, `media_type`, `owner_domain`, `access` |
| `K.EvidenceRef` | `journal_id`, `sequence`, `event_id`, `event_hash`, `pointer` |
| `K.JournalPrefix` | `journal_id`, `last_sequence`, `head_hash` |
| `K.VersionPin` | `id`, `version`, `artifact_digest` |
| `K.MeasurementEvidence` | `measurement`, `evidence_refs` |

Artifact access is `public` or `restricted`. References grant no read authority.

Canonicalization uses `kernel-jcs-sha256/1`: UTF-8, RFC 8785 canonical JSON, SHA-256, and `sha256:<64 lowercase hexadecimal digits>`. Artifact digests identify exact bytes. Strings and array order remain unchanged. Redacted exports are different artifacts.

Validation rejects duplicate mapping keys, unknown versions, nonfinite numbers, undeclared closed-object properties, unsupported formats, unresolved references, and invalid hashes.

### 3.5 Journal and producer rules

Untrusted producers submit `K.EventSubmission`, whose fields are:

`producer_sequence`, `event_kind`, `event_schema_version`, `occurred_at`, and `payload`.

`K.EvidencePayload` contains `data`, `measurements`, `evidence_refs`, and `artifact_refs`. Every nested artifact identity is included in `artifact_refs`.

The ingestion authority assigns the journal envelope’s identity, sequence, authenticated producer, owner domain, role, assertion kind, provenance, recorded time, evidence scope, and hashes. Callers cannot submit those fields as trusted authority.

The first event is `manifest_admitted`. Sequences are contiguous. Identical producer-sequence retries deduplicate; conflicting content is an integrity incident. Gaps, loss, overflow, closure, and flush receipts remain explicit.

A local authoritative effect, idempotency record, revision advance, journal effect, and replayable response commit atomically within that owner. Remote employer effects cannot join that transaction.

---

## 4. Identity and duplicate handling

| Identity | Meaning |
|---|---|
| `(target, job_id)` | Source posting root, `W.JobEntityKey` |
| `portfolio_job_id` | Product-facing job identity |
| `L.JobReference.job_id` | Same portfolio-facing identity |
| `(attempt_id, kind)` | Immutable application-attempt identity |
| `commission_id` | Immutable commission record |
| `run_id`, `journal_id` | Evidence identities |
| `local_handle` | Connector-local logical execution |
| `native_run_id` | Actually observed native identity |
| `origin_application_id` | Actually observed employer identity |
| `candidate_id` | Opaque candidate reference |
| `evaluation_id`, `artifact_id` | Product artifact identities |

The legacy formulas are preserved as duplicate-candidate hints:

- Jobs: `sha256(companyName + "|" + jobTitle + "|" + locationRaw)`.
- Applications: `companyName + "|" + jobTitle`.

They are not primary keys, merge authority, or resubmission guarantees. They cannot merge different source roots, locations, practice/production attempts, or employer operations.

The legacy hash’s encoding and normalization are not supplied. Existing hashes are preserved. Recomputing requires a pinned adapter; trimming, case folding, or Unicode normalization cannot be introduced silently.

### 4.1 Manual discovery

A manually discovered job may receive a portfolio identity and immutable snapshot without a crawler root.

For that path:

- Unknown source target and job ID use `Missing(not_observed)`.
- No crawler coverage, render verdict, revision, or `JobEntityKey` is fabricated.
- No `EvaluationReference` requiring a nonexistent crawler input is fabricated.
- Human selection evidence may be commissioned directly.
- Later crawler association is a new evidenced relation, not a rewrite of the commission.

---

## 5. Read-only crawler consumption

### 5.1 LogicalRow admission

A crawler-backed evaluation consumes an immutable `W.LogicalRow` containing:

`record_type`, `schema_version`, `entity`, `registration_digest`, `registration`, `domains`, and `seal_point`.

For a job, `domains` contains exactly `crawler` and `downstream`.

Each nonzero published slot contains `revision`, `document`, `publication_ref`, and complete `snapshot`. A zero slot contains `revision: 0` and `value: Missing`.

Admission verifies:

1. Job entity and registration identity agree.
2. Registration digest matches complete bytes.
3. Crawler slot is nonzero.
4. Slot revision equals embedded revision.
5. Embedded entity, registration digest, domain, owner, and writer agree.
6. Document digest matches the complete embedded publication.
7. Publication evidence proves complete installation in the named view.
8. Seal vector matches every slot.
9. Seal-selection evidence is within its prefix.
10. Referenced bytes and evidence are available and authentic.
11. No revision identity has conflicting content.

A zero downstream slot is valid. The crawler must not initialize a pretend product revision.

### 5.2 Crawler field map

All fields below are read-only to Job Hunter.

| Field group | Fields and consumption |
|---|---|
| Acquisition provenance | `source_url`, `listing_page_url`, `source_response`, `extractor`, `rendered_at`, `evidence_refs` identify observed content |
| Acquisition identity | `fetch_key`, `fetch_key_profile`, `fetch_identity` identify the exact request/listing basis |
| Content contract | `content_declarations`, `content` supply typed evaluation input |
| Render evidence | `render_verdict`, `render_basis`, `render_history` establish acquisition quality |
| Processing state | `pipeline_state`, `classification_surface`, `active_run_id` remain crawler operational facts |
| Fencing | `input_revision`, `generation_id`, `lease` remain crawler-owned |
| Retry accounting | `retry_count`, `max_retries_effective`, `last_failure_reason` are not product retries |
| Classification | `classifier_results`, `final_genuine_result_id`, `bypass_reason` retain genuine versus bypassed classification |
| Semantic candidate | `semantic_candidate`, `semantic_evidence_refs` do not become product selection |
| Discovery | `first_seen_run_id`, `last_seen_run_id`, `first_seen_at`, `last_seen_at`, `coverage` retain observation scope |
| Replacement | `replacement_lineage` retains backward archive dependency |

### 5.3 JobContent transformation

| Canonical field | Legacy field/source | Rule |
|---|---|---|
| `title` | `title` | Secondary suitability signal |
| `employer` | `company` or normalized `org` | Preserve source text |
| `snippet` | Source snippet | Not a substitute for required full description |
| `description` | `rawDescription` or normalized `description` | Main reranker input |
| `posted_date` | Source posting date | Preserve source semantics |
| `location` | `location` | Do not invent remote eligibility |
| `direct_apply_url` | `directApplyUrl` | Never default from source URL |
| `portal_type` | `portalType` | Routing hint, not capability evidence |
| `closing_date` | `closingDate` | Preserve text; no invented timezone or instant |
| `extended` | Declared salary, requirements, or other extractions | Typed, declared, evidenced values only |

Salary and requirements do not become undeclared properties of `JobContent`. They are declared extended fields or evidence-backed evaluation-input artifacts.

### 5.4 State interpretation

| State | Required interpretation |
|---|---|
| Render `Pass` with required fields | Usable acquisition |
| `Pass` missing required extraction | Reject as `incomplete_extraction` |
| `ThinShell`, `RenderIncomplete`, `EdgeBlock`, `SensorFail`, `ChallengeIncomplete` | Non-Pass acquisition; not candidate unsuitability |
| `pending_classification` | Crawler work pending |
| `ready` | Crawler readiness only |
| `vetoed` | Crawler relevance veto only |
| `render_failed` | No successful extracted-content result |
| `failed` | Crawler operational failure |
| `DISCOVERED` | Source candidate discovered |
| `SHORTLISTED` | Crawler relevance candidate, not product `go` |
| `CLOSED` | Requires closure evidence; not inferred from one missing crawl |

Non-Pass acquisitions have reasoned missingness for every content value and no genuine classifier result. Bypass produces no classifier result. Shadow-mode raw `VETO` applied as `PASS` remains distinguishable.

`ClassifierResult` fields remain unchanged: `result_id`, `stage`, `model`, `tokenizer_digest`, `prompt_digest`, `canonicalization_version`, `input_hash`, `verdict`, `verdict_applied`, `confidence`, `reason`, `classified_at`, `latency`, `application_revision`, `policy_revision`, and `evidence_refs`.

### 5.5 Coverage

Every coverage reference retains `run_id`, `partition_id`, `partition_definition_hash`, `status`, `pagination_coverage_proven`, `ledger`, and `evidence_refs`.

| Status | Meaning |
|---|---|
| `open` | Ongoing partition |
| `bisected` | Subdivided partition |
| `proven` | Referenced proof establishes declared pagination coverage |
| `incomplete` | Known unresolved coverage |
| `empty_unproven` | No observations do not prove emptiness |

Job Hunter does not convert empty search results into universal absence of opportunities.

---

## 6. Product-owned downstream interface

### 6.1 JobDownstreamValue

`W.JobDownstreamValue` contains exactly:

| Field | Type and ownership |
|---|---|
| `track` | Product `MaybeString` |
| `priority_hint` | Product `MaybeNumber`; no inherited formula |
| `selection` | `W.ProductSelection | Missing` |
| `ownership` | `W.DownstreamOwnership` |
| `evaluations` | `W.EvaluationReference[]` |
| `materials` | `W.MaterialReference[]` |
| `application_attempts` | `W.AttemptLink[]` |

### 6.2 EvaluationReference and LogicalRow linkage

`W.EvaluationReference` contains:

| Field | Mapping |
|---|---|
| `evaluation_id` | Evaluation identity |
| `crawler_input` | Exact nonzero crawler revision and document digest |
| `candidate_profile` | Exact profile artifact |
| `evaluation` | Versioned evaluation artifact |
| `evidence_refs` | Nonempty derivation/registration support |

**The shared type does not contain a `LogicalRow` field.** The evaluation artifact defined below contains the exact logical-row artifact, its registration reference, and seal ID. Its crawler pin must equal the row’s crawler slot and the reference’s `crawler_input`.

This supplies the requested pinned-row linkage without illegally extending Contract 04.

### 6.3 Other downstream records

| Record | Complete field set and constraints |
|---|---|
| `W.MaterialReference` | `artifact_id`, `role`, `content`, `evidence_refs`; role is `resume`, `cover_letter`, `supplemental_responses`, or `other` |
| `W.ProductSelection` | `decision`, `evaluation_id`, `rationale`, `evidence_refs`; decision is `go`, `no_go`, or `review` |
| `W.DownstreamOwnership` | `state`, `claimant`, `lease`, `evidence_refs`; claimed requires claimant and kernel lease artifact; unclaimed makes both inapplicable |
| `W.AttemptLink` | `attempt`, `commission_digest`, `evidence_refs`; commission must identify this portfolio job |

Human selection may use a missing evaluation ID. Actual submitted materials belong to attempt evidence, not merely the latest product material reference.

### 6.4 Complete publication

Every downstream write produces `W.DataDomainRevision`:

`record_type: owned_domain_revision`, `schema_version: owner-separated-write-domains/0.1.0`, `entity`, `registration_digest`, `domain: downstream`, `owner_domain`, `writer_id`, `revision`, `previous_revision`, `evidence_prefix`, `evidence_refs`, and complete `value`.

Revision is previous revision plus one. Stale expected revisions reject the entire write.

### 6.5 Private product operations

| Operation | Preconditions | Owner-local effect |
|---|---|---|
| Record evaluation | Valid matching input pins | Append immutable reference |
| Record material | Valid bytes and provenance | Append immutable reference |
| Set selection | Authorized policy or human decision | New selection with historical decision retained |
| Set track | Authorized product decision | Change only track |
| Set priority | Pinned prioritization basis | Change only priority |
| Claim work | Valid kernel lease grant | Claimed ownership |
| Renew work | Current unexpired lease | New lease reference |
| Release/reclaim work | Authorized fenced transition | Unclaimed ownership |
| Link attempt | Commission already durable | Append attempt link |

Each operation preserves unrelated downstream fields, writes no crawler fields, uses owner-local idempotency, and publishes asynchronously.

### 6.6 Selection transitions

Initial selection may become `go`, `no_go`, or `review` with evidence.

Every pairwise transition among those three states is permitted only through a new authorized decision:

- Review resolves to go or no-go.
- Go returns to review for stale inputs or new uncertainty.
- Go becomes no-go for a new veto.
- No-go returns to review for reconsideration.
- No-go becomes go only with explicit new rationale.
- Same-state revisions may add support.

Prior decisions remain journaled. Selection changes do not mutate existing commissions or stop native work. Those require separate authority and controls.

---

## 7. Candidate profile, playbooks, and search inputs

### 7.1 Source fidelity

Candidate data distinguishes raw history, candidate statements, analytical interpretation, proposed translations, and independently verified credentials.

The inventory’s documentary labels do not establish that the underlying corpus or employer verification was independently inspected.

Required ambiguity handling includes:

- `CDL` in an exclusion query does not establish current license possession.
- Minted salary value `22` in a monthly-salary field is not silently converted to hourly pay.
- Conflicting employment dates remain unresolved until evidenced.
- Inferred capabilities are not credentials.
- Sensitive personal history is not automatically approved application content.
- “Equivalent experience” does not automatically satisfy an employer’s mandatory degree rule.

### 7.2 CandidateProfileArtifact

| Field | Type |
|---|---|
| `record_type` | Constant `candidate_profile_artifact` |
| `schema_version` | Constant `job-hunter-candidate-profile/0.1.0` |
| `candidate_id` | Identifier |
| `source_documents` | Artifact reference array |
| `source_evidence_refs` | Evidence reference array |
| `employment_history` | Artifact reference or `Missing` |
| `capability_profile` | Artifact reference |
| `playbook_catalog` | Version pin |
| `constraints` | Artifact reference or `Missing` |
| `disclosure_policy` | Version pin |
| `unresolved_items` | `JH.UnresolvedItem[]` |
| `evidence_prefix` | Journal prefix |

`UnresolvedItem` contains `code`, nonempty `detail`, nonempty string array `affected_fields`, and `evidence_refs`.

### 7.3 Eight-playbook catalog

The following IDs are proposed stable product identifiers.

| ID | Source playbook | Operational interpretation |
|---|---|---|
| `pb01_structural_deconstruction` | Recursive Structural Deconstruction & Isomorphic Mapping | Decompose systems, identify invariants, normalize mismatches |
| `pb02_human_asset_optimization` | Human Asset Optimization & Reverse-Pyramid Leadership | Train, coach, remove obstacles, delegate, measure cohorts |
| `pb03_compliance_automation` | Compliance-to-Automation Pipeline | Interpret rules, author SOPs, automate checks, remediate |
| `pb04_field_triage` | High-Stakes De-escalation & Autonomous Field Triage | De-escalate, apply policy, preserve safety, document |
| `pb05_hardware_software_integration` | Cross-Domain Hardware/Software Integration | Integrate hardware, firmware, sensors, actuators, software |
| `pb06_cognitive_offloading` | Latency-Aware Cognitive Offloading | Route local/cloud reasoning, retrieve context, preserve responsiveness |
| `pb07_public_governance` | Public/Community Governance & Parliamentary Procedure | Parliamentary procedure, reporting, consensus, public presentation |
| `pb08_campaign_engineering` | Data-Driven Campaign Engineering | BI, demographic targeting, conversion, budget optimization |

`JH.PlaybookCatalog` contains `record_type: playbook_catalog`, `schema_version: job-hunter-playbooks/0.1.0`, and exactly eight `entries`.

Each entry contains `playbook_id`, `name`, `primitive_actions`, `trigger_conditions`, `limitations`, and nonempty `source_refs`. The three descriptive collections are string arrays. IDs occur exactly once.

Candidate playbooks are not executor `CapabilityDescriptor` capabilities.

### 7.4 Query schema and families

`JH.QueryArtifact` contains:

`record_type: job_search_query`, `schema_version: job-hunter-query/0.1.0`, `query_id`, `family`, `board`, `query_text`, `category_exclusions`, `series_filters`, `candidate_profile`, `playbook_catalog`, `veto_policy`, `syntax_mapping`, and nonempty `evidence_refs`.

`family` is `A`, `B`, `C`, `D`, `E`, `broad`, or `title_expansion`. Query text is nonempty; category and series fields are string arrays.

| Family | Source meaning |
|---|---|
| A | Systems, integration, automation |
| B | Compliance, regulatory work, SOPs |
| C | Human performance, training, programs |
| D | Business systems, operations |
| E | Accessibility, edge hardware, field integration |

The exact source query text is retained in the artifact. Title expansion remains secondary.

Board transformations preserve the source’s distinctions:

- Google: phrase and minus-term syntax.
- GovernmentJobs/NeoGov: keyword searches separate from UI category exclusions.
- USAJobs: keywords, series, and exclusions separate.
- LinkedIn and Indeed: their pinned syntax mappings.
- Greenhouse/Lever: site restrictions retained.
- County/transit sites: independently evidenced adapters.
- Exa: search/contents semantics under its actual adapter.

No listed API establishes current credentials, quota, response shape, or acquisition permission.

### 7.5 Veto policy

`JH.VetoPolicy` contains `record_type: negative_veto_policy`, `schema_version: job-hunter-veto-policy/0.1.0`, `entries`, and nonempty `approval_refs`.

Each entry contains exactly:

- `term`: nonempty string.
- `type`: `hard` or `soft`.
- `reason`: nonempty string.
- `action`: `exclude` or `flag`.

Start with hard exclusions. Soft exclusions require explicit activation. “Bachelor’s required” is flagged rather than automatically excluded under the supplied source rule.

A global query veto, a crawler relevance veto, and a job-specific product no-go are distinct facts.

---

## 8. Evaluation pipeline and artifacts

### 8.1 Eight-stage transformation

| Stage | Output and boundary rule |
|---|---|
| Query generator | Pinned query artifact from primitives, domains, constraints, exclusions |
| Scraper/API | Read-only source evidence; no employer mutation |
| Normalize | Pinned job input preserving salary, requirements, and location uncertainty |
| Prefilter | Broad recall evidence; no hidden soft exclusion |
| Embed | Versioned similarity evidence, not eligibility |
| LLM rerank | Validated structured assessment |
| Queue | Explicit product selection; unknown is not automatic pass |
| Tailor | Supported material artifacts, not invented facts |

### 8.2 Embedding evidence

`JH.EmbeddingArtifact` contains:

`record_type: job_profile_embedding_comparison`, `schema_version: job-hunter-embedding/0.1.0`, `comparison_id`, `candidate_profile`, `job_snapshot`, `chunking_policy`, `model`, positive `vector_dimension`, `profile_vectors`, `job_vector`, `similarity_method: cosine`, `similarities`, and nonempty `evidence_refs`.

Vector artifacts declare their numeric representation, dimensions, chunk identities, and normalization under pinned schemas. Model/version mismatches invalidate comparison.

Disabled embedding is `Missing(not_enabled)`, not zero similarity.

### 8.3 Raw and normalized reranker fields

The raw response is retained unchanged as an artifact. Its source fields map as follows:

| Source field | Normalized type | Rule |
|---|---|---|
| `can_do_70_percent` | Boolean or `Missing` | Actual assessment only |
| `hard_blockers` | String array or `Missing` | Empty means assessed absence |
| `playbooks_matched` | Catalog-ID array or `Missing` | Unknown labels cause normalization issues |
| `would_tolerate` | Boolean or `Missing` | Actual assessment only |
| `pay_ok` | `acceptable`, `unacceptable`, `unknown` | Pinned interpretation |
| `legibility_gap` | String or `Missing` | Preserve assessment |
| `resume_translation` | String array or `Missing` | Recommendations, not factual amendments |
| `score` | Finite number or `Missing` | Scale supplied by rubric |

These eight fields form closed `JH.NormalizedRerankerOutput`.

The source explicitly demonstrates raw `"unknown"` for pay; it maps to normalized `unknown`. Other representations require a pinned normalizer. The example score `78` does not establish a universal 0–100 scale or threshold.

### 8.4 EvaluationArtifact

| Field | Type |
|---|---|
| `record_type` | Constant `job_hunter_evaluation` |
| `schema_version` | Constant `job-hunter-evaluation/0.1.0` |
| `evaluation_id`, `candidate_id` | Identifiers |
| `job_input` | `JH.EvaluationJobInput` |
| `candidate_profile` | Artifact reference |
| `playbook_catalog` | Version pin |
| `policies` | `JH.EvaluationPolicyPins` |
| `method` | `llm`, `deterministic`, or `human_assessment` |
| `raw_reranker` | Artifact reference or `Missing` |
| `normalized_reranker` | `JH.NormalizedRerankerOutput` |
| `embedding` | Artifact reference or `Missing` |
| `stage_one`, `stage_two` | `JH.EvaluationStage` |
| `pay_decision` | `acceptable`, `unacceptable`, or `unknown` |
| `recommended_selection` | `go`, `no_go`, or `review` |
| `playbook_matches` | `JH.PlaybookMatch[]` |
| `normalization_issues` | `JH.UnresolvedItem[]` |
| `model_calls` | Artifact reference array |
| `input_prefix` | Journal prefix |
| `evidence_refs` | Nonempty evidence reference array |

Nested records are closed:

| Record | Complete fields |
|---|---|
| `EvaluationJobInput` | `portfolio_job_id`, `source_key: W.JobEntityKey`, `logical_row: ArtifactReference`, `logical_row_ref: EvidenceRef`, `seal_id`, `crawler_input: W.NonzeroDomainPin` |
| `EvaluationPolicyPins` | `rubric`, `eligibility`, `tolerance`, `pay`, `veto`, `normalizer`, `prompt`; veto and normalizer are VersionPins; others are VersionPin or Missing |
| `EvaluationStage` | `result: pass/fail/review`, nonempty `rationale`, nonempty `evidence_refs` |
| `PlaybookMatch` | `playbook_id`, nonempty string array `job_primitives`, nonempty `candidate_source_refs`, nonempty `job_source_refs`, nonempty `rationale`, string array `limitations` |

All copied job/profile pins agree with `EvaluationReference`. A missing policy necessary for automatic evaluation requires review, not invented business logic.

### 8.5 Two-stage decision table

| Condition | Required automatic result |
|---|---|
| Established nonwaivable hard blocker | Stage one fail |
| Established capability criterion failure | Stage one fail |
| Eligibility evidence missing/conflicting | Stage one review |
| Capability criterion satisfied and no blockers established | Stage one pass |
| Tolerance explicitly unacceptable | Stage two fail |
| Required tolerance facts/policy missing | Stage two review |
| Tolerance established acceptable | Stage two pass |
| Any stage fails or pay unacceptable | Recommended no-go |
| No failure but a stage is review or pay unknown | Recommended review |
| Both stages pass and pay acceptable | Recommended go |

Human selection may differ only as a separate authenticated `ProductSelection` with rationale. It does not rewrite the evaluation.

### 8.6 Ranking and staleness

`JH.RankingArtifact` contains `record_type: job_hunter_ranking`, `schema_version: job-hunter-ranking/0.1.0`, `ranking_id`, `policy`, nonempty `evaluation_refs`, nonempty unique `ordered_evaluation_ids`, `input_prefix`, and nonempty `evidence_refs`.

The ordered IDs identify exactly the included evaluations. Rank is one-based position within that artifact.

An evaluation remains historically valid for its pins. A newer crawler revision, profile, rubric, constraints, playbook catalog, pay policy, or tolerance policy may make it stale for a current decision. Staleness never deletes history.

---

## 9. Materials and factual integrity

`JH.MaterialPackage` contains:

| Field | Type |
|---|---|
| `record_type` | Constant `job_hunter_material_package` |
| `schema_version` | Constant `job-hunter-material/0.1.0` |
| `artifact_id`, `portfolio_job_id` | Identifiers |
| `candidate_profile`, `job_snapshot` | Artifact references |
| `evaluation` | Artifact reference or `Missing` |
| `functional_title` | String or `Missing` |
| `resume_json`, `cover_letter`, `supplemental_responses` | Artifact references or `Missing` |
| `rendered_documents` | Artifact reference array |
| `claim_support` | `JH.MaterialClaim[]` |
| `fabrication_log` | `JH.MaterialIssue[]` |
| `generation_policy` | Version pin |
| `renderer` | Version pin or `Missing` |
| `approval_refs` | Evidence reference array |
| `evidence_refs` | Nonempty evidence reference array |

`MaterialClaim` contains `claim_id`, `text`, nonempty `source_refs`, and `transformation_rationale`.

`MaterialIssue` contains `issue_id`, `kind`, `detail`, `resolution`, and `evidence_refs`. Kinds are `unsupported_claim`, `source_conflict`, `unit_ambiguity`, `disclosure_restriction`, and `translation_risk`. Resolution is `removed`, `corrected`, or `unresolved`.

Rules:

- Translation changes vocabulary, not history.
- A functional title does not replace an actual title when the form requests the latter.
- Credentials, dates, salary units, supervisory counts, and contact permissions require support.
- The fabrication log records integrity issues; it does not authorize fabrication.
- Unresolved unsupported claims block affected automatic submission.
- Rendered documents pin source and renderer.
- Typst remains an implementation option.
- Later materials do not rewrite commission `initial_materials`.
- Actual submitted bytes are separately journaled.
- Sensitive source history is disclosed only under the pinned policy.

---

## 10. Commissioning and manual execution

### 10.1 Admission ordering

The commissioner resolves candidate, job, target, kind, task, execution, permissions, assistance, budgets, owners, and duplicate-risk review before dispatch.

The durable sequence is:

1. Install immutable input artifacts.
2. Admit a manifest with registered producers, clocks, and event registry.
3. Record/import authorization and selection evidence.
4. Construct and retain the commission referencing admission.
5. Register commission bytes.
6. Register the owner-separated attempt entity.
7. Independently publish the downstream attempt link.
8. Permit subject-mode Prepare and Start.

Registration follows artifact construction; records never cite their own future registration as input evidence.

### 10.2 Manifest mapping

`K.Manifest` fields are mapped completely:

| Field | Job Hunter value |
|---|---|
| `record_type`, `schema_version` | `manifest`, `evidence-kernel/0.1.0` |
| `manifest_id`, `run_id`, `journal_id` | Immutable allocated identities |
| `owner_domain`, `commissioner_id` | Authenticated admission ownership |
| `activity` | `application_attempt`, `discovery`, or explicit conformance activity |
| `attempt` | Attempt context for applications; inapplicable for discovery |
| `execution` | Manual, subject, or service only where kernel permits |
| `task`, `task_semantic_hash` | Exact task and declared semantic profile |
| `effective_configuration` | Complete admitted policies, budgets, permissions, context requirements |
| `environment` | Recorded environment facts; no invented deployment assumptions |
| `seed` | Actual seed or reasoned missingness |
| `build_pins` | Recorder and applicable implementation artifacts |
| `event_registry` | Exact kind/version, role, assertion kind, writer grants |
| `producers` | Authenticated producer registrations |
| `clocks` | Actual clock descriptors |

Application commissions restrict execution to manual or subject; service mode does not become an application executor.

### 10.3 AttemptCommission field map

| Field | Required mapping |
|---|---|
| `record_type`, `schema_version`, `kernel_version` | Exact supplied discriminators and versions |
| `commission_id`, `run_id`, `journal_id` | Immutable identities |
| `manifest_hash`, `admission_ref` | Exact admitted manifest and sequence-one evidence |
| `commissioned_by`, `commissioned_at` | Authenticated principal and actual TimePoint |
| `attempt` | Immutable `AttemptContext` |
| `candidate_id`, `candidate_profile` | Opaque identity; exact profile or honest missingness |
| `job` | Exact `JobReference` |
| `selection_evidence` | Evaluation or human decision artifact, or honest missingness |
| `task`, `task_semantic_hash` | Exact task and semantic hash |
| `initial_materials` | Initially available immutable artifacts |
| `execution` | Exact execution descriptor |
| `owners` | Five immutable bindings |
| `idempotency_key` | Stable logical attempt key |
| `authorization_refs` | Nonempty task authority |
| `recovery_review_refs` | Required duplicate-risk review support |
| `observation_policy` | Explicit finite local bounds |
| `origin_policy` | Pinned receipt-verification policy |

`JobReference` contains `job_id`, `source_target`, `source_job_id`, and `snapshot`.

`AttemptContext` contains `attempt_id`, `kind`, `target_class`, `target_id`, `evaluation_partition`, `rehearsal_of`, `performance_of`, and `derived_from`.

Fixtures are practice/held-in. Employer origins are held-out. Production requires employer origin. Derivation is same-kind and acyclic. Lineage links resolve to already commissioned identities and confer no outcome.

### 10.4 Execution and owner bindings

`ExecutionDescriptor` contains `mode`, `subject`, `connector_version`, `binding_version`, and `assistance`.

Assistance contains `planning_owner`, `assistance_track`, `planner_identity`, `plan`, `online_replanning`, and `description`. Realized assistance is also journaled.

Each owner binding contains `role`, `source_id`, `writer_id`, `owner_domain`, and `publication_policy`.

Bindings are:

- Dispatch: connector.
- Observation: connector role, including a manual recorder.
- Execution: subject.
- Application: origin.
- Report: reconciler.

The report writer has no execution/application write grant.

### 10.5 Observation policy

Fields are `active_limit`, `drain_limit`, `native_cancel_wait_limit`, `cleanup_wait_limit`, and `fixture_close_action`.

Each limit is `{kind: exact, unit: ms, value: nonnegative finite number}`. No default duration is selected. Zero means immediate.

Employer origins require `fixture_close_action: not_applicable`.

If production receipt verification is not established, the required origin-policy pin may identify an explicit observation-only policy that accepts no facts. Manual recording remains possible; unverified receipts remain observations.

### 10.6 Manual lane

Manual mode requires:

- Subject, connector version, and binding version: `Missing(not_applicable)`.
- Dispatch: `UnpublishedAxis` with revision zero and inapplicable value.
- Execution: the same.
- No fabricated descriptor, native ID, subject claim, or capability.
- No Prepare or Start.
- Observation owned by the recorder.
- Human actions retain manual provenance.
- Independently verified employer receipts may establish application facts.

A `TaskEnvelope` may describe manual intent without making the commission dispatchable.

Manual transitions are open observation, append actions/pauses, capture receipts, close under policy, and append late evidence. A human submit note is not an origin fact.

The minimum manual path requires no crawler, model, Hellscape, executor, Firebase, or Restate.

### 10.7 New-attempt conditions

Changing kind, candidate, target, job/task identity, subject version, execution configuration, task permissions, or logical execution requires a new commission where the lifecycle requires immutable scope.

A new attempt preserves prior uncertainty and requires duplicate-risk review when prior delivery or commitment creates resubmission risk.

---

## 11. Five-axis lifecycle

### 11.1 AxisRevision

Every nonzero publication contains:

`record_type: attempt_axis_revision`, `schema_version: application-attempt-lifecycle/0.1.0`, `attempt`, `commission_digest`, `axis`, `owner_domain`, `writer_id`, `revision`, `previous_revision`, `evidence_prefix`, `evidence_refs`, and typed `value`.

Revisions are complete, immutable, and owner-local. Same identity with different bytes is an integrity conflict.

### 11.2 Dispatch

`DispatchValue` contains `state`, `local_handle`, `native_run_id`, `request_digest`, `delivery_refs`, `acceptance_refs`, `recovery_authorization_refs`, and `reason`.

| From | Allowed next states |
|---|---|
| Unpublished | `not_started`, `prepared`, `rejected` |
| `not_started` | `prepared`, `rejected` |
| `prepared` | `dispatching`, `rejected` |
| `dispatching` | `accepted`, `rejected`, `uncertain` |
| `uncertain` | `uncertain`, `accepted`, `rejected` |
| `accepted` | `accepted` |
| `rejected` | `rejected` |

Prepared requires request identity. Dispatching requires durable handle and intent before wire delivery. Accepted requires correlated native evidence. A local Start receipt is not native acceptance. Rejection after possible delivery requires nonacceptance evidence. Same-state publication does not authorize another execution.

### 11.3 Observation

`ObservationValue` contains:

`state`, `window_id`, `opened_at`, `active_deadline`, `drain_started_at`, `drain_deadline`, `closed_at`, `close_reason`, `at_close`, `control_observations`, `late_evidence_refs`, and `measurements`.

| From | Allowed next states |
|---|---|
| Unpublished | `not_opened`, `open`, `closed` |
| `not_opened` | `open`, `closed` |
| `open` | `open`, `draining`, `closed` |
| `draining` | `draining`, `closed` |
| `closed` | `closed` |

Close reasons are `normal_completion`, `operator_stop`, `local_deadline`, `translation_failure`, `launch_failure`, `subject_terminal`, `connection_lost`, and `infrastructure_interruption`.

Closed-first is valid for prelaunch failure. Closed-to-closed may append evidence but preserves original closure fields.

`CloseSnapshot` contains `closure_id`, `boundary_ref`, `known_versions`, `execution_knowledge`, `execution_evidence_refs`, `application_knowledge`, `application_evidence_refs`, and `limitations`.

Execution knowledge is `running`, `terminal`, `unknown`, or `not_applicable`. Application knowledge is `committed`, `not_committed`, or `unknown`. Only evidence available at the boundary supports the snapshot.

### 11.4 Execution claims

`ExecutionValue` contains cumulative `claims`.

Each claim contains:

`claim_id`, `scope`, `state`, `application_assertions`, `native_run_id`, `native_message_id`, `native_report`, `mapping`, `source_checks`, `made_at`, `received_at`, `evidence_available_to_claimant`, `evidence_refs`, and `limitations`.

Scope is `primitive`, `application_postcondition`, `execution_lifecycle`, or `unknown`. State is an actual `running`, `completed`, `failed`, `stopped`, `unknown` claim or `Missing`.

Primitive scope has inapplicable task state and no application assertions. Unknown scope has missing state and no application assertions.

Each commitment assertion contains `assertion_id`, `value`, `span`, `boundary_ref`, and `evidence_refs`. Values are `committed`, `not_committed`, `outcome_unknown`; spans are `at_boundary`, `after_boundary`, `entire_attempt`.

Claims append, including contradictory claims. No truth-state machine suppresses later evidence. “Stopped” alone does not mean “no commitment.”

### 11.5 Application facts

`ApplicationValue` contains cumulative `facts`.

Each fact contains:

`fact_id`, `origin_id`, `candidate_id`, `job_id`, `state`, `coverage`, `boundary_ref`, `origin_application_id`, `origin_revision`, `receipt`, `verification_kind`, `source_checks`, `authority_seal_ref`, `occurred_at`, `received_at`, and `evidence_refs`.

The containing publication binds the fact to the exact attempt.

- State: `committed` or `not_committed`.
- Coverage: `at_boundary` or `final_for_attempt`.
- Verification: `local_origin_transaction` for fixture truth or `verified_origin_receipt` for production.
- Final noncommitment requires origin-owned finality evidence.
- No accepted facts means unknown, not noncommitment.
- As-of absence and later commitment may coexist.
- Withdrawal, rejection, or closure does not erase historical commitment.

### 11.6 Source checks

`SourceChecks` contains `authentication`, `correlation`, `trace_correlation`, `verification_policy`, `matched_by`, and `evidence_refs`.

Authentication is `verified`, `failed`, or `unknown`. Correlation is `matched`, `mismatched`, or `unknown`. Trace correlation is `matched`, `mismatched`, `not_observed`, or `not_applicable`.

Accepted claims/facts require verified authentication, matched correlation, nonempty matching inputs, and actual verification evidence. A sender’s serialized “verified” label is insufficient.

A trace mismatch may coexist with independently established alternate correlation, but that basis must be explicit.

### 11.7 Report

`ReportValue` contains `state`, `coverage`, `inputs`, `evaluator`, `comparisons`, `issues`, `limitations`, and `diagnostic`.

Inputs pin dispatch, observation, execution, and application with revision and digest.

Comparison fields are `claim_id`, `assertion_id`, `claim_ref`, `fact_ids`, `fact_refs`, `result`, `temporal_relation`, `rationale`, and `limitations`.

Temporal relation contains `relation`, `basis`, and `evidence_refs`. Known ordering requires same-clock, causal, or documented origin-sequence evidence. Receipt order and UTC alone are insufficient.

| Condition | Report |
|---|---|
| Any proved contradiction | `contradicted` |
| No contradiction and all comparisons accounted for | `reconciled`, complete coverage |
| Relevant comparison unresolved | Missing state with `not_observed` or `observation_lost`, incomplete coverage |
| No applicable subject claims | Inapplicable state/coverage, empty comparisons |
| Narrow execution completion without application claim | `not_comparable`, not success |
| Close-time outcome unknown, later commitment | Compatible uncertainty |
| Entire-attempt no-commit claim, verified commitment | Contradiction |
| Earlier boundary assertion, later-arriving receipt | Requires actual temporal relation |

Issue kinds are `origin_fact_conflict`, `subject_claim_conflict`, `insufficient_evidence`, `incomparable_scope`, `untrusted_observation`, `mapping_error`, and `multiple_origin_commitments`.

Report pins do not regress. Reconciled does not mean successful application.

### 11.8 Snapshot

`AttemptSnapshot` contains `record_type`, `schema_version`, `attempt`, `commission`, `commission_digest`, `input_prefix`, all five axis slots, and `seal_point`.

Seal names are `commissioned`, `observation_closed`, and `evidence_updated`. Vectors match slots exactly. A closed seal requires closed observation.

Snapshots are read compositions, never whole-attempt update commands. A current snapshot may contain newer facts than its report; the dashboard must display that staleness.

---

## 12. Task construction and connector protocol

### 12.1 TaskEnvelope

| Field | Construction |
|---|---|
| `record_type`, `schema_version` | `connector_task`, `external-connector/0.1.0` |
| `task_id` | Immutable task identity |
| `task_type` | `apply`, `extract`, or `discover_jobs` |
| `entry` | `logical_id` and evidenced authorized URL |
| `goal` | Explicit bounded objective |
| `success_criteria` | Unique criterion IDs and descriptions |
| `inputs` | Unique names, purposes, artifact references |
| `permitted_origins` | Unique logical IDs and actual canonical origins |
| `permitted_interfaces` | `ordinary_browser`, `read_only_acquisition` as authorized |
| `effect_policy` | `commissioned_application` for apply; otherwise `read_only` |
| `budgets` | Explicit admitted limits |
| `context_policy` | Separate browser and learning policies |
| `output_schema` | Required VersionPin for extract/discovery; VersionPin or Missing for apply |

Entry origin must be permitted. Redirects, accounts, and data destinations remain authorized. Unknown apply URLs remain unknown. No Page, ElementHandle, shared selector engine, or generic browser action protocol is added.

Read-only extraction cannot perform apply, self-referral, contact-reveal, or equivalent mutations merely because a request uses a nominally read-like HTTP method.

### 12.2 Budgets and state policy

Budgets contain `active_limit`, `action_limit`, `observation_byte_limit`, `recovery_limit`, and `model_token_limit`. Active limit equals the observation policy. Zero is an actual zero allowance.

Context policy contains `browser_state` and `learning_state`, each with `mode`, `requirement`, `resource_ref`, and `baseline`.

Browser modes: `fresh`, `reuse`, `subject_default`, `not_applicable`. Learning also permits `frozen`. Requirement is `required` or `best_effort`.

Required unsupported policy blocks preparation. Best-effort limitations are disclosed. Reuse requires authorized binding. Fresh context does not prove isolation; fresh browser state does not prove fresh learning state.

### 12.3 Hashes

Task semantic hashing removes `task_id`, replaces entry URL and permitted-origin values with their logical IDs, preserves every other value and array order, then applies JCS/SHA-256 under `external-connector-task/1`.

Full task, destinations, commission, preparation, delivered task, and native request remain separately pinned. Equal semantic hashes do not authorize changed destinations.

### 12.4 Scope and configuration

`WorkScope` fields are `activity`, `run_id`, `journal_id`, `manifest_hash`, `admission_ref`, `attempt`, `commission`, `commission_ref`, `authorization_refs`, and `observation_policy`.

Application scope resolves an exact subject-mode commission. Discovery uses inapplicable attempt/commission fields and does not invent lifecycle publications.

`ConfigurationPin` fields are `connector_id`, `connector_version`, `binding`, `subject`, `descriptor`, and `descriptor_ref`. All copied values match retained descriptor bytes.

### 12.5 Envelope and nine operations

Requests contain `record_type`, `schema_version`, `request_id`, `connector_id`, `operation`, `call_limit`, and `payload`. Responses contain `record_type`, `schema_version`, `request_id`, `connector_id`, `operation`, and `result`.

The proposed carrier is authenticated `POST /connector`, UTF-8 JSON, at a deployment-configured address. It is not a claim that a native framework already exposes that route.

| Operation | Exact responsibility |
|---|---|
| `Describe` | Return pinned declarations; no probing or task execution |
| `Prepare` | Validate and serialize without execution |
| `Start` | Durably admit one logical execution asynchronously |
| `Observe` | Read journal-backed observations through a cutoff |
| `RequestNativeCancel` | Invoke only an evidenced native cancellation mapping |
| `CloseObservationConnection` | Close local observation transport; optionally finalize observation |
| `CollectArtifacts` | Inventory/transfer retained or mapped already-produced artifacts |
| `ReleaseNativeContext` | Release only the authorized mapped native context |
| `Contain` | Execute a separately authorized reviewed containment policy |

### 12.6 Describe and capabilities

Describe payload is an empty closed object.

Descriptor fields are `record_type`, `schema_version`, `connector_id`, `connector_version`, `build`, `binding`, `subject`, `capabilities`, `operations`, `task_mappings`, `observation_channels`, `action_grounding`, `execution_substrate`, `limits`, `budget_accounting`, and `evidence_prefix`.

Each verb appears once. Each task type has at most one mapping. Subject identity equals capability-descriptor subject.

The minimum capability catalog includes native goal task, plan execution, cancellation, context release, artifact retrieval, revision, DOM access, browser isolation, browser persistence, and learning-state control under the supplied IDs.

Every new subject version starts unknown. Declaration is not assessment. Unmapped does not automatically mean native absent.

### 12.7 Prepare

Prepare fields are `scope`, `configuration`, `task`, `assistance`, `planning_evidence_refs`, `preparation_measurements`, and `runtime_access`.

Runtime access contains `purpose`, `access_ref`, and `authorization_refs`; purpose is `application_entry`, `account_session`, or `input_artifact`.

Prepare cannot browse, test login, invoke hidden planning, reset context, improve a plan, add recovery, or execute actions.

`PreparedTask` contains:

`record_type`, `schema_version`, `preparation_id`, `scope`, `configuration`, `task`, `task_semantic_hash`, `assistance`, `planning_evidence_refs`, `runtime_access`, `delivered_task`, `delivered_task_hash`, `native_request`, `native_request_hash`, `translation`, `budget_mapping`, `concerns`, and `evidence_prefix`.

Budget mappings cover exactly `active_observation`, `action_count`, `observation_bytes`, `recovery_count`, and `model_tokens`; each identifies enforcer, evidence, and limitations. Active observation is connector-enforced.

Concern fields are `concern_id`, `category`, `disposition`, `detail`, and `evidence_refs`. Disposition is `requires_acceptance` or `informational`. Blocking concerns produce errors, not startable preparations.

Prepare result contains `kind`, `preparation`, and `record`. Preparation reference contains `preparation_id`, `artifact`, and `registration_ref`.

### 12.8 Start

Start fields are `preparation`, `idempotency_key`, `accepted_concern_ids`, `authorization_refs`, and `recovery`.

Initial recovery is inapplicable. Required concerns must be accepted; nonexistent concern IDs reject.

Before native delivery, the connector durably commits handle, immutable request binding, logical key, and dispatch intent.

Start result contains `kind`, `disposition`, `handle`, `handle_artifact`, and `receipt_ref`. Disposition is `accepted_locally`, `existing_handle`, or `resume_authorized`.

The immutable handle contains `record_type`, `schema_version`, `handle`, `preparation`, `scope`, `idempotency_key`, and `created_at`. The nested handle reference contains `connector_id` and `local_handle`.

Local acceptance is neither native acceptance nor commitment.

### 12.9 Observe

Request fields are `handle`, `after`, `through`, `max_items`, and `wait_limit`.

Cursor fields are `handle`, `journal_id`, `sequence`, and `event_hash`; sequence zero has inapplicable hash.

Page fields are `kind`, `handle`, `after`, `through`, `next`, `has_more`, `observation_close_ref`, `items`, and `limitations`.

Rules:

- First live page pins a cutoff.
- Continuations retain that cutoff and have zero wait.
- Entries are unique, increasing, after the incoming cursor, and within cutoff.
- Next is the last scanned journal position.
- `has_more` is exactly whether next precedes cutoff.
- Empty pages do not prove termination.
- Late evidence requires a new cutoff.
- Unavailable cursor history is explicit.
- Oversized entries are not silently skipped.

Observation items contain `event_ref`, `recorded_at`, `provenance`, `payload`, `measurements`, and `artifact_refs`. Metadata matches the cited complete journal event.

Payload kinds are `native_report`, `context_observation`, `task_output`, `connector_incident`, `control_observation`, `lifecycle_publication`, `artifact_available`, and `clock_registered`.

Lifecycle references may carry only dispatch, observation, or delegated execution.

---

## 13. Recovery, controls, and errors

### 13.1 Idempotency levels

| Level | Key and guarantee |
|---|---|
| Connector command | Principal, connector ID, request ID; identical mutating/collecting request returns retained receipt |
| Logical execution | Principal, connector ID, Start key; repeated initial Start returns same handle |
| Commission | Cannot acquire another logical execution by changing key, caller, or executor |
| Employer effect | No exactly-once guarantee without actual origin semantics |

Changed content under a reused command/key is rejected. Describe and Observe may return newer read evidence.

### 13.2 Failure recovery

| Failure | Required action |
|---|---|
| Prepare response lost | Retry identical command; no hidden replanning |
| Stale preparation | Reject; no silent reprepare |
| Start response lost | Retry same command/key |
| Delivery may have occurred | Preserve uncertainty; observe and reconcile |
| Native acceptance known, terminal response lost | Continue observation; do not relaunch |
| Late callback | Authenticate, correlate, append |
| Transport closed | Do not infer cancellation |
| Lease expired | Fence local commit only; do not infer noncommitment |
| Executor unavailable after uncertain delivery | No automatic executor switch |
| Artifact lost | Preserve known identity and record loss |
| Journal repair needed | Never repeat employer mutation to repair local evidence |

Resume requires existing handle/key, same request/context, checkpoint artifact, native resume contract, authorization, evidence, and an open observation window. `ResumeAuthorization` contains `handle`, `checkpoint`, `native_resume_contract`, `authorization_refs`, and `evidence_refs`.

Resume uses a new command identity but the same logical execution. It never repeats completed side-effecting steps.

### 13.3 Controls and closure

Control request payloads are:

| Operation | Fields |
|---|---|
| Native cancel | `handle`, `reason`, `authorization_refs` |
| Close connection | `handle`, `reason`, `end_observation`, `authorization_refs` |
| Release context | `handle`, `context_ref`, `authorization_refs` |
| Contain | `handle`, `target`, `policy`, `reason`, `authorization_refs` |

Containment target contains `kind` and `resource_id`; arbitrary shell text or unverified PIDs are forbidden.

Each control observation contains:

`control_event_id`, `operation_id`, `operation`, `target_scope`, `disposition`, `at`, `authorization_ref`, `capability_ref`, `opportunity`, `request_ref`, `response_ref`, `response_checks`, `native_claim_refs`, `effect_refs`, `affected_attempts`, `measurements`, and `limitations`.

Dispositions are `not_requested`, `unsupported`, `requested`, `acknowledged`, `effect_observed`, and `unknown`.

Acknowledgement requires verified response evidence. Effect-observed requires effect evidence. A stop claim remains a claim.

Closing with `end_observation: false` closes only transport. True additionally stops commands and begins bounded finalization. Neither implies cancellation or closes durable Observe.

On closure, stop workflow commands, record controls separately, drain and clean up within bounds, freeze close knowledge, then accept late evidence without reopening. Restart registers a new clock and records interruption; no cross-boot subtraction is allowed.

### 13.4 Artifact collection

Selectors are:

- Inventory: `mode`.
- Named: `mode`, unique nonempty `names`.
- Bytes: `mode`, registered `digest`, `offset`, positive `max_bytes`.

Inventory fields: `kind`, `handle`, `artifacts`, `coverage`, `evidence_prefix`, `limitations`.

Every named request receives exactly those names, including missing slots. Each slot contains `name`, `expected_digest`, `content`, and `evidence_refs`.

Chunk fields: `kind`, `handle`, `digest`, `size_bytes`, `offset`, `returned_bytes`, `data_base64`, `chunk_digest`, `end_of_artifact`, `evidence_refs`.

Consumers verify canonical base64, lengths, chunk hash, bounds, progress, EOF, and assembled digest. Collection cannot rerun tasks or fetch arbitrary paths/URLs.

### 13.5 Errors

Every error contains `kind`, `code`, `fault_domain`, `detail`, `operation_delivery`, `retry_guidance`, `retry_after`, `handle`, and `evidence_refs`.

Complete codes:

`INVALID_REQUEST`, `UNSUPPORTED_VERSION`, `UNAUTHENTICATED`, `FORBIDDEN`, `UNKNOWN_HANDLE`, `UNKNOWN_PREPARATION`, `STALE_PREPARATION`, `IDEMPOTENCY_CONFLICT`, `UNSUPPORTED_MAPPING`, `PREREQUISITE_UNAVAILABLE`, `BUDGET_EXCEEDED`, `NOT_ADMITTED`, `OBSERVATION_CLOSED`, `STALE_CONTEXT`, `RESOURCE_BUSY`, `STORAGE_UNAVAILABLE`, `DELIVERY_UNCERTAIN`, `CURSOR_INVALID`, `CURSOR_UNAVAILABLE`, `OBSERVATION_LOST`, `RESPONSE_TOO_LARGE`, `ARTIFACT_UNAVAILABLE`, `NATIVE_PROTOCOL_ERROR`, `INTEGRITY_CONFLICT`, `INTERNAL_ERROR`.

Delivery is `not_dispatched`, `may_have_dispatched`, `dispatched`, or `not_applicable`. Retry guidance is `same_command_only`, `new_command_if_not_dispatched`, `operator_review`, or `do_not_retry`.

These describe connector operations, not application outcomes. Native failed/completed/stopped claims remain ordinary Observe evidence.

---

## 14. Origin verification and reconciliation ingress

A confirmation page, email, screenshot, portal response, or receipt enters first as a restricted observation artifact.

The fact recorder checks independently:

1. Source identity.
2. Receipt semantics under the pinned policy.
3. Candidate, job, origin, and attempt correlation.
4. Trace correlation or evidenced alternate matching.
5. Commitment versus as-of absence versus final absence.
6. Temporal or origin-sequence scope.
7. Practice, production, synthetic, and historical evidence scope.
8. Raw artifact integrity and availability.

HTTP 200, successful mailbox access, authenticated connector transport, a submit click, or a human note is insufficient alone.

A production origin need not implement the portfolio protocol. Its designated recorder may normalize verified receipts without becoming the origin.

If checks fail or remain unknown:

- Retain the observation and verification outcome.
- Publish no accepted `OriginFact`.
- Preserve application knowledge as unknown.
- Record an untrusted-observation or insufficient-evidence issue where relevant.
- Do not manufacture origin IDs, revisions, or application IDs.

Reconciliation reads exact source pins. It does not make live network lookups or query mutable rows as unrecorded evidence. Additional verification observations must first be journaled and then included in a new pinned revision.

An origin fact conflict is not resolved by deleting one fact or automatically accusing the executor. Multiple commitments, contradictory final facts, and mapping errors remain explicit issues.

---

## 15. Publication, archives, retention, and leases

### 15.1 Publication boundary

Owner durability and read-view visibility are separate events.

A `W.PublicationReceipt` contains:

`record_type`, `schema_version`, `receipt_id`, `entity`, `registration_digest`, `view_id`, `publisher_id`, `domain`, `revision`, `document`, `supersedes`, `observed_owner_head`, `source_prefix`, `installed_at`, `publication_ref`, and `publication_delay`.

Complete bytes are transferred, validated, and installed before pointer advance. Failure leaves the prior complete revision visible. Reordered deliveries cannot roll back the current pointer. Identical retries return the existing receipt.

Publication delay is a valid kernel measurement, not arbitrary source/destination UTC subtraction.

### 15.2 Seals

`W.SealPoint` contains `seal_id`, `name`, `view_id`, `versions`, `sealed_at`, `input_prefix`, and `evidence_refs`.

A seal pins locally available complete publications. It does not require global synchronous freshness or freeze future writes.

Job seals use `published`, `fetch_key_replacement`, or `evidence_updated`. Attempt seals use `commissioned`, `observation_closed`, or `evidence_updated`.

### 15.3 Crawler replacement obligations observed by Job Hunter

Job Hunter never changes acquisition to force a refresh.

- Same fetch key means acquisition no-op, even if a newer response or extractor exists.
- Independent classification/lease/discovery changes may advance the crawler revision.
- Changed fetch key requires a complete prior-row archive.
- The replacement cut includes the old crawler revision and latest fully published downstream revision in the named ingest-side view.
- Unpublished product updates are excluded.
- A concurrent checked-pointer change requires reselection.
- Product publication must make complete immutable downstream bytes available before installation.
- Crawler replacement must not wait for peer transactions or serialize large downstream payloads under its writer lock.

### 15.4 Archive and retention

`W.ArchiveRecord` contains `record_type`, `schema_version`, `root`, `storage_manifest`, and complete `payload_json`.

The root hashes the canonical storage manifest, not the expanded wrapper. The manifest contains `encoding`, `schema_version`, `entity`, `registration`, `domains`, and `seal_point`.

Expansion reconstructs the exact complete old logical row without consulting mutable peer state. Hash lists or crawler-only snapshots are insufficient.

`FetchKeyReplacement` retains `replacement_id`, entity and registration identity, old crawler pin/key, complete new crawler revision, archive root, archived vector, retention pin ID, commit reference, prefix, and evidence references.

`RetentionPinRevision` retains pin/owner/writer identity, revision pair, dependent, archive root, state, release reference, prefix, and support. State is active or released. Release requires evidenced retirement; transitive roots remain protected.

Loss is an integrity incident, not successful garbage collection.

### 15.5 Product leases

Product work uses kernel leases independently of crawler leases.

The lease record retains resource, policy, issuer, authority epoch, entity/input revisions, generation, resource and eligible state, lease state, token, owner, owner/session epochs, issue/expiry points, retries, failure reason, prefix, and evidence.

Claiming does not change resource state. Completion checks current token, unexpired authority-clock deadline, revisions, and epochs. Stale completion has no effect. Failed generations increment retries at most once.

Authority restart durably fences the old epoch. Lease expiry revokes local commit authority, not evidence that native work or employer transactions stopped.

---

## 16. Localization of all twelve Firestore collections

### 16.1 Storage rule

The twelve names below are private legacy storage namespaces or projections. They are not shared wire contracts and do not select Firestore as Job Hunter’s primary store.

Authoritative shared effects remain journaled under owner-separated contracts. Private projections are rebuildable. If Firebase is retained for the dashboard, it contains authorized projections rather than orchestrator authority.

Legacy documents are imported as immutable restricted source artifacts before transformation. Unknown legacy enums and absent types remain preserved, not guessed.

### 16.2 `jobs`

| Legacy field | Canonical/private mapping |
|---|---|
| `jobId` | Portfolio identity; explicit association to source root |
| `track` | Downstream `track` |
| `company` | Crawler `content.employer` |
| `title` | Crawler `content.title` |
| `location` | Crawler `content.location` |
| `sourceUrl` | Acquisition `source_url` |
| `directApplyUrl` | `content.direct_apply_url`; no fallback |
| `portalType` | `content.portal_type` |
| `rawDescription` | `content.description` with source artifact |
| `status` | Preserved legacy text; derived display only |
| `closingDate` | Source-preserved `closing_date` text |

A private jobs projection may combine domains for reading but is never accepted as a multi-owner write.

### 16.3 `evaluations`

| Legacy field | Mapping |
|---|---|
| `evaluationId` | Immutable evaluation identity |
| `jobId` | Portfolio job identity |
| `goNoGo` | Explicit product selection/recommendation under pinned policy |
| `suitabilityScore` | Evaluation score only when the rubric establishes equivalence |
| `desirabilityRank` | Position in a named ranking artifact |
| `scoreBreakdownNotes` | Retained rationale and evidence-backed assessment |
| `vetoReason` | Job-specific rejection rationale; not posting closure |

Absent original types or scoring semantics are migration issues, not defaults.

### 16.4 `artifacts`

| Legacy field | Mapping |
|---|---|
| `artifactId` | Product artifact identity |
| `jobId` | Portfolio job identity |
| `functionalTitle` | Material package functional title |
| `resumeJson` | Immutable restricted structured-resume artifact |
| `coverLetter` | Immutable restricted cover artifact |
| `supplementalResponses` | Immutable restricted response artifact |
| `fabricationLog` | Preserved integrity issues and resolutions |

The legacy collection’s content is not overwritten when a new version is generated.

### 16.5 `trackers`

| Legacy field | Mapping |
|---|---|
| `trackerId` | Private projection identity |
| `jobId` | Portfolio identity |
| `status` | Legacy display value only; five axes are authoritative |
| `submissionMode` | Commissioned mode plus realized assistance evidence |
| `dateApplied` | Source-preserved business value backed by commitment evidence when claimed as applied |
| `targetSalarySubmitted` | Actually entered/submitted value with unit, currency, and evidence |
| `cheatSheetGenerated` | Known generation fact; false is not unknown |

The supplied field list contains no executable status enum. Unknown values remain uninterpreted legacy data.

A tracker links all relevant attempts rather than treating one job row as one immutable application. Confirmed production commitment may support an APPLIED display; clicks, practice receipts, and native completion cannot.

### 16.6 `emails`

| Legacy field | Mapping |
|---|---|
| `emailId` | Provider-scoped message identity |
| `threadId` | Provider-scoped thread identity |
| `category` | Versioned classification result |
| `companyName` | Extracted candidate employer match, not identity authority |
| `jobTitle` | Extracted candidate job match |
| `actionRequired` | Policy-derived work recommendation |
| `summary` | Derived summary citing retained message bytes |

Classification is not origin verification. Company/title similarity alone cannot bind an email to an attempt.

### 16.7 `schedules`

| Legacy field | Mapping |
|---|---|
| `eventId` | Actual provider event identity |
| `jobId` | Product job association |
| `startTime` | Typed calendar value with actual timezone semantics |
| `endTime` | Typed calendar value with actual timezone semantics |
| `calendarId` | Authorized provider calendar |
| `cheatSheetUrl` | Private resolver output for an immutable artifact, not evidence identity |

A calendar write acknowledgement does not prove interview attendance or employer confirmation. URLs are not substitutes for retained document bytes.

### 16.8 `settings`

| Legacy field | Mapping |
|---|---|
| `userId` | Authenticated local principal association |
| `references` | Restricted versioned candidate-reference data |
| `costLimits` | Explicit configuration declarations |
| `notificationPrefs` | Versioned notification policy |
| `addressOverrides` | Authorized source-preserving address policy |

Settings updates do not retroactively alter commissioned tasks. Address anchors and zone rules must come from authorized profile/policy data; no guessed address substitution is permitted.

### 16.9 `vault`

| Legacy field | Mapping |
|---|---|
| `key` | Private secret lookup identity |
| `ciphertext` | Secret-provider-managed encrypted bytes |
| `iv` | Provider-defined cryptographic parameter |
| `tag` | Provider-defined authentication parameter |

The field names do not establish a cipher suite, key-management system, rotation policy, or authentication algorithm. Those require an actual secret-provider contract.

Secret bytes never enter ordinary journals, task fields, logs, source control, or dashboard caches. Runtime access uses opaque scoped references. Candidate PII resides in controlled restricted storage, not public fixtures or git.

### 16.10 `logs`

| Legacy field | Mapping |
|---|---|
| `agent` | Registered component/producer identity |
| `level` | Private operational severity |
| `message` | Sanitized operational text |
| `timestamp` | Original source annotation plus actual ingestion TimePoint |
| `jobId` | Optional association represented honestly; no fabricated job ID |

Operational logs are not citable evidence unless registered in the relevant journal prefix. Non-job resources use actual resource scope.

### 16.11 `costs`

| Legacy field | Mapping |
|---|---|
| `callId` | Stable provider-call/accounting identity |
| `model` | Observed model identity and available version information |
| `inputTokens` | Reported/measured scalar usage with provenance |
| `outputTokens` | Reported/measured scalar usage with provenance |
| `costUsd` | Priced derivation or provider charge with declared basis |
| `timestamp` | Actual receipt TimePoint; source billing date retained separately |

Missing usage or price remains missing. Exact computed cost is exact under its pricing inputs, not automatically an invoice fact.

### 16.12 `tasks`

| Legacy field | Mapping |
|---|---|
| `taskId` | Private orchestration work identity; explicitly related to connector task when applicable |
| `service` | Private durable service name |
| `handler` | Private handler name |
| `status` | Local scheduler state only |
| `payload` | Validated private command referencing immutable inputs |
| `result` | Durable local result or typed uncertainty/error |

Restate completion does not establish native acceptance or employer commitment. Workflow replay must not repeat external mutations.

### 16.13 `noGoList`

| Legacy field | Mapping |
|---|---|
| `jobId` | Portfolio job association |
| `title` | Historical display snapshot |
| `company` | Historical display snapshot |
| `reason` | Evidenced product rejection rationale |
| `hashedKey` | Legacy duplicate hint only |

A no-go entry is not a crawler closure, permanent global exclusion, or proof of a mandatory credential. Reconsideration creates a new decision while retaining the old entry’s evidence.

---

## 17. Correspondence, scheduling, costs, and runtime support

### 17.1 Email intake

Gmail `Users.messages`, `Users.history`, and watch notifications remain adapter surfaces, not assumed receipt guarantees.

The adapter retains mailbox identity, message identity, raw bytes, provider metadata, ingestion evidence, and classification version. Notifications trigger retrieval; they are not themselves complete message evidence.

Duplicate notifications deduplicate by actual provider/message identity. History gaps cause explicit resynchronization evidence, not assumed completeness.

Interview invitations, rejection letters, acknowledgements, requests for information, and ambiguous messages may drive private work queues. Only independently verified and correlated receipt semantics may affect the application axis.

### 17.2 Scheduling and outbound communication

Calendar events, ACLs, and free/busy are distinct provider operations. Job Hunter must preserve timezone, all-day versus timed semantics, provider revision, and actual response evidence.

Outbound email, notifications, calendar writes, and follow-ups require:

- Explicit operation authority.
- Pinned provider adapter semantics.
- Immutable intended payload.
- Stable local command identity.
- Durable intent before dispatch.
- Actual acknowledgement/effect evidence.
- Explicit uncertain delivery when needed.

These are private external operations, not fabricated job-application attempts and not read-only extraction.

No live send endpoint, callback verifier, or native idempotency guarantee is inferred from the endpoint inventory. Retrying an uncertain send requires the provider’s evidenced semantics or duplicate-risk review.

### 17.3 Model execution and costs

Model preference from the inventory is retained as configurable policy: choose the cheapest suitable model, with the stated Muse Spark and DeepSeek preferences treated as historical configuration rather than guaranteed current availability.

Every model call retains:

- Call identity.
- Provider/model identity and available version evidence.
- Prompt/schema/policy pins.
- Input artifact identities.
- Raw response artifact.
- Structured validation outcome.
- Usage measurements.
- Pricing version or missingness.
- Cost derivation.
- Authorization and disclosure scope.

Token budgets are declarations. Usage is evidence. Reservations, estimates, reported usage, and invoiced charges remain distinct. Cost-limit changes do not silently alter a frozen commission.

### 17.4 External service boundaries

| Service | Required boundary treatment |
|---|---|
| OpenCode Go | Pin actual completion/response/message mapping; validate structured output |
| Exa | Read-only search/contents under authorized source policy |
| USAJobs | Pin actual search/job response mapping |
| Gmail | Retain messages and history evidence; separate classification from origin verification |
| Google Calendar | Separate read, write, ACL, and scheduling semantics |
| CapSolver | External dependency only under explicit task authority; no assumed success |
| Camoufox | Executor-internal binding, not orchestrator browser API |
| Restate | Optional private durability implementation; not evidence authority |

Unavailable external documentation blocks the affected adapter operation, not unrelated manual recording.

### 17.5 Dashboard

The dashboard consumes an HTTP API independent of orchestrator language.

It must display:

- Product selection and its basis.
- Crawler input revision and coverage.
- Evaluation/profile/policy freshness.
- Attempt kind and target.
- All five axes or explicit inapplicability.
- Close-time knowledge separately from later facts.
- Report coverage and input-pin staleness.
- Missing/lost evidence.
- Duplicate-risk and integrity issues.

It must not offer a generic “set application status” write. Buttons submit authorized commands such as selecting a job, commissioning, requesting a control, or recording a manual observation.

### 17.6 Development tools

`get_module_spec`, `get_firestore_contract`, `get_candidate_profile`, `ask_hermes`, and `run_verification` remain development tools. They are not runtime application credentials.

Implementation retains the inventory disciplines: read the module specification, honor module boundaries, do not guess business rules, keep secrets out of git, run deterministic verification, and stop on ambiguity.

Each implementation module’s `.omp-spec.md` must provide the exact verification command for its actual implementation. This document does not claim nonexistent executables were run.

---

## 18. Privacy, evidence scope, and practice isolation

1. Candidate source history, resumes, references, employer receipts, native bodies, emails, and session-bearing captures are restricted unless explicitly reviewed otherwise.
2. Models receive only data authorized for that provider and purpose.
3. Hash possession grants no artifact access.
4. Redaction produces a new artifact with derivation evidence.
5. Logs exclude secret values and unnecessary personal details.
6. Raw secrets remain behind runtime access bindings.
7. Historical imported material remains `historical_unscored`.
8. Fabricated test bodies remain synthetic.
9. Real manual interaction with a fixture is current-run practice evidence, not production.
10. Practice receipts cannot support production commitment.
11. Hellscape forms are not employer-representative merely because their text came from a real job.
12. Practice completion never triggers automatic production dispatch.
13. New executor versions do not inherit capability presence or absence.
14. Curriculum results may inform future reviewed decisions but cannot amend an active commission.
15. Diagnostic replay invokes no browser, subject, control action, email send, calendar write, or employer mutation.

A production diagnostic may be re-derived offline. That is not live reproduction. Live reproduction is a new attempt.

---

## 19. End-to-end required traces

### 19.1 Crawler-backed manual production

1. Consume verified sealed crawler row.
2. Evaluate against pinned profile and policies.
3. Publish evaluation and selection downstream.
4. Generate supported materials.
5. Admit manual production manifest and commission.
6. Publish attempt link.
7. Keep dispatch/execution at revision zero and inapplicable.
8. Record human actions.
9. Capture and verify employer receipt.
10. Publish application fact.
11. Close observation.
12. Publish report with inapplicable subject comparison.
13. Display confirmed production commitment without crediting an executor.

### 19.2 Automated production with lost response

1. Admit exact subject-mode commission.
2. Prepare without execution.
3. Start with stable key.
4. Native delivery occurs but response is lost.
5. Preserve handle and dispatch uncertainty.
6. Retry only the same connector command; do not relaunch.
7. Close observation within bounds if necessary.
8. Accept later verified receipt.
9. Publish new application revision and stale-report indicator.
10. Reconcile over new pins without rewriting close-time knowledge.

### 19.3 Claimed cancellation contradicted

1. Retain an authenticated explicit entire-attempt no-commit assertion.
2. Close observation independently.
3. Receive a verified matching commitment.
4. Preserve both source histories.
5. Publish contradiction with exact claim/fact references.
6. Do not rewrite the claim to unknown or erase the commitment.

### 19.4 Practice followed by independently authorized production

1. Commission practice against the fixture.
2. Retain practice results and diagnostics.
3. Independently select a real employer target.
4. Commission production with its own permissions, profile, task, and owner bindings.
5. Optionally link `performance_of`.
6. Use only production receipt evidence for production commitment.

### 19.5 Concurrent crawler replacement and product update

1. Product owner durably commits a new downstream revision.
2. Publication may lag.
3. Crawler selects the latest fully installed downstream revision in its named view.
4. Changed fetch key archives that exact complete cut.
5. A pointer race rejects/reselects the replacement cut.
6. Product acknowledgement never waits for crawler transaction completion.
7. Archive reconstruction remains exact after subsequent publications.

---

## 20. Conformance requirements

The Job Hunter suite runs against fixtures, synthetic connectors, local evidence stores, and mock provider responses. Live portals are manual/smoke tests, not CI prerequisites.

| Test | Required result |
|---|---|
| Bare normalized null | Reject |
| Missing salary/tokens/timing | Preserve Missing; never zero |
| Native exact zero | Preserve source value |
| Cross-clock or cross-boot subtraction | Reject |
| Spoofed provenance/writer identity | Reject |
| Invalid evidence pointer/hash | Reject |
| Missing artifact bytes | Explicit loss/unavailability |
| Same producer sequence, same content | Deduplicate |
| Same producer sequence, different content | Integrity incident |
| Crawler row with partial publication | Reject |
| Crawler Pass missing required extraction | Reject as incomplete extraction |
| Failed render presented as usable content | Reject |
| Bypass represented as genuine PASS | Reject |
| Empty unproven coverage presented as complete | Reject |
| Job Hunter writes crawler field | Reject entire write |
| Downstream revision race | Reject stale update without lost fields |
| Evaluation pin differs from logical-row crawler slot | Reject |
| Profile pin differs between reference and artifact | Reject |
| Unknown playbook label | Preserve raw response; surface issue |
| Unknown pay | Automatic review |
| Missing scoring rubric | No invented score semantics |
| Bachelor’s requirement flag | No automatic hard exclusion under source policy |
| Unsupported material claim | Block affected automatic submission |
| Legacy company/title collision | No automatic identity merge |
| Manual job without crawler | Commission without fabricated crawler evidence |
| Manual dispatch/execution publication | Reject |
| Manual verified production receipt | Accept under origin policy |
| Prepare browses or invokes planning | Fail connector conformance |
| Start before commission registration | Reject |
| Required preparation concern unaccepted | Reject |
| Stale configuration/preparation | Reject |
| Repeated Start with new request ID and same logical key | Same handle |
| Changed request under same command identity | Conflict |
| Changed executor after uncertain delivery | No automatic second execution |
| Lease expiry after possible submit | Preserve outcome uncertainty |
| Resume after draining/closure | Reject |
| Observe fixed-cutoff pagination | Stable cutoff, correct scanned cursor |
| Empty Observe page | No termination inference |
| Oversized observation | Explicit error, no skip |
| Authenticated but uncorrelated callback | No accepted claim |
| Trace mismatch with valid alternate correlation | Retain mismatch and actual basis |
| Native completed response | Execution claim only |
| HTTP 200 or submit click | No origin fact |
| Cancel acknowledgement | No inferred no-commit fact |
| Process containment | No native-cancellation certification |
| Late commitment after close-time unknown | Compatible; preserve close snapshot |
| Late commitment against entire-attempt no-commit claim | Contradicted report |
| Receipt arrival order without temporal evidence | Unknown temporal relation |
| Reconciled narrow claim | No application-success label |
| New facts with old report | Explicit stale report |
| Employer rejection after commitment | Preserve historical commitment |
| Practice fact cited for production | Reject |
| New subject version | Unknown capabilities until own evidence |
| CollectArtifacts arbitrary path/URL | Reject |
| Artifact chunk corruption | Reject |
| Same fetch key, different response | Acquisition no-op; retain observation |
| Changed fetch key without full archive | Reject replacement |
| Archive requires mutable peer lookup | Fail |
| Archive dependency reclaimed while reachable | Fail |
| Peer writer blocked | Other owner still acknowledges independently |
| Email company/title-only match | No automatic attempt fact |
| Mail history gap | Explicit incomplete observation |
| Calendar timezone missing | No invented instant |
| Uncertain outbound send | No blind retry |
| Missing provider usage | No zero-cost default |
| Dashboard scalar-status mutation | Reject |
| Replay causes external write | Fail |
| Legacy unknown status/type | Preserve source, require mapping |
| Secrets in ordinary journal/task/log | Reject or quarantine before publication |

The suite additionally verifies every permitted dispatch and observation transition, every rejected transition, cumulative claim/fact preservation, nonregressing report pins, publication ordering, and all twelve collection adapters.

Passing structural validation alone is insufficient. Authorization, reference resolution, arithmetic, idempotency, revision fencing, provenance, retention, and state semantics are mandatory.

---

## 21. Unresolved inputs and bounded stop conditions

| Missing input | Required treatment | Work that remains available |
|---|---|---|
| Executable legacy Firestore schemas | Preserve raw documents; admit only evidenced mappings | New canonical records |
| Candidate constraint/zone/address policies | Block decisions requiring them | Human selection and restricted recording |
| Compensation thresholds and score weights | Review; no invented rubric | Manual selection |
| Complete raw pay-output enum | Pin an explicit normalizer before accepting new forms | Known unknown representation |
| Current native request/callback contracts | No guessed endpoints or authentication | Synthetic connector conformance and manual work |
| Current per-origin receipt mapping | Observation-only policy; no accepted facts | Tracked unresolved attempts |
| Current subject capability evidence | Complete unknown descriptor | Explicitly authorized bounded work where policy permits |
| Native resume guarantee | No automatic resume after uncertain delivery | Observation and reconciliation |
| Deployment write-isolation proof | Do not certify owner independence | Schema and synthetic tests |
| Legacy closing-date semantics | Preserve source text | Non-deadline-dependent evaluation |
| Secret-provider cryptographic contract | Do not infer cipher/key behavior | Nonsecret operations |
| Historical raw qualification artifacts | Documentary, historical-unscored evidence | Current-version synthetic and authorized observations |

Stop conditions are scoped. An unsupported calendar write does not block manual application recording. A missing scoring policy does not require fabricating a score. A missing browser capability does not require blocking all production evidence collection.

---

## 22. Completion and release criteria

Track 2.5 implementation is complete only when:

1. Every seam in the register has a named owner and validated boundary adapter.
2. Crawler access is strictly read-only.
3. Evaluations retain exact logical-row, crawler, profile, and policy pins.
4. Product writes publish complete `JobDownstreamValue` revisions.
5. All eight playbooks and both veto stages are represented without invented business thresholds.
6. Materials preserve factual support and actual submitted versions.
7. Manual production works without an automation connector or laboratory.
8. Subject execution uses exactly the shared nine-verb connector surface.
9. Network uncertainty never creates an implicit second logical execution.
10. Five lifecycle axes remain independently owned and separately visible.
11. Origin facts require actual verified source and correlation evidence.
12. Late evidence produces new immutable revisions, not historical edits.
13. All twelve legacy collections are private adapters/projections rather than shared authority.
14. Publication, archive, retention, lease, and restart tests pass.
15. Privacy, missingness, timing, provenance, and practice/production tests pass.
16. The component passes its silo conformance suite before peer integration.

No whole-system integration milestone, qualification product, browser rewrite, Firebase deployment, or laboratory success is a prerequisite for shipping the evidence-correct manual lane. The release unit is an independently conforming Job Hunter component whose decisions, attempts, uncertainties, and genuine production results remain distinguishable and reproducible.
