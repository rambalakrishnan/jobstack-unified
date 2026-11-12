# Crawler PRD — Illinois discovery with honest provenance

**Status:** Step 0 review draft; this document specifies the crawler’s intended behavior and acceptance obligations, not evidence that current Illinois endpoints, a BrowserOxide build, or a deployment have passed them. [proposed: distinguish product requirements from observed implementation and target behavior]

**Contract baseline:** the six shared `0.1.0` contract drafts, particularly the evidence kernel, external connector, BrowserOxide internal binding, and owner-separated write domains; their conformance documents govern the applicable boundaries. [extracted: contracts/00-evidence-kernel.yaml; contracts/02-external-connector.yaml; contracts/03-internal-browser-binding.yaml; contracts/04-owner-separated-write-domains.yaml; decisions/invariants-and-provisionals.md]

**Decision baseline:** retain Rust and BrowserOxide, Illinois-first discovery, and the handoff amendments HA-01 through HA-04; this PRD introduces no further handoff amendment. [extracted: decisions/invariants-and-provisionals.md, P-02, P-03, P-08, and §7]

## 1. Product purpose and first useful outcome

The crawler finds real jobs and emits usable records with honest acquisition, content, classification, and enumeration evidence; job-hunter—not the crawler—decides which jobs suit Ram Balakrishnan and which applications to commission. [inferred: 1-handoff-brief.txt, Position and component interface notes; current request, Purpose]

The first useful delivery is an Illinois feed that a person or job-hunter can evaluate immediately, without waiting for Ringmaster’s form actions, Circus Tent’s extension route, multi-state coverage, or an inference service. [inferred: decisions/invariants-and-provisionals.md, HA-02 and P-13; 2-state-bank-crawler-blueprint.json, §§3 and 5–6]

The portfolio’s first application does not wait for this feed: manual discovery, profile-based evaluation, and manual application continue through the durable recording path described in the integration PRD. [extracted: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, §2]

### 1.1 What makes the feed useful

The candidate’s value lies in problem signatures—turning ambiguous environments into rules, middleware, SOPs, automation, supported people, and audit-ready processes—rather than one occupational title; discovery must preserve enough description and source context for that evaluation. [inferred: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]

The eight playbooks belong to job-hunter’s evaluation policy; crawler classification may support recall-oriented filtering, but cannot silently replace playbook matching, tolerability review, pay review, or credential analysis. [inferred: 1-handoff-brief.txt, Position; 6-get-a-job.xml.txt, job_search_queries.txt]

The feed must not hard-code an absent salary threshold, infer a current license from prior employment, or discard every bachelor’s-required posting; the supplied search policy calls for evaluating actual blockers and flagging degree requirements for their substitution language. [extracted: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]

### 1.2 Scope

| In scope | Explicit boundary |
|---|---|
| Read-only listing and description acquisition from an authorized Illinois surface. | “Read-only” is an operation property, not an HTTP-method assumption; discovery cannot perform an application, self-referral, or contact-reveal mutation. [inferred: contracts/02-external-connector.yaml, EXT-READ-ONLY; decisions/invariants-and-provisionals.md, INV-28] |
| Source-root identity, extraction, render evidence, optional declared classification, and immutable job publications. | No crawler publication establishes an application commitment or employer outcome. [extracted: contracts/04-owner-separated-write-domains.yaml, job domain layout] |
| Per-partition traversal, coverage accounting, durable cursors, leases, and recovery. | Incomplete enumeration remains incomplete even when useful postings were found. [extracted: 2-state-bank-crawler-blueprint.json, §§5, 7–8, and 11] |
| A BrowserOxide-native Rust implementation using the facilities actually required by the selected surface. | The crawler is not a cross-browser framework and does not share an implementation with Python Circus Tent. [extracted: 1-handoff-brief.txt, cohesion principle and internal-binding invariant] |
| A feed usable without a running downstream consumer. | Product evaluation and application execution cannot become synchronous dependencies of crawler commits. [extracted: 2-state-bank-crawler-blueprint.json, Decision 8; 1-handoff-brief.txt, owner-separated writes] |

Multi-state activation, authenticated Wisconsin handoff, Oregon challenge solving, general commercial-board discovery, tailored materials, employer-form completion, and autonomous job selection are outside the first slice. [inferred: 1-handoff-brief.txt, Illinois-first position; 2-state-bank-crawler-blueprint.json, §§3–4 and 13; current request, Purpose]

## 2. Boundaries and contract responsibilities

The supplied crawler blueprint is already BrowserOxide-oriented; its HTTP-first allocation is not a Camoufox implementation awaiting a wholesale browser port. [extracted: decisions/invariants-and-provisionals.md, HA-01]

The Rust-cluster boundary remains useful, but `browseroxide-core` grows only around exercised common facilities; the Illinois crawler must not wait for a speculative shared DOM/action framework. [extracted: decisions/invariants-and-provisionals.md, HA-02 and P-02]

| Boundary | Crawler responsibility | Authority retained elsewhere |
|---|---|---|
| Acquisition declaration | Pin adapter version, endpoint capabilities, representation, extraction binding, profile identity, ordering, partitioning, and effective limits. | Actual target behavior must be evidenced; a declaration cannot override an observed contradiction. [inferred: 2-state-bank-crawler-blueprint.json, §§13 and 15] |
| Evidence kernel | Journal admitted observations, local effects, timings, provenance, failures, and artifact registrations. | A server ingesting an observation does not become the authority for the posting’s assertions or an employer commitment. [inferred: contracts/00-evidence-kernel.yaml, EK-JOURNAL and EK-PROVENANCE] |
| External connector | Expose commissioned discovery work through the shared asynchronous, task-shaped surface rather than a second browser-control protocol. | Consumers assess capability; recognizing an operation does not establish a native mapping or successful effect. [inferred: 1-handoff-brief.txt, external connector; contracts/02-external-connector.yaml] |
| BrowserOxide binding | Use browser-specific synchronous primitives at full native strength where needed. | No shared `ElementHandle`, Camoufox compatibility layer, or neutral browser driver is introduced. [extracted: 1-handoff-brief.txt, internal-binding invariant] |
| Job publication | Write the `crawler` domain: acquisition, content, render, discovery, coverage, processing, classifier provenance, and replacement lineage. | job-hunter alone writes the `downstream` domain: evaluations, selection, materials, work ownership, and attempt links. [extracted: contracts/04-owner-separated-write-domains.yaml, job layout] |
| Application lifecycle | Supply pinned source material that a commissioner may select. | Commissioning, execution claims, origin facts, and reconciliation remain separate authorities; a crawler lease is not an application attempt. [inferred: contracts/01-application-attempt-lifecycle.yaml; contracts/04-owner-separated-write-domains.yaml] |

The shared connector recognizes `Describe`, `Prepare`, `Start`, `Observe`, `RequestNativeCancel`, `CloseObservationConnection`, `CollectArtifacts`, `ReleaseNativeContext`, and `Contain`; crawler mappings must preserve their distinctions, including honest unsupported or uncertain outcomes. [extracted: 1-handoff-brief.txt, external connector definition]

`Prepare` does not acquire target content; `Start` begins only the authorized discovery task, and closing observation does not establish that an in-flight native request stopped. [inferred: contracts/02-external-connector.yaml, EXT-PREPARE, EXT-START, and EXT-CLOSE]

Discovery uses a discovery manifest, not a fabricated practice or production application attempt; fields that genuinely do not apply use the kernel’s reasoned missingness rather than dummy posting or attempt identities. [inferred: contracts/00-evidence-kernel.yaml, Manifest and EK-NULL; 2-state-bank-crawler-blueprint.json, §11.0]

## 3. Illinois first-slice activation

### 3.1 Supplied allocation

The following is the supplied adapter allocation to validate, not a claim about current live behavior. [extracted: 2-state-bank-crawler-blueprint.json, §§3, 7–10, and 13]

| Dimension | Supplied Illinois position | Consequence |
|---|---|---|
| Runtime and transport | Rust/BrowserOxide; IL-A uses `HttpClient`, with `bootstrap_mode='none'`. | Start with the native HTTP acquisition path; browser launch is not a prerequisite merely because BrowserOxide is the substrate. [inferred: 1-handoff-brief.txt, Position; 2-state-bank-crawler-blueprint.json, §3.1] |
| Representation | Structured JSON and a synthetic 32-hex `_session_id` request convention. | Validate the actual request construction and returned representation; this token is not authentication evidence or permission to invent tokens in emitted source URLs. [inferred: 2-state-bank-crawler-blueprint.json, §§3.1 and 11.1; 5-browser-qualification.md] |
| Content allocation | `classification_surface='phase_a_full_description'`. | Extract the full posting from Phase A and finalize it without a routine Phase B fetch. [extracted: 2-state-bank-crawler-blueprint.json, §§5.2 and 13.A] |
| Phase B | IL-B is dormant under the full-description allocation. | Do not activate it to compensate silently for incomplete Phase A extraction. [inferred: 2-state-bank-crawler-blueprint.json, §3.1] |
| Session topology | Stateless-per-request, `shard_topology='none'`. | No fabricated shard identity and zero `session_state` rows for this allocation. [extracted: 2-state-bank-crawler-blueprint.json, §9.2] |
| Browser warmth | Initial browser pool size is zero; HTTP connection warmth is separate. | No retained Page pool is required for the initial HTTP surface. [extracted: 2-state-bank-crawler-blueprint.json, §§10.1–10.3] |
| Ordering | Deterministic page enumeration with `coverage_scope='per_run'`. | Positional pagination is allowed only within that declared scope and with clamp/drift detection. [extracted: 2-state-bank-crawler-blueprint.json, §8.3] |
| Truncation and partitions | A 10,000-match ceiling, tail clamping, county and `work_type` facets, and an equality baseline using facet counts. | Count, partition, pagination, and response evidence must support the same proof cohort. [extracted: 2-state-bank-crawler-blueprint.json, §7.1] |
| Challenges | Empty solver fleet and `unsolvable_policy='abort'`. | Unexpected challenges produce explicit failure or activation limits, not an inherited Circus Tent/CapSolver capability. [inferred: 2-state-bank-crawler-blueprint.json, §4.1; 4-circus-tent-arch.md, §3] |

### 3.2 Activation evidence

Before automated activation, retain an authorized reconnaissance bundle demonstrating request identity, endpoint non-mutation, actual posting IDs, full-description fields, source URLs, facet units and predicates, pagination behavior, and termination/clamp behavior under the pinned adapter. [proposed: turn the supplied allocation into a falsifiable activation gate rather than treating descriptive reconnaissance as permanent target truth]

The bundle must also identify the actual BrowserOxide build and available HTTP/binding surface; source names such as `HttpClient` and `Page::from_html` do not establish current signatures or current-version capability. [inferred: decisions/invariants-and-provisionals.md, §8.3; contracts/03-internal-browser-binding.yaml]

Concrete Illinois endpoint URLs, complete request/response fixtures, extraction selectors or paths, and current API signatures are not supplied here; obtain them from the actual adapter inventory and authorized reconnaissance rather than filling the gap with plausible routes. [uncertain: the compacted crawler source provides allocation and invariants but not a complete executable Illinois adapter bundle]

A missing required declaration, unavailable required capability, or contradictory mapping produces a declaration-validation audit and an `INCOMPLETE` activation result; it does not silently change ordering, enable another state, or label a challenge page as a job listing. [extracted: 2-state-bank-crawler-blueprint.json, §13.A]

If Illinois no longer offers the smallest useful authorized slice, apply P-08’s explicit flip condition; manual discovery continues while that decision is made. [extracted: decisions/invariants-and-provisionals.md, P-08 and HA-03]

## 4. Acquisition and processing workflow

### 4.1 First-slice pipeline

The Illinois path is **Extract → Description Classify → Finalize**, with a declared classification bypass permitted where supported; it is not the snippet/enrichment pipeline used by other allocations. [extracted: 2-state-bank-crawler-blueprint.json, §§5.1–5.2, 6, and 11.13]

| Stage | Required behavior | Owner-local durable boundary |
|---|---|---|
| Acquire and validate | Build the canonical request; retain response evidence, worker identity, transport attempts, and the final render verdict; validate structured responses before extraction. | Register retained bytes before citing them, and journal the acquisition evidence without fabricating a successful posting. [inferred: 2-state-bank-crawler-blueprint.json, §§3.3–3.7; contracts/00-evidence-kernel.yaml, EK-ARTIFACTS] |
| Extract | Validate source job IDs and URLs; materialize full-description listings; account for accepted page observations independently of deduplication. | Listing changes, page evidence, coverage deltas, cursor advancement, and audit commit together. [extracted: 2-state-bank-crawler-blueprint.json, §§5.1 and 7.2] |
| Description Classify | Obtain or reuse a genuine description verdict, or record an explicitly permitted bypass without a fabricated verdict. | Publish the classifier provenance or bypass evidence and advance the listing to `pending_finalize` through a fenced transition. [inferred: 2-state-bank-crawler-blueprint.json, §§5.1, 6, and 11.13] |
| Finalize | Map `title`, `employer`, `snippet`, and `full_description` to detail content, with `full_description → description`; apply fetch-key rules. | Final detail, listing completion, audit, and any eligible `seen_ids` update commit together within crawler ownership. [extracted: 2-state-bank-crawler-blueprint.json, §§5.1 and 11.4] |
| Publish | Export a complete immutable crawler revision and its evidence dependencies. | Downstream publication and read-view installation are asynchronous; no job-hunter acknowledgement is part of the crawler transaction. [extracted: contracts/04-owner-separated-write-domains.yaml; 2-state-bank-crawler-blueprint.json, Decision 8] |

Durable entity state is the source of pending work; queue notifications accelerate discovery of work but cannot be its only copy. [extracted: 2-state-bank-crawler-blueprint.json, §§5.3–5.4]

### 4.2 Classification is not a delivery prerequisite

For the initial useful feed, prefer a versioned, explicitly permitted description-classification bypass while the model is unavailable; preserve the declared Illinois content surface, genuine missing classifier fields, and `DISCOVERED` candidate semantics rather than manufacturing `PASS` or silently switching to `classification_surface='none'`. [proposed: use the blueprint’s bypass route to avoid making inference infrastructure a prerequisite for real job evaluation; 2-state-bank-crawler-blueprint.json, §§5–6]

If a bypass is not authorized by the effective policy, the affected work must wait, retry, or fail explicitly; implementation convenience cannot create an undeclared bypass. [inferred: 2-state-bank-crawler-blueprint.json, §§6 and 13]

When inference is enabled, retain model identity and digests, input identity/revision, stage, genuine verdict, applied verdict, confidence, reason, and policy revision; reuse requires compatible inputs and policy, not merely a matching job title. [extracted: 2-state-bank-crawler-blueprint.json, §§6.2–6.6 and 11.2]

The historical LiteRT, 0.5B–1.5B, quantization, batch, and latency envelope is a benchmark direction, not evidence that a selected model is accurate for this candidate or that it can meet the envelope on the deployed host. [inferred: 2-state-bank-crawler-blueprint.json, §6 and A8; decisions/invariants-and-provisionals.md, §8.2]

A model crash or memory failure must not kill the crawler or lose acknowledged work; fence stale responses and apply the declared retry/bypass policy, with inference outside crawler-worker address space and with evidenced resource isolation. [extracted: 2-state-bank-crawler-blueprint.json, §§5.7, 6.1, and Decision 1]

### 4.3 Render and extraction truth

The six render verdicts remain `Pass`, `ThinShell`, `RenderIncomplete`, `EdgeBlock`, `SensorFail`, and `ChallengeIncomplete`; render, content validity, relevance, and pagination completeness must not collapse into one success flag. [extracted: 2-state-bank-crawler-blueprint.json, §§3 and 14; contracts/04-owner-separated-write-domains.yaml, RenderVerdict]

For a declared HTML-capable route, the blueprint’s escalation is HTTP → optional `Page::from_html` when required inputs are already present → fresh cold navigation when needed; `from_html` itself performs no network request, and all attempted stages retain their evidence. [extracted: 2-state-bank-crawler-blueprint.json, §3.4]

The initial structured Illinois path must not feed an invalid JSON response or challenge body into an invented DOM fallback; escalation requires a declared compatible representation and an evidenced native capability. [inferred: 2-state-bank-crawler-blueprint.json, §§3.4–3.5 and 13.A]

A final non-`Pass` render may produce a failed-render record for a known posting, but cannot produce a ready content row; a failed listing page without known posting IDs affects its partition rather than generating dummy jobs. [extracted: 2-state-bank-crawler-blueprint.json, §3.7]

A valid render with missing required extraction fields follows `incomplete_extraction` handling; it is not equivalent to a successful row whose required title or URL is blank. [extracted: 2-state-bank-crawler-blueprint.json, §§3.7 and 11.1]

## 5. Coverage and cursor correctness

### 5.1 Per-partition evidence, not a run-wide impression

For a partition \(P\), let \(O_P\) be the accepted observations in distinct committed packets, \(U_P\) the exact set of observed posting IDs, and \(T_P\) an independently obtained count of jobs for the same partition and proof cohort; these symbols explain the proof and do not introduce new wire fields. [proposed: express the existing coverage ledger as reviewable algebra; 2-state-bank-crawler-blueprint.json, §7]

Illinois equality requires \(|U_P| = T_P\), but equality alone is insufficient: the count source, unit, predicate, cohort, allowed traversal, render validity, and absence or resolution of truncation/clamp evidence must also support the proof. [inferred: 2-state-bank-crawler-blueprint.json, §§7.1–7.3 and 8]

`observed_total` and `distinct_observed_total` are not interchangeable; duplicate observations, repeated terminal IDs, and successful-detail deduplication cannot manufacture additional coverage. [extracted: 2-state-bank-crawler-blueprint.json, §§7.2 and 11.5]

The `seen_ids` cache must never suppress coverage evidence for a posting observed again; processing novelty and enumeration coverage are independent. [extracted: 2-state-bank-crawler-blueprint.json, §7.2]

| Situation | Required interpretation |
|---|---|
| Independent count missing or incompatible | Preserve observations, but no positive equality proof. [extracted: 2-state-bank-crawler-blueprint.json, §7] |
| No observations | Zero alone proves nothing; use `empty_unproven` in the initial slice unless an explicit evidence-backed empty-partition rule is supplied and validated. [proposed: prevent vacuous zero-equals-zero completion while the compacted source does not supply an executable empty-proof rule] |
| Cap boundary reached | Do not equate ordinary termination with completeness; reconcile the boundary or split using verified predicates. [extracted: 2-state-bank-crawler-blueprint.json, §7.3] |
| Terminal page/item repeats beyond range | Detect tail clamping, retain the corroborating observations, and stop repeated acquisition without claiming new progress. [extracted: 2-state-bank-crawler-blueprint.json, §7.3] |
| Distinct requested coordinates repeat page-one content without progress | Apply no-op-pagination detection rather than committing a fabricated next page. [extracted: 2-state-bank-crawler-blueprint.json, §7.3] |
| Parent partition is split | Preserve its predicate, child references, split evidence, and proof relationships; do not relabel the parent proven merely because children exist. [inferred: 2-state-bank-crawler-blueprint.json, §§7 and 11.5] |
| Children overlap | Use exact-ID union for aggregate observations; summing child counts is valid only with evidenced disjointness and compatible units/cohorts. [inferred: 2-state-bank-crawler-blueprint.json, §7, per-partition coverage discipline] |
| One leaf fails | Keep that leaf incomplete without discarding valid sibling postings or overstating the parent’s coverage. [inferred: 2-state-bank-crawler-blueprint.json, Decision 7; decisions/invariants-and-provisionals.md, INV-28] |

Coverage publications retain the ledger’s predicate and definition hash, count source/unit, observations, render health, proof cohort, detector evidence, and explicit status: `open`, `bisected`, `proven`, `incomplete`, or `empty_unproven`. [extracted: 2-state-bank-crawler-blueprint.json, §11.5]

An individually valid posting remains useful to job-hunter even when its enumeration partition is incomplete; the consumer must see that limitation rather than receive either a false completeness claim or an unnecessarily empty feed. [inferred: prd/00-integration.md, §4.1; 2-state-bank-crawler-blueprint.json, Decision 7]

### 5.2 Durable cursor rules

Offset pagination is permitted only under `ordering_model='Deterministic'` and `coverage_scope='per_run'`; storing a number or following a “Next” link does not transform an offset into a continuation capability. [extracted: 2-state-bank-crawler-blueprint.json, §8.1]

A committed cursor must never point beyond durably materialized observations and entities; after a crash, replay only the uncommitted or incomplete traversal from the last compatible committed coordinate. [extracted: 2-state-bank-crawler-blueprint.json, §§1, 5.7, and 8.2]

Resume requires a compatible ordering fingerprint and proof cohort; drift invalidates the affected interpretation rather than authorizing an adapter to relabel its ordering model. [extracted: 2-state-bank-crawler-blueprint.json, §§8.2–8.5]

Over-fetch factors are planning multipliers, not coverage proofs, and a configured retry or reconciliation limit cannot convert exhaustion into completeness. [extracted: 2-state-bank-crawler-blueprint.json, §§7–8]

## 6. Job records, ownership, and replacement

### 6.1 Published job meaning

The source root remains `(target, job_id)`; partition and session records use their own scoped identities and must not invent a posting ID to fit a job-shaped schema. [extracted: 2-state-bank-crawler-blueprint.json, §11.0]

| Record concern | Required meaning |
|---|---|
| Source URLs | For full-description Phase A, `source_url` identifies the actual listing response from which content was extracted; `listing_page_url` retains the enumeration response identity. [extracted: 2-state-bank-crawler-blueprint.json, §11.1] |
| Apply destination | Preserve an actually observed direct-apply location with evidence; do not derive a plausible employer URL or follow a mutating action merely to obtain it. [inferred: contracts/04-owner-separated-write-domains.yaml, JobContent; contracts/02-external-connector.yaml, EXT-READ-ONLY] |
| Core content | Retain title, employer, snippet, description, and dates according to the adapter’s validated required/nullable declarations. [extracted: 2-state-bank-crawler-blueprint.json, §§11.1, 11.4, and 13] |
| Missing content | Use the kernel’s reasoned missingness; no empty-string, zero, or guessed-value substitutes for absent fields. [extracted: contracts/00-evidence-kernel.yaml, EK-NULL] |
| Closing date | Preserve observed text without inventing a timezone or exact deadline where the source does not establish one. [extracted: contracts/04-owner-separated-write-domains.yaml, open evidence] |
| Processing | Preserve operational detail state separately from render verdict, classifier result, coverage, and product selection. [extracted: 2-state-bank-crawler-blueprint.json, §§11.4 and 14] |
| Candidate semantics | The crawler domain retains `DISCOVERED`, `SHORTLISTED`, and `CLOSED` semantics under its rules; downstream ownership and attempt outcomes do not become crawler writes. [extracted: contracts/04-owner-separated-write-domains.yaml, JobProcessing and source reconciliation] |
| Product decisions | Evaluations, materials, selection, priority, downstream leases, and attempt links are separate owner publications pinned to the input revision. [extracted: contracts/04-owner-separated-write-domains.yaml, JobDownstreamValue] |

The old shared `semantic_state` transitions involving `CLAIMED` and `APPLIED`, Firestore job/tracker `status`, and company/title deduplication keys cannot override owner separation, source identity, or the five application-attempt axes. [inferred: 2-state-bank-crawler-blueprint.json, §11.14; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md; contracts/04-owner-separated-write-domains.yaml]

### 6.2 Applicable operational entities

The first slice uses the relevant `listing`, `job_detail`, `coverage_ledger`, `cursor_state`, `audit_log`, `dead_letter`, and `seen_ids` responsibilities; classifier records appear only for genuine classifier results. [inferred: 2-state-bank-crawler-blueprint.json, §§5–6 and 11]

Dormant Phase B does not require fabricated `work_item` activity, sessionless IL does not require `session_state` rows, and the existence of `state_mutation_record` in the broader blueprint does not authorize discovery to mutate a target. [inferred: 2-state-bank-crawler-blueprint.json, §§3.1, 9.2, and 11.3–11.9; contracts/02-external-connector.yaml, EXT-READ-ONLY]

These are logical responsibilities, not a mandate to deploy eleven storage services or reproduce the historical table layout; the selected implementation must preserve the contract’s transaction, ownership, and publication behavior. [inferred: 1-handoff-brief.txt, semantic boundaries and owner-separated writes]

### 6.3 Fetch identity and archives

Use the versioned fetch-key profile in the owner-separated contract: Phase B identity includes target, phase, job ID, and canonical request, while the full-description Phase A identity includes target, `A_full`, job ID, and listing source URL. [extracted: contracts/04-owner-separated-write-domains.yaml, x-fetch-key-profile]

A same-fetch-key content write remains a no-op, including when the returned content changed or an earlier render failed; a run nonce, timestamp, or arbitrary query change must not be smuggled into identity to obtain refresh behavior. [extracted: decisions/invariants-and-provisionals.md, §5; contracts/04-owner-separated-write-domains.yaml, source reconciliation]

This creates a real freshness limitation for repeated Phase A acquisition from a stable URL; preserve new acquisition observations separately and expose the limitation rather than presenting the stored detail as freshly replaced. [inferred: contracts/04-owner-separated-write-domains.yaml, fetch-key profile and same-key rule]

Changing that behavior requires an explicit versioned contract decision and regression cases; meanwhile, an operator can retain a newer manual source snapshot without falsely claiming that the crawler refreshed its row. [proposed: keep the retained idempotency rule honest while preserving the application-producing manual path]

A different-fetch-key replacement archives the complete prior published logical row at a named owner version vector, including downstream data and registration—not just crawler columns. [extracted: contracts/04-owner-separated-write-domains.yaml, archive requirements]

The retained `owner-domain-extents/1` mechanism pins already immutable domain artifacts, allowing complete reconstruction without serializing downstream payloads or waiting for a downstream transaction in the crawler critical path. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-EXTENT-ENCODING]

Archive bytes and transitive dependencies must be durable and GC-protected before replacement acknowledgement; readers observe an old or new complete root, never a partially replaced composition. [extracted: contracts/04-owner-separated-write-domains.yaml, archive expansion and read-root rules]

Only successfully completed `ready` or `vetoed` detail revisions enter `seen_ids`; render failure is not successful acquisition. [extracted: 2-state-bank-crawler-blueprint.json, §11.11]

## 7. Runtime, recovery, and evidence

### 7.1 Native runtime and bounded work

Use BrowserOxide’s native HTTP and, when required, DOM/V8 facilities without CDP indirection; do not introduce a Playwright-like cross-browser layer to make the crawler and Ringmaster look alike. [extracted: 1-handoff-brief.txt, component interface notes and internal-binding invariant]

If Page execution is activated, each Page, isolate-local handle, DOM reference, and solver remains on its owning OS thread; asynchronous queues exchange durable work references or owned data, not borrowed browser handles. [extracted: 2-state-bank-crawler-blueprint.json, §§1, 5.5, and 9]

A shared Rust library does not itself authorize shared profiles, cookies, lease owners, or learned state between crawler and Ringmaster; actual state ownership and scope remain explicit. [inferred: 1-handoff-brief.txt, independent products; 2-state-bank-crawler-blueprint.json, §§9–10]

Bound admissions by both rows and bytes, bound observation and diagnostic buffering, and configure positive navigation/retry/reconciliation limits through the effective declaration; the PRD does not invent deployment-wide timeout or queue constants. [inferred: 2-state-bank-crawler-blueprint.json, §§5, 13, and deployment assumptions]

The blueprint’s memory and inference numbers remain sizing targets under stated assumptions, not permission to drop acknowledged work, truncate descriptions, or treat the whole crawler as one hard memory limit. [inferred: 2-state-bank-crawler-blueprint.json, §§2 and 6]

### 7.2 Fenced work and failure handling

| Condition | Required response |
|---|---|
| Work claim | Atomically establish the lease and fencing identity without changing pipeline state; retain the input revision being processed. [extracted: contracts/00-evidence-kernel.yaml, EK-LEASE] |
| Stale completion | Reject effects from an obsolete lease, worker epoch, or input revision; retain evidence of the rejected publication. [inferred: contracts/00-evidence-kernel.yaml, EK-LEASE; 2-state-bank-crawler-blueprint.json, §§5.7 and 9.7] |
| Release or expiry | Account for the failure/retry at most once; do not introduce an “in-progress” pipeline state as a second ownership mechanism. [extracted: 2-state-bank-crawler-blueprint.json, §§14 and 16.2] |
| Worker crash | Preserve committed observations and cursors, fence the old worker, and recover eligible durable work under the measured deployment bounds. [extracted: 2-state-bank-crawler-blueprint.json, §5.7] |
| Lease-authority restart | Apply registered clock/epoch recovery rules; never subtract monotonic values across boots. [extracted: contracts/00-evidence-kernel.yaml, EK-LEASE-RESTART] |
| Extraction or render exhaustion | Retain scoped failure and dead-letter evidence; never force a ready row to make the queue drain. [inferred: 2-state-bank-crawler-blueprint.json, §§3.7, 5.7, and 11.10] |
| Storage pressure or unavailable durability | Apply bounded backpressure and expose incomplete work; do not acknowledge evidence or effects that were not durably committed. [inferred: contracts/00-evidence-kernel.yaml, EK-ATOMICITY; 2-state-bank-crawler-blueprint.json, Decision 5] |
| Stop, timeout, or containment | Preserve completed local effects and uncertain in-flight observations; distinguish harness deadline, transport closure, native stop, and process termination. [extracted: 5-browser-qualification.md, evidence discipline; contracts/02-external-connector.yaml] |

### 7.3 Evidence requirements

Every measurement identifies its origin, clock, and boot; durations are exact, bounded, or unavailable with reason and censoring, and UTC is annotation rather than a subtraction clock. [extracted: contracts/00-evidence-kernel.yaml, EK-TIME]

Preserve exact zero when observed or reported; missing request timing, source dates, classification confidence, and coverage totals cannot be defaulted to zero. [inferred: contracts/00-evidence-kernel.yaml, EK-NULL and EK-TIMING-INTERPRETATION]

Authenticated ingestion assigns provenance and authority; raw target responses, extracted assertions, classifier results, operator notes, and derived coverage assessments remain distinguishable. [inferred: contracts/00-evidence-kernel.yaml, EK-PROVENANCE]

Retain response and request evidence as access-classified immutable artifacts, excluding raw credentials from ordinary logs and public exports; request identity must preserve meaningful acquisition inputs without publishing secrets. [inferred: contracts/00-evidence-kernel.yaml, EK-ARTIFACTS; 2-state-bank-crawler-blueprint.json, §§3.3 and 11; 6-get-a-job.xml.txt, AGENTS.md]

Replay of crawler evidence means deterministic re-derivation from recorded inputs where supported; it is not another live fetch, and Hellscape exact-fixture replay must not be advertised as replay of a state job bank. [inferred: contracts/00-evidence-kernel.yaml, EK-REPLAY; 3-hellscape-blueprint.md, §6.5]

## 8. Delivery and acceptance

### 8.1 Sequence

| Increment | Independently useful result | Not a prerequisite |
|---|---|---|
| Parallel operating lane | Manually sourced jobs are evaluated and applied to with durable evidence. | Any crawler implementation milestone. [extracted: decisions/invariants-and-provisionals.md, HA-03] |
| Contract and fixture slice | Local kernel, acquisition, extraction, coverage, lease, and publication tests run against retained synthetic or authorized captured inputs. | A running Hellscape service, job-hunter deployment, or live browser executor. [inferred: 1-handoff-brief.txt, silo-test discipline] |
| Illinois activation | A pinned declaration and reconnaissance bundle establish the smallest supported read-only surface. | Multi-state activation or unrelated browser primitives. [inferred: decisions/invariants-and-provisionals.md, P-08 and HA-02] |
| Useful feed | The selected Illinois pipeline publishes source-backed jobs, explicit classification/bypass provenance, and per-partition coverage. | Deployed SLM inference, embeddings, automatic tailoring, or complete enumeration of every partition. [inferred: 2-state-bank-crawler-blueprint.json, §§5–7; decisions/invariants-and-provisionals.md, P-13] |
| Consumer assembly | job-hunter evaluates pinned crawler revisions and publishes only its downstream domain. | Cross-owner transactions or a shared canonical Firestore database. [extracted: contracts/04-owner-separated-write-domains.yaml; 1-handoff-brief.txt, Firebase decision] |
| Evidence-driven expansion | Add a capability or state only when its activation evidence and conformance scope are satisfied. | Speculative implementation of every historical adapter and solver. [inferred: 2-state-bank-crawler-blueprint.json, §13; 1-handoff-brief.txt, minimal-slice-first invariant] |

Kernel correctness is required, but the kernel reference component’s deployment is not: the crawler proves its own applicable obligations before peer contact. [inferred: 1-handoff-brief.txt, Step 0 and silo-test discipline]

### 8.2 Acceptance cases

The following cases supplement the shared suites; each test retains its declared inputs, journal, expected effects, and relevant publications, and no result is asserted to have passed in this draft. [proposed: make the crawler slice independently verifiable]

| Case | Acceptance oracle |
|---|---|
| **Happy path: full-description Illinois page** | Valid source IDs, URLs, descriptions, page evidence, and cursor changes commit consistently; the feed contains no invented Phase B activity. [proposed: test §§3–4 against the supplied Illinois allocation] |
| **Declared classifier bypass** | No classifier service is required; the record contains explicit permitted bypass evidence, no fabricated `PASS`, and no silent content-surface change. [proposed: test the application-producing first-feed policy] |
| **Genuine classifier execution** | Raw and applied verdicts, model/input/policy identity, and reuse conditions remain inspectable; stale leased replies have no effects. [proposed: test classification provenance and fencing] |
| **Duplicate and already-seen jobs** | Repeated IDs do not inflate distinct coverage; observed postings already in `seen_ids` still contribute observation evidence. [proposed: test the independence of processing deduplication and coverage] |
| **Equality, mismatch, and empty boundary** | Compatible independent count plus valid traversal can prove a partition; mismatch, incompatible cohorts, or zero observations alone cannot. [proposed: test the coverage proof rather than a page-count heuristic] |
| **Cap, no-op, and tail clamp** | Detector evidence stops false progress and triggers declared reconciliation/splitting or incomplete status; repeated terminal content cannot advance coverage. [proposed: test hostile enumeration behavior with deterministic fixtures] |
| **One incomplete child** | Valid sibling postings remain available; parent completion is not asserted and overlap is not double-counted. [proposed: test partition-local failure and aggregate honesty] |
| **Crash around page commit** | Recovery sees either the complete committed page effects or the previous cursor, never a cursor beyond durable jobs/evidence. [proposed: test owner-local atomicity] |
| **Lease expiry and stale worker** | Claim does not alter pipeline state; duplicate release/expiry accounts once, and old-owner completion is rejected. [proposed: test EK-LEASE and the Stage1 lease invariants] |
| **Malformed or blocked response** | No ready job is extracted from a failed render; known-posting failure and unknown-ID partition failure remain distinct. [proposed: test failure materialization without fabricated identities] |
| **Same fetch key** | Content remains unchanged even after changed bytes or a prior failed render; new observations do not masquerade as a replaced detail. [proposed: test the retained fetch-key limitation explicitly] |
| **Different fetch key under concurrent writes** | The complete prior logical row reconstructs at its pinned vector; readers see old-or-new roots, ingest does not wait on downstream payload serialization, and GC cannot remove dependencies. [proposed: test replacement, isolation, and transitive retention together] |
| **Sessionless runtime** | Illinois produces no dummy shard or `session_state` records and requires no Page pool; HTTP evidence does not certify DOM/action capabilities. [proposed: test the actual first-slice surface rather than the broader engine] |
| **Ownership and mutation denial** | Crawler attempts to write product fields or execute application/contact-reveal mutations are rejected and audited. [proposed: test both data authority and discovery permissions] |
| **Clock, null, and provenance corruption** | Cross-clock subtraction, unreasoned nulls, zero-as-missing, forged provenance, and unjournaled evidence are rejected or reported as harness/integrity failures. [proposed: apply the retired qualification discipline through kernel conformance] |

Run the applicable kernel, external-connector, owner-separated-write-domain, and BrowserOxide-binding suites locally; declare unexercised native capabilities and exemptions rather than treating the HTTP-only slice as proof of all browser primitives. [inferred: 1-handoff-brief.txt, Step 0; conformance/00-evidence-kernel.md; conformance/02-external-connector.md; conformance/03-internal-browser-binding.md; conformance/04-owner-separated-write-domains.md]

CI uses fixtures and synthetic backends, not live employer writes; authorized target reconnaissance is separately labeled and retained, not passed off as a deterministic fixture test. [inferred: 6-get-a-job.xml.txt, AGENTS.md; 5-browser-qualification.md]

## 9. Operating measures and unresolved evidence

### 9.1 Measures

Report discovered source-root jobs, successfully materialized details, render failures, extraction failures, genuine classifications, bypasses, and publication lag separately; there is no single crawler status that can stand for all of them. [proposed: expose useful throughput without collapsing acquisition, processing, and publication semantics]

Report coverage by partition and proof cohort, including proven, incomplete, and empty-unproven work; do not publish a percentage whose denominator is an unverified total. [inferred: 2-state-bank-crawler-blueprint.json, §§7 and 11.5]

Preserve the blueprint’s `stage_rows_in`, `stage_rows_out`, `stage_latency_ms`, `queue_depth`, `phase_request_overhead_ms`, and `signals_emit_latency_ms` meanings, with the kernel’s measurement discipline applied to their records. [extracted: 2-state-bank-crawler-blueprint.json, §2.6; contracts/00-evidence-kernel.yaml]

The product review asks whether the feed led to useful evaluations and real applications, but application counts come from job-hunter’s tracked attempts and verified origin evidence—not from crawler rows, shortlist states, or link clicks. [inferred: current request, Purpose; contracts/01-application-attempt-lifecycle.yaml]

### 9.2 Unclosed crawler backlog

No first-slice scope reduction closes an `INCOMPLETE` marker or validates a deployment assumption. [extracted: decisions/invariants-and-provisionals.md, §§7–8]

| Marker | Evidence still required |
|---|---|
| `§4.OR-solver` | An operational solver with retained challenge, continuity, deadline, and recovery evidence; a registered placeholder is insufficient. [uncertain: Oregon operational solver evidence is absent; 2-state-bank-crawler-blueprint.json, §4] |
| `§7.proof-sources` | Verified MI aggregate extraction and an independent OR total/floor source with compatible units and predicates. [uncertain: required independent count evidence is absent; 2-state-bank-crawler-blueprint.json, §7] |
| `§8.nonoffset-cursors` | Permitted continuation/keyset evidence for affected MN/WI/MI walks; renaming positional offsets does not satisfy the Floor. [uncertain: required cursor capabilities are unestablished; 2-state-bank-crawler-blueprint.json, §8] |
| `§15.veto-projections` | Candidate-relevant labeled measurements and genuine/applied verdict provenance; capacity cannot assume filtering savings before measurement. [uncertain: veto-rate evidence is absent; 2-state-bank-crawler-blueprint.json, export declaration and §15] |

| Assumption | Deployment proof required before relying on it |
|---|---|
| A1 — hardware and resource isolation | Inventory the host and demonstrate that inference pressure cannot reclaim crawler/OS resources. [uncertain: actual deployment isolation evidence is absent; decisions/invariants-and-provisionals.md, §8.2] |
| A2 — persistence service domains | Measure ingest under concurrent downstream writes and exchange; separate tables alone do not establish independently reserved I/O. [uncertain: storage service and commit-latency evidence is absent; 2-state-bank-crawler-blueprint.json, A2 and Decision 8] |
| A3 — network benchmark | Measure the actual target’s pagination time and orchestration overhead; the supplied 200 ms reference is not a live Illinois measurement. [uncertain: current target timing is absent; 2-state-bank-crawler-blueprint.json, A3] |
| A4 — recovery bounds | Fault-inject process loss, measure detection/replacement, and validate fencing and lease policy against those results. [uncertain: deployed recovery measurements are absent; 2-state-bank-crawler-blueprint.json, A4] |
| A5 — clocks | Establish lease-authority clock/epoch behavior and scheduling uncertainty without cross-clock elapsed subtraction. [uncertain: deployed timekeeping evidence is absent; 2-state-bank-crawler-blueprint.json, A5; contracts/00-evidence-kernel.yaml] |
| A6 — entity sizes | Sample actual payload and evidence sizes for bounded admission; reference sizes must not become parser limits. [uncertain: representative deployment samples are absent; 2-state-bank-crawler-blueprint.json, A6] |
| A7 — downstream workload | Exercise actual write distribution, publication lag, and archive load without blocking ingest. [uncertain: workload evidence is absent; decisions/invariants-and-provisionals.md, §8.2] |
| A8 — inference envelope | Benchmark pinned model/runtime/tokenizer and complete-input handling on the actual host. [uncertain: full-input performance evidence is absent; 2-state-bank-crawler-blueprint.json, §6; decisions/invariants-and-provisionals.md, §8.2] |
| A9 — durability fault model | Verify acknowledged-write recovery under crash and reboot; permanent-media-loss claims require separate evidence. [uncertain: deployment durability tests are absent; decisions/invariants-and-provisionals.md, §8.2] |

The complete deployment thresholds and omitted implementation details must be recovered from the unabridged blueprint and selected contract artifacts before making an executable acceptance claim; the compacted reference is not a substitute for missing formulas, field definitions, or native signatures. [uncertain: portions of the supplied crawler blueprint and prior contracts are compacted; retrieve the full artifacts and validate the implementation against them]

The crawler succeeds first by supplying useful, source-backed opportunities without obstructing applications; broader coverage, faster acquisition, and richer native infrastructure are improvements to that service, not reasons to postpone using it. [inferred: current request, Purpose; 1-handoff-brief.txt, minimal-slice-first and thin-slice discipline]
