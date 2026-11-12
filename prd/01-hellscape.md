# Hellscape PRD — form-fidelity laboratory and evidence reference

**Status:** Step 0 review draft; requirements below describe intended behavior, not an implemented system or a qualified automation subject. [proposed: distinguish specification from observed capability]

**Contract baseline:** evidence kernel, application-attempt lifecycle, external connector, owner-separated write domains, and suggested-fix registry at `0.1.0`; browser-specific binding conformance belongs to the executor products, not to a universal Hellscape driver. [inferred: contracts/00-evidence-kernel.yaml; contracts/01-application-attempt-lifecycle.yaml; contracts/02-external-connector.yaml; 1-handoff-brief.txt, Parts V–VIII]

**Decision baseline:** `decisions/invariants-and-provisionals.md`, especially INV-07 through INV-24, P-06, P-10 through P-12, and HA-03; this PRD specifies the storage implementation and acceptance conditions left open by P-06 without introducing another handoff amendment. [proposed: resolve the documented storage tension through an explicit provisional implementation choice]

## 1. Purpose and product boundary

Hellscape is a controlled form-fidelity laboratory that records what happened, distinguishes fixture truth from observations and subject claims, and produces reproducible diagnostics that help improve application execution. [extracted: 1-handoff-brief.txt, Parts I and III; 3-hellscape-blueprint.md, Product and §1]

Its value to the job-search portfolio is better-understood execution failures and independently evidenced improvements—not simulated application volume or proof that a subject can handle an employer’s forms. [inferred: current request, Purpose; 1-handoff-brief.txt, Parts III and IX]

Real job descriptions may supply realistic task content, but Hellscape remains a laboratory fixture using synthetic identities and documents; it is neither an ATS nor a fake employer. [extracted: 1-handoff-brief.txt, Part III; 3-hellscape-blueprint.md, §1]

### 1.1 Users and useful outputs

| User | Need | Useful output |
|---|---|---|
| Manual validator | Establish that the fixture and observer agree with an ordinary browser walkthrough. | Durable state, timeline, rejected-and-corrected steps, scoped elapsed measurements, diagnostic, and replay receipt. [extracted: 3-hellscape-blueprint.md, M1 acceptance and first-run procedure] |
| Circus Tent or Ringmaster developer | Determine where an identified execution failed without confusing a fixture defect, missing capability, or connector error with a subject defect. | Evidence-backed findings with source, scope, attribution, contrary evidence, and reproduction inputs. [inferred: 3-hellscape-blueprint.md, §§3–4; current request, Products] |
| job-hunter developer | Exercise commissioning, closure, claims, origin facts, and reconciliation without employer writes. | Practice attempts using the same external contract and lifecycle distinctions as production. [inferred: 1-handoff-brief.txt, Parts VI and IX] |
| Candidate/operator | Receive useful learning without delaying real applications. | Separately reported laboratory findings while manual or authorized automated production work continues. [inferred: 1-handoff-brief.txt, Parts VII–IX; decisions/invariants-and-provisionals.md, HA-03] |

Hellscape availability is not a prerequisite for the day-one application lane; manual discovery, evaluation, application, and evidence recording proceed independently. [extracted: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, §2]

### 1.2 Non-goals

- Hellscape does not execute real applications, hold real applicant identities, solve production CAPTCHAs, or promise production bot-detection resistance. [extracted: 3-hellscape-blueprint.md, §1, Outside product]
- It does not repair framework source, supply an undisclosed planner, or infer private selectors, reasoning, or recovery tiers from silence. [extracted: 3-hellscape-blueprint.md, §1, Outside product]
- It does not guarantee native cancellation, infer rollback from process termination, or redefine containment as isolation. [extracted: 3-hellscape-blueprint.md, §§1 and 13]
- It does not require a browser-engine fork or substrate build to deliver M1. [extracted: 3-hellscape-blueprint.md, §1, Outside product]
- It does not turn a practice success, browser benchmark, or reviewed fix proposal into production authorization. [inferred: 1-handoff-brief.txt, Parts III and VI; decisions/invariants-and-provisionals.md, P-14]

## 2. First release: M1, not another qualification gate

**M1 ships a cooperative SPA and an observer that correctly characterizes a manual walkthrough, plus a subject-agnostic connector implementation tested against synthetic backends.** [extracted: 3-hellscape-blueprint.md, Product, §§7–8 and 15]

M1 acceptance requires no live automation subject and no subject-completion result; M2 is the first live subject milestone, and a subject’s failure there remains useful output rather than a reason to redefine the fixture. [extracted: 3-hellscape-blueprint.md, Product and §7]

The retired m0 harness contributes evidence discipline and regression scenarios, not a resurrected pre-M1 proceed/stop gate or a separately deployed product. [extracted: 1-handoff-brief.txt, Parts I and VIII; 3-hellscape-blueprint.md, Product]

### 2.1 M1 scope

| Included | Deferred or excluded from M1 |
|---|---|
| Eight-state cooperative SPA, synthetic tasks/documents, manual operation, server-owned predicates, and explicit finalization. | Hostile packs, shadow/frame challenges, artificial timing races, curriculum, and minimization. [extracted: 3-hellscape-blueprint.md, §§8–9] |
| Immutable manifests, durable owner-local journals and state, artifact retention, diagnostics in structured and readable forms. | Behavioral scoring and production-grade transport/fingerprint analysis. [extracted: 3-hellscape-blueprint.md, §8] |
| Shared connector lifecycle, initial documented Circus Tent REST translation, authenticated callback handling, and synthetic-native response cases. | Live Circus Tent completion, a Ringmaster-specific native mapping, or invented native cancellation/release endpoints. [extracted: 3-hellscape-blueprint.md, §§5 and 8] |
| Exact fixture replay and diagnostic re-derivation with retained build and input pins. | Re-executing a browser or subject as “exact replay.” [extracted: 3-hellscape-blueprint.md, §§6 and 10] |
| Explicitly disabled fix suggestions and fingerprint sections. | A deployed registry, autonomous repair, JA3/JA4 capture, and HTTP/2 fingerprint analysis. [extracted: 3-hellscape-blueprint.md, §§7–8; 1-handoff-brief.txt, Part VII] |

### 2.2 Meaning of cooperative

A cooperative fixture has visibly labeled controls, stable layout and semantic identities, and no deliberately obstructive treatments: no class churn, decoys, delayed hydration, shadow/frame challenge, network-idle trap, injected transport failure, production challenge service, or artificial timing race. [extracted: 3-hellscape-blueprint.md, §1, Cooperative definition]

Ordinary validation, uploads, asynchronous transitions, identity confirmation, and submission guards remain present; “cooperative” is a property of the fixture, not a promise that an automation framework will complete it. [extracted: 3-hellscape-blueprint.md, §1]

## 3. Cooperative application requirements

### 3.1 Workflow and authoritative checkpoints

The application flow is `LISTING → DETAIL → CONTACT → HISTORY → UPLOAD → IDENTITY → REVIEW → CONFIRMATION`. [extracted: 3-hellscape-blueprint.md, §§6 and 9]

| State | Ordinary interaction | Authoritative check |
|---|---|---|
| LISTING / DETAIL | Read a synthetic posting and choose to continue. | The selected job exists and belongs to the explicitly bound attempt. [extracted: 3-hellscape-blueprint.md, §9] |
| CONTACT | Enter contact data and explicitly save/continue. | Required values satisfy the current section contract. [extracted: 3-hellscape-blueprint.md, §9] |
| HISTORY | Enter work history, encounter visible validation, and correct invalid values. | An end-before-start interval is rejected without advancing; later valid data is recorded as a separate accepted attempt. [extracted: 3-hellscape-blueprint.md, §9 and first-run procedure] |
| UPLOAD | Use a visible ordinary file input with progress and completion feedback. | Uploaded bytes match a manifest-pinned synthetic document digest. [extracted: 3-hellscape-blueprint.md, §9] |
| IDENTITY | Complete synthetic identity verification. | Verification evidence belongs to this attempt and current epoch. [extracted: 3-hellscape-blueprint.md, §9] |
| REVIEW | Review current data and submit explicitly. | Contact, history, upload, identity, and review revisions are current, with no prior commitment. [extracted: 3-hellscape-blueprint.md, §9] |
| CONFIRMATION | Read the returned receipt. | Server commitment and confirmation rendering are recorded separately. [extracted: 3-hellscape-blueprint.md, §§4 and 9] |

Section validation is bound to section, revision, and generation; stale validation never authorizes a later transition, and entering a section does not establish its completeness. [extracted: 3-hellscape-blueprint.md, §§6 and 9]

Every fixture attempt permits at most one commitment; repeated submission with the same operation identity and payload returns the retained receipt, while reuse of that identity with changed content is a conflict. [extracted: 3-hellscape-blueprint.md, §9]

The baseline uses explicit save/continue rather than autosave, normal focus and keyboard behavior, visible validation, and readiness after controls are rendered and enabled; it exposes no private selector hints or hidden assistance. [extracted: 3-hellscape-blueprint.md, §9]

### 3.2 Application and control surfaces

The ordinary application API covers job selection, draft retrieval, contact/history updates, upload, synthetic identity verification, review validation, submission, and confirmation; each mutation carries operation identity and the expected revisions required by its contract. [extracted: 3-hellscape-blueprint.md, §9, API and transaction rules]

Control operations create sessions, expose permitted task inputs, dispatch subjects, record manual notes, end observation, request separately authorized controls, retrieve evidence, and export/replay bundles. [extracted: 3-hellscape-blueprint.md, §11]

A manual note is evidence from an observer, never a command to set a business predicate; neither a telemetry event nor an administrative annotation may manufacture submission or verification success. [extracted: 3-hellscape-blueprint.md, §§3 and 11]

## 4. Architecture and authority

### 4.1 Runtime choice

M1 retains the blueprint’s Go binary, Vite-built strict TypeScript with vanilla Web Components in light DOM, SQLite/WAL persistence, and content-addressed artifacts, subject to the owner-local storage arrangement in §5. [proposed: preserve the independently buildable M1 stack while correcting its shared-database interpretation; 3-hellscape-blueprint.md, §§3 and 8]

The runtime serves built frontend assets and requires writable storage, TLS configuration, and an ordinary browser; it does not require a Node server, database daemon, proxy capture process, model service, or executor service for manual validation. [extracted: 3-hellscape-blueprint.md, §11, Build and runtime]

Go remains provisional because a useful M1 is already specified in it, not because future fingerprint capture must block the kernel; production capture remains M5 work. [inferred: decisions/invariants-and-provisionals.md, P-06; 3-hellscape-blueprint.md, §§7 and 11]

### 4.2 Responsibility cuts

| Responsibility | Owns | Forbidden promotion |
|---|---|---|
| Application truth | Fixture reducer, current state, validation decisions, operation receipts, and commitments. | Browser observations cannot write fixture truth. [extracted: 3-hellscape-blueprint.md, §3] |
| Observation | Requests, fixture-client events, transport evidence, manual notes, source claims, and completeness records. | Receiving a claim does not make it true. [extracted: 3-hellscape-blueprint.md, §3] |
| Execution connector | Faithful task translation, bounded dispatch/observation, and lifecycle publications under its grants. | It cannot declare application success or requirement satisfaction. [extracted: contracts/02-external-connector.yaml, EXT-DECLARE-NOT-ASSESS] |
| Judgment | Diagnostic findings and report-only reconciliation over pinned inputs. | The reconciler cannot overwrite subject claims or origin facts. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES and LIFE-RECONCILE] |
| Policy | Selection of future experiments and curriculum cells. | It cannot change an active manifest or quietly increase assistance mid-run. [extracted: 3-hellscape-blueprint.md, §§3 and 6] |
| Containment | Bounded local waiting, fixture mutation authority, and separately authorized local resources. | Prevented fixture writes do not prove that the subject stopped. [extracted: 3-hellscape-blueprint.md, §§3 and 13] |

These are logical authorities even inside one binary; deployment colocation does not authorize cross-owner transactions or shared write credentials. [inferred: 1-handoff-brief.txt, Parts V–VI; decisions/invariants-and-provisionals.md, §5]

### 4.3 Three authorization planes

- **Application:** ordinary browser interfaces with explicit attempt binding, never a global “current session” cookie that chooses the record for every request. [extracted: 3-hellscape-blueprint.md, §3]
- **Telemetry:** write-only fixture-owned producers with registered event types, server-assigned provenance, sequence deduplication, and recorded gaps/overflow; client-emittable types exclude server commitment and verification success. [extracted: 3-hellscape-blueprint.md, §3]
- **Control:** separately authenticated manifests, administration, evidence, diagnostics, and replay; application cookies and CORS configuration do not confer control authority. [extracted: 3-hellscape-blueprint.md, §3]

Task inputs exclude control credentials, hidden field identifiers, feature schedules, class maps, and expected failures; diagnostic target aliases remain internal unless deliberately exposed in labeled non-comparable debug sessions. [extracted: 3-hellscape-blueprint.md, §§3 and 5]

## 5. Storage decision: SQLite without a cross-owner writer bottleneck

### 5.1 Explicit resolution of the Decision 8 tension

**Chosen provisional design:** use an owner-local SQLite/WAL database, writer connection, bounded work queue, and artifact namespace for each independently writable domain, rather than one shared database/writer for all Hellscape records. [proposed: retain SQLite’s owner-local durability while removing its global writer lock from independent write paths; 2-state-bank-crawler-blueprint.json, Decision 8; 3-hellscape-blueprint.md, §9]

The minimum session decomposition is application, observation, and diagnostic ownership; separately bound lifecycle publication writers retain their own grants and cannot be merged merely because they run in the same binary. [inferred: decisions/invariants-and-provisionals.md, §4; contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES]

| Session domain | Owner-local mutable data | Publication behavior |
|---|---|---|
| Application | Fixture state, operation/idempotency records, authoritative journal, and replayable responses. | Publishes immutable origin/state evidence asynchronously after local durable commit. [proposed: map the fixture transaction to its application owner rather than the whole session database] |
| Observation | Admitted observations, connector/manual evidence, imports, completeness, and observation journal. | Publishes pinned evidence views and references to authoritative attempt-axis publications without becoming another writer of those axes. [proposed: preserve one observation authority and explicit imported evidence] |
| Diagnostic | Analysis requests, deterministic output artifacts, and diagnostic revision records. | Publishes complete diagnostic revisions; report reconciliation follows its separate report grant and never shares an application-effect transaction. [proposed: keep derivation independent of the truth and observation writers] |

This arrangement removes a shared SQLite write lock, but separate files, WAL mode, and separate goroutines do **not** by themselves establish Decision 8’s independently reserved I/O service or non-blocking publication requirement. [inferred: 2-state-bank-crawler-blueprint.json, §0 A2 and Decision 8; decisions/invariants-and-provisionals.md, §5]

A conforming deployment must provision independently serviced storage paths for the relevant owners and their artifacts, with bounded memory/admission and no shared synchronous writer, serializer, exchange queue, or checkpoint operation in another owner’s commit path. [proposed: enforce Decision 8 at the actual contention points instead of treating table separation as isolation]

For example, independently provisioned storage devices can supply the service separation while retaining one Go binary; shared-device developer deployments remain useful for functional tests but cannot claim the non-blocking storage gate without equivalent evidence. [proposed: provide a concrete deployment route without asserting that ordinary shared-disk SQLite is already sufficient]

### 5.2 Local atomicity and asynchronous composition

A fixture mutation acknowledges only after its input, idempotency record, authoritative state change, journal events, and replayable response commit together in the application owner’s durable transaction. [extracted: contracts/00-evidence-kernel.yaml, EK-ATOMICITY; 3-hellscape-blueprint.md, §9]

It does not synchronously append to an observation-owned journal or wait for a diagnostic, publication consumer, or session-wide transaction before acknowledging. [inferred: 1-handoff-brief.txt, Part VI; 2-state-bank-crawler-blueprint.json, Decision 8]

The other owners use their own durable commits and import source publications asynchronously, preserving original authority, digest, journal support, and missingness; there is no mandatory global journal writer on every effect path. [proposed: implement journal truth as owner-local durable evidence plus explicit imports rather than a cross-owner transaction service]

Before a diagnostic cites imported evidence, that evidence and its registration must be present in the diagnostic’s pinned input journal prefix; import order is not assumed to be event-occurrence order. [inferred: contracts/00-evidence-kernel.yaml, EK-JOURNAL and EK-DIAGNOSTIC; contracts/01-application-attempt-lifecycle.yaml, LIFE-EVIDENCE and LIFE-TIME]

Session readers install a complete old-or-new publication root, and a seal names the state and pins the application, observation, and diagnostic revisions actually included; a seal is not a barrier forcing every owner to reach a globally current revision. [inferred: 1-handoff-brief.txt, Part VI; decisions/invariants-and-provisionals.md, INV-25]

Artifact installation follows durable temporary write, digest verification, flush, and atomic installation before journal reference; retained publications and replay bundles protect their transitive artifact dependencies from garbage collection. [inferred: 3-hellscape-blueprint.md, §9; contracts/00-evidence-kernel.yaml, EK-ARTIFACTS; decisions/invariants-and-provisionals.md, INV-26]

### 5.3 Qualification, limits, and flip conditions

The storage qualification workload must pin its hardware, service reservations, admission envelope, baseline latency observations, and acceptance tolerances before testing; Stage1’s assumed reference commit latency is not a measured Hellscape SLA. [proposed: evaluate non-blocking behavior against declared deployment evidence rather than import an unvalidated sizing constant]

| Test | Required evidence |
|---|---|
| Hold an observation or diagnostic write transaction open. | Application commits continue without waiting on that owner’s SQLite lock, queue, or acknowledgement. [proposed: directly test independence of writer paths] |
| Saturate downstream artifact writes, diagnostic scans, and publication exchange within their admitted envelopes. | Application service remains within the declared independent-service tolerance, with bounded resource use and explicit downstream lag. [proposed: test I/O independence rather than just logical ownership] |
| Stall application storage instead. | Observation and diagnostic owners retain their own admitted work without entering a cross-owner transaction or fabricating an application acknowledgement. [proposed: test the reverse dependency and honest failure behavior] |
| Crash after an acknowledged application operation. | Recovery preserves its effects, journal, idempotency result, and response; replay does not execute the external request again. [extracted: contracts/00-evidence-kernel.yaml, EK-ATOMICITY; 3-hellscape-blueprint.md, §10] |
| Crash during publication or artifact installation. | Readers retain the prior complete root or receive the complete new root; missing bytes never become a valid citable publication. [inferred: 1-handoff-brief.txt, Part VI; contracts/00-evidence-kernel.yaml, EK-ARTIFACTS] |

If the selected deployment cannot demonstrate independent service, the storage gate remains incomplete: functional/manual validation may continue, but Hellscape does not claim conforming concurrent owner-separated storage or pass the peer-integration gate. [proposed: allow development without silently waiving Decision 8]

The choice flips to independently serviced persistence processes/services, or another demonstrated owner-local durable design, if SQLite deployment, resource sharing, checkpointing, or artifact I/O prevents the required independence or recovery behavior. [proposed: name measurable triggers for replacing the mechanism rather than weakening the invariant]

Such a flip would reopen the no-database-daemon/single-runtime packaging preference, not the one-writer, asynchronous-publication, or local-atomicity requirements; it must be recorded before shipping the changed deployment. [inferred: 1-handoff-brief.txt, Parts IV, VI, and VII; decisions/invariants-and-provisionals.md, P-06]

## 6. Evidence and diagnostic requirements

### 6.1 Evidence admitted before interpretation

Admission pins the task, seed, fixture/frontend builds, feature configuration, origin topology, environment, budgets, context policies, event registry, clocks, and analysis versions needed for reproducible interpretation. [extracted: 3-hellscape-blueprint.md, §§4 and 6; contracts/00-evidence-kernel.yaml, Manifest]

Provenance is assigned by authenticated ingestion, not accepted from a client’s asserted `server` label; storing a manual observation or native claim on the server never promotes its source authority. [extracted: contracts/00-evidence-kernel.yaml, EK-PROVENANCE; decisions/invariants-and-provisionals.md, INV-12]

Producer gaps, overflow, deduplication conflicts, unavailable native artifacts, and infrastructure incidents remain visible in completeness and validity records rather than disappearing through defaults. [inferred: 3-hellscape-blueprint.md, §§3–4 and 10]

Every null uses exactly one kernel reason—`not_enabled`, `not_applicable`, `not_observed`, `observation_lost`, `unsupported_by_subject`, or `manual_override`—with detail for domain-specific explanations. [extracted: contracts/00-evidence-kernel.yaml, EK-NULL]

### 6.2 Timing

Every measurement identifies its origin, clock, and boot, with duration represented as exact, bounded, or unavailable with reason and censoring; subtraction requires compatible monotonic endpoints and never crosses a clock or restart boundary. [extracted: contracts/00-evidence-kernel.yaml, EK-TIME]

M1 records at least session elapsed time, per-step ready-to-postcondition intervals, per-operation admission-to-commit intervals, and applicable connector-call intervals; a human pause belongs in workflow elapsed time, not in invented primitive execution time. [extracted: 3-hellscape-blueprint.md, §10, Clocks]

Native `_elapsed()` zero is retained as exact zero at the subject-reported origin beside independently measured intervals; it is neither missingness nor proof that Hellscape measured zero elapsed time. [extracted: 3-hellscape-blueprint.md, §§1 and 4; contracts/00-evidence-kernel.yaml, EK-TIMING-INTERPRETATION]

The validator must not divide total `/run` duration among steps, infer native timeout from a harness deadline, or subtract UTC annotations to manufacture cross-clock precision. [extracted: 3-hellscape-blueprint.md, §4; 5-browser-qualification.md, evidence discipline]

### 6.3 Diagnostic pipeline and shape

The diagnostic is a deterministic function of the immutable manifest, named journal prefix, and pinned classifier bundle; readable output is a rendering of that structured result rather than a separately authored narrative. [extracted: contracts/00-evidence-kernel.yaml, EK-DIAGNOSTIC; 3-hellscape-blueprint.md, §10]

| Stage | Required behavior |
|---|---|
| Validate inputs | Check manifest, source artifacts, producer completeness, scoped validity, and evidence limits before attributing failure. [extracted: 3-hellscape-blueprint.md, §4, Pipeline M1] |
| Join evidence | Relate observed actions, requests, validations, authoritative transitions, claims, and compatible timings without inventing causality. [extracted: 3-hellscape-blueprint.md, §4, Pipeline M1] |
| Evaluate steps | Determine postconditions, preserve rejected attempts and recovery, identify the first unmet contract, and mark downstream blockage explicitly. [extracted: 3-hellscape-blueprint.md, §4, Pipeline M1] |
| Compare claims | Compare only compatible scope and knowledge boundaries against source facts, retaining uncertainty and contradictions. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-RECONCILE] |
| Publish | Retain validity, capabilities, requirement assessments, observed actions, exposures, steps, measurements, claims, findings, observation/application summaries, and artifact references in the kernel diagnostic shape. [extracted: contracts/00-evidence-kernel.yaml, DiagnosticDocument] |

The legacy `hellscape.diagnostic/1` document supplies semantic content but is not a second competing wire contract; its broader assessment enums are normalized to the handoff-governed kernel rather than copied wholesale. [inferred: 1-handoff-brief.txt, Part VI; decisions/invariants-and-provisionals.md, §5]

Capability availability is `present | absent | unknown | not_applicable`, opportunity is `exposed | unexposed | blocked`, and assessment result is `satisfied | violated | native_absence | indeterminate | not_exercised`; no aggregate success value replaces those independent dimensions. [extracted: 1-handoff-brief.txt, Part VI]

Manual fixture validation has no automation subject and earns no subject requirement credit; R1–R10 remain unexercised even when the human completes every step. [extracted: 3-hellscape-blueprint.md, §§4 and 11; contracts/00-evidence-kernel.yaml, EK-MANUAL]

R1–R10 retain their separate concerns—interaction, isolation, truthful errors, cancellation, local application access, transport consistency, behavior, DOM access, local operation, and maintainability—with absence or uncertainty recorded rather than waived. [extracted: 3-hellscape-blueprint.md, §2]

For isolation, browser state, fixture state, and learning state remain separate, and failed write/read controls make the affected inference indeterminate rather than establishing leakage or isolation. [extracted: 3-hellscape-blueprint.md, §§1–3 and §7, M2]

M1 suggestions and fingerprint analysis are explicitly `not_enabled`; later recommendations require registry-supported findings, not a plausible causal guess. [inferred: 3-hellscape-blueprint.md, §§4 and 8; 1-handoff-brief.txt, Part VII]

## 7. Connector, closure, and attempt semantics

### 7.1 Shared surface, faithful mappings

Hellscape consumes the browser-agnostic asynchronous connector and does not introduce a common primitive driver for Circus Tent and Ringmaster. [extracted: 1-handoff-brief.txt, Parts V–VI]

| Connector operation | Hellscape obligation |
|---|---|
| `Describe` | Pin the exact subject/version/mode/interface descriptor and mapping evidence; assess it independently. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE and EXT-DECLARE-NOT-ASSESS] |
| `Prepare` | Validate supplied task, plan, grants, artifacts, limits, and mappings without target visits, login checks, context reset, or hidden planning. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE] |
| `Start` | Retain local handle and dispatch intent before native delivery; local acknowledgement is not native acceptance. [extracted: contracts/02-external-connector.yaml, EXT-START] |
| `Observe` | Retain bounded, journal-ordered evidence, raw native bodies, mapping versions, source checks, and conflicting responses. [extracted: contracts/02-external-connector.yaml, EXT-OBSERVE and EXT-NORMALIZE] |
| `RequestNativeCancel` | Distinguish mapped support, request, acknowledgement, claim, and observed effect. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `CloseObservationConnection` | Distinguish transport closure from ending observation and from stopping native execution. [extracted: contracts/02-external-connector.yaml, EXT-CLOSE] |
| `CollectArtifacts` | Return retained authorized evidence or explicit missingness without inventing native retrieval support. [extracted: contracts/02-external-connector.yaml, EXT-ARTIFACTS] |
| `ReleaseNativeContext` | Attempt only an evidenced authorized mapping and preserve failure or unsupported status. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `Contain` | Record separately authorized local containment and its actual scope without claiming native cancellation or rollback. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |

The initial Circus Tent documentary mapping uses explicit-step `/run`, `/extract`, terminal responses, and authenticated callbacks; it does not establish goal submission, native run querying, cancellation, fresh-context creation, release, revision retrieval, or artifact downloading. [extracted: 3-hellscape-blueprint.md, §5]

External planning is separately recorded assistance, including public inputs, planner identity, preparation cost, plan hash, and translation version; translation preserves supplied order, targets, values, and retry semantics rather than silently improving the plan. [extracted: 3-hellscape-blueprint.md, §5; contracts/02-external-connector.yaml, EXT-PREPARE]

Callback authentication, attempt correlation, and trace correlation are separate checks; authenticated but unresolved messages remain retained evidence, not claims assigned to a convenient session. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-SOURCE-CHECKS]

Historical cancellation failures and the repaired page-lifetime defect remain scoped historical evidence, not automatic capability findings for a new Circus Tent or Ringmaster version. [extracted: 3-hellscape-blueprint.md, §§1 and 4; contracts/00-evidence-kernel.yaml, EK-CAPABILITY]

### 7.2 Closure and late evidence

Every admitted session finalizes or recovers to an explicit interrupted/incomplete result under finite local observation, drain, cancellation-wait, and cleanup bounds, even if remote execution continues. [inferred: 3-hellscape-blueprint.md, §§5 and 10; contracts/02-external-connector.yaml, EXT-BOUNDS]

Ending observation stops new workflow commands, records available cancellation controls and any authorized attempts, closes the selected transport, drains within the manifest bound, and seals fixture mutation authority when configured. [extracted: 3-hellscape-blueprint.md, §5; contracts/01-application-attempt-lifecycle.yaml, LIFE-CLOSE]

Sealing fixture authority does not establish subject termination, context destruction, or native cancellation; unresolved resources are reported and, when authorized, quarantined through separately labeled containment. [extracted: 3-hellscape-blueprint.md, §§5 and 13]

After closure, late evidence is appended and produces new source publications and analysis revisions without reopening the original observation window or rewriting its knowledge snapshot. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LATE-EVIDENCE]

A close-time `outcome_unknown` claim is compatible with a later commitment; definite no-commitment assertions require comparison at their actual temporal scope, not merely against callback receipt order. [extracted: contracts/01-application-attempt-lifecycle.yaml, reconciliation algorithm]

On restart, unfinished work is marked infrastructure-interrupted and ambiguous dispatch remains uncertain; Hellscape never assumes the native subject stopped or automatically replays a side-effecting request under a new key. [extracted: 3-hellscape-blueprint.md, §10; contracts/02-external-connector.yaml, EXT-IDEMPOTENCY]

### 7.3 Practice boundary

Every Hellscape application attempt is immutable `practice`, targets a `laboratory_fixture`, and carries `held_in`; real job content, a production-like page, or a successful receipt cannot change those values. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE]

Rehearsal/performance links describe relationships without transferring credit, while `derived_from` remains same-kind and acyclic. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE]

Later experimental holdout sets inside the laboratory must be labeled as fixture-corpus holdouts separately from the contract’s employer-origin `held_out` partition; they do not make a Hellscape form origin-representative. [proposed: preserve the blueprint’s held-out experiment discipline without violating LIFE-LINEAGE]

## 8. Replay, acceptance, and silo delivery

### 8.1 Exact replay

Exact fixture replay consumes the pinned manifest, recorded inputs and lifecycle observations, and immutable artifacts; it recomputes derived events, authoritative final state, and diagnostic semantics without a browser, subject, external writes, or sleeping to reproduce recorded delays. [extracted: contracts/00-evidence-kernel.yaml, EK-REPLAY; 3-hellscape-blueprint.md, §10]

The receipt identifies the replay inputs and versions and records matched, mismatched, or unavailable comparisons rather than treating missing output as a match. [extracted: contracts/00-evidence-kernel.yaml, ReplayReceipt]

Live reproduction is a new attempt with its own observations and lineage, not exact replay or fresh proof of an old subject’s behavior. [extracted: 3-hellscape-blueprint.md, §6]

### 8.2 Manual acceptance procedure

The M1 validator uses a fixed manifest and synthetic task, then selects a job, enters contact information, submits an invalid history interval, observes rejection, corrects it, uploads the pinned document, completes synthetic verification, validates review, pauses for a measured interval, submits once, and reads the receipt. [extracted: 3-hellscape-blueprint.md, first-run procedure]

| Acceptance oracle | Required result |
|---|---|
| Validation and recovery | Invalid history remains a recorded rejection, later correction is accepted, and HISTORY is characterized as recovered rather than a framework failure. [extracted: 3-hellscape-blueprint.md, first-run expected results] |
| Timing | The pause appears in the appropriate elapsed interval; an independent stopwatch comparison uses tolerances documented before the walkthrough, with bounded/unavailable results where clocks are not comparable. [extracted: 3-hellscape-blueprint.md, first-run cross-checks] |
| Application truth | Exactly one commitment exists for the successful walkthrough, and committed values and document digest match the submitted synthetic inputs. [extracted: 3-hellscape-blueprint.md, first-run expected results] |
| Observation | Confirmation rendering is distinguishable from server commitment, and telemetry provenance cannot forge either authority. [extracted: 3-hellscape-blueprint.md, first-run expected results] |
| Subject absence | No fabricated native claims, automation identity, or R1–R10 credit appears. [extracted: 3-hellscape-blueprint.md, first-run expected results] |
| Durability and replay | Journal, authoritative state, referenced artifacts, structured/readable diagnostic, and replay receipt are retained, with matching replay semantics. [extracted: 3-hellscape-blueprint.md, M1 acceptance bundle] |

An uncompletable cooperative manual path is a fixture defect to repair, not newly discovered hostility or an excuse to relax acceptance. [extracted: 3-hellscape-blueprint.md, §11, first-run procedure]

### 8.3 Companion cases

| Case family | Minimum distinguishing behavior |
|---|---|
| Boundary behavior | Early stop, incomplete fields, repeat submit, close before telemetry flush, and restart after acknowledgement preserve state, missingness, and idempotency correctly. [extracted: 3-hellscape-blueprint.md, manual companion cases] |
| Native normalization | Success/failure responses, nullable/missing fields, malformed bodies, zero/unavailable durations, and conflicting callbacks remain faithfully represented. [extracted: 3-hellscape-blueprint.md, §10, Synthetic-backend tests] |
| Lifecycle control | Unsupported cancellation/release, close with continuing execution, late callback, and bounded finalization do not acquire false stop or rollback claims. [extracted: 3-hellscape-blueprint.md, §§5 and 10] |
| Authority attacks | Client commitment forgery, wrong attempt binding, application-cookie control access, and uncorrelated signed callbacks cannot mutate the wrong domain. [inferred: 3-hellscape-blueprint.md, §§3 and 5] |
| Storage and replay | Owner contention, partial publication, missing artifacts, crash recovery, tampered hashes, and semantic replay mismatch produce explicit failures or incompleteness. [inferred: contracts/00-evidence-kernel.yaml; §5 of this PRD] |

When raw historical m0 artifacts are unavailable, synthetic reproductions must be labeled synthetic rather than presented as imported historical transcripts. [extracted: decisions/invariants-and-provisionals.md, §8.3]

### 8.4 Build and shipping sequence

1. Implement schema validation, deterministic goldens, fixture reducer, and owner-local durability before connecting a live subject. [inferred: 3-hellscape-blueprint.md, §11; §5 of this PRD]
2. Build the ordinary SPA, manual observation/finalization path, diagnostic derivation, and replay. [extracted: 3-hellscape-blueprint.md, §11]
3. Exercise the connector against synthetic native backends and complete the manual acceptance bundle. [extracted: 3-hellscape-blueprint.md, §11]
4. Pass the kernel, lifecycle, external-connector, and applicable owner-separated conformance obligations before peer integration; registry schema validation is not registry deployment. [inferred: 1-handoff-brief.txt, Part VIII; decisions/invariants-and-provisionals.md, HA-04]
5. Admit a live subject at M2 and report what it does without requiring completion or replacing the manual production lane. [extracted: 3-hellscape-blueprint.md, §7; decisions/invariants-and-provisionals.md, HA-03]

Acceptance bundles retain the manifest, task, build receipt, journal/evidence, authoritative state, measurements, manual observations, structured/readable diagnostic, replay receipt, checks, and synthetic document. [extracted: 3-hellscape-blueprint.md, M1 acceptance bundle]

## 9. Later product evolution and learning

| Milestone | Added value | Boundary preserved |
|---|---|---|
| M2 — first live subject | Observe an identified executor against the cooperative fixture, including controlled isolation and closure cases. | A first-interaction failure is a valid diagnostic result; zero hostility supports no shadow/frame conclusion. [extracted: 3-hellscape-blueprint.md, §7] |
| M3 — hostility and diagnosis | Versioned feature packs, local hostile mechanisms, counterfactuals, minimization, and reviewed fix matching. | Fixture defects remain fixture defects; unsupported attribution yields uncertainty and reasoned missing suggestions. [extracted: 3-hellscape-blueprint.md, §7] |
| M4 — curriculum | Deterministic selection, per-subject lineages/frontiers, regressions, quotas, and fixture holdouts. | Active manifests remain fixed, learned state is explicit, and Circus Tent/Ringmaster histories are not one alternating chain. [inferred: 3-hellscape-blueprint.md, §7; 1-handoff-brief.txt, Part VII] |
| M5 — transport and detection | Honest TLS/HTTP2 observations, fingerprint profiles, transport faults, and scoped cohorts. | Missing capture remains incomplete; ordinary TLS operation is not retrospective fingerprint evidence. [extracted: 3-hellscape-blueprint.md, §7] |
| M6 — capacity, transfer, hardening | Soak/crash/resource testing, paired revisions, adapters, and evidence for declared transfer questions. | Engine throughput is not subject throughput or production application rate. [extracted: 3-hellscape-blueprint.md, §7] |

Feature packs declare dependencies, exclusions, human/degradation paths, exposure events, failure signatures, regression cases, and digests; they do not load arbitrary JavaScript, executables, or plugins. [extracted: 3-hellscape-blueprint.md, §6]

Configuration, rendering/arming, exposure, activation, and recovery remain separate observations, and an unexposed mechanism earns no success credit. [extracted: 3-hellscape-blueprint.md, §6]

The inner loop may autonomously propose fixture variants, while the outer loop proposes evidence-supported fix instances under human-approved rule classes; neither loop automatically patches an executor or authorizes employer submission. [extracted: 1-handoff-brief.txt, Part IX; decisions/invariants-and-provisionals.md, INV-29]

A fix instance must cite diagnostic findings, scope, required evidence, contraindications, and a falsifiable verification plan; implementation and new-version verification remain separate events from recommendation. [extracted: 1-handoff-brief.txt, Part VIII; decisions/invariants-and-provisionals.md, INV-29]

## 10. Measures, unresolved inputs, and change conditions

Hellscape reports attempted, eligible, completed, early-failure, and unexposed sessions separately, with subject/version, assistance, environment, browser-state, and learning-state context retained for comparisons. [extracted: 3-hellscape-blueprint.md, §§2 and 5]

The blueprint’s target of at least 100 eligible finalized sessions per hour belongs to later sustained-testing/capacity work, not M1’s manual correctness gate and not the portfolio’s production application count. [inferred: 3-hellscape-blueprint.md, §§2, 7, and 8]

| Open input | Reconnaissance or decision required |
|---|---|
| Storage service independence | Select actual owner-local storage paths and admission envelopes, then run §5’s contention, lag, and recovery tests before claiming Decision 8 compliance. [uncertain: deployed storage isolation and latency evidence are not supplied] |
| Current native interfaces | Pin each subject’s build/configuration and inspect actual mappings; historical REST documentation does not certify current cancellation, context, revision, or artifact capabilities. [uncertain: current Circus Tent and Ringmaster mapping evidence is not supplied] |
| Historical raw evidence | Obtain the named cancellation/isolation/timing artifacts before claiming faithful historical import; use labeled synthetic cases meanwhile. [uncertain: raw historical bundles are absent from the supplied sources] |
| Timing tolerances | Establish the chosen clocks’ resolution and the independent manual comparison method before acceptance; do not invent a tolerance after observing disagreement. [uncertain: deployment-specific timing calibration is not supplied] |
| Later fingerprint capture | Validate capture completeness, privacy, and versioned interpretation at M5; keep M1 analysis disabled. [uncertain: production-grade capture implementation and current validation evidence are not supplied] |
| Recommendation support | Obtain the exact diagnostic and approved registry inputs for each proposed fix; no supported match means no recommendation. [inferred: 1-handoff-brief.txt, Parts VI and VIII; decisions/invariants-and-provisionals.md, INV-29] |

Hellscape ships first as a trustworthy observer of a small fixture, grows only through separately evidenced capabilities, and remains subordinate to the portfolio’s real application work throughout that growth. [inferred: 3-hellscape-blueprint.md, §15; current request, Purpose]
