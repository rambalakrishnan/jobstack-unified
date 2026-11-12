# Hellscape — Lossless Technical Feature Inventory

**Source Blueprint:** `/home/whipsthellamasass/workspace/unification/tree/full-featured-blueprints/3-hellscape-blueprint.md`
**Product:** Framework-agnostic browser fixture and diagnostic engine (`Go` single deployable engine + `Vite` / strict `TypeScript` / vanilla `Web Components` SPA + `SQLite/WAL` durable structured evidence + content-addressed artifact directory).

---

## 0. Foundational Architecture, Requirements, and Contracts

### 0.1 Product & Milestone Foundation
- **Status:** Replacement design, ready for M1 implementation. Does not claim M1 has been built or additional trials have been run.
- **Milestone Sequence:** Starts at **M1**. M0's findings remain evidence inputs; M0's preflight milestone and proceed/stop gate are retired.
- **M1 Primary Acceptance Criterion:**
  > **The diagnostic engine correctly characterizes a manual walkthrough of the cooperative SPA: steps succeed or fail as reported, durations reflect measured elapsed wall-clock time, and authoritative server state agrees with what the walkthrough produced.**
  >
  > No automation subject participates in this acceptance test. M1 nevertheless ships the subject-agnostic connector, including its lifecycle implementation and the initial circus-tent REST binding. M2 is its first live subject use.

### 0.2 Cooperative Configuration Invariants (§1.1)
A cooperative configuration has no deliberately obstructive treatments:
- ordinary, visibly labeled controls;
- stable layout and semantic identities;
- no shadow-root or frame traversal challenge (M1 controls render in light DOM; Web Components do not imply shadow DOM in cooperative configuration);
- no class churn, decoys, delayed hydration, or network-idle trap;
- no injected transport failures;
- no production challenge services;
- no artificial timing races.
Normal application behavior remains: validation, file upload, state transitions, identity confirmation, and submission guards.

### 0.3 Explicit Exclusions (§1.2, §8.2)
Hellscape does not:
- repair or replace the framework under test;
- supply an undisclosed planner to make an executor appear autonomous;
- infer private selectors, internal reasoning, or exhausted recovery tiers from silence;
- promise production bot-detection resistance;
- submit real applications or require real identities;
- solve production CAPTCHAs or use paid solving services;
- automatically modify subject source code;
- guarantee that every framework can be stopped through its native interface;
- treat process termination as transaction rollback;
- build a browser engine or adopt the substrate memo's proposed fork as its own dependency.

Explicitly excluded from M1 (§8.2):
- hostile composition runtime beyond a versioned cooperative manifest;
- shadow/frame challenges;
- injected network or timing hostility;
- full causal minimization;
- adaptive curriculum;
- behavioral detection scores;
- JA4/HTTP2 fingerprint analysis;
- production-quality transport fault injection;
- multiple live subject integrations;
- any requirement that circus-tent complete the application.
Disabled analyses have explicit `not_enabled` status. Missing fingerprint data is not emitted as a zero score.

### 0.4 Historical Evidence Carried Forward (§1.3)
| Evidence | Finding carried forward | Consequence for Hellscape |
|---|---|---|
| M0 documented-interface audit | circus-tent `/run` consumes explicit steps, not a goal-shaped task. | Planning ownership and assistance must be recorded separately from execution. |
| `FINDINGS-v2.md`, orchestration diagnosis and verification | The per-step page-lifetime defect was repaired in the tested deployment; the reported navigation/fill/click/assert check then completed. | There is a legitimate execution binding. This does not certify the full SPA workflow or a future deployment. |
| Substrate survey, together with the circus-tent audit | No local framework in the surveyed class supplies the required native bounded-cancellation contract; circus-tent is not an exception. | Native capability absence is a first-class finding. Close behavior remains independently testable. |
| `cancellation-fixed.jsonl` | Both candidate cancel routes returned 404. Client disconnect did not stop the tested run; a later side effect and authenticated terminal callback were observed. | Connection closure, execution termination, application commitment, and reporting must be separate facts. |
| `FINDINGS-v2.md` | `_elapsed()` returns zero in the diagnosed circus-tent implementation. | Native duration reports are retained as claims, not used as Hellscape’s clock. |
| `isolation-fixed.jsonl` | A cross-session marker signal was observed, but the write control was invalid. | **Non-isolation is not established by this experiment.** Preserve the signal and the invalid control; do not publish a confirmed leak finding. |
| Corrected-quota capacity runs | Five eligible samples per hold level; tested concurrency reached three without pressure. | These are bounded microtask observations, not full-workflow capacity or a measured maximum. |
| Rate-limiter diagnosis | Earlier blanket 429s arose from configuration and diagnosed charging/bucket defects. Raising the sandbox quota was a mitigation, not repair of both code defects. | Admission failures must not be mistaken for browser capacity or SPA difficulty. |
| Inventory and callback records | Nullable/missing response fields differ from documentation; authenticated callbacks were observed with trace-correlation mismatches. MCP initialization encountered a redirect and remained inconclusive. | Preserve raw response shape, mapping version, callback authentication, and correlation quality separately. |
| Revision/artifact audit | No native revision or artifact-retrieval contract was established on the audited surface. | Operator-attested identity and explicit artifact missingness are supported. |

### 0.5 Subject-Facing Requirements: R1–R10 (§2.1)
| ID | Subject requirement retained | What Hellscape measures and reports |
|---|---|---|
| **R1 — Rendering and interaction** | Render and operate the application correctly, including the browser structures relevant to the task. | Rendering/readiness observations, reachable controls, effects of actions, data correctness, and exposed structural boundaries. A missing field interaction alone does not establish a particular internal locator defect. |
| **R2 — Durable, isolated session/authentication state** | Preserve state where requested and isolate it across the declared boundaries. | **The harness measures whether the subject isolates session state, and reports non-isolation as a finding.** Cookie, local-storage, IndexedDB, profile, restart, and learning-state results remain separate facets. A failed write control makes the affected isolation conclusion indeterminate. |
| **R3 — Truthful errors and results** | Report action failures, uncertainty, and timing truthfully at the scope actually claimed. | Primitive claims, task claims, native errors, reported durations, independently measured intervals, and contradictions with authoritative postconditions. Adapter overclaims are harness errors, not subject dishonesty. |
| **R4 — Bounded cancellation** | Support bounded cancellation and preserve honest uncertainty around possibly committed work. | **The harness measures whether the subject supports bounded cancellation and, where it does not, whether the subject honestly reports outcome-unknown on connection close.** Native absence, behavior after close, close-time reporting, later reconciliation, and resource cleanup are separate results. |
| **R5 — Application-layer access** | Reach and use the relevant application surfaces, including declared local gates and recovery paths. | Access to the local application, progress through gates, recovery, and authoritative transaction results. Local results do not establish acceptance by Workday, a federal portal, or a commercial defense. |
| **R6 — Transport consistency** | Present transport and browser claims that are internally consistent for the declared environment. | Directly captured TLS/HTTP2 characteristics, browser declarations, capture validity, and matched-reference differences. Native browser transport is not deficient merely because it cannot impersonate arbitrary fingerprints. |
| **R7 — Behavioral interaction** | Produce the required interaction semantics and handle timing/readiness correctly. | Input sequences, targeting, readiness, retries, modality, and—when enabled—named behavioral-policy signals. Fast typing or absent mouse motion alone is not a failure. |
| **R8 — DOM/HTML access** | Provide the observation access required by the selected mode and task. | Native observation capability, extraction coverage/fidelity, frame/root coverage, and explicit unsupported access. A vision-only subject can complete a visual task without thereby demonstrating native DOM access. |
| **R9 — Local operation** | Operate in the declared local configuration without mandatory remote control, cloud-browser, or paid-solver dependencies. | Deployment declarations, configured endpoints, and available operator egress evidence. A missing local mode is a capability finding; traffic visible only to the fixture cannot prove absence of all external calls. |
| **R10 — Operator maintainability** | Remain identifiable, configurable, inspectable, and replaceable within the operator’s maintenance boundary. | Revision/configuration provenance, documented interfaces, artifact availability, patch ownership, and longitudinal operational evidence. One browser session cannot prove long-term maintainability. |

Multi-facet evaluation example for R4:
- `native_cancel: native_absence`;
- `behavior_after_close: continued_execution_observed`;
- `native_close_report: indeterminate`;
- `connector_close_report: satisfied`;
- `final_application_state: committed`.
**Absence is not a waiver.** If a required native capability is absent, the requirement gap remains visible even if external containment makes the experiment safe.

### 0.6 Hellscape Product Obligations: H1–H10 (§2.2)
| ID | Product obligation |
|---|---|
| **H1 — Adaptive selection** | Select future experiments from versioned, finalized evidence and recorded operator decisions. |
| **H2 — Sustained testing** | Support repeated and eventually concurrent sessions; retain the target of at least 100 eligible finalized sessions/hour under a published workload and hardware profile. (Separately publish attempted sessions, eligible finalized sessions, application completions, early failures, and unexposed tasks. Immediate launch-failure loops do not satisfy the target.) |
| **H3 — Bounded escalation** | Use measurable feature domains, solvability constraints, exposure receipts, and explicit graceful-degradation tasks. |
| **H4 — Diagnostic output** | Produce a diagnostic for every durably admitted session, including launch failures and interrupted sessions, subject to explicit storage-failure limitations. |
| **H5 — Evidence-backed recommendations** | Emit reviewed recommendations only when evidence supports them; otherwise emit null with a reason. |
| **H6 — Reproducibility** | Reproduce fixture semantics from the same manifest and ordered input journal. Do not promise identical live browser behavior from a seed alone. |
| **H7 — Ordinary browser interface** | Require no fixture-specific subject plugin. The application uses ordinary browser protocols and controls. |
| **H8 — Independent human usability** | Provide a normal human completion path, or a deliberately declared degradation objective, for every admitted composition. |
| **H9 — Single deployable engine** | Embed the SPA, application server, journal, diagnostics, and experiment services in one Go binary. Browsers and subjects remain external. |
| **H10 — Framework-agnostic integration** | Bind different execution modes through an explicit connector contract without confusing harness assistance with native subject capability. |

### 0.7 Architectural Boundaries, Planes, and State Separation (§3.2–§3.4, §8.3)
**Six Strict Separation Boundaries (§3.2):**
1. **Application truth:** The server reducer owns accepted data, workflow transitions, validation generations, identity receipts, and submission commitment.
2. **Observation:** DOM events, request evidence, transport facts, manual notes, and native results are observations with provenance. They cannot manufacture application truth.
3. **Execution:** The connector sends supported commands and observes responses. It does not decide whether the application succeeded.
4. **Judgment:** The diagnostic engine evaluates contracts against evidence. It does not alter the run to obtain a better result.
5. **Policy:** The curriculum chooses future sessions. It never silently changes the active session.
6. **Containment:** Hellscape bounds its own waiting, fixture effects, and resource exposure. Such containment is not relabeled as subject-native cancellation or isolation.

**Three Logical Surfaces (§3.3):**
1. **Application plane:** SPA assets and ordinary application APIs.
2. **Write-only telemetry plane:** Bounded ingestion from fixture-owned producers.
   - Accepts only client-emittable event types;
   - Assigns provenance at ingestion;
   - Deduplicates producer sequence numbers;
   - Records gaps and overflow;
   - Cannot emit `submission_committed` or server verification success;
   - Uses scoped, write-only capabilities.
3. **Control plane:** Manifests, session administration, diagnostics, evidence, and replay. Separately authenticated; not authorized by application cookies. CORS is not authentication. Subject-facing entry credentials never grant control access.
- Canonical diagnostic target aliases live in internal registries (not universal scored-mode DOM selectors; debug aliases permitted only in labeled, non-comparable debug sessions).
- Later closed-root instrumentation is installed inside the component while the fixture owns its root reference; outside `composedPath()` inspection is not treated as a way to recover closed-root internals.

**Three State Domains (§3.4):**
1. **Fixture application state:** Scoped via explicit attempt binding (not a mutable global "current session" cookie).
2. **Browser state:** Cookies, local storage, IndexedDB, profile contents. (R2 experiments deliberately use the same relevant origin and storage keys for A and B while keeping server-side application records independently bound.)
3. **Framework learning state:** Selector caches, demonstrations, memory, recovery history.

**Suggested Module Structure (§8.3):**
```text
cmd/hellscape/
internal/
  manifest/       # schemas, canonicalization, task compilation
  application/    # reducer, guards, authoritative predicates
  session/        # admission, clocks, lifecycle, finalization
  journal/        # durable append and transaction boundary
  artifacts/      # content-addressed storage
  observation/    # event ingestion, provenance, completeness
  diagnostic/     # assessment, findings, JSON and readable rendering
  connector/
    contract/
    lifecycle/
    circustent/   # REST translation; no invented native operations
  replay/
  control/
web/
  src/
    routes/
    components/
    application-client/
    telemetry/
schemas/
migrations/
testdata/
  tasks/
  documents/
  synthetic-native-responses/
  diagnostic-goldens/
```

### 0.8 Connector and Execution Contract (§5, §10.6)
**Subject Descriptor Fields (§5.1):**
- planning ownership;
- observation channels;
- action grounding;
- browser or non-browser execution substrate;
- browser-state and learning-state policy;
- control boundary;
- recovery ownership;
- deployment, model, and browser identities.

**Internal Connector Interface (§5.2):**
| Operation | Contract |
|---|---|
| `Describe` | Return versioned capabilities, native mappings, and evidence provenance. Unknown remains unknown. |
| `Prepare` | Validate task eligibility and translation; record assistance and request hashes. No hidden browsing or recovery. |
| `Start` | Durably allocate a connector-local handle, then dispatch asynchronously. |
| `Observe` | Return accumulated native responses, callbacks, artifacts, and local transport observations. |
| `RequestNativeCancel` | Return unsupported, requested, confirmed stopped, or unknown, with evidence. |
| `CloseObservationConnection` | Close the connector-owned transport and record the action. Make no cancellation claim. |
| `CollectArtifacts` | Return available artifacts and explicit missingness. |
| `ReleaseNativeContext` | Use a supported native operation or report unsupported. |
| `Contain` | Apply an explicitly authorized harness policy, separately labeled from native behavior. |

**Initial circus-tent REST Binding (§5.3):**
- Uses audited surface:
  - `/run` for explicit execution plans;
  - `/extract` for eligible extraction tasks;
  - `/health` and `/shards` for optional operational observations;
  - terminal responses and authenticated callbacks for native results.
- Does **not** invent:
  - goal submission;
  - `GET /runs/{id}`;
  - native cancellation;
  - fresh-context creation;
  - context release;
  - revision or artifact-download endpoints.
- Local handle allocated before making the blocking-shaped `/run` request; native run ID attached only when actually received.
- Response translation supports observed nullable fields and retains the original body as a restricted artifact.
- Callback handling:
  - authenticates raw body where signing contract and key are configured;
  - correlates callback to the attempt;
  - deduplicates delivery without discarding conflicting messages;
  - records trace-correlation failure separately from signature validity;
  - never substitutes a missing trace ID for the actual execution outcome.

**Task Envelope & Planning Assistance (§5.4):**
- Task envelope contains: entry URL; goal and user-understandable success criteria; synthetic data and document references; permitted origins and interfaces; wall-time, action, observation, recovery, and model budgets; requested browser and learning-state policy.
- Task envelope excludes: control credentials, hidden field identities, feature schedules, private class maps, and expected failures.
- Step executor consumes a separately recorded canonical plan derived from the public application, not fixture internals.
- Assistance record includes: planner identity, public observation inputs, preparation cost, plan hash, translation version, and any permitted online replanning.
- Translation preserves action order, semantic targets, values, and retry policy without adding framework-specific sleeps, selector alternatives, or recovery actions. Incomplete mapping yields a connector limitation or `UNSUPPORTED_MAPPING`.

**Bounded Observation Closure Protocol (§5.5):**
At observation closure, Hellscape:
1. stops issuing new commands;
2. records whether native cancellation was available and attempted;
3. records any connector transport close;
4. retains a bounded effect-observation and evidence-drain window;
5. seals the application’s mutation authority according to the manifest;
6. finalizes with execution state unknown unless stronger evidence exists.
Late callbacks or observed requests are appended as late evidence and produce a new analysis revision over a new journal prefix (never rewriting an already published diagnostic silently).

**M1 Connector Implementation & Synthetic Backend Tests (§10.6):**
- Includes: durable local handles; bounded worker and connection ownership; request serialization and response normalization; capability snapshots; assistance and plan hashes; authenticated callback ingestion; transport-close handling; artifact missingness; timeout finalization; typed unsupported-operation responses.
- Crash recovery around dispatch: Before external dispatch, the engine records the intended request and marks dispatch beginning. If the engine crashes around delivery, the attempt is recovered as dispatch-uncertain. It is not automatically retried with a new idempotency key.
- Local synthetic backend test coverage:
  - terminal success and failure;
  - nullable native fields;
  - malformed results;
  - native capability absence;
  - connection close with later callback;
  - conflicting response/callback claims;
  - unavailable native step timing;
  - explicit zero reported timing;
  - unsupported context release;
  - bounded local finalization despite continuing remote work.

---

## 1. THE 8-STATE WORKFLOW & AUTHENTIC CHECKS (§6.1, §9.1, §9.2, §9.3)

### 1.1 The 8-State Workflow Sequence (§6.1)
**`LISTING → DETAIL → CONTACT → HISTORY → UPLOAD → IDENTITY → REVIEW → CONFIRMATION`**

State names describe authoritative server milestones, not necessarily separate routes. Specifically, the contact form remains on the detail view; `CONTACT` is the accepted-contact milestone, not an unnecessary separate page. The identity control is a clearly labeled synthetic local action and does not claim to perform real identity verification.

### 1.2 Visible Workflow States, Ordinary User Actions, and Authoritative Server Effects (§9.1)
| Current state | Ordinary user action | Authoritative effect and next state |
|---|---|---|
| **LISTING** | Choose the specified synthetic job. | Store selected job; enter DETAIL. |
| **DETAIL** | Enter and validate contact information. | Store accepted contact revision; enter CONTACT. |
| **CONTACT** | Continue to work history. | Enter HISTORY. |
| **HISTORY** | Enter and save valid history. | Store accepted history revision; enter UPLOAD. |
| **UPLOAD** | Select the supplied synthetic document using a visible file input. | Store content hash and metadata; enter IDENTITY. |
| **IDENTITY** | Activate the inline local verification control. | Verify a session-bound local receipt; enter REVIEW. |
| **REVIEW** | Inspect accepted data and submit. | Revalidate required revisions; commit one application; enter CONFIRMATION. |
| **CONFIRMATION** | Read the receipt. | Record confirmation rendering; no additional submission effect. |

### 1.3 Core Workflow Invariants (§6.1)
These invariants are fixture correctness (not hostile features):
- Validation is bound to section, value revision, and generation.
- Stale validation cannot authorize current progress.
- Entering a section does not imply its data is already complete.
- Identity receipt possession and server verification are distinct.
- Submission requires authoritative stored data.
- A submission is committed at most once per application attempt.
- Telemetry cannot mutate business state.
- Confirmation rendering is recorded separately from commitment.

### 1.4 Authoritative Business-State Rules & Server Checkpoints (§9.3)
Each accepted section has a **value revision** and **validation generation**. Edits invalidate dependent acceptance according to explicit dependency rules.

Required authoritative server checks include:
1. **Selected job check:** Selected job exists.
2. **Contact & History currency check:** Accepted contact and history are current (bound to current value revision and validation generation).
3. **Upload artifact integrity check:** Upload exists and its digest matches the stored artifact.
4. **Identity receipt binding check:** Identity receipt belongs to the attempt and relevant epoch.
5. **Review currency check:** Review refers to current accepted data.
6. **Single-commit guard:** Submission has not already committed.

**Negative Path & Idempotency Rules:**
- An invalid history interval (for example, an end date before its start date) returns a validation rejection and leaves the workflow in `HISTORY`. It must not advance to `UPLOAD`.
- Submission is idempotent: repeating the same valid submission operation returns the same receipt.
- Reusing an operation key with different content returns a conflict.

### 1.5 Baseline Cooperative Frontend Behavior (§9.2)
M1 uses:
- native inputs and buttons with visible labels;
- standard keyboard navigation and focus;
- stable, ordinary form semantics;
- visible validation messages;
- explicit save/continue actions;
- normal asynchronous requests with progress indication;
- no artificial delay;
- no perpetual polling;
- no hidden required controls;
- no framework-specific selector hints.
- **Readiness Contract:** The SPA records readiness after the relevant controls are rendered and enabled. Network silence is not its readiness contract.
- **Autosave:** The baseline does not require autosave. Later autosave and WebSocket treatments can be introduced without changing the business reducer’s authority.

---

## 2. APPLICATION REST API CONTRACT (§9.4, §11.1)

### 2.1 Scoping & Mounting
The application API is mounted within an **opaque attempt binding** (`…/api/…`), so a shared browser context cannot redirect writes through a global active-session variable. These are Hellscape endpoints, not circus-tent endpoints.

### 2.2 Complete Application REST Endpoints Table (§9.4)
| Operation | Purpose | Expected Payload Fields, Generation/Revision Headers, & Idempotency Rules |
|---|---|---|
| `GET …/api/jobs` and `GET …/api/jobs/{id}` | Public synthetic job information. | Read-only retrieval of synthetic job listing and specific job detail by `{id}` within the opaque attempt binding. |
| `POST …/api/job-selection` | Select the task’s job. | Mutation request carrying: selected synthetic job identifier, operation identity (`idempotency_key`), and expected state revision. Transitions authoritative state from `LISTING` to `DETAIL`. |
| `GET …/api/draft` | Recover the ordinary user-visible accepted draft. | Read-only retrieval of current authoritative accepted sections, value revisions, validation generations, and workflow state. |
| `PUT …/api/contact` | Validate and accept contact data. | Mutation request carrying: contact fields payload, operation identity (`idempotency_key`), expected value revision, and validation generation. Stores accepted contact revision and advances authoritative state from `DETAIL` to `CONTACT` (or returns structured validation/conflict results). |
| `POST …/api/history/enter` | Advance from accepted contact to history. | Mutation request carrying: operation identity (`idempotency_key`), expected state revision, and current accepted contact revision/generation reference. Verifies contact acceptance is current and transitions authoritative state from `CONTACT` to `HISTORY`. |
| `PUT …/api/history` | Validate and accept history data. | Mutation request carrying: work history fields payload (including date intervals), operation identity (`idempotency_key`), expected value revision, and validation generation. On valid data: stores accepted history revision and advances authoritative state from `HISTORY` to `UPLOAD`. On invalid data (e.g., end date before start date): returns structured validation rejection and leaves workflow in `HISTORY`. |
| `POST …/api/upload` | Accept a bounded synthetic document. | Mutation request carrying: bounded synthetic document payload/metadata, operation identity (`idempotency_key`), and expected state/value revision. Enforces manifest-pinned size/type policy, writes to temporary file, hashes, flushes, and atomically installs under the content-addressed artifact root before transaction commit; never executes uploaded content. Stores content hash and metadata; advances authoritative state from `UPLOAD` to `IDENTITY`. |
| `POST …/api/identity/verify` | Issue and verify local session-bound identity evidence. | Mutation request carrying: inline local verification action payload/receipt token, operation identity (`idempotency_key`),attempt/epoch binding, and expected state revision. Verifies session-bound and epoch-bound local receipt; advances authoritative state from `IDENTITY` to `REVIEW`. |
| `POST …/api/review/validate` | Validate current review prerequisites. | Mutation request carrying: operation identity (`idempotency_key`), expected state revision, and references to current accepted revisions/generations for job selection, contact, history, upload artifact digest, and verified identity receipt. Validates all prerequisites are current and uninvalidated by edits. |
| `POST …/api/submit` | Commit the application idempotently. | Mutation request carrying: operation identity (`idempotency_key`), expected state revision, and expected value/validation generation references across all required sections. Revalidates required revisions (`selected job exists`, `accepted contact and history are current`, `upload exists and digest matches stored artifact`, `identity receipt belongs to attempt and relevant epoch`, `review refers to current accepted data`, `submission has not already committed`). Commits at most one application per attempt and transitions to `CONFIRMATION`. Repeating the same valid operation key + request digest returns the same committed receipt; reusing an operation key with different request content returns a conflict. |
| `GET …/api/confirmation` | Return the ordinary confirmation receipt. | Read-only retrieval of the committed confirmation receipt. Allows the SPA to render confirmation (confirmation rendering is recorded separately from submission commitment). |

### 2.3 Mutation Semantics, Generation/Revision Tracking, and Idempotency Rules (§9.3, §9.4, §10.1)
1. **Operation Identity & Idempotency Key:** Every mutation request (`POST`, `PUT`) carries an explicit operation identity (`idempotency_key`) and a computed `request_digest` persisted in the `operations` table.
2. **Expected Value/State Revision & Validation Generation:**
   - Every mutation request carries expected state revision, section value revision, and validation generation headers/fields.
   - Validation is strictly bound to `(section, value_revision, validation_generation)`.
   - Stale validation cannot authorize current progress; edits to earlier sections invalidate dependent acceptance according to explicit dependency rules.
3. **Structured Server Responses:**
   - The server returns structured validation rejection or revision/idempotency conflict results.
   - The frontend does not infer success merely from an HTTP connection completing.
4. **Idempotent Replay vs. Conflict:**
   - Repeating a mutation with the same `idempotency_key` and matching `request_digest` returns the persisted `committed_response` from the `operations` table without duplicating state transitions or business events.
   - Reusing an `idempotency_key` with a different `request_digest` (different content) returns an explicit conflict response.
5. **Upload Security & Storage Policy:**
   - Enforces manifest-pinned size and MIME/type policy.
   - Stores only under the content-addressed artifact root.
   - Never executes uploaded content.
   - Written to a temporary file, hashed, flushed, and atomically installed before the SQLite transaction references it.

### 2.4 Operator Control Surface Operations (§11.1)
Separate from the application API, M1 provides CLI or authenticated control-plane operations (using idempotency keys on control mutations; never authorized by application cookies):
- creating a manual or connector session (manifests become immutable at admission);
- retrieving its task and entry URL;
- starting connector dispatch;
- adding authenticated manual observation notes (can record "operator observed receipt X" or mark an interval, but **cannot** set an authoritative business predicate to passed);
- ending observation;
- requesting native cancellation or connection closure as distinct operations;
- reading events, application state, and diagnostics;
- exporting and replaying a bundle.

---

## 3. THE HOSTILE FEATURE CATALOG & COMPOSITION CONTRACT (§6.2, §6.3, §6.4)

### 3.1 Declarative Feature-Pack Composition Contract (§6.2)
Hellscape uses a prebuilt SPA shell plus declarative, versioned composition manifests.
A feature pack contains:
- typed parameter domains;
- dependencies and exclusions;
- registered primitive recipes;
- human-completion or degradation contract;
- exposure and activation events;
- expected failure signatures;
- regression cases;
- asset and schema digests.

**Execution & Security Constraints:**
- Manifests contain parameters and registered recipes, **not** arbitrary executable JavaScript.
- New browser primitives require reviewed frontend code.
- No runtime `eval`, downloaded executable feature code, or native plugin loading is part of the core.

**5-Stage Feature Exposure Lifecycle:**
**`configured → rendered/armed → exposed → activated → recovered or unresolved`**
- Enabled-but-unexposed features receive no success or failure credit.
- Tracked per instance in `Diagnostic.feature_exposures`:
  - `instance_id: string`
  - `configured: boolean`
  - `rendered_or_armed: boolean`
  - `exposed: boolean`
  - `activated: boolean`
  - `recovery_observed: boolean | null`
  - `evidence_refs: [EvidenceRef]`

### 3.2 Complete Hostile Feature Catalog (§6.3)
*(Note: The blueprint organizes the retained hostile mechanisms into 12 named table rows in §6.3, plus specific delay/challenge/applicability sub-contracts covering all 14 functional challenge areas requested: structural shadow roots, structural iframes, dynamic classes/node replacement/hydration, semantics/layout, native interaction/DnD upload, validation races, network traps/faults, transport disruptions, extraction/instruction decoys, honeypots/behavioral detection, fingerprint policy, challenge lifecycle, and external/simulated challenge widgets.)*

| Family | Retained Mechanisms (Exact Identifiers) | Parameters, Variants, Principal Bounds, and Evidentiary Rules |
|---|---|---|
| **1. Structural traversal — Shadow DOM** | `shadow_dom`, `nested_shadow_dom`, `closed_shadow_root` | Open-root coverage varies from none to all selected controls. Nested shadow DOM depth is bounded. `closed_shadow_root` tasks retain a visible human completion path. Closed-root instrumentation is installed inside the component while the fixture owns its root reference; outside `composedPath()` inspection is not treated as a way to recover closed-root internals. |
| **2. Structural traversal — Iframes** | `same_origin_iframe`, `cross_origin_iframe` | Wraps selected sections or controls across same-origin or cross-origin frame boundaries (`frame_alias` tracked in `observed_actions`). Tests frame/root coverage and cross-origin observation/interaction boundaries under R1 and R8. |
| **3. DOM identity and rendering** | `dynamic_classes`, `node_replacement`, `async_routes`, `hydration_skeleton`, `content_visibility`, `virtualized_lists`, `asset_revision_skew` | Render generations (`render_generation: integer | null`) and readiness receipts distinguish stale handles from missing observation. Applicability depends on configured subject mode: `dynamic_classes` (class churn) does not test a coordinate-only action path unless another consumed channel depends on those classes. |
| **4. Semantics and layout** | `inconsistent_labels`, `icon_buttons`, `rtl_section`, `semantic_decoys`, `moving_fields`, `inert_sections`, `conditional_fields`, `repeater_reindex` | Challenges semantic targeting, layout shifts, directional layout (`rtl_section`), decoy controls, dynamic form repeaters, and conditional visibility. Inaccessible variants are explicitly labeled and excluded from inappropriate accessibility judgments. |
| **5. Native interaction (including Drag-and-Drop Upload)** | `dnd_upload`, `upload_hidden_fallback`, `custom_controls`, `input_masks`, `interaction_overlays`, `before_unload_guard` | `upload_hidden_fallback` is an affordance parameter, not automatically increasing hostility. Tests drag-and-drop file transfer (`dnd_upload`), masked input entry, custom widget state, overlay dismissal/avoidance, and navigation guard handling. |
| **6. Validation and state races** | `async_validation`, `validation_races`, `session_token_gate`, `reload_recovery`, `session_expiry`, `idp_verification` | Extra delay/race treatments are explicitly distinct from baseline validation correctness (section/value-revision/validation-generation binding). Tests out-of-order validation resolution, token gates, mid-session reload state recovery, token/session expiration recovery, and local IdP verification flows. |
| **7. Application network behavior (Network Traps & Faults)** | `network_idle_trap`, `network_faults`, `slow_endpoints`, `redirect_on_submit`, `websocket_state`, `submit_ambiguity` | Faults have bounded recovery budgets. Committed submissions are **never** duplicated to make retry behavior appear realistic. `network_idle_trap` defeats readiness strategies that wait for network silence instead of control readiness. `submit_ambiguity` tests reconciliation when commit response delivery is uncertain. |
| **8. Transport disruption** | `connection_faults`, `websocket_faults` | Must record `matched`, `scheduled`, `fired`, and `observed` effects separately. WebSocket application-message reorder is explicitly distinguished from TCP-byte reorder. Even vision-based subjects are exposed to the network connection they use. |
| **9. Extraction and task relevance** | `extraction_ambiguity`, `instruction_decoys` | Hidden stale facts, visible ambiguity, and untrusted instructions are distinct treatments. All destinations and data remain strictly local. |
| **10. Interaction-policy observation (Honeypots & Behavioral)** | `honeypots`, `dom_fingerprint`, `behavioral_detection` | Structural mutations and behavioral anomalies are recorded as evidence, **not** automatic proof of maliciousness or general bot detection. Fast typing or absent mouse motion alone is not a failure unless named behavioral-policy signals are enabled. |
| **11. Fingerprint policy** | `fingerprint_consistency`, `fingerprint_policy_simulation` | Real captured transport/browser differences (TLS/JA4/HTTP2 vs. browser declarations) and synthetic detector inputs **never** share an evidentiary label. |
| **12. Challenge lifecycle** | `challenge.modes.*=simulated`, `challenge_orchestration`, local identity/challenge validators | Preserves interruption, expiry, rejection, and resumption tests across local challenge gates. |
| **13. Simulated challenge kinds & signatures** | hCaptcha-shaped mocks, `px` simulated signature | Local challenge kinds can include hCaptcha-shaped mocks. `px` remains a simulated signature, not a fabricated vendor verifier. reCAPTCHA v3 is **not** included without a separate test contract. Deprecated `simulated_challenge` is retained only as an import alias, not another mechanism. |
| **14. External compatibility widgets** | `real_challenge_widgets` | Remains optional, unscored, and strictly outside deterministic adaptive sessions. |

### 3.3 Global Timing & Applicability Bounds (§6.3)
- **Fast-campaign delay domain bound:** Bounded, generally up to **5 seconds** (`<= 5000 ms`); longer waits belong to explicitly separate soak profiles.
- **Mode-dependent applicability:** Applicability depends on the configured subject mode. Class churn (`dynamic_classes`) does not test a coordinate-only action path unless another consumed channel depends on those classes. A vision-based subject is nevertheless exposed to the network connection it uses.

### 3.4 Compiler Solvability & Validity Constraints (§6.4)
The manifest/task compiler rejects `completion` tasks that:
1. hide a required control without a human path;
2. require an observational-only mock to satisfy verification;
3. permanently reject every required verifier;
4. exceed their budget by construction;
5. remove all recovery paths while requiring successful recovery;
6. depend on a browser capability absent from the declared fixture environment.
- **Graceful-Degradation Exception:** Permanent rejection can still be a valid `graceful_degradation` experiment (`expected_outcome: completion | graceful_degradation`).
- **Fixture Defect Rule:** A fixture defect is not "extra hostility." Undeclared failures invalidate the affected opportunity (`validity.fixture: invalid`) and must be repaired as fixture bugs.

---

## 4. DATABASE OUTBOX & PERSISTENCE TABLES (§10.1, §10.2, §10.3, §10.7)

### 4.1 SQLite WAL Configuration & Atomic Transaction Boundary (§10.1)
- **Storage Engine & Mode:** SQLite running in **WAL (Write-Ahead Logging)** mode with a durability configuration appropriate to acknowledged writes; **M1 uses full synchronization** (`PRAGMA synchronous = FULL`) rather than promising durability while relying on a weaker default.
- **Single-Transaction Atomic Commit Boundary (Outbox Pattern):**
  A successful application operation commits, **in one single SQLite transaction**:
  1. the admitted command;
  2. its operation/idempotency record (`operations`);
  3. resulting authoritative state (`application_state`);
  4. emitted business events (`events`);
  5. the response representation needed for idempotent replay (`operations.committed_response`).
- **Post-Commit Publication Rule:**
  Only **after** the SQLite transaction commits does the engine acknowledge the transition to the caller or publish the new in-memory actor state. This avoids the ambiguity of "log before effect" when the log and effect can diverge.
- **Pre-Transaction Content-Addressed Artifact Installation Rule:**
  Large artifacts are:
  1. written to a temporary file,
  2. hashed (content-addressed digest),
  3. flushed (`fsync`), and
  4. atomically installed into the content-addressed artifact directory **before** the SQLite transaction references them.
  *Crash invariant:* A crash may leave an unreferenced artifact on disk for garbage collection; it must **never** leave an acknowledged upload in SQLite pointing at absent bytes.

### 4.2 Minimum Durable Tables & Complete Schema Specification (§10.2)
| Table Name | Authoritative Blueprint Contents (§10.2) | Complete Required Columns & Mechanical Schema Specification |
|---|---|---|
| `sessions` | Manifest reference, mode, lifecycle, admission record, current journal head. | `session_id` (PK), `experiment_group_id` (nullable), `manifest_hash` (FK → `manifests`), `mode` (`manual \| subject`), `admission_status`, `admission_record` (JSON/structured), `lifecycle_state` (`admitted \| running \| draining \| finalized \| infrastructure_interrupted`), `termination_reason` (nullable), `authority_sealed` (boolean), `current_journal_sequence` (integer head pointer), `current_journal_prefix_hash` (digest), `created_at_utc`, `updated_at_utc`. |
| `manifests` | Immutable canonical manifest and digest. | `manifest_hash` (PK digest), `canonical_manifest_json` (immutable canonical JSON blob pinning build, task, feature packs, seed, policies, origins, budgets, environment declarations), `task_semantic_hash` (digest), `fixture_build_digest` (digest), `frontend_asset_digest` (digest), `created_at_utc`. Immutable at session admission. |
| `events` | Ordered session journal, producer sequence, provenance, causal references, payload version. | `session_id` (FK → `sessions`), `journal_sequence` (monotonic per-session integer, composite PK `(session_id, journal_sequence)`), `event_id` (unique identifier), `event_schema_version` (string), `event_kind` (enum of core event types), `role` (`external_input \| derived_output \| lifecycle_observation`), `producer_id` (string), `producer_sequence` (nullable integer; deduplicated per producer), `provenance` (`server \| fixture_client \| connector \| manual_observer`, assigned by server at ingestion), `causal_refs_json` (array of causal `event_id` / `EvidenceRef` strings), `clock_id` (string), `monotonic_offset_ns` / `monotonic_offset_ms` (nullable number relative to `clock_id`), `utc_annotation` (ISO-8601 timestamp string), `payload_json` (versioned structured event payload). |
| `operations` | Idempotency key, request digest, committed response, state transition references. | `session_id` (FK → `sessions`), `idempotency_key` (string, composite PK `(session_id, idempotency_key)`), `operation_kind` (endpoint/command identifier), `request_digest` (SHA-256 digest of canonical request payload), `expected_state_revision` (integer), `resulting_state_revision` (nullable integer), `state_transition_refs_json` (references to emitted `journal_sequence` / `event_id` rows), `committed_response_status` (HTTP status integer), `committed_response_json` (serialized response representation for exact idempotent replay), `committed_at_journal_sequence` (integer). |
| `application_state` | Authoritative materialized state and revision. | `session_id` (PK, FK → `sessions`), `state_revision` (monotonic integer cutoff `application_state_cutoff`), `workflow_state` (`LISTING \| DETAIL \| CONTACT \| HISTORY \| UPLOAD \| IDENTITY \| REVIEW \| CONFIRMATION`), `selected_job_id` (nullable string), `contact_value_revision` (integer), `contact_validation_generation` (integer), `contact_accepted_json` (nullable JSON), `history_value_revision` (integer), `history_validation_generation` (integer), `history_accepted_json` (nullable JSON), `upload_artifact_digest` (nullable FK → `artifacts`), `upload_metadata_json` (nullable JSON), `identity_receipt_id` (nullable string), `identity_epoch` (nullable integer), `identity_verified` (boolean), `review_validated_revision` (nullable integer), `submission_committed` (boolean), `submission_receipt_json` (nullable JSON), `confirmation_rendered` (boolean), `materialized_state_hash` (digest). |
| `connector_attempts` | Local handle, dispatch state, native identifiers, request/result references. | `attempt_id` / `local_handle` (PK string, allocated durably before external dispatch), `session_id` (FK → `sessions`), `connector_version` (string), `binding_version` (string), `dispatch_state` (`prepared \| dispatch_beginning \| in_flight \| dispatch_uncertain \| terminal_received \| transport_closed \| timed_out \| contained`), `native_run_id` (nullable string, attached only when actually received), `assistance_record_json` (`AssistanceRecord`), `task_semantic_hash` (digest), `delivered_task_hash` (digest), `native_request_hash` (nullable digest), `request_artifact_digest` (nullable FK → `artifacts`), `response_artifact_digest` (nullable FK → `artifacts`), `callback_refs_json` (array of callback event/artifact refs), `started_at_journal_sequence` (integer), `ended_at_journal_sequence` (nullable integer). |
| `capability_snapshots` | Scoped capability inventory and evidence provenance. | `snapshot_id` (PK string), `session_id` (FK → `sessions`), `subject_identity_ref` (string), `configured_mode` (string), `interface_surface` (string), `capabilities_json` (serialized `[NativeCapability]` array with `capability_id`, `requirement_refs`, `availability`, `scope`, `evidence`, `claim_origin`, `limitations`, `supersedes_ref`), `created_at_journal_sequence` (integer). |
| `artifacts` | Digests, sizes, types, access classification, retention state. | `artifact_digest` (PK content-addressed SHA-256 digest), `session_id` (FK → `sessions`), `artifact_kind` (`synthetic_document \| uploaded_document \| native_request_body \| native_response_body \| callback_body \| screenshot \| diagnostic_json \| diagnostic_md \| export_bundle`), `byte_size` (integer), `media_type` (MIME string), `storage_rel_path` (path under content-addressed artifact directory), `access_classification` (`public_fixture \| restricted_raw_native \| operator_only`), `retention_state` (`active \| pinned \| gc_eligible \| purged`), `installed_at_utc` (timestamp). |
| `diagnostic_revisions` | Immutable analysis documents and the exact journal prefix analyzed. | `diagnostic_id` (PK string), `session_id` (FK → `sessions`), `analysis_revision` (monotonic integer per session, unique `(session_id, analysis_revision)`), `schema_version` (`hellscape.diagnostic/1`), `classifier_version` (string), `requirement_registry_version` (string), `fix_registry_version` (nullable string), `journal_cutoff_sequence` (integer), `journal_prefix_hash` (digest), `application_state_cutoff` (integer), `canonical_semantic_output_hash` (digest), `diagnostic_json` (immutable full JSON document), `diagnostic_markdown` (immutable rendered Markdown report), `created_at_utc` (timestamp). |

### 4.3 Finalization, Restart, and Storage Failure Rules (§10.7)
- **Finalization Triggers:** A durably admitted session is finalized after:
  1. normal manual completion;
  2. operator termination;
  3. deadline;
  4. launch/translation error;
  5. native terminal result;
  6. infrastructure interruption.
- **Bounded Evidence Drain:** Evidence drain has a finite bound. Missing producer tails are recorded (`producer_completeness`) rather than awaited indefinitely.
- **Engine Restart Behavior:** On restart, M1:
  1. restores authoritative application state from `application_state` and `events`;
  2. marks unfinished observation sessions `infrastructure-interrupted`;
  3. does **not** assume a native run stopped (`execution_state_at_observation_close: unknown`);
  4. does **not** automatically replay side-effecting subject requests (attempts in `dispatch_beginning` are recovered as `dispatch-uncertain`);
  5. generates an interrupted diagnostic revision in `diagnostic_revisions` when the store is available.
- **Storage Failure Backpressure:** Storage failures are surfaced explicitly, session admission stops when persistence cannot be trusted, and any unpersisted tail is never called complete.

---

## 5. DIAGNOSTIC REDUCER & TIMING ENGINE (§4, §10.3, §10.4, §10.5)

### 5.1 The 3-Way Core Distinction (§4.1)
The diagnostic engine must preserve three non-interchangeable distinctions across separate axes (capability availability vs. behavioral outcome):

1. **Native capability absence (`native_capability_absent` / `native_absence`):**
   - *Definition:* The configured, audited subject surface does not provide the required primitive.
   - *Example:* No native cancel primitive on the audited surface.
   - *Strict Rules (§4.3):*
     - A harness watchdog does **not** make `native_cancel` present.
     - A fresh fixture application record does **not** make native browser isolation present.
     - A new API version string does **not** establish a framework revision.
     - Absence is scoped to the audited/configured surface and evidence version.
     - A future revision does **not** inherit an old absence finding automatically.
     - Documentation saying a capability exists does **not** establish that it worked in a run.
     - A connector's incomplete mapping is **not** automatically subject-native absence.

2. **Observed requirement violation (`requirement_violation` / `violated`):**
   - *Definition:* A valid opportunity was presented (`opportunity.state: exposed`) and the observed behavior violated the requirement.
   - *Example:* A supported cancel request is acknowledged, but an independently observed stop exceeds the declared bound.

3. **Indeterminate result (`indeterminate`):**
   - *Definition:* The run lacks the control, exposure, observation, or claim semantics needed to decide.
   - *Example:* No side effect occurs after connection close, but neither execution termination nor adequate observation is established; or an R2 isolation experiment's write control failed.

### 5.2 Complete Diagnostic Document Schema (`hellscape.diagnostic/1`) (§4.2–§4.5)
Every nullable field that affects interpretation has an explicit reason field in its type ("Unknown", "not enabled", "not applicable", and "missing due to observation loss" are distinct reasons).

```yaml
Diagnostic:
  schema_version: hellscape.diagnostic/1
  diagnostic_id: string
  analysis_revision: integer
  session_id: string
  experiment_group_id: string | null

  execution:
    mode: manual | subject
    subject: SubjectIdentity | null
    connector_version: string | null
    binding_version: string | null
    assistance: AssistanceRecord
    task_semantic_hash: digest
    delivered_task_hash: digest
    native_request_hash: digest | null

  provenance:
    manifest_hash: digest
    fixture_build_digest: digest
    frontend_asset_digest: digest
    feature_pack_digests: [digest]
    classifier_version: string
    requirement_registry_version: string
    fix_registry_version: string | null
    journal_cutoff_sequence: integer
    journal_prefix_hash: digest
    imported_evidence_refs: [EvidenceRef]

  configuration:
    task: TaskEnvelope
    seed: string
    features: [FeatureConfiguration]
    expected_outcome: completion | graceful_degradation
    budgets: BudgetRecord
    origin_topology: object
    requested_context_policy: ContextPolicy
    realized_context_policy: ObservedContextPolicy

  validity:
    fixture: valid | invalid | incomplete
    scoped_checks: [ValidityCheck]
    producer_completeness: [ProducerCompleteness]
    infrastructure_incidents: [Incident]
    limitations: [string]

  native_capabilities: [NativeCapability]
  requirement_assessments: [RequirementAssessment]

  observed_actions:
    - action_id: string
      kind: string
      target_alias: string | null
      frame_alias: string | null
      render_generation: integer | null
      evidence_refs: [EvidenceRef]
      observed_effect: object | null
      provenance: server | fixture_client | connector | manual_observer
      limitations: [string]

  feature_exposures:
    - instance_id: string
      configured: boolean
      rendered_or_armed: boolean
      exposed: boolean
      activated: boolean
      recovery_observed: boolean | null
      evidence_refs: [EvidenceRef]

  steps:
    - step_id: string
      contract_id: string
      status: passed | recovered | failed | blocked | skipped | unobserved
      attempts: [StepAttempt]
      authoritative_postconditions: [PredicateResult]
      measurements: [Measurement]
      finding_refs: [string]

  claims: [Claim]
  findings: [Finding]

  lifecycle:
    admission_status: string
    termination_reason: string
    observation_window: ObservationWindow
    execution_state_at_observation_close: running | terminal | unknown | not_applicable
    cancellation: CancellationRecord
    connection_close: ConnectionCloseRecord
    containment: [ContainmentAction]
    late_evidence_refs: [EvidenceRef]

  outcome:
    application_goal: completed | not_completed | unknown | not_applicable
    application_state_cutoff: integer
    expectation_met: true | false | null
    subject_reported_goal: completed | not_completed | outcome_unknown | absent
    subject_execution_state: completed | failed | stopped | running | unknown | not_applicable
    detection_observed: boolean
    detection_enforced: boolean
    eligibility: [EligibilityDecision]

  behavioral_profile: BehavioralProfile
  fingerprint_profile: FingerprintProfile

  reproduction:
    bundle_hash: digest
    canonical_semantic_output_hash: digest
    exact_replay: matched | mismatched | not_run
    minimal_reproducer_ref: string | null

  artifacts: [ArtifactReference]
```

**Sub-Schemas (§4.3–§4.5):**
```yaml
NativeCapability:
  capability_id: string
  requirement_refs: [string]
  availability: present | absent | unknown | not_applicable
  scope:
    subject_identity_ref: string
    configured_mode: string
    interface_surface: string
  evidence:
    - basis: documentation | executed_observation | source_diagnosis | operator_attestation
      ref: EvidenceRef
  claim_origin: native | composed_subject | harness
  limitations: [string]
  supersedes_ref: string | null

RequirementAssessment:
  requirement_id: R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10
  facet: string
  contract_version: string
  capability_refs: [string]
  opportunity:
    state: exposed | unexposed | blocked | not_applicable
    evidence_refs: [EvidenceRef]
  result: satisfied | violated | native_absence | indeterminate |
          not_exercised | blocked | not_applicable
  evidence_refs: [EvidenceRef]
  contrary_evidence_refs: [EvidenceRef]
  finding_refs: [string]
  rationale: string

Finding:
  finding_id: string
  kind: native_capability_absent | requirement_violation |
        claim_contradiction | measurement_discrepancy |
        observation | indeterminate | fixture_error | harness_error
  requirement_refs: [string]
  symptom: string
  scope: object
  causal_role: primary | contributing | downstream | not_applicable
  trigger_feature_refs: [string]
  defect_locus: subject | external_planner | connector | fixture |
                environment | policy | unknown | not_applicable
  attribution: confirmed | supported | suspected | unknown
  evidence_refs: [EvidenceRef]
  contrary_evidence_refs: [EvidenceRef]
  limitations: [string]
  suggested_fix: FixRecommendation | null
  no_fix_reason: string | null

Claim:
  claim_id: string
  source: native_framework | native_planner | connector | manual_operator
  scope: primitive | application_postcondition | execution_lifecycle | unknown
  proposition: object
  made_at: TimeReference | null
  received_at: TimeReference
  evidence_available_to_claimant: [EvidenceRef]
  comparison: consistent | contradicted | not_comparable | indeterminate
  comparison_evidence_refs: [EvidenceRef]

Measurement:
  measurement_id: string
  scope: session | connector_call | workflow_step | application_operation |
         native_primitive | recovery
  origin: engine_measured | browser_measured | subject_reported | manual_reference
  clock_id: string
  start_ref: EvidenceRef | null
  end_ref: EvidenceRef | null
  elapsed_ms: number | null
  lower_bound_ms: number | null
  upper_bound_ms: number | null
  resolution_ms: number | null
  censoring: none | left | right | both | unavailable
  comparability_group: string | null
  unavailable_reason: string | null
```

### 5.3 Journal Event Envelope & Core Event Types (§10.3)
Every journal entry carries the exact envelope:
```text
session_id
journal_sequence
event_id
event_schema_version
event_kind
role: external_input | derived_output | lifecycle_observation
producer_id
producer_sequence, where applicable
provenance assigned by the server
causal_refs[]
clock_id and monotonic offset, where available
UTC annotation
payload
```

**15 Core Event Categories (§10.3):**
1. session admission/start/end;
2. component ready;
3. observed input/click/change;
4. request admitted/completed/rejected;
5. validation accepted/rejected/superseded;
6. workflow transition committed;
7. upload stored;
8. identity verified;
9. submission committed;
10. confirmation rendered;
11. connector dispatch/result/transport close;
12. native callback received/authenticated/rejected;
13. deadline and observation closure;
14. producer gap/flush/closure;
15. fixture authority sealed.
*(High-rate telemetry is batched without destructive trailing debounce.)*

### 5.4 Monotonic Clock Scopes & Timing Engine Rules (§4.5, §10.4, §12.3)
**Four Separate Clock Identities (`clock_id` / `origin`):**
1. **Engine process clock (`engine_measured`):** Monotonic offsets persisted relative to the engine process boot identity. Never subtract monotonic values across process restarts.
2. **Browser document producer clock (`browser_measured`):** One clock identity per browser document producer using `performance.now()` to measure workflow intervals with explicit endpoints. Server receipt time is also retained, but telemetry delivery latency is never mistaken for original event time.
3. **External/native report clock (`subject_reported`):** Native reported durations retained unchanged as claims (e.g., circus-tent `_elapsed()` returning `0` remains `0` in the raw report alongside independently measured intervals; Hellscape never silently "corrects" subject data).
4. **Manual reference clock (`manual_reference`):** Independent manual timing references (monotonic stopwatch or local validation clock) covering explicitly marked intervals during manual validation.

**Measurement Scopes (`Measurement.scope`):**
- `session`: session observation duration.
- `connector_call`: connector request duration when a connector is used.
- `workflow_step`: each workflow step's available ready-to-postcondition interval.
- `application_operation`: each server operation's admitted-to-commit interval.
- `native_primitive`: native reported primitive duration.
- `recovery`: interval spent recovering from a rejected attempt or fault.
- Any censored (`left | right | both`) or unavailable (`unavailable` with `unavailable_reason`) interval.

**Timing Invariants & Non-Fabrication Rules:**
- Elapsed wall-clock time is measured using monotonic clocks. UTC timestamps are annotations and correlation aids, never the basis for duration subtraction across clock adjustments.
- Hellscape does **not** divide a total `/run` duration by the number of steps to invent primitive durations.
- Hellscape does **not** infer that summed step durations must equal request latency (queueing, setup, and teardown may occupy the difference; a `measurement_discrepancy` finding requires comparable boundaries or a defensible lower bound).
- Human reading and pauses are included in workflow elapsed time; they are not described as framework primitive execution time.
- **Acceptance Tolerances (§12.3):**
  - Server intervals must equal their recorded endpoint differences within serialization resolution.
  - Browser intervals must use one producer clock.
  - Independent manual timing comparisons allow only the declared marker/measurement uncertainty.
  - Intervals lacking comparable endpoints are marked `unavailable` or bounded (`lower_bound_ms`, `upper_bound_ms`), not forced into agreement.

### 5.5 Diagnostic Reducer, Classification Pipeline & Postcondition Evaluation Rules (§4.6, §4.7, §10.5)
**7-Stage M1 Classification Pipeline (§4.7):**
1. Validate the manifest and relevant fixture invariants.
2. Establish producer completeness and scoped observation limits.
3. Join actions, requests, validations, transitions, claims, and timings.
4. Evaluate authoritative step and task postconditions.
5. Identify the first unmet contract; mark downstream unreachable steps `blocked`.
6. Produce capability, violation, contradiction, and uncertainty findings.
7. Render a report (both JSON and readable Markdown) with evidence references and explicit `null` recommendations (`no_fix_reason` populated).

**9 Deterministic Reducer Operations (§10.5):**
The M1 analyzer is a deterministic function of the pinned inputs `(manifest, referenced_evidence, journal_prefix, classifier_version)`. It:
1. checks authoritative state consistency;
2. identifies completed and incomplete postconditions;
3. associates attempted actions with visible effects where evidence permits;
4. marks expected validation rejection separately from fixture failure;
5. retains recovery attempts (`attempts: [StepAttempt]`, step status `recovered`) rather than replacing them with the final success;
6. compares only semantically compatible claims (`consistent | contradicted | not_comparable | indeterminate`);
7. emits native absence and indeterminate results as distinct types;
8. reports disabled analyses (`not_enabled`) and missing evidence explicitly;
9. generates a readable timeline and summary from the structured result.

**Strict Anti-Default Invariant (§10.5):**
- **No classifier branch may use a default zero (`0`) to mean missing duration, a default `false` to mean unknown completion, or an empty capability object (`{}`) to mean absence.**

**Postcondition, Step Status, and Claim Evaluation Rules (§4.4, §4.6):**
- **Step Status Values:** `passed | recovered | failed | blocked | skipped | unobserved`.
  - If a step has one or more rejected attempts followed by an accepted attempt satisfying its authoritative postcondition, its status is `recovered` and all attempts remain in `attempts[]`.
  - Once the first unmet step contract is identified, downstream unreachable steps are marked `blocked` (or `unobserved` if cutoff occurred before reaching them).
- **Manual Session Rule (§4.4):** Manual sessions have `execution.mode: manual` and `execution.subject: null`. All R1–R10 `requirement_assessments` have `result: not_exercised` with rationale/reason `manual_fixture_validation`.
- **Scoped Validity Rule (§4.4):** Validity is scoped (`validity.scoped_checks`). A failed isolation write control makes the R2 isolation assessment `indeterminate`, but does not invalidate unrelated application evidence (`validity.fixture` remains `valid`).
- **Outcome & Knowledge-Boundary Claim Semantics (§4.6):**
  - Connection closure, native execution state, application commitment, and terminal callbacks are independent facts.
  - A close-time `outcome_unknown` claim is **consistent** (honest at its knowledge boundary `evidence_available_to_claimant`), even if the subject continues running and the application commits later.
  - A close-time claim that work was definitely cancelled is **contradicted** if later application commitment or execution is observed.
  - circus-tent `/run status=completed` maps to `subject_execution_state: completed` (execution lifecycle scope), **not** automatically `application_goal: completed` (application postcondition scope).
  - Server submission commitment (`submission_committed`) and browser confirmation receipt display (`confirmation_rendered`) are evaluated as separate postconditions.

---

## 6. EXACT REPLAY ENGINE & HASH EQUATIONS (§6.5, §10.8)

### 6.1 Exact Fixture Replay Contract vs. Live Reproduction (§6.5, §10.8)
Hellscape defines two strictly distinct operations:
1. **Exact fixture replay:** No browser or automation subject is invoked. Recorded external inputs and lifecycle observations from the journal are fed through the application reducer and diagnostic classifier against the pinned manifest to reproduce identical state transitions, semantic outputs, and diagnostics. Proves fixture consistency for the recorded input sequence.
2. **Live reproduction:** The same fixture manifest is presented to a new live attempt; different subject behavior remains possible and is measured.

### 6.2 State Transition & Deterministic Randomness Equations (§6.5)
**State Transition Function:**
$$(S_{i+1}, O_i) = T(S_i, I_i, M)$$
Where:
- $M$: Pinned immutable canonical manifest (pinning build digest, task, feature packs, seed, policies, origins, budgets, and environment declarations).
- $S_i$: Authoritative fixture state at step/event index $i$ (starting from initial state $S_0$ derived solely from $M$).
- $I_i$: Admitted external input or lifecycle observation at index $i$ (`role ∈ {external_input, lifecycle_observation}` in the ordered journal, with runtime credentials and dynamic locators normalized to stable semantic aliases).
- $S_{i+1}$: Next authoritative fixture state produced deterministically by reducer transition function $T$.
- $O_i$: Emitted semantic output / derived business event (`role = derived_output`) at index $i$.

**Domain-Separated Deterministic Random Derivation:**
$$\text{Draw}(M.\text{seed}, \text{domain\_version}, \text{feature\_namespace}, \text{semantic\_id}) = \text{HMAC-SHA256}\big(K = M.\text{seed},\; \text{msg} = \text{domain\_version} \;\|\; \text{feature\_namespace} \;\|\; \text{semantic\_id}\big)$$
- Semantic identifiers and feature parameter draws are domain-separated so they remain **independent of unrelated feature activation** (enabling counterfactual runs in M3 to preserve unrelated semantic randomness).
- Runtime credentials, session tokens, and TLS randomness are excluded from semantic identities and replaced by stable semantic aliases during canonicalization.

### 6.3 5-Step Exact Replay Execution Algorithm (§10.8)
M1 exact replay executes the following sequence:
1. **Load pinned manifest:** Load immutable $M$ and verify $\text{SHA256}(\text{canonical}(M)) == \text{manifest\_hash}$.
2. **Consume recorded inputs only:** Filter the recorded journal prefix $J_{1..N}$ (up to `journal_cutoff_sequence` $N$) to consume **only** recorded external inputs (`role == external_input`) and lifecycle observations (`role == lifecycle_observation`). Recorded timing measurements remain preserved inputs; replay **never sleeps** to reproduce elapsed wall-clock time.
3. **Recompute reducer outputs:** Apply $(S_{i+1}', O_i') = T(S_i', I_i, M)$ iteratively for $i = 0 \dots k-1$ across all consumed inputs.
4. **Compare semantic event and final-state hashes:** Verify that recomputed semantic outputs $\{O_i'\}$ and final materialized state $S_{\text{final}}'$ match the recorded hashes.
5. **Recompute diagnostic with pinned classifier:** Run the deterministic diagnostic reducer $D(M, J_{1..N}', S_{\text{final}}', \text{classifier\_version})$ and compare the resulting canonical semantic diagnostic hash.

### 6.4 Hash Comparison Equations (§4.2, §6.5, §10.2, §10.8)
Let $\text{Canon}(\cdot)$ denote deterministic canonical JSON serialization with runtime credentials/ephemeral locators mapped to stable semantic aliases:

1. **Journal Prefix Hash (`journal_prefix_hash`):**
   $$H_{\text{journal}}(N) = \text{SHA256}\Big(\text{Canon}\big(\langle E_1, E_2, \dots, E_N \rangle\big)\Big)$$
   where $N = \text{journal\_cutoff\_sequence}$.

2. **Semantic Event Stream Hash (`semantic_events_hash`):**
   $$H_{\text{events}} = \text{SHA256}\Big(\text{Canon}\big(\langle \text{SemanticProjection}(O_0), \text{SemanticProjection}(O_1), \dots, \text{SemanticProjection}(O_{k-1}) \rangle\big)\Big)$$
   $$H_{\text{events}}' = \text{SHA256}\Big(\text{Canon}\big(\langle \text{SemanticProjection}(O_0'), \text{SemanticProjection}(O_1'), \dots, \text{SemanticProjection}(O_{k-1}') \rangle\big)\Big)$$

3. **Authoritative Final-State Hash (`final_state_hash` / `materialized_state_hash`):**
   $$H_{\text{state}} = \text{SHA256}\Big(\text{Canon}\big(S_{\text{cutoff}}\big)\Big), \quad H_{\text{state}}' = \text{SHA256}\Big(\text{Canon}\big(S_{\text{cutoff}}'\big)\Big)$$
   where $\text{cutoff} = \text{application\_state\_cutoff}$.

4. **Canonical Semantic Output & Diagnostic Hash (`canonical_semantic_output_hash`):**
   $$H_{\text{semantic}} = \text{SHA256}\Big(\text{Canon}\big(H_{\text{events}} \;\|\; H_{\text{state}} \;\|\; \text{SemanticDiagnostic}(D)\big)\Big)$$
   $$H_{\text{semantic}}' = \text{SHA256}\Big(\text{Canon}\big(H_{\text{events}}' \;\|\; H_{\text{state}}' \;\|\; \text{SemanticDiagnostic}(D')\big)\Big)$$

5. **Exact Replay Verification Predicate (`reproduction.exact_replay`):**
   $$\text{exact\_replay} = \begin{cases} \texttt{matched} & \text{if } (H_{\text{events}}' == H_{\text{events}}) \;\land\; (H_{\text{state}}' == H_{\text{state}}) \;\land\; (H_{\text{semantic}}' == H_{\text{semantic}}) \\ \texttt{mismatched} & \text{otherwise} \end{cases}$$

---

## 7. THE 14-STEP MANUAL WALKTHROUGH ACCEPTANCE SCRIPT (§12.1–§12.6)

### 7.1 Pre-Walkthrough Setup (§12.2)
1. Create a fixed cooperative manifest (`manifest.json`) with zero hostile features and a deterministic synthetic task (`task.json`) plus synthetic document (`artifacts/synthetic-document`).
2. Record the browser/environment declaration.
3. Start a **manual** session (`execution.mode: manual`, `execution.subject: null`) via the authenticated control plane.

### 7.2 The 14-Step Operator Walkthrough Script (§12.2)
The human operator performs the following exact sequence against the cooperative SPA:

1. **Step 1 — Open Entry URL:** Opens the task’s ordinary entry URL in an ordinary browser. (SPA renders `LISTING` view and emits component readiness telemetry).
2. **Step 2 — Select Job (`LISTING → DETAIL`):** Selects the specified synthetic job (`POST …/api/job-selection`). Server stores selected job and transitions authoritative state to `DETAIL`.
3. **Step 3 — Supply Valid Contact Information (`DETAIL → CONTACT`):** Supplies valid contact information matching the synthetic task on the detail view and saves (`PUT …/api/contact`). Server stores accepted contact value revision and validation generation, transitioning authoritative state to `CONTACT`.
4. **Step 4 — Enter History (`CONTACT → HISTORY`):** Activates continue to work history (`POST …/api/history/enter`). Server verifies accepted contact currency and transitions authoritative state to `HISTORY`.
5. **Step 5 — Submit Deliberate Invalid Date Interval (`HISTORY` rejection):** Submits an intentionally invalid work history interval—specifically, **an end date before its start date** (`PUT …/api/history`). *(This deliberate invalid value is an ordinary application error path, not fixture hostility.)*
6. **Step 6 — Verify Ordinary Validation Error (`HISTORY` retained):** Observes the visible ordinary validation error message in the UI. Server records the rejected validation attempt in the journal and keeps authoritative workflow state in `HISTORY` (must not advance to `UPLOAD`).
7. **Step 7 — Correct Interval and Save (`HISTORY → UPLOAD` recovery):** Corrects the history date interval to valid task values and saves (`PUT …/api/history`). Server accepts the new history value revision and validation generation, transitioning authoritative state to `UPLOAD`.
8. **Step 8 — Upload Synthetic Document (`UPLOAD → IDENTITY`):** Selects and uploads the supplied synthetic document using the visible native file input (`POST …/api/upload`). Server verifies size/type policy, atomically stores the content-addressed artifact, verifies digest, and transitions authoritative state to `IDENTITY`.
9. **Step 9 — Perform Inline Local Identity Action (`IDENTITY → REVIEW`):** Activates the clearly labeled inline local verification control (`POST …/api/identity/verify`). Server issues and verifies the session-bound, epoch-bound local identity receipt and transitions authoritative state to `REVIEW`.
10. **Step 10 — Review Accepted Data (`REVIEW` validation):** Inspects the accepted data summary on the review view (`POST …/api/review/validate`). Server confirms all required section revisions and artifact digests are current.
11. **Step 11 — Timed Pause at Recorded Checkpoint:** Pauses at a recorded checkpoint (marked via authenticated manual observation note and timed against an independent monotonic stopwatch / local validation clock) for an independently timed interval.
12. **Step 12 — Submit Application Once (`REVIEW → CONFIRMATION`):** Clicks submit once (`POST …/api/submit`). Server revalidates all required revisions and commits exactly one application record, transitioning authoritative state to `CONFIRMATION`.
13. **Step 13 — Observe Confirmation Receipt (`CONFIRMATION` rendered):** Reads the confirmation receipt (`GET …/api/confirmation`). SPA renders the receipt and emits confirmation-rendered telemetry (recorded separately from server submission commitment).
14. **Step 14 — End Observation & Bounded Flush:** Ends observation via the control surface and allows the bounded client telemetry flush to complete before session finalization.

### 7.3 Expected Diagnostic Content for the 14-Step Walkthrough (§12.2)
The generated diagnostic (`diagnostic.json` and `diagnostic.md`) must satisfy all 12 assertions:
1. All intended final workflow postconditions (`LISTING`, `DETAIL`, `CONTACT`, `HISTORY`, `UPLOAD`, `IDENTITY`, `REVIEW`, `CONFIRMATION`) are satisfied (`outcome.application_goal: completed`, `outcome.expectation_met: true`).
2. The invalid history attempt (Step 5) is preserved in `steps[history].attempts[]` as a rejected attempt.
3. The history step (`steps[history].status`) is reported as `recovered`, with the correction (Step 7) visible.
4. The validation rejection is **not** attributed to a framework (`defect_locus` is not `subject`).
5. The timed pause (Step 11) appears in the appropriate measured workflow interval (`measurements[]`) and agrees with the independent manual reference clock within declared marker/measurement uncertainty.
6. Exactly one application is committed (`submission_committed == true`, operation count for submit commit $= 1$).
7. Accepted contact/history values and uploaded document SHA-256 digest match the synthetic task specification.
8. Identity verification has `server` provenance (not client-telemetry self-assertion).
9. Confirmation rendering (`confirmation_rendered`) is recorded as a separate fact/postcondition from submission commitment (`submission_committed`).
10. No native subject claim or native duration is fabricated (`execution.subject: null`, no `subject_reported` measurements).
11. `R1–R10` are **not** credited to a nonexistent subject (all `requirement_assessments` have `result: not_exercised` with reason `manual_fixture_validation`).
12. Exact replay of `journal.jsonl` against `manifest.json` produces `reproduction.exact_replay: matched`.

### 7.4 Companion Manual Validation Cases (§12.4)
| Case | Required Characterization |
|---|---|
| **1. Stop before submission.** | `outcome.application_goal: not_completed` at cutoff; no receipt; remaining downstream steps marked `unobserved` or `blocked` as appropriate. |
| **2. Repeat the submit action.** | Exactly one committed application; repeated operation key resolves idempotently to the existing receipt. |
| **3. End observation with an incomplete field.** | Honest partial outcome, not a fabricated field failure or success. |
| **4. Close the browser before telemetry flush.** | Authoritative server facts retained; missing client tail marked incomplete in `validity.producer_completeness`. |
| **5. Restart the engine after an acknowledged operation.** | Operation remains durable in SQLite; unfinished observation session is identified as `infrastructure-interrupted`; no automatic duplicate action. |
| **6. Replay the first walkthrough journal.** | Identical semantic outputs and authoritative state; deterministic diagnostic reconstruction (`exact_replay: matched`). |

### 7.5 Expected First Validation Bundle Structure (`m1-manual-001/`) (§12.6)
```text
m1-manual-001/
  manifest.json
  task.json
  build-receipt.json
  journal.jsonl
  authoritative-state.json
  timing-measurements.json
  manual-observations.json
  diagnostic.json
  diagnostic.md
  replay-receipt.json
  acceptance-checks.json
  artifacts/
    synthetic-document
```

### 7.6 M1 Acceptance Checklist (§12.5)
- [ ] The ordinary full manual path is usable.
- [ ] Successful and rejected attempts are distinguished correctly.
- [ ] The report matches authoritative state and independent manual observations.
- [ ] Durations are measured, scoped, and honestly qualified.
- [ ] Every durably admitted test session finalizes or is recovered as interrupted.
- [ ] Missing evidence remains visible.
- [ ] Client telemetry cannot forge server business events.
- [ ] Submission idempotency prevents duplicate application records.
- [ ] Exact replay matches.
- [ ] Connector contract tests cover unsupported capabilities and close-time uncertainty.
- [ ] The shipped connector has not been credited with native capabilities supplied only by the harness.
- [ ] No live subject was required for acceptance.
