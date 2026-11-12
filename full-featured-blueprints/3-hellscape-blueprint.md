# Hellscape — Rewritten Grand Design and M1 Blueprint

**Status:** replacement design, ready for M1 implementation. This document does not claim that M1 has been built or that additional trials have been run.

**Product:** a framework-agnostic browser fixture and diagnostic engine. Hellscape presents controlled application tasks, observes execution, preserves evidence, and explains what happened. A subject’s inability to complete a task is a possible product output—not a reason the fixture cannot ship.

**Milestone sequence:** starts at **M1**. M0’s findings remain evidence inputs; M0’s preflight milestone and proceed/stop gate are retired.

> **M1 acceptance criterion**
>
> **The diagnostic engine correctly characterizes a manual walkthrough of the cooperative SPA: steps succeed or fail as reported, durations reflect measured elapsed wall-clock time, and authoritative server state agrees with what the walkthrough produced.**
>
> No automation subject participates in this acceptance test. M1 nevertheless ships the subject-agnostic connector, including its lifecycle implementation and the initial circus-tent REST binding. M2 is its first live subject use.

**Readiness:** **yes, M1 is buildable now.** Its first integrated validation produces a manual-session diagnostic, durable event journal, authoritative state snapshot, measured timeline, and replay receipt. No circus-tent repair, further contract probe, cancellation primitive, or transport-fingerprint proof is a prerequisite.

---

# Part I — Grand Design

## 1. What Hellscape is

Hellscape is an operator-controlled laboratory for browser automation. Its two central assets are:

1. **A browser-driveable SPA** whose application behavior and hostile mechanisms are explicit, bounded, independently testable, and versioned.
2. **A diagnostic engine** that distinguishes application truth, observed browser behavior, subject claims, capability gaps, infrastructure incidents, and uncertainty.

The same SPA can be visited manually or driven by circus-tent, a later circus-tent revision, Stagehand, Browser Use, or another framework. Their differences belong in subject descriptors, assistance records, and connector bindings—not in framework-specific versions of the application’s truth.

The principal output is an evidence document. It answers:

- What task and environment were presented?
- Which opportunities and hostile mechanisms were actually encountered?
- What actions and effects were observed?
- What did the subject report, and what did that report mean?
- Which application postconditions became true?
- Which requirements were demonstrated, violated, unavailable natively, or not determinable?
- What evidence supports those conclusions?
- What remains unknown?

Task completion is one observation within that document. It is neither the definition of a useful session nor the acceptance criterion for Hellscape itself.

### 1.1 Cooperative means a property of the fixture

A cooperative configuration has no deliberately obstructive treatments:

- ordinary, visibly labeled controls;
- stable layout and semantic identities;
- no shadow-root or frame traversal challenge;
- no class churn, decoys, delayed hydration, or network-idle trap;
- no injected transport failures;
- no production challenge services;
- no artificial timing races.

Normal application behavior remains: validation, file upload, state transitions, identity confirmation, and submission guards.

A framework may fail on this configuration. Hellscape must be able to report that failure without redefining “cooperative” or adding hidden assistance until the framework succeeds.

### 1.2 What remains outside the product

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
- build a browser engine or adopt the substrate memo’s proposed fork as its own dependency.

The substrate survey informs test requirements. Its recommendation for an application-runner substrate does not select Hellscape’s subject or create another qualification gate.

### 1.3 Evidence carried forward

The supplied evidence has different scopes and dates. The rewrite preserves those distinctions.

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

The historical probes remain **unscored historical evidence**. They are not retroactively turned into Hellscape benchmark sessions.

The old M0 document’s “no probes have been run” status and pending gate are superseded. There is no remaining pre-M1 probe assignment.

---

## 2. Requirements and responsibilities

Two numbering systems existed in the source material. This rewrite uses:

- **R1–R10:** requirements on subjects that Hellscape measures, following the substrate requirement set.
- **H1–H10:** obligations of Hellscape itself, preserving the useful product commitments from the former Grand Design.

This prevents “R2 isolation” from being confused with the former Grand Design’s “R2 battering.”

### 2.1 Subject-facing requirements: R1–R10

These requirements are not relaxed because a subject—or the whole surveyed class—does not meet them. What changes is Hellscape’s response: it records the answer rather than making subject compliance a condition for building the product.

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

A requirement can contain several independently evaluated facets. R4, for example, can yield:

- `native_cancel: native_absence`;
- `behavior_after_close: continued_execution_observed`;
- `native_close_report: indeterminate`;
- `connector_close_report: satisfied`;
- `final_application_state: committed`.

That is not a contradictory result. It is a more accurate account than a single cancellation pass/fail flag.

**Absence is not a waiver.** If a required native capability is absent, the requirement gap remains visible even if external containment makes the experiment safe.

### 2.2 Hellscape obligations: H1–H10

| ID | Product obligation |
|---|---|
| **H1 — Adaptive selection** | Select future experiments from versioned, finalized evidence and recorded operator decisions. |
| **H2 — Sustained testing** | Support repeated and eventually concurrent sessions; retain the target of at least 100 eligible finalized sessions/hour under a published workload and hardware profile. |
| **H3 — Bounded escalation** | Use measurable feature domains, solvability constraints, exposure receipts, and explicit graceful-degradation tasks. |
| **H4 — Diagnostic output** | Produce a diagnostic for every durably admitted session, including launch failures and interrupted sessions, subject to explicit storage-failure limitations. |
| **H5 — Evidence-backed recommendations** | Emit reviewed recommendations only when evidence supports them; otherwise emit null with a reason. |
| **H6 — Reproducibility** | Reproduce fixture semantics from the same manifest and ordered input journal. Do not promise identical live browser behavior from a seed alone. |
| **H7 — Ordinary browser interface** | Require no fixture-specific subject plugin. The application uses ordinary browser protocols and controls. |
| **H8 — Independent human usability** | Provide a normal human completion path, or a deliberately declared degradation objective, for every admitted composition. |
| **H9 — Single deployable engine** | Embed the SPA, application server, journal, diagnostics, and experiment services in one Go binary. Browsers and subjects remain external. |
| **H10 — Framework-agnostic integration** | Bind different execution modes through an explicit connector contract without confusing harness assistance with native subject capability. |

H2 measures useful experiment throughput, not guaranteed business success. Reports must separately publish attempted sessions, eligible finalized sessions, application completions, early failures, and unexposed tasks. Immediate launch-failure loops do not satisfy the target.

---

## 3. Architecture

### 3.1 Selected implementation

Retain:

- **Go** for the engine;
- **Vite, strict TypeScript, and vanilla Web Components** for the SPA;
- **SQLite/WAL** for durable structured evidence;
- a **content-addressed artifact directory** for documents, native response bodies, screenshots, and exported bundles.

Web Components do not imply shadow DOM in the cooperative configuration. M1’s controls render in light DOM. Shadow and frame wrappers become explicit hostile primitives later.

```text
                         Operator
                            |
                  authenticated control plane
                            |
+------------------------ Hellscape -------------------------+
|                                                           |
| Manifest / task compiler ---- Session lifecycle            |
|          |                         |                      |
|          v                         v                      |
| Cooperative or hostile SPA    Generic connector           |
|          |                         |                      |
| Application reducer                +---- Subject binding --+--> framework
|          |                                                |       |
|          +---- authoritative effects                      |       v
|          |                                                |     browser
| Observation gateway <---------- ordinary browser traffic --+-------+
|          |
| Durable journal + application state + artifacts
|          |
| Diagnostic engine ---- readable report / JSON / replay
|          |
| Later: counterfactuals, fix registry, curriculum, cohorts
+-----------------------------------------------------------+
```

For manual validation, the connector dispatch path is not used. A person operates the same application; the same server, observation gateway, journal, and diagnostic engine run.

There is no separate “manual oracle implementation” that bypasses ordinary application transitions.

### 3.2 Boundaries that must remain separate

**Application truth.** The server reducer owns accepted data, workflow transitions, validation generations, identity receipts, and submission commitment.

**Observation.** DOM events, request evidence, transport facts, manual notes, and native results are observations with provenance. They cannot manufacture application truth.

**Execution.** The connector sends supported commands and observes responses. It does not decide whether the application succeeded.

**Judgment.** The diagnostic engine evaluates contracts against evidence. It does not alter the run to obtain a better result.

**Policy.** The curriculum chooses future sessions. It never silently changes the active session.

**Containment.** Hellscape bounds its own waiting, fixture effects, and resource exposure. Such containment is not relabeled as subject-native cancellation or isolation.

### 3.3 Application, telemetry, and control planes

The binary exposes three logical surfaces:

1. **Application plane:** SPA assets and ordinary application APIs.
2. **Write-only telemetry plane:** bounded ingestion from fixture-owned producers.
3. **Control plane:** manifests, session administration, diagnostics, evidence, and replay.

The control plane is separately authenticated and is not authorized by application cookies. CORS is not authentication. Subject-facing entry credentials never grant control access.

Telemetry:

- accepts only client-emittable event types;
- assigns provenance at ingestion;
- deduplicates producer sequence numbers;
- records gaps and overflow;
- cannot emit `submission_committed` or server verification success;
- uses scoped, write-only capabilities.

Canonical diagnostic target aliases live in internal registries. They are not universal scored-mode DOM selectors. Debug aliases are permitted only in labeled, non-comparable debug sessions.

Later closed-root instrumentation is installed inside the component while the fixture owns its root reference. Outside `composedPath()` inspection is not treated as a way to recover closed-root internals.

### 3.4 State separation

Three state domains are always recorded separately:

- **fixture application state**;
- **browser state**: cookies, local storage, IndexedDB, profile contents;
- **framework learning state**: selector caches, demonstrations, memory, recovery history.

Hellscape’s application state must remain correctly scoped even when a subject reuses browser state. An explicit attempt binding—not a mutable global “current session” cookie—selects the application actor.

Conversely, Hellscape must not mask a browser-isolation test by allocating different origins to A and B. R2 experiments deliberately use the same relevant origin and storage keys, while keeping server-side application records independently bound.

---

## 4. Expanded diagnostic engine

This is the central contract of the product and is implemented in M1 at baseline depth.

### 4.1 Three distinctions the schema must preserve

The engine must distinguish:

1. **Native capability absence**  
   The configured, audited subject surface does not provide the required primitive.

2. **Observed requirement violation**  
   A valid opportunity was presented and the observed behavior violated the requirement.

3. **Indeterminate result**  
   The run lacks the control, exposure, observation, or claim semantics needed to decide.

These are not interchangeable error codes.

Examples:

- No native cancel primitive: **native capability absence**.
- A supported cancel request is acknowledged, but an independently observed stop exceeds the declared bound: **requirement violation**.
- No side effect occurs after close, but neither execution termination nor adequate observation is established: **indeterminate**.

Capability availability and behavioral outcome are therefore separate axes.

### 4.2 Document shape

M1 implements a versioned JSON Schema and generates both JSON and a readable report from the same analysis object. The following specifies the document structure; it is not a claim that executable schema files already exist.

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

Every nullable field that affects interpretation has a reason field in its type. “Unknown,” “not enabled,” “not applicable,” and “missing due to observation loss” are different reasons.

### 4.3 Native capability record

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
```

Rules:

- A harness watchdog does not make `native_cancel` present.
- A fresh fixture application record does not make native browser isolation present.
- A new API version string does not establish a framework revision.
- Absence is scoped to the audited/configured surface and evidence version.
- A future revision does not inherit an old absence finding automatically.
- Documentation saying a capability exists does not establish that it worked in a run.
- A connector’s incomplete mapping is not automatically subject-native absence.

The class-wide cancellation finding and the circus-tent-specific finding are stored as separate evidence sources. Together they establish that circus-tent is not an exception within the surveyed local class; they do not establish a timeless fact about all future frameworks.

### 4.4 Requirement assessment and finding types

```yaml
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
```

A diagnostic can contain a valid application result and an indeterminate isolation result. Validity is scoped; a failed isolation control does not erase unrelated application evidence.

Likewise, native absence does not make the fixture invalid. It is a valid finding about the subject.

Manual sessions have `subject: null`. Their subject requirement assessments are `not_exercised`, with reason `manual_fixture_validation`. Human operation is not credited as evidence that circus-tent—or any other framework—meets R1–R10.

### 4.5 Claims and timing

```yaml
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

Elapsed wall-clock time is measured using monotonic clocks. UTC timestamps are annotations and correlation aids, not the basis for duration subtraction across clock adjustments.

Hellscape records:

- engine-observed session and connector intervals;
- server request-to-commit intervals;
- browser-observed ready-to-action or ready-to-render intervals;
- native reported durations, unchanged;
- independent manual timing references used during validation.

It does **not** divide a total `/run` duration by the number of steps to invent primitive durations.

Nor does it infer that summed step durations must equal request latency: queueing, setup, and teardown may occupy the difference. A discrepancy requires comparable boundaries or a defensible lower bound.

The known `_elapsed()` defect is retained as historical source-diagnosis evidence. In a new run, zero native durations remain zero in the raw report; Hellscape supplies independently measured intervals alongside them. It does not silently “correct” the subject’s data.

### 4.6 Outcome and claim semantics

The former `succeeded | failed | detected` result is insufficient as the sole outcome.

The following can all be true:

- the connector’s HTTP connection closed;
- the native execution state was then unknown;
- the application had not yet committed;
- the subject continued working;
- the application committed later;
- an authenticated native callback later reported execution completion.

A close-time `outcome_unknown` report is not disproved by later commitment. It was honest at its knowledge boundary.

Conversely, a close-time claim that work was definitely cancelled can be contradicted by later evidence.

For circus-tent specifically, `/run status=completed` is mapped initially to **execution completion**. It is not automatically an application-submission claim. An adapter that upgrades it without supporting semantics owns the resulting overclaim.

A successful server submission and confirmation rendering are also distinct. The server may commit while the browser never displays the receipt.

### 4.7 Classification pipeline

M1 implements:

1. Validate the manifest and relevant fixture invariants.
2. Establish producer completeness and scoped observation limits.
3. Join actions, requests, validations, transitions, claims, and timings.
4. Evaluate authoritative step and task postconditions.
5. Identify the first unmet contract; mark downstream unreachable steps blocked.
6. Produce capability, violation, contradiction, and uncertainty findings.
7. Render a report with evidence references and explicit null recommendations.

M3 adds competing causal hypotheses, counterfactual execution, minimization, and reviewed fix matching.

The diagnostic engine must remain useful before sophisticated attribution exists. “History was never accepted; upload was consequently blocked; cause unknown” is a valid baseline diagnosis. Naming an unsupported internal selector defect is not.

---

## 5. Connector and execution contract

### 5.1 A subject is a configured mode

A subject descriptor records:

- planning ownership;
- observation channels;
- action grounding;
- browser or non-browser execution substrate;
- browser-state and learning-state policy;
- control boundary;
- recovery ownership;
- deployment, model, and browser identities.

Brand names alone are insufficient. Stagehand primitives, Browser Use’s goal loop, and circus-tent’s step executor do not consume identical native requests or provide identical assistance.

Comparison cohorts fix the task family, permitted interfaces, assistance track, environment, state policy, and budgets.

### 5.2 Internal interface

These are Hellscape interfaces, not invented subject endpoints.

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

A connector can drive the subject without guaranteeing task completion. Its correctness consists of faithful translation, bounded local behavior, and truthful observation.

### 5.3 Initial circus-tent binding

M1 includes a REST binding based on the audited surface:

- `/run` for explicit execution plans;
- `/extract` for eligible extraction tasks;
- `/health` and `/shards` for optional operational observations;
- terminal responses and authenticated callbacks for native results.

It does not invent:

- goal submission;
- `GET /runs/{id}`;
- native cancellation;
- fresh-context creation;
- context release;
- revision or artifact-download endpoints.

The binding creates a local handle before making the blocking-shaped `/run` request. A native run ID is attached only when actually received.

Response translation supports observed nullable fields and retains the original body as a restricted artifact. Schema divergence is reported without necessarily discarding otherwise interpretable results.

Callback handling:

- authenticates the raw body where a signing contract and key are configured;
- correlates the callback to the attempt;
- deduplicates delivery without discarding conflicting messages;
- records trace-correlation failure separately from signature validity;
- never substitutes a missing trace ID for the actual execution outcome.

MCP remains a later binding option. The recorded redirect is not proof that MCP is absent, and resolving it is not an M1 dependency.

### 5.4 Planning assistance

The task envelope remains goal-shaped and framework-independent. It contains:

- entry URL;
- goal and user-understandable success criteria;
- synthetic data and document references;
- permitted origins and interfaces;
- wall-time, action, observation, recovery, and model budgets;
- requested browser and learning-state policy.

It excludes control credentials, hidden field identities, feature schedules, private class maps, and expected failures.

For a step executor, the connector consumes a separately recorded canonical plan. That plan is derived from the public application, not fixture internals.

The assistance record includes planner identity, public observation inputs, preparation cost, plan hash, translation version, and any permitted online replanning.

Translation preserves action order, semantic targets, values, and retry policy. It does not add framework-specific sleeps, selector alternatives, or recovery actions to obtain success.

If a mapping is incomplete, the result is a connector limitation or `UNSUPPORTED_MAPPING`, not an invented subject capability or an automatic framework failure.

### 5.5 Bounded observation without pretending to cancel

Hellscape owns its deadline even when the subject does not.

At observation closure it:

1. stops issuing new commands;
2. records whether native cancellation was available and attempted;
3. records any connector transport close;
4. retains a bounded effect-observation and evidence-drain window;
5. seals the application’s mutation authority according to the manifest;
6. finalizes with execution state unknown unless stronger evidence exists.

Sealing fixture authority prevents future fixture commits. It does not prove that the subject stopped running.

Unresolved subject resources can quarantine that subject deployment or concurrency slot. This is operational containment, not a gate on Hellscape’s existence.

Late callbacks or observed requests are appended as late evidence. They produce a new analysis revision over a new journal prefix; they never rewrite an already published diagnostic silently.

---

## 6. Hostile SPA, experiment system, and adaptive destination

### 6.1 Application flow

Retain the eight-state workflow:

**LISTING → DETAIL → CONTACT → HISTORY → UPLOAD → IDENTITY → REVIEW → CONFIRMATION**

State names describe server milestones, not necessarily separate routes.

Core invariants:

- validation is bound to section, value revision, and generation;
- stale validation cannot authorize current progress;
- entering a section does not imply its data is already complete;
- identity receipt possession and server verification are distinct;
- submission requires authoritative stored data;
- a submission is committed at most once per application attempt;
- telemetry cannot mutate business state;
- confirmation rendering is recorded separately from commitment.

These invariants are not hostile features. They are fixture correctness.

### 6.2 Composition contract

Use a prebuilt SPA shell plus declarative, versioned composition manifests.

A feature pack contains:

- typed parameter domains;
- dependencies and exclusions;
- registered primitive recipes;
- human-completion or degradation contract;
- exposure and activation events;
- expected failure signatures;
- regression cases;
- asset and schema digests.

Manifests contain parameters and registered recipes, not arbitrary executable JavaScript. New browser primitives require reviewed frontend code. No runtime `eval`, downloaded executable feature code, or native plugin loading is part of the core.

Feature exposure follows:

**configured → rendered/armed → exposed → activated → recovered or unresolved**

Enabled-but-unexposed features receive no success or failure credit.

### 6.3 Feature catalog retained

The previous mechanisms remain the product’s intended experiment space. They are reorganized by the signal and behavior they challenge rather than by a circus-tent implementation assumption.

| Family | Retained mechanisms and principal bounds |
|---|---|
| **Structural traversal** | `shadow_dom`, `nested_shadow_dom`, `closed_shadow_root`, `same_origin_iframe`, `cross_origin_iframe`. Open-root coverage varies from none to all selected controls; nested depth is bounded; closed-root tasks retain a visible human path. |
| **DOM identity and rendering** | `dynamic_classes`, `node_replacement`, `async_routes`, `hydration_skeleton`, `content_visibility`, `virtualized_lists`, `asset_revision_skew`. Render generations and readiness receipts distinguish stale handles from missing observation. |
| **Semantics and layout** | `inconsistent_labels`, `icon_buttons`, `rtl_section`, `semantic_decoys`, `moving_fields`, `inert_sections`, `conditional_fields`, `repeater_reindex`. Inaccessible variants are labeled and excluded from inappropriate accessibility judgments. |
| **Native interaction** | `dnd_upload`, `upload_hidden_fallback`, `custom_controls`, `input_masks`, `interaction_overlays`, `before_unload_guard`. Upload fallback is an affordance parameter, not automatically increasing hostility. |
| **Validation and state** | `async_validation`, `validation_races`, `session_token_gate`, `reload_recovery`, `session_expiry`, `idp_verification`. Extra delay/race treatments are distinct from baseline validation correctness. |
| **Application network behavior** | `network_idle_trap`, `network_faults`, `slow_endpoints`, `redirect_on_submit`, `websocket_state`, `submit_ambiguity`. Faults have bounded recovery budgets; committed submissions are never duplicated to make retry behavior appear realistic. |
| **Transport disruption** | `connection_faults`, `websocket_faults`. Record matched, scheduled, fired, and observed effects separately. WebSocket application-message reorder is not TCP-byte reorder. |
| **Extraction and task relevance** | `extraction_ambiguity`, `instruction_decoys`. Hidden stale facts, visible ambiguity, and untrusted instructions are distinct treatments. All destinations and data remain local. |
| **Interaction-policy observation** | `honeypots`, `dom_fingerprint`, `behavioral_detection`. Structural mutations and behavioral anomalies are evidence, not automatic proof of maliciousness or general bot detection. |
| **Fingerprint policy** | `fingerprint_consistency`, `fingerprint_policy_simulation`. Real captured differences and synthetic detector inputs never share an evidentiary label. |
| **Challenge lifecycle** | `challenge.modes.*=simulated`, `challenge_orchestration`, local identity/challenge validators. Preserve interruption, expiry, rejection, and resumption tests. |
| **External compatibility** | `real_challenge_widgets` remains optional, unscored, and outside deterministic adaptive sessions. Deprecated `simulated_challenge` is an import alias, not another mechanism. |

The initial fast-campaign delay domains remain bounded, generally up to five seconds; longer waits belong to explicitly separate soak profiles.

Local challenge kinds can include hCaptcha-shaped mocks. `px` remains a simulated signature, not a fabricated vendor verifier. reCAPTCHA v3 is not included without a separate test contract.

Applicability depends on the configured subject mode. Class churn does not test a coordinate-only action path unless another consumed channel depends on those classes. A vision-based subject is nevertheless exposed to the network connection it uses.

### 6.4 Solvability and validity

The compiler rejects completion tasks that:

- hide a required control without a human path;
- require an observational-only mock to satisfy verification;
- permanently reject every required verifier;
- exceed their budget by construction;
- remove all recovery paths while requiring successful recovery;
- depend on a browser capability absent from the declared fixture environment.

Permanent rejection can still be a valid **graceful-degradation** experiment.

A fixture defect is not “extra hostility.” Undeclared failures invalidate the affected opportunity and must be repaired as fixture bugs.

### 6.5 Determinism and replay

The executable contract is:

\[
(S_{i+1}, O_i) = T(S_i, I_i, M)
\]

Identical manifest and identical ordered inputs produce identical semantic outputs.

The manifest pins build, task, feature packs, seed, policies, origins, budgets, and environment declarations. The journal records admitted external inputs, timing measurements, native observations, and lifecycle decisions.

Random derivation uses versioned, domain-separated HMAC-SHA-256. Semantic identifiers and feature draws are independent of unrelated feature activation. Runtime credentials and TLS randomness are not semantic identities.

Two operations remain distinct:

- **Exact fixture replay:** no browser or subject is invoked; recorded inputs reproduce state transitions and semantic outputs.
- **Live reproduction:** the same fixture manifest is presented to a new attempt; different subject behavior remains possible and is measured.

### 6.6 Adaptive loop and recommendations

The adaptive destination remains a deterministic capability-frontier search, not an opaque reinforcement-learning controller.

The loop:

1. reads a pinned finalized history prefix;
2. selects a task/configuration;
3. validates composition and budgets;
4. persists the manifest;
5. executes or admits manual operation;
6. observes and finalizes;
7. updates capability evidence and regression specimens;
8. explains the next decision.

Capability cells include subject revision, task, assistance track, environment, state policy, feature family, and parameter level.

Native absence is retained as a capability gap. It does not count as a successful graceful-degradation result merely because the harness contained the run. It also does not prevent unrelated capability families from being exercised.

Preserve the initial scheduling lanes: frontier progression, interaction coverage, regression/diagnosis, diverse exploration, and frozen sentinels. Promotion requires valid exposure, composition diversity, acceptable recovery cost, and no unresolved relevant regression.

Counterfactuals preserve unrelated semantic randomness. Minimization produces a reproducer that is minimal within the explored neighborhood, not necessarily globally minimal.

Fix recommendations use reviewed rules with evidence requirements, exclusions, scope, confidence, and verification plans. A suggestion is not evidence of implementation. A claimed future circus-tent fix remains a plan until a separately identified revision is evaluated.

---

## 7. Milestones, re-sequenced

**M0 is not a milestone in this plan.** Its historical documents and results are archived inputs. There is no replacement preflight milestone under another name.

| Milestone | Product output and acceptance | Scope change |
|---|---|---|
| **M1 — Cooperative SPA and diagnostic foundation** | Embedded cooperative SPA; authoritative eight-state workflow; durable journal; baseline diagnostic engine; generic connector and initial REST binding; exact fixture replay. **Acceptance is diagnostic correctness on manual operation, with no subject.** | Diagnostic semantics become larger and more explicit. Connector work becomes smaller than a success-producing orchestration layer: no hidden planner, recovery loop, or subject repair. |
| **M2 — First circus-tent use** | Run the actual SPA through the shipped connector and produce the first Hellscape diagnostic about circus-tent. Preserve assistance, native responses, measured timings, server effects, and requirement gaps. | Substantially smaller than the old M2 feature-development milestone. It is product use, not a requirement that circus-tent complete the workflow. |
| **M3 — Composable hostility and evidence-backed diagnosis** | Feature-pack runtime; baseline local hostile mechanisms; structural, semantic, interaction, validation, and recovery packs; causal timelines; counterfactual runner; minimizer; reviewed initial fix registry. | Larger: it absorbs the former M2 composition work. Some elementary diagnosis has moved earlier into M1, but that does not offset the added frontend/pack scope. Implement in bounded internal batches. |
| **M4 — Adaptive curriculum** | Deterministic lineages, capability frontiers, mastery gates, quotas, regression corpus, held-out selection, and decision replay. | Similar in spirit. Eligibility now distinguishes native absence, exposure, uncertainty, and functional results rather than treating successful completion as the only useful evidence. |
| **M5 — Transport and detection laboratory** | Production-quality embedded TLS/HTTP2 capture, connection/WebSocket faults, behavioral profiles, reference cohorts, and explicit policy gates. | Similar scope, with broader subject/environment cohorts. Capture conformance belongs here, not in a resurrected pre-M1 gate. |
| **M6 — Capacity, transfer, and hardening** | Parallel lineages, published workload benchmarks, soak/crash/resource testing, held-out families, paired revisions, and external benchmark-result adapters. | More explicit separation of engine capacity, subject throughput, and application completion. No milestone guarantees a particular subject’s success rate. |

### 7.1 M2 is an output milestone

M2 begins with the cooperative application. Its first document is useful even if circus-tent stops at the first interaction.

The initial M2 session set also includes the linked state observations needed to resolve the historical isolation signal: acknowledged A write/read, B read before overwrite, acknowledged B write, and return to A, using the actual SPA and the declared browser-state policy. Valid controls can confirm or refute the suspected sharing behavior for that scope. Failed controls yield an explicit indeterminate finding, not another design gate.

A separate lifecycle case can close the connector connection during exposed work and observe subsequent effects and reporting. It does not search for speculative endpoints.

No shadow-traversal conclusion is drawn from the zero-hostility first session. When a validated shadow treatment is introduced, inability to traverse it is another diagnostic result—not a reason to weaken the SPA. The same applies to cancellation absence and timing discrepancies.

M2 may uncover a connector or fixture defect. That warrants a repair against the existing contract, not an amendment requiring the subject to succeed.

### 7.2 Later acceptance remains product-owned

- **M3:** known fixture defects are not attributed to subjects; unknown causes produce uncertainty and null fixes; minimizers preserve the target signature.
- **M4:** independent recomputation selects identical manifests; scripted capability histories exercise promotion, regression, absence, and uncertainty paths.
- **M5:** capture matches independent references and declared algorithms; incomplete capture stays incomplete; fault effects are verified.
- **M6:** publish the measured throughput envelope, exclusions, resource use, and outcome distribution. A reference-load engine benchmark is not mislabeled as circus-tent throughput.

---

# Part II — M1 Implementation Blueprint

## 8. M1 deliverables and exclusions

M1 is a complete, independently useful product slice—not a mock waiting for a framework to make it meaningful.

### 8.1 Required deliverables

1. One Go binary serving the application and control surfaces.
2. Embedded cooperative SPA implementing the complete eight-state workflow.
3. Deterministic synthetic task and document fixtures.
4. Durable session admission, business transitions, event journal, and artifacts.
5. Server-authoritative outcome predicates.
6. Baseline diagnostic engine implementing the expanded distinctions in §4.
7. JSON and readable diagnostic output.
8. Manual-session operation and finalization.
9. Generic connector lifecycle and initial circus-tent REST binding.
10. Local connector contract tests with synthetic backends.
11. Exact fixture replay and semantic-output comparison.
12. Manual acceptance procedure and retained validation artifacts.

### 8.2 Explicitly excluded from M1

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

### 8.3 Suggested module structure

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

Synthetic native-response fixtures are labeled synthetic. The shape-only historical probe outputs are not misrepresented as complete captured native response bodies.

---

## 9. Cooperative application specification

### 9.1 Visible workflow and authoritative effects

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

The contact form remains on the detail view. CONTACT is the accepted-contact milestone, not an unnecessary separate page.

The identity control is a clearly labeled synthetic local action. It does not claim to perform real identity verification.

### 9.2 Frontend behavior

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

The SPA records readiness after the relevant controls are rendered and enabled. Network silence is not its readiness contract.

The baseline does not require autosave. Later autosave and WebSocket treatments can be introduced without changing the business reducer’s authority.

### 9.3 Business-state rules

Each accepted section has a value revision and validation generation. Edits invalidate dependent acceptance according to explicit dependency rules.

Required checks include:

- selected job exists;
- accepted contact and history are current;
- upload exists and its digest matches the stored artifact;
- identity receipt belongs to the attempt and relevant epoch;
- review refers to current accepted data;
- submission has not already committed.

An invalid history interval, for example, returns a validation rejection and leaves the workflow in HISTORY. It must not advance to UPLOAD.

Submission is idempotent. Repeating the same valid submission operation returns the same receipt. Reusing an operation key with different content returns a conflict.

### 9.4 Proposed application API

The application API is mounted within an opaque attempt binding, so a shared browser context cannot redirect writes through a global active-session variable.

| Operation | Purpose |
|---|---|
| `GET …/api/jobs` and `GET …/api/jobs/{id}` | Public synthetic job information. |
| `POST …/api/job-selection` | Select the task’s job. |
| `GET …/api/draft` | Recover the ordinary user-visible accepted draft. |
| `PUT …/api/contact` | Validate and accept contact data. |
| `POST …/api/history/enter` | Advance from accepted contact to history. |
| `PUT …/api/history` | Validate and accept history data. |
| `POST …/api/upload` | Accept a bounded synthetic document. |
| `POST …/api/identity/verify` | Issue and verify local session-bound identity evidence. |
| `POST …/api/review/validate` | Validate current review prerequisites. |
| `POST …/api/submit` | Commit the application idempotently. |
| `GET …/api/confirmation` | Return the ordinary confirmation receipt. |

These are Hellscape endpoints, not circus-tent endpoints.

Mutation requests carry operation identity and expected value/state revision. The server returns structured validation or conflict results. The frontend does not infer success merely from an HTTP connection completing.

Upload handling enforces a manifest-pinned size/type policy, stores only under the artifact root, and never executes uploaded content.

---

## 10. Journal, clocks, diagnostics, and connector implementation

### 10.1 Durable transaction boundary

SQLite runs in WAL mode with a durability configuration appropriate to acknowledged writes; M1 uses full synchronization rather than promising durability while relying on a weaker default.

A successful application operation commits, in one transaction:

- the admitted command;
- its operation/idempotency record;
- resulting authoritative state;
- emitted business events;
- the response representation needed for idempotent replay.

Only after commit does the engine acknowledge the transition or publish the new in-memory actor state.

This avoids the ambiguity of “log before effect” when the log and effect can diverge.

Large artifacts are written to a temporary file, hashed, flushed, and atomically installed before the transaction references them. A crash may leave an unreferenced artifact for garbage collection; it must not leave an acknowledged upload pointing at absent bytes.

### 10.2 Minimum durable tables

| Table/group | Contents |
|---|---|
| `sessions` | Manifest reference, mode, lifecycle, admission record, current journal head. |
| `manifests` | Immutable canonical manifest and digest. |
| `events` | Ordered session journal, producer sequence, provenance, causal references, payload version. |
| `operations` | Idempotency key, request digest, committed response, state transition references. |
| `application_state` | Authoritative materialized state and revision. |
| `connector_attempts` | Local handle, dispatch state, native identifiers, request/result references. |
| `capability_snapshots` | Scoped capability inventory and evidence provenance. |
| `artifacts` | Digests, sizes, types, access classification, retention state. |
| `diagnostic_revisions` | Immutable analysis documents and the exact journal prefix analyzed. |

A diagnostic is reproducible from its manifest, referenced evidence, journal prefix, and classifier version.

### 10.3 Event envelope

Every journal entry carries:

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

Core events include:

- session admission/start/end;
- component ready;
- observed input/click/change;
- request admitted/completed/rejected;
- validation accepted/rejected/superseded;
- workflow transition committed;
- upload stored;
- identity verified;
- submission committed;
- confirmation rendered;
- connector dispatch/result/transport close;
- native callback received/authenticated/rejected;
- deadline and observation closure;
- producer gap/flush/closure;
- fixture authority sealed.

High-rate telemetry is batched without destructive trailing debounce. M1 needs only a bounded subset sufficient for interaction and timing correctness; detailed pointer profiling is deferred.

### 10.4 Timing implementation

Use separate clock identities for:

- the engine process;
- each browser document producer;
- external/native reports;
- manual reference measurements.

Persist engine monotonic offsets relative to the process boot identity. Do not subtract monotonic values across restarts.

For the SPA’s persistent document, `performance.now()` can measure workflow intervals with explicit endpoints. Server receipt time is also retained, but telemetry delivery latency is not mistaken for the original event time.

M1 reports at least:

- session observation duration;
- each workflow step’s available ready-to-postcondition interval;
- each server operation’s admitted-to-commit interval;
- connector request duration when a connector is used;
- any censored or unavailable interval.

Human reading and pauses are included in workflow elapsed time. They are not described as framework primitive execution time.

### 10.5 Diagnostic reducer

The M1 analyzer is a deterministic function of the pinned inputs. It:

1. checks authoritative state consistency;
2. identifies completed and incomplete postconditions;
3. associates attempted actions with visible effects where evidence permits;
4. marks expected validation rejection separately from fixture failure;
5. retains recovery attempts rather than replacing them with the final success;
6. compares only semantically compatible claims;
7. emits native absence and indeterminate results as distinct types;
8. reports disabled analyses and missing evidence explicitly;
9. generates a readable timeline and summary from the structured result.

No classifier branch may use a default zero to mean missing duration, a default false to mean unknown completion, or an empty capability object to mean absence.

### 10.6 Connector implementation in M1

The connector is shipped code, not just an interface declaration.

It includes:

- durable local handles;
- bounded worker and connection ownership;
- request serialization and response normalization;
- capability snapshots;
- assistance and plan hashes;
- authenticated callback ingestion;
- transport-close handling;
- artifact missingness;
- timeout finalization;
- typed unsupported-operation responses.

Before external dispatch, the engine records the intended request and marks dispatch beginning. If the engine crashes around delivery, the attempt is recovered as dispatch-uncertain. It is not automatically retried with a new idempotency key.

Connector tests use local synthetic backends to cover:

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

These are M1 implementation tests, not renewed probes against circus-tent.

### 10.7 Finalization, restart, and late evidence

A durably admitted session is finalized after:

- normal manual completion;
- operator termination;
- deadline;
- launch/translation error;
- native terminal result;
- infrastructure interruption.

Evidence drain has a finite bound. Missing producer tails are recorded rather than awaited indefinitely.

On restart, M1:

- restores authoritative application state;
- marks unfinished observation sessions infrastructure-interrupted;
- does not assume a native run stopped;
- does not automatically replay side-effecting subject requests;
- generates an interrupted diagnostic when the store is available.

The promise is not that evidence survives destruction of the storage device. Storage failures are surfaced explicitly, admission stops when persistence cannot be trusted, and any unpersisted tail is not called complete.

### 10.8 Replay

M1 exact replay:

1. loads the pinned manifest;
2. consumes only recorded external inputs and lifecycle observations;
3. recomputes reducer outputs;
4. compares semantic event and final-state hashes;
5. recomputes the diagnostic with the pinned classifier.

Runtime credentials and locators are represented by stable semantic aliases. Recorded timing measurements remain inputs; replay does not sleep to reproduce elapsed time.

Replay invokes neither circus-tent nor a browser. It proves fixture consistency for the recorded input sequence, not repeatability of an unknown subject.

---

## 11. M1 control surface and build sequence

### 11.1 Minimal operator surface

M1 provides CLI or authenticated control operations for:

- creating a manual or connector session;
- retrieving its task and entry URL;
- starting connector dispatch;
- adding authenticated manual observation notes;
- ending observation;
- requesting native cancellation or connection closure as distinct operations;
- reading events, application state, and diagnostics;
- exporting and replaying a bundle.

Control mutations use idempotency keys. Manifests become immutable at admission.

A manual note can say “operator observed receipt X” or mark an interval. It cannot set an authoritative business predicate to passed.

The application browser need not hold control credentials. Operator controls run through a separate authenticated surface.

### 11.2 Implementation sequence—all inside M1

1. **Define schemas and golden contracts.**  
   Task, manifest, event, state, capability, diagnostic, and artifact schemas; canonicalization and clock conventions.

2. **Implement the application reducer.**  
   Eight states, validation generations, idempotency, submission predicates, and explicit negative paths.

3. **Implement persistence and admission.**  
   Atomic state/event commits, artifact storage, lifecycle records, and restart classification.

4. **Build the light-DOM SPA.**  
   Complete ordinary workflow, visible errors, native upload, local identity control, and receipt view.

5. **Add observation and baseline diagnostics.**  
   Producer sequencing, timing, postcondition evaluation, claim semantics, native-absence representation, and readable output.

6. **Implement connector lifecycle and REST binding.**  
   Exercise them against synthetic local backends, without contacting the live subject.

7. **Implement finalization and exact replay.**

8. **Run the manual integrated validation.**

Unit tests accompany implementation. The first end-to-end validation is the manual walkthrough after the application and observer exist. There is no preceding subject-qualification step.

### 11.3 Build and deployment constraints

M1’s build receipt records the exact Go toolchain, Go modules, frontend lockfile, schema versions, and asset digests. Dependency versions are selected and pinned during implementation rather than copied from unverified historical examples.

The runtime requires:

- the Hellscape binary;
- writable evidence storage;
- local application/control TLS configuration;
- an ordinary browser for manual validation.

No Node development server, database daemon, reverse-proxy capture process, model service, or circus-tent service is required for M1 acceptance.

M1 uses ordinary in-process TLS serving. The replaceable fingerprint-observer boundary exists, but fingerprint capture is disabled. Embedded fingerproxy remains a supported implementation direction for M5, subject to its production conformance, bounds, and concurrency tests. No unexecuted proof is reported as a passed result.

---

## 12. M1 validation and acceptance

### 12.1 Primary acceptance test

> **The diagnostic engine correctly characterizes a manual walkthrough of the SPA—steps succeed or fail as reported, durations reflect measured elapsed wall-clock time, and server state is consistent with what the walkthrough produced.**

This is entirely within M1’s control.

It validates the essential premise of every later subject run: if the engine cannot characterize a known manual trace, it cannot be trusted to characterize an unknown framework.

### 12.2 First integrated validation run

Create a fixed cooperative manifest and a synthetic task. Record the browser/environment declaration and start a **manual** session.

The operator then:

1. opens the task’s ordinary entry URL;
2. selects the specified job;
3. supplies valid contact information;
4. enters HISTORY;
5. submits an intentionally invalid history interval, such as an end date before its start date;
6. observes the ordinary validation error;
7. corrects the interval and saves;
8. uploads the supplied synthetic document;
9. performs the inline local identity action;
10. reviews the data;
11. pauses at a recorded checkpoint for an independently timed interval;
12. submits once;
13. observes the confirmation receipt;
14. ends observation and allows the bounded telemetry flush.

The deliberate invalid value is not hostility. It is an ordinary application error path exercised by the operator.

Expected diagnostic content:

- all intended final workflow postconditions are satisfied;
- the invalid history attempt is preserved as a rejected attempt;
- the history step is reported as recovered, with the correction visible;
- the validation rejection is not attributed to a framework;
- the pause appears in the appropriate measured workflow interval;
- one application is committed;
- accepted values and document digest match the task;
- identity verification has server provenance;
- confirmation rendering is separate from submission commitment;
- no native subject claim or duration is fabricated;
- R1–R10 are not credited to a nonexistent subject.

If the application unexpectedly cannot complete this ordinary path, M1 has a fixture defect to repair. Correctly diagnosing that defect is useful, but it does not remove the requirement that the cooperative SPA itself be usable.

### 12.3 Independent cross-checks

Avoid validating the diagnostic merely by comparing it with another view of the same unexamined reducer output.

Use three sources:

1. **The scripted manual procedure and observed UI results.**
2. **Persisted application rows, artifact digest, and operation count.**
3. **The diagnostic’s reconstructed timeline and predicates.**

Timing receives an additional independent reference: a monotonic stopwatch or local validation clock covering the same explicitly marked interval.

Acceptance tolerances are documented before the run:

- server intervals must equal their recorded endpoint differences within serialization resolution;
- browser intervals must use one producer clock;
- independent manual timing comparisons allow only the declared marker/measurement uncertainty;
- intervals lacking comparable endpoints are unavailable or bounded, not forced into agreement.

The check is not “the duration is nonzero.” It is that the measured interval has the claimed boundaries and agrees with an independent measurement at the declared precision.

### 12.4 Companion manual cases

After the first walkthrough, validate these bounded cases without an automation subject:

| Case | Required characterization |
|---|---|
| Stop before submission. | Application not completed at cutoff; no receipt; remaining steps unobserved or blocked as appropriate. |
| Repeat the submit action. | One committed application; repeated operation resolves to the existing receipt. |
| End observation with an incomplete field. | Honest partial outcome, not a fabricated field failure or success. |
| Close the browser before telemetry flush. | Authoritative server facts retained; missing client tail marked incomplete. |
| Restart the engine after an acknowledged operation. | Operation remains durable; interrupted observation is identified; no automatic duplicate action. |
| Replay the first walkthrough journal. | Identical semantic outputs and authoritative state; deterministic diagnostic reconstruction. |

These cases exercise M1’s own application and observation contracts. They do not reintroduce the M0 subject audit.

### 12.5 Acceptance checklist

M1 is accepted when:

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

### 12.6 First validation artifacts

The first run produces a bundle equivalent to:

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

These names describe planned outputs, not existing files.

The diagnostic is Hellscape’s first internally validated product output. M2 then produces the first output about an automation subject.

---

## 13. Operational risks and ownership

| Risk | Required treatment |
|---|---|
| **Subject continues after close.** | Record unknown execution state, observe within a bounded window, seal fixture effects, and quarantine unresolved resources. Never claim native cancellation. |
| **Harness containment masks the tested behavior.** | Record containment time and scope. Do not credit prevented writes as proof the subject stopped. |
| **Isolation is confused with fixture namespacing.** | Keep server records isolated while running R2 storage checks on the same relevant origin and declared context boundary. |
| **Native claims are overinterpreted.** | Preserve claim source and scope. Primitive success is not application completion. |
| **Timing comparison creates false accusations.** | Compare matching intervals or defensible bounds; retain queue/setup overhead and missing native timestamps. |
| **Observer traffic changes readiness.** | No perpetual telemetry polling in M1; bounded batching and explicit readiness. Measure overhead before behavioral claims. |
| **Fixture bugs are attributed to the subject.** | Validity-first diagnosis and independent manual controls. Repair fixture behavior rather than naming it hostility. |
| **Journal or disk pressure loses evidence.** | Bounded queues, admission backpressure, explicit incomplete status, and retention receipts. |
| **Framework revisions or assistance contaminate comparisons.** | Pin identities and assistance records. An unknown identity limits comparability, not basic diagnostic operation. |
| **Transport capture produces plausible but incomplete fingerprints.** | Defer scoring until M5 conformance; report missingness and capture invalidity explicitly. |
| **Curriculum optimizes for cheap failures.** | Fixed workload definitions, exposure requirements, lane quotas, and separate capability/functional/detection scorecards. |

Safety and containment rules protect the operator’s environment. They are not excuses to redefine a subject requirement as satisfied.

---

## 14. Delta from the previous Grand Design

This document replaces the previous design rather than appending amendments to it. The substantive changes are:

| Previous center of gravity | Rewritten design |
|---|---|
| A self-improving engine primarily for circus-tent. | An independently valuable SPA and diagnostic engine for configured browser-automation subjects. |
| Subject capabilities influenced what had to work before construction. | Capability gaps are findings. Hellscape’s own correctness governs construction and acceptance. |
| M0 contract audit as a proceed gate. | No M0 milestone. Historical findings inform schemas and tests; the plan starts at M1. |
| Cooperative slice associated with subject completion. | Cooperative describes zero fixture hostility. M1 acceptance is a manual diagnostic-correctness test. |
| Connector could drift toward making an executor complete the task. | Connector translates and observes; assistance is disclosed and does not become native capability. |
| Outcomes centered on success, failure, and detection. | Application truth, execution state, claims, native absence, violations, uncertainty, and containment are independent fields. |
| Cancellation handled mainly as an integration limitation. | Cancellation remains a subject requirement; native absence, behavior-on-close, and honest outcome-unknown reporting are explicit targets. |
| Isolation could become a prerequisite for clean campaigns. | Isolation is measured. Unsupported fresh-context controls and unconfirmed leakage are represented separately. |
| Native durations were available diagnostic enrichment. | Native timing is an untrusted report alongside independently measured wall-clock intervals. |
| M2 implemented the hostile catalog. | M2 is first real subject use. Composition work moves into a larger M3. |
| Early transport feasibility was load-bearing. | M1 uses ordinary TLS; production fingerprint capture is validated within M5. |
| Throughput risk could be read as a requirement that circus-tent succeed often enough. | Engine capacity, eligible experiment throughput, and business completion rates are published separately. |

Retained in substance: the eight-state application, native Web Components, the hostile feature space, single-binary deployment, durable evidence, deterministic fixture replay, local-only scored experiments, human-interactable configurations, causal diagnosis, reviewed fixes, adaptive coverage, and held-out transfer checks.

---

## 15. Readiness decision

**M1 is buildable now.**

Nothing in its acceptance criterion requires circus-tent to plan a goal, isolate browser state, report correct native durations, expose logs, support MCP successfully, or cancel an in-flight run.

Those are matters Hellscape can characterize once a subject arrives.

M1’s first validation run will produce a diagnostic of a manual cooperative walkthrough with:

- an observed validation rejection and correction;
- measured workflow and operation durations;
- exactly one authoritative application commitment;
- matching task data and document digest;
- a durable journal;
- explicit absence of subject evidence;
- a matching exact-replay receipt.

The required next work is implementation of M1, followed by that manual validation. There is no missing prerequisite that requires an earlier milestone or another probe phase.

**Build the SPA and its observer. Validate them together. Then let circus-tent come to the SPA, and report what it does.**