# Track 2.2 — Circus Tent (Camoufox) Boundary Seam Mapping Specification

## 1. Authority, Scope, and Reading Rules

### 1.1 Specification identity

| Property | Value |
|---|---|
| Specification | `circus-tent-seam-mapping` |
| Revision | `0.1.0` |
| Track | `2.2` |
| Implementation boundary | Python Circus Tent controller and Camoufox-specific binding |
| Evidence contract | `evidence-kernel/0.1.0` |
| Application lifecycle | `application-attempt-lifecycle/0.1.0` |
| External connector | `external-connector/0.1.0` |
| Internal binding | `internal-browser-binding.camoufox/0.1.0` |
| Initial native mapping basis | Documented Circus Tent REST API |
| Compatibility route | `legacy_playwright_juggler` |
| Proposed native route | `extension_native` |
| Status | Mapping specification; not implementation certification |

This document defines the complete boundary transformation. It incorporates the supplied schemas by their exact versions; it does not introduce alternative wire definitions for their types. Field inventories below specify how every record used at these seams is populated, validated, interpreted, and transitioned.

An implementation MUST pass structural validation and the applicable EK, LIFE, EXT, and CF semantic rules. Passing JSON Schema alone is insufficient.

### 1.2 Source precedence

1. Governing invariants in `full-featured-blueprints/1-handoff-brief.txt`.
2. Supplied Contracts 00–03.
3. `feature-inventories/circus-tent-feature-inventory.md`.
4. Implementation mechanisms specified here.

Contract 03 contains two independent YAML documents. This track uses only:

`urn:job-application:contracts:internal-browser-binding:camoufox:0.1.0`

BrowserOxide primitives, handles, thread rules, and representations are not Camoufox substitutes.

The inventory remains the product-feature baseline. Its numerical defaults and benchmarks are not automatically portfolio-wide constants. Conflicts with governing contracts are identified explicitly rather than silently resolved by weakening either requirement.

### 1.3 Evidence status

The supplied inventory is documentary evidence, not executable source or a current deployment observation. The supplied material does not establish:

- Complete deployed `/run`, `/extract`, MCP, and native step schemas.
- Callback signing, key distribution, or verification rules.
- A built Firefox extension, its transport, permissions, or API coverage.
- Native cancel, context-release, revision, or artifact-download endpoints.
- Current per-origin production receipt verification policies.
- Current-version benchmark results.

The mapping therefore distinguishes:

| Term | Meaning |
|---|---|
| Required | A contract or inventory obligation. |
| Documentary mapping | Supported by supplied descriptions, not current execution certification. |
| Unestablished mapping | Required native evidence or schema is unavailable. |
| Contract gap | The current closed schema cannot faithfully represent the desired operation. |
| Proposed mechanism | An implementation rule that preserves supplied contracts. |

An unestablished mapping causes explicit rejection, limitation, or missingness. It never authorizes a guessed endpoint, fabricated identity, assumed success, or inherited capability.

### 1.4 Architectural cut

The three boundaries remain separate:

1. **External connector:** asynchronous, task-shaped, browser-agnostic.
2. **Circus Tent controller:** plans, workflow steps, healing, extraction, budgets, scheduling, ledgers, and profile policy.
3. **Camoufox binding:** synchronous primitive calls with route-specific observations.

A synchronous primitive resolves to a return, error, or bounded uncertainty before dependent actions proceed. Internally awaiting a Firefox transport is permitted. Blocking the event loop that services that transport is not.

---

## 2. Seam and Ownership Register

| Seam | Source → destination | Allowed transfer | Prohibited inference |
|---|---|---|---|
| S01 Commission | Commissioner → connector | Manifest, commission, task, grants | Goal text is permission |
| S02 Description | Configuration authority → consumer | Descriptor, capabilities, mappings, limits | Declaration is qualification |
| S03 Preparation | Consumer → translator | Recorded plan and immutable inputs | Preparation may browse or improve the plan |
| S04 Start | Admission → dispatcher | Durable handle, request binding, intent | Local acceptance is native acceptance |
| S05 Native delivery | Dispatcher → REST/MCP | Exact authorized request | Native asynchronous polling exists |
| S06 Scheduling | API → fairness/cluster manager | Registered account and shard | `session_id` creates quota authority |
| S07 Primitive call | Controller → binding | One authorized `fx.*` request | Binding owns healing or workflow retries |
| S08 Page transport | Binding → Firefox | Pinned route-specific operation | Extension label proves bypass |
| S09 Reduction | Firefox → controller | Scoped reduced content and boundaries | Flattened text has global selector scope |
| S10 Models | Controller → LiteLLM/provider | Authorized healing/vision input | Model output is trusted browser authority |
| S11 Upload | Input resolver → binding | Authorized immutable bytes | Artifact reference permits arbitrary fetching |
| S12 Challenges | Controller → solver/browser | Authorized solve and injection mapping | Solved challenge proves application success |
| S13 Profiles | Cluster manager → process/storage | Fingerprint, profile, flush/exit evidence | Close acknowledgement proves process exit |
| S14 Reports | Native interface → verifier | Exact response/callback bytes | HTTP 200 proves completion |
| S15 Journal | Registered producer → authority | `EventSubmission` | Producer may assign provenance |
| S16 Observe | Journal projection → consumer | Prefix-bounded observations | Empty page proves termination |
| S17 Lifecycle | Axis owner → readers | Immutable revision | Whole-attempt status is writable |
| S18 Receipts | Collector → origin-fact recorder | Receipt observations | Connector may declare commitment |
| S19 Reconcile | Source publications → reconciler | Claims and facts | Reconciler may rewrite sources |
| S20 Artifacts | Artifact owner → consumer | Authorized digest-addressed content | Local capture establishes native download API |
| S21 Controls | Authorized caller → resource owner | Cancel, close, release, containment | Killing a process is cooperative cancellation |
| S22 Telemetry | Runtime → operations | Redacted logs, metrics, traces | Unjournaled telemetry is diagnostic evidence |

### 2.1 Lifecycle ownership

| Axis | Semantic authority | Circus Tent connector permission |
|---|---|---|
| `dispatch` | Connector | Bound publication writer |
| `observation` | Connector | Bound publication writer |
| `execution` | Subject | Faithful publication only under delegated writer authority |
| `application` | Origin | No connector write authority |
| `report` | Reconciler | No connector write authority |

Co-location does not combine grants. The report writer cannot hold execution/application write authority. Publication is owner-local, asynchronous, immutable, and versioned; no cross-owner transaction is required.

---

## 3. Shared Evidence Types and Hashing

### 3.1 Scalar and structural validation

| Type | Required interpretation |
|---|---|
| `Identifier` | Nonempty opaque string; spelling grants no authority or order. |
| `Revision` | Integer `0..9007199254740991`. |
| `PositiveInteger` | Integer `1..9007199254740991`. |
| `Digest` | `sha256:` and exactly 64 lowercase hexadecimal digits. |
| `EvidenceMap` | Recursively JSON-compatible evidence; normalized nulls use `Missing`. |
| Closed object | Reject unknown properties. |
| Numeric field | Reject non-finite or out-of-bounds values. |
| Date-time | Enforce format assertions. |
| URL/origin | Parse, normalize under policy, and authorize; format validity is insufficient. |

YAML decoding rejects duplicate keys. Unknown schema versions are rejected. Native bytes containing literal nulls remain artifacts until explicitly normalized.

### 3.2 Missingness

`Missing` fields are `value: null`, required `reason`, and optional nonempty `detail`.

| `NullReason` | Mapping |
|---|---|
| `not_enabled` | Facility deliberately disabled. |
| `not_applicable` | Field has no meaning in the declared scope. |
| `not_observed` | Value was not established. |
| `observation_lost` | Expected or previously available observation was lost. |
| `unsupported_by_subject` | Exact scoped native facility is evidenced absent. |
| `manual_override` | Authenticated journaled operator decision, preserving superseded evidence. |

Rules:

- Missing duration is not zero.
- Missing native state is not an explicit `"unknown"` subject claim.
- Unknown collection contents are not an empty array.
- Unmapped connector operation is not automatically `unsupported_by_subject`.
- Native `None` is not successful completion.
- Empty arrays mean established emptiness in the declared scope.
- Required unavailable fields contain `Missing`; they are not omitted.

### 3.3 Clocks and time points

`ClockDescriptor` fields:

- `clock_id`: registered clock.
- `boot_id`: its lifetime.
- `origin`: `engine_measured`, `browser_measured`, `subject_reported`, or `manual_reference`.
- `source_id`: actual source.
- `basis`: `monotonic_offset` or `opaque_report`.
- `unit`: `ms`.

`TimePoint` fields:

- `clock_id`, `boot_id`, `origin`: matching registered clock coordinates.
- `monotonic_offset_ms`: nonnegative offset.
- `utc_annotation`: valid date-time or `Missing`.

UTC is annotation only. A native UTC timestamp does not become a fabricated monotonic coordinate. Preserve it in native evidence and use missingness where a normalized source `TimePoint` is unavailable.

Connector restart, browser process restart, and browser document replacement create distinct relevant clock lifetimes. No subtraction crosses clock IDs or boots.

### 3.4 Measurements

Every `Measurement` contains:

| Field | Mapping |
|---|---|
| `measurement_id` | Unique immutable identity |
| `name` | Pinned semantic interval/scalar name |
| `scope` | `{kind, id}` for the actual run, call, step, primitive, resource, or operation |
| `quantity` | `duration` or `scalar` |
| `unit` | `ms` for duration; explicit scalar unit otherwise |
| `origin` | Actual measurement source |
| `clock_id`, `boot_id` | Registered source lifetime |
| `method` | `endpoint_difference`, `source_value`, `evidence_bound`, or `unavailable` |
| `start`, `end` | `TimePoint` or reasoned missingness |
| `estimate` | One discriminated variant below |
| `resolution` | Nonnegative granularity or missingness; not an invented tolerance |
| `censoring` | `none`, `left`, `right`, `both`, or `unavailable` |
| `comparability_group` | Semantic label or missingness; label alone proves no comparability |

| Estimate | Fields | Constraints |
|---|---|---|
| Exact | `kind: exact`, `value` | Duration nonnegative; censoring `none`; source value or same-clock endpoint difference |
| Bounded | `kind: bounded`, `lower_bound`, `upper_bound` | Each numeric or `Missing`; at least one numeric; ordered if both numeric; method `evidence_bound` |
| Unavailable | `kind: unavailable`, `value: Missing` | Method and censoring `unavailable` |

Endpoint differences require matching clock, boot, and origin; end is at least start; value equals end minus start.

Timing ownership:

- Independent connector timing: `engine_measured`.
- Circus Tent controller/binding timing: `subject_reported`.
- Browser-origin measurements: `browser_measured`.
- Human stopwatch/reference: `manual_reference`.

A native reported duration without native endpoints uses an opaque-report clock and `source_value`. Preserve exact zero. Never divide total runtime into invented step durations or compare unrelated intervals as a discrepancy.

### 3.5 References and artifacts

| Type | Fields and semantics |
|---|---|
| `EvidenceRef` | `journal_id`, positive `sequence`, `event_id`, `event_hash`, `pointer`; all resolve consistently |
| `JournalPrefix` | `journal_id`, positive `last_sequence`, `head_hash`; hash equals cutoff event |
| `ArtifactReference` | `digest`, `size_bytes`, `media_type`, `owner_domain`, `access: public | restricted` |
| `ArtifactSlot` | `name`, `expected_digest`, `content`, `evidence_refs`; known identity survives content loss |
| `VersionPin` | `id`, `version`, `artifact_digest` |
| `MeasurementEvidence` | `measurement`, nonempty `evidence_refs` matching the journaled measurement |

Artifacts are immutable and content-addressed. Possession of a reference grants no access. A resolver supplies an authorized locator.

Hashing uses `kernel-jcs-sha256/1`:

- Structured records: RFC 8785 canonical JSON.
- Artifact digest: exact stored bytes.
- Event digest: canonical event excluding only `event_hash`.
- Manifest/diagnostic: complete canonical record.
- Journal prefix digest: cutoff event hash.

Redaction creates a distinct artifact and derivation. Sanitized bytes cannot retain the original digest.

---

## 4. Identity, Descriptors, and Capabilities

### 4.1 Noninterchangeable identities

Keep separate:

- Connector `request_id`.
- Logical `idempotency_key`.
- Kernel `run_id`.
- Application `attempt_id`.
- Connector `local_handle`.
- Actually received `native_run_id`.
- Informational native `session_id`.
- Registered account.
- Persistent profile.
- Browser process generation.
- Tab/document/element lifetimes.
- Subject version.
- External native-interface mapping version.
- Internal Camoufox binding version.

The application execution descriptor’s `binding_version` names the external mapping, corresponding to `ConfigurationPin.binding.version`. Internal browser binding identity belongs in the subject stack.

### 4.2 Component and subject identity

`ComponentIdentity` contains `component`, `reported_version`, `build_digest`, and `configuration_digest`; unavailable version/digests use `Missing`.

`SubjectIdentity` contains:

| Field | Source |
|---|---|
| `subject_id` | Registered Circus Tent identity |
| `subject_version` | Immutable evidence-catalog version |
| `revision_basis` | `native_revision`, `source_digest`, `operator_attestation`, or `unknown` |
| `native_revision` | Actually observed revision or missingness |
| `configured_mode` | Exact configured execution mode |
| `interface_surface` | Exact native REST/MCP surface |
| `configuration_digest` | Complete non-secret effective configuration/reference identity |
| `stack` | Actual controller, browser, driver/extension, and relevant subsystem identities |

Documented Camoufox `0.5.7`, Crawl4AI `0.9.4`, and Python `3.14` are requirements, not proof of installed versions.

### 4.3 Capability records

`CapabilityRecord` fields are `capability_id`, `requirement_refs`, `availability`, `claim_origin`, `evidence`, and `limitations`.

- Availability: `present`, `absent`, `unknown`, `not_applicable`.
- Claim origin: `native`, `composed_subject`, `harness`.
- Evidence entries: `basis` and `ref`.
- Evidence basis: `documentation`, `executed_observation`, `source_diagnosis`, `operator_attestation`.

Every new version begins unknown. Non-unknown declarations require exact-scope journaled support. Documentation supports declarations, not run-success assessments.

`CapabilityDescriptor` contains `record_type`, kernel `schema_version`, `descriptor_id`, positive `descriptor_revision`, `declared_by`, `subject`, `catalog`, `evidence_prefix`, `supersedes`, and `capabilities`.

The complete pinned catalog appears exactly once. `supersedes` refers only within the same subject/version/mode/surface. No opportunity or result belongs in this descriptor.

### 4.4 Required catalogs

External minimum catalog:

| ID | Mapping limitation |
|---|---|
| `native_goal_task` | No native goal endpoint established |
| `native_plan_execution` | Documentary `/run` mapping; deployed schema required |
| `native_cancel` | No endpoint established |
| `native_context_release` | Internal tab closure is not external release |
| `native_artifact_retrieval` | Local retention is not native download |
| `native_revision` | Source/operator versioning is not a revision endpoint |
| `native_dom_access` | Route-scoped observation capability |
| `browser_state_isolation` | Domain separation does not prove account/tab isolation |
| `browser_state_persistence` | Profile/MFA persistence requires exact-version tests |
| `learning_state_control` | Cache reuse/reset/freeze must be independently established |

Camoufox minimum catalog:

`cf.extension_page_surface`, `cf.page_script_evaluation`, `cf.frame_observation`, `cf.open_shadow_observation`, `cf.closed_shadow_observation`, `cf.native_input`, `cf.synthetic_drag_drop`, `cf.native_file_input`, `cf.localized_capture`, `cf.profile_persistence`, `cf.fingerprint_persistence`, `cf.browser_context_isolation`, `cf.native_wait_termination`, `cf.profile_safe_shutdown`.

Mapped does not mean exercised. Unmapped does not mean natively absent.

### 4.5 Connector descriptor

`ConnectorDescriptor` fields:

| Field | Mapping |
|---|---|
| `record_type`, `schema_version` | `connector_descriptor`, external contract version |
| `connector_id`, `connector_version` | Configured connector identity/build version |
| `build`, `binding` | Immutable connector build and external mapping pins |
| `subject`, `capabilities` | Exact matching subject scope |
| `operations` | Exactly nine unique operation mappings |
| `task_mappings` | Unique by task type; only supported translations |
| `observation_channels` | Actual supported retained channels |
| `action_grounding` | Actual `semantic`, `recorded_selectors`, `coordinates`, `hybrid`, `not_applicable`, or `unknown` mode |
| `execution_substrate` | Actual `browser`, `non_browser`, `hybrid`, or `unknown` |
| `limits` | Configured finite limits |
| `budget_accounting` | Pinned accounting policy |
| `evidence_prefix` | Supporting prefix |

`OperationMapping` contains `operation`, `implementation`, `native_contract`, `capability_refs`, `evidence_refs`, and `limitations`. Implementation is `connector_local`, `native_mapping`, or `unmapped`. Native mappings require actual contract pins and evidence.

`TaskMapping` contains `task_type`, `input_form`, `mapping`, `planning_owner`, `recovery_owner`, and `limitations`. Initial application input is `recorded_plan`, not `goal`. Extraction uses `extraction_request`. Discovery is advertised only with a complete discovery/output mapping.

`ConnectorLimits` contains `max_call_wait`, `max_observe_items`, `max_request_bytes`, `max_response_bytes`, `max_artifact_chunk_bytes`, `max_queued_tasks`, and `max_active_tasks`. Native shard defaults do not substitute for these limits.

---

## 5. External Connector Operations and Task Preparation

### 5.1 Carrier

The proposed carrier is UTF-8 JSON over `POST /connector`; its address is deployment-configured. It does not inherit native `127.0.0.1:8000`.

The native API remains `/run`, `/extract`, `/health`, `/shards`, `/metrics`, and Streamable HTTP MCP at `/mcp`. No WebSocket or invented `/runs/{id}` polling endpoint is introduced.

`ConnectorRequest` fields are `record_type: connector_request`, external `schema_version`, `request_id`, `connector_id`, `operation`, `call_limit`, and operation-specific `payload`.

`ConnectorResponse` fields are `record_type: connector_response`, external `schema_version`, matching `request_id`, `connector_id`, `operation`, and typed `result`.

Authentication comes from the channel. IDs, digests, trace headers, account labels, and artifact references are not credentials.

### 5.2 Nine verbs

| Verb | Mapping | Result |
|---|---|---|
| `Describe` | Read registered configuration; no probe/browser launch | `ConnectorDescriptor` |
| `Prepare` | Validate and serialize supplied inputs; no execution | `PrepareResult` |
| `Start` | Durable local admission; dispatch `/run` or eligible `/extract` separately | `StartResult` |
| `Observe` | Journal-backed bounded pull; no native polling required | `ObservationPage` |
| `RequestNativeCancel` | Only evidenced native mapping; otherwise unsupported control observation | `ControlReceipt` |
| `CloseObservationConnection` | Close owned native transport; optionally request local finalization | `ControlReceipt` |
| `CollectArtifacts` | Authorized retained inventory/bytes; optional evidenced native retrieval | `ArtifactInventory` or `ArtifactChunk` |
| `ReleaseNativeContext` | Only evidenced native release; no guessed profile reset | `ControlReceipt` |
| `Contain` | Installed reviewed resource policy under separate authority | `ControlReceipt` |

Every verb has a handler even if its native mapping is unavailable.

### 5.3 Scope and configuration

`WorkScope` fields:

- `activity`
- `run_id`
- `journal_id`
- `manifest_hash`
- `admission_ref`
- `attempt`
- `commission`
- `commission_ref`
- `authorization_refs`
- `observation_policy`

Application work uses `activity: application_attempt`, exact commissioned attempt, commission artifact/reference, and subject execution mode.

Extraction/discovery uses `activity: discovery`; attempt and commission fields are `Missing(not_applicable)`. No application lifecycle is fabricated. Synthetic conformance preserves synthetic evidence scope.

`ConfigurationPin` contains `connector_id`, `connector_version`, `binding`, `subject`, `descriptor`, and `descriptor_ref`; all copied values must match resolved descriptor bytes.

### 5.4 Task envelope

| Field | Mapping |
|---|---|
| `record_type`, `schema_version` | `connector_task`, external version |
| `task_id` | Immutable task identity |
| `task_type` | `apply`, `extract`, or `discover_jobs` |
| `entry` | `logical_id` and authorized HTTP(S) `url`, without userinfo |
| `goal` | Commissioned objective; not authorization for hidden planning |
| `success_criteria` | Unique `criterion_id` and `description`; no satisfied predicates |
| `inputs` | Unique `name`, `purpose`, immutable `content` artifact |
| `permitted_origins` | Unique logical identities and canonical origins |
| `permitted_interfaces` | `ordinary_browser` and/or `read_only_acquisition` |
| `effect_policy` | `commissioned_application` for apply; `read_only` otherwise |
| `budgets` | Complete finite task budgets |
| `context_policy` | Independent browser and learning policies |
| `output_schema` | Pin or permitted missingness; required pin for extraction/discovery |

`apply` requires `ordinary_browser` and application scope. Extraction/discovery cannot perform application mutations through plan text, redirects, evaluation, or nominally read-only HTTP methods.

No external `steps`, `selector`, `account`, `session_id`, or `callback_url` field is added. These belong to pinned plans, mappings, runtime bindings, or connector configuration.

### 5.5 Assistance and runtime access

`AssistanceRecord` contains:

- `planning_owner`: subject, external planner, operator, or none.
- `assistance_track`.
- `planner_identity`.
- `plan`.
- `online_replanning`.
- `description`.

Recorded-plan mappings require an immutable plan and public-observation planning provenance. Native healing is disclosed subject recovery, not hidden connector planning.

`RuntimeAccess` contains `purpose`, `access_ref`, and `authorization_refs`. Purpose is `application_entry`, `account_session`, or `input_artifact`. References resolve only under the authenticated principal and commissioned target; they contain no secret bytes.

### 5.6 Native field transformation

| Native concern | Source |
|---|---|
| Domain/shard | Authorized entry and pinned declaration-order routing |
| Steps | Exact recorded plan validated against pinned native step schema |
| Account | Registered authorized account-session reference |
| Session label | Informational mapping value; never quota identity |
| Idempotency key | Application commission key, available before preparation |
| Callback URL | Configured authorized destination pinned during preparation |
| Extract URL | Authorized task entry or explicitly mapped input |
| Query | Explicit extraction input under the mapping; not guessed from prose |
| Extraction schema | Pinned schema artifact |
| Raw HTML | Authorized immutable input artifact |
| Credentials/signatures | Runtime bindings outside retained ordinary request bytes |

A raw-HTML task still requires a truthful authorized `TaskEnvelope.entry`. Without one, reject the current shape rather than fabricate a URL.

MCP is a separate native mapping. REST evidence does not establish MCP tool parity.

### 5.7 Prepare restrictions and result

`PrepareRequest` contains `scope`, `configuration`, `task`, `assistance`, `planning_evidence_refs`, `preparation_measurements`, and `runtime_access`.

Preparation MUST NOT navigate, preflight authentication, open/reset a browser, clear caches, solve a challenge, invoke models, improve plans, insert waits/retries/selectors, or probe speculative endpoints.

`PreparedTask` contains:

`record_type: connector_preparation`, `schema_version`, `preparation_id`, `scope`, `configuration`, `task`, `task_semantic_hash`, `assistance`, `planning_evidence_refs`, `runtime_access`, `delivered_task`, `delivered_task_hash`, `native_request`, `native_request_hash`, `translation`, `budget_mapping`, `concerns`, `evidence_prefix`.

The native and delivered hashes identify exact retained bytes. Runtime credentials are excluded; runtime resolution cannot change semantics, values, destinations, or permissions.

The task semantic hash removes `task_id`, replaces `entry.url` with its logical ID, and replaces each permitted origin with its logical ID. Everything else, including array order, remains. Equal semantic hashes do not authorize destination changes.

`PreparationReference` contains `preparation_id`, `artifact`, and `registration_ref`. `PrepareResult` contains `kind: prepared`, `preparation`, and complete `record`. Artifact bytes precede registration.

### 5.8 Budgets and concerns

`TaskBudgets` contains `active_limit`, `action_limit`, `observation_byte_limit`, `recovery_limit`, and `model_token_limit`. Active limit equals the admitted observation limit.

Exactly five `BudgetMapping` entries identify `dimension`, `enforcer`, `evidence_refs`, and `limitations`:

| Dimension | Required treatment |
|---|---|
| `active_observation` | Connector-enforced; accepted queue time consumes it |
| `action_count` | Explicit counting and evidenced native enforcement, or disclosed gap |
| `observation_bytes` | Bounded connector storage/projection; native-private memory is separate |
| `recovery_count` | Accounts for actual controller recovery policy |
| `model_tokens` | Task-level enforcement; daily shard/session caps are insufficient alone |

Enforcer is `connector`, `subject`, `not_enforced`, or `not_applicable`. Zero is an actual limit. Required unenforceable policies reject preparation.

`PreparationConcern` contains `concern_id`, `category`, `disposition`, `detail`, and `evidence_refs`. Categories are exactly `native_capability_absent`, `native_capability_unknown`, `budget_not_enforced`, `state_policy_unverified`, `assistance_limit`, `observation_limit`. Disposition is `requires_acceptance` or `informational`.

Blocking permission/translation/state-policy failures are errors, not accepted concerns. Missing cancellation alone is not a universal blocker.

### 5.9 State policy

`ContextPolicy` contains `browser_state` and `learning_state`. Each `StatePolicy` contains `mode`, `requirement`, `resource_ref`, and `baseline`.

- Browser modes: `fresh`, `reuse`, `subject_default`, `not_applicable`.
- Learning additionally supports `frozen`.
- Requirement: `required` or `best_effort`.

Reuse requires authorized resource identity. New tabs do not establish freshness or isolation. Fresh browser state does not clear learning. Frozen learning requires suppressing cache writes and background revalidation mutations. Unsupported required policies reject preparation; accepted best-effort limits are disclosed before Start.

---

## 6. Start, Dispatch, Checkpoints, and Idempotency

### 6.1 Start records

`StartRequest` contains `preparation`, `idempotency_key`, `accepted_concern_ids`, `authorization_refs`, and `recovery`.

Initial recovery is `Missing(not_applicable)`. Required concern IDs must all be accepted; nonexistent IDs are rejected.

`ConnectorHandle` contains `record_type: connector_handle`, external `schema_version`, `handle`, `preparation`, `scope`, `idempotency_key`, and `created_at`.

`HandleReference` contains `connector_id` and `local_handle`. It is not a native run ID.

`StartResult` contains `kind: start_receipt`, `disposition`, `handle`, `handle_artifact`, and `receipt_ref`. Disposition is `accepted_locally`, `existing_handle`, or `resume_authorized`.

### 6.2 Atomic local admission

Before native delivery, durably commit:

- Command identity and exact request comparison value.
- Logical execution association.
- Immutable handle/preparation binding.
- Admission/queue decision.
- Dispatch intent.
- Replayable receipt.
- Journal evidence.

Install referenced artifacts before commit. Native delivery occurs afterward. No transaction includes the native service or employer.

Cross-executor duplicate prevention uses the commission authority’s single execution authorization; executors cannot self-authorize additional logical executions.

### 6.3 Idempotency layers

| Key | Behavior |
|---|---|
| Principal, connector, request ID | Identical command returns retained receipt; changed request conflicts |
| Principal, connector, Start key | Same immutable preparation/commission returns same handle |
| Commission execution authorization | Cannot gain second execution through another key, caller, or executor |
| Native key/request identity | Governed by evidenced native ledger semantics |
| Logical run and side-effecting step | Completed side effects never re-execute |
| Producer ID/sequence | Identical duplicates deduplicate; conflicting duplicates are integrity incidents |
| Native message ID, when established | Preserve repeat/conflict distinctions |

Repeated Start is not native resend. Lease expiry is not safe retry evidence.

### 6.4 Dispatch transitions and fields

| From | Allowed next |
|---|---|
| Unpublished | `not_started`, `prepared`, `rejected` |
| `not_started` | `prepared`, `rejected` |
| `prepared` | `dispatching`, `rejected` |
| `dispatching` | `accepted`, `rejected`, `uncertain` |
| `uncertain` | `uncertain`, `accepted`, `rejected` |
| `accepted` | `accepted` |
| `rejected` | `rejected` |

`DispatchValue` contains `state`, `local_handle`, `native_run_id`, `request_digest`, `delivery_refs`, `acceptance_refs`, `recovery_authorization_refs`, and `reason`.

- Prepared requires request digest.
- Dispatching/accepted/uncertain require handle, digest, and delivery evidence.
- Accepted requires correlated native acceptance/result evidence.
- Not-started has no native ID, delivery refs, or acceptance refs.
- Rejection after possible delivery requires evidence of non-acceptance.
- Same-state revisions add evidence, never authorize another logical execution.

A native preflight failure may still prove request acceptance. HTTP 429 proves rejection only if the pinned native semantics establish non-acceptance.

### 6.5 Crash boundaries

| Boundary | Required recovery |
|---|---|
| Before durable admission | No acknowledged start and no native delivery |
| Admitted, not yet delivered | Recover same handle and bounded queue |
| Intent persisted, send uncertain | Preserve uncertainty unless no-send evidence exists |
| Sent, response lost | No new key or automatic resend |
| Raw response retained, normalization interrupted | Normalize retained bytes only |
| Side effect sent, ledger completion absent | Fence duplicate action; reconcile uncertainty |
| Checkpoint durable, response lost | Recover retained checkpoint evidence |
| Publication/callback delivery failed | Retry publication only, not workflow |

### 6.6 Checkpoint mapping

Native checkpoint fields:

- `step_index`: last completed index.
- `extracted_form_values`: restricted, secret-filtered checkpoint values.
- `url`: authorized checkpoint destination.
- `shard`: same bound shard.
- `profile`: same persistent profile identity.
- Ledger key: same logical/native idempotency association.

`ResumeAuthorization` contains `handle`, `checkpoint`, `native_resume_contract`, `authorization_refs`, and `evidence_refs`.

Resume requires new command identity, existing logical key, exact request/context, evidenced native recovery semantics, remaining budgets, open observation, and explicit recovery authority. Completed side effects remain skipped.

The inventory does not establish a checkpoint retrieval endpoint. Without actual checkpoint evidence and retrieval mapping, resume is unsupported. Draining/closed observation or changed context rejects resume. An uncertain side effect cannot be repaired by switching executors.

---

## 7. Camoufox Route, Descriptor, and Live Token Lifetimes

### 7.1 Route and descriptor

`CFRoute` contains `path`, `extension_build`, `channel_contract`, and `bridge_components`.

| Route | Requirements |
|---|---|
| `legacy_playwright_juggler` | Extension build inapplicable; bridge list explicitly identifies Playwright and Juggler |
| `extension_native` | Pinned extension build/channel; bridge list empty; page operations bypass Playwright/Juggler |

No undocumented extension transport or privilege is assumed.

`CFBindingDescriptor` contains `record_type: camoufox_binding_descriptor`, Camoufox `schema_version`, `binding_id`, `controller_build`, `browser`, `route`, `capabilities`, `primitive_mappings`, `profile_policy`, `max_tabs_per_profile`, `privacy_policy`, and `evidence_prefix`.

Exactly 13 `CFMapping` entries contain `operation`, `execution_place`, `native_symbol`, `native_contract`, and `evidence_refs`.

Execution place is `controller_lifecycle`, `firefox_extension`, `legacy_juggler`, or `unmapped`. Controller lifecycle is permitted only for profile open/flush-exit. Other mapped operations follow the declared page route.

Route changes require a new scoped binding/subject configuration. They cannot occur silently within a commissioned execution.

### 7.2 Tokens

| Type | Fields |
|---|---|
| `CFProfileRef` | `profile_id`, `domain_family`, `process_id`, `process_generation`, `controller_lifetime`, `fingerprint_digest` |
| `CFTabRef` | `profile`, `browsing_context_id`, `tab_epoch` |
| `CFDocumentRef` | `tab`, `frame_context_id`, `document_epoch` |
| `CFTargetRef` | `document`, `node_token`, `element_epoch` |

Legacy `Page`, `Frame`, and element objects are registered under these identities but never serialized as shared handles. Deserializing a token creates no native object and grants no authority.

A cached selector is not a target token. A locator re-resolving to a replacement node cannot silently preserve an old element epoch.

### 7.3 Invalidation transitions

| Event | Required invalidation |
|---|---|
| Tab open | New tab epoch; document registered when observed |
| Cross-document navigation | Old document and its targets invalid |
| Frame navigation/detach | Affected frame document and descendants invalid |
| SPA node replacement | Replaced target invalid; document may remain current |
| Tab close | Tab, documents, targets invalid |
| Browser exit | All tokens for process generation invalid |
| Same-profile recycle | Profile/fingerprint retained; new process generation and live tokens |
| Full profile reset | Old identity/session binding invalid; explicit reauthentication |
| Route change | Old route registry and tokens invalid |
| Controller lifetime loss | Registry tokens unusable until explicitly re-established |

Stale references are rejected before input. The binding does not silently act on a replacement target.

---

## 8. Complete Primitive Request/Reply Mapping

### 8.1 Transcript and failures

`CFPrimitiveTranscript` contains:

`record_type: camoufox_primitive_transcript`, `schema_version`, `binding_digest`, `call_id`, `route`, `operation`, `authorization_ref`, `wait_limit`, `request`, `reply`, `measurements`, `route_evidence_refs`, `effect_refs`.

At least one measurement records the controller interval or its unavailability. Its origin is `subject_reported`, scope is `native_primitive`, and scope ID equals `call_id`. Browser measurements retain separate clocks.

`CFReturned` contains `kind: returned` and typed `data`; returned is not semantic success.

`CFFailure` contains:

- `kind`: `errored`, `unsupported`, `uncertain`.
- `code`: `STALE_DOCUMENT`, `STALE_TARGET`, `PROFILE_BUSY`, `INVALID_INPUT`, `UNAUTHORIZED`, `UNMAPPED_OPERATION`, `NATIVE_ERROR`, `NATIVE_TIMEOUT`, `LOCAL_WAIT_EXPIRED`, `TRANSPORT_LOST`, `BROWSER_EXITED`, `RESPONSE_LIMIT`.
- `delivery`: `not_sent`, `sent`, `unknown`.
- `native_error`: artifact or `Missing`.
- `detail`: sanitized explanation.

Local expiry or transport loss after possible delivery retains effect uncertainty. Native timeout requires native evidence. Empty effect references do not prove no effect.

### 8.2 Primitive matrix

| Primitive | Complete request fields | Complete returned data | Boundary rules |
|---|---|---|---|
| `fx.profile_open` | `profile_id`, `domain_family`, `fingerprint`, `storage_binding`, `launch_options`, `prior_exit_ref` | `profile`, `launch_refs`, `fingerprint_observations` | Provision fingerprint first; absent prior exit legal only for registry-verified never-launched profile |
| `fx.tab_open` | `profile` | `CFTabRef` | Permits already held; no hidden navigation or reset |
| `fx.navigate` | `tab`, `url`, `navigation_policy` | `document`, `native_response`, `final_url` | Authorized redirects; navigation return is not readiness/authentication |
| `fx.context_tree` | `tab` | `tab`, `boundaries`, `completeness`, `limitations` | Preserve inaccessible boundaries |
| `fx.reduce_document` | `document`, `reduction_profile`, `byte_budget`, `include_frames`, `root_access` | `CFReduction` | Browser-side bounded reduction; no model call |
| `fx.resolve_target` | `document`, `root_path`, `strategy`, `query`, `exact`, `max_matches` | `matches`, `completeness`, `limitation` | One strategy; no hidden first-match action |
| `fx.input` | `target`, `mechanism`, `action` | `CFInputReply` | One explicit action; mechanism cannot silently change |
| `fx.upload` | `target`, `method`, `files`, `event_recipe` | `CFInputReply` | Validate file authority, identity, size, MIME |
| `fx.evaluate` | `document`, `world`, `script`, `argument` | `representation`, `value` | Authorized script/world only; not an escape hatch |
| `fx.await_condition` | `document`, `read_only_predicate`, `wait_mapping` | `document`, `predicate_value`, `observation` | Scoped explicit condition; local timeout is not native stop |
| `fx.capture_crop` | `document`, `crop`, `layout_evidence_refs` | `document`, `image`, `geometry` | Current localized geometry; no silent full viewport |
| `fx.tab_close` | `tab` | `tab`, `close_refs` | Not profile flush, process exit, cancel, or rollback |
| `fx.profile_flush_exit` | `profile` | `profile`, `flush_ref`, `process_exit_ref` | Requires actual flush and OS exit/reaping evidence |

### 8.3 Nested structures

`CFBoundary` contains `boundary_id`, `parent_boundary_id`, `kind`, `document`, `access`, `marker`, and `limitation`.

- Kind: `top_document`, `frame`, `open_shadow`, `closed_shadow`.
- Access: `readable`, `unreadable`, `unobserved`.
- Unreadable/unobserved requires limitation.
- Missing access does not erase a known boundary.

`CFReduction` contains `record_type: camoufox_dom_reduction`, Camoufox `schema_version`, `document`, `reduction_profile`, `sections`, `boundaries`, `completeness`, and `limitations`.

Each section contains `document`, `boundary_id`, `text`. IDs resolve and preserve scope. Completeness describes the declared reduction, not lossless HTML. Budget excess yields explicit partial output or size error.

Reduction profiles are `EXTRACT` and `HEAL`; root access is `open_only` or `privileged_if_proven`.

`CFRootHop` contains `host_selector` and `access: open | privileged_closed`. Closed access requires exact-route evidence and authority.

Resolution strategies are only `css`, `role`, `label`, `text`. Empty complete matches means no match for that lookup. Partial matches cannot establish uniqueness.

`CFInputAction` variants:

| Kind | Fields |
|---|---|
| `fill` | `kind`, `text: ArtifactReference` |
| `click` | `kind`, `button: primary | secondary` |
| `select` | `kind`, `values: string array` |
| `press` | `kind`, `key` |

Mechanism is `native_browser_input` or `dom_property_and_events`.

`CFInputReply` contains `target`, `native_return`, `observed_events`, `effect_observation`, `event_trust`. Event trust is `browser_trusted`, `synthetic`, `unknown`, or `not_applicable`, supported by observation rather than request intent.

Upload method is `native_file_input` or `synthetic_drag_drop`. Synthetic upload requires a pinned recipe; native input uses inapplicable recipe.

Evaluation world is `page`, `extension_isolated`, or `privileged`. Evaluation reply representation is `json`, `text`, `bytes`, `unserializable`, or `unit`. Native unit/None remains non-success evidence.

`CFCropRequest` contains nonnegative `x`, nonnegative `y`, positive `width`, positive `height`, and `unit: css_px`.

Capture geometry is `Measurement[]` naming actual crop origin, viewport/image dimensions, frame offsets, and scale. Unavailable geometry is unavailable measurement, not zero/unit-scale defaults. An image without geometry cannot authorize coordinate action.

---

## 9. Workflow, Healing, and Cache Transformation

### 9.1 Step mapping

| Native step | Binding/controller mapping |
|---|---|
| `navigate` | `fx.navigate`; explicit readiness/challenge checks afterward |
| `fill` | Resolve current target, then `fx.input(fill)` |
| `click` | Resolve current target, then `fx.input(click)` |
| `select` | Resolve current target, then `fx.input(select)` |
| `wait` | Explicit `fx.await_condition` or pinned controller wait semantics |
| `extract` | Readiness, reduction, deterministic controller extraction |
| `assert` | Read-only observation plus controller assertion contract |
| `upload` | Resolve target, then explicit `fx.upload` method |
| `checkpoint` | Controller ledger commit using observed URL/form state |

The controller, not the binding, owns tiers, retries, models, checkpoints, side-effect fencing, and task semantics.

Preflight runs after Start and before workflow actions. It navigates to the configured preflight URL and observes the configured authenticated marker. Failure emits `SESSION_EXPIRED` native evidence and `session_expired`; it is not an origin fact.

### 9.2 Local execution states

These are controller states, not additions to shared enums.

| State | Permitted continuation |
|---|---|
| Pending | Resolve, skip from durable completed ledger, or block |
| Resolving | Ready, text heal, fail, or block |
| Ready | Persist intent, fail, or block |
| Intent recorded | Send/await return or record uncertainty |
| Awaiting return | Postcondition check, fail, or uncertainty |
| Postcondition check | Complete, safe recovery, fail, or uncertainty |
| Text heal | Resolve healed selector, one semantic retry, vision preparation, fail, or block |
| Vision preparation | Cache validation, model localization, fail, or block |
| Vision action ready | Authorized representable action or block |
| Uncertain | Reconcile with new evidence; never automatic duplicate side effect |
| Completed | Terminal for the step |
| Failed | Terminal unless explicit authorized workflow recovery applies |
| Blocked | Remains blocked or authorized continuation within open budget |
| Skipped from ledger | Terminal for this invocation; prior completion retained |

Resolution failure before action delivery can heal. Errors after possible side-effect delivery cannot blindly retry. The controller must establish no-send, safe repeatability, or explicit recovery authority; otherwise it fences the step.

### 9.3 Tier 1

Selector cache fields are `domain`, native format `version`, file `last_verified`, and `steps`. Each step has `selector`, `strategy`, `confidence`, `hit_count`, `heal_count`, `fallback_text`, `last_verified`, and `stale`.

The prose additionally requires `schema_version: 1`, while the example omits it. A pinned cache schema/migration must reconcile this; the loader cannot silently alias `version` and `schema_version`.

Selectors resolve in the current document/root scope. Cache confidence is metadata, not independent correctness probability.

Success increments hit count and updates verification metadata under a durable cache policy. Background revalidation and stale demotion are learning-state mutations and must respect frozen-state requests.

The documented exception names require validation against actual driver classes. The inventory alone does not prove every named exception exists.

### 9.4 Tier 2

The controller retains:

1. Failed selector/attempt evidence.
2. `HEAL` reduction and its completeness.
3. Fallback text and exact prompt.
4. Model/configuration/budget authorization.
5. Raw model response.
6. JSON parsing/repair derivation.
7. Recovered selector validation.
8. Actual action attempt and result.
9. Cache update.

Heal output fields are `selector`, `strategy`, `confidence`, `reason`. JSON repair uses the documented parser/repair pipeline before the one semantic retry. Repair never overwrites original response bytes.

The documented Muse 1.3 primary and Muse 1.2 timeout/5xx fallback are configuration pins. Every call uses LiteLLM, required User-Agent, and stable `x-opencode-session`. Provider failover and semantic action retry are separate accounting events.

Healed selectors are written back only after successful validation/execution. Confidence decrement magnitude must be specified in the pinned policy; no numeric decrement is supplied by the inventory.

### 9.5 Selector strategy gap

The native healing vocabulary includes `xpath` and `testid`, but `CFResolveTarget` does not.

- Test-ID may map to CSS only through a pinned equivalence-preserving attribute/escaping rule.
- XPath cannot be silently relabeled or implemented through an unrecorded evaluation escape.
- Unsupported strategy yields explicit mapping failure or a versioned contract revision.
- Multiple matches never imply permission to click the first.

### 9.6 Tier 3 and coordinate gap

Preserve localized failing-container capture with documented 100 px padding, current crop geometry, dHash lookup, and vision on eligible cache miss. Capture clipping is recorded; invalid negative crop coordinates are not serialized.

Coordinate cache fields are `domain`, `entries`, hash key, `x`, `y`, `width`, `height`, `viewport.width`, `viewport.height`, `step_id`, `hit_count`, `created_at`. The `phash` label does not change the documented dHash algorithm.

A hit requires current document/layout, viewport, scale, crop origin, frame offsets, and intended-control correspondence. Similar image hash alone is insufficient.

**Contract gap:** Contract 03 has no coordinate-click primitive or coordinates in `CFInput`. Therefore direct bounding-box-center click is not faithfully representable in version `0.1.0`.

The implementation must not:

- Add undeclared coordinate fields.
- Hide mouse input inside evaluation.
- Fabricate a target token from coordinates.
- Claim complete three-tier coverage while direct-coordinate action is unmapped.

Vision-assisted semantic target identification may be separately mapped if disclosed and semantically valid. Full direct-coordinate behavior requires a versioned Camoufox contract revision.

### 9.7 Budget and circuit breaker

The documented 30% rolling-hour shard heal-rate breaker remains product policy. Pin step/heal counting, window semantics, restart behavior, reset authority, and task-budget interaction.

A trip disables healing under policy; it does not establish native capability absence or application non-commitment. Missing token usage is unavailable/bounded, not zero.

---

## 10. Extraction, Upload, and Challenge Boundaries

### 10.1 Stabilization and reduction

The documented live-page readiness policy combines:

- Zero observed in-flight requests for 500 ms.
- DOM quiet for 300 ms.
- Configured text signatures.

These are scoped observations, not universal readiness. The mapping identifies network visibility; page script or extension access cannot claim unobserved network completeness.

All waits share remaining task budget. Timeout preserves condition observations and `stabilization_partial`; continuation requires policy permission.

Reduction preserves the inventory transformation order and semantics:

- Remove non-content tags.
- Convert meaningful image/SVG markers.
- Explicitly traverse open shadow roots.
- Account for frames using route-supported access.
- Retain accessibility attributes.
- Normalize whitespace.

Before stripping iframe tags, retain mount/boundary information. Unreadable frames emit markers and boundary limitations. Closed-root access is never assumed.

`EXTRACT` and `HEAL` exact byte budgets must be pinned, including KB interpretation and UTF-8 accounting. No silent truncation is allowed.

### 10.2 Extraction

Fast path remains in-process:

- Query: `BM25ContentFilter`.
- No query: `PruningContentFilterLXML`.
- Markdown: `DefaultMarkdownGenerator`.
- Schema extraction: deterministic validated heuristics, never LLM.

Raw HTML bypasses semantic live-page pruning. Live-page extraction retains frame/shadow scope.

The `AsyncWebCrawler.arun(html=...)` compatibility fallback may spawn a browser and materially alter resource/latency behavior. It must be disabled or explicitly declared and authorized; it cannot silently activate under browserless bounded extraction.

Bounded gathering does not itself prevent synchronous CPU work from blocking controls. Scheduling must reserve control/closure progress.

`TaskOutput` fields are `kind: task_output`, `name`, `output_schema`, `content`, `completeness`, `evidence_refs`, `limitations`.

`schema_incomplete` and `stabilization_partial` remain separate limitations. Partial objects are valid output only if the pinned output schema admits a partial-result envelope. Otherwise retain the native partial artifact and report validation failure; do not fabricate fields or claim full-schema validation.

### 10.3 Upload custody

Before upload:

- Resolve only authorized input bindings.
- Verify digest and size.
- Enforce byte limit before unbounded loading.
- Enforce MIME allowlist.
- Verify execution-time bytes match admitted identity.
- Retain submitted material identity.
- Avoid duplicate ordinary persistent storage in Circus Tent.

The evidence owner may retain immutable application materials without requiring the framework to persist an additional upload copy.

Synthetic drag/drop preserves `dragenter`, `dragover`, `drop` order and the pinned `DataTransfer` recipe. It remains synthetic. File assignment or drop does not prove server acceptance.

### 10.4 Challenges

All nine documented families remain product requirements: reCAPTCHA, hCaptcha, FunCaptcha/Arkose, Turnstile, DataDome, GeeTest, Imperva, Akamai, PerimeterX.

For each attempt retain detector evidence, provider/task mapping, cost authorization, create/poll observations, injection mapping, and subsequent page evidence. “Enabled” is not proof of current provider support.

Challenge handling occurs only after Start. It is controller recovery, not hidden primitive behavior.

Token/callback injection may use an evidenced authorized evaluation mapping. Context cookie insertion, especially HttpOnly cookies, is not automatically representable through evaluation. Contract 03 has no generic cookie setter. Missing coverage requires explicit mapping/schema resolution, not a hidden legacy call under extension-native identity.

---

## 11. Scheduling, Profiles, Recycling, and Shutdown

### 11.1 Routing and concurrency

The seven shards remain `workday`, `greenhouse`, `lever`, `governmentjobs`, `indeed`, `linkedin`, and final catch-all `misc`.

Routing is declaration-order first match. Routing configuration is pinned; a changed rule cannot silently move admitted work to another profile.

Concurrency layers remain independent:

- Connector queue/active limits.
- Native per-caller rate limit.
- Registered-account quota, documented default 3.
- Shard permit cap, documented default 12.
- Target RPM/session-step limits.
- Tab/profile operation serialization.

`session_id` is informational. Fairness uses registered accounts. Permit acquisition/release must balance across timeout, rejection, shutdown, and browser failure.

Accepted queued tasks consume active observation budget. No native delivery starts after the active boundary. Already-dispatched monolithic `/run` may continue internally; local closure does not prove step cessation.

### 11.2 Backpressure and target backoff

Native depth above 1000 produces HTTP 429 with `Retry-After` and `X-Queue-Depth`. The exact before/after-enqueue comparison is pinned and tested.

Connector overload uses typed errors. Native headers are retained evidence, not substitutes for `ConnectorError`.

The overload benchmark’s success-or-429 condition applies to its healthy overload workload; it does not erase unrelated auth, validation, storage, or task failures.

Target 429/403/503 and challenge signatures trigger configured backoff. `pages_processed` freezes during cooldown. The counting definition is pinned, not inferred from the counter name.

### 11.3 Profile identity and bootstrap

Profile layout remains `fingerprint.json`, `user_data/`, `manifest_created_at.txt`, and `health.json`, under restricted `0700` directories.

Fingerprint provisioning records the complete resolved identity bundle. Subsequent launch pins identity and required launcher flags. Runtime surface checks compare like-for-like measurements; a manifest hash is not automatically the same hash as a runtime surface vector.

Bootstrap is operator-authorized visual MFA. Production uses the configured virtual framebuffer. Production startup does not opportunistically create a missing manifest.

The inventory’s complete launch-bundle immutability and bootstrap/production display-mode change require an explicit profile policy distinguishing identity-affecting options from the authorized display transition, or a reviewed correction. Silent option mutation is forbidden.

### 11.4 Instance lifecycle

| Transition | Guard |
|---|---|
| Enter `INITIALIZING` | Authorized profile, fingerprint, prior-exit safety, launch mapping |
| `INITIALIZING → READY` | Responsive page and required fingerprint checks |
| `READY → DRAINING` | Recycle/shutdown decision; stop routing |
| `DRAINING → TERMINATED` | Actual exit evidence; unresolved exit remains an operational uncertainty, not fabricated termination |

Replacement is a new instance, not resurrection of the terminated one.

At documented threshold 500:

1. Stop routing to old instance.
2. Drain within configured grace, documented default 60 seconds.
3. Persist session state using actual flush mapping.
4. Close contexts/browser.
5. Obtain OS exit/reaping evidence.
6. Relaunch same profile and fingerprint.
7. Health-check and atomically swap local registry reference.

Record old/new process identities, page count, and measured duration. No live profile copying and no overlapping writers.

Grace expiry cannot be reported as clean drain. Forced exit records affected attempts and uncertainty; clean recycle benchmark remains unsatisfied for that execution.

### 11.5 Shutdown

On SIGTERM/SIGINT:

- Stop new admission.
- Stop issuing new workflow commands.
- Preserve control/finalization progress.
- Drain within bounds.
- Flush profiles.
- Close and verify process exit.
- Persist required ledger/cache/evidence state.
- Report supervisor status 0 for clean drain, 1 for forced timeout.

Supervisor status is not application outcome. Unestablished flush/exit quarantines profile reuse. A forced-death path cannot claim an observed safe flush.

---

## 12. Kernel Admission, Journaling, and Observation Projection

### 12.1 Manifest and producers

`Manifest` fields are:

`record_type`, `schema_version`, `manifest_id`, `run_id`, `journal_id`, `owner_domain`, `commissioner_id`, `activity`, `attempt`, `execution`, `task`, `task_semantic_hash`, `effective_configuration`, `environment`, `seed`, `build_pins`, `event_registry`, `producers`, `clocks`.

They pin the complete admitted scope, non-secret effective policy, actual execution identity, artifacts, registry, and clocks. Discovery uses inapplicable attempt. Manual mode has no automation subject.

`ExecutionDescriptor` contains `mode`, `subject`, `connector_version`, `binding_version`, and `assistance`. Kernel service mode applies to non-application work; application lifecycle permits only manual or subject.

`ProducerDescriptor` contains `producer_id`, `principal_id`, `owner_domain`, `role`, `provenance`, `sequence_required`, `allowed_event_kinds`.

`EventKindDeclaration` contains `event_kind`, `event_schema_version`, `role`, `assertion_kind`, `writer_roles`.

Producers cannot self-register authority or recycle sequence identities.

### 12.2 Event ingress and envelope

`EventSubmission` contains only `producer_sequence`, `event_kind`, `event_schema_version`, `occurred_at`, and `payload`. The channel supplies producer/run identity.

`EvidencePayload` contains `data`, `measurements`, `evidence_refs`, `artifact_refs`. All nested artifact identities appear in retention references.

`JournalEnvelope` contains:

| Fields | Authority |
|---|---|
| `record_type`, `schema_version` | Kernel record/version |
| `run_id`, `journal_id`, `manifest_hash` | Immutable admitted binding |
| `journal_sequence`, `event_id` | Journal authority |
| `event_kind`, `event_schema_version`, `role`, `assertion_kind` | Validated registry |
| `owner_domain`, `producer_id`, `provenance` | Authenticated producer registration |
| `producer_sequence` | Validated sequence or permitted missingness |
| `evidence_scope` | Ingestion-assigned current, historical-unscored, or synthetic |
| `recorded_at`, `occurred_at` | Receipt time and honest source time |
| `causal_refs`, `payload` | Validated support/content |
| `previous_event_hash`, `event_hash` | Verified hash chain |

Sequence 1 is `manifest_admitted`, with inapplicable predecessor. Events are contiguous, immutable, never backdated. Acknowledgement means durable append.

### 12.3 Dependency order

Install raw bytes, register receipt, register verification, construct normalized evidence, register normalized evidence, construct dependent transcript/publication, install/register it, then return references.

Nested claims/controls cite prior support, never their own future registration. Artifact bytes are retained while any retained manifest, prefix, diagnostic, replay, or archive depends on them.

Journal gaps, overflow, loss, flush receipts, and producer closure are explicit. Closed HTTP is not producer completeness.

### 12.4 Observe records

`ObserveRequest`: `handle`, `after`, `through`, `max_items`, `wait_limit`.

`ObservationCursor`: `handle`, `journal_id`, `sequence`, `event_hash`. Zero is before admission with inapplicable hash. Positive cursors verify against retained history.

`ObservationPage`: `kind: observation_page`, `handle`, `after`, `through`, `next`, `has_more`, `observation_close_ref`, `items`, `limitations`.

Rules:

- A live first page pins `through`.
- Continuations retain that cutoff and use zero wait.
- `after < item.sequence ≤ next ≤ through`.
- `next` is last scanned position, including non-projected journal events.
- `has_more` exactly means next is below cutoff.
- Empty cutoff page is valid, not termination.
- Late evidence requires a new live cutoff.
- Oversized individual item errors explicitly; it is not skipped.
- Unavailable cursor history is explicit.

`ObservationItem`: `event_ref`, `recorded_at`, `provenance`, `payload`, `measurements`, `artifact_refs`. Its event pointer is empty; metadata and payload match the journaled projection.

Allowed payloads are `native_report`, `context_observation`, `task_output`, `connector_incident`, `control_observation`, `lifecycle_publication`, `artifact_available`, and `clock_registered`. No arbitrary progress shape is added.

`ContextObservation`: `kind`, `domain`, `requested_policy_ref`, `realization`, `context_ref`, `evidence_refs`, `limitations`. Domain is browser or learning state; realization is fresh, reused, frozen, subject-default, unavailable, or unknown.

`ConnectorIncident`: `kind`, `code`, `scope`, `detail`, `evidence_refs`. Codes are observation loss, producer gap, conflicting message, malformed native body, unsupported native shape, trace mismatch, storage interruption, unresolved resource, and mapping error, using Contract 02’s exact underscore spellings.

---

## 13. Native Reports, Claims, and Source Verification

### 13.1 Source checks

`SourceChecks` contains:

- `authentication`: verified, failed, unknown.
- `correlation`: matched, mismatched, unknown.
- `trace_correlation`: matched, mismatched, not-observed, not-applicable, using schema spellings.
- `verification_policy`.
- `matched_by`.
- `evidence_refs`.

Accepted claims require verified authentication, matched correlation, and actual nonempty matching inputs. Signature verification and trace correlation are independent.

`NativeReportObservation` contains `kind: native_report`, `channel`, `raw`, `source_event`, `source_checks`, `mapping`, `normalized_claims`, `limitations`.

Channels are terminal response, callback, or evidenced native stream. Initial documentation establishes no native stream. Unverified or uncorrelated reports retain raw evidence but have no accepted normalized claims.

### 13.2 Execution claim fields

`ExecutionClaim` contains:

`claim_id`, `scope`, `state`, `application_assertions`, `native_run_id`, `native_message_id`, `native_report`, `mapping`, `source_checks`, `made_at`, `received_at`, `evidence_available_to_claimant`, `evidence_refs`, `limitations`.

Scope is `primitive`, `application_postcondition`, `execution_lifecycle`, or `unknown`.

| Native content | Mapping |
|---|---|
| Audited task completed | Execution-lifecycle claim `completed` |
| Audited task failed | Faithful scoped `failed` claim |
| Explicit running/stopped/unknown | Preserve exact claim |
| Primitive acknowledgement | Primitive scope; state inapplicable |
| Missing task-state field | Reasoned missingness, not invented unknown |
| Unit/None | Retained raw/native evidence, no success default |
| HTTP 200 alone | Transport observation, no completion inference |
| Local timeout | Connector observation, not subject failure/stop |
| Extracted confirmation text | Receipt candidate, not automatic origin fact |
| Malformed/unmapped body | Incident and raw artifact |
| Native `SESSION_EXPIRED` | Only the failure scope established by its actual response contract |

Native IDs are never synthesized. Source time is missing unless established; receipt time is actual local time.

`CommitmentAssertion` contains `assertion_id`, `value`, `span`, `boundary_ref`, `evidence_refs`. Value is committed, not-committed, or outcome-unknown using schema spellings. Span is at-boundary, after-boundary, or entire-attempt. Entire-attempt uses inapplicable boundary; other spans require evidence.

Completion/stopped claims do not implicitly contain commitment assertions.

### 13.3 History preservation

`ExecutionValue` contains cumulative nonempty `claims`.

Identical message duplicates deduplicate. Same message identity with changed content is integrity conflict. Different authenticated contradictory messages are both retained. Later terminal-looking claims do not suppress earlier or later evidence.

Native timing is preserved unchanged in kernel measurements. Normalization cannot “repair” a zero-duration report by replacing it with connector timing.

---

## 14. Application Lifecycle Publications

### 14.1 Commission

`AttemptContext` contains `attempt_id`, `kind`, `target_class`, `target_id`, `evaluation_partition`, `rehearsal_of`, `performance_of`, `derived_from`.

- Laboratory fixture: practice, held-in.
- Employer origin: held-out; production requires employer origin.
- Derived-from links are same-kind and acyclic.
- Practice rehearsal links and production performance links are lineage, not evidence promotion.

`AttemptCommission` contains:

`record_type`, lifecycle `schema_version`, `kernel_version`, `commission_id`, `run_id`, `journal_id`, `manifest_hash`, `admission_ref`, `commissioned_by`, `commissioned_at`, `attempt`, `candidate_id`, `candidate_profile`, `job`, `selection_evidence`, `task`, `task_semantic_hash`, `initial_materials`, `execution`, `owners`, `idempotency_key`, `authorization_refs`, `recovery_review_refs`, `observation_policy`, `origin_policy`.

All copied task, subject, scope, key, policy, and identity values must match admission. Subject/version/target/task/kind changes create a new attempt.

`JobReference` contains `job_id`, `source_target`, `source_job_id`, `snapshot`. Company/title matching is not application identity.

`OwnerBindings` contains exactly dispatch, observation, execution, application, report. Each `AuthorityBinding` contains `role`, `source_id`, `writer_id`, `owner_domain`, `publication_policy`. Actual authorization verifies these declarations.

### 14.2 Axis publication

`AxisRevision` contains `record_type: attempt_axis_revision`, lifecycle `schema_version`, `attempt`, `commission_digest`, `axis`, `owner_domain`, `writer_id`, `revision`, `previous_revision`, `evidence_prefix`, `evidence_refs`, `value`.

Revision is previous plus one. Same key with changed bytes is integrity conflict. Artifact installation precedes registration. Publication does not include its own future registration in derivation inputs.

`LifecyclePublicationReference` contains lifecycle `schema_version`, `attempt`, `commission_digest`, `axis`, `revision`, `owner_domain`, `content`, `registration_ref`. Connector axes are restricted to dispatch, observation, execution.

### 14.3 Observation policy and states

`ObservationPolicy` contains `active_limit`, `drain_limit`, `native_cancel_wait_limit`, `cleanup_wait_limit`, `fixture_close_action`.

Each `DurationLimit` is `kind: exact`, `unit: ms`, finite nonnegative `value`; zero is immediate. No universal durations are introduced. Employer origins require fixture-close action inapplicable.

| From | Allowed next |
|---|---|
| Unpublished | `not_opened`, `open`, `closed` |
| `not_opened` | `open`, `closed` |
| `open` | `open`, `draining`, `closed` |
| `draining` | `draining`, `closed` |
| `closed` | `closed` |

`ObservationValue` contains `state`, `window_id`, `opened_at`, `active_deadline`, `drain_started_at`, `drain_deadline`, `closed_at`, `close_reason`, `at_close`, `control_observations`, `late_evidence_refs`, `measurements`.

Close reasons are `normal_completion`, `operator_stop`, `local_deadline`, `translation_failure`, `launch_failure`, `subject_terminal`, `connection_lost`, `infrastructure_interruption`.

Open/draining requires actual open time and active deadline. Draining requires drain coordinates and reason. Closed requires close time, reason, and snapshot. Before closure, close time/snapshot are inapplicable.

Closed-first is allowed for early failure. Closed-to-closed may add evidence but cannot rewrite the original boundary or reopen commands.

### 14.4 Close snapshot

`CloseSnapshot` contains `closure_id`, `boundary_ref`, `known_versions`, `execution_knowledge`, `execution_evidence_refs`, `application_knowledge`, `application_evidence_refs`, `limitations`.

`known_versions` pins dispatch, execution, application, report, excluding the closing publication.

Execution knowledge: running, terminal, unknown, not-applicable. Application knowledge: committed, not-committed, unknown.

Silence yields unknown. Earlier running or as-of absence does not automatically establish the state at closure. Restart records interruption; it does not invent cross-boot elapsed time or backdate closure.

### 14.5 Origin facts

The connector only collects receipt observations. A separately authorized recorder verifies source, meaning, candidate/job/attempt correlation, and origin policy.

`OriginFact` contains:

`fact_id`, `origin_id`, `candidate_id`, `job_id`, `state`, `coverage`, `boundary_ref`, `origin_application_id`, `origin_revision`, `receipt`, `verification_kind`, `source_checks`, `authority_seal_ref`, `occurred_at`, `received_at`, `evidence_refs`.

- State: `committed` or `not_committed`; unknown observations are not negative facts.
- Coverage: `at_boundary` or `final_for_attempt`.
- Production verification: `verified_origin_receipt`.
- Practice local transaction: `local_origin_transaction`.
- Final negative fact requires origin-owned finality evidence.
- Confirmation rendering and commitment remain distinct.
- Later rejection, withdrawal, or job closure does not erase historical commitment.

`ApplicationValue` contains cumulative nonempty `facts`. Conflicts and multiple commitments remain visible.

### 14.6 Reports and snapshots

`ReportValue` contains `state`, `coverage`, `inputs`, `evaluator`, `comparisons`, `issues`, `limitations`, `diagnostic`.

`ReportInputPins` names dispatch, observation, execution, application. Each `DomainPin` contains `revision` and `record_digest`; zero means unpublished with missing digest.

`ClaimComparison` contains `claim_id`, `assertion_id`, `claim_ref`, `fact_ids`, `fact_refs`, `result`, `temporal_relation`, `rationale`, `limitations`.

Result is consistent, contradicted, not-comparable, or indeterminate. `TemporalRelation` contains relation, basis, evidence refs; receipt order alone does not establish occurrence order.

`ReconciliationIssue` contains `kind`, `detail`, `evidence_refs`; kinds are origin-fact conflict, subject-claim conflict, insufficient evidence, incomparable scope, untrusted observation, mapping error, multiple commitments, using schema spellings.

Rules:

- Any proved contradiction makes report contradicted.
- Complete comparisons without contradiction yield reconciled.
- Unresolved comparison yields reasoned missing state.
- No applicable claims yields inapplicable coverage, not success.
- Execution completion without application assertion is narrowly not-comparable.
- Outcome-unknown is compatible with later commitment.
- Entire-attempt no-commit is contradicted by valid commitment.
- Boundary-scoped assertions require actual temporal/causal evidence.

`AttemptSnapshot` contains `record_type`, `schema_version`, `attempt`, `commission`, `commission_digest`, `input_prefix`, all five axis slots, and `seal_point`.

`SealPoint` contains `seal_id`, `name`, `versions`, `evidence_refs`; name is commissioned, observation-closed, or evidence-updated using schema spellings. `VersionVector` contains all five revisions.

`UnpublishedAxis` is revision zero plus `Missing`. It cannot erase an existing publication. Report freshness is determined by comparing its input pins with snapshot source pins.

Manual runs bypass the connector; dispatch/execution stay revision zero and inapplicable. Human actions remain manual observations, while verified employer receipts may establish production facts.

---

## 15. Controls, Artifact Transfer, and Error Mapping

### 15.1 Separate controls

| Operation | Request fields | Scope |
|---|---|---|
| `RequestNativeCancel` | `handle`, `reason`, `authorization_refs` | `native_execution` |
| `CloseObservationConnection` | `handle`, `reason`, `end_observation`, `authorization_refs` | `observation_connection` |
| `ReleaseNativeContext` | `handle`, `context_ref`, `authorization_refs` | `native_context` |
| `Contain` | `handle`, `target`, `policy`, `reason`, `authorization_refs` | Authorized fixture authority/process/slot/harness resource |

`ContainmentTarget` contains `kind` and registry `resource_id`, not arbitrary PID or shell text.

Closing with `end_observation: false` closes only the selected owned native transport. True also initiates bounded local finalization. Neither requests native cancellation. Durable Observe remains available.

Release failure never silently triggers containment. Shared-resource containment records known affected attempts and unresolved impact. Only fixture-origin authority may seal fixture mutation; employers cannot be sealed by this connector.

### 15.2 Control observations

`ControlObservation` contains:

`control_event_id`, `operation_id`, `operation`, `target_scope`, `disposition`, `at`, `authorization_ref`, `capability_ref`, `opportunity`, `request_ref`, `response_ref`, `response_checks`, `native_claim_refs`, `effect_refs`, `affected_attempts`, `measurements`, `limitations`.

Disposition is `not_requested`, `unsupported`, `requested`, `acknowledged`, `effect_observed`, or `unknown`.

- Requested is a request attempt.
- Acknowledged requires verified response evidence.
- Effect-observed requires effect evidence.
- Unsupported mapping is not native absence.
- Unknown delivery is not unsupported.
- Stop claims remain subject claims.
- Effect evidence never implies employer rollback.

`Opportunity` contains `state: exposed | unexposed | blocked`, nonempty `evidence_refs`, and `rationale`.

`ControlReceipt` contains `kind: control_receipt`, `handle`, `observation`, `registration_ref`. Later effects append new control-event IDs under the same operation ID.

### 15.3 Artifact transfer

`CollectArtifactsRequest` contains `handle` and `selector`.

Selector variants:

- Inventory: `mode: inventory`.
- Named: `mode: named`, unique nonempty `names`.
- Bytes: `mode: bytes`, `digest`, `offset`, positive `max_bytes`.

`ArtifactInventory` contains `kind`, `handle`, `artifacts`, `coverage`, `evidence_prefix`, `limitations`. Named requests return exactly requested names, including missing slots. Coverage concerns declared sources, not all private native artifacts.

`ArtifactChunk` contains `kind`, `handle`, `digest`, `size_bytes`, `offset`, `returned_bytes`, `data_base64`, `chunk_digest`, `end_of_artifact`, `evidence_refs`.

Validate canonical padded base64, chunk size/hash, requested offset, bounds, and progress. EOF is true exactly at artifact size. Zero-byte success is legal at EOF only. Consumer verifies assembled full digest and size.

No arbitrary path/URL retrieval, rerun, or new browser session is permitted to manufacture missing artifacts.

### 15.4 Errors

`ConnectorError` contains `kind: connector_error`, `code`, `fault_domain`, `detail`, `operation_delivery`, `retry_guidance`, `retry_after`, `handle`, `evidence_refs`.

Fault domain is request, connector, native interface, environment, policy, or unknown. Delivery is not-dispatched, may-have-dispatched, dispatched, or not-applicable using schema spellings.

Retry guidance is `same_command_only`, `new_command_if_not_dispatched`, `operator_review`, or `do_not_retry`. Advisory retry-after is a `DurationLimit` or missingness, never permission for native resend.

| Codes | Treatment |
|---|---|
| `INVALID_REQUEST`, `UNSUPPORTED_VERSION` | Reject malformed/versioned input before effects |
| `UNAUTHENTICATED`, `FORBIDDEN` | No unauthorized handle disclosure |
| `UNKNOWN_HANDLE`, `UNKNOWN_PREPARATION` | No guessed resource recovery |
| `STALE_PREPARATION`, `STALE_CONTEXT` | Reject changed pins/lifetimes |
| `IDEMPOTENCY_CONFLICT`, `INTEGRITY_CONFLICT` | Preserve conflict; no overwrite |
| `UNSUPPORTED_MAPPING` | Explicit translation/operation gap |
| `PREREQUISITE_UNAVAILABLE` | Infrastructure/prerequisite, not fabricated subject failure |
| `BUDGET_EXCEEDED`, `NOT_ADMITTED`, `RESOURCE_BUSY` | Explicit bounded admission/policy result |
| `OBSERVATION_CLOSED` | Reject workflow resume/new commands |
| `STORAGE_UNAVAILABLE` | No fabricated durable receipt/reference |
| `DELIVERY_UNCERTAIN` | `may_have_dispatched`; no fresh-key retry |
| `CURSOR_INVALID`, `CURSOR_UNAVAILABLE`, `OBSERVATION_LOST` | Explicit history/observation problem |
| `RESPONSE_TOO_LARGE` | No silent item dropping |
| `ARTIFACT_UNAVAILABLE` | Preserve known digest and missingness |
| `NATIVE_PROTOCOL_ERROR` | Connector operation cannot satisfy native protocol mapping |
| `INTERNAL_ERROR` | Sanitized local failure with honest delivery status |

Observed native failure or malformed retained native output normally appears through Observe as evidence/incident, not as a rewritten task-wide connector error.

---

## 16. Configuration, Security, Callbacks, and Operational Evidence

### 16.1 Configuration

Managed YAML and cache formats require explicit schema versions. Effective configuration pins:

- Shards, domains, caps, recycle threshold, preflight, target limits.
- Model roles/providers/budgets/breaker policy.
- Registered accounts and quotas.
- Caller tokens by environment reference, shard/tool/account grants, rate limits.
- Selector/coordinate schema and cache policy.
- Native mapping, callback verification, privacy, and artifact policies.

`${VAR}` is required environment lookup; `${VAR:-default}` uses declared fallback. Development dotenv uses `override=False`; real environment wins. No resolved secret enters effective-configuration artifacts.

Required native environment references include Muse and DeepSeek keys/base URLs, CapSolver key, wrapper bearer key, and account credential variables.

### 16.2 Sensitive data reconciliation

Ordinary journals/logs/configs/cache metadata must exclude credentials, bearer tokens, cookie values, and signing secrets. Restricted DOM/images/receipts require access control and retention policy. Log redaction precedes emission.

The inventory’s absolute “no secret in any file, including profiles” conflicts with persistent authenticated cookies/storage and its dotenv fallback. This cannot be silently certified.

The implementation must obtain an explicit policy resolution distinguishing authorized session-secret storage from forbidden ordinary leakage, or reject the incompatible persistence configuration. Benchmark 8 remains binding as written until formally revised; no hidden exclusions are allowed.

Exact-native-byte retention and redaction also remain distinct. If required exact evidence contains disallowed secrets, do not persist sanitized bytes under its original digest. Apply an explicitly authorized controlled-storage policy or record evidence unavailability and block claims requiring those bytes.

### 16.3 Callbacks

Callback destinations are configured and authorized, not arbitrary shared-interface URLs. Pin destination, signing/verifier contract, key references, correlation rules, retry policy, and size bounds.

Before accepting a callback claim:

- Retain permitted exact body.
- Verify source.
- Independently correlate attempt/native request.
- Preserve trace mismatch.
- Deduplicate actual message identity.
- Retain conflicting authenticated messages.
- Publish late evidence without reopening observation.

Callback POST acknowledgement proves delivery only. Persistent delivery failure appears in health; it does not change the application axis or authorize workflow retry.

### 16.4 Telemetry

W3C traceparent propagates through connector, acquisition, browser steps, and model requests where mapped. Trace identity is not authentication.

Prometheus metrics retain native `circus_tent_*` naming and cover waits, queues, utilization, pages, recycles, heal rates, tokens, and callbacks. High-cardinality or sensitive labels are controlled.

Operational logs, traces, `/health`, `/shards`, and `/metrics` become diagnostic evidence only when captured and registered. Describe does not probe them. Health and shard telemetry do not prove browser isolation, cancellation, or employer outcome.

---

## 17. Diagnostics, Replay, and Lease Boundaries

### 17.1 Consumer assessment

The connector declares; the authorized consumer assesses.

`RequirementAssessment` retains `requirement_id`, `facet`, `contract_version`, `scope`, `capability_refs`, `opportunity`, `result`, `evidence_refs`, `contrary_evidence_refs`, `finding_refs`, `rationale`.

Results are exactly `satisfied`, `violated`, `native_absence`, `indeterminate`, `not_exercised`.

Satisfied/violated requires exposed opportunity and valid controls. Unsupported mapping is not native absence. Invalid isolation controls cannot establish leakage or isolation.

### 17.2 Diagnostic mapping

A consumer-created `DiagnosticDocument` uses:

- Identity/version fields: `record_type`, `schema_version`, `diagnostic_id`, `analysis_revision`, `run_id`, `manifest_hash`.
- Derivation pins: `input_prefix`, `analysis_request_ref`, `classifier`, `requirement_registry`, `fix_registry`.
- Commissioned execution: `attempt`, `execution`, `delivered_task_hash`, `native_request_hash`.
- Evidence sections: `validity`, `capability_descriptors`, `requirement_assessments`, `observed_actions`, `feature_exposures`, `steps`, `measurements`, `claims`, `findings`.
- Summaries/artifacts: `observation`, `application`, `behavioral_profile`, `fingerprint_profile`, `artifacts`.

Every copied observation resolves within the named prefix. Disabled analyses are `Missing(not_enabled)`, not empty score objects. No overall attempt status or self-certification is added.

The prefix ends at `analysis_requested`, which pins diagnostic ID/revision and classifier/requirement/fix versions. Late evidence creates a new request and revision.

### 17.3 Replay

`ReplayReceipt` fields remain `record_type`, `schema_version`, `replay_id`, `mode`, `run_id`, `manifest_hash`, `source_prefix`, `source_diagnostic`, `input_bundle`, `classifier`, `reducer`, `replay_engine`, `comparisons`, `result`, `limitations`, `invoked_browser`, `invoked_subject`, `performed_external_writes`.

The last three are false. Exact fixture replay compares semantic events, final state, diagnostic. Diagnostic rederivation compares only diagnostic and has inapplicable reducer. Missing required comparisons cannot yield matched.

Replay never calls Start, browser primitives, controls, or employer writes. Live reproduction is a new attempt.

### 17.4 Leases

If dispatch workers use kernel leases, the resource owner alone issues them. `LeaseRecord` retains resource/policy/issuer, authority and owner epochs, entity/input revisions, generation, resource/eligible/lease states, lease ID/owner, session epoch, lease times, retry counts, failure reason, journal prefix, and evidence refs.

Claim does not change resource state. Completion verifies current token, deadline, revisions, and epochs. Restart fences the old authority epoch. Reclamation revokes local commit authority; it does not prove the browser or employer stopped.

No TTL, retry count, storage vendor, or cross-owner transaction is introduced by this mapping.

---

## 18. Conformance and Acceptance Matrix

### 18.1 Structural and evidence cases

| Test | Required result |
|---|---|
| T01 Unknown version/field, duplicate YAML key, non-finite number | Rejected |
| T02 Bare normalized null or default-zero missing duration | Rejected |
| T03 Exact native zero | Preserved at native origin |
| T04 Cross-clock/boot subtraction | Rejected |
| T05 Unregistered clock or false endpoint arithmetic | Rejected |
| T06 Artifact/hash/pointer mismatch | Rejected |
| T07 Producer-supplied provenance/authority | Rejected |
| T08 Duplicate producer sequence, identical body | Deduplicated |
| T09 Duplicate producer sequence, conflicting body | Integrity incident |
| T10 Missing artifact bytes with known digest | Identity preserved; loss explicit |
| T11 Redacted bytes under original digest | Rejected |
| T12 Self-referencing future registration | Rejected |

### 18.2 Connector and lifecycle cases

| Test | Required result |
|---|---|
| T13 Describe/Prepare instrumented for browser/model/network activity | No task execution or speculative probing |
| T14 Changed preparation/configuration/plan | Stale/conflict rejection |
| T15 Missing required concern acceptance | Start rejected |
| T16 Repeated Start, new request ID, same logical key | Same handle, no duplicate execution |
| T17 Changed content under command/key | Conflict |
| T18 Crash after intent/before response | Honest uncertainty |
| T19 Completed side effect followed by retry | Never re-executed |
| T20 Resume without checkpoint/native contract/authority | Rejected |
| T21 Resume after drain/close/context change | Rejected |
| T22 Accepted queue exceeds active bound | No later native delivery |
| T23 Close transport without end-observation | Observation not implicitly finalized/cancelled |
| T24 End observation without native cancel | Local closure completes within bounds |
| T25 Forced kill/release/fixture seal | Not classified native cancellation or rollback |
| T26 Late valid commitment after outcome-unknown | Compatible; new revisions, old close snapshot unchanged |
| T27 Valid commitment contradicts entire-attempt no-commit claim | Contradiction retained |
| T28 Authenticated callback with trace mismatch | Mismatch retained; separate correlation decision |
| T29 Uncorrelated callback | No accepted execution claim |
| T30 Conflicting terminal responses | Both retained |
| T31 Manual production receipt | No fabricated subject/dispatch/execution |
| T32 Practice commitment used for production | Rejected |
| T33 Report over older input pins | Marked stale, not silently applied |
| T34 Read-only extraction plan attempts mutation | Rejected |
| T35 Fixed-cutoff Observe with unrelated journal events | Correct scanned cursor and cutoff |
| T36 Oversized observation item/history loss | Explicit error, no silent skip |
| T37 Named missing artifact | Returned missing slot |
| T38 Artifact chunk corruption/EOF errors | Rejected |

### 18.3 Binding and controller cases

| Test | Required result |
|---|---|
| T39 Legacy transcript labeled extension-native | Rejected |
| T40 Extension route secretly calls Playwright/Juggler | Bypass claim fails |
| T41 New version inherits capabilities | Rejected |
| T42 Navigation/node replacement followed by stale input | Rejected before input |
| T43 Multiple or partial target matches | No first-match click |
| T44 Unsupported XPath/test-ID mapping | Explicit mapping failure |
| T45 Coordinate action added to current CFInput | Schema rejection |
| T46 Crop missing scale/frame offset | No coordinate authorization |
| T47 dHash hit after layout change | Cache validity fails |
| T48 Native versus synthetic input substitution | Rejected |
| T49 Synthetic upload | Correct event order; no trusted-input claim |
| T50 File mutation/MIME/size violation | Rejected before injection |
| T51 Local primitive timeout after possible send | Uncertainty, no automatic side-effect retry |
| T52 Unreadable frame/open-root traversal/truncation | Scoped boundaries and limitations retained |
| T53 Frozen learning with background cache write | Violation |
| T54 Daily token cap claimed as per-task cap | Mapping rejected unless task enforcement established |
| T55 Challenge cookie injection without mapped primitive | Explicit gap |
| T56 Same-profile launch before old PID reaped | Prevented |
| T57 Missing flush evidence after forced death | No clean-exit claim; profile quarantined |
| T58 Secret-bearing logs/artifacts/profile policy | Required leakage tests and explicit conflict handling |
| T59 Offline replay invokes browser or external write | Rejected |
| T60 Controls under queue saturation | Reserved progress and bounded finalization |

### 18.4 Eight binding inventory benchmarks

| # | Workload | Binding acceptance |
|---|---|---|
| 1 | 100 consecutive pinned-profile launches; canvas, WebGL, audio, navigator, screen, fonts | Identical surface hashes and unchanged manifest on all launches |
| 2 | 500 × 150 KB HTML strings through in-process filters/markdown | p95 below 200 ms; peak RSS below 2 GB |
| 3 | 20% ATS DOM mutation; HEAL reduction and repair pipeline | More than 85% first-attempt recovery |
| 4 | 100 concurrent sessions × 20 tasks on one shard | Zero shard/account quota violations; maximum wait below 3× median |
| 5 | Continuous run to 500 processed pages and recycle | No orphan process; unchanged fingerprint; clean in-flight drain |
| 6 | Visual MFA then 20 automated virtual-mode sessions | Zero reauthentication/MFA prompts |
| 7 | Flood beyond twice cap and queue threshold | Success or explicit 429 with both backpressure headers in the benchmark workload |
| 8 | Seed secrets; inspect emitted logs/configs/caches/profiles | Zero matches under the stated benchmark scope |

Mocked healing tests establish behavior against synthetic responses, not live-model success. Short CI fingerprint runs do not replace the full 100-launch target. MFA is operator/staging verification. CI never touches live ATS endpoints; nightly drift checks remain separately authorized outside CI.

Every result records build, route, configuration, fixtures, clocks, workload, evidence prefix, and limitations. Passing compatibility tests does not certify extension bypass or employer readiness.

---

## 19. Required Mapping Artifacts, Blocking Gaps, and Completion Gate

### 19.1 Required immutable implementation artifacts

A startable implementation supplies and registers:

1. Exact native REST or MCP request/response schemas.
2. Native step schema and semantics.
3. External translation and response-normalization mapping.
4. Native idempotency/checkpoint contract and retrieval evidence.
5. Callback destination and verification policy.
6. Connector budget accounting/enforcement policy.
7. Browser-state and learning-state realization policy.
8. Camoufox route/channel/permission mapping.
9. All 13 primitive mappings, including explicit unmapped entries.
10. Profile fingerprint, launch, flush, exit, and reset policy.
11. Selector/coordinate-cache schemas and migration rules.
12. Reduction byte-accounting and readiness policies.
13. Upload resolver, size, MIME, and event recipe policy.
14. Model/provider/repair/budget/circuit-breaker configuration.
15. Challenge detector/provider/injection mappings.
16. Privacy, restricted-artifact, session-storage, and retention policy.
17. Complete capability catalogs and exact-version descriptors.
18. Journal event registry and producer/clock registrations.
19. Origin receipt policy for any claimed production fact.
20. Conformance evidence for the advertised scope.

These are required inputs, not placeholders to be silently supplied by runtime guesses.

### 19.2 Explicit unresolved cuts

| Gap | Mandatory disposition |
|---|---|
| Exact deployed native schemas absent | No speculative serialization; unsupported mapping until pinned |
| Extension transport/permissions unestablished | Preserve compatibility route; no extension-native claim |
| Direct coordinate action absent from CF schema | Versioned contract revision or explicit unsupported tier |
| XPath/test-ID mismatch | Proven equivalent mapping or explicit rejection |
| Native cancel/release/artifact/revision endpoints unestablished | Honest unmapped handlers and unknown capabilities |
| Task-level budgets not mapped by native API | Reject required enforcement or disclose accepted best effort |
| Fresh/frozen state unsupported | Reject required policy; no false realization |
| Cookie/challenge injection outside primitive coverage | Explicit mapping/schema resolution |
| Fingerprint launch-mode immutability ambiguity | Pinned reviewed identity/display policy |
| Absolute secret-free disk versus persistent sessions | Explicit policy resolution; no false benchmark certification |
| Partial extraction against strict output schema | Valid partial envelope or explicit output failure |
| Production receipt semantics absent | Retain observations; application knowledge remains unknown |

### 19.3 Completion criteria

Track 2.2 is complete when:

- Every advertised native field has an explicit pinned transformation.
- Every external verb has a truthful handler.
- Every Camoufox primitive has a mapped or explicitly unmapped entry.
- Every live token has enforced ownership and invalidation.
- Every accepted effect has prior authority and durable intent.
- Every uncertainty remains distinct from failure, absence, and success.
- Every observation and publication is journal-backed and hash-verifiable.
- Every timing value and missing value conforms to Contract 00.
- Dispatch, observation, execution claims, origin facts, and reports remain independently owned.
- Compatibility and extension-native claims are independently tested.
- All required product benchmarks retain their stated targets.
- Unsupported scope is rejected or explicitly limited, never hidden behind fallback.
- The connector passes its synthetic-backend suite before peer integration.
- The Camoufox binding passes its own route-scoped suite independently.
- Manual production recording remains available without waiting for browser, extension, laboratory, or orchestration completion.

The release claim is therefore a precise, versioned statement of supported mappings and observed behavior—not a blanket qualification, an employer-success guarantee, or an assertion that all documentary features have already been implemented.

---

## Appendix A — Normative contract-identifier cross-reference

The Camoufox document in Contract 03 defines **`CFPrimitive`** at `#/$defs/CFPrimitive`: the closed enum of 13 `fx.*` primitive operations. It belongs to `internal-browser-binding.camoufox/0.1.0`, not the independent BrowserOxide schema.

Every `CFMapping.operation` MUST be a member of `CFPrimitive`. The binding descriptor MUST enumerate each member exactly once, including operations whose mapping is explicitly unavailable.

| `CFMapping.operation` value | Required enum membership | Request/reply implementation |
|---|---|---|
| `fx.profile_open` | Member of `CFPrimitive` | Section 8.2 |
| `fx.tab_open` | Member of `CFPrimitive` | Section 8.2 |
| `fx.navigate` | Member of `CFPrimitive` | Section 8.2 |
| `fx.context_tree` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.reduce_document` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.resolve_target` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.input` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.upload` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.evaluate` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.await_condition` | Member of `CFPrimitive` | Section 8.2 |
| `fx.capture_crop` | Member of `CFPrimitive` | Sections 8.2–8.3 |
| `fx.tab_close` | Member of `CFPrimitive` | Section 8.2 |
| `fx.profile_flush_exit` | Member of `CFPrimitive` | Section 8.2 |

### Implementation cross-references

- **Primitive table:** Section 8.2, “Primitive matrix,” maps all `CFPrimitive` members to their complete request fields, returned data, and boundary rules. Section 8.3 specifies their nested structures.
- **Transcripts:** Section 8.1, “Transcript and failures,” specifies `CFPrimitiveTranscript`. Its `operation` MUST also belong to `CFPrimitive` and match the selected descriptor mapping and operation-specific request/reply schemas.
- **Route handling:** Section 7.1, “Route and descriptor,” specifies `CFRoute`, `CFBindingDescriptor`, and `CFMapping.execution_place`. Only `fx.profile_open` and `fx.profile_flush_exit` may use `controller_lifecycle`; other mapped operations follow the declared `extension_native` or `legacy_playwright_juggler` page route.
- **Token validity:** Sections 7.2–7.3 define the live identities and invalidation rules governing primitive arguments and replies.

Enum membership establishes a recognized operation name—not native support, exercised capability, successful effect, or permission to substitute an undeclared primitive.
