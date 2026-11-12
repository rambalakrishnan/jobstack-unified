# Ringmaster — BrowserOxide application executor

**Status:** Step 0 review draft; the requirements and experiments below do not certify an implementation, BrowserOxide build, or employer origin. [proposed: distinguish intended architecture from observed capability]

**Implementation:** Rust, independently implementing Stagehand-inspired learn-run-heal, DOM reduction, and tiered selector resolution over BrowserOxide’s native surface; Ringmaster is neither a Stagehand port nor Circus Tent with a different driver. [extracted: current request, Products; 1-handoff-brief.txt, Parts III and V]

**Contract baseline:** the six `0.1.0` shared contracts, especially the asynchronous external connector and the separate BrowserOxide document within `contracts/03-internal-browser-binding.yaml`. [extracted: decisions/invariants-and-provisionals.md, Contract baseline]

**Decision baseline:** P-02’s evidence-driven Rust sharing boundary, P-05’s provisional packaging recommendation, P-14’s initial human-controlled production policy, and HA-03’s independent manual application lane; this PRD introduces no further handoff amendment. [proposed: develop the recorded decisions without silently revising contracts]

## 1. Purpose and product boundary

Ringmaster executes authorized application work against real employer forms: navigating, entering approved information, handling validation, uploading approved documents, and submitting when the commission permits it. [inferred: current request, Purpose and Products; 1-handoff-brief.txt, component interface notes]

Its value is reducing the candidate’s application effort while preserving enough evidence to distinguish what was attempted, what the subject claimed, what the employer established, and what should change before another attempt. [inferred: current request, Purpose; contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES]

The first useful release need not automate every portal or every step; a narrowly scoped, honestly assisted application is useful, whereas fabricated completion or unexplained uncertainty is not. [inferred: 1-handoff-brief.txt, Parts VII–IX; 5-browser-qualification.md, evidence discipline]

Manual production applications continue while Ringmaster is being built or qualified; BrowserOxide research, Hellscape milestones, and fix-registry deployment are not prerequisites for applying. [extracted: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, §2]

| Ringmaster owns | Boundary it must preserve |
|---|---|
| BrowserOxide-specific execution, native resource ownership, DOM observation/reduction, selector resolution, and learn-run-heal. | No shared execution implementation, internal handle type, or cross-browser driver with Circus Tent. [extracted: current request, Products; contracts/03-internal-browser-binding.yaml, BrowserOxide boundary] |
| Faithful task translation, bounded connector behavior, retained observations, and source-attributed execution claims. | It does not assess its own qualification or write employer facts and reconciler verdicts. [extracted: contracts/02-external-connector.yaml, EXT-DECLARE-NOT-ASSESS and EXT-EVIDENCE] |
| Execution of the supplied task with its exact materials, permissions, state policies, and budgets. | job-hunter owns job selection, candidate matching, material approval, and commissioning; Ringmaster cannot invent answers or expand task authority. [inferred: contracts/02-external-connector.yaml, EXT-TASK and EXT-AUTHORITY; 1-handoff-brief.txt, Part I] |
| Authorized native healing and its learning-state history. | Healing is not automatic source repair, a reviewed registry fix, or permission to change application meaning. [inferred: decisions/invariants-and-provisionals.md, INV-29 and INV-30] |
| BrowserOxide facilities actually shared with discovery. | Ringmaster is not the crawler, and Illinois discovery does not wait for its DOM/action machinery. [extracted: decisions/invariants-and-provisionals.md, HA-02] |

Ringmaster makes no blanket promise of employer compatibility, undetectability, native bounded cancellation, or exactly-once remote submission; those properties require scoped evidence rather than inference from direct DOM access. [inferred: 1-handoff-brief.txt, Parts III and VI; contracts/03-internal-browser-binding.yaml, open evidence; contracts/01-application-attempt-lifecycle.yaml, reconciliation]

## 2. Packaging decision

### 2.1 What the native-access bet does—and does not—establish

BrowserOxide’s direct DOM/V8 design puts Ringmaster closer to the browser-resident access pattern that makes Stagehand’s ModCDP effective than an external controller operating through CDP-style bridges. [extracted: current request, Products]

That architectural advantage is a premise to test, not a measured speedup or proof of complete interaction semantics; the supplied sources do not establish current-build screenshot, file-assignment, trusted-input, closed-root, or native-interruption support. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide reconciliation and open evidence]

The packaging decision must therefore optimize native-surface fidelity, ownership, bounded supervision, and failure containment—not imitate an extension/controller split solely because Stagehand uses one. [proposed: choose the mechanism that preserves BrowserOxide’s strengths rather than copying a package whose original purpose was to bypass protocol limitations]

### 2.2 Alternatives considered

| Alternative | Benefit | Cost or unresolved premise | Disposition |
|---|---|---|---|
| **In-process library linked through FFI** | Can place execution logic inside an engine host when that host exposes the necessary ABI and lifecycle. | The sources establish neither a required foreign-language boundary nor a current ABI; embedding in job-hunter would also couple native failures and lifetimes to product orchestration. | Retain for an isolated engine host if actual integration requires it; do not introduce FFI without that requirement. [proposed: evaluate the actual host and ABI before accepting their ownership and maintenance costs] |
| **Separate Rust binary using BrowserOxide’s native API** | Provides an independently supervised execution product, native Rust ownership, and a clear place to enforce Page/thread confinement. | Required API access must be demonstrated on a pinned engine; “API” must not be mistaken for an already supplied remote HTTP/RPC service. | Preferred delivery hypothesis, subject to the native-surface experiment below. [proposed: preserve direct access while separating execution failures from job-hunter; decisions/invariants-and-provisionals.md, P-05] |
| **Browser extension plus controller** | Could expose useful browser-resident privileges or observations unavailable through the engine API. | BrowserOxide already supplies the direct-access premise; no source establishes an additional extension-only advantage or its support costs. | Select only if reconnaissance demonstrates an essential capability or fidelity advantage unavailable to the direct worker. [proposed: add another boundary only for an evidenced benefit; current request, Products] |

**Recommendation:** build Ringmaster as an independently supervised Rust executable whose execution worker calls BrowserOxide’s native surface directly, with native resources confined to their owning process and thread. [proposed: adopt the second option for P-05’s reasons, conditional on the pinned engine’s actual embedding and API support]

“Separate executable” means separate from job-hunter, Circus Tent, and Hellscape; it does not require serializing every primitive into a remote browser service, nor forbid linking an available Rust engine library inside the worker. [proposed: distinguish product deployment boundaries from native call placement]

If the engine requires an FFI boundary, place that integration inside the isolated worker and retain its lifecycle obligations; if the required native surface cannot be exposed there, reopen the recommendation rather than inserting a hidden Playwright/CDP bridge. [proposed: explicit flip condition for the preferred package while preserving full-strength native binding]

### 2.3 Intended responsibility placement

The following is a responsibility sketch, not an assertion that a particular native ABI or IPC protocol already exists. [proposed: make the recommended package reviewable without inventing an engine service]

    job-hunter or another authorized consumer
                       |
            asynchronous task connector
                       |
                Rust Ringmaster
       admission / bounded observation / evidence
       explicit task execution / budgets / healing
                       |
          BrowserOxide-only primitive binding
             synchronous native call boundary
                       |
          confined BrowserOxide execution worker
         native Page / DOM / V8 / live HTTP client

The external boundary remains asynchronous and task-shaped; the internal boundary returns a primitive value, typed failure, unsupported mapping, or uncertainty—not another task handle. [extracted: contracts/02-external-connector.yaml, EXT-SURFACE; contracts/03-internal-browser-binding.yaml, BrowserOxide representation]

A blocking native call must not block the connector’s observation deadline or control servicing; the worker/supervisor arrangement must demonstrate that separation without moving thread-bound Page objects or DOM references between threads. [proposed: reconcile synchronous primitives with EXT-BOUNDS and BO-THREAD]

### 2.4 Sharing with the crawler

`browseroxide-core` is an extraction boundary for demonstrated common facilities, not a prerequisite framework that both products must finish before either ships. [extracted: decisions/invariants-and-provisionals.md, P-02 and HA-02]

Candidate shared facilities include native ownership, profile/client lifecycle, observation, acquisition, and capture where both products actually exercise them; application planning, selector healing, candidate policy, and crawler coverage remain outside that common surface. [proposed: apply the handoff’s cohesion principle to observed consumers rather than predicted code reuse]

The supplied Illinois slice is HTTP-first, with no Page bootstrap and dormant Phase B under its full-description allocation; it supplies no evidence that Ringmaster’s interactive DOM surface is already implemented or needed by that slice. [extracted: 2-state-bank-crawler-blueprint.json, §§3.1, 9.1, and 10.3; decisions/invariants-and-provisionals.md, HA-02]

## 3. Native binding and resource ownership

### 3.1 Preserve the browser’s native strengths

| Surface | Ringmaster requirement |
|---|---|
| **Page ownership** | Allocate, enter, reset, and destroy a Page on its owning OS thread; native handles and isolate-local objects cannot escape that ownership boundary. [extracted: contracts/03-internal-browser-binding.yaml, BO-THREAD; 2-state-bank-crawler-blueprint.json, §§5.5 and 9] |
| **DOM identity** | Preserve page, frame, document, root, node, and generation identity; a selector string is not a durable node identity, and a serialized audit reference is not a transferable native handle. [inferred: contracts/03-internal-browser-binding.yaml, BO-DOM and BOPageRef/BORootRef/BONodeRef] |
| **Direct DOM/V8 access** | Enter the evidenced native API directly; do not insert a neutral driver or route through another browser’s binding. [extracted: contracts/03-internal-browser-binding.yaml, BO-NATIVE] |
| **Live HTTP state** | Preserve client/pool/profile/session identity, request order, cookie generation, and cookie-application order when acquisition participates in a live session. [extracted: contracts/03-internal-browser-binding.yaml, BO-HTTP] |
| **Offline rendering** | Treat `bo.from_html` as network-forbidden; a requirement for missing subresources must become a separately authorized acquisition, not hidden network access. [extracted: contracts/03-internal-browser-binding.yaml, BO-OFFLINE] |
| **Reset and reuse** | Invalidate old DOM references and verify intended cookie continuity before reuse; reset failure quarantines the resource instead of returning it to service. [inferred: contracts/03-internal-browser-binding.yaml, BO-REUSE; 2-state-bank-crawler-blueprint.json, §10] |
| **Native interruption** | Declare support only for the exact evidenced build and operation; a supervisor timeout or process termination cannot be relabeled native deadline interruption. [inferred: contracts/03-internal-browser-binding.yaml, BO-CAPS; 5-browser-qualification.md, evidence discipline] |

The binding’s primitive records are audit representations of typed native calls, not a new JSON-RPC driver protocol; Ringmaster must retain the distinction between native resource identity and exported evidence. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide representation]

### 3.2 Map actions before advertising them

The contract supplies BrowserOxide-specific primitives for acquisition, DOM reads/writes, event dispatch, V8 evaluation, file assignment, capture, verdicts, reset, and destruction; their presence in the schema does not prove a current native implementation or successful application effect. [inferred: contracts/03-internal-browser-binding.yaml, BOPrimitive and BOMapping]

The sources do not supply verified native mappings for every application-level click, key action, selection, upload, or wait; reconnaissance must identify the actual mapping and event semantics for each required action. [uncertain: pin the BrowserOxide source/build, inspect its action APIs, and exercise ordinary form fixtures before declaring interactive coverage]

Direct property mutation, synthetic DOM event dispatch, and native browser input are different mechanisms; a value readback or returned unit value cannot establish that framework validation, event handlers, or the employer’s state changed as intended. [extracted: contracts/03-internal-browser-binding.yaml, BO-INPUT; 5-browser-qualification.md, evidence discipline]

Where the task requires input semantics that the binding cannot evidence, reject the requirement or obtain explicit best-effort acceptance before execution; do not hide the gap behind arbitrary V8 code or an undocumented neutral action API. [proposed: make unsupported semantics visible at the task boundary rather than silently weakening them]

A genuinely new native primitive requires a versioned BrowserOxide binding addition and corresponding tests, not a matching Camoufox operation or a cross-browser escape hatch. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide catalog rules]

### 3.3 Sessions and confinement

Browser state, account/session ownership, and framework learning state are independently requested and observed; a new Page or fixture namespace does not prove fresh or isolated browser state. [extracted: contracts/02-external-connector.yaml, EXT-STATE-POLICY]

Until same-origin controls establish the engine’s actual session-storage isolation, allocate separate processes for independently isolated session domains rather than trusting namespacing or cloned clients. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide open evidence]

Any later consolidation must demonstrate acknowledged writes, pre-overwrite reads, return-to-original-session checks, cookie continuity, and restart behavior for the relevant state stores; failed controls leave isolation indeterminate. [inferred: 3-hellscape-blueprint.md, §§1.3 and 7; contracts/03-internal-browser-binding.yaml, BO-HTTP and open evidence]

Profile retirement, context release, task termination, and learning-cache reset remain separate actions; reusing a context requires evidenced compatibility, not merely an available worker slot. [inferred: contracts/02-external-connector.yaml, EXT-STATE-POLICY and EXT-RESUME; 2-state-bank-crawler-blueprint.json, §§9–10]

## 4. Execution behavior: learn, run, verify, heal

### 4.1 Initial task scope

The proposed first execution mode consumes an explicit recorded plan and approved materials, leaving external planning to job-hunter or another disclosed planner before `Prepare`; this is a Ringmaster scope choice, not inheritance of Circus Tent’s `/run` endpoint. [proposed: reduce hidden planning and make the initial execution/evidence boundary testable; 3-hellscape-blueprint.md, §5.4]

A future goal-planning mode requires its own declared planning ownership, assistance, budgets, task mapping, and version evidence; it cannot appear as an undocumented improvement during preparation. [inferred: contracts/02-external-connector.yaml, EXT-PREPARE, EXT-DESCRIBE, and EXT-TASK]

The engine needs application-level navigation, fill, click, selection, wait, extraction, assertion, upload, and checkpoint behavior, but only actions with established native mappings may enter an executable plan. [proposed: retain the Stagehand-inspired functional scope while refusing to confuse task vocabulary with implemented BrowserOxide APIs; 4-circus-tent-arch.md, §4]

### 4.2 Execution loop

| Stage | Required behavior |
|---|---|
| **Learn** | Read scoped selector and interaction evidence as hypotheses; verify current context, identity, and applicability before reuse. [inferred: 4-circus-tent-arch.md, §§4–5; current request, Products] |
| **Run** | Execute only authorized plan actions using approved values and artifacts, preserving task order and declared recovery rules. [inferred: contracts/02-external-connector.yaml, EXT-TASK and EXT-PREPARATION-PIN] |
| **Verify** | Keep primitive return, observed DOM effect, validation result, and authoritative application postcondition separate; advance only on the plan’s declared evidence. [inferred: 3-hellscape-blueprint.md, §§4 and 9; 5-browser-qualification.md, evidence discipline] |
| **Heal** | Escalate resolution within recovery/model/action bounds without changing the answer, intended control, task meaning, or permission set. [proposed: apply the learn-run-heal lineage without granting the healer product-policy authority] |
| **Stop or hand off** | Preserve partial progress, unmet conditions, uncertain side effects, and required human action; assistance remains visible and is never reported as unattended success. [inferred: 5-browser-qualification.md, evidence discipline; contracts/02-external-connector.yaml, EXT-FAILURE] |

Authentication checks that visit the target occur only after `Start`; `Prepare` may validate the supplied account references and declared mapping but may not test login or create/reset native context. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE]

An HTTP 200, visible page, or missing auth marker must be interpreted within an evidenced authentication policy; none alone establishes a valid credentialed session. [inferred: 5-browser-qualification.md, evidence discipline; 4-circus-tent-arch.md, §5]

### 4.3 Tiered resolution

| Tier | Behavior and boundary |
|---|---|
| **1 — cached/local resolution** | Use retained selectors and native semantic observations without model calls; recheck frame/root scope, uniqueness, document generation, and intended control identity. Ambiguity is not permission to select the first match. [proposed: implement the zero-token tier using BrowserOxide-native identity rather than imported Playwright handles; 4-circus-tent-arch.md, §§4–5] |
| **2 — text healing** | Supply bounded reduced DOM, intended target semantics, and failure evidence to an authorized model; validate the proposed selector locally before acting, preserving the original task values and scope. [inferred: 4-circus-tent-arch.md, §5; current request, Products] |
| **3 — localized vision** | Enable only after raster capture and coordinate/action mappings are independently evidenced; retain image identity, context, geometry, and layout freshness before using a proposed target. [proposed: preserve late vision fallback without assuming BrowserOxide’s currently unverified capture surface] |

Ringmaster implements these tiers in Rust and browser-specific code; it does not import Circus Tent’s Python implementation, Crawl4AI dependency, cache files, model provider configuration, or numerical thresholds as shared machinery. [inferred: current request, Products; 1-handoff-brief.txt, Parts III and V]

Selector/cache updates must retain scope, source evidence, and revision history; a successful local heal is not automatically a reviewed fix-registry result or proof of transfer to another employer. [inferred: decisions/invariants-and-provisionals.md, INV-30; contracts/05-suggested-fix-registry.yaml]

After a possibly delivered side effect, failure to observe the expected result is not an ordinary selector-retry case; resolve delivery and commitment uncertainty before any repeated effect. [extracted: contracts/02-external-connector.yaml, EXT-IDEMPOTENCY and EXT-RESUME]

### 4.4 DOM reduction, extraction, and readiness

Perform semantic reduction close to the native DOM/V8 surface before transferring large representations to models or other consumers; preserve useful labels, roles, text, control semantics, and explicit frame/root boundaries. [inferred: current request, Products; 4-circus-tent-arch.md, §§5–6; contracts/03-internal-browser-binding.yaml, BO-DOM]

Unreadable or unobserved frames and roots remain explicit limitations; direct access does not authorize claiming complete cross-frame or closed-root coverage without evidence. [extracted: contracts/03-internal-browser-binding.yaml, BODomExport, BOBoundary, and BO-CAPS]

Use local deterministic extraction for the declared output schema and return partial results with reasons when it cannot be satisfied; do not invent missing application facts through an LLM fallback. [proposed: retain the source architecture’s local-first, deterministic extraction discipline in Ringmaster’s independent implementation; 4-circus-tent-arch.md, §6]

Network-idle, DOM quiet, and text stability may inform observation but cannot replace task-specific readiness or success predicates; waits need explicit local bounds and must preserve timeout, invalidation, and observation-loss distinctions. [inferred: contracts/03-internal-browser-binding.yaml, reconciliation; 3-hellscape-blueprint.md, §§4 and 9]

Uploads require authorized immutable bytes, declared size/type policy, evidenced assignment semantics, and observation of the task’s required upload/verification result; file assignment alone is not completion. [inferred: 4-circus-tent-arch.md, §5; 3-hellscape-blueprint.md, §9; contracts/03-internal-browser-binding.yaml, bo.assign_files]

## 5. External connector and attempt lifecycle

Ringmaster implements the same nine asynchronous verbs as Circus Tent, independently; no Ringmaster native HTTP path, cancellation endpoint, run-query API, or artifact-download service is established by the supplied sources. [inferred: contracts/02-external-connector.yaml, EXT-SURFACE and native reconciliation]

| Verb | Ringmaster obligation |
|---|---|
| `Describe` | Pin subject, engine, binding, configuration, mappings, limits, and capabilities; declare rather than qualify, with new versions starting unknown. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE] |
| `Prepare` | Validate and freeze supplied task, plan, permissions, artifact identities, policies, and mappings without target access, planning, authentication tests, or context effects. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE and EXT-PREPARATION-PIN] |
| `Start` | Durably commit local identity, idempotency association, intended request, and dispatch intent before native delivery; acknowledge local admission without waiting for completion. [extracted: contracts/02-external-connector.yaml, EXT-START] |
| `Observe` | Return journal-ordered evidence for the exact handle and pinned cutoff, preserving original claims, raw shapes, source checks, and mapping versions. [extracted: contracts/02-external-connector.yaml, EXT-OBSERVE and EXT-NORMALIZE] |
| `RequestNativeCancel` | Separate support, mapping, request, acknowledgement, and observed effect; report unsupported or unknown honestly. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `CloseObservationConnection` | Distinguish transport closure from ending observation; the latter stops new workflow commands and starts bounded drain/finalization without claiming native stop. [extracted: contracts/02-external-connector.yaml, EXT-CLOSE] |
| `CollectArtifacts` | Return retained authorized bytes or explicit missingness; artifact inventory completeness is limited to its declared scope. [extracted: contracts/02-external-connector.yaml, EXT-ARTIFACTS] |
| `ReleaseNativeContext` | Perform only an authorized, evidenced release mapping and preserve its outcome; failure does not silently authorize stronger containment. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `Contain` | Bound authorized local resources or processes separately from native cancellation; process death cannot establish rollback or absence of an already dispatched employer effect. [inferred: contracts/02-external-connector.yaml, EXT-CONTROLS; 5-browser-qualification.md, evidence discipline] |

Recognition of all verbs does not imply native support for all of them; an unmapped connector operation is not proof of native capability absence. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE]

Repeated initial `Start` with the same logical idempotency association returns the same handle; changed content is rejected, and a crash around delivery preserves uncertainty instead of generating a fresh attempt key. [extracted: contracts/02-external-connector.yaml, EXT-START and EXT-IDEMPOTENCY]

Resume requires the existing handle/key, explicit recovery authority, compatible context, an evidenced native checkpoint/idempotency contract, and an open observation window; a local lease expiry alone authorizes none of this. [extracted: contracts/02-external-connector.yaml, EXT-RESUME]

An uncertain Ringmaster submission cannot be “finished” automatically by Circus Tent; executor substitution is a new commissioning decision only after prior side-effect uncertainty is addressed. [inferred: contracts/01-application-attempt-lifecycle.yaml, idempotency reconciliation; decisions/invariants-and-provisionals.md, INV-23]

Ringmaster publishes dispatch and observation, plus faithfully attributed subject execution claims; the origin owns application facts and the reconciler writes only report. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES]

A subject’s completion claim is not employer commitment, and local observation closure does not prove non-commitment; late evidence creates new immutable publications and assessments without rewriting close-time knowledge. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-CLAIMS, LIFE-ORIGIN, and LIFE-LATE-EVIDENCE]

## 6. Evidence, safety, and learning

### 6.1 Evidence retained per attempt

Retain the commission and task inputs, exact materials, descriptor/build pins, preparation, plan/translation identity, assistance, primitive transcripts, relevant effects, control observations, raw native outputs, and immutable closure boundary. [inferred: contracts/00-evidence-kernel.yaml; contracts/02-external-connector.yaml, EXT-EVIDENCE; contracts/03-internal-browser-binding.yaml, BO-EVIDENCE]

Durable local intent precedes side-effect delivery; subsequent native responses and observations are appended, without implying that a local journal transaction can atomically commit an employer’s remote state. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-DISPATCH; contracts/03-internal-browser-binding.yaml, BO-EVIDENCE]

A native binding’s elapsed timer and transcript are subject-reported evidence even when measured correctly; separate observer measurements retain their own origin, clock, boot, endpoints, estimate, and censoring. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide representation and BO-TIME]

Exact zero remains zero, missing timing remains unavailable with reason, and UTC/receipt order cannot justify cross-clock subtraction or occurrence ordering. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-TIME]

Capability availability, opportunity, and result remain separate; nulls use only the kernel’s six reasons, and imported historical Circus Tent findings do not become Ringmaster findings. [inferred: 1-handoff-brief.txt, Part VI; contracts/03-internal-browser-binding.yaml, BO-CAPS]

Owner publications remain asynchronous and complete, with seals pinning revisions; Ringmaster cannot acquire origin or report write authority merely because those records appear in the same attempt view. [extracted: contracts/04-owner-separated-write-domains.yaml, attempt layout; contracts/01-application-attempt-lifecycle.yaml, LIFE-PUBLICATION]

### 6.2 Safety and bounded operation

All call, admission, queue, active-observation, drain, cancellation-wait, cleanup, action, recovery, and model limits must be explicit for the release/task scope; do not inherit Circus Tent’s tab counts or crawler memory/throughput targets as Ringmaster constants. [proposed: enforce EXT-BOUNDS without converting product-specific historical settings into unmeasured execution guarantees]

A local deadline remains effective even if native work continues; unresolved resources are accounted for and quarantined or contained under separate authority, not silently returned to a pool. [inferred: contracts/02-external-connector.yaml, EXT-BOUNDS and EXT-CONTROLS; 3-hellscape-blueprint.md, §13]

Page content, extracted text, images, and model outputs are untrusted inputs and cannot change task authority, submitted answers, credential access, or artifact permissions. [proposed: preserve EXT-AUTHORITY and EXT-TASK across native DOM and model-assisted resolution]

Resolve credentials only through authorized runtime references; keep candidate materials and raw responses access-classified, with redacted presentations distinct from retained immutable evidence. [inferred: contracts/02-external-connector.yaml, EXT-AUTHORITY and EXT-ARTIFACTS; 6-get-a-job.xml.txt, AGENTS.md]

No challenge service, model provider, or live portal write is a fixture-test prerequisite; such production capabilities require explicit configuration, authority, budgets, and their own evidence. [inferred: 3-hellscape-blueprint.md, §§1 and 8; 6-get-a-job.xml.txt, AGENTS.md]

### 6.3 Learning without conflation

Native healing updates Ringmaster’s declared learning state; the portfolio loop separately turns diagnostic findings into scoped rule instances with required evidence, contraindications, and verification plans. [inferred: decisions/invariants-and-provisionals.md, INV-29 and INV-30; contracts/05-suggested-fix-registry.yaml]

Humans approve rule classes, the product owner implements changes, and the resulting version earns new evidence; a recommendation is neither a patch nor a capability result. [extracted: 1-handoff-brief.txt, Parts VIII–IX; contracts/05-suggested-fix-registry.yaml]

Ringmaster and Circus Tent retain separate curriculum and learning-state lineages; practice results, another executor’s capabilities, and prior-version findings do not inherit into the candidate build. [extracted: decisions/invariants-and-provisionals.md, P-12; 1-handoff-brief.txt, Part VI]

Registry implementation is deferred to M3 and cannot block useful execution; unsupported recommendations remain reasoned missing values. [extracted: decisions/invariants-and-provisionals.md, P-10]

## 7. Acceptance and the silo gate

Ringmaster must pass its applicable contract suites against its own fixtures and synthetic backends before peer integration; neither Circus Tent nor a successfully completing Hellscape subject is required to ship that independently useful scope. [extracted: 1-handoff-brief.txt, Part VIII]

| Gate | Required evidence |
|---|---|
| **Kernel — `conformance/00-evidence-kernel.md`** | Durable journal/artifacts, source-assigned provenance, explicit missingness, exact/bounded/unavailable timing, retained zero, and no elevation of native claims into origin facts. [inferred: contracts/00-evidence-kernel.yaml; contracts/03-internal-browser-binding.yaml, BO-EVIDENCE and BO-TIME] |
| **Lifecycle — `conformance/01-application-attempt-lifecycle.md`** | Five-owner separation, repeated Start, ambiguous delivery, bounded closure, continued native work, late evidence, and practice/production lineage rules. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| **Connector — `conformance/02-external-connector.md`** | All nine verbs, non-executing preparation, faithful unsupported mappings, finite local bounds, malformed/nullable outputs, conflicting responses, and source/correlation checks where applicable. [extracted: contracts/02-external-connector.yaml] |
| **BrowserOxide binding — `conformance/03-internal-browser-binding.md`** | Exact build/mapping evidence, direct native entry, owner-thread confinement, stale-reference rejection, frame/root accounting, event semantics, HTTP/cookie continuity, and safe reset. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide invariants] |
| **Owner-separated writes — `conformance/04-owner-separated-write-domains.md`** | Complete immutable attempt-domain publications, old-or-new reads, pinned seals, and rejection of unauthorized origin/report writes. [inferred: contracts/04-owner-separated-write-domains.yaml, attempt layout] |
| **Fix records — `conformance/05-suggested-fix-registry.md`** | Any emitted recommendation satisfies scope/evidence/contraindication/verification requirements without requiring a deployed registry. [inferred: contracts/05-suggested-fix-registry.yaml; decisions/invariants-and-provisionals.md, P-10] |

Truthful unsupported behavior may satisfy a connector-mapping test while leaving the corresponding native capability unqualified; an all-unsupported executor does not satisfy an advertised interactive application scope. [inferred: contracts/02-external-connector.yaml, EXT-DESCRIBE; 5-browser-qualification.md, skipped-required discipline]

### 7.1 Native-access and packaging experiment

Before locking the preferred package, pin the BrowserOxide build and demonstrate native DOM/V8 access, owner-thread lifetime enforcement, a representative form action with observed event/application effects, evidence capture, and connector responsiveness while a primitive blocks. [proposed: test the premises that justify the direct supervised worker rather than benchmark an assumed implementation]

Exercise stale nodes after navigation/reset, ambiguous targets, unreadable frames, synthetic-versus-trusted event distinctions, upload assignment without verification, native-call failure, process loss, and unavailable capture/interruption mappings. [proposed: make fidelity and uncertainty first-class acceptance cases for the BrowserOxide bet]

For the advertised scope, missing a required mapping is a failed or blocked capability gate—not an exemption disguised as success; optional vision or other unimplemented features may remain explicitly disabled. [inferred: 5-browser-qualification.md, evidence discipline; contracts/03-internal-browser-binding.yaml, BO-CAPS]

Measure latency, transfer volume, resource use, and observation overhead with pinned workload, state, scope, and clock origins; no supplied evidence supports a Ringmaster speedup, concurrency number, or extraction benchmark today. [uncertain: current Ringmaster implementation and benchmark data are absent; collect scoped measurements after native fidelity is established]

Circus Tent’s benchmark targets and the crawler’s sizing assumptions are not Ringmaster acceptance numbers; any Ringmaster performance target needs its own declared workload and rationale. [proposed: avoid certifying an independent product against borrowed, unmeasured assumptions]

### 7.2 Application semantics

Local fixtures must establish that a returned primitive does not automatically pass a step, that a validation rejection remains visible, and that a later correction is recorded as recovery rather than erasing the failure. [inferred: 3-hellscape-blueprint.md, §§4 and 9; 5-browser-qualification.md, evidence discipline]

The cooperative Hellscape integration is a subsequent practice test, useful even if Ringmaster stops at its first unsupported interaction; it neither certifies employer transfer nor enables autonomous production submission. [extracted: 3-hellscape-blueprint.md, M2; decisions/invariants-and-provisionals.md, P-14]

CI runs local fixtures and synthetic backends, never live employer writes; production applications remain separately authorized operations with real evidence. [extracted: 6-get-a-job.xml.txt, AGENTS.md]

## 8. Delivery and operational use

| Delivery slice | Independently useful result |
|---|---|
| **Continue the manual lane** | Real jobs are evaluated and applied to with durable evidence while Ringmaster remains unfinished. [extracted: decisions/invariants-and-provisionals.md, HA-03] |
| **Pin and investigate the engine** | Produce a build/API/mapping inventory and evidence for or against the preferred package; keep unsupported action/capture/interruption surfaces explicit. [proposed: resolve packaging premises before investing in a broad execution engine] |
| **Build connector and narrow native execution in parallel** | Synthetic lifecycle cases prove the connector while native fixtures prove the smallest useful form scope; neither waits for a complete shared Rust core. [inferred: 1-handoff-brief.txt, Part VIII; decisions/invariants-and-provisionals.md, HA-02] |
| **Ship a scoped executor** | An explicit plan can execute its supported actions with verified effects, bounded failure, artifact retention, and honest human handoff. [proposed: prioritize application utility over portal breadth or generalized agent capability] |
| **Integrate practice** | Run against the cooperative fixture after silo gates, preserving held-in practice evidence and useful non-completion. [extracted: 1-handoff-brief.txt, Part IX; 3-hellscape-blueprint.md, M2] |
| **Use assisted production** | Select a specifically authorized origin/task scope, review materials, retain initial human-controlled final submission, and preserve receipt/uncertainty and next actions. [extracted: decisions/invariants-and-provisionals.md, P-14] |
| **Expand only on evidence** | Add native mappings, resolution tiers, and production autonomy through new versioned evidence and explicit authorization, not through a high practice completion rate. [inferred: contracts/03-internal-browser-binding.yaml, BO-CAPS; decisions/invariants-and-provisionals.md, P-14] |

When Ringmaster performs part of an application and a human performs the final action, record the subject and the assistance; do not relabel the attempt as wholly manual or unattended. [extracted: prd/00-integration.md, §2; 5-browser-qualification.md, evidence discipline]

The operating view must distinguish assisted production attempts, verified origin commitments, unresolved outcomes, human effort, and follow-up actions from fixture completion, selector-heal rate, and engineering throughput. [proposed: measure whether Ringmaster reduces application work without turning subject claims into business outcomes]

## 9. Open decisions and reconnaissance

| Decision or gap | Evidence needed; consequence |
|---|---|
| **Preferred native worker package** | Verify actual embedding/API access, lifecycle ownership, and failure containment; flip to an isolated FFI host or extension split only for an evidenced native-surface advantage or requirement. [proposed: retain P-05 as an evidence-dependent recommendation] |
| **Current BrowserOxide capabilities** | Pin source/build and test each required mapping; schema entries and documentary native symbols are not implementation certification. [uncertain: a current verified API/build bundle is absent; contracts/03-internal-browser-binding.yaml, open evidence] |
| **Action, upload, capture, and interruption semantics** | Establish native entry, event trust, readback, observed effects, geometry, and timeout behavior separately; keep unavailable features disabled or reject tasks requiring them. [uncertain: current-build proofs are absent; contracts/03-internal-browser-binding.yaml, reconciliation] |
| **Session consolidation** | Demonstrate valid same-origin isolation and continuity controls before sharing a process across independently isolated domains; retain separate-process allocation otherwise. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide open evidence] |
| **Shared Rust core size** | Extract only exercised common code; persistent low overlap favors a small core and never delays Illinois discovery. [extracted: decisions/invariants-and-provisionals.md, P-02 and HA-02] |
| **Models, caches, and resource settings** | Choose Rust-compatible implementations and explicit bounded configurations using retained fixture results and maintenance cost; do not inherit Circus Tent’s providers, cache formats, or quotas. [proposed: keep implementation choices product-specific and evidence-driven] |
| **Origin receipt and recovery policies** | Obtain authorized employer evidence establishing source, candidate/job/attempt correlation, and relevant temporal scope; an absent receipt remains unknown and cannot authorize blind resubmission. [uncertain: per-origin production mappings are not supplied; contracts/01-application-attempt-lifecycle.yaml, open evidence] |
| **Greater production autonomy** | Require explicit operator authorization for the named origin/task/subject scope, supported by receipt correlation and ambiguity recovery; practice success alone never flips the initial policy. [extracted: decisions/invariants-and-provisionals.md, P-14] |

BrowserOxide remains a bet rather than a reason to deprecate Camoufox; a failed Ringmaster premise must produce a scoped limitation or revised package, not a merged browser abstraction or a suspension of the job search. [inferred: 1-handoff-brief.txt, Parts III and X; current request, Purpose]

Ringmaster succeeds when its native strengths make real, tracked applications easier and its evidence makes the next attempt better—not when its browser architecture becomes an end in itself. [inferred: current request, Purpose; 1-handoff-brief.txt, Parts VII and IX]
