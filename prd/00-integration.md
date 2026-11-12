# Integration PRD — applications first, machinery in service

**Status:** Step 0 review draft; this document specifies intended integration and acceptance obligations, not evidence that any implementation, browser version, or employer origin has passed them. [proposed: distinguish the portfolio design from observed operational results]

**Contract baseline:** the six `0.1.0` drafts in `contracts/00` through `contracts/05`, alongside the separately versioned `conformance/` suite documents; the internal-binding file contains independently specified BrowserOxide and Camoufox schemas. [extracted: contracts/00-evidence-kernel.yaml; contracts/01-application-attempt-lifecycle.yaml; contracts/02-external-connector.yaml; contracts/03-internal-browser-binding.yaml; contracts/04-owner-separated-write-domains.yaml; contracts/05-suggested-fix-registry.yaml]

**Decision baseline:** `decisions/invariants-and-provisionals.md`, including handoff amendments HA-01 through HA-04; this PRD operationalizes those decisions and introduces no further handoff amendment. [proposed: keep integration requirements aligned with the recorded amendment process]

## 1. Product outcome

The portfolio exists to find, evaluate, and apply to jobs for Ram Balakrishnan, then track each attempt and subsequent outcome; its success is useful, real application activity rather than the completion of a browser platform. [extracted: current request, Purpose; 6-get-a-job.xml.txt, AGENTS.md]

The operating requirement is to pursue a suitable, tracked production application from day one, substituting disclosed manual work for unfinished machinery; the handoff’s “top five this week” is an operating target, not a schema constant or permission to apply to unsuitable jobs. [inferred: current request, Purpose; 1-handoff-brief.txt, Parts VII and IX; decisions/invariants-and-provisionals.md, HA-03]

A commissioned attempt, a submit click, a native completion claim, and a verified employer commitment are different observations; the operating report must distinguish them rather than manufacture a successful-application count. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-DISPATCH, LIFE-CLAIMS, and LIFE-ORIGIN]

### 1.1 Candidate-specific selection, not generic job matching

The candidate’s recurring value is turning chaotic, under-documented environments into rules, middleware, SOPs, automation, better-supported people, and audit-ready records; job selection must recognize that pattern across technical, compliance, operations, training, and public-facing work. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]

The eight playbooks are the common vocabulary for evaluation and material preparation: [extracted: 6-get-a-job.xml.txt, capability_profile.txt]

- Recursive Structural Deconstruction & Isomorphic Mapping; Human Asset Optimization & Reverse-Pyramid Leadership. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]
- Compliance-to-Automation Pipeline; High-Stakes De-escalation & Autonomous Field Triage. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]
- Cross-Domain Hardware/Software Integration; Latency-Aware Cognitive Offloading. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]
- Public/Community Governance & Parliamentary Procedure; Data-Driven Campaign Engineering. [extracted: 6-get-a-job.xml.txt, capability_profile.txt]

Evaluations must separate demonstrated ability, hard blockers, tolerability, pay uncertainty, playbook matches, and the legibility gap between the candidate’s evidence and the employer’s vocabulary; titles are recall aids, not the principal matching rule. [inferred: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]

The profile does not establish a degree, deep Microsoft-stack ownership, or multi-year multi-time-zone delegation at scale; truthful translation must not manufacture those qualifications, while a bachelor’s requirement is flagged for its actual substitution language rather than automatically treated as either waived or disqualifying. [extracted: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]

Current pay, schedule, travel, location/address rules, and credential status require owner input where absent; unresolved preferences remain explicit review questions rather than invented scoring constants. [uncertain: the supplied candidate material lacks complete current policy values; obtain and version the owner’s decisions before applying them as filters]

### 1.2 Scope and exclusions

| In scope | Boundary |
|---|---|
| Discover useful jobs with honest source and coverage evidence. | The crawler cannot perform application, self-referral, or contact-reveal mutations under a discovery task. [extracted: contracts/02-external-connector.yaml, EXT-READ-ONLY] |
| Evaluate, select, prepare truthful materials, commission execution, and follow up. | job-hunter owns product policy, not browser primitives or employer truth. [inferred: 1-handoff-brief.txt, Parts I and V–VI; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |
| Execute authorized applications through either browser product. | Circus Tent and Ringmaster are independent implementations, not interchangeable internal drivers beneath a shared framework. [extracted: current request, Products; 1-handoff-brief.txt, Parts III and V] |
| Preserve evidence and improve execution from supported findings. | A diagnosis or fix suggestion is not an implemented repair, production authorization, or proof of improvement. [extracted: contracts/05-suggested-fix-registry.yaml, ownership and semantic rules] |
| Operate a controlled form-fidelity laboratory. | Hellscape is not an ATS, fake employer, origin-representation service, or mandatory gateway for manual applications. [extracted: 1-handoff-brief.txt, Parts III and IX] |

This integration does not require a universal browser abstraction, shared cross-product database, mandatory message broker, deployed fix-registry service, or finished dashboard before useful application work can begin. [inferred: 1-handoff-brief.txt, Parts V–X; decisions/invariants-and-provisionals.md, P-10, P-13, and P-15]

## 2. Day-one production lane

The first application lane requires neither Hellscape nor an executor nor an automated crawler/reranker; it requires a small durable recording path that preserves the applicable kernel and lifecycle semantics. [inferred: decisions/invariants-and-provisionals.md, HA-03; contracts/00-evidence-kernel.yaml, EK-MANUAL; contracts/01-application-attempt-lifecycle.yaml, LIFE-MANUAL]

The following is the proposed operating procedure, not a claim that such a recorder already exists. [proposed: make the smallest application-producing workflow implementable independently of the infrastructure roadmap]

| Step | Operator action | Retained result and authority |
|---|---|---|
| 1. Capture a real opportunity | Save the listing, actual source location, description, and any observed closing-date information. | Journal a manually sourced observation and register an immutable job snapshot; do not fabricate crawler coverage, source IDs, or crawler-owned revisions. [proposed: use manual evidence without impersonating the discovery service; decisions/invariants-and-provisionals.md, HA-03] |
| 2. Evaluate | Compare the actual requirements with the profile and playbooks; resolve material uncertainties with the candidate. | Retain the profile/policy inputs, rationale, blockers, uncertainty, and selection decision; human evaluation is an acceptable first implementation of job-hunter’s policy. [inferred: 6-get-a-job.xml.txt, job_search_queries.txt; decisions/invariants-and-provisionals.md, P-13 and P-16] |
| 3. Prepare materials | Tailor supported experience to the employer’s vocabulary and review all submitted answers. | Register the exact resume, cover letter, supplemental answers, and approval evidence as restricted artifacts where they contain personal data; the legacy `fabricationLog` name does not authorize fabrication. [inferred: 6-get-a-job.xml.txt, AGENTS.md, raw_job_history.txt, and docs/contracts/firestore-collections.md] |
| 4. Commission | Record the candidate, job snapshot, employer target, task, permissions, and intended manual execution before submission. | Admit an immutable `production` attempt targeting an employer origin, with `held_out` evaluation partition; manual dispatch and execution remain inapplicable, with no invented automation identity or native run. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION, LIFE-LINEAGE, and LIFE-MANUAL] |
| 5. Apply | The operator completes the real form and performs the initial policy’s final submission action. | Journal manual actions and assistance honestly; initial human-controlled submission is a commissioning policy, not a permanent prohibition on authorized automated submission. [proposed: follow decisions/invariants-and-provisionals.md, P-14 while origin-specific automation evidence is absent] |
| 6. Establish what happened | Retain the employer’s receipt, confirmation, or other response without strengthening its meaning. | The designated origin-fact recorder checks source identity and candidate/job/attempt correlation under a pinned policy; an operator assertion alone is not an origin fact. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-ORIGIN and LIFE-SOURCE-CHECKS] |
| 7. Close and follow up | Record the observation boundary, remaining uncertainty, and next action. | Preserve the close-time snapshot and receipt references; later correspondence and follow-up decisions are appended evidence and product projections, not edits to the original commission or commitment fact. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-LATE-EVIDENCE; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md] |

An absent receipt leaves the outcome unresolved; it does not establish non-commitment and must not automatically trigger another submission, a fresh idempotency key, or a switch to the other executor. [extracted: contracts/01-application-attempt-lifecycle.yaml, reconciliation and idempotency rules]

A manually reviewed verification policy for a particular retained employer receipt can precede an automated origin adapter; its source and correlation evidence must still be preserved. [proposed: permit useful manual fact recording without weakening LIFE-ORIGIN or waiting for a universal receipt-mapping service]

If an executor performs part of the work and a human performs the final action, the attempt records the subject and disclosed operator assistance; it is not relabeled as wholly manual or unattended. [inferred: contracts/00-evidence-kernel.yaml, ExecutionDescriptor and AssistanceRecord; 5-browser-qualification.md, evidence discipline]

Manual evidence can precede a full diagnostic implementation, but operator notes must not be labeled as a deterministic diagnostic; later analysis derives a new artifact from a pinned journal prefix and classifier. [inferred: contracts/00-evidence-kernel.yaml, EK-DIAGNOSTIC; decisions/invariants-and-provisionals.md, HA-03]

## 3. Architecture and ownership

The intended data flow separates job selection from browser execution and separates both from evidence judgment; the kernel is a shared contract surface, not a mandatory central runtime. [inferred: 1-handoff-brief.txt, Parts V–VI]

    Manual discovery or IL crawler
                  |
        source evidence / job snapshots
                  v
             job-hunter
       evaluate → select → tailor
                  |
         immutable commission
                  v
       Circus Tent OR Ringmaster ──────> employer form
                  |
        observations / native claims
                  v
         journal and artifacts <──────── verified origin receipt
                  |
          reconciliation / diagnostics
                  |
         product tracking and follow-up

    Separate practice lane:
      Hellscape fixture ↔ selected executor
          → journal → diagnostic → supported fix proposal
          → product-owner change → separately evidenced new version

### 3.1 Seven semantic boundaries

These are responsibility boundaries, not a requirement for seven services or seven repositories. [extracted: 1-handoff-brief.txt, Parts IV–V]

| Boundary | Cohesive responsibility | Integration consequence |
|---|---|---|
| **Contracts** | Versioned records, authority rules, conformance, and language bindings. | Shared language does not imply shared execution code or a shared runtime. [extracted: 1-handoff-brief.txt, Part V] |
| **Rust browser cluster** | BrowserOxide-native facilities actually exercised by the crawler and Ringmaster. | Extract common native facilities when justified; Illinois HTTP acquisition does not wait for a speculative large browser core. [inferred: decisions/invariants-and-provisionals.md, HA-01 and HA-02; 2-state-bank-crawler-blueprint.json, §§3 and 10] |
| **Python Circus Tent** | Camoufox-specific control, learn-run-heal behavior, DOM reduction, selector resolution, and native evidence. | It shares the external connector contract and evidence discipline with Ringmaster, not its implementation or internal handle types. [extracted: current request, Products; 1-handoff-brief.txt, Parts III and V] |
| **Hellscape** | Fixture truth, observation, diagnostics, replay, and later experiment services. | It measures subjects and explains failures; it neither owns employer truth nor repairs subjects automatically. [extracted: 3-hellscape-blueprint.md, §§1 and 3] |
| **job-hunter** | Candidate-specific evaluation, materials, selection, commissioning, tracking, and follow-up. | Its language and canonical storage remain undecided; product work can begin with manual steps and contract fixtures. [inferred: 1-handoff-brief.txt, Parts I and VII–IX] |
| **Dashboard** | TypeScript/Angular presentation through HTTP. | It consumes projections and cannot rewrite source domains; Firebase is dashboard-only if retained. [extracted: 1-handoff-brief.txt, Parts V and VII] |
| **Tools** | Hermes→OMP decomposition, schema generation, and development-time fixture tooling. | Tool availability is not a runtime dependency of discovering or applying to a job. [extracted: 1-handoff-brief.txt, Part V] |

The “job pipeline,” “browser-use framework,” and “test harness” are not additional shared-runtime boundaries: discovery and product policy remain separate, the browser implementations remain separate, and Hellscape is a component rather than a layer through which all work passes. [extracted: 1-handoff-brief.txt, Part V, non-boundaries]

### 3.2 Browser architecture

Circus Tent’s identified compatibility route is Python → Playwright → Juggler → Camoufox; its target architecture is a Firefox extension exposing a richer browser-resident surface to the Python controller, bypassing those page-operation bridges. [extracted: current request, Products; contracts/03-internal-browser-binding.yaml, Camoufox boundary]

The extension route is an architectural target, not an established capability: its transport, permissions, packaging, and primitive coverage require reconnaissance, and legacy-route results cannot certify it. [extracted: contracts/03-internal-browser-binding.yaml, CF-ROUTE and open evidence]

Ringmaster benefits from BrowserOxide’s direct DOM/V8 design, but its packaging must be chosen from actual engine integration evidence; P-05 recommends an independently supervised Rust worker using the native API rather than presuming FFI or an extension. [inferred: current request, Products; decisions/invariants-and-provisionals.md, P-05 and §6.1]

Here “native API” does not presume a supplied remote HTTP/RPC service; Ringmaster’s sibling PRD must compare in-process/FFI, separate-worker, and extension/controller alternatives against native-surface fidelity, ownership, lifecycle control, and failure containment. [inferred: decisions/invariants-and-provisionals.md, §6.1; contracts/03-internal-browser-binding.yaml, BrowserOxide packaging boundary]

Both products expose the same asynchronous task connector while maintaining separate synchronous, primitive-shaped internal bindings; there is no shared `ElementHandle`, cross-browser DOM reference, or neutral driver beneath them. [extracted: 1-handoff-brief.txt, Parts III and VI; contracts/03-internal-browser-binding.yaml]

## 4. Automated integration choreography

Automation replaces individual manual steps as each component becomes useful; it does not replace the evidence or authority rules. [inferred: 1-handoff-brief.txt, Parts VII–IX; decisions/invariants-and-provisionals.md, P-13]

### 4.1 Discovery → evaluation → selection

1. **Consume a pinned job publication.** The crawler publishes acquisition, content, render, processing, and coverage evidence under source identity `(target, job_id)`; job-hunter evaluates a named crawler revision rather than an unversioned mutable row. [extracted: contracts/04-owner-separated-write-domains.yaml, job domain layout and EvaluationReference]

2. **Keep posting validity separate from enumeration completeness.** An individually valid posting may be considered while its partition remains incomplete; the product must preserve that coverage limitation rather than either claiming a complete search or discarding all valid siblings. [inferred: 2-state-bank-crawler-blueprint.json, §§7–8; 1-handoff-brief.txt, crawler interface notes]

3. **Write only the downstream domain.** Evaluations, materials, selection, product priority, work ownership, and attempt links belong to job-hunter; crawler operational state and crawler semantic candidate state do not become application outcome facts. [extracted: contracts/04-owner-separated-write-domains.yaml, JobCrawlerValue and JobDownstreamValue]

4. **Pin the decision inputs.** Each evaluation identifies the candidate profile, crawler input, and evaluation artifact; materials and commissions retain their own exact inputs even if the listing or policy later changes. [inferred: contracts/04-owner-separated-write-domains.yaml, EvaluationReference and MaterialReference; contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION]

5. **Treat similarity as a review aid.** Legacy company/title/location hashes may suggest duplicates, but cannot silently merge different requisitions, source identities, origins, or attempts; uncertain prior submission history requires review before another side effect. [inferred: decisions/invariants-and-provisionals.md, §5; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md]

6. **Commission only an authorized decision.** A product selection does not itself authorize browser writes; the commission freezes task, candidate, job snapshot, target, subject configuration, assistance, permissions, and attempt kind. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-COMMISSION; contracts/02-external-connector.yaml, EXT-AUTHORITY and EXT-TASK]

### 4.2 Commission → connector

| Operation or preparation | Integration requirement |
|---|---|
| `Describe` | Select the exact subject/version/mode/interface descriptor and inspect mappings, capability evidence, context policies, and bounds; the connector declares, while the consumer assesses suitability for this task. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE and EXT-DECLARE-NOT-ASSESS] |
| Planning, when external | Prepare the explicit plan before connector preparation, using permitted public observations and disclosed assistance/cost; Circus Tent’s documented `/run` surface accepts steps, not goals. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE and native reconciliation; 3-hellscape-blueprint.md, §5.4] |
| `Prepare` | Validate and pin the supplied task, plan, mappings, permissions, artifacts, state policies, and limits without visiting the target, testing login, resetting context, or secretly improving the plan. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE and EXT-PREPARATION-PIN] |
| `Start` | Durably record the local handle, request binding, idempotency association, and delivery intent before native delivery; return local admission without waiting for completion. [extracted: contracts/02-external-connector.yaml, EXT-START] |
| `Observe` | Consume journal-ordered observations for the exact handle and pinned page cutoff; preserve raw native bodies, mapping version, authentication, correlation, and source scope. [extracted: contracts/02-external-connector.yaml, EXT-OBSERVE and EXT-NORMALIZE] |
| `CollectArtifacts` | Retrieve retained artifacts within the authorized handle scope; return available bytes or explicit missingness, never an invented native artifact endpoint or silently incomplete inventory. [extracted: contracts/02-external-connector.yaml, EXT-ARTIFACTS] |
| `RequestNativeCancel` | Record support/mapping, request, response, and observed effect independently; neither a request nor acknowledgement proves native stop. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `CloseObservationConnection` | Distinguish transport closure from ending observation; ending observation stops new workflow commands and begins bounded drain/finalization without asserting native cancellation. [extracted: contracts/02-external-connector.yaml, EXT-CLOSE] |
| `ReleaseNativeContext` | Attempt only the mapped, authorized release operation and record its outcome; failure does not silently authorize stronger containment. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `Contain` | Bound separately authorized local processes, deployment slots, fixture authority, or harness resources; containment is not native cancellation, isolation, or rollback. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS; 3-hellscape-blueprint.md, §13] |

All nine verbs must be recognized, but recognition does not imply nine native mappings; an honest unsupported mapping is preferable to a speculative endpoint, and a mapping gap is not automatically native capability absence. [extracted: contracts/02-external-connector.yaml, EXT-SURFACE and EXT-DESCRIBE]

Local call, active-observation, drain, cancellation-wait, cleanup, admission, and buffering bounds must be explicitly configured and evidenced; no legacy timeout or queue setting becomes a portfolio-wide constant through this PRD. [inferred: contracts/02-external-connector.yaml, EXT-BOUNDS; contracts/03-internal-browser-binding.yaml, reconciliation]

Browser-state policy and framework-learning-state policy are separately requested and observed; a fresh fixture record or new browser tab proves neither native isolation nor clean learned state. [extracted: contracts/02-external-connector.yaml, EXT-STATE-POLICY; 3-hellscape-blueprint.md, §§3.4 and 4.3]

A crash around delivery creates dispatch uncertainty unless stronger evidence resolves it; authorized same-key resume requires the existing handle, compatible context, recovery authority, and an evidenced native checkpoint/idempotency contract. [extracted: contracts/02-external-connector.yaml, EXT-START, EXT-IDEMPOTENCY, and EXT-RESUME]

### 4.3 Observation → origin fact → report

| Axis | Sole authoritative source | Meaning retained by integration |
|---|---|---|
| Dispatch | Connector | Intended delivery, local handle, native acceptance evidence, rejection, or uncertainty. [extracted: contracts/01-application-attempt-lifecycle.yaml, ownership] |
| Observation | Connector; manual recorder in wholly manual execution | What was observable, local bounds, closure, drain, cleanup, and immutable close-time knowledge. [extracted: contracts/01-application-attempt-lifecycle.yaml, ownership and LIFE-MANUAL] |
| Execution | Subject | Authenticated, correlated subject claims, faithfully published without strengthening their scope. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-CLAIMS] |
| Application | Origin | Fixture transactions for practice, or verified employer-origin receipts for production; a designated recorder preserves rather than acquires that authority. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-ORIGIN] |
| Report | Reconciler | Comparisons over pinned source revisions, writing only report and never repairing either input axis. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-RECONCILE] |

A native `/run` response saying `completed` initially establishes an execution-lifecycle claim, not application commitment; a successful primitive, `None`, HTTP 200, or a signed callback does not independently prove semantic success, authentication, and attempt correlation. [extracted: 3-hellscape-blueprint.md, §§1.3 and 4.6; 5-browser-qualification.md, evidence discipline]

Authentication, attempt correlation, and trace correlation remain separate checks: authenticated but uncorrelated evidence is retained without attaching it to an arbitrary attempt, while an evidenced alternate correlation may resolve a trace defect. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-SOURCE-CHECKS]

For example, closed observation, unknown native execution, a close-time `outcome_unknown` claim, and a later verified commitment can all be valid; the late fact creates new publications and a new assessment without contradicting honest earlier uncertainty or rewriting the close-time snapshot. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE-CLOSE, LIFE-LATE-EVIDENCE, and reconciliation algorithm]

A definite no-commitment assertion can be contradicted only at its actual scope and temporal boundary; later receipt time alone does not prove later occurrence, and a stopped claim does not undo an already dispatched origin transaction. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-RECONCILE and LIFE-TIME]

`reconciled` means the declared comparisons were accounted for, not that the application succeeded; undecidable report state uses reasoned missingness rather than a third success value. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-REPORT-COVERAGE]

## 5. Durable exchange, evidence, and learning

### 5.1 Owner-separated exchange

Every write domain has one authenticated logical writer; local workers act through that owner’s fenced gateway, while consumers import publications rather than opening cross-owner transactions. [extracted: contracts/04-owner-separated-write-domains.yaml, ownership rules]

The exchange unit is an immutable owner publication with its referenced artifacts and journal support; explicit artifact export/import is sufficient for the initial manual path, while automated delivery can use a deployment-specific transport without changing the record semantics. [proposed: support incremental integration without choosing a shared database or broker]

Before acknowledgement, a locally authoritative operation durably commits its admitted input, idempotency record, effects, journal entries, and replayable response within that owner; artifacts exist durably before journal references cite them. [extracted: contracts/00-evidence-kernel.yaml, EK-ATOMICITY and EK-ARTIFACTS]

Publication to readers is asynchronous: a read view installs a complete old-or-new logical root, and a seal identifies the named state and exact owner revision vector rather than claiming that every owner was globally current at one instant. [inferred: contracts/04-owner-separated-write-domains.yaml, LogicalRow, SealPoint, and proposed read-root mechanism]

| Logical entity | Independently owned domains |
|---|---|
| Job | `crawler` and `downstream`; a downstream attempt link is not an application fact. [extracted: contracts/04-owner-separated-write-domains.yaml, job layout] |
| Application attempt | `dispatch`, `observation`, `execution`, `application`, and `report`; commissioning is immutable metadata, not a sixth outcome axis. [extracted: contracts/04-owner-separated-write-domains.yaml, attempt layout] |
| Hellscape session | `application`, `observation`, and `diagnostic`; a pinned copy of attempt observation is not a second lifecycle authority. [extracted: contracts/04-owner-separated-write-domains.yaml, session layout] |

A different-fetch-key replacement archives the complete prior published job row at its named vector, including downstream data and registration, using immutable content-addressed extents with transitive retention; it cannot wait for downstream payload serialization or a cross-owner acknowledgement in the crawler critical path. [extracted: contracts/04-owner-separated-write-domains.yaml, archive encoding and expansion; decisions/invariants-and-provisionals.md, INV-26]

Same-fetch-key content writes remain no-ops under the retained contract, including after changed content or a failed render; a freshness remedy needs an explicit versioned decision, not a hidden run nonce. [extracted: decisions/invariants-and-provisionals.md, §5; contracts/04-owner-separated-write-domains.yaml, source reconciliation]

### 5.2 Evidence discipline at every boundary

- **Citable means journaled.** Hash-check imported evidence, retain its original scope and trust, and journal its local registration; storage on a server does not promote a manual observation or subject claim into an origin fact. [inferred: contracts/00-evidence-kernel.yaml, EK-JOURNAL, EK-HASHES, and EK-PROVENANCE]
- **Missingness is explicit.** Null reasons are exactly `not_enabled`, `not_applicable`, `not_observed`, `observation_lost`, `unsupported_by_subject`, and `manual_override`; zero, false, empty, missing, and unknown cannot substitute for one another. [extracted: contracts/00-evidence-kernel.yaml, EK-NULL]
- **Timing is scoped.** Every measurement identifies origin, clock, and boot; duration is exact, bounded, or unavailable with reason and censoring, with no cross-clock or cross-boot subtraction and UTC used only as annotation. [extracted: contracts/00-evidence-kernel.yaml, EK-TIME]
- **Reported timing stays reported.** Native zero remains exact zero at its declared origin, beside independently measured intervals where available; neither division of a task total nor a controller timeout manufactures primitive timing or native timeout. [extracted: 3-hellscape-blueprint.md, §4; 5-browser-qualification.md, evidence discipline]
- **Capability is not performance.** Capability availability, opportunity, and result remain orthogonal; descriptors apply only to the exact subject/version/mode/interface, with new versions starting unknown rather than inheriting qualification. [extracted: contracts/00-evidence-kernel.yaml, EK-CAPABILITY and EK-ASSESSMENT]
- **Replay is not re-execution.** Exact fixture replay invokes no browser, subject, or external mutation; production evidence can support diagnostic re-derivation without implying replay of an employer application. [extracted: contracts/00-evidence-kernel.yaml, EK-REPLAY and ReplayReceipt]

### 5.3 Practice, production, and the learning loop

Hellscape sessions remain practice and held-in even when their task text uses real crawler content; employer origins remain held-out, and no practice commitment contributes to production commitment counts or automatically authorizes an origin. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE; 1-handoff-brief.txt, Part III]

`kind` is immutable, `derived_from` is same-kind, and rehearsal/performance links record relationships without transferring evidence credit; copied task content does not change these rules. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LINEAGE]

The learning loop is: retained execution evidence → scoped diagnostic finding → supported rule instance under a human-approved rule class → product-owner change → separately evidenced candidate version; each stage preserves its own authority and does not imply the next occurred. [inferred: contracts/05-suggested-fix-registry.yaml, ownership and semantic rules]

A recommendation requires diagnostic support, scope match, required evidence, contraindication checks, and a falsifiable verification plan; unsupported causal attribution yields a reasoned missing suggestion rather than a plausible repair. [extracted: contracts/05-suggested-fix-registry.yaml, FIX-REQUIRED-EVIDENCE, FIX-ATTRIBUTION, FIX-CONTRAINDICATIONS, and FIX-RECOMMEND]

Native selector healing and cache updates remain authorized executor behavior, not automatically reviewed registry fixes; Circus Tent and Ringmaster retain separate learning-state histories and per-subject curriculum lineages. [extracted: decisions/invariants-and-provisionals.md, INV-30 and P-12]

Registry implementation is deferred to M3; manually authored reviewed records may be used earlier, but neither registry deployment nor a non-null suggestion is required for M1 or a production application. [extracted: contracts/05-suggested-fix-registry.yaml, Step 0 scope]

### 5.4 Privacy and control boundaries

Candidate materials, account access, and raw native bodies must remain access-classified; task/artifact permissions are scoped to the commissioned work, and secrets or personal data must not enter public repositories or ordinary logs. [inferred: contracts/00-evidence-kernel.yaml, EK-ARTIFACTS; contracts/02-external-connector.yaml, EXT-AUTHORITY; 6-get-a-job.xml.txt, AGENTS.md]

Credential references are resolved inside the authorized runtime rather than embedded as control credentials in tasks; Circus Tent’s environment-name configuration policy can coexist with a separately selected product secret store. [inferred: 4-circus-tent-arch.md, §2; contracts/02-external-connector.yaml, runtime access and authority rules]

Hellscape receives synthetic identities and documents, not the candidate’s live application identity; its application, telemetry, and control planes remain separately authorized, and fixture-client telemetry cannot emit commitment or server-verification success. [extracted: 3-hellscape-blueprint.md, §§1 and 3]

Redaction creates a separately identified export without rewriting retained evidence bytes or hashes; restricted raw evidence and its redacted presentation must not be confused. [inferred: contracts/00-evidence-kernel.yaml, EK-HASHES and EK-ARTIFACTS; contracts/05-suggested-fix-registry.yaml, canonicalization]

## 6. Delivery sequence and silo gates

The invariant is that each component ships against its own conformance suite before peer integration; another component’s availability or ability to complete a task is not its shipping prerequisite. [extracted: 1-handoff-brief.txt, Parts IV and VIII]

### 6.1 Parallel lanes

| Lane | First independently useful result | What it does not wait for |
|---|---|---|
| **Day-one product operation** | Manual discovery/evaluation/application with durable evidence, truthful outcome tracking, and a next action. | Crawler, reranker, Hellscape, executor, registry, or dashboard completion. [inferred: decisions/invariants-and-provisionals.md, HA-03] |
| **Kernel reference / Hellscape M1** | Cooperative manual walkthrough, valid diagnostic, durable journal/state, measured pause, one fixture commitment, and matching exact replay. | A live automation subject, native cancellation, hostile packs, or production fingerprint capture. [extracted: 1-handoff-brief.txt, Part IX; 3-hellscape-blueprint.md, §§8 and 15] |
| **Illinois discovery** | Useful source-backed job publications with per-partition coverage and owner-separated writes. | Ringmaster DOM/action work or resolution of unrelated state activation blockers. [inferred: decisions/invariants-and-provisionals.md, HA-01 and HA-02] |
| **Ringmaster** | Independently implemented external connector and BrowserOxide-native binding evidence for the exercised scope. | Circus Tent internals, a universal browser driver, or a live employer in CI. [inferred: 1-handoff-brief.txt, Part VIII; current request, Products] |
| **Circus Tent** | Maintained, honestly identified compatibility route, plus separately evidenced extension-route work. | BrowserOxide readiness or a claim that legacy-route conformance proves the extension route. [inferred: contracts/03-internal-browser-binding.yaml, Camoufox boundary and CF-ROUTE] |
| **job-hunter automation** | Feed consumption, profile-backed evaluation, durable commissioning, and tracking against fixtures; then a cooperative Hellscape practice integration. | A final language choice before manual operation, or a subject-completion guarantee from Hellscape. [inferred: 1-handoff-brief.txt, Parts VII–IX] |
| **Later learning services** | Supported diagnosis, reviewed matching/verification, then per-subject curriculum and held-out evaluation. | Their completion is not required to keep applying manually. [extracted: 1-handoff-brief.txt, Parts VII–IX; 3-hellscape-blueprint.md, §7] |

There is no resurrected M0 qualification gate: retired qualification evidence informs enforced conformance, while Hellscape begins at M1 with manual correctness and synthetic connector backends. [extracted: 1-handoff-brief.txt, Parts I and VIII; 3-hellscape-blueprint.md, §§1 and 7]

Promotion to more autonomous production execution is a separately authorized origin/task/subject decision; practice success alone cannot trigger it, and the manual lane remains available while evidence accumulates. [proposed: apply decisions/invariants-and-provisionals.md, P-14 without turning laboratory progress into production permission]

### 6.2 Contract gates

| Suite | Required integration use |
|---|---|
| `conformance/00-evidence-kernel.md` | Producers and consumers validate provenance, missingness, clocks, durable effects, evidence references, diagnostics, leases, and applicable replay behavior. [extracted: contracts/00-evidence-kernel.yaml] |
| `conformance/01-application-attempt-lifecycle.md` | Manual recorder, connector publishers, origin-fact recorder, and reconciler demonstrate five-owner separation, idempotency, closure, late evidence, and kind/lineage rules. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `conformance/02-external-connector.md` | Each executor and its consumers exercise faithful translation and bounded lifecycle behavior against synthetic backends before a live peer. [extracted: 1-handoff-brief.txt, Part VIII; contracts/02-external-connector.yaml] |
| `conformance/03-internal-browser-binding.md` | Run separately for BrowserOxide and Camoufox, with declared per-browser scope and exemptions; an Illinois HTTP result does not certify DOM actions, and Camoufox compatibility results do not certify extension bypass. [inferred: contracts/03-internal-browser-binding.yaml; decisions/invariants-and-provisionals.md, HA-04] |
| `conformance/04-owner-separated-write-domains.md` | Exercise all three record compositions, concurrency, lag, old-or-new reads, full-row archives, and retention under the selected deployment. [extracted: contracts/04-owner-separated-write-domains.yaml] |
| `conformance/05-suggested-fix-registry.md` | Validate schema and recommendation semantics without requiring a deployed registry; disabled recommendations remain explicitly disabled. [extracted: contracts/05-suggested-fix-registry.yaml] |

These are six suite documents with separate internal-binding executions — seven suite instances per HA-04 — not a single whole-system pass/fail test; required skipped cases, invalid controls, missing dependencies, and harness failures remain distinguishable from subject failures. [inferred: decisions/invariants-and-provisionals.md, HA-04; 5-browser-qualification.md, evidence discipline]

CI uses local fixtures and synthetic backends, never live employer writes; actual production evidence is an authorized operating activity and must not be synthesized from CI results. [extracted: 6-get-a-job.xml.txt, AGENTS.md; 5-browser-qualification.md]

## 7. Integration acceptance and operating measures

The following proposed integration scenarios supplement, rather than replace, the contract suites; each retains its manifest, journal, referenced artifacts, relevant owner publications, and assessment evidence. [proposed: test boundary assembly after components have proved their own contracts]

| Scenario | Acceptance oracle |
|---|---|
| **Manual operation with peers absent** | With crawler, executors, and Hellscape unavailable, a manually captured job can be evaluated, commissioned, applied to, and tracked without fabricated native fields; commitment is counted only when verified origin evidence exists. [proposed: acceptance for HA-03 and LIFE-MANUAL] |
| **Candidate-specific decision trace** | A reviewer can trace selection and materials to the exact job/profile inputs, matched playbooks, blockers, and unresolved preferences; title similarity or a generic score alone cannot explain approval. [proposed: make the supplied capability profile operational rather than decorative] |
| **Publication lag and replacement** | Concurrent crawler/downstream writes yield only complete pinned views; replacement reconstructs the entire archived prior row, and a lagging report/evaluation remains visibly tied to its original inputs. [proposed: integrated acceptance for owner-separated publication and immutable evaluation inputs] |
| **Ambiguous dispatch** | A crash around native delivery produces a retained handle and uncertainty, with no new-key retry or executor switch; repeated Start returns the same logical execution identity. [proposed: integrated acceptance for EXT-START and EXT-IDEMPOTENCY] |
| **Close followed by late evidence** | Closure remains immutable, late evidence is appended, source axes are preserved, and a new report does not falsely contradict an honest close-time unknown claim. [proposed: integrated acceptance for LIFE-LATE-EVIDENCE and LIFE-RECONCILE] |
| **Authentication/correlation disagreement** | A valid signature with unresolved attempt correlation remains unassigned evidence; conflicting authenticated responses are preserved rather than deduplicated into a convenient result. [proposed: integrated acceptance for LIFE-SOURCE-CHECKS and EXT-NORMALIZE] |
| **Practice boundary** | Real job text in Hellscape produces only practice evidence; rehearsal/performance links cannot increase production commitment counts or transfer capability credit to another version. [proposed: integrated acceptance for LIFE-LINEAGE and EK-CAPABILITY] |
| **Kernel reference walkthrough** | Invalid history is rejected and corrected, the human pause appears in the correct elapsed interval, exactly one fixture commitment exists, and replay matches without browser or subject execution. [extracted: 3-hellscape-blueprint.md, manual acceptance procedure] |
| **Supported learning** | An eligible fix resolves to its exact approved class, scoped evidence, contraindication checks, and plan; unsupported attribution yields missingness, and an implemented candidate receives new-version evidence. [proposed: integrated acceptance for the fix-registry contract] |

The operating view must separately expose jobs evaluated, decisions awaiting owner input, production attempts, verified origin commitments, unresolved outcomes, manual assistance, and follow-up actions; practice sessions and engineering throughput belong in separate views. [proposed: keep the portfolio’s actual purpose visible without collapsing lifecycle axes]

Discovery measures must retain partition and proof context, while executor measures retain subject/version/route and assistance context; neither a laboratory completion rate nor a browser benchmark is a production application rate. [inferred: 2-state-bank-crawler-blueprint.json, §7; 3-hellscape-blueprint.md, §§2 and 7]

No actual operating counts or performance measurements are supplied with this draft; the first operating report must record observed values and limitations rather than treating absence of data as zero or success. [uncertain: production operating evidence is not supplied; collect it through the day-one lane]

## 8. Decisions and evidence debt

The exhaustive invariant and provisional registers remain in `decisions/invariants-and-provisionals.md`; the following unresolved inputs affect integration implementation, not permission to suspend manual job-search work. [inferred: decisions/invariants-and-provisionals.md, §§6–9]

| Question | Next evidence and consequence |
|---|---|
| **job-hunter language and canonical storage** | Select when durable scheduling/storage implementation requires it, comparing maintenance cost, library fit, and conformance effort; do not inherit TypeScript/Firebase solely from the retired Stagehand rationale. [extracted: decisions/invariants-and-provisionals.md, P-07 and P-15] |
| **Automated publication transport and artifact custody** | Choose deployment adapters and prove bounded publication, import deduplication, digest verification, independent owner commits, and retention; shared-table names alone do not establish independent I/O service. [proposed: defer transport packaging while enforcing contracts/04-owner-separated-write-domains.yaml and Stage1 A2/A7] |
| **BrowserOxide build and Ringmaster package** | Pin the actual engine source/build and prove required native actions, capture, ownership, and lifecycle behavior before locking packaging or advertising capability. [uncertain: current native API/build evidence is not supplied; execute the reconnaissance in decisions/invariants-and-provisionals.md, §6.1] |
| **Firefox extension feasibility** | Establish supported Camoufox packaging, privileges, transport, event semantics, frame/root access, upload, capture, and bounded control; keep compatibility-route evidence distinct meanwhile. [uncertain: no implemented extension surface or current qualification evidence is supplied; contracts/03-internal-browser-binding.yaml] |
| **Current Illinois surface** | Verify the supplied deterministic per-run, HTTP-first, full-description allocation against authorized current observations; if it no longer offers the smallest useful slice, apply P-08 rather than expanding reflexively to five states. [inferred: 2-state-bank-crawler-blueprint.json, §§3 and 8; decisions/invariants-and-provisionals.md, P-08] |
| **Crawler backlog** | Preserve the four `INCOMPLETE` markers and nine `ASSUMED` values as unresolved until their named evidence exists; an Illinois-only delivery does not close unrelated debts. [extracted: decisions/invariants-and-provisionals.md, §§7–8] |
| **Production origin mappings** | Establish receipt authentication, candidate/job/attempt correlation, and temporal scope per origin; absent receipt remains unknown, and no universal final-absence mapping is presumed. [uncertain: current per-origin mappings are absent; contracts/01-application-attempt-lifecycle.yaml, open evidence] |
| **Registry artifact completeness** | Run executable registry intake with structural plus FIX validation against the retained complete contract; the retained `contracts/05-suggested-fix-registry.yaml` fully defines `RuleClass`, `RuleScope`, `RuleInstance`, `VerificationPlan`, `RegistrySnapshot`, `FixReference`, and `VerificationReceipt` (the shortened copy shown at generation time did not). [uncertain: executable intake validation against the retained registry contract has not been run; run it before registry-dependent implementation] |

Detailed product requirements belong in the sibling PRDs: Hellscape in `prd/01-hellscape.md`, discovery in `prd/02-crawler.md`, Circus Tent in `prd/03-circus-tent.md`, Ringmaster in `prd/04-ringmaster.md`, and candidate-facing product policy in `prd/05-job-hunter.md`; none may silently redefine the shared contracts. [proposed: preserve independent product ownership while keeping one versioned integration language]

The portfolio succeeds by replacing manual steps with trustworthy machinery while continuing to produce real applications—not by waiting until every layer is complete before asking the candidate to apply. [inferred: current request, Purpose; 1-handoff-brief.txt, Parts VII, IX, and X]
