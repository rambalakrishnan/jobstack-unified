# Circus Tent — Camoufox application executor

**Status:** Step 0 review draft; requirements and acceptance targets below are not evidence that a deployment, browser route, or employer origin has passed them. [proposed: distinguish intended behavior from observed qualification]

**Implementation:** Python controller and Camoufox-specific execution machinery, with a browser-resident Firefox extension as the target page-operation surface; Ringmaster is a separate Rust/BrowserOxide product, not another backend inside Circus Tent. [extracted: current request, Products; decisions/invariants-and-provisionals.md, P-03 and P-04]

**Contract baseline:** the six `0.1.0` shared contracts, particularly the external connector and the independently defined Camoufox document within `contracts/03-internal-browser-binding.yaml`. [extracted: decisions/invariants-and-provisionals.md, Contract baseline]

**Decision baseline:** the invariant register, P-04’s extension direction, P-14’s initial human-controlled production policy, and HA-03’s independent manual application lane; this PRD introduces no further handoff amendment. [proposed: implement the recorded decisions without silently changing shared contracts]

## 1. Product purpose and first useful outcome

Circus Tent executes authorized application work for the candidate: navigate employer forms, enter approved information, upload approved documents, handle ordinary validation, and submit when the commission permits it. [inferred: 1-handoff-brief.txt, Position and component interface notes; 4-circus-tent-arch.md, §§1 and 4]

Its value is reducing the effort and failure rate of real applications while preserving enough evidence to understand each attempt; building an impressive browser framework without producing applications is not success. [inferred: current request, Purpose]

The first useful release need not solve every portal or complete every fixture: it must faithfully execute its supported scope, expose limitations, preserve uncertain outcomes, and permit disclosed human assistance without misreporting it as unattended execution. [inferred: 1-handoff-brief.txt, Parts VIII–IX; 3-hellscape-blueprint.md, M2; 5-browser-qualification.md, evidence discipline]

Manual applications continue while Circus Tent is incomplete, including while the extension route is being investigated; neither Circus Tent nor Hellscape is a prerequisite for the day-one production lane. [extracted: decisions/invariants-and-provisionals.md, HA-03; prd/00-integration.md, §2]

### 1.1 Responsibilities and exclusions

| Circus Tent owns | It does not own |
|---|---|
| Camoufox-specific browser/profile lifecycle, execution, extraction, selector resolution, and learn-run-heal behavior. | Ringmaster internals, a shared cross-browser driver, or a common `ElementHandle`. [extracted: 1-handoff-brief.txt, Parts III and VI; current request, Products] |
| Faithful implementation of the external connector, including bounded observation and retained native claims. | Independent qualification, requirement satisfaction, or authoritative employer commitment. [extracted: contracts/02-external-connector.yaml, EXT-DECLARE-NOT-ASSESS] |
| Execution of a supplied, authorized task using exact approved materials and disclosed assistance. | Candidate scoring, deciding which jobs to pursue, inventing application answers, or expanding task permissions. [inferred: 1-handoff-brief.txt, component interface notes; contracts/02-external-connector.yaml, EXT-AUTHORITY and EXT-TASK] |
| Native selector healing and product-owned learning state within the commissioned limits. | Automatic application of registry recommendations, automatic source repair, or changing the application’s business meaning to make a step pass. [inferred: decisions/invariants-and-provisionals.md, INV-29 and INV-30] |
| Credentialed interaction with explicitly permitted origins. | A general crawler, unrestricted browser agent, or promise of production bot-detection resistance. [inferred: 4-circus-tent-arch.md, §1; contracts/02-external-connector.yaml, EXT-AUTHORITY] |

The documented `/run` interface consumes explicit steps, not goals; job-hunter or a disclosed external planner must produce that plan before `Prepare`, rather than relying on an undisclosed Circus Tent planner. [extracted: 3-hellscape-blueprint.md, §5; contracts/02-external-connector.yaml, EXT-PREPARE]

## 2. Architecture: repair the controller-to-page boundary

### 2.1 Existing route versus target route

The identified compatibility route is **Python → Playwright → Juggler → Camoufox**, with two protocol layers between controller and page; the older blueprint’s “no Juggler layer” description does not govern this design. [extracted: current request, Products]

The target is **Python controller ↔ Firefox extension ↔ browser-resident operations**, following the useful architectural pattern of Stagehand’s ModCDP rather than porting Stagehand or sharing its implementation. [extracted: current request, Products]

Moving DOM pruning into `page.evaluate()` is valuable but does not, by itself, remove the Playwright/Juggler boundary; the extension work must expose a richer browser-resident surface, not merely relocate the same pruning script behind the old transport. [inferred: current request, Products; 4-circus-tent-arch.md, §§5–6]

The following is a responsibility sketch, not a specified transport protocol or an assertion that the extension exists. [proposed: make the target boundary concrete without inventing native APIs]

    job-hunter or other authorized consumer
                     |
          asynchronous task connector
                     |
        Python Circus Tent controller
       plans / budgets / learn-run-heal
       profiles / evidence / extraction
                     |
        Camoufox-only primitive binding
          synchronous Python boundary
                     |
       authenticated extension channel
                     |
         Firefox-resident extension
      document/frame/root bookkeeping
      semantic reduction and resolution
      evidenced input / waits / capture
                     |
                  Camoufox

A passed compatibility-route test does not certify extension bypass, extension privileges, or full-strength native access. [extracted: contracts/03-internal-browser-binding.yaml, CF-ROUTE]

### 2.2 Placement of responsibilities

| Location | Responsibility | Boundary requirement |
|---|---|---|
| Python external connector | Authentication, authorization, immutable preparation, durable handles, bounded dispatch/observation, artifacts, and controls. | Exposes task operations, not browser objects or primitive handles. [extracted: contracts/02-external-connector.yaml] |
| Python execution engine | Explicit-plan execution, selector tiers, checkpoints, budget accounting, healing decisions, and product learning state. | Preserves supplied order, targets, values, permissions, and side-effect constraints. [inferred: 4-circus-tent-arch.md, §§4–5; 3-hellscape-blueprint.md, §5.4] |
| Python extraction services | Local relevance filtering, markdown construction, and deterministic schema extraction from reduced content. | Does not require a second browser launch or an LLM to invent missing fields. [extracted: 4-circus-tent-arch.md, §§5–6] |
| Firefox extension | Browser-resident context accounting, bounded reduction, target resolution, observations, and those action/capture operations its verified privileges support. | Reports inaccessible boundaries and unsupported mappings rather than claiming omniscience because it runs inside the browser. [proposed: implement the ModCDP-equivalent direction subject to the Camoufox binding’s capability and structure rules] |
| Browser/profile owner | Exclusive profile ownership, immutable fingerprint association, launch, drain, flush, and process exit. | Remains distinct from tab identity, document lifetime, and learned selector state. [extracted: contracts/03-internal-browser-binding.yaml, CF-PROFILE and CF-STATE] |

Python remains the controller implementation; the requested Firefox extension is not prohibited by the historical “single-runtime Python” principle, and does not justify adding an unrelated controller runtime or merging Circus Tent with another product. [inferred: current request, Products; decisions/invariants-and-provisionals.md, §5]

The binding is synchronous and primitive-shaped at its Python-facing boundary even if its implementation uses an asynchronous channel; primitive calls return a value, typed failure, unsupported result, or uncertainty—not a task handle. [extracted: contracts/03-internal-browser-binding.yaml, CF-SYNC]

Long-running primitive work must not block external API servicing or defeat local observation deadlines; the implementation must separate primitive execution from connector request handling while retaining the verified route’s context-affinity requirements. [proposed: reconcile a synchronous native boundary with the asynchronous connector and bounded waiting obligations]

### 2.3 Required browser-resident surface

These are product requirements mapped to the proposed Camoufox binding, not claims about existing Firefox extension APIs. [proposed: distinguish contract-level operations from native implementation evidence]

| Surface | Required behavior | Evidence needed before advertisement |
|---|---|---|
| Context tree | Account for top document, frames, and accessible roots; identify unreadable and unobserved boundaries. | Frame/root fixtures, document replacement, and access-denial observations for the pinned browser/extension build. [inferred: contracts/03-internal-browser-binding.yaml, CF-STRUCTURE] |
| Semantic reduction | Reduce in-browser before transfer; retain useful text, labels, roles, titles, alternatives, and icon semantics under `EXTRACT` or `HEAL` profiles. | Retained input/output specimens, byte-budget enforcement, and omissions explicitly marked rather than silently dropped. [inferred: 4-circus-tent-arch.md, §§5–6; contracts/03-internal-browser-binding.yaml, CF-STRUCTURE] |
| Target resolution | Resolve CSS, role, label, or text within explicit document/root scope; return bounded matches and completeness. | Ambiguous matches, stale documents, node replacement, frame changes, and open-root traversal tests. [extracted: contracts/03-internal-browser-binding.yaml, CFResolveTarget and CFMatches] |
| Input | Preserve the distinction between native browser input and DOM property mutation plus events. | Readback, observed event semantics, and independently observed application effects; synthetic events must not be labeled browser-trusted. [extracted: contracts/03-internal-browser-binding.yaml, CF-INPUT] |
| Upload | Use approved artifact bytes with declared file-input or synthetic drag/drop mapping. | File contents, size/type enforcement, resulting events, and fixture-side upload verification; assignment alone is not upload success. [inferred: 4-circus-tent-arch.md, §5; contracts/03-internal-browser-binding.yaml, CF-INPUT] |
| Scoped waits | Evaluate explicit read-only conditions within a local bound. | Ready, false, timed-out, interrupted, and document-invalidated cases; network quiet is not a semantic postcondition. [inferred: contracts/03-internal-browser-binding.yaml, CFAwaitCondition and reconciliation] |
| Capture | Produce localized images with document identity and actual coordinate geometry. | Scale, viewport, frame-offset, layout-change, and stale-image cases before using coordinates for input. [extracted: contracts/03-internal-browser-binding.yaml, CF-IMAGE] |
| Lifecycle | Open and close tabs, navigate, and retire profiles with observed lifecycle evidence. | Exclusive profile ownership, stale-token rejection, flush/exit behavior, and no reuse before the prior owning process exits. [inferred: contracts/03-internal-browser-binding.yaml, CF-PROFILE; 4-circus-tent-arch.md, §7] |

A `CFTargetRef` is a binding-local, document-lifetime target identity, not a durable selector, transferable DOM object, or Playwright handle; learned selectors may survive under their own validation policy, but target tokens do not survive document invalidation. [extracted: contracts/03-internal-browser-binding.yaml, Camoufox representation rules]

Closed-root access, cross-origin access, trusted input, upload privileges, capture, and native interruption remain independently evidenced capabilities; extension residency does not establish any of them automatically. [inferred: contracts/03-internal-browser-binding.yaml, open evidence and CF-CAPS]

### 2.4 Channel and privilege design

The extension channel must bind messages to the authorized controller instance, browser/profile lifetime, and document context; content from the page must not be able to impersonate controller commands or assign evidence provenance. [proposed: enforce task authority and server-assigned provenance across the new browser-resident boundary]

Page-visible code must not receive control credentials, unrestricted local-file access, or a general privileged-evaluation facility; extension permissions and any page-world bridge require a reviewed least-privilege design. [proposed: avoid converting a richer observation surface into a page-controlled privileged deputy]

The sources do not select a transport, signing arrangement, supported extension packaging, or exact Firefox permissions; reconnaissance must establish these against the actual Camoufox build before the channel is specified or advertised. [uncertain: no implemented extension protocol or current privilege inventory is supplied; inspect Camoufox extension support and exercise candidate channels on local fixtures]

An extension-native attempt must not silently fall back through Playwright/Juggler for missing page operations; the route is pinned, and a missing required mapping is a preparation or execution limitation rather than permission to mislabel a mixed route. [inferred: contracts/03-internal-browser-binding.yaml, CF-ROUTE; contracts/02-external-connector.yaml, EXT-PREPARATION-PIN]

Changing route does not authorize resubmission after an uncertain side effect; evidence and explicit recovery authority must resolve the existing attempt before another execution is considered. [inferred: contracts/02-external-connector.yaml, EXT-IDEMPOTENCY and EXT-RESUME]

## 3. Execution behavior: learn, run, heal

### 3.1 Authorized task intake

Before execution, Circus Tent must know the exact subject/build/route, task, supplied plan, permitted origins/interfaces, account access references, approved documents, browser-state policy, learning-state policy, and commissioned limits. [extracted: contracts/02-external-connector.yaml, EXT-TASK and EXT-PREPARATION-PIN]

`Prepare` validates those supplied inputs without visiting the target, testing authentication, resetting context, invoking a planner, or silently improving the plan; live auth preflight belongs after `Start` under task authority. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE; 4-circus-tent-arch.md, §5]

A missing auth marker is retained as a session/authentication observation and may require a human handoff; HTTP 200 alone cannot establish that login succeeded. [inferred: 4-circus-tent-arch.md, §5; 5-browser-qualification.md, evidence discipline]

### 3.2 Native execution loop

| Phase | Product requirement |
|---|---|
| Learn | Associate usable selectors and extraction knowledge with their origin, profile/configuration scope, task semantics, and evidence; a cached choice is a hypothesis to validate, not an authorization. [proposed: retain learn-run-heal utility while preventing cache reuse from bypassing task scope] |
| Run | Execute the explicit plan using the documented action families—navigate, fill, click, select, wait, extract, assert, upload, and checkpoint—where the selected native mapping is established. [extracted: 4-circus-tent-arch.md, §4] |
| Verify | Separate primitive return, observed interaction, validation result, and application postcondition; advancing the plan requires the declared condition, not merely lack of an exception. [inferred: 5-browser-qualification.md, evidence discipline; 3-hellscape-blueprint.md, §§4 and 9] |
| Heal | Escalate selector resolution within the configured recovery/token limits without changing approved values, task intent, permissions, or application answers. [inferred: 4-circus-tent-arch.md, §§4–6; contracts/02-external-connector.yaml, EXT-TASK] |
| Stop or hand off | Preserve unmet conditions, limitations, and uncertain side effects; report a useful partial execution instead of fabricating completion. [inferred: 3-hellscape-blueprint.md, §§4–5; contracts/02-external-connector.yaml, EXT-FAILURE] |

### 3.3 Tiered selector resolution

| Tier | Mechanism | Guardrail |
|---|---|---|
| 1 — cached/local | Try validated selectors and deterministic semantic resolution without model calls. | Recheck document identity, uniqueness, and the intended target before input; a cache hit does not override ambiguity. [inferred: 4-circus-tent-arch.md, §§4–5; contracts/03-internal-browser-binding.yaml, CFResolveTarget] |
| 2 — text healing | Use reduced DOM, fallback text, and the failed selector to request a structured selector proposal. | Validate the response shape and proposed target locally; malformed-output repair and the documented limited retry are not permission to invent a new plan. [inferred: 4-circus-tent-arch.md, §5] |
| 3 — localized vision | Use a localized crop, image identity, and coordinate proposal when text resolution is inadequate. | Validate current geometry and layout before clicking; stale crop/hash reuse must not authorize an action on a changed page. [inferred: 4-circus-tent-arch.md, §5; contracts/03-internal-browser-binding.yaml, CF-IMAGE] |

Successful native healing may update the product’s selector cache, but the update must retain its originating evidence, revision, scope, and changed confidence; it does not become a reviewed fix-registry result merely because a model proposed it. [inferred: 4-circus-tent-arch.md, §5; decisions/invariants-and-provisionals.md, INV-30]

DOM text and images are untrusted task data; instructions embedded in an employer page must not expand the task, reveal secrets, change approved answers, or override control policy. [proposed: protect the planner/healer boundary from page-supplied instruction content]

A failed response after a possibly side-effecting click is not a selector-healing opportunity until delivery and effect uncertainty are addressed; another selector must not become a disguised retry of submission. [inferred: contracts/02-external-connector.yaml, EXT-IDEMPOTENCY and EXT-RESUME]

### 3.4 Extraction and model use

DOM reduction remains browser-resident, followed by local BM25/pruning/markdown processing and deterministic schema extraction; unsatisfied fields produce partial output and a limitation, not model-generated substitutes. [extracted: 4-circus-tent-arch.md, §§5–6]

The blueprint’s network-idle and mutation-quiet heuristics may support stabilization, but cannot establish form readiness, complete extraction, or application success without scoped predicates. [extracted: contracts/03-internal-browser-binding.yaml, Camoufox reconciliation]

Heal and vision usage must be separately bounded and accounted for, with configured session/shard limits and explicit behavior when a tier is disabled or exhausted. [extracted: 4-circus-tent-arch.md, §6]

Crawl4AI, LiteLLM, the named heal/vision providers, and their historical versions are implementation choices from the blueprint, not portfolio-wide dependencies; a release must pin its actual configuration and verify changed providers against the same semantic and cost boundaries. [inferred: 4-circus-tent-arch.md, §§3, 6, and 9; contracts/00-evidence-kernel.yaml, versioned evidence discipline]

## 4. External connector and attempt lifecycle

### 4.1 Shared operations, honest mappings

Circus Tent recognizes the same nine asynchronous task verbs as Ringmaster, while implementing all browser execution independently. [extracted: 1-handoff-brief.txt, Parts V–VI; current request, Products]

| Verb | Circus Tent obligation |
|---|---|
| `Describe` | Publish the exact subject/version/mode/route descriptor, operation mappings, capability evidence, and configured bounds; declare rather than assess. [extracted: contracts/02-external-connector.yaml, EXT-DESCRIBE] |
| `Prepare` | Produce an immutable, non-executing preparation or reject missing required mappings/authority; disclose concerns requiring acceptance. [extracted: contracts/02-external-connector.yaml, EXT-PREPARE and EXT-PREPARATION-PIN] |
| `Start` | Durably allocate the local handle, request binding, idempotency association, and delivery intent before native delivery; return local admission without waiting for completion. [extracted: contracts/02-external-connector.yaml, EXT-START] |
| `Observe` | Return registered observations in journal order for the exact handle and pinned cutoff; retain raw native bodies and faithful normalized claims. [extracted: contracts/02-external-connector.yaml, EXT-OBSERVE and EXT-NORMALIZE] |
| `RequestNativeCancel` | Report the mapped native operation, request, acknowledgement, and observed effect separately; unsupported or uncertain is a valid truthful result. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `CloseObservationConnection` | Distinguish transport closure from ending observation; end-observation stops new workflow commands and begins bounded drain/finalization. [extracted: contracts/02-external-connector.yaml, EXT-CLOSE] |
| `CollectArtifacts` | Return retained authorized artifacts or explicit missingness, without inventing a native download endpoint. [extracted: contracts/02-external-connector.yaml, EXT-ARTIFACTS] |
| `ReleaseNativeContext` | Execute only an authorized, evidenced release mapping; failure does not automatically authorize stronger containment. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |
| `Contain` | Bound separately authorized local processes, slots, or harness resources; never label containment native cancellation or rollback. [extracted: contracts/02-external-connector.yaml, EXT-CONTROLS] |

The documented REST compatibility surface includes `/run`, `/extract`, and operational observations such as `/health`, `/shards`, and `/metrics`; MCP is an optional delivery surface, not a second semantic contract. [inferred: 4-circus-tent-arch.md, §§3–5; contracts/02-external-connector.yaml, native reconciliation]

The supplied evidence does not establish native run-query, cancellation, fresh-context creation, context release, revision, or artifact-download contracts; local connector facilities must not be misrepresented as those native capabilities. [extracted: 3-hellscape-blueprint.md, §5.3]

New Circus Tent implementations may add capabilities, but each new version starts unknown and must earn its own scoped evidence; historical absence is neither a permanent prohibition nor permission to advertise support without tests. [inferred: contracts/02-external-connector.yaml, EXT-DESCRIBE; contracts/03-internal-browser-binding.yaml, CF-CAPS]

### 4.2 Delivery, checkpoints, and ambiguity

Repeated initial `Start` for the same logical idempotency association must return the same handle; changed request content under an existing key is rejected. [extracted: contracts/02-external-connector.yaml, EXT-IDEMPOTENCY]

The blueprint’s checkpoint ledger suppresses replay of completed side-effecting steps, but cannot guarantee exactly-once employer commitment when a remote effect occurred before local acknowledgement or checkpoint persistence. [inferred: 4-circus-tent-arch.md, §5; contracts/01-application-attempt-lifecycle.yaml, idempotency reconciliation]

Resume requires the existing handle/key, compatible context, explicit recovery authority, and an evidenced native checkpoint/idempotency contract; lease expiry, response loss, or a fresh executor is not sufficient. [extracted: contracts/02-external-connector.yaml, EXT-RESUME]

A crash around delivery yields uncertainty unless stronger evidence resolves acceptance or non-acceptance; the controller must not retry under a new key or switch to Ringmaster to “finish” an unresolved submission. [extracted: contracts/01-application-attempt-lifecycle.yaml, idempotency reconciliation]

### 4.3 Closure, callbacks, and truth

Finite local bounds govern API calls, queued work, observation, drain, cancellation waiting, cleanup, and buffering; a local timeout remains a harness/controller boundary, not proof of native timeout or stop. [extracted: contracts/02-external-connector.yaml, EXT-BOUNDS; 5-browser-qualification.md, evidence discipline]

Callbacks must preserve the exact received body, authentication result, attempt correlation, trace correlation, and mapping version; conflicting authenticated responses remain evidence rather than being deduplicated into a convenient final status. [extracted: contracts/02-external-connector.yaml, EXT-NORMALIZE; contracts/01-application-attempt-lifecycle.yaml, LIFE-SOURCE-CHECKS]

Circus Tent supplies dispatch and observation publications and faithfully attributable execution claims; the employer supplies application facts, and the reconciler writes only report. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES]

A native `completed` response is initially an execution claim, not proof of submission; a submit click, returned `None`, HTTP 200, or signed callback does not independently establish the employer’s commitment. [extracted: 3-hellscape-blueprint.md, §4.6; 5-browser-qualification.md, evidence discipline]

Late evidence creates new journal entries and immutable publications without rewriting close-time knowledge; an honest close-time unknown can coexist with a later verified commitment. [extracted: contracts/01-application-attempt-lifecycle.yaml, LIFE-LATE-EVIDENCE]

## 5. Profiles, authentication, and bounded resources

### 5.1 Profile and session discipline

Circus Tent retains one owning browser process per configured domain-family profile, immutable fingerprint identity, persistent authentication where authorized, and an explicit human MFA/bootstrap path. [inferred: 4-circus-tent-arch.md, §§2 and 7; contracts/03-internal-browser-binding.yaml, CF-PROFILE]

A fingerprint change requires a full reset and authentication handoff; same-profile relaunch cannot occur until the previous owning process has exited. [extracted: 4-circus-tent-arch.md, §§2 and 4]

A new tab in a persistent profile is not a fresh or isolated browser context, and a fresh profile is not proof of clean selector caches or framework memory; browser and learning state must be requested and observed separately. [extracted: contracts/03-internal-browser-binding.yaml, CF-STATE; contracts/02-external-connector.yaml, EXT-STATE-POLICY]

Domain routing, including a catch-all shard, does not grant permission to visit or mutate arbitrary origins; the commission’s origin/account scope remains authoritative. [inferred: 4-circus-tent-arch.md, §4; contracts/02-external-connector.yaml, EXT-AUTHORITY]

### 5.2 Resource policy

The legacy blueprint specifies 12 tabs per shard, 3 tasks per account, queue back-pressure above 1,000, and recycling at 500 pages; retain these as documented Circus Tent configuration baselines subject to review, not constants imposed on the shared connector or Ringmaster. [inferred: 4-circus-tent-arch.md, §§2, 4, and 9; contracts/03-internal-browser-binding.yaml, Camoufox reconciliation]

Every deployment must publish its actual hard admission limits, fair-share behavior, recycling policy, and finite waits, and demonstrate explicit back-pressure rather than dropping accepted work. [inferred: contracts/02-external-connector.yaml, EXT-BOUNDS; 4-circus-tent-arch.md, §8]

Recycle must drain or explicitly account for active work, preserve retained evidence, invalidate stale tokens, and observe process exit before profile reuse; forced termination cannot be reported as successful native cancellation. [inferred: 4-circus-tent-arch.md, §§4 and 7; 5-browser-qualification.md, evidence discipline]

Target-side rate limits, access failures, and challenges require scoped backoff or human review; increasing concurrency to compensate is not an acceptable recovery policy. [inferred: 4-circus-tent-arch.md, §4]

### 5.3 Secrets and challenge handling

Secrets remain runtime-resolved through environment-name references under Circus Tent’s configuration policy; configurations, logs, public repositories, model prompts, and application tasks must not carry secret values. [inferred: 4-circus-tent-arch.md, §§2 and 7; contracts/02-external-connector.yaml, EXT-AUTHORITY]

Application documents and raw responses can contain personal data and require restricted artifact access, scoped retrieval, and redacted presentation without rewriting the retained evidence bytes. [inferred: contracts/02-external-connector.yaml, EXT-ARTIFACTS and EXT-NORMALIZE; 6-get-a-job.xml.txt, AGENTS.md]

The blueprint’s challenge-solver integration is a separately configured and budgeted production capability, not a prerequisite for the cooperative fixture or permission to send every encountered challenge to a paid service. [inferred: 4-circus-tent-arch.md, §§3 and 5; 3-hellscape-blueprint.md, §§1 and 8]

Provider calls require explicit task/configuration authority and retained cost/effect evidence; no CI case may depend on solving production challenges or writing to a live employer. [proposed: preserve the documented solver feature while enforcing task scope and fixture-only acceptance]

## 6. Evidence and the learning loop

### 6.1 Evidence produced by Circus Tent

Each attempt must retain its admitted task and preparation, exact material references, descriptor and route, assistance, native request/response bodies, primitive transcripts, observed effects, controls, and close-time knowledge sufficient to explain the supported execution scope. [inferred: contracts/00-evidence-kernel.yaml; contracts/02-external-connector.yaml; contracts/03-internal-browser-binding.yaml, CF-EVIDENCE]

Evidence needed to cite a side-effecting operation must be journaled with durable intent before delivery, while receipts and observed effects are appended when available; this local discipline does not make remote browser or employer effects transactional with the journal. [inferred: contracts/03-internal-browser-binding.yaml, CF-EVIDENCE; contracts/01-application-attempt-lifecycle.yaml, LIFE-DISPATCH]

The browser extension remains part of the subject: its events and Python binding timings do not acquire independent assessor or employer authority because they were transported into a server-side journal. [inferred: contracts/03-internal-browser-binding.yaml, representation and CF-EVIDENCE; decisions/invariants-and-provisionals.md, INV-12]

Every measurement records origin, clock, boot, estimate, and censoring; binding-reported zero stays zero, missing timing stays unavailable with reason, and an independent observer’s interval remains a separate measurement. [extracted: contracts/03-internal-browser-binding.yaml, CF-TIME; 3-hellscape-blueprint.md, §4]

Capability availability, opportunity, and result remain separate, and missing values use the kernel’s six reasons rather than ad hoc nulls or success defaults. [extracted: 1-handoff-brief.txt, evidence-kernel invariants]

### 6.2 Product learning versus reviewed fixes

Native healing may improve selector caches during an authorized task; later portfolio learning consumes evidence-backed findings and proposes a scoped rule instance with required evidence, contraindications, and a verification plan. [inferred: 4-circus-tent-arch.md, §5; contracts/05-suggested-fix-registry.yaml, scope]

Human approval applies to the rule class, product owners implement changes, and a new subject/build receives fresh verification; a recommendation is not an automatic patch or evidence that the repair worked. [extracted: decisions/invariants-and-provisionals.md, INV-29 and INV-30]

Circus Tent’s curriculum and learned-state lineage remain separate from Ringmaster’s, and comparison runs must pin assistance, browser state, learning state, task family, and budgets. [inferred: 1-handoff-brief.txt, curriculum provisional; 3-hellscape-blueprint.md, §5.1]

Registry implementation is deferred to M3 and must not block this executor’s useful releases or the manual application lane; unsupported recommendations remain reasoned missing suggestions. [extracted: decisions/invariants-and-provisionals.md, P-10]

## 7. Conformance and acceptance

### 7.1 Independent shipping gate

Circus Tent must pass its applicable contract cases against synthetic backends and local browser fixtures before peer integration; neither Ringmaster readiness nor completion of Hellscape’s full workflow is its shipping prerequisite. [extracted: 1-handoff-brief.txt, silo discipline and roadmap]

| Gate | Required evidence |
|---|---|
| Kernel | Honest provenance, nulls, timing, immutable artifacts, journal support, and durable local effects; self-reported observations remain claims. [inferred: `conformance/00-evidence-kernel.md`; contracts/03-internal-browser-binding.yaml, CF-EVIDENCE] |
| Attempt lifecycle | Five-axis ownership, manual-assistance disclosure, idempotency, uncertain dispatch, bounded closure, and late-evidence behavior. [inferred: contracts/01-application-attempt-lifecycle.yaml; `conformance/01-application-attempt-lifecycle.md`] |
| External connector | All nine verbs recognized; preparation side-effect free; synthetic success, failure, missing/malformed responses, conflicting callbacks, unavailable cancellation/release, and remote continuation after close. [inferred: contracts/02-external-connector.yaml; 3-hellscape-blueprint.md, M1 synthetic-backend tests] |
| Camoufox binding | Separate execution for the exact route/build; primitive mappings, document lifetimes, frame/root accounting, action semantics, capture geometry, and declared limitations. [extracted: contracts/03-internal-browser-binding.yaml; `conformance/03-internal-browser-binding.md`] |
| Owner-separated publications | Circus Tent publishes only its authorized attempt domains; reports and origin facts cannot be overwritten by connector completion. [inferred: contracts/04-owner-separated-write-domains.yaml; contracts/01-application-attempt-lifecycle.yaml, LIFE-AXES] |
| Fix records, when emitted | Validate scoped evidence and verification requirements without requiring a deployed registry service. [inferred: contracts/05-suggested-fix-registry.yaml; decisions/invariants-and-provisionals.md, P-10] |

An explicit unsupported result can pass a truthful-mapping case while leaving the corresponding product capability unqualified; required skipped cases, invalid controls, and missing dependencies are not passes. [inferred: 5-browser-qualification.md, evidence discipline; contracts/02-external-connector.yaml, EXT-DESCRIBE]

### 7.2 Extension-route exit criteria

The extension route is acceptable only when retained evidence establishes that its mapped page operations bypass Playwright/Juggler, its context/target lifetimes are correct, and its observations and actions satisfy the Camoufox-specific suite within declared scope. [inferred: contracts/03-internal-browser-binding.yaml, CF-ROUTE, CF-SYNC, CF-STRUCTURE, and CF-INPUT]

Performance comparison must use pinned workloads, browser/configuration, assistance, state policy, output completeness, and measurement scopes; measure round trips, bytes crossing the boundary, operation latency, and controller overhead rather than assuming an extension must be faster. [proposed: test the architectural hypothesis without trading fidelity for an impressive latency number]

No source supplies a measured speedup or a complete extension capability inventory; those remain experiment results to collect, not acceptance claims to copy from the ModCDP analogy. [uncertain: extension implementation and route-comparison measurements are absent]

### 7.3 Retained Circus Tent benchmark targets

The following are the blueprint’s fixture acceptance targets, not measured results; each must name its route, build, workload, timing origin, and any revised operational definition before execution. [extracted: 4-circus-tent-arch.md, §8; contracts/03-internal-browser-binding.yaml, CF-CAPS and CF-TIME]

| Target | Qualification boundary |
|---|---|
| 100 launches with a pinned manifest produce identical canvas/WebGL/audio/navigator/screen/font hashes. | Establishes the tested fingerprint stability, not universal undetectability. [extracted: 4-circus-tent-arch.md, §8.1] |
| 500 × 150 KB extraction workload: p95 below 200 ms and RSS below 2 GB. | Must pin the measured interval and reduction completeness; omitting content cannot manufacture a pass. [inferred: 4-circus-tent-arch.md, §8.2; contracts/03-internal-browser-binding.yaml, CF-STRUCTURE] |
| 20% DOM mutation: more than 85% first-attempt heal. | Requires a retained mutation workload and target oracle; healing the wrong control is failure. [inferred: 4-circus-tent-arch.md, §8.3] |
| 100 sessions × 20 tasks: no quota violations and maximum wait below three times median wait. | Measures the declared fairness workload, not employer throughput. [extracted: 4-circus-tent-arch.md, §8.4] |
| Recycle at 500 pages: no orphans and unchanged fingerprint. | Requires exit and profile-continuity evidence, not merely a recycle acknowledgement. [inferred: 4-circus-tent-arch.md, §8.5] |
| 20 sessions after MFA: no re-authentication. | Applies to the authorized tested persistence fixture/scope, not every employer’s session policy. [inferred: 4-circus-tent-arch.md, §8.6] |
| Twice configured cap load: success or explicit back-pressure with retry/queue information. | Accepted work must remain accounted for; refusal is not execution success. [inferred: 4-circus-tent-arch.md, §8.7] |
| Secret scan: zero matches. | Complements authorization and artifact-access tests; it does not replace them. [inferred: 4-circus-tent-arch.md, §8.8; contracts/02-external-connector.yaml, EXT-AUTHORITY] |

These tests run on local fixtures; live employer writes are authorized operating activity, not CI acceptance fixtures. [extracted: 4-circus-tent-arch.md, §8; 6-get-a-job.xml.txt, AGENTS.md]

## 8. Delivery sequence and production use

| Lane | Deliverable | Non-prerequisite |
|---|---|---|
| Immediate operation | Continue manual job selection/application and capture useful executor failures or partial assistance honestly. | No extension, registry, crawler, or laboratory completion gate. [extracted: decisions/invariants-and-provisionals.md, HA-03] |
| Compatibility maintenance | Pin the actual deployed stack, preserve raw response shapes, implement truthful connector behavior, and pass scoped synthetic/legacy-route tests. | Does not claim to fix the architectural bridge problem. [inferred: contracts/02-external-connector.yaml; contracts/03-internal-browser-binding.yaml, compatibility scope] |
| Browser-resident reconnaissance | Establish packaging, permissions, channel security, native mappings, and unsupported surfaces; build the smallest local fixture that answers each uncertainty. | Does not require a wholesale engine rewrite before learning whether the route is feasible. [proposed: reduce the extension bet to falsifiable native-surface experiments] |
| Extension-native execution | Bring bounded observation/reduction/resolution and evidenced action mappings through the synchronous Camoufox binding; run the route-specific suite and comparative measurements. | Does not inherit compatibility-route capability claims. [inferred: contracts/03-internal-browser-binding.yaml, CF-ROUTE and CF-CAPS] |
| Practice integration | Let Hellscape measure the exact Circus Tent version and disclosed assistance against the cooperative fixture, including useful non-completion. | Practice success is neither employer representation nor automatic production permission. [extracted: 3-hellscape-blueprint.md, M2; 1-handoff-brief.txt, Hellscape invariant] |
| Scoped production assistance | Use approved materials and human-reviewed final submission initially; retain actual employer evidence and unresolved outcomes. | Does not require general autonomous submission capability. [extracted: decisions/invariants-and-provisionals.md, P-14] |
| Later autonomy and learning | Expand only authorized origin/task/subject scope with evidenced receipt correlation, ambiguity recovery, and independently verified revisions. | No promotion based solely on a practice completion rate or healed-selector count. [inferred: decisions/invariants-and-provisionals.md, P-14; contracts/05-suggested-fix-registry.yaml] |

When a human performs the final action after Circus Tent fills a form, the attempt records both the subject and the assistance; it is neither wholly manual nor unattended automation. [inferred: prd/00-integration.md, §2; 5-browser-qualification.md, evidence discipline]

The operating view should distinguish assisted production attempts, verified employer commitments, unresolved outcomes, operator effort, execution failures, and follow-up needs from fixture throughput, model spend, and browser benchmarks. [proposed: keep application-producing value visible while retaining diagnostic engineering measures]

## 9. Open decisions and flip conditions

| Decision or gap | Current position | Evidence that changes or resolves it |
|---|---|---|
| Firefox extension route | Preferred target; preserve the named compatibility route during migration. | If supported privileges or lifecycle control cannot deliver the required surface, investigate another Firefox-specific full-strength route rather than a universal driver. [extracted: decisions/invariants-and-provisionals.md, P-04] |
| Extension package/channel | Not selected by the supplied sources. | Pin the Camoufox build, test supported packaging/permissions, inspect process ownership and authentication, and publish the actual channel contract. [uncertain: implemented transport and packaging evidence is absent] |
| Action/capture/closed-root capabilities | Unknown until evidenced for the exact route/build. | Native mapping inventory plus fixture observations of event semantics, inaccessible boundaries, uploads, capture geometry, and interruption. [uncertain: current extension-native capability evidence is absent; contracts/03-internal-browser-binding.yaml, open evidence] |
| Current legacy deployment | Documentary behavior is available, but current deployment certification is not. | Obtain build/configuration identity, endpoint/raw-response specimens, and synthetic lifecycle results; preserve operator-attested identity where stronger revision evidence is unavailable. [uncertain: current Circus Tent build and retained qualification bundle are not supplied; 3-hellscape-blueprint.md, §§1.3 and 5.3] |
| Limits and benchmark details | Retain documented Circus Tent baselines while publishing actual configured values. | Measure the real host/workload, define byte units and timing boundaries, and resolve the exact semantics of legacy recycle deadlines before enforcing them. [proposed: avoid converting underspecified historical numbers into unreviewed shared constants; 4-circus-tent-arch.md, §§4–9] |
| Providers and local extraction stack | Retain the blueprint’s implementation direction where useful. | Change when compatible alternatives demonstrate better maintenance, cost, or fidelity under pinned tests; provider replacement creates new configuration evidence. [proposed: preserve behavior rather than freeze historical vendor/model choices] |
| Autonomous production submission | Human-controlled initially. | Explicit operator authorization for a named origin/task/subject scope with evidenced receipt correlation and ambiguity recovery; practice alone cannot flip the policy. [extracted: decisions/invariants-and-provisionals.md, P-14] |

Circus Tent is successful when its browser-specific machinery makes real, tracked applications easier and its evidence makes failures actionable; architectural migration is a means to that outcome, never a reason to stop applying. [inferred: current request, Purpose and Products; 1-handoff-brief.txt, thin-slice discipline]
