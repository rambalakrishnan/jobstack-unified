# Application attempt lifecycle — conformance suite

## 1. Target and acceptance boundary

| Item | Value |
|---|---|
| Contract | `contracts/01-application-attempt-lifecycle.yaml`, wire version `application-attempt-lifecycle/0.1.0`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| Kernel dependency | `evidence-kernel/0.1.0`; common types retain the meanings tested in `conformance/00-evidence-kernel.md`. [extracted: contracts/01-application-attempt-lifecycle.yaml, `x-kernel-compatibility`] |
| Suite identifier | `application-attempt-lifecycle-conformance/0.1.0`; case IDs use the prefix `LIFE01-`. [proposed: stable selection and verification receipts] |
| Status | Review draft specifying tests, not evidence that any implementation has passed them. [proposed: distinguish acceptance criteria from executed verification] |
| Maintainer | The contracts boundary owns the shared corpus; Hellscape M1 exercises the lifecycle with synthetic backends, without a live subject. [inferred: 1-handoff-brief.txt, Parts V and VIII–IX] |
| Purpose | Make real applications—including manual applications—trackable without turning delivery, silence, laboratory success, or a native status into an employer commitment. [inferred: 1-handoff-brief.txt, Parts VI–IX] |

This suite tests five independently authored axes, not a linear “application status” machine. [extracted: 1-handoff-brief.txt, Part VI]

| Axis | Authority | What the suite must keep distinct |
|---|---|---|
| `dispatch` | Connector | Local preparation and delivery, native acceptance, and delivery uncertainty. [extracted: contracts/01-application-attempt-lifecycle.yaml, `x-ownership`] |
| `observation` | Connector or manual recorder in that role | Observation window, connection closure, controls, and frozen close-time knowledge. [extracted: contracts/01-application-attempt-lifecycle.yaml, `x-ownership`] |
| `execution` | Subject | Source-authored claims, faithfully published by the bound writer; not independently established application facts. [extracted: contracts/01-application-attempt-lifecycle.yaml, `LIFE-CLAIMS`] |
| `application` | Origin | Verified origin facts, recorded under the commissioned origin policy; not observer or subject assertions. [extracted: contracts/01-application-attempt-lifecycle.yaml, `LIFE-ORIGIN`] |
| `report` | Reconciler | Comparisons over pinned inputs; no authority to repair either compared source. [extracted: contracts/01-application-attempt-lifecycle.yaml, `LIFE-RECONCILE`] |

The same process may implement several roles, but that does not merge their write grants, transactions, or semantic authority; the report writer must not hold execution/application write authority. [extracted: contracts/01-application-attempt-lifecycle.yaml, `LIFE-AXES` and `LIFE-PUBLICATION`]

### 1.1 Load-bearing counterexamples

| Rule | Why it must be tested |
|---|---|
| Connection closure is not execution termination. | The described cancellation experiment observed continued work and a later authenticated callback after disconnect. [extracted: 3-hellscape-blueprint.md, §1.3] |
| Unknown at close is compatible with later commitment. | A single outcome enum would either erase the earlier uncertainty or misclassify the later fact as a contradiction. [extracted: 1-handoff-brief.txt, Part VI] |
| A definite cancellation guarantee can be false. | A verified commitment contradicts an explicit no-commit assertion when the commitment falls within the assertion’s actual scope. [inferred: 3-hellscape-blueprint.md, §§4.5–4.6] |
| Native acknowledgement is not application success. | `None`, protocol acknowledgement, HTTP 200, and execution completion establish different—and narrower—facts. [extracted: 5-browser-qualification.md, Evidence discipline] |
| Publication cannot rewrite another owner. | Waiting for another owner’s transaction or replacing its fields defeats the independent write-domain discipline. [inferred: 2-state-bank-crawler-blueprint.json, §11.17 and Decision 8] |
| Practice cannot become production evidence. | Tuning against Hellscape’s forms does not establish employer-form compatibility or an employer application. [extracted: 1-handoff-brief.txt, Part III] |

### 1.2 Corpus provenance and limits

The governing brief assigns m0’s cancellation discipline to this suite; Hellscape supplies the documented scenarios and the synthetic-backend implementation approach. [extracted: 1-handoff-brief.txt, Part VIII; 3-hellscape-blueprint.md, §§1.3 and 10.6]

The original `cancellation-fixed.jsonl`, `isolation-fixed.jsonl`, complete native bodies, and `FINDINGS-v2.md` are not supplied; their byte-level fixtures cannot be reconstructed as historical captures from these descriptions. [uncertain: obtain the original artifacts with checksums and deployment scope to add an authentic historical-import corpus]

Until originals are available, the cases below are explicitly synthetic reconstructions of the documented semantics, not new observations of Circus Tent or Ringmaster. [proposed: preserve the cancellation corpus without fabricating its original evidence]

Missing historical bytes do not block the synthetic suite, Hellscape M1, or the candidate’s manual applications, and do not create another live-probe milestone. [inferred: 1-handoff-brief.txt, Parts VII–IX; 3-hellscape-blueprint.md, §§1.3 and 15]

This suite does not certify browser isolation, employer compatibility, native cancellation in a current deployment, or application success rates. [inferred: 1-handoff-brief.txt, Parts III and VI]

## 2. Test execution model

### 2.1 Layers and verdicts

Use the verification layers established by the evidence-kernel suite. [proposed: keep shared acceptance terminology consistent]

| Layer | Required demonstration |
|---|---|
| **S — Structure** | Decode and validate the complete record against the pinned schema, including required fields, closed objects, discriminators, and reasoned missingness. [inferred: contracts/01-application-attempt-lifecycle.yaml] |
| **I — Integrity and authority** | Resolve identities, source checks, grants, revisions, digests, evidence references, lineage, and semantic guards. [inferred: contracts/01-application-attempt-lifecycle.yaml, `x-invariants`] |
| **B — Stateful behavior** | Exercise the actual durable publication, dispatch, recovery, and closure paths under races and faults. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-PUBLICATION`, `LIFE-DISPATCH`, and `LIFE-CLOSE`] |
| **D — Derivation** | Reconcile only the pinned claims and facts, preserving scope, uncertainty, and close-time knowledge. [extracted: contracts/01-application-attempt-lifecycle.yaml, `x-reconciler-algorithm`] |
| **R — Re-derivation** | Reproduce historical analysis from retained inputs without issuing application commands or replacing the current report publication. [inferred: contracts/01-application-attempt-lifecycle.yaml, report transition rule; contracts/00-evidence-kernel.yaml, `EK-REPLAY`] |

Case classes are **H** for happy path, **B** for boundary, and **F** for adversarial input or injected failure; every listed subcase is required for a full reference pass. [proposed: make case selection explicit]

An F case passes when the expected rejection, containment, or uncertainty is correctly evidenced; a failed application can therefore occur inside a passing conformance test. [proposed: keep test correctness separate from application outcome]

“Reject” means no unauthorized publication, business effect, or dispatch; an independently authorized audit/incident event may still record the refusal. [proposed: refusals must be observable without accepting the refused assertion]

A valid subject claim that is false or contradicted is retained, whereas a forged, uncorrelated, or incorrectly normalized claim is not accepted into the attempt’s execution publication. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-CLAIMS` and `LIFE-SOURCE-CHECKS`]

### 2.2 Isolated runner

The runner must exercise one implementation at a time, with local synthetic sources and independently observed effects; no crawler, job-hunter deployment, live employer, browser executor, or model service is required. [proposed: implement the silo gate without recreating a portfolio integration dependency]

The implementation adapter must expose test hooks for admission/commissioning, authenticated axis publication, snapshot reads, dispatch/control operations, reconciliation, restart, clock advancement, and fault injection; these hooks are not new runtime connector verbs. [proposed: observe the contract through implementation-specific adapters while keeping the wire surface unchanged]

For B cases, use the implementation’s actual durable state and transition path rather than a replacement in-memory model. [proposed: a mock storage path cannot establish dispatch or publication durability]

The controller must independently retain command-delivery counts, synthetic origin commits, injected faults, acknowledgements, and attempted writes by principal; the implementation’s own output is not its sole oracle. [proposed: extend Hellscape’s independent cross-check discipline to lifecycle verification]

The proposed development command is an implementation target, not an existing executable supplied by this draft. [proposed: provide a reproducible entry point without choosing an implementation language]

    ./tools/conformance/application-attempt-lifecycle \
      --implementation <implementation-adapter> \
      --profile reference \
      --output <evidence-directory>

A **reference** run executes every case below; a product-specific run may declare a narrower role scope and exact case list, but may not call an emission-only, reader-only, or schema-only result “full lifecycle conformance.” [proposed: permit independent delivery without overstating what was tested]

Circus Tent and Ringmaster use the same external lifecycle vectors independently; this does not require shared implementation, primitives, or browser handles. [inferred: 1-handoff-brief.txt, Parts III and V]

### 2.3 Fixture families

All names, identities, schedules, and synthetic claims in this table are corpus proposals, not records of actual job applications. [proposed: make the provenance of test data explicit]

| Fixture | Required contents |
|---|---|
| `F-practice` | A commissioned `practice`, `held_in`, `laboratory_fixture` attempt, a synthetic subject, and a local origin reducer that can commit once, return an as-of absence, or seal mutation authority. [proposed: controlled origin facts without a browser dependency] |
| `F-remote` | A production-shaped `production`, `held_out`, `employer_origin` attempt in an isolated kernel-conformance run, with a fake remote origin and `fixture_close_action=not_applicable`. [proposed: permit post-close commitment tests without contacting or impersonating an employer] |
| `F-manual` | A production-shaped manual attempt with no subject, connector version, binding version, native run, or active execution writer; a local recorder and synthetic receipt verifier remain available. [proposed: test the day-one recording path independently of automation] |
| `F-versions` | Two separately commissioned synthetic subject versions, with version-specific capability evidence and mappings; the second begins without inherited capability findings. [proposed: test that old cancellation evidence is not a new-version assumption] |
| `F-publication` | Independently blockable owner domains, complete immutable publication artifacts, a composition reader, and two competing requests to the same owner revision. [proposed: test asynchronous composition without deploying other products] |

Every fabricated observation uses kernel `evidence_scope=synthetic`; production-shaped test records must never contribute to a real application count. [inferred: contracts/00-evidence-kernel.yaml, `JournalEnvelope.evidence_scope`; contracts/01-application-attempt-lifecycle.yaml, `LIFE-EVIDENCE`]

Fixture factories must create complete, schema-valid records with real digests over retained bytes, registered event kinds, authenticated test producers, registered clocks, and resolvable references before applying a negative mutation. [proposed: avoid tests that pass merely because unrelated required fields were omitted]

For a synthetic production receipt, `verified` means verified against the pinned **test** authority and mapping; it makes no assertion about a real employer’s receipt-verification mechanism. [proposed: prevent synthetic source verification from becoming production evidence]

### 2.4 Notation and independent knowledge

`M(reason)` abbreviates the complete wire object `{"value":null,"reason":"<reason>"}`; `Z(reason)` abbreviates an unpublished axis slot with `revision=0` and that Missing value. [proposed: concise test notation without introducing alternative wire types]

Tables show selected field projections, not standalone valid JSON records; fixture factories must supply every other required field and compute all evidence references after append. [proposed: keep review examples readable without weakening schema completeness]

The controller’s knowledge of an unseen commit is **not** available to the reconciler until a verified origin observation is journaled and published into the analyzed input scope. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-EVIDENCE`]

For temporal tests, the controller separately schedules command delivery, origin commitment, receipt delivery, transport closure, and observation closure; delayed receipt delivery alone must never establish when commitment occurred. [proposed: expose the timing ambiguity that cancellation tests must preserve]

## 3. Structure and commissioning

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-S01` | H / S,I | Validate a complete `AttemptCommission`, each of the five `AxisRevision` variants, and snapshots with both published and unpublished slots. | All valid forms pass; each axis validates against its own value type, and every snapshot’s commission, attempt identities, and seal vector agree. [proposed: cover every exported lifecycle record and variant] |
| `LIFE01-S02` | F / S | Remove required fields; add a whole-attempt `status`; supply an unknown wire version, axis, enum, or unreasoned null; use `service` as an application execution mode. | Reject the mutated record without defaulting, coercing, or copying a legacy status into the lifecycle; service execution remains a kernel capability for non-application work, not this commission type. [proposed: enforce the lifecycle’s closed application-specific surface] |
| `LIFE01-S03` | F / I,B | Change the attempt kind, candidate, job snapshot, target, task hash, subject version, execution configuration, or owner binding after commission; separately mismatch commission fields against the admitted manifest. | Reject mutation or mismatched publication; changed commissioned work requires a new attempt where the contract requires it, with lineage and recovery review rather than an in-place rewrite. [proposed: make immutable commissioning operational, not documentary] |
| `LIFE01-S04` | H/F / I,B | Commission and journal an authorized attempt, then try dispatch before admission, before commission registration, or with an authorization reference that does not authorize the requested task. | Only the admitted, durably commissioned, authorized request may dispatch; a nonempty but irrelevant reference is insufficient. [proposed: test permission and persistence before external effect] |
| `LIFE01-S05` | B/F / S,I | Compare `ExecutionClaim.state=unknown`, a missing mapped statement, no execution publication, and manual inapplicability; try empty `claims` or `facts` publications as substitutes. | Preserve the four meanings; empty histories cannot pass their nonempty publication definitions, and no subject claim is invented to represent observer ignorance. [proposed: prevent “unknown” from becoming an unauthored subject statement] |

Schema validation alone does not establish source authority, revision arithmetic, equality with the admitted manifest, or the semantic validity of a reference. [extracted: contracts/01-application-attempt-lifecycle.yaml, `x-kernel-compatibility.validation_gate`]

## 4. Owner publications and composed snapshots

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-W01` | H / I,B | Publish each axis under its bound principal; include a faithful adapter publishing a subject-authored claim and a receipt recorder publishing a verified origin fact. | Accept the publications while retaining the semantic subject/origin identities; the storing process is not automatically the authoritative source of the claim or fact. [proposed: test legitimate delegation without authority laundering] |
| `LIFE01-W02` | F / I,B | Have the reconciler write execution/application, a subject write an origin fact, an observer write commitment, or another connector write this attempt’s dispatch; also submit caller-authored server/provenance labels. | Refuse each escalation; forged header labels and valid hashes grant no authority, and the report principal cannot possess the prohibited source-domain write grants. [proposed: enforce the five-owner boundary at actual write admission] |
| `LIFE01-W03` | B/F / I,B | Race two different next revisions from the same predecessor; redeliver an identical accepted revision; change bytes under its key; skip a revision; delete or alter an earlier claim/fact in a later cumulative publication. | At most one competing next revision commits; identical publication is not a second logical update; conflicting, skipped, or destructive histories are rejected with the original retained. [proposed: test revision fencing, immutable identity, and cumulative evidence] |
| `LIFE01-W04` | F / B | Block application or report persistence/publication while dispatch and observation proceed; expose a partially transferred publication and a checksum failure to the reader. | Independent owner-local commits continue without the blocked owner’s lock or acknowledgement; the reader retains the last complete publication, never partial fields or a mixed body. [proposed: apply Stage1’s non-blocking publication discipline to attempts] |
| `LIFE01-W05` | F / I,D | Mismatch a snapshot’s attempt, commission digest, embedded commission, axis revision, seal vector, registration evidence, or content digest; supply an unregistered source artifact. | Reject the invalid composition; a seal is a pinned composition, not permission to invent missing owner content. [proposed: verify snapshot closure and version-vector integrity] |
| `LIFE01-W06` | B / I,B,D | Publish a report over application revision 1; publish application revision 2 while the report writer is unavailable; later publish a report using revision 2. | The intermediate snapshot validly contains the newer fact and older report, exposes their differing input pins, and must not present that report as current; neither publication waits for synchronous reconciliation. [proposed: test explicit staleness rather than a hidden cross-owner transaction] |
| `LIFE01-W07` | F / I,D,R | Attempt a current report publication whose input revision pins regress; separately re-derive the older report as a historical artifact. | Reject regression of the current report domain; allow offline historical re-derivation without replacing current publications or prior seals. [proposed: distinguish history inspection from current-state rollback] |

The test oracle must compare each source publication’s bytes before and after reconciliation, not merely its displayed latest value. [proposed: detect a reconciler that secretly “fixes” claims or facts while producing a plausible report]

`AttemptSnapshot.seal_point`, `ObservationValue.at_close`, and an origin’s mutation-authority seal are three different objects; none may substitute for another. [inferred: contracts/01-application-attempt-lifecycle.yaml, `SealPoint`, `CloseSnapshot`, and `OriginFact`]

## 5. Dispatch, idempotency, and recovery

### 5.1 Dispatch cases

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-D01` | H / I,B | Prepare a valid task, then Start it against a delayed synthetic backend; inspect durable state at the first wire delivery and return a native result without a native run ID. | Prepare causes no browsing or execution; a local handle, request digest, idempotency identity, and dispatch intent are durable before delivery; local Start acknowledgement is distinct from native acceptance, and no native run ID is invented. [proposed: verify the asynchronous handle-before-wire contract] |
| `LIFE01-D02` | B/F / I,B | Generate every dispatch transition below and every omitted edge, including unsupported same-state revisions and initial-state shortcuts. | Accept only listed edges with satisfied guards; refuse illegal edges without dropping any contradictory raw native observation that prompted the attempt. [proposed: make the transition relation executable rather than example-only] |
| `LIFE01-D03` | B/F / I,B | Repeat and concurrently invoke Start with the same commissioning principal/key/request; reuse the key with changed content; repeat under a distinct principal. | Same principal/key/request resolves to the same attempt/handle without a second logical execution; changed content conflicts; another principal cannot recover the first principal’s identity by key collision. [proposed: test idempotency scope and effect count] |
| `LIFE01-D04` | F / B,D | Execute every crash cut in §5.2, then recover and repeat the original local request. | Recovered state agrees with durable evidence; ambiguous delivery remains uncertain and is not repaired through an automatic new submission. [proposed: exercise the side-effect boundary under real process failure] |
| `LIFE01-D05` | H/F / I,B | Request same-key native resume with a verified checkpoint/idempotency contract and explicit recovery authority; repeat without either guarantee, with changed request bytes, another profile/subject, or a completed side-effecting step scheduled again. | Only the supported same-logical-execution recovery is allowed; it journals additional delivery and does not repeat completed effects, while unsupported recovery remains uncertain rather than acquiring a new key or executor silently. [proposed: preserve native checkpoint value without promising exactly-once employer effects] |
| `LIFE01-D06` | F / I,B,D | Fail task translation or a local prerequisite before delivery; separately lose a response after possible delivery and provide only HTTP success or transport acknowledgement. | The first may establish local dispatch rejection with no subject failure claim; the second is uncertain absent correlated native acceptance/non-acceptance evidence, and neither establishes application success. [proposed: keep local failures, transport results, and native claims separate] |
| `LIFE01-D07` | F / I,B | Commission another attempt for the same candidate/job after an unresolved or committed attempt, changing only the idempotency key or executor; supply absent, irrelevant, and valid duplicate-risk review evidence in separate variants. | No automatic resubmission follows key rotation, executor switch, lease expiry, or practice success; an explicitly reviewed new try is a new immutable attempt and preserves the prior uncertainty or commitment. [proposed: prevent local retry machinery from duplicating a real application] |

For `LIFE01-D02`, use this exact transition relation; `unpublished` is test notation for revision zero, not a serialized dispatch state. [extracted: contracts/01-application-attempt-lifecycle.yaml, dispatch transition rules]

| From | Allowed next state |
|---|---|
| `unpublished` | `not_started`, `prepared`, `rejected`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `not_started` | `prepared`, `rejected`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `prepared` | `dispatching`, `rejected`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `dispatching` | `accepted`, `rejected`, `uncertain`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `uncertain` | `uncertain`, `accepted`, `rejected`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `accepted` | `accepted`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `rejected` | `rejected`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |

An `accepted` or `rejected` self-transition may add evidence but must not authorize a new logical execution, and rejection after possible delivery requires evidence of non-acceptance rather than silence. [extracted: contracts/01-application-attempt-lifecycle.yaml, dispatch guards]

### 5.2 Crash-cut oracle for `LIFE01-D04`

The following are independent fixture resets, not one run repeatedly crashing at every cut. [proposed: isolate the causal effect of each durability boundary]

| Cut | Required recovery |
|---|---|
| After Prepare, before durable Start intent | Preserve the prepared attempt; no backend delivery has occurred, and a later explicit authorized Start can perform the first delivery. [proposed: distinguish non-executing preparation from dispatch] |
| After durable handle/dispatch intent, before the controller allows wire delivery | Recover as uncertain unless durable implementation evidence proves non-delivery; the controller’s private knowledge that it blocked delivery is not an input to the recovered implementation. [proposed: test the indistinguishable delivery window conservatively] |
| After native acceptance or origin commitment, before local response persistence | Preserve delivery uncertainty until separately received evidence resolves it; do not repeat the request to discover whether the first one worked. [proposed: expose the remote-commit/local-acknowledgement gap] |
| After native result persistence, before local acknowledgement to the caller | Retain the accepted claim/result and return the same local handle on retry without another logical execution. [proposed: verify durable response recovery] |
| After application fact publication, before reconciliation | Preserve the fact, permit a stale or absent report, and reconcile later without rolling back the fact or blocking another owner. [proposed: test asynchronous reporting after durable origin evidence] |
| During a failed local storage commit | Do not acknowledge a partial publication; after storage recovery, preserve the last acknowledged state and explicitly identify any unpersisted observation tail. [proposed: enforce the durability promise without pretending to survive unavailable storage] |

The independent synthetic origin ledger must verify the number of actual commitments, while the application axis may use that information only after its receipt passes the commissioned verification and correlation policy. [proposed: avoid both duplicate effects and omniscient reconciliation]

## 6. Baseline end-to-end lifecycles

| ID | Class / layers | Procedure and required result |
|---|---|---|
| `LIFE01-H01` | H / B,D | In `F-practice`, prepare and dispatch once, receive a synthetic task report explicitly claiming both execution completion and commitment, accept one origin commitment, close observation, then reconcile: dispatch is accepted, the original execution claim remains completed, the origin fact remains committed, and the supported application assertion compares consistent with `report.state=reconciled`, `coverage=complete`. [proposed: positive control exercising all five authorities] |
| `LIFE01-H02` | H / B,D | Receive an execution-lifecycle `completed` claim with **no** application assertion, but no verified origin receipt: the application slot remains unresolved, and the claim is `not_comparable` to commitment; a complete reconciled report accounts for that narrow scope and must not be displayed as application success. [proposed: prove that reconciled is not a business-success flag] |
| `LIFE01-H03` | H / B,D | Receive a genuine synthetic execution failure, stop before fixture submission, and obtain origin-owned final absence after fixture sealing: preserve the failed claim and not-committed fact, finalize locally, and do not retry automatically; the conformance case passes despite no application completion. [proposed: make useful failure output a first-class happy path] |

For each baseline, create the observation-close seal from the versions actually available at closure, then use a new evidence-updated composition when reporting or late evidence advances a domain; do not backfill the original seal. [proposed: exercise publication order without a self-referential report/closure dependency]

## 7. Cancellation and late-commitment corpus

### 7.1 Common procedure

1. Commission `F-remote` and establish native acceptance before the close experiment, so dispatch uncertainty does not confound the cancellation observation. [proposed: isolate execution/application uncertainty from delivery uncertainty]
2. Use separate barriers for transport close, observation-window close, origin commitment, and native callback delivery; record which barriers are visible to the implementation. [proposed: test distinct lifecycle boundaries rather than a single shutdown timestamp]
3. At observation closure, retain the original `at_close` object, its input pins, and the close seal bytes for later equality checks. [proposed: make retrospective rewriting detectable]
4. Deliver late evidence only after the first close snapshot is durable, append it at the current journal head, and request a new analysis over new pins. [proposed: exercise the actual late-evidence path]
5. Check every source claim/fact before and after reconciliation, along with the native-command log and the still-closed observation window. [proposed: detect mutation, hidden retry, or reopening disguised as reconciliation]

These production-shaped cases use a synthetic origin because a laboratory origin sealed at observation close cannot legitimately perform a new post-seal commitment. [inferred: 3-hellscape-blueprint.md, §5.5; contracts/01-application-attempt-lifecycle.yaml, `LIFE-ORIGIN`]

For practice, a receipt received after close may instead prove a commitment made **before** the fixture seal; the receipt’s late arrival must not move the commit event after the seal. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-TIME`]

### 7.2 Required cases

| ID | Class / layers | Inputs and schedule | Required outcome |
|---|---|---|---|
| `LIFE01-X01` | B / B,D | Close with no subject terminal claim and no origin fact available; after observation closes, deliver a verified commitment and a correlated callback claiming execution completion only. | At close, execution/application knowledge is unknown and the execution slot has no fabricated unknown claim; later publications add the commitment and callback, while `at_close` stays byte-identical. The callback’s execution-only claim is not comparable to commitment, not contradicted, and observation remains closed. [proposed: reproduce disconnect → continued work → later result without retroactive knowledge] |
| `LIFE01-X02` | B / D | The subject explicitly reports `state=unknown` and `outcome_unknown` at the close boundary; a verified commitment arrives later. | Retain the explicit unknown claim and its knowledge boundary; compare the application uncertainty as consistent with later commitment, yielding a complete reconciled report when this is the only comparison. [proposed: direct golden for the handoff’s honest-uncertainty counterexample] |
| `LIFE01-X03` | F / D | The subject explicitly claims cancellation prevented commitment throughout the attempt; a verified commitment later arrives. Repeat with a no-future-commit assertion whose `after_boundary` scope is disproved by recorded causal evidence. | Both variants produce `contradicted`; the first needs no invented occurrence timestamp because the assertion covers the entire attempt, while the second cites proof that the commit falls after its boundary. Neither source is rewritten. [proposed: direct golden for definite cancellation contradicted by a covered commitment] |
| `LIFE01-X04` | B / D | The subject claims only `stopped`; an origin transaction already in flight commits afterward. | Do not synthesize a no-commit assertion from stopped; the execution-only claim is not comparable to the application fact, and commitment alone does not prove that the native execution kept running. [proposed: distinguish stopping execution from rolling back remote work] |
| `LIFE01-X05` | B / D | A subject’s `not_committed` assertion is limited to boundary B; an origin fact establishes absence at B, followed by a later commitment. Repeat without the as-of absence fact. | With the as-of fact, the limited assertion remains consistent and both origin facts are retained. Without evidence establishing absence at B, later commitment alone leaves that assertion indeterminate rather than proving or contradicting it. [proposed: test temporally limited negative claims] |
| `LIFE01-X06` | F / D | A no-future-commit claim is followed by a receipt delivered after close, but the commit’s occurrence relation to the claim boundary is unknown. Then append evidence establishing the relation. | Initially record `temporal_relation=unknown` and an incomplete report with `M(not_observed)`, not contradiction from delivery order. A later report may contradict only when the new evidence places commitment within the asserted forbidden interval. [proposed: prevent late receipt time from becoming a false causal conclusion] |
| `LIFE01-X07` | H / B,D | A synthetic subject with its own evidenced cancel capability acknowledges cancellation, independent evidence establishes stop within its declared test bound, and the origin supplies a valid final no-commit guarantee. | Keep request, acknowledgement, observed stop, and final absence separately cited; an explicit supported no-commit assertion compares consistent. The passing case proves these test semantics, not cancellation capability in either real executor. [proposed: positive control for actual bounded cancellation rather than treating universal absence as the only possible answer] |
| `LIFE01-X08` | B / B,D | A required native cancellation capability is evidenced absent for the exact synthetic subject version; the operation is unsupported, local observation closes, and work may continue. | Preserve absence, blocked opportunity, unsupported operation, unknown execution knowledge, and any later origin fact separately; bounded harness finalization does not make native cancellation present or satisfied. [proposed: retain the native requirement gap even when the harness remains usable] |
| `LIFE01-X09` | F / B,D | Native cancellation is acknowledged, but no stop effect or origin finality is established before the local waits expire; in a companion variant, independent stop is observed after the declared native bound. | Acknowledgement alone yields no stopped/no-commit fact; silence leaves uncertainty. The late-stop variant preserves the measured bound violation rather than calling it timely cancellation, while application truth remains independently determined. [proposed: separate control acknowledgement, timeliness, and business effect] |

For `LIFE01-X08`, a kernel requirement assessment—if emitted—uses `native_absence` for the required evidenced gap, not `satisfied`; an unexposed cancellation opportunity remains `not_exercised` even when capability availability is absent. [extracted: contracts/00-evidence-kernel.yaml, `EK-ASSESSMENT`]

These assessment checks do not add a cancellation-result field to the lifecycle schema; the underlying capability reference, opportunity, control observations, and measured effects must remain sufficient for independent assessment. [proposed: preserve the kernel’s orthogonality without duplicating its diagnostic types]

## 8. Observation, controls, and timing

### 8.1 Observation transitions and bounds

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-O01` | B/F / I,B | Generate the observation edges listed below and every omitted edge; include closed-first translation/launch/infrastructure failure. | Accept valid edges with supporting evidence; closed-first failures do not invent an opened interval, and a closed window never reopens through late evidence or another Start. [proposed: verify the complete local observation state machine] |
| `LIFE01-O02` | F / B | Use a backend that never terminates or flushes its tail; cross the commissioned active, drain, cancel-wait, and cleanup-wait bounds using controlled clocks, including zero-valued limits. | Stop issuing workflow commands at the active boundary, end each wait within its declared local bound, finalize without remote cooperation, and record missing tails/unknown execution rather than awaiting them indefinitely. Zero is an immediate configured boundary, not “disabled” or “missing.” [proposed: prove bounded local behavior without a native timeout claim] |
| `LIFE01-O03` | H/F / I,B | Exercise the four control operations separately, with request, acknowledgement, and effect observations sharing an operation ID but using distinct control-event IDs; repeat with no containment authority or a broader affected scope than declared. | Preserve append-only control history; evidence for one operation cannot establish another. Reject unauthorized containment and disclose known affected attempts/limitations instead of hiding collateral scope. [proposed: prevent cleanup and cancellation from collapsing into one action] |
| `LIFE01-O04` | B/F / I,B,D | Seal the practice origin after drain; try a later fixture commit; preserve a commitment that occurred before sealing. Separately try to seal a production origin through observation closure or a snapshot seal. | The practice seal prevents new fixture commits but neither erases earlier commitment nor proves native stop. A connector/snapshot seal cannot establish production final absence, and an employer commission cannot enable `seal_after_drain`. [proposed: distinguish application authority from local observation authority] |
| `LIFE01-O05` | F / B,D | Restart with an unfinished observation window; later deliver a native callback and origin receipt. | Mark the observation interrupted and close it under the new boot, preserve acknowledged facts and old closure knowledge, append late evidence normally, and issue no automatic side-effecting request. [proposed: test restart without assuming remote execution stopped] |
| `LIFE01-O06` | B/F / I,D | Deliver a transport error while native execution may continue; then attempt to replace the frozen closure reason, boundary, or close-time version pins in a closed-to-closed revision. | Connection loss is a local observation, not native failure; valid late/cleanup additions may append, but the original closure fields and `at_close` snapshot cannot change. [proposed: enforce immutability within otherwise advancing observation publications] |

The transition relation used by `LIFE01-O01` is as follows. [extracted: contracts/01-application-attempt-lifecycle.yaml, observation transition rules]

| From | Allowed next state |
|---|---|
| `unpublished` | `not_opened`, `open`, `closed`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `not_opened` | `open`, `closed`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `open` | `open`, `draining`, `closed`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `draining` | `draining`, `closed`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |
| `closed` | `closed`. [extracted: contracts/01-application-attempt-lifecycle.yaml] |

`RequestNativeCancel`, `CloseObservationConnection`, `ReleaseNativeContext`, and `Contain` must retain their separate operation names and target scopes; a process kill or fixture seal is not normalized into native cancellation. [extracted: contracts/01-application-attempt-lifecycle.yaml, `ControlObservation` and `LIFE-CONTROLS`]

Unsupported native context release is a valid lifecycle observation, not a reason to invent a release endpoint or to prevent local finalization. [inferred: 3-hellscape-blueprint.md, §§5.3, 5.5, and 10.6]

### 8.2 Timing cross-checks

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-T01` | H/B / S,I,D | Record a real exact zero interval, an unchanged subject-reported zero under an opaque-report clock, a bounded post-close observation, and unavailable native timing. | Preserve all four forms with origin, clock, boot, method, and censoring; neither exact zero nor unavailable timing is rewritten into the other. [proposed: apply kernel timing discipline at the lifecycle boundary] |
| `LIFE01-T02` | F / I,D | Subtract across engine/native clocks, across browser documents, or across restart boots; reverse UTC annotations while monotonic offsets advance. | Reject unsupported exact arithmetic and occurrence ordering; use evidenced bounds or unavailable timing where necessary, and never derive elapsed time from UTC annotations. [proposed: prevent cross-clock cancellation and restart claims] |
| `LIFE01-T03` | F / D | Compare native primitive zero against aggregate request latency, then against an independently supported lower bound for that same primitive interval. | Aggregate latency alone does not establish a native timing discrepancy; a discrepancy needs comparable boundaries or a defensible matching bound, and native reported bytes remain unchanged in either case. [proposed: prevent the timing defect’s test from becoming a false-accusation generator] |

All injected durations and scheduler margins must be pinned in the test configuration; they are corpus values, not production timeout defaults or claims about native performance. [proposed: deterministic tests without inheriting unverified deployment assumptions]

A runner watchdog is separate from every commissioned lifecycle deadline; its expiry cannot be reported as subject-native timeout, cooperative cancellation, or successful closure. [extracted: 5-browser-qualification.md, Evidence discipline]

## 9. Source checks and origin facts

### 9.1 Authentication/correlation matrix

`LIFE01-A01` exercises every row through the real ingestion/verification boundary, not by directly inserting a pre-approved `SourceChecks` object. [proposed: test provenance assignment rather than trusting serialized claims of verification]

| Authentication | Attempt correlation | Trace condition | Required treatment |
|---|---|---|---|
| Verified | Matched | Matched | Accept a correctly scoped claim/fact if its remaining mapping and ownership checks pass. [proposed: positive source-verification control] |
| Verified | Mismatched or unknown | Any | Retain receipt evidence, but do not attach an accepted claim/fact to this attempt. [proposed: authenticated does not mean correlated] |
| Failed or unknown | Matched | Even matched | Retain untrusted observation where authorized; do not accept it into the source-authored histories. [proposed: matching identifiers do not authenticate a sender] |
| Verified | Matched by independently evidenced alternate inputs | Mismatched | Acceptance may proceed under the pinned policy, but trace mismatch remains visible and the alternate correlation evidence is retained. [proposed: distinguish an actual correlation defect from an unusable trace field] |
| Verified | Claimed matched in the payload only | Any | Refuse the asserted match until the verification path establishes it; caller-authored `verified`/`matched` values are not evidence. [proposed: block source-check forgery] |

### 9.2 Origin cases

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-A02` | H/F / I,D | Supply a valid matching origin receipt; separately supply a submit click, operator note, native success, HTTP 200, or confirmation-looking content with no verified origin semantics. | Only the verified receipt can establish its supported application fact; the other observations remain citable observations, not commitment. [proposed: positive and negative controls for origin authority] |
| `LIFE01-A03` | F / I | Change origin, candidate, job, attempt binding, kind, or receipt association while preserving otherwise valid syntax and source authentication. | Reject the fact for this attempt; company/title similarity, a matching trace string, or a valid signature cannot repair mismatched commissioned identities. [proposed: require the receipt to prove this application, not merely some application] |
| `LIFE01-A04` | B/F / I,D | Provide an as-of absence; later provide commitment. Separately claim final absence using only an observation-close event, local deadline, or snapshot seal; include a positive origin-owned finality control. | Retain compatible as-of absence and later commitment; reject fabricated finality; accept final absence only with the origin guarantee covering the attempt under the pinned policy. [proposed: distinguish temporary absence from impossibility of future commitment] |
| `LIFE01-A05` | B / I,D | Deliver corroborating receipts for one origin commitment, then verified distinct commitments for the same attempt; append a later withdrawal, recruiting rejection, or job-closure observation. | Corroboration does not count as another commitment; verified distinct commitments produce `multiple_origin_commitments` evidence/issue rather than deduplication by convenience. Later recruiting events do not rewrite historical commitment as not committed. [proposed: preserve both duplicate-risk evidence and the fact that an application was submitted] |
| `LIFE01-A06` | F / I,D | Supply mutually inconsistent final origin facts; reverse receipt order and repeat reconciliation. | Preserve both facts and an `origin_fact_conflict` issue; do not select truth by newest receipt, erase the conflict, or automatically blame the subject. Relevant unresolved conflict keeps comparison coverage incomplete. [proposed: make origin-source inconsistency visible instead of last-write-wins] |

## 10. Claim normalization and reconciliation

### 10.1 Claim cases

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-R01` | H/F / I,D | Normalize native execution `completed` without application semantics; then attempt a mapping that upgrades it to committed, upgrades a primitive `None`/acknowledgement to success, or invents a missing native ID. | The faithful narrow mapping is accepted; unsupported strengthening is refused or diagnosed as a mapping error, never attributed as an original native overclaim. Raw bodies and mapping pins remain available. [proposed: enforce the audited `/run` semantic boundary] |
| `LIFE01-R02` | B/F / I,D | Deliver conflicting authenticated/correlated terminal response and callback claims, in both receipt orders; also deliver an identical callback twice and conflicting content under the same native message identity. | Preserve distinct conflicting claims and source-conflict evidence; duplicate delivery adds no duplicate logical claim; identity conflict is surfaced rather than overwriting the original or choosing the latest response. [proposed: make callback retries and contradictions independently observable] |
| `LIFE01-R03` | B/F / I,D | Use a predecessor version’s capability or claim evidence for a new subject version; separately expose an unsupported connector cancel mapping where native capability is unknown or documented present. | Reject cross-version claim attribution and unearned capability inheritance; connector mapping limitations do not establish native absence, and known presence alone does not establish successful behavior. [proposed: keep version scope and mapping coverage separate] |
| `LIFE01-R04` | H/F / D | Exercise every report-coverage row in §10.2 and mutate each resulting state/coverage combination into an unsupported one. | Correct outputs are accepted; unsupported `reconciled`, suppressed contradiction, omitted comparisons, or fabricated inapplicability are rejected. [proposed: enforce the meaning of the binary decided verdict plus explicit missingness] |
| `LIFE01-R05` | F / I,D | Cite a future event, an unjournaled screenshot, an unimported external reference, a mismatched fact/claim ID, a bad pointer, or evidence outside the pinned source revisions. | Refuse the unsupported comparison; current wall time, newer rows, or controller-only knowledge cannot fill the gap. [proposed: require citation closure at the actual analysis boundary] |
| `LIFE01-R06` | H/F / D,R | Re-derive a report with identical source pins and evaluator, then change live network data, mutable projections, and current wall time; remove a required pinned evaluator/artifact in a separate variant. | Identical retained inputs yield the same substantive report value; unrelated live changes do not enter analysis. Missing required inputs produce explicit unavailability, not “latest version” substitution or a fresh external execution. [proposed: verify deterministic reporting without promising repeatable live browser behavior] |

Conflicting claims are not subject to a truth-state transition filter: a new claim after a terminal-looking claim remains evidence, including when it contradicts the previous one. [extracted: contracts/01-application-attempt-lifecycle.yaml, execution transition rule]

### 10.2 Report-coverage oracle for `LIFE01-R04`

Each row uses a fresh fixture with exactly the stated claims, facts, and limitations, and every claim/application assertion in the pinned execution publication must be accounted for. [proposed: make aggregation expectations deterministic]

| Inputs | Required comparison and report |
|---|---|
| No applicable subject claims in the analyzed prefix, including a manual attempt with a committed origin fact | `comparisons=[]`, `coverage=not_applicable`, `state=M(not_applicable)`; explain that there is no subject claim to assess, not that execution or application failed. [proposed: manual origin success does not need a fabricated execution claim] |
| Execution-only completed/stopped/failed claim with no application assertion | A scope-supported `not_comparable` comparison; `coverage=complete`, `state=reconciled`, with no implication that the native claim’s truth was independently proved. [proposed: complete accounting is not universal verification] |
| Explicit committed assertion plus a matching verified commitment | `consistent`, `coverage=complete`, `state=reconciled`. [proposed: positive claim/fact agreement] |
| Explicit committed assertion plus origin-owned final absence covering the assertion | `contradicted`, `coverage=complete`, `state=contradicted`. [proposed: application-success overclaim with authoritative contrary evidence] |
| Relevant application assertion, but outcome evidence was never established | `indeterminate`, `coverage=incomplete`, `state=M(not_observed)`. [proposed: missing evidence is neither negative application fact nor reconciliation success] |
| Relevant application assertion, with journaled loss of the necessary outcome observation | `indeterminate`, `coverage=incomplete`, `state=M(observation_lost)`, retaining known identities and the loss evidence. [proposed: distinguish loss from never-observed outcome] |
| One proved contradiction and another unresolved comparison | Preserve both; `coverage=incomplete`, `state=contradicted`, with the unresolved limitation still visible. [proposed: incompleteness must not hide an already established contradiction] |
| An unknown native claim scope that the mapping cannot interpret | Preserve scope uncertainty and relevant evidence; do not use `not_comparable` merely to turn an undecidable claim into complete coverage. [proposed: distinguish established narrow scope from unknown semantics] |

A reconciled report may describe a failed application, a completed application, or an application whose commitment was outside the native claim’s scope; readers must present the application axis and report limitations separately. [inferred: contracts/01-application-attempt-lifecycle.yaml, `ReportValue`]

## 11. Manual work, lineage, and production accounting

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `LIFE01-M01` | H / I,B,D | Commission `F-manual` with a pinned manually discovered job/task, genuine test authorization, and reasoned missing profile/evaluation material where unavailable; record human actions, close observation, then receive a separately verified synthetic origin receipt. | No crawler, reranker, executor, laboratory, or model call occurs; dispatch/execution remain `Z(not_applicable)`, observation is recorder-owned, and the origin fact is usable without fabricated subject claims or comparison success. [proposed: test the smallest honest manual-application recording path] |
| `LIFE01-M02` | B/F / I,D | Repeat the manual path with only an operator note claiming receipt, an unfinished form, or missing confirmation; also attempt to assign a subject/native ID or credit an executor. | Notes and partial work remain tracked, unresolved application knowledge stays unresolved unless origin facts establish otherwise, and no automation identity or unattended credit is fabricated. [proposed: manual evidence must be useful without becoming false authority] |
| `LIFE01-M03` | H/F / I,B | Commission production P, then practice Q with `rehearsal_of=P`; separately commission practice first, then production with `performance_of` pointing to it. Exercise valid same-kind `derived_from`, wrong-kind derivation, unresolved/misidentified links, self-links, and cycles. | Valid links resolve to immutable commissioned identities without reciprocal edits; invalid links are rejected. Completing the rehearsal does not Start production, copy source facts, or change kind. [proposed: make lineage usable without evidence promotion or cyclic commissioning] |
| `LIFE01-M04` | F / I,D | Put real-job content in a laboratory task, relabel the fixture held-out/production, or import its commitment as proof of an employer application. | Content realism does not change form provenance; the laboratory remains practice/held-in, and its commitment cannot establish the production application axis. [proposed: direct guard against Hellscape-as-production qualification] |
| `LIFE01-M05` | B/F / I,D | Use two distinct job IDs with the same company/title, import a legacy tracker `status`, and present a synthetic production-shaped success to an application-counting reader. | Keep the attempt identities distinct; legacy status is historical input, not authoritative lifecycle state; synthetic/historical-unscored evidence contributes no real application credit. [proposed: prevent old deduplication and tracker conventions from erasing or inventing applications] |
| `LIFE01-M06` | B / I,D | In a subject attempt whose declared assistance policy allows human intervention, record an actual manual intervention before a later native completion claim. | Preserve the commissioned assistance declaration and realized intervention evidence separately; do not edit the native claim or call the resulting work unattended, and do not credit manual actions as native capability. [proposed: enforce assistance honesty without forbidding useful authorized help] |

The manual production-shaped fixtures exercise the recording contract only; they do not substitute for the candidate finding and applying to an actual job. [inferred: 1-handoff-brief.txt, Parts VII–IX]

Hellscape’s ordinary manual cooperative-SPA acceptance remains in the evidence-kernel suite; lifecycle conformance does not duplicate it as a prerequisite for recording real manual work. [inferred: 1-handoff-brief.txt, Part IX; conformance/00-evidence-kernel.md, manual M1 acceptance]

## 12. Coverage index

All abbreviated case IDs below carry the `LIFE01-` prefix. [proposed: compact indexing with one stable naming convention]

| Contract rule | Principal cases |
|---|---|
| `LIFE-COMMISSION` | `S01`, `S03–S04`, `D01`, `D07`. [proposed: admission, immutability, permissions, and new-attempt coverage] |
| `LIFE-AXES` | `W01–W02`, `H01–H03`, `M01–M02`. [proposed: authority separation and manual inapplicability coverage] |
| `LIFE-PUBLICATION` | `W03–W07`, `D04`. [proposed: revision, atomic-publication, and asynchronous-reader coverage] |
| `LIFE-EVIDENCE` | `W05`, `A01–A03`, `R05–R06`, `M05`. [proposed: source verification, reference closure, and evidence-scope coverage] |
| `LIFE-DISPATCH` | `D01–D04`, `D06`. [proposed: handle-before-wire, state guards, and delivery uncertainty coverage] |
| `LIFE-IDEMPOTENCY` | `D03–D05`, `D07`, `A05`. [proposed: local deduplication, native resume limits, and duplicate-risk coverage] |
| `LIFE-CLOSE` | `X01–X09`, `O01–O02`, `O05–O06`. [proposed: finite observation, distinct connection closure, and immutable knowledge coverage] |
| `LIFE-CONTROLS` | `X07–X09`, `O02–O04`. [proposed: request/acknowledgement/effect and authorized containment coverage] |
| `LIFE-CLAIMS` | `S05`, `X01–X06`, `R01–R03`. [proposed: faithful claims, explicit uncertainty, conflicts, and exact-version coverage] |
| `LIFE-ORIGIN` | `A02–A06`, `O04`, `M01–M04`. [proposed: commitment, temporal absence, finality, and non-promotion coverage] |
| `LIFE-SOURCE-CHECKS` | `W01–W02`, `A01–A03`, `R01–R03`. [proposed: authentication, correlation, provenance, and mapping coverage] |
| `LIFE-RECONCILE` | `H01–H03`, `X01–X07`, `R01–R06`. [proposed: claim/fact comparison without input mutation] |
| `LIFE-REPORT-COVERAGE` | `H02`, `A06`, `R04`, `M01`. [proposed: decided, incomplete, and inapplicable report coverage] |
| `LIFE-LATE-EVIDENCE` | `W06–W07`, `X01–X06`, `O05–O06`. [proposed: appended evidence, stale reports, new revisions, and preserved close snapshots] |
| `LIFE-LINEAGE` | `S03`, `D07`, `M03–M05`. [proposed: immutable kind, valid links, and no practice promotion] |
| `LIFE-MANUAL` | `S05`, `M01–M02`, `M06`. [proposed: manual recording and disclosed assistance coverage] |
| `LIFE-TIME` | `X05–X09`, `O02`, `O05`, `T01–T03`. [proposed: semantic interval, censoring, clock identity, and restart coverage] |

The reference run must also enforce the mirrored kernel type semantics; it may reuse the already-versioned kernel test vectors rather than maintaining a divergent null, clock, hash, or provenance corpus. [proposed: test one shared meaning instead of creating parallel implementations of the contract]

## 13. Evidence package and final gate

### 13.1 Required retained evidence

Each execution receipt must identify the suite/contract digests, implementation build/configuration, declared role scope, selected cases/subcases, fixture and evaluator pins, test clock configuration, fault schedule, and independent controller version. [proposed: bind a pass to what actually ran]

For each case, retain the expected assertions, observed assertions, verdict, rejection/failure location where applicable, and content-addressed supporting artifacts. [proposed: make verdicts inspectable rather than descriptive]

The evidence package must contain the applicable manifests, commissions, journals, complete owner publications, source bodies/receipts, close snapshots, seal vectors, report inputs/outputs, restart traces, and the independent delivery/commit ledger. [proposed: permit verification of both evidence semantics and actual effects]

Use synthetic candidate data and test credentials in the corpus; restrict native bodies and receipt artifacts where required, and do not place real candidate material or authentication secrets in ordinary logs or checked-in goldens. [inferred: contracts/00-evidence-kernel.yaml, `EK-ARTIFACTS`; 6-get-a-job.xml.txt, AGENTS.md]

The package must state that synthetic production-shaped outcomes are excluded from real application counts and that no current executor capability was established by a fake backend. [proposed: prevent conformance output from acquiring unintended product meaning]

### 13.2 Verdict and process-exit discipline

Use `pass`, `fail`, `blocked`, `error`, and `not_run` as test-controller verdicts, distinct from lifecycle values. [proposed: retain the evidence-kernel suite’s verification vocabulary]

A full reference pass requires every required case/subcase to pass, valid supporting artifacts, no unreported exclusions, no golden regeneration from the implementation’s current output, and no prohibited external execution. [proposed: make acceptance mechanical and evidence-backed]

For the proposed CLI, preserve the established exit discipline: `0` for the fully passed selected scope, `1` for established assertion failures, `2` for blocked prerequisites, `3` for runner/oracle integrity errors, `4` for otherwise incomplete required evidence, and `130` for interruption. [proposed: reuse conformance/00-evidence-kernel.md’s process contract without restoring m0 as a standalone gate]

When conditions overlap, use interruption, runner error, established failure, blocked prerequisite, then other incompleteness as precedence; retain all per-case outcomes regardless of aggregate exit. [proposed: keep process results deterministic]

A missing dependency is not a subject failure, a skipped case is not a pass, and an expected injected failure that is correctly handled is not a runner error. [inferred: 5-browser-qualification.md, Evidence discipline]

### 13.3 Contract-review stop condition

If a complete, authority-valid scenario cannot be represented by the pinned contract, retain the minimized case and report a contract-review issue; do not silently alter enums, weaken source checks, collapse axes, or redefine missingness to make the implementation pass. [inferred: 1-handoff-brief.txt, Parts IV and VIII]

The provisional report-coverage mechanism should be revised only if concrete corpus evidence cannot distinguish decided, incomplete, and inapplicable comparison under its current representation; the claim/fact separation remains invariant. [extracted: contracts/01-application-attempt-lifecycle.yaml, `LIFE-REPORT-COVERAGE`]

Passing this suite permits the declared lifecycle implementation to ship independently; it neither requires the entire portfolio to work nor excuses postponing real, tracked applications while the infrastructure matures. [inferred: 1-handoff-brief.txt, Parts IV, VII, and IX]
