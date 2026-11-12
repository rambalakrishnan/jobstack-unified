# External connector — conformance suite

## 1. Target and acceptance boundary

| Item | Value |
|---|---|
| Contract | `contracts/02-external-connector.yaml`, wire version `external-connector/0.1.0`. [extracted: contracts/02-external-connector.yaml] |
| Dependencies | `evidence-kernel/0.1.0` and `application-attempt-lifecycle/0.1.0`; their common types and ownership rules retain their established meanings. [extracted: contracts/02-external-connector.yaml, `x-compatibility`] |
| Suite identifier | `external-connector-conformance/0.1.0`; case IDs use `EXT02-`. [proposed: stable corpus selection and verification receipts] |
| Status | Review draft specifying executable acceptance criteria, not a report that an implementation has passed. [proposed: distinguish the test specification from execution evidence] |
| Reference corpus | Hellscape M1’s local synthetic-backend suite; no live subject participates in reference acceptance. [extracted: 1-handoff-brief.txt, Part VIII; 3-hellscape-blueprint.md, §10.6] |
| Maintainer | The contracts boundary owns the shared vectors; implementations supply adapters that exercise their actual connector code. [proposed: keep contracts as inputs rather than derive separate tests from each implementation] |
| Purpose | Make commissioned work observable and recoverable without mistaking local delivery, native completion, or laboratory success for a real application commitment. [inferred: 1-handoff-brief.txt, Parts VI–IX] |

Conformance concerns faithful translation, durable asynchronous dispatch, bounded local behavior, and truthful evidence—not whether the subject completes the task. [extracted: 3-hellscape-blueprint.md, §5.2]

Circus Tent and Ringmaster run these vectors independently; passing does not require shared code, native primitives, browser handles, or runtime packaging. [inferred: 1-handoff-brief.txt, Parts III and V]

The crawler’s discovery/extraction mappings use the same external mechanics without inventing application attempts, while manual applications bypass connector dispatch and remain recordable through the kernel and lifecycle. [extracted: contracts/02-external-connector.yaml, `x-contract`, `EXT-TASK`, and `EXT-READ-ONLY`]

### 1.1 Counterexamples the suite must preserve

| Distinction | Load-bearing reason |
|---|---|
| External tasks versus internal browser primitives | A shared browser abstraction would reproduce the Stagehand-on-Juggler failure; a shared task protocol does not require such an abstraction. [extracted: 1-handoff-brief.txt, Parts III and V] |
| Connection closure versus native stop | The documented cancellation experiment observed continued work and a later authenticated callback after disconnect. [extracted: 3-hellscape-blueprint.md, §1.3] |
| Execution claim versus origin fact | An audited `/run` completion initially establishes execution completion only; upgrading it to application submission is a mapping overclaim. [extracted: 3-hellscape-blueprint.md, §4.6] |
| Reported zero versus missing timing | The diagnosed `_elapsed()` defect requires native zero reports to remain source claims beside independently measured intervals. [extracted: 3-hellscape-blueprint.md, §§1.3 and 4.5] |
| Authentication versus correlation | A signed callback can still have a trace mismatch, and HTTP 200 establishes neither authentication nor attempt correlation. [extracted: 3-hellscape-blueprint.md, §§1.3 and 5.3; 5-browser-qualification.md, Evidence discipline] |
| Capability declaration versus assessment | Native absence, unavailable connector mapping, invalid controls, and failed behavior are different findings; the connector cannot certify itself. [extracted: 1-handoff-brief.txt, Part VI] |

### 1.2 Evidence limits

The supplied sources describe historical native bodies and callbacks but do not supply the complete original artifacts or the callback signing/key-distribution contract; authentic historical-import vectors require those bytes, their digests, deployment scope, and verifier specification. [uncertain: obtain the original audit artifacts and versioned native verification contract before labeling any corpus item a historical capture]

Until then, reconstructed native messages and callback signatures are explicitly synthetic, with a pinned test-only verifier rather than an invented production signing algorithm. [proposed: exercise authentication mechanics without fabricating the audited interface]

These gaps do not block synthetic conformance, Hellscape M1, or manual applications, and do not create another pre-M1 probe milestone. [inferred: 1-handoff-brief.txt, Parts VIII–IX; 3-hellscape-blueprint.md, §§10.6 and 15]

This suite does not establish current employer compatibility, browser isolation, native cancellation in a deployed executor, or production application throughput. [inferred: 1-handoff-brief.txt, Parts III and VI]

## 2. Execution model

### 2.1 Verification layers and case classes

| Layer | Required demonstration |
|---|---|
| **S — Structure** | Decode and validate complete records against the pinned schema, including discriminators, closed objects, required fields, formats, and reasoned missingness. [proposed: use the established kernel/lifecycle verification layering] |
| **I — Integrity and authority** | Resolve references, digests, subject/configuration pins, grants, source checks, and cross-record constraints that JSON Schema alone cannot establish. [proposed: distinguish syntactic validity from authoritative evidence] |
| **B — Stateful behavior** | Exercise real admission, durable dispatch, command deduplication, observation, control, storage, and restart paths under faults. [proposed: require implementation behavior rather than a passing replacement model] |
| **D — Derivation** | Verify that normalization and consumer interpretation preserve source scope, uncertainty, assistance, and ownership. [proposed: test semantic claims independently of transport success] |
| **R — Re-derivation** | Reconstruct retained observation/analysis results from pinned evidence without live task execution or control effects. [proposed: preserve evidence replay rather than promise repeatable browser behavior] |

Cases are **H** for happy path, **B** for boundary, and **F** for adversarial input or injected failure; an F case passes when the specified refusal, containment, or uncertainty is correctly evidenced. [proposed: separate application failure from conformance failure]

“Reject” means no unauthorized dispatch, publication, data disclosure, or resource effect; an authorized refusal event may still be recorded. [proposed: make negative-test success observable without accepting the rejected command]

For malformed responses, “reject” means the consumer refuses the unsupported interpretation while retaining authorized raw evidence; it does not mean erasing an inconvenient native claim. [inferred: contracts/02-external-connector.yaml, `EXT-NORMALIZE` and `EXT-FAILURE`]

### 2.2 Declared test scope

| Profile | Required scope and claim |
|---|---|
| `reference` | Execute every case and subcase using the reference connector machinery plus synthetic mappings sufficient to expose the specified branches; a full reference pass has no excluded required cases. [proposed: make Hellscape M1’s shared corpus complete without requiring a live framework] |
| `provider` | Exercise all nine handlers, mandatory local semantics, every advertised task mapping, and applicable native-operation branches through the product’s actual connector; test unsupported branches explicitly and list unsupported-only positive branches as out of scope rather than passed. [proposed: native capability absence must not force invented implementations] |
| `consumer` | Drive a scripted provider, validate its replies and references, and demonstrate the refusal/interpretation assertions applicable to a consumer; this is not provider dispatch or durability conformance. [proposed: let job-hunter and Hellscape consumers ship independently] |
| `native-mapping` | Exercise one pinned mapping against a synthetic implementation of that native surface, retaining request bytes and normalization results; this is narrower than full connector conformance. [proposed: permit an initial REST mapping to be verified without a deployed executor] |

The selected cases, conditional branches, descriptor pins, and exclusions must be declared before execution; a failing supported branch cannot be relabeled unsupported afterward. [proposed: prevent post-hoc scope reduction]

An unmapped native operation is a tested outcome, not permission to omit its external handler. [extracted: contracts/02-external-connector.yaml, `OperationMapping`]

A descriptor with no executable task mappings can be structurally valid, but its pass cannot be advertised as application-executor or discovery delivery acceptance. [inferred: contracts/02-external-connector.yaml, `ConnectorDescriptor`; 1-handoff-brief.txt, Part I]

### 2.3 Isolated runner and independent oracle

The runner uses local synthetic backends, a contract-valid evidence service or test fixture, synthetic candidate material, and an independent command/effect ledger; it requires no crawler, orchestrator deployment, employer, browser, model service, or paid solver. [proposed: realize the silo gate without a portfolio integration dependency]

For B cases, invoke the implementation’s real durable path and actual request/control handlers, not an in-memory substitute that bypasses its persistence or concurrency machinery. [proposed: mocks may implement remote behavior but cannot prove the connector’s durability]

Test hooks may pause delivery, block an owner publication, advance a registered clock, crash/restart a process, or inspect durable state; they are implementation-adapter facilities, not additional external connector verbs. [proposed: expose test control without enlarging the runtime protocol]

The independent ledger records delivered native requests, synthetic origin commitments, control effects, artifact retrievals, and prohibited activity such as speculative endpoint calls or hidden planning. [proposed: avoid using the connector’s own success report as its sole oracle]

The reconciler receives only evidence actually journaled and admitted into its pinned inputs; the controller’s private knowledge of an unseen commit is not available to it. [inferred: contracts/00-evidence-kernel.yaml; contracts/01-application-attempt-lifecycle.yaml, `LIFE-EVIDENCE`]

The following command is a proposed implementation entry point, not an executable supplied by this draft. [proposed: give independently implemented runners a reproducible invocation]

    ./tools/conformance/external-connector \
      --implementation <implementation-adapter> \
      --profile reference \
      --output <evidence-directory>

### 2.4 Fixture families

All fixture names, identities, native messages, schedules, and test authority keys below are synthetic corpus proposals, not actual application records. [proposed: make fixture provenance explicit]

| Fixture | Required behavior |
|---|---|
| `F-plan` | Accept a separately recorded public-observation plan, block native completion independently of delivery, and return execution completion or failure without necessarily supplying a native run ID. [proposed: exercise a blocking-shaped native plan executor behind asynchronous Start] |
| `F-rest` | Implement the documented `/run` and eligible `/extract` shapes under a pinned synthetic mapping; record every route invoked and leave unestablished native routes unmapped. [proposed: exercise the initial Circus Tent binding without certifying its deployment] |
| `F-read` | Serve discovery/extraction data and a tempting state-mutating operation; independently count any mutation attempt. [proposed: enforce the crawler’s acquisition boundary] |
| `F-controls` | Provide separately selectable cancel/release mappings: evidenced present, evidenced absent, unknown, and native-present-but-unmapped; independently control acknowledgement and effect. [proposed: expose capability, mapping, and behavioral distinctions] |
| `F-late` | Keep work running after transport closure, deliver callbacks later, and provide synthetic origin receipts independently of native reports. [proposed: reproduce close-time uncertainty without contacting an employer] |
| `F-state` | Keep browser-state and learning-state registries separate, with explicit context identities and recording hooks for creation, reset, reuse, and release. [proposed: test policy realization without claiming browser-level isolation] |
| `F-artifacts` | Retain exact byte artifacts, support bounded transfer, optionally expose an evidenced native retrieval mapping, and inject loss/corruption independently of metadata. [proposed: test available bytes rather than plausible locators] |

Application fixtures use valid commissions; discovery fixtures use reasoned inapplicability for attempt/commission fields. [extracted: contracts/02-external-connector.yaml, `WorkScope`]

A post-close origin commitment uses an isolated production-shaped `employer_origin` scenario with no fixture-seal claim; a practice fixture instead permits a late receipt for a pre-seal commitment and rejects new post-seal commits. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-ORIGIN`; 3-hellscape-blueprint.md, §5.5]

Every fabricated observation carries kernel `evidence_scope=synthetic`, including production-shaped test attempts, and is excluded from real application counts. [inferred: contracts/02-external-connector.yaml, `EXT-EVIDENCE`; contracts/00-evidence-kernel.yaml]

### 2.5 Fixture construction and timing

Build complete valid records, install artifact bytes, register clocks and producers, establish grants, and compute real digests before applying each negative mutation. [proposed: prevent rejection for an unrelated missing field from satisfying a test]

`M(reason)` abbreviates the complete wire object `{"value":null,"reason":"<reason>"}`; tables showing selected fields are projections, not alternative wire schemas. [proposed: concise review notation while preserving schema completeness]

Pin test limits and clock/scheduler configuration before execution, and use barriers rather than arbitrary sleeps wherever possible. [proposed: make race and deadline tests reproducible]

Injected durations and queue sizes are corpus settings, not production defaults or claims about the historical executor’s capacity. [proposed: avoid inheriting unverified deployment numbers]

A runner watchdog remains separate from connector call limits, observation deadlines, native timeouts, and cancellation bounds; watchdog expiry cannot count as successful local finalization. [inferred: 5-browser-qualification.md, Evidence discipline]

## 3. Surface, carrier, and authority

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-S01` | H / S,I | Round-trip every request/result pairing for the nine verbs, all five exported standalone record forms, every observation payload variant, and each typed error form. | Valid records pass without field loss or discriminator coercion; responses match the request’s connector, operation, correlation identity, and authorized handle/scope. [proposed: cover the complete external message surface] |
| `EXT02-S02` | F / S | Generate mutations of every required field, closed-object field, enum, discriminator, and conditional branch; include unknown versions, an extra primitive verb, `Page`/element/node-handle fields, a composite task `status`, and `confirmed_stopped` as a control disposition. | Reject unknown or invalid normalized forms; selectors inside a properly referenced native plan remain permissible native data, not a new shared primitive API. [proposed: enforce the external/internal boundary without banning legitimate native plans] |
| `EXT02-S03` | B/F / S,I | Exercise reasoned missingness and exact zero; inject bare normalized nulls, duplicate JSON keys, non-finite numbers, malformed digests, invalid timestamps, URL userinfo, and noncanonical origin values containing paths, queries, or fragments. | Enforce schema and semantic validation without silent defaults; raw native bodies remain opaque retained bytes even when they contain nulls or invalid JSON. [proposed: distinguish strict normalized records from faithfully retained native input] |
| `EXT02-S04` | H/F / S,B | Run the reference carrier through `POST /connector` using UTF-8 JSON; return ordinary results, typed errors, an unauthenticated response without a correlated body, and a lost response. | Normal results use HTTP 200, typed errors use appropriate 4xx/5xx statuses, and clients inspect the body; transport success, rejection, or silence establishes no native task outcome. [proposed: test the selected carrier without asserting it already exists on a native service] |
| `EXT02-A01` | F / I,B | Supply valid IDs/digests but missing or wrong channel authentication, an application-session credential as a control credential, and caller-authored principal/provenance/source-verification fields. | No control authority is obtained; authorization derives from authenticated registration, and rejected traffic reveals no protected handles or artifacts. [proposed: test authentication independently of payload plausibility] |
| `EXT02-A02` | F / I,B | Cross connector, handle, run, journal, attempt, account, subject, and artifact scopes using another principal’s references; repeat with an authorized principal whose grant excludes the requested verb or resource. | Refuse unauthorized access/effects even when the referenced object exists; opaque references and hashes are not bearer grants. [proposed: enforce scoped authority on every handler] |
| `EXT02-A03` | F / I,B | Use forbidden entry/redirect destinations, substitute a runtime-access binding for another account, request an arbitrary callback destination, or embed control credentials in task data. | Refuse the unauthorized destination or credential use before that effect; runtime access resolves only under the commissioned policy, and callbacks use configured authorized destinations rather than caller-supplied arbitrary URLs. [proposed: preserve task permission boundaries across serialization and runtime binding] |
| `EXT02-A04` | F / I,B,D | Attempt connector publication of application/report axes or have a reconciler overwrite source claims; separately block an authorized application/report owner while connector-local work proceeds. | Reject authority escalation, preserve source publications, and allow independently authorized connector commits without waiting for the blocked owner’s transaction or acknowledgement. [proposed: test owner separation at the connector boundary] |

The reference carrier and pull-pagination mechanics are provisional mechanisms, but their currently pinned semantics are testable; adding another carrier requires a versioned profile rather than silently changing these results. [extracted: contracts/02-external-connector.yaml, `x-reference-carrier` and `EXT-OBSERVE`]

## 4. Describe and configuration identity

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-D01` | H/F / S,I,B | Describe a configured subject; mutate operation coverage, duplicate a verb, omit a catalog capability, duplicate a task mapping, mismatch `subject` and `capabilities.subject`, or cite an unregistered descriptor. | Return one coherent versioned declaration with exactly one entry per verb and per catalog capability, including the contract’s minimum capability IDs; reject invalid declarations without task execution, browser launch, hidden planning, or speculative endpoint discovery. [proposed: test descriptor completeness rather than infer it from a brand name] |
| `EXT02-D02` | B/F / I,D | Start a second subject version with no new evidence; try to copy the predecessor’s presence, absence, isolation, timing, revision, and capacity findings; then add evidence explicitly scoped to the second version. | Initially publish unknown capabilities for the new version; accept later declarations only to the extent supported by that version’s evidence, without treating a changed interface version string as an observed native revision. [proposed: exercise no inheritance in both positive and negative directions] |
| `EXT02-D03` | B / I,D | Compare native-present-but-unmapped, evidenced-native-absent, unknown availability, a documented capability not yet exercised, and a missing local dependency. | Keep mapping coverage, native availability, prerequisite failure, and behavioral result distinct; emit no connector-owned qualification or requirement-satisfaction result. [proposed: prevent unsupported mapping and infrastructure failure from becoming subject findings] |
| `EXT02-D04` | H/B / I,B | Repeat Describe after a registered descriptor/configuration update while retaining an earlier preparation pin; inspect build, binding, configured mode, stack, budget accounting, and limits. | A read may return the newer declaration, but earlier pins remain resolvable and immutable; current configuration cannot silently replace the configuration already accepted for Start. [proposed: make descriptor evolution compatible with immutable commissioning] |

The suite must not require the historical native concurrency defaults, a native revision endpoint, or a shared browser-binding inventory. [inferred: contracts/02-external-connector.yaml, `ConnectorLimits`, `SubjectIdentity`, and `EXT-SURFACE`]

## 5. Prepare, task semantics, and assistance

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-P01` | H / I,B | Prepare a valid admitted task using `F-plan`, a recorded public-observation plan, and scoped runtime-access references; observe all external activity hooks. | Persist the complete immutable preparation, exact delivered-task/native-request bytes and hashes, translation pin, assistance, budget mapping, and concerns; no target browsing, native task, planner call, context reset, credential test, or recovery occurs. [proposed: positive control for non-executing preparation] |
| `EXT02-P02` | F / S,I,B | Mismatch task/scope/commission fields, submit a manual commission to Start, omit application authorization, give discovery an application identity, or commission an apply task as read-only extraction. | Reject before execution; application work resolves its immutable commission, discovery keeps attempt/commission inapplicable, and manual recording does not acquire a fabricated automation subject. [proposed: enforce work-type and commissioning boundaries] |
| `EXT02-P03` | B/F / I | Execute the hash relations in §5.1, including equal semantic hashes across different admitted runtime destinations and altered native bytes under the same digest. | Verify every hash at its stated boundary; semantic equality is never accepted as proof of full-request equality or authority to change destinations. [proposed: test all three task/request identities independently] |
| `EXT02-P04` | F / I,B,D | Ask a plan mapping to supply a missing planner; substitute hidden fixture data for public planning evidence; inject extra sleeps, selector alternatives, values, retries, or recovery steps; separately use an explicitly declared native goal-planning mode. | Incomplete translation returns `UNSUPPORTED_MAPPING`, hidden assistance is refused, and the native goal planner runs only after Start; legitimate declared native recovery remains subject behavior, not secret connector assistance. [proposed: preserve assistance attribution and faithful translation] |
| `EXT02-P05` | H/B/F / I,B | Request separate browser/learning policies: required unsupported fresh state, permitted best-effort unknown state, authorized reuse, and frozen learning state; try frozen browser state or unauthorized reuse. | Required unsupported policies are not startable; best-effort limitations are recorded before Start and later realization is evidenced separately; no fixture namespace or fresh browser context proves learning reset or browser isolation. [proposed: test state-policy honesty without testing browser internals here] |
| `EXT02-P06` | B/F / I,B | Omit a required concern acceptance, accept a nonexistent concern, change task/mapping/subject/runtime-access bytes after preparation, or Start against a stale configuration; include an accepted native-cancel limitation as a positive control. | Refuse the invalid or stale preparation instead of silently repreparing; an acknowledged non-blocking capability gap does not itself prevent authorized execution or become a satisfied capability. [proposed: make acceptance bind to exactly the preparation reviewed] |
| `EXT02-P07` | F / I,B | In `F-read`, route discovery/extraction through a self-referral, contact-reveal, account mutation, or application submission, including a mutating GET and an acquisition POST. | The decision follows operation semantics, not HTTP method; the mutation counter remains zero, permitted acquisition still works, and crawler authority is not expanded by task prose or plan artifacts. [proposed: reproduce Stage1’s acquisition-versus-write boundary] |
| `EXT02-P08` | B/F / I,B | Fail a local prerequisite or task translation before dispatch; provide an irrelevant nonempty authorization reference as a companion case. | Return a connector/policy/environment error with truthful delivery information, no native failure claim, and no target activity; a syntactically present reference is not accepted as permission. [proposed: keep local preparation failures out of subject execution truth] |

### 5.1 Hash oracle for `EXT02-P03`

Use independent canonicalization/hash goldens, not digest values produced solely by the implementation under test. [proposed: avoid a serializer and validator agreeing on the same defect]

| Mutation | Required relation |
|---|---|
| Change only object-member serialization order in a structured record | Its RFC 8785 structured-record digest is unchanged. [proposed: verify the pinned canonical structured hash] |
| Change only `task_id` | The semantic task hash is unchanged, while the complete task/preparation identity changes. [proposed: verify the explicit semantic-hash exclusion] |
| Change `entry.url` or a permitted origin’s actual address while retaining immutable logical IDs, using separately valid admissions | The semantic hash may remain equal under the prescribed replacement, but full task/request pins differ and the old preparation cannot authorize the new destination. [proposed: separate reproducible semantic aliases from dispatch authority] |
| Change goal, input artifact, logical ID, permission, budget, state policy, success criterion, or array order | Recompute the semantic hash; none of these fields is silently stripped by the profile. [proposed: test that the semantic projection excludes only its named fields] |
| Change exact delivered-task or native-request bytes, including meaningful serialization differences | Their exact-byte digests change, even when a separate structured interpretation would be equivalent. [proposed: preserve what the subject was actually given] |
| Add authorized transport authentication outside the retained native-request boundary | Preserve the prepared task/request meaning and compare dispatch against the pinned mapping boundary; retain any sensitive transport evidence under restricted access rather than hashing away changed task values. [proposed: distinguish transport credentials from task mutation] |

## 6. Start, command identity, and recovery

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-E01` | H / I,B | Start a prepared task while `F-plan` accepts delivery but indefinitely blocks native completion; inspect durable state at the first permitted wire send. | The local handle, request binding, logical idempotency association, and dispatch intent are durable before delivery; Start returns its local receipt without awaiting native completion, and the handle contains no invented native run ID. [proposed: directly prove asynchronous handle-before-wire behavior] |
| `EXT02-E02` | B/F / I,B | Run the command-identity matrix in §6.1, including concurrent duplicate calls and changed content under an existing key. | Exactly one logical command/effect is admitted where deduplication applies; conflicts are explicit and retained receipts are not rewritten into newer outcomes. [proposed: test retries through the actual concurrency and storage path] |
| `EXT02-E03` | F / B,D | Execute every crash cut in §6.2 with an independent fixture reset and repeat the original local command after restart. | Recovery follows durable evidence, preserves ambiguity where necessary, and never uses a fresh key or speculative native resend to discover whether the earlier submission worked. [proposed: test the remote-effect/local-acknowledgement gap] |
| `EXT02-E04` | H/F / I,B | Resume with a new command identity, the same logical key/handle/request/context, a valid checkpoint/native-resume contract, and recovery authority; remove each guard in turn, change context, or begin draining/close observation. | Only the evidenced same-logical-execution recovery is allowed; additional delivery is journaled, completed side-effecting steps are not repeated, and unsupported/closed recovery remains refused or uncertain rather than restarting from the top. [proposed: preserve checkpoint value without promising employer exactly-once semantics] |
| `EXT02-E05` | F / I,B | Rotate the logical key, caller, connector, or executor for an already commissioned application; then present a separately commissioned, explicitly reviewed new attempt. | The old commission cannot gain a second logical execution; a legitimate new attempt retains its own identity and duplicate-risk review without erasing the prior attempt’s commitment or uncertainty. [proposed: prevent local retry mechanics from duplicating a real application] |

### 6.1 Command-identity matrix for `EXT02-E02`

| Operation / variant | Required behavior |
|---|---|
| Identical `Prepare`, `Start`, control, or `CollectArtifacts` request under the same authenticated principal, connector, and `request_id` | Once a durable receipt exists, return that retained receipt without repeating the command’s effect; a lost reply is not a new command. [proposed: test the shared mutating/collecting command key] |
| Changed payload, operation, or other canonical request content under that command key | Return `IDEMPOTENCY_CONFLICT` without replacing the first command or performing the changed effect. [proposed: test full-request command identity, including cross-verb collisions] |
| Repeated initial Start with a new `request_id` but the same principal/connector/logical key and preparation | Return the same immutable handle without another logical execution; the new lookup is distinct from replaying the original retained receipt. [proposed: separate command deduplication from logical-execution deduplication] |
| Same logical key with a different preparation/request | Refuse the logical-key conflict, even if the semantic task hash is unchanged. [proposed: prevent a comparison hash from weakening execution identity] |
| Same key string used by another principal | Do not reveal or recover the first principal’s handle merely by key collision; independently enforce commission and grant constraints. [proposed: verify principal-scoped identity without allowing duplicate commission execution] |
| Same live Describe or Observe request repeated after new registered evidence | A newer read result is permitted; neither operation is forced to return a stale mutating-command receipt. [proposed: distinguish fresh reads from effect deduplication] |
| Same CollectArtifacts command repeated after another artifact arrives, followed by a new collection command | The first returns its retained result; the new command can collect the newer inventory. [proposed: expose collection freshness explicitly rather than mutate an acknowledged receipt] |

### 6.2 Crash-cut oracle for `EXT02-E03`

| Cut | Required recovery and independent check |
|---|---|
| Preparation bytes installed, registration not committed | No startable registered preparation or native delivery exists; recovery may retain an unreferenced artifact but must not publish a dangling registration. [proposed: test artifact-before-reference ordering] |
| Before durable Start admission/intent | No native send is allowed; a later explicitly authorized retry can perform the first dispatch. [proposed: test refusal to cross the effect boundary without durability] |
| After durable handle/intent, before an externally visible send | Recover as uncertain unless durable implementation evidence proves non-delivery; the controller’s private delivery barrier is not recovery evidence. [proposed: test the indistinguishable crash window conservatively] |
| After native acceptance or a synthetic origin commit, before local result persistence | Preserve uncertainty and the existing handle; a later verified response/callback/receipt can resolve its own axis without a new submission. [proposed: prevent duplicate effects after lost acknowledgements] |
| After durable local/native receipt, before reply to caller | Recover the retained receipt and handle without a new logical execution or altered source claim. [proposed: test durable acknowledgement recovery] |
| After callback body installation/receipt, before normalization or publication | Resume evidence processing idempotently; retain raw bytes and produce no duplicate logical claim from repeated callback delivery. [proposed: test recovery across the ingestion/interpretation boundary] |
| After a control effect but before the caller receives its receipt | Recover durable command information or explicit delivery uncertainty; do not silently repeat the destructive control or manufacture an observed effect without evidence. [proposed: extend command safety beyond Start] |
| During storage failure before or after possible delivery | Do not acknowledge partial state or fabricate a journal reference; stop new unsafe admission, retain acknowledged state after recovery, and disclose any unpersisted tail without claiming the remote work stopped. [proposed: keep the storage fault model honest] |

The independent delivery and origin ledgers must be checked after each crash case, but their contents become application facts only through the fixture’s separately authorized origin-verification path. [proposed: detect duplicate effects without giving the connector omniscient authority]

## 7. Bounded execution and backpressure

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-B01` | H/B/F / B | Fill configured active and queue capacity with blocked synthetic tasks, including a zero-queue configuration; submit more work and request local close/control operations while saturated. | Admission stays within declared limits, excess work receives explicit backpressure/refusal, acknowledged work is not silently dropped, and the reserved local control path still progresses. [proposed: test bounded work admission without importing historical capacity defaults] |
| `EXT02-B02` | B/F / B,D | Advance the active budget while an accepted task remains queued; separately cross call, drain, cancellation-wait, and cleanup-wait limits against a nonterminating backend, including zero-valued limits. | Queued time consumes the active observation budget, no new workflow delivery starts after its boundary, and each local wait ends within its declared bound; zero means immediate rather than disabled, and no local timeout becomes a native stop or timeout claim. [proposed: verify finite local behavior under native noncooperation] |
| `EXT02-B03` | F / I,B | Exceed declared request, response, observation-buffer, or artifact-transfer bounds; inject a producer gap and an unflushed observation tail. | Reject or contain the over-bound operation at its declared boundary, retain known gaps/loss, and never silently truncate a native body into a valid claim or label incomplete evidence complete. [proposed: make resource bounds compatible with evidence integrity] |
| `EXT02-B04` | B/F / I,B,D | Advertise subject-enforced or unenforced action/model/recovery budgets; request a required unenforceable policy, then a separately authorized best-effort policy with concerns accepted. | Preparation accurately identifies all five enforcement dimensions; unsupported required policy is not silently downgraded, and accepted limitations remain visible rather than proving zero cost or native enforcement. [proposed: test budget declarations independently of measured consumption] |

The suite measures local bounds with registered clocks and predeclared uncertainty, not by increasing tolerances after a late result. [proposed: prevent a passing deadline test from being defined retrospectively]

## 8. Observe, pagination, and publication

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-O01` | H/B / I,B | Read a live cutoff, then paginate through that fixed prefix while the journal receives unrelated events and new target observations. | Return only registered projections for the requested handle, in increasing journal order; continue against the pinned cutoff and expose later evidence only through a new live cutoff. [proposed: test snapshot-like pagination over an append-only journal] |
| `EXT02-O02` | F / S,I,B | Tamper with cursor handle, journal, sequence/hash, zero-position missingness, or `through`; use `after > through`, an unrecognized prefix, and unavailable valid history as distinct cases. | Reject invalid cursors without skipping to the head; report unavailable history explicitly through the appropriate cursor/loss error rather than treating it as an empty complete scan. [proposed: test cursor integrity and retention failure separately] |
| `EXT02-O03` | B / B,D | Poll with no new projected events, with a closed observation window, and after late evidence arrives; repeat a live read under the same request identity. | Bounded reads may return empty pages, `has_more=false` describes only the cutoff, closure does not disable durable Observe, and neither emptiness nor closure means native termination or no future callback. [proposed: test the meaning of observation availability] |
| `EXT02-O04` | B/F / S,I,B | Vary `max_items`, wait limits, response-byte limits, and a single item larger than the response bound; try nonzero waiting with a fixed cutoff. | Respect item/byte/call limits, require zero wait for a fixed cutoff, and return `RESPONSE_TOO_LARGE` rather than advance past an undelivered oversized item; fewer items may be returned without losing scan correctness. [proposed: test bounded paging without silent loss] |
| `EXT02-O05` | F / I,D | Change a projection’s provenance, timestamp, payload, measurements, artifact list, whole-event pointer, registration, or referenced lifecycle metadata while leaving its outward shape valid. | Refuse the forged projection; `ObservationItem` metadata and `payload.data` match the registered event, nested evidence is supported, and complete lifecycle publication bytes match their copied identity, revision, digest, and authorized axis. [proposed: verify that Observe is a read projection, not an alternative truth source] |
| `EXT02-O06` | B/F / I,B,D | Delay a lifecycle publication, interrupt its transfer, or publish a newer connector-owned axis while application/report is stale; continue scanning. | Readers see complete old-or-new publications and explicit revision pins, never mixed partial fields or a fabricated current report; dispatch/observation evidence remains available without synchronous reconciliation. [proposed: test asynchronous composition through the external surface] |

### 8.1 Cursor cross-check

For `EXT02-O01`, construct a journal segment containing, in order, a nonprojected kernel event, a target-handle observation, another handle’s event, another nonprojected event, and a second target-handle observation. [proposed: force scanning and returned-item positions to differ]

Use a cutoff at the segment’s end and an item limit of one; concatenating the pages must return exactly the two target observations without duplication or omission, while `next` may identify a scanned nonprojected event. [proposed: test the contract’s last-scanned cursor rather than assuming last-returned equals last-scanned]

At every page, verify `after < item.sequence <= next <= through`, `next`’s hash against the actual journal entry, and `has_more == (next.sequence < through.last_sequence)`. [extracted: contracts/02-external-connector.yaml, `EXT-OBSERVE`]

A missing or corrupted event cannot be crossed by pretending it was merely an unrelated event. [inferred: contracts/02-external-connector.yaml, `EXT-OBSERVE` and `EXT-EVIDENCE`]

## 9. Native ingestion and normalization

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-N01` | H/B / I,B,D | Deliver terminal execution completion and terminal execution failure, with and without native IDs; also deliver primitive acknowledgements and a `None`-equivalent result under a pinned synthetic mapping. | Preserve the exact source body and narrow claim scope; a genuine native failure is normal Observe evidence, local handles never become invented native IDs, and acknowledgements do not become application or primitive semantic success. [proposed: positive and negative controls for claim normalization] |
| `EXT02-N02` | B/F / S,I,B,D | Return native null/missing fields, unexpected optional shape, malformed JSON, truncated bytes, and an uninterpretable result scope. | Retain original bytes and report the scoped mapping/protocol limitation; retain interpretable narrow claims where justified, otherwise emit no accepted claim or explicit unknown scope, never repair the body into success or blame a local mapping defect on the subject. [proposed: exercise the observed documentation/body divergence honestly] |
| `EXT02-N03` | H/F / I,B | Execute every source-check row in §9.1 through actual raw-message ingestion and the pinned verifier. | Only authenticated, correlated messages yield accepted execution claims; caller-authored `verified` or `matched` flags cannot bypass verification. [proposed: test provenance assignment, not insertion of preapproved SourceChecks] |
| `EXT02-N04` | B/F / I,B,D | Repeat identical callbacks, send conflicting terminal response/callback claims in both orders, and reuse a native message identity with conflicting content. | Deduplicate logical delivery without deleting distinct conflicts; preserve source bodies and conflict evidence rather than selecting the newest response or emitting duplicate logical claims. [proposed: make retry and contradiction independent behaviors] |
| `EXT02-N05` | F / I,D | Mutate the mapping to turn native execution completion into commitment, stopped into a no-future-commit guarantee, or a submit click into an origin fact. | Refuse/diagnose the unsupported normalization while retaining raw evidence; the connector produces no application/report publication, and the mapping error is not attributed as an original subject claim. [proposed: prevent adapter overclaim and claim-as-fact] |
| `EXT02-N06` | H/F / I,D | Produce complete and valid partial extraction/discovery outputs under schemas that represent those forms; then return schema-invalid content, omit required facts, or mark an origin-looking output as application success. | Validate emitted `TaskOutput` bytes against the pinned output schema, preserve partial/unknown completeness and discovery provenance, and retain invalid native output as evidence without inventing values or commitment. [proposed: partial output is useful only when its contract actually represents partiality] |

### 9.1 Authentication and correlation oracle for `EXT02-N03`

| Raw-message condition | Required treatment |
|---|---|
| Verified source, independently matched attempt, matched trace | Accept only claims supported by the pinned mapping and exact subject/version scope. [proposed: positive verification control] |
| Verified source, matched attempt through authorized alternate correlation evidence, mismatched trace | Acceptance may proceed under the pinned policy, but preserve the trace mismatch and the alternate matching evidence. [proposed: distinguish trace quality from overall correlation] |
| Verified source, mismatched or unknown attempt | Retain authorized receipt evidence without accepting claims into this attempt. [proposed: authentication does not establish correlation] |
| Failed or unknown authentication, matching IDs or trace text | No accepted claims; identifiers and HTTP status do not authenticate the sender. [proposed: negative verification control] |
| Payload asserts verification or provenance that the gateway has not established | Ignore/refuse the asserted authority and assign source checks through the verifier. [proposed: prevent authentication laundering] |
| Valid signature for a different subject version, configuration, or commission | Do not attach the claim to the requested attempt merely because the message is genuine. [proposed: enforce immutable source scope] |
| Signing contract or configured verification key unavailable | Preserve raw observations and explicit unknown authentication; do not silently accept unsigned messages or fabricate a native signing contract. [proposed: make the documented evidence gap operational] |

For the initial REST mapping, capture the route log while running these cases: `/run`, eligible `/extract`, and any explicitly configured documented operational observations do not authorize probing `GET /runs/{id}`, speculative cancel/release/revision routes, or a guessed artifact-download endpoint. [inferred: contracts/02-external-connector.yaml, `x-native-reconciliation`; 3-hellscape-blueprint.md, §5.3]

The recorded MCP redirect is neither a required test dependency nor evidence that MCP is universally unavailable. [extracted: 3-hellscape-blueprint.md, §5.3]

## 10. Controls, close-time knowledge, and late evidence

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-C01` | H/B/F / I,B,D | With an evidenced synthetic cancel mapping, separately schedule request delivery, acknowledgement, subject stop claim, and independently observed stop; repeat with acknowledgement only, uncertain delivery, and stop after the declared native bound. | Keep separate control events with one operation identity; acknowledgement is not effect, a subject stop report remains a claim, silence leaves uncertainty, and measured late stop cannot be credited as bounded cancellation. [proposed: test every control-evidence stage] |
| `EXT02-C02` | B / I,B,D | Request cancellation under native-absent, native-unknown, and native-present-but-unmapped descriptors. | Return a truthful unsupported control observation for the unmapped request without speculative calls; preserve whether the limitation is native absence or mapping coverage, and finalize locally when required without making native cancel present. [proposed: test unsupported behavior as a valid connector result] |
| `EXT02-C03` | H/B / I,B | Close the native observation transport with `end_observation=false`; separately use `true`, repeat the command, and attempt later workflow/resume delivery. | False closes only that transport; true also starts bounded local drain/finalization, without sending implicit cancel; the connector carrier and durable Observe remain usable, closed observation never reopens, and later cleanup/late evidence may still append. [proposed: make the two meanings of close explicit] |
| `EXT02-C04` | B/F / I,B,D | Run the late-evidence matrix in §10.1 after saving the original observation-close object, version pins, and publication bytes. | Preserve close-time knowledge and source histories while appending late evidence; only the independent consumer/reconciler derives updated comparisons, and no new application request is issued. [proposed: carry the cancellation corpus through the actual external protocol] |
| `EXT02-C05` | H/B/F / I,B | Release an evidenced native context, request unsupported release, supply a stale/foreign context, and test missing context identity with and without a verified handle-scoped release mapping. | Invoke only the authorized mapped release, preserve unsupported/uncertain outcomes, and never substitute logout, profile purge, shared-context reset, or process containment; unsupported release does not prevent local finalization. [proposed: separate native context cleanup from broader resource destruction] |
| `EXT02-C06` | H/F / I,B,D | Contain an authorized synthetic resource under a pinned policy; repeat without authority, with caller-supplied shell/PID-like data, and against a shared resource affecting other attempts. | Execute only the registered reviewed policy for the authorized resource, retain independently observed effects and known affected attempts/limitations, and refuse unauthorized or undisclosed scope escalation. [proposed: test containment authority and collateral scope] |
| `EXT02-C07` | B/F / I,B,D | Seal a practice origin under actual fixture-origin authority, reject a new post-seal write, and retain a pre-seal commitment; try the same no-future-commit conclusion for a production-shaped origin after a local close or process kill. | Fixture sealing prevents new fixture commits without proving native stop or erasing earlier commitment; local observation/containment cannot establish production final absence. [proposed: distinguish fixture mutation authority from remote application truth] |

### 10.1 Late-evidence matrix for `EXT02-C04`

The independent origin recorder supplies verified synthetic facts under its own grant; the connector only carries native reports and observations, and the reconciler writes only report. [inferred: contracts/01-application-attempt-lifecycle.yaml, `LIFE-AXES`; contracts/02-external-connector.yaml, `EXT-AUTHORITY`]

| Close-time source evidence | Later evidence | Required interpretation |
|---|---|---|
| No subject terminal/outcome claim | Correlated execution-only completion callback and verified commitment | Close-time execution/application knowledge remains unknown; no fabricated subject `unknown` claim and no contradiction arise merely from the later fact. [proposed: exercise the documented disconnect/continuation counterexample] |
| Explicit subject `outcome_unknown` at its knowledge boundary | Verified commitment | The uncertainty was compatible with later commitment; preserve both the claim and the earlier knowledge boundary. [proposed: test honest uncertainty rather than retrospective correctness] |
| Explicit no-commit assertion covering the entire attempt | Verified commitment within that scope | The independent reconciler can derive contradiction; the connector preserves the original claim and does not “correct” it. [proposed: test a definite overclaim with actual contrary evidence] |
| Execution-only `stopped` claim with no application assertion | A remote transaction commits | Do not invent a no-commit guarantee or infer continued execution solely from the transaction’s completion. [proposed: separate execution stop from rollback of in-flight work] |
| No-future-commit assertion after a boundary | Receipt arrives late, but commit occurrence relative to the boundary is unknown | Receipt arrival alone cannot establish contradiction; preserve unknown temporal relation until occurrence/causal evidence supports a comparison. [proposed: prevent delivery order from substituting for event time] |

These assertions reuse the meanings exercised by `LIFE01-X01`–`LIFE01-X06`; passing the lifecycle suite alone does not prove that this connector preserved the necessary native evidence. [inferred: conformance/01-application-attempt-lifecycle.md, §7]

## 11. Artifact collection and transfer

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-F01` | H/B / I,B | Collect an inventory and named artifacts containing available, disabled, not observed, lost, and evidenced unsupported items; retain a known digest after content loss. | Return unique names, exactly the requested names for named collection, available bytes or reasoned missingness for each, and honest inventory coverage; available content matches `expected_digest`, and loss does not erase known identity. [proposed: test useful artifact missingness rather than empty success] |
| `EXT02-F02` | H/B / S,I,B | Transfer artifacts across multiple byte chunks, including an empty artifact, a final short chunk, exact EOF, and maximum configured transfer size. | Canonical base64 decodes to `returned_bytes`, each chunk digest and offset are correct, transfers respect envelope overhead/limits, non-EOF chunks progress, EOF is exact, and the assembled full digest/size matches the registered artifact. [proposed: verify retained bytes end to end] |
| `EXT02-F03` | F / S,I,B | Request an offset beyond EOF, zero/over-bound chunk limits, unknown or unauthorized digests, URL/path-like selectors, corrupted bytes, or unavailable content previously registered as available. | Reject or report artifact unavailability explicitly without arbitrary fetches, unauthorized disclosure, digest substitution, silent truncation, or a false empty artifact. [proposed: test transfer integrity and constrained resolution] |
| `EXT02-F04` | H/F / I,B,D | Retrieve an already-produced artifact through an evidenced native mapping; remove that mapping and repeat; offer a “retrieve” path that would rerun a task or create a new screenshot/browser session. | Use only the declared retrieval contract, refuse workflow re-execution, and preserve native retrieval absence separately from locally retained response artifacts. [proposed: prevent evidence collection from manufacturing new evidence] |
| `EXT02-F05` | B/F / I,B | Lose inventory-source access, interrupt artifact installation, and present a partial checksum-invalid publication; repeat a previously acknowledged collection command. | Do not report an unavailable inventory as established complete emptiness, publish references to absent bytes, or replace a retained command receipt with a fresher inventory; new collection commands can expose subsequently registered evidence. [proposed: test publication and collection durability together] |

Restricted native bodies and synthetic credential-bearing artifacts may remain in authorized evidence storage, but their content must not leak into ordinary logs, error details, unauthenticated transfers, or checked-in public goldens. [inferred: contracts/00-evidence-kernel.yaml, artifact rules; 6-get-a-job.xml.txt, AGENTS.md]

## 12. Shared evidence rules and consumer behavior

| ID | Class / layers | Exercise | Required result |
|---|---|---|---|
| `EXT02-K01` | H/B/F / S,I,D | Record a real exact-zero duration, a native reported zero under its opaque-report clock, bounded timing, and unavailable timing; attempt cross-clock/cross-boot arithmetic and compare unlike native/request intervals. | Preserve origin, clock, boot, method, bounds, censoring, and reasoned missingness; never substitute zero, divide aggregate latency into step timings, or accuse native timing using incomparable boundaries. [proposed: apply the kernel timing rules to connector evidence] |
| `EXT02-K02` | F / I,D | Cite an unjournaled screenshot, future event, bad pointer, unregistered clock, self-supporting normalized claim, changed native artifact, or evidence outside the declared prefix. | Refuse the unsupported derivation/projection while preserving authorized raw observations; source artifacts and supporting events precede their normalized references. [proposed: test citation closure rather than plausible-looking IDs] |
| `EXT02-K03` | H/B/F / I,D | Feed consumer tests a local Start receipt, HTTP 200, native completed/failed/stopped claims, a documented capability, a harness watchdog/containment effect, and an absent capability with unexposed versus required blocked opportunity. | Keep dispatch, execution, application, capability, opportunity, and result distinct; only the independent consumer assessment applies kernel result semantics, and no connector/harness convenience becomes native satisfaction. [proposed: enforce “the connector declares; the consumer assesses” on both sides] |
| `EXT02-K04` | H/F / I,D,R | Reconstruct retained observations and analysis using identical prefixes/mappings, then alter live data/current time/current descriptor; remove a pinned dependency in a separate run. | Retained substantive results are reproducible from their pins, current mutable state is not substituted, missing dependencies are explicit, and offline re-derivation issues no native task/control/retrieval calls. [proposed: test replay without replaying external effects] |
| `EXT02-K05` | F / I,D | Give a counting/selection consumer a synthetic production-shaped commitment, a practice success with real-job content, a legacy tracker status, and a manually recorded receipt with no subject. | Do not count synthetic/practice work as real employer applications, trigger production from rehearsal, import a legacy status as authoritative truth, or credit manual action as unattended executor capability. [proposed: preserve the product purpose at the consumption boundary] |

For `EXT02-K03`, reuse the kernel’s versioned capability/opportunity/result vectors instead of maintaining a second assessment algorithm inside the connector. [proposed: enforce one shared interpretation without moving judgment into the judged component]

The manual receipt case is a consumer compatibility test, not a requirement to commission a connector for manual work. [inferred: contracts/02-external-connector.yaml, `x-native-reconciliation.manual`]

## 13. Coverage index

All abbreviated case IDs below carry the `EXT02-` prefix. [proposed: compact indexing with stable case identities]

### 13.1 Required Hellscape M1 synthetic cases

| Source requirement | Principal coverage |
|---|---|
| Terminal success and failure | `E01`, `N01`, `K03`. [proposed: expose native terminal claims through asynchronous execution] |
| Nullable native fields | `S03`, `N01–N02`. [proposed: retain raw shape and normalize missingness honestly] |
| Malformed results | `N02`, `B03`, `K02`. [proposed: retain evidence without fabricated interpretation] |
| Native capability absence | `D02–D03`, `C02`, `K03`. [proposed: distinguish absence from mapping and result] |
| Connection close with later callback | `C03–C04`, `O03`. [proposed: exercise continuation and late evidence after closure] |
| Conflicting response/callback claims | `N04`, `C04`. [proposed: preserve conflicts and immutable source histories] |
| Unavailable native step timing | `N02`, `K01`. [proposed: no default-zero or invented primitive intervals] |
| Explicit zero reported timing | `K01`. [proposed: retain zero as a source value beside independent measurements] |
| Unsupported context release | `C05`. [proposed: keep cleanup limits independent of finalization] |
| Bounded finalization despite continuing remote work | `B01–B02`, `C02–C04`. [proposed: establish local progress without claiming native cancellation] |

### 13.2 Contract-rule coverage

| Contract rule | Principal cases |
|---|---|
| `EXT-SURFACE` | `S01–S02`, `D01`, `P04`. [proposed: nine verbs and no shared primitive layer] |
| `EXT-AUTHORITY` | `A01–A04`, `P02`, `C05–C07`, `F03`. [proposed: caller, resource, and writer authority] |
| `EXT-DESCRIBE` | `D01–D04`, `N03`. [proposed: complete exact-version declarations without inheritance] |
| `EXT-DECLARE-NOT-ASSESS` | `D03`, `N05`, `K03`. [proposed: independent consumer judgment] |
| `EXT-TASK` | `P02–P03`, `E05`, `K05`. [proposed: commissioned task/kind/lineage integrity] |
| `EXT-READ-ONLY` | `P07`, `N06`. [proposed: acquisition versus mutation] |
| `EXT-PREPARE` | `P01`, `P04`, `P08`. [proposed: non-execution and faithful translation] |
| `EXT-PREPARATION-PIN` | `D04`, `P03`, `P06`, `E02`. [proposed: immutable configuration and concern acceptance] |
| `EXT-START` | `E01–E03`, `B02`. [proposed: handle-before-wire and asynchronous receipt] |
| `EXT-IDEMPOTENCY` | `E02–E05`, `F05`. [proposed: command, logical execution, and collection deduplication] |
| `EXT-RESUME` | `E04–E05`, `C03`. [proposed: guarded same-logical recovery] |
| `EXT-OBSERVE` | `O01–O06`, `C04`. [proposed: bounded cutoff scans and late evidence] |
| `EXT-NORMALIZE` | `N01–N05`, `K01–K02`. [proposed: raw preservation, source checks, and narrow claims] |
| `EXT-CLOSE` | `B02`, `C03–C04`, `C07`. [proposed: bounded closure with immutable knowledge] |
| `EXT-CONTROLS` | `C01–C07`, `E02–E03`. [proposed: separate requested, acknowledged, and observed effects] |
| `EXT-BOUNDS` | `B01–B04`, `O04`, `F02–F03`. [proposed: admission, wait, and transfer limits] |
| `EXT-STATE-POLICY` | `P05–P06`, `C05`, `K03`. [proposed: separate browser and learning state] |
| `EXT-ARTIFACTS` | `F01–F05`, `O05`, `K02`. [proposed: durable, authorized, content-addressed evidence] |
| `EXT-EVIDENCE` | `A04`, `O05–O06`, `N03`, `K02`, `K04–K05`. [proposed: registered provenance and owner-separated publication] |
| `EXT-TIME-NULL` | `S03`, `B02`, `K01`. [proposed: reasoned missingness and comparable measurements] |
| `EXT-FAILURE` | `S04`, `P08`, `E03`, `N01–N02`, `K04`. [proposed: local errors, native evidence, and safe offline replay] |

Shared type tests may reuse the pinned evidence-kernel and lifecycle vectors, but the connector-specific transport, mutation, and fault cases must run through the connector implementation itself. [proposed: reuse semantics without substituting another component’s pass for this one]

## 14. Evidence package and final gate

### 14.1 Retained verification evidence

Each verification receipt must pin the suite/contract digests, implementation build and configuration, profile, selected cases/subcases, exclusions, descriptor/mapping/verifier versions, fixtures, clock configuration, fault schedule, and independent controller version. [proposed: bind the result to the implementation and scope actually tested]

For each case, retain expected assertions, actual observations, verdict, failure/refusal location, and supporting content-addressed evidence. [proposed: make a pass independently inspectable]

Retain the applicable manifests, commissions, preparations, handle records, command/response bodies, journals, source checks, native bodies, control observations, complete lifecycle publications, close-time pins, artifact transfers, and replay outputs. [proposed: preserve the inputs needed to verify protocol and evidence behavior]

Also retain the independent delivery/effect ledger, forbidden-activity log, fault/restart trace, and timing cross-checks; output generated solely by the implementation under test is insufficient for B-case verification. [proposed: prevent circular validation]

Use synthetic candidate data and test credentials; disclose that production-shaped successes are synthetic and establish no current executor capability against an employer. [proposed: keep the verification package from acquiring unintended product meaning]

### 14.2 Verdict and exit discipline

Use test-controller verdicts `pass`, `fail`, `blocked`, `error`, and `not_run`, distinct from connector, lifecycle, and requirement-result values. [proposed: preserve the verification vocabulary used by the preceding suites]

A full reference pass requires every required case/subcase to pass, complete supporting evidence, no undeclared exclusion, and no prohibited external execution. [proposed: make full acceptance mechanical rather than narrative]

A provider/consumer/native-mapping receipt must name its scope and exclusions and cannot call that narrower result a full reference pass. [proposed: allow independent shipping without overstating coverage]

For the proposed CLI, use `0` for the fully passed selected scope, `1` for established assertion failures, `2` for blocked prerequisites, `3` for runner/oracle integrity errors, `4` for otherwise incomplete required evidence, and `130` for interruption. [proposed: reuse conformance/00-evidence-kernel.md and conformance/01-application-attempt-lifecycle.md exit discipline]

When conditions overlap, use interruption, runner error, established failure, blocked prerequisite, then other incompleteness as aggregate precedence, while retaining every per-case result. [proposed: make aggregate status deterministic]

A skipped required case is not a pass, a missing dependency is not native failure, a correctly handled injected fault is not runner error, and a native task failure is not automatically connector nonconformance. [inferred: 5-browser-qualification.md, Evidence discipline; 3-hellscape-blueprint.md, §5.2]

### 14.3 Contract-review stop condition

If an authority-valid scenario cannot be represented by the pinned contract, retain its minimized request/evidence trace and raise a contract-review issue rather than add a hidden verb, coerce a new enum, weaken evidence checks, or redefine missingness. [inferred: 1-handoff-brief.txt, Parts IV and VIII]

A measured need for another carrier or streaming mechanism may justify the contract’s stated provisional flip, but does not justify removing prefix integrity, owner separation, truthful uncertainty, or the task-shaped external boundary. [extracted: contracts/02-external-connector.yaml, `x-reference-carrier` and `EXT-OBSERVE`]

Passing the declared scope permits that connector or consumer to ship independently; neither full portfolio integration nor a subject’s successful application is a prerequisite for its conformance result. [inferred: 1-handoff-brief.txt, Parts IV and VIII]

Real, tracked applications—including manual ones—continue alongside this work rather than waiting for the connector infrastructure to mature. [inferred: 1-handoff-brief.txt, Parts VII and IX]
