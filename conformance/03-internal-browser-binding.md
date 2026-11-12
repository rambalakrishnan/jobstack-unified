# Internal browser binding — conformance suite 0.1.0

## 1. Authority and scope

This is a review-draft test specification for the two independent documents in `contracts/03-internal-browser-binding.yaml`; it is not a test-execution receipt or evidence that either proposed native surface exists. [proposed: distinguish contract review from executed qualification.]

Run the suite independently for BrowserOxide and Camoufox, using their respective native implementations; common evidence assertions do not authorize a shared driver, shared element handle, shared selector implementation, or cross-browser fallback. [extracted: 1-handoff-brief.txt, internal-binding and independent-product invariants.]

| Suite instance | Schema selected by `$id` | Entry points | Consumers |
|---|---|---|---|
| BrowserOxide | `urn:job-application:contracts:internal-browser-binding:browseroxide:0.1.0` | `BOBindingDescriptor`, `BOPrimitiveRecord`, `BODomExport` | Crawler and Ringmaster. [extracted: contracts/03-internal-browser-binding.yaml, BrowserOxide document.] |
| Camoufox | `urn:job-application:contracts:internal-browser-binding:camoufox:0.1.0` | `CFBindingDescriptor`, `CFPrimitiveTranscript`, `CFReduction` | Python Circus Tent. [extracted: contracts/03-internal-browser-binding.yaml, Camoufox document.] |

BrowserOxide's full-strength claim requires executed proof of direct native DOM and V8 access; reading serialized HTML through a protocol bridge cannot satisfy it. [extracted: contracts/03-internal-browser-binding.yaml, BO-NATIVE and BO-CAPS.]

Camoufox runs are additionally scoped to `extension_native` or `legacy_playwright_juggler`; a compatibility-route pass cannot certify the extension route, and a route label alone cannot prove bypass. [extracted: contracts/03-internal-browser-binding.yaml, CF-ROUTE and CF-CAPS.]

These gates govern component claims and peer integration, not the candidate's ability to apply manually: journaled production applications continue alongside binding construction and conformance. [extracted: 1-handoff-brief.txt, silo discipline and parallel thin slice.]

## 2. Execution model and acceptance claims

### 2.1 Four verification layers

1. **Structural validation:** parse both YAML documents, select one by `$id`, and validate records using only that document's local definitions, with JSON Schema 2020-12 and asserted formats. Reject duplicate YAML keys rather than accepting last-key-wins parsing. [proposed: executable implementation of both documents' validation rules.]
2. **Semantic validation:** resolve descriptors, artifacts, journal prefixes, permissions, clock registrations, and native object lifetimes; evaluate the selected document's `x-rules` and description-level constraints that JSON Schema cannot express. [proposed: schema shape alone cannot prove identity, authority, arithmetic, or ownership.]
3. **Native execution:** run the browser-specific fixture implementation against the pinned build; independently observe native entry, actual route, browser events, resource ownership, and fixture application effects. [proposed: prevent a structurally valid transcript from substituting for the direct-access or route claim.]
4. **Evidence re-evaluation:** validate the retained bundle without rerunning the browser, then recompute the same case decisions from its pinned journal prefix; classify a new browser execution separately as live reproduction. [proposed: preserve the evidence discipline without claiming exact replay of a browser.]

A schema sample or fault-injected fake backend can prove validation and reporting behavior, but cannot establish a native browser capability. [inferred: 1-handoff-brief.txt, capability/opportunity/result separation; 3-hellscape-blueprint.md, exact replay versus live reproduction.]

### 2.2 Scope declared before execution

The admission record must pin the selected schema, browser/binding build, complete configured subject identity, capability catalog, mapping inventory, requested functional claims, local fixture digests, budgets, privacy policy, and requested exemptions before cases execute. [proposed: prevent retrospective narrowing to erase failures.]

| Requested claim | Non-exemptible proof |
|---|---|
| BrowserOxide full-strength binding | Direct native DOM **and** V8 execution, owner-thread enforcement, lifetime invalidation, and applicable evidence/authority tests; unsupported optional facilities remain disclosed. [proposed: operationalize BO-NATIVE, BO-THREAD, BO-DOM, and BO-CAPS without presuming every proposed facility exists.] |
| BrowserOxide acquisition-only binding | Actual declared live-client/acquisition operations, their continuity and pool semantics, acquisition authorization, and applicable evidence tests; no browser-operation qualification follows. [proposed: support the handoff's minimal HTTP-capable slice without miscrediting unexercised native access.] |
| Camoufox extension-native binding | Executed browser-resident page operations through the pinned extension with independent evidence of Playwright/Juggler bypass; token, profile, authority, and evidence tests remain mandatory. [proposed: operationalize CF-ROUTE without treating an extension descriptor as implementation evidence.] |
| Camoufox compatibility binding | Faithful identification and execution of the declared Playwright/Juggler route, with truthful unsupported results and the same applicable ownership/evidence obligations; extension bypass is explicitly unclaimed. [proposed: preserve useful maintenance coverage without equating the routes.] |

Functional claims must name the primitives and capability scope actually requested; there is no unqualified “browser passed” result. [inferred: 5-browser-qualification.md, qualification names exact scope.]

### 2.3 Harness separation and proposed invocation

Use two independently implemented native fixture drivers: a BrowserOxide-native driver and a Python/Camoufox-specific driver; a common bundle validator may inspect their evidence but must not dispatch through a universal browser action interface. [proposed: share evidence validation, not browser implementation.]

The proposed offline verification target is:

- `step0-conformance binding --browser BrowserOxide --schema contracts/03-internal-browser-binding.yaml --bundle conformance-output/browseroxide --report conformance-output/browseroxide-result.json`
- `step0-conformance binding --browser Camoufox --schema contracts/03-internal-browser-binding.yaml --bundle conformance-output/camoufox --report conformance-output/camoufox-result.json`

These are proposed commands for validating produced bundles, not assertions that this CLI exists or that an offline validator can execute missing native cases. [proposed: give implementation work an exact verification target while preserving epistemic status.]

The actual build and native-fixture launch commands must be captured in each implementation's build receipt; current BrowserOxide API inventory and extension implementation details are absent, so their commands cannot be supplied as known working commands here. [uncertain: inspect the pinned BrowserOxide repository and build the Camoufox extension specimen to establish reproducible native launch commands.]

No running Hellscape, crawler, job-hunter, or sibling executor is required for the binding's silo test; use local synthetic pages, controlled HTTP endpoints, native instrumentation, and a restricted test oracle. [proposed: implement the handoff's conformance-before-peer-contact gate.]

## 3. Evidence and fixture discipline

### 3.1 Required bundle

Each instance produces the following proposed bundle, with every cited artifact registered in the journal before citation; file names are packaging proposals, not new binding fields. [proposed: make review and re-evaluation possible without expanding either native schema.]

| File or directory | Required content |
|---|---|
| `admission.json` | Requested scope, schema/build/configuration/catalog pins, fixture manifest, configured limits, authorization scope, route where applicable, and predeclared exemptions. [proposed: immutable test admission.] |
| `build-receipt.json` | Source/build identities, toolchain and dependency pins, actual build/launch commands, native mapping evidence, and route-inspection method. Missing revision evidence stays explicit rather than inferred from a version label. [proposed: reproducible subject identity.] |
| `descriptor.json` | Exactly the selected browser's binding descriptor, including its complete primitive inventory and capability descriptor. [proposed: validate the actual subject being tested.] |
| `journal.jsonl` | Server-assigned provenance, authorized intents, native observations, fixture effects, clock registrations, control results, faults, and artifact registrations. [proposed: journal-backed assertions.] |
| `records/` | BrowserOxide records/exports **or** Camoufox transcripts/reductions, validated against their own schema document. [proposed: preserve separate native encodings.] |
| `oracle-observations.json` | Independent fixture state and event observations, cited through the journal; never a replacement for journaled facts. [proposed: separate native acknowledgements from effects.] |
| `case-results.json` | Per-case assertions, disposition, evidence refs, findings, capability/opportunity/result assessments where applicable, and exemption details. [proposed: machine-readable review surface.] |
| `artifacts/` | Immutable bytes for native returns, sanitized route traces, DOM/capture output, fixture documents, and other referenced evidence; sensitive artifacts remain restricted. [proposed: preserve raw evidence and access boundaries.] |
| `revalidation-receipt.json` | Input digests and journal cutoff, validator/classifier versions, recomputed decision digest, and explicit match/mismatch. This is evidence re-evaluation, not a claim of browser replay. [proposed: deterministic offline checking.] |

An artifact digest, descriptor, native object token, or test fixture URL is not an authorization grant. [extracted: contracts/03-internal-browser-binding.yaml, BO-AUTHORITY, BO-EVIDENCE, and CF-EVIDENCE.]

### 3.2 Local fixtures

| Fixture | Required behavior and oracle |
|---|---|
| `form-effects` | Visibly labeled inputs, a rejecting validation path, file input/drop zone, and guarded submit; server state records accepted values, upload digest, operation identity, and commitment independently of browser acknowledgements. [proposed: test input semantics without a real employer or identity.] |
| `dom-lifetimes` | Replace a node while retaining its visible label/selector, navigate a frame, reset or recreate native resources, and expose explicit generation-change barriers. [proposed: detect stale-reference use rather than relying on timing races.] |
| `boundaries` | Top document, nested readable frames, an intentionally inaccessible frame, open roots, a closed root, and oversized semantic content; the fixture oracle knows what was created, while the binding must report only what it can observe. [proposed: exercise scope and honest missingness.] |
| `session-continuity` | Controlled redirect and cookie-rotation sequences, authenticated and unauthenticated HTTP-200 responses, and stable server-side request/connection identities. [proposed: distinguish live-client continuity, pool reuse, and authentication.] |
| `observation-loss` | Deterministic barriers permitting reply loss, local wait expiry, process loss, and a late server effect after the observer closes. [proposed: reproduce uncertainty without pretending that a timeout cancels native work.] |
| `profile-controls` | Synthetic profile state, fingerprint probes, and acknowledged same-origin storage controls; no real account, MFA credential, or candidate PII. [proposed: test persistence and scoped isolation safely.] |

Test-control endpoints and expected-answer data belong to the harness oracle, not to the binding's authorization scope; ordinary fixture controls remain the only application interaction surface for action tests. [proposed: prevent the oracle from becoming hidden execution assistance.]

Use barriers and explicit state predicates rather than sleeps to establish ordering; configured bounds are recorded limits, while measured elapsed values retain their own clocks and origins. [proposed: deterministic scheduling with honest timing.]

## 4. Shared assertion corpus — executed independently per browser

Rows describe test designs, not successful executions; “reject” means the named validator must detect the defect, while native-input rejection must occur before the forbidden native entry or effect. [proposed: distinguish negative-case success from subject failure.]

| ID / layer | Stimulus | Required oracle |
|---|---|---|
| K-01 / structural | Load the two-document YAML stream; validate one valid descriptor, one call record/transcript, and one export/reduction for each document. | Select by exact `$id`; every `$ref` resolves locally. Cross-feed BO records to CF and CF records to BO: reject. A boolean union dispatcher must not replace the two schemas. [proposed: tests independent schema entry points.] |
| K-02 / structural | For every primitive, generate a valid argument/returned-value sample and each permitted non-return branch; then mutate the operation, remove a required field, substitute another operation's result, or add an unknown field. | Accept valid samples; reject all mismatched or undeclared shapes. Schema-only samples receive no native capability credit. [proposed: exhaustive coverage of both operation discriminators.] |
| K-03 / structural and semantic | Supply duplicate keys, a non-finite number, unknown schema version, malformed digest, invalid asserted URI/date-time, out-of-range revision, or a bare normalized null. | Reject at the appropriate layer. Reject a required field omitted to disguise unavailable data. Raw native bytes may retain their original shape in restricted artifacts. [proposed: tests document validation and lossless normalization.] |
| K-04 / structural and semantic | Exercise all six `Missing.reason` values, exact zero, empty observed text, empty matches, and unavailable values. Also use an illegal seventh reason or a contextually false `not_applicable`. | Preserve valid distinctions; reject malformed or semantically dishonest missingness. Empty text/matches are not unavailable access; zero is not missing. [proposed: tests Missing, Inapplicable, and kernel semantics.] |
| K-05 / semantic | Use same-clock endpoints at offsets 10 and 10, then 10 and 17; add bounded and unavailable intervals. Mutate clock, boot, origin, endpoint order, bounds order, scope ID, or estimate. | Accept exact 0 and 7 ms for these synthetic endpoints; accept honest bounded/unavailable estimates. Reject cross-clock/boot/origin arithmetic, negative durations, inverted bounds, fabricated exactness, and call-ID mismatch. [proposed: deterministic timing vectors for BO-TIME and CF-TIME.] |
| K-06 / semantic | Retain a subject-reported zero alongside a nonzero independent engine interval; omit native timing in a separate case. | Preserve both measurements with separate origin/clock/scope. Do not correct the raw zero, average them, divide task time among primitives, or insert default zero for missing timing. [proposed: regression for the documented `_elapsed()` failure.] |
| K-07 / semantic | Add a client-supplied provenance field, forge an origin commitment, cite a future event, cite beyond a prefix, alter a referenced artifact, or use an unresolved evidence pointer. | Reject forged normalized provenance/authority and invalid references; do not publish a passing assertion from the damaged evidence. Only journaled support is citable. [proposed: tests BO-EVIDENCE and CF-EVIDENCE.] |
| K-08 / semantic and native | Native call returns unit/None or an acknowledgement, while the fixture rejects the value or leaves its application state unchanged. | Preserve the native return without calling it semantic success; `effect_refs: []` means no cited effect, not proven absence of effects. The binding never writes the application axis. [proposed: tests acknowledgement versus origin fact.] |
| K-09 / semantic | Start a new build/configuration/route identity with copied capability entries; provide only documentation for a claimed in-run success. | New identity begins unknown; no inherited presence or absence. Documentation may support a scoped declaration but cannot substitute for executed capability proof. [proposed: tests BO-CAPS and CF-CAPS.] |
| K-10 / structural and semantic | Duplicate a mapping while retaining the required array length, omit a required capability ID, duplicate a capability, or declare a mapped native symbol without supporting contract/evidence. | Reject inventory and evidence defects. BO has exactly one mapping for each of 14 primitives; CF has exactly one for each of 13. Every required catalog ID appears exactly once. [proposed: tests descriptors beyond array-length validation.] |
| K-11 / native and semantic | Request an unmapped operation, then exercise a mapped operation against a blocked or unexposed fixture feature. | Return honest typed unsupported/uncertain/error information as applicable. Mapping absence does not establish native capability absence; unexposed features earn no success credit. [proposed: tests capability/opportunity/result orthogonality.] |
| K-12 / native | Present an authorized artifact with an unauthorized target, account, file, script effect, or destination; attempt to obtain control credentials through evaluation. | Reject before the forbidden effect; record authorization failure without leaking credentials. Authority cannot be expanded by script evaluation or artifact lookup. [proposed: tests BO-AUTHORITY and CF-EVIDENCE.] |
| K-13 / native and evidence | Lose observation after possible delivery of a side-effecting primitive; let the fixture later record its effect. | Preserve delivery/entry uncertainty, no automatic side-effect retry, and a separate late effect. Local closure or process termination is never represented as cancellation or rollback. [proposed: regression for the cancellation corpus.] |
| K-14 / evidence | Insert synthetic secret canaries in allowed session storage and native response artifacts; scan ordinary logs, records, and diagnostics. | No canary in ordinary output; restricted artifacts retain access controls and resolvable hashes. Redaction/truncation is disclosed rather than silently relabeled complete. [proposed: tests privacy boundaries without using real secrets.] |
| K-15 / evidence | Re-evaluate an unchanged retained prefix, then change an artifact or classifier pin; run the browser anew with the same fixture. | Unchanged inputs reproduce case semantics; tampering or incompatible pins are detected. The new browser run receives a new execution identity and is not labeled exact fixture replay. [proposed: tests deterministic evidence judgment.] |

For K-11 and other capability assessments, use the handoff's separate axes: availability `present|absent|unknown|not_applicable`, opportunity `exposed|unexposed|blocked`, and result `satisfied|violated|native_absence|indeterminate|not_exercised`; a test-harness disposition is not one of these axes. [extracted: 1-handoff-brief.txt, evidence-kernel orthogonality.]

## 5. BrowserOxide instance

### 5.1 Native proof and ownership cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| BO-01 — direct DOM/V8 | Create a Page on its owner thread; read a live native DOM node, execute V8 in that document, mutate the node, and inspect the resulting state through native access and the fixture observer. | Retain exact mapped native symbols, build evidence, and executed path evidence. No CDP, Playwright, Juggler, alternate browser, or serialized-HTML bridge lies beneath the DOM/V8 operations. A fake record alone fails this proof. [proposed: mandatory full-strength test for BO-NATIVE.] |
| BO-02 — thread confinement | Allocate, enter, reset, and destroy on the owner thread. Attempt wrong-thread entry and transfer of Page, isolate-local values, DOM references, and solver instances. | Compile-time confinement cases fail where the native type system forbids transfer; runtime/FFI misuse is rejected before engine entry with `WRONG_THREAD`. Owned bytes and diagnostic IDs may cross boundaries, but deserializing an ID creates no native object or authority. [proposed: tests BO-THREAD across safe and unsafe boundaries.] |
| BO-03 — synchronous boundary | Execute a bounded native primitive while instrumenting its entry and return; inspect the caller-facing API and queued work. | A value or typed failure returns, not a task handle requiring Observe/polling. Queues may schedule owner-thread work outside native execution; no live native borrow escapes while awaiting another runtime. [proposed: tests the native/external boundary.] |
| BO-04 — stale identity | Capture root/node references; replace a node with an identical-looking node, navigate its document, reset the Page, then destroy it in separate variants. | Each affected old reference is rejected before mutation with `STALE_REFERENCE`; replacement identity is not silently substituted. Unaffected scoped identities remain valid only where the native lifetime contract permits. [proposed: tests BO-DOM.] |
| BO-05 — graph integrity | Export nested roots and frames; introduce duplicate node identities, dangling undeclared parents, wrong frame/document generations, and a cycle into retained exports. | Valid scoped graphs resolve; malformed or incompatible graphs fail semantic validation. Parent exclusions are justified by the declared rooted query, not silently ignored. [proposed: tests BODomExport graph semantics.] |

### 5.2 HTTP, rendering, and resource cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| BO-06 — live-client pools | Exercise `create_retained`, `share_process`, and `clone_independent` under a pinned native mapping; use controlled connection identities and native pool instrumentation. | Actual sharing preserves the shared pool; an ordinary clone has a distinct pool. Relabeling `pool_id` without matching native behavior fails. Request/response evidence preserves profile, client, session domain, and epoch. [proposed: tests BO-HTTP and BOClientCreate.] |
| BO-07 — ordered cookies | Run a stateful and rotating cookie sequence through redirects; attempt concurrent jar-affecting requests and an out-of-order publication. | At most one relevant request proceeds until redirect/cookie processing completes; returned cookie generations and request sequences match observed continuity. Stale owners cannot publish current-session evidence. [proposed: tests BO-HTTP against rotating-state corruption.] |
| BO-08 — independent sessions | Run valid same-origin write/read controls for independent session domains, then repeat with a failed control and with unknown storage namespacing. | Process-global or unknown storage uses separate engine processes for independent domains. `verified_namespaced` requires valid executed evidence; failed controls yield indeterminate assessment, not isolation or leakage. Cookie snapshots do not authorize live session distribution. [proposed: tests BO-HTTP and the descriptor's storage model.] |
| BO-09 — offline rendering | Call `bo.from_html` with complete retained inputs while a network sentinel records attempts; repeat with required resources absent. | Complete offline execution makes no network acquisition. Missing inputs produce `INPUTS_INCOMPLETE` or another evidenced pre-entry rejection, not a hidden fetch. Any separately authorized cold navigation is a new primitive with its own evidence. [proposed: tests BO-OFFLINE.] |
| BO-10 — transport non-monotonicity | Supply a complete structured HTTP response and a deliberately incomplete browser document for the same fixture task; inspect acquisition and render results. | Preserve both observations; do not assume Page is a superset of the live HTTP client. Structured content is normalized before an HTML-only classifier; challenge clearance, HTTP 200, and `Pass` do not establish authentication or job relevance. [proposed: tests source-preserving render semantics.] |
| BO-11 — rendering vocabulary | Exercise retained samples for `Pass`, `ThinShell`, `RenderIncomplete`, `EdgeBlock`, `SensorFail`, and `ChallengeIncomplete`, each with evidence. | Preserve verdict and basis per attempt; no fallback overwrites earlier history. Synthetic verdict samples prove encoding, not native challenge capability or employer compatibility. [proposed: tests BORenderVerdict without unsourced native claims.] |
| BO-12 — safe reuse | Reset a compatible Page, then test reset failure, unexpected cookie-jar change, and wrong profile/target/session reuse. | Successful reset invalidates old DOM identities and returns a newer page generation with actual cookie-continuity support. Failure quarantines the Page for owner-thread destruction; it never returns to the pool. [proposed: tests BO-REUSE and BOResetReturn.] |

### 5.3 Interaction, limits, and failure cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| BO-13 — explicit input mechanism | Set `value`, `checked`, and `selected` through `bo.dom_write`; dispatch separate events with varied `bubbles`, `cancelable`, and `composed` settings. | Setting properties does not imply an undisclosed event recipe. Record actual observed event behavior; synthetic dispatch is not trusted user input. Readback and native returns remain separate from validation and commitment. [proposed: tests BO-INPUT.] |
| BO-14 — acquisition cannot apply | Use an acquisition-only grant for an apparently read-only HTTP POST, redirect, V8 script, and DOM write that would mutate fixture application state. | Policy rejects mutating acquisition paths before effects, including hidden write semantics. `bo.http_exchange` remains acquisition-only; an executor grant does not silently repurpose it as a direct application API. [proposed: tests BO-AUTHORITY.] |
| BO-15 — boundary honesty | Request frames, open roots, and a closed root under a depth/byte-limited read; deny one boundary and force truncation. | Report boundary scope, access, limitations, and partial/unknown completeness honestly. An inaccessible root is not an empty complete tree; direct DOM access alone does not prove closed-root support. [proposed: tests BO-DOM and BODomRead.] |
| BO-16 — files and raster | Exercise authorized `bo.assign_files` and `bo.capture` if mapped; otherwise exercise explicit unsupported handling. For capture, test missing geometry and a stale document. | File assignment alone is not server upload acceptance. Raster evidence carries native geometry or reasoned missingness; no unavailable zero-offset/unit-scale substitution. Unsupported handling passes honesty assertions but earns no upload/capture capability credit. [proposed: tests proposed optional native facilities.] |
| BO-17 — native versus local timeout | Separately cause an evidenced native timeout, supervisor-local bound expiry during uninterruptible native work, and owner loss. Include a zero configured limit. | Use `NATIVE_TIMEOUT` only with native evidence; `LOCAL_DEADLINE` or `OWNER_LOST` retains actual entry/effect uncertainty. No fabricated native stop, negative elapsed value, or zero-as-missing rule. Containment remains outside the primitive. [proposed: tests BO-TIME and BOFailure.] |
| BO-18 — no hidden recovery | Force an error after a potentially mutating native entry; instrument native call count, model calls, browser launches, and network operations. | No binding-level hidden heal, planner, alternate browser, selector retry, or employer API submission occurs. A later authorized controller recovery is separately journaled and counted. [proposed: tests BO-INPUT's primitive-only boundary.] |

### 5.4 BrowserOxide operation coverage

Each operation requires structural branch coverage under K-02 and native behavior evidence for every functional claim that includes it; an unmapped operation must still pass its unsupported-reporting case. [proposed: exhaustive inventory without manufacturing native implementations.]

| Primitive | Behavioral cases |
|---|---|
| `bo.client_create` | BO-06, BO-08. [proposed: coverage mapping.] |
| `bo.http_exchange` | BO-06–08, BO-10, BO-14. [proposed: coverage mapping.] |
| `bo.page_create` | BO-01–03. [proposed: coverage mapping.] |
| `bo.navigate` | BO-04, BO-10, BO-17. [proposed: coverage mapping.] |
| `bo.from_html` | BO-09. [proposed: coverage mapping.] |
| `bo.dom_read` | BO-01, BO-04–05, BO-15. [proposed: coverage mapping.] |
| `bo.dom_write` | BO-01, BO-04, BO-13–14. [proposed: coverage mapping.] |
| `bo.event_dispatch` | BO-13, BO-18. [proposed: coverage mapping.] |
| `bo.v8_evaluate` | BO-01–02, BO-14. [proposed: coverage mapping.] |
| `bo.assign_files` | BO-16, K-12. [proposed: coverage mapping.] |
| `bo.capture` | BO-16. [proposed: coverage mapping.] |
| `bo.render_verdict` | BO-10–11. [proposed: coverage mapping.] |
| `bo.reset_for_reuse` | BO-02, BO-04, BO-12. [proposed: coverage mapping.] |
| `bo.page_destroy` | BO-02, BO-04, BO-12, K-13. [proposed: coverage mapping.] |

## 6. Camoufox instance

Run the applicable cases once for each declared route being qualified; retain different descriptors and receipts rather than merging extension and compatibility results. [proposed: route-scoped qualification under CF-CAPS.]

### 6.1 Route, profile, and token cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| CF-01 — actual page route | Execute mapped page operations under the selected route with pinned source/call-path inspection and independent transport instrumentation. Where feasible, disable the legacy page-operation path after native profile launch for the extension test. | `extension_native` operations continue through the pinned Firefox extension, with no Playwright/Juggler page hop. Legacy execution explicitly identifies both bridge components. A missing extension or a mislabeled bridge cannot pass the bypass claim. [proposed: mandatory route proof for CF-ROUTE.] |
| CF-02 — mapping consistency | Attempt a page operation mapped as `controller_lifecycle`, an extension route with legacy mappings, a compatibility route with extension mappings, and a silent route change within a commissioned execution. | Reject inconsistencies. `controller_lifecycle` is allowed only for profile open/flush-exit. An authorized route change creates a new scoped configuration and invalidates previous tokens; it is not an internal fallback. [proposed: tests CFMapping and CF-ROUTE.] |
| CF-03 — synchronous primitive | Exercise a request/reply transport and a locally bounded wait while instrumenting the Python-facing call and reply-servicing loop. | Return a primitive value or typed error/uncertainty, not a durable workflow handle. Internal awaiting does not deadlock the reply loop or turn the boundary into the external asynchronous connector. [proposed: tests CF-SYNC.] |
| CF-04 — exclusive profile | Open a profile, attempt overlapping ownership, then change fingerprint/launch identity while retaining session storage. | Reject overlapping ownership with `PROFILE_BUSY` as applicable. Identity change is not silent reuse: require explicit reset and authentication-handoff policy. A profile artifact or directory locator is not permission to access it. [proposed: tests CF-PROFILE.] |
| CF-05 — safe exit and reopen | Flush/exit, observe actual process reaping, then reopen. In variants, withhold flush evidence, withhold exit evidence, or return only a close acknowledgement. | `CFProfileExited` requires both actual flush and process-exit evidence. Otherwise return honest uncertainty; forbid storage reuse until ownership is safely established. Grace-period expiry is not process-exit evidence. [proposed: tests CFProfileExited and CF-PROFILE.] |
| CF-06 — native fingerprint evidence | Reopen with the same immutable manifest and independently compare selected observed fingerprint surfaces; test mismatch. | Retain the observations and mismatches. Reusing `fingerprint_digest` alone does not prove surface equality, origin compatibility, or authentication continuity. [proposed: tests profile persistence without importing historical performance claims.] |
| CF-07 — document/target lifetimes | Resolve a target, replace the node, navigate its frame, close/reopen its tab, recycle its process, and change route in separate variants. | Reject affected tokens as `STALE_TARGET` or `STALE_DOCUMENT` before input. Identical text/selectors do not authorize implicit re-resolution. Process, tab, document, and element lifetimes remain distinct. [proposed: tests CF-STATE.] |
| CF-08 — state domains | Use acknowledged same-origin controls across tabs/profiles: A write and read, B read before overwrite, B acknowledged write, then A reread. Repeat with a failed write control and separately scoped storage types. | Report actual sharing/isolation per storage type and configured policy. A new tab is not an isolated context; a failed control yields indeterminate evidence. Browser-state changes do not erase or prove isolation of selector/learning caches. [proposed: tests CF-STATE and historical invalid-control regression.] |

### 6.2 Observation and interaction cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| CF-09 — browser-resident reduction | Feed a large local document containing semantic controls and disposable markup through EXTRACT and HEAL; inspect where reduction occurs and bytes crossing the page-operation boundary. | Reduction occurs in-browser before bulk transfer. Preserve useful semantic attributes/text/icon meaning under the selected profile. No model invocation occurs inside the binding. Full-page serialization followed by Python-only pruning fails this requirement. [proposed: tests CF-STRUCTURE.] |
| CF-10 — frames and roots | Traverse nested readable frames and open roots; include unreadable and closed boundaries. Exercise both `root_access` settings. | Keep boundary IDs, ancestry, document epochs, markers, and limitations. Ordinary cloning does not count as shadow traversal. Closed-root access requires actual route-specific evidence and authority, not the requested setting alone. [proposed: tests CFContextTree, CFReduction, and CFRootHop.] |
| CF-11 — bounded reduction | Force the byte budget, interrupt observation, and inject duplicate boundary IDs or a section pointing to a nonexistent boundary. | Return explicit partial/unknown output or `RESPONSE_LIMIT`; never silent truncation. Semantic validation rejects broken boundary references. Completeness describes the declared reduction scope, not lossless HTML. [proposed: tests CFReduction integrity.] |
| CF-12 — one lookup strategy | Resolve unique, absent, ambiguous, and more-than-`max_matches` targets with CSS, role, label, and text strategies supported by the mapping. | Return bounded matches and truthful completeness. Empty complete means no match for that lookup. Ambiguity never silently clicks the first target; unsupported strategies do not invoke another strategy or a heal model. [proposed: tests CFResolveTarget and CF-INPUT.] |
| CF-13 — requested input semantics | Exercise fill, click, select, and press using each supported mechanism; deliberately request an unsupported mechanism. Inspect actual browser events and server validation. | Preserve `native_browser_input` versus `dom_property_and_events`; reject unsupported requests rather than substitute. `event_trust` is evidenced by observation, not inferred from request intent. None/acknowledgement is not a passed form postcondition. [proposed: tests CFInput and CFInputReply.] |
| CF-14 — uploads | Assign an authorized synthetic file through native file input; separately use the declared synthetic DataTransfer recipe. Attempt bad MIME/size, unauthorized bytes, and a missing recipe. | Enforce the admitted file policy. Native input uses inapplicable recipe; synthetic drag/drop pins its recipe and stays labeled synthetic. Server acceptance and file digest are separately observed; file assignment alone earns neither. [proposed: tests CFUpload.] |
| CF-15 — execution world | Evaluate authorized scripts in each mapped world; request an unproven privileged world and a script whose effects exceed the task grant. | Preserve requested world semantics; no speculative elevation or authority expansion. Unsupported mappings stay explicit; unit/unserializable results are not coerced to success. [proposed: tests CFEvaluate and CF-EVIDENCE.] |
| CF-16 — scoped waits | Wait on an explicit read-only predicate while the fixture maintains persistent network activity; test false, true, native timeout, and local wait expiry. | Predicate observations remain scoped to their document. Network idle is not a universal prerequisite or application-completion predicate. `NATIVE_TIMEOUT` requires native evidence; `LOCAL_WAIT_EXPIRED` retains delivery/effect uncertainty. [proposed: tests CFAwaitCondition and CF-TIME.] |
| CF-17 — localized capture | Capture a declared crop, then alter frame offsets, viewport scale, or layout; withhold geometry in another variant. | Preserve requested versus actual geometry and document epoch. Do not silently expand to full-page capture. Missing geometry stays unavailable and cannot authorize coordinate use; perceptual similarity alone does not validate cached target coordinates. [proposed: tests CF-IMAGE.] |

### 6.3 Bounds, loss, and recovery cases

| ID | Procedure | Required observations and failure oracle |
|---|---|---|
| CF-18 — serialization and tab bound | Admit exactly the configured tab cap, then one additional request; contend on context-affecting operations in a single tab/profile lifetime. | Do not exceed the pinned cap or overlap conflicting operations. Any waiting/backpressure is bounded and evidenced; a tab cannot be fabricated in a successful reply. No historical cap is assumed when another value was explicitly configured. [proposed: tests descriptor configuration and CF-SYNC.] |
| CF-19 — loss after delivery | Drop the transport after sending input; separately exit the browser and expire a zero/nonzero local wait limit. Allow a late fixture effect after observation loss. | Use `TRANSPORT_LOST`, `BROWSER_EXITED`, or `LOCAL_WAIT_EXPIRED` with truthful `delivery`. Fence dependent actions until safe; no side-effecting retry, definite cancellation, or rollback claim follows. Late effects remain separately journaled. [proposed: tests CFFailure and CF-SYNC.] |
| CF-20 — no hidden recovery | Fail a selector/input and instrument target lookups, model calls, browser launches, and native action counts. | Binding adds no hidden planner, tier escalation, alternate selector, browser fallback, or mutating retry. Circus Tent may later commission explicit recovery above the binding, recorded separately. [proposed: tests CF-SYNC and the controller/binding boundary.] |
| CF-21 — tab close is not profile exit | Close a tab while its persistent profile remains live; retain a server operation already in flight. | `CFTabClosed` proves the scoped tab-close observation only. It does not prove profile flush, process exit, native cancellation, storage erasure, or rollback of the in-flight operation. [proposed: tests CFTabClosed and evidence separation.] |

### 6.4 Camoufox operation coverage

| Primitive | Behavioral cases |
|---|---|
| `fx.profile_open` | CF-04–06. [proposed: coverage mapping.] |
| `fx.tab_open` | CF-07–08, CF-18. [proposed: coverage mapping.] |
| `fx.navigate` | CF-07, CF-19. [proposed: coverage mapping.] |
| `fx.context_tree` | CF-10–11. [proposed: coverage mapping.] |
| `fx.reduce_document` | CF-09–11. [proposed: coverage mapping.] |
| `fx.resolve_target` | CF-07, CF-12. [proposed: coverage mapping.] |
| `fx.input` | CF-13, CF-19–20. [proposed: coverage mapping.] |
| `fx.upload` | CF-14, K-12. [proposed: coverage mapping.] |
| `fx.evaluate` | CF-15, K-12. [proposed: coverage mapping.] |
| `fx.await_condition` | CF-16, CF-19. [proposed: coverage mapping.] |
| `fx.capture_crop` | CF-17. [proposed: coverage mapping.] |
| `fx.tab_close` | CF-07, CF-21. [proposed: coverage mapping.] |
| `fx.profile_flush_exit` | CF-05–06. [proposed: coverage mapping.] |

CF-01–03 and shared structural/evidence cases apply across this inventory, not just to a representative navigation. [proposed: prevent an extension path for one operation from concealing legacy fallback for another.]

## 7. Exemptions and missing native support

An exemption record must name the case/assertion, browser, exact subject/build/configuration, route if applicable, reason, supporting evidence, effect on the requested claim, and reconnaissance/retest trigger; it must be admitted before execution or retained as a visible amendment that cannot erase the original result. [proposed: explicit, reviewable scope narrowing.]

| Situation | Permitted treatment | Forbidden treatment |
|---|---|---|
| BrowserOxide HTTP-only release | Declare browser execution outside the requested functional scope; retain every required mapping/capability entry and test honest unsupported reporting. [proposed: minimal-slice exemption.] | Calling this a full-strength binding pass or exempting BO-01 while retaining direct-DOM/V8 qualification. [extracted: contracts/03-internal-browser-binding.yaml, BO-CAPS.] |
| BrowserOxide file assignment, raster capture, closed-root access, or interruption not established | Mark native exercise blocked or outside the requested scope; publish unknown/appropriately evidenced absence separately and run reporting tests. [proposed: no invented native facilities.] | Treating `UNMAPPED_PRIMITIVE` as proof of native absence or a successful capability exercise. [extracted: contracts/03-internal-browser-binding.yaml, BO-CAPS.] |
| Camoufox compatibility route | Exclude extension-bypass qualification explicitly; still prove the actual legacy route and pass applicable CF ownership/evidence cases. [proposed: route-specific exemption.] | Certifying extension-native behavior from compatibility results. [extracted: contracts/03-internal-browser-binding.yaml, CF-ROUTE.] |
| Camoufox extension not built or required operation unmapped | Report the requested extension functional claim incomplete; retain compatibility/manual work as separate, useful scope. [proposed: avoid turning reconnaissance into a whole-portfolio gate.] | Substituting Playwright/Juggler silently and labeling the transcript extension-native. [extracted: contracts/03-internal-browser-binding.yaml, CF-ROUTE.] |
| Browser-specific optional feature genuinely inapplicable | Record the scoped reason and evidence; never require a matching operation in the other browser. [proposed: preserve native asymmetry.] | Inventing a shared ElementHandle or lowest-common-denominator operation to remove the asymmetry. [extracted: 1-handoff-brief.txt, internal-binding invariant.] |
| Missing dependency, invalid oracle, failed control, or broken harness | Mark affected cases blocked or harness-invalid, repair the fixture, and rerun under a new receipt. [proposed: valid controls precede attribution.] | Counting the case as passed, or attributing the harness/configuration problem to native capability failure. [extracted: 5-browser-qualification.md, evidence discipline.] |

Timing, null semantics, provenance, authority, stale-reference safety, truthful route reporting, and claim-versus-fact separation have no exemption that permits dishonest output; inability to execute a required case produces an incomplete claim, not a waiver. [inferred: 1-handoff-brief.txt, load-bearing evidence and binding invariants.]

## 8. Result calculation and release gate

Per assertion, record `pass`, `fail`, `blocked`, or `exempt`; these proposed harness dispositions are independent of capability availability and requirement assessment results. [proposed: a correct unsupported response can pass an honesty assertion without satisfying a functional requirement.]

Use the following aggregate rules, applied separately to each browser/configuration/route and requested claim. [proposed: deterministic release decision.]

1. **Pass, scoped:** all required structural, semantic, and native assertions pass; every exemption is valid and compatible with the claim; all evidence resolves. Publish the exact claim and unclaimed capabilities alongside the result. [proposed: no skipped-required-means-pass loophole.]
2. **Fail:** valid evidence demonstrates a required invariant or functional-claim violation; a deliberately invalid input correctly rejected is a passed negative test, not this aggregate failure. [proposed: distinguish subject defects from expected rejection.]
3. **Incomplete:** required native evidence, dependency, mapping, or case execution is missing; do not upgrade an offline schema pass into native conformance. [proposed: honest treatment of unresolved implementation.]
4. **Harness error:** oracle controls, evidence integrity, or the evaluator itself are invalid; preserve any unaffected scoped findings, but withhold the damaged claim's pass. [proposed: validity-first attribution.]

The gate receipt must include requested and admitted scope, attempted/passed/failed/blocked/exempt counts, mapped/unmapped primitives, capability gaps, journal cutoff, evidence-integrity result, and exact build/route identity; a single aggregate color is insufficient. [proposed: retain the distinctions needed for downstream commissioning.]

A component may contact a peer only within the contract scope for which its own applicable suite has passed; excluded native capabilities remain excluded rather than being discovered through integration failure. [inferred: 1-handoff-brief.txt, conformance-before-peer-contact discipline.]

Neither a local fixture pass nor an extension-bypass measurement proves employer-origin compatibility, production application commitment, unattended operation, fingerprint resistance, or native cancellation. [inferred: 1-handoff-brief.txt, practice/production separation; 5-browser-qualification.md, loopback and assistance discipline.]

## 9. Outstanding reconnaissance and decision boundaries

- **BrowserOxide inventory:** inspect the pinned source/API and compile minimal owner-thread DOM/V8, live-client, frame/root, file, capture, reset, and interruption specimens; until executed, exact native mappings and capabilities remain unresolved. [uncertain: the referenced current engine inventory is not supplied.]
- **Camoufox extension:** establish transport, permissions, signing/packaging, supported worlds, input/upload/capture semantics, and observable Playwright/Juggler bypass on the pinned Firefox/Camoufox build; do not invent an extension endpoint or privileged permission. [uncertain: the extension/controller implementation is not supplied.]
- **Native performance:** retain scoped measured intervals and transfer sizes, but set no new latency promise from the ModCDP analogy or historical compatibility benchmarks; comparable before/after measurements are needed. [uncertain: no executed extension-versus-bridge or current BrowserOxide measurements are supplied.]
- **Ringmaster packaging:** these tests require native ownership and evidence, not an in-process library, separate binary, or extension/controller split; packaging remains for the Ringmaster PRD to recommend using actual API and deployment evidence. [extracted: governing task, Products; contracts/03-internal-browser-binding.yaml, BrowserOxide boundary.]
- **Handoff amendments:** this suite introduces no handoff amendment; test procedures and runner packaging are proposals, while unknown native support remains unknown. [proposed: preserve the governing invariants without mistaking conformance design for new evidence.]
