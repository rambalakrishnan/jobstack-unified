# Evidence kernel — conformance suite

## 1. Target and scope

| Item | Value |
|---|---|
| Contract | `contracts/00-evidence-kernel.yaml`, wire version `evidence-kernel/0.1.0`. [extracted: contracts/00-evidence-kernel.yaml] |
| Suite identifier | `evidence-kernel-conformance/0.1.0`; case identifiers below are stable within this suite version. [proposed: reproducible implementation-independent test selection] |
| Status | Review draft specifying tests, not a receipt that tests have run. [proposed: distinguish a verification plan from verification evidence] |
| Owner | The contracts boundary maintains the corpus; Hellscape M1 supplies the first reference implementation. [extracted: 1-handoff-brief.txt, Parts V and VIII] |
| Acceptance surface | Structural validation **and** the contract’s `EK-*` semantic rules, including authorization, persistence, reference resolution, arithmetic, and derivation. [extracted: contracts/00-evidence-kernel.yaml] |
| Production purpose | Preserve trustworthy evidence of real job applications, including manually executed applications while automation is unfinished. [extracted: 1-handoff-brief.txt, Parts VII–IX] |

The automated suite runs against one implementation in isolation, with synthetic producers, controlled clocks, local artifacts, and fault injection—not a crawler, executor, orchestrator, or employer deployment. [proposed: implement the silo gate without creating another integration dependency]

Hellscape’s additional manual acceptance exercise uses an ordinary browser and its cooperative SPA, with no automation subject; passing synthetic tests does not substitute for that exercise. [extracted: 3-hellscape-blueprint.md, §§11–12]

The reference suite does not certify native cancellation, browser isolation, stealth, employer-form compatibility, or job-search quality. [inferred: 1-handoff-brief.txt, Parts III, VI, and VIII]

No executable runner, materialized golden corpus, or execution receipts are supplied with the source documents; implementation must supply these before claiming a pass. [uncertain: runnable conformance tooling and retained test outputs are absent; materialize and execute this suite against the identified implementation]

### 1.1 Why these checks are mandatory

| Invariant | Counterexample or derivation |
|---|---|
| Journal first; immutable diagnostic prefixes | Retroactively adding evidence makes a published diagnosis irreproducible. [extracted: 1-handoff-brief.txt, Part VI] |
| Exact, bounded, or unavailable timing | The diagnosed `_elapsed()` zero defect shows why missing time cannot become zero. [extracted: 1-handoff-brief.txt, Part VI] |
| Capability, opportunity, and result remain separate | An absent capability can be unexercised or establish a required native gap; those findings cannot share one status. [extracted: 1-handoff-brief.txt, Part VI] |
| Claims do not become application facts | Connection closure followed by later commitment is compatible with close-time uncertainty, but can contradict a definite cancellation claim. [extracted: 1-handoff-brief.txt, Part VI] |
| Practice does not establish production success | Tuning against a laboratory form does not qualify an executor for an employer’s form. [extracted: 1-handoff-brief.txt, Part III] |
| Lease ownership is not workflow progress | A claim must fence concurrent writers without changing the resource’s pending state. [extracted: 2-state-bank-crawler-blueprint.json, §11.15] |

## 2. Execution and verdict discipline

### 2.1 Verification layers

| Layer | What must be demonstrated |
|---|---|
| **S — Structure** | JSON-compatible decoding, schema validation, format assertions, required properties, discriminated unions, enums, and closed objects. [extracted: contracts/00-evidence-kernel.yaml, `x-validation`] |
| **I — Integrity and authority** | Hashes, immutable identities, reference bounds, authorized provenance, scope matching, clock registration, and other semantic predicates that JSON Schema cannot enforce alone. [inferred: contracts/00-evidence-kernel.yaml, `x-semantic-rules`] |
| **B — Stateful behavior** | Actual durable acknowledgement, crash recovery, deduplication, fencing, and owner-local atomicity through the implementation’s persistence path. [inferred: 2-state-bank-crawler-blueprint.json, §11; 3-hellscape-blueprint.md, §10] |
| **D — Derivation** | Diagnostic results and limitations agree with independently specified evidence and controls. [extracted: 3-hellscape-blueprint.md, §§4 and 12.3] |
| **R — Replay** | Offline recomputation compares the required outputs without invoking a browser, subject, or external mutation. [extracted: 3-hellscape-blueprint.md, §10.8] |

An implementation that passes **S** but accepts a cross-clock duration, forged writer, or unsupported success claim fails full conformance. [inferred: contracts/00-evidence-kernel.yaml, `x-validation`]

The case classes are **H** for a happy path, **B** for a boundary, and **F** for adversarial input or injected failure; an F case passes when the implementation rejects or characterizes the failure correctly. [proposed: keep test verdicts distinct from the outcomes being tested]

“Reject” means no unauthorized business effect, accepted evidence claim, or resource transition; a separately authorized rejection/incident event may still be appended. [proposed: make refusal observable without confusing an audit record with the refused effect]

Malformed untrusted input must not enter the accepted evidence stream as a valid event, whereas a validly recorded subject failure or unknown outcome must remain admissible evidence. [inferred: 1-handoff-brief.txt, Part VI; 3-hellscape-blueprint.md, §4]

### 2.2 Implementation adapters

The development-time test adapter must expose ways to validate records, admit a run, ingest an `EventSubmission` under an authenticated test identity, read a prefix, derive a diagnostic, replay a bundle, exercise lease operations, retrieve artifacts, and inject persistence faults. [proposed: these are test hooks for observing kernel behavior, not new product endpoints]

The adapter must use the real persistence and transition code for B cases; an in-memory substitute may support deterministic reducer tests but cannot establish durability. [proposed: prevent a mock implementation from certifying the untested storage path]

The test controller must independently record acknowledgements, injected fault positions, attempted external effects, and durable-state observations so a broken kernel cannot certify itself solely through its own journal. [proposed: extend Hellscape’s independent cross-check discipline to the conformance harness]

The following invocation shape is proposed tooling, not an assertion that these commands already exist. [proposed: provide an explicit implementation target without selecting a runtime language]

    ./tools/conformance/evidence-kernel \
      --implementation <implementation-adapter> \
      --profile reference \
      --phase automated \
      --output <evidence-directory>

    ./tools/conformance/evidence-kernel \
      --implementation <implementation-adapter> \
      --profile reference \
      --phase manual-m1 \
      --output <evidence-directory>

The automated phase forbids live employer access and subject/browser launch; the manual phase permits only the operator’s ordinary browser against the local cooperative fixture. [proposed: enforce the isolation boundary through the test controller rather than trusting reported flags]

A test watchdog must be finite and recorded in the test configuration, but its expiry is a harness interruption—not a native timeout, successful cancellation, or passed case. [inferred: 5-browser-qualification.md, Evidence discipline]

### 2.3 Scope of a pass

- A **reference-kernel automated pass** requires all automated cases below, including every listed subcase; no semantic rule may be waived because a JSON Schema validator cannot express it. [proposed: bind the reference claim to the complete specified corpus]
- A **Hellscape M1 acceptance claim** additionally requires the manual cases against the same identified build/configuration, plus Hellscape’s separate connector suite; no live executor is required. [inferred: 1-handoff-brief.txt, Parts VIII–IX; 3-hellscape-blueprint.md, §12.5]
- A producer, reader, or serializer may publish a narrower claim naming its exact case selection and exercised responsibilities, but must not label a wire-only or emission-only pass “full kernel conformance.” [proposed: let independently shippable products consume the contract without requiring each to implement the entire kernel]
- Circus Tent and Ringmaster use the same external evidence vectors without sharing browser primitives or an internal browser abstraction. [inferred: 1-handoff-brief.txt, Parts III and V]
- A missing test dependency, skipped required case, absent fixture, or runner error prevents the corresponding pass; none counts as successful behavior by the implementation. [inferred: 5-browser-qualification.md, Evidence discipline]
- Pairwise cross-language comparisons may be added when implementations exist, but the first implementation can pass against independently reviewed golden bytes without waiting for another runtime. [proposed: preserve the silo gate while retaining a common interoperability oracle]

## 3. Corpus construction

### 3.1 Fixture families

The following names and synthetic values are test-corpus proposals, not records of actual applications or measurements of existing browser products. [proposed: separate test inputs from empirical evidence]

| Fixture | Construction and use |
|---|---|
| `F-core` | A `kernel_conformance` manifest in `service` mode, with no application attempt or judged subject, plus complete task/configuration artifacts, build pins, event registry, producers, and clocks. [proposed: smallest valid admission and integrity fixture] |
| `F-discovery` | A `discovery` manifest with `attempt=Missing(not_applicable)` and service execution, carrying a synthetic discovered-job artifact and explicit coverage observations. [proposed: test discovery evidence without fabricating an application or requiring job-hunter] |
| `F-cooperative` | A practice, held-in laboratory attempt in manual mode, exercising the eight-state workflow, rejected history input, correction, upload, identity verification, review pause, and one commitment. [inferred: 3-hellscape-blueprint.md, §§9 and 12.2] |
| `F-subject` | A synthetic subject with version keys `v1` and `v2`, a catalog containing `native_cancel` and `native_dom_access`, and explicitly declared mode, interface, configuration, and stack identity. [proposed: small catalog for no-inheritance and orthogonality tests] |
| `F-production-model` | Isolated `kernel_conformance` vectors containing a production-shaped, held-out employer attempt and synthetic receipt/claim observations; these model production semantics but are never published or counted as real applications. [proposed: test the manual production path without contacting or impersonating an employer] |
| `F-lease` | One owner-local resource with test states `pending`, `done`, and `failed`, a pinned test policy, controlled authority clock, worker epochs, and an independently observable transition/dead-letter ledger. [proposed: exercise the generic lease rules using Stage1’s work-item vocabulary] |

All automated fabricated observations use `evidence_scope=synthetic`; the actual manual cooperative walkthrough uses `current_run` evidence while its attempt remains `practice` and `held_in`. [inferred: contracts/00-evidence-kernel.yaml, `JournalEnvelope.evidence_scope` and `EK-ATTEMPT-SCOPE`]

Factories must emit complete schema-valid objects rather than relying on omitted required fields, placeholder digests, implicit defaults, or illustrative fragments. [proposed: ensure every negative test starts from an independently valid baseline]

Every used event kind/version and writer role must be registered before admission; subsequently introduced producers and clocks use the authorized registration path, not test-only privileges hidden inside a payload. [inferred: contracts/00-evidence-kernel.yaml, `Manifest`, `ProducerDescriptor`, and `EK-PROVENANCE`]

The actual source files named by Hellscape’s historical audit are not available here, so reconstructed cancellation and isolation examples must be labeled synthetic, not captured historical responses. [uncertain: raw historical audit artifacts are absent; import their original bytes and scope separately if obtained]

### 3.2 Value and identity notation

`M(reason)` below abbreviates the complete wire object `{"value":null,"reason":"<reason>"}`; it is notation for the test specification, not a new serialized value. [proposed: shorten cases while preserving the contract’s exact missingness representation]

Symbolic event labels such as “history rejected” must resolve to actual `EvidenceRef` objects after append, including journal, sequence, event ID, digest, and JSON Pointer. [proposed: avoid hand-written fake hashes and sequence assumptions in fixture descriptions]

The deterministic clock fixture uses separate engine, browser-document, native-report, and manual-reference identities, each with an explicit boot; only the native-report clock uses `basis=opaque_report`. [proposed: exercise all four measurement origins without assuming clock synchronization]

Times used below, including `100`, `137.5`, and lease deadlines, are injected coordinates in milliseconds—not sleep requirements, performance targets, or production timeout defaults. [proposed: deterministic boundary testing without inheriting Stage1 deployment assumptions]

### 3.3 Golden construction and independent oracles

- Canonical expected bytes must be reviewed independently of the implementation under test; for example, structured input `{"b":2,"a":1}` canonicalizes to `{"a":1,"b":2}`, while raw artifact bytes retain their original representation. [proposed: concrete oracle for the kernel’s canonicalization profile]
- Calculate fixture digests from actual bytes using an independent implementation of the pinned `kernel-jcs-sha256/1` profile; never accept “matches itself” as the only hash test. [proposed: prevent the same canonicalization defect from generating both expected and actual values]
- Keep string contents and array order significant, and test canonically equivalent object-member ordering separately from byte-distinct raw artifacts. [extracted: contracts/00-evidence-kernel.yaml, `x-canonicalization`]
- Pin a small deterministic test reducer and its expected semantic-output and final-state JSON values; exclude no field merely because it causes a mismatch. [proposed: make replay’s semantic comparison independent of the captured derived outputs]
- Generate expected diagnostic assertions from the scripted procedure and evidence controls, not by blessing the analyzer’s current output as a golden. [inferred: 3-hellscape-blueprint.md, §12.3]
- Record any generated-case seed and failure schedule; rerunning the same test inputs must produce the same substantive verdict, while real elapsed test-run time remains separately measured. [proposed: separate deterministic contract assertions from variable test execution duration]

## 4. Structural and missingness cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-S01` | H / S | Validate one complete instance of each root type: manifest, journal event, diagnostic, replay receipt, lease record, and capability descriptor; separately validate an `EventSubmission` against its local definition. | All instances pass their intended definitions; `EventSubmission` does not pass as a durable root record. [proposed: cover every exported record and the distinct ingress shape] |
| `EK00-S02` | F / S | For each root type, remove each required property in turn, add an unknown top-level property, change `record_type`, and change `schema_version` to an unsupported value. | Each mutation is rejected without filling a default or guessing a compatible version. [proposed: verify closed, versioned records rather than only happy examples] |
| `EK00-S03` | B/F / S | Exercise duplicate mapping keys, non-finite numbers, invalid date-time strings, wrong scalar types, and revision values at and beyond `9007199254740991`. | Duplicate keys/non-finite values fail decoding; invalid formats/types fail validation; the declared revision maximum is accepted and its successor rejected. [proposed: enforce the contract’s parser and numeric boundaries] |
| `EK00-S04` | F / S | Supply old opportunity/result values `not_applicable` or `blocked` where the new enums exclude them, and supply a legacy flat `elapsed_ms` measurement. | Reject these as current-version wire records; a deliberate versioned importer may preserve and normalize the raw legacy artifact, but must not silently reinterpret it. [proposed: test the source reconciliations encoded in the kernel] |
| `EK00-N01` | H / S,I | Exercise all six null reasons in nullable definitions, with contextual evidence for each use. | Preserve the distinct reasons `not_enabled`, `not_applicable`, `not_observed`, `observation_lost`, `unsupported_by_subject`, and `manual_override`; acceptance of a reason’s spelling alone does not establish its contextual truth. [proposed: cover the full missingness vocabulary and its meaning] |
| `EK00-N02` | F / S | Supply bare null; a wrapper without `reason`; an unrecognized reason; an extra wrapper property; and bare null nested inside an evidence map or array. | Reject every malformed normalized value; the same literal native null may remain unchanged inside restricted raw artifact bytes. [proposed: verify recursive null discipline without rewriting source evidence] |
| `EK00-N03` | B / S,D | Compare exact numeric zero, an observed boolean false, an established empty collection, and an unavailable value with reason. | Preserve four different meanings; no conversion of missing to zero/false/empty and no conversion of a genuine zero to missing. [proposed: guard the defaults that would erase uncertainty] |
| `EK00-N04` | H/F / I,D | Append an authenticated operator decision withholding a previously observed value; repeat without that decision or with a subject attempting the override. | The supported override retains the old observation and cites the decision; unsupported `manual_override` does not authorize suppression or alteration of the evidence. [proposed: make manual override auditable rather than a data-cleaning escape hatch] |
| `EK00-N05` | F / S,D | Set a manual execution’s subject or connector version to a fabricated value, or use `manual_fixture_validation` as a null reason. | Reject the fabricated identity or seventh reason; use `M(not_applicable)` for the manual identity fields and the phrase only as an assessment rationale. [proposed: test the explicit manual-session reconciliation] |

## 5. Journal, durability, and ownership cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-J01` | H / S,I,B | Admit `F-core`, append authorized observations, and read a prefix ending at an `analysis_requested` event. | Sequence 1 is `manifest_admitted`; its artifact digest identifies the complete manifest; subsequent run/journal/manifest identities agree; the hash chain and prefix head verify. [proposed: establish a citable admission-to-analysis path] |
| `EK00-J02` | F / I | Independently mutate an event’s payload, predecessor hash, sequence, event ID, manifest digest, or a reference pointer; also try inserting a second admission event. | Reject the inconsistent record or prefix; no ordinary successful diagnostic or matched replay may rely on it. [proposed: isolate each journal/reference integrity guard] |
| `EK00-J03` | B/F / I,B | Deliver the same producer sequence and content twice, then deliver conflicting content under that key. | The identical delivery has one accepted observation/effect; the conflict is retained as an integrity incident without replacing the original or applying a second effect. [proposed: test deduplication and conflict preservation independently] |
| `EK00-J04` | B / B,D | Receive producer sequences 1 and 3, observe a declared final sequence of 3, derive a diagnostic, then receive sequence 2 late. | The first diagnostic exposes the gap; sequence 2 is appended at the current journal head, not inserted retroactively; a new analysis may close the gap while the original diagnostic bytes remain unchanged. [proposed: test producer order independently of journal order] |
| `EK00-J05` | B / I,D | Compare an evidenced producer closure with final sequence 0 against an empty observation set with no closure receipt. | The former may be complete with no emitted events; the latter cannot claim completeness from silence or a closed connection. [proposed: distinguish exact zero events from an unknown producer tail] |
| `EK00-J06` | F / B | Kill the process before artifact installation, after artifact installation but before transaction commit, during the owner-local operation transaction, after durable commit but before acknowledgement, and after acknowledgement. | Before commit, no partial operation/state/journal effect is visible; an installed unreferenced artifact may remain; after commit, the complete operation and replayable response survive; a retried operation key does not duplicate the effect. [proposed: exercise the durable acknowledgement boundary at every relevant cut] |
| `EK00-J07` | F / B,D | Delete or corrupt only a materialized application projection, then separately insert an unjournaled success into that projection. | Rebuild from the valid manifest and journal; the invented success is not cited, and a projection inconsistency is surfaced rather than silently treated as new evidence. [proposed: demonstrate that current rows are not an independent truth source] |
| `EK00-J08` | F / B,D | Interrupt an admitted observation session and restart with a new engine boot identity. | Acknowledged facts survive; interrupted observation is visible; no stopped-subject claim or automatic repeat of a side-effecting external request is manufactured. [proposed: distinguish recovery of local state from knowledge of remote execution] |
| `EK00-J09` | F / B | Block a second owner’s transaction/publication while completing a local owner’s journaled operation; inject a partial publication. | The local commit does not require the other owner’s lock or acknowledgement; a reader retains the previous complete published snapshot rather than observing partial imported data. [proposed: kernel-level sentinel for owner separation, with full archive/vector tests reserved for the owner-domain suite] |
| `EK00-J10` | F / B,D | Make durable storage unavailable before admission and during an existing run’s append. | No false durable acknowledgement or new admission; surviving evidence is recovered when possible, and any unpersisted tail remains missing rather than complete. [proposed: test the explicit limit of the durability promise] |

The crash oracle must compare the controller’s acknowledgement log, the recovered operation/state records, and the reconstructed journal; absence of an exception alone is not a pass. [proposed: make crash assertions independent of the code path being tested]

Permanent destruction of the evidence medium is not a promised recovery case, but detection of missing or corrupt retained evidence must still prevent a false completeness or replay claim. [inferred: 2-state-bank-crawler-blueprint.json, A9; 3-hellscape-blueprint.md, §10.7]

## 6. Provenance and authentication cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-P01` | H / I,B | Ingest valid submissions from registered fixture-client, connector, subject, manual-observer, and server producers. | The ingestion authority assigns the envelope fields from authenticated registration; client occurrence time remains separate from engine receipt time. [proposed: verify source attribution through the real ingestion path] |
| `EK00-P02` | F / S,I | Add `provenance: server`, `owner_domain`, `producer_id`, `journal_sequence`, `role`, or `assertion_kind` to an untrusted `EventSubmission`; separately place a claim of server provenance inside ordinary payload data. | Reserved ingress fields are rejected; a string inside payload data grants no authority and cannot alter the assigned envelope. [proposed: test both direct spoofing and nested authority laundering] |
| `EK00-P03` | F / I,B | Let an observer, connector, subject, or importer attempt application commitment or identity-verification effects, including through a misconfigured registry entry permitting the wrong role. | Refuse the application-authority escalation even if the packet is well formed or the caller is otherwise authenticated; an actual application-origin producer remains the positive control. [proposed: make provenance enforcement stronger than a label or permissive allowlist] |
| `EK00-P04` | F / I | Use an unregistered producer, an expired/revoked test grant, an unauthorized event version, or a producer bound to another run/domain. | Reject before authorized append/effect; recomputing a valid content hash does not repair the missing authority. [proposed: ensure integrity hashes are never treated as authentication] |
| `EK00-P05` | B / I,D | Cross the four callback conditions: authenticated/correlated, authenticated/miscorrelated, unauthenticated/correlated, and unauthenticated/miscorrelated. | Retain authentication and correlation as separate observations; only supported correlation attaches a claim to the attempt, and no callback condition alone establishes application commitment. [proposed: kernel tests use synthetic authentication outcomes; native signing mechanics belong to the connector suite] |
| `EK00-P06` | F / D | Present HTTP 200 without authenticated identity evidence, or native acknowledgement/`None` without a semantic postcondition. | Retain the response or return value as an observation; do not derive authentication or application success from it. [proposed: turn qualification’s false-positive traps into diagnostic assertions] |
| `EK00-P07` | B / I,D | Import documentary historical evidence with its source scope and raw bytes; attempt to cite an unimported external record or relabel the import as current server fact. | A local import event makes the bytes citable within the prefix while preserving `historical_unscored`; an external reference alone or provenance relabeling does not establish current-version behavior. [proposed: preserve historical learning without retroactive benchmark credit] |

## 7. Timing cases

The primary arithmetic vector has `quantity=duration`, `unit=ms`, `method=endpoint_difference`, one registered engine clock/boot/origin, start offset `100`, end offset `137.5`, `estimate={kind: exact, value: 37.5}`, and `censoring=none`. [proposed: an exactly representable fractional vector makes arithmetic errors distinguishable from arbitrary tolerance choices]

A native zero vector instead uses `origin=subject_reported`, an opaque-report clock, `method=source_value`, unavailable native endpoints with reasons, and `estimate={kind: exact, value: 0}`. [proposed: reproduce the dangerous reported-zero shape without claiming the historical deployment was retested]

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-T01` | H/B / S,I | Validate the arithmetic vector, an otherwise identical vector with equal endpoint offsets and exact value 0, and a scalar count whose observed value is 0. | All pass; exact zero is not replaced or rejected as missing, and endpoint arithmetic agrees exactly with the recorded coordinates. [proposed: cover positive, fractional, and zero measurements] |
| `EK00-T02` | B / S,I,D | Produce a bounded duration with both numeric bounds, then one-sided bounds with the missing side reasoned; exercise censoring `none`, `left`, `right`, and `both` with supporting observations. | At least one numeric bound remains; bounds are nonnegative and ordered; the diagnostic retains censoring and does not invent a missing endpoint. [proposed: test uncertainty as a first-class measured result] |
| `EK00-T03` | F / S,I | Supply no numeric bound, inverted bounds, negative duration/bounds, mixed exact/bounded fields, or a censoring/method combination inconsistent with the estimate discriminator. | Structural contradictions fail S; cross-field ordering failures fail I even when S passes. [proposed: distinguish structural union checks from arithmetic checks] |
| `EK00-T04` | H/B / S,I,D | Supply unavailable timing with a justified reason and separately supply the native zero vector. | Both remain valid but different; unavailable timing stays unavailable, and reported zero stays zero with subject origin. [proposed: directly guard the `_elapsed()` failure mode] |
| `EK00-T05` | F / I | Change only one endpoint’s clock ID, boot ID, or origin; also reuse the same numerical offsets after a process restart or browser-document replacement. | Reject endpoint subtraction; equal numbers or matching UTC annotations do not establish a common clock epoch. [proposed: test all components of the timing identity] |
| `EK00-T06` | B / I,D | Move UTC annotations backward while monotonic offsets advance; delay telemetry delivery while retaining the original browser occurrence coordinate. | Elapsed values follow the source monotonic coordinates; receipt latency does not become browser action duration, and UTC movement causes no negative elapsed interval. [proposed: separate correlation timestamps from duration clocks] |
| `EK00-T07` | F / I | Use an unregistered clock, assign native monotonic coordinates to an opaque-report clock without evidence, or mismatch a clock’s registered origin. | Refuse the unsupported timing interpretation; preserve the raw report or an unavailable/bounded measurement instead of inventing a clock. [proposed: verify clock registration and opaque-source limits] |
| `EK00-T08` | B / D | Compare reported zero against an independent positive lower bound for the **same declared primitive interval**, then compare zero against a differently scoped request interval. | The first may support `measurement_discrepancy`; the second is not comparable and cannot establish a false native-duration claim. [proposed: require semantic interval equivalence, not merely a common unit] |
| `EK00-T09` | F / D | Provide aggregate request duration and a step count, or provide step durations whose sum is smaller than request latency. | Do not divide the total into invented step timings or allege discrepancy merely from queue/setup/teardown time; retain missing step timing explicitly. [proposed: enforce Hellscape’s prohibition on fabricated primitive duration] |
| `EK00-T10` | F / D | End observation at a harness deadline while the synthetic subject has no terminal evidence. | Record the local deadline and censored/unavailable execution interval; do not emit a native timeout, exact execution duration, or native-cancellation success. [proposed: distinguish bounded observation from bounded native execution] |
| `EK00-T11` | F / I,D | Encode an observed duration in an untyped timing field instead of `Measurement`, or omit clock/origin from a normalized measurement. | Reject the normalized representation for evidentiary use; raw vendor timing may remain in its artifact but must not bypass the common timing rules. [proposed: prevent adapters from escaping the contract through payload maps] |

## 8. Capability and assessment cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-C01` | H / S,I | Publish a complete `F-subject` catalog with every capability explicitly `unknown`; append scoped evidence and publish a same-version descriptor revision. | Unknown is valid without fabricated evidence; non-unknown availability cites appropriate evidence, while the previous descriptor stays immutable. [proposed: test a legitimate evidence-backed declaration lifecycle] |
| `EK00-C02` | F / I | Omit or duplicate a catalog capability, reuse another subject’s evidence, use a different mode/interface/configuration scope, or supersede a descriptor across subject versions. | Reject the incomplete/mismatched descriptor or its use for assessment; no omission or predecessor record supplies a default. [proposed: make descriptor scope and catalog completeness enforceable] |
| `EK00-C03` | B / I,D | Give `v1` a demonstrated presence and a documented absence; initialize `v2` without its own evidence. | Both `v2` capabilities remain `unknown`; neither positive nor negative findings inherit automatically. [proposed: exercise both directions of the no-inheritance rule] |
| `EK00-C04` | H/B / S,I,D | Execute every row of the orthogonality matrix below. | Preserve availability, opportunity, and facet result independently rather than generating a single combined status. [proposed: make the central three-way distinction observable in outputs] |
| `EK00-C05` | F / D | Observe a cross-session marker while the A write/read control is invalid; retain a separately valid application commitment in the same trace. | Isolation remains `indeterminate`, the marker and bad control remain visible, and unrelated valid application facts remain usable. [proposed: reproduce the invalid-control trap without claiming a newly confirmed leak] |
| `EK00-C06` | F / D | Supply a harness watchdog, fresh fixture application record, missing connector mapping, or documentation-only presence claim. | Do not credit native cancellation, native browser isolation, native absence from mapping failure, or exercised success from documentation alone. [proposed: test assistance and implementation-boundary attribution] |
| `EK00-C07` | F / D | Block launch because a required dependency is absent, or skip a required action without an exposure receipt. | Record prerequisite/infrastructure limitations and unexercised work; neither driver failure nor requirement satisfaction is established. [proposed: preserve qualification’s missing-dependency and skipped-step discipline] |

### Orthogonality matrix for `EK00-C04`

Each row is an independent facet fixture with journaled support; “required” refers to the pinned task/requirement registry rather than a judgment supplied by the subject. [proposed: fix applicability before the assessment under test]

| Capability availability | Opportunity | Evidence condition | Expected result |
|---|---|---|---|
| `present` | `exposed` | Valid controls and the required postcondition are demonstrated. | `satisfied`. [proposed: positive behavioral control] |
| `present` | `exposed` | Valid controls establish a violation of the requirement. | `violated`. [proposed: distinguish violation from absence] |
| `present` | `unexposed` | Earlier work prevents reaching the opportunity. | `not_exercised`. [proposed: presence is not exercise] |
| `absent` | `unexposed` | The capability was never required by the encountered opportunity. | `not_exercised`. [proposed: preserve the handoff’s absent-but-unexercised case] |
| `absent` | `blocked` | A required native facility is evidenced absent in the exact configured scope. | `native_absence`, without converting containment into satisfaction. [proposed: absence is a visible requirement gap, not a waiver] |
| `unknown` | `exposed` | Observation or controls cannot establish the relevant outcome. | `indeterminate`. [proposed: incomplete evidence must not become absence or violation] |
| `not_applicable` | `unexposed` | The facet is outside this task’s declared applicability, with supporting scope evidence. | `not_exercised` with rationale, not an extra result enum. [proposed: exercise the narrower handoff vocabulary] |

## 9. Diagnostic, claim, and attempt-scope cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-D01` | H / D | Derive `F-cooperative` from a valid prefix with a rejected history attempt, accepted correction, valid uploaded digest, identity verification, one submission, and separate confirmation rendering. | History is `recovered` with both attempts retained; authoritative postconditions and measurements resolve to the prefix; no native subject claims or timings are fabricated. [proposed: end-to-end diagnostic golden for the reference workflow] |
| `EK00-D02` | H/B / D | Provide a close-time outcome-unknown claim followed by a correlated commitment; repeat with a definite claim that cancellation prevented any later commitment. | The first claim is not contradicted by later knowledge; the second is contradicted where its asserted scope is disproved; original claims and facts remain unchanged. [proposed: test knowledge-boundary-sensitive reconciliation] |
| `EK00-D03` | B / D | Provide native `completed` at execution scope without an origin receipt; separately provide origin commitment without confirmation rendering. | Execution completion alone leaves application outcome unsupported; commitment remains established despite missing confirmation rendering, with that missing observation explicit. [proposed: keep execution, commitment, and presentation separate] |
| `EK00-D04` | B / I,D | Publish a diagnostic, append late evidence, request a new analysis, then re-derive the original prefix; separately request a new classifier version. | Each new analysis has a new immutable identity/revision and pinned inputs; the original diagnostic re-derives unchanged and cannot cite the later evidence. [proposed: preserve both historical knowledge and subsequent learning] |
| `EK00-D05` | H / I,D | Record manual production-shaped work in `F-production-model` with no connector, subject, or laboratory dependency; test a manual action note alone and then a separately attributed, correlated origin receipt. | The note does not prove commitment; the receipt supports only the fact its validated origin semantics establish; human assistance remains explicit and no executor gains credit. [proposed: verify the day-one manual path without inventing a real application] |
| `EK00-D06` | H / S,I,D | Derive `F-discovery` with incomplete coverage evidence and no attempt. | Discovery output remains useful with honest provenance and incomplete coverage; it has no fabricated subject or application completion and requires no orchestrator. [proposed: verify a non-application consumer of the shared kernel] |
| `EK00-D07` | H/F / I,D | Test valid `rehearsal_of`/`performance_of` links; then wrong-kind `derived_from`, unresolved/misidentified attempts, self-links, derivation cycles, changed commissioning kind, and a laboratory target labeled production. | Valid lineage conveys no evidence promotion; invalid linkage/scope is rejected and practice commitment never establishes production commitment. [proposed: enforce lineage without turning a rehearsal into a production credential] |
| `EK00-D08` | F / I,D | Support a finding with an unjournaled screenshot, a future event, an event from another journal without a local import, or a bad pointer/hash; duplicate internal IDs or leave an internal reference dangling. | Reject the unsupported diagnostic as conformant output; valid uncertainty may be reported from the actual prefix, but the missing support cannot be fabricated. [proposed: test citation closure and internal referential integrity] |
| `EK00-D09` | H/F / S,D | Disable fingerprint/behavioral analysis and fix matching; then inject zero-score objects, an unsupported internal-selector diagnosis, or a fix presented as already implemented. | Disabled sections use `M(not_enabled)`; unsupported causes remain unknown and fixes remain absent or explicitly recommendations; no implementation/verification credit is inferred. [proposed: keep M1 useful without invented advanced diagnosis] |
| `EK00-D10` | F / S,D | Add a top-level all-purpose application `status`; separately retain a native status field inside its raw response artifact. | Reject the new root field, but preserve the native artifact without upgrading its status to a multi-owner outcome. [proposed: prohibit outcome collapse without destroying original source shape] |
| `EK00-D11` | F / I,D | Change current wall time, mutable application rows, or network-visible data after fixing the manifest, analysis request, prefix, and classifier bundle. | The diagnostic remains identical; missing pinned classifier/registry material yields an explicit inability to derive, never a silent “latest version” substitution. [proposed: test the declared derivation inputs rather than just repeat a function call] |

The automated production-shaped fixture must never contribute to a real application count; actual production tracking requires evidence of the owner’s real employer-directed attempt, not merely a structurally valid test record. [inferred: 1-handoff-brief.txt, Parts III and IX]

`EK00-D05` is a contract test of the recording path, not a requirement to finish Hellscape before the owner applies manually to a real job. [inferred: 1-handoff-brief.txt, Parts VII–IX]

## 10. Replay cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-R01` | H / R | Replay `F-cooperative` using its manifest, ordered inputs, lifecycle observations, original analysis request, and pinned reducer/classifier artifacts. | Exactly the required `semantic_events`, `final_state`, and `diagnostic` comparisons are present and matched; the complete original diagnostic identity/revision is preserved during re-derivation. [proposed: verify exact fixture replay against independent golden outputs] |
| `EK00-R02` | H / R | Re-derive `F-production-model` in `diagnostic_rederivation` mode. | Only the diagnostic comparison is required, `reducer=M(not_applicable)`, and no employer mutation is performed or claimed to be replayed. [proposed: make production evidence replay safe by construction] |
| `EK00-R03` | F / S,I,R | Independently corrupt each expected/actual output; omit or duplicate a required comparison; then construct a receipt whose aggregate result contradicts its comparisons. | Real recomputation differences yield `mismatched`; structurally or semantically false receipts are rejected; a duplicate output name cannot replace a missing required comparison. [proposed: test both replay behavior and receipt truthfulness] |
| `EK00-R04` | F / R | Remove a required artifact or pinned implementation from the replay bundle while retaining its known digest. | The affected comparison is `unavailable` with a reason, known identity is retained, and no fallback browser/subject execution or `matched` receipt occurs. [proposed: make missing replay inputs visible rather than self-repairing through live work] |
| `EK00-R05` | F / R | Poison a recorded derived output while leaving its admitted input unchanged; observe whether replay consumes the poisoned value as input. | Replay independently recomputes the output and detects the mismatch instead of echoing the poisoned event. [proposed: distinguish replay from copying the journal’s asserted results] |
| `EK00-R06` | B/F / R | Use long recorded intervals, unavailable timings, and runtime credential/locator differences outside the pinned semantic representation; install launch/network spies that fail on browser, subject, or external-write invocation. | Recorded timing remains input without sleeping to reproduce it; the pinned semantic alias rules determine comparisons; prohibited invocations remain absent and the receipt’s false flags agree with the controller’s observations. [proposed: independently enforce offline replay and avoid meaningless byte comparisons of runtime secrets] |

The replay bundle may contain the original diagnostic artifact published after its analyzed prefix for comparison, but that artifact’s existence does not make later observations available to the diagnostic being re-derived. [inferred: contracts/00-evidence-kernel.yaml, `EK-DIAGNOSTIC` and `ReplayReceipt`]

The semantic-event and final-state serialization used in a replay test must be specified by its pinned reducer fixture, while the diagnostic comparison hashes the complete diagnostic under the kernel profile. [proposed: resolve replay test bytes without inventing a universal employer-state reducer]

## 11. Lease cases

For the deterministic expiry tests, `F-lease` uses a test policy with issue coordinate `100`, expiry coordinate `150`, and a retry limit of `2`; these are corpus values, not portfolio defaults. [proposed: small values expose exact boundary and exhaustion behavior without clock sleeps]

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-L01` | H / S,I,B | Claim an eligible unleased resource; renew while current; then complete successfully. | Claim assigns a unique token, owner/epochs and authority-clock interval, advances revision, clears the previous failure reason, and leaves `resource_state=pending`; completion releases the lease and applies the authorized owner transition without adding a failed retry. [proposed: test the orthogonal claim lifecycle] |
| `EK00-L02` | B / B | Release two workers simultaneously against one pending row using a barrier-controlled schedule. | Exactly one obtains the current lease; the loser cannot perform a completion under the winner’s token or overwrite ownership. [proposed: test an actual atomic claim rather than sequential API examples] |
| `EK00-L03` | B/F / I,B | Complete just before expiry, exactly at expiry, and after expiry on fresh fixtures; mutate token, input revision, entity revision, generation, owner epoch, and applicable session epoch separately. | Only the current, unexpired completion succeeds; at or after expiry and under each stale identity, the completion has no resource/downstream effect. [proposed: cover every fencing predicate and the unexpired boundary] |
| `EK00-L04` | F / B | Fail early release, run the expiry sweeper twice, and deliver confirmed-worker-death recovery for the same failed lease generation. | The generation consumes at most one retry; remaining retries preserve pending state, exhaustion applies the terminal route and one occurrence accounting update, and old completion cannot revive the row. [proposed: guard against double accounting across recovery paths] |
| `EK00-L05` | B / B | Exercise a terminal failure with a recorded reason and one with no recorded reason; advance the same entity to another stage and separately create a downstream entity. | Terminal routing uses the recorded reason or `retry_exhausted`; the entity counter persists across its stages, while a new entity has its own counter and does not erase upstream history. [proposed: preserve Stage1’s distinction between entity retries and terminal failure occurrences] |
| `EK00-L06` | F / I,B | Restart the lease authority before expiry; inject a new boot whose offset numerically resembles the old boot; race an old worker completion with reclamation. | Durably fence the old authority epoch before reclaiming; reject the stale completion without cross-boot subtraction or UTC-based elapsed inference. [proposed: exercise the kernel’s explicit restart mechanism] |
| `EK00-L07` | F / S,I | Supply a partly cleared unleased record, a held record without required ownership/times, expiry at/before issue, or an interval spanning different authority clocks/boots. | Reject the invalid snapshot; `session_epoch` is explicitly inapplicable only where the resource policy does not require it. [proposed: validate the record as well as the lease operation code] |
| `EK00-L08` | F / B,D | Reclaim a locally fenced lease while the external-effect simulator reports a later commitment. | Local stale writes remain rejected, but the late external observation is preserved and reconciled; lease loss is not relabeled as cancellation or rollback. [proposed: connect storage fencing to honest application uncertainty] |

Worker wall clocks must not decide expiry; the acceptance test observes the lease authority’s clock and epoch and does not assume Stage1 A5’s clock-skew bound. [inferred: contracts/00-evidence-kernel.yaml, `EK-LEASE-RESTART`]

The full fetch-key replacement, seal-point, and multi-owner archive matrix belongs to the owner-separated-write-domains suite rather than being duplicated here. [inferred: 1-handoff-brief.txt, Part VIII]

## 12. Artifact and privacy cases

| ID | Class / layer | Exercise | Required result |
|---|---|---|---|
| `EK00-A01` | H / I,B | Install known artifact bytes, journal the reference, retrieve under an authorized identity, and verify digest and length. | The registered bytes are immutable and retrievable; registration follows durable installation, not merely receipt of a locator. [proposed: establish usable evidence, not just an inventory entry] |
| `EK00-A02` | F / I,B | Reference absent bytes, alter stored bytes under an existing digest, or record inconsistent size/digest metadata. | Refuse the false reference or surface retained-evidence corruption; no successful replay or citation silently uses replacement bytes. [proposed: verify content-addressed integrity end to end] |
| `EK00-A03` | B / B,R | Remove transient application projections and run garbage collection while artifacts remain reachable from a retained manifest, prefix, diagnostic, replay bundle, or archive; also test an installed but never referenced artifact. | Referenced bytes remain protected; an unreferenced installation may be reclaimed according to explicit policy, and a complete retained archive still resolves to its promised content. [proposed: test evidence roots separately from current operational rows] |
| `EK00-A04` | F / B,D,R | Simulate genuine loss of a previously registered artifact after a successful run. | Preserve its known digest, append loss evidence when storage is usable, report `observation_lost` in later analysis/replay availability, and leave earlier published records unchanged. [proposed: distinguish new knowledge of loss from retroactive evidence editing] |
| `EK00-A05` | F / I,B | Attempt unauthorized retrieval of restricted receipts/native bodies; inject identifiable test credentials into ordinary logging paths. | Deny retrieval without authority and expose no test credential in ordinary journal/log/report output; possession of a digest is not access permission. [proposed: exercise the kernel’s privacy boundary without using real candidate secrets] |
| `EK00-A06` | B/F / I,B | Export a redacted derivative and then try publishing its different bytes under the original digest. | The derivative has its own digest and journaled derivation; original bytes/hash remain unchanged, and same-digest replacement is rejected. [proposed: retain honest provenance across privacy-preserving exports] |

## 13. Manual M1 acceptance

### `EK00-M01` — first integrated cooperative walkthrough

This is a product-owned acceptance exercise of Hellscape’s application and observer, not a qualification test of Circus Tent or Ringmaster. [extracted: 3-hellscape-blueprint.md, §§11–12]

**Setup**

1. Pin the cooperative manifest, task, synthetic document, build/assets, ordinary browser declaration, and analysis versions; commission a `practice`, `held_in`, manual attempt. [inferred: 3-hellscape-blueprint.md, §§10 and 12.2]
2. Keep the application browser separate from authenticated operator controls, and admit no automation subject or hidden execution planner. [extracted: 3-hellscape-blueprint.md, §§3.3 and 11.1]
3. Declare the observation/drain bounds and timing-comparison method before the run; document marker uncertainty and measurement resolution rather than choosing a tolerance after seeing the result. [extracted: 3-hellscape-blueprint.md, §§5.5 and 12.3]
4. Retain an independent manual-procedure record and direct persisted-operation/state checks in addition to the diagnostic. [extracted: 3-hellscape-blueprint.md, §12.3]

**Procedure**

1. Open the ordinary entry, choose the specified job, enter valid contact information, and proceed to history. [extracted: 3-hellscape-blueprint.md, §12.2]
2. Submit an intentionally invalid history interval, observe the visible error, then correct and save it through the ordinary controls. [extracted: 3-hellscape-blueprint.md, §12.2]
3. Upload the supplied synthetic document using the visible file input, perform the local identity action, and enter review. [extracted: 3-hellscape-blueprint.md, §§9 and 12.2]
4. Mark a review checkpoint, pause while an independent monotonic reference measures the same marked interval, then submit once and observe the receipt. [extracted: 3-hellscape-blueprint.md, §§12.2–12.3]
5. End observation, allow the bounded telemetry drain, derive the diagnostic, export the bundle, and perform exact fixture replay without the browser. [extracted: 3-hellscape-blueprint.md, §§10.8 and 12.2–12.6]

**Required assertions**

| Area | Acceptance assertion |
|---|---|
| Application usability | The ordinary human path completes without control-plane writes replacing UI operations or undisclosed assistance. [extracted: 3-hellscape-blueprint.md, §§3.1 and 12.2] |
| Validation and recovery | The invalid history attempt remains rejected, the correction is retained, and the history step is `recovered`, not rewritten as a first-attempt pass. [extracted: 3-hellscape-blueprint.md, §12.2] |
| State and document | Accepted task values, validation revisions, upload digest, and identity verification agree with persisted records and the independent procedure record. [extracted: 3-hellscape-blueprint.md, §§9.3 and 12.3] |
| Commitment | Exactly one authoritative application commitment exists, with confirmation rendering cited separately. [extracted: 1-handoff-brief.txt, Part IX] |
| Timing | Server intervals use engine endpoints; browser intervals use one document clock; the pause is included in the appropriate workflow interval and agrees with the independent marked measurement within the predeclared uncertainty. [extracted: 3-hellscape-blueprint.md, §§10.4 and 12.3] |
| Boundary naming | A browser interval ending when acceptance is observed is not mislabeled as ending at the server’s exact commit coordinate; those are independently timed boundaries. [inferred: 3-hellscape-blueprint.md, §§4.5 and 10.4] |
| Subject evidence | Subject, connector, and binding fields are inapplicable; R1–R10 are not credited to a nonexistent subject and have `not_exercised` assessments with the manual-validation rationale. [inferred: contracts/00-evidence-kernel.yaml, `EK-MANUAL`] |
| Disabled facilities | Fingerprint/behavioral analysis and unavailable fix matching have explicit missingness, not zero scores or fabricated recommendations. [extracted: 3-hellscape-blueprint.md, §§8.2 and 10.5] |
| Replay | The semantic-event, final-state, and diagnostic comparisons match, and the replay controller observes no subject/browser launch or external write. [inferred: 3-hellscape-blueprint.md, §10.8] |

A useful diagnosis of an unexpected fixture failure does not by itself pass this full-path acceptance exercise; repair the fixture and retain the failed run before repeating it. [extracted: 3-hellscape-blueprint.md, §12.2]

### `EK00-M02` — companion manual cases

| Subcase | Action | Required characterization |
|---|---|---|
| `M02a` | Stop before submission. | The fixture’s authoritative no-commit state establishes `application.goal=not_completed` at the cutoff; remaining work is unobserved or blocked as supported, not automatically a subject failure. [inferred: 3-hellscape-blueprint.md, §12.4] |
| `M02b` | Repeat a valid submit operation, then reuse its operation identity with different content. | The valid repetition resolves to the existing receipt with one commitment; conflicting reuse does not create or overwrite an application. [extracted: 3-hellscape-blueprint.md, §§9.3 and 12.4] |
| `M02c` | End observation with an incomplete field. | Preserve partial progress without inventing field success or an unobserved failed interaction. [extracted: 3-hellscape-blueprint.md, §12.4] |
| `M02d` | Close the browser before telemetry flush. | Retain server facts, expose the missing client tail, and avoid treating connection closure as complete observation. [extracted: 3-hellscape-blueprint.md, §12.4] |
| `M02e` | Restart the engine after an acknowledged operation. | Recover the durable operation, identify interrupted observation, register the new clock boot, and do not repeat the effect automatically. [inferred: 3-hellscape-blueprint.md, §§10.7 and 12.4] |
| `M02f` | Replay the retained primary walkthrough after the manual browser is closed. | Recover the same semantic outputs and diagnostic solely from the pinned bundle, not current browser or application memory. [extracted: 3-hellscape-blueprint.md, §§10.8 and 12.4] |

These exercises must not postpone the parallel discipline of finding jobs and recording the owner’s real manual applications; practice acceptance and production activity have different purposes and evidence scopes. [extracted: 1-handoff-brief.txt, Parts VII–IX]

## 14. Coverage index

### 14.1 Record coverage

| Record | Principal cases |
|---|---|
| Manifest | `S01–S04`, `J01–J02`, `P01–P04`, `D05–D07`, `M01`. [proposed: trace each record to positive and invalid-input coverage] |
| Journal envelope / ingress | `J01–J10`, `P01–P07`, `N02`, `T04–T07`. [proposed: cover structure, provenance, ordering, loss, and persistence together] |
| Diagnostic document | `C04–C07`, `D01–D11`, `T08–T10`, `M01–M02`. [proposed: cover successful, failed, and indeterminate derivations] |
| Replay receipt | `R01–R06`, `A02–A04`, `M01`, `M02f`. [proposed: cover all receipt outcomes and offline behavior] |
| Lease record | `L01–L08`, `J06`, `J09`. [proposed: cover snapshot validity, atomic operations, races, and restart] |
| Capability descriptor | `C01–C07`, `P07`, `D08`. [proposed: cover declaration completeness, own-version evidence, and assessment separation] |

All abbreviated IDs in this index carry the `EK00-` prefix. [proposed: compact indexing without introducing alternative case names]

### 14.2 Semantic-rule coverage

| Contract rule | Required case families |
|---|---|
| `EK-JOURNAL` | `J01–J04`, `J07`, `D04`, `D08`. [proposed: prefix truth and immutability coverage] |
| `EK-ATOMICITY` | `J06`, `J08–J10`, `L08`, `A01–A02`. [proposed: local atomicity and remote uncertainty coverage] |
| `EK-HASHES` | `J01–J02`, `P04`, `R03`, `A01–A02`, `A06`. [proposed: identity and content-integrity coverage] |
| `EK-PROVENANCE` | `P01–P07`. [proposed: authorized assignment and anti-forgery coverage] |
| `EK-OBSERVATION` | `J03–J05`, `J08`, `T10`, `M02d`. [proposed: deduplication, gaps, and tail-loss coverage] |
| `EK-NULL` | `N01–N05`, `S03–S04`, `D09`. [proposed: recursive missingness and forbidden defaults coverage] |
| `EK-TIME` | `T01–T07`, `L06–L07`, `M01`. [proposed: arithmetic, epoch, and measurement-origin coverage] |
| `EK-TIMING-INTERPRETATION` | `T04`, `T06–T11`, `M01`. [proposed: semantic comparability and native-report coverage] |
| `EK-CAPABILITY` | `C01–C03`, `C06`, `P07`. [proposed: scope, evidence, and no-inheritance coverage] |
| `EK-ASSESSMENT` | `C04–C07`, `D01`, `D09`. [proposed: orthogonality and control-validity coverage] |
| `EK-CLAIMS` | `P05–P06`, `D02–D03`, `T08–T10`, `L08`. [proposed: claim/fact and knowledge-boundary coverage] |
| `EK-ATTEMPT-SCOPE` | `D05–D07`, `M01`. [proposed: production/practice separation and linkage coverage] |
| `EK-MANUAL` | `N05`, `D05`, `M01–M02`. [proposed: human operation without executor credit coverage] |
| `EK-DIAGNOSTIC` | `J07`, `D01–D11`, `R01–R02`. [proposed: closed-input derivation and revision coverage] |
| `EK-REPLAY` | `R01–R06`, `M01`, `M02f`. [proposed: offline re-derivation coverage] |
| `EK-LEASE` | `L01–L05`, `L07`. [proposed: claim, completion, and retry-accounting coverage] |
| `EK-LEASE-RESTART` | `L06`, `L08`, `J08`. [proposed: authority-epoch and remote-effect coverage] |
| `EK-ARTIFACTS` | `A01–A06`, `J06`, `J10`, `R04`. [proposed: durability, retention, loss, and restricted-access coverage] |

## 15. Evidence package and final gate

Each execution must retain a manifest of the selected cases, contract and suite digests, implementation/build/configuration identity, fixture/reducer/classifier pins, seeds and fault schedules, observed results, and references to the supporting bytes. [proposed: make the conformance claim independently inspectable and repeatable]

For each case, report its ID, layers exercised, expected result, actual result, test verdict, failure/rejection location where applicable, and evidence references; measured test durations use the kernel’s clock/origin and estimate discipline. [proposed: avoid a green check mark with no recoverable basis]

Use these **test-run verdicts**, separately from application and requirement outcomes. [proposed: one test controller may summarize its own checks without collapsing application owners]

| Verdict | Meaning |
|---|---|
| `pass` | The required behavior—including an expected refusal, uncertainty, or failure characterization—was observed and evidenced. [proposed: conformance is correctness, not application completion] |
| `fail` | Available evidence demonstrates a mismatch with a required assertion. [proposed: separate a proved defect from missing evidence] |
| `blocked` | A prerequisite prevented the case from being exercised. [proposed: no credit for unavailable test setup] |
| `error` | The test controller, fixture, or oracle failed in a way that prevents a reliable verdict. [proposed: do not attribute harness defects to the implementation] |
| `not_run` | The required case or phase has not been executed. [proposed: preserve incomplete verification explicitly] |

A pass receipt is valid only when all cases required for its declared scope have `pass`, all supporting artifacts are available and hash-valid, and no unreported exclusion or automatic golden regeneration occurred. [proposed: deterministic acceptance gate with no silent skips]

If using the proposed CLI, exit `0` only for the fully passed selected scope; use `1` for established assertion failures, `2` for blocked setup, `3` for runner/oracle integrity errors, `4` for otherwise incomplete required evidence, and `130` for interruption, with per-case results retained regardless of the aggregate code. [proposed: adapt qualification’s evidence-aware exit discipline without reviving its product gate]

When several aggregate conditions occur, interruption takes precedence, followed by runner error, established failure, blocked setup, and other incompleteness; an expected injected storage failure that was correctly handled remains a passed test rather than a runner error. [proposed: make process-level results deterministic and interpretable]

The manual M1 evidence package must additionally include the actual procedure record, state/operation cross-checks, independent timing reference, structured and readable diagnostics, retained journal, and replay receipt. [extracted: 3-hellscape-blueprint.md, §12.6]

A discrepancy between the schema, semantic rules, and an executable test is a contract-review issue to resolve explicitly, not permission to weaken a validator until the suite turns green. [inferred: 1-handoff-brief.txt, Parts IV and VIII]

Passing this suite establishes the declared evidence-kernel scope; the portfolio still has to produce real, tracked applications for the candidate. [inferred: 1-handoff-brief.txt, Parts VII–X]
