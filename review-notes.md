# Review notes — Step 0 closeout

**Disposition:** retain `review_draft`; the supplied material supports review of the architecture and contract decisions, but does not establish complete-artifact validation, implementation conformance, or successful production operation. [inferred: supplied compacted contract representations; decisions/invariants-and-provisionals.md; prd/00-integration.md]

**Scope:** this review follows the current twenty-item manifest and five-product organization, not the older meta-prompt’s file tree or four-component terminology. [extracted: current request, Products and Output manifest]

**Change boundary:** this note introduces no new wire fields, lifecycle states, native endpoints, or handoff amendments. [proposed: close the review without silently revising the contracts]

## 1. Review basis and limits

The available review packet contains the supplied sources, the full decisions document and integration PRD, and compacted representations of all six contracts. [extracted: current turn, supplied sources and prior artifacts]

The six conformance-document bodies and five product-PRD bodies are not included in this review packet; their absence here does not establish that they are absent from the deliverable. [uncertain: inspect the complete file set to establish their contents, coverage, and consistency]

Compacted representations are not executable schemas, so omitted definitions, flattened enum lists, and required/optional summaries cannot establish either schema validity or a defect in the original file. [inferred: the supplied prior contracts are explicitly labeled compacted]

In particular, the lifecycle summary’s empty `$defs` and the integration PRD’s registry-elision warning require inspection of the originals rather than reconstruction by guesswork; the registry summary now names `RuleClass` and `RuleScope`, but naming them is not proof of complete definitions. [inferred: supplied compacted contracts/01-application-attempt-lifecycle.yaml; supplied compacted contracts/05-suggested-fix-registry.yaml; prd/00-integration.md §8]

No validation receipts, native qualification results, timed review record, or production application receipts accompany this packet, so none is reported as passed or completed below. [uncertain: obtain the corresponding retained artifacts before asserting those results]

Three acceptance questions must remain separate: whether Step 0 is a complete reviewable specification, whether an implementation passes its applicable conformance suite, and whether the portfolio is producing real applications. [inferred: 0-unified-meta-prompt.md, Deliverable and Self-check; 1-handoff-brief.txt, shipping discipline; current request, Purpose]

## 2. Required self-check

“Addressed” below means specified in the visible design, not demonstrated by an implementation. [proposed: prevent a documentary review label from becoming a qualification claim]

| # | Question | Answer |
|---|---|---|
| 1 | Can the primary contracts be reviewed in one afternoon? | **Not demonstrated.** Complete schemas and a timed review are needed; summaries cannot establish the reading burden, and any reduction must cut secondary repetition rather than definitions or constraints. [uncertain: obtain the canonical files and time a primary-contract review under the review horizon in 0-unified-meta-prompt.md] |
| 2 | Does every substantive claim carry an epistemic tag? | **Complete-pack audit outstanding.** The visible decisions and integration documents use the required convention, but the missing document bodies and compacted field annotations prevent an exhaustive determination. [inferred: decisions/invariants-and-provisionals.md; prd/00-integration.md; supplied artifact representations] |
| 3 | Is every concrete detail traceable to a source or marked uncertain? | **Addressed as a discipline, not exhaustively verified.** The decisions distinguish proposed wire mechanisms from native facts and retain explicit reconnaissance gaps; the final audit must check actual field annotations and every claimed native mapping against the complete artifacts. [inferred: decisions/invariants-and-provisionals.md §§2, 6.2, and 8; contracts/03-internal-browser-binding.yaml] |
| 4 | Do invariants carry derivations and provisionals carry flip conditions? | **Yes in the visible decision register.** Its invariant table includes counterexamples or consequences, and its provisional register includes reasons and flip conditions; sibling PRDs must not silently promote those choices into permanent constraints. [extracted: decisions/invariants-and-provisionals.md §§3 and 6] |
| 5 | Is the thin slice parallel rather than a later phase? | **Yes.** Manual discovery, evaluation, application, and tracking can proceed before the crawler, reranker, Hellscape, either executor, registry, or dashboard is ready. [extracted: decisions/invariants-and-provisionals.md HA-03; prd/00-integration.md §§2 and 6] |
| 6 | Does every contract have a conformance suite? | **Every contract has a named companion; coverage remains unverified here.** The manifest specifies six suite documents, and the binding suite requires separate BrowserOxide and Camoufox executions rather than one cross-browser pass. [inferred: current request, Output manifest items 1–12; decisions/invariants-and-provisionals.md HA-04] |
| 7 | Are external connector and internal binding distinct? | **Yes in the visible contracts.** The external surface is asynchronous, task-shaped, and browser-agnostic; the internal surfaces are separate synchronous primitive contracts with no shared `ElementHandle` or neutral driver underneath them. [extracted: contracts/02-external-connector.yaml EXT-SURFACE; contracts/03-internal-browser-binding.yaml, browser boundaries] |
| 8 | Are practice/production and subject-claim/origin-fact distinctions explicit? | **Yes.** Kind is immutable, lineage cannot transfer evidence credit, and execution claims and application facts have different authorities; the reconciler writes only report, and wholly manual execution fabricates no subject claim. [extracted: contracts/01-application-attempt-lifecycle.yaml LIFE-AXES, LIFE-LINEAGE, LIFE-RECONCILE, and LIFE-MANUAL] |
| 9 | Does owner-separated composition appear in at least three applications? | **Yes.** Job records compose `crawler`/`downstream`; attempts compose the five lifecycle axes; Hellscape sessions compose `application`/`observation`/`diagnostic`. [extracted: contracts/04-owner-separated-write-domains.yaml, domain layouts] |
| 10 | What assumptions could be wrong, and what resolves them? | **They remain explicit rather than certified.** Section 6 below identifies the consequential premises, evidence required, and operating response; the crawler’s four `INCOMPLETE` markers and nine `ASSUMED` values remain unresolved. [inferred: decisions/invariants-and-provisionals.md §§6–8] |

These answers do not support declaring the entire artifact set complete from this packet alone; they also do not justify waiting for every product implementation before accepting a complete Step 0 specification. [inferred: 0-unified-meta-prompt.md, Deliverable and Self-check; 1-handoff-brief.txt, contracts-first and silo discipline]

## 3. Synthesis and amendment ledger

The important synthesis is the replacement of ambiguous shared statuses and implementation-derived interfaces with explicit authorities, evidence boundaries, and independently testable product surfaces. [inferred: 1-handoff-brief.txt, Position and genuine invariants; contracts/00–04]

### Recorded handoff amendments

| Amendment | Evidence and downstream consequence |
|---|---|
| **HA-01 — supplied crawler description** | The supplied crawler draft already names BrowserOxide facilities and HTTP-first transport allocations; use its applicable data-plane contracts rather than plan a fictitious Camoufox-to-BrowserOxide migration. [extracted: decisions/invariants-and-provisionals.md HA-01; 2-state-bank-crawler-blueprint.json §§3, 9, and 10] |
| **HA-02 — initial shared-core size** | Illinois initially exercises HTTP acquisition rather than the executor’s DOM/action surface; grow shared BrowserOxide implementation around demonstrated overlap instead of making a large speculative core a feed prerequisite. [extracted: decisions/invariants-and-provisionals.md HA-02] |
| **HA-03 — day-one dependency chain** | The handoff explicitly permits an earlier application-producing path, and the supplied playbook evaluation can be performed manually; crawler and reranker readiness therefore do not gate the first application. [extracted: decisions/invariants-and-provisionals.md HA-03] |
| **HA-04 — suite count** | Six contracts each require a suite, with the binding suite exercised separately per browser; the handoff’s closing reference to five suites does not remove an artifact or merge native gates. [extracted: decisions/invariants-and-provisionals.md HA-04] |

None of these amendments closes a crawler activation gap, validates a deployment assumption, or establishes a current browser capability. [extracted: decisions/invariants-and-provisionals.md §7]

### Other consequential reconciliations

- **Product workflow is not attempt truth.** Firestore tracker status and crawler semantic state survive only in their proper owner-specific roles or projections, not as replacements for the five lifecycle authorities. [inferred: 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md; contracts/01-application-attempt-lifecycle.yaml; contracts/04-owner-separated-write-domains.yaml]
- **Hellscape is a laboratory.** Real job text may inform a practice task without making the fixture an employer, its form representative, or its commitment production evidence. [extracted: 1-handoff-brief.txt, Hellscape invariant; contracts/01-application-attempt-lifecycle.yaml LIFE-LINEAGE]
- **The browser architecture follows the current clarification.** Circus Tent’s compatibility route includes Playwright→Juggler, while the Firefox-extension route is a target requiring evidence; the historical blueprint’s contrary bridge description cannot certify bypass. [extracted: current request, Products; contracts/03-internal-browser-binding.yaml CF-ROUTE]
- **Ringmaster is an independent implementation.** The provisional Rust-worker recommendation follows comparison of FFI, worker/API, and extension/controller alternatives, not a presumed BrowserOxide remote service or a port of Circus Tent. [extracted: decisions/invariants-and-provisionals.md P-05 and §6.1]
- **Qualification discipline survives retirement of m0.** Missing values, acknowledgements, harness timeouts, HTTP success, forced termination, human assistance, and loopback results retain their limited meanings rather than becoming a new pre-M1 qualification gate. [inferred: 5-browser-qualification.md; 1-handoff-brief.txt, m0 disposition; 3-hellscape-blueprint.md, Product and sequence]
- **The registry does not authorize repairs or applications.** Human class approval, recommendation eligibility, product implementation, and independently evidenced improvement remain distinct; registry deployment is deferred rather than inserted into the day-one dependency chain. [extracted: contracts/05-suggested-fix-registry.yaml, ownership, FIX-NO-AUTO-PATCH, and Step 0 scope]

## 4. Artifact-level review obligations

### 4.1 Primary contracts and companion suites

The following is a review checklist for the complete files, not a report that their checks have run. [proposed: make the remaining acceptance work specific without inventing results]

| Contract and companion | Highest-value inspection |
|---|---|
| `contracts/00-evidence-kernel.yaml` ↔ `conformance/00-evidence-kernel.md` | Verify all six record families; durable owner-local effects; server-assigned provenance; six null reasons; exact zero; clock/boot restrictions; orthogonal capability/opportunity/result; replay without external effects; fenced leases. [inferred: contracts/00-evidence-kernel.yaml, EK rules] |
| `contracts/01-application-attempt-lifecycle.yaml` ↔ `conformance/01-application-attempt-lifecycle.md` | Verify five authorities, immutable commissioning, manual mode, ambiguous delivery, close-time knowledge, late evidence, temporal claim comparison, and same-kind derivation. [inferred: contracts/01-application-attempt-lifecycle.yaml, LIFE rules] |
| `contracts/02-external-connector.yaml` ↔ `conformance/02-external-connector.md` | Verify all nine verbs, non-executing Prepare, durable local identity before dispatch, same-key behavior, bounded observation, raw-response retention, independent authentication/correlation, and honest unsupported mappings. [inferred: contracts/02-external-connector.yaml, EXT rules] |
| `contracts/03-internal-browser-binding.yaml` ↔ `conformance/03-internal-browser-binding.md` | Validate two independent schema documents and browser-specific suites; exercise native strengths, ownership/lifetime rules, action semantics, and evidence scoped to the actual route and build. [inferred: contracts/03-internal-browser-binding.yaml, BO and CF rules] |
| `contracts/04-owner-separated-write-domains.yaml` ↔ `conformance/04-owner-separated-write-domains.md` | Verify all three entity compositions, asynchronous complete publications, revision-vector seals, stale-writer fencing, full prior-row reconstruction, and transitive archive retention under concurrent writes. [inferred: contracts/04-owner-separated-write-domains.yaml, domain layouts and archive expansion] |
| `contracts/05-suggested-fix-registry.yaml` ↔ `conformance/05-suggested-fix-registry.md` | Verify local definition completeness, exact class approval, diagnostic citations, applicability cells, required evidence, contraindications, falsifiable plans, and withholding unsupported recommendations. [inferred: contracts/05-suggested-fix-registry.yaml, FIX rules] |

Each suite must contain happy-path, boundary, and failure cases; unavailable dependencies, invalid controls, required skips, and harness errors cannot be reported as subject passes. [extracted: 0-unified-meta-prompt.md, Contracts; 5-browser-qualification.md, Evidence discipline]

An honest unsupported result can establish correct connector behavior without establishing that an executor can perform a task requiring that capability; similarly, an Illinois HTTP pass cannot prove Ringmaster’s direct-DOM bet. [inferred: contracts/02-external-connector.yaml EXT-DESCRIBE; contracts/03-internal-browser-binding.yaml; 1-handoff-brief.txt, Step 0]

### 4.2 Product PRDs requiring full-body inspection

The obligations below identify what to check when the sibling PRDs are available, rather than asserting what those unseen documents contain. [uncertain: obtain prd/01-hellscape.md through prd/05-job-hunter.md for line-by-line review]

| PRD | Required alignment |
|---|---|
| `prd/01-hellscape.md` | M1 must validate the cooperative manual walkthrough, rejection and correction, measured pause, one fixture commitment, and exact replay without requiring a live subject to complete the task. [extracted: 3-hellscape-blueprint.md, M1 acceptance and manual procedure] |
| `prd/02-crawler.md` | The first automated slice must remain minimal and Illinois-focused, preserve acquisition/render/classification/coverage distinctions, and avoid application mutations or dependencies on unrelated state blockers. [inferred: 1-handoff-brief.txt, crawler position; decisions/invariants-and-provisionals.md HA-01 and HA-02] |
| `prd/03-circus-tent.md` | Python/Camoufox learn-run-heal, DOM reduction, and tiered resolution must remain product requirements, with compatibility and extension-native routes separately identified and evidenced. [inferred: current request, Products; 4-circus-tent-arch.md §§4–6; contracts/03-internal-browser-binding.yaml] |
| `prd/04-ringmaster.md` | The Rust sibling must independently implement the external surface and native execution behavior, and substantiate its packaging recommendation by comparing the three requested alternatives. [extracted: current request, Products; decisions/invariants-and-provisionals.md §6.1] |
| `prd/05-job-hunter.md` | The product must operationalize all eight playbooks, truthful material preparation, uncertainty-aware selection, durable commissioning, and follow-up rather than merely orchestrate browser tasks. [inferred: current request, Purpose; 6-get-a-job.xml.txt, capability_profile.txt, job_search_queries.txt, and storage collections] |

## 5. How to finish specification review

1. **Establish the review snapshot.** Inspect the complete twenty-file set and retain its identity so findings apply to actual bytes rather than changing excerpts. [proposed: make the closeout reproducible without requiring a new runtime service]

2. **Validate complete schemas.** Use strict YAML parsing and JSON Schema 2020-12 validation, resolve every local reference, and validate each browser document independently; check unknown versions, undeclared fields, required properties, finite numbers, and reasoned missingness. [inferred: contracts/00–05, validation requirements]

3. **Check cross-file semantics.** Compare mirrored kernel types and lifecycle meanings across contracts, especially `Missing`, measurements, evidence references, capability identities, attempt scope, and owner publications; syntactic validity alone cannot establish semantic consistency. [inferred: contracts/01–05, compatibility declarations]

4. **Inspect the conformance oracles.** Ensure tests would detect forged origin facts, exact-zero loss, cross-boot subtraction, claim strengthening, new-key retries after uncertain delivery, late-evidence rewriting, partial read roots, incomplete archives, inherited capabilities, and unsupported fix recommendations. [inferred: contracts/00–05, semantic rules]

5. **Audit epistemic annotations.** Check substantive prose and field-level `x-status`/`x-source`, including concrete primitives, endpoints, defaults, thresholds, and deployment assertions; a citation to a design draft establishes a requirement, not deployed native behavior. [inferred: 0-unified-meta-prompt.md, Epistemic discipline; contracts/03-internal-browser-binding.yaml, native mapping requirements]

6. **Run the human review against the actual horizon.** Review the primary contracts and their oracles before secondary prose; if the review exceeds an afternoon, remove repetition from the supporting documents without truncating schemas. [extracted: 0-unified-meta-prompt.md, Review horizon]

These steps establish specification quality; component-local execution receipts remain separate shipping gates, and they must name the actual version, scope, route, exemptions, and limitations. [inferred: 1-handoff-brief.txt, silo discipline; 5-browser-qualification.md, scoped qualification]

CI and conformance use local fixtures and synthetic backends rather than live employer portals; production observations belong to separately authorized operating attempts. [extracted: 4-circus-tent-arch.md, Acceptance; 6-get-a-job.xml.txt, AGENTS.md]

## 6. Consequential assumptions and residual risks

| Premise or risk | Evidence needed and response until resolved |
|---|---|
| **Current Illinois behavior matches the supplied allocation.** | Verify current structured full descriptions, deterministic per-run enumeration, count evidence, and clamp handling; if Illinois no longer offers the smallest useful slice, apply P-08 while continuing manual discovery. [inferred: 2-state-bank-crawler-blueprint.json §§3, 7–8; decisions/invariants-and-provisionals.md P-08] |
| **Crawler deployment assumptions are adequate.** | Measure the selected host, isolation, storage service, network overhead, recovery, clocks, payload sizes, downstream workload, inference envelope, and durability; the nine assumptions are not production guarantees. [uncertain: deployment measurements are absent; follow decisions/invariants-and-provisionals.md §8.2] |
| **BrowserOxide provides the required current native surface.** | Pin the engine and demonstrate DOM/V8 access, owner-thread confinement, actual event semantics, upload, capture, reset, and interruption separately; direct access alone does not prove form fidelity or determine packaging. [uncertain: current build/API and exercised capability evidence are absent; contracts/03-internal-browser-binding.yaml, BrowserOxide open evidence] |
| **A Firefox extension can supply the desired surface.** | Establish Camoufox packaging, transport, privileges, frame/root access, input, upload, capture, and bounded control; maintain the identified legacy route without borrowing its evidence to certify extension-native operation. [uncertain: implemented extension and qualification evidence are absent; contracts/03-internal-browser-binding.yaml, Camoufox open evidence] |
| **Production receipts can be authenticated and correlated reliably.** | Establish per-origin source, candidate/job/attempt correlation, and temporal scope under a pinned policy; absent receipts remain unknown, and ambiguous submission does not authorize retrying under a new key or another executor. [uncertain: current origin mappings are absent; contracts/01-application-attempt-lifecycle.yaml LIFE-ORIGIN and LIFE-IDEMPOTENCY] |
| **The retained fetch-key policy is operationally sufficient.** | Same-key content writes remain no-ops even after changed content or failed render; retain this limitation visibly and require a versioned change for freshness repair rather than a hidden run nonce. [extracted: decisions/invariants-and-provisionals.md §5; contracts/04-owner-separated-write-domains.yaml, source reconciliation] |
| **Chosen storage realizes owner separation.** | Prove independent owner commits, bounded publication, old-or-new reads, and complete retained archives under concurrent load; separate tables or one SQLite writer do not by themselves establish the required separation. [inferred: 2-state-bank-crawler-blueprint.json Decision 8; contracts/04-owner-separated-write-domains.yaml; decisions/invariants-and-provisionals.md §5] |
| **Candidate policy is complete enough for automatic filtering.** | Obtain current pay, schedule, travel, location/address, and credential decisions; do not invent thresholds, claim a degree, assume a waiver, or turn every bachelor’s requirement into automatic exclusion. [uncertain: complete current policy inputs are absent; 6-get-a-job.xml.txt, AGENTS.md, capability_profile.txt, and job_search_queries.txt] |
| **Historical observations support current capability or repair claims.** | Import the raw historical corpus where needed and test identified current versions independently; documentary cancellation, timing, and invalid isolation-control reports cannot certify a new build or justify an unsupported fix. [inferred: 3-hellscape-blueprint.md §§1 and 4; contracts/00-evidence-kernel.yaml EK-CAPABILITY; contracts/05-suggested-fix-registry.yaml] |
| **Current packaging choices remain economical.** | Retain the recorded flip conditions for monorepo, shared Rust-core size, Hellscape implementation, orchestrator language/storage, and dashboard persistence; none is permission to merge runtimes or postpone applications. [extracted: decisions/invariants-and-provisionals.md P-01 through P-08 and P-15] |

The legacy Firestore collection table supplies useful product vocabulary but not executable migration schemas; inspect actual producers before assigning precise types or importing old statuses as authoritative facts. [uncertain: shared/firestore-contracts and producer implementations are not supplied; 6-get-a-job.xml.txt, docs/contracts/firestore-collections.md]

## 7. Operating acceptance remains applications-first

The draft’s strongest anti-avoidance decision is HA-03: the first production application needs a durable, honest manual recording path, not the completed infrastructure stack. [inferred: decisions/invariants-and-provisionals.md HA-03; current request, Purpose]

The next useful operating evidence should contain the following, with manual substitutions disclosed rather than impersonating unfinished services. [proposed: inspect one real attempt end to end instead of using engineering completion as a proxy]

- A retained real listing and source observation, without fabricated crawler coverage or source identity. [inferred: prd/00-integration.md §2]
- A selection rationale tied to the candidate profile, matched playbooks, actual requirements, and unresolved preferences. [inferred: 6-get-a-job.xml.txt, capability_profile.txt and job_search_queries.txt]
- The exact truthful materials and submitted answers, access-restricted where they contain personal data. [inferred: 6-get-a-job.xml.txt, AGENTS.md and raw_job_history.txt; contracts/00-evidence-kernel.yaml EK-ARTIFACTS]
- An immutable production commission and an honest record of manual or assisted execution, without invented native identity or claims. [extracted: contracts/01-application-attempt-lifecycle.yaml LIFE-COMMISSION and LIFE-MANUAL]
- A verified employer receipt where available, or explicit unresolved outcome where it is not; the next follow-up action must not silently become another submission. [inferred: contracts/01-application-attempt-lifecycle.yaml LIFE-ORIGIN and LIFE-IDEMPOTENCY; prd/00-integration.md §2]

No actual application count is established by this review packet; missing operating evidence is neither a zero count nor proof that the portfolio has succeeded. [uncertain: inspect retained production attempt journals and verified origin facts to establish operating results]

**Closeout recommendation:** complete the artifact-level review and record its real results, while continuing the manual application lane; accept Step 0 for its specified contract surface, qualify each implementation separately, and judge the portfolio by real tracked applications and outcomes. [proposed: preserve the handoff’s independent shipping gates without reproducing the failure mode of perfecting lower layers before applying]
