# Owner-separated write domains — conformance suite

**Suite version:** `owner-separated-write-domains-conformance/0.1.0`; **contract under test:** `contracts/04-owner-separated-write-domains.yaml`, `owner-separated-write-domains/0.1.0`; **status:** review draft, not an execution receipt. [proposed: versioned test specification for the accepted Step 0 contract]

## 1. Purpose and acceptance boundary

This suite proves that independently owned facts can be published, composed, sealed, archived, and recovered without permitting one owner to overwrite another or making crawler commits wait for downstream work. [inferred: 1-handoff-brief.txt, owner-separated writes; 2-state-bank-crawler-blueprint.json, Decision 8]

The three required applications are the job record, application-attempt record, and Hellscape session record; passing only the job tests is insufficient for a portfolio-wide conformance claim. [extracted: contracts/04-owner-separated-write-domains.yaml, x-domain-layouts]

Conformance requires both JSON Schema validation and the applicable `OWD-*` semantic rules; structurally valid records can still have forged authority, false evidence, stale revision checks, incomplete archives, or unsafe publication behavior. [extracted: contracts/04-owner-separated-write-domains.yaml, x-validation]

A conforming read composition is not a multi-owner write API, and a seal describes a locally available version vector rather than a globally synchronized state. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-OWNER, OWD-VIEW, OWD-SEAL]

The suite uses synthetic writers, subjects, origins, journals, and fixture records; no real employer, credential, application submission, or running portfolio peer is required. [proposed: satisfy the handoff’s silo-test gate without waiting for whole-system integration]

Passing this suite does not establish job coverage, candidate suitability, browser reliability, native cancellation, or production application success. [inferred: 1-handoff-brief.txt, evidence and lifecycle invariants]

### 1.1 Authority and inherited checks

| Surface | Required interpretation |
|---|---|
| Record shapes | Validate the exact local definitions in contract 04, including embedded `AxisRevision` records whose `schema_version` remains `application-attempt-lifecycle/0.1.0`. Do not rewrite those versions to the enclosing owner-domain version. [extracted: contracts/04-owner-separated-write-domains.yaml, x-compatibility, AxisRevision] |
| Evidence and clocks | Reuse the evidence-kernel rules for references, prefixes, artifact identity, provenance, missingness, and measurements; copying their field shapes does not waive their semantics. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-TIME-PROVENANCE] |
| Attempt behavior | Reuse lifecycle transition, authority, cumulative-history, manual-execution, and reconciliation rules; do not implement a looser second lifecycle reducer inside storage. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-ATTEMPT] |
| Conflict handling | A schema/suite disagreement is an integrity blocker requiring review, not permission for the runner to repair the schema, reinterpret a field, or relax a failing invariant. [proposed: prevent conformance code from silently becoming a competing specification] |
| Missing dependencies | If the pinned kernel/lifecycle validators or their required corpus cases are unavailable, report the affected gate incomplete; do not replace them with permissive stubs and claim conformance. [inferred: 5-browser-qualification.md, skipped-required and missing-dependency discipline] |

## 2. Runner, oracle, and retained evidence

### 2.1 Proposed invocation

The following commands specify a runner interface to implement; they are not claims that this repository already contains that runner. [proposed: deterministic verification entry point]

- `python3 tools/conformance/owner_domains.py --sut-manifest <pinned-manifest.json> --profile logical --output <bundle-directory>` runs structural, authorization, publication, archival, recovery, and cross-record cases against the declared implementation. [proposed: logical conformance command]
- `python3 tools/conformance/owner_domains.py --sut-manifest <pinned-manifest.json> --profile deployment --output <bundle-directory>` additionally runs the two-writer and physical-contention cases on the declared persistence deployment. [proposed: deployment conformance command]

The SUT manifest must pin the implementation/build/configuration, schema and suite digests, persistence layout, logical writer bindings, test-adapter executable and arguments, clock registrations, workload sizes, fault schedule, and predeclared measurement acceptance limits. [proposed: reproducible scope and non-post-hoc deployment assessment]

The test adapter exposes only test operations: register an entity, submit an owner-local transition, stage and install a publication, obtain a sealed read, perform fetch-key replacement, resolve an archive, and exercise retention/GC. [proposed: minimum controllable surface needed to test the contract]

Those operations are harness vocabulary, not new external-connector verbs, production endpoint names, or a required common storage implementation. [proposed: keep a conformance adapter separate from the portfolio’s runtime contracts]

The adapter must also expose barriers at durability and publication boundaries, authenticated writer identities, persistent-state inspection, and failpoints sufficient to distinguish an uncommitted operation from a committed operation whose acknowledgement was lost. [proposed: make crash and concurrency assertions observable rather than inferred from API success]

### 2.2 Independent oracle

The reference oracle is a small append-only model of owner revision histories, installed view pointers, immutable bytes, seal selections, and retention reachability; it consumes the prescribed test schedule rather than the SUT’s reported result. [proposed: avoid validating storage with its own projection logic]

Expected archive contents are captured from the independently verified pre-replacement row at the selected vector, not reconstructed from the SUT’s current row after replacement. [proposed: detect current-value substitution and partial archives]

Every accepted domain revision is checked against both its authenticated writer binding and its predecessor; a client-supplied `writer_id`, `owner_domain`, or verification label is never the authentication oracle. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-OWNER, x-validation]

The reader oracle compares complete domain documents, not just revisions or a few sentinel fields, and enumerates the complete set of row roots permitted by the schedule. [proposed: detect torn publications that retain plausible version numbers]

### 2.3 Bundle and results

| Retained output | Contents |
|---|---|
| `manifest.json` | Exact test scope, pins, workloads, clock identities, acceptance limits, failpoints, and declared deployment assumptions. [proposed: reproducible test admission record] |
| `journal/` | Owner-local, publication, retention, and harness evidence with authenticated provenance and ordered prefixes; their storage identities remain distinguishable. [proposed: preserve the contract’s independent durability boundaries] |
| `records/` and `artifacts/` | Accepted records, rejected candidates, immutable byte objects, selected seals, archive manifests, expanded archives, and evidence required to resolve their references. [proposed: independently inspectable outcomes] |
| `measurements.json` | Kernel-shaped measurements and evidence for commit, publication, replacement, archive-resolution, and contention intervals. [proposed: auditable timing rather than opaque benchmark summaries] |
| `checks.json` | Case ID, applicable rule IDs, input pins, expected outcome, actual outcome, evidence references, and case disposition. [proposed: machine-reviewable assertions] |
| `report.md` | Scope-qualified result, failed/incomplete cases, deployment limitations, freshness limitations, and reconstruction instructions. [proposed: human-reviewable gate result] |

Use `PASS`, `FAIL`, `BLOCKED`, `INCOMPLETE`, and `HARNESS_ERROR` as proposed per-case dispositions; an expected rejection is a case pass only when the rejection and absence of unauthorized effects are both evidenced. [proposed: distinguish invalid test inputs from implementation failures]

The aggregate report uses `QUALIFIED`, `NOT_QUALIFIED`, `INCOMPLETE`, `INCOMPARABLE`, or `HARNESS_ERROR`; `QUALIFIED` always names the tested profile and exact implementation/deployment scope. [extracted: 5-browser-qualification.md, report statuses and qualification scope]

Use exit `0` for a qualified requested scope, `1` for a measured contract failure, `2` for blocked safety/configuration/dependencies, `3` for harness/integrity failure, `4` for incomplete required evidence, and `130` for interruption. [extracted: 5-browser-qualification.md, exit-code discipline]

No omitted required case may be counted as passed, and a logical-profile result cannot stand in for unmeasured deployment isolation. [inferred: 5-browser-qualification.md; contracts/04-owner-separated-write-domains.yaml, x-open-evidence]

## 3. Fixture construction

### 3.1 Common construction rules

Fixtures must be complete JSON instances, constructed in dependency order and validated before the behavior under test begins; the recipes below are not permission to leave placeholders in emitted records. [proposed: keep fixture preparation errors separate from SUT failures]

Generate real canonical bytes, real SHA-256 digests, exact sizes, actual journal sequences, and resolving JSON pointers; do not use a repeated dummy digest or an evidence reference that only resembles the required shape. [extracted: contracts/04-owner-separated-write-domains.yaml, x-compatibility, x-validation]

Use UTF-8 RFC 8785 canonical JSON under `kernel-jcs-sha256/1`; archive roots hash canonical `ArchiveStorageManifest` bytes, while domain-document digests hash their complete canonical snapshots. [extracted: contracts/04-owner-separated-write-domains.yaml, x-compatibility]

Evidence registration must avoid self-reference: supporting effects and seal selection precede the artifact registration of the document or row they support. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-SEAL, DataDomainRevision]

Negative cases start from an accepted complete fixture and alter the named condition; where structural validity is necessary to test a semantic rule, recompute affected legitimate hashes instead of letting an incidental checksum failure hide the intended defect. [proposed: one diagnostic failure cause per negative fixture]

### 3.2 Fixture families

| Fixture | Required construction |
|---|---|
| **J — job** | Register one synthetic source root, with distinct crawler/downstream owner bindings and persistence identities. Construct complete crawler `C1` and downstream `D1` documents and install them into an ingest-side view. Use a synthetic `https://fixture.invalid/…` listing URL solely as fixture data; it is not a claimed board endpoint. [proposed: controlled job composition baseline] |
| **J content** | Include evidenced title and description, an observed empty optional text field, a genuine date, a missing direct-apply URL, and other declared optional values with six-reason `Missing` envelopes. Provide every core content declaration and any extended declarations. Begin with a valid `Pass` acquisition, `ready` processing, `DISCOVERED` candidate, and an explicitly recorded classification bypass rather than an invented model verdict. [proposed: valid baseline exercising presence, empty values, missingness, and bypass] |
| **J versions** | `C2` is an authorized discovery/processing revision preserving acquisition and replacement lineage; `D2` changes product-owned selection or priority; `D3` is durable at its owner but initially unpublished. A later crawler revision changes the evidenced fetch identity and requires replacement archival. [proposed: distinguish owner durability, publication age, and acquisition replacement] |
| **A — subject attempt** | Register a practice attempt with immutable commission and all five owner bindings. Populate dispatch, observation, execution, application, and report from valid lifecycle publications, retaining their original axis revision numbers. [proposed: five-axis composition baseline] |
| **M — manual attempt** | Register a production manual attempt using synthetic origin receipts, with inapplicable subject/connector/binding identities and permanently unpublished, inapplicable dispatch/execution slots. No real production action occurs. [proposed: day-one manual-path fixture without fabricated native execution] |
| **H — Hellscape session** | Register a practice, held-in laboratory session, its pinned manifest and build, and separate application/observation/diagnostic owners. Include the eight-state reducer path, an invalid-history rejection followed by correction, one commitment, and separately recorded receipt rendering. [proposed: session truth/observation/judgment separation fixture] |
| **R — retention chain** | Perform two changed-fetch-key replacements. The later archived crawler document retains its backward link to the earlier archive; include shared artifact dependencies and at least two distinct retention roots. [proposed: direct and transitive reachability fixture] |
| **L — large downstream domain** | Generate valid downstream documents with many evaluation/material references and sizeable immutable referenced content, using manifest-pinned ordinary and maximum-admitted sizes. Do not add arbitrary undeclared payload fields. [proposed: realistic archive/publication load within the actual schema] |

For deterministic interleaving tests, use a controlled monotonic clock and barriers rather than sleeping; for deployment measurements, record actual monotonic intervals with their clock, boot, origin, resolution, and censoring. [proposed: reproducible race schedules without substituting simulated time for measured performance]

## 4. Structural, evidence, and ownership cases

For cases marked **reject**, the entire candidate operation or record must fail admission/publication, previously accepted source state and read pointers must remain unchanged, and the rejection must have inspectable evidence. [proposed: common failure oracle for all rejection cases]

| ID / rules | Action and required oracle |
|---|---|
| **S01 — accepted record inventory** | Validate examples of every top-level alternative: `EntityRegistration`, `DataDomainRevision`, `AxisRevision`, `PublicationReceipt`, `LogicalRow`, `ArchiveRecord`, `FetchKeyReplacement`, and active/released `RetentionPinRevision`; include all three entity types and every applicable domain. Each must pass structural and semantic validation. [proposed: exercise the complete schema, not only the job happy path] |
| **S02 — version and shape boundaries** | Reject unknown schema versions, wrong discriminators, duplicate YAML keys, non-JSON values, non-finite numbers, unknown fields, missing required fields, and integer values outside declared bounds. Confirm an embedded lifecycle version is accepted only in the lifecycle record branch. [proposed: tests for x-validation and the schema’s closed shapes] |
| **S03 — OWD-VIEW, OWD-TIME-PROVENANCE** | Exercise all six `Missing.reason` values in valid contexts. Reject bare null, null without a reason, a seventh reason, and an inapplicable manual axis represented as `not_observed`. Preserve observed `""`, `false`, `0`, and known-empty arrays without converting them to absence. [proposed: test contextual missingness without default fabrication] |
| **S04 — OWD-TIME-PROVENANCE** | Accept an exact zero duration, an evidenced one-sided bound, and unavailable publication delay with a reason. Reject cross-clock or cross-boot endpoint subtraction, negative duration, inverted numeric bounds, and UTC-only subtraction presented as exact elapsed time. Preserve subject-reported zero separately from an independent measured interval. [proposed: kernel timing regression cases at the publication boundary] |
| **S05 — OWD-TIME-PROVENANCE, OWD-SEAL** | Reject wrong artifact bytes/size, unresolved or mismatched evidence pointers, false event hashes, evidence beyond the pinned prefix, and a seal supported only by its own later registration. Re-signing a record in the test harness must not make an unauthorized source authoritative. [proposed: reference integrity and provenance are checked independently] |
| **O01 — OWD-OWNER, OWD-JOB** | Attempt crawler writes to downstream fields, downstream writes to acquisition, reconciler writes to execution/application, and observer writes to fixture commitment. Reject each, including a composed `LogicalRow` submitted as an update. Exercise identical and conflicting values: lack of authority is not excused by writing the same value. [proposed: authority is checked before value-level convenience] |
| **O02 — OWD-OWNER** | Mutate the registered owner, publication policy, storage-domain identity, or commission binding without a versioned migration. Reject; a new worker may act under the same logical writer only through its authenticated, fenced gateway. Two domains with the same `owner_domain` must also be rejected. [proposed: immutable ownership and domain-identity cases] |
| **O03 — OWD-REVISION** | Race two owner-local transitions from the same expected revision. Exactly one may advance to the next revision; the loser cannot alter fields, journal an accepted effect, or advance publication. Reject skipped revision numbers and stale lease/worker epochs. [proposed: deterministic lost-update and fencing test] |
| **O04 — OWD-REVISION** | Retry an identical committed revision after acknowledgement loss and require the existing outcome with no extra revision/effect. Submit different bytes under the same entity/domain/revision key and require an integrity conflict. [proposed: distinguish idempotent delivery from revision-key collision] |
| **O05 — OWD-LOCAL-COMMIT** | At owner commit boundaries, verify effect, revision, and supporting journal evidence are durable together before acknowledgement. Crash before durability: none is accepted. Crash after durability but before acknowledgement: all recover, and an identical retry is idempotent. A separately blocked composition-journal importer must not block this local acknowledgement. [proposed: local atomicity without a cross-owner journal transaction] |

## 5. Publication, read composition, and seals

| ID / rules | Action and required oracle |
|---|---|
| **P01 — OWD-PUBLISH, OWD-VIEW** | With `C1/D1` published, durably commit `C2` and `D2` but pause both transfers. Readers must still obtain `C1/D1`; owner acknowledgements must already have completed. Publish only `C2`: the valid composition is `C2/D1`, not an invented synchronized `C2/D2`. [proposed: demonstrate asynchronous freshness explicitly] |
| **P02 — OWD-PUBLISH** | Pause transfer after each component/chunk of a new domain document and its dependencies. Repeated reads must return the old complete document until installation, then the new complete document. Checksum failure, transfer interruption, or missing dependencies must leave the prior pointer visible and issue no success publication receipt. [proposed: old-or-new visibility under partial transfer] |
| **P03 — OWD-PUBLISH, OWD-REVISION** | Deliver revisions out of order, repeat an installed revision, and attempt to install a higher revision with missing lineage evidence. No delivery may regress a pointer; an identical installed retry returns the existing receipt. A skipped visible revision is accepted only after its owner lineage is verified. [proposed: reordered asynchronous delivery cases] |
| **P04 — OWD-VIEW** | Read an entity before a domain’s first publication and require a zero slot with reasoned missingness. After publication, make its bytes unavailable: detect an integrity/observation-loss condition and retain known identity in incident evidence; never return revision zero as if it had never existed. [proposed: distinguish unpublished from lost data] |
| **P05 — OWD-VIEW, OWD-ATTEMPT** | Reject missing/extra domain slots, wrong entity identities, mismatched registration digest, vector/slot disagreement, slot/document revision disagreement, wrong axis in an attempt slot, and documents from another owner or attempt. Recompute surrounding hashes so semantic mismatches are actually exercised. [proposed: cross-record equality checks beyond JSON Schema] |
| **P06 — OWD-SEAL** | Seal a known installed vector, continue owner writes/publications, and reread the first seal. Its vector, documents, name, view, prefix, and bytes must remain unchanged. A seal must not freeze owner progress or silently include a durable-but-unpublished revision. [proposed: immutable cut without distributed synchronization] |
| **P07 — OWD-SEAL** | Reject `observation_closed` without a pinned closed observation publication; for a session, verify its copied attempt-observation publication is the matching closed original. Reject `diagnostic_published` without a diagnostic publication and `fetch_key_replacement` without a published prior crawler domain. [proposed: seal names assert a supported state, not merely a label] |
| **P08 — OWD-PUBLISH, OWD-SEAL** | Verify every publication receipt against the document, registered writer, target view, superseded pin, source prefix, and installation event. An unknown `observed_owner_head` stays missing; installation must not fabricate knowledge of the source’s current head or exact cross-clock publication delay. [proposed: publication receipts report what was actually installed and known] |

A row observed between two owner publications is allowed to have mixed publication ages; the forbidden outcome is a partial domain document, a false vector, or a row whose named components cannot be resolved. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-PUBLISH, OWD-VIEW]

## 6. Job semantics and fetch identity

| ID / rules | Action and required oracle |
|---|---|
| **J01 — OWD-JOB** | Refresh crawler data while downstream selection, evaluations, materials, and attempt links exist. All downstream content must remain byte-identical until its owner publishes a new revision. Crawler initialization must leave the downstream slot unpublished rather than manufacture a product revision. [proposed: crawler refresh cannot erase or impersonate product work] |
| **J02 — OWD-JOB** | Preserve the original crawler input pin on an evaluation after a newer crawler revision publishes. Surface the mismatch as stale input without deleting or silently rescoring the evaluation. Reject an attempt link whose resolved commission identifies another portfolio job. [proposed: explicit evaluation freshness and attempt linkage] |
| **J03 — source-field reconciliation** | Preserve `source_url`, missing `direct_apply_url`, employer, description, location, portal type, and source-preserved closing-date text independently. Reject invented required URL evidence; do not copy a listing URL into the apply URL or convert ambiguous closing-date text into an invented closing instant. [proposed: tests for x-source-reconciliation and JobContent] |
| **J04 — identity reconciliation** | Construct two different `(target, job_id)` roots with identical company/title/location hints, and practice/production attempts sharing company/title. They must remain distinct identities; legacy deduplication hints must not authorize merge or overwrite. [proposed: tests for source roots and the legacy deduplication conflict resolution] |
| **J05 — OWD-RENDER** | For `Pass`, remove each declared required field or supply a wrong type/`Missing`. Reject successful-detail materialization as `incomplete_extraction`; do not relabel valid rendering as failed rendering. Verify full-description mapping to `description` without inventing undeclared content. [proposed: rendering and extraction remain separate] |
| **J06 — OWD-RENDER** | For each non-`Pass` verdict, require `render_failed`, reasoned missingness for every content value, retained acquisition/render evidence, and no genuine classifier result or successful-only completion membership. Reject a non-`Pass` document with plausible extracted content or `ready` processing. [proposed: failed rendering cannot produce apparently usable content] |
| **J07 — OWD-RENDER, OWD-JOB** | Exercise genuine PASS, genuine VETO, shadow-overridden VETO, classification bypass, and bypass preserving a prior genuine applied PASS. Verify genuine/applied verdicts remain distinct and bypass alone cannot shortlist. A content veto or disappearance from one crawl must not become authoritative posting closure. [proposed: classification and closure provenance cases] |
| **J08 — OWD-FETCH-IDENTITY** | Compute independent golden fetch keys for `A_full` and `B` using the declared JCS arrays and request fields. Verify source root, phase, and actual listing URL/request identity are retained; check uppercase method, actual body digest, representation headers, fragment removal, and scheme/host/default-port normalization. [proposed: exact request-identity framing test] |
| **J09 — OWD-FETCH-IDENTITY** | Change only cookie/session identity, run ID, crawl date, response bytes, or extractor version and require the same fetch key. Change representation-determining input and require the appropriate different key. Preserve query and meaningful multi-value order unless the pinned endpoint evidence authorizes normalization. [proposed: no hidden nonce or over-aggressive canonicalization] |
| **J10 — OWD-FETCH-NOOP** | Reacquire an existing identical key with newer content and require acquisition/replacement-lineage no-op and no new archive. Journal the new observation. Then perform an independent discovery, lease, or classifier transition and permit its revision advance only with acquisition and replacement lineage unchanged. [proposed: same-key no-op is not a ban on independent owner transitions] |
| **J11 — OWD-FETCH-NOOP** | Start with same-key `render_failed` acquisition and later obtain a `Pass` response. Under this contract, reject in-place acquisition replacement; retain the new observation and expose the freshness limitation. Adding a run nonce to force a different key must fail fetch-key validation. [proposed: explicitly test the accepted contract’s same-key repair limitation] |
| **J12 — OWD-JOB, OWD-ATTEMPT** | Attempt to derive an authoritative `APPLIED` state from a product selection, click, native `completed` claim, or Hellscape receipt. None qualifies. A correlated production origin commitment may support an APPLIED display, but that display is not a writable shared semantic field. [proposed: no claim-as-fact or practice-as-production in job projections] |

The same-key freshness limitation is a required expected outcome here, not a claim that the limitation is desirable; changing it requires a versioned contract decision rather than a test-only exception. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-FETCH-NOOP]

## 7. Complete archives and replacement atomicity

### 7.1 Replacement and reconstruction cases

| ID / rules | Action and required oracle |
|---|---|
| **A01 — OWD-FETCH-NOOP, OWD-REPLACE** | Insert an absent root and require no predecessor archive. For an existing root, replace with a genuinely different fetch key and require an archive, backward replacement link, replacement receipt, and active retention protection before acknowledgement. [proposed: initial insert and replacement have different obligations] |
| **A02 — OWD-REPLACE, OWD-SEAL** | With old crawler `C2`, locally published downstream `D2`, and owner-durable but unpublished `D3`, select a replacement seal. The archive must contain exactly `C2/D2`; it must neither wait for nor include `D3`. The new crawler revision must directly follow the checked old revision. [proposed: archive the selected published vector, not the peer’s latest source head] |
| **A03 — OWD-REPLACE** | After staging the archive but before commit, independently change (a) the old crawler revision/key or (b) the local downstream publication pointer. In each schedule the stale replacement must reject/reselect; it cannot acknowledge an archive with a mismatched cut. Rescheduling must not require a transaction or acknowledgement from the downstream owner. [proposed: compare-and-commit checks on both locally selected pointers] |
| **A04 — OWD-ARCHIVE** | Resolve the committed archive after newer downstream publication, cache eviction, owner-process shutdown, and loss of access to the downstream source store. Require exact reconstruction of the captured prior `LogicalRow`, including registration, all domain fields, missingness, receipts/evidence references, and seal vector. No mutable peer lookup is permitted. [proposed: archive completeness independent of current peer state] |
| **A05 — OWD-ARCHIVE** | Reject a crawler-only archive, changed-field diff, hash list presented as `payload_json`, omitted zero slot, default-filled missing value, or substituted current downstream revision. Also reject a self-consistent but wrong historical row that does not match the replacement seal and checked old crawler. [proposed: logical completeness is stronger than internal hash consistency] |
| **A06 — OWD-ARCHIVE** | Verify root digest/size against storage-manifest bytes, then verify every immutable component and exact expanded `payload_json`. Reject hashing the wrapper or expanded payload as the archive root, wrong document bytes, unresolved components, and expansion that changes access, values, or revisions. If any dependency is restricted, the archive/root response must be restricted. [proposed: physical extent encoding and access propagation checks] |
| **A07 — OWD-ARCHIVE, OWD-LOCAL-COMMIT** | With fixture L already fully installed, replace a fetch key while trapping reads/serialization of large downstream bytes on the crawler writer path. Only bounded local metadata selection and immutable extent references may participate there. Full archive expansion may stream separately; a shortcut returning only hashes is still a failure. [proposed: complete logical archives without large downstream serialization in the critical path] |
| **A08 — OWD-REPLACE, OWD-RETENTION** | Verify the receipt, new crawler backward link, archive root, archived vector, old fetch key, retention pin, and commit evidence all agree. Reject any mismatch even when each individual record validates structurally. [proposed: replacement is one coherent committed effect across its records] |

### 7.2 Required crash matrix

Run each crash point with restart and an identical client retry; inspect durable owner state, publication state, archive reachability, and journal evidence before allowing the retry to proceed. [proposed: test recovery from partial execution rather than only clean operation]

| Crash point | Required recovery |
|---|---|
| **C01 — during extent staging** | Prior crawler state remains authoritative; a staged partial object is not a committed archive or publication. Retry may restage verified bytes. [proposed: OWD-PUBLISH, OWD-REPLACE] |
| **C02 — complete archive staged, before replacement commit** | No replacement acknowledgement/effect exists; any staged orphan is distinguishable from a committed archive. The old row remains available. [proposed: OWD-REPLACE] |
| **C03 — inside replacement durability boundary** | Recovery exposes either the entire old state or the new crawler revision plus backward link, replacement evidence, complete archive, and durable retention protection. No new acknowledged row may lack any dependency. [proposed: OWD-LOCAL-COMMIT, OWD-REPLACE] |
| **C04 — after durable replacement, before acknowledgement** | Recover the complete committed replacement; identical retry must not create a second replacement or archive history entry. [proposed: OWD-REVISION, OWD-REPLACE] |
| **C05 — during read-view installation** | Readers obtain the old complete root or the new complete root, never a partially installed document. Source-owner durability is not rolled back because publication crashed. [proposed: OWD-PUBLISH, OWD-VIEW] |
| **C06 — during archive resolution** | A failed streaming response is incomplete, not a successful truncated archive; the stored immutable archive and retention roots remain unchanged. A later complete read reconstructs the same row. [proposed: OWD-ARCHIVE, OWD-RETENTION] |

A test backend that cannot inject a failure at a necessary boundary must report that boundary untested; process termination at an unrelated point is not equivalent evidence. [proposed: prevent crash coverage from being claimed by name alone]

## 8. Retention and garbage collection

| ID / rules | Action and required oracle |
|---|---|
| **G01 — OWD-RETENTION** | After replacement, publish newer job revisions, expire cache TTLs, evict caches, and run GC. The live replacement must still resolve its archive and every transitive immutable dependency. Cache policy must not act as retention policy. [proposed: archive durability survives ordinary maintenance] |
| **G02 — OWD-RETENTION** | Use fixture R. Retain the later archive containing the backward link, then remove a redundant direct pin on the earlier archive through an authorized release. The earlier archive must remain reachable and protected through the later archive. [proposed: transitive history is part of reachability] |
| **G03 — OWD-RETENTION** | Create two valid retention roots for shared bytes. Release one root with proper evidence and run GC: bytes remain protected by the other. Reject pin mutation of `dependent` or `archive_root`, unauthorized release, initial released state, and release without evidenced root retirement. [proposed: immutable pin identity and independent protection] |
| **G04 — OWD-RETENTION** | Interleave a new pin with GC’s reachability check/deletion boundary. Require a fenced result: either the pin protects existing bytes, or admission of the pin cannot succeed until its bytes are durably available. Never accept a live pin to reclaimed content. [proposed: deterministic pin-versus-delete race] |
| **G05 — OWD-RETENTION** | Retire every reaching root with journaled authorization, then allow reclamation under the declared policy. Verify that release history remains auditable and archived payloads were not rewritten to erase their former dependencies. [proposed: safe reclamation is possible without mutation of evidence] |
| **G06 — OWD-ARCHIVE, OWD-RETENTION** | Corrupt or remove a protected component outside legitimate GC. Require an integrity incident and failed/incomplete resolution, not successful GC, fabricated missingness, or reconstruction using a newer owner value. [proposed: storage loss cannot be hidden by mutable fallback] |

## 9. Application-attempt and Hellscape compositions

### 9.1 Attempt cases

| ID / rules | Action and required oracle |
|---|---|
| **T01 — OWD-ATTEMPT, OWD-SEAL** | Publish dispatch accepted, observation closed with close-time outcome unknown, a subject execution claim, and an origin at-boundary fact. Seal the row. Later publish a correlated origin commitment and then a new report. Preserve the original close snapshot and both claim/fact histories; the intermediate row must visibly have an old report input vector. [proposed: cancellation corpus expressed through owner publication] |
| **T02 — OWD-ATTEMPT** | Give the reconciler a claim that is contradicted by the correlated origin fact. Require a report revision only; attempted rewriting of either source domain must fail. Separately verify that a close-time `outcome_unknown` or a primitive-only claim is not converted into a false contradiction. [proposed: reconcile compatible propositions without rewriting them] |
| **T03 — OWD-ATTEMPT** | Reject an outer slot revision unequal to its embedded axis revision, an added competing axis revision counter, wrong commission digest, regressing report input pins, or a claim/fact revision that silently drops prior history. Preserve contradictory native messages as evidence rather than deduplicating away disagreement. [proposed: exact lifecycle publications, not approximate storage copies] |
| **T04 — OWD-ATTEMPT, OWD-TIME-PROVENANCE** | Attempt origin-fact publication from a manual note, connector acknowledgement, authenticated but uncorrelated callback, or self-asserted verification label. Reject authoritative admission unless the required source verification and correlation evidence actually resolves. Importing evidence must not change its authority class. [proposed: source authority is not acquired by storage ingestion] |
| **T05 — OWD-ATTEMPT** | Exercise fixture M through observation and a verified synthetic origin receipt. Require dispatch/execution zero slots with `not_applicable`, no fabricated subject publication, and no report claiming native execution success. The composition must remain usable without a browser subject. [proposed: owner separation supports the manual thin slice] |
| **T06 — OWD-ATTEMPT, OWD-JOB** | Reject cross-kind `derived_from`, mismatched resolved lineage identities, or production status supported only by a practice receipt. Preserve permitted rehearsal/performance links as links without copying outcomes across kinds. [proposed: inherited lifecycle lineage checks at the storage boundary] |

### 9.2 Hellscape session cases

| ID / rules | Action and required oracle |
|---|---|
| **H01 — OWD-SESSION** | Execute the cooperative manual fixture with invalid history, correction, upload, identity, review, and repeated identical submit. Require one immutable commitment and retained rejection/recovery evidence. Application truth may publish while observation or diagnostics lag. [proposed: reducer truth remains independent of observation completeness] |
| **H02 — OWD-SESSION** | Submit fixture-client telemetry or manual notes asserting commitment, accepted data, or identity verification. Reject mutation of application-owned state while retaining the input as correctly attributed observation where admissible. A rendered confirmation is not an independent server commitment. [proposed: telemetry cannot manufacture application truth] |
| **H03 — OWD-SESSION** | Edit a section after acceptance, replay a stale validation generation, and reuse a submit operation key with different content. Enforce reducer invalidation/conflict behavior; observer or diagnostic publication must not repair the application state to make the walk succeed. [proposed: preserve fixture reducer invariants through owner separation] |
| **H04 — OWD-SESSION, OWD-SEAL** | Publish a diagnostic pinned to older application/observation revisions and a fixed journal prefix, then publish late telemetry and a newer diagnostic. Both immutable diagnostic selections remain resolvable; display input lag rather than silently applying the old analysis to new evidence. Replay of the old prefix retains its old semantics. [proposed: asynchronous diagnosis with reproducible input cuts] |
| **H05 — OWD-SESSION, OWD-ATTEMPT** | Alter the session’s copied attempt-observation document or substitute one from another attempt. Reject unless it matches the original axis publication and session identity exactly. The session observer gains no second authority to close the attempt. [proposed: verified copy rather than duplicate lifecycle ownership] |
| **H06 — OWD-SESSION** | Seal fixture mutation authority while native state remains unknown; require the seal to prevent subsequent fixture effects without claiming the subject stopped. Reject active-session mutation by curriculum and any Hellscape session registered as production or held-out. Real job content does not change the session’s practice/held-in classification. [proposed: containment, future policy, and practice provenance stay distinct] |

These cases supplement, rather than replace, the complete lifecycle cancellation corpus and kernel replay checks required by the embedded record types. [extracted: contracts/04-owner-separated-write-domains.yaml, x-validation, OWD-ATTEMPT, SessionDiagnosticValue]

## 10. Two-writer and deployment isolation

### 10.1 Required experiments

| ID / rules | Controlled experiment and required oracle |
|---|---|
| **D01 — OWD-LOCAL-COMMIT** | Hold a downstream transaction before its durable commit while issuing admitted crawler writes, then reverse the roles. The independent owner must make durable progress without the held transaction releasing. Instrument lock/wait dependencies so a timeout, buffering-only acknowledgement, or hidden cross-owner transaction cannot masquerade as independence. [proposed: deterministic two-writer blocking test] |
| **D02 — OWD-LOCAL-COMMIT, OWD-PUBLISH** | Stop publication/exchange and the composition-journal importer while both owners commit bounded workloads. Owner acknowledgements and recoverable source histories must progress independently; views remain at complete older revisions and expose lag. Resume exchange and verify lineage-preserving catch-up. [proposed: publication is not on either source commit’s acknowledgement path] |
| **D03 — OWD-LOCAL-COMMIT, OWD-ARCHIVE** | Saturate downstream persistence, large-document generation, and snapshot transfer separately on the actual deployment. Measure crawler commits/replacements against the pinned quiet baseline; repeat with crawler pressure against downstream. Require measured limits and dependency instrumentation to support the claimed independence. [proposed: exercise physical I/O interference, not merely separate table names] |
| **D04 — OWD-REPLACE, OWD-ARCHIVE** | Repeatedly replace changed keys with fixture L already locally published. Measure critical-section work separately from background transfer and archive expansion. Confirm metadata-only archive assembly does not read or serialize large downstream payloads under the crawler writer. [proposed: reconcile complete archive semantics with bounded ingest work] |
| **D05 — OWD-PUBLISH, OWD-RETENTION** | Fill the declared publication/artifact admission capacity and interrupt transfer. Require explicit bounded admission/backpressure, unchanged published roots, no loss of acknowledged source commits, and no deletion of pinned components to manufacture capacity. [proposed: resource exhaustion preserves durability and honest incomplete publication] |

### 10.2 Measurement protocol

Before the deployment run, pin workload sizes, concurrency, repetition count, quiet-baseline procedure, latency summary calculation, acceptable degradation/absolute limits, and maximum permitted wait for each barrier test. [proposed: numerical acceptance must not be chosen after observing the result]

Use both wait-dependency evidence and elapsed-time measurements: favorable latency alone does not prove that no peer lock or transaction was acquired. [inferred: contracts/04-owner-separated-write-domains.yaml, OWD-LOCAL-COMMIT]

Compute commit latency from acknowledgement endpoints observed on one registered clock/boot, and verify durability independently through restart; a short enqueue call is not a durable-commit measurement. [proposed: eliminate buffer-acknowledgement false positives]

Publication-delay measurements must use compatible endpoints or evidenced bounds; separate source/destination UTC annotations cannot be subtracted into an exact delay. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-TIME-PROVENANCE]

The Stage1 reference host, ingest latency, payload sizes, and storage/I/O reservations are assumptions or workload baselines, not evidence that a newly selected deployment passes. [extracted: contracts/04-owner-separated-write-domains.yaml, x-open-evidence]

If relevant deployment limits or baseline details are missing, run the logical safety tests but leave deployment qualification incomplete; do not invent a numeric guarantee from the compacted source. [proposed: explicit treatment of unresolved deployment assumptions]

A single process, database brand, separate tables, or low-contention success does not by itself establish independent write paths. [extracted: contracts/04-owner-separated-write-domains.yaml, OWD-LOCAL-COMMIT]

## 11. Gate and review checklist

The logical gate requires every applicable S/O/P/J/A/C/G/T/H case, deterministic barrier portions of D01–D02, and inherited kernel/lifecycle checks to pass with replayable evidence. [proposed: explicit logical-profile completion criteria]

The deployment gate additionally requires D01–D05 on the named deployment with valid predeclared limits, physical-contention evidence, and no unresolved admission/durability gaps. [proposed: explicit deployment-profile completion criteria]

A component may qualify its declared subset before peer contact, but its report must list unimplemented entity families; only coverage of jobs, attempts, and Hellscape sessions supports a portfolio-wide result. [proposed: permit independent component shipping without exaggerating the covered contract surface]

The final reviewer must be able to answer all of the following from the retained bundle, without consulting mutable owner state. [proposed: afternoon-review acceptance checklist]

- Which authenticated writer owned every accepted field, and which unauthorized writes were rejected? [proposed: OWD-OWNER review question]
- Which owner-local effects were durable before acknowledgement, even while a peer or importer was stopped? [proposed: OWD-LOCAL-COMMIT review question]
- Which complete revision was installed in each view, and which owner revisions were still unpublished? [proposed: OWD-PUBLISH review question]
- Does each named seal reconstruct exactly its vector, including zero slots and stale diagnostic/report inputs? [proposed: OWD-VIEW and OWD-SEAL review question]
- Can every committed replacement’s complete prior row be resolved with the downstream owner offline? [proposed: OWD-REPLACE and OWD-ARCHIVE review question]
- Do direct and transitive retention roots survive publication, cache eviction, crash, and concurrent GC? [proposed: OWD-RETENTION review question]
- Are origin facts, subject claims, manual observations, and diagnostic judgments still separately attributable? [proposed: OWD-ATTEMPT and OWD-SESSION review question]
- Are zero, bounded timing, unavailable timing, missing data, and observation loss represented honestly? [proposed: OWD-TIME-PROVENANCE review question]
- Does the report explicitly preserve the same-fetch-key freshness limitation and any unmeasured deployment assumptions? [proposed: OWD-FETCH-NOOP and deployment-scope review question]

No handoff amendment is introduced by this suite; it makes the accepted owner-domain contract falsifiable without choosing a datastore, merging runtimes, or delaying real manual applications until infrastructure is complete. [proposed: preserve the Step 0 boundary and parallel thin-slice discipline]
