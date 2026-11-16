//! Conformance test for [C23]: old-or-new publication.
//!
//! The test drives the real owner journal (`MemoryOwnerStore`) and immutable
//! artifact store (`MemoryArtifactStore`). Only the failing read used to
//! simulate an interrupted transfer wraps the artifact store; the pointer,
//! receipt, seal, and row behavior all run through the module under test.
//!
//! C23 requires:
//! * no partial domain is ever exposed (the snapshot, digest, receipt, and row
//!   slot are complete or the publication is refused);
//! * reordered delivery cannot regress the read-view pointer (an identical old
//!   revision returns its existing receipt while the pointer stays at the
//!   newest installed revision);
//! * readers can still obtain the complete old row through an old seal.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_publication::{compose_row, install_revision, select_seal};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const JOURNAL: &str = "crawler-publication-journal";
const RUN: &str = "run-publication-1";
const PRODUCER: &str = "publication-writer";
const OWNER: &str = "crawler";
const VIEW: &str = "ingest";
const REGISTRATION_DIGEST: &str =
    "b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

/// `CheckedRecord` is intentionally not `Clone`; copies are re-gated values.
fn copy(record: &CheckedRecord) -> CheckedRecord {
    check("audit_log", record_value(record).clone())
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn entity() -> Value {
    json!({"entity": "job", "id": "job-1"})
}

fn registration() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "entity": entity(),
            "registration_digest": REGISTRATION_DIGEST,
            "domains": ["crawler", "downstream"],
        }),
    )
}

fn crawler_value(revision: u64, marker: &str) -> Value {
    json!({
        "domain": "crawler",
        "revision": revision,
        "marker": marker,
        "acquisition": {
            "status": "complete",
            "evidence": format!("evidence-{revision}"),
        },
        "processing": {"pipeline_state": "materialized"},
        "discovery": {"coverage_refs": [format!("coverage-{revision}")]},
        "replacement_lineage": missing("not_applicable"),
    })
}

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "publication-clock",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

struct FixedClock {
    tick: AtomicU64,
}

impl FixedClock {
    fn new() -> Self {
        Self {
            tick: AtomicU64::new(0),
        }
    }
}

impl ClockAuthority for FixedClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        let offset = self.tick.fetch_add(1, Ordering::SeqCst);
        validate("audit_log", timepoint(1_000 + offset))
    }
}

struct FlakyArtifacts {
    inner: MemoryArtifactStore,
    fail_reads: AtomicBool,
}

impl FlakyArtifacts {
    fn new() -> Self {
        Self {
            inner: MemoryArtifactStore::new(),
            fail_reads: AtomicBool::new(false),
        }
    }

    fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::SeqCst);
    }
}

impl ArtifactStore for FlakyArtifacts {
    fn install(
        &self,
        grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        restricted: bool,
    ) -> Result<CheckedRecord, Fault> {
        self.inner.install(grant, bytes, media_type, restricted)
    }

    fn read(&self, grant: &Grant, reference: &CheckedRecord) -> Result<Vec<u8>, Fault> {
        if self.fail_reads.load(Ordering::SeqCst) {
            return Err(Fault {
                code: "bytes_unavailable".to_string(),
                detail: "injected interrupted transfer: installed bytes are not yet verifiable"
                    .to_string(),
            });
        }
        self.inner.read(grant, reference)
    }

    fn delete(
        &self,
        grant: &Grant,
        reference: &CheckedRecord,
        gc_certificate: &CheckedRecord,
    ) -> Result<(), Fault> {
        self.inner.delete(grant, reference, gc_certificate)
    }
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-publication-1",
            "producer_registry": [
                {
                    "producer_id": PRODUCER,
                    "owner_domain": OWNER,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": "domain_revision_published", "permitted_provenance": ["server"]},
                {"event_kind": "seal_selected", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn principal_of(manifest: &CheckedRecord) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": PRODUCER,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn grant_for(manifest: &CheckedRecord, event_kind: &str) -> Grant {
    let principal = principal_of(manifest);
    let submission = check("audit_log", json!({"event_kind": event_kind}));
    authorize_producer(&principal, &submission, manifest).expect("producer grant must issue")
}

struct Fixture {
    store: MemoryOwnerStore,
    artifacts: Arc<FlakyArtifacts>,
    install_grant: Grant,
    seal_grant: Grant,
}

fn fixture() -> Fixture {
    let manifest = manifest_fixture();
    let artifacts = Arc::new(FlakyArtifacts::new());
    let artifacts_dyn: Arc<dyn ArtifactStore> = artifacts.clone();
    let store = MemoryOwnerStore::new(
        copy(&manifest),
        Arc::new(FixedClock::new()),
        artifacts_dyn,
    )
    .expect("owner store must admit its manifest");
    let admission_grant = grant_for(&manifest, "manifest_admitted");
    let admission = check(
        "audit_log",
        json!({
            "operation": "admit_manifest",
            "journal_id": JOURNAL,
            "run_id": RUN,
            "manifest": record_value(&manifest).clone(),
            "principal": {
                "producer_id": PRODUCER,
                "manifest_digest": binding_of(&manifest),
            },
        }),
    );
    store
        .transact(&admission_grant, &admission)
        .expect("journal admission must commit");
    Fixture {
        store,
        artifacts,
        install_grant: grant_for(&manifest, "domain_revision_published"),
        seal_grant: grant_for(&manifest, "seal_selected"),
    }
}

fn revision_with(rev: u64, previous: u64, value: Value, extra: Value) -> CheckedRecord {
    let mut map = json!({
        "journal_id": JOURNAL,
        "view": VIEW,
        "entity": entity(),
        "registration_digest": REGISTRATION_DIGEST,
        "domain": "crawler",
        "owner_domain": OWNER,
        "writer_id": "writer-1",
        "revision": rev,
        "previous_revision": previous,
        "value": value,
        "evidence_refs": [],
    });
    if let (Some(map), Value::Object(extra)) = (map.as_object_mut(), extra) {
        for (key, value) in extra {
            map.insert(key, value);
        }
    }
    check("audit_log", map)
}

fn seal_request(domains: Value, expected: Option<Value>) -> CheckedRecord {
    let mut map = json!({
        "journal_id": JOURNAL,
        "view": VIEW,
        "entity": entity(),
        "registration_digest": REGISTRATION_DIGEST,
        "domains": domains,
        "support": [],
    });
    if let (Some(map), Some(expected)) = (map.as_object_mut(), expected) {
        map.insert("expected_version_vector".to_string(), expected);
    }
    check("audit_log", map)
}

fn vector_of(seal: &CheckedRecord) -> BTreeMap<String, u64> {
    let entries = record_value(seal)["version_vector"]
        .as_array()
        .expect("seal carries a version vector array");
    let mut vector = BTreeMap::new();
    for entry in entries {
        let domain = entry["domain"].as_str().expect("vector entry names a domain");
        let revision = entry["revision"]
            .as_u64()
            .expect("vector entry names a revision");
        vector.insert(domain.to_string(), revision);
    }
    vector
}

fn journal_last_sequence(store: &dyn OwnerStore, grant: &Grant) -> u64 {
    let query = check("audit_log", json!({"query": "prefix", "journal_id": JOURNAL}));
    let prefix = store.read(grant, &query).expect("journal prefix must read");
    record_value(&prefix)["last_sequence"]
        .as_u64()
        .expect("prefix carries its last sequence")
}

fn slot<'a>(row: &'a CheckedRecord, domain: &str) -> &'a Value {
    record_value(row)["domains"]
        .get(domain)
        .unwrap_or_else(|| panic!("row must contain the declared {domain:?} slot"))
}

fn publication_delay_measurement(delay_ms: u64) -> Value {
    json!({
        "measurement_id": "publication-delay-1",
        "name": "publication_delay",
        "scope": {"kind": "run", "id": RUN},
        "quantity": "duration",
        "unit": "ms",
        "origin": "engine_measured",
        "clock_id": "publication-clock",
        "boot_id": "boot-1",
        "method": "source_value",
        "start": missing("not_observed"),
        "end": missing("not_observed"),
        "estimate": {"kind": "exact", "value": delay_ms},
        "resolution": missing("not_observed"),
        "censoring": "none",
        "comparability_group": missing("not_observed"),
    })
}

fn registered_clocks() -> Value {
    json!({
        "clocks": [
            {"clock_id": "publication-clock", "boot_id": "boot-1"},
        ],
        "receipt": missing("not_observed"),
    })
}

// ---------------------------------------------------------------------------
// C23 — old-or-new publication
// ---------------------------------------------------------------------------

#[test]
fn c23_old_or_new_publication_no_partial_domain_and_reordering_cannot_regress_pointer() {
    let fixture = fixture();
    let store = &fixture.store;
    let artifacts = fixture.artifacts.as_ref();
    let install_grant = &fixture.install_grant;
    let seal_grant = &fixture.seal_grant;
    let registration = registration();

    // A fabricated delay from independent UTC annotations is refused before
    // anything is installed; the view remains empty.
    let mut bad_delay = publication_delay_measurement(9);
    bad_delay["source_utc"] = json!("2026-11-16T10:00:00Z");
    bad_delay["destination_utc"] = json!("2026-11-16T10:00:09Z");
    let bad = revision_with(
        1,
        0,
        crawler_value(1, "bad-delay"),
        json!({
            "publication_delay": bad_delay,
            "registered_clocks": registered_clocks(),
        }),
    );
    let err = install_revision(store, artifacts, install_grant, &bad)
        .expect_err("UTC subtraction must not become a publication delay");
    assert_eq!(err.code, "utc_subtraction_refused");

    let empty_seal = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("selecting an empty view must produce explicit zero slots");
    assert_eq!(vector_of(&empty_seal).get("crawler"), Some(&0));
    assert_eq!(vector_of(&empty_seal).get("downstream"), Some(&0));

    // 1. Install revision 1; the complete document becomes retrievable before
    //    the pointer advance is observable.
    let value1 = crawler_value(1, "first");
    let revision1 = revision_with(1, 0, value1.clone(), json!({}));
    let receipt1 = install_revision(store, artifacts, install_grant, &revision1)
        .expect("revision 1 must install");
    assert_eq!(record_value(&receipt1)["record_type"], json!("publication_receipt"));
    assert_eq!(record_value(&receipt1)["revision"], json!(1));
    assert_eq!(record_value(&receipt1)["value"], value1);
    let digest1 = record_value(&receipt1)["document_digest"]
        .as_str()
        .expect("receipt carries a document digest")
        .to_string();
    assert_eq!(digest1.len(), 64);
    let document1 = record_value(&receipt1)["document"].clone();
    assert_eq!(document1["digest"], json!(digest1));
    let installed = check("audit_log", document1);
    let bytes = artifacts
        .read(install_grant, &installed)
        .expect("the complete document must be retrievable");
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("document bytes are JSON"),
        value1
    );

    let seal1 = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after revision 1");
    assert_eq!(vector_of(&seal1).get("crawler"), Some(&1));
    assert_eq!(vector_of(&seal1).get("downstream"), Some(&0));

    let row1 = compose_row(&seal1, &registration, &[copy(&receipt1)])
        .expect("complete row at revision 1");
    assert_eq!(slot(&row1, "crawler")["revision"], json!(1));
    assert_eq!(slot(&row1, "crawler")["snapshot"], value1);
    assert_eq!(slot(&row1, "downstream")["revision"], json!(0));
    assert!(
        slot(&row1, "downstream")["snapshot"]["value"].is_null(),
        "a zero slot is a typed Missing envelope, never lost bytes"
    );
    let domains = record_value(&row1)["domains"]
        .as_object()
        .expect("row domains is a map");
    assert_eq!(domains.len(), 2, "both declared domain slots are present");

    // 2. Identical delivery returns the existing receipt and never appends a
    //    second pointer advance.
    let sequence_before_duplicate = journal_last_sequence(store, install_grant);
    let duplicate1 = install_revision(store, artifacts, install_grant, &revision1)
        .expect("identical delivery must return the existing receipt");
    assert_eq!(
        record_value(&duplicate1)["receipt_id"],
        record_value(&receipt1)["receipt_id"]
    );
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_duplicate,
        "identical delivery returns the existing receipt without appending a new pointer advance"
    );
    let seal1b = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after duplicate delivery");
    assert_eq!(vector_of(&seal1b).get("crawler"), Some(&1));

    // 3. Different bytes under the same revision key are an integrity
    //    conflict, and the installed pointer is unchanged.
    let conflicting1 = revision_with(1, 0, crawler_value(1, "different-bytes"), json!({}));
    let sequence_before_conflict = journal_last_sequence(store, install_grant);
    let err = install_revision(store, artifacts, install_grant, &conflicting1)
        .expect_err("different bytes under one revision key must be refused");
    assert_eq!(err.code, "revision_conflict");
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_conflict,
        "a conflicting delivery never appends a pointer advance"
    );
    let seal1c = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after conflict");
    assert_eq!(vector_of(&seal1c).get("crawler"), Some(&1));

    // 4. Install revision 2 with a validated publication-delay measurement.
    let value2 = crawler_value(2, "second");
    let revision2 = revision_with(
        2,
        1,
        value2.clone(),
        json!({
            "publication_delay": publication_delay_measurement(12),
            "registered_clocks": registered_clocks(),
        }),
    );
    let receipt2 = install_revision(store, artifacts, install_grant, &revision2)
        .expect("revision 2 must install");
    assert_eq!(record_value(&receipt2)["revision"], json!(2));
    assert_eq!(
        record_value(&receipt2)["publication_delay"]["estimate"]["kind"],
        json!("exact")
    );
    assert_eq!(
        record_value(&receipt2)["publication_delay"]["estimate"]["value"],
        json!(12)
    );
    assert_eq!(
        record_value(&receipt2)["installation_time"]["clock_id"],
        json!("publication-clock")
    );
    // 5. Reordered delivery of the identical old revision returns the old
    //    receipt while the view pointer stays at revision 2.
    let sequence_before_reordered = journal_last_sequence(store, install_grant);
    let reordered1 = install_revision(store, artifacts, install_grant, &revision1)
        .expect("identical old delivery returns the existing receipt");
    assert_eq!(record_value(&reordered1)["revision"], json!(1));
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_reordered,
        "reordered delivery returns the old receipt without appending to the pointer"
    );
    let seal2 = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after revision 2");
    assert_eq!(
        vector_of(&seal2).get("crawler"),
        Some(&2),
        "reordered delivery must not regress the pointer"
    );

    // An old seal still reads the complete old row: readers see old or new,
    // never a mixed row.
    let old_row = compose_row(&seal1, &registration, &[copy(&reordered1)])
        .expect("the old seal still composes the complete old row");
    assert_eq!(slot(&old_row, "crawler")["revision"], json!(1));
    assert_eq!(slot(&old_row, "crawler")["snapshot"], value1);
    assert_eq!(slot(&old_row, "downstream")["revision"], json!(0));

    let new_row = compose_row(&seal2, &registration, &[copy(&receipt2)])
        .expect("the new seal composes the complete new row");
    assert_eq!(slot(&new_row, "crawler")["revision"], json!(2));
    assert_eq!(slot(&new_row, "crawler")["snapshot"], value2);

    // A different document under the already published old revision key is
    // still an integrity conflict, and the pointer remains at 2.
    let sequence_before_old_conflict = journal_last_sequence(store, install_grant);
    let err = install_revision(store, artifacts, install_grant, &conflicting1)
        .expect_err("conflicting old delivery must be refused");
    assert_eq!(err.code, "revision_conflict");
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_old_conflict,
        "a conflicting old delivery never appends to the pointer"
    );
    let seal2b = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after conflicting old delivery");
    assert_eq!(vector_of(&seal2b).get("crawler"), Some(&2));

    // 6. Skipping requires verified lineage: revision 4 cannot arrive before
    //    revision 3 exists anywhere in the journal.
    let value4 = crawler_value(4, "fourth");
    let revision4 = revision_with(4, 3, value4.clone(), json!({}));
    let sequence_before_skip = journal_last_sequence(store, install_grant);
    let err = install_revision(store, artifacts, install_grant, &revision4)
        .expect_err("a gap in the predecessor chain must be refused");
    assert_eq!(err.code, "unverified_lineage");
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_skip,
        "an unverified skip never appends to the pointer"
    );
    let seal2c = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after lineage refusal");
    assert_eq!(vector_of(&seal2c).get("crawler"), Some(&2));

    // 7. Revision 3 becomes installable once its lineage is complete.
    let value3 = crawler_value(3, "third");
    let revision3 = revision_with(3, 2, value3.clone(), json!({}));
    let receipt3 = install_revision(store, artifacts, install_grant, &revision3)
        .expect("revision 3 must install");
    let seal3 = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after revision 3");
    assert_eq!(vector_of(&seal3).get("crawler"), Some(&3));

    // 8. An interrupted transfer installs bytes but fails verification before
    //    the pointer advance. The view stays complete at revision 3.
    let sequence_before_failed = journal_last_sequence(store, install_grant);
    artifacts.set_fail_reads(true);
    let err = install_revision(store, artifacts, install_grant, &revision4)
        .expect_err("an unverifiable transfer must not advance the pointer");
    assert_eq!(err.code, "artifact_verification_failed");
    artifacts.set_fail_reads(false);
    assert_eq!(
        journal_last_sequence(store, install_grant),
        sequence_before_failed,
        "an unverifiable transfer leaves the journal pointer at the last complete revision"
    );
    let seal3b = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after interrupted transfer");
    assert_eq!(
        vector_of(&seal3b).get("crawler"),
        Some(&3),
        "a partial transfer leaves the last complete revision visible"
    );
    let row3 = compose_row(&seal3b, &registration, &[copy(&receipt3)])
        .expect("row after interrupted transfer");
    assert_eq!(slot(&row3, "crawler")["snapshot"], value3);
    assert_eq!(slot(&row3, "downstream")["revision"], json!(0));

    // 9. The retried revision installs once the transfer is complete and the
    //    row is composed from complete snapshots only.
    let receipt4 = install_revision(store, artifacts, install_grant, &revision4)
        .expect("revision 4 installs after transfer succeeds");
    let seal4 = select_seal(
        store,
        seal_grant,
        &seal_request(json!(["crawler", "downstream"]), None),
    )
    .expect("seal after revision 4");
    assert_eq!(vector_of(&seal4).get("crawler"), Some(&4));
    let row4 = compose_row(&seal4, &registration, &[copy(&receipt4)])
        .expect("complete row at revision 4");
    assert_eq!(slot(&row4, "crawler")["revision"], json!(4));
    assert_eq!(slot(&row4, "crawler")["snapshot"], value4);

    // 10. Partial rows are refused. A seal that omits a declared domain can
    //     never compose a row, even when every published snapshot is present.
    let mut truncated = record_value(&seal4).clone();
    let entries = truncated["version_vector"]
        .as_array_mut()
        .expect("seal carries a vector array");
    entries.retain(|entry| entry["domain"] != json!("downstream"));
    let truncated = check("audit_log", truncated);
    let err = compose_row(&truncated, &registration, &[copy(&receipt4)])
        .expect_err("a seal without every declared domain is not a complete row");
    assert_eq!(err.code, "incomplete_row");

    // 11. A missing nonzero snapshot is not replaced by a zero slot.
    let zero_crawler = check(
        "audit_log",
        json!({"domain": "crawler", "revision": 0}),
    );
    let err = compose_row(&seal4, &registration, &[zero_crawler])
        .expect_err("zero must never replace published bytes");
    assert_eq!(err.code, "published_bytes_lost");

    let err = compose_row(&seal4, &registration, &[])
        .expect_err("omitting a published domain is a partial row");
    assert_eq!(err.code, "incomplete_row");

    // 12. The expected-vector guard detects a pointer that moved under an
    //     archived selection instead of pinning a mismatched state.
    let err = select_seal(
        store,
        seal_grant,
        &seal_request(
            json!(["crawler", "downstream"]),
            Some(json!([
                {"domain": "crawler", "revision": 3},
                {"domain": "downstream", "revision": 0},
            ])),
        ),
    )
    .expect_err("a stale expected vector must force reselection");
    assert_eq!(err.code, "view_changed");
}
