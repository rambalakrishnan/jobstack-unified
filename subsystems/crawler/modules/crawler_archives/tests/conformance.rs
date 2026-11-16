//! Conformance tests for [C20], [C21], and [C24] of Contract 04 §23.
//!
//! * **C20** — a changed fetch key commits the complete prior `LogicalRow` and
//!   retention protection together with the replacement.
//! * **C21** — a changed local downstream (or crawler) publication pointer
//!   forces reselection instead of committing a mismatched archive.
//! * **C24** — archive expansion reconstructs the exact complete row from local
//!   immutable extents.
//!
//! The tests drive the real owner journal (`MemoryOwnerStore`), the real
//! immutable artifact store (`MemoryArtifactStore`, wrapped only to count
//! installs), the real publication seam (`install_revision`, `select_seal`),
//! the real retention seam (`collect_unreachable`), and the module under test.

use crawler_archives::{expand_archive, replace_fetch_key};
use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_publication::{install_revision, select_seal};
use crawler_retention::collect_unreachable;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const JOURNAL: &str = "crawler-archives-journal";
const RUN: &str = "run-archives-1";
const PRODUCER: &str = "crawler-writer";
const OWNER: &str = "crawler";
const VIEW: &str = "ingest";
const SCHEMA_VERSION: &str = "owner-separated-write-domains/0.1.0";
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

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn entity() -> Value {
    json!({"entity": "job", "id": "job-1"})
}

fn registration_value() -> Value {
    json!({
        "entity": entity(),
        "registration_digest": REGISTRATION_DIGEST,
        "domains": ["crawler", "downstream"],
        "identity": {"job_id": "job-1", "source": "example"},
    })
}

/// Deterministic 64-hex fetch key / digest text for a single hex digit.
fn hexkey(digit: char) -> String {
    std::iter::repeat(digit).take(64).collect()
}

fn crawler_value(revision: u64, key: &str, marker: &str, lineage: Value) -> Value {
    json!({
        "acquisition": {
            "status": "complete",
            "fetch_key": key,
            "fetch_identity": {
                "phase_token": "B",
                "canonical_request": {
                    "url": "https://example.test/jobs/1",
                    "method": "GET",
                    "body_hash": missing("not_applicable", "GET has no body"),
                    "header_identity_set": [],
                },
            },
            "evidence": format!("acquisition-evidence-{revision}"),
        },
        "processing": {"pipeline_state": "materialized", "marker": marker},
        "discovery": {"coverage_refs": [format!("coverage-{revision}")]},
        "replacement_lineage": lineage,
    })
}

fn downstream_value(revision: u64, marker: &str) -> Value {
    json!({
        "domain": "downstream",
        "revision": revision,
        "marker": marker,
        "payload": {"title": format!("job title {revision}"), "state": "complete"},
    })
}

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "archives-clock",
        "boot_id": "boot-1",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed", "no UTC annotation"),
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

/// Real immutable store wrapped only to count installs, so the same-key no-op
/// can assert that no archive extent was even staged.
struct CountingArtifacts {
    inner: MemoryArtifactStore,
    installs: AtomicU64,
    reads: AtomicU64,
}

impl CountingArtifacts {
    fn new() -> Self {
        Self {
            inner: MemoryArtifactStore::new(),
            installs: AtomicU64::new(0),
            reads: AtomicU64::new(0),
        }
    }

    fn installs(&self) -> u64 {
        self.installs.load(Ordering::SeqCst)
    }
}

impl ArtifactStore for CountingArtifacts {
    fn install(
        &self,
        grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        restricted: bool,
    ) -> Result<CheckedRecord, Fault> {
        self.installs.fetch_add(1, Ordering::SeqCst);
        self.inner.install(grant, bytes, media_type, restricted)
    }

    fn read(&self, grant: &Grant, reference: &CheckedRecord) -> Result<Vec<u8>, Fault> {
        self.reads.fetch_add(1, Ordering::SeqCst);
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
            "manifest_id": "manifest-archives-1",
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
                {"event_kind": "fetch_key_replacement", "permitted_provenance": ["server"]},
                {"event_kind": "retention_recorded", "permitted_provenance": ["server"]},
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
    artifacts: Arc<CountingArtifacts>,
    /// One registry-derived writer grant authors publications, the seal
    /// selection, and the replacement: the crawler's local ingest-side view
    /// writer is the owner that reads back the documents it archives.
    writer_grant: Grant,
    retention_grant: Grant,
}

fn fixture() -> Fixture {
    let manifest = manifest_fixture();
    let artifacts = Arc::new(CountingArtifacts::new());
    let artifacts_dyn: Arc<dyn ArtifactStore> = artifacts.clone();
    let store = MemoryOwnerStore::new(copy(&manifest), Arc::new(FixedClock::new()), artifacts_dyn)
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
    let writer_grant = grant_for(&manifest, "fetch_key_replacement");
    let retention_grant = grant_for(&manifest, "retention_recorded");
    Fixture {
        store,
        artifacts,
        writer_grant,
        retention_grant,
    }
}

fn revision_request(domain: &str, revision: u64, previous: u64, value: Value) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "journal_id": JOURNAL,
            "view": VIEW,
            "entity": entity(),
            "registration_digest": REGISTRATION_DIGEST,
            "domain": domain,
            "owner_domain": OWNER,
            "writer_id": "writer-1",
            "revision": revision,
            "previous_revision": previous,
            "value": value,
            "evidence_refs": [],
        }),
    )
}

fn publish(
    fx: &Fixture,
    domain: &str,
    revision: u64,
    previous: u64,
    value: Value,
) -> CheckedRecord {
    install_revision(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &revision_request(domain, revision, previous, value),
    )
    .expect("domain revision must publish")
}

fn seal_request() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "journal_id": JOURNAL,
            "view": VIEW,
            "entity": entity(),
            "registration_digest": REGISTRATION_DIGEST,
            "domains": ["crawler", "downstream"],
            "seal_name": "fetch_key_replacement",
            "support": [],
        }),
    )
}

fn replace_request(new_revision: u64, new_previous: u64, new_value: Value) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "journal_id": JOURNAL,
            "view": VIEW,
            "entity": entity(),
            "registration": registration_value(),
            "registration_digest": REGISTRATION_DIGEST,
            "new_crawler": {
                "record_type": "owned_domain_revision",
                "schema_version": SCHEMA_VERSION,
                "entity": entity(),
                "registration_digest": REGISTRATION_DIGEST,
                "domain": "crawler",
                "owner_domain": OWNER,
                "writer_id": "writer-1",
                "revision": new_revision,
                "previous_revision": new_previous,
                "evidence_refs": [],
                "value": new_value,
            },
        }),
    )
}

fn with_field(mut request: CheckedRecord, field: &str, value: Value) -> CheckedRecord {
    let mut map = record_value(&request).clone();
    map.as_object_mut()
        .expect("request must be an object")
        .insert(field.to_string(), value);
    request = check("audit_log", map);
    request
}

fn journal(fx: &Fixture) -> Value {
    let query = check(
        "audit_log",
        json!({"query": "journal", "journal_id": JOURNAL}),
    );
    record_value(
        &fx.store
            .read(&fx.writer_grant, &query)
            .expect("journal must read"),
    )
    .clone()
}

fn prefix_sequence(fx: &Fixture) -> u64 {
    let query = check(
        "audit_log",
        json!({"query": "prefix", "journal_id": JOURNAL}),
    );
    let prefix = fx
        .store
        .read(&fx.writer_grant, &query)
        .expect("prefix must read");
    record_value(&prefix)["last_sequence"]
        .as_u64()
        .expect("prefix carries its last sequence")
}

fn journal_event(fx: &Fixture, sequence: u64) -> CheckedRecord {
    let query = check(
        "audit_log",
        json!({
            "query": "event",
            "journal_id": JOURNAL,
            "journal_sequence": sequence,
        }),
    );
    fx.store
        .read(&fx.writer_grant, &query)
        .expect("journal event must read")
}

fn vector_revision(payload: &Value, domain: &str) -> u64 {
    payload["version_vector"]
        .as_array()
        .expect("row carries its sealed version vector")
        .iter()
        .find(|entry| entry["domain"] == json!(domain))
        .and_then(|entry| entry["revision"].as_u64())
        .expect("vector names every declared domain")
}

fn replacement_field(replacement: &CheckedRecord, field: &str) -> Value {
    record_value(replacement)[field].clone()
}

fn archive_of(replacement: &CheckedRecord) -> CheckedRecord {
    let value = record_value(replacement)
        .get("archive")
        .expect("committed replacement carries the complete archive")
        .clone();
    check("audit_log", value)
}

/// No replacement commit (and therefore no retention pin) landed after the
/// given journal sequence.
fn assert_no_replacement_committed_since(fx: &Fixture, since: u64) {
    let journal = journal(fx);
    for event in journal["events"].as_array().expect("events array") {
        let sequence = event["journal_sequence"].as_u64().expect("event sequence");
        if sequence <= since {
            continue;
        }
        let data = &event["payload"]["data"];
        assert!(
            data.get("fetch_key_replacement").is_none(),
            "a rejected replacement must never be journaled: {data}"
        );
        assert!(
            data.get("archive_retention_pin").is_none(),
            "a rejected replacement must never journal retention protection: {data}"
        );
    }
}

/// Installation order check: the archive root hashes canonical
/// storage-manifest bytes, not the expanded wrapper.
fn assert_root_hashes_canonical_manifest(archive: &CheckedRecord) {
    let value = record_value(archive);
    let manifest = check("audit_log", value["storage_manifest"].clone());
    let expected = digest_bytes(&canonical_bytes(&manifest).expect("canonical manifest"));
    assert_eq!(
        value["root"]["digest"],
        json!(expected),
        "archive root must be the digest of the canonical storage manifest"
    );
    assert_eq!(
        value["storage_manifest"]["encoding"],
        json!("owner-domain-extents/1")
    );
    assert_eq!(
        value["storage_manifest"]["schema_version"],
        json!(SCHEMA_VERSION)
    );
}

// ---------------------------------------------------------------------------
// C20 — changed key commits the full prior row and retention with replacement
// ---------------------------------------------------------------------------

#[test]
fn c20_changed_key_commits_complete_archive_and_retention_with_replacement() {
    let fx = fixture();
    let key_a = hexkey('a');
    let key_b = hexkey('b');
    let crawler1 = crawler_value(1, &key_a, "first", missing("not_applicable", "initial row"));
    let downstream1 = downstream_value(1, "first downstream");
    let crawler_receipt = publish(&fx, "crawler", 1, 0, crawler1.clone());
    let downstream_receipt = publish(&fx, "downstream", 1, 0, downstream1.clone());

    // A same-key write is an acquisition no-op: no archive, no replacement,
    // no staged extent.
    let installs_before = fx.artifacts.installs();
    let sequence_before = prefix_sequence(&fx);
    let noop = replace_request(
        2,
        1,
        crawler_value(2, &key_a, "same-key", missing("not_applicable", "x")),
    );
    let err = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &noop,
    )
    .expect_err("an identical fetch key is a no-op and never creates an archive");
    assert_eq!(err.code, "fetch_key_unchanged");
    assert_eq!(
        prefix_sequence(&fx),
        sequence_before,
        "a same-key no-op must not journal anything"
    );
    assert_eq!(
        fx.artifacts.installs(),
        installs_before,
        "a same-key no-op must not stage archive extents"
    );
    assert_no_replacement_committed_since(&fx, sequence_before);

    // The changed key commits: complete prior row + retention protection.
    let replacement = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &replace_request(
            2,
            1,
            crawler_value(
                2,
                &key_b,
                "replacement",
                missing("not_applicable", "authored by the archive commit"),
            ),
        ),
    )
    .expect("a changed fetch key must commit the replacement archive");

    // Receipt facts: old pin/key and the complete new revision.
    assert_eq!(
        replacement_field(&replacement, "record_type"),
        json!("fetch_key_replacement")
    );
    assert_eq!(
        replacement_field(&replacement, "old_crawler")["revision"],
        json!(1)
    );
    assert_eq!(
        replacement_field(&replacement, "old_crawler")["record_digest"],
        record_value(&crawler_receipt)["document_digest"]
    );
    assert_eq!(
        replacement_field(&replacement, "old_fetch_key"),
        json!(key_a)
    );
    assert_eq!(
        replacement_field(&replacement, "archived_vector"),
        json!({"crawler": 1, "downstream": 1})
    );
    let replacement_id = replacement_field(&replacement, "replacement_id")
        .as_str()
        .expect("replacement id is a string")
        .to_string();
    let root = replacement_field(&replacement, "archive_root");
    assert_eq!(
        replacement_field(&replacement, "new_crawler")["revision"],
        json!(2)
    );
    assert_eq!(
        replacement_field(&replacement, "new_crawler")["previous_revision"],
        json!(1)
    );
    assert_eq!(
        replacement_field(&replacement, "new_crawler")["value"]["replacement_lineage"]
            ["replacement_id"],
        json!(replacement_id)
    );
    assert_eq!(
        replacement_field(&replacement, "new_crawler")["value"]["replacement_lineage"]
            ["archive_root"]["digest"],
        root["digest"]
    );

    // The archive contains the entire prior logical row: registration, both
    // complete domain snapshots, publication references, and the seal vector.
    let archive = archive_of(&replacement);
    assert_root_hashes_canonical_manifest(&archive);
    let archive_value = record_value(&archive);
    let payload = &archive_value["payload_json"];
    assert_eq!(payload["record_type"], json!("logical_row"));
    assert_eq!(payload["registration"], registration_value());
    assert_eq!(payload["domains"]["crawler"]["revision"], json!(1));
    assert_eq!(payload["domains"]["crawler"]["snapshot"], crawler1);
    assert_eq!(payload["domains"]["downstream"]["revision"], json!(1));
    assert_eq!(payload["domains"]["downstream"]["snapshot"], downstream1);
    assert_eq!(
        payload["domains"]["crawler"]["snapshot"]["acquisition"]["fetch_key"],
        json!(key_a),
        "the archive holds the prior fetch key, never the replacement value"
    );
    for domain in ["crawler", "downstream"] {
        assert_eq!(
            payload["domains"][domain]["publication_ref"]["journal_id"],
            json!(JOURNAL)
        );
        assert!(payload["domains"][domain]["publication_ref"]["sequence"]
            .as_u64()
            .is_some_and(|sequence| sequence > 0));
    }
    assert_eq!(
        payload["domains"]["crawler"]["document_digest"],
        record_value(&crawler_receipt)["document_digest"]
    );
    assert_eq!(
        payload["domains"]["downstream"]["document_digest"],
        record_value(&downstream_receipt)["document_digest"]
    );
    assert_eq!(vector_revision(payload, "crawler"), 1);
    assert_eq!(vector_revision(payload, "downstream"), 1);
    assert_eq!(
        payload["seal_point"]["name"],
        json!("fetch_key_replacement")
    );
    assert_eq!(
        payload["seal_point"]["versions"],
        json!({"crawler": 1, "downstream": 1})
    );
    assert_eq!(
        payload["input_prefix"]["head_hash"],
        payload["seal_point"]["selection_event"]["event_hash"],
        "the row's input prefix includes the seal-selection event, not its own registration"
    );

    // The commit event is the replacement's evidence and carries the archive
    // root plus the active retention pin atomically.
    let commit_ref = replacement_field(&replacement, "commit_ref");
    let sequence = commit_ref["sequence"].as_u64().expect("commit sequence");
    let event = journal_event(&fx, sequence);
    let event_value = record_value(&event);
    let data = &event_value["payload"]["data"];
    assert_eq!(event_value["event_hash"], commit_ref["event_hash"]);
    assert_eq!(
        data["fetch_key_replacement"]["replacement_id"],
        json!(replacement_id)
    );
    assert_eq!(data["archive_root"]["digest"], root["digest"]);
    let pin_id = replacement_field(&replacement, "retention_pin_id");
    assert_eq!(data["archive_retention_pin"]["pin_id"], pin_id);
    assert_eq!(data["archive_retention_pin"]["state"], json!("active"));
    assert_eq!(
        data["archive_retention_pin"]["archive_root"]["digest"], root["digest"],
        "retention protection commits with the replacement, in the same event"
    );
    assert_eq!(
        replacement_field(&replacement, "evidence_prefix")["last_sequence"],
        json!(sequence)
    );

    // Transitive retention protection: GC cannot reclaim the root or any
    // immutable dependency of the live replacement.
    let registration_ref = archive_value["storage_manifest"]["registration"].clone();
    let crawler_doc = archive_value["storage_manifest"]["domains"]["crawler"]["document"].clone();
    let downstream_doc =
        archive_value["storage_manifest"]["domains"]["downstream"]["document"].clone();
    let candidates = vec![
        check("audit_log", root.clone()),
        check("audit_log", registration_ref),
        check("audit_log", crawler_doc),
        check("audit_log", downstream_doc),
    ];
    let mut fence = json!({
        "journal_id": JOURNAL,
        "last_sequence": sequence,
        "head_hash": commit_ref["event_hash"].clone(),
    });
    // The fence must equal the current journal prefix.
    let query = check(
        "audit_log",
        json!({"query": "prefix", "journal_id": JOURNAL}),
    );
    let prefix = fx
        .store
        .read(&fx.writer_grant, &query)
        .expect("prefix must read");
    fence["last_sequence"] = record_value(&prefix)["last_sequence"].clone();
    fence["head_hash"] = record_value(&prefix)["head_hash"].clone();
    let gc = collect_unreachable(
        &fx.store,
        &*fx.artifacts,
        &fx.retention_grant,
        &check(
            "audit_log",
            json!({
                "journal_id": JOURNAL,
                "fence": fence,
                "candidates": candidates
                    .iter()
                    .map(|candidate| record_value(candidate).clone())
                    .collect::<Vec<Value>>(),
            }),
        ),
    )
    .expect("fenced collection must evaluate against the committed pins");
    let gc_value = record_value(&gc);
    assert_eq!(
        gc_value["protected"]
            .as_array()
            .expect("protected array")
            .len(),
        4,
        "the live replacement pins the archive root and its whole closure"
    );
    assert_eq!(
        gc_value["collected"]
            .as_array()
            .expect("collected array")
            .len(),
        0
    );

    // Expansion of the committed archive equals payload_json exactly.
    let expanded = expand_archive(&*fx.artifacts, &fx.writer_grant, &archive)
        .expect("expansion of a committed archive must succeed");
    assert_eq!(
        record_value(&expanded),
        payload,
        "expansion reconstructs the exact complete prior row"
    );
}

// ---------------------------------------------------------------------------
// C21 — publication race forces reselection, never a mismatched archive
// ---------------------------------------------------------------------------

#[test]
fn c21_publication_race_forces_reselection_never_mismatched_archive() {
    let fx = fixture();
    let key_a = hexkey('a');
    let key_b = hexkey('b');
    let key_c = hexkey('c');
    let crawler1 = crawler_value(1, &key_a, "first", missing("not_applicable", "initial row"));
    let downstream1 = downstream_value(1, "first downstream");
    publish(&fx, "crawler", 1, 0, crawler1.clone());
    publish(&fx, "downstream", 1, 0, downstream1.clone());

    // A seal taken before the downstream pointer advances.
    let stale_downstream_seal = select_seal(&fx.store, &fx.writer_grant, &seal_request())
        .expect("seal selection must journal the pinned vector");
    let downstream2 = downstream_value(2, "second downstream");
    publish(&fx, "downstream", 2, 1, downstream2.clone());
    let sequence_before = prefix_sequence(&fx);

    let stale = with_field(
        replace_request(
            2,
            1,
            crawler_value(
                2,
                &key_b,
                "replacement",
                missing("not_applicable", "authored"),
            ),
        ),
        "archive_seal",
        record_value(&stale_downstream_seal).clone(),
    );
    let err = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &stale,
    )
    .expect_err("a changed downstream pointer must force reselection");
    assert_eq!(err.code, "publication_race");
    assert_eq!(
        prefix_sequence(&fx),
        sequence_before,
        "a rejected replacement must not append anything"
    );
    assert_no_replacement_committed_since(&fx, sequence_before);

    // Reselection pins the newly published downstream revision and succeeds.
    let first = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &replace_request(
            2,
            1,
            crawler_value(
                2,
                &key_b,
                "replacement",
                missing("not_applicable", "authored"),
            ),
        ),
    )
    .expect("reselection must archive the current pointers");
    let first_archive = archive_of(&first);
    let first_payload = &record_value(&first_archive)["payload_json"];
    assert_eq!(vector_revision(first_payload, "downstream"), 2);
    assert_eq!(first_payload["domains"]["downstream"]["revision"], json!(2));
    assert_eq!(
        first_payload["domains"]["downstream"]["snapshot"], downstream2,
        "the archive must contain the reselected downstream revision, never the stale one"
    );
    assert_eq!(first_payload["domains"]["crawler"]["snapshot"], crawler1);
    assert_eq!(
        record_value(&first)["archived_vector"],
        json!({"crawler": 1, "downstream": 2})
    );
    let first_id = record_value(&first)["replacement_id"].clone();

    // Publish the replacement's new crawler revision (asynchronous publish).
    let crawler2 = record_value(&first)["new_crawler"]["value"].clone();
    publish(&fx, "crawler", 2, 1, crawler2.clone());

    // A seal taken before the crawler pointer advances.
    let stale_crawler_seal = select_seal(&fx.store, &fx.writer_grant, &seal_request())
        .expect("seal selection must journal the pinned vector");
    let lineage3 = crawler2["replacement_lineage"].clone();
    let crawler3 = crawler_value(3, &key_b, "metadata-only", lineage3);
    publish(&fx, "crawler", 3, 2, crawler3.clone());
    let sequence_before = prefix_sequence(&fx);

    let stale_crawler = with_field(
        replace_request(
            4,
            3,
            crawler_value(4, &key_c, "third", missing("not_applicable", "authored")),
        ),
        "archive_seal",
        record_value(&stale_crawler_seal).clone(),
    );
    let err = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &stale_crawler,
    )
    .expect_err("a changed crawler pointer must force reselection");
    assert_eq!(err.code, "publication_race");
    assert_eq!(
        prefix_sequence(&fx),
        sequence_before,
        "a rejected replacement must not append anything"
    );
    assert_no_replacement_committed_since(&fx, sequence_before);

    // A stale explicit old pin is refused before any selection is journaled.
    let stale_old_pin = with_field(
        replace_request(
            4,
            3,
            crawler_value(4, &key_c, "third", missing("not_applicable", "authored")),
        ),
        "old_crawler",
        json!({"revision": 1, "record_digest": record_value(&first)["archive_root"]["digest"].clone()}),
    );
    let err = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &stale_old_pin,
    )
    .expect_err("a stale declared old pin must be refused");
    assert_eq!(err.code, "stale_old_crawler");
    assert_eq!(prefix_sequence(&fx), sequence_before);

    // Reselection archives the revision that is current at commit time.
    let second = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &replace_request(
            4,
            3,
            crawler_value(4, &key_c, "third", missing("not_applicable", "authored")),
        ),
    )
    .expect("reselection must archive the current crawler revision");
    let second_archive = archive_of(&second);
    let second_payload = &record_value(&second_archive)["payload_json"];
    assert_eq!(vector_revision(second_payload, "crawler"), 3);
    assert_eq!(vector_revision(second_payload, "downstream"), 2);
    assert_eq!(
        second_payload["domains"]["crawler"]["snapshot"], crawler3,
        "the archive must contain the reselected crawler revision"
    );
    assert_eq!(
        second_payload["domains"]["downstream"]["snapshot"],
        downstream2
    );
    assert_eq!(record_value(&second)["old_crawler"]["revision"], json!(3));
    assert_eq!(record_value(&second)["old_fetch_key"], json!(key_b));
    // The prior row still carries the earlier replacement's backward link, so
    // the retention closure reaches the earlier archive.
    assert_eq!(
        second_payload["domains"]["crawler"]["snapshot"]["replacement_lineage"]["replacement_id"],
        first_id
    );
    assert_eq!(
        second_payload["domains"]["crawler"]["snapshot"]["replacement_lineage"]["archive_root"]
            ["digest"],
        record_value(&first)["archive_root"]["digest"]
    );

    let expanded = expand_archive(&*fx.artifacts, &fx.writer_grant, &second_archive)
        .expect("expansion of the reselected archive must succeed");
    assert_eq!(record_value(&expanded), second_payload);
}

// ---------------------------------------------------------------------------
// C24 — archive expansion reconstructs the exact complete row
// ---------------------------------------------------------------------------

#[test]
fn c24_archive_expansion_reconstructs_exact_complete_row_from_local_extents() {
    let fx = fixture();
    let key_a = hexkey('a');
    let key_b = hexkey('b');
    let key_c = hexkey('c');
    let crawler1 = crawler_value(1, &key_a, "first", missing("not_applicable", "initial row"));
    publish(&fx, "crawler", 1, 0, crawler1.clone());

    let first = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &replace_request(
            2,
            1,
            crawler_value(
                2,
                &key_b,
                "replacement",
                missing("not_applicable", "authored"),
            ),
        ),
    )
    .expect("a changed key commits even with no downstream publication");
    let archive1 = archive_of(&first);
    let archive1_value = record_value(&archive1);
    let payload1 = archive1_value["payload_json"].clone();

    // The unpublished downstream slot is exact typed missingness, never a
    // default body.
    assert_eq!(payload1["domains"]["downstream"]["revision"], json!(0));
    assert!(
        is_missing(&payload1["domains"]["downstream"]["snapshot"]),
        "an unpublished domain must stay a typed Missing slot"
    );
    assert!(
        payload1["domains"]["downstream"].get("document").is_none()
            || is_missing(&payload1["domains"]["downstream"]["document"])
    );
    assert_eq!(
        archive1_value["storage_manifest"]["domains"]["downstream"]["revision"],
        json!(0)
    );
    assert!(
        is_missing(&archive1_value["storage_manifest"]["domains"]["downstream"]["value"]),
        "an unpublished extent must preserve exact typed Missing"
    );

    // Expansion from the complete archive equals payload_json exactly.
    let expanded1 = expand_archive(&*fx.artifacts, &fx.writer_grant, &archive1)
        .expect("expansion from the archive record must succeed");
    assert_eq!(
        record_value(&expanded1),
        &payload1,
        "expansion must equal the archived payload exactly"
    );

    // Publishing a downstream revision afterwards cannot change history:
    // expansion from the root reference never consults current state.
    let downstream1 = downstream_value(1, "first downstream");
    publish(&fx, "downstream", 1, 0, downstream1.clone());
    let root1 = check("audit_log", archive1_value["root"].clone());
    let expanded_after = expand_archive(&*fx.artifacts, &fx.writer_grant, &root1)
        .expect("expansion from the root reference must succeed");
    assert_eq!(
        record_value(&expanded_after),
        &payload1,
        "expansion never upgrades to the latest downstream revision"
    );
    assert!(is_missing(
        &record_value(&expanded_after)["domains"]["downstream"]["snapshot"]
    ));

    // A second replacement archives a row with both domains published.
    let crawler2 = record_value(&first)["new_crawler"]["value"].clone();
    publish(&fx, "crawler", 2, 1, crawler2.clone());
    let second = replace_fetch_key(
        &fx.store,
        &*fx.artifacts,
        &fx.writer_grant,
        &fx.retention_grant,
        &replace_request(
            3,
            2,
            crawler_value(3, &key_c, "third", missing("not_applicable", "authored")),
        ),
    )
    .expect("second replacement must commit");
    let archive2 = archive_of(&second);
    let archive2_value = record_value(&archive2);
    let payload2 = archive2_value["payload_json"].clone();
    assert_eq!(payload2["domains"]["crawler"]["revision"], json!(2));
    assert_eq!(payload2["domains"]["crawler"]["snapshot"], crawler2);
    assert_eq!(payload2["domains"]["downstream"]["revision"], json!(1));
    assert_eq!(payload2["domains"]["downstream"]["snapshot"], downstream1);
    assert_eq!(payload2["registration"], registration_value());

    let expanded2 = expand_archive(&*fx.artifacts, &fx.writer_grant, &archive2)
        .expect("expansion of the second archive must succeed");
    assert_eq!(
        record_value(&expanded2),
        &payload2,
        "expansion reconstructs the exact complete row from immutable extents"
    );

    // The reconstruction is derived from the extents, never copied from the
    // wrapper: an altered payload_json is an integrity incident.
    let mut tampered = archive2_value.clone();
    tampered["payload_json"]["domains"]["crawler"]["snapshot"]["processing"]["pipeline_state"] =
        json!("tampered");
    let tampered = check("audit_log", tampered);
    let err = expand_archive(&*fx.artifacts, &fx.writer_grant, &tampered)
        .expect_err("expansion must never trust payload_json over the extents");
    assert_eq!(err.code, "archive_integrity");

    // A lost or fabricated extent is an integrity fault, never a default fill.
    let mut broken_manifest = archive2_value["storage_manifest"].clone();
    broken_manifest["domains"]["downstream"]["document"]["digest"] = json!(hexkey('f'));
    let broken_manifest = check("audit_log", broken_manifest);
    let broken_bytes = canonical_bytes(&broken_manifest).expect("canonical broken manifest");
    let broken_root = fx
        .artifacts
        .install(&fx.writer_grant, &broken_bytes, "application/json", false)
        .expect("broken manifest bytes install as an inert orphan extent");
    let err = expand_archive(&*fx.artifacts, &fx.writer_grant, &broken_root)
        .expect_err("a lost extent must fault instead of fabricating content");
    assert_eq!(err.code, "bytes_unavailable");
}
