//! Conformance tests for `crawler_store`.
//!
//! * **[C07]** Durable contiguous ordering, deduplication, conflict detection,
//!   producer gaps, and late evidence retained.
//! * **[C22]** Two writers: product large writes/transfer cannot hold the
//!   ingest writer or require ingest acknowledgement.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{import_event, MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

const SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "store-clk",
        "boot_id": "boot-9",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

/// Receipt clock with a strictly increasing monotonic offset.
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

/// Manifest with an ingest writer domain, a product writer domain, and an
/// importer domain.
fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-1",
            "producer_registry": [
                {
                    "producer_id": "ingest",
                    "owner_domain": "crawler_ingest",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
                {
                    "producer_id": "product-writer",
                    "owner_domain": "product",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
                {
                    "producer_id": "importer",
                    "owner_domain": "crawler_ingest",
                    "role": "external_input",
                    "provenance": "importer",
                    "assertion_kind": "observation",
                },
            ],
            "event_registry": [
                {
                    "event_kind": "manifest_admitted",
                    "permitted_provenance": ["server"],
                },
                {
                    "event_kind": "listing_observed",
                    "permitted_provenance": ["server"],
                },
                {
                    "event_kind": "downstream_revision_installed",
                    "permitted_provenance": ["server"],
                },
                {
                    "event_kind": "producer_closed",
                    "permitted_provenance": ["server"],
                },
                {
                    "event_kind": "evidence_imported",
                    "permitted_provenance": ["importer"],
                },
            ],
        }),
    )
}

fn principal(manifest: &CheckedRecord, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn grant_for(manifest: &CheckedRecord, producer_id: &str, event_kind: &str) -> Grant {
    let principal = principal(manifest, producer_id);
    let submission = check("audit_log", json!({ "event_kind": event_kind }));
    authorize_producer(&principal, &submission, manifest).expect("producer grant must issue")
}

fn admission_tx(
    manifest: &CheckedRecord,
    journal_id: &str,
    run_id: &str,
    producer_id: &str,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "admit_manifest",
            "journal_id": journal_id,
            "run_id": run_id,
            "manifest": record_value(manifest).clone(),
            "principal": {
                "producer_id": producer_id,
                "manifest_digest": binding_of(manifest),
            },
        }),
    )
}

#[allow(clippy::too_many_arguments)]
fn append_tx(
    manifest: &CheckedRecord,
    journal_id: &str,
    producer_id: &str,
    producer_sequence: Value,
    event_kind: &str,
    data: Value,
    causal_refs: Value,
    artifact_refs: Value,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "append_event",
            "journal_id": journal_id,
            "principal": {
                "producer_id": producer_id,
                "manifest_digest": binding_of(manifest),
            },
            "submission": {
                "producer_sequence": producer_sequence,
                "event_kind": event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing("not_observed"),
                "payload": {
                    "data": data,
                    "measurements": [],
                    "evidence_refs": [],
                    "artifact_refs": artifact_refs,
                },
            },
            "causal_refs": causal_refs,
        }),
    )
}

fn simple_append(
    manifest: &CheckedRecord,
    journal_id: &str,
    producer_id: &str,
    producer_sequence: u64,
    event_kind: &str,
    data: Value,
) -> CheckedRecord {
    append_tx(
        manifest,
        journal_id,
        producer_id,
        json!(producer_sequence),
        event_kind,
        data,
        json!([]),
        json!([]),
    )
}

fn query(kind: &str, journal_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({ "query": kind, "journal_id": journal_id }),
    )
}

fn event_query(journal_id: &str, sequence: u64) -> CheckedRecord {
    check(
        "audit_log",
        json!({ "query": "event", "journal_id": journal_id, "journal_sequence": sequence }),
    )
}

fn event_reference(envelope: &Value) -> Value {
    json!({
        "journal_id": envelope["journal_id"],
        "sequence": envelope["journal_sequence"],
        "event_id": envelope["event_id"],
        "event_hash": envelope["event_hash"],
        "pointer": "",
    })
}

/// Recompute the kernel event hash: SHA-256 over canonical bytes with only
/// `event_hash` removed.
fn recompute_hash(envelope: &Value) -> String {
    let mut unsealed = envelope.clone();
    unsealed
        .as_object_mut()
        .expect("envelope must be an object")
        .remove("event_hash");
    let record = check("audit_log", unsealed);
    digest_bytes(&canonical_bytes(&record).expect("canonical bytes must exist"))
}

/// Verify contiguity, the hash chain, the admitted scope, and the manifest pin
/// of one journal.
fn assert_journal_chain(store: &MemoryOwnerStore, grant: &Grant, journal_id: &str, expected: u64) {
    let view = store
        .read(grant, &query("journal", journal_id))
        .expect("journal view must be readable");
    let view = record_value(&view);
    assert_eq!(
        view["last_sequence"],
        json!(expected),
        "journal {journal_id} must be contiguous and complete"
    );
    let events = view["events"].as_array().expect("events must be an array");
    assert_eq!(events.len() as u64, expected);
    let manifest_hash = store.manifest_hash().to_string();
    let run_id = events[0]["run_id"].clone();
    let mut previous: Option<Value> = None;
    for (index, event) in events.iter().enumerate() {
        let sequence = index as u64 + 1;
        assert_eq!(event["record_type"], json!("journal_event"));
        assert_eq!(
            event["journal_sequence"],
            json!(sequence),
            "sequences are contiguous and strictly increasing from 1"
        );
        match &previous {
            None => {
                assert_eq!(event["previous_event_hash"]["value"], Value::Null);
                assert_eq!(
                    event["previous_event_hash"]["reason"],
                    json!("not_applicable"),
                    "sequence 1 has no predecessor"
                );
            }
            Some(head) => assert_eq!(
                event["previous_event_hash"], *head,
                "event {sequence} must name the exact previous event hash"
            ),
        }
        assert_eq!(
            event["event_hash"],
            json!(recompute_hash(event)),
            "event {sequence} hash must cover its canonical bytes"
        );
        assert_eq!(event["manifest_hash"], json!(manifest_hash));
        assert_eq!(event["run_id"], run_id);
        assert_eq!(event["journal_id"], json!(journal_id));
        previous = Some(event["event_hash"].clone());
    }
    assert_eq!(view["head_hash"], previous.expect("nonempty journal"));
}

// ---------------------------------------------------------------------------
// [C07] Journal: durable contiguous ordering, deduplication, conflict
// detection, producer gaps, and late evidence retained.
// ---------------------------------------------------------------------------

#[test]
fn c07_journal_contiguous_dedup_conflict_gaps_late_evidence_retained() {
    let manifest = manifest_fixture();
    let store = MemoryOwnerStore::new(
        manifest_fixture(),
        Arc::new(FixedClock::new()),
        Arc::new(MemoryArtifactStore::new()),
    )
    .expect("store must admit its manifest");
    let grant = grant_for(&manifest, "ingest", "listing_observed");
    let journal = "journal-1";
    let run = "run-1";

    // --- Durable contiguous ordering; sequence 1 pins the manifest. ---
    let admission = record_value(
        &store
            .transact(&grant, &admission_tx(&manifest, journal, run, "ingest"))
            .expect("admission must commit"),
    )
    .clone();
    assert_eq!(admission["durable"], json!(true));
    assert_eq!(admission["disposition"], json!("appended"));
    assert_eq!(admission["journal_sequence"], json!(1));
    let pinned = &admission["event"];
    assert_eq!(pinned["event_kind"], json!("manifest_admitted"));
    assert_eq!(pinned["role"], json!("external_input"));
    assert_eq!(pinned["provenance"], json!("server"));
    assert_eq!(pinned["previous_event_hash"]["reason"], json!("not_applicable"));
    assert_eq!(pinned["manifest_hash"], json!(store.manifest_hash()));
    assert_eq!(
        pinned["payload"]["data"]["manifest"],
        record_value(&manifest).clone(),
        "sequence 1 pins the complete immutable manifest"
    );
    assert_eq!(
        pinned["payload"]["data"]["manifest_digest"],
        json!(binding_of(&manifest))
    );

    let second_admission = store
        .transact(&grant, &admission_tx(&manifest, journal, run, "ingest"))
        .expect_err("a journal admits its manifest exactly once");
    assert_eq!(second_admission.code, "journal_exists");

    // Producer sequence 1 is consumed by the admission itself.
    let second = record_value(
        &store
            .transact(
                &grant,
                &append_tx(
                    &manifest,
                    journal,
                    "ingest",
                    json!(2),
                    "listing_observed",
                    json!({"index": 2}),
                    json!([event_reference(pinned)]),
                    json!([]),
                ),
            )
            .expect("second event must commit"),
    )
    .clone();
    assert_eq!(second["journal_sequence"], json!(2));
    assert_eq!(second["previous_event_hash"], pinned["event_hash"]);
    assert_eq!(
        second["event"]["causal_refs"][0]["event_hash"],
        pinned["event_hash"],
        "earlier registered support is resolved and retained"
    );

    let third = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    3,
                    "listing_observed",
                    json!({"index": 3}),
                ),
            )
            .expect("third event must commit"),
    )
    .clone();
    assert_eq!(third["journal_sequence"], json!(3));
    assert_eq!(third["previous_event_hash"], second["event_hash"]);
    assert_journal_chain(&store, &grant, journal, 3);

    // Every later event names the admitted run/journal/manifest digest.
    let view = record_value(&store.read(&grant, &query("journal", journal)).expect("view"))
        .clone();
    for event in view["events"].as_array().expect("events") {
        assert_eq!(event["run_id"], json!(run));
        assert_eq!(event["journal_id"], json!(journal));
        assert_eq!(event["manifest_hash"], json!(store.manifest_hash()));
    }

    // Causal references must resolve to an earlier registered event.
    let bad_ref = json!([{
        "journal_id": journal,
        "sequence": 2,
        "event_id": "evt-2-not-the-real-id",
        "event_hash": second["event_hash"],
        "pointer": "",
    }]);
    let unresolved = store
        .transact(
            &grant,
            &append_tx(
                &manifest,
                journal,
                "ingest",
                json!(4),
                "listing_observed",
                json!({"index": 4}),
                bad_ref,
                json!([]),
            ),
        )
        .expect_err("an unresolved reference is refused");
    assert_eq!(unresolved.code, "unresolved_evidence_ref");
    assert_journal_chain(&store, &grant, journal, 3);

    // --- Deduplication without duplicated effects. ---
    let duplicate = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    2,
                    "listing_observed",
                    json!({"index": 2}),
                ),
            )
            .expect("identical delivery is idempotent"),
    )
    .clone();
    assert_eq!(duplicate["disposition"], json!("duplicate"));
    assert_eq!(duplicate["journal_sequence"], json!(2));
    assert_eq!(duplicate["head_hash"], second["head_hash"]);
    assert_journal_chain(&store, &grant, journal, 3);

    // --- Conflict detection under one producer key is an integrity incident. ---
    let conflict = store
        .transact(
            &grant,
            &simple_append(
                &manifest,
                journal,
                "ingest",
                2,
                "listing_observed",
                json!({"index": 999}),
            ),
        )
        .expect_err("conflicting content under one producer key is refused");
    assert_eq!(conflict.code, "producer_conflict");
    assert_journal_chain(&store, &grant, journal, 3);

    // --- Producer gaps are journaled when a sequence jump is observed. ---
    let jump = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    6,
                    "listing_observed",
                    json!({"index": 6}),
                ),
            )
            .expect("a forward sequence jump commits and journals its gap"),
    )
    .clone();
    assert_eq!(jump["journal_sequence"], json!(4));
    assert_eq!(jump["gap_detected"]["from_sequence"], json!(4));
    assert_eq!(jump["gap_detected"]["to_sequence"], json!(5));

    let view = record_value(&store.read(&grant, &query("journal", journal)).expect("view"))
        .clone();
    let producers = view["producers"].as_array().expect("producers");
    assert_eq!(producers.len(), 1);
    assert_eq!(producers[0]["producer_id"], json!("ingest"));
    assert_eq!(producers[0]["next_sequence"], json!(7));
    assert_eq!(producers[0]["gaps"][0]["from_sequence"], json!(4));
    assert_eq!(producers[0]["gaps"][0]["to_sequence"], json!(5));
    assert_eq!(producers[0]["gaps"][0]["detected_at"], json!(4));
    assert_eq!(producers[0]["gaps"][0]["unresolved"], json!([4, 5]));

    // --- Late evidence appends at the current head; the gap retains it. ---
    let late_four = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    4,
                    "listing_observed",
                    json!({"index": 4}),
                ),
            )
            .expect("late evidence is retained at the current head"),
    )
    .clone();
    assert_eq!(late_four["journal_sequence"], json!(5));
    assert_eq!(late_four["late_evidence"], json!(true));

    let late_five = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    5,
                    "listing_observed",
                    json!({"index": 5}),
                ),
            )
            .expect("late evidence is retained at the current head"),
    )
    .clone();
    assert_eq!(late_five["journal_sequence"], json!(6));

    let view = record_value(&store.read(&grant, &query("journal", journal)).expect("view"))
        .clone();
    let events = view["events"].as_array().expect("events");
    assert_eq!(
        events[1]["producer_sequence"],
        json!(2),
        "late evidence never rewrites an earlier prefix"
    );
    assert_eq!(events[3]["producer_sequence"], json!(6));
    assert_eq!(events[4]["producer_sequence"], json!(4));
    assert_eq!(events[4]["journal_sequence"], json!(5));
    let ingest = &view["producers"][0];
    assert_eq!(
        ingest["gaps"][0]["observed_late"],
        json!([
            {"producer_sequence": 4, "journal_sequence": 5},
            {"producer_sequence": 5, "journal_sequence": 6},
        ])
    );
    assert_eq!(ingest["gaps"][0]["unresolved"], json!([]));
    assert_eq!(ingest["late_evidence"], json!([5, 6]));
    assert_journal_chain(&store, &grant, journal, 6);

    // --- Producer closure is journaled; gaps remain and late fills still land. ---
    let reopened_gap = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    9,
                    "listing_observed",
                    json!({"index": 9}),
                ),
            )
            .expect("sequence 9 journals the gap 7..8"),
    )
    .clone();
    assert_eq!(reopened_gap["journal_sequence"], json!(7));
    assert_eq!(reopened_gap["gap_detected"]["from_sequence"], json!(7));

    let closure = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    10,
                    "producer_closed",
                    json!({"lost_sequences": [7, 8]}),
                ),
            )
            .expect("closure is a journaled event"),
    )
    .clone();
    assert_eq!(closure["journal_sequence"], json!(8));

    let after_closure = store
        .transact(
            &grant,
            &simple_append(
                &manifest,
                journal,
                "ingest",
                11,
                "listing_observed",
                json!({"index": 11}),
            ),
        )
        .expect_err("a closed producer lifetime accepts no new sequence");
    assert_eq!(after_closure.code, "producer_closed");

    let late_seven = record_value(
        &store
            .transact(
                &grant,
                &simple_append(
                    &manifest,
                    journal,
                    "ingest",
                    7,
                    "listing_observed",
                    json!({"index": 7}),
                ),
            )
            .expect("late evidence for a recorded gap survives closure"),
    )
    .clone();
    assert_eq!(late_seven["journal_sequence"], json!(9));
    assert_eq!(late_seven["late_evidence"], json!(true));

    let view = record_value(&store.read(&grant, &query("journal", journal)).expect("view"))
        .clone();
    let ingest = &view["producers"][0];
    assert_eq!(ingest["closed"], json!(true));
    assert_eq!(ingest["terminal_sequence"], json!(10));
    assert_eq!(
        ingest["gaps"][1]["observed_late"],
        json!([{"producer_sequence": 7, "journal_sequence": 9}])
    );
    assert_eq!(
        ingest["gaps"][1]["unresolved"],
        json!([8]),
        "gap 8 stays retained as missing evidence"
    );
    assert_journal_chain(&store, &grant, journal, 9);

    // The single-event read returns exactly the envelope at that sequence.
    let single = store
        .read(&grant, &event_query(journal, 5))
        .expect("event");
    let single = record_value(&single);
    assert_eq!(single["journal_sequence"], json!(5));
    assert_eq!(single["event_hash"], late_four["event_hash"]);

    // --- Cross-owner import retains original authority, never upgrades scope. ---
    let source = foreign_envelope(7, json!({"remote": "listing"}));
    let importer = grant_for(&manifest, "importer", "evidence_imported");
    let imported = record_value(
        &import_event(&store, &importer, &source).expect("verified foreign evidence imports"),
    )
    .clone();
    assert_eq!(imported["operation"], json!("import_event"));
    assert_eq!(imported["journal_sequence"], json!(1));
    let local = &imported["event"];
    assert_eq!(local["event_kind"], json!("evidence_imported"));
    assert_eq!(local["evidence_scope"], json!("historical_unscored"));
    assert_eq!(local["role"], json!("external_input"));
    assert_eq!(
        local["payload"]["data"]["source_event"],
        record_value(&source).clone(),
        "the imported record retains the source envelope verbatim"
    );
    assert_eq!(local["payload"]["data"]["source_sequence"], json!(7));
    assert_eq!(
        local["payload"]["data"]["source_journal_id"],
        json!("remote-journal")
    );
    assert_eq!(
        local["payload"]["data"]["source_evidence_scope"],
        json!("current_run"),
        "imported evidence retains its original scope as evidence"
    );

    let reimport = record_value(
        &import_event(&store, &importer, &source).expect("identical import is idempotent"),
    )
    .clone();
    assert_eq!(reimport["disposition"], json!("duplicate"));
    assert_eq!(reimport["journal_sequence"], json!(1));

    let different_source = foreign_envelope(7, json!({"remote": "different bytes"}));
    let import_conflict = import_event(&store, &importer, &different_source)
        .expect_err("different content under one source coordinate is an incident");
    assert_eq!(import_conflict.code, "import_conflict");

    let mut tampered = record_value(&source).as_object().cloned().expect("object");
    tampered.insert("payload".to_string(), json!({
        "data": {"remote": "edited after the fact"},
        "measurements": [],
        "evidence_refs": [],
        "artifact_refs": [],
    }));
    let tampered = check("audit_log", Value::Object(tampered));
    let digest_mismatch = import_event(&store, &importer, &tampered)
        .expect_err("edited foreign evidence fails its hash verification");
    assert_eq!(digest_mismatch.code, "import_digest_mismatch");

    assert_journal_chain(&store, &importer, "remote-journal", 1);
}

/// A well-formed foreign journal envelope, sealed over its canonical bytes.
fn foreign_envelope(source_sequence: u64, data: Value) -> CheckedRecord {
    let mut envelope = json!({
        "record_type": "journal_event",
        "schema_version": SCHEMA_VERSION,
        "run_id": "remote-run",
        "journal_id": "remote-journal",
        "manifest_hash": "a".repeat(64),
        "journal_sequence": source_sequence,
        "event_id": format!("remote-evt-{source_sequence}"),
        "event_kind": "listing_observed",
        "event_schema_version": SCHEMA_VERSION,
        "role": "external_input",
        "assertion_kind": "observation",
        "owner_domain": "remote-connector",
        "producer_id": "remote-producer",
        "producer_sequence": source_sequence,
        "provenance": "connector",
        "evidence_scope": "current_run",
        "recorded_at": timepoint(50),
        "occurred_at": missing("not_observed"),
        "causal_refs": [],
        "payload": {
            "data": data,
            "measurements": [],
            "evidence_refs": [],
            "artifact_refs": [],
        },
        "previous_event_hash": "b".repeat(64),
    });
    let hash = recompute_hash(&envelope);
    envelope["event_hash"] = Value::String(hash);
    check("audit_log", envelope)
}

// ---------------------------------------------------------------------------
// [C22] Two writers: product large writes/transfer cannot hold the ingest
// writer or require ingest acknowledgement.
// ---------------------------------------------------------------------------

/// Artifact store that blocks `read` of one digest until released, standing in
/// for a large in-flight product transfer.
struct GatedArtifacts {
    inner: MemoryArtifactStore,
    gated_digest: String,
    entered: Mutex<Option<mpsc::Sender<()>>>,
    released: Mutex<bool>,
    release: Condvar,
}

impl GatedArtifacts {
    fn new(gated_digest: String) -> Self {
        Self {
            inner: MemoryArtifactStore::new(),
            gated_digest,
            entered: Mutex::new(None),
            released: Mutex::new(false),
            release: Condvar::new(),
        }
    }

    fn expect_entry(&self) -> mpsc::Receiver<()> {
        let (tx, rx) = mpsc::channel();
        *self.entered.lock().expect("entered lock") = Some(tx);
        rx
    }

    fn release_transfer(&self) {
        *self.released.lock().expect("release lock") = true;
        self.release.notify_all();
    }
}

impl ArtifactStore for GatedArtifacts {
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
        let digest = record_value(reference)["digest"]
            .as_str()
            .unwrap_or_default();
        if digest == self.gated_digest {
            if let Some(notify) = self.entered.lock().expect("entered lock").take() {
                let _ = notify.send(());
            }
            let mut released = self.released.lock().expect("release lock");
            while !*released {
                released = self.release.wait(released).expect("release wait");
            }
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

#[test]
fn c22_product_transfer_cannot_hold_ingest_writer_or_require_acknowledgement() {
    let manifest = manifest_fixture();
    let large_bytes = vec![7u8; 1 << 20];
    let large_digest = digest_bytes(&large_bytes);
    let artifacts = Arc::new(GatedArtifacts::new(large_digest.clone()));
    let store = Arc::new(
        MemoryOwnerStore::new(
            manifest_fixture(),
            Arc::new(FixedClock::new()),
            artifacts.clone(),
        )
        .expect("store must admit its manifest"),
    );

    let ingest_grant = Arc::new(grant_for(&manifest, "ingest", "listing_observed"));
    let product_grant = Arc::new(grant_for(&manifest, "product-writer", "downstream_revision_installed"));
    let ingest_journal = "ingest-journal";
    let product_journal = "product-journal";

    // Ingest writer: admitted manifest plus two operational events.
    let ingest_admission = record_value(
        &store
            .transact(
                &ingest_grant,
                &admission_tx(&manifest, ingest_journal, "run-1", "ingest"),
            )
            .expect("ingest journal admission"),
    )
    .clone();
    for sequence in 2..=3u64 {
        store
            .transact(
                &ingest_grant,
                &simple_append(
                    &manifest,
                    ingest_journal,
                    "ingest",
                    sequence,
                    "listing_observed",
                    json!({"index": sequence}),
                ),
            )
            .expect("ingest event commits");
    }

    // Product writer: its own admitted journal, in its own owner domain.
    let product_admission = record_value(
        &store
            .transact(
                &product_grant,
                &admission_tx(&manifest, product_journal, "product-run", "product-writer"),
            )
            .expect("product journal admission"),
    )
    .clone();
    assert_eq!(product_admission["journal_sequence"], json!(1));
    assert_eq!(product_admission["owner_domain"], json!("product"));

    // The product writer installs one large artifact under its own grant.
    let large_reference = artifacts
        .install(&product_grant, &large_bytes, "application/json", false)
        .expect("large artifact installs durably");
    assert_eq!(record_value(&large_reference)["digest"], json!(large_digest));

    let entered = artifacts.expect_entry();
    let (product_done_tx, product_done_rx) = mpsc::channel();
    let product_store = store.clone();
    let product_write_grant = grant_for(
        &manifest,
        "product-writer",
        "downstream_revision_installed",
    );
    let product_transaction = append_tx(
        &manifest,
        product_journal,
        "product-writer",
        json!(2),
        "downstream_revision_installed",
        json!({"revision": 1, "snapshot_bytes": large_bytes.len()}),
        json!([]),
        json!([record_value(&large_reference).clone()]),
    );
    let product_thread = thread::spawn(move || {
        let receipt = product_store.transact(&product_write_grant, &product_transaction);
        let _ = product_done_tx.send(receipt.map(|receipt| record_value(&receipt).clone()));
    });

    // The product commit is now parked inside its large artifact transfer.
    entered
        .recv_timeout(Duration::from_secs(20))
        .expect("product write must reach its artifact transfer");

    // The ingest writer must keep committing, with no ingest acknowledgement
    // from the product side and no shared writer lock.
    let (ingest_done_tx, ingest_done_rx) = mpsc::channel();
    let ingest_store = store.clone();
    let ingest_write_grant = grant_for(&manifest, "ingest", "listing_observed");
    let ingest_manifest = manifest_fixture();
    let ingest_thread = thread::spawn(move || {
        let mut receipts = Vec::new();
        for sequence in 4..=28u64 {
            let receipt = ingest_store
                .transact(
                    &ingest_write_grant,
                    &simple_append(
                        &ingest_manifest,
                        ingest_journal,
                        "ingest",
                        sequence,
                        "listing_observed",
                        json!({"index": sequence}),
                    ),
                )
                .expect("ingest commit must not wait for the product transfer");
            receipts.push(record_value(&receipt).clone());
        }
        let _ = ingest_done_tx.send(receipts);
    });

    let ingest_receipts = ingest_done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("ingest writer must commit while the product transfer is in flight");
    assert_eq!(ingest_receipts.len(), 25);
    assert!(
        product_done_rx.try_recv().is_err(),
        "the product commit must still be blocked; ingest did not require its acknowledgement"
    );

    // Reading the ingest journal is likewise not gated by the product writer.
    let ingest_view = record_value(
        &store
            .read(&ingest_grant, &query("journal", ingest_journal))
            .expect("ingest journal stays readable during the product transfer"),
    )
    .clone();
    assert_eq!(ingest_view["last_sequence"], json!(28));
    assert_eq!(ingest_view["owner_domain"], json!("crawler_ingest"));
    assert_eq!(
        ingest_view["head_hash"],
        ingest_receipts.last().expect("receipts")["event_hash"]
    );

    // Release the transfer; the product commit completes on its own journal.
    artifacts.release_transfer();
    let product_receipt = product_done_rx
        .recv_timeout(Duration::from_secs(20))
        .expect("the released product write must complete")
        .expect("product commit must succeed");
    product_thread.join().expect("product thread");
    ingest_thread.join().expect("ingest thread");

    assert_eq!(product_receipt["journal_sequence"], json!(2));
    assert_eq!(product_receipt["owner_domain"], json!("product"));
    assert_eq!(
        product_receipt["previous_event_hash"], product_admission["event_hash"],
        "the product chain continues from its own admitted prefix"
    );
    assert_ne!(product_receipt["previous_event_hash"], ingest_view["head_hash"]);

    // The product commit required no ingest event or acknowledgement.
    let ingest_after = record_value(
        &store
            .read(&ingest_grant, &query("journal", ingest_journal))
            .expect("ingest view"),
    )
    .clone();
    assert_eq!(
        ingest_after["last_sequence"],
        json!(28),
        "the product commit appends nothing to the ingest journal"
    );
    assert_eq!(ingest_after["head_hash"], ingest_view["head_hash"]);

    // Two independent writers commit concurrently on their own durability
    // boundaries; each journal stays contiguous.
    let ingest_writer = {
        let store = store.clone();
        let grant = grant_for(&manifest, "ingest", "listing_observed");
        let manifest = manifest_fixture();
        thread::spawn(move || {
            for sequence in 29..=48u64 {
                store
                    .transact(
                        &grant,
                        &simple_append(
                            &manifest,
                            ingest_journal,
                            "ingest",
                            sequence,
                            "listing_observed",
                            json!({"index": sequence}),
                        ),
                    )
                    .expect("ingest writer");
            }
        })
    };
    let product_writer = {
        let store = store.clone();
        let grant = grant_for(&manifest, "product-writer", "downstream_revision_installed");
        let manifest = manifest_fixture();
        thread::spawn(move || {
            for sequence in 3..=22u64 {
                store
                    .transact(
                        &grant,
                        &simple_append(
                            &manifest,
                            product_journal,
                            "product-writer",
                            sequence,
                            "downstream_revision_installed",
                            json!({"revision": sequence}),
                        ),
                    )
                    .expect("product writer");
            }
        })
    };
    ingest_writer.join().expect("ingest writer");
    product_writer.join().expect("product writer");

    assert_journal_chain(&store, &ingest_grant, ingest_journal, 48);
    assert_journal_chain(&store, &product_grant, product_journal, 22);

    // Writers are distinct owners: cross-owner writes and reads are refused.
    let cross_write = store
        .transact(
            &ingest_grant,
            &simple_append(
                &manifest,
                product_journal,
                "ingest",
                49,
                "listing_observed",
                json!({"index": 49}),
            ),
        )
        .expect_err("the ingest writer cannot write the product owner's journal");
    assert_eq!(cross_write.code, "unauthorized_owner");

    let cross_read = store
        .read(&product_grant, &query("journal", ingest_journal))
        .expect_err("the product writer cannot read the ingest owner's journal");
    assert_eq!(cross_read.code, "unauthorized_owner");

    // Ingest acknowledgements are never a precondition for a product commit:
    // the product journal's chain is complete and self-contained.
    let product_view = record_value(
        &store
            .read(&product_grant, &query("journal", product_journal))
            .expect("product view"),
    )
    .clone();
    assert_eq!(product_view["last_sequence"], json!(22));
    assert_eq!(product_view["owner_domain"], json!("product"));
    for event in product_view["events"].as_array().expect("events") {
        assert_eq!(event["owner_domain"], json!("product"));
        assert_eq!(event["manifest_hash"], json!(store.manifest_hash()));
    }
    assert_eq!(
        ingest_admission["event"]["owner_domain"],
        json!("crawler_ingest")
    );
}
