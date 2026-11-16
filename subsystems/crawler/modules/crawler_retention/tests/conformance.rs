//! Conformance tests for [C25]: retention race.
//!
//! Transitive dependency cannot be collected while any root reaches it, a
//! concurrent pin creation invalidates a collection plan instead of racing its
//! deletion boundary, and release/GC refuse TTL, cache, and identity-mutation
//! shortcuts.
//!
//! The tests drive the real owner journal (`MemoryOwnerStore`) and immutable
//! artifact store (`MemoryArtifactStore`); only the deterministic pin-versus-GC
//! interleave wraps the journal to inject the concurrent commit at the exact
//! snapshot/deletion boundary.

use crawler_artifacts::{ArtifactStore, MemoryArtifactStore};
use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_retention::{collect_unreachable, plan_retention_pin, release_pin};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

const JOURNAL: &str = "crawler-retention-journal";
const RUN: &str = "run-retention-1";
const SCHEMA_VERSION: &str = "owner-separated-write-domains/0.1.0";
const PRODUCER: &str = "retention-writer";

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

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": "retention-clk",
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

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-retention-1",
            "producer_registry": [
                {
                    "producer_id": PRODUCER,
                    "owner_domain": "crawler",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": "retention_recorded", "permitted_provenance": ["server"]},
                {"event_kind": "retention_released", "permitted_provenance": ["server"]},
                {"event_kind": "root_retired", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn foreign_manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-retention-foreign",
            "producer_registry": [
                {
                    "producer_id": "downstream-writer",
                    "owner_domain": "downstream",
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "retention_released", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn principal_of(manifest: &CheckedRecord, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn grant_for(manifest: &CheckedRecord, producer_id: &str, event_kind: &str) -> Grant {
    let principal = principal_of(manifest, producer_id);
    let submission = check("audit_log", json!({"event_kind": event_kind}));
    authorize_producer(&principal, &submission, manifest).expect("producer grant must issue")
}

struct Fixture {
    store: MemoryOwnerStore,
    artifacts: Arc<MemoryArtifactStore>,
    manifest: CheckedRecord,
    record_grant: Grant,
    release_grant: Grant,
    retire_grant: Grant,
}

fn fixture() -> Fixture {
    let manifest = manifest_fixture();
    let artifacts = Arc::new(MemoryArtifactStore::new());
    let store = MemoryOwnerStore::new(
        copy(&manifest),
        Arc::new(FixedClock::new()),
        artifacts.clone(),
    )
    .expect("owner store must admit its manifest");
    let record_grant = grant_for(&manifest, PRODUCER, "retention_recorded");
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
        .transact(&record_grant, &admission)
        .expect("journal admission must commit");
    Fixture {
        store,
        artifacts,
        manifest,
        record_grant,
        release_grant: grant_for(&manifest_fixture(), PRODUCER, "retention_released"),
        retire_grant: grant_for(&manifest_fixture(), PRODUCER, "root_retired"),
    }
}

fn foreign_grant() -> Grant {
    grant_for(&foreign_manifest_fixture(), "downstream-writer", "retention_released")
}

fn append_tx(
    manifest: &CheckedRecord,
    producer_id: &str,
    event_kind: &str,
    data: Value,
    causal_refs: Value,
) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "operation": "append_event",
            "journal_id": JOURNAL,
            "principal": {
                "producer_id": producer_id,
                "manifest_digest": binding_of(manifest),
            },
            "submission": {
                "producer_sequence": missing("not_applicable"),
                "event_kind": event_kind,
                "event_schema_version": SCHEMA_VERSION,
                "occurred_at": missing("not_observed"),
                "payload": {
                    "data": data,
                    "measurements": [],
                    "evidence_refs": causal_refs.clone(),
                    "artifact_refs": [],
                },
            },
            "causal_refs": causal_refs,
        }),
    )
}

fn append(
    store: &MemoryOwnerStore,
    grant: &Grant,
    manifest: &CheckedRecord,
    event_kind: &str,
    data: Value,
    causal_refs: Value,
) -> CheckedRecord {
    let transaction = append_tx(manifest, PRODUCER, event_kind, data, causal_refs);
    store
        .transact(grant, &transaction)
        .expect("journal append must commit")
}

fn install(artifacts: &MemoryArtifactStore, grant: &Grant, bytes: &[u8]) -> CheckedRecord {
    artifacts
        .install(grant, bytes, "application/json", false)
        .expect("artifact install must succeed")
}

fn dependent(root_id: &str, kind: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "entity": {"entity": "job", "id": "job-1"},
            "kind": kind,
            "root_id": root_id,
        }),
    )
}

fn reference(hex: char, size_bytes: u64, owner: &str) -> CheckedRecord {
    let digest: String = std::iter::repeat(hex).take(64).collect();
    check(
        "audit_log",
        json!({
            "digest": digest,
            "size_bytes": size_bytes,
            "media_type": "application/json",
            "owner_domain": owner,
            "access": "public",
        }),
    )
}

fn digest_of(reference: &CheckedRecord) -> String {
    record_value(reference)["digest"]
        .as_str()
        .expect("reference carries a digest")
        .to_string()
}

fn journal_pin(
    store: &MemoryOwnerStore,
    grant: &Grant,
    manifest: &CheckedRecord,
    pin: &CheckedRecord,
) {
    append(
        store,
        grant,
        manifest,
        "retention_recorded",
        json!({"retention_pin": record_value(pin).clone()}),
        json!([]),
    );
}

fn journal_retirement(
    store: &MemoryOwnerStore,
    grant: &Grant,
    manifest: &CheckedRecord,
    root_id: &str,
) -> Value {
    let receipt = append(
        store,
        grant,
        manifest,
        "root_retired",
        json!({"retirement": {"root_id": root_id, "retired": true}}),
        json!([]),
    );
    let map = record_value(&receipt);
    json!({
        "journal_id": map["journal_id"].clone(),
        "sequence": map["journal_sequence"].clone(),
        "event_id": map["event"]["event_id"].clone(),
        "event_hash": map["event_hash"].clone(),
        "pointer": "/payload/data/retirement",
    })
}

fn prefix_of(store: &dyn OwnerStore, grant: &Grant) -> Value {
    let query = check("audit_log", json!({"query": "prefix", "journal_id": JOURNAL}));
    let view = store.read(grant, &query).expect("prefix must read");
    json!({
        "journal_id": record_value(&view)["journal_id"].clone(),
        "last_sequence": record_value(&view)["last_sequence"].clone(),
        "head_hash": record_value(&view)["head_hash"].clone(),
    })
}

fn gc_request_with_fence(fence: &Value, candidates: &[CheckedRecord]) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "journal_id": JOURNAL,
            "fence": fence.clone(),
            "candidates": candidates
                .iter()
                .map(|reference| record_value(reference).clone())
                .collect::<Vec<_>>(),
        }),
    )
}

fn gc_request(
    store: &dyn OwnerStore,
    grant: &Grant,
    candidates: &[CheckedRecord],
) -> CheckedRecord {
    gc_request_with_fence(&prefix_of(store, grant), candidates)
}

fn release_request(pin: &CheckedRecord, root_id: &str, evidence: Vec<Value>) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "journal_id": JOURNAL,
            "pin": record_value(pin).clone(),
            "retirement": {
                "root_id": root_id,
                "retired": true,
                "evidence_refs": evidence,
            },
        }),
    )
}

fn digest_set(values: &Value) -> BTreeSet<String> {
    values
        .as_array()
        .expect("digest list must be an array")
        .iter()
        .filter_map(|value| value.get("digest").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn set_of(entries: &[String]) -> BTreeSet<String> {
    entries.iter().cloned().collect()
}

/// Deterministic pin-versus-delete interleave: the first journal read returns
/// the pre-pin snapshot, then a concurrent pin commit advances the prefix
/// before `collect_unreachable` reaches its deletion boundary.
struct RaceStore<'a> {
    inner: &'a MemoryOwnerStore,
    grant: &'a Grant,
    transaction: &'a CheckedRecord,
    armed: AtomicBool,
}

impl OwnerStore for RaceStore<'_> {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.inner.transact(grant, transaction)
    }

    fn read(&self, grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let view = self.inner.read(grant, query)?;
        let kind = record_value(query).get("query").and_then(Value::as_str);
        if kind == Some("journal") && self.armed.swap(false, Ordering::SeqCst) {
            self.inner.transact(self.grant, self.transaction)?;
        }
        Ok(view)
    }
}

// ---------------------------------------------------------------------------
// [C25] Transitive dependency cannot be collected while any root reaches it
// ---------------------------------------------------------------------------

#[test]
fn c25_transitive_dependencies_survive_gc_and_evidenced_release() {
    let fixture = fixture();
    let earlier = install(&fixture.artifacts, &fixture.record_grant, b"{\"archive\":\"earlier\"}");
    let shared = install(&fixture.artifacts, &fixture.record_grant, b"{\"extent\":\"shared\"}");
    let unrelated = install(&fixture.artifacts, &fixture.record_grant, b"{\"extent\":\"unrelated\"}");
    let later = install(&fixture.artifacts, &fixture.record_grant, b"{\"archive\":\"later\"}");

    let earlier_pin = plan_retention_pin(
        &dependent("root-earlier", "retained_archive"),
        &earlier,
        &[copy(&shared)],
    )
    .expect("earlier archive pin plans");
    journal_pin(
        &fixture.store,
        &fixture.record_grant,
        &fixture.manifest,
        &earlier_pin,
    );

    // A live replacement's backward link reaches the earlier archive, which in
    // turn reaches the shared immutable extent.
    let later_pin = plan_retention_pin(
        &dependent("root-live-replacement", "live_replacement"),
        &later,
        &[copy(&earlier)],
    )
    .expect("live replacement pin plans");
    journal_pin(
        &fixture.store,
        &fixture.record_grant,
        &fixture.manifest,
        &later_pin,
    );

    let result = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(
            &fixture.store,
            &fixture.record_grant,
            &[copy(&earlier), copy(&shared), copy(&unrelated)],
        ),
    )
    .expect("fenced GC must run");

    let earlier_digest = digest_of(&earlier);
    let shared_digest = digest_of(&shared);
    let unrelated_digest = digest_of(&unrelated);
    assert_eq!(
        digest_set(&record_value(&result)["collected"]),
        set_of(&[unrelated_digest.clone()]),
        "only the unreachable extent may be reclaimed"
    );
    assert_eq!(
        digest_set(&record_value(&result)["protected"]),
        set_of(&[earlier_digest.clone(), shared_digest.clone()]),
        "the reached archive and its transitive dependency stay protected"
    );
    assert!(
        fixture.artifacts.read(&fixture.record_grant, &earlier).is_ok(),
        "a reached archive root must still resolve"
    );
    assert!(
        fixture.artifacts.read(&fixture.record_grant, &shared).is_ok(),
        "a transitive dependency of a reached archive must still resolve"
    );
    assert!(
        fixture
            .artifacts
            .read(&fixture.record_grant, &unrelated)
            .is_err(),
        "the unreachable extent was reclaimed"
    );

    // Retire the earlier archive's redundant direct pin. The later retained
    // archive's backward link must keep the earlier archive and its dependency
    // reachable.
    let evidence = journal_retirement(
        &fixture.store,
        &fixture.retire_grant,
        &fixture.manifest,
        "root-earlier",
    );
    let released = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&earlier_pin, "root-earlier", vec![evidence.clone()]),
    )
    .expect("evidenced release must commit");
    let released_map = record_value(&released);
    assert_eq!(released_map["state"], json!("released"));
    assert_eq!(released_map["revision"], json!(2));
    assert_eq!(released_map["previous_revision"], json!(1));
    assert_eq!(
        released_map["dependent"],
        record_value(&earlier_pin)["dependent"],
        "release never rewrites the dependent identity"
    );
    assert_eq!(
        released_map["archive_root"],
        record_value(&earlier_pin)["archive_root"],
        "release never rewrites the archive identity"
    );
    let release_sequence = released_map["release_ref"]["sequence"]
        .as_u64()
        .expect("released pin cites its journal event");
    assert_eq!(
        released_map["evidence_prefix"]["last_sequence"],
        json!(release_sequence),
        "the release establishes the evidence prefix"
    );
    let journal_query = check("audit_log", json!({"query": "journal", "journal_id": JOURNAL}));
    let journal_view = fixture
        .store
        .read(&fixture.release_grant, &journal_query)
        .expect("journal reads");
    let events = record_value(&journal_view)["events"]
        .as_array()
        .expect("journal events");
    let release_event = events
        .get((release_sequence - 1) as usize)
        .expect("the release is journaled before acknowledgement");
    assert_eq!(
        release_event["event_hash"], released_map["release_ref"]["event_hash"],
        "the released revision cites the durable journal event"
    );

    let after = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(
            &fixture.store,
            &fixture.record_grant,
            &[copy(&earlier), copy(&shared)],
        ),
    )
    .expect("GC after release must run");
    assert!(
        digest_set(&record_value(&after)["collected"]).is_empty(),
        "releasing one root never releases bytes another root still reaches"
    );
    assert_eq!(
        digest_set(&record_value(&after)["protected"]),
        set_of(&[earlier_digest, shared_digest]),
        "the earlier archive and its dependency remain protected through the later archive"
    );
    assert!(fixture.artifacts.read(&fixture.record_grant, &earlier).is_ok());
    assert!(fixture.artifacts.read(&fixture.record_grant, &shared).is_ok());
}

#[test]
fn c25_gc_fence_refuses_pin_created_after_the_snapshot() {
    let fixture = fixture();
    let earlier = install(&fixture.artifacts, &fixture.record_grant, b"{\"archive\":\"earlier\"}");
    let unrelated = install(&fixture.artifacts, &fixture.record_grant, b"{\"extent\":\"unrelated\"}");
    let later = install(&fixture.artifacts, &fixture.record_grant, b"{\"archive\":\"later\"}");

    let earlier_pin = plan_retention_pin(
        &dependent("root-earlier", "retained_archive"),
        &earlier,
        &[],
    )
    .expect("earlier archive pin plans");
    journal_pin(
        &fixture.store,
        &fixture.record_grant,
        &fixture.manifest,
        &earlier_pin,
    );

    let fence = prefix_of(&fixture.store, &fixture.record_grant);
    let later_pin = plan_retention_pin(
        &dependent("root-live-replacement", "live_replacement"),
        &later,
        &[copy(&earlier)],
    )
    .expect("live replacement pin plans");
    let concurrent = append_tx(
        &fixture.manifest,
        PRODUCER,
        "retention_recorded",
        json!({"retention_pin": record_value(&later_pin).clone()}),
        json!([]),
    );
    let racing = RaceStore {
        inner: &fixture.store,
        grant: &fixture.record_grant,
        transaction: &concurrent,
        armed: AtomicBool::new(true),
    };

    let request = gc_request_with_fence(&fence, &[copy(&earlier), copy(&unrelated)]);
    let error = collect_unreachable(
        &racing,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &request,
    )
    .expect_err("a pin created after the snapshot must invalidate the plan");
    assert_eq!(error.code, "gc_fence_stale");
    assert!(
        fixture.artifacts.read(&fixture.record_grant, &earlier).is_ok(),
        "the raced plan deleted nothing; a live root never points at reclaimed content"
    );
    assert!(
        fixture
            .artifacts
            .read(&fixture.record_grant, &unrelated)
            .is_ok(),
        "a stale fence skips every candidate, not only protected ones"
    );

    // With the pin durably journaled, a fresh fence protects the reached archive
    // and still reclaims the unrelated extent.
    fixture
        .store
        .transact(&fixture.record_grant, &concurrent)
        .expect("the concurrent pin commit is durable");
    let result = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(
            &fixture.store,
            &fixture.record_grant,
            &[copy(&earlier), copy(&unrelated)],
        ),
    )
    .expect("fresh fenced GC must run");
    assert_eq!(
        digest_set(&record_value(&result)["protected"]),
        set_of(&[digest_of(&earlier)]),
        "the newly created pin protects its backward link"
    );
    assert_eq!(
        digest_set(&record_value(&result)["collected"]),
        set_of(&[digest_of(&unrelated)]),
        "the unrelated extent remains collectable"
    );
    assert!(fixture.artifacts.read(&fixture.record_grant, &earlier).is_ok());
}

// ---------------------------------------------------------------------------
// Release and GC guards
// ---------------------------------------------------------------------------

#[test]
fn c25_release_requires_evidence_and_immutable_identity() {
    let fixture = fixture();
    let archive = install(&fixture.artifacts, &fixture.record_grant, b"{\"archive\":\"live\"}");
    let pin = plan_retention_pin(
        &dependent("root-live-replacement", "live_replacement"),
        &archive,
        &[],
    )
    .expect("pin plans");
    journal_pin(
        &fixture.store,
        &fixture.record_grant,
        &fixture.manifest,
        &pin,
    );
    let evidence = journal_retirement(
        &fixture.store,
        &fixture.retire_grant,
        &fixture.manifest,
        "root-live-replacement",
    );

    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&pin, "root-live-replacement", vec![]),
    )
    .expect_err("release without evidence must fail");
    assert_eq!(error.code, "release_without_evidence");

    let mut ttl_request = record_value(&release_request(
        &pin,
        "root-live-replacement",
        vec![evidence.clone()],
    ))
    .as_object()
    .expect("release request")
    .clone();
    ttl_request.insert("ttl_seconds".to_string(), json!(0));
    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &check("audit_log", Value::Object(ttl_request)),
    )
    .expect_err("TTL is not retention authority");
    assert_eq!(error.code, "retention_policy_not_authority");

    let mut mutated = record_value(&pin).as_object().expect("pin").clone();
    let mut mutated_dependent = mutated["dependent"].as_object().expect("dependent").clone();
    mutated_dependent.insert("root_id".to_string(), json!("root-other"));
    mutated.insert("dependent".to_string(), Value::Object(mutated_dependent));
    let mutated = check("audit_log", Value::Object(mutated));
    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&mutated, "root-other", vec![evidence.clone()]),
    )
    .expect_err("pin identity is immutable");
    assert_eq!(error.code, "pin_identity_mutation");

    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&pin, "root-unrelated", vec![evidence.clone()]),
    )
    .expect_err("evidence must name this pin's dependent root");
    assert_eq!(error.code, "retirement_root_mismatch");

    let error = release_pin(
        &fixture.store,
        &foreign_grant(),
        &release_request(&pin, "root-live-replacement", vec![evidence.clone()]),
    )
    .expect_err("release never crosses the persistence domain");
    assert_eq!(error.code, "owner_mismatch");

    let mut initial_release = record_value(&pin).as_object().expect("pin").clone();
    initial_release.insert("state".to_string(), json!("released"));
    let initial_release = check("audit_log", Value::Object(initial_release));
    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&initial_release, "root-live-replacement", vec![evidence.clone()]),
    )
    .expect_err("a pin cannot be born released");
    assert_eq!(error.code, "pin_not_active");

    let released = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&pin, "root-live-replacement", vec![evidence]),
    )
    .expect("valid release must commit");
    assert_eq!(record_value(&released)["state"], json!("released"));
    let error = release_pin(
        &fixture.store,
        &fixture.release_grant,
        &release_request(&released, "root-live-replacement", vec![]),
    )
    .expect_err("release is terminal");
    assert_eq!(error.code, "pin_not_active");
}

#[test]
fn c25_plan_pins_the_complete_closure_deterministically() {
    let archive = reference('f', 10, "crawler");
    let dependency_a = reference('a', 20, "crawler");
    let dependency_b = reference('b', 30, "crawler");
    let dependent = check(
        "audit_log",
        json!({
            "entity": {"entity": "job", "id": "job-1"},
            "kind": "live_replacement",
            "root_id": "root-live-1",
            "writer_id": "writer-9",
        }),
    );
    let first = plan_retention_pin(
        &dependent,
        &archive,
        &[copy(&dependency_b), copy(&dependency_a)],
    )
    .expect("plan");
    let second = plan_retention_pin(
        &dependent,
        &archive,
        &[copy(&dependency_a), copy(&dependency_b)],
    )
    .expect("plan");
    assert_eq!(
        record_value(&first),
        record_value(&second),
        "identical plans are deterministic regardless of closure order"
    );
    let map = record_value(&first);
    assert_eq!(map["revision"], json!(1));
    assert_eq!(map["previous_revision"], json!(0));
    assert_eq!(map["state"], json!("active"));
    assert_eq!(map["owner_domain"], json!("crawler"));
    assert_eq!(map["writer_id"], json!("writer-9"));
    assert!(
        map["release_ref"]["value"].is_null(),
        "an active pin carries a typed Inapplicable release reference"
    );
    let dependencies = map["dependencies"].as_array().expect("dependencies");
    assert_eq!(dependencies.len(), 2);
    assert!(
        dependencies[0]["digest"].as_str().unwrap() < dependencies[1]["digest"].as_str().unwrap(),
        "the closure is emitted in digest order"
    );
    assert_eq!(dependencies[0]["digest"], json!(digest_of(&dependency_a)));
    assert_eq!(dependencies[1]["digest"], json!(digest_of(&dependency_b)));

    let no_writer = check(
        "audit_log",
        json!({
            "entity": {"entity": "job", "id": "job-1"},
            "kind": "retained_archive",
            "root_id": "root-earlier-1",
        }),
    );
    let planned = plan_retention_pin(&no_writer, &archive, &[]).expect("plan");
    assert_eq!(
        record_value(&planned)["writer_id"],
        json!("crawler:retention-authority"),
        "an unspecified writer names the persistence domain's retention authority"
    );

    let bad_kind = check(
        "audit_log",
        json!({"entity": {"entity": "job", "id": "job-1"}, "kind": "cache_entry", "root_id": "r"}),
    );
    assert_eq!(
        plan_retention_pin(&bad_kind, &archive, &[]).unwrap_err().code,
        "invalid_dependent_kind"
    );
    let bad_archive = check(
        "audit_log",
        json!({"digest": "nope", "size_bytes": 1, "media_type": "x", "owner_domain": "crawler", "access": "public"}),
    );
    assert_eq!(
        plan_retention_pin(&dependent, &bad_archive, &[])
            .unwrap_err()
            .code,
        "invalid_archive_root"
    );
    assert_eq!(
        plan_retention_pin(&dependent, &archive, &[copy(&archive)])
            .unwrap_err()
            .code,
        "self_dependency"
    );
    let no_entity = check(
        "audit_log",
        json!({"kind": "retained_archive", "root_id": "root-earlier-1"}),
    );
    assert_eq!(
        plan_retention_pin(&no_entity, &archive, &[]).unwrap_err().code,
        "missing_entity"
    );
}

#[test]
fn c25_lost_bytes_are_an_integrity_incident_not_successful_gc() {
    let fixture = fixture();
    let orphan = install(&fixture.artifacts, &fixture.record_grant, b"{\"extent\":\"orphan\"}");
    let orphan_digest = digest_of(&orphan);

    let first = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(&fixture.store, &fixture.record_grant, &[copy(&orphan)]),
    )
    .expect("an unreachable extent is collectable");
    assert_eq!(
        digest_set(&record_value(&first)["collected"]),
        set_of(&[orphan_digest])
    );

    let error = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(&fixture.store, &fixture.record_grant, &[copy(&orphan)]),
    )
    .expect_err("lost bytes are never a successful collection");
    assert_eq!(error.code, "bytes_unavailable");
    assert!(
        error.detail.contains("integrity incident"),
        "the fault names storage loss as an integrity incident: {}",
        error.detail
    );
}

#[test]
fn c25_gc_requires_a_current_fence_and_ignores_policy_shortcuts() {
    let fixture = fixture();
    let orphan = install(&fixture.artifacts, &fixture.record_grant, b"{\"extent\":\"orphan\"}");

    let unfenced = check(
        "audit_log",
        json!({"journal_id": JOURNAL, "candidates": [record_value(&orphan).clone()]}),
    );
    let error = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &unfenced,
    )
    .expect_err("an unfenced plan is refused");
    assert_eq!(error.code, "gc_fence_required");

    let mut shortcut = record_value(&gc_request(
        &fixture.store,
        &fixture.record_grant,
        &[copy(&orphan)],
    ))
    .as_object()
    .expect("GC request")
    .clone();
    shortcut.insert("cache_eviction".to_string(), json!(true));
    let error = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &check("audit_log", Value::Object(shortcut)),
    )
    .expect_err("cache eviction is not retention authority");
    assert_eq!(error.code, "retention_policy_not_authority");

    let mut newer = record_value(&gc_request(
        &fixture.store,
        &fixture.record_grant,
        &[copy(&orphan)],
    ))
    .as_object()
    .expect("GC request")
    .clone();
    newer.insert("newer_revision".to_string(), json!(7));
    let error = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &check("audit_log", Value::Object(newer)),
    )
    .expect_err("a newer publication revision is not retention authority");
    assert_eq!(error.code, "retention_policy_not_authority");

    let stale = gc_request(
        &fixture.store,
        &fixture.record_grant,
        &[copy(&orphan)],
    );
    journal_retirement(
        &fixture.store,
        &fixture.retire_grant,
        &fixture.manifest,
        "root-retired-unpinned",
    );
    let error = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &stale,
    )
    .expect_err("a fence that no longer matches the journal prefix is stale");
    assert_eq!(error.code, "gc_fence_stale");
    assert!(
        fixture
            .artifacts
            .read(&fixture.record_grant, &orphan)
            .is_ok(),
        "the stale plan reclaimed nothing"
    );

    let fresh = collect_unreachable(
        &fixture.store,
        fixture.artifacts.as_ref(),
        &fixture.record_grant,
        &gc_request(&fixture.store, &fixture.record_grant, &[orphan]),
    )
    .expect("a fresh fence collects the unreachable extent");
    assert_eq!(
        digest_set(&record_value(&fresh)["collected"]).len(),
        1
    );
}
