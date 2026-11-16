//! Conformance tests for `crawler_recovery`.
//!
//! * **[C44]** Recovery | Acknowledged work survives process/reboot model;
//!   proven partitions not refetched.
//!
//! The tests drive the real [`recover`] coordinator with a recording owner
//! store (prefix/event reads plus `lease_transition` commits), the real
//! authority-clock shape, the real fencing [`reclaim`], the real
//! [`expand_archive`], the real [`LocalPipeline`], and — for the session
//! test — the real [`MemoryOwnerStore`]/[`MemoryAdmission`]/
//! [`MemorySessionManager`] journal. Every assertion is about the module's
//! actual emitted receipt or its propagated fault; sibling targets and
//! unexpired leases are proven untouched.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_artifacts::MemoryArtifactStore;
use crawler_authority::{authorize_producer, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_pipeline::LocalPipeline;
use crawler_recovery::recover;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_sessions::{MemorySessionManager, SessionManager};
use crawler_store::{MemoryOwnerStore, OwnerStore};
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const CLOCK_ID: &str = "recovery-clk";
const BOOT_ID: &str = "boot-recovery";
const NEW_BOOT: &str = "boot-recovery-b";
const OWNER: &str = "crawler_worker";
const OWNER_DOMAIN: &str = "crawler_ingest";
const TARGET: &str = "target-1";
const SIBLING: &str = "target-2";
const JOURNAL: &str = "journal-recovery";
const HELD_LEASE: &str = "held-lease-1";

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn point_on(clock_id: &str, boot_id: &str, offset_ms: f64) -> Value {
    json!({
        "clock_id": clock_id,
        "boot_id": boot_id,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
    })
}

fn point(offset_ms: f64) -> Value {
    point_on(CLOCK_ID, BOOT_ID, offset_ms)
}

struct TestClock {
    clock_id: &'static str,
    boot_id: &'static str,
    offset_ms: f64,
}

impl TestClock {
    fn new(offset_ms: f64) -> Self {
        Self {
            clock_id: CLOCK_ID,
            boot_id: BOOT_ID,
            offset_ms,
        }
    }

    fn on_boot(offset_ms: f64, boot_id: &'static str) -> Self {
        Self {
            clock_id: CLOCK_ID,
            boot_id,
            offset_ms,
        }
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            point_on(self.clock_id, self.boot_id, self.offset_ms),
        )
    }
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes"))
}

fn manifest_simple() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-recovery",
            "producer_registry": [
                {
                    "producer_id": OWNER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
            ],
            "event_registry": [
                {"event_kind": "lease_reclaimed", "permitted_provenance": ["server"]},
                {"event_kind": "recovery_probe", "permitted_provenance": ["server"]},
            ],
        }),
    )
}

fn grant_simple() -> Grant {
    let manifest = manifest_simple();
    let principal = check(
        "audit_log",
        json!({
            "producer_id": OWNER,
            "manifest_digest": binding_of(&manifest),
        }),
    );
    let submission = check("audit_log", json!({"event_kind": "lease_reclaimed"}));
    authorize_producer(&principal, &submission, &manifest).expect("grant must issue")
}

/// Recording owner store: serves prefix/event/journal reads from a fixture and
/// accepts the fencing `lease_transition` transaction. Anything else faults.
struct TestStore {
    prefix_sequence: u64,
    prefix_head: String,
    events: HashMap<u64, Value>,
    transacts: Mutex<Vec<Value>>,
    fail_read: Mutex<Option<(String, String)>>,
    fail_transact: Mutex<Option<(String, String)>>,
}

impl TestStore {
    fn new(prefix_sequence: u64, prefix_head: &str, events: Vec<(u64, Value)>) -> Self {
        Self {
            prefix_sequence,
            prefix_head: prefix_head.to_string(),
            events: events.into_iter().collect(),
            transacts: Mutex::new(Vec::new()),
            fail_read: Mutex::new(None),
            fail_transact: Mutex::new(None),
        }
    }

    fn with_prefix(prefix_sequence: u64, prefix_head: &str) -> Self {
        Self::new(prefix_sequence, prefix_head, Vec::new())
    }

    fn transact_count(&self) -> usize {
        self.transacts.lock().expect("lock").len()
    }

    fn fail_reads(&self, code: &str, detail: &str) {
        *self.fail_read.lock().expect("lock") = Some((code.to_string(), detail.to_string()));
    }

    fn fail_transacts(&self, code: &str, detail: &str) {
        *self.fail_transact.lock().expect("lock") = Some((code.to_string(), detail.to_string()));
    }
}

impl OwnerStore for TestStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        if let Some((code, detail)) = self.fail_transact.lock().expect("lock").clone() {
            return Err(Fault { code, detail });
        }
        let value = record_value(transaction).clone();
        let operation = value.get("operation").and_then(Value::as_str).unwrap_or("");
        if operation != "lease_transition" {
            return Err(Fault {
                code: "unknown_operation".to_string(),
                detail: format!("test store accepts only lease_transition, got {operation:?}"),
            });
        }
        let mut calls = self.transacts.lock().expect("lock");
        calls.push(value);
        validate(
            "audit_log",
            json!({
                "durable": true,
                "acknowledged": true,
                "journal_sequence": calls.len(),
            }),
        )
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        if let Some((code, detail)) = self.fail_read.lock().expect("lock").clone() {
            return Err(Fault { code, detail });
        }
        let map = record_value(query).as_object().expect("query must be an object");
        let kind = map.get("query").and_then(Value::as_str).unwrap_or("");
        let journal_id = map.get("journal_id").and_then(Value::as_str).unwrap_or("");
        match kind {
            "prefix" => validate(
                "audit_log",
                json!({
                    "record_type": "journal_prefix",
                    "journal_id": journal_id,
                    "last_sequence": self.prefix_sequence,
                    "head_hash": self.prefix_head,
                }),
            ),
            "event" => {
                let sequence = map.get("journal_sequence").and_then(Value::as_u64).unwrap_or(0);
                match self.events.get(&sequence) {
                    Some(envelope) => validate("audit_log", envelope.clone()),
                    None => Err(Fault {
                        code: "unknown_event".to_string(),
                        detail: format!("journal {journal_id:?} has no event at sequence {sequence}"),
                    }),
                }
            }
            "journal" => {
                let mut sequences: Vec<u64> = self.events.keys().copied().collect();
                sequences.sort_unstable();
                let events: Vec<Value> = sequences
                    .iter()
                    .filter_map(|sequence| self.events.get(sequence).cloned())
                    .collect();
                validate(
                    "audit_log",
                    json!({
                        "record_type": "journal_view",
                        "journal_id": journal_id,
                        "last_sequence": self.prefix_sequence,
                        "head_hash": self.prefix_head,
                        "events": events,
                    }),
                )
            }
            _ => Err(Fault {
                code: "unknown_query".to_string(),
                detail: format!("query {kind:?} is not one of journal, prefix, event"),
            }),
        }
    }
}

struct RefusingAdmission;

impl Admission for RefusingAdmission {
    fn reserve_response(&self, _request: &CheckedRecord) -> Result<crawler_admission::ResponseCredit, Fault> {
        Err(Fault {
            code: "unexpected_admission".to_string(),
            detail: "this recovery path reserves no response credit".to_string(),
        })
    }

    fn reserve_control(&self, _scope: &CheckedRecord) -> Result<crawler_admission::ControlCredit, Fault> {
        Err(Fault {
            code: "unexpected_admission".to_string(),
            detail: "this recovery path reserves no control credit".to_string(),
        })
    }

    fn reserve_page(
        &self,
        _scope: &CheckedRecord,
        _control: bool,
    ) -> Result<crawler_admission::PagePermit, Fault> {
        Err(Fault {
            code: "unexpected_admission".to_string(),
            detail: "this recovery path reserves no page permit".to_string(),
        })
    }

    fn settle_response(
        &self,
        _credit: crawler_admission::ResponseCredit,
        _outcome: &CheckedRecord,
    ) -> Result<(), Fault> {
        Err(Fault {
            code: "unexpected_admission".to_string(),
            detail: "recovery never settles a response".to_string(),
        })
    }
}

struct UnusedSessions;

impl SessionManager for UnusedSessions {
    fn establish(
        &self,
        _grant: &Grant,
        _request: &CheckedRecord,
        _credit: &crawler_admission::ControlCredit,
    ) -> Result<crawler_sessions::LiveSession, Fault> {
        Err(Fault {
            code: "unexpected_session".to_string(),
            detail: "this recovery path establishes no session".to_string(),
        })
    }

    fn exchange(
        &self,
        _grant: &Grant,
        _request: &crawler_readonly::ReadOnlyRequest,
        _credit: &crawler_admission::ResponseCredit,
    ) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_session".to_string(),
            detail: "recovery never exchanges".to_string(),
        })
    }

    fn commit_boundary(&self, _grant: &Grant, _receipt: &CheckedRecord) -> Result<(), Fault> {
        Err(Fault {
            code: "unexpected_session".to_string(),
            detail: "recovery never commits a boundary".to_string(),
        })
    }

    fn retire(
        &self,
        _grant: &Grant,
        _request: &CheckedRecord,
        _credit: &crawler_admission::ControlCredit,
    ) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "unexpected_session".to_string(),
            detail: "recovery never retires".to_string(),
        })
    }
}

fn expect_fault<T: std::fmt::Debug>(result: Result<T, Fault>, code: &str) -> Fault {
    match result {
        Ok(value) => panic!("expected fault {code:?}, got success: {value:?}"),
        Err(error) => {
            assert_eq!(error.code, code, "fault detail: {}", error.detail);
            error
        }
    }
}

fn incident_base(journal_id: &str, trigger: &str, target: &str) -> Value {
    json!({
        "incident_id": "inc-1",
        "journal_id": journal_id,
        "trigger": trigger,
        "target": target,
    })
}

/// Complete claimable row (§5) in the requested operational state.
fn row(state: &str) -> Value {
    json!({
        "target": TARGET,
        "job_id": "job-1",
        "active_run_id": "run-1",
        "partition_id": "partition-1",
        "entity_revision": 4,
        "input_revision": 2,
        "retry_count": 0,
        "max_retries_effective": 3,
        "pipeline_state": state,
        "lease_id": missing("not_applicable"),
        "lease_owner": missing("not_applicable"),
        "leased_at": missing("not_applicable"),
        "lease_expires_at": missing("not_applicable"),
        "last_failure_reason": missing("not_applicable"),
        "created_at": point(800.0),
        "updated_at": point(900.0),
        "endpoint_id": "endpoint-b",
    })
}

fn held_row(state: &str) -> Value {
    let mut value = row(state);
    value["lease_id"] = json!(HELD_LEASE);
    value["lease_owner"] = json!(OWNER);
    value["leased_at"] = point(1000.0);
    value["lease_expires_at"] = point(1030.0);
    value
}

fn held_lease() -> Value {
    json!({
        "issuer": "lease-authority",
        "authority_epoch": 7,
        "owner": OWNER,
        "owner_epoch": 11,
        "generation_id": "gen-7-11",
        "policy_pin": "lease-policy-v1",
        "session_epoch": 3,
        "ttl_ms": 30.0,
        "lease_id": HELD_LEASE,
    })
}

fn expected_with(authority_epoch: u64) -> Value {
    json!({
        "entity_revision": 4,
        "input_revision": 2,
        "lease_id": HELD_LEASE,
        "authority_epoch": authority_epoch,
        "owner_epoch": 11,
        "session_epoch": 3,
    })
}

fn reclaim_entry(trigger: &str, authority_epoch: u64, failure_reason: Value) -> Value {
    json!({
        "operation": "reclaim",
        "entity_type": "work_item",
        "row": held_row("pending"),
        "lease": held_lease(),
        "expected": expected_with(authority_epoch),
        "reclaim": {
            "trigger": trigger,
            "failure_reason": failure_reason,
        },
    })
}

fn replay_command(packet_id: &str) -> Value {
    json!({
        "surface": "phase_a_full_description",
        "before": {
            "durable_packet_id": packet_id,
            "durable_packets": [packet_id],
            "listings": [],
            "works": [],
            "details": [],
        },
        "transaction": {
            "stage": "extract",
            "packet_id": packet_id,
        },
    })
}

#[test]
fn c44_acknowledged_prefix_survives_restart() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;

    // Acknowledged prefix at sequence 3 with two pinned coordinates.
    let store = TestStore::new(
        3,
        "head-abc",
        vec![
            (1, json!({"event_id": "evt-1", "journal_sequence": 1})),
            (2, json!({"event_id": "evt-2", "journal_sequence": 2})),
            (3, json!({"event_id": "evt-3", "journal_sequence": 3})),
        ],
    );
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["expected_prefix"] = json!({"last_sequence": 3, "head_hash": "head-abc"});
    incident["acknowledged"] = json!([
        {"journal_sequence": 1, "event_id": "evt-1"},
        {"journal_sequence": 3, "event_id": "evt-3"},
    ]);
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("acknowledged work must survive restart");
    let value = record_value(&receipt);
    assert_eq!(value["record_type"], "recovery_receipt");
    assert_eq!(value["trigger"], "restart");
    assert_eq!(value["survived_prefix"]["last_sequence"], 3);
    assert_eq!(value["survived_prefix"]["head_hash"], "head-abc");
    assert_eq!(value["acknowledged_verified"], 2);
    assert_eq!(value["durable"], true);
    // The receipt revalidates through the closed gate: any null survives only
    // inside a typed Missing envelope (e.g. the clock's utc_annotation).
    validate("audit_log", value.clone()).expect("receipt must revalidate");

    // A short prefix proves the acknowledgement was lost: no receipt.
    let short = TestStore::new(
        2,
        "head-short",
        vec![
            (1, json!({"event_id": "evt-1", "journal_sequence": 1})),
            (2, json!({"event_id": "evt-2", "journal_sequence": 2})),
        ],
    );
    let mut incident = incident_base(JOURNAL, "reboot", TARGET);
    incident["expected_prefix"] = json!({"last_sequence": 3, "head_hash": "head-abc"});
    expect_fault(
        recover(
            &short,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "acknowledgement_lost",
    );

    // A missing acknowledged coordinate is lost even when the prefix matches.
    let gap = TestStore::new(
        3,
        "head-abc",
        vec![
            (1, json!({"event_id": "evt-1", "journal_sequence": 1})),
            (2, json!({"event_id": "evt-2", "journal_sequence": 2})),
        ],
    );
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["acknowledged"] = json!([{"journal_sequence": 3, "event_id": "evt-3"}]);
    expect_fault(
        recover(
            &gap,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "acknowledgement_lost",
    );

    // An event-id mismatch is not the acknowledged event.
    let mismatch = TestStore::new(
        3,
        "head-abc",
        vec![(1, json!({"event_id": "evt-other", "journal_sequence": 1}))],
    );
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["acknowledged"] = json!([{"journal_sequence": 1, "event_id": "evt-1"}]);
    expect_fault(
        recover(
            &mismatch,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "acknowledgement_lost",
    );
}

#[test]
fn c44_proven_partitions_not_refetched() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;
    let store = TestStore::with_prefix(1, "head-1");

    let mut incident = incident_base(JOURNAL, "reboot", TARGET);
    incident["proven_partitions"] = json!([
        {"partition_id": "p-proven-1", "status": "proven"},
        {"partition_id": "p-proven-2", "status": "proven"},
    ]);
    incident["incomplete_packets"] = json!([
        {"packet_id": "pkt-incomplete-1"},
    ]);
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("proven partitions survive reboot without refetch");
    let value = record_value(&receipt);
    let proven = value["proven"].as_array().expect("proven array");
    assert_eq!(proven.len(), 2);
    for entry in proven {
        assert_eq!(entry["status"], "proven");
        assert_eq!(entry["refetch"], false);
    }
    let replayable = value["replayable"].as_array().expect("replayable array");
    assert_eq!(replayable.len(), 1);
    assert_eq!(replayable[0]["packet_id"], "pkt-incomplete-1");
    assert_eq!(replayable[0]["replayable"], true);
    assert_eq!(replayable[0]["replayed"], false);
    // No lease effects were emitted for a pure coverage recovery.
    assert_eq!(store.transact_count(), 0);
}

#[test]
fn c44_proven_refetch_refused() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;
    let store = TestStore::with_prefix(1, "head-1");

    // An explicit refetch of a proven partition is refused.
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["proven_partitions"] = json!([
        {"partition_id": "p-proven-1", "status": "proven", "refetch": true},
    ]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "proven_refetch_refused",
    );

    // Smuggling a proven id through the incomplete set is the same violation.
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["proven_partitions"] = json!([
        {"partition_id": "p-proven-1", "status": "proven"},
    ]);
    incident["incomplete_packets"] = json!([
        {"packet_id": "p-proven-1"},
    ]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "proven_refetch_refused",
    );

    // Non-proven status does not belong in the proven pin.
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["proven_partitions"] = json!([
        {"partition_id": "p-1", "status": "incomplete"},
    ]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "invalid_provenance",
    );
}

#[test]
fn c44_incomplete_replays_idempotently_via_pipeline() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;
    let store = TestStore::with_prefix(1, "head-1");

    // An incomplete packet with a durable replay commits atomically.
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["incomplete_packets"] = json!([
        {"packet_id": "pkt-1", "replay": replay_command("pkt-1")},
        {"packet_id": "pkt-2"},
    ]);
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("incomplete packets replay idempotently");
    let value = record_value(&receipt);
    let replayable = value["replayable"].as_array().expect("replayable");
    assert_eq!(replayable.len(), 2);
    assert_eq!(replayable[0]["replayed"], true);
    assert_eq!(replayable[0]["effect"]["stage"], "extract");
    assert_eq!(replayable[0]["effect"]["packet_id"], "pkt-1");
    assert_eq!(replayable[1]["replayed"], false);
    assert_eq!(replayable[1]["replayable"], true);

    // A replay beyond the durable packet is refused before any effect.
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["incomplete_packets"] = json!([
        {"packet_id": "pkt-9", "replay": json!({
            "surface": "phase_a_full_description",
            "before": {
                "durable_packet_id": "pkt-1",
                "durable_packets": ["pkt-1"],
            },
            "transaction": {"stage": "extract", "packet_id": "pkt-9"},
        })},
    ]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "orphan_packet",
    );
}

#[test]
fn c44_worker_death_fenced_reclaim() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    // Recovery authority runs on a new boot; the old deadline is never compared.
    let clock = TestClock::on_boot(5000.0, NEW_BOOT);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;

    // Confirmed death with a newer authority epoch fences and reclaims once.
    let store = TestStore::with_prefix(1, "head-1");
    let mut incident = incident_base(JOURNAL, "worker_death", TARGET);
    incident["leases"] = json!([reclaim_entry(
        "death_recovery",
        8,
        json!("worker_death_confirmed"),
    )]);
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("confirmed death must fence and reclaim within lease bounds");
    let value = record_value(&receipt);
    let reclaimed = value["reclaimed"].as_array().expect("reclaimed");
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0]["row"]["retry_count"], 1);
    assert_eq!(reclaimed[0]["row"]["lease_id"]["reason"], "not_applicable");
    assert_eq!(reclaimed[0]["transition"]["previous_authority_epoch"], 7);
    assert_eq!(reclaimed[0]["transition"]["authority_epoch"], 8);
    assert_eq!(reclaimed[0]["transition"]["failed_generation_charged"], true);
    assert_eq!(store.transact_count(), 1);

    // Reusing the old epoch is not a fence: rejected with no effect.
    let store = TestStore::with_prefix(1, "head-1");
    let mut incident = incident_base(JOURNAL, "worker_death", TARGET);
    incident["leases"] = json!([reclaim_entry(
        "death_recovery",
        7,
        json!("worker_death_confirmed"),
    )]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "restart_not_fenced",
    );
    assert_eq!(store.transact_count(), 0);
}

#[test]
fn c44_storage_failure_no_acknowledgement() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;

    // Unavailable storage fails the prefix read: no receipt, no cursor advance.
    let store = TestStore::with_prefix(3, "head-abc");
    store.fail_reads("storage_unavailable", "the owner-local durable read failed");
    let incident = incident_base(JOURNAL, "restart", TARGET);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "storage_unavailable",
    );

    // A failed lease commit propagates; recovery never acknowledges it.
    let store = TestStore::with_prefix(1, "head-1");
    store.fail_transacts("storage_unavailable", "the owner-local durable append failed");
    let mut incident = incident_base(JOURNAL, "worker_death", TARGET);
    incident["leases"] = json!([reclaim_entry(
        "death_recovery",
        8,
        json!("worker_death_confirmed"),
    )]);
    let failing_clock = TestClock::on_boot(5000.0, NEW_BOOT);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &failing_clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "storage_unavailable",
    );
    assert_eq!(store.transact_count(), 0);
}

#[test]
fn c44_sibling_isolation() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::on_boot(5000.0, NEW_BOOT);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;

    // A sibling lease in a target-scoped incident is refused before any commit.
    let store = TestStore::with_prefix(1, "head-1");
    let mut sibling_row = held_row("pending");
    sibling_row["target"] = json!(SIBLING);
    let mut incident = incident_base(JOURNAL, "worker_death", TARGET);
    incident["leases"] = json!([{
        "operation": "reclaim",
        "entity_type": "work_item",
        "row": sibling_row,
        "lease": held_lease(),
        "expected": expected_with(8),
        "reclaim": {"trigger": "death_recovery", "failure_reason": "worker_death_confirmed"},
    }]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "cross_target_refused",
    );
    assert_eq!(
        store.transact_count(),
        0,
        "a sibling failure must leave this target's journal untouched"
    );

    // A sibling session is refused the same way, without reserving control.
    let store = TestStore::with_prefix(1, "head-1");
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["sessions"] = json!([{
        "target": SIBLING,
        "run_id": "run-1",
        "phase": "A",
        "shard_id": "shard-a",
        "journal_id": JOURNAL,
        "session_topology": "per_shard",
    }]);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "cross_target_refused",
    );
}

#[test]
fn c44_archive_verification_propagates_integrity() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;
    let store = TestStore::with_prefix(1, "head-1");

    // A locator alone is never promised content: the missing extent faults and
    // recovery issues no receipt.
    let mut incident = incident_base(JOURNAL, "reboot", TARGET);
    incident["archive_roots"] = json!([{
        "digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "size_bytes": 16,
    }]);
    let error = expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "missing_grant_binding",
    );
    assert!(
        error.detail.contains("archive storage manifest"),
        "fault must name the unverifiable extent: {}",
        error.detail
    );

    // No archives to verify is a successful no-op for that seam.
    let store = TestStore::with_prefix(1, "head-1");
    let incident = incident_base(JOURNAL, "reboot", TARGET);
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("empty archive set must succeed");
    assert_eq!(record_value(&receipt)["archives"].as_array().unwrap().len(), 0);
}

#[test]
fn c44_session_new_epoch_on_recovery() {
    // Real durable journal + admission + sessions: cold crash recovery journals
    // session_recovered with epoch + 1 and a fresh client, never the old one.
    let manifest = check(
        "audit_log",
        json!({
            "manifest_id": "manifest-recovery-sessions",
            "producer_registry": [
                {
                    "producer_id": "ingest",
                    "owner_domain": OWNER_DOMAIN,
                    "role": "external_input",
                    "provenance": "server",
                    "assertion_kind": "claim",
                },
                {
                    "producer_id": OWNER,
                    "owner_domain": OWNER_DOMAIN,
                    "role": "lifecycle_observation",
                    "provenance": "server",
                    "assertion_kind": "observation",
                },
            ],
            "event_registry": [
                {"event_kind": "manifest_admitted", "permitted_provenance": ["server"]},
                {"event_kind": "session_established", "permitted_provenance": ["server"]},
                {"event_kind": "session_recovered", "permitted_provenance": ["server"]},
                {"event_kind": "session_boundary_committed", "permitted_provenance": ["server"]},
                {"event_kind": "session_expired", "permitted_provenance": ["server"]},
                {"event_kind": "session_retired", "permitted_provenance": ["server"]},
            ],
        }),
    );
    let grant_for = |producer: &str, event_kind: &str| {
        let principal = check(
            "audit_log",
            json!({
                "producer_id": producer,
                "manifest_digest": binding_of(&manifest),
            }),
        );
        let submission = check("audit_log", json!({"event_kind": event_kind}));
        authorize_producer(&principal, &submission, &manifest).expect("grant must issue")
    };

    let clock = Arc::new(TestClock::new(1_000.0));
    let artifacts = Arc::new(MemoryArtifactStore::new());
    let manifest_for_store =
        validate("audit_log", record_value(&manifest).clone()).expect("manifest must revalidate");
    let store = Arc::new(
        MemoryOwnerStore::new(manifest_for_store, clock.clone(), artifacts.clone())
            .expect("owner store must admit its manifest"),
    );
    let admit_grant = grant_for("ingest", "manifest_admitted");
    store
        .transact(
            &admit_grant,
            &check(
                "audit_log",
                json!({
                    "operation": "admit_manifest",
                    "journal_id": JOURNAL,
                    "run_id": "run-1",
                    "manifest": record_value(&manifest).clone(),
                    "principal": {
                        "producer_id": "ingest",
                        "manifest_digest": binding_of(&manifest),
                    },
                }),
            ),
        )
        .expect("journal must admit its manifest");

    let worker_grant = grant_for(OWNER, "session_established");
    let admission = MemoryAdmission::new(
        AdmissionConfig::default(),
        clock.clone(),
        store.clone(),
        grant_for(OWNER, "session_established"),
    )
    .expect("admission must configure");

    // First generation establishes epoch 1 on the pre-crash manager.
    let before_crash = MemorySessionManager::new(store.clone(), clock.clone());
    let scope = check(
        "audit_log",
        json!({"scope_id": "bootstrap-1", "target": TARGET}),
    );
    let credit = admission
        .reserve_control(&scope)
        .expect("control credit must reserve");
    let establish = check(
        "audit_log",
        json!({
            "target": TARGET,
            "run_id": "run-1",
            "phase": "A",
            "shard_id": "shard-a",
            "journal_id": JOURNAL,
            "session_topology": "per_shard",
            "worker_identity": "worker-1",
            "owner_epoch": 1,
            "preset": "chrome_148_linux",
            "profile_ref": "profile:chrome_148_linux",
        }),
    );
    let live = before_crash
        .establish(&worker_grant, &establish, &credit)
        .expect("first generation must establish");
    let first = record_value(&live.generation).clone();
    assert_eq!(first["session_epoch"], 1);
    drop(before_crash);

    // Cold manager recovers the same identity through the coordinator.
    let cold = MemorySessionManager::new(store.clone(), clock.clone());
    let pipeline = LocalPipeline;
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["sessions"] = json!([record_value(&establish).clone()]);
    let receipt = recover(
        store.as_ref(),
        artifacts.as_ref(),
        clock.as_ref(),
        &admission,
        &cold,
        &pipeline,
        &worker_grant,
        &check("audit_log", incident),
    )
    .expect("cold recovery must establish a new epoch");
    let value = record_value(&receipt);
    let generations = value["sessions"].as_array().expect("sessions");
    assert_eq!(generations.len(), 1);
    assert_eq!(generations[0]["session_epoch"], 2);
    assert_eq!(generations[0]["cookie_generation"], 0);
    assert_ne!(
        generations[0]["client_generation"], first["client_generation"],
        "recovery uses a fresh client, never the crashed one"
    );

    // The journal proves the acknowledged first generation survived and the
    // recovery epoch was journaled as session_recovered.
    let view = store
        .read(
            &worker_grant,
            &check("audit_log", json!({"query": "journal", "journal_id": JOURNAL})),
        )
        .expect("journal must be readable");
    let events = record_value(&view)["events"]
        .as_array()
        .expect("journal events")
        .clone();
    let kinds: Vec<&str> = events
        .iter()
        .filter_map(|event| event.get("event_kind").and_then(Value::as_str))
        .collect();
    assert!(kinds.contains(&"session_established"), "kinds: {kinds:?}");
    assert!(kinds.contains(&"session_recovered"), "kinds: {kinds:?}");
    let recovered = events
        .iter()
        .find(|event| event.get("event_kind").and_then(Value::as_str) == Some("session_recovered"))
        .expect("recovered event");
    assert_eq!(recovered["payload"]["data"]["recovered_from_crash"], true);
    assert_eq!(
        recovered["payload"]["data"]["session_state"]["cookie_jar_snapshot"]["reason"],
        "not_observed"
    );
}

#[test]
fn c44_rejects_unknown_trigger_without_side_effects() {
    let grant = grant_simple();
    let artifacts = MemoryArtifactStore::new();
    let clock = TestClock::new(2000.0);
    let pipeline = LocalPipeline;
    let admission = RefusingAdmission;
    let sessions = UnusedSessions;
    let store = TestStore::with_prefix(1, "head-1");

    // Permanent media loss is outside the process/reboot model: refused.
    let incident = incident_base(JOURNAL, "permanent_media_loss", TARGET);
    expect_fault(
        recover(
            &store,
            &artifacts,
            &clock,
            &admission,
            &sessions,
            &pipeline,
            &grant,
            &check("audit_log", incident),
        ),
        "invalid_trigger",
    );
    assert_eq!(store.transact_count(), 0);

    // Empty incident sections are a successful survival probe.
    let store = TestStore::with_prefix(2, "head-2");
    let mut incident = incident_base(JOURNAL, "restart", TARGET);
    incident["expected_prefix"] = json!({"last_sequence": 2, "head_hash": "head-2"});
    incident["proven_partitions"] = missing_detail("not_applicable", "no proven partitions in scope");
    let receipt = recover(
        &store,
        &artifacts,
        &clock,
        &admission,
        &sessions,
        &pipeline,
        &grant,
        &check("audit_log", incident),
    )
    .expect("empty recovery scope must succeed");
    let value = record_value(&receipt);
    assert_eq!(value["proven"].as_array().unwrap().len(), 0);
    assert_eq!(value["reclaimed"].as_array().unwrap().len(), 0);
}
