//! [C37] Start idempotency: same command/key returns the retained
//! handle; conflicting content is rejected; no duplicate execution.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_authority::{authorize, Grant};
use crawler_dispatch::start;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_prepare::prepare;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

fn missing_detail(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn dummy_digest_hex(ch: char) -> String {
    std::iter::repeat(ch).take(64).collect()
}

fn dummy_digest(ch: char) -> String {
    format!("sha256:{}", dummy_digest_hex(ch))
}

fn evidence_ref(journal_id: &str, sequence: u64, event_id: &str, ch: char) -> Value {
    json!({
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": dummy_digest(ch),
        "pointer": "",
    })
}

fn assert_no_bare_nulls(value: &Value) {
    match value {
        Value::Null => panic!("produced record contains a bare JSON null"),
        Value::Array(items) => items.iter().for_each(assert_no_bare_nulls),
        Value::Object(map) => {
            if map.get("value").is_some_and(Value::is_null) {
                assert!(
                    map.get("reason").and_then(Value::as_str).is_some(),
                    "Missing envelope requires a reason"
                );
                for (key, item) in map {
                    if key != "value" {
                        assert_no_bare_nulls(item);
                    }
                }
            } else {
                map.values().for_each(assert_no_bare_nulls);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Clocks, stores, admission
// ---------------------------------------------------------------------------

struct TestClock {
    offset_ms: AtomicU64,
    now_calls: AtomicU64,
}

impl TestClock {
    fn new() -> Self {
        Self {
            offset_ms: AtomicU64::new(1_000),
            now_calls: AtomicU64::new(0),
        }
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        self.now_calls.fetch_add(1, Ordering::SeqCst);
        let offset = self.offset_ms.fetch_add(10, Ordering::SeqCst);
        validate(
            "audit_log",
            json!({
                "clock_id": "dispatch-clock",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": offset,
                "utc_annotation": missing("not_observed"),
            }),
        )
    }
}

/// Owner-local dispatch journal: records every dispatch commit.
#[derive(Default)]
struct RecordingDispatchStore {
    transactions: Mutex<Vec<Value>>,
    transact_calls: AtomicU64,
}

impl RecordingDispatchStore {
    fn transaction_count(&self) -> usize {
        self.transactions.lock().expect("store lock").len()
    }

    fn transactions(&self) -> Vec<Value> {
        self.transactions.lock().expect("store lock").clone()
    }
}

impl OwnerStore for RecordingDispatchStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.transact_calls.fetch_add(1, Ordering::SeqCst);
        let value = record_value(transaction).clone();
        let sequence = {
            let mut transactions = self.transactions.lock().expect("store lock");
            transactions.push(value.clone());
            transactions.len() as u64
        };
        validate(
            "audit_log",
            json!({
                "durable": true,
                "journal_sequence": sequence,
                "transaction": value,
            }),
        )
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({"rows": [], "query": record_value(query).clone()}),
        )
    }
}

/// Prepare prefix stub: grounds journal-1, rejects everything else.
struct StubPrepareStore;

impl OwnerStore for StubPrepareStore {
    fn transact(&self, _grant: &Grant, _transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "write_forbidden".to_string(),
            detail: "prepare performs no writes".to_string(),
        })
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let journal_id = record_value(query)
            .get("journal_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if journal_id != "journal-1" {
            return Err(Fault {
                code: "unknown_journal".to_string(),
                detail: format!("journal {journal_id:?} has not admitted a manifest"),
            });
        }
        validate(
            "audit_log",
            json!({
                "record_type": "journal_prefix",
                "journal_id": "journal-1",
                "last_sequence": 1,
                "head_hash": dummy_digest('a'),
            }),
        )
    }
}

/// Admission wrapper that counts response reservations.
struct CountingAdmission {
    inner: MemoryAdmission,
    reserves: AtomicU64,
}

impl CountingAdmission {
    fn new(inner: MemoryAdmission) -> Self {
        Self {
            inner,
            reserves: AtomicU64::new(0),
        }
    }

    fn reserve_count(&self) -> u64 {
        self.reserves.load(Ordering::SeqCst)
    }
}

impl Admission for CountingAdmission {
    fn reserve_response(
        &self,
        request: &CheckedRecord,
    ) -> Result<crawler_admission::ResponseCredit, Fault> {
        self.reserves.fetch_add(1, Ordering::SeqCst);
        self.inner.reserve_response(request)
    }

    fn reserve_control(
        &self,
        scope: &CheckedRecord,
    ) -> Result<crawler_admission::ControlCredit, Fault> {
        self.inner.reserve_control(scope)
    }

    fn reserve_page(
        &self,
        scope: &CheckedRecord,
        control: bool,
    ) -> Result<crawler_admission::PagePermit, Fault> {
        self.inner.reserve_page(scope, control)
    }

    fn settle_response(
        &self,
        credit: crawler_admission::ResponseCredit,
        outcome: &CheckedRecord,
    ) -> Result<(), Fault> {
        self.inner.settle_response(credit, outcome)
    }
}

// ---------------------------------------------------------------------------
// Grants
// ---------------------------------------------------------------------------

fn registration_fixture() -> CheckedRecord {
    check(json!({
        "registration_id": "dispatch-channel",
        "principals": [{
            "principal_id": "tester",
            "verbs": ["Prepare", "Start"],
            "connectors": ["jobs-connector"],
            "control": false,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn grant_for(verb: &str) -> Grant {
    let registration = registration_fixture();
    let principal = check(json!({
        "principal_id": "tester",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({
        "verb": verb,
        "connector": "jobs-connector",
        "subject": "jobs",
    }));
    authorize(&principal, &request, &registration).expect("grant must issue")
}

// ---------------------------------------------------------------------------
// Prepare fixtures (valid immutable preparation via prepare())
// ---------------------------------------------------------------------------

fn subject_pin() -> Value {
    json!({
        "subject_id": "il-crawler",
        "subject_version": "v1",
        "configured_mode": "service",
        "interface_surface": "ordinary_browser",
    })
}

fn minimum_capabilities() -> Vec<Value> {
    [
        "native_goal_task",
        "native_plan_execution",
        "native_cancel",
        "native_context_release",
        "native_artifact_retrieval",
        "native_revision",
        "native_dom_access",
        "browser_state_isolation",
        "browser_state_persistence",
        "learning_state_control",
    ]
    .into_iter()
    .map(|id| {
        json!({
            "capability_id": id,
            "availability": "unknown",
            "claim_origin": "native",
        })
    })
    .collect()
}

fn descriptor_fixture() -> CheckedRecord {
    check(json!({
        "record_type": "connector_descriptor",
        "schema_version": "external-connector/0.1.0",
        "connector_id": "jobs-connector",
        "connector_version": "0.1.0",
        "subject": subject_pin(),
        "capabilities": {
            "capabilities": minimum_capabilities(),
            "subject": subject_pin(),
        },
        "task_mappings": [
            {
                "task_type": "discover_jobs",
                "input_form": "goal",
                "mapping": {
                    "id": "il-mapping",
                    "version": "1",
                    "artifact_digest": dummy_digest('b'),
                },
                "planning_owner": "external_planner",
                "recovery_owner": "none",
                "limitations": [],
            },
            {
                "task_type": "extract",
                "input_form": "extraction_request",
                "mapping": {
                    "id": "il-extract-mapping",
                    "version": "1",
                    "artifact_digest": dummy_digest('c'),
                },
                "planning_owner": "external_planner",
                "recovery_owner": "none",
                "limitations": [],
            },
        ],
    }))
}

fn duration_ms(value: u64) -> Value {
    json!({"kind": "exact", "unit": "ms", "value": value})
}

fn scope_fixture() -> Value {
    json!({
        "activity": "discovery",
        "run_id": "run-1",
        "journal_id": "journal-1",
        "manifest_hash": dummy_digest('d'),
        "admission_ref": evidence_ref("journal-1", 1, "evt-admit", 'e'),
        "attempt": missing("not_applicable"),
        "commission": missing("not_applicable"),
        "commission_ref": missing("not_applicable"),
        "authorization_refs": [evidence_ref("journal-1", 1, "evt-auth", 'f')],
        "observation_policy": {
            "active_limit": duration_ms(30000),
            "drain_limit": duration_ms(5000),
            "native_cancel_wait_limit": duration_ms(2000),
            "cleanup_wait_limit": duration_ms(2000),
            "fixture_close_action": "not_applicable",
        },
    })
}

fn task_fixture(task_id: &str) -> Value {
    json!({
        "record_type": "connector_task",
        "schema_version": "external-connector/0.1.0",
        "task_id": task_id,
        "task_type": "discover_jobs",
        "entry": {
            "logical_id": "entry-1",
            "url": "https://jobs.illinois.gov/search",
        },
        "goal": "discover listings",
        "success_criteria": [
            {"criterion_id": "crit-1", "description": "identify current listings"},
        ],
        "inputs": [],
        "permitted_origins": [
            {"logical_id": "origin-1", "origin": "https://jobs.illinois.gov"},
        ],
        "permitted_interfaces": ["read_only_acquisition"],
        "effect_policy": "read_only",
        "budgets": {
            "active_limit": duration_ms(30000),
            "action_limit": 100,
            "observation_byte_limit": 1000000,
            "recovery_limit": 0,
            "model_token_limit": 0,
        },
        "context_policy": {
            "browser_state": {
                "mode": "fresh",
                "requirement": "required",
                "resource_ref": missing("not_applicable"),
                "baseline": missing("not_applicable"),
            },
            "learning_state": {
                "mode": "not_applicable",
                "requirement": "best_effort",
                "resource_ref": missing("not_applicable"),
                "baseline": missing("not_applicable"),
            },
        },
        "output_schema": {
            "id": "job-feed",
            "version": "1",
            "artifact_digest": dummy_digest('b'),
        },
    })
}

fn configuration_fixture(descriptor: &CheckedRecord) -> Value {
    let descriptor_hex = binding_of(descriptor);
    let descriptor_bytes = canonical_bytes(descriptor).expect("descriptor bytes");
    json!({
        "connector_id": "jobs-connector",
        "connector_version": "0.1.0",
        "binding": {
            "id": "crawler-binding",
            "version": "1",
            "artifact_digest": dummy_digest('b'),
        },
        "subject": subject_pin(),
        "descriptor": {
            "digest": format!("sha256:{descriptor_hex}"),
            "size_bytes": descriptor_bytes.len() as u64,
            "media_type": "connector-descriptor/1",
            "owner_domain": "crawler",
            "access": "public",
        },
        "descriptor_ref": evidence_ref("journal-1", 1, "evt-desc", 'e'),
    })
}

fn assistance_fixture() -> Value {
    json!({
        "planning_owner": "external_planner",
        "assistance_track": "track-1",
        "planner_identity": "planner-1",
        "plan": missing("not_applicable"),
        "online_replanning": false,
        "description": "external plan with public observation",
    })
}

fn prepare_request_fixture(descriptor: &CheckedRecord, task_id: &str) -> CheckedRecord {
    check(json!({
        "scope": scope_fixture(),
        "configuration": configuration_fixture(descriptor),
        "task": task_fixture(task_id),
        "assistance": assistance_fixture(),
        "planning_evidence_refs": [],
        "preparation_measurements": [],
        "runtime_access": [],
    }))
}

fn authorization_for(preparation: &CheckedRecord) -> Value {
    let concerns = record_value(preparation)
        .get("concerns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut accepted = Vec::new();
    for concern in &concerns {
        if concern.get("disposition").and_then(Value::as_str) == Some("requires_acceptance") {
            if let Some(id) = concern.get("concern_id").and_then(Value::as_str) {
                accepted.push(Value::String(id.to_string()));
            }
        }
    }
    let scope_refs = record_value(preparation)
        .get("scope")
        .and_then(|scope| scope.get("authorization_refs"))
        .cloned()
        .unwrap_or_else(|| Value::Array(vec![evidence_ref("journal-1", 1, "evt-auth", 'f')]));
    json!({
        "accepted_concerns": accepted,
        "authorization_refs": scope_refs,
    })
}

fn valid_preparation(task_id: &str) -> (Value, Value, Value) {
    let grant = grant_for("Prepare");
    let store = StubPrepareStore;
    let descriptor = descriptor_fixture();
    let request = prepare_request_fixture(&descriptor, task_id);
    let preparation =
        prepare(&store, &grant, &request, &descriptor).expect("valid prepare must succeed");
    let preparation_value = record_value(&preparation).clone();
    let configuration = preparation_value
        .get("configuration")
        .cloned()
        .expect("preparation must carry configuration");
    let authorization = authorization_for(&preparation);
    (preparation_value, configuration, authorization)
}

fn start_request(
    request_id: &str,
    idempotency_key: &str,
    preparation: Value,
    configuration: Value,
    authorization: Value,
) -> CheckedRecord {
    check(json!({
        "connector_id": "jobs-connector",
        "request_id": request_id,
        "idempotency_key": idempotency_key,
        "preparation": preparation,
        "configuration": configuration,
        "authorization": authorization,
        "recovery": missing("not_applicable"),
    }))
}

// ---------------------------------------------------------------------------
// C37
// ---------------------------------------------------------------------------

#[test]
fn c37_start_idempotency_retained_handle_conflict_rejected_no_duplicate() {
    let clock = Arc::new(TestClock::new());
    let dispatch_store = RecordingDispatchStore::default();
    let admission_store = Arc::new(RecordingDispatchStore::default());
    let admission = CountingAdmission::new(
        MemoryAdmission::new(
            AdmissionConfig::default(),
            clock.clone(),
            admission_store,
            grant_for("Start"),
        )
        .expect("admission must build"),
    );
    let grant = grant_for("Start");

    let (preparation, configuration, authorization) = valid_preparation("task-1");
    let preparation_id = preparation
        .get("preparation_id")
        .and_then(Value::as_str)
        .expect("preparation must carry an id")
        .to_string();

    // --- Fresh Start commits handle + binding + idempotency + intent.
    let request = start_request(
        "c37-cmd-1",
        "c37-logical-1",
        preparation.clone(),
        configuration.clone(),
        authorization.clone(),
    );
    let first = start(&dispatch_store, clock.as_ref(), &admission, &grant, &request)
        .expect("fresh Start must commit");
    let first_value = record_value(&first).clone();
    assert_no_bare_nulls(&first_value);
    assert_eq!(
        first_value.get("record_type").and_then(Value::as_str),
        Some("dispatch_receipt")
    );
    assert_eq!(
        first_value.get("disposition").and_then(Value::as_str),
        Some("committed")
    );
    let handle = first_value
        .get("handle")
        .expect("receipt must carry a handle");
    assert_eq!(
        handle.get("record_type").and_then(Value::as_str),
        Some("connector_handle")
    );
    let handle_ref = handle
        .get("handle_ref")
        .and_then(Value::as_str)
        .expect("handle must carry a reference");
    assert!(!handle_ref.is_empty(), "handle reference must be nonempty");
    assert_eq!(
        handle.get("preparation_ref").and_then(Value::as_str),
        Some(preparation_id.as_str()),
        "handle must pin the exact preparation"
    );
    assert_eq!(
        handle.get("idempotency_key").and_then(Value::as_str),
        Some("c37-logical-1")
    );
    // Real creation TimePoint from the registered clock; no native run ID.
    let created_at = handle.get("created_at").expect("handle needs created_at");
    assert_eq!(
        created_at.get("clock_id").and_then(Value::as_str),
        Some("dispatch-clock")
    );
    assert!(
        handle.get("native_run_id").is_some_and(|v| v
            .as_object()
            .is_some_and(|m| m.get("value").is_some_and(Value::is_null))),
        "native run ID attaches only in later source-backed observations"
    );
    // Durable commit happened exactly once.
    assert_eq!(dispatch_store.transaction_count(), 1);
    assert_eq!(admission.reserve_count(), 1);
    let committed = &dispatch_store.transactions()[0];
    assert_eq!(
        committed.get("operation").and_then(Value::as_str),
        Some("dispatch_start")
    );
    assert_eq!(
        committed.get("idempotency_key").and_then(Value::as_str),
        Some("c37-logical-1")
    );
    assert!(
        committed.get("handle").is_some(),
        "commit must include the local handle"
    );
    assert!(
        committed.get("request_binding").is_some(),
        "commit must include the immutable request binding"
    );
    assert!(
        committed.get("dispatch_intent").is_some(),
        "commit must include the dispatch intent"
    );

    // --- Same command/key with identical content returns the retained
    // handle without another effect.
    let retry = start_request(
        "c37-cmd-1",
        "c37-logical-1",
        preparation.clone(),
        configuration.clone(),
        authorization.clone(),
    );
    let second = start(&dispatch_store, clock.as_ref(), &admission, &grant, &retry)
        .expect("identical retry must return the retained receipt");
    let second_value = record_value(&second).clone();
    assert_no_bare_nulls(&second_value);
    assert_eq!(
        second_value, first_value,
        "retained receipt must be returned byte-for-byte"
    );
    assert_eq!(
        second_value
            .get("handle")
            .and_then(|h| h.get("handle_ref"))
            .and_then(Value::as_str),
        Some(handle_ref),
        "same command/key must return the retained handle"
    );
    assert_eq!(
        dispatch_store.transaction_count(),
        1,
        "duplicate must not journal another effect"
    );
    assert_eq!(
        admission.reserve_count(),
        1,
        "duplicate must not reserve again"
    );

    // --- Same command/key with conflicting content is rejected.
    let (other_preparation, other_configuration, other_authorization) =
        valid_preparation("task-2");
    assert_ne!(
        other_preparation.get("preparation_id"),
        preparation.get("preparation_id"),
        "conflict fixture needs a distinct preparation"
    );
    let conflict = start_request(
        "c37-cmd-1",
        "c37-logical-1",
        other_preparation.clone(),
        other_configuration.clone(),
        other_authorization.clone(),
    );
    let err = start(&dispatch_store, clock.as_ref(), &admission, &grant, &conflict)
        .expect_err("conflicting content under one command key must be rejected");
    assert_eq!(err.code, "integrity_conflict");
    assert_eq!(
        dispatch_store.transaction_count(),
        1,
        "conflict must not journal another effect"
    );
    assert_eq!(
        admission.reserve_count(),
        1,
        "conflict must not reserve capacity"
    );

    // --- Same logical key with different preparation is also rejected,
    // even under a new command identity.
    let logical_conflict = start_request(
        "c37-cmd-2",
        "c37-logical-1",
        other_preparation,
        other_configuration,
        other_authorization,
    );
    let err = start(
        &dispatch_store,
        clock.as_ref(),
        &admission,
        &grant,
        &logical_conflict,
    )
    .expect_err("same logical key with different preparation must be rejected");
    assert_eq!(err.code, "integrity_conflict");
    assert_eq!(dispatch_store.transaction_count(), 1);
    assert_eq!(admission.reserve_count(), 1);

    // --- A distinct logical key commits a distinct handle.
    let fresh = start_request(
        "c37-cmd-3",
        "c37-logical-2",
        preparation,
        configuration,
        authorization,
    );
    let third = start(&dispatch_store, clock.as_ref(), &admission, &grant, &fresh)
        .expect("distinct logical key must commit a distinct dispatch");
    let third_value = record_value(&third).clone();
    let third_handle = third_value
        .get("handle")
        .and_then(|h| h.get("handle_ref"))
        .and_then(Value::as_str)
        .expect("third receipt needs a handle");
    assert_ne!(
        third_handle, handle_ref,
        "distinct logical keys must not share a handle"
    );
    assert_eq!(dispatch_store.transaction_count(), 2);
    assert_eq!(admission.reserve_count(), 2);

    // Silence unused helper in builds without the detail path.
    let _ = missing_detail("not_observed", "unused");
}
