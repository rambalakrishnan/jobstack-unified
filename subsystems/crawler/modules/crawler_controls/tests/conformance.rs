//! Conformance tests for **[C39]**: close, cancel, release, contain, claim,
//! acknowledgement, and effect remain distinct.
//!
//! Every test drives the real [`control`] seam with an owner store, a
//! registered monotonic clock, an admission ledger, and a recording native
//! control adapter. The assertions read the emitted `control_receipt`; none of
//! the states are inferred from a successful function return alone.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_authority::{authorize, Grant};
use crawler_controls::{control, NativeControls};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const ALL_VERBS: &[&str] = &[
    "Describe",
    "Prepare",
    "Start",
    "Observe",
    "RequestNativeCancel",
    "CloseObservationConnection",
    "CollectArtifacts",
    "ReleaseNativeContext",
    "Contain",
];

const CAPABILITY_IDS: &[&str] = &[
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
];

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

/// Contract 02 `EvidenceRef`: journal coordinate, not a bare label.
fn evidence_ref(event_id: &str) -> Value {
    json!({
        "journal_id": "journal-1",
        "sequence": 2,
        "event_id": event_id,
        "event_hash": "0000000000000000000000000000000000000000000000000000000000000001",
        "pointer": format!("/{event_id}"),
    })
}

struct TestClock {
    offset_ms: AtomicU64,
}

impl TestClock {
    fn new() -> Self {
        Self {
            offset_ms: AtomicU64::new(0),
        }
    }

    fn advance(&self, delta_ms: u64) {
        self.offset_ms.fetch_add(delta_ms, Ordering::SeqCst);
    }
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            json!({
                "clock_id": "controls-clock",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": self.offset_ms.load(Ordering::SeqCst),
                "utc_annotation": missing("not_observed"),
            }),
        )
    }
}

/// Owner-local store seam. `read` returns an immutable prefix; `transact` is
/// never reached by the control path (control reads evidence, it does not
/// rewrite close-time knowledge).
#[derive(Default)]
struct RecordingStore {
    reads: Mutex<Vec<Value>>,
}

impl OwnerStore for RecordingStore {
    fn transact(
        &self,
        _grant: &Grant,
        _transaction: &CheckedRecord,
    ) -> Result<CheckedRecord, Fault> {
        panic!("control must not transact; close-time evidence is read-only here")
    }

    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.reads
            .lock()
            .expect("store lock")
            .push(record_value(query).clone());
        validate(
            "audit_log",
            json!({
                "journal_id": "journal-1",
                "last_sequence": 3,
                "head_hash": "head-hash-1",
                "query": record_value(query).clone(),
            }),
        )
    }
}

fn registration_fixture() -> CheckedRecord {
    check(json!({
        "registration_id": "controls-channel",
        "principals": [
            {
                "principal_id": "operator",
                "verbs": ["Describe", "RequestNativeCancel", "CloseObservationConnection", "ReleaseNativeContext", "Contain"],
                "connectors": ["jobs-connector"],
                "control": true,
                "owner_domain": "crawler",
                "restricted_access": false,
            },
            {
                "principal_id": "reader",
                "verbs": ["Describe"],
                "connectors": ["jobs-connector"],
                "control": false,
                "owner_domain": "crawler",
                "restricted_access": false,
            },
        ],
    }))
}

fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn grant_for(verb: &str, subject: &str) -> Grant {
    let registration = registration_fixture();
    let principal = check(json!({
        "principal_id": "operator",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({
        "verb": verb,
        "connector": "jobs-connector",
        "subject": subject,
    }));
    authorize(&principal, &request, &registration).expect("control grant must issue")
}

/// A grant issued to a principal without control authority.
fn non_control_grant() -> Grant {
    let registration = registration_fixture();
    let principal = check(json!({
        "principal_id": "reader",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({"verb": "Describe", "connector": "jobs-connector"}));
    authorize(&principal, &request, &registration).expect("reader grant must issue")
}

fn subject_pin() -> Value {
    json!({
        "subject_id": "subject-1",
        "subject_version": "1.0.0",
        "configured_mode": "read_only",
        "interface_surface": "read_only_acquisition",
    })
}

fn unmapped(verb: &str) -> Value {
    json!({
        "operation": verb,
        "implementation": "unmapped",
        "native_contract": missing("not_observed"),
        "capability_refs": [],
        "evidence_refs": [],
        "limitations": ["unsupported mapping is not native absence"],
    })
}

fn native_mapping(verb: &str) -> Value {
    json!({
        "operation": verb,
        "implementation": "native_mapping",
        "native_contract": {
            "id": format!("{verb}-native-contract"),
            "version": "1",
        },
        "capability_refs": [],
        "evidence_refs": [evidence_ref("native-contract-evidence")],
        "limitations": [],
    })
}

fn connector_local(verb: &str) -> Value {
    json!({
        "operation": verb,
        "implementation": "connector_local",
        "native_contract": missing("not_applicable"),
        "capability_refs": [],
        "evidence_refs": [],
        "limitations": [],
    })
}

/// Build one complete connector descriptor with the requested operation
/// mappings. Every capability except `native_cancel` stays `unknown`.
fn descriptor_for(overrides: &[(&str, Value)], cancel_availability: &str) -> Value {
    let catalog: Vec<Value> = CAPABILITY_IDS
        .iter()
        .map(|capability_id| {
            let availability = if *capability_id == "native_cancel" {
                cancel_availability
            } else {
                "unknown"
            };
            let evidence = if *capability_id == "native_cancel" && cancel_availability == "present"
            {
                json!([{
                    "basis": "documentation",
                    "ref": evidence_ref("capability-doc-1"),
                }])
            } else {
                json!([])
            };
            json!({
                "capability_id": capability_id,
                "availability": availability,
                "claim_origin": "native",
                "requirement_refs": [],
                "evidence": evidence,
                "limitations": [],
            })
        })
        .collect();

    let operations: Vec<Value> = ALL_VERBS
        .iter()
        .map(|verb| {
            overrides
                .iter()
                .find(|(candidate, _)| candidate == verb)
                .map(|(_, value)| value.clone())
                .unwrap_or_else(|| unmapped(verb))
        })
        .collect();

    json!({
        "record_type": "connector_descriptor",
        "schema_version": "evidence-kernel/0.1.0",
        "connector_id": "jobs-connector",
        "connector_version": "2.0.0",
        "build": {"id": "build-1", "version": "1"},
        "binding": {"id": "binding-1", "version": "1"},
        "subject": subject_pin(),
        "capabilities": {
            "subject": subject_pin(),
            "capabilities": catalog,
        },
        "operations": operations,
        "task_mappings": [],
        "observation_channels": [],
        "action_grounding": "semantic",
        "execution_substrate": "browser",
        "limits": {},
        "budget_accounting": {},
        "evidence_prefix": missing("not_observed"),
    })
}

fn request_value(verb: &str, operation_id: &str, descriptor: Value) -> Value {
    json!({
        "verb": verb,
        "operation_id": operation_id,
        "connector": "jobs-connector",
        "subject": "subject-1",
        "journal_id": "journal-1",
        "handle": {
            "handle_id": "handle-1",
            "journal_id": "journal-1",
            "subject_id": "subject-1",
        },
        "descriptor": descriptor,
        "authorization_refs": [],
        "bounds": {
            "call_bound_ms": 1000,
            "drain_bound_ms": 500,
            "cancellation_wait_ms": 500,
            "cleanup_wait_ms": 500,
        },
    })
}

fn with_fields(mut request: Value, fields: Value) -> Value {
    let target = request
        .as_object_mut()
        .expect("request fixture must be an object");
    for (key, value) in fields.as_object().expect("fields must be an object") {
        target.insert(key.clone(), value.clone());
    }
    request
}

fn default_response() -> Value {
    json!({
        "outcome": "acknowledged",
        "acknowledgement": {
            "verified": true,
            "response_ref": evidence_ref("native-response-1"),
        },
        "subject_claim": missing("not_observed"),
        "effect": missing("not_observed"),
        "timing": {"observed_elapsed_ms": 1},
        "limitations": [],
    })
}

struct RecordingNative {
    clock: Arc<TestClock>,
    invocations: Mutex<Vec<Value>>,
    response: Mutex<Option<Value>>,
    advance_ms: u64,
}

impl RecordingNative {
    fn new(clock: Arc<TestClock>) -> Self {
        Self {
            clock,
            invocations: Mutex::new(Vec::new()),
            response: Mutex::new(None),
            advance_ms: 0,
        }
    }

    fn with_response(clock: Arc<TestClock>, response: Value) -> Self {
        Self {
            clock,
            invocations: Mutex::new(Vec::new()),
            response: Mutex::new(Some(response)),
            advance_ms: 0,
        }
    }

    fn advancing(clock: Arc<TestClock>, advance_ms: u64) -> Self {
        Self {
            clock,
            invocations: Mutex::new(Vec::new()),
            response: Mutex::new(None),
            advance_ms,
        }
    }

    fn invocations(&self) -> Vec<Value> {
        self.invocations.lock().expect("invocation lock").clone()
    }
}

impl NativeControls for RecordingNative {
    fn invoke(&self, _grant: &Grant, operation: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let operation_value = record_value(operation).clone();
        self.invocations
            .lock()
            .expect("invocation lock")
            .push(operation_value.clone());
        if self.advance_ms > 0 {
            self.clock.advance(self.advance_ms);
        }
        let mut response = self
            .response
            .lock()
            .expect("response lock")
            .clone()
            .unwrap_or_else(default_response);
        let operation_id = operation_value["operation_id"]
            .as_str()
            .expect("operation id")
            .to_string();
        response["operation_id"] = json!(operation_id);
        validate("audit_log", response)
    }
}

fn execute(
    verb: &str,
    request: CheckedRecord,
    native: &RecordingNative,
    clock: &Arc<TestClock>,
    store: &Arc<RecordingStore>,
) -> Result<CheckedRecord, Fault> {
    execute_with_config(
        verb,
        request,
        native,
        clock,
        store,
        AdmissionConfig::default(),
    )
}

fn execute_with_config(
    verb: &str,
    request: CheckedRecord,
    native: &RecordingNative,
    clock: &Arc<TestClock>,
    store: &Arc<RecordingStore>,
    config: AdmissionConfig,
) -> Result<CheckedRecord, Fault> {
    let admission = MemoryAdmission::new(
        config,
        clock.clone(),
        store.clone(),
        grant_for("RequestNativeCancel", "subject-1"),
    )
    .expect("admission must build");
    let grant = grant_for(verb, "subject-1");
    control(
        store.as_ref(),
        clock.as_ref(),
        &admission,
        native,
        &grant,
        &request,
    )
}

fn execute_with_grant(
    request: CheckedRecord,
    native: &RecordingNative,
    clock: &Arc<TestClock>,
    store: &Arc<RecordingStore>,
    grant: Grant,
) -> Result<CheckedRecord, Fault> {
    let admission = MemoryAdmission::new(
        AdmissionConfig::default(),
        clock.clone(),
        store.clone(),
        grant_for("RequestNativeCancel", "subject-1"),
    )
    .expect("admission must build");
    control(
        store.as_ref(),
        clock.as_ref(),
        &admission,
        native,
        &grant,
        &request,
    )
}

fn observation(receipt: &CheckedRecord) -> serde_json::Map<String, Value> {
    record_value(receipt)
        .get("observation")
        .and_then(Value::as_object)
        .expect("receipt observation")
        .clone()
}

fn event_dispositions(observation: &serde_json::Map<String, Value>) -> Vec<String> {
    observation["events"]
        .as_array()
        .expect("observation events")
        .iter()
        .map(|event| {
            event["disposition"]
                .as_str()
                .expect("event disposition")
                .to_string()
        })
        .collect()
}

fn error_code(result: Result<CheckedRecord, Fault>) -> String {
    match result {
        Ok(receipt) => panic!(
            "expected a fault, got receipt {}",
            record_value(&receipt)
        ),
        Err(error) => error.code,
    }
}

// ---------------------------------------------------------------------------
// C39: close, cancel, release, contain, claim, acknowledgement, effect
// ---------------------------------------------------------------------------

#[test]
fn c39_close_without_end_observation_closes_transport_only() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "CloseObservationConnection",
            connector_local("CloseObservationConnection"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("CloseObservationConnection", "op-close-1", descriptor),
        json!({"reason": "normal_completion", "end_observation": false}),
    );

    let receipt = execute(
        "CloseObservationConnection",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("close must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(observed["transport_closed"], json!(true));
    assert_eq!(observed["observation_ended"], json!(false));
    assert_eq!(observed["workflow_delivery_stop_requested"], json!(false));
    assert_eq!(observed["workflow_delivery_stopped"], json!(false));
    assert_eq!(observed["drain_started"], json!(false));
    assert_eq!(observed["cancel_requested"], json!(false));
    assert_eq!(observed["context_release_effect_observed"], json!(false));
    assert_eq!(observed["containment_effect_observed"], json!(false));
    assert_eq!(
        event_dispositions(&observed),
        vec!["requested".to_string(), "acknowledged".to_string()]
    );

    let invocations = native.invocations();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0]["verb"], json!("CloseObservationConnection"));
    assert_eq!(
        invocations[0]["parameters"]["end_observation"],
        json!(false)
    );
    assert_eq!(
        invocations[0]["target_scope"],
        json!("observation_connection")
    );
    assert_eq!(
        invocations[0]["evidence_prefix"]["journal_id"],
        json!("journal-1")
    );
}

#[test]
fn c39_end_observation_starts_bounded_drain_without_implying_cancel() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "CloseObservationConnection",
            connector_local("CloseObservationConnection"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("CloseObservationConnection", "op-close-2", descriptor),
        json!({"reason": "operator_stop", "end_observation": true}),
    );

    let receipt = execute(
        "CloseObservationConnection",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("close must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["transport_closed"], json!(true));
    assert_eq!(observed["observation_ended"], json!(true));
    assert_eq!(observed["workflow_delivery_stop_requested"], json!(true));
    assert_eq!(observed["workflow_delivery_stopped"], json!(true));
    assert_eq!(observed["drain_started"], json!(true));
    assert_eq!(observed["drain_completed"], json!(false));
    assert_eq!(observed["timing"]["drain_bound_ms"], json!(500));
    assert!(observed["timing"]["drain_deadline"]["monotonic_offset_ms"].is_number());
    assert_eq!(observed["cancel_requested"], json!(false));
    assert_eq!(observed["cancel_acknowledged"], json!(false));
    assert_eq!(observed["cancel_effect_observed"], json!(false));
    assert_eq!(native.invocations().len(), 1);
}

#[test]
fn c39_local_finalization_does_not_wait_for_native_acknowledgement() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let unknown = json!({
        "outcome": "unknown",
        "acknowledgement": missing("not_observed"),
        "subject_claim": missing("not_observed"),
        "effect": missing("not_observed"),
        "limitations": ["native transport delivery is uncertain"],
    });
    let native = RecordingNative::with_response(clock.clone(), unknown);
    let descriptor = descriptor_for(
        &[(
            "CloseObservationConnection",
            connector_local("CloseObservationConnection"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("CloseObservationConnection", "op-close-unknown", descriptor),
        json!({"reason": "local_deadline", "end_observation": true}),
    );

    let receipt = execute(
        "CloseObservationConnection",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("close must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("unknown"));
    assert_eq!(observed["transport_closed"], json!(false));
    assert_eq!(observed["observation_ended"], json!(true));
    assert_eq!(observed["workflow_delivery_stopped"], json!(true));
    assert_eq!(observed["drain_started"], json!(true));
    assert_eq!(observed["drain_completed"], json!(false));
    assert_eq!(observed["cancel_requested"], json!(false));
    assert_eq!(
        event_dispositions(&observed),
        vec!["requested".to_string(), "unknown".to_string()]
    );
}

#[test]
fn c39_cancel_request_acknowledgement_claim_and_effect_stay_distinct() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let response = json!({
        "outcome": "acknowledged",
        "acknowledgement": {
            "verified": true,
            "response_ref": evidence_ref("cancel-ack-1"),
        },
        "subject_claim": {
            "source": "subject",
            "claim_ref": evidence_ref("subject-stop-claim-1"),
        },
        "effect": missing("not_observed"),
        "timing": {"observed_elapsed_ms": 2},
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), response);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-1", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );

    let receipt = execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("cancel must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(observed["cancel_requested"], json!(true));
    assert_eq!(observed["cancel_acknowledged"], json!(true));
    assert_eq!(observed["cancel_effect_observed"], json!(false));
    assert_eq!(observed["stop_claim_recorded"], json!(true));
    assert_eq!(observed["subject_claim"]["source"], json!("subject"));
    assert_eq!(
        observed["subject_claim"]["claim_ref"]["event_id"],
        json!("subject-stop-claim-1")
    );
    assert_eq!(observed["effect"]["value"], Value::Null);
    assert_eq!(observed["forced_termination"], json!(false));
    assert_eq!(observed["rollback_established"], json!(false));
    assert_eq!(observed["no_remote_effect_established"], json!(false));
    assert_eq!(
        event_dispositions(&observed),
        vec!["requested".to_string(), "acknowledged".to_string()]
    );

    let invocations = native.invocations();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0]["target_scope"], json!("native_execution"));
    assert_eq!(
        invocations[0]["capability_ref"]["capability_id"],
        json!("native_cancel")
    );
    assert_eq!(
        invocations[0]["native_contract"]["id"],
        json!("RequestNativeCancel-native-contract")
    );
}

#[test]
fn c39_effect_observation_requires_matching_effect_evidence() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let response = json!({
        "outcome": "effect_observed",
        "acknowledgement": missing("not_observed"),
        "subject_claim": missing("not_observed"),
        "effect": {
            "effect_kind": "native_cancellation",
            "effect_refs": [evidence_ref("observed-cancel-effect-1")],
        },
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), response);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-effect", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );

    let receipt = execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("cancel must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("effect_observed"));
    assert_eq!(observed["cancel_requested"], json!(true));
    assert_eq!(observed["cancel_acknowledged"], json!(false));
    assert_eq!(observed["cancel_effect_observed"], json!(true));
    assert_eq!(observed["forced_termination"], json!(false));
    assert_eq!(
        event_dispositions(&observed),
        vec!["requested".to_string(), "effect_observed".to_string()]
    );
}

#[test]
fn c39_effect_without_evidence_is_rejected_not_acknowledged() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let response = json!({
        "outcome": "effect_observed",
        "acknowledgement": {
            "verified": true,
            "response_ref": evidence_ref("cancel-ack-1"),
        },
        "subject_claim": missing("not_observed"),
        "effect": missing("not_observed"),
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), response);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-no-effect", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );

    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "unevidenced_effect");
    assert_eq!(native.invocations().len(), 1);
}

#[test]
fn c39_effect_evidence_cannot_cross_control_verbs() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let response = json!({
        "outcome": "effect_observed",
        "acknowledgement": missing("not_observed"),
        "subject_claim": missing("not_observed"),
        "effect": {
            "effect_kind": "context_released",
            "effect_refs": [evidence_ref("release-effect-1")],
        },
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), response);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-cross", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );

    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "effect_scope_mismatch");
}

#[test]
fn c39_acknowledgement_requires_verified_response() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let unverified = json!({
        "outcome": "acknowledged",
        "acknowledgement": {"verified": false},
        "subject_claim": missing("not_observed"),
        "effect": missing("not_observed"),
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), unverified);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-unverified", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );
    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "unverified_acknowledgement");

    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let without_ack = json!({
        "outcome": "acknowledged",
        "acknowledgement": missing("not_observed"),
        "subject_claim": missing("not_observed"),
        "effect": missing("not_observed"),
        "limitations": [],
    });
    let native = RecordingNative::with_response(clock.clone(), without_ack);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-no-ack", descriptor),
        json!({"reason": "operator requested cooperative stop"}),
    );
    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "unverified_acknowledgement");
}

#[test]
fn c39_unsupported_mapping_is_not_native_absence() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "CloseObservationConnection",
            unmapped("CloseObservationConnection"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("CloseObservationConnection", "op-close-unmapped", descriptor),
        json!({"reason": "operator_stop", "end_observation": false}),
    );

    let receipt = execute(
        "CloseObservationConnection",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("every verb has a handler");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("unsupported"));
    assert_eq!(observed["native_absence_established"], json!(false));
    assert_eq!(observed["transport_closed"], json!(false));
    assert_eq!(observed["observation_ended"], json!(false));
    assert_eq!(observed["cancel_requested"], json!(false));
    assert_eq!(
        event_dispositions(&observed),
        vec!["requested".to_string(), "unsupported".to_string()]
    );
    assert!(observed["limitations"]
        .as_array()
        .expect("limitations")
        .iter()
        .any(|item| item.as_str() == Some("unsupported mapping is not native absence")));
    assert_eq!(native.invocations().len(), 0);

    let receipt_value = record_value(&receipt);
    assert_eq!(
        receipt_value["native_mapping"]["supported"],
        json!(false)
    );
    assert_eq!(receipt_value["native_invoked"], json!(false));
}

#[test]
fn c39_release_context_does_not_logout_purge_or_contain() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "ReleaseNativeContext",
            native_mapping("ReleaseNativeContext"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("ReleaseNativeContext", "op-release-1", descriptor),
        json!({"context_ref": "native-context-1"}),
    );

    let receipt = execute(
        "ReleaseNativeContext",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("release must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(observed["release_requested"], json!(true));
    assert_eq!(observed["release_acknowledged"], json!(true));
    assert_eq!(observed["context_release_effect_observed"], json!(false));
    assert_eq!(observed["implicit_logout"], json!(false));
    assert_eq!(observed["profile_purged"], json!(false));
    assert_eq!(observed["global_reset"], json!(false));
    assert_eq!(observed["containment_triggered_by_release"], json!(false));
    assert_eq!(observed["target_scope"], json!("native_context"));

    let invocations = native.invocations();
    assert_eq!(invocations.len(), 1);
    assert_eq!(invocations[0]["target_scope"], json!("native_context"));
    assert_eq!(
        invocations[0]["parameters"]["context_ref"],
        json!("native-context-1")
    );
}

#[test]
fn c39_release_cannot_carry_implicit_effect_fields() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "ReleaseNativeContext",
            native_mapping("ReleaseNativeContext"),
        )],
        "unknown",
    );
    let request = with_fields(
        request_value("ReleaseNativeContext", "op-release-implicit", descriptor),
        json!({"context_ref": "native-context-1", "logout": true}),
    );

    let error = error_code(execute(
        "ReleaseNativeContext",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "implicit_effect_forbidden");
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_contain_uses_versioned_policy_and_records_affected_work() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(&[("Contain", connector_local("Contain"))], "unknown");
    let request = with_fields(
        request_value("Contain", "op-contain-1", descriptor),
        json!({
            "reason": "operator containment after repeated failures",
            "target": {"kind": "local_process", "resource_id": "process-1"},
            "policy": {"id": "containment-policy", "version": "3"},
            "affected_attempts": [{"attempt_id": "attempt-1"}],
            "unresolved_impact": ["remote job state remains unknown"],
        }),
    );

    let receipt = execute("Contain", check(request), &native, &clock, &store)
        .expect("contain must be handled");
    let observed = observation(&receipt);

    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(observed["target_scope"], json!("local_process"));
    assert_eq!(observed["containment_requested"], json!(true));
    assert_eq!(observed["containment_acknowledged"], json!(true));
    assert_eq!(observed["containment_effect_observed"], json!(false));
    assert_eq!(observed["forced_termination"], json!(false));
    assert_eq!(observed["rollback_established"], json!(false));
    assert_eq!(observed["no_remote_effect_established"], json!(false));
    assert_eq!(observed["affected_attempts"], json!([{"attempt_id": "attempt-1"}]));
    assert_eq!(
        observed["unresolved_impact"],
        json!(["remote job state remains unknown"])
    );

    let invocations = native.invocations();
    assert_eq!(invocations.len(), 1);
    assert_eq!(
        invocations[0]["parameters"]["policy"],
        json!({"id": "containment-policy", "version": "3"})
    );
    assert_eq!(
        invocations[0]["parameters"]["target"]["resource_id"],
        json!("process-1")
    );
}

#[test]
fn c39_contain_rejects_arbitrary_commands_and_pids() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(&[("Contain", connector_local("Contain"))], "unknown");

    let command_request = with_fields(
        request_value("Contain", "op-contain-command", descriptor.clone()),
        json!({
            "reason": "operator containment",
            "command": "rm -rf /",
            "target": {"kind": "local_process", "resource_id": "process-1"},
            "policy": {"id": "containment-policy", "version": "3"},
            "affected_attempts": [{"attempt_id": "attempt-1"}],
            "unresolved_impact": ["remote job state remains unknown"],
        }),
    );
    let error = error_code(execute("Contain", check(command_request), &native, &clock, &store));
    assert_eq!(error, "arbitrary_execution_forbidden");

    let pid_request = with_fields(
        request_value("Contain", "op-contain-pid", descriptor),
        json!({
            "reason": "operator containment",
            "target": {"kind": "local_process", "resource_id": "process-1", "pid": 4242},
            "policy": {"id": "containment-policy", "version": "3"},
            "affected_attempts": [{"attempt_id": "attempt-1"}],
            "unresolved_impact": ["remote job state remains unknown"],
        }),
    );
    let error = error_code(execute("Contain", check(pid_request), &native, &clock, &store));
    assert_eq!(error, "arbitrary_execution_forbidden");
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_close_request_cannot_carry_cancel_or_reopen() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[(
            "CloseObservationConnection",
            connector_local("CloseObservationConnection"),
        )],
        "unknown",
    );

    for field in ["cancel", "request_native_cancel", "reopen", "resume_observation"] {
        let request = with_fields(
            request_value("CloseObservationConnection", "op-close-implication", descriptor.clone()),
            json!({"reason": "operator_stop", "end_observation": false, field: true}),
        );
        let error = error_code(execute(
            "CloseObservationConnection",
            check(request),
            &native,
            &clock,
            &store,
        ));
        assert_eq!(error, "implication_forbidden", "field {field} must be rejected");
    }
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_cancel_rejects_forced_termination() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-forced", descriptor),
        json!({"reason": "operator stop", "force": true}),
    );

    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "forced_termination_forbidden");
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_control_requires_scoped_control_grant() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-auth", descriptor),
        json!({"reason": "operator stop"}),
    );

    // A non-control grant cannot invoke any control verb.
    let native = RecordingNative::new(clock.clone());
    let error = error_code(execute_with_grant(
        check(request.clone()),
        &native,
        &clock,
        &store,
        non_control_grant(),
    ));
    assert_eq!(error, "control_not_granted");
    assert_eq!(native.invocations().len(), 0);

    // A control grant for another verb cannot be reused for cancel.
    let native = RecordingNative::new(clock.clone());
    let error = error_code(execute_with_grant(
        check(request.clone()),
        &native,
        &clock,
        &store,
        grant_for("CloseObservationConnection", "subject-1"),
    ));
    assert_eq!(error, "verb_not_granted");

    // A grant for another subject cannot control this subject.
    let native = RecordingNative::new(clock.clone());
    let error = error_code(execute_with_grant(
        check(request.clone()),
        &native,
        &clock,
        &store,
        grant_for("RequestNativeCancel", "subject-2"),
    ));
    assert_eq!(error, "subject_not_granted");
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_control_progresses_when_data_admission_is_saturated() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let config = AdmissionConfig {
        queue_rows: 1,
        queue_bytes: 1000,
        staging_bytes: 1000,
        observation_bytes: 1000,
        response_bound_bytes: 1000,
        stream_buffer_bytes: 100,
        control_slots: 2,
        control_cpu_units: 2,
        control_cpu_per_command: 1,
        cold_bootstrap_bytes: 1000,
        bootstrap_bytes_per_command: 100,
        ..AdmissionConfig::default()
    };
    let admission = MemoryAdmission::new(
        config,
        clock.clone(),
        store.clone(),
        grant_for("RequestNativeCancel", "subject-1"),
    )
    .expect("admission must build");

    let data_request = check(json!({
        "request_id": "data-1",
        "target": "jobs",
        "max_packet_rows": 1,
        "max_packet_bytes": 100,
    }));
    let held = admission
        .reserve_response(&data_request)
        .expect("first data reservation fits");
    let second = admission.reserve_response(&data_request);
    assert!(second.is_err(), "data queue must be saturated");
    assert_eq!(second.err().expect("fault").code, "backpressure_rows");

    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-under-pressure", descriptor),
        json!({"reason": "operator stop"}),
    );
    let grant = grant_for("RequestNativeCancel", "subject-1");
    let receipt = control(
        store.as_ref(),
        clock.as_ref(),
        &admission,
        &native,
        &grant,
        &check(request),
    )
    .expect("control progress is independently reserved");
    let observed = observation(&receipt);
    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(observed["cancel_requested"], json!(true));
    assert_eq!(
        record_value(&receipt)["native_invoked"],
        json!(true)
    );
    drop(held);
}

#[test]
fn c39_call_bound_is_enforced_on_the_registered_clock() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::advancing(clock.clone(), 50);
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-bound", descriptor),
        json!({
            "reason": "operator stop",
            "bounds": {
                "call_bound_ms": 10,
                "drain_bound_ms": 10,
                "cancellation_wait_ms": 10,
                "cleanup_wait_ms": 10,
            },
        }),
    );

    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "call_bound_exceeded");
    assert_eq!(native.invocations().len(), 1);
}

#[test]
fn c39_request_cannot_assert_acknowledgement_or_effect() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "unknown",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-assert", descriptor),
        json!({
            "reason": "operator stop",
            "acknowledged": true,
            "effect_refs": [evidence_ref("forged-effect")],
        }),
    );

    let error = error_code(execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    ));
    assert_eq!(error, "control_assertion_forbidden");
    assert_eq!(native.invocations().len(), 0);
}

#[test]
fn c39_present_capability_is_cited_without_becoming_the_mapping() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let native = RecordingNative::new(clock.clone());
    let descriptor = descriptor_for(
        &[("RequestNativeCancel", native_mapping("RequestNativeCancel"))],
        "present",
    );
    let request = with_fields(
        request_value("RequestNativeCancel", "op-cancel-capability", descriptor),
        json!({"reason": "operator stop"}),
    );

    let receipt = execute(
        "RequestNativeCancel",
        check(request),
        &native,
        &clock,
        &store,
    )
    .expect("cancel must be handled");
    let observed = observation(&receipt);
    let receipt_value = record_value(&receipt);

    assert_eq!(observed["disposition"], json!("acknowledged"));
    assert_eq!(
        receipt_value["capability_ref"]["capability_id"],
        json!("native_cancel")
    );
    assert_eq!(
        receipt_value["capability_ref"]["availability"],
        json!("present")
    );
    assert_eq!(
        receipt_value["native_mapping"]["implementation"],
        json!("native_mapping")
    );
    assert_eq!(
        native.invocations()[0]["capability_ref"]["availability"],
        json!("present")
    );
}
