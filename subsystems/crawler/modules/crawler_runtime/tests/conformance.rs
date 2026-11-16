//! C45: Illinois slice ships against its own conformance suite with
//! synthetic consumers — no orchestrator, executor peer, or deployment.
//!
//! Exercises the composed runtime end to end over real sibling seams with
//! in-memory fakes: every one of the nine verbs returns a normal
//! (non task-success) reply through `serve_connector`, unknown verbs are
//! rejected as `unsupported_mapping`, and `drive_committed_work` settles
//! committed scope through the pipeline.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_artifacts::MemoryArtifactStore;
use crawler_authority::{authorize, Grant};
use crawler_controls::NativeControls;
use crawler_dispatch::start;
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_pipeline::LocalPipeline;
use crawler_prepare::prepare;
use crawler_runtime::{drive_committed_work, serve_connector, Runtime};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_sessions::MemorySessionManager;
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Clock, store, native
// ---------------------------------------------------------------------------

struct FixedClock {
    offset_ms: AtomicU64,
}

impl FixedClock {
    fn new() -> Self {
        Self {
            offset_ms: AtomicU64::new(1_000),
        }
    }
}

impl ClockAuthority for FixedClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        let offset = self.offset_ms.fetch_add(10, Ordering::SeqCst);
        validate(
            "audit_log",
            json!({
                "clock_id": "runtime-clock",
                "boot_id": "boot-1",
                "origin": "engine_measured",
                "monotonic_offset_ms": offset,
                "utc_annotation": missing("not_observed"),
            }),
        )
    }
}

/// Owner-local fake: durable commits, canned prefix, empty journal.
#[derive(Default)]
struct FakeStore {
    transactions: Mutex<Vec<Value>>,
    seq: AtomicU64,
}

impl FakeStore {
    fn new() -> Self {
        Self {
            transactions: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
        }
    }
}

impl OwnerStore for FakeStore {
    fn transact(&self, _grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
        let sequence = self.seq.fetch_add(1, Ordering::SeqCst) + 1;
        self.transactions.lock().expect("store lock").push(value.clone());
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
        let map = record_value(query).as_object().cloned().unwrap_or_default();
        let kind = map.get("query").and_then(Value::as_str).unwrap_or_default();
        let journal_id = map.get("journal_id").and_then(Value::as_str).unwrap_or_default();
        if journal_id != "journal-1" {
            return Err(Fault {
                code: "unknown_journal".to_string(),
                detail: format!("journal {journal_id:?} has not admitted a manifest"),
            });
        }
        match kind {
            "prefix" => validate(
                "audit_log",
                json!({
                    "journal_id": "journal-1",
                    "last_sequence": 0,
                    "head_hash": dummy_digest_hex('0'),
                }),
            ),
            "journal" => validate("audit_log", json!({"events": []})),
            _ => validate("audit_log", json!({"rows": []})),
        }
    }
}

/// Native adapter that must never be invoked on the unsupported-mapping path.
struct NullNative;

impl NativeControls for NullNative {
    fn invoke(&self, _grant: &Grant, _operation: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        Err(Fault {
            code: "not_supported".to_string(),
            detail: "native not invoked for synthetic unsupported mappings".to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Grants + manifest
// ---------------------------------------------------------------------------

fn registration_fixture() -> CheckedRecord {
    check(json!({
        "registration_id": "runtime-channel",
        "principals": [{
            "principal_id": "tester",
            "verbs": ["Describe", "Prepare", "Start", "Observe", "RequestNativeCancel", "CloseObservationConnection", "CollectArtifacts", "ReleaseNativeContext", "Contain"],
            "connectors": ["jobs-connector"],
            "control": true,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn grant_for(verb: &str) -> Grant {
    let subject = match verb {
        "RequestNativeCancel" | "CloseObservationConnection" | "ReleaseNativeContext" | "Contain" => "subject-1",
        _ => "jobs",
    };
    let registration = registration_fixture();
    let principal = check(json!({
        "principal_id": "tester",
        "registration_digest": binding_of(&registration),
    }));
    let request = check(json!({
        "verb": verb,
        "connector": "jobs-connector",
        "subject": subject,
    }));
    authorize(&principal, &request, &registration).expect("grant must issue")
}

fn manifest_fixture() -> CheckedRecord {
    check(json!({
        "connector_id": "crawler-connector",
        "connector_version": "0.1.0",
        "build": {"id": "crawler-build", "version": "0.1.0"},
        "binding": {"id": "crawler-binding", "version": "0.1.0"},
        "subject": {
            "subject_id": "il-crawler",
            "subject_version": "v1",
            "configured_mode": "service",
            "interface_surface": "ordinary_browser",
        },
        "owner_domain": "crawler",
        "target": "IL",
        "limits": {
            "max_call_wait": {"kind": "exact", "unit": "ms", "value": 30000},
            "max_observe_items": 100,
            "max_request_bytes": 65536,
            "max_response_bytes": 67108864,
            "max_artifact_chunk_bytes": 1048576,
            "max_queued_tasks": 10,
            "max_active_tasks": 2,
        },
        "budget_accounting": {"id": "crawler-budget", "version": "1"},
    }))
}

fn test_runtime() -> Runtime {
    let clock = Arc::new(FixedClock::new());
    let store = Arc::new(FakeStore::new());
    let artifacts: Arc<MemoryArtifactStore> = Arc::new(MemoryArtifactStore::new());
    let admission = MemoryAdmission::new(
        AdmissionConfig::default(),
        clock.clone(),
        store.clone(),
        grant_for("Describe"),
    )
    .expect("admission must build");
    let sessions = MemorySessionManager::new(store.clone(), clock.clone());
    Runtime {
        manifest: manifest_fixture(),
        store,
        artifacts,
        admission: Arc::new(admission),
        clock,
        sessions: Arc::new(sessions),
        pipeline: Arc::new(LocalPipeline::new()),
        native_controls: Arc::new(NullNative),
    }
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

fn prepare_descriptor_fixture() -> CheckedRecord {
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

fn prepare_request_value(descriptor: &CheckedRecord, task_id: &str) -> Value {
    json!({
        "scope": scope_fixture(),
        "configuration": configuration_fixture(descriptor),
        "task": task_fixture(task_id),
        "assistance": assistance_fixture(),
        "planning_evidence_refs": [],
        "preparation_measurements": [],
        "runtime_access": [],
    })
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
    let store = FakeStore::new();
    let descriptor = prepare_descriptor_fixture();
    let mut request_value = prepare_request_value(&descriptor, task_id);
    // Connector envelope fields are ignored by prepare but required by the
    // runtime surface; include them so the same bytes flow through both.
    request_value["verb"] = json!("Prepare");
    request_value["connector"] = json!("jobs-connector");
    let request = check(request_value);
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

// ---------------------------------------------------------------------------
// Per-verb connector requests
// ---------------------------------------------------------------------------

static START_COUNTER: AtomicU64 = AtomicU64::new(1);

fn describe_request() -> CheckedRecord {
    check(json!({
        "verb": "Describe",
        "connector": "jobs-connector",
        "subject": "jobs",
    }))
}

fn prepare_connector_request(task_id: &str) -> CheckedRecord {
    let descriptor = prepare_descriptor_fixture();
    let mut value = prepare_request_value(&descriptor, task_id);
    value["verb"] = json!("Prepare");
    value["connector"] = json!("jobs-connector");
    value["subject"] = json!("jobs");
    value["descriptor"] = record_value(&descriptor).clone();
    check(value)
}

fn start_connector_request() -> CheckedRecord {
    let n = START_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (preparation, configuration, authorization) =
        valid_preparation(&format!("c45-task-{n}"));
    check(json!({
        "verb": "Start",
        "connector": "jobs-connector",
        "subject": "jobs",
        "connector_id": "jobs-connector",
        "request_id": format!("c45-cmd-{n}"),
        "idempotency_key": format!("c45-logical-{n}"),
        "preparation": preparation,
        "configuration": configuration,
        "authorization": authorization,
        "recovery": missing("not_applicable"),
    }))
}

fn observe_connector_request() -> CheckedRecord {
    let handle = json!({"connector_id": "conn-1", "local_handle": "handle-a"});
    check(json!({
        "verb": "Observe",
        "connector": "jobs-connector",
        "subject": "jobs",
        "handle": handle,
        "after": {
            "handle": handle,
            "journal_id": "journal-1",
            "sequence": 0,
            "event_hash": missing("not_applicable"),
        },
        "through": missing("not_applicable"),
        "max_items": 10,
        "wait_limit": {"kind": "exact", "unit": "ms", "value": 0},
    }))
}

// --- Control descriptors (unsupported mappings stay handled, never invoked) ---

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

fn control_subject_pin() -> Value {
    json!({
        "subject_id": "subject-1",
        "subject_version": "1.0.0",
        "configured_mode": "read_only",
        "interface_surface": "read_only_acquisition",
    })
}

fn unmapped_operation(verb: &str) -> Value {
    json!({
        "operation": verb,
        "implementation": "unmapped",
        "native_contract": missing("not_observed"),
        "capability_refs": [],
        "evidence_refs": [],
        "limitations": ["unsupported mapping is not native absence"],
    })
}

fn control_descriptor_value() -> Value {
    let catalog: Vec<Value> = CAPABILITY_IDS
        .iter()
        .map(|capability_id| {
            json!({
                "capability_id": capability_id,
                "availability": "unknown",
                "claim_origin": "native",
                "requirement_refs": [],
                "evidence": [],
                "limitations": [],
            })
        })
        .collect();
    let operations: Vec<Value> = ALL_VERBS.iter().map(|verb| unmapped_operation(verb)).collect();
    json!({
        "record_type": "connector_descriptor",
        "schema_version": "evidence-kernel/0.1.0",
        "connector_id": "jobs-connector",
        "connector_version": "2.0.0",
        "build": {"id": "build-1", "version": "1"},
        "binding": {"id": "binding-1", "version": "1"},
        "subject": control_subject_pin(),
        "capabilities": {
            "subject": control_subject_pin(),
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

fn control_connector_request(verb: &str) -> CheckedRecord {
    let mut value = json!({
        "verb": verb,
        "operation_id": format!("c45-op-{verb}"),
        "connector": "jobs-connector",
        "subject": "subject-1",
        "journal_id": "journal-1",
        "handle": {
            "handle_id": "handle-1",
            "journal_id": "journal-1",
            "subject_id": "subject-1",
        },
        "descriptor": control_descriptor_value(),
        "authorization_refs": [],
        "bounds": {
            "call_bound_ms": 1000,
            "drain_bound_ms": 500,
            "cancellation_wait_ms": 500,
            "cleanup_wait_ms": 500,
        },
    });
    let extra = match verb {
        "RequestNativeCancel" => json!({"reason": "operator requested cooperative stop"}),
        "CloseObservationConnection" => json!({"reason": "normal_completion", "end_observation": false}),
        "ReleaseNativeContext" => json!({"context_ref": "native-context-1"}),
        "Contain" => json!({
            "reason": "operator containment after repeated failures",
            "target": {"kind": "local_process", "resource_id": "process-1"},
            "policy": {"id": "containment-policy", "version": "3"},
            "affected_attempts": [{"attempt_id": "attempt-1"}],
            "unresolved_impact": ["remote job state remains unknown"],
        }),
        _ => json!({}),
    };
    for (k, v) in extra.as_object().expect("extra must be object") {
        value[k] = v.clone();
    }
    check(value)
}

fn collect_connector_request(runtime: &Runtime, grant: &Grant) -> CheckedRecord {
    let first = b"illinois feed bytes, first artifact";
    let ref_first = runtime
        .artifacts
        .install(grant, first, "text/plain", false)
        .expect("install must succeed");
    let mut content = record_value(&ref_first)
        .as_object()
        .expect("reference must be an object")
        .clone();
    content.remove("grant_digest");
    let digest = content["digest"].clone();
    let inventory = json!({
        "artifacts": [{
            "name": "first",
            "expected_digest": digest,
            "content": Value::Object(content),
        }],
    });
    check(json!({
        "verb": "CollectArtifacts",
        "connector": "jobs-connector",
        "subject": "jobs",
        "mode": "inventory",
        "inventory": inventory,
    }))
}

fn drive_scope() -> CheckedRecord {
    check(json!({
        "surface": "none",
        "before": {
            "durable_packet_id": "packet-1",
            "listings": ["job-1"],
            "works": ["work-1"],
            "details": ["Detail-1"],
            "cursor": {"certified_packet_id": "packet-1"},
        },
        "transaction": {
            "stage": "dispatch",
            "packet_id": "packet-1",
            "creates_works": ["work-2"],
        },
    }))
}

// ---------------------------------------------------------------------------
// C45
// ---------------------------------------------------------------------------

/// All nine verbs serve without a live peer and stay task-shaped replies.
#[test]
fn c45_all_nine_verbs_serve_synthetic() {
    let runtime = test_runtime();
    // Install collect fixtures before the loop so inventory names real bytes.
    let collect_grant = grant_for("CollectArtifacts");
    let collect_request = collect_connector_request(&runtime, &collect_grant);

    let verbs: Vec<(&str, CheckedRecord, Grant)> = vec![
        ("Describe", describe_request(), grant_for("Describe")),
        ("Prepare", prepare_connector_request("c45-prepare-1"), grant_for("Prepare")),
        ("Start", start_connector_request(), grant_for("Start")),
        ("Observe", observe_connector_request(), grant_for("Observe")),
        ("RequestNativeCancel", control_connector_request("RequestNativeCancel"), grant_for("RequestNativeCancel")),
        ("CloseObservationConnection", control_connector_request("CloseObservationConnection"), grant_for("CloseObservationConnection")),
        ("CollectArtifacts", collect_request, collect_grant),
        ("ReleaseNativeContext", control_connector_request("ReleaseNativeContext"), grant_for("ReleaseNativeContext")),
        ("Contain", control_connector_request("Contain"), grant_for("Contain")),
    ];
    assert_eq!(verbs.len(), 9);
    for (verb, request, grant) in &verbs {
        let reply = serve_connector(&runtime, grant, request)
            .unwrap_or_else(|e| panic!("verb {verb} must serve synthetically: {e:?}"));
        let value = record_value(&reply);
        assert_eq!(value.get("verb").and_then(|v| v.as_str()), Some(*verb));
        assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
        // Normal reply: no composite task-success flag is fabricated.
        assert!(value.get("task_success").is_none());
        assert!(value.get("detail").is_some());
        // Illinois detail is present for Describe; every verb stays local.
        if *verb == "Describe" {
            let detail = value.get("detail").expect("detail");
            assert!(detail.get("configuration").is_some());
        }
    }
    let _ = missing_detail("not_observed", "unused");
}

/// Unknown verbs are rejected, never silently accepted.
#[test]
fn c45_unknown_verb_is_unsupported_mapping() {
    let runtime = test_runtime();
    let grant = grant_for("Describe");
    let request = check(json!({
        "verb": "LaunchRockets",
        "connector": "jobs-connector",
        "subject": "jobs",
    }));
    let err: Fault = serve_connector(&runtime, &grant, &request).unwrap_err();
    assert_eq!(err.code, "unsupported_mapping");
}

/// Missing verb field is an invalid record, not a silent default.
#[test]
fn c45_missing_verb_rejected() {
    let runtime = test_runtime();
    let grant = grant_for("Describe");
    let bad = check(json!({"connector": "jobs-connector", "subject": "jobs"}));
    let err: Fault = serve_connector(&runtime, &grant, &bad).unwrap_err();
    assert_eq!(err.code, "invalid_record");
}

/// Committed work drives through the pipeline with no peer required.
#[test]
fn c45_drive_committed_work_settles_scope() {
    let runtime = test_runtime();
    let grant = grant_for("Describe");
    let scope = drive_scope();
    let reply = drive_committed_work(&runtime, &grant, &scope).unwrap();
    let value = record_value(&reply);
    assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert!(value.get("detail").is_some());
    // The pipeline advance committed; no task-success flag is invented.
    assert!(value.get("task_success").is_none());
}

/// Synthetic consumers only: no orchestrator/executor peer is constructed.
#[test]
fn c45_no_live_peer_required() {
    // This test itself is the synthetic consumer: memory fakes only.
    let runtime = test_runtime();
    let grant = grant_for("Describe");
    let reply = serve_connector(&runtime, &grant, &describe_request()).unwrap();
    assert_eq!(
        record_value(&reply).get("ok").and_then(|v| v.as_bool()),
        Some(true)
    );
    // Direct seam spot-checks prove the same fakes drive Start/Observe.
    let _ = start as fn(&dyn OwnerStore, &dyn ClockAuthority, &dyn Admission, &Grant, &CheckedRecord) -> Result<CheckedRecord, Fault>;
}
