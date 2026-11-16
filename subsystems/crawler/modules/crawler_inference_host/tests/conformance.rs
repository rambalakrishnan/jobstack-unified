//! Conformance test for **C17 — SLM isolation**.
//!
//! Inference memory failure cannot terminate the crawler; an induced
//! isolation violation invalidates the run. The run then can never be
//! represented as a successful completion, and no classifier work is admitted
//! before readiness.

use crawler_admission::{Admission, AdmissionConfig, MemoryAdmission};
use crawler_authority::{authorize, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_inference_host::{BoundedInferenceHost, HostConfig, InferenceEngine, InferenceHost};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const CLOCK_ID: &str = "inference-host-clock";
const BOOT_ID: &str = "boot-1";

fn check(value: Value) -> CheckedRecord {
    validate("audit_log", value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
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

fn timepoint(offset_ms: u64) -> Value {
    json!({
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": missing("not_observed"),
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
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "audit_log",
            timepoint(self.offset_ms.load(Ordering::SeqCst)),
        )
    }
}

/// Owner-local store seam; admission settlement must become durable here.
#[derive(Default)]
struct RecordingStore {
    transactions: Mutex<Vec<Value>>,
}

impl RecordingStore {
    fn transactions(&self) -> Vec<Value> {
        self.transactions.lock().expect("store lock").clone()
    }
}

impl OwnerStore for RecordingStore {
    fn transact(&self, grant: &Grant, transaction: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let value = record_value(transaction).clone();
        let owner_domain = record_value(grant_record(grant))["owner_domain"].clone();
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
                "owner_domain": owner_domain,
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

fn registration_fixture() -> CheckedRecord {
    check(json!({
        "registration_id": "inference-host-channel",
        "principals": [{
            "principal_id": "inference-owner",
            "verbs": ["Start"],
            "connectors": ["jobs-connector"],
            "control": true,
            "owner_domain": "crawler",
            "restricted_access": false,
        }],
    }))
}

fn owner_grant() -> Grant {
    let registration = registration_fixture();
    let binding = digest_bytes(
        &canonical_bytes(&registration).expect("registration canonical bytes must exist"),
    );
    let principal = check(json!({
        "principal_id": "inference-owner",
        "registration_digest": binding,
    }));
    let request = check(json!({"verb": "Start", "connector": "jobs-connector"}));
    authorize(&principal, &request, &registration).expect("owner grant must issue")
}

fn subject_pin() -> Value {
    json!({
        "subject_id": "mn-crawler",
        "subject_version": "v1",
        "configured_mode": "service",
        "interface_surface": "ordinary_browser",
    })
}

/// Minimal honest connector descriptor: every required capability is present
/// in the catalog as `unknown` with an explicit limitation.
fn descriptor() -> Value {
    let ids = [
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
    let catalog: Vec<Value> = ids
        .iter()
        .map(|id| {
            json!({
                "capability_id": id,
                "availability": "unknown",
                "claim_origin": "native",
                "requirement_refs": [],
                "evidence": [],
                "limitations": ["no executed observation for this subject version"],
            })
        })
        .collect();
    json!({
        "record_type": "connector_descriptor",
        "subject": subject_pin(),
        "capabilities": {
            "subject": subject_pin(),
            "capabilities": catalog,
        },
    })
}

/// Pinned classifier manifest. `engine_domain` is the isolation axis under
/// test: a separate process/domain is admissible, an in-process engine is an
/// induced violation.
fn manifest(run_id: &str, engine_domain: &str) -> CheckedRecord {
    check(json!({
        "run_id": run_id,
        "manifest_revision": "rev-1",
        "model": {
            "id": "slm-classifier",
            "version": "slm-0.1.0",
            "artifact_digest": format!("sha256:{}", "a".repeat(64)),
            "tokenizer_digest": format!("sha256:{}", "b".repeat(64)),
            "prompt_digest": format!("sha256:{}", "c".repeat(64)),
        },
        "limits": {
            "max_items": 25,
            "collection_dwell_ms": 20,
            "batch_token_budget": 8192,
        },
        "isolation": {
            "engine_domain": engine_domain,
            "host_memory_bytes": 2_147_483_648u64,
            "ipc_buffer_bytes": 1_048_576u64,
            "crawler_reserve_bytes": 209_715_200u64,
            "storage_reserve_bytes": 104_857_600u64,
            "os_reserve_bytes": 268_435_456u64,
            "control_lane_slots": 1,
        },
        "capability": {
            "capability_id": "learning_state_control",
            "descriptor": descriptor(),
            "scope": subject_pin(),
        },
    }))
}

fn batch(run_id: &str, batch_id: &str) -> CheckedRecord {
    check(json!({
        "run_id": run_id,
        "manifest_revision": "rev-1",
        "batch_id": batch_id,
        "target": "MN",
        "stage": "snippet",
        "model_version": "slm-0.1.0",
        "items": [
            {
                "job_id": "job-1",
                "input_hash": format!("sha256:{}", "1".repeat(64)),
                "token_count": 64u64,
                "title": "Rust engineer",
                "employer": "Acme",
            },
            {
                "job_id": "job-2",
                "input_hash": format!("sha256:{}", "2".repeat(64)),
                "token_count": 48u64,
                "title": "Systems engineer",
                "employer": "Beta",
            },
        ],
        "collection_dwell_ms": 5u64,
        "token_estimate": 112u64,
        "lease_expires_at": timepoint(60_000),
    }))
}

#[derive(Clone, Debug)]
enum EngineScript {
    Success { verdict: &'static str, confidence: f64 },
    MemoryFailure,
    WidenedMemoryBound,
    Panic,
}

struct ScriptedEngine {
    script: Mutex<EngineScript>,
    calls: AtomicU64,
    requests: Mutex<Vec<Value>>,
}

impl ScriptedEngine {
    fn new(script: EngineScript) -> Self {
        Self {
            script: Mutex::new(script),
            calls: AtomicU64::new(0),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, script: EngineScript) {
        *self.script.lock().expect("script lock") = script;
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

fn success_result(
    request: &Value,
    verdict: &str,
    confidence: f64,
    limit_delta: u64,
) -> Result<CheckedRecord, Fault> {
    let host_bound = request["isolation"]["host_memory_bytes"]
        .as_u64()
        .expect("dispatch isolates host memory");
    let items = request["items"].as_array().expect("dispatch carries items");
    let outputs: Vec<Value> = items
        .iter()
        .map(|item| {
            json!({
                "job_id": item["job_id"].clone(),
                "input_hash": item["input_hash"].clone(),
                "verdict": verdict,
                "verdict_applied": verdict,
                "confidence": confidence,
                "reason": "title and employer correlate with the pinned job",
            })
        })
        .collect();
    validate(
        "audit_log",
        json!({
            "run_id": request["run_id"].clone(),
            "manifest_revision": request["manifest_revision"].clone(),
            "target": request["target"].clone(),
            "stage": request["stage"].clone(),
            "model_version": request["model"]["version"].clone(),
            "memory": {
                "peak_bytes": 536_870_912u64,
                "limit_bytes": host_bound + limit_delta,
            },
            "items": outputs,
        }),
    )
}

impl InferenceEngine for ScriptedEngine {
    fn execute(&self, request: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request_value = record_value(request).clone();
        self.requests
            .lock()
            .expect("request log lock")
            .push(request_value.clone());
        let script = self.script.lock().expect("script lock").clone();
        match script {
            EngineScript::Panic => panic!("induced inference-domain panic"),
            EngineScript::MemoryFailure => Err(Fault {
                code: "inference_memory_exceeded".to_string(),
                detail: "the bounded inference domain exhausted its heap under an oversized item"
                    .to_string(),
            }),
            EngineScript::Success {
                verdict,
                confidence,
            } => success_result(&request_value, verdict, confidence, 0),
            EngineScript::WidenedMemoryBound => {
                success_result(&request_value, "PASS", 0.9, 1_073_741_824)
            }
        }
    }
}

fn build_host(
    clock: Arc<TestClock>,
    store: Arc<RecordingStore>,
    engine: Arc<ScriptedEngine>,
) -> (BoundedInferenceHost, Arc<MemoryAdmission>) {
    let admission = Arc::new(
        MemoryAdmission::new(
            AdmissionConfig::default(),
            clock.clone(),
            store,
            owner_grant(),
        )
        .expect("admission must build"),
    );
    let host = BoundedInferenceHost::new(
        clock,
        admission.clone() as Arc<dyn Admission>,
        engine,
        HostConfig::default(),
    )
    .expect("inference host must build");
    (host, admission)
}

#[test]
fn c17_slm_isolation_memory_failure_cannot_terminate_crawler() {
    let clock = Arc::new(TestClock::new());
    let store = Arc::new(RecordingStore::default());
    let engine = Arc::new(ScriptedEngine::new(EngineScript::Success {
        verdict: "PASS",
        confidence: 0.92,
    }));
    let (host, admission) = build_host(clock, store.clone(), engine.clone());

    // ------------------------------------------------------------------
    // Readiness is the claim gate: a separately bounded domain, independent
    // host memory, bounded IPC, and crawler/storage/OS reserves are declared.
    // ------------------------------------------------------------------
    let ready = host
        .ensure_ready(&manifest("run-a", "separate_process"))
        .expect("isolated manifest must become ready");
    let ready = record_value(&ready);
    assert_eq!(ready["status"], "ready");
    assert_eq!(ready["claim_gate"], "open");
    assert_eq!(ready["isolation"]["engine_domain"], "separate_process");
    assert_eq!(
        ready["isolation"]["host_memory_bytes"],
        json!(2_147_483_648u64)
    );
    assert_eq!(ready["crawler_terminated"], false);
    // Unverified capability stays honestly unknown; readiness does not
    // fabricate a certified finding.
    assert_eq!(ready["capability"]["availability"], "unknown");
    assert_no_bare_nulls(ready);
    let stats = admission.stats().expect("admission stats");
    assert_eq!(stats.committed_total, 0);
    assert_eq!(stats.control_slots_used, 0);

    // ------------------------------------------------------------------
    // Admitted inference: bounded reservation, correlated outputs, durable
    // settlement, and no fabricated measured target.
    // ------------------------------------------------------------------
    let results = host
        .infer(&batch("run-a", "batch-1"))
        .expect("admitted inference must succeed");
    let results = record_value(&results);
    assert_eq!(results["accepted_count"], 2);
    assert_eq!(results["partial"], false);
    assert_eq!(results["items"][0]["verdict"], "PASS");
    assert_eq!(results["items"][0]["stage"], "snippet");
    assert_eq!(results["items"][0]["model_version"], "slm-0.1.0");
    assert_eq!(results["crawler_terminated"], false);
    assert_no_bare_nulls(results);
    let stats = admission.stats().expect("admission stats");
    assert_eq!(stats.committed_total, 1);
    assert_eq!(stats.rows_used, 0);
    assert_eq!(stats.bytes_used, 0);
    assert_eq!(store.transactions().len(), 1);

    // ------------------------------------------------------------------
    // Inference memory failure is contained: no abort, no crawler
    // termination, run invalidated, claims stopped, and the reservation is
    // released rather than silently retained.
    // ------------------------------------------------------------------
    engine.set(EngineScript::MemoryFailure);
    let cancelled_before = admission
        .stats()
        .expect("admission stats")
        .cancelled_total;
    let error = host
        .infer(&batch("run-a", "batch-2"))
        .expect_err("memory failure must be a contained fault");
    assert_eq!(error.code, "inference_memory_failure");
    let stats = admission.stats().expect("admission stats");
    assert_eq!(stats.cancelled_total, cancelled_before + 1);
    assert_eq!(stats.rows_used, 0);
    assert_eq!(stats.bytes_used, 0);
    let events = host.containment_events().expect("containment evidence");
    let events = record_value(&events);
    assert_eq!(events["total_events"], 1);
    assert_eq!(events["events"][0]["event_kind"], "inference_memory_failure");
    assert_eq!(events["events"][0]["crawler_terminated"], false);
    assert_eq!(events["events"][0]["contained_outside_crawler"], true);
    assert_eq!(events["events"][0]["run_invalidated"], true);
    assert_eq!(events["events"][0]["claims"], "stopped");
    assert_eq!(
        events["events"][0]["successful_completion_prevented"],
        true
    );
    assert_no_bare_nulls(events);

    // The crawler process (and this host) still serves another run: a
    // memory failure in the inference domain is not crawler termination.
    engine.set(EngineScript::Success {
        verdict: "VETO",
        confidence: 0.4,
    });
    host.ensure_ready(&manifest("run-b", "separate_process"))
        .expect("host survives the contained memory failure");
    let veto = host
        .infer(&batch("run-b", "batch-3"))
        .expect("healthy inference after containment");
    let veto = record_value(&veto);
    assert_eq!(veto["items"][0]["verdict"], "VETO");

    // The invalidated run can never be represented as a successful
    // completion: neither re-readiness nor a fresh batch reopens it.
    let error = host
        .infer(&batch("run-a", "batch-4"))
        .expect_err("invalidated run must be fenced");
    assert_eq!(error.code, "run_invalidated");
    let error = host
        .ensure_ready(&manifest("run-a", "separate_process"))
        .expect_err("invalidated run cannot become ready again");
    assert_eq!(error.code, "run_invalidated");

    // ------------------------------------------------------------------
    // Induced isolation violation: the engine ran under a widened memory
    // bound instead of the admitted host bound. The run is invalidated.
    // ------------------------------------------------------------------
    engine.set(EngineScript::WidenedMemoryBound);
    let error = host
        .infer(&batch("run-b", "batch-5"))
        .expect_err("widened memory bound must be rejected");
    assert_eq!(error.code, "isolation_violation");
    let events = host.containment_events().expect("containment evidence");
    let events = record_value(&events);
    assert_eq!(events["total_events"], 2);
    assert_eq!(events["events"][1]["event_kind"], "isolation_violation");
    assert_eq!(events["events"][1]["engine_domain"], "separate_process");
    assert_eq!(events["events"][1]["run_invalidated"], true);
    let error = host
        .infer(&batch("run-b", "batch-6"))
        .expect_err("run-b stays invalidated");
    assert_eq!(error.code, "run_invalidated");

    // ------------------------------------------------------------------
    // Induced isolation violation at readiness: an in-process engine
    // declaration is never admitted, never dispatches inference, and
    // invalidates the run.
    // ------------------------------------------------------------------
    let calls_before = engine.calls();
    let error = host
        .ensure_ready(&manifest("run-c", "in_process"))
        .expect_err("in-process inference domain must be rejected");
    assert_eq!(error.code, "isolation_violation");
    assert_eq!(
        engine.calls(),
        calls_before,
        "an unready manifest never dispatches inference"
    );
    let events = host.containment_events().expect("containment evidence");
    let events = record_value(&events);
    assert_eq!(events["total_events"], 3);
    assert_eq!(events["events"][2]["event_kind"], "isolation_violation");
    assert_eq!(events["events"][2]["run_invalidated"], true);
    assert_eq!(
        events["events"][2]["contained_outside_crawler"],
        false,
        "an in-process engine declaration is not evidence of a separate containment domain"
    );
    let error = host
        .ensure_ready(&manifest("run-c", "separate_process"))
        .expect_err("run-c stays invalidated");
    assert_eq!(error.code, "run_invalidated");

    // ------------------------------------------------------------------
    // An inference-domain panic cannot terminate the crawler either; it is
    // contained at the boundary and invalidates the run.
    // ------------------------------------------------------------------
    engine.set(EngineScript::Panic);
    host.ensure_ready(&manifest("run-d", "separate_process"))
        .expect("run-d readiness");
    let error = host
        .infer(&batch("run-d", "batch-7"))
        .expect_err("engine panic must be contained");
    assert_eq!(error.code, "inference_engine_panic");
    let events = host.containment_events().expect("containment evidence");
    let events = record_value(&events);
    assert_eq!(events["total_events"], 4);
    assert_eq!(events["events"][3]["event_kind"], "inference_engine_panic");
    assert_eq!(events["events"][3]["crawler_terminated"], false);
    assert_eq!(events["retention_bound"], 64);

    // Every containment left the host callable for a fresh run.
    engine.set(EngineScript::Success {
        verdict: "PASS",
        confidence: 0.5,
    });
    host.ensure_ready(&manifest("run-e", "separate_process"))
        .expect("run-e readiness after every containment");
    host.infer(&batch("run-e", "batch-8"))
        .expect("run-e inference after every containment");
    let stats = admission.stats().expect("admission stats");
    assert_eq!(stats.committed_total, 3);
    assert!(stats.cancelled_total >= 3);
    assert_eq!(stats.rows_used, 0);
    assert_eq!(stats.bytes_used, 0);
    let final_events = host.containment_events().expect("containment evidence");
    assert_eq!(record_value(&final_events)["crawler_terminated"], false);
    assert!(record_value(&final_events).get("events").is_some());
}
