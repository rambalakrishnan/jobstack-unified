//! C45: Illinois slice ships against its own conformance suite with
//! synthetic consumers — no orchestrator, executor peer, or deployment.
//!
//! Exercises the composed runtime end to end over in-memory stubs:
//! every one of the nine verbs returns a normal (non task-success)
//! reply through `serve_connector`, unknown verbs are rejected as
//! `unsupported_mapping`, and `drive_committed_work` settles committed
//! scope through the pipeline.

use crawler_runtime::{
    authorize, validate, Fault, Grant, MemoryAdmission, MemoryArtifacts, MemoryStore,
    NullNativeControls, NullPipeline, NullSessions, Runtime, TestClock,
};
use serde_json::json;
use std::sync::Arc;

fn test_runtime() -> Runtime {
    let manifest = validate("manifest", json!({"slice": "illinois"})).unwrap();
    Runtime {
        manifest,
        store: Arc::new(MemoryStore),
        artifacts: Arc::new(MemoryArtifacts),
        admission: Arc::new(MemoryAdmission),
        clock: Arc::new(TestClock {
            utc: "2026-01-01T00:00:00Z".to_string(),
            tick: 1,
        }),
        sessions: Arc::new(NullSessions),
        pipeline: Arc::new(NullPipeline),
        native_controls: Arc::new(NullNativeControls),
    }
}

fn test_grant() -> Grant {
    authorize(
        &validate("principal", json!({})).unwrap(),
        &validate("request", json!({})).unwrap(),
        &validate("registration", json!({})).unwrap(),
    )
    .unwrap()
}

fn request(verb: &str) -> crawler_runtime::CheckedRecord {
    validate(
        "connector.request",
        json!({"verb": verb, "handle": "h-1", "scope": "illinois"}),
    )
    .unwrap()
}

/// All nine verbs serve without a live peer and stay task-shaped replies.
#[test]
fn c45_all_nine_verbs_serve_synthetic() {
    let runtime = test_runtime();
    let grant = test_grant();
    for verb in [
        "Describe",
        "Prepare",
        "Start",
        "Observe",
        "RequestNativeCancel",
        "CloseObservationConnection",
        "CollectArtifacts",
        "ReleaseNativeContext",
        "Contain",
    ] {
        let reply =
            crawler_runtime::serve_connector(&runtime, &grant, &request(verb)).unwrap();
        let value = crawler_runtime::record_value(&reply);
        assert_eq!(value.get("verb").and_then(|v| v.as_str()), Some(verb));
        assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
        // Normal reply: no composite task-success flag is fabricated.
        assert!(value.get("task_success").is_none());
        assert!(value.get("detail").is_some());
    }
}

/// Unknown verbs are rejected, never silently accepted.
#[test]
fn c45_unknown_verb_is_unsupported_mapping() {
    let runtime = test_runtime();
    let grant = test_grant();
    let err: Fault =
        crawler_runtime::serve_connector(&runtime, &grant, &request("LaunchRockets"))
            .unwrap_err();
    assert_eq!(err.code, "unsupported_mapping");
}

/// Missing verb field is an invalid record, not a silent default.
#[test]
fn c45_missing_verb_rejected() {
    let runtime = test_runtime();
    let grant = test_grant();
    let bad = validate("connector.request", json!({"scope": "illinois"})).unwrap();
    let err: Fault = crawler_runtime::serve_connector(&runtime, &grant, &bad).unwrap_err();
    assert_eq!(err.code, "invalid_record");
}

/// Committed work drives through the pipeline with no peer required.
#[test]
fn c45_drive_committed_work_settles_scope() {
    let runtime = test_runtime();
    let grant = test_grant();
    let scope = validate("work.scope", json!({"unit": "stage-1", "slice": "illinois"})).unwrap();
    let reply = crawler_runtime::drive_committed_work(&runtime, &grant, &scope).unwrap();
    let value = crawler_runtime::record_value(&reply);
    assert_eq!(value.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert!(value.get("detail").is_some());
}

/// Synthetic consumers only: no orchestrator/executor peer is constructed.
#[test]
fn c45_no_live_peer_required() {
    // This test itself is the synthetic consumer: memory stubs only.
    let runtime = test_runtime();
    let grant = test_grant();
    let reply =
        crawler_runtime::serve_connector(&runtime, &grant, &request("Describe")).unwrap();
    assert_eq!(
        crawler_runtime::record_value(&reply).get("ok").and_then(|v| v.as_bool()),
        Some(true)
    );
}
