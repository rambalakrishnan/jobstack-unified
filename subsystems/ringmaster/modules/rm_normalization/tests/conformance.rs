//! Conformance tests for RM-C33 (authenticated trace mismatch) and RM-C34
//! (Unit/None, primitive return, lifecycle completion carry no automatic
//! application success).
//!
//! Every test name carries `rm_c33` or `rm_c34` so the verification filter
//! `cargo test -p rm_normalization -- rm_c33 rm_c34` selects the suite.

use rm_authority::{authenticate_channel, Manifest};
use rm_evidence::{
    append_event, install_artifact, journal_id_for, manifest_artifact_reference, AccessClass,
    ArtifactReference, AuthenticatedPrincipal, EvidencePayload, EvidenceRef, EventSubmission,
    JournalEnvelope, PositiveInteger,
};
use rm_normalization::{
    ClaimState, ConnectorHandle, MaybeEvidenceRef, NativeReportObservation, SourceChecks,
    VersionPin,
};
use rm_time::{MaybeString, MaybeTimePoint, MeasurementOrigin, Missing, TimePoint, UtcAnnotation};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn principal(id: &str) -> AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": id,
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": format!("binding-{id}"),
        },
    });
    let bytes = serde_json::to_vec(&registration).expect("registration serializes");
    authenticate_channel(&mut Cursor::new(bytes)).expect("test principal authenticates")
}

fn test_manifest(run: &str) -> Manifest {
    let mut m = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "clock_registered",
            "dispatch_published",
            "observation_opened",
            "observation_closed",
            "context_observation",
            "execution_claim",
            "native_report",
            "task_output",
            "origin_fact",
            "report_published",
            "artifact_available",
            "control_observation",
            "connector_incident",
            "lifecycle_publication",
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&m);
    m.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    m
}

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive integer")
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact = manifest_artifact_reference(manifest).expect("manifest artifact reference");
    EventSubmission {
        producer_sequence: Some(seq(1)),
        event_kind: "manifest_admitted".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_applicable")),
        payload: EvidencePayload {
            data: json!({"manifest": artifact.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![artifact],
        },
    }
}

fn admit(writer: &AuthenticatedPrincipal, manifest: &Manifest) -> JournalEnvelope {
    append_event(writer, manifest, admission(manifest)).expect("manifest admission")
}

fn ref_to(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    install_artifact(writer, &reference, bytes).expect("artifact install");
    reference
}

fn test_timepoint(clock: &str, boot: &str, offset: f64) -> TimePoint {
    TimePoint {
        clock_id: clock.to_string(),
        boot_id: boot.to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn handle_for(manifest: &Manifest, journal_id: &str, local: &str) -> ConnectorHandle {
    ConnectorHandle {
        record_type: "connector_handle".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        connector_id: "rm-normalization-test".to_string(),
        local_handle: local.to_string(),
        preparation_id: format!("prep-{local}"),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id.to_string(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        idempotency_key: format!("key-{local}"),
        created_at: test_timepoint("clock-handle", "boot-handle", 1.0),
    }
}

fn mapping_pin(tag: &str) -> VersionPin {
    VersionPin {
        id: format!("mapping-{tag}"),
        version: "v1".to_string(),
        artifact_digest: artifact_digest(format!("mapping-{tag}").as_bytes()),
    }
}

fn verifier_pin(tag: &str) -> VersionPin {
    VersionPin {
        id: format!("verifier-{tag}"),
        version: "v1".to_string(),
        artifact_digest: artifact_digest(format!("verifier-{tag}").as_bytes()),
    }
}

fn checks_for(
    authentication: &str,
    correlation: &str,
    trace: &str,
    matched_by: Vec<String>,
    evidence: Vec<EvidenceRef>,
    tag: &str,
) -> SourceChecks {
    SourceChecks {
        authentication: authentication.to_string(),
        correlation: correlation.to_string(),
        trace_correlation: trace.to_string(),
        verification_policy: verifier_pin(tag),
        matched_by,
        evidence_refs: evidence,
    }
}

/// Asserts the emitted observation JSON carries no bare nulls: every null must
/// sit inside a `{value: null, reason}` Missing envelope.
fn assert_no_bare_nulls(value: &Value, path: &str) {
    match value {
        Value::Null => panic!("bare null at {path}; expected a Missing envelope"),
        Value::Object(map) => {
            if map.get("value") == Some(&Value::Null) {
                assert!(
                    map.contains_key("reason"),
                    "null carrier at {path} must be a Missing envelope"
                );
                for key in map.keys() {
                    assert!(
                        ["value", "reason", "Detail", "detail", "detail"].contains(&key.as_str()),
                        "Missing envelope at {path} carries undeclared field {key:?}"
                    );
                }
                return;
            }
            for (key, item) in map {
                assert_no_bare_nulls(item, &format!("{path}.{key}"));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                assert_no_bare_nulls(item, &format!("{path}[{index}]"));
            }
        }
        _ => {}
    }
}

fn assert_no_bare_nulls_observation(observation: &NativeReportObservation) {
    assert_no_bare_nulls(&observation.to_json(), "observation");
}

// ---------------------------------------------------------------------------
// RM-C33: authenticated trace mismatch
// ---------------------------------------------------------------------------

#[test]
fn rm_c33_trace_mismatch_without_alternate_has_no_claims() {
    let run = "rm-norm-c33-no-alternate";
    let writer = principal("writer-c33-no-alternate");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c33-no-alternate");
    let mapping = mapping_pin("c33-no-alternate");

    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "status": "completed",
        "native_run_id": "native-run-1",
        "native_message_id": "native-msg-1",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");

    // Authenticated + correlated, but the trace mismatches with no explicit
    // alternate mechanism: no accepted claims.
    let checks = checks_for(
        "verified",
        "matched",
        "mismatched",
        Vec::new(),
        vec![seq1.clone()],
        "c33-no-alternate",
    );
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("trace mismatch without alternate yields an observation");
    assert_eq!(observation.kind, "native_report");
    assert!(
        observation.normalized_claims.is_empty(),
        "trace mismatch without proven alternate correlation must yield zero claims"
    );
    assert_eq!(observation.source_checks.authentication, "verified");
    assert_eq!(observation.source_checks.correlation, "matched");
    assert_eq!(observation.source_checks.trace_correlation, "mismatched");
    assert!(
        observation
            .limitations
            .iter()
            .any(|text| text.contains("trace mismatch")),
        "trace mismatch must be disclosed, got {:?}",
        observation.limitations
    );
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c33_trace_mismatch_with_alternate_yields_claims() {
    let run = "rm-norm-c33-alternate";
    let writer = principal("writer-c33-alternate");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c33-alternate");
    let mapping = mapping_pin("c33-alternate");

    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "callback",
        "status": "completed",
        "native_run_id": "native-run-2",
        "native_message_id": "native-msg-2",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");

    // Same trace mismatch, but now with explicit alternate correlation plus
    // retained evidence: the lifecycle claim is accepted and the mismatch is
    // still preserved on the checks.
    let checks = checks_for(
        "verified",
        "matched",
        "mismatched",
        vec!["alternate-request-binding".to_string()],
        vec![seq1.clone()],
        "c33-alternate",
    );
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("proven alternate correlation yields claims");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "execution_lifecycle");
    assert_eq!(claim.state, ClaimState::Completed);
    assert!(
        claim.application_assertions.is_empty(),
        "lifecycle completion carries no automatic application assertions"
    );
    assert_eq!(claim.source_checks.trace_correlation, "mismatched");
    assert_eq!(claim.source_checks.authentication, "verified");
    assert_eq!(claim.source_checks.correlation, "matched");
    assert!(
        claim
            .limitations
            .iter()
            .any(|text| text.contains("trace mismatch") && text.contains("alternate")),
        "alternate correlation must be explicit, got {:?}",
        claim.limitations
    );
    // Agreement: claim pins the exact raw, mapping, and checks.
    assert_eq!(claim.native_report, raw);
    assert_eq!(claim.mapping, mapping);
    assert_eq!(claim.source_checks, observation.source_checks);
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c33_authenticated_but_uncorrelated_has_no_claims() {
    let run = "rm-norm-c33-uncorrelated";
    let writer = principal("writer-c33-uncorrelated");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c33-uncorrelated");
    let mapping = mapping_pin("c33-uncorrelated");

    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "status": "failed",
        "native_run_id": "native-run-3",
        "native_message_id": "native-msg-3",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");

    // Case A: authenticated but correlation mismatched.
    let mismatched = checks_for(
        "verified",
        "mismatched",
        "mismatched",
        Vec::new(),
        vec![seq1.clone()],
        "c33-uncorrelated-a",
    );
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw,
        &seq1,
        &mismatched,
        &mapping,
    )
    .expect("mismatched correlation yields an observation");
    assert!(
        observation.normalized_claims.is_empty(),
        "authenticated but uncorrelated messages remain receipt evidence, not claims"
    );
    assert_eq!(observation.source_checks.authentication, "verified");
    assert_eq!(observation.source_checks.correlation, "mismatched");
    assert_no_bare_nulls_observation(&observation);

    // Case B: correlation matched on paper but authentication failed.
    let failed_auth = checks_for(
        "failed",
        "matched",
        "not_observed",
        vec!["trace-9".to_string()],
        vec![seq1.clone()],
        "c33-uncorrelated-b",
    );
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw,
        &seq1,
        &failed_auth,
        &mapping,
    )
    .expect("failed authentication yields an observation");
    assert!(
        observation.normalized_claims.is_empty(),
        "unverified source yields no accepted claims even when correlation claims matched"
    );
    assert_eq!(observation.source_checks.authentication, "failed");
    assert_no_bare_nulls_observation(&observation);

    // Case C: both unknown.
    let unknown = checks_for(
        "unknown",
        "unknown",
        "not_observed",
        Vec::new(),
        vec![seq1.clone()],
        "c33-uncorrelated-c",
    );
    let observation = rm_normalization::normalize_report(
        &writer, &handle, &raw, &seq1, &unknown, &mapping,
    )
    .expect("unknown checks yield an observation");
    assert!(observation.normalized_claims.is_empty());
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c33_unresolved_verification_evidence_is_rejected() {
    let run = "rm-norm-c33-unresolved";
    let writer = principal("writer-c33-unresolved");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c33-unresolved");
    let mapping = mapping_pin("c33-unresolved");

    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "status": "completed",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");

    // Serialized verified/matched labels without retained verification
    // evidence must not be trusted.
    let bogus = EvidenceRef {
        journal_id: "journal-does-not-exist".to_string(),
        sequence: seq(1),
        event_id: "event-bogus".to_string(),
        event_hash: artifact_digest(b"bogus"),
        pointer: String::new(),
    };
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-bogus".to_string()],
        vec![bogus],
        "c33-unresolved",
    );
    let error =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect_err("unresolved verification evidence must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("verification evidence") || error.detail.contains("retained"),
        "unexpected detail: {}",
        error.detail
    );
}

// ---------------------------------------------------------------------------
// RM-C34: no automatic application success
// ---------------------------------------------------------------------------

#[test]
fn rm_c34_unit_none_has_no_application_success() {
    let run = "rm-norm-c34-unit";
    let writer = principal("writer-c34-unit");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-unit");
    let mapping = mapping_pin("c34-unit");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-unit".to_string()],
        vec![seq1.clone()],
        "c34-unit",
    );

    // Bare native null: Unit/None.
    let raw_null = install_bytes(&writer, b"null", "execution");
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw_null,
        &seq1,
        &checks,
        &mapping,
    )
    .expect("Unit null normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "unknown");
    assert!(
        matches!(claim.state, ClaimState::Missing(_)),
        "absent Unit state is Missing, not an invented unknown string: {:?}",
        claim.state
    );
    assert!(claim.application_assertions.is_empty());
    assert!(
        claim
            .limitations
            .iter()
            .any(|text| text.contains("Unit/None")),
        "Unit limitation missing: {:?}",
        claim.limitations
    );
    assert_no_bare_nulls_observation(&observation);

    // Object form with an explicit null result and no other statement.
    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "result": null,
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("null result normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "unknown");
    assert!(matches!(claim.state, ClaimState::Missing(_)));
    assert!(claim.application_assertions.is_empty());
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c34_primitive_return_has_no_application_assertions() {
    let run = "rm-norm-c34-primitive";
    let writer = principal("writer-c34-primitive");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-primitive");
    let mapping = mapping_pin("c34-primitive");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-prim".to_string()],
        vec![seq1.clone()],
        "c34-primitive",
    );

    // Structured primitive return.
    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "primitive": "bo.dom_read",
        "result": {"text": "hello"},
        "native_run_id": "native-run-prim",
        "native_message_id": "native-msg-prim",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("primitive return normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "primitive");
    match &claim.state {
        ClaimState::Missing(missing) => assert_eq!(missing.reason, "not_applicable"),
        other => panic!("primitive scope requires inapplicable state, got {other:?}"),
    }
    assert!(claim.application_assertions.is_empty());
    assert!(
        matches!(claim.native_run_id, MaybeString::Text(_)),
        "actual source identities are preserved"
    );
    assert_no_bare_nulls_observation(&observation);

    // Bare scalar return is likewise a primitive value, not success.
    let raw_scalar = install_bytes(&writer, b"42", "execution");
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw_scalar,
        &seq1,
        &checks,
        &mapping,
    )
    .expect("scalar return normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    assert_eq!(observation.normalized_claims[0].scope, "primitive");
    assert!(observation.normalized_claims[0]
        .application_assertions
        .is_empty());
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c34_lifecycle_completed_has_no_automatic_commitment() {
    let run = "rm-norm-c34-lifecycle";
    let writer = principal("writer-c34-lifecycle");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-lifecycle");
    let mapping = mapping_pin("c34-lifecycle");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-life".to_string()],
        vec![seq1.clone()],
        "c34-lifecycle",
    );

    // Completed lifecycle without explicit application assertions.
    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "callback",
        "status": "completed",
        "native_run_id": "native-run-9",
        "native_message_id": "native-msg-9",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("completed lifecycle normalizes");
    assert_eq!(observation.channel, "callback");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "execution_lifecycle");
    assert_eq!(claim.state, ClaimState::Completed);
    assert!(
        claim.application_assertions.is_empty(),
        "lifecycle completion must not invent a commitment assertion"
    );
    assert!(
        claim
            .limitations
            .iter()
            .any(|text| text.contains("does not imply application commitment")),
        "completion limitation missing: {:?}",
        claim.limitations
    );
    // Receipt time comes from the retained source receipt.
    assert_eq!(claim.received_at, admission_envelope.recorded_at);
    assert_no_bare_nulls_observation(&observation);

    // Observed native failure is normal evidence, not a connector failure.
    let failed_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "status": "failed",
        "native_run_id": "native-run-9",
    }))
    .expect("raw serializes");
    let raw_failed = install_bytes(&writer, &failed_bytes, "execution");
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw_failed,
        &seq1,
        &checks,
        &mapping,
    )
    .expect("observed native failure is evidence, not a connector error");
    assert_eq!(observation.normalized_claims.len(), 1);
    assert_eq!(observation.normalized_claims[0].state, ClaimState::Failed);
    assert!(observation.normalized_claims[0]
        .application_assertions
        .is_empty());
    assert_no_bare_nulls_observation(&observation);

    // Stopped likewise carries no commitment implication.
    let stopped_bytes = serde_json::to_vec(&json!({
        "channel": "native_stream",
        "status": "stopped",
    }))
    .expect("raw serializes");
    let raw_stopped = install_bytes(&writer, &stopped_bytes, "execution");
    let observation = rm_normalization::normalize_report(
        &writer,
        &handle,
        &raw_stopped,
        &seq1,
        &checks,
        &mapping,
    )
    .expect("stopped normalizes");
    assert_eq!(observation.normalized_claims[0].state, ClaimState::Stopped);
    assert!(
        observation.normalized_claims[0]
            .limitations
            .iter()
            .any(|text| text.contains("no commitment")),
        "stopped limitation missing: {:?}",
        observation.normalized_claims[0].limitations
    );
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c34_conflicting_claims_append_without_replacement() {
    let run = "rm-norm-c34-conflict";
    let writer = principal("writer-c34-conflict");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-conflict");
    let mapping = mapping_pin("c34-conflict");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-conflict".to_string()],
        vec![seq1.clone()],
        "c34-conflict",
    );

    let raw_bytes = serde_json::to_vec(&json!([
        {
            "channel": "terminal_response",
            "status": "completed",
            "native_run_id": "native-run-c",
            "native_message_id": "msg-first",
        },
        {
            "channel": "terminal_response",
            "status": "failed",
            "native_run_id": "native-run-c",
            "native_message_id": "msg-second",
        },
    ]))
    .expect("batch serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("conflicting batch normalizes");
    assert_eq!(
        observation.normalized_claims.len(),
        2,
        "conflicting claims must append without replacement"
    );
    let first = &observation.normalized_claims[0];
    let second = &observation.normalized_claims[1];
    assert_eq!(first.state, ClaimState::Completed);
    assert_eq!(second.state, ClaimState::Failed);
    assert_ne!(first.claim_id, second.claim_id);
    assert!(first.application_assertions.is_empty());
    assert!(second.application_assertions.is_empty());
    assert_no_bare_nulls_observation(&observation);
    let _ = admission_envelope;
}

#[test]
fn rm_c34_acknowledgement_is_not_commitment() {
    let run = "rm-norm-c34-ack";
    let writer = principal("writer-c34-ack");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-ack");
    let mapping = mapping_pin("c34-ack");
    let checks = checks_for(
        "verified",
        "matched",
        "not_observed",
        vec!["alternate-ack-binding".to_string()],
        vec![seq1.clone()],
        "c34-ack",
    );

    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "native_stream",
        "ack": true,
        "native_message_id": "msg-ack-1",
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("acknowledgement normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "unknown");
    assert!(matches!(claim.state, ClaimState::Missing(_)));
    assert!(claim.application_assertions.is_empty());
    assert!(
        claim
            .limitations
            .iter()
            .any(|text| text.contains("acknowledgement")),
        "ack limitation missing: {:?}",
        claim.limitations
    );
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c34_explicit_application_assertion_is_preserved() {
    let run = "rm-norm-c34-explicit";
    let writer = principal("writer-c34-explicit");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-explicit");
    let mapping = mapping_pin("c34-explicit");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-explicit".to_string()],
        vec![seq1.clone()],
        "c34-explicit",
    );

    // Only explicit source assertions become application assertions. The
    // boundary reference below cites the retained receipt.
    let seq1_json = seq1.to_json();
    let raw_bytes = serde_json::to_vec(&json!({
        "channel": "terminal_response",
        "scope": "application_postcondition",
        "state": "completed",
        "native_run_id": "native-run-e",
        "native_message_id": "native-msg-e",
        "application_assertions": [
            {
                "assertion_id": "assert-explicit-1",
                "value": "committed",
                "span": "entire_attempt",
                "boundary_ref": {"value": null, "reason": "not_applicable"},
                "evidence_refs": [seq1_json],
            }
        ],
    }))
    .expect("raw serializes");
    let raw = install_bytes(&writer, &raw_bytes, "execution");
    let observation =
        rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
            .expect("explicit assertion normalizes");
    assert_eq!(observation.normalized_claims.len(), 1);
    let claim = &observation.normalized_claims[0];
    assert_eq!(claim.scope, "application_postcondition");
    assert_eq!(claim.state, ClaimState::Completed);
    assert_eq!(claim.application_assertions.len(), 1);
    let assertion = &claim.application_assertions[0];
    assert_eq!(assertion.assertion_id, "assert-explicit-1");
    assert_eq!(assertion.value, "committed");
    assert_eq!(assertion.span, "entire_attempt");
    assert!(matches!(
        assertion.boundary_ref,
        MaybeEvidenceRef::Missing(_)
    ));
    assert_no_bare_nulls_observation(&observation);
}

#[test]
fn rm_c34_malformed_native_body_is_connector_error_not_subject_failure() {
    let run = "rm-norm-c34-malformed";
    let writer = principal("writer-c34-malformed");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let handle = handle_for(&manifest, &journal_id, "handle-c34-malformed");
    let mapping = mapping_pin("c34-malformed");
    let checks = checks_for(
        "verified",
        "matched",
        "matched",
        vec!["trace-malformed".to_string()],
        vec![seq1.clone()],
        "c34-malformed",
    );

    let raw = install_bytes(&writer, b"{not-json", "execution");
    let error = rm_normalization::normalize_report(&writer, &handle, &raw, &seq1, &checks, &mapping)
        .expect_err("malformed native body must be an operation failure, not a subject claim");
    assert_eq!(error.code, "NATIVE_PROTOCOL_ERROR");
    assert_eq!(error.fault_domain, "native_interface");
}
