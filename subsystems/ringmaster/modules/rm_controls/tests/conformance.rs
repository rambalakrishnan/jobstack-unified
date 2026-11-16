//! Conformance tests for RM-C26 … RM-C29.
//!
//! - RM-C26: an unsupported native cancel never blocks local finalization.
//! - RM-C27: `end_observation=false` closes only a mapped transport while
//!   `true` starts bounded finalization; neither requests cancellation, and a
//!   closed window never reopens.
//! - RM-C28: a release failure is unresolved knowledge, never an implicit
//!   process containment.
//! - RM-C29: containment records its authorized scope and the affected
//!   attempts, and refuses unauthorized or inventing targets.
//!
//! Every test name carries `rm_c26`, `rm_c27`, `rm_c28`, or `rm_c29` so the
//! verification filter selects the suite. All tests run against real admitted
//! evidence journals, real preparations from `rm_preparation`, real leases,
//! real delivery admissions, and real published lifecycle revisions.

use std::io::Cursor;

use rm_authority::{
    authenticate_channel, AttemptCommission, AttemptKind, AuthenticatedPrincipal,
    EvaluationPartition, ExecutionMode, Manifest, TargetClass, WorkScope,
};
use rm_catalog::{DescribeRequest, DurationLimit, VersionPin};
use rm_controls::{
    close_at_boundary, control, control_history, local_now, record_control_response, window_state,
    CloseRequestReason, ConnectorRequest, ContainmentKind, ContainmentTarget, ControlParameters,
    ControlRequest, ControlResponse, ControlResponseKind, Disposition, LocalFinalization,
    MaybeEvidenceRef, OpportunityState, ResponseChecks, WindowState,
};
use rm_delivery::{MaybeCommission, StartRequest, CONTROL_VERBS, START_VERB};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, JournalEnvelope, Missing,
    PositiveInteger,
};
use rm_lifecycle::{
    AppKnowledge, Axis, AxisValue, CloseReason, ExecKnowledge, MaybeCloseReason,
    MaybeCloseSnapshot, ObservationState,
};
use rm_leases::LeaseRecord;
use rm_preparation::{
    AssistanceRecord, CatalogMaybeString, CatalogMaybeVersionPin, ConfigurationPin, ContextPolicy,
    EntryPoint, MaybeArtifact, PermittedOrigin, PrepareRequest, PrepareResult, StatePolicy,
    SuccessCriterion, TaskBudgets, TaskEnvelope,
};
use rm_time::{MaybeString, MeasurementOrigin, TimePoint, UtcAnnotation};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::json;

/// Admitted active limit used by every test handle. It is deliberately tiny
/// so the local boundary is reached without waiting.
const ACTIVE_LIMIT_MS: f64 = 5.0;

// ---------------------------------------------------------------------------
// Fixtures: principals, manifests, journals
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
    authenticate_channel(&mut Cursor::new(bytes)).expect("principal authenticates")
}

fn test_manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "artifact_available",
            "dispatch_published",
            "control_observation",
            "native_report",
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    manifest
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact =
        rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact reference");
    EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("positive sequence")),
        event_kind: "manifest_admitted".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: rm_time::MaybeTimePoint::Missing(Missing::new("not_applicable")),
        payload: rm_evidence::EvidencePayload {
            data: json!({"manifest": artifact.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![artifact],
        },
    }
}

fn admit(writer: &AuthenticatedPrincipal, manifest: &Manifest) -> JournalEnvelope {
    rm_evidence::append_event(writer, manifest, admission(manifest)).expect("manifest admission")
}

fn install_bytes(writer: &AuthenticatedPrincipal, bytes: &[u8], owner: &str) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(writer, &reference, bytes).expect("artifact installs")
}

fn synthetic_ref(seed: &str) -> EvidenceRef {
    EvidenceRef {
        journal_id: format!("journal-synthetic-{seed}"),
        sequence: PositiveInteger::new(1).expect("positive"),
        event_id: format!("event-synthetic-{seed}"),
        event_hash: artifact_digest(format!("event-{seed}").as_bytes()),
        pointer: String::new(),
    }
}

/// Appends one retained evidence event and returns its exact reference.
fn append_retained(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    event_kind: &str,
    data: serde_json::Value,
    artifact_refs: Vec<ArtifactReference>,
) -> EvidenceRef {
    let journal_id = rm_evidence::journal_id_for(manifest).expect("journal identity");
    let head = rm_evidence::journal_head(writer, &journal_id).expect("journal head");
    let submission = EventSubmission {
        producer_sequence: Some(
            PositiveInteger::new(head.last_sequence.get() + 1).expect("positive sequence"),
        ),
        event_kind: event_kind.to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: rm_time::MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: rm_evidence::EvidencePayload {
            data,
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs,
        },
    };
    let envelope = rm_evidence::append_event(writer, manifest, submission)
        .expect("retained evidence appends");
    evidence_ref(&envelope)
}

/// Retained subject statement used as claim evidence.
fn retained_subject_report(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    seed: &str,
) -> EvidenceRef {
    let raw = install_bytes(
        writer,
        format!("subject-report-{seed}").as_bytes(),
        "artifact",
    );
    append_retained(
        writer,
        manifest,
        "native_report",
        json!({
            "kind": "native_report",
            "channel": format!("subject_statement_{seed}"),
            "raw": raw.to_json(),
            "source_event": synthetic_ref(&format!("subject-report-{seed}")).to_json(),
            "source_checks": {},
            "mapping": containment_policy().to_json(),
            "normalized_claims": [],
            "limitations": ["the subject reports its own state"],
        }),
        vec![raw],
    )
}

/// Retained artifact-availability event used as effect evidence.
fn retained_effect_evidence(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    seed: &str,
) -> EvidenceRef {
    let reference = install_bytes(writer, format!("effect-{seed}").as_bytes(), "artifact");
    append_retained(
        writer,
        manifest,
        "artifact_available",
        json!({"kind": "artifact_available", "artifact": reference.to_json()}),
        vec![reference],
    )
}

fn evidence_ref(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Fixtures: tasks, scopes, preparations
// ---------------------------------------------------------------------------

fn descriptor_pin(
    writer: &AuthenticatedPrincipal,
    tag: &str,
) -> (rm_catalog::ConnectorDescriptor, ConfigurationPin) {
    let descriptor = rm_catalog::describe(writer, &DescribeRequest).expect("describe succeeds");
    let bytes = serde_json::to_vec(&descriptor.to_json()).expect("descriptor serializes");
    let reference = install_bytes(writer, &bytes, "artifact");
    let configuration = ConfigurationPin {
        connector_id: descriptor.connector_id.clone(),
        connector_version: descriptor.connector_version.clone(),
        binding: descriptor.binding.clone(),
        subject: descriptor.subject.clone(),
        descriptor: reference,
        descriptor_ref: synthetic_ref(&format!("descriptor-{tag}")),
    };
    (descriptor, configuration)
}

fn test_budgets(active_limit_ms: f64) -> TaskBudgets {
    TaskBudgets {
        active_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: active_limit_ms,
        },
        action_limit: 100,
        observation_byte_limit: 65536,
        recovery_limit: 5,
        model_token_limit: 1000,
    }
}

fn test_context() -> ContextPolicy {
    ContextPolicy {
        browser_state: StatePolicy {
            mode: "fresh".to_string(),
            requirement: "required".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        learning_state: StatePolicy {
            mode: "not_applicable".to_string(),
            requirement: "best_effort".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
    }
}

fn apply_task(task_id: &str, entry_url: &str, origin: &str, active_limit_ms: f64) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: "apply".to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: entry_url.to_string(),
        },
        goal: format!("apply at {entry_url}"),
        success_criteria: vec![SuccessCriterion {
            criterion_id: "c1".to_string(),
            description: "application submitted".to_string(),
        }],
        inputs: Vec::new(),
        permitted_origins: vec![PermittedOrigin {
            logical_id: "o1".to_string(),
            origin: origin.to_string(),
        }],
        permitted_interfaces: vec!["ordinary_browser".to_string()],
        effect_policy: "commissioned_application".to_string(),
        budgets: test_budgets(active_limit_ms),
        context_policy: test_context(),
        output_schema: CatalogMaybeVersionPin::Missing(Missing::new("not_applicable")),
    }
}

fn apply_assistance() -> AssistanceRecord {
    AssistanceRecord {
        planning_owner: "operator".to_string(),
        assistance_track: "track-apply".to_string(),
        planner_identity: CatalogMaybeString::Text("operator-1".to_string()),
        plan: MaybeArtifact::Missing(Missing::new("not_applicable")),
        online_replanning: false,
        description: "declared goal assistance".to_string(),
    }
}

fn task_scope(manifest: &Manifest, commission: &AttemptCommission, tag: &str) -> WorkScope {
    WorkScope {
        activity: "apply".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal identity"),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: Some(commission.attempt_id.clone()),
        commission_id: Some(commission.commission_id.clone()),
        commission_ref: Some(format!("commission-ref-{tag}")),
        attempt_kind: Some(AttemptKind::Production),
        authorization_refs: vec![format!("grant-apply-{tag}")],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

/// Control scope: the same admitted attempt binding with control grants.
fn control_scope(
    manifest: &Manifest,
    commission: &AttemptCommission,
    tag: &str,
    grants: Vec<&str>,
) -> WorkScope {
    let mut scope = task_scope(manifest, commission, tag);
    scope.authorization_refs = grants.iter().map(|grant| (*grant).to_string()).collect();
    scope
}

/// Computes the Contract 02 semantic hash the same way the module does.
fn semantic_hash_of(task: &TaskEnvelope) -> String {
    let mut value = task.to_json();
    if let serde_json::Value::Object(map) = &mut value {
        map.remove("task_id");
        if let Some(serde_json::Value::Object(entry)) = map.get_mut("entry") {
            let logical = entry.get("logical_id").cloned().unwrap_or(serde_json::Value::Null);
            entry.insert("url".to_string(), logical);
        }
        if let Some(serde_json::Value::Array(origins)) = map.get_mut("permitted_origins") {
            for origin in origins {
                if let serde_json::Value::Object(item) = origin {
                    let logical = item.get("logical_id").cloned().unwrap_or(serde_json::Value::Null);
                    item.insert("origin".to_string(), logical);
                }
            }
        }
    }
    let bytes = serde_json::to_vec(&value).expect("semantic serializes");
    canonical_digest(&bytes)
        .expect("semantic hashes")
        .as_str()
        .to_string()
}

fn production_commission(
    manifest: &Manifest,
    task: &TaskEnvelope,
    tag: &str,
) -> AttemptCommission {
    AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        commission_id: format!("commission-{tag}"),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal identity"),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: format!("attempt-{tag}"),
        kind: AttemptKind::Production,
        target_class: TargetClass::Employer,
        evaluation_partition: EvaluationPartition::HeldOut,
        target_id: format!("employer-{tag}"),
        derived_from: Vec::new(),
        rehearsal_of: None,
        performance_of: None,
        task_semantic_hash: semantic_hash_of(task),
        idempotency_key: format!("idem-{tag}"),
        imported_evidence: Vec::new(),
    }
}

fn prepare_command(
    configuration: &ConfigurationPin,
    scope: WorkScope,
    manifest: &Manifest,
    commission: Option<AttemptCommission>,
    task: TaskEnvelope,
    assistance: AssistanceRecord,
    tag: &str,
) -> rm_preparation::ConnectorRequest {
    rm_preparation::ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: format!("prepare-{tag}"),
        connector_id: configuration.connector_id.clone(),
        operation: "Prepare".to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: PrepareRequest {
            scope,
            manifest: manifest.clone(),
            commission,
            configuration: configuration.clone(),
            task,
            assistance,
            planning_evidence_refs: Vec::new(),
            preparation_measurements: Vec::new(),
            runtime_access: Vec::new(),
            native_binding: None,
        },
    }
}

fn prepare_application(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    tag: &str,
    active_limit_ms: f64,
) -> (PrepareResult, AttemptCommission, ConfigurationPin) {
    let (_descriptor, configuration) = descriptor_pin(writer, tag);
    let task = apply_task(
        &format!("task-{tag}"),
        "https://employer.example/jobs/1",
        "https://employer.example",
        active_limit_ms,
    );
    let commission = production_commission(manifest, &task, tag);
    let scope = task_scope(manifest, &commission, tag);
    let command = prepare_command(
        &configuration,
        scope,
        manifest,
        Some(commission.clone()),
        task,
        apply_assistance(),
        tag,
    );
    let prepared = rm_preparation::prepare(writer, &command).expect("application prepares");
    (prepared, commission, configuration)
}

// ---------------------------------------------------------------------------
// Fixtures: clocks and leases
// ---------------------------------------------------------------------------

fn time_point(offset_ms: f64) -> TimePoint {
    let clock = rm_evidence::evidence_clock();
    TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset_ms,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn shift(point: &TimePoint, offset_ms: f64) -> TimePoint {
    let mut shifted = point.clone();
    shifted.monotonic_offset_ms += offset_ms;
    shifted
}

fn time_json(offset_ms: f64) -> serde_json::Value {
    serde_json::to_value(time_point(offset_ms)).expect("time point serializes")
}

fn missing(reason: &str) -> serde_json::Value {
    json!({"value": null, "reason": reason})
}

fn held_lease(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    entity_id: &str,
    tag: &str,
    expires_ms: f64,
) -> LeaseRecord {
    let journal_id = rm_evidence::journal_id_for(manifest).expect("journal identity");
    let prefix = rm_evidence::journal_head(writer, &journal_id).expect("journal head");
    let admission_envelope = rm_evidence::read_event(
        writer,
        &journal_id,
        PositiveInteger::new(1).expect("positive"),
    )
    .expect("admission is retained");
    let value = json!({
        "record_type": "lease_record",
        "schema_version": "evidence-kernel/0.1.0",
        "resource": {
            "owner_domain": "execution",
            "entity_type": "connector_task",
            "entity_id": entity_id,
        },
        "policy": {
            "id": "controls-lease",
            "version": "1",
            "artifact_digest": artifact_digest(b"controls-lease-policy-1").as_str(),
        },
        "issuer_id": "lease-authority",
        "authority_epoch": "authority-epoch-1",
        "entity_revision": 1,
        "input_revision": 1,
        "generation_id": "generation-1",
        "resource_state": "pending",
        "eligible_state": "pending",
        "lease_state": "held",
        "lease_id": format!("lease-{tag}"),
        "lease_owner": "delivery-worker",
        "owner_epoch": "owner-epoch-1",
        "session_epoch": "session-epoch-1",
        "leased_at": time_json(0.0),
        "lease_expires_at": time_json(expires_ms),
        "retry_count": 0,
        "max_retries_effective": 2,
        "last_failure_reason": missing("not_applicable"),
        "journal_prefix": prefix.to_json(),
        "evidence_refs": [evidence_ref(&admission_envelope).to_json()],
    });
    LeaseRecord::from_json(&value).expect("held lease parses")
}

// ---------------------------------------------------------------------------
// Fixtures: Start and control commands
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn start_command(
    connector_id: &str,
    prepared: &PrepareResult,
    manifest: &Manifest,
    commission: MaybeCommission,
    lease: LeaseRecord,
    idempotency_key: &str,
    request_id: &str,
    authorization_refs: Vec<String>,
) -> rm_delivery::ConnectorRequest {
    rm_delivery::ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: request_id.to_string(),
        connector_id: connector_id.to_string(),
        operation: START_VERB.to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: rm_delivery::CommandPayload::Start(StartRequest {
            preparation: prepared.preparation.clone(),
            idempotency_key: idempotency_key.to_string(),
            accepted_concern_ids: prepared
                .record
                .concerns
                .iter()
                .map(|concern| concern.concern_id.clone())
                .collect(),
            authorization_refs,
            recovery: rm_delivery::MaybeResume::Missing(Missing::new("not_applicable")),
            manifest: manifest.clone(),
            commission,
            lease,
        }),
    }
}

/// Admitted application attempt with a real handle and a published dispatch
/// revision.
fn application_subject(
    writer: &AuthenticatedPrincipal,
    tag: &str,
) -> (Manifest, AttemptCommission, rm_delivery::ConnectorHandle, String) {
    let manifest = test_manifest(&format!("rm-controls-{tag}-run"));
    admit(writer, &manifest);
    let (prepared, commission, configuration) =
        prepare_application(writer, &manifest, tag, ACTIVE_LIMIT_MS);
    // Application work is leased to its exact attempt resource.
    let lease = held_lease(writer, &manifest, &commission.attempt_id, tag, 600_000.0);
    let command = start_command(
        &configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Present(commission.clone()),
        lease,
        &format!("idem-{tag}"),
        &format!("request-{tag}-start"),
        vec![format!("grant-apply-{tag}")],
    );
    let receipt = rm_delivery::start(writer, &command).expect("application Start admits");
    (
        manifest,
        commission,
        receipt.handle,
        configuration.connector_id,
    )
}

/// Builds one control command envelope.
#[allow(clippy::too_many_arguments)]
fn control_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    scope: WorkScope,
    parameters: ControlParameters,
    request_id: &str,
) -> ConnectorRequest {
    let operation = parameters.operation();
    assert!(
        CONTROL_VERBS.contains(&operation.as_str()),
        "the test builds a control verb"
    );
    ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: request_id.to_string(),
        connector_id: connector_id.to_string(),
        operation: operation.as_str().to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: ControlRequest {
            scope,
            manifest: manifest.clone(),
            handle: handle.handle.clone(),
            parameters,
        },
    }
}

fn cancel_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    scope: WorkScope,
    request_id: &str,
) -> ConnectorRequest {
    control_command(
        connector_id,
        manifest,
        handle,
        scope,
        ControlParameters::RequestNativeCancel {
            reason: "operator requested stop".to_string(),
        },
        request_id,
    )
}

#[allow(clippy::too_many_arguments)]
fn close_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    scope: WorkScope,
    reason: CloseRequestReason,
    end_observation: bool,
    request_id: &str,
) -> ConnectorRequest {
    control_command(
        connector_id,
        manifest,
        handle,
        scope,
        ControlParameters::CloseObservationConnection {
            reason,
            end_observation,
        },
        request_id,
    )
}

fn release_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    scope: WorkScope,
    context_ref: MaybeString,
    request_id: &str,
) -> ConnectorRequest {
    control_command(
        connector_id,
        manifest,
        handle,
        scope,
        ControlParameters::ReleaseNativeContext { context_ref },
        request_id,
    )
}

fn containment_policy() -> VersionPin {
    VersionPin {
        id: "harness-containment".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: artifact_digest(b"harness-containment-policy-1"),
    }
}

#[allow(clippy::too_many_arguments)]
fn contain_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    scope: WorkScope,
    kind: ContainmentKind,
    resource_id: &str,
    request_id: &str,
) -> ConnectorRequest {
    control_command(
        connector_id,
        manifest,
        handle,
        scope,
        ControlParameters::Contain {
            target: ContainmentTarget {
                kind,
                resource_id: resource_id.to_string(),
            },
            policy: containment_policy(),
            reason: "operator containment".to_string(),
        },
        request_id,
    )
}

fn drain_coordinates(receipt: &rm_controls::ControlReceipt) -> (TimePoint, TimePoint) {
    match &receipt.observation.local_finalization {
        LocalFinalization::Started {
            drain_started_at,
            drain_deadline,
        } => (drain_started_at.clone(), drain_deadline.clone()),
        other => panic!("expected bounded finalization, found {other:?}"),
    }
}

fn closed_value(revision: &rm_lifecycle::AxisRevision) -> &rm_lifecycle::ObservationValue {
    match &revision.value {
        AxisValue::Observation(value) => value,
        other => panic!("expected an observation revision, found {other:?}"),
    }
}

fn close_snapshot(value: &rm_lifecycle::ObservationValue) -> &rm_lifecycle::CloseSnapshot {
    match &value.at_close {
        MaybeCloseSnapshot::Present(snapshot) => snapshot,
        other => panic!("a closed window requires its close snapshot, found {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// RM-C26: native unsupported cancel never blocks local finalization
// ---------------------------------------------------------------------------

#[test]
fn rm_c26_unsupported_native_cancel_never_blocks_local_finalization() {
    let writer = principal("rm-controls-c26");
    let (manifest, commission, handle, connector_id) = application_subject(&writer, "c26");

    let cancel = cancel_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(
            &manifest,
            &commission,
            "c26",
            vec!["control:request_native_cancel"],
        ),
        "request-c26-cancel",
    );

    // The operation is authorized, observed, and recorded as unsupported: a
    // missing cancel mapping is not native absence, and no request is issued.
    let receipt = control(&writer, &cancel).expect("the cancel request is observed");
    assert_eq!(receipt.kind, "control_receipt");
    assert_eq!(receipt.observation.operation, "RequestNativeCancel");
    assert_eq!(receipt.observation.disposition, Disposition::Unsupported);
    assert_eq!(
        receipt.observation.opportunity.state,
        OpportunityState::Unexposed
    );
    assert!(
        matches!(receipt.observation.request_ref, MaybeEvidenceRef::Missing(_)),
        "no request is delivered when the descriptor exposes no native cancel mapping"
    );
    assert!(receipt.observation.effect_refs.is_empty());
    assert!(receipt.observation.native_claim_refs.is_empty());
    assert_eq!(
        receipt.observation.local_finalization,
        LocalFinalization::NotRequested
    );
    assert!(
        receipt
            .observation
            .limitations
            .iter()
            .any(|limitation| limitation.contains("bounded local finalization")),
        "the observation discloses that local finalization does not depend on cancellation"
    );
    // The pinned cancellation-wait bound is recorded; nothing was waited on.
    assert_eq!(receipt.observation.measurements.len(), 1);
    assert_eq!(receipt.observation.measurements[0].name, "native_cancel_wait");
    // Nothing reached the owner control queue.
    assert!(rm_delivery::take_owner_control(&writer, &handle)
        .expect("control queue reads")
        .is_none());

    // A subject's confirmed-stop statement is retained as a claim: a new
    // observation with the same operation_id and a new control_event_id.
    let claim_reference = retained_subject_report(&writer, &manifest, "c26-subject-stop");
    let claim = ControlResponse {
        kind: ControlResponseKind::SubjectClaim,
        response_ref: MaybeString::Text("subject-stop-claim".to_string()),
        checks: ResponseChecks::none(),
        effect_refs: Vec::new(),
        native_claim_refs: vec![claim_reference.clone()],
        detail: MaybeString::Text("subject reports that it stopped".to_string()),
    };
    let claimed = record_control_response(&writer, &cancel, &claim)
        .expect("the claim is appended as a new observation");
    assert_eq!(
        claimed.observation.operation_id, receipt.observation.operation_id,
        "observations of one operation share the operation_id"
    );
    assert_ne!(
        claimed.observation.control_event_id, receipt.observation.control_event_id,
        "new observations append with a new control_event_id"
    );
    assert_eq!(
        claimed.observation.disposition,
        Disposition::Unsupported,
        "a subject claim never upgrades the unsupported disposition"
    );
    assert_eq!(claimed.observation.native_claim_refs, vec![claim_reference]);
    assert!(claimed.observation.effect_refs.is_empty());

    // The retained request observation is immutable.
    let history = control_history(&writer, &handle).expect("history reads");
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].control_event_id,
        receipt.observation.control_event_id
    );
    assert_eq!(history[0].disposition, Disposition::Unsupported);
    assert!(history[0].native_claim_refs.is_empty());

    // Local finalization still succeeds at the local boundary.
    let now = shift(&local_now(), 60_000.0);
    let revision = close_at_boundary(&writer, &handle, &now)
        .expect("bounded local finalization succeeds without native cancel support");
    assert_eq!(revision.axis, Axis::Observation);
    assert_eq!(revision.owner_domain, "observation");
    assert_eq!(revision.attempt.attempt_id, commission.attempt_id);
    let value = closed_value(&revision);
    assert_eq!(value.state, ObservationState::Closed);
    assert_eq!(
        value.close_reason,
        MaybeCloseReason::Present(CloseReason::LocalDeadline)
    );
    let snapshot = close_snapshot(value);
    assert_eq!(
        snapshot.execution_knowledge,
        ExecKnowledge::Unknown,
        "a subject stop claim never establishes native termination"
    );
    assert_eq!(snapshot.application_knowledge, AppKnowledge::Unknown);
    assert_eq!(
        value.control_observations.len(),
        2,
        "both retained control observations support the closure"
    );
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Closed
    );

    // The returned revision is publishable by the lifecycle owner: it carries
    // the attempt's own identity and every citation resolves.
    assert_eq!(
        revision.evidence_prefix.journal_id,
        rm_evidence::journal_id_for(&manifest).expect("journal identity")
    );
    for reference in &revision.evidence_refs {
        rm_evidence::resolve_evidence(&writer, reference, &revision.evidence_prefix)
            .expect("the closure cites resolvable evidence");
    }
    let publication = rm_lifecycle::publish_axis(&writer, &commission, &revision)
        .expect("the lifecycle owner publishes the closure revision");
    assert_eq!(publication.axis, Axis::Observation);
    assert_eq!(publication.revision, 1);
}

// ---------------------------------------------------------------------------
// RM-C27: close false versus true
// ---------------------------------------------------------------------------

#[test]
fn rm_c27_close_false_is_transport_only_and_true_finalizes_without_cancel() {
    let writer = principal("rm-controls-c27");
    let (manifest, commission, handle, connector_id) = application_subject(&writer, "c27");
    let close_grants = vec!["control:close_observation_connection"];

    // end_observation=false: only a mapped native transport could be closed.
    let transport = close_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c27", close_grants.clone()),
        CloseRequestReason::OperatorStop,
        false,
        "request-c27-transport",
    );
    let transport_receipt = control(&writer, &transport).expect("the transport close is observed");
    assert_eq!(
        transport_receipt.observation.disposition,
        Disposition::Unsupported,
        "no separable native observation transport is disclosed by the pinned descriptor"
    );
    assert_eq!(
        transport_receipt.observation.opportunity.state,
        OpportunityState::Unexposed
    );
    assert_eq!(
        transport_receipt.observation.local_finalization,
        LocalFinalization::NotRequested,
        "end_observation=false never finalizes the window"
    );
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Open,
        "a transport-only close leaves the observation window open"
    );
    assert!(rm_delivery::take_owner_control(&writer, &handle)
        .expect("control queue reads")
        .is_none());

    // end_observation=true: bounded local finalization starts.
    let finalize = close_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c27", close_grants),
        CloseRequestReason::OperatorStop,
        true,
        "request-c27-finalize",
    );
    let finalize_receipt = control(&writer, &finalize).expect("bounded finalization is admitted");
    assert_eq!(
        finalize_receipt.observation.disposition,
        Disposition::Requested
    );
    assert_eq!(
        finalize_receipt.observation.opportunity.state,
        OpportunityState::Exposed
    );
    let (drain_started_at, drain_deadline) = drain_coordinates(&finalize_receipt);
    assert!(drain_deadline.monotonic_offset_ms >= drain_started_at.monotonic_offset_ms);
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Draining
    );

    // A repeated end request never extends the recorded drain bound.
    let repeated_end = close_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(
            &manifest,
            &commission,
            "c27",
            vec!["control:close_observation_connection"],
        ),
        CloseRequestReason::OperatorStop,
        true,
        "request-c27-repeated-end",
    );
    let repeated_receipt =
        control(&writer, &repeated_end).expect("the repeated end request is observed");
    assert_eq!(
        repeated_receipt.observation.disposition,
        Disposition::NotRequested
    );
    assert_eq!(
        repeated_receipt.observation.opportunity.state,
        OpportunityState::Blocked
    );
    assert_eq!(
        repeated_receipt.observation.local_finalization,
        LocalFinalization::NotRequested
    );
    assert_eq!(
        drain_coordinates(&finalize_receipt),
        (drain_started_at, drain_deadline),
        "the recorded drain coordinates are the original ones"
    );

    let delivered = rm_delivery::take_owner_control(&writer, &handle)
        .expect("control queue reads")
        .expect("the finalization request reaches the owner queue");
    assert_eq!(delivered.operation, "CloseObservationConnection");
    assert!(
        rm_delivery::take_owner_control(&writer, &handle)
            .expect("control queue reads")
            .is_none(),
        "a repeated or blocked request is never delivered"
    );

    // Neither setting requested cancellation.
    let history = control_history(&writer, &handle).expect("history reads");
    assert!(history
        .iter()
        .all(|observation| observation.operation == "CloseObservationConnection"));
    assert!(history
        .iter()
        .all(|observation| observation.native_claim_refs.is_empty()));
    assert!(history
        .iter()
        .all(|observation| observation.effect_refs.is_empty()));
    assert!(!history
        .iter()
        .any(|observation| observation.operation == "RequestNativeCancel"));

    // The window closes at its local boundary with the requested reason.
    let now = shift(&local_now(), 60_000.0);
    let first = close_at_boundary(&writer, &handle, &now).expect("the window closes");
    assert_eq!(first.revision, 1);
    assert_eq!(first.previous_revision, 0);
    let value = closed_value(&first);
    assert_eq!(value.state, ObservationState::Closed);
    assert_eq!(
        value.close_reason,
        MaybeCloseReason::Present(CloseReason::OperatorStop)
    );
    assert!(
        matches!(value.drain_started_at, rm_time::MaybeTimePoint::Present(_)),
        "the drained close preserves its drain start"
    );
    assert!(
        matches!(value.drain_deadline, rm_time::MaybeTimePoint::Present(_)),
        "the drained close preserves its drain deadline"
    );
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Closed
    );

    // A closed window cannot reopen: a repeated closure with no new evidence
    // is refused rather than rewriting the retained closure.
    let repeated = close_at_boundary(&writer, &handle, &now)
        .expect_err("a closed window cannot reopen without new evidence");
    assert_eq!(repeated.code, "NOT_ADMITTED");

    // A later close request is observed as blocked and never delivered.
    let reopen = close_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c27", vec!["control:close_observation_connection"]),
        CloseRequestReason::OperatorStop,
        true,
        "request-c27-reopen",
    );
    let reopen_receipt = control(&writer, &reopen).expect("the reopen attempt is observed");
    assert_eq!(
        reopen_receipt.observation.disposition,
        Disposition::NotRequested
    );
    assert_eq!(
        reopen_receipt.observation.opportunity.state,
        OpportunityState::Blocked
    );
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Closed
    );
    assert!(rm_delivery::take_owner_control(&writer, &handle)
        .expect("control queue reads")
        .is_none());

    // Late evidence is appended at the current journal head by a
    // closed-to-closed revision that preserves the original closure.
    let late = close_at_boundary(&writer, &handle, &now).expect("late evidence revises the closure");
    assert_eq!(late.revision, 2);
    assert_eq!(late.previous_revision, 1);
    let late_value = closed_value(&late);
    assert_eq!(
        late_value.closed_at, value.closed_at,
        "the original close coordinate is preserved"
    );
    assert_eq!(late_value.close_reason, value.close_reason);
    assert_eq!(
        close_snapshot(late_value).closure_id,
        close_snapshot(value).closure_id
    );
    assert_eq!(late_value.late_evidence_refs.len(), 1);
    let retained = control_history(&writer, &handle).expect("history reads");
    assert_eq!(retained.len(), 4);
    assert_eq!(
        late_value.control_observations.len(),
        retained.len(),
        "every prior control observation is retained"
    );
}

// ---------------------------------------------------------------------------
// RM-C28: release failure never escalates to containment
// ---------------------------------------------------------------------------

#[test]
fn rm_c28_release_failure_never_escalates_to_containment() {
    let writer = principal("rm-controls-c28");
    let (manifest, commission, handle, connector_id) = application_subject(&writer, "c28");
    let release = release_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(
            &manifest,
            &commission,
            "c28",
            vec!["control:release_native_context"],
        ),
        MaybeString::Text("context:page:fixture-1".to_string()),
        "request-c28-release",
    );

    let receipt = control(&writer, &release).expect("release is admitted to the owner queue");
    assert_eq!(receipt.observation.disposition, Disposition::Requested);
    assert_eq!(
        receipt.observation.target_scope,
        "native_context:context:page:fixture-1"
    );
    assert_eq!(
        rm_delivery::take_owner_control(&writer, &handle)
            .expect("control queue reads")
            .expect("the release reaches the owner queue")
            .operation,
        "ReleaseNativeContext"
    );

    // An acknowledgement requires verified correlation and is still not an
    // observed effect.
    let acknowledged = record_control_response(
        &writer,
        &release,
        &ControlResponse {
            kind: ControlResponseKind::Acknowledged,
            response_ref: MaybeString::Text("owner-ack-1".to_string()),
            checks: ResponseChecks::verified(),
            effect_refs: Vec::new(),
            native_claim_refs: Vec::new(),
            detail: MaybeString::Text("release accepted by the owner".to_string()),
        },
    )
    .expect("a verified acknowledgement is recorded");
    assert_eq!(
        acknowledged.observation.disposition,
        Disposition::Acknowledged
    );
    assert!(acknowledged.observation.effect_refs.is_empty());

    let unverified = record_control_response(
        &writer,
        &release,
        &ControlResponse {
            kind: ControlResponseKind::Acknowledged,
            response_ref: MaybeString::Text("owner-reply-1".to_string()),
            checks: ResponseChecks::none(),
            effect_refs: Vec::new(),
            native_claim_refs: Vec::new(),
            detail: MaybeString::Missing(Missing::new("not_observed")),
        },
    )
    .expect_err("a bare reply is not an acknowledgement");
    assert_eq!(unverified.code, "INVALID_REQUEST");

    // The release fails: delivery/effect knowledge is unresolved and nothing
    // escalates.
    let failed = record_control_response(
        &writer,
        &release,
        &ControlResponse {
            kind: ControlResponseKind::Failed,
            response_ref: MaybeString::Text("owner-failure-1".to_string()),
            checks: ResponseChecks {
                response_present: true,
                authentication: rm_lifecycle::AuthStatus::Verified,
                correlation: rm_lifecycle::CorrelationStatus::Mismatched,
            },
            effect_refs: Vec::new(),
            native_claim_refs: Vec::new(),
            detail: MaybeString::Text("page destruction failed".to_string()),
        },
    )
    .expect("the failure is recorded as unresolved knowledge");
    assert_eq!(failed.observation.disposition, Disposition::Unknown);
    assert!(failed.observation.effect_refs.is_empty());
    assert!(
        failed
            .observation
            .limitations
            .iter()
            .any(|limitation| limitation.contains("does not implicitly trigger containment")),
        "the failure discloses that containment requires its own authorization"
    );

    // No containment observation exists, and the window is untouched.
    let history = control_history(&writer, &handle).expect("history reads");
    assert_eq!(history.len(), 3);
    assert!(history
        .iter()
        .all(|observation| observation.operation == "ReleaseNativeContext"));
    assert!(history
        .iter()
        .all(|observation| observation.effect_refs.is_empty()));
    assert_eq!(
        window_state(&writer, &handle).expect("window state reads"),
        WindowState::Open
    );

    // Containment cannot be inferred from the failed release: the same scope
    // grants do not authorize a containment target.
    let escalation = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(
            &manifest,
            &commission,
            "c28",
            vec!["control:release_native_context"],
        ),
        ContainmentKind::LocalProcess,
        "fixture-worker-1",
        "request-c28-escalate",
    );
    let refused = control(&writer, &escalation)
        .expect_err("release failure never authorizes containment");
    assert_eq!(refused.code, "FORBIDDEN");

    // A fabricated reference is not effect evidence: cited evidence must be
    // retained in this attempt journal.
    let fabricated = record_control_response(
        &writer,
        &release,
        &ControlResponse {
            kind: ControlResponseKind::Acknowledged,
            response_ref: MaybeString::Text("owner-forged-1".to_string()),
            checks: ResponseChecks::verified(),
            effect_refs: vec![synthetic_ref("c28-unretained")],
            native_claim_refs: Vec::new(),
            detail: MaybeString::Missing(Missing::new("not_observed")),
        },
    )
    .expect_err("unretained effect evidence is rejected");
    assert_eq!(fabricated.code, "INVALID_REQUEST");

    // Only actual effect evidence supports effect_observed.
    let effect = retained_effect_evidence(&writer, &manifest, "c28-release-effect");
    let observed = record_control_response(
        &writer,
        &release,
        &ControlResponse {
            kind: ControlResponseKind::Acknowledged,
            response_ref: MaybeString::Text("owner-effect-1".to_string()),
            checks: ResponseChecks::verified(),
            effect_refs: vec![effect.clone()],
            native_claim_refs: Vec::new(),
            detail: MaybeString::Text("page destroyed".to_string()),
        },
    )
    .expect("an evidenced effect is recorded");
    assert_eq!(
        observed.observation.disposition,
        Disposition::EffectObserved
    );
    assert_eq!(observed.observation.effect_refs, vec![effect]);
}

// ---------------------------------------------------------------------------
// RM-C29: containment of a shared resource
// ---------------------------------------------------------------------------

#[test]
fn rm_c29_containment_records_authorized_scope_and_affected_attempts() {
    let writer = principal("rm-controls-c29");
    let (manifest, commission, handle, connector_id) = application_subject(&writer, "c29");
    let grants = vec![
        "control:contain:harness_resources:fixture-worker-pool",
        "control:policy:harness-containment@1.0.0",
    ];

    let containment = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c29", grants.clone()),
        ContainmentKind::HarnessResources,
        "fixture-worker-pool",
        "request-c29-contain",
    );
    let receipt = control(&writer, &containment).expect("authorized containment is admitted");
    assert_eq!(receipt.observation.disposition, Disposition::Requested);
    assert_eq!(
        receipt.observation.target_scope,
        "containment:harness_resources:fixture-worker-pool"
    );
    assert_eq!(
        receipt.observation.authorization_ref,
        MaybeString::Text("control:contain:harness_resources:fixture-worker-pool".to_string())
    );
    assert_eq!(
        receipt.observation.policy_ref,
        MaybeString::Text("harness-containment@1.0.0".to_string())
    );
    assert_eq!(receipt.observation.affected_attempts.len(), 1);
    let affected = &receipt.observation.affected_attempts[0];
    assert_eq!(
        affected.attempt_id,
        MaybeString::Text(commission.attempt_id.clone())
    );
    assert_eq!(
        affected.commission_ref,
        MaybeString::Text("commission-ref-c29".to_string())
    );
    assert_eq!(
        affected.kind,
        MaybeString::Text("production".to_string())
    );
    assert_eq!(affected.handle, handle.handle);
    assert!(
        receipt
            .observation
            .limitations
            .iter()
            .any(|limitation| limitation.contains("neither cooperative cancellation nor rollback")),
        "containment never claims cancellation or rollback"
    );
    assert!(
        receipt
            .observation
            .limitations
            .iter()
            .any(|limitation| limitation.contains("sharing the contained resource")),
        "unresolved shared-resource impact is disclosed"
    );
    assert!(receipt.observation.effect_refs.is_empty());
    assert_eq!(
        rm_delivery::take_owner_control(&writer, &handle)
            .expect("control queue reads")
            .expect("the containment reaches the owner queue")
            .operation,
        "Contain"
    );

    // Ringmaster cannot seal employer mutation authority.
    let employer_seal = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c29", grants.clone()),
        ContainmentKind::FixtureMutationAuthority,
        "employer-mutation-authority",
        "request-c29-employer-seal",
    );
    let refused = control(&writer, &employer_seal)
        .expect_err("employer mutation authority cannot be sealed");
    assert_eq!(refused.code, "FORBIDDEN");

    // Arbitrary shell text and caller PIDs are not containment targets.
    let shell_text = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c29", grants.clone()),
        ContainmentKind::LocalProcess,
        "kill -9 4242",
        "request-c29-shell",
    );
    assert_eq!(
        control(&writer, &shell_text)
            .expect_err("shell text is never a containment target")
            .code,
        "FORBIDDEN"
    );
    let caller_pid = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c29", grants.clone()),
        ContainmentKind::LocalProcess,
        "4242",
        "request-c29-pid",
    );
    assert_eq!(
        control(&writer, &caller_pid)
            .expect_err("a caller PID is never a containment target")
            .code,
        "FORBIDDEN"
    );

    // A well-formed but unauthorized resource is refused.
    let unauthorized = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(&manifest, &commission, "c29", grants),
        ContainmentKind::DeploymentSlot,
        "deployment-slot-other",
        "request-c29-unauthorized",
    );
    assert_eq!(
        control(&writer, &unauthorized)
            .expect_err("containment requires scoped authorization for its exact resource")
            .code,
        "FORBIDDEN"
    );

    // Containment without a pinned installed policy is not admitted.
    let unpinned = contain_command(
        &connector_id,
        &manifest,
        &handle,
        control_scope(
            &manifest,
            &commission,
            "c29",
            vec!["control:contain:harness_resources:fixture-worker-pool"],
        ),
        ContainmentKind::HarnessResources,
        "fixture-worker-pool",
        "request-c29-unpinned",
    );
    assert_eq!(
        control(&writer, &unpinned)
            .expect_err("containment requires a pinned installed policy")
            .code,
        "NOT_ADMITTED"
    );
}
