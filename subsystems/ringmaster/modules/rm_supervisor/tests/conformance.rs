//! Conformance for RM-C25: a native call that blocks indefinitely never
//! consumes local close/control progress.
//!
//! Every test name carries `rm_c25` so the verification filter
//! `cargo test -p rm_supervisor -- rm_c25` selects the suite. The suite runs
//! against real admitted evidence journals, real `rm_preparation` records,
//! real `rm_delivery` admissions and claims, real `rm_controls` windows, real
//! `rm_lifecycle` publications, and real `rm_evidence` registration.
//!
//! - `rm_c25_blocked_native_owner_never_blocks_local_closure`: an execution
//!   whose owner entered native work and never returned is reported as an
//!   unresolved owner and closed at its local boundary; no completion,
//!   cancellation, or replacement execution is fabricated.
//! - `rm_c25_late_evidence_revises_closure_without_reopening`: evidence that
//!   arrives after closure produces a closed-to-closed revision at the current
//!   journal head while preserving the original closure and publication.
//! - `rm_c25_queue_pressure_never_consumes_reserved_close_progress`: a due
//!   closure is served before a queued workflow is claimed, even though the
//!   queue is ready.
//! - `rm_c25_expired_queue_entry_never_begins_a_workflow`: work whose active
//!   budget was consumed in the queue is never handed to the native owner.

use std::io::Cursor;

use rm_authority::{
    authenticate_channel, AttemptCommission, AttemptKind, AuthenticatedPrincipal,
    EvaluationPartition, ExecutionMode, Manifest, TargetClass, WorkScope,
};
use rm_catalog::{DescribeRequest, DurationLimit};
use rm_controls::{
    control, control_history, Disposition, WindowState, ConnectorRequest, ControlParameters,
    ControlRequest,
};
use rm_delivery::{ConnectorHandle, MaybeCommission, StartRequest, START_VERB};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, JournalEnvelope, Missing,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_preparation::{
    AssistanceRecord, CatalogMaybeString, CatalogMaybeVersionPin, ConfigurationPin, ContextPolicy,
    EntryPoint, MaybeArtifact, PermittedOrigin, PrepareRequest, PrepareResult, StatePolicy,
    SuccessCriterion, TaskBudgets, TaskEnvelope,
};
use rm_time::{MeasurementOrigin, TimePoint, UtcAnnotation};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};

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
            "execution_claim",
            "task_output",
            "native_report",
            "connector_incident",
            "lifecycle_publication",
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

fn evidence_ref(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

fn journal_events(
    writer: &AuthenticatedPrincipal,
    journal_id: &str,
) -> Vec<JournalEnvelope> {
    let head = rm_evidence::journal_head(writer, journal_id).expect("journal head");
    let mut events = Vec::new();
    for sequence in 1..=head.last_sequence.get() {
        events.push(
            rm_evidence::read_event(
                writer,
                journal_id,
                PositiveInteger::new(sequence).expect("positive sequence"),
            )
            .expect("retained event reads"),
        );
    }
    events
}

fn events_of_kind<'a>(
    events: &'a [JournalEnvelope],
    kind: &str,
) -> Vec<&'a JournalEnvelope> {
    events
        .iter()
        .filter(|envelope| envelope.event_kind == kind)
        .collect()
}

fn next_sequence(writer: &AuthenticatedPrincipal, journal_id: &str) -> PositiveInteger {
    let mut highest = 0_u64;
    for envelope in journal_events(writer, journal_id) {
        if let Some(sequence) = envelope.producer_sequence {
            highest = highest.max(sequence.get());
        }
    }
    PositiveInteger::new(highest + 1).expect("positive sequence")
}

/// Appends the execution owner's real native-entry evidence and then stops:
/// the owner never reports a return. This is the blocked-call seam, expressed
/// as the retained evidence the supervisor is allowed to observe.
fn append_blocked_native_entry(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    handle: &ConnectorHandle,
) -> EvidenceRef {
    let journal_id = rm_evidence::journal_id_for(manifest).expect("journal identity");
    let submission = EventSubmission {
        producer_sequence: Some(next_sequence(writer, &journal_id)),
        event_kind: "execution_claim".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: rm_time::MaybeTimePoint::Present(local_now()),
        payload: rm_evidence::EvidencePayload {
            data: json!({
                "execution": "owner_work_admitted",
                "handle": handle.handle.to_json(),
                "local_handle": handle.handle.local_handle,
                "note": "the synchronous native call has not returned",
            }),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: Vec::new(),
        },
    };
    let envelope = rm_evidence::append_event(writer, manifest, submission)
        .expect("entry evidence appends");
    evidence_ref(&envelope)
}

// ---------------------------------------------------------------------------
// Fixtures: tasks, scopes, preparations, commissions
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
    if let Value::Object(map) = &mut value {
        map.remove("task_id");
        if let Some(Value::Object(entry)) = map.get_mut("entry") {
            let logical = entry
                .get("logical_id")
                .cloned()
                .unwrap_or(Value::Null);
            entry.insert("url".to_string(), logical);
        }
        if let Some(Value::Array(origins)) = map.get_mut("permitted_origins") {
            for origin in origins {
                if let Value::Object(item) = origin {
                    let logical = item
                        .get("logical_id")
                        .cloned()
                        .unwrap_or(Value::Null);
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

fn local_now() -> TimePoint {
    rm_controls::local_now()
}

fn shift(point: &TimePoint, offset_ms: f64) -> TimePoint {
    let mut shifted = point.clone();
    shifted.monotonic_offset_ms += offset_ms;
    shifted
}

fn time_json(offset_ms: f64) -> Value {
    let clock = rm_evidence::evidence_clock();
    let point = TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset_ms,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    serde_json::to_value(point).expect("time point serializes")
}

fn missing(reason: &str) -> Value {
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
            "id": "supervisor-lease",
            "version": "1",
            "artifact_digest": artifact_digest(b"supervisor-lease-policy-1").as_str(),
        },
        "issuer_id": "lease-authority",
        "authority_epoch": "authority-epoch-1",
        "entity_revision": 1,
        "input_revision": 1,
        "generation_id": format!("generation-{tag}"),
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
    active_limit_ms: f64,
) -> (
    Manifest,
    AttemptCommission,
    ConnectorHandle,
    String,
) {
    let manifest = test_manifest(&format!("rm-supervisor-{tag}-run"));
    admit(writer, &manifest);
    let (prepared, commission, configuration) =
        prepare_application(writer, &manifest, tag, active_limit_ms);
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

fn cancel_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &ConnectorHandle,
    scope: WorkScope,
    request_id: &str,
) -> ConnectorRequest {
    ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: request_id.to_string(),
        connector_id: connector_id.to_string(),
        operation: "RequestNativeCancel".to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: ControlRequest {
            scope,
            manifest: manifest.clone(),
            handle: handle.handle.clone(),
            parameters: ControlParameters::RequestNativeCancel {
                reason: "operator requested stop".to_string(),
            },
        },
    }
}

// ---------------------------------------------------------------------------
// Fixtures: publication inspection
// ---------------------------------------------------------------------------

fn publication_registrations(events: &[JournalEnvelope]) -> Vec<Value> {
    events_of_kind(events, "lifecycle_publication")
        .into_iter()
        .map(|envelope| envelope.payload.data.clone())
        .collect()
}

fn load_revision(
    writer: &AuthenticatedPrincipal,
    registration: &Value,
) -> Value {
    let content = ArtifactReference::from_json(
        registration
            .get("content")
            .expect("registration cites its content"),
    )
    .expect("content reference parses");
    let bytes = rm_evidence::load_artifact(writer, &content).expect("published bytes retained");
    serde_json::from_slice(&bytes).expect("revision bytes are JSON")
}

fn incidents(events: &[JournalEnvelope], incident: &str) -> Vec<Value> {
    events_of_kind(events, "connector_incident")
        .into_iter()
        .filter(|envelope| {
            envelope
                .payload
                .data
                .get("incident")
                .and_then(Value::as_str)
                == Some(incident)
        })
        .map(|envelope| envelope.payload.data.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// RM-C25: blocked native call never blocks local close/control progress
// ---------------------------------------------------------------------------

#[test]
fn rm_c25_blocked_native_owner_never_blocks_local_closure() {
    let writer = principal("rm-supervisor-c25-blocked");
    let (manifest, commission, handle, connector_id) =
        application_subject(&writer, "c25-blocked", 60_000.0);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");

    // One bounded quantum adopts the queued execution. The delivery claim's
    // durable dispatching intent is the entry hand-off; the supervisor never
    // runs the native primitive itself.
    rm_supervisor::drive_once(&writer, &local_now()).expect("the first quantum is bounded");
    assert_eq!(
        rm_delivery::local_state(&writer, &handle).expect("delivery state reads"),
        "assigned",
        "the claimed execution is assigned, not delivered twice"
    );
    assert!(
        rm_delivery::claim_work(&writer, &local_now())
            .expect("second claim reads")
            .is_none(),
        "one logical execution is never claimed twice"
    );

    // The owner enters native work and never returns: only entry evidence
    // exists, and no terminal evidence will ever be appended.
    append_blocked_native_entry(&writer, &manifest, &handle);

    // Control requests make progress while the owner is blocked. The pinned
    // descriptor exposes no native cancellation, so nothing is delivered to
    // the owner queue and no cancellation is claimed.
    for request in ["request-c25-cancel-1", "request-c25-cancel-2"] {
        let receipt = control(
            &writer,
            &cancel_command(
                &connector_id,
                &manifest,
                &handle,
                control_scope(
                    &manifest,
                    &commission,
                    "c25-blocked",
                    vec!["control:request_native_cancel"],
                ),
                request,
            ),
        )
        .expect("a control request is observed while the owner is blocked");
        assert_eq!(receipt.observation.disposition, Disposition::Unsupported);
        assert!(receipt.observation.native_claim_refs.is_empty());
        assert!(receipt.observation.effect_refs.is_empty());
    }
    assert_eq!(
        control_history(&writer, &handle)
            .expect("control history reads")
            .len(),
        2,
        "both control observations are retained"
    );
    assert!(
        rm_delivery::take_owner_control(&writer, &handle)
            .expect("control queue reads")
            .is_none(),
        "an unmapped native cancel never reaches the owner queue"
    );
    assert_eq!(
        rm_controls::window_state(&writer, &handle)
            .expect("the control observations opened the window"),
        WindowState::Open,
        "the window is still open before the local boundary"
    );
    assert!(
        publication_registrations(&journal_events(&writer, &journal_id)).is_empty(),
        "no closure publication exists before the local boundary"
    );

    // The local active boundary is reached while the native call is still
    // blocked. Local closure must still complete and publish.
    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now)
        .expect("bounded local closure succeeds while the native call is blocked");

    assert_eq!(
        rm_controls::window_state(&writer, &handle).expect("window state reads"),
        WindowState::Closed
    );

    let events = journal_events(&writer, &journal_id);
    let publications = publication_registrations(&events);
    assert_eq!(
        publications.len(),
        1,
        "exactly one observation publication is registered"
    );
    let revision = load_revision(&writer, &publications[0]);
    assert_eq!(revision["axis"].as_str(), Some("observation"));
    assert_eq!(revision["owner_domain"].as_str(), Some("observation"));
    assert_eq!(revision["revision"].as_u64(), Some(1));
    assert_eq!(revision["previous_revision"].as_u64(), Some(0));
    assert_eq!(revision["attempt"]["attempt_id"].as_str(), Some(commission.attempt_id.as_str()));
    assert_eq!(
        revision["value"]["state"].as_str(),
        Some("closed"),
        "the published revision is the closed observation"
    );
    let snapshot = &revision["value"]["at_close"];
    assert_eq!(
        snapshot["execution_knowledge"].as_str(),
        Some("unknown"),
        "a blocked owner never establishes execution knowledge"
    );
    assert_eq!(
        snapshot["known_versions"]["execution"].as_u64(),
        Some(1),
        "the retained entry evidence is counted without being promoted to completion"
    );
    assert_eq!(
        revision["value"]["control_observations"]
            .as_array()
            .expect("control observations retained")
            .len(),
        2
    );

    // Loss reporting: the supervisor journals its own unresolved-owner
    // observation, and does not fabricate a timer, completion, failure, or
    // cancellation.
    let loss = incidents(&events, "unresolved_native_owner_at_local_boundary");
    assert_eq!(loss.len(), 1, "the unresolved owner is reported once");
    assert_eq!(loss[0]["detail"]["entry_observed"].as_bool(), Some(true));
    assert_eq!(
        loss[0]["detail"]["terminal_evidence_observed"].as_bool(),
        Some(false)
    );
    assert_eq!(
        loss[0]["detail"]["native_cancel_fabricated"].as_bool(),
        Some(false)
    );
    assert!(
        events_of_kind(&events, "task_output").is_empty(),
        "no completion is fabricated for a blocked owner"
    );
    assert_eq!(
        rm_preparation::verify_preparation(&writer, &handle.preparation)
            .expect("the preparation is still the exact retained one")
            .preparation_id,
        handle.preparation.preparation_id,
        "the unresolved execution is not logically replaced"
    );

    // A further bounded quantum has nothing due: it neither rewrites the
    // closure nor appends another registration.
    rm_supervisor::drive_once(&writer, &now).expect("an idle quantum is bounded");
    assert_eq!(
        publication_registrations(&journal_events(&writer, &journal_id)).len(),
        1,
        "a closed window without new evidence is never rewritten"
    );
    assert!(rm_delivery::claim_work(&writer, &now)
        .expect("claim reads")
        .is_none());
}

#[test]
fn rm_c25_late_evidence_revises_closure_without_reopening() {
    let writer = principal("rm-supervisor-c25-late");
    let (manifest, commission, handle, connector_id) =
        application_subject(&writer, "c25-late", 60_000.0);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");

    rm_supervisor::drive_once(&writer, &local_now()).expect("the execution is adopted");
    append_blocked_native_entry(&writer, &manifest, &handle);

    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now).expect("the window closes at its local boundary");

    let first_events = journal_events(&writer, &journal_id);
    let first_publication = publication_registrations(&first_events)
        .into_iter()
        .next()
        .expect("the first closure is registered");
    let first_revision = load_revision(&writer, &first_publication);
    assert_eq!(first_revision["revision"].as_u64(), Some(1));
    let first_closed_at = first_revision["value"]["closed_at"].clone();
    let first_content = ArtifactReference::from_json(
        first_publication
            .get("content")
            .expect("the first publication cites its bytes"),
    )
    .expect("the first content reference parses");
    let first_bytes =
        rm_evidence::load_artifact(&writer, &first_content).expect("first bytes retained");

    // Late evidence arrives after closure: a control observation is appended
    // at the current journal head. The window stays closed.
    let late = control(
        &writer,
        &cancel_command(
            &connector_id,
            &manifest,
            &handle,
            control_scope(
                &manifest,
                &commission,
                "c25-late",
                vec!["control:request_native_cancel"],
            ),
            "request-c25-late",
        ),
    )
    .expect("late control evidence is retained");
    assert_eq!(late.observation.disposition, Disposition::Unsupported);
    assert_eq!(
        rm_controls::window_state(&writer, &handle).expect("window stays closed"),
        WindowState::Closed,
        "late evidence never reopens the observation window"
    );

    // The next bounded quantum publishes a closed-to-closed revision at the
    // current head; it never re-closes the window from scratch.
    rm_supervisor::drive_once(&writer, &now).expect("late evidence is published without reopening");

    let events = journal_events(&writer, &journal_id);
    let publications = publication_registrations(&events);
    assert_eq!(publications.len(), 2, "one new closure revision is registered");
    assert_eq!(
        publications[1]["revision"].as_u64(),
        Some(2),
        "the late revision advances the observation axis"
    );
    assert_eq!(publications[1]["previous_revision"].as_u64(), Some(1));
    let late_revision = load_revision(&writer, &publications[1]);
    assert_eq!(late_revision["value"]["state"].as_str(), Some("closed"));
    assert_eq!(
        late_revision["value"]["closed_at"].clone(),
        first_closed_at,
        "the original close coordinate is preserved"
    );
    assert_eq!(
        late_revision["value"]["at_close"]["closure_id"].clone(),
        first_revision["value"]["at_close"]["closure_id"].clone(),
        "the original closure identity is preserved"
    );
    assert_eq!(
        late_revision["value"]["at_close"]["execution_knowledge"].as_str(),
        Some("unknown"),
        "late control evidence never upgrades execution knowledge"
    );
    assert_eq!(
        late_revision["value"]["late_evidence_refs"]
            .as_array()
            .expect("late references retained")
            .len(),
        1,
        "the new revision cites the late evidence"
    );
    assert_eq!(
        late_revision["value"]["control_observations"]
            .as_array()
            .expect("control observations retained")
            .len(),
        1
    );

    // Every prior publication and its seals are preserved unchanged.
    assert_eq!(
        rm_evidence::load_artifact(&writer, &first_content).expect("first bytes still retained"),
        first_bytes,
        "an installed publication is never replaced under its digest"
    );
    assert!(
        events_of_kind(&events, "task_output").is_empty(),
        "late evidence is never promoted to a completion"
    );
    assert!(
        rm_delivery::claim_work(&writer, &now)
            .expect("claim reads")
            .is_none(),
        "late evidence never starts a replacement execution"
    );
}

#[test]
fn rm_c25_queue_pressure_never_consumes_reserved_close_progress() {
    let writer = principal("rm-supervisor-c25-pressure");

    // An execution already in the supervisor's registry, close to its
    // boundary.
    let (first_manifest, _first_commission, first_handle, _first_connector) =
        application_subject(&writer, "c25-pressure-a", 60_000.0);
    rm_supervisor::drive_once(&writer, &local_now()).expect("the first execution is adopted");

    // A second workflow is queued and ready; its boundary is far away.
    let (second_manifest, _second_commission, second_handle, _second_connector) =
        application_subject(&writer, "c25-pressure-b", 600_000.0);
    assert_eq!(
        rm_delivery::local_state(&writer, &second_handle).expect("state reads"),
        "admitted_queued"
    );

    // The first execution reaches its boundary. Reserved close progress is
    // served before the ready queue is claimed.
    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now)
        .expect("the due closure is served under queue pressure");

    assert_eq!(
        rm_controls::window_state(&writer, &first_handle).expect("first window reads"),
        WindowState::Closed,
        "the due closure made progress before any new claim"
    );
    let first_journal = rm_evidence::journal_id_for(&first_manifest).expect("journal identity");
    assert_eq!(
        publication_registrations(&journal_events(&writer, &first_journal)).len(),
        1,
        "the due closure is published even while new work is queued"
    );
    assert_eq!(
        rm_delivery::local_state(&writer, &second_handle).expect("second state reads"),
        "admitted_queued",
        "workflow queue pressure never consumes reserved close progress"
    );
    assert!(
        rm_controls::window_state(&writer, &second_handle).is_err(),
        "the queued workflow was not touched"
    );

    // The following quantum may now claim the ready workflow.
    rm_supervisor::drive_once(&writer, &now).expect("the ready workflow is claimed in its bound");
    assert_eq!(
        rm_delivery::local_state(&writer, &second_handle).expect("second state reads"),
        "assigned",
        "the second execution is adopted once"
    );
    assert!(
        rm_delivery::claim_work(&writer, &now)
            .expect("claim reads")
            .is_none()
    );
    let second_journal = rm_evidence::journal_id_for(&second_manifest).expect("journal identity");
    assert!(
        publication_registrations(&journal_events(&writer, &second_journal)).is_empty(),
        "the newly claimed execution is not closed before its own boundary"
    );
    assert!(
        rm_controls::window_state(&writer, &second_handle).is_err(),
        "no observation window is invented before the new execution reaches its boundary"
    );
}

#[test]
fn rm_c25_expired_queue_entry_never_begins_a_workflow() {
    let writer = principal("rm-supervisor-c25-expired");
    let (manifest, _commission, handle, _connector_id) =
        application_subject(&writer, "c25-expired", 1.0);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");

    // The active budget is consumed while the work waits in the queue. The
    // supervisor's quantum sees no deliverable work and never begins a
    // workflow primitive for it.
    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now).expect("the quantum is bounded");

    assert_eq!(
        rm_delivery::local_state(&writer, &handle).expect("delivery state reads"),
        "expired_before_entry",
        "queue time counts against the active budget"
    );
    assert!(
        rm_delivery::claim_work(&writer, &now)
            .expect("claim reads")
            .is_none(),
        "expired work is never handed to a native owner"
    );
    let events = journal_events(&writer, &journal_id);
    assert!(
        events_of_kind(&events, "execution_claim").is_empty(),
        "no workflow primitive began after the active boundary"
    );
    assert!(
        events_of_kind(&events, "task_output").is_empty(),
        "no completion is fabricated for expired work"
    );
    assert!(
        publication_registrations(&events).is_empty(),
        "expired work never fabricates an application observation revision"
    );
    assert!(
        rm_controls::window_state(&writer, &handle).is_err(),
        "no observation window was opened for undelivered work"
    );
    // The expiry decision is retained as dispatch evidence, not silently
    // dropped.
    assert!(
        events
            .iter()
            .any(|envelope| envelope.event_kind == "dispatch_published"
                && envelope.payload.data.get("detail").is_some_and(|detail| {
                    detail.get("reason").and_then(Value::as_str)
                        == Some("queue_expired_before_entry")
                })),
        "the expiry decision is durably recorded"
    );

    // A later quantum is still bounded and still delivers nothing.
    rm_supervisor::drive_once(&writer, &now).expect("the idle quantum is bounded");
    assert_eq!(
        rm_delivery::local_state(&writer, &handle).expect("delivery state reads"),
        "expired_before_entry"
    );
}

/// The registered closure cites only resolvable evidence inside its own
/// prefix, carries the exact recovered commission digest, and is registered
/// under the exact installed bytes.
#[test]
fn rm_c25_published_closure_cites_resolvable_evidence_and_exact_commission() {
    let writer = principal("rm-supervisor-c25-shape");
    let (manifest, commission, handle, _connector_id) =
        application_subject(&writer, "c25-shape", 60_000.0);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    rm_supervisor::drive_once(&writer, &local_now()).expect("the execution is adopted");
    append_blocked_native_entry(&writer, &manifest, &handle);

    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now).expect("the window closes");

    let events = journal_events(&writer, &journal_id);
    let registration = publication_registrations(&events)
        .into_iter()
        .next()
        .expect("the closure is registered");
    assert_eq!(
        registration["handle"]["local_handle"].as_str(),
        Some(handle.handle.local_handle.as_str())
    );
    let revision = load_revision(&writer, &registration);

    // The registered revision carries the exact recovered commission identity.
    assert_eq!(
        revision["commission_digest"].as_str(),
        Some(
            rm_lifecycle::commission_digest(&commission)
                .expect("the commission hashes")
                .as_str()
        )
    );
    assert_eq!(
        revision["value"]["window_id"].as_str(),
        Some(
            format!(
                "window:{}:{}",
                handle.handle.connector_id, handle.handle.local_handle
            )
            .as_str()
        )
    );

    // Every cited closure reference resolves inside the revision's own
    // evidence prefix; the prefix names the attempt's journal.
    let prefix = &revision["evidence_prefix"];
    assert_eq!(
        prefix["journal_id"].as_str(),
        Some(commission.journal_id.as_str())
    );
    let prefix_value = rm_evidence::JournalPrefix {
        journal_id: prefix["journal_id"]
            .as_str()
            .expect("prefix journal")
            .to_string(),
        last_sequence: PositiveInteger::new(
            prefix["last_sequence"].as_u64().expect("prefix sequence"),
        )
        .expect("positive prefix sequence"),
        head_hash: rm_evidence::Digest::parse(
            prefix["head_hash"].as_str().expect("prefix head hash"),
        )
        .expect("valid prefix head hash"),
    };
    for reference in revision["evidence_refs"]
        .as_array()
        .expect("closure evidence refs")
    {
        let reference = EvidenceRef::from_json(reference).expect("closure evidence ref parses");
        rm_evidence::resolve_evidence(&writer, &reference, &prefix_value)
            .expect("closure evidence resolves inside its cited prefix");
    }

    // The registered bytes are the exact bytes of the cited content artifact.
    let content = ArtifactReference::from_json(
        registration
            .get("content")
            .expect("registration cites content"),
    )
    .expect("content reference parses");
    let bytes = rm_evidence::load_artifact(&writer, &content).expect("content bytes are retained");
    assert_eq!(artifact_digest(&bytes), content.digest);
    assert_eq!(bytes.len() as u64, content.size_bytes);
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("content bytes are JSON"),
        revision
    );
}

/// A coordinate from another boot is never ordered against the admitted
/// lifetime: closure is refused instead of subtracting incompatible clocks,
/// and the execution remains available for a later, comparable quantum.
#[test]
fn rm_c25_cross_boot_coordinates_never_close_or_rebind_lifetimes() {
    let writer = principal("rm-supervisor-c25-lifetime");
    let (manifest, _commission, handle, _connector_id) =
        application_subject(&writer, "c25-lifetime", 60_000.0);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    rm_supervisor::drive_once(&writer, &local_now()).expect("the execution is adopted");

    let mut foreign = shift(&local_now(), 120_000.0);
    foreign.boot_id = "different-boot".to_string();
    let error = rm_supervisor::drive_once(&writer, &foreign)
        .expect_err("a foreign boot is never ordered against the admitted lifetime");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("boot"),
        "the refusal names the boot mismatch: {}",
        error.detail
    );
    assert!(
        publication_registrations(&journal_events(&writer, &journal_id)).is_empty(),
        "no closure is fabricated from a foreign-boot coordinate"
    );
    assert_eq!(
        rm_delivery::local_state(&writer, &handle).expect("delivery state reads"),
        "assigned",
        "the execution is not rebound or replaced by the refused coordinate"
    );

    // A comparable coordinate from the admitted lifetime still closes within
    // the same bounded path.
    let now = shift(&local_now(), 120_000.0);
    rm_supervisor::drive_once(&writer, &now).expect("the comparable closure succeeds");
    assert_eq!(
        rm_controls::window_state(&writer, &handle).expect("window state reads"),
        WindowState::Closed
    );
    assert_eq!(
        publication_registrations(&journal_events(&writer, &journal_id)).len(),
        1
    );
}
