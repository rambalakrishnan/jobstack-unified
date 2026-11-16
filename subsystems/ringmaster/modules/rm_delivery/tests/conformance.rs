//! Conformance tests for RM-C22, RM-C23, and RM-C24.
//!
//! - RM-C22: a repeated Start command and logical key yield one handle and one
//!   logical execution, even under concurrent delivery of distinct commands.
//! - RM-C23: a crash around dispatch preserves honest uncertainty and never
//!   silently resends; only explicit, evidenced recovery authorizes another
//!   delivery.
//! - RM-C24: a queue that expires before native entry produces no workflow
//!   delivery, while owner control admission stays independent.
//!
//! Every test name carries `rm_c22`, `rm_c23`, or `rm_c24` so the verification
//! filter `cargo test -p rm_delivery -- rm_c22 rm_c23 rm_c24` selects the
//! suite. All tests use real admitted evidence journals, real preparations
//! from `rm_preparation`, real lease records, and real lifecycle publications.

use std::io::Cursor;

use rm_authority::{
    authenticate_channel, AttemptCommission, AttemptKind, AuthenticatedPrincipal,
    EvaluationPartition, ExecutionMode, Manifest, TargetClass, WorkScope,
};
use rm_catalog::{DescribeRequest, VersionPin};
use rm_delivery::{
    claim_work, dispatch_value, enqueue_owner_control, lifecycle_publication, local_state,
    recover_delivery, start, take_owner_control, CommandPayload, ConnectorHandle, ConnectorRequest,
    MaybeCommission, MaybeResume, PublicationState, RecoveryState, ResumeAuthorization, StartRequest,
    StartDisposition, CONTROL_VERBS, START_VERB,
};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, JournalEnvelope, Missing,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_lifecycle::{Axis, DispatchState};
use rm_preparation::{
    AssistanceRecord, CatalogMaybeString, CatalogMaybeVersionPin, ConfigurationPin, ContextPolicy,
    DurationLimit, EntryPoint, MaybeArtifact, PermittedOrigin, PrepareRequest,
    PrepareResult, StatePolicy, SuccessCriterion, TaskBudgets, TaskEnvelope,
};
use rm_time::{MaybeString, MeasurementOrigin, TimePoint, UtcAnnotation};
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
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire).expect("manifest hashes").as_str().to_string();
    manifest
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact =
        rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact reference");
    EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("positive sequence")),
        event_kind: "manifest_admitted".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: rm_evidence::MaybeTimePoint::Missing(Missing::new("not_applicable")),
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

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner: &str,
) -> ArtifactReference {
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

// ---------------------------------------------------------------------------
// Fixtures: tasks, scopes, preparations
// ---------------------------------------------------------------------------

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

fn discovery_task(task_id: &str, entry_url: &str, origin: &str, active_limit_ms: f64) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: "extract".to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: entry_url.to_string(),
        },
        goal: format!("extract from {entry_url}"),
        success_criteria: vec![SuccessCriterion {
            criterion_id: "c1".to_string(),
            description: "extraction completes".to_string(),
        }],
        inputs: Vec::new(),
        permitted_origins: vec![PermittedOrigin {
            logical_id: "o1".to_string(),
            origin: origin.to_string(),
        }],
        permitted_interfaces: vec!["read_only_acquisition".to_string()],
        effect_policy: "read_only".to_string(),
        budgets: test_budgets(active_limit_ms),
        context_policy: test_context(),
        output_schema: CatalogMaybeVersionPin::Present(VersionPin {
            id: "output-schema".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(b"output-schema-1"),
        }),
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

fn discovery_assistance() -> AssistanceRecord {
    AssistanceRecord {
        planning_owner: "external_planner".to_string(),
        assistance_track: "track-extract".to_string(),
        planner_identity: CatalogMaybeString::Text("planner-1".to_string()),
        plan: MaybeArtifact::Missing(Missing::new("not_applicable")),
        online_replanning: false,
        description: "declared extraction assistance".to_string(),
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

fn discovery_scope(manifest: &Manifest, tag: &str) -> WorkScope {
    WorkScope {
        activity: "discovery".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal identity"),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec![format!("grant-discovery-{tag}")],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

fn apply_scope(manifest: &Manifest, commission: &AttemptCommission, tag: &str) -> WorkScope {
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

/// Computes the Contract 02 semantic hash the same way the module does.
fn semantic_hash_of(task: &TaskEnvelope) -> String {
    let mut value = task.to_json();
    if let Value::Object(map) = &mut value {
        map.remove("task_id");
        if let Some(Value::Object(entry)) = map.get_mut("entry") {
            let logical = entry.get("logical_id").cloned().unwrap_or(Value::Null);
            entry.insert("url".to_string(), logical);
        }
        if let Some(Value::Array(origins)) = map.get_mut("permitted_origins") {
            for origin in origins {
                if let Value::Object(item) = origin {
                    let logical = item.get("logical_id").cloned().unwrap_or(Value::Null);
                    item.insert("origin".to_string(), logical);
                }
            }
        }
    }
    let bytes = serde_json::to_vec(&value).expect("semantic serializes");
    canonical_digest(&bytes).expect("semantic hashes").as_str().to_string()
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

fn prepare_discovery(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
    tag: &str,
    active_limit_ms: f64,
) -> PrepareResult {
    let (_descriptor, configuration) = descriptor_pin(writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://fixture.example/jobs/1",
        "https://fixture.example",
        active_limit_ms,
    );
    let scope = discovery_scope(manifest, tag);
    let command = prepare_command(
        &configuration,
        scope,
        manifest,
        None,
        task,
        discovery_assistance(),
        tag,
    );
    rm_preparation::prepare(writer, &command).expect("discovery preparation succeeds")
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
    let scope = apply_scope(manifest, &commission, tag);
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
// Fixtures: leases and clocks
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

fn time_json(offset_ms: f64) -> Value {
    serde_json::to_value(time_point(offset_ms)).expect("time point serializes")
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
            "id": "delivery-lease",
            "version": "1",
            "artifact_digest": artifact_digest(b"delivery-lease-policy-1").as_str(),
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

fn start_command(
    connector_id: &str,
    prepared: &PrepareResult,
    manifest: &Manifest,
    commission: MaybeCommission,
    lease: LeaseRecord,
    idempotency_key: &str,
    request_id: &str,
    authorization_refs: Vec<String>,
) -> ConnectorRequest {
    ConnectorRequest {
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
        payload: CommandPayload::Start(StartRequest {
            preparation: prepared.preparation.clone(),
            idempotency_key: idempotency_key.to_string(),
            accepted_concern_ids: prepared
                .record
                .concerns
                .iter()
                .map(|concern| concern.concern_id.clone())
                .collect(),
            authorization_refs,
            recovery: MaybeResume::Missing(Missing::new("not_applicable")),
            manifest: manifest.clone(),
            commission,
            lease,
        }),
    }
}

fn control_scope(manifest: &Manifest) -> WorkScope {
    WorkScope {
        activity: "discovery".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal identity"),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec!["control:cancel-1".to_string()],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

fn control_command(
    connector_id: &str,
    manifest: &Manifest,
    handle: &ConnectorHandle,
    request_id: &str,
    operation: &str,
) -> ConnectorRequest {
    assert!(CONTROL_VERBS.contains(&operation), "test uses a control verb");
    ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: request_id.to_string(),
        connector_id: connector_id.to_string(),
        operation: operation.to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: CommandPayload::Control(rm_delivery::ControlRequest {
            scope: control_scope(manifest),
            manifest: manifest.clone(),
            handle: handle.handle.clone(),
        }),
    }
}

// ---------------------------------------------------------------------------
// RM-C22: one handle, one logical execution
// ---------------------------------------------------------------------------

#[test]
fn rm_c22_repeated_start_command_and_key_yield_one_handle() {
    let writer = principal("rm-delivery-c22-repeat");
    let manifest = test_manifest("rm-delivery-c22-repeat-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c22-repeat", 60_000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c22-repeat",
        600_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease.clone(),
        "idem-c22-repeat",
        "request-c22-a",
        vec!["grant-discovery-c22-repeat".to_string()],
    );

    let accepted = start(&writer, &command).expect("first Start admits locally");
    assert_eq!(accepted.kind, "start_receipt");
    assert_eq!(accepted.disposition, StartDisposition::AcceptedLocally);
    assert_eq!(accepted.handle.handle.connector_id, command.connector_id);

    // The handle artifact is the exact durable handle, not a fabricated one.
    let bytes = rm_evidence::load_artifact(&writer, &accepted.handle_artifact).expect("handle loads");
    let parsed: Value = serde_json::from_slice(&bytes).expect("handle bytes are JSON");
    let parsed = ConnectorHandle::from_json(&parsed).expect("handle parses");
    assert_eq!(parsed, accepted.handle);
    assert_eq!(parsed.idempotency_key, "idem-c22-repeat");
    assert_eq!(parsed.preparation, prepared.preparation);

    // The same command returns its retained receipt without another effect.
    let head_after_first = rm_evidence::journal_head(
        &writer,
        &rm_evidence::journal_id_for(&manifest).expect("journal identity"),
    )
    .expect("journal head");
    let repeated = start(&writer, &command).expect("retained command returns its receipt");
    assert_eq!(repeated.disposition, StartDisposition::AcceptedLocally);
    assert_eq!(repeated.handle, accepted.handle);
    assert_eq!(repeated.receipt_ref, accepted.receipt_ref);
    let head_after_repeat = rm_evidence::journal_head(
        &writer,
        &rm_evidence::journal_id_for(&manifest).expect("journal identity"),
    )
    .expect("journal head");
    assert_eq!(
        head_after_repeat, head_after_first,
        "a retained command must not append another admission effect"
    );

    // A new transport request over the same logical key returns the same
    // handle and the same retained receipt.
    let mut renamed = command.clone();
    renamed.request_id = "request-c22-b".to_string();
    let existing = start(&writer, &renamed).expect("same logical key returns the same handle");
    assert_eq!(existing.disposition, StartDisposition::ExistingHandle);
    assert_eq!(existing.handle.handle, accepted.handle.handle);
    assert_eq!(existing.receipt_ref, accepted.receipt_ref);

    // Changed content under the same logical key is rejected, never silently
    // replaced with a second execution.
    let other = prepare_discovery(&writer, &manifest, "c22-repeat-other", 60_000.0);
    let conflicting = start_command(
        &other.record.configuration.connector_id,
        &other,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        held_lease(
            &writer,
            &manifest,
            &other.record.task.task_id,
            "c22-repeat-other",
            600_000.0,
        ),
        "idem-c22-repeat",
        "request-c22-conflict",
        vec!["grant-discovery-c22-repeat-other".to_string()],
    );
    let error = start(&writer, &conflicting).expect_err("changed content under one key is rejected");
    assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");

    // A preparation whose bytes do not verify is never a Start authority.
    let fake = install_bytes(&writer, br#"{"record_type":"prepared_task"}"#, "artifact");
    let mut tampered = command.clone();
    tampered.request_id = "request-c22-tampered".to_string();
    if let CommandPayload::Start(payload) = &mut tampered.payload {
        payload.preparation.artifact = fake;
    }
    assert!(
        start(&writer, &tampered).is_err(),
        "Start must verify the exact retained preparation"
    );

    // Exactly one admitted execution is claimable.
    let now = shift(&accepted.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("the single admitted execution is claimable");
    assert_eq!(claimed.handle.local_handle, accepted.handle.handle.local_handle);
    assert_eq!(
        local_state(&writer, &claimed).expect("state reads"),
        "assigned"
    );
    assert!(
        claim_work(&writer, &now).expect("second claim runs").is_none(),
        "one logical execution is never claimed twice"
    );
}

#[test]
fn rm_c22_concurrent_start_commands_yield_one_handle() {
    let writer = principal("rm-delivery-c22-concurrent");
    let manifest = test_manifest("rm-delivery-c22-concurrent-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c22-concurrent", 60_000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c22-concurrent",
        600_000.0,
    );
    let mut commands = Vec::new();
    for index in 0..4 {
        commands.push(start_command(
            &prepared.record.configuration.connector_id,
            &prepared,
            &manifest,
            MaybeCommission::Missing(Missing::new("not_applicable")),
            lease.clone(),
            "idem-c22-concurrent",
            &format!("request-c22-concurrent-{index}"),
            vec!["grant-discovery-c22-concurrent".to_string()],
        ));
    }

    // Distinct transport commands, one logical key, delivered concurrently.
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = commands
            .iter()
            .map(|command| scope.spawn(|| start(&writer, command)))
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("start thread joins"))
            .collect()
    });
    let receipts: Vec<_> = results
        .into_iter()
        .map(|result| result.expect("concurrent Start never double-admits"))
        .collect();
    let first = &receipts[0];
    let accepted = receipts
        .iter()
        .filter(|receipt| receipt.disposition == StartDisposition::AcceptedLocally)
        .count();
    assert_eq!(accepted, 1, "exactly one command commits the admission effect");
    for receipt in &receipts {
        assert_eq!(receipt.handle.handle, first.handle.handle);
        assert_eq!(receipt.receipt_ref, first.receipt_ref);
    }
    let now = shift(&first.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("one handle is claimable");
    assert_eq!(claimed.handle, first.handle.handle);
    assert!(claim_work(&writer, &now).expect("second claim runs").is_none());
}

#[test]
fn rm_c22_changed_key_never_buys_a_second_execution_for_one_commission() {
    let writer = principal("rm-delivery-c22-commission");
    let manifest = test_manifest("rm-delivery-c22-commission-run");
    admit(&writer, &manifest);
    let (prepared, commission, configuration) =
        prepare_application(&writer, &manifest, "c22-commission", 60_000.0);
    let lease = held_lease(&writer, &manifest, &commission.attempt_id, "c22-commission", 600_000.0);
    let first_command = start_command(
        &configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Present(commission.clone()),
        lease.clone(),
        "idem-c22-commission-a",
        "request-c22-commission-a",
        vec!["grant-apply-c22-commission".to_string()],
    );
    let first = start(&writer, &first_command).expect("application Start admits");
    assert_eq!(first.disposition, StartDisposition::AcceptedLocally);
    assert_eq!(
        first.handle.scope.attempt_id.as_deref(),
        Some(commission.attempt_id.as_str())
    );

    // A changed key over the same commission is not a second execution.
    let changed_key = start_command(
        &configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Present(commission.clone()),
        lease,
        "idem-c22-commission-b",
        "request-c22-commission-b",
        vec!["grant-apply-c22-commission".to_string()],
    );
    let error = start(&writer, &changed_key).expect_err("a changed key is rejected");
    assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");
    // The binding is durable: a restart reading only the journal rejects the
    // changed key too, so a lost memory cache cannot buy a second execution.
    let durable_error =
        recover_delivery(&writer, &changed_key).expect_err("the durable binding rejects it too");
    assert_eq!(durable_error.code, "IDEMPOTENCY_CONFLICT");

    let now = shift(&first.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("the commissioned attempt is claimable once");
    assert_eq!(claimed.handle.local_handle, first.handle.handle.local_handle);
    assert!(claim_work(&writer, &now).expect("second claim runs").is_none());
}

#[test]
fn rm_c22_application_start_publishes_dispatch_axis_after_local_commit() {
    let writer = principal("rm-delivery-c22-publish");
    let manifest = test_manifest("rm-delivery-c22-publish-run");
    admit(&writer, &manifest);
    let (prepared, commission, configuration) =
        prepare_application(&writer, &manifest, "c22-publish", 60_000.0);
    let lease = held_lease(&writer, &manifest, &commission.attempt_id, "c22-publish", 600_000.0);
    let command = start_command(
        &configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Present(commission.clone()),
        lease,
        "idem-c22-publish",
        "request-c22-publish",
        vec!["grant-apply-c22-publish".to_string()],
    );
    let receipt = start(&writer, &command).expect("application Start admits");
    let publication = lifecycle_publication(&writer, &receipt.handle).expect("publication reads");
    let reference = match publication {
        PublicationState::Published(reference) => reference,
        other => panic!("dispatch publication must be admitted: {other:?}"),
    };
    assert_eq!(reference.axis, Axis::Dispatch);
    assert_eq!(reference.revision, 1);
    let bytes = rm_evidence::load_artifact(&writer, &reference.content).expect("revision loads");
    let revision: Value = serde_json::from_slice(&bytes).expect("revision is JSON");
    assert_eq!(revision["value"]["state"], "prepared");
    assert_eq!(
        revision["value"]["local_handle"],
        receipt.handle.handle.local_handle
    );

    // Claiming records the dispatching revision after the local claim commit.
    let now = shift(&receipt.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("application execution is claimable");
    let dispatch = dispatch_value(&writer, &claimed).expect("dispatch reads");
    assert_eq!(dispatch.state, DispatchState::Dispatching);
    assert_eq!(dispatch.delivery_refs.len(), 1);
    assert!(
        dispatch.acceptance_refs.is_empty(),
        "local Start and claim are never native acceptance"
    );
    let publication = lifecycle_publication(&writer, &claimed).expect("publication reads");
    let reference = match publication {
        PublicationState::Published(reference) => reference,
        other => panic!("dispatching publication must be admitted: {other:?}"),
    };
    assert_eq!(reference.revision, 2);
    let bytes = rm_evidence::load_artifact(&writer, &reference.content).expect("revision loads");
    let revision: Value = serde_json::from_slice(&bytes).expect("revision is JSON");
    assert_eq!(revision["value"]["state"], "dispatching");
}

// ---------------------------------------------------------------------------
// RM-C23: crash around dispatch preserves uncertainty
// ---------------------------------------------------------------------------

#[test]
fn rm_c23_crash_around_dispatch_preserves_uncertainty_and_requires_resume() {
    let writer = principal("rm-delivery-c23-dispatch");
    let manifest = test_manifest("rm-delivery-c23-dispatch-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c23-dispatch", 600_000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c23-dispatch",
        600_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease,
        "idem-c23-dispatch",
        "request-c23-dispatch-a",
        vec!["grant-discovery-c23-dispatch".to_string()],
    );
    let receipt = start(&writer, &command).expect("Start admits");
    let prepared_dispatch = dispatch_value(&writer, &receipt.handle).expect("dispatch reads");
    assert_eq!(prepared_dispatch.state, DispatchState::Prepared);
    assert!(prepared_dispatch.delivery_refs.is_empty());

    let now = shift(&receipt.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("execution is claimable once");
    let dispatching = dispatch_value(&writer, &claimed).expect("dispatch reads");
    assert_eq!(dispatching.state, DispatchState::Dispatching);
    assert_eq!(dispatching.delivery_refs.len(), 1);
    assert!(dispatching.acceptance_refs.is_empty());
    assert_eq!(
        dispatching.native_run_id,
        MaybeString::Missing(Missing::new("not_observed")),
        "no native run ID is ever fabricated from a local claim"
    );

    // Restart reading: the journal alone shows a delivery attempt, so the
    // execution is awaiting source-backed evidence rather than deliverable.
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    let head_before = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    let recovered = recover_delivery(&writer, &command)
        .expect("recovery reads the journal")
        .expect("retained admission is found");
    assert_eq!(recovered.state, RecoveryState::AwaitingEvidence);
    assert_eq!(recovered.dispatch.state, DispatchState::Dispatching);
    assert_eq!(recovered.dispatch.delivery_refs.len(), 1);
    assert_eq!(recovered.admission_receipt, receipt.receipt_ref);
    let head_after = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    assert_eq!(
        head_after, head_before,
        "recovery is a read and never reruns the external action"
    );

    // A repeated initial Start does not resend and does not claim acceptance.
    let mut repeated = command.clone();
    repeated.request_id = "request-c23-dispatch-b".to_string();
    let existing = start(&writer, &repeated).expect("same logical key returns the same handle");
    assert_eq!(existing.disposition, StartDisposition::ExistingHandle);
    assert_eq!(existing.handle.handle, receipt.handle.handle);
    assert_eq!(existing.receipt_ref, receipt.receipt_ref);
    let still_dispatching = dispatch_value(&writer, &existing.handle).expect("dispatch reads");
    assert_eq!(still_dispatching.state, DispatchState::Dispatching);
    assert_eq!(still_dispatching.delivery_refs.len(), 1);
    assert!(still_dispatching.acceptance_refs.is_empty());
    assert!(
        claim_work(&writer, &now).expect("claim runs").is_none(),
        "a possible delivery is never silently resent"
    );

    // Explicit recovery requires evidenced native resume authority and a new
    // command identity; task grants alone are not recovery authority.
    let checkpoint = install_bytes(&writer, br#"{"checkpoint":"native-1"}"#, "artifact");
    let contract = install_bytes(&writer, br#"{"resume":"idempotent"}"#, "artifact");
    let mut unauthorized = repeated.clone();
    unauthorized.request_id = "request-c23-dispatch-c".to_string();
    if let CommandPayload::Start(payload) = &mut unauthorized.payload {
        payload.recovery = MaybeResume::Authorized(ResumeAuthorization {
            handle: receipt.handle.handle.clone(),
            checkpoint: checkpoint.clone(),
            native_resume_contract: contract.clone(),
            authorization_refs: vec!["grant-discovery-c23-dispatch".to_string()],
            evidence_refs: vec![dispatching.delivery_refs[0].clone()],
        });
    }
    let error = start(&writer, &unauthorized).expect_err("task grants do not authorize resume");
    assert_eq!(error.code, "FORBIDDEN");

    let mut resume = repeated.clone();
    resume.request_id = "request-c23-dispatch-resume".to_string();
    if let CommandPayload::Start(payload) = &mut resume.payload {
        payload.recovery = MaybeResume::Authorized(ResumeAuthorization {
            handle: receipt.handle.handle.clone(),
            checkpoint,
            native_resume_contract: contract,
            authorization_refs: vec!["recovery:checkpoint-1".to_string()],
            evidence_refs: vec![dispatching.delivery_refs[0].clone()],
        });
    }
    let resumed = start(&writer, &resume).expect("explicit recovery authorizes another delivery");
    assert_eq!(resumed.disposition, StartDisposition::ResumeAuthorized);
    assert_eq!(resumed.handle.handle, receipt.handle.handle);
    let resumed_dispatch = dispatch_value(&writer, &resumed.handle).expect("dispatch reads");
    assert_eq!(resumed_dispatch.state, DispatchState::Dispatching);
    assert_eq!(resumed_dispatch.delivery_refs.len(), 2);
    assert_eq!(
        resumed_dispatch.recovery_authorization_refs,
        vec!["recovery:checkpoint-1".to_string()]
    );

    // The authorized additional delivery is claimable exactly once more.
    let claimed_again = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("resumed execution is deliverable again");
    assert_eq!(claimed_again.handle.local_handle, receipt.handle.handle.local_handle);
    let final_dispatch = dispatch_value(&writer, &claimed_again).expect("dispatch reads");
    assert_eq!(final_dispatch.delivery_refs.len(), 3);
    assert!(final_dispatch.acceptance_refs.is_empty());
    assert!(claim_work(&writer, &now).expect("claim runs").is_none());
}

#[test]
fn rm_c23_crash_between_admission_and_delivery_recovers_one_handle() {
    let writer = principal("rm-delivery-c23-admission");
    let manifest = test_manifest("rm-delivery-c23-admission-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c23-admission", 600_000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c23-admission",
        600_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease,
        "idem-c23-admission",
        "request-c23-admission-a",
        vec!["grant-discovery-c23-admission".to_string()],
    );
    let receipt = start(&writer, &command).expect("Start admits");

    // Restart before any delivery: the same logical execution is recovered and
    // may be delivered again only within the remaining boundary.
    let recovered = recover_delivery(&writer, &command)
        .expect("recovery reads the journal")
        .expect("retained admission is found");
    assert_eq!(recovered.state, RecoveryState::Deliverable);
    assert_eq!(recovered.dispatch.state, DispatchState::Prepared);
    assert_eq!(recovered.handle, receipt.handle);
    assert_eq!(recovered.admission_receipt, receipt.receipt_ref);
    assert!(recovered.dispatch.delivery_refs.is_empty());

    // A repeated Start between admission and delivery does not enqueue a
    // second copy: the exact command returns its retained receipt and a new
    // transport identity over the same key returns the same handle.
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    let head_before = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    let mut renamed = command.clone();
    renamed.request_id = "request-c23-admission-b".to_string();
    let existing = start(&writer, &renamed).expect("same key returns the same handle");
    assert_eq!(existing.disposition, StartDisposition::ExistingHandle);
    assert_eq!(existing.handle, receipt.handle);
    assert_eq!(existing.receipt_ref, receipt.receipt_ref);
    let head_after = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    assert_eq!(
        head_after, head_before,
        "a repeated Start must not append a second admission"
    );

    let now = shift(&receipt.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &now)
        .expect("claim runs")
        .expect("recovered execution is claimable once");
    assert_eq!(claimed.handle.local_handle, receipt.handle.handle.local_handle);
    assert!(claim_work(&writer, &now).expect("second claim runs").is_none());
}

// ---------------------------------------------------------------------------
// RM-C24: queue expiry before native entry
// ---------------------------------------------------------------------------

#[test]
fn rm_c24_queue_expires_before_entry_no_workflow_delivery() {
    let writer = principal("rm-delivery-c24-expiry");
    let manifest = test_manifest("rm-delivery-c24-expiry-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c24-expiry", 1000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c24-expiry",
        600_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease.clone(),
        "idem-c24-expiry",
        "request-c24-expiry",
        vec!["grant-discovery-c24-expiry".to_string()],
    );
    let receipt = start(&writer, &command).expect("Start admits");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    let head_before = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");

    // Queue time counts: the active boundary is crossed before the first claim.
    let late = shift(&receipt.handle.created_at, 5000.0);
    assert!(
        claim_work(&writer, &late).expect("claim runs").is_none(),
        "expired queued work is never delivered"
    );
    let head_after = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    assert!(
        head_after.last_sequence > head_before.last_sequence,
        "expiry is retained as owner-local evidence"
    );
    let expiry_event = rm_evidence::read_event(&writer, &journal_id, head_after.last_sequence)
        .expect("expiry event is retained");
    assert_eq!(expiry_event.event_kind, "dispatch_published");
    assert_eq!(expiry_event.payload.data["operation"], "expire_before_entry");
    assert_eq!(expiry_event.payload.data["dispatch_state"], "rejected");
    assert_eq!(
        expiry_event.payload.data["detail"]["reason"],
        "queue_expired_before_entry"
    );

    let dispatch = dispatch_value(&writer, &receipt.handle).expect("dispatch reads");
    assert_eq!(dispatch.state, DispatchState::Rejected);
    assert_eq!(
        dispatch.reason,
        MaybeString::Text("queue_expired_before_entry".to_string())
    );
    assert!(dispatch.delivery_refs.is_empty());
    assert!(dispatch.acceptance_refs.is_empty());
    assert_eq!(
        local_state(&writer, &receipt.handle).expect("state reads"),
        "expired_before_entry"
    );
    assert!(
        claim_work(&writer, &shift(&receipt.handle.created_at, 1.0))
            .expect("claim runs")
            .is_none(),
        "an expired entry stays undelivered even under an earlier observation"
    );
    let recovered = recover_delivery(&writer, &command)
        .expect("recovery reads")
        .expect("admission is retained");
    assert_eq!(recovered.state, RecoveryState::ExpiredBeforeEntry);

    // Resume never extends a boundary that was reached before native entry.
    let checkpoint = install_bytes(&writer, br#"{"checkpoint":"native-1"}"#, "artifact");
    let contract = install_bytes(&writer, br#"{"resume":"idempotent"}"#, "artifact");
    let mut resume = command.clone();
    resume.request_id = "request-c24-expiry-resume".to_string();
    if let CommandPayload::Start(payload) = &mut resume.payload {
        payload.recovery = MaybeResume::Authorized(ResumeAuthorization {
            handle: receipt.handle.handle.clone(),
            checkpoint,
            native_resume_contract: contract,
            authorization_refs: vec!["recovery:checkpoint-1".to_string()],
            evidence_refs: Vec::new(),
        });
    }
    let error = start(&writer, &resume).expect_err("expired work cannot be resumed");
    assert_eq!(error.code, "STALE_CONTEXT");

    // The queue continues past the expired entry: a fresh long-budget
    // execution is still claimable.
    let later = prepare_discovery(&writer, &manifest, "c24-expiry-later", 600_000.0);
    let later_command = start_command(
        &later.record.configuration.connector_id,
        &later,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        held_lease(
            &writer,
            &manifest,
            &later.record.task.task_id,
            "c24-expiry-later",
            600_000.0,
        ),
        "idem-c24-expiry-later",
        "request-c24-expiry-later",
        vec!["grant-discovery-c24-expiry-later".to_string()],
    );
    let later_receipt = start(&writer, &later_command).expect("later Start admits");
    let claim_now = shift(&later_receipt.handle.created_at, 1.0);
    let claimed = claim_work(&writer, &claim_now)
        .expect("claim runs")
        .expect("later execution is claimable");
    assert_eq!(claimed.handle.local_handle, later_receipt.handle.handle.local_handle);
    assert!(claim_work(&writer, &claim_now).expect("claim runs").is_none());
}

#[test]
fn rm_c24_fenced_lease_before_entry_never_delivers() {
    let writer = principal("rm-delivery-c24-fenced");
    let manifest = test_manifest("rm-delivery-c24-fenced-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c24-fenced", 600_000.0);
    // The lease is valid at admission but expires before the claim.
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c24-fenced",
        60_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease,
        "idem-c24-fenced",
        "request-c24-fenced",
        vec!["grant-discovery-c24-fenced".to_string()],
    );
    let receipt = start(&writer, &command).expect("Start admits under the live lease");
    let after_expiry = shift(&receipt.handle.created_at, 70_000.0);
    assert!(
        claim_work(&writer, &after_expiry).expect("claim runs").is_none(),
        "a stale lease fences the entry instead of delivering"
    );
    let dispatch = dispatch_value(&writer, &receipt.handle).expect("dispatch reads");
    assert_eq!(dispatch.state, DispatchState::Rejected);
    assert_eq!(
        dispatch.reason,
        MaybeString::Text("fenced_before_entry".to_string())
    );
    assert!(dispatch.delivery_refs.is_empty());
    assert!(dispatch.acceptance_refs.is_empty());
    assert_eq!(
        local_state(&writer, &receipt.handle).expect("state reads"),
        "fenced"
    );
    assert!(
        claim_work(&writer, &shift(&receipt.handle.created_at, 1.0))
            .expect("claim runs")
            .is_none(),
        "a fenced entry is never delivered later"
    );
    let recovered = recover_delivery(&writer, &command)
        .expect("recovery reads")
        .expect("admission is retained");
    assert_eq!(recovered.state, RecoveryState::Fenced);
}

#[test]
fn rm_c24_owner_control_progress_survives_workflow_expiry() {
    let writer = principal("rm-delivery-c24-control");
    let manifest = test_manifest("rm-delivery-c24-control-run");
    admit(&writer, &manifest);
    let prepared = prepare_discovery(&writer, &manifest, "c24-control", 1000.0);
    let lease = held_lease(
        &writer,
        &manifest,
        &prepared.record.task.task_id,
        "c24-control",
        600_000.0,
    );
    let command = start_command(
        &prepared.record.configuration.connector_id,
        &prepared,
        &manifest,
        MaybeCommission::Missing(Missing::new("not_applicable")),
        lease,
        "idem-c24-control",
        "request-c24-control",
        vec!["grant-discovery-c24-control".to_string()],
    );
    let receipt = start(&writer, &command).expect("Start admits");
    assert!(
        claim_work(&writer, &shift(&receipt.handle.created_at, 5000.0))
            .expect("claim runs")
            .is_none(),
        "workflow delivery is expired"
    );

    // Owner control admission is not behind the workflow queue: it commits its
    // own evidence even though no workflow delivery will ever happen.
    let cancel = control_command(
        &command.connector_id,
        &manifest,
        &receipt.handle,
        "request-c24-control-cancel",
        "RequestNativeCancel",
    );
    let control_receipt =
        enqueue_owner_control(&writer, &cancel).expect("owner control admits independently");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    let head = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    let event = rm_evidence::read_event(&writer, &journal_id, head.last_sequence)
        .expect("control event is retained");
    assert_eq!(event.event_kind, "control_observation");
    assert_eq!(
        event.payload.data["control_target"],
        receipt.handle.handle.local_handle
    );
    assert_eq!(event.payload.data["request_id"], "request-c24-control-cancel");

    // Identical retry returns the retained receipt without another effect.
    let retained = enqueue_owner_control(&writer, &cancel).expect("retry returns retained receipt");
    assert_eq!(retained, control_receipt);
    let head_after =
        rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    assert_eq!(head_after, head, "a retained control retry adds no effect");

    // Conflicting content under one control command identity is rejected.
    let conflicting = control_command(
        &command.connector_id,
        &manifest,
        &receipt.handle,
        "request-c24-control-cancel",
        "Contain",
    );
    let error =
        enqueue_owner_control(&writer, &conflicting).expect_err("changed control content is rejected");
    assert_eq!(error.code, "IDEMPOTENCY_CONFLICT");

    let taken = take_owner_control(&writer, &receipt.handle)
        .expect("control take runs")
        .expect("the admitted control is takeable");
    assert_eq!(taken.request_id, "request-c24-control-cancel");
    assert_eq!(taken.operation, "RequestNativeCancel");
    assert!(
        take_owner_control(&writer, &receipt.handle)
            .expect("second take runs")
            .is_none(),
        "a control command is taken once"
    );
}
