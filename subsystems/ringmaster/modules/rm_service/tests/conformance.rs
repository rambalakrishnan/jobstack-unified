//! [RM-C54] Manual production recording against the real sibling
//! composition: no fabricated subject/connector, no Ringmaster dependency.
//!
//! Each test name contains `rm_c54` so the verification filter
//! `cargo test -p rm_service -- rm_c54` selects the whole suite.

use rm_authority::{authorize_work, manifest_wire_bytes, Operation, WorkScope};
use rm_catalog::{DescribeRequest, VersionPin};
use rm_evidence::{AccessClass, ArtifactReference, EvidenceRef, Missing, PositiveInteger};
use rm_lifecycle::SlotValue;
use rm_preparation::{
    AssistanceRecord, CatalogMaybeString, CatalogMaybeVersionPin, ConfigurationPin,
    ConnectorRequest, ContextPolicy, DurationLimit, EntryPoint, MaybeArtifact, PermittedOrigin,
    PrepareRequest, StatePolicy, SuccessCriterion, TaskBudgets, TaskEnvelope,
};
use rm_service::*;
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn manifest(run: &str) -> Manifest {
    let mut m = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: vec![
            "manifest_admitted".to_string(),
            "artifact_available".to_string(),
        ],
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = manifest_wire_bytes(&m);
    m.manifest_hash = canonical_digest(&wire).expect("manifest hashes").as_str().to_string();
    m
}

fn channel_for(operator: &str) -> Cursor<Vec<u8>> {
    let registration = json!({
        "principal_id": operator,
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": format!("binding-{operator}"),
        },
    });
    Cursor::new(serde_json::to_vec(&registration).expect("registration serializes"))
}

fn production_commission(operator: &str) -> ManualCommission {
    ManualCommission {
        commission_id: format!("commission-{operator}"),
        attempt_id: format!("attempt-{operator}"),
        operator: operator.to_string(),
        journal_id: format!("journal-{operator}"),
        kind: AttemptKind::Production,
        target_class: TargetClass::Employer,
        target_id: format!("employer-{operator}"),
        notes: vec!["submitted application by hand with disclosed assistance".to_string()],
        assistance: Some("operator used a spellchecker; no automated agent".to_string()),
    }
}

fn practice_commission(operator: &str) -> ManualCommission {
    ManualCommission {
        commission_id: format!("commission-{operator}"),
        attempt_id: format!("attempt-{operator}"),
        operator: operator.to_string(),
        journal_id: format!("journal-{operator}"),
        kind: AttemptKind::Practice,
        target_class: TargetClass::Fixture,
        target_id: format!("fixture-{operator}"),
        notes: vec!["rehearsed the form by hand".to_string()],
        assistance: None,
    }
}

fn slot_reason(slot: &rm_lifecycle::AxisSlot) -> &str {
    match &slot.value {
        SlotValue::Unpublished(missing) => missing.reason.as_str(),
        SlotValue::Published(_) => panic!("manual snapshot must not publish any axis"),
    }
}

// --- Prepare-path fixtures (same proven shape as rm_preparation's suite) ---

fn admission(manifest: &Manifest) -> rm_evidence::EventSubmission {
    let artifact = rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact");
    rm_evidence::EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("positive")),
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

fn admit(writer: &AuthenticatedPrincipal, manifest: &Manifest) {
    rm_evidence::append_event(writer, manifest, admission(manifest)).expect("admission");
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
    rm_evidence::install_artifact(writer, &reference, bytes).expect("install");
    reference
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

fn descriptor_pin(
    writer: &AuthenticatedPrincipal,
    tag: &str,
) -> (rm_catalog::ConnectorDescriptor, ConfigurationPin) {
    let descriptor = rm_service::describe(writer, &DescribeRequest).expect("describe succeeds");
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

fn test_budgets() -> TaskBudgets {
    TaskBudgets {
        active_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
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

fn discovery_task(task_id: &str, entry_url: &str, origin: &str) -> TaskEnvelope {
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
        budgets: test_budgets(),
        context_policy: test_context(),
        output_schema: CatalogMaybeVersionPin::Present(VersionPin {
            id: "output-schema".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(b"output-schema-1"),
        }),
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

fn discovery_scope(manifest: &Manifest, journal_id: &str, tag: &str) -> WorkScope {
    WorkScope {
        activity: "discovery".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id.to_string(),
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

fn prepare_command(
    configuration: &ConfigurationPin,
    scope: WorkScope,
    manifest: Manifest,
    task: TaskEnvelope,
    assistance: AssistanceRecord,
    tag: &str,
) -> ConnectorRequest {
    ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: format!("req-{tag}"),
        connector_id: configuration.connector_id.clone(),
        operation: "Prepare".to_string(),
        call_limit: DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 5000.0,
        },
        payload: PrepareRequest {
            scope,
            manifest,
            commission: None,
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

// ---------------------------------------------------------------------------
// RM-C54 tests
// ---------------------------------------------------------------------------

/// Happy path: a real manual production application records with zero
/// dispatch/execution revisions, manual provenance, an origin reference,
/// and no dispatch-path dependency call.
#[test]
fn rm_c54_manual_production_records_without_dispatch() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-prod");
    let commission = production_commission("operator-prod");
    let recorded = record_manual_production(
        &mut channel_for("operator-prod"),
        &m,
        &commission,
        Some("origin-receipt-employer-1".to_string()),
    )
    .expect("manual production records");

    assert_eq!(recorded.attempt_id, commission.attempt_id);
    assert_eq!(recorded.commission_id, commission.commission_id);
    assert_eq!(recorded.kind, AttemptKind::Production);
    assert_eq!(recorded.operator, "operator-prod");
    assert_eq!(recorded.provenance, MANUAL_PROVENANCE);
    assert_eq!(
        recorded.origin_refs,
        vec!["origin-receipt-employer-1".to_string()]
    );
    assert_eq!(recorded.notes.len(), 1);
    assert_eq!(recorded.notes[0].provenance, MANUAL_PROVENANCE);
    assert_eq!(
        recorded.assistance.as_deref(),
        Some("operator used a spellchecker; no automated agent")
    );

    // The commission binds to the admitted manifest run; the task hash
    // covers the admitted manifest task.
    assert_eq!(recorded.commission.run_id, m.run_id);
    assert_eq!(recorded.commission.manifest_hash, m.manifest_hash);
    assert!(rm_wire::is_valid_digest(
        &recorded.commission.task_semantic_hash
    ));

    // LIFE-MANUAL: dispatch and execution stay at revision zero with
    // not_applicable; nothing is published anywhere.
    assert_eq!(recorded.snapshot.dispatch.revision, 0);
    assert_eq!(recorded.snapshot.execution.revision, 0);
    assert_eq!(slot_reason(&recorded.snapshot.dispatch), "not_applicable");
    assert_eq!(slot_reason(&recorded.snapshot.execution), "not_applicable");
    assert_eq!(recorded.snapshot.observation.revision, 0);
    assert_eq!(recorded.snapshot.application.revision, 0);
    assert_eq!(recorded.snapshot.report.revision, 0);

    // Exactly the three read-side calls; Prepare/Start never invoked.
    assert_eq!(
        dependency_calls(),
        vec![
            "authenticate_channel".to_string(),
            "verify_attempt_scope".to_string(),
            "validate_snapshot".to_string(),
        ]
    );
}

/// Practice manual work records against a fixture target without an
/// origin reference.
#[test]
fn rm_c54_manual_practice_records_without_origin_ref() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-practice");
    let commission = practice_commission("operator-practice");
    let recorded =
        record_manual_production(&mut channel_for("operator-practice"), &m, &commission, None)
            .expect("manual practice records");

    assert_eq!(recorded.kind, AttemptKind::Practice);
    assert_eq!(recorded.target_class, TargetClass::Fixture);
    assert!(recorded.origin_refs.is_empty());
    assert_eq!(recorded.snapshot.dispatch.revision, 0);
    assert_eq!(recorded.snapshot.execution.revision, 0);
    assert_eq!(
        dependency_calls(),
        vec![
            "authenticate_channel".to_string(),
            "verify_attempt_scope".to_string(),
            "validate_snapshot".to_string(),
        ]
    );
}

/// Production without an employer origin reference is not admitted.
/// The failure is a policy ConnectorError, not silent acceptance.
#[test]
fn rm_c54_production_without_origin_ref_not_admitted() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-noorigin");
    let commission = production_commission("operator-noorigin");

    let error = record_manual_production(
        &mut channel_for("operator-noorigin"),
        &m,
        &commission,
        None,
    )
    .expect_err("production without an origin ref must not record");
    assert_eq!(error.kind, "connector_error");
    assert_eq!(error.code, "NOT_ADMITTED");
    assert_eq!(error.fault_domain, "policy");
    assert_eq!(error.operation_delivery, "not_applicable");
    assert_eq!(error.retry_guidance, "operator_review");

    // An empty reference is the same as none.
    let error = record_manual_production(
        &mut channel_for("operator-noorigin"),
        &m,
        &commission,
        Some(String::new()),
    )
    .expect_err("empty origin ref must not record");
    assert_eq!(error.code, "NOT_ADMITTED");
}

/// Practice/held_in versus production/held_out coherence is enforced by
/// the real scope check: mismatched kind/target pairs are not admitted.
#[test]
fn rm_c54_kind_target_incoherence_not_admitted() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-incoherent");

    let mut mismatched = production_commission("operator-incoherent");
    mismatched.kind = AttemptKind::Practice;
    mismatched.target_class = TargetClass::Employer;
    let error = record_manual_production(
        &mut channel_for("operator-incoherent"),
        &m,
        &mismatched,
        Some("origin-receipt-1".to_string()),
    )
    .expect_err("practice/employer mismatch must not record");
    assert_eq!(error.code, "NOT_ADMITTED");
    assert!(error.detail.contains("incoherence"), "detail: {}", error.detail);

    let mut mismatched = practice_commission("operator-incoherent");
    mismatched.kind = AttemptKind::Production;
    mismatched.target_class = TargetClass::Fixture;
    let error = record_manual_production(
        &mut channel_for("operator-incoherent"),
        &m,
        &mismatched,
        Some("origin-receipt-1".to_string()),
    )
    .expect_err("production/fixture mismatch must not record");
    assert_eq!(error.code, "NOT_ADMITTED");
}

/// The authenticated principal must be the commissioning operator;
/// another principal's handle is never usable (no cross-principal leak).
/// The failure happens before any scope or snapshot work.
#[test]
fn rm_c54_operator_mismatch_forbidden() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-mismatch");
    let commission = production_commission("operator-a");
    let error = record_manual_production(
        &mut channel_for("operator-b"),
        &m,
        &commission,
        Some("origin-receipt-1".to_string()),
    )
    .expect_err("cross-principal recording must be forbidden");
    assert_eq!(error.code, "FORBIDDEN");
    assert_eq!(error.fault_domain, "policy");
    assert!(
        error.detail.contains("operator mismatch"),
        "detail: {}",
        error.detail
    );
    assert_eq!(dependency_calls(), vec!["authenticate_channel".to_string()]);
}

/// No automation subject, native run ID, connector version, or execution
/// publication is fabricated: the recorded attempt carries only manual
/// provenance and zero revisions, and its debug form names no
/// subject/connector/native-run field.
#[test]
fn rm_c54_no_subject_or_connector_fabricated() {
    clear_dependency_calls();
    let m = manifest("rm-svc-run-c54-nofab");
    let commission = production_commission("operator-nofab");
    let recorded = record_manual_production(
        &mut channel_for("operator-nofab"),
        &m,
        &commission,
        Some("origin-receipt-1".to_string()),
    )
    .expect("manual production records");

    for slot in [
        &recorded.snapshot.dispatch,
        &recorded.snapshot.observation,
        &recorded.snapshot.execution,
        &recorded.snapshot.application,
        &recorded.snapshot.report,
    ] {
        assert_eq!(slot.revision, 0);
        assert!(
            matches!(slot.value, SlotValue::Unpublished(_)),
            "no execution publication may exist"
        );
    }
    // The run binding is the admitted manifest run, not an invented native run.
    assert_eq!(recorded.commission.run_id, m.run_id);

    let debug = format!("{:?}", recorded);
    assert!(
        debug.contains(MANUAL_PROVENANCE),
        "manual provenance must be visible"
    );
    // Field-shaped patterns: a fabricated automation handle would appear as
    // a `name:` field in the debug form. (The word "subject" legitimately
    // appears inside the "no automation subject" missingness detail.)
    for fabricated in [
        "subject:",
        "subject_id",
        "connector_version",
        "native_run",
        "native_binding",
        "preparation_id",
    ] {
        assert!(
            !debug.contains(fabricated),
            "recorded attempt must not name {fabricated:?}: {debug}"
        );
    }
}

/// Manual commissions are not dispatchable: full-path Prepare rejects a
/// manual command through the real shared authority gate, and the same
/// gate rejects the Start verb for manual scopes. Start additionally
/// requires a verified preparation first (rm_delivery checks the
/// preparation before authorizing), which manual commissions can never
/// obtain because Prepare refuses them — so Start is unreachable for
/// manual work by construction, with the gate as belt-and-suspenders.
#[test]
fn rm_c54_prepare_start_reject_manual_mode() {
    let tag = "c54-manual";
    let mut channel = channel_for(&format!("rm-svc-{tag}"));
    let writer = rm_service::authenticate_channel(&mut channel).expect("writer authenticates");
    let run = format!("rm-svc-run-{tag}");
    let m = manifest(&run);
    admit(&writer, &m);
    let journal_id = rm_evidence::journal_id_for(&m).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);

    let task = discovery_task(
        &format!("task-{tag}"),
        "https://trap.invalid/job-1",
        "https://trap.invalid",
    );
    let mut scope = discovery_scope(&m, &journal_id, tag);
    scope.execution_mode = ExecutionMode::Manual;
    let command = prepare_command(
        &configuration,
        scope,
        m.clone(),
        task,
        discovery_assistance(),
        tag,
    );

    clear_dependency_calls();
    let error =
        rm_service::prepare(&writer, &command).expect_err("manual Prepare must be rejected");
    assert_eq!(error.code, "NOT_ADMITTED");
    assert_eq!(error.fault_domain, "policy");
    assert!(
        error.detail.contains("not dispatchable"),
        "detail: {}",
        error.detail
    );
    assert_eq!(dependency_calls(), vec!["prepare".to_string()]);

    // The identical shared gate also refuses the Start verb for manual
    // scopes (this is the check rm_delivery::start invokes).
    let mut manual = discovery_scope(&m, &journal_id, tag);
    manual.execution_mode = ExecutionMode::Manual;
    for verb in ["Prepare", "Start"] {
        let operation = Operation {
            verb: verb.to_string(),
            connector_id: "connector-1".to_string(),
            subject_id: "subject-1".to_string(),
            task_scope: format!("discovery:task-{tag}"),
            account_binding: None,
            artifact_refs: Vec::new(),
            control_target: None,
        };
        let error = authorize_work(&writer, &manual, &operation)
            .expect_err(&format!("manual {verb} must be refused at the gate"));
        assert_eq!(error.code, "NOT_ADMITTED");
        assert!(
            error.detail.contains("not dispatchable"),
            "detail: {}",
            error.detail
        );
    }
}

/// Manual path requires no Ringmaster startup, browser, Hellscape, or
/// portfolio integration: recording succeeds with only the manifest,
/// the commission, and the operator channel — the manifest here is
/// never admitted to any journal.
#[test]
fn rm_c54_no_ringmaster_startup_required() {
    clear_dependency_calls();
    // Deliberately never admitted: no journal, no artifacts, no browser.
    let m = manifest("rm-svc-run-c54-standalone");
    let commission = production_commission("operator-standalone");
    let recorded = record_manual_production(
        &mut channel_for("operator-standalone"),
        &m,
        &commission,
        Some("origin-receipt-standalone".to_string()),
    )
    .expect("recording needs no Ringmaster startup");
    assert_eq!(recorded.provenance, MANUAL_PROVENANCE);
    assert_eq!(recorded.snapshot.dispatch.revision, 0);
    assert_eq!(recorded.snapshot.execution.revision, 0);
    assert_eq!(
        dependency_calls(),
        vec![
            "authenticate_channel".to_string(),
            "verify_attempt_scope".to_string(),
            "validate_snapshot".to_string(),
        ]
    );
}

/// Exactly nine verbs are recognized; a tenth verb is rejected by the
/// real authority gate and no shared browser primitive endpoint exists
/// on this surface.
#[test]
fn rm_c54_exactly_nine_verbs_no_browser_primitive() {
    assert_eq!(
        NINE_OPERATIONS,
        [
            "Describe",
            "Prepare",
            "Start",
            "Observe",
            "RequestNativeCancel",
            "CloseObservationConnection",
            "CollectArtifacts",
            "ReleaseNativeContext",
            "Contain",
        ]
    );
    assert!(!NINE_OPERATIONS.contains(&"DeleteEverything"));
    for verb in NINE_OPERATIONS {
        for primitive in ["Page", "ElementHandle", "selector", "DOM", "node"] {
            assert!(
                !verb.contains(primitive),
                "verb {verb:?} must not be a browser primitive"
            );
        }
    }

    // Behavioral: the real gate refuses a tenth verb.
    let mut channel = channel_for("operator-verbs");
    let principal =
        rm_service::authenticate_channel(&mut channel).expect("principal authenticates");
    let m = manifest("rm-svc-run-c54-verbs");
    let scope = discovery_scope(&m, "journal-verbs", "c54-verbs");
    let operation = Operation {
        verb: "DeleteEverything".to_string(),
        connector_id: "connector-1".to_string(),
        subject_id: "subject-1".to_string(),
        task_scope: "discovery:task-1".to_string(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    };
    let error = authorize_work(&principal, &scope, &operation)
        .expect_err("a tenth verb must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("nine versioned verbs"),
        "detail: {}",
        error.detail
    );
}
