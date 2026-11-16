//! Conformance tests for RM-C20 (non-executing Prepare trap) and RM-C21
//! (stale/conflicting preparation rejection).
//!
//! Every test name carries `rm_c20` or `rm_c21` so the verification filter
//! `cargo test -p rm_preparation -- rm_c20 rm_c21` selects the suite.

use rm_authority::{
    authenticate_channel, AttemptCommission, AttemptKind, EvaluationPartition, ExecutionMode,
    Manifest, TargetClass, WorkScope,
};
use rm_catalog::{DescribeRequest, VersionPin};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, JournalPrefix, Missing, PositiveInteger,
};
use rm_preparation::{
    AssistanceRecord, BudgetMapping, ConfigurationPin, ConnectorRequest, ContextPolicy,
    EntryPoint, MaybeArtifact, PermittedOrigin, PreparationMeasurement, PreparationReference,
    PrepareRequest, RuntimeAccess, StatePolicy, SuccessCriterion, TaskBudgets, TaskEnvelope,
};
use rm_preparation::{CatalogMaybeString, CatalogMaybeVersionPin, DurationLimit};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn principal(id: &str) -> rm_authority::AuthenticatedPrincipal {
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
    let wire = rm_authority::manifest_wire_bytes(&m);
    m.manifest_hash = canonical_digest(&wire).expect("manifest hashes").as_str().to_string();
    m
}

fn admission(manifest: &Manifest) -> rm_evidence::EventSubmission {
    let artifact =
        rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact");
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

fn admit(
    writer: &rm_authority::AuthenticatedPrincipal,
    manifest: &Manifest,
) -> rm_evidence::JournalEnvelope {
    rm_evidence::append_event(writer, manifest, admission(manifest)).expect("admission")
}

fn install_bytes(
    writer: &rm_authority::AuthenticatedPrincipal,
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
    writer: &rm_authority::AuthenticatedPrincipal,
    tag: &str,
) -> (rm_catalog::ConnectorDescriptor, ConfigurationPin) {
    let descriptor =
        rm_catalog::describe(writer, &DescribeRequest).expect("describe succeeds");
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

fn apply_task(task_id: &str, entry_url: &str, origin: &str) -> TaskEnvelope {
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
        budgets: test_budgets(),
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

fn production_commission(manifest: &Manifest, task: &TaskEnvelope, tag: &str) -> AttemptCommission {
    AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        commission_id: format!("commission-{tag}"),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal id"),
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

fn apply_scope(manifest: &Manifest, commission: &AttemptCommission, tag: &str) -> WorkScope {
    WorkScope {
        activity: "apply".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: rm_evidence::journal_id_for(manifest).expect("journal id"),
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

fn connector_request(
    configuration: &ConfigurationPin,
    scope: WorkScope,
    manifest: Manifest,
    commission: Option<AttemptCommission>,
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

// ---------------------------------------------------------------------------
// RM-C20: Describe/Prepare target-network trap
// ---------------------------------------------------------------------------

#[test]
fn rm_c20_prepare_is_non_executing_trap() {
    let tag = "c20-trap";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);

    // Trap target: unroutable host that must never be visited, probed, or
    // used to test authentication. Prepare validates the supplied bytes only.
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://trap.invalid/job-1",
        "https://trap.invalid",
    );
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let mut command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task.clone(),
        discovery_assistance(),
        tag,
    );
    // Opaque runtime binding: never materialized, never login-tested.
    command.payload.runtime_access = vec![RuntimeAccess {
        purpose: "application_entry".to_string(),
        access_ref: "opaque-binding-trap-1".to_string(),
        authorization_refs: Vec::new(),
    }];

    let result = rm_preparation::prepare(&writer, &command).expect("trap prepares");
    assert_eq!(result.kind, "prepared");
    assert_eq!(result.preparation.preparation_id, result.record.preparation_id);

    // Delivered task preserves the trap URL exactly without fetching content.
    let delivered_bytes =
        rm_evidence::load_artifact(&writer, &result.record.delivered_task).expect("delivered loads");
    let delivered_value: Value =
        serde_json::from_slice(&delivered_bytes).expect("delivered is JSON");
    let delivered_task = delivered_value.get("task").expect("delivered carries task");
    assert_eq!(
        delivered_task.get("entry").and_then(|e| e.get("url")).and_then(Value::as_str),
        Some("https://trap.invalid/job-1"),
        "delivered entry preserves the trap URL without visiting it"
    );
    // No fetched enrichment: the serialization adds no page-derived fields.
    let delivered_text = String::from_utf8(delivered_bytes.clone()).expect("utf8");
    assert!(
        !delivered_text.contains("fetched_title")
            && !delivered_text.contains("page_content")
            && !delivered_text.contains("healed_selector"),
        "delivered bytes must not carry secretly fetched or healed content: {delivered_text}"
    );

    // Native request preserves intent without credentials.
    let native_bytes =
        rm_evidence::load_artifact(&writer, &result.record.native_request).expect("native loads");
    let native_value: Value = serde_json::from_slice(&native_bytes).expect("native is JSON");
    assert_eq!(
        native_value.get("entry").and_then(|e| e.get("url")).and_then(Value::as_str),
        Some("https://trap.invalid/job-1")
    );
    let native_text = String::from_utf8(native_bytes).expect("utf8");
    assert!(
        !native_text.contains("secret") && !native_text.contains("password"),
        "native bytes must exclude runtime credentials"
    );
    // Opaque runtime refs survive without materialization.
    assert_eq!(
        result.record.runtime_access.len(),
        1,
        "runtime access bindings are recorded opaquely"
    );
    assert_eq!(result.record.runtime_access[0].access_ref, "opaque-binding-trap-1");

    // The preparation verifies against its retained bytes.
    let verified = rm_preparation::verify_preparation(&writer, &result.preparation)
        .expect("trap preparation verifies");
    assert_eq!(verified.preparation_id, result.preparation.preparation_id);
}

#[test]
fn rm_c20_no_hidden_planning_or_auth_probe() {
    let tag = "c20-hidden";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/extract",
        "https://example.invalid",
    );

    // Hidden planning: a supplied plan without prior evidence is rejected.
    let plan_bytes = b"{\"steps\":[]}";
    let plan_ref = install_bytes(&writer, plan_bytes, "artifact");
    let mut hidden = discovery_assistance();
    hidden.plan = MaybeArtifact::Present(plan_ref.clone());
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task.clone(),
        hidden,
        &format!("{tag}-1"),
    );
    let error = rm_preparation::prepare(&writer, &command).expect_err("hidden planning rejects");
    assert!(
        error.detail.contains("planning evidence") || error.detail.contains("hidden"),
        "unexpected detail: {}",
        error.detail
    );

    // Auth probe: a URI-shaped access_ref is not an opaque binding.
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let mut command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task.clone(),
        discovery_assistance(),
        &format!("{tag}-2"),
    );
    command.payload.runtime_access = vec![RuntimeAccess {
        purpose: "account_session".to_string(),
        access_ref: "https://example.invalid/login?token=secret".to_string(),
        authorization_refs: Vec::new(),
    }];
    let error = rm_preparation::prepare(&writer, &command).expect_err("auth probe rejects");
    assert!(
        error.detail.contains("opaque") || error.detail.contains("secret"),
        "unexpected detail: {}",
        error.detail
    );

    // Declared prior planning with evidence and disclosed cost succeeds.
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let mut command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task.clone(),
        discovery_assistance(),
        &format!("{tag}-3"),
    );
    let mut declared = discovery_assistance();
    declared.plan = MaybeArtifact::Present(plan_ref);
    command.payload.assistance = declared;
    command.payload.planning_evidence_refs = vec![synthetic_ref(&format!("{tag}-plan"))];
    command.payload.preparation_measurements = vec![PreparationMeasurement {
        cost_id: "planning-cost-1".to_string(),
        evidence: synthetic_ref(&format!("{tag}-cost")),
        detail: "prior external planning cost".to_string(),
    }];
    rm_preparation::prepare(&writer, &command).expect("declared planning prepares");
}

#[test]
fn rm_c20_translation_preserves_intent() {
    let tag = "c20-intent";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);

    // Application path: the commission pins the exact semantic task.
    let mut task = apply_task(
        &format!("task-{tag}"),
        "https://employer.example/jobs/1",
        "https://employer.example",
    );
    task.goal = "apply as candidate-7 to job-1 without changing values".to_string();
    task.success_criteria = vec![
        SuccessCriterion {
            criterion_id: "criterion-first".to_string(),
            description: "first objective".to_string(),
        },
        SuccessCriterion {
            criterion_id: "criterion-second".to_string(),
            description: "second objective".to_string(),
        },
    ];
    let commission = production_commission(&manifest, &task, tag);
    let scope = apply_scope(&manifest, &commission, tag);
    let command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        Some(commission),
        task.clone(),
        apply_assistance(),
        tag,
    );

    let result = rm_preparation::prepare(&writer, &command).expect("apply prepares");
    // Translation is the pinned advertised mapping, not a guessed native.
    assert_eq!(result.record.translation.id, "apply-mapping");

    // Delivered bytes equal the commissioned task exactly, in order.
    let delivered_bytes =
        rm_evidence::load_artifact(&writer, &result.record.delivered_task).expect("delivered loads");
    let delivered_value: Value =
        serde_json::from_slice(&delivered_bytes).expect("delivered JSON");
    let delivered_task = TaskEnvelope::from_json(
        delivered_value.get("task").expect("delivered carries task"),
    )
    .expect("delivered task parses");
    assert_eq!(delivered_task.to_json(), task.to_json(), "translation preserves full intent");
    assert_eq!(
        delivered_task.success_criteria.iter().map(|c| c.criterion_id.clone()).collect::<Vec<_>>(),
        vec!["criterion-first".to_string(), "criterion-second".to_string()],
        "criterion order is preserved"
    );

    // Native bytes carry the same destinations without hidden additions.
    let native_bytes =
        rm_evidence::load_artifact(&writer, &result.record.native_request).expect("native loads");
    let native_value: Value = serde_json::from_slice(&native_bytes).expect("native JSON");
    let native_object = native_value.as_object().expect("native is object");
    let allowed_native_keys = [
        "record_type",
        "schema_version",
        "translation",
        "task_digest",
        "task_type",
        "entry",
        "goal",
        "effect_policy",
        "budgets",
        "context_policy",
        "permitted_interfaces",
        "planning_owner",
        "online_replanning",
        "runtime_access",
    ];
    for key in native_object.keys() {
        assert!(
            allowed_native_keys.contains(&key.as_str()),
            "native request carries undeclared field {key:?}: hidden improvement is forbidden"
        );
    }
    assert_eq!(
        native_object.get("goal").and_then(Value::as_str),
        Some(task.goal.as_str())
    );
    assert_eq!(
        native_object.get("task_digest").and_then(Value::as_str),
        Some(result.record.delivered_task_hash.as_str())
    );
}

#[test]
fn rm_c20_invalid_native_binding_rejected() {
    let tag = "c20-binding";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/extract",
        "https://example.invalid",
    );
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let mut command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task,
        discovery_assistance(),
        tag,
    );
    // Structurally invalid binding: wrong discriminator, no primitives.
    let descriptor_value = rm_catalog::describe(&writer, &DescribeRequest)
        .expect("describe")
        .capabilities;
    command.payload.native_binding = Some(rm_catalog::BOBindingDescriptor {
        record_type: "wrong_record".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        binding_id: "binding-1".to_string(),
        binding_build: VersionPin {
            id: "build".to_string(),
            version: "1".to_string(),
            artifact_digest: artifact_digest(b"build"),
        },
        engine: rm_catalog::ComponentIdentity {
            component: "engine".to_string(),
            reported_version: CatalogMaybeString::Text("1".to_string()),
            build_digest: rm_catalog::MaybeDigest::Present(artifact_digest(b"build")),
            configuration_digest: rm_catalog::MaybeDigest::Present(artifact_digest(b"config")),
        },
        capabilities: descriptor_value,
        primitive_mappings: Vec::new(),
        session_storage_model: "unknown".to_string(),
        session_isolation_refs: Vec::new(),
        privacy_policy: VersionPin {
            id: "privacy".to_string(),
            version: "1".to_string(),
            artifact_digest: artifact_digest(b"privacy"),
        },
        evidence_prefix: JournalPrefix {
            journal_id: "journal-synthetic-binding".to_string(),
            last_sequence: PositiveInteger::new(1).expect("positive"),
            head_hash: artifact_digest(b"head"),
        },
    });
    let error = rm_preparation::prepare(&writer, &command).expect_err("invalid binding rejects");
    assert!(
        error.detail.contains("record_type") || error.detail.contains("primitive"),
        "unexpected detail: {}",
        error.detail
    );
}

// ---------------------------------------------------------------------------
// RM-C21: Changed preparation or task destination
// ---------------------------------------------------------------------------

#[test]
fn rm_c21_stale_preparation_id_rejected() {
    let tag = "c21-stale-id";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/a",
        "https://example.invalid",
    );
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let command =
        connector_request(&configuration, scope, manifest, None, task, discovery_assistance(), tag);
    let result = rm_preparation::prepare(&writer, &command).expect("prepares");

    // Same bytes, wrong identity: never silently reprepared.
    let tampered = PreparationReference {
        preparation_id: "prep-wrong-identity".to_string(),
        artifact: result.preparation.artifact.clone(),
        registration_ref: result.preparation.registration_ref.clone(),
    };
    let error =
        rm_preparation::verify_preparation(&writer, &tampered).expect_err("stale id rejects");
    assert_eq!(error.code, "STALE_PREPARATION", "unexpected: {error:?}");
}

#[test]
fn rm_c21_changed_destination_rejected_despite_equal_semantic_hash() {
    let tag = "c21-dest";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);

    let task_a = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/job-1",
        "https://example.invalid",
    );
    // Same logical IDs, different actual destinations: equal semantic hash.
    let mut task_b = task_a.clone();
    task_b.task_id = format!("task-{tag}-b");
    task_b.entry.url = "https://evil.invalid/job-1".to_string();
    task_b.permitted_origins[0].origin = "https://evil.invalid".to_string();
    assert_eq!(
        semantic_hash_of(&task_a),
        semantic_hash_of(&task_b),
        "fixture must share a semantic hash while destinations differ"
    );

    let scope = discovery_scope(&manifest, &journal_id, tag);
    let command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        None,
        task_a.clone(),
        discovery_assistance(),
        tag,
    );
    let result = rm_preparation::prepare(&writer, &command).expect("prepares");

    // A second preparation over the changed destinations is a new identity,
    // never the same receipt.
    let scope_b = discovery_scope(&manifest, &journal_id, &format!("{tag}-b"));
    let command_b = connector_request(
        &configuration,
        scope_b,
        manifest.clone(),
        None,
        task_b.clone(),
        discovery_assistance(),
        &format!("{tag}-b"),
    );
    let result_b = rm_preparation::prepare(&writer, &command_b).expect("second prepares");
    assert_ne!(
        result.preparation.preparation_id, result_b.preparation.preparation_id,
        "changed destinations create a new preparation"
    );
    assert_ne!(
        result.record.delivered_task_hash, result_b.record.delivered_task_hash,
        "delivered bytes differ when destinations differ"
    );

    // Tamper: rewrite the retained preparation task destinations while keeping
    // the semantic hash (equal by construction). Verification must still
    // reject the changed actual destinations.
    let bytes = rm_evidence::load_artifact(&writer, &result.preparation.artifact).expect("loads");
    let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
    let task_json = value.get_mut("task").expect("has task");
    task_json
        .get_mut("entry")
        .expect("has entry")
        .as_object_mut()
        .expect("entry object")
        .insert("url".to_string(), Value::String("https://evil.invalid/job-1".to_string()));
    task_json
        .get_mut("permitted_origins")
        .expect("has origins")
        .as_array_mut()
        .expect("origins array")[0]
        .as_object_mut()
        .expect("origin object")
        .insert("origin".to_string(), Value::String("https://evil.invalid".to_string()));
    let tampered_bytes = serde_json::to_vec(&value).expect("serializes");
    let tampered_ref = install_bytes(&writer, &tampered_bytes, "artifact");
    let tampered = PreparationReference {
        preparation_id: result.preparation.preparation_id.clone(),
        artifact: tampered_ref,
        registration_ref: result.preparation.registration_ref.clone(),
    };
    let error =
        rm_preparation::verify_preparation(&writer, &tampered).expect_err("changed dest rejects");
    assert_eq!(error.code, "STALE_PREPARATION", "unexpected: {error:?}");
    assert!(
        error.detail.contains("destinations") || error.detail.contains("semantic"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c21_tampered_registration_rejected() {
    let tag = "c21-reg";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/a",
        "https://example.invalid",
    );
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let command =
        connector_request(&configuration, scope, manifest, None, task, discovery_assistance(), tag);
    let result = rm_preparation::prepare(&writer, &command).expect("prepares");

    // Registration pointing at the admission event (wrong kind, no citation).
    let admission_envelope = rm_evidence::read_event(
        &writer,
        &journal_id,
        PositiveInteger::new(1).expect("positive"),
    )
    .expect("admission reads");
    let wrong_kind = PreparationReference {
        preparation_id: result.preparation.preparation_id.clone(),
        artifact: result.preparation.artifact.clone(),
        registration_ref: EvidenceRef {
            journal_id: admission_envelope.journal_id.clone(),
            sequence: admission_envelope.journal_sequence,
            event_id: admission_envelope.event_id.clone(),
            event_hash: admission_envelope.event_hash.clone(),
            pointer: String::new(),
        },
    };
    let error = rm_preparation::verify_preparation(&writer, &wrong_kind)
        .expect_err("wrong-kind registration rejects");
    assert!(
        error.code == "STALE_PREPARATION"
            || error.code == "INTEGRITY_CONFLICT"
            || error.code == "INTEGRITY_INCIDENT",
        "unexpected: {error:?}"
    );

    // Registration with a mismatched event hash.
    let mut tampered_ref = result.preparation.registration_ref.clone();
    tampered_ref.event_hash = artifact_digest(b"tampered-event-hash");
    let tampered = PreparationReference {
        preparation_id: result.preparation.preparation_id.clone(),
        artifact: result.preparation.artifact.clone(),
        registration_ref: tampered_ref,
    };
    let error = rm_preparation::verify_preparation(&writer, &tampered)
        .expect_err("hash-mismatched registration rejects");
    assert!(
        error.code == "STALE_PREPARATION"
            || error.code == "INTEGRITY_CONFLICT"
            || error.code == "INTEGRITY_INCIDENT"
            || error.code == "INVALID_REQUEST",
        "unexpected: {error:?}"
    );
}

#[test]
fn rm_c21_stale_configuration_rejected() {
    let tag = "c21-config";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal id");
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);
    let task = discovery_task(
        &format!("task-{tag}"),
        "https://example.invalid/a",
        "https://example.invalid",
    );
    let scope = discovery_scope(&manifest, &journal_id, tag);
    let command =
        connector_request(&configuration, scope, manifest, None, task, discovery_assistance(), tag);
    let result = rm_preparation::prepare(&writer, &command).expect("prepares");

    // Rewrite the pinned subject version inside the retained bytes. The bytes
    // still parse, but the configuration is stale against the descriptor.
    let bytes = rm_evidence::load_artifact(&writer, &result.preparation.artifact).expect("loads");
    let mut value: Value = serde_json::from_slice(&bytes).expect("JSON");
    value
        .get_mut("configuration")
        .expect("has configuration")
        .get_mut("subject")
        .expect("has subject")
        .as_object_mut()
        .expect("subject object")
        .insert(
            "subject_version".to_string(),
            Value::String("ringmaster-9.9.9".to_string()),
        );
    let tampered_bytes = serde_json::to_vec(&value).expect("serializes");
    let tampered_ref = install_bytes(&writer, &tampered_bytes, "artifact");
    let tampered = PreparationReference {
        preparation_id: result.preparation.preparation_id.clone(),
        artifact: tampered_ref,
        registration_ref: result.preparation.registration_ref.clone(),
    };
    let error =
        rm_preparation::verify_preparation(&writer, &tampered).expect_err("stale config rejects");
    assert_eq!(error.code, "STALE_PREPARATION", "unexpected: {error:?}");
    assert!(
        error.detail.contains("configuration") || error.detail.contains("descriptor"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c21_commission_mismatch_rejected() {
    let tag = "c21-commission";
    let writer = principal(&format!("rm-prep-{tag}"));
    let run = format!("rm-prep-run-{tag}");
    let manifest = test_manifest(&run);
    admit(&writer, &manifest);
    let (_descriptor, configuration) = descriptor_pin(&writer, tag);

    // Commission pins task A, but Prepare carries task B (changed goal).
    let task_a = apply_task(
        &format!("task-{tag}"),
        "https://employer.example/jobs/1",
        "https://employer.example",
    );
    let mut task_b = task_a.clone();
    task_b.task_id = format!("task-{tag}-b");
    task_b.goal = "changed goal after commissioning".to_string();
    let commission = production_commission(&manifest, &task_a, tag);
    let scope = apply_scope(&manifest, &commission, tag);
    let command = connector_request(
        &configuration,
        scope,
        manifest.clone(),
        Some(commission),
        task_b,
        apply_assistance(),
        tag,
    );
    let error = rm_preparation::prepare(&writer, &command).expect_err("commission mismatch rejects");
    assert_eq!(error.code, "NOT_ADMITTED", "unexpected: {error:?}");

    // Manual commissions are not dispatchable through Prepare.
    let task = apply_task(
        &format!("task-{tag}-manual"),
        "https://employer.example/jobs/2",
        "https://employer.example",
    );
    let commission = production_commission(&manifest, &task, &format!("{tag}-manual"));
    let mut scope = apply_scope(&manifest, &commission, &format!("{tag}-manual"));
    scope.execution_mode = ExecutionMode::Manual;
    let command = connector_request(
        &configuration,
        scope,
        manifest,
        Some(commission),
        task,
        apply_assistance(),
        &format!("{tag}-manual"),
    );
    let error = rm_preparation::prepare(&writer, &command).expect_err("manual rejects");
    assert_eq!(error.code, "NOT_ADMITTED", "unexpected: {error:?}");

    // Budget mapping shape is enforced: exactly five dimensions.
    let bad = vec![BudgetMapping {
        dimension: "active_observation".to_string(),
        enforcer: "connector".to_string(),
        evidence_refs: Vec::new(),
        limitations: Vec::new(),
    }];
    assert_eq!(bad.len(), 1, "fixture carries one dimension, not five");
}
