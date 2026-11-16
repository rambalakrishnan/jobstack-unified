//! Conformance for RM-C35 (Tier 1 no match versus possible action effect).
//!
//! Every test name carries `rm_c35` so the verification filter
//! `cargo test -p rm_execution -- rm_c35` selects the suite.
//!
//! - `rm_c35_tier1_no_match_routes_toward_recovery`: a Tier 1 `TARGET_NOT_FOUND`
//!   before any mutation is effect-safe and routes toward recovery; with a
//!   zero recovery budget the execution fails with `FORBIDDEN` (budget), never
//!   `RECONCILIATION_REQUIRED`, and no mutation is journaled.
//! - `rm_c35_possible_effect_requires_reconciliation`: a compound `fill` whose
//!   `dom_write` succeeded and whose subsequent synthetic dispatch cannot
//!   enter (unmapped primitive) preserves the prior effect and fails with
//!   `RECONCILIATION_REQUIRED`; the whole action is never replayed.
//! - `rm_c35_successful_apply_workflow`: an apply workflow with navigate,
//!   fill, click, wait, assert, upload, extract (application-local), and
//!   checkpoint succeeds end to end, journals explicit synthetic events
//!   without trusted-input claims, and retains a §7.4 checkpoint.
//! - `rm_c35_extract_workflow_uses_deterministic_extraction`: an extract
//!   workflow calls the deterministic extraction contract and succeeds.
//! - `rm_c35_preflight_destination_must_be_permitted`: preflight after Start
//!   rejects an unpermitted destination.
//!
//! All tests run against real admitted journals, real leases, real native
//! sessions, and real Tier 1 resolution. No mocks, no invented primitives.

use rm_authority::{
    authenticate_channel, manifest_wire_bytes, AttemptKind, AuthenticatedPrincipal, ExecutionMode,
    Manifest, WorkScope,
};
use rm_catalog::{
    VersionPin as CatalogPin, MaybeString as CatalogMaybeString,
    MaybeVersionPin as CatalogMaybePin,
};
use rm_delivery::{ConnectorHandle as DeliveryHandle, HandleReference};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidencePayload, EvidenceRef, EventSubmission, JournalPrefix,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_preparation::{
    AssistanceRecord, ConfigurationPin, ContextPolicy as PrepContext, EntryPoint, PermittedOrigin,
    PreparationReference, PreparedTask, StatePolicy as PrepState, SuccessCriterion, TaskBudgets,
    TaskEnvelope, TaskInput,
};
use rm_time::{
    MaybeString as TimeMaybeString, MaybeTimePoint, MeasurementOrigin, Missing, TimePoint,
    UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures: principals, manifests, journals
// ---------------------------------------------------------------------------

fn principal(id: &str) -> AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": id,
        "channel_binding": {"mechanism": "test-harness", "binding": format!("binding-{id}")},
    });
    let bytes = serde_json::to_vec(&registration).expect("registration");
    authenticate_channel(&mut Cursor::new(bytes)).expect("principal")
}

fn test_pin(id: &str, version: &str) -> CatalogPin {
    CatalogPin {
        id: id.to_string(),
        version: version.to_string(),
        artifact_digest: artifact_digest(format!("{id}-{version}").as_bytes()),
    }
}

fn execution_manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: vec![
            "manifest_admitted".to_string(),
            "execution_claim".to_string(),
            "native_report".to_string(),
            "task_output".to_string(),
            "artifact_available".to_string(),
        ],
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire).expect("hash").as_str().to_string();
    manifest
}

fn binding_manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: vec![
            "manifest_admitted".to_string(),
            "artifact_available".to_string(),
            "execution_claim".to_string(),
        ],
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire).expect("hash").as_str().to_string();
    manifest
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact = rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact");
    EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("pos")),
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

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner: &str,
    media: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media.to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(writer, &reference, bytes).expect("install");
    reference
}

fn journal_fixture(test: &str) -> (AuthenticatedPrincipal, JournalPrefix, EvidenceRef) {
    let writer = principal(&format!("rm-exec-bind-{test}"));
    let run = format!("rm-exec-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-exec-evidence-{test}").into_bytes();
    let reference = ArtifactReference {
        digest: artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: "evidence".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(&writer, &reference, &bytes).expect("install");
    rm_evidence::append_event(&writer, &manifest, admission(&manifest)).expect("admit");
    let artifact_event = rm_evidence::append_event(
        &writer,
        &manifest,
        EventSubmission {
            producer_sequence: Some(PositiveInteger::new(2).expect("pos")),
            event_kind: "artifact_available".to_string(),
            event_schema_version: "evidence-kernel/0.1.0".to_string(),
            occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
            payload: EvidencePayload {
                data: json!({}),
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs: vec![reference],
            },
        },
    )
    .expect("artifact event");
    rm_evidence::append_event(
        &writer,
        &manifest,
        EventSubmission {
            producer_sequence: Some(PositiveInteger::new(3).expect("pos")),
            event_kind: "execution_claim".to_string(),
            event_schema_version: "evidence-kernel/0.1.0".to_string(),
            occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
            payload: EvidencePayload {
                data: json!({}),
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs: Vec::new(),
            },
        },
    )
    .expect("claim");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&writer, &journal_id).expect("head");
    let evidence = EvidenceRef {
        journal_id: artifact_event.journal_id.clone(),
        sequence: artifact_event.journal_sequence,
        event_id: artifact_event.event_id.clone(),
        event_hash: artifact_event.event_hash.clone(),
        pointer: String::new(),
    };
    (writer, prefix, evidence)
}

fn held_lease(
    run: &str,
    entity: &str,
    prefix: &JournalPrefix,
    evidence: &EvidenceRef,
) -> LeaseRecord {
    let tp = |offset: f64| TimePoint {
        clock_id: "lease-clock".to_string(),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    let issued = tp(1000.0);
    let deadline = tp(31000.0);
    let value = json!({
        "record_type": "lease_record",
        "schema_version": "evidence-kernel/0.1.0",
        "resource": {"owner_domain": "execution", "entity_type": "connector_task", "entity_id": entity},
        "policy": {"id": "execution_lease", "version": "1", "artifact_digest": artifact_digest(format!("policy-{run}").as_bytes()).as_str()},
        "issuer_id": "lease-authority",
        "authority_epoch": "authority-epoch-1",
        "entity_revision": 2,
        "input_revision": 1,
        "generation_id": format!("generation-{run}"),
        "resource_state": "pending",
        "eligible_state": "pending",
        "lease_state": "held",
        "lease_id": serde_json::to_value(TimeMaybeString::Text(format!("lease-{run}"))).unwrap(),
        "lease_owner": serde_json::to_value(TimeMaybeString::Text("lease-owner".to_string())).unwrap(),
        "owner_epoch": serde_json::to_value(TimeMaybeString::Text("owner-epoch-1".to_string())).unwrap(),
        "session_epoch": serde_json::to_value(TimeMaybeString::Missing(Missing::new("not_applicable"))).unwrap(),
        "leased_at": serde_json::to_value(MaybeTimePoint::Present(issued)).unwrap(),
        "lease_expires_at": serde_json::to_value(MaybeTimePoint::Present(deadline)).unwrap(),
        "retry_count": 0,
        "max_retries_effective": 2,
        "last_failure_reason": serde_json::to_value(TimeMaybeString::Missing(Missing::new("not_applicable"))).unwrap(),
        "journal_prefix": prefix.to_json(),
        "evidence_refs": [evidence.to_json()],
    });
    LeaseRecord::from_json(&value).expect("held lease parses")
}

// ---------------------------------------------------------------------------
// Fixtures: tasks, scopes, preparations, handles
// ---------------------------------------------------------------------------

fn test_budgets(recovery_limit: u64) -> TaskBudgets {
    TaskBudgets {
        active_limit: rm_preparation::DurationLimit {
            kind: "exact".to_string(),
            unit: "ms".to_string(),
            value: 30000.0,
        },
        action_limit: 20,
        observation_byte_limit: 1_000_000,
        recovery_limit,
        model_token_limit: 1000,
    }
}

fn test_context() -> PrepContext {
    PrepContext {
        browser_state: PrepState {
            mode: "fresh".to_string(),
            requirement: "best_effort".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        learning_state: PrepState {
            mode: "fresh".to_string(),
            requirement: "best_effort".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
    }
}

fn apply_task(task_id: &str, inputs: Vec<TaskInput>) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: "apply".to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: "https://example.test/jobs".to_string(),
        },
        goal: format!("execute apply workflow for {task_id}"),
        success_criteria: vec![SuccessCriterion {
            criterion_id: "c1".to_string(),
            description: "workflow completes".to_string(),
        }],
        inputs,
        permitted_origins: vec![PermittedOrigin {
            logical_id: "o1".to_string(),
            origin: "https://example.test".to_string(),
        }],
        permitted_interfaces: vec!["ordinary_browser".to_string()],
        effect_policy: "commissioned_application".to_string(),
        budgets: test_budgets(1),
        context_policy: test_context(),
        output_schema: CatalogMaybePin::Missing(Missing::new("not_applicable")),
    }
}

fn extract_task(task_id: &str, inputs: Vec<TaskInput>) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: "extract".to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: "https://example.test/jobs".to_string(),
        },
        goal: format!("extract listings for {task_id}"),
        success_criteria: vec![SuccessCriterion {
            criterion_id: "c1".to_string(),
            description: "extraction completes".to_string(),
        }],
        inputs,
        permitted_origins: vec![PermittedOrigin {
            logical_id: "o1".to_string(),
            origin: "https://example.test".to_string(),
        }],
        permitted_interfaces: vec!["read_only_acquisition".to_string()],
        effect_policy: "read_only".to_string(),
        budgets: test_budgets(1),
        context_policy: test_context(),
        output_schema: CatalogMaybePin::Present(CatalogPin {
            id: rm_extraction::PARTIAL_SCHEMA_ID.to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(b"rm-exec-partial-schema"),
        }),
    }
}

fn apply_scope(manifest: &Manifest, journal_id: &str, tag: &str) -> WorkScope {
    WorkScope {
        activity: "apply".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id.to_string(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: Some(format!("attempt-{tag}")),
        commission_id: Some(format!("commission-{tag}")),
        commission_ref: Some(format!("commission-ref-{tag}")),
        attempt_kind: Some(AttemptKind::Production),
        authorization_refs: vec![format!("grant-exec-{tag}")],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

fn extract_scope(manifest: &Manifest, journal_id: &str, tag: &str) -> WorkScope {
    WorkScope {
        activity: "extract".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id.to_string(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec![format!("grant-exec-{tag}")],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

fn make_configuration(
    writer: &AuthenticatedPrincipal,
    descriptor_ref: EvidenceRef,
    tag: &str,
) -> ConfigurationPin {
    let descriptor =
        rm_catalog::describe(writer, &rm_catalog::DescribeRequest).expect("describe succeeds");
    let mut bytes = serde_json::to_vec(&descriptor.to_json()).expect("descriptor serializes");
    bytes.extend_from_slice(format!("-{tag}").as_bytes());
    let reference = install_bytes(writer, &bytes, "artifact", "application/json");
    ConfigurationPin {
        connector_id: descriptor.connector_id.clone(),
        connector_version: descriptor.connector_version.clone(),
        binding: descriptor.binding.clone(),
        subject: descriptor.subject.clone(),
        descriptor: reference,
        descriptor_ref,
    }
}

fn make_preparation(
    preparation_id: &str,
    scope: WorkScope,
    configuration: ConfigurationPin,
    task: TaskEnvelope,
    prefix: JournalPrefix,
    writer: &AuthenticatedPrincipal,
    tag: &str,
) -> PreparedTask {
    let delivered_bytes = format!("delivered-{tag}-{preparation_id}").into_bytes();
    let delivered = install_bytes(writer, &delivered_bytes, "artifact", "application/json");
    let native_bytes = format!("native-{tag}-{preparation_id}").into_bytes();
    let native = install_bytes(writer, &native_bytes, "artifact", "application/json");
    let task_json = task.to_json();
    let task_bytes = serde_json::to_vec(&task_json).expect("task serializes");
    PreparedTask {
        record_type: "connector_preparation".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        preparation_id: preparation_id.to_string(),
        scope,
        configuration,
        task,
        task_semantic_hash: artifact_digest(&task_bytes),
        assistance: AssistanceRecord {
            planning_owner: "external_planner".to_string(),
            assistance_track: "track-exec".to_string(),
            planner_identity: CatalogMaybeString::Text("planner-1".to_string()),
            plan: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
            online_replanning: false,
            description: "declared execution assistance".to_string(),
        },
        planning_evidence_refs: Vec::new(),
        runtime_access: Vec::new(),
        delivered_task: delivered.clone(),
        delivered_task_hash: delivered.digest.clone(),
        native_request: native.clone(),
        native_request_hash: native.digest.clone(),
        translation: test_pin("translation", "1"),
        budget_mapping: Vec::new(),
        concerns: Vec::new(),
        evidence_prefix: prefix,
    }
}

fn make_handle(
    preparation: &PreparedTask,
    writer: &AuthenticatedPrincipal,
    tag: &str,
) -> DeliveryHandle {
    let record_bytes = serde_json::to_vec(&preparation.to_json()).expect("prep serializes");
    let mut tagged = record_bytes.clone();
    tagged.extend_from_slice(format!("-handle-{tag}").as_bytes());
    let artifact = {
        let reference = ArtifactReference {
            digest: artifact_digest(&tagged),
            size_bytes: tagged.len() as u64,
            media_type: "application/json".to_string(),
            owner_domain: "artifact".to_string(),
            access: AccessClass::Public,
        };
        rm_evidence::install_artifact(writer, &reference, &tagged).expect("handle prep install");
        reference
    };
    // Share the lease clock so the active boundary is comparable without
    // consulting UTC annotations.
    let created_at = TimePoint {
        clock_id: "lease-clock".to_string(),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: 0.0,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    let registration_ref = EvidenceRef {
        journal_id: preparation.evidence_prefix.journal_id.clone(),
        sequence: preparation.evidence_prefix.last_sequence.clone(),
        event_id: format!("event-reg-{tag}"),
        event_hash: preparation.evidence_prefix.head_hash.clone(),
        pointer: String::new(),
    };
    DeliveryHandle {
        record_type: "connector_handle".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        handle: HandleReference {
            connector_id: preparation.configuration.connector_id.clone(),
            local_handle: format!("local-{tag}"),
        },
        preparation: PreparationReference {
            preparation_id: preparation.preparation_id.clone(),
            artifact,
            registration_ref,
        },
        scope: preparation.scope.clone(),
        idempotency_key: format!("key-{tag}"),
        created_at,
    }
}

// ---------------------------------------------------------------------------
// Fixtures: recipes, values, plans
// ---------------------------------------------------------------------------

fn target_recipe_json(strategy: &str, query: &str, fallback: &str, policy: &CatalogPin) -> Value {
    json!({
        "frame_path": [],
        "shadow_path": [],
        "strategy": strategy,
        "query": query,
        "exact": true,
        "max_matches": 10,
        "fallback_text": fallback,
        "resolver_policy": policy.to_json(),
    })
}

fn install_recipe(
    writer: &AuthenticatedPrincipal,
    strategy: &str,
    query: &str,
    fallback: &str,
) -> ArtifactReference {
    let policy = test_pin("resolver", "1");
    let value = target_recipe_json(strategy, query, fallback, &policy);
    let bytes = serde_json::to_vec(&value).expect("recipe serializes");
    canonical_digest(&bytes).expect("recipe structurally valid");
    // Validate through the Tier 1 parser so only durable intent is installed.
    rm_targets::parse_target_recipe(&bytes).expect("recipe parses");
    install_bytes(writer, &bytes, "artifact", "application/json")
}

fn event_recipe_value(events: Vec<Value>) -> Value {
    json!({"record_type": "event_recipe", "events": events})
}

fn single_input_event() -> Value {
    json!({
        "event_type": "input",
        "bubbles": true,
        "cancelable": false,
        "composed": true,
        "detail": {"value": null, "reason": "not_applicable"},
    })
}

fn single_click_event() -> Value {
    json!({
        "event_type": "click",
        "bubbles": true,
        "cancelable": true,
        "composed": true,
        "detail": {"value": null, "reason": "not_applicable"},
    })
}

fn install_event_recipe(
    writer: &AuthenticatedPrincipal,
    events: Vec<Value>,
) -> (ArtifactReference, CatalogPin) {
    let value = event_recipe_value(events);
    let bytes = serde_json::to_vec(&value).expect("event recipe serializes");
    canonical_digest(&bytes).expect("event recipe structurally valid");
    let reference = install_bytes(writer, &bytes, "artifact", "application/json");
    let pin = CatalogPin {
        id: "event-recipe".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: reference.digest.clone(),
    };
    (reference, pin)
}

fn manifest_json(manifest: &Manifest) -> Value {
    json!({
        "record_type": manifest.record_type,
        "schema_version": manifest.schema_version,
        "run_id": manifest.run_id,
        "task": manifest.task,
        "subject": manifest.subject,
        "event_kinds": manifest.event_kinds,
        "admission_ref": manifest.admission_ref,
        "manifest_hash": manifest.manifest_hash,
    })
}

#[allow(clippy::too_many_arguments)]
fn plan_json(
    manifest: &Manifest,
    prefix: &JournalPrefix,
    evidence: &EvidenceRef,
    unmapped: Vec<&str>,
    destination: &str,
    scope: &str,
    steps: Vec<Value>,
    allowance: u64,
    heal_policy: &CatalogPin,
) -> Value {
    json!({
        "record_type": "execution_plan",
        "schema_version": "rm-execution/0.1.0",
        "manifest": manifest_json(manifest),
        "binding_prefix": prefix.to_json(),
        "binding_evidence": evidence.to_json(),
        "binding_id": "bo-binding-1",
        "storage_model": "process_global",
        "unmapped": unmapped,
        "preflight": {
            "destination": destination,
            "account_binding": "account-1",
            "marker": "hello",
            "scope": scope,
            "policy": test_pin("preflight-policy", "1").to_json(),
        },
        "steps": steps,
        "recovery": {
            "allowance_remaining": allowance,
            "heal_profile_policy": heal_policy.to_json(),
        },
    })
}

fn fill_step(
    target: &ArtifactReference,
    text: &ArtifactReference,
    event_recipe: &CatalogPin,
) -> Value {
    json!({
        "action": "fill",
        "target": target.to_json(),
        "text": text.to_json(),
        "event_recipe": event_recipe.to_json(),
    })
}

fn click_step(target: &ArtifactReference, event_recipe: &CatalogPin) -> Value {
    json!({
        "action": "click",
        "target": target.to_json(),
        "event_recipe": event_recipe.to_json(),
    })
}

fn navigate_step(url: &str) -> Value {
    json!({
        "action": "navigate",
        "url": url,
        "navigation_policy": test_pin("navigation-policy", "1").to_json(),
    })
}

fn wait_step(predicate: &ArtifactReference) -> Value {
    json!({
        "action": "wait",
        "predicate": predicate.to_json(),
        "predicate_mapping": test_pin("predicate-mapping", "1").to_json(),
    })
}

fn assert_step(predicate: &ArtifactReference) -> Value {
    json!({
        "action": "assert",
        "predicate": predicate.to_json(),
        "predicate_mapping": test_pin("predicate-mapping", "1").to_json(),
    })
}

fn upload_step(
    target: &ArtifactReference,
    files: &[ArtifactReference],
    event_recipe: Value,
) -> Value {
    json!({
        "action": "upload",
        "target": target.to_json(),
        "files": files.iter().map(ArtifactReference::to_json).collect::<Vec<Value>>(),
        "upload_policy": test_pin("upload-policy", "1").to_json(),
        "event_recipe": event_recipe,
    })
}

fn checkpoint_step() -> Value {
    json!({
        "action": "checkpoint",
        "checkpoint_policy": test_pin("checkpoint-policy", "1").to_json(),
    })
}

fn extract_step(query: Value) -> Value {
    json!({
        "action": "extract",
        "query": query,
        "output_schema": test_pin("output-schema", "1").to_json(),
        "extraction_policy": test_pin("extraction-policy", "1").to_json(),
    })
}

/// Reads every retained event in one journal (bounded scan).
fn read_all_events(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
) -> Vec<rm_evidence::JournalEnvelope> {
    let head = rm_evidence::journal_head(principal, journal_id).expect("head");
    let last = head.last_sequence.get();
    let mut out = Vec::new();
    for sequence in 1..=last {
        let envelope = rm_evidence::read_event(
            principal,
            journal_id,
            PositiveInteger::new(sequence).expect("pos"),
        )
        .expect("read event");
        out.push(envelope);
    }
    out
}

fn journal_contains(envelopes: &[rm_evidence::JournalEnvelope], needle: &str) -> bool {
    for envelope in envelopes {
        let text = serde_json::to_string(&envelope.payload.data).unwrap_or_default();
        if text.contains(needle) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// RM-C35: Tier 1 no match routes toward recovery (budget)
// ---------------------------------------------------------------------------

#[test]
fn rm_c35_tier1_no_match_routes_toward_recovery() {
    let tag = "c35-nomatch";
    let princ = principal(&format!("rm-exec-{tag}"));
    let run = format!("rm-exec-run-{tag}");
    let manifest = execution_manifest(&run);
    rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");

    let (_bw, bprefix, bevidence) = journal_fixture(tag);
    let lease_evidence = {
        let envelopes = read_all_events(&princ, &journal_id);
        let first = envelopes.first().expect("admission retained");
        EvidenceRef {
            journal_id: first.journal_id.clone(),
            sequence: first.journal_sequence.clone(),
            event_id: first.event_id.clone(),
            event_hash: first.event_hash.clone(),
            pointer: String::new(),
        }
    };
    let lease = held_lease(&run, &format!("entity-{tag}"), &prefix, &lease_evidence);

    // Non-matching Tier 1 recipe: no mutation can occur before resolution.
    let recipe = install_recipe(&princ, "css", "#nonexistent-xyz", &format!("fallback-{tag}"));
    let text = install_bytes(&princ, b"filled-value", "artifact", "text/plain");
    let (event_ref, event_pin) = install_event_recipe(&princ, vec![single_input_event()]);
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    let steps = vec![fill_step(&recipe, &text, &event_pin)];
    let plan_value = plan_json(
        &manifest,
        &bprefix,
        &bevidence,
        Vec::new(),
        "https://example.test/jobs",
        "apply",
        steps,
        1,
        &heal_policy,
    );
    let plan_bytes = serde_json::to_vec(&plan_value).expect("plan serializes");
    canonical_digest(&plan_bytes).expect("plan structurally valid");
    let plan_ref = install_bytes(&princ, &plan_bytes, "artifact", "application/json");

    let mut task = apply_task(
        &format!("task-{tag}"),
        vec![
            TaskInput {
                name: "execution_plan".to_string(),
                purpose: "input_artifact".to_string(),
                content: plan_ref.clone(),
            },
            TaskInput {
                name: "event_recipe_fill".to_string(),
                purpose: "input_artifact".to_string(),
                content: event_ref.clone(),
            },
            TaskInput {
                name: "fill_target".to_string(),
                purpose: "input_artifact".to_string(),
                content: recipe.clone(),
            },
            TaskInput {
                name: "fill_text".to_string(),
                purpose: "input_artifact".to_string(),
                content: text.clone(),
            },
        ],
    );
    // Zero recovery budget: the effect-safe failure must surface as an
    // explicit budget refusal, never as reconciliation or silent success.
    task.budgets.recovery_limit = 0;
    let scope = apply_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix.clone(),
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);

    let error = rm_execution::run_owner_work(princ.clone(), preparation, handle, lease)
        .expect_err("zero-budget Tier 1 no-match must not succeed");
    assert_eq!(error.code, "FORBIDDEN", "unexpected error: {error}");
    assert!(
        error.detail.contains("recovery"),
        "effect-safe routing must mention recovery, got: {}",
        error.detail
    );

    // No mutation occurred: the journal carries no property write.
    let envelopes = read_all_events(&princ, &journal_id);
    assert!(
        !journal_contains(&envelopes, "property_write"),
        "Tier 1 no-match must not mutate"
    );
}

// ---------------------------------------------------------------------------
// RM-C35: possible effect requires reconciliation (no whole-action replay)
// ---------------------------------------------------------------------------

#[test]
fn rm_c35_possible_effect_requires_reconciliation() {
    let tag = "c35-partial";
    let princ = principal(&format!("rm-exec-{tag}"));
    let run = format!("rm-exec-run-{tag}");
    let manifest = execution_manifest(&run);
    rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");

    let (_bw, bprefix, bevidence) = journal_fixture(tag);
    let lease_evidence = {
        let envelopes = read_all_events(&princ, &journal_id);
        let first = envelopes.first().expect("admission retained");
        EvidenceRef {
            journal_id: first.journal_id.clone(),
            sequence: first.journal_sequence.clone(),
            event_id: first.event_id.clone(),
            event_hash: first.event_hash.clone(),
            pointer: String::new(),
        }
    };
    let lease = held_lease(&run, &format!("entity-{tag}"), &prefix, &lease_evidence);

    // Matching recipe: dom_write will succeed, then the synthetic dispatch
    // cannot enter because the primitive is unmapped in this binding.
    let recipe = install_recipe(&princ, "css", "#main", &format!("fallback-{tag}"));
    let text = install_bytes(&princ, b"filled-value", "artifact", "text/plain");
    let (event_ref, event_pin) = install_event_recipe(&princ, vec![single_input_event()]);
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    let steps = vec![fill_step(&recipe, &text, &event_pin)];
    let plan_value = plan_json(
        &manifest,
        &bprefix,
        &bevidence,
        vec!["bo.event_dispatch"],
        "https://example.test/jobs",
        "apply",
        steps,
        1,
        &heal_policy,
    );
    let plan_bytes = serde_json::to_vec(&plan_value).expect("plan serializes");
    canonical_digest(&plan_bytes).expect("plan structurally valid");
    let plan_ref = install_bytes(&princ, &plan_bytes, "artifact", "application/json");

    let task = apply_task(
        &format!("task-{tag}"),
        vec![
            TaskInput {
                name: "execution_plan".to_string(),
                purpose: "input_artifact".to_string(),
                content: plan_ref.clone(),
            },
            TaskInput {
                name: "event_recipe_fill".to_string(),
                purpose: "input_artifact".to_string(),
                content: event_ref.clone(),
            },
            TaskInput {
                name: "fill_target".to_string(),
                purpose: "input_artifact".to_string(),
                content: recipe.clone(),
            },
            TaskInput {
                name: "fill_text".to_string(),
                purpose: "input_artifact".to_string(),
                content: text.clone(),
            },
        ],
    );
    let scope = apply_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix.clone(),
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);

    let error = rm_execution::run_owner_work(princ.clone(), preparation, handle, lease)
        .expect_err("partial compound failure must not succeed");
    assert_eq!(error.code, "RECONCILIATION_REQUIRED", "unexpected error: {error}");
    assert!(
        error.detail.contains("prior effect") || error.detail.contains("reconcile"),
        "partial failure must demand reconciliation, got: {}",
        error.detail
    );

    // Prior effects are preserved: the property write and the partial-failure
    // report are both retained. Exactly one property write exists: the whole
    // action was never replayed.
    let envelopes = read_all_events(&princ, &journal_id);
    assert!(
        journal_contains(&envelopes, "property_write"),
        "prior dom_write effect must be preserved"
    );
    assert!(
        journal_contains(&envelopes, "partial_failure"),
        "partial failure must be journaled"
    );
    let mut writes = 0;
    for envelope in &envelopes {
        let text = serde_json::to_string(&envelope.payload.data).unwrap_or_default();
        if text.contains("property_write") {
            writes += 1;
        }
    }
    assert_eq!(writes, 1, "whole-action replay is forbidden after a partial effect");
}

// ---------------------------------------------------------------------------
// RM-C35: successful apply workflow (all mutation-safe actions + checkpoint)
// ---------------------------------------------------------------------------

#[test]
fn rm_c35_successful_apply_workflow() {
    let tag = "c35-apply-ok";
    let princ = principal(&format!("rm-exec-{tag}"));
    let run = format!("rm-exec-run-{tag}");
    let manifest = execution_manifest(&run);
    rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");

    let (_bw, bprefix, bevidence) = journal_fixture(tag);
    let lease_evidence = {
        let envelopes = read_all_events(&princ, &journal_id);
        let first = envelopes.first().expect("admission retained");
        EvidenceRef {
            journal_id: first.journal_id.clone(),
            sequence: first.journal_sequence.clone(),
            event_id: first.event_id.clone(),
            event_hash: first.event_hash.clone(),
            pointer: String::new(),
        }
    };
    let lease = held_lease(&run, &format!("entity-{tag}"), &prefix, &lease_evidence);

    let fill_recipe = install_recipe(&princ, "css", "#main", &format!("fallback-{tag}"));
    let click_recipe = install_recipe(&princ, "css", "div", &format!("fallback-{tag}"));
    let upload_recipe = install_recipe(&princ, "css", "#main", &format!("fallback-{tag}"));
    let text = install_bytes(&princ, b"filled-value", "artifact", "text/plain");
    let predicate = install_bytes(&princ, b"hello", "artifact", "text/plain");
    let file = install_bytes(&princ, b"file-bytes", "artifact", "application/octet-stream");
    let (fill_events, fill_pin) = install_event_recipe(&princ, vec![single_input_event()]);
    let (click_events, click_pin) = install_event_recipe(&princ, vec![single_click_event()]);
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");

    let steps = vec![
        navigate_step("https://example.test/jobs"),
        fill_step(&fill_recipe, &text, &fill_pin),
        click_step(&click_recipe, &click_pin),
        wait_step(&predicate),
        assert_step(&predicate),
        upload_step(
            &upload_recipe,
            std::slice::from_ref(&file),
            json!({"value": null, "reason": "not_applicable"}),
        ),
        extract_step(Value::String("hello".to_string())),
        checkpoint_step(),
    ];
    let plan_value = plan_json(
        &manifest,
        &bprefix,
        &bevidence,
        Vec::new(),
        "https://example.test/jobs",
        "apply",
        steps,
        1,
        &heal_policy,
    );
    let plan_bytes = serde_json::to_vec(&plan_value).expect("plan serializes");
    canonical_digest(&plan_bytes).expect("plan structurally valid");
    let plan_ref = install_bytes(&princ, &plan_bytes, "artifact", "application/json");

    let task = apply_task(
        &format!("task-{tag}"),
        vec![
            TaskInput {
                name: "execution_plan".to_string(),
                purpose: "input_artifact".to_string(),
                content: plan_ref.clone(),
            },
            TaskInput {
                name: "event_recipe_fill".to_string(),
                purpose: "input_artifact".to_string(),
                content: fill_events.clone(),
            },
            TaskInput {
                name: "event_recipe_click".to_string(),
                purpose: "input_artifact".to_string(),
                content: click_events.clone(),
            },
            TaskInput {
                name: "fill_target".to_string(),
                purpose: "input_artifact".to_string(),
                content: fill_recipe.clone(),
            },
            TaskInput {
                name: "fill_text".to_string(),
                purpose: "input_artifact".to_string(),
                content: text.clone(),
            },
            TaskInput {
                name: "wait_predicate".to_string(),
                purpose: "input_artifact".to_string(),
                content: predicate.clone(),
            },
            TaskInput {
                name: "upload_file".to_string(),
                purpose: "input_artifact".to_string(),
                content: file.clone(),
            },
        ],
    );
    let scope = apply_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix.clone(),
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);

    let result = rm_execution::run_owner_work(princ.clone(), preparation, handle, lease)
        .expect("apply workflow must succeed");
    let result_bytes = rm_evidence::load_artifact(&princ, &result).expect("result retained");
    let result_value: Value = serde_json::from_slice(&result_bytes).expect("result JSON");
    assert_eq!(
        result_value.get("record_type").and_then(Value::as_str),
        Some("ringmaster_execution_result")
    );
    let completed = result_value
        .get("completed_steps")
        .and_then(Value::as_array)
        .expect("completed steps");
    assert_eq!(completed.len(), 8, "all eight steps must complete");

    // Synthetic events are disclosed as synthetic, never as trusted input.
    let envelopes = read_all_events(&princ, &journal_id);
    assert!(
        journal_contains(&envelopes, "synthetic_dom_event_dispatch"),
        "synthetic dispatch mechanism must be disclosed"
    );
    assert!(
        journal_contains(&envelopes, "property_mutation_not_typing"),
        "property mutation must be disclosed as not typing"
    );
    // No trusted-input claim is ever journaled.
    for envelope in &envelopes {
        let text = serde_json::to_string(&envelope.payload.data).unwrap_or_default();
        assert!(
            !text.contains("\"trusted_input\":true"),
            "trusted input must never be claimed: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// RM-C35: extract workflow uses the deterministic contract
// ---------------------------------------------------------------------------

#[test]
fn rm_c35_extract_workflow_uses_deterministic_extraction() {
    let tag = "c35-extract-ok";
    let princ = principal(&format!("rm-exec-{tag}"));
    let run = format!("rm-exec-run-{tag}");
    let manifest = execution_manifest(&run);
    rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");

    let (_bw, bprefix, bevidence) = journal_fixture(tag);
    let lease_evidence = {
        let envelopes = read_all_events(&princ, &journal_id);
        let first = envelopes.first().expect("admission retained");
        EvidenceRef {
            journal_id: first.journal_id.clone(),
            sequence: first.journal_sequence.clone(),
            event_id: first.event_id.clone(),
            event_hash: first.event_hash.clone(),
            pointer: String::new(),
        }
    };
    let lease = held_lease(&run, &format!("entity-{tag}"), &prefix, &lease_evidence);

    let source = install_bytes(
        &princ,
        b"title: Engineer\ncompany: ExampleCorp",
        "artifact",
        "text/plain",
    );
    let predicate = install_bytes(&princ, b"hello", "artifact", "text/plain");
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    let steps = vec![
        navigate_step("https://example.test/jobs"),
        wait_step(&predicate),
        extract_step(Value::String("Engineer".to_string())),
        assert_step(&predicate),
        checkpoint_step(),
    ];
    let plan_value = plan_json(
        &manifest,
        &bprefix,
        &bevidence,
        Vec::new(),
        "https://example.test/jobs",
        "extract",
        steps,
        1,
        &heal_policy,
    );
    let plan_bytes = serde_json::to_vec(&plan_value).expect("plan serializes");
    canonical_digest(&plan_bytes).expect("plan structurally valid");
    let plan_ref = install_bytes(&princ, &plan_bytes, "artifact", "application/json");

    let task = extract_task(
        &format!("task-{tag}"),
        vec![
            TaskInput {
                name: "execution_plan".to_string(),
                purpose: "input_artifact".to_string(),
                content: plan_ref.clone(),
            },
            TaskInput {
                name: "acquisition".to_string(),
                purpose: "acquisition_source".to_string(),
                content: source.clone(),
            },
            TaskInput {
                name: "wait_predicate".to_string(),
                purpose: "input_artifact".to_string(),
                content: predicate.clone(),
            },
        ],
    );
    let scope = extract_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix.clone(),
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);

    let result = rm_execution::run_owner_work(princ.clone(), preparation, handle, lease)
        .expect("extract workflow must succeed");
    let result_bytes = rm_evidence::load_artifact(&princ, &result).expect("result retained");
    let result_value: Value = serde_json::from_slice(&result_bytes).expect("result JSON");
    let completed = result_value
        .get("completed_steps")
        .and_then(Value::as_array)
        .expect("completed steps");
    assert_eq!(completed.len(), 5, "all five extract steps must complete");

    let envelopes = read_all_events(&princ, &journal_id);
    assert!(
        journal_contains(&envelopes, "predicate_satisfied"),
        "wait must observe the predicate"
    );
}

// ---------------------------------------------------------------------------
// RM-C35: preflight destination must be permitted
// ---------------------------------------------------------------------------

#[test]
fn rm_c35_preflight_destination_must_be_permitted() {
    let tag = "c35-preflight";
    let princ = principal(&format!("rm-exec-{tag}"));
    let run = format!("rm-exec-run-{tag}");
    let manifest = execution_manifest(&run);
    rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");

    let (_bw, bprefix, bevidence) = journal_fixture(tag);
    let lease_evidence = {
        let envelopes = read_all_events(&princ, &journal_id);
        let first = envelopes.first().expect("admission retained");
        EvidenceRef {
            journal_id: first.journal_id.clone(),
            sequence: first.journal_sequence.clone(),
            event_id: first.event_id.clone(),
            event_hash: first.event_hash.clone(),
            pointer: String::new(),
        }
    };
    let lease = held_lease(&run, &format!("entity-{tag}"), &prefix, &lease_evidence);

    let predicate = install_bytes(&princ, b"hello", "artifact", "text/plain");
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    let steps = vec![wait_step(&predicate)];
    // Destination outside the admitted permitted origins.
    let plan_value = plan_json(
        &manifest,
        &bprefix,
        &bevidence,
        Vec::new(),
        "https://evil.test/trap",
        "apply",
        steps,
        1,
        &heal_policy,
    );
    let plan_bytes = serde_json::to_vec(&plan_value).expect("plan serializes");
    canonical_digest(&plan_bytes).expect("plan structurally valid");
    let plan_ref = install_bytes(&princ, &plan_bytes, "artifact", "application/json");

    let task = apply_task(
        &format!("task-{tag}"),
        vec![
            TaskInput {
                name: "execution_plan".to_string(),
                purpose: "input_artifact".to_string(),
                content: plan_ref.clone(),
            },
            TaskInput {
                name: "wait_predicate".to_string(),
                purpose: "input_artifact".to_string(),
                content: predicate.clone(),
            },
        ],
    );
    let scope = apply_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix.clone(),
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);

    let error = rm_execution::run_owner_work(princ, preparation, handle, lease)
        .expect_err("unpermitted preflight destination must be rejected");
    assert_eq!(error.code, "FORBIDDEN", "unexpected error: {error}");
    assert!(
        error.detail.contains("permitted") || error.detail.contains("destination"),
        "preflight must enforce permitted destinations, got: {}",
        error.detail
    );
}
