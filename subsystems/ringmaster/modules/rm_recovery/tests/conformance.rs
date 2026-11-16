//! Conformance for RM-C41 (dHash hit with changed geometry/layout).
//!
//! Every test name carries `rm_c41` so the verification filter
//! `cargo test -p rm_recovery -- rm_c41` selects the suite.

use rm_authority::{
    authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, ExecutionMode, Manifest,
    WorkScope,
};
use rm_browseroxide::{
    open_native_session, BOFailure, BOOwner, BOPageRef, BOPrimitiveRecord, BORootRef, MaybeBOFailure,
    MaybeClient, NativeSession,
};
use rm_catalog::{
    BO_CAPABILITIES, BO_PRIMITIVES, BOBindingDescriptor, BOMapping, CapabilityDescriptor,
    CapabilityRecord, ComponentIdentity, DurationLimit, SubjectIdentity,
    VersionPin as CatalogVersionPin, BO_RECORD_TYPE as CATALOG_BO_RECORD,
    BO_SCHEMA_VERSION as CATALOG_BO_SCHEMA, CAPABILITY_RECORD_TYPE, CAPABILITY_SCHEMA_VERSION,
    MaybeDigest as CatalogMaybeDigest, MaybeString as CatalogMaybeString,
    MaybeVersionPin as CatalogMaybePin,
};
use rm_delivery::{ConnectorHandle as DeliveryHandle, HandleReference};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload, JournalPrefix,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_preparation::{
    AssistanceRecord, ConfigurationPin, ContextPolicy, EntryPoint, PermittedOrigin, PreparedTask,
    StatePolicy, SuccessCriterion, TaskBudgets as PrepBudgets, TaskEnvelope,
};
use rm_time::{
    MaybeString as TimeMaybeString, MaybeTimePoint, Measurement, MeasurementOrigin,
    Method, Missing, Quantity, Scope, ScopeKind, TimePoint, UtcAnnotation, Censoring, Estimate,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn principal(id: &str) -> AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": id,
        "channel_binding": {"mechanism": "test-harness", "binding": format!("binding-{id}")},
    });
    let bytes = serde_json::to_vec(&registration).expect("registration");
    authenticate_channel(&mut Cursor::new(bytes)).expect("principal")
}

fn test_pin(id: &str, version: &str) -> CatalogVersionPin {
    CatalogVersionPin {
        id: id.to_string(),
        version: version.to_string(),
        artifact_digest: artifact_digest(format!("{id}-{version}").as_bytes()),
    }
}

fn session_manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: vec!["manifest_admitted".to_string(), "execution_claim".to_string()],
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire).expect("hash").as_str().to_string();
    manifest
}

fn models_manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
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

fn journal_fixture(test: &str) -> (AuthenticatedPrincipal, JournalPrefix, EvidenceRef) {
    let writer = principal(&format!("rm-rec-bind-{test}"));
    let run = format!("rm-rec-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-rec-evidence-{test}").into_bytes();
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

fn bo_engine() -> ComponentIdentity {
    ComponentIdentity {
        component: "browseroxide-engine".to_string(),
        reported_version: CatalogMaybeString::Text("2.0.0".to_string()),
        build_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-rec-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(artifact_digest(
            b"rm-rec-engine-config",
        )),
    }
}

fn bo_subject(engine: &ComponentIdentity) -> SubjectIdentity {
    SubjectIdentity {
        subject_id: "bo-binding-1".to_string(),
        subject_version: "1.0.0".to_string(),
        revision_basis: "native_revision".to_string(),
        native_revision: CatalogMaybeString::Text("native-rev-1".to_string()),
        configured_mode: "default".to_string(),
        interface_surface: "browseroxide-ffi".to_string(),
        configuration_digest: artifact_digest(b"rm-rec-config"),
        stack: vec![engine.clone()],
    }
}

fn bo_record(id: &str) -> CapabilityRecord {
    CapabilityRecord {
        capability_id: id.to_string(),
        requirement_refs: Vec::new(),
        availability: "unknown".to_string(),
        claim_origin: "harness".to_string(),
        evidence: Vec::new(),
        limitations: vec![format!("{id} is unassessed")],
    }
}

fn bo_mapped(primitive: &str, evidence: &EvidenceRef) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "mapped".to_string(),
        native_symbol: CatalogMaybeString::Text(format!(
            "native_{}",
            primitive.replace('.', "_")
        )),
        native_contract: CatalogMaybePin::Present(CatalogVersionPin {
            id: "bo-contract".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(primitive.as_bytes()),
        }),
        evidence_refs: vec![evidence.clone()],
    }
}

fn bo_unmapped(primitive: &str) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "unmapped".to_string(),
        native_symbol: CatalogMaybeString::Missing(Missing::new("not_applicable")),
        native_contract: CatalogMaybePin::Missing(Missing::new("not_applicable")),
        evidence_refs: Vec::new(),
    }
}


fn bo_descriptor_with_unmapped(
    prefix: &JournalPrefix,
    evidence: &EvidenceRef,
    unmapped: &[&str],
) -> BOBindingDescriptor {
    let engine = bo_engine();
    let subject = bo_subject(&engine);
    BOBindingDescriptor {
        record_type: CATALOG_BO_RECORD.to_string(),
        schema_version: CATALOG_BO_SCHEMA.to_string(),
        binding_id: "bo-binding-1".to_string(),
        binding_build: CatalogVersionPin {
            id: "bo-binding-1".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(b"rm-rec-binding-build"),
        },
        engine,
        capabilities: CapabilityDescriptor {
            record_type: CAPABILITY_RECORD_TYPE.to_string(),
            schema_version: CAPABILITY_SCHEMA_VERSION.to_string(),
            descriptor_id: "bo-capabilities-1".to_string(),
            descriptor_revision: 1,
            declared_by: "bo-binding-1".to_string(),
            subject,
            catalog: CatalogVersionPin {
                id: "bo-catalog".to_string(),
                version: "0.1.0".to_string(),
                artifact_digest: artifact_digest(b"rm-rec-catalog"),
            },
            evidence_prefix: prefix.clone(),
            supersedes: CatalogMaybeDigest::Missing(Missing::new("not_applicable")),
            capabilities: BO_CAPABILITIES.iter().map(|id| bo_record(id)).collect(),
        },
        primitive_mappings: BO_PRIMITIVES
            .iter()
            .map(|primitive| {
                if unmapped.contains(primitive) {
                    bo_unmapped(primitive)
                } else {
                    bo_mapped(primitive, evidence)
                }
            })
            .collect(),
        session_storage_model: "process_global".to_string(),
        session_isolation_refs: Vec::new(),
        privacy_policy: CatalogVersionPin {
            id: "bo-privacy".to_string(),
            version: "0.1.0".to_string(),
            artifact_digest: artifact_digest(b"rm-rec-privacy"),
        },
        evidence_prefix: prefix.clone(),
    }
}

fn held_lease(run: &str, entity: &str, prefix: &JournalPrefix, evidence: &EvidenceRef) -> LeaseRecord {
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

fn test_limit() -> DurationLimit {
    DurationLimit {
        kind: "exact".to_string(),
        unit: "ms".to_string(),
        value: 5000.0,
    }
}

#[allow(clippy::type_complexity)]
fn open_session(
    test: &str,
) -> (
    AuthenticatedPrincipal,
    NativeSession,
    EvidenceRef,
    DurationLimit,
    JournalPrefix,
    Manifest,
    EvidenceRef,
) {
    open_session_with_unmapped(test, &[])
}

#[allow(clippy::type_complexity)]
fn open_session_with_unmapped(
    test: &str,
    unmapped: &[&str],
) -> (
    AuthenticatedPrincipal,
    NativeSession,
    EvidenceRef,
    DurationLimit,
    JournalPrefix,
    Manifest,
    EvidenceRef,
) {
    let (_bw, bprefix, bevidence) = journal_fixture(test);
    let binding = bo_descriptor_with_unmapped(&bprefix, &bevidence, unmapped);
    let princ = principal(&format!("rm-rec-{test}"));
    let run = format!("rm-rec-run-{test}");
    let manifest = session_manifest(&run);
    let admission_envelope =
        rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    let claim = rm_evidence::append_event(
        &princ,
        &manifest,
        EventSubmission {
            producer_sequence: Some(PositiveInteger::new(2).expect("pos")),
            event_kind: "execution_claim".to_string(),
            event_schema_version: "evidence-kernel/0.1.0".to_string(),
            occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
            payload: EvidencePayload {
                data: json!({"grant": format!("grant-{test}")}),
                measurements: Vec::new(),
                evidence_refs: Vec::new(),
                artifact_refs: Vec::new(),
            },
        },
    )
    .expect("claim");
    let auth = EvidenceRef {
        journal_id: claim.journal_id.clone(),
        sequence: claim.journal_sequence,
        event_id: claim.event_id.clone(),
        event_hash: claim.event_hash.clone(),
        pointer: String::new(),
    };
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let prefix = rm_evidence::journal_head(&princ, &journal_id).expect("head");
    let lease_evidence = EvidenceRef {
        journal_id: admission_envelope.journal_id.clone(),
        sequence: admission_envelope.journal_sequence,
        event_id: admission_envelope.event_id.clone(),
        event_hash: admission_envelope.event_hash.clone(),
        pointer: String::new(),
    };
    let lease = held_lease(&run, &format!("entity-{test}"), &prefix, &lease_evidence);
    let session = open_native_session(princ.clone(), manifest.clone(), binding, lease).expect("open");
    let limit = test_limit();
    (princ, session, auth, limit, prefix, manifest, bevidence)
}

fn make_page_for(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    tag: &str,
) -> BOPageRef {
    let writer = principal(&format!("rm-rec-writer-{tag}"));
    let profile_bytes = format!("profile-{tag}").into_bytes();
    let profile = ArtifactReference {
        digest: artifact_digest(&profile_bytes),
        size_bytes: profile_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "execution".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(&writer, &profile, &profile_bytes).expect("profile");
    let options_bytes = format!("options-{tag}").into_bytes();
    let options = ArtifactReference {
        digest: artifact_digest(&options_bytes),
        size_bytes: options_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "execution".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(&writer, &options, &options_bytes).expect("options");
    let out = rm_browseroxide::page_create(
        session,
        &rm_browseroxide::BOPageCreate {
            profile,
            native_options: options,
            client: MaybeClient::Missing(Missing::new("not_applicable")),
        },
        auth,
        limit,
    )
    .expect("page_create");
    assert_eq!(out.record.return_state, "returned");
    out.value.expect("page")
}

fn navigate_for_root(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    page: &BOPageRef,
) -> BORootRef {
    let out = rm_browseroxide::navigate(
        session,
        &rm_browseroxide::BONavigate {
            page: page.clone(),
            url: "https://example.test/".to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: test_pin("navigation", "1"),
        },
        auth,
        limit,
    )
    .expect("navigate");
    assert_eq!(out.record.return_state, "returned");
    let nav = out.value.expect("nav");
    match nav.document_root {
        rm_browseroxide::MaybeRoot::Present(root) => root,
        rm_browseroxide::MaybeRoot::Missing(_) => panic!("navigate must expose root"),
    }
}

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner: &str,
    media_type: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(writer, &reference, bytes).expect("install");
    reference
}

fn test_budgets() -> PrepBudgets {
    PrepBudgets {
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
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        learning_state: StatePolicy {
            mode: "reuse".to_string(),
            requirement: "best_effort".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
    }
}

fn make_task(task_id: &str) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: "extract".to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: "https://example.test/jobs".to_string(),
        },
        goal: format!("recover target for {task_id}"),
        success_criteria: vec![SuccessCriterion {
            criterion_id: "c1".to_string(),
            description: "recovery completes".to_string(),
        }],
        inputs: Vec::new(),
        permitted_origins: vec![PermittedOrigin {
            logical_id: "o1".to_string(),
            origin: "https://example.test".to_string(),
        }],
        permitted_interfaces: vec!["read_only_acquisition".to_string(), "ordinary_browser".to_string()],
        effect_policy: "commissioned_application".to_string(),
        budgets: test_budgets(),
        context_policy: test_context(),
        output_schema: CatalogMaybePin::Missing(Missing::new("not_applicable")),
    }
}

fn make_scope(manifest: &Manifest, journal_id: &str, tag: &str) -> WorkScope {
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
        authorization_refs: vec![format!("grant-rec-{tag}")],
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
            assistance_track: "track-rec".to_string(),
            planner_identity: CatalogMaybeString::Text("planner-1".to_string()),
            plan: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
            online_replanning: false,
            description: "declared recovery assistance".to_string(),
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
    // Install the tagged bytes so the handle artifact is unique per test, but
    // reference the tagged digest (the handle does not need to equal the raw
    // preparation bytes for recovery linkage, only the preparation_id/scope).
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
    let created_at = TimePoint {
        clock_id: format!("clock-rec-{tag}"),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: 0.0,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    // Registration ref must validate; reuse a synthetic-but-valid ref tied to
    // the preparation evidence prefix journal.
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
        preparation: rm_preparation::PreparationReference {
            preparation_id: preparation.preparation_id.clone(),
            artifact,
            registration_ref,
        },
        scope: preparation.scope.clone(),
        idempotency_key: format!("idem-{tag}"),
        created_at,
    }
}

fn test_timepoint(tag: &str, offset: f64) -> TimePoint {
    TimePoint {
        clock_id: format!("clock-rec-{tag}"),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::DateTime("2026-01-01T00:00:00Z".to_string()),
    }
}

fn dummy_measurement(tag: &str) -> Measurement {
    let point = |offset: f64| TimePoint {
        clock_id: format!("clock-rec-{tag}"),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    Measurement {
        measurement_id: format!("m-{tag}"),
        name: "recovery_elapsed".to_string(),
        scope: Scope {
            kind: ScopeKind::Recovery,
            id: format!("scope-{tag}"),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: format!("clock-rec-{tag}"),
        boot_id: "boot-1".to_string(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(point(0.0)),
        end: MaybeTimePoint::Present(point(10.0)),
        estimate: Estimate::Exact { value: 10.0 },
        resolution: rm_time::MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: TimeMaybeString::Missing(Missing::new("not_applicable")),
    }
}

fn failed_call(
    tag: &str,
    primitive: &str,
    return_state: &str,
    code: &str,
    native_entry: &str,
    detail: &str,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    effect_refs: Vec<EvidenceRef>,
) -> BOPrimitiveRecord {
    let owner = BOOwner {
        process_id: format!("proc-{tag}"),
        boot_id: format!("boot-{tag}"),
        os_thread_id: format!("thread-{tag}"),
    };
    let error = if return_state == "failed" {
        MaybeBOFailure::Present(BOFailure {
            code: code.to_string(),
            native_entry: native_entry.to_string(),
            native_error: rm_browseroxide::MaybeArtifact::Missing(Missing::new("not_applicable")),
            detail: detail.to_string(),
        })
    } else if return_state == "unsupported" {
        MaybeBOFailure::Present(BOFailure {
            code: "UNSUPPORTED".to_string(),
            native_entry: "not_entered".to_string(),
            native_error: rm_browseroxide::MaybeArtifact::Missing(Missing::new("not_applicable")),
            detail: "primitive unmapped".to_string(),
        })
    } else {
        MaybeBOFailure::Missing(Missing::new("not_applicable"))
    };
    let value = serde_json::to_value(Missing::new("not_applicable")).unwrap_or(Value::Null);
    BOPrimitiveRecord {
        record_type: "browseroxide_primitive_record".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        binding_digest: artifact_digest(format!("binding-{tag}").as_bytes()),
        call_id: format!("call-{tag}"),
        owner,
        primitive: primitive.to_string(),
        authorization_ref: auth.clone(),
        limit: limit.clone(),
        arguments: json!({}),
        return_state: return_state.to_string(),
        value,
        error,
        elapsed: dummy_measurement(tag),
        evidence_refs: vec![auth.clone()],
        effect_refs,
    }
}

fn safe_failed_dom_read(tag: &str, auth: &EvidenceRef, limit: &DurationLimit) -> BOPrimitiveRecord {
    failed_call(
        tag,
        "bo.dom_read",
        "failed",
        "TARGET_NOT_FOUND",
        "not_entered",
        "no match for Tier 1 recipe; recovery if authorized and budgeted",
        auth,
        limit,
        Vec::new(),
    )
}

// --- Models policy / binding / budgets JSON (mirrors rm_models fixtures) ---

fn provider_policy_json() -> Value {
    json!({
        "id": "provider-policy",
        "version": "1.0.0",
        "artifact_digest": artifact_digest(b"rm-rec-provider-policy").as_str(),
        "role": "recovery",
        "providers": ["provider-a"],
        "model": "model-1",
        "protocol": "https",
        "endpoint_ref": "endpoint-1",
        "credential_ref": "cred-1",
        "headers": [],
        "timeout_ms": 5000,
        "failover_enabled": true,
        "retention": "none",
        "privacy": "restricted",
        "user_agent": "ringmaster/0.1.0",
        "disclosure_allowed": true,
    })
}

fn models_binding_json() -> Value {
    let primitives = [
        "bo.client_create",
        "bo.http_exchange",
        "bo.page_create",
        "bo.navigate",
        "bo.from_html",
        "bo.dom_read",
        "bo.dom_write",
        "bo.event_dispatch",
        "bo.v8_evaluate",
        "bo.assign_files",
        "bo.capture",
        "bo.render_verdict",
        "bo.reset_for_reuse",
        "bo.page_destroy",
    ];
    let mappings: Vec<Value> = primitives
        .iter()
        .map(|prim| {
            json!({
                "primitive": prim,
                "mapping_state": "mapped",
                "native_symbol": format!("sym-{prim}"),
                "evidence_refs": ["ev-1"],
            })
        })
        .collect();
    json!({
        "record_type": "browseroxide_binding_descriptor",
        "schema_version": "internal-browser-binding.browseroxide/0.1.0",
        "binding_id": "binding-1",
        "primitive_mappings": mappings,
        "session_storage_model": "process_global",
        "session_isolation_refs": [],
    })
}

fn models_budgets_json() -> Value {
    json!({
        "active_limit_ms": 1000.0,
        "action_limit": 100,
        "observation_byte_limit": 1000000,
        "recovery_limit": 5,
        "model_token_limit": 1000,
        "enforcers": {
            "active_observation": "connector",
            "action_count": "connector",
            "observation_bytes": "connector",
            "recovery_count": "connector",
            "model_tokens": "connector",
        },
        "tokens_reserved": 100,
        "tokens_used": 10,
        "tokens_per_call": 10,
        "breaker": {
            "shard": "shard-1",
            "numerator": 1,
            "denominator": 100,
            "window_clock_id": "clock-rec-breaker",
            "sample_minimum": 10,
            "tripped": false,
            "reset_authority": "operator",
        },
        "session_limit": 10,
        "sessions_used": 1,
        "observation_open": true,
        "active_allowance_remaining": 5,
        "recovery_allowance_remaining": 5,
    })
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

fn failed_recipe_json(pin: &CatalogVersionPin, fallback: Value) -> Value {
    json!({
        "frame_path": [],
        "shadow_path": [],
        "strategy": "css",
        "query": ".nonexistent-target",
        "exact": true,
        "max_matches": 10,
        "fallback_text": fallback,
        "resolver_policy": {
            "id": pin.id,
            "version": pin.version,
            "artifact_digest": pin.artifact_digest.as_str(),
        },
    })
}

fn crop_json(ox: Value, oy: Value, w: Value, h: Value) -> Value {
    json!({"origin_x": ox, "origin_y": oy, "width": w, "height": h})
}

fn viewport_json(w: Value, h: Value) -> Value {
    json!({"width": w, "height": h})
}

fn missing(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

fn coordinate_entry_json(
    step: &str,
    dhash: &str,
    root: &BORootRef,
    layout: &str,
    target: &str,
) -> Value {
    json!({
        "step": step,
        "perceptual_hash": dhash,
        "coordinate_space": "viewport_css",
        "crop": crop_json(json!(10.0), json!(20.0), json!(200.0), json!(150.0)),
        "viewport": viewport_json(json!(1024.0), json!(768.0)),
        "scale": 2.0,
        "frame_offset_x": 0.0,
        "frame_offset_y": 0.0,
        "layout_digest": layout,
        "root": root.to_json(),
        "target_identity": target,
        "permission_granted": true,
    })
}

#[allow(clippy::too_many_arguments)]
fn current_geometry_json(
    step: &str,
    dhash: &str,
    root: &BORootRef,
    layout: Value,
    target: Value,
    crop: Value,
    viewport: Value,
    scale: Value,
    fox: Value,
    foy: Value,
    image_w: Value,
    image_h: Value,
    permission: bool,
) -> Value {
    json!({
        "step": step,
        "perceptual_hash": dhash,
        "crop": crop,
        "viewport": viewport,
        "scale": scale,
        "frame_offset_x": fox,
        "frame_offset_y": foy,
        "layout_digest": layout,
        "root": root.to_json(),
        "target_identity": target,
        "permission_granted": permission,
        "image_width": image_w,
        "image_height": image_h,
    })
}

fn default_current_geometry(step: &str, dhash: &str, root: &BORootRef, layout: &str, target: &str) -> Value {
    current_geometry_json(
        step,
        dhash,
        root,
        json!(layout),
        json!(target),
        crop_json(json!(10.0), json!(20.0), json!(200.0), json!(150.0)),
        viewport_json(json!(1024.0), json!(768.0)),
        json!(2.0),
        json!(0.0),
        json!(0.0),
        json!(400.0),
        json!(300.0),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn step_json(
    step_id: &str,
    failed_recipe: Value,
    current_root: &BORootRef,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    now: &TimePoint,
    deadline: &TimePoint,
    recovery_allowance: u64,
    fallback_text: &str,
    commissioned_job: &str,
    commissioned_target: &str,
    heal_policy: &CatalogVersionPin,
    models_manifest: &Manifest,
    coordinate_entry: Value,
    current_geometry: Value,
    bbox: Value,
) -> Value {
    json!({
        "record_type": "ringmaster_recovery_step",
        "schema_version": "ringmaster-recovery/0.1.0",
        "step_id": step_id,
        "failed_recipe": failed_recipe,
        "current_root": current_root.to_json(),
        "authorization_ref": auth.to_json(),
        "limit": limit.to_json(),
        "now": serde_json::to_value(now).unwrap(),
        "active_deadline": serde_json::to_value(deadline).unwrap(),
        "recovery_allowance_remaining": recovery_allowance,
        "fallback_text": fallback_text,
        "commissioned_job": commissioned_job,
        "commissioned_target": commissioned_target,
        "heal_profile_policy": heal_policy.to_json(),
        "provider_policy": provider_policy_json(),
        "models_binding": models_binding_json(),
        "models_budgets": models_budgets_json(),
        "models_manifest": manifest_json(models_manifest),
        "coordinate_entry": coordinate_entry,
        "current_geometry": current_geometry,
        "bbox_proposal": bbox,
    })
}

fn install_step(
    writer: &AuthenticatedPrincipal,
    value: &Value,
) -> ArtifactReference {
    let bytes = serde_json::to_vec(value).expect("step serializes");
    // Structural check mirrors the implementation gate.
    canonical_digest(&bytes).expect("step structurally valid");
    let reference = ArtifactReference {
        digest: artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "testowner".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(writer, &reference, &bytes).expect("step installs");
    reference
}

fn admit_models_manifest(writer: &AuthenticatedPrincipal, manifest: &Manifest) {
    rm_evidence::append_event(writer, manifest, admission(manifest)).expect("models admit");
}

fn assert_no_bare_null(value: &Value) {
    match value {
        Value::Null => panic!("bare null found"),
        Value::Object(map) => {
            if map.get("value") == Some(&Value::Null) {
                assert!(map.contains_key("reason"), "Missing envelope requires reason");
            } else {
                for item in map.values() {
                    assert_no_bare_null(item);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_bare_null(item);
            }
        }
        _ => {}
    }
}

struct RecoveryFixture {
    principal: AuthenticatedPrincipal,
    session: NativeSession,
    auth: EvidenceRef,
    limit: DurationLimit,
    preparation: PreparedTask,
    handle: DeliveryHandle,
    root: BORootRef,
    models_manifest: Manifest,
    heal_policy: CatalogVersionPin,
}

fn recovery_fixture(tag: &str) -> RecoveryFixture {
    let (princ, mut session, auth, limit, prefix, manifest, bevidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let root = navigate_for_root(&mut session, &auth, &limit, &page);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task_id = format!("task-{tag}");
    let task = make_task(&task_id);
    let scope = make_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix,
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);
    let models_run = format!("rm-rec-models-{tag}");
    let models_manifest = models_manifest(&models_run);
    admit_models_manifest(&princ, &models_manifest);
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    RecoveryFixture {
        principal: princ,
        session,
        auth,
        limit,
        preparation,
        handle,
        root,
        models_manifest,
        heal_policy,
    }
}

fn other_root() -> BORootRef {
    // A distinct native scope: different page/frame/root identity.
    let owner = BOOwner {
        process_id: "proc-other".to_string(),
        boot_id: "boot-other".to_string(),
        os_thread_id: "thread-other".to_string(),
    };
    let page = BOPageRef {
        owner,
        page_id: "page-other".to_string(),
        page_generation: 0,
        profile_digest: artifact_digest(b"profile-other"),
    };
    BORootRef {
        page,
        frame_id: "frame-other".to_string(),
        document_generation: 0,
        root_id: "root-other".to_string(),
        root_kind: "document".to_string(),
    }
}

// ---------------------------------------------------------------------------
// RM-C41: dHash hit with changed geometry/layout blocks action
// ---------------------------------------------------------------------------

#[test]
fn rm_c41_dhash_changed_crop_blocks_action() {
    let tag = "c41-crop";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-abc123";
    let layout = "layout-digest-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    // Changed crop origin: similarity must not authorize action.
    let current = current_geometry_json(
        "step-1",
        dhash,
        &fx.root,
        json!(layout),
        json!(target),
        crop_json(json!(99.0), json!(20.0), json!(200.0), json!(150.0)),
        viewport_json(json!(1024.0), json!(768.0)),
        json!(2.0),
        json!(0.0),
        json!(0.0),
        json!(400.0),
        json!(300.0),
        true,
    );
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("changed crop must block action");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(
        error.detail.contains("crop") || error.detail.contains("revalidated"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c41_dhash_changed_layout_blocks_action() {
    let tag = "c41-layout";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-layout-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, "layout-old", "target-apply-1");
    let current = default_current_geometry("step-1", dhash, &fx.root, "layout-new", "target-apply-1");
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("changed layout must block action");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(error.detail.contains("layout"), "detail: {}", error.detail);
}

#[test]
fn rm_c41_dhash_changed_viewport_blocks_action() {
    let tag = "c41-viewport";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-vp-1";
    let layout = "layout-vp-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    let current = current_geometry_json(
        "step-1",
        dhash,
        &fx.root,
        json!(layout),
        json!(target),
        crop_json(json!(10.0), json!(20.0), json!(200.0), json!(150.0)),
        viewport_json(json!(800.0), json!(600.0)),
        json!(2.0),
        json!(0.0),
        json!(0.0),
        json!(400.0),
        json!(300.0),
        true,
    );
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("changed viewport must block action");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(error.detail.contains("viewport"), "detail: {}", error.detail);
}

#[test]
fn rm_c41_dhash_missing_geometry_not_defaulted() {
    let tag = "c41-missing";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-miss-1";
    let layout = "layout-miss-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    // Missing scale must be explicit, never unit scale.
    let current = current_geometry_json(
        "step-1",
        dhash,
        &fx.root,
        json!(layout),
        json!(target),
        crop_json(json!(10.0), json!(20.0), json!(200.0), json!(150.0)),
        viewport_json(json!(1024.0), json!(768.0)),
        missing("not_observed"),
        json!(0.0),
        json!(0.0),
        json!(400.0),
        json!(300.0),
        true,
    );
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("missing scale must block, never default to one");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(
        error.detail.contains("missing") || error.detail.contains("scale"),
        "detail: {}",
        error.detail
    );
}

#[test]
fn rm_c41_dhash_full_viewport_rejected() {
    let tag = "c41-fullvp";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-full-1";
    let layout = "layout-full-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    // Crop equals the full viewport: never a silent fallback.
    let current = current_geometry_json(
        "step-1",
        dhash,
        &fx.root,
        json!(layout),
        json!(target),
        crop_json(json!(0.0), json!(0.0), json!(1024.0), json!(768.0)),
        viewport_json(json!(1024.0), json!(768.0)),
        json!(2.0),
        json!(0.0),
        json!(0.0),
        json!(2048.0),
        json!(1536.0),
        true,
    );
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("full-viewport fallback must be explicit");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(
        error.detail.contains("full viewport") || error.detail.contains("viewport"),
        "detail: {}",
        error.detail
    );
}

#[test]
fn rm_c41_dhash_permission_denied_blocks_action() {
    let tag = "c41-perm";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-perm-1";
    let layout = "layout-perm-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    let mut current_value =
        default_current_geometry("step-1", dhash, &fx.root, layout, target);
    current_value
        .as_object_mut()
        .expect("object")
        .insert("permission_granted".to_string(), json!(false));
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current_value,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("similarity without permission must not authorize");
    assert_eq!(error.code, "FORBIDDEN");
}

#[test]
fn rm_c41_dhash_changed_root_blocks_action() {
    let tag = "c41-root";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-root-1";
    let layout = "layout-root-1";
    let target = "target-apply-1";
    // Stored entry names a different native root.
    let entry = coordinate_entry_json("step-1", dhash, &other_root(), layout, target);
    let current = default_current_geometry("step-1", dhash, &fx.root, layout, target);
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("changed root must block action");
    assert_eq!(error.code, "REVALIDATION_REQUIRED");
    assert!(error.detail.contains("root"), "detail: {}", error.detail);
}

#[test]
fn rm_c41_failure_routing_wrong_thread_fenced() {
    let tag = "c41-thread";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        missing("not_applicable"),
        missing("not_applicable"),
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = failed_call(
        tag,
        "bo.dom_read",
        "failed",
        "WRONG_THREAD",
        "not_entered",
        "native entry refused: caller thread is not the owning OS thread",
        &fx.auth,
        &fx.limit,
        Vec::new(),
    );
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("wrong thread must fence, not heal");
    assert_eq!(error.code, "FENCED");
}

#[test]
fn rm_c41_failure_routing_side_effect_requires_reconcile() {
    let tag = "c41-sidefx";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        missing("not_applicable"),
        missing("not_applicable"),
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = failed_call(
        tag,
        "bo.dom_write",
        "failed",
        "NATIVE_ERROR",
        "entered",
        "mutation failed after native entry",
        &fx.auth,
        &fx.limit,
        vec![fx.auth.clone()],
    );
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("possible side effect must reconcile, not replay");
    assert_eq!(error.code, "RECONCILIATION_REQUIRED");
}

#[test]
fn rm_c41_failure_routing_budget_exhausted_no_escalation() {
    let tag = "c41-budget";
    let mut fx = recovery_fixture(tag);
    // Active boundary already reached: now beyond deadline.
    let now = test_timepoint(tag, 2000.0);
    let deadline = test_timepoint(tag, 1000.0);
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        missing("not_applicable"),
        missing("not_applicable"),
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let error = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect_err("exhausted deadline must not escalate");
    assert_eq!(error.code, "NOT_ADMITTED");
}

#[test]
fn rm_c41_tier2_compatible_geometry_recovers() {
    let tag = "c41-tier2";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-tier2-1";
    let layout = "layout-tier2-1";
    let target = "target-apply-1";
    // Fully compatible geometry: the hit may revalidate and proceed to Tier 2.
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    let current = default_current_geometry("step-1", dhash, &fx.root, layout, target);
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        missing("not_applicable"),
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    // Predict the Tier 2 prompt: run the same HEAL reduction the recovery
    // will run, then rebuild the identical prompt bytes.
    let dom_request = rm_browseroxide::BODomRead {
        root: fx.root.clone(),
        selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
        depth_limit: 100,
        byte_limit: 1_000_000,
        include_frames: true,
        include_accessible_shadow_roots: true,
    };
    let reduction_ref = rm_reduction::reduce_document(
        &fx.principal,
        &mut fx.session,
        &dom_request,
        "HEAL",
        &fx.heal_policy,
        &fx.auth,
        &fx.limit,
    )
    .expect("pre-reduction succeeds");
    let reduction_bytes = rm_evidence::load_artifact(&fx.principal, &reduction_ref).expect("load");
    let reduction_value: Value = serde_json::from_slice(&reduction_bytes).expect("json");
    let sections = reduction_value
        .get("sections")
        .and_then(Value::as_array)
        .expect("sections");
    let mut section_labels = Vec::new();
    for section in sections {
        section_labels.push(
            section
                .get("section_id")
                .and_then(Value::as_str)
                .expect("section_id")
                .to_string(),
        );
    }
    let limitations_value = reduction_value
        .get("limitations")
        .and_then(Value::as_array)
        .expect("limitations");
    let mut limitations = Vec::new();
    for item in limitations_value {
        limitations.push(item.as_str().expect("limitation").to_string());
    }
    limitations.push(format!(
        "recovery of {} after {} [{}]",
        "css", "bo.dom_read", failed.call_id
    ));
    let heal_reduction = String::from_utf8(reduction_bytes).expect("utf8");
    let prompt_bytes = rm_recovery::build_tier2_prompt_bytes(
        &heal_reduction,
        &format!("fallback-{tag}"),
        ".nonexistent-target",
        "css:.nonexistent-target",
        &section_labels,
        &limitations,
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.root.root_id,
    )
    .expect("prompt builds");
    let prompt_digest = artifact_digest(&prompt_bytes);
    // The live DOM always exposes div#main with text hello: propose a
    // selector that re-resolves there.
    let proposal = serde_json::to_vec(&json!({
        "selector": "#main",
        "strategy": "css",
        "confidence": 0.9,
        "reason": format!("heal {tag} to live main node"),
    }))
    .expect("proposal");
    rm_models::stub_provider_responses(prompt_digest.as_str(), vec![proposal]);
    let recovered = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect("compatible geometry must recover via Tier 2");
    assert_eq!(rm_models::provider_call_count(prompt_digest.as_str()), 1);
    // The returned recipe is a tentative closed TargetRecipe for #main, with
    // no bare nulls, and it re-resolves to the live node.
    let recipe_bytes = rm_evidence::load_artifact(&fx.principal, &recovered).expect("recipe load");
    let recipe_value: Value = serde_json::from_slice(&recipe_bytes).expect("recipe json");
    assert_no_bare_null(&recipe_value);
    let parsed = rm_targets::parse_target_recipe(&recipe_bytes).expect("recipe parses");
    assert_eq!(parsed.strategy, "css");
    assert_eq!(parsed.query, "#main");
    let resolved = rm_targets::resolve_target(
        &fx.principal,
        &mut fx.session,
        &recovered,
        &fx.root,
        &fx.auth,
        &fx.limit,
    )
    .expect("recovered recipe resolves");
    assert_eq!(resolved.nodes.len(), 1);
    rm_models::clear_provider_stub(prompt_digest.as_str());
}

#[test]
fn rm_c41_tier3_compatible_geometry_recovers() {
    let tag = "c41-tier3";
    let mut fx = recovery_fixture(tag);
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-tier3-1";
    let layout = "layout-tier3-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &fx.root, layout, target);
    let current = default_current_geometry("step-1", dhash, &fx.root, layout, target);
    // Valid localized bbox inside the 400x300 image; its center (50,50)
    // transforms to viewport (10 + 50*2 + 0, 20 + 50*2 + 0) = (110,120),
    // inside 1024x768.
    let bbox = json!({"x": 40.0, "y": 40.0, "width": 20.0, "height": 20.0});
    let failed_recipe = failed_recipe_json(&fx.heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &fx.root,
        &fx.auth,
        &fx.limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &fx.preparation.task.task_id,
        "entry-1",
        &fx.heal_policy,
        &fx.models_manifest,
        entry,
        current,
        bbox,
    );
    let step_ref = install_step(&fx.principal, &step_value);
    let failed = safe_failed_dom_read(tag, &fx.auth, &fx.limit);
    let recovered = rm_recovery::recover_target(
        &fx.principal,
        &mut fx.session,
        &fx.preparation,
        &fx.handle,
        &step_ref,
        &failed,
    )
    .expect("compatible Tier 3 geometry must ground to a DOM recipe");
    // Vision-assisted grounding returns a synthetic DOM recipe (text hello),
    // never an invented coordinate-click primitive.
    let recipe_bytes = rm_evidence::load_artifact(&fx.principal, &recovered).expect("recipe load");
    let recipe_value: Value = serde_json::from_slice(&recipe_bytes).expect("recipe json");
    assert_no_bare_null(&recipe_value);
    let parsed = rm_targets::parse_target_recipe(&recipe_bytes).expect("recipe parses");
    assert_eq!(parsed.strategy, "text");
    assert_eq!(parsed.query, "hello");
    let resolved = rm_targets::resolve_target(
        &fx.principal,
        &mut fx.session,
        &recovered,
        &fx.root,
        &fx.auth,
        &fx.limit,
    )
    .expect("grounded recipe resolves");
    assert_eq!(resolved.nodes.len(), 1);
}

#[test]
fn rm_c41_tier3_capture_unmapped_is_limitation() {
    let tag = "c41-capunmap";
    // Session whose binding leaves bo.capture unmapped.
    let (princ, mut session, auth, limit, prefix, manifest, bevidence) =
        open_session_with_unmapped(tag, &["bo.capture"]);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let root = navigate_for_root(&mut session, &auth, &limit, &page);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task_id = format!("task-{tag}");
    let task = make_task(&task_id);
    let scope = make_scope(&manifest, &journal_id, tag);
    let configuration = make_configuration(&princ, bevidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        prefix,
        &princ,
        tag,
    );
    let handle = make_handle(&preparation, &princ, tag);
    let models_run = format!("rm-rec-models-{tag}");
    let models_manifest = models_manifest(&models_run);
    admit_models_manifest(&princ, &models_manifest);
    let heal_policy = test_pin(&format!("heal-{tag}"), "1.0.0");
    let now = test_timepoint(tag, 100.0);
    let deadline = test_timepoint(tag, 1000.0);
    let dhash = "dhash-capunmap-1";
    let layout = "layout-capunmap-1";
    let target = "target-apply-1";
    let entry = coordinate_entry_json("step-1", dhash, &root, layout, target);
    let current = default_current_geometry("step-1", dhash, &root, layout, target);
    let bbox = json!({"x": 40.0, "y": 40.0, "width": 20.0, "height": 20.0});
    let failed_recipe = failed_recipe_json(&heal_policy, json!(format!("fallback-{tag}")));
    let step_value = step_json(
        "step-1",
        failed_recipe,
        &root,
        &auth,
        &limit,
        &now,
        &deadline,
        5,
        &format!("fallback-{tag}"),
        &preparation.task.task_id,
        "entry-1",
        &heal_policy,
        &models_manifest,
        entry,
        current,
        bbox,
    );
    let step_ref = install_step(&princ, &step_value);
    let failed = safe_failed_dom_read(tag, &auth, &limit);
    let error = rm_recovery::recover_target(
        &princ,
        &mut session,
        &preparation,
        &handle,
        &step_ref,
        &failed,
    )
    .expect_err("unmapped capture must be an explicit limitation");
    assert_eq!(error.code, "UNSUPPORTED_MAPPING");
    assert!(
        error.detail.contains("capture") || error.detail.contains("unmapped"),
        "detail: {}",
        error.detail
    );
}


