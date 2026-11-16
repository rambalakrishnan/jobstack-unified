//! Conformance for RM-C44 (partial schema extraction).
//!
//! Every test name carries `rm_c44` so the verification filter
//! `cargo test -p rm_extraction -- rm_c44` selects the suite.

use rm_authority::{
    authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, ExecutionMode, Manifest,
    WorkScope,
};
use rm_browseroxide::{
    open_native_session, BODomExport, BODomNode, BONodeRef, BOOwner, BOPageRef, BORootRef,
    MaybeNodeParent, NativeSession,
};
use rm_catalog::{
    BO_CAPABILITIES, BO_PRIMITIVES, BOBindingDescriptor, BOMapping, CapabilityDescriptor,
    CapabilityRecord, ComponentIdentity, DurationLimit, SubjectIdentity,
    VersionPin as CatalogVersionPin, BO_RECORD_TYPE as CATALOG_BO_RECORD,
    BO_SCHEMA_VERSION as CATALOG_BO_SCHEMA, CAPABILITY_RECORD_TYPE, CAPABILITY_SCHEMA_VERSION,
    MaybeDigest as CatalogMaybeDigest, MaybeString as CatalogMaybeString,
    MaybeVersionPin as CatalogMaybePin,
};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload, JournalPrefix,
    PositiveInteger,
};
use rm_extraction::{PARTIAL_SCHEMA_ID, STRICT_SCHEMA_ID};
use rm_leases::LeaseRecord;
use rm_preparation::{
    AssistanceRecord, ConfigurationPin, ContextPolicy, EntryPoint, PermittedOrigin, PreparedTask,
    StatePolicy, SuccessCriterion, TaskBudgets, TaskEnvelope, TaskInput,
};
use rm_time::{
    MaybeString as TimeMaybeString, MaybeTimePoint, MeasurementOrigin, Missing, TimePoint,
    UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
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

fn test_root(tag: &str) -> BORootRef {
    BORootRef {
        page: BOPageRef {
            owner: BOOwner {
                process_id: format!("proc-{tag}"),
                boot_id: format!("boot-{tag}"),
                os_thread_id: format!("thread-{tag}"),
            },
            page_id: format!("page-{tag}"),
            page_generation: 0,
            profile_digest: artifact_digest(format!("profile-{tag}").as_bytes()),
        },
        frame_id: format!("frame-{tag}"),
        document_generation: 0,
        root_id: format!("root-{tag}"),
        root_kind: "document".to_string(),
    }
}

fn test_node(
    root: &BORootRef,
    node_id: &str,
    node_name: &str,
    attributes: &[(&str, &str)],
    text: Option<&str>,
) -> BODomNode {
    let mut map = BTreeMap::new();
    for (key, value) in attributes {
        map.insert(key.to_string(), value.to_string());
    }
    BODomNode {
        node_ref: BONodeRef {
            root: root.clone(),
            node_id: node_id.to_string(),
            node_generation: 0,
        },
        parent: MaybeNodeParent::Missing(Missing::new("not_applicable")),
        node_name: node_name.to_string(),
        attributes: map,
        text: match text {
            Some(value) => TimeMaybeString::Text(value.to_string()),
            None => TimeMaybeString::Missing(Missing::new("not_observed")),
        },
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
    let writer = principal(&format!("rm-ext-bind-{test}"));
    let run = format!("rm-ext-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-ext-evidence-{test}").into_bytes();
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
        build_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-ext-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(artifact_digest(
            b"rm-ext-engine-config",
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
        configuration_digest: artifact_digest(b"rm-ext-config"),
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

fn bo_descriptor(prefix: &JournalPrefix, evidence: &EvidenceRef) -> BOBindingDescriptor {
    let engine = bo_engine();
    let subject = bo_subject(&engine);
    BOBindingDescriptor {
        record_type: CATALOG_BO_RECORD.to_string(),
        schema_version: CATALOG_BO_SCHEMA.to_string(),
        binding_id: "bo-binding-1".to_string(),
        binding_build: CatalogVersionPin {
            id: "bo-binding-1".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(b"rm-ext-binding-build"),
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
                artifact_digest: artifact_digest(b"rm-ext-catalog"),
            },
            evidence_prefix: prefix.clone(),
            supersedes: CatalogMaybeDigest::Missing(Missing::new("not_applicable")),
            capabilities: BO_CAPABILITIES.iter().map(|id| bo_record(id)).collect(),
        },
        primitive_mappings: BO_PRIMITIVES
            .iter()
            .map(|primitive| bo_mapped(primitive, evidence))
            .collect(),
        session_storage_model: "process_global".to_string(),
        session_isolation_refs: Vec::new(),
        privacy_policy: CatalogVersionPin {
            id: "bo-privacy".to_string(),
            version: "0.1.0".to_string(),
            artifact_digest: artifact_digest(b"rm-ext-privacy"),
        },
        evidence_prefix: prefix.clone(),
    }
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
    let (_bw, bprefix, bevidence) = journal_fixture(test);
    let binding = bo_descriptor(&bprefix, &bevidence);
    let princ = principal(&format!("rm-ext-{test}"));
    let run = format!("rm-ext-run-{test}");
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
    let writer = principal(&format!("rm-ext-writer-{tag}"));
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
            client: rm_browseroxide::MaybeClient::Missing(Missing::new("not_applicable")),
        },
        auth,
        limit,
    )
    .expect("page_create");
    assert_eq!(out.record.return_state, "returned");
    out.value.expect("page")
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
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        learning_state: StatePolicy {
            mode: "not_applicable".to_string(),
            requirement: "best_effort".to_string(),
            resource_ref: CatalogMaybeString::Missing(Missing::new("not_applicable")),
            baseline: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
    }
}

fn make_task(
    task_id: &str,
    task_type: &str,
    schema_id: &str,
    inputs: Vec<TaskInput>,
) -> TaskEnvelope {
    TaskEnvelope {
        record_type: "connector_task".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        task_id: task_id.to_string(),
        task_type: task_type.to_string(),
        entry: EntryPoint {
            logical_id: "entry-1".to_string(),
            url: "https://example.test/jobs".to_string(),
        },
        goal: format!("extract job listings for {task_id}"),
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
        budgets: test_budgets(),
        context_policy: test_context(),
        output_schema: CatalogMaybePin::Present(CatalogVersionPin {
            id: schema_id.to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: artifact_digest(format!("{schema_id}-1").as_bytes()),
        }),
    }
}

fn make_scope(manifest: &Manifest, journal_id: &str, tag: &str, activity: &str) -> WorkScope {
    WorkScope {
        activity: activity.to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id.to_string(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec![format!("grant-extract-{tag}")],
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

#[allow(clippy::too_many_arguments)]
fn make_preparation(
    preparation_id: &str,
    scope: WorkScope,
    configuration: ConfigurationPin,
    task: TaskEnvelope,
    planning_refs: Vec<EvidenceRef>,
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
            assistance_track: "track-extract".to_string(),
            planner_identity: CatalogMaybeString::Text("planner-1".to_string()),
            plan: rm_preparation::MaybeArtifact::Missing(Missing::new("not_applicable")),
            online_replanning: false,
            description: "declared extraction assistance".to_string(),
        },
        planning_evidence_refs: planning_refs,
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

fn satisfied_stabilization() -> rm_reduction::StabilizationObservation {
    let policy = rm_reduction::StabilizationPolicy::permissive(test_pin("stable", "1"));
    rm_reduction::observe_stabilization(&policy, "satisfied", "satisfied", "satisfied", Vec::new(), Vec::new())
        .expect("satisfied stabilization")
}

fn make_reduction_source(
    writer: &AuthenticatedPrincipal,
    tag: &str,
    node_texts: Vec<(&str, &str)>,
    auth: &EvidenceRef,
) -> ArtifactReference {
    let root = test_root(&format!("ext-{tag}"));
    let mut nodes = Vec::new();
    for (node_id, text) in node_texts {
        nodes.push(test_node(&root, node_id, "div", &[("id", node_id)], Some(text)));
    }
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root,
        nodes,
        boundaries: Vec::new(),
        completeness: "complete".to_string(),
        limitations: Vec::new(),
    };
    let reduction = rm_reduction::reduce_export(
        &export,
        "EXTRACT",
        &test_pin("extract-policy", "1"),
        rm_reduction::EXTRACT_CEILING,
        std::slice::from_ref(auth),
        &satisfied_stabilization(),
    )
    .expect("reduction succeeds");
    let bytes = reduction.to_bytes().expect("reduction serializes");
    install_bytes(writer, &bytes, "artifact", "application/json")
}

fn make_html_source(
    writer: &AuthenticatedPrincipal,
    tag: &str,
    html: &str,
) -> ArtifactReference {
    let bytes = format!("<!-- {tag} -->\n{html}").into_bytes();
    install_bytes(writer, &bytes, "artifact", "text/html")
}

fn make_query_input(
    writer: &AuthenticatedPrincipal,
    tag: &str,
    query: &str,
) -> TaskInput {
    let bytes = format!("{query} {tag}").into_bytes();
    let content = install_bytes(writer, &bytes, "artifact", "text/plain");
    TaskInput {
        name: "query".to_string(),
        purpose: "relevance filter".to_string(),
        content,
    }
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

// ---------------------------------------------------------------------------
// RM-C44: partial schema extraction
// ---------------------------------------------------------------------------

#[test]
fn rm_c44_partial_schema_permits_valid_partial() {
    let tag = "c44-partial";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    // Only title is observable; company is absent and must not be invented.
    let source = make_reduction_source(
        &princ,
        tag,
        vec![
            ("n1", &format!("Title: Senior Engineer {tag}")),
            ("n2", "Team overview and responsibilities without an employer marker"),
        ],
        &auth,
    );
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(&format!("task-{tag}"), "extract", PARTIAL_SCHEMA_ID, Vec::new());
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task.clone(),
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let output =
        rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
            .expect("partial schema permits valid partial TaskOutput");
    assert_eq!(output.kind, "task_output");
    assert_eq!(output.name, task.task_id);
    assert_eq!(output.output_schema.id, PARTIAL_SCHEMA_ID);
    assert_eq!(output.completeness, "partial");
    assert!(!output.evidence_refs.is_empty());
    assert!(!output.limitations.is_empty());
    for limitation in &output.limitations {
        assert!(!limitation.is_empty());
    }
    let joined = output.limitations.join("\n");
    assert!(joined.contains("zero model calls"), "limitations: {joined}");
    assert!(joined.contains("deterministic"), "limitations: {joined}");
    assert!(
        joined.contains("scoped to the output contract"),
        "limitations: {joined}"
    );
    output.validate().expect("TaskOutput validates");
    let content_bytes =
        rm_evidence::load_artifact(&princ, &output.content).expect("content loads");
    let content: Value = serde_json::from_slice(&content_bytes).expect("content is JSON");
    assert_no_bare_null(&content);
    let object = content.as_object().expect("content object");
    assert_eq!(object.len(), 3, "content must be exactly title/company/schema_incomplete");
    let title = object.get("title").and_then(Value::as_str).expect("title string");
    assert!(title.contains("Senior Engineer"), "title: {title}");
    let company = object.get("company").expect("company present");
    let company_map = company.as_object().expect("company is a Missing envelope, not invented");
    assert_eq!(company_map.get("value"), Some(&Value::Null));
    assert_eq!(
        company_map.get("reason").and_then(Value::as_str),
        Some("not_observed")
    );
    let incomplete = object
        .get("schema_incomplete")
        .and_then(Value::as_array)
        .expect("schema_incomplete array");
    assert_eq!(incomplete.len(), 1);
    assert_eq!(incomplete[0].as_str(), Some("company"));
}

#[test]
fn rm_c44_strict_schema_rejects_partial_as_diagnostic_only() {
    let tag = "c44-strict-diag";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let source = make_reduction_source(
        &princ,
        tag,
        vec![("n1", &format!("Title: Support Engineer {tag}"))],
        &auth,
    );
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(&format!("task-{tag}"), "extract", STRICT_SCHEMA_ID, Vec::new());
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task.clone(),
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let error = rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
        .expect_err("strict schema must not publish partial TaskOutput");
    assert_eq!(error.code, "SCHEMA_INCOMPLETE", "detail: {} handle: {:?}", error.detail, error.handle);
    assert!(error.detail.contains("diagnostic-only"), "detail: {}", error.detail);
    assert!(error.detail.contains("company"), "detail: {}", error.detail);
    assert!(
        error.detail.contains("does not waive schema validation"),
        "detail: {}",
        error.detail
    );
    let handle = error.handle.expect("diagnostic handle carries the artifact reference");
    let handle_value: Value = serde_json::from_str(&handle).expect("handle is JSON");
    let diagnostic_ref = ArtifactReference::from_json(&handle_value).expect("handle parses");
    let diagnostic_bytes =
        rm_evidence::load_artifact(&princ, &diagnostic_ref).expect("diagnostic loads");
    rm_wire::validate_record("diagnostic/v1", &diagnostic_bytes)
        .expect("diagnostic is wire-valid");
    let diagnostic: Value =
        serde_json::from_slice(&diagnostic_bytes).expect("diagnostic is JSON");
    assert_no_bare_null(&diagnostic);
    let object = diagnostic.as_object().expect("diagnostic object");
    assert_eq!(object.get("record_type").and_then(Value::as_str), Some("diagnostic"));
    let result = object.get("result").and_then(Value::as_object).expect("result object");
    let partial_title = result.get("partial_title").and_then(Value::as_str).expect("partial title preserved");
    assert!(partial_title.contains("Support Engineer"), "partial title: {partial_title}");
    let partial_company = result.get("partial_company").expect("partial company present");
    assert!(
        partial_company.as_object().is_some(),
        "missing company is a Missing envelope, not invented"
    );
    let missing = result.get("missing_fields").and_then(Value::as_array).expect("missing fields");
    assert_eq!(missing.len(), 1);
    assert_eq!(missing[0].as_str(), Some("company"));
}

#[test]
fn rm_c44_complete_extraction_publishes_task_output() {
    let tag = "c44-complete";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let source = make_reduction_source(
        &princ,
        tag,
        vec![
            ("n1", &format!("Title: Staff Engineer {tag}")),
            ("n2", &format!("Company: Acme {tag}")),
        ],
        &auth,
    );
    // Query retains both carriers, exercising pinned relevance filtering.
    let query = make_query_input(&princ, tag, "Engineer Acme");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(
        &format!("task-{tag}"),
        "extract",
        STRICT_SCHEMA_ID,
        vec![query],
    );
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task.clone(),
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let output =
        rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
            .expect("complete extraction publishes TaskOutput");
    assert_eq!(output.completeness, "complete");
    let joined = output.limitations.join("\n");
    assert!(joined.contains("query supplied"), "limitations: {joined}");
    assert!(joined.contains("relevance filtering"), "limitations: {joined}");
    assert!(joined.contains("zero model calls"), "limitations: {joined}");
    output.validate().expect("TaskOutput validates");
    let content_bytes =
        rm_evidence::load_artifact(&princ, &output.content).expect("content loads");
    let content: Value = serde_json::from_slice(&content_bytes).expect("content is JSON");
    assert_no_bare_null(&content);
    let object = content.as_object().expect("content object");
    assert_eq!(object.len(), 2, "strict content is exactly title/company");
    assert!(!object.contains_key("schema_incomplete"), "strict schema defines no schema_incomplete");
    let title = object.get("title").and_then(Value::as_str).expect("title");
    let company = object.get("company").and_then(Value::as_str).expect("company");
    assert!(title.contains("Staff Engineer"), "title: {title}");
    assert!(company.contains("Acme"), "company: {company}");
}

#[test]
fn rm_c44_read_only_enforced_and_no_live_shadow_from_raw_html() {
    let tag = "c44-rawhtml";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let html = format!(
        "<html><body><h1>Title: Frontend Engineer {tag}</h1><p>Join the team.</p><script>alert(1)</script></body></html>"
    );
    let source = make_html_source(&princ, tag, &html);
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(&format!("task-{tag}"), "discover_jobs", PARTIAL_SCHEMA_ID, Vec::new());
    let scope = make_scope(&manifest, &journal_id, tag, "discover_jobs");
    let configuration = make_configuration(&princ, binding_evidence.clone(), tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task.clone(),
        vec![auth.clone()],
        prefix.clone(),
        &princ,
        tag,
    );
    let output =
        rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
            .expect("raw HTML partial extraction succeeds");
    assert_eq!(output.completeness, "partial");
    let joined = output.limitations.join("\n");
    assert!(joined.contains("raw HTML"), "limitations: {joined}");
    assert!(
        joined.contains("no live shadow/frame"),
        "limitations: {joined}"
    );
    assert!(!joined.contains("alert"), "script must not leak: {joined}");
    let content_bytes =
        rm_evidence::load_artifact(&princ, &output.content).expect("content loads");
    let content: Value = serde_json::from_slice(&content_bytes).expect("content is JSON");
    assert_no_bare_null(&content);
    let title = content.get("title").and_then(Value::as_str).expect("title");
    assert!(title.contains("Frontend Engineer"), "title: {title}");
    // Application work is never dispatchable through extraction.
    let mut apply_task = make_task(&format!("task-{tag}-apply"), "apply", STRICT_SCHEMA_ID, Vec::new());
    apply_task.effect_policy = "commissioned_application".to_string();
    apply_task.permitted_interfaces = vec!["ordinary_browser".to_string()];
    apply_task.output_schema =
        CatalogMaybePin::Missing(Missing::new("not_applicable"));
    let apply_scope = make_scope(&manifest, &journal_id, &format!("{tag}-apply"), "apply");
    let apply_configuration = make_configuration(&princ, binding_evidence, &format!("{tag}-apply"));
    let apply_preparation = make_preparation(
        &format!("prep-{tag}-apply"),
        apply_scope,
        apply_configuration,
        apply_task,
        vec![auth.clone()],
        prefix,
        &princ,
        &format!("{tag}-apply"),
    );
    let rejected = rm_extraction::extract_output(&princ, &mut session, &apply_preparation, &page, &source)
        .expect_err("apply tasks are rejected");
    assert_eq!(rejected.code, "INVALID_REQUEST");
}

#[test]
fn rm_c44_unknown_when_nothing_established_and_no_fabrication() {
    let tag = "c44-unknown";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let source = make_reduction_source(
        &princ,
        tag,
        vec![
            ("n1", &format!("Welcome to the jobs page {tag}")),
            ("n2", "Cookie policy and navigation footer"),
        ],
        &auth,
    );
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(&format!("task-{tag}"), "extract", PARTIAL_SCHEMA_ID, Vec::new());
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let output =
        rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
            .expect("empty extraction yields unknown, not fabrication");
    assert_eq!(output.completeness, "unknown");
    output.validate().expect("TaskOutput validates");
    let content_bytes =
        rm_evidence::load_artifact(&princ, &output.content).expect("content loads");
    let content: Value = serde_json::from_slice(&content_bytes).expect("content is JSON");
    assert_no_bare_null(&content);
    let object = content.as_object().expect("content object");
    for key in ["title", "company"] {
        let field = object.get(key).expect("field present");
        let map = field.as_object().expect("unestablished field is a Missing envelope");
        assert_eq!(map.get("value"), Some(&Value::Null));
        assert_eq!(map.get("reason").and_then(Value::as_str), Some("not_observed"));
    }
    let incomplete = object.get("schema_incomplete").and_then(Value::as_array).expect("incomplete");
    assert_eq!(incomplete.len(), 2);
}

#[test]
fn rm_c44_unbounded_export_rejected_before_extraction() {
    let tag = "c44-export-reject";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let root = test_root(&format!("ext-{tag}"));
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root,
        nodes: vec![test_node(
            &test_root(&format!("ext-{tag}")),
            "n1",
            "div",
            &[("id", "n1")],
            Some(&format!("Title: Engineer {tag}")),
        )],
        boundaries: Vec::new(),
        completeness: "complete".to_string(),
        limitations: Vec::new(),
    };
    let export_bytes = serde_json::to_vec(&export.to_json()).expect("export serializes");
    rm_wire::validate_record("browseroxide_dom_export/v1", &export_bytes)
        .expect("export fixture is wire-valid");
    let source = install_bytes(&princ, &export_bytes, "artifact", "application/json");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let task = make_task(&format!("task-{tag}"), "extract", PARTIAL_SCHEMA_ID, Vec::new());
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let error = rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
        .expect_err("unbounded export must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error.detail.contains("bounded"), "detail: {}", error.detail);
    assert!(error.detail.contains("reduction"), "detail: {}", error.detail);
}

#[test]
fn rm_c44_effect_policy_mutation_rejected() {
    let tag = "c44-effect";
    let (princ, mut session, auth, limit, prefix, manifest, binding_evidence) = open_session(tag);
    let page = make_page_for(&mut session, &auth, &limit, tag);
    let source = make_reduction_source(
        &princ,
        tag,
        vec![("n1", &format!("Title: Engineer {tag}"))],
        &auth,
    );
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("jid");
    let mut task = make_task(&format!("task-{tag}"), "extract", PARTIAL_SCHEMA_ID, Vec::new());
    task.effect_policy = "commissioned_application".to_string();
    let scope = make_scope(&manifest, &journal_id, tag, "extract");
    let configuration = make_configuration(&princ, binding_evidence, tag);
    let preparation = make_preparation(
        &format!("prep-{tag}"),
        scope,
        configuration,
        task,
        vec![auth.clone()],
        prefix,
        &princ,
        tag,
    );
    let error = rm_extraction::extract_output(&princ, &mut session, &preparation, &page, &source)
        .expect_err("mutation effect policy must be rejected");
    assert_eq!(error.code, "FORBIDDEN");
}
