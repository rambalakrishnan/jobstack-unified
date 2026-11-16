//! Conformance for RM-C13..C16. Each test name carries its token.

use rm_authority::{authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, Manifest};
use rm_browseroxide::{
    open_native_session, BODomExport, BODomNode, BODomRead, BONodeRef, BOOwner, BOPageRef, BORootRef,
    BOBoundary, MaybeNodeParent, MaybeRoot, NativeSession,
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
use rm_leases::LeaseRecord;
use rm_reduction::{
    ceiling_for_profile, observe_stabilization, reduce_document, reduce_export,
    validate_stabilization_measurements, StabilizationPolicy, EXTRACT_CEILING, HEAL_CEILING,
};
use rm_time::{
    ClockBasis, ClockDescriptor, Estimate, MaybeNumber, MaybeString as TimeMaybeString,
    MaybeTimePoint, Measurement, MeasurementOrigin, Method, Missing, Quantity, Scope, ScopeKind,
    TimePoint, UtcAnnotation, Censoring,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::collections::BTreeMap;
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

fn test_boundary(
    boundary_id: &str,
    kind: &str,
    root: Option<BORootRef>,
    access: &str,
    limitation: Option<&str>,
) -> BOBoundary {
    BOBoundary {
        boundary_id: boundary_id.to_string(),
        kind: kind.to_string(),
        root: match root {
            Some(root) => MaybeRoot::Present(root),
            None => MaybeRoot::Missing(Missing::new("not_observed")),
        },
        access: access.to_string(),
        limitation: match limitation {
            Some(text) => TimeMaybeString::Text(text.to_string()),
            None => TimeMaybeString::Missing(Missing::new("not_applicable")),
        },
    }
}

fn test_evidence(tag: &str) -> EvidenceRef {
    EvidenceRef {
        journal_id: format!("journal-{tag}"),
        sequence: PositiveInteger::new(1).expect("pos"),
        event_id: format!("event-{tag}"),
        event_hash: artifact_digest(format!("event-{tag}").as_bytes()),
        pointer: String::new(),
    }
}

fn satisfied_stabilization(pin: CatalogVersionPin) -> rm_reduction::StabilizationObservation {
    let policy = StabilizationPolicy::permissive(pin);
    observe_stabilization(&policy, "satisfied", "satisfied", "satisfied", Vec::new(), Vec::new())
        .expect("satisfied stabilization")
}


// Session helpers (end-to-end for reduce_document).

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
    let writer = principal(&format!("rm-red-bind-{test}"));
    let run = format!("rm-red-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-red-evidence-{test}").into_bytes();
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
        build_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-red-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-red-engine-config")),
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
        configuration_digest: artifact_digest(b"rm-red-config"),
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
        native_symbol: CatalogMaybeString::Text(format!("native_{}", primitive.replace('.', "_"))),
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
            artifact_digest: artifact_digest(b"rm-red-binding-build"),
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
                artifact_digest: artifact_digest(b"rm-red-catalog"),
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
            artifact_digest: artifact_digest(b"rm-red-privacy"),
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

fn open_session(test: &str) -> (AuthenticatedPrincipal, NativeSession, EvidenceRef, DurationLimit) {
    let (_bw, bprefix, bevidence) = journal_fixture(test);
    let binding = bo_descriptor(&bprefix, &bevidence);
    let princ = principal(&format!("rm-red-{test}"));
    let run = format!("rm-red-run-{test}");
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
    let session = open_native_session(princ.clone(), manifest, binding, lease).expect("open");
    let limit = test_limit();
    (princ, session, auth, limit)
}

fn make_page_for(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    tag: &str,
) -> rm_browseroxide::BOPageRef {
    let writer = principal(&format!("rm-red-writer-{tag}"));
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

fn navigate_for_root(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    page: &rm_browseroxide::BOPageRef,
) -> BORootRef {
    let out = rm_browseroxide::navigate(
        session,
        &rm_browseroxide::BONavigate {
            page: page.clone(),
            url: "https://example.test/".to_string(),
            client: rm_browseroxide::MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: test_pin("navigation", "1"),
        },
        auth,
        limit,
    )
    .expect("navigate");
    assert_eq!(out.record.return_state, "returned");
    let nav = out.value.expect("nav");
    match nav.document_root {
        MaybeRoot::Present(root) => root,
        MaybeRoot::Missing(_) => panic!("navigate must expose a document root"),
    }
}

// ---------------------------------------------------------------------------
// RM-C13: open roots and readable/unreadable nested frames
// ---------------------------------------------------------------------------

#[test]
fn rm_c13_scoped_content_and_explicit_boundaries() {
    let root = test_root("c13-main");
    let shadow_root = test_root("c13-shadow");
    let frame_root = test_root("c13-frame1");
    let nodes = vec![
        test_node(&root, "n1", "div", &[("id", "main")], Some("Welcome   to\n test")),
        test_node(&root, "n2", "script", &[], Some("alert(1)")),
        test_node(
            &root,
            "n3",
            "img",
            &[("alt", "Company logo")],
            None,
        ),
        test_node(&root, "n4", "svg", &[], None),
        test_node(&root, "n5", "iframe", &[("id", "frame1")], None),
        test_node(&root, "n6", "iframe", &[("id", "frame2")], None),
        test_node(&root, "n7", "button", &[("id", "submit")], Some("Submit")),
        test_node(&root, "n8", "style", &[], Some(".x{color:red}")),
    ];
    let boundaries = vec![
        test_boundary("shadow-1", "open_shadow", Some(shadow_root.clone()), "complete", None),
        test_boundary("frame-1", "frame", Some(frame_root.clone()), "complete", None),
        test_boundary(
            "frame-2",
            "frame",
            None,
            "unavailable",
            Some("frame-2 is cross-origin and unreadable in this build"),
        ),
    ];
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root: root.clone(),
        nodes,
        boundaries,
        completeness: "complete".to_string(),
        limitations: Vec::new(),
    };
    let pin = test_pin("reduction-extract", "1");
    let stabilization = satisfied_stabilization(test_pin("stabilization", "1"));
    let source_refs = vec![test_evidence("c13")];

    // EXTRACT: scoped content plus explicit boundaries.
    let reduction = reduce_export(&export, "EXTRACT", &pin, EXTRACT_CEILING, &source_refs, &stabilization)
        .expect("extract reduces");
    assert_eq!(reduction.profile, "EXTRACT");
    assert_eq!(reduction.completeness, "partial");
    assert!(
        reduction.limitations.iter().any(|limitation| limitation.contains("incomplete access")),
        "incomplete access must be disclosed: {:?}",
        reduction.limitations
    );
    // Main section: normalized text, image markers, excluded tags dropped.
    let main = reduction.sections.iter().find(|section| section.section_id == "section-main").expect("main section");
    assert!(main.semantic_text.contains("Welcome to test"), "whitespace must normalize: {:?}", main.semantic_text);
    assert!(main.semantic_text.contains("[image: Company logo]"), "observed alt must become a marker: {:?}", main.semantic_text);
    assert!(main.semantic_text.contains("[image]"), "unlabeled svg must not invent a label: {:?}", main.semantic_text);
    assert!(!main.semantic_text.contains("alert(1)"), "script content must be excluded");
    assert!(!main.semantic_text.contains(".x{color:red}"), "style content must be excluded");
    // Unique source nodes.
    let mut seen = std::collections::BTreeSet::new();
    for node in &main.source_nodes {
        assert!(seen.insert(node.to_json().to_string()), "source_nodes must be unique");
    }
    // Scoped sections for accessible roots; explicit record for the unreadable frame.
    assert_eq!(reduction.sections.len(), 3, "main plus two accessible scoped sections");
    assert_eq!(reduction.boundaries.len(), 3);
    let frame2 = reduction.boundaries.iter().find(|boundary| boundary.boundary.boundary_id == "frame-2").expect("frame-2 boundary");
    assert_eq!(frame2.boundary.access, "unavailable");
    match &frame2.child_section_id {
        TimeMaybeString::Missing(missing) => assert!(!missing.reason.is_empty()),
        TimeMaybeString::Text(_) => panic!("unavailable frame must not gain a child section"),
    }
    // Scope preservation: child roots differ from the main root.
    let child_roots: Vec<String> = reduction.sections.iter().skip(1).map(|section| section.root.root_id.clone()).collect();
    for child in &child_roots {
        assert_ne!(child, &root.root_id, "scoped sections must retain their own root scope");
    }
    // HEAL: interactive nodes retained, layout wrappers stripped.
    let heal_pin = test_pin("reduction-heal", "1");
    let heal = reduce_export(&export, "HEAL", &heal_pin, HEAL_CEILING, &source_refs, &stabilization)
        .expect("heal reduces");
    let heal_main = heal.sections.iter().find(|section| section.section_id == "section-main").expect("heal main");
    assert!(heal_main.semantic_text.contains("Submit"), "HEAL must retain interactive nodes: {:?}", heal_main.semantic_text);
    assert!(!heal_main.semantic_text.contains("Welcome to test"), "HEAL must strip layout-only wrappers: {:?}", heal_main.semantic_text);
    assert_eq!(heal.boundaries.len(), 3, "HEAL preserves boundary records");

    // End-to-end: native traversal on the owner thread installs a closed artifact.
    let (princ, mut session, auth, limit) = open_session("c13-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c13-e2e");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let request = BODomRead {
        root: live_root.clone(),
        selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
        depth_limit: 10,
        byte_limit: 1_000_000,
        include_frames: true,
        include_accessible_shadow_roots: true,
    };
    let artifact = reduce_document(&princ, &mut session, &request, "EXTRACT", &pin, &auth, &limit)
        .expect("reduce_document installs");
    assert_eq!(artifact.owner_domain, "artifact");
    let bytes = rm_evidence::load_artifact(&princ, &artifact).expect("load reduction");
    let value: Value = serde_json::from_slice(&bytes).expect("reduction is JSON");
    rm_reduction::RingmasterReduction::validate_json(&value).expect("closed shape validates");
    assert_eq!(value["record_type"], "ringmaster_dom_reduction");
    assert_eq!(value["profile"], "EXTRACT");
    // Stabilization is unknown without native instrumentation, so the live
    // reduction is honestly partial.
    assert_eq!(value["completeness"], "partial");
    assert!(value["limitations"].as_array().map(|items| !items.is_empty()).unwrap_or(false));
}

// ---------------------------------------------------------------------------
// RM-C14: closed-root access unavailable
// ---------------------------------------------------------------------------

#[test]
fn rm_c14_closed_root_no_complete_empty_tree() {
    let root = test_root("c14-main");
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root: root.clone(),
        nodes: Vec::new(),
        boundaries: vec![test_boundary(
            "closed-1",
            "closed_shadow",
            None,
            "unavailable",
            Some("closed shadow root is not accessible in this build"),
        )],
        completeness: "unknown".to_string(),
        limitations: vec!["source capture reports unknown completeness".to_string()],
    };
    let pin = test_pin("reduction-extract", "1");
    // Even with satisfied stabilization, unavailable access forbids completeness.
    let stabilization = satisfied_stabilization(test_pin("stabilization", "1"));
    let source_refs = vec![test_evidence("c14")];
    let reduction = reduce_export(&export, "EXTRACT", &pin, EXTRACT_CEILING, &source_refs, &stabilization)
        .expect("closed-root export reduces");
    assert_ne!(reduction.completeness, "complete", "missing access is not an empty complete tree");
    assert!(
        reduction.limitations.iter().any(|limitation| limitation.contains("explicit boundaries")),
        "limitations must explain the explicit boundary: {:?}",
        reduction.limitations
    );
    assert_eq!(reduction.boundaries.len(), 1);
    assert_eq!(reduction.boundaries[0].boundary.access, "unavailable");
    assert_eq!(reduction.sections.len(), 1);
    assert!(reduction.sections[0].semantic_text.is_empty());
    assert!(reduction.sections[0].source_nodes.is_empty());
    // HEAL agrees: no profile may substitute a complete empty tree.
    let heal = reduce_export(&export, "HEAL", &test_pin("reduction-heal", "1"), HEAL_CEILING, &source_refs, &stabilization)
        .expect("heal reduces closed root");
    assert_ne!(heal.completeness, "complete");
    assert_eq!(heal.boundaries.len(), 1);
}

// ---------------------------------------------------------------------------
// RM-C15: reduction overflow and multibyte boundary
// ---------------------------------------------------------------------------

#[test]
fn rm_c15_overflow_partial_or_size_failure_valid_utf8() {
    let root = test_root("c15-main");
    // Large multibyte content: ASCII plus 4-byte emoji.
    let big_text = format!("{}{}", "a".repeat(3000), "🌍".repeat(800));
    let mut nodes = Vec::new();
    for index in 0..4 {
        nodes.push(test_node(
            &root,
            &format!("big-{index}"),
            "div",
            &[("id", "content")],
            Some(&big_text),
        ));
    }
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root: root.clone(),
        nodes,
        boundaries: vec![test_boundary(
            "frame-1",
            "frame",
            Some(test_root("c15-frame")),
            "complete",
            None,
        )],
        completeness: "complete".to_string(),
        limitations: vec!["original capture note".to_string()],
    };
    let pin = test_pin("reduction-extract", "1");
    let stabilization = satisfied_stabilization(test_pin("stabilization", "1"));
    let source_refs = vec![test_evidence("c15")];

    // Full reduction establishes the overflow baseline.
    let full = reduce_export(&export, "EXTRACT", &pin, EXTRACT_CEILING, &source_refs, &stabilization)
        .expect("full reduction fits the profile ceiling");
    let full_bytes = full.to_bytes().expect("full serializes");
    assert!(full_bytes.len() > 8000, "fixture must be large enough to overflow small budgets");

    // Partial output: fits the budget, valid UTF-8, limitations retained.
    let small_budget = (full_bytes.len() as u64 / 2).max(2500);
    let partial = reduce_export(&export, "EXTRACT", &pin, small_budget, &source_refs, &stabilization)
        .expect("overflow yields explicit partial output");
    assert_eq!(partial.completeness, "partial");
    let partial_bytes = partial.to_bytes().expect("partial serializes");
    assert!(
        partial_bytes.len() as u64 <= small_budget,
        "partial output must fit the budget: {} > {small_budget}",
        partial_bytes.len()
    );
    assert!(
        partial.limitations.iter().any(|limitation| limitation.contains("byte_budget")),
        "overflow must be disclosed: {:?}",
        partial.limitations
    );
    assert!(
        partial.limitations.iter().any(|limitation| limitation.contains("original capture note")),
        "original limitations must be retained: {:?}",
        partial.limitations
    );
    // Boundary records survive overflow.
    assert_eq!(partial.boundaries.len(), 1);
    // Multibyte safety: no replacement chars, valid UTF-8, char-boundary cut.
    for section in &partial.sections {
        assert!(
            !section.semantic_text.contains('\u{FFFD}'),
            "truncation must not produce replacement chars"
        );
        assert!(section.semantic_text.is_char_boundary(section.semantic_text.len()));
        for ch in section.semantic_text.chars() {
            assert!(ch == 'a' || ch == '🌍' || ch == ' ', "unexpected char {ch:?}");
        }
    }
    let text = String::from_utf8(partial_bytes.clone()).expect("reduction bytes are valid UTF-8");
    assert!(text.contains("byte_budget"));

    // Size failure: metadata alone exceeds a tiny budget.
    let error = reduce_export(&export, "EXTRACT", &pin, 100, &source_refs, &stabilization)
        .expect_err("tiny budget must fail explicitly");
    assert_eq!(error.code, "REDUCTION_TOO_LARGE");
    assert!(error.detail.contains("byte_budget"));

    // Zero budget is rejected as a non-positive integer.
    let zero = reduce_export(&export, "EXTRACT", &pin, 0, &source_refs, &stabilization)
        .expect_err("zero budget must fail");
    assert_eq!(zero.code, "INVALID_REQUEST");

    // Profile ceilings are pinned Ringmaster settings.
    assert_eq!(ceiling_for_profile("EXTRACT").expect("extract ceiling"), 250_000);
    assert_eq!(ceiling_for_profile("HEAL").expect("heal ceiling"), 50_000);
    assert!(ceiling_for_profile("UNKNOWN").is_err());
}

// ---------------------------------------------------------------------------
// RM-C16: stabilization timeout/unsupported instrumentation
// ---------------------------------------------------------------------------

#[test]
fn rm_c16_stabilization_partial_or_required_block() {
    let policy_pin = test_pin("stabilization-policy", "1");

    // Permissive unknown: proceeds with partial=true and structured limitations.
    let permissive = StabilizationPolicy::permissive(policy_pin.clone());
    let partial = observe_stabilization(&permissive, "unknown", "unknown", "unknown", Vec::new(), Vec::new())
        .expect("permissive unknown proceeds");
    assert!(partial.stabilization_partial);
    assert_eq!(partial.network_idle, "unknown");
    assert_eq!(partial.dom_quiet, "unknown");
    assert_eq!(partial.text_signatures, "unknown");
    assert!(partial.limitations.len() >= 3, "each unknown needs explanation: {:?}", partial.limitations);

    // Required unknown: blocks.
    let required = StabilizationPolicy::required(policy_pin.clone());
    let blocked = observe_stabilization(&required, "unknown", "unknown", "unknown", Vec::new(), Vec::new())
        .expect_err("required unknown must block");
    assert_eq!(blocked.code, "STABILIZATION_REQUIRED");

    // Required unsatisfied: also blocks (baseline not met).
    let blocked_unsatisfied = observe_stabilization(&required, "unsatisfied", "satisfied", "satisfied", Vec::new(), Vec::new())
        .expect_err("required unsatisfied must block");
    assert_eq!(blocked_unsatisfied.code, "STABILIZATION_REQUIRED");

    // Permissive unsatisfied: proceeds as partial.
    let unsatisfied = observe_stabilization(&permissive, "unsatisfied", "satisfied", "satisfied", Vec::new(), Vec::new())
        .expect("permissive unsatisfied proceeds");
    assert!(unsatisfied.stabilization_partial);

    // Required satisfied: proceeds without partial.
    let satisfied = observe_stabilization(&required, "satisfied", "satisfied", "satisfied", Vec::new(), Vec::new())
        .expect("required satisfied proceeds");
    assert!(!satisfied.stabilization_partial);

    // not_applicable: explicit, never silent.
    let na = observe_stabilization(&permissive, "not_applicable", "not_applicable", "satisfied", Vec::new(), Vec::new())
        .expect("not_applicable proceeds");
    assert!(!na.stabilization_partial);
    assert!(na.limitations.iter().any(|limitation| limitation.contains("not applicable")));

    // Reduction integration: unknown stabilization forces partial output.
    let root = test_root("c16-main");
    let export = BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root: root.clone(),
        nodes: vec![test_node(&root, "n1", "div", &[("id", "main")], Some("hello world"))],
        boundaries: Vec::new(),
        completeness: "complete".to_string(),
        limitations: Vec::new(),
    };
    let source_refs = vec![test_evidence("c16")];
    let reduction = reduce_export(&export, "EXTRACT", &test_pin("reduction-extract", "1"), EXTRACT_CEILING, &source_refs, &partial)
        .expect("permissive reduction proceeds");
    assert_eq!(reduction.completeness, "partial");
    assert!(
        reduction.limitations.iter().any(|limitation| limitation.contains("stabilization is partial")),
        "stabilization partial must be disclosed: {:?}",
        reduction.limitations
    );
    // Satisfied stabilization allows completeness when nothing else is partial.
    let complete = reduce_export(&export, "EXTRACT", &test_pin("reduction-extract", "1"), EXTRACT_CEILING, &source_refs, &satisfied)
        .expect("satisfied reduction proceeds");
    assert_eq!(complete.completeness, "complete");

    // Measurement validation: exact zero is valid; cross-clock is rejected.
    let clock = ClockDescriptor {
        clock_id: "clk-engine-1".to_string(),
        boot_id: "boot-9".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: "src-engine-1".to_string(),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    };
    let valid = Measurement {
        measurement_id: "m-1".to_string(),
        name: "stabilization.wait".to_string(),
        scope: Scope { kind: ScopeKind::NativePrimitive, id: "op-1".to_string() },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: clock.origin,
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        method: Method::SourceValue,
        start: MaybeTimePoint::Missing(Missing::new("not_observed")),
        end: MaybeTimePoint::Missing(Missing::new("not_observed")),
        estimate: Estimate::Exact { value: 0.0 },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: TimeMaybeString::Missing(Missing::new("not_applicable")),
    };
    validate_stabilization_measurements(&[valid.clone()], &[clock.clone()]).expect("exact zero validates");
    let other_clock = ClockDescriptor {
        clock_id: "clk-other".to_string(),
        boot_id: "boot-9".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: "src-other".to_string(),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    };
    let mut cross_clock = valid;
    cross_clock.clock_id = other_clock.clock_id.clone();
    let rejected = validate_stabilization_measurements(&[cross_clock], &[clock])
        .expect_err("cross-clock measurement must be rejected");
    assert_eq!(rejected.code, "INVALID_REQUEST");
}
