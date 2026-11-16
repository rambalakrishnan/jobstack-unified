//! Conformance for RM-C17 (duplicate labels across frames).
//! Every test name carries the `rm_c17` token for the verification filter.

use rm_authority::{authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, Manifest};
use rm_browseroxide::{
    open_native_session, BODomExport, BODomNode, BONodeRef, BOOwner, BOPageRef, BORootRef,
    MaybeNodeParent, MaybeRoot, NativeSession,
};
use rm_catalog::{
    BO_CAPABILITIES, BO_PRIMITIVES, BOBindingDescriptor, BOMapping, CapabilityDescriptor,
    CapabilityRecord, ComponentIdentity, DurationLimit, SubjectIdentity,
    VersionPin as CatalogVersionPin,
    BO_RECORD_TYPE as CATALOG_BO_RECORD, BO_SCHEMA_VERSION as CATALOG_BO_SCHEMA,
    CAPABILITY_RECORD_TYPE, CAPABILITY_SCHEMA_VERSION, MaybeDigest as CatalogMaybeDigest,
    MaybeString as CatalogMaybeString, MaybeVersionPin as CatalogMaybePin,
};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload, JournalPrefix,
    PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_targets::{parse_target_recipe, resolve_in_export, resolve_target, TargetRecipe};
use rm_time::{
    MaybeString as TimeMaybeString, MaybeTimePoint, MeasurementOrigin, Missing, TimePoint,
    UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers (mirrors rm_reduction harness with rm-tgt tags)
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

fn test_export(root: &BORootRef, nodes: Vec<BODomNode>) -> BODomExport {
    BODomExport {
        record_type: "browseroxide_dom_export".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        root: root.clone(),
        nodes,
        boundaries: Vec::new(),
        completeness: "complete".to_string(),
        limitations: Vec::new(),
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
    let writer = principal(&format!("rm-tgt-bind-{test}"));
    let run = format!("rm-tgt-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-tgt-evidence-{test}").into_bytes();
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
        build_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-tgt-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-tgt-engine-config")),
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
        configuration_digest: artifact_digest(b"rm-tgt-config"),
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
            artifact_digest: artifact_digest(b"rm-tgt-binding-build"),
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
                artifact_digest: artifact_digest(b"rm-tgt-catalog"),
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
            artifact_digest: artifact_digest(b"rm-tgt-privacy"),
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
    let princ = principal(&format!("rm-tgt-{test}"));
    let run = format!("rm-tgt-run-{test}");
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
    let writer = principal(&format!("rm-tgt-writer-{tag}"));
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

// Recipe helpers.

fn install_recipe(
    owner: &AuthenticatedPrincipal,
    frame_path: Vec<&str>,
    shadow_path: Vec<&str>,
    strategy: &str,
    query: &str,
    exact: bool,
    max_matches: u64,
    fallback: Value,
    pin: &CatalogVersionPin,
) -> ArtifactReference {
    let value = json!({
        "frame_path": frame_path,
        "shadow_path": shadow_path,
        "strategy": strategy,
        "query": query,
        "exact": exact,
        "max_matches": max_matches,
        "fallback_text": fallback,
        "resolver_policy": {
            "id": pin.id,
            "version": pin.version,
            "artifact_digest": pin.artifact_digest.as_str(),
        },
    });
    let bytes = serde_json::to_vec(&value).expect("recipe json");
    let reference = ArtifactReference {
        digest: artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "artifact".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(owner, &reference, &bytes).expect("install recipe");
    reference
}

fn install_raw_recipe(owner: &AuthenticatedPrincipal, raw: &[u8]) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(raw),
        size_bytes: raw.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "artifact".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(owner, &reference, raw).expect("install raw recipe");
    reference
}

fn parsed_recipe(
    strategy: &str,
    query: &str,
    exact: bool,
    max_matches: u64,
    tag: &str,
) -> TargetRecipe {
    let pin = test_pin(&format!("resolver-{tag}"), "1");
    let value = json!({
        "frame_path": [],
        "shadow_path": [],
        "strategy": strategy,
        "query": query,
        "exact": exact,
        "max_matches": max_matches,
        "fallback_text": format!("fallback-{tag}"),
        "resolver_policy": {
            "id": pin.id,
            "version": pin.version,
            "artifact_digest": pin.artifact_digest.as_str(),
        },
    });
    let bytes = serde_json::to_vec(&value).expect("recipe json");
    parse_target_recipe(&bytes).expect("recipe parses")
}

// ---------------------------------------------------------------------------
// RM-C17: duplicate labels across frames — scoped resolution, no global match
// ---------------------------------------------------------------------------

#[test]
fn rm_c17_scoped_resolution_duplicate_labels_across_frames() {
    let (princ, mut session, auth, limit) = open_session("c17-scope");
    let page_a = make_page_for(&mut session, &auth, &limit, "c17-scope-a");
    let root_a = navigate_for_root(&mut session, &auth, &limit, &page_a);
    let page_b = make_page_for(&mut session, &auth, &limit, "c17-scope-b");
    let root_b = navigate_for_root(&mut session, &auth, &limit, &page_b);
    assert_ne!(root_a.root_id, root_b.root_id, "two frames need distinct roots");

    // Both synthetic frames expose the same duplicate label "hello" via
    // bo.dom_read. Scoped resolution must return each frame's own node.
    let pin = test_pin("resolver-c17-scope", "1");
    let text_recipe = install_recipe(
        &princ,
        vec![],
        vec![],
        "text",
        "hello",
        true,
        5,
        json!("fallback-scope"),
        &pin,
    );
    let export_a = resolve_target(&princ, &mut session, &text_recipe, &root_a, &auth, &limit)
        .expect("root A resolves its own hello");
    assert_eq!(export_a.root, root_a);
    assert_eq!(export_a.nodes.len(), 1);
    assert_eq!(export_a.nodes[0].node_ref.root, root_a);
    assert_eq!(export_a.completeness, "complete");
    assert!(!export_a.limitations.is_empty());

    let export_b = resolve_target(&princ, &mut session, &text_recipe, &root_b, &auth, &limit)
        .expect("root B resolves its own hello");
    assert_eq!(export_b.root, root_b);
    assert_eq!(export_b.nodes.len(), 1);
    assert_eq!(export_b.nodes[0].node_ref.root, root_b);
    // Distinct native identities prove no flattened global first match.
    assert_ne!(
        export_a.nodes[0].node_ref.node_id, export_b.nodes[0].node_ref.node_id,
        "duplicate labels across frames must keep distinct node identities"
    );

    // CSS strategy is likewise scoped.
    let css_recipe = install_recipe(
        &princ,
        vec![],
        vec![],
        "css",
        "div",
        true,
        5,
        json!("fallback-css"),
        &pin,
    );
    let css_a = resolve_target(&princ, &mut session, &css_recipe, &root_a, &auth, &limit)
        .expect("css resolves in root A");
    assert_eq!(css_a.root, root_a);
    assert_eq!(css_a.nodes[0].node_ref.root, root_a);
    let css_b = resolve_target(&princ, &mut session, &css_recipe, &root_b, &auth, &limit)
        .expect("css resolves in root B");
    assert_eq!(css_b.root, root_b);
    assert_ne!(
        css_a.nodes[0].node_ref.node_id, css_b.nodes[0].node_ref.node_id
    );
}

#[test]
fn rm_c17_no_global_first_match_ambiguity_within_scope() {
    let root = test_root("c17-ambig");
    let nodes = vec![
        test_node(&root, "n1", "button", &[("id", "a")], Some("Submit")),
        test_node(&root, "n2", "button", &[("id", "b")], Some("Submit")),
    ];
    let export = test_export(&root, nodes);

    // Two identical labels in one scope: ambiguity, never first match.
    let recipe = parsed_recipe("text", "Submit", true, 10, "c17-ambig");
    let error = resolve_in_export(&export, &recipe, &root).expect_err("duplicate must not resolve");
    assert_eq!(error.code, "TARGET_AMBIGUOUS");
    assert!(
        error.detail.contains("matched 2") && error.detail.contains("first match"),
        "ambiguity must name the match count and refuse first match: {}",
        error.detail
    );

    // Bounded truncation: max_matches=1 with 2 matches is ambiguous, not first.
    let truncated = parsed_recipe("text", "Submit", true, 1, "c17-trunc");
    let error = resolve_in_export(&export, &truncated, &root).expect_err("truncated must not resolve");
    assert_eq!(error.code, "TARGET_AMBIGUOUS");
    assert!(
        error.detail.contains("exceeding max_matches")
            && error.detail.contains("truncated")
            && error.detail.contains("cannot prove uniqueness"),
        "truncation must be explicit: {}",
        error.detail
    );

    // Universal selector over two nodes is likewise ambiguous.
    let star = parsed_recipe("css", "*", true, 10, "c17-star");
    let error = resolve_in_export(&export, &star, &root).expect_err("star must be ambiguous");
    assert_eq!(error.code, "TARGET_AMBIGUOUS");
}

#[test]
fn rm_c17_truncated_collection_does_not_prove_uniqueness() {
    let root = test_root("c17-partial");
    let nodes = vec![test_node(&root, "n1", "div", &[("id", "main")], Some("hello"))];

    for completeness in ["partial", "unknown"] {
        let mut export = test_export(&root, nodes.clone());
        export.completeness = completeness.to_string();
        export.limitations = vec![format!("capture is {completeness}")];
        let recipe = parsed_recipe("text", "hello", true, 5, &format!("c17-{completeness}"));
        let error = resolve_in_export(&export, &recipe, &root)
            .expect_err("partial/unknown single match must not resolve");
        assert_eq!(error.code, "TARGET_AMBIGUOUS");
        assert!(
            error.detail.contains("truncated collection does not prove uniqueness"),
            "must cite the truncation rule: {}",
            error.detail
        );
    }

    // Control: the same single match in a complete collection resolves.
    let export = test_export(&root, nodes);
    let recipe = parsed_recipe("text", "hello", true, 5, "c17-complete-ctl");
    let resolved = resolve_in_export(&export, &recipe, &root).expect("complete single resolves");
    assert_eq!(resolved.nodes.len(), 1);
    assert_eq!(resolved.completeness, "complete");
}

#[test]
fn rm_c17_playwright_syntax_is_not_native_css() {
    let root = test_root("c17-pw");
    let export = test_export(
        &root,
        vec![test_node(&root, "n1", "div", &[("id", "main")], Some("hello"))],
    );
    let playwright_queries = vec![
        "div >> text=Submit",
        "text=Submit",
        "xpath=//button",
        "role=button",
        "button:has-text(\"hi\")",
        "div >> role=button",
    ];
    for (index, query) in playwright_queries.iter().enumerate() {
        let recipe = parsed_recipe("css", query, true, 5, &format!("c17-pw-{index}"));
        let error = resolve_in_export(&export, &recipe, &root)
            .expect_err("playwright syntax must be rejected");
        assert_eq!(error.code, "INVALID_REQUEST", "query {query:?}: {}", error.detail);
        assert!(
            error.detail.contains("Playwright") || error.detail.contains("unsupported selector grammar"),
            "query {query:?} must name Playwright: {}",
            error.detail
        );
    }

    // Bracketed attribute selectors are native CSS, not engines: they parse
    // and yield scoped no-match (not a grammar rejection) when absent.
    let attr = parsed_recipe("css", "[data-testid=\"submit\"]", true, 5, "c17-pw-attr");
    let error = resolve_in_export(&export, &attr, &root).expect_err("missing attr is no-match");
    assert_eq!(error.code, "TARGET_NOT_FOUND");

    // Unsupported native constructs report mapping limits, not CSS matches.
    for query in ["div:has(.x)", "div:is(.x)", "div > span", "div, span", "div:hover"] {
        let recipe = parsed_recipe("css", query, true, 5, "c17-pw-unsupported");
        let error = resolve_in_export(&export, &recipe, &root)
            .expect_err("unsupported construct must not guess");
        assert_eq!(error.code, "UNSUPPORTED_MAPPING", "query {query:?}: {}", error.detail);
    }

    // End-to-end: grammar gate fires before native entry.
    let (princ, mut session, auth, limit) = open_session("c17-pw-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c17-pw-e2e");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let pin = test_pin("resolver-c17-pw-e2e", "1");
    let recipe = install_recipe(
        &princ,
        vec![],
        vec![],
        "css",
        "div >> text=hi",
        true,
        5,
        json!("fallback"),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &recipe, &live_root, &auth, &limit)
        .expect_err("playwright must be rejected end-to-end");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error.detail.contains("Playwright"));
}

#[test]
fn rm_c17_xpath_requires_established_mapping() {
    let root = test_root("c17-xpath");
    let export = test_export(
        &root,
        vec![test_node(&root, "n1", "button", &[("id", "go")], Some("Go"))],
    );
    let recipe = parsed_recipe("xpath", "//button", true, 5, "c17-xpath");
    let error = resolve_in_export(&export, &recipe, &root).expect_err("xpath must be unsupported");
    assert_eq!(error.code, "UNSUPPORTED_MAPPING");
    assert!(
        error.detail.contains("xpath") && error.detail.contains("no established"),
        "must cite the missing mapping: {}",
        error.detail
    );

    let (princ, mut session, auth, limit) = open_session("c17-xpath-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c17-xpath-e2e");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let pin = test_pin("resolver-c17-xpath-e2e", "1");
    let recipe = install_recipe(
        &princ,
        vec![],
        vec![],
        "xpath",
        "//button[@id=\"go\"]",
        true,
        5,
        json!("Go"),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &recipe, &live_root, &auth, &limit)
        .expect_err("xpath must be unsupported end-to-end");
    assert_eq!(error.code, "UNSUPPORTED_MAPPING");
}

#[test]
fn rm_c17_frame_and_shadow_paths_require_explicit_mounts() {
    let root = test_root("c17-paths");
    let export = test_export(
        &root,
        vec![test_node(&root, "n1", "div", &[("id", "main")], Some("hello"))],
    );
    let pin = test_pin("resolver-c17-paths", "1");
    // Frame path with zero frame mounts: explicit no-match.
    let frame_value = json!({
        "frame_path": ["frame-1"],
        "shadow_path": [],
        "strategy": "text",
        "query": "hello",
        "exact": true,
        "max_matches": 5,
        "fallback_text": "fallback",
        "resolver_policy": {"id": pin.id, "version": pin.version, "artifact_digest": pin.artifact_digest.as_str()},
    });
    let frame_recipe =
        parse_target_recipe(&serde_json::to_vec(&frame_value).unwrap()).expect("frame recipe parses");
    let error = resolve_in_export(&export, &frame_recipe, &root).expect_err("frame path must not match globally");
    assert_eq!(error.code, "TARGET_NOT_FOUND");
    assert!(
        error.detail.contains("frame_path") && error.detail.contains("no global match"),
        "must cite frame traversal: {}",
        error.detail
    );
    // Shadow path with zero shadow mounts: explicit no-match.
    let shadow_value = json!({
        "frame_path": [],
        "shadow_path": ["host-1"],
        "strategy": "text",
        "query": "hello",
        "exact": true,
        "max_matches": 5,
        "fallback_text": "fallback",
        "resolver_policy": {"id": pin.id, "version": pin.version, "artifact_digest": pin.artifact_digest.as_str()},
    });
    let shadow_recipe =
        parse_target_recipe(&serde_json::to_vec(&shadow_value).unwrap()).expect("shadow recipe parses");
    let error = resolve_in_export(&export, &shadow_recipe, &root).expect_err("shadow path must not match globally");
    assert_eq!(error.code, "TARGET_NOT_FOUND");
    assert!(error.detail.contains("shadow_path"));

    // End-to-end: live observation exposes zero mounts, so paths fail there too.
    let (princ, mut session, auth, limit) = open_session("c17-paths-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c17-paths-e2e");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let live_pin = test_pin("resolver-c17-paths-e2e", "1");
    let live_recipe = install_recipe(
        &princ,
        vec!["frame-1"],
        vec![],
        "text",
        "hello",
        true,
        5,
        json!("fallback"),
        &live_pin,
    );
    let error = resolve_target(&princ, &mut session, &live_recipe, &live_root, &auth, &limit)
        .expect_err("live frame path must not match");
    assert_eq!(error.code, "TARGET_NOT_FOUND");
}

#[test]
fn rm_c17_recipe_is_durable_intent_not_live_reference_and_stale_rejected() {
    // A query that spells a node id is still a CSS selector, not a handle
    // dereference: tag "root-x-node-1" does not match div#main.
    let root = test_root("c17-intent");
    let export = test_export(
        &root,
        vec![test_node(&root, "root-c17-intent-node-1", "div", &[("id", "main")], Some("hello"))],
    );
    let recipe = parsed_recipe("css", "root-c17-intent-node-1", true, 5, "c17-intent");
    let error = resolve_in_export(&export, &recipe, &root).expect_err("node-id text is not a handle");
    assert_eq!(error.code, "TARGET_NOT_FOUND");

    // Mismatched scope is stale, never cross-resolved.
    let other = test_root("c17-intent-other");
    let good = parsed_recipe("text", "hello", true, 5, "c17-intent-good");
    let error = resolve_in_export(&export, &good, &other).expect_err("wrong scope must not resolve");
    assert_eq!(error.code, "STALE_REFERENCE");

    // End-to-end stale: navigating the same page invalidates the first root.
    let (princ, mut session, auth, limit) = open_session("c17-stale-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c17-stale-e2e");
    let root_one = navigate_for_root(&mut session, &auth, &limit, &page);
    let root_two = navigate_for_root(&mut session, &auth, &limit, &page);
    assert_ne!(root_one.root_id, root_two.root_id);
    let pin = test_pin("resolver-c17-stale-e2e", "1");
    let recipe = install_recipe(
        &princ,
        vec![],
        vec![],
        "text",
        "hello",
        true,
        5,
        json!("fallback"),
        &pin,
    );
    let stale = resolve_target(&princ, &mut session, &recipe, &root_one, &auth, &limit)
        .expect_err("old root must be stale");
    assert_eq!(stale.code, "STALE_REFERENCE");
    let fresh = resolve_target(&princ, &mut session, &recipe, &root_two, &auth, &limit)
        .expect("current generation resolves anew");
    assert_eq!(fresh.root, root_two);
}

#[test]
fn rm_c17_no_healing_cache_or_model_during_lookup_fallback_ignored() {
    // Live frame exposes "hello". A non-matching query with a matching
    // fallback must still fail: Tier 1 never heals via fallback_text.
    let (princ, mut session, auth, limit) = open_session("c17-nofallback");
    let page = make_page_for(&mut session, &auth, &limit, "c17-nofallback");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let pin = test_pin("resolver-c17-nofallback", "1");

    let text_heal = install_recipe(
        &princ,
        vec![],
        vec![],
        "text",
        "nonexistent-label-xyz",
        true,
        5,
        json!("hello"),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &text_heal, &live_root, &auth, &limit)
        .expect_err("fallback must not heal text");
    assert_eq!(error.code, "TARGET_NOT_FOUND");

    let css_heal = install_recipe(
        &princ,
        vec![],
        vec![],
        "css",
        "#missing-id",
        true,
        5,
        json!("hello"),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &css_heal, &live_root, &auth, &limit)
        .expect_err("fallback must not heal css");
    assert_eq!(error.code, "TARGET_NOT_FOUND");

    // XPath stays unsupported even when the fallback would match.
    let xpath_heal = install_recipe(
        &princ,
        vec![],
        vec![],
        "xpath",
        "//div",
        true,
        5,
        json!("hello"),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &xpath_heal, &live_root, &auth, &limit)
        .expect_err("fallback must not heal xpath");
    assert_eq!(error.code, "UNSUPPORTED_MAPPING");

    // Missing-envelope fallback likewise never heals.
    let missing_fallback = install_recipe(
        &princ,
        vec![],
        vec![],
        "text",
        "nonexistent-label-xyz",
        true,
        5,
        json!({"value": null, "reason": "not_applicable"}),
        &pin,
    );
    let error = resolve_target(&princ, &mut session, &missing_fallback, &live_root, &auth, &limit)
        .expect_err("missing fallback must not heal");
    assert_eq!(error.code, "TARGET_NOT_FOUND");
}

#[test]
fn rm_c17_closed_recipe_shape_and_missingness() {
    let pin = test_pin("resolver-c17-closed", "1");
    let base = |mutate: &dyn Fn(&mut serde_json::Map<String, Value>)| -> Vec<u8> {
        let mut value = json!({
            "frame_path": [],
            "shadow_path": [],
            "strategy": "text",
            "query": "hello",
            "exact": true,
            "max_matches": 5,
            "fallback_text": "fallback",
            "resolver_policy": {"id": pin.id, "version": pin.version, "artifact_digest": pin.artifact_digest.as_str()},
        });
        mutate(value.as_object_mut().unwrap());
        serde_json::to_vec(&value).unwrap()
    };

    // Extra field.
    let bytes = base(&|map| {
        map.insert("extra".to_string(), json!("nope"));
    });
    let error = parse_target_recipe(&bytes).expect_err("extra field must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error.detail.contains("undeclared field"));

    // Missing field.
    let bytes = base(&|map| {
        map.remove("resolver_policy");
    });
    let error = parse_target_recipe(&bytes).expect_err("missing field must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error.detail.contains("missing required field"));

    // Duplicate keys (raw text; serde alone would keep the last).
    let raw = format!(
        "{{\"frame_path\":[],\"shadow_path\":[],\"strategy\":\"text\",\"query\":\"hello\",\"query\":\"bye\",\"exact\":true,\"max_matches\":5,\"fallback_text\":\"f\",\"resolver_policy\":{{\"id\":{:?},\"version\":{:?},\"artifact_digest\":{:?}}}}}",
        pin.id, pin.version, pin.artifact_digest.as_str()
    );
    let error = parse_target_recipe(raw.as_bytes()).expect_err("duplicate keys must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("duplicate key") || error.detail.contains("recipe bytes rejected"),
        "duplicate detail: {}",
        error.detail
    );

    // Bare null query.
    let raw_null = format!(
        "{{\"frame_path\":[],\"shadow_path\":[],\"strategy\":\"text\",\"query\":null,\"exact\":true,\"max_matches\":5,\"fallback_text\":\"f\",\"resolver_policy\":{{\"id\":{:?},\"version\":{:?},\"artifact_digest\":{:?}}}}}",
        pin.id, pin.version, pin.artifact_digest.as_str()
    );
    let error = parse_target_recipe(raw_null.as_bytes()).expect_err("bare null must be rejected");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Invalid strategy.
    let bytes = base(&|map| {
        map.insert("strategy".to_string(), json!("playwright"));
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Empty query.
    let bytes = base(&|map| {
        map.insert("query".to_string(), json!(""));
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Zero max_matches.
    let bytes = base(&|map| {
        map.insert("max_matches".to_string(), json!(0));
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Bad resolver digest.
    let bytes = base(&|map| {
        map.insert(
            "resolver_policy".to_string(),
            json!({"id": "r", "version": "1", "artifact_digest": "not-a-digest"}),
        );
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Empty fallback string.
    let bytes = base(&|map| {
        map.insert("fallback_text".to_string(), json!(""));
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Bad Missing reason.
    let bytes = base(&|map| {
        map.insert(
            "fallback_text".to_string(),
            json!({"value": null, "reason": "bogus"}),
        );
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Empty frame_path entry.
    let bytes = base(&|map| {
        map.insert("frame_path".to_string(), json!([""]));
    });
    assert_eq!(parse_target_recipe(&bytes).unwrap_err().code, "INVALID_REQUEST");

    // Reasoned Missing fallback is accepted.
    let bytes = base(&|map| {
        map.insert(
            "fallback_text".to_string(),
            json!({"value": null, "reason": "not_applicable"}),
        );
    });
    parse_target_recipe(&bytes).expect("missing fallback must parse");

    // End-to-end: malformed recipe artifact fails through resolve_target.
    let (princ, mut session, auth, limit) = open_session("c17-closed-e2e");
    let page = make_page_for(&mut session, &auth, &limit, "c17-closed-e2e");
    let live_root = navigate_for_root(&mut session, &auth, &limit, &page);
    let bad_bytes = base(&|map| {
        map.insert("extra".to_string(), json!(1));
    });
    let bad = install_raw_recipe(&princ, &bad_bytes);
    let error = resolve_target(&princ, &mut session, &bad, &live_root, &auth, &limit)
        .expect_err("closed violation must fail end-to-end");
    assert_eq!(error.code, "INVALID_REQUEST");
}

#[test]
fn rm_c17_css_role_testid_pinned_semantics() {
    let root = test_root("c17-sem");
    let export = test_export(
        &root,
        vec![
            test_node(&root, "n1", "div", &[("id", "main"), ("class", "card primary")], Some("  Hello   world ")),
            test_node(&root, "n2", "button", &[("role", "button"), ("aria-label", "Go")], Some("Go")),
            test_node(&root, "n3", "input", &[("data-testid", "submit"), ("type", "text")], None),
        ],
    );

    // CSS: tag, id, class, attribute, combinations.
    for (query, want_id) in [
        ("div", Some("n1")),
        ("#main", Some("n1")),
        (".primary", Some("n1")),
        ("div#main", Some("n1")),
        ("[id=\"main\"]", Some("n1")),
        ("[data-testid=\"submit\"]", Some("n3")),
        ("span", None),
        ("#missing", None),
    ] {
        let recipe = parsed_recipe("css", query, true, 5, &format!("c17-css-{query}"));
        match want_id {
            Some(id) => {
                let resolved = resolve_in_export(&export, &recipe, &root)
                    .unwrap_or_else(|e| panic!("css {query:?} must resolve: {e}"));
                assert_eq!(resolved.nodes[0].node_ref.node_id, id);
            }
            None => {
                let error = resolve_in_export(&export, &recipe, &root)
                    .expect_err("css miss must be no-match");
                assert_eq!(error.code, "TARGET_NOT_FOUND", "query {query:?}");
            }
        }
    }
    // CSS exact=false folds id/class/attr case.
    let folded = parsed_recipe("css", "#MAIN", false, 5, "c17-css-fold");
    let resolved = resolve_in_export(&export, &folded, &root).expect("case-folded css resolves");
    assert_eq!(resolved.nodes[0].node_ref.node_id, "n1");
    let strict = parsed_recipe("css", "#MAIN", true, 5, "c17-css-strict");
    assert_eq!(
        resolve_in_export(&export, &strict, &root).unwrap_err().code,
        "TARGET_NOT_FOUND"
    );

    // Text: exact equality vs case-insensitive substring, whitespace normalized.
    let exact = parsed_recipe("text", "Hello world", true, 5, "c17-text-exact");
    assert_eq!(
        resolve_in_export(&export, &exact, &root).unwrap().nodes[0].node_ref.node_id,
        "n1"
    );
    let substr = parsed_recipe("text", "hello", false, 5, "c17-text-sub");
    assert_eq!(
        resolve_in_export(&export, &substr, &root).unwrap().nodes[0].node_ref.node_id,
        "n1"
    );
    let miss = parsed_recipe("text", "hello", true, 5, "c17-text-miss");
    assert_eq!(
        resolve_in_export(&export, &miss, &root).unwrap_err().code,
        "TARGET_NOT_FOUND"
    );
    // Missing text never matches.
    let missing_text_export = test_export(
        &root,
        vec![test_node(&root, "n9", "div", &[("id", "x")], None)],
    );
    let any_text = parsed_recipe("text", "x", false, 5, "c17-text-missing");
    assert_eq!(
        resolve_in_export(&missing_text_export, &any_text, &root).unwrap_err().code,
        "TARGET_NOT_FOUND"
    );

    // Role: explicit role attribute only.
    let role_exact = parsed_recipe("role", "button", true, 5, "c17-role-exact");
    assert_eq!(
        resolve_in_export(&export, &role_exact, &root).unwrap().nodes[0].node_ref.node_id,
        "n2"
    );
    let role_sub = parsed_recipe("role", "but", false, 5, "c17-role-sub");
    assert_eq!(
        resolve_in_export(&export, &role_sub, &root).unwrap().nodes[0].node_ref.node_id,
        "n2"
    );
    let role_miss = parsed_recipe("role", "link", true, 5, "c17-role-miss");
    assert_eq!(
        resolve_in_export(&export, &role_miss, &root).unwrap_err().code,
        "TARGET_NOT_FOUND"
    );

    // Test id: pinned data-testid convention.
    let tid = parsed_recipe("testid", "submit", true, 5, "c17-tid");
    assert_eq!(
        resolve_in_export(&export, &tid, &root).unwrap().nodes[0].node_ref.node_id,
        "n3"
    );
    let tid_miss = parsed_recipe("testid", "other", true, 5, "c17-tid-miss");
    assert_eq!(
        resolve_in_export(&export, &tid_miss, &root).unwrap_err().code,
        "TARGET_NOT_FOUND"
    );
}
