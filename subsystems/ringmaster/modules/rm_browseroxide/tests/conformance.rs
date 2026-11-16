//! Conformance for RM-C05..C12, C18, C19, C42. Each test name carries its token.

use rm_authority::{authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, Manifest};
use rm_browseroxide::*;
use rm_catalog::{
    BO_CAPABILITIES, BO_PRIMITIVES, BOBindingDescriptor, BOMapping,
    CapabilityDescriptor, CapabilityRecord, ComponentIdentity, DurationLimit,
    MaybeDigest as CatalogMaybeDigest,
    MaybeString as CatalogMaybeString, MaybeVersionPin as CatalogMaybePin, SubjectIdentity,
    VersionPin as CatalogVersionPin, BO_RECORD_TYPE as CATALOG_BO_RECORD,
    BO_SCHEMA_VERSION as CATALOG_BO_SCHEMA, CAPABILITY_RECORD_TYPE, CAPABILITY_SCHEMA_VERSION,
};
use rm_evidence::{
    AccessClass, ArtifactReference, EvidenceRef, EventSubmission, EvidencePayload,
    JournalPrefix, MaybeTimePoint, Missing, PositiveInteger,
};
use rm_leases::LeaseRecord;
use rm_time::{
    MeasurementOrigin, MaybeString as TimeMaybeString, TimePoint, UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::json;
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

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: "execution".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(writer, &reference, bytes).expect("install");
    reference
}

fn journal_fixture(test: &str) -> (AuthenticatedPrincipal, JournalPrefix, EvidenceRef) {
    let writer = principal(&format!("rm-bo-bind-{test}"));
    let run = format!("rm-bo-bind-run-{test}");
    let manifest = binding_manifest(&run);
    let bytes = format!("rm-bo-evidence-{test}").into_bytes();
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
        build_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-bo-engine-build")),
        configuration_digest: CatalogMaybeDigest::Present(artifact_digest(b"rm-bo-engine-config")),
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
        configuration_digest: artifact_digest(b"rm-bo-config"),
        stack: vec![engine.clone()],
    }
}

fn bo_record(id: &str, evidence: &EvidenceRef) -> CapabilityRecord {
    // Unknown baseline: no executed-observation claim without evidence.
    let _ = evidence;
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

fn bo_unmapped(primitive: &str) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "unmapped".to_string(),
        native_symbol: CatalogMaybeString::Missing(Missing::new("not_observed")),
        native_contract: CatalogMaybePin::Missing(Missing::new("not_applicable")),
        evidence_refs: Vec::new(),
    }
}

fn bo_descriptor(
    prefix: &JournalPrefix,
    evidence: &EvidenceRef,
    storage_model: &str,
    isolation: Vec<EvidenceRef>,
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
            artifact_digest: artifact_digest(b"rm-bo-binding-build"),
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
                artifact_digest: artifact_digest(b"rm-bo-catalog"),
            },
            evidence_prefix: prefix.clone(),
            supersedes: CatalogMaybeDigest::Missing(Missing::new("not_applicable")),
            capabilities: BO_CAPABILITIES.iter().map(|id| bo_record(id, evidence)).collect(),
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
        session_storage_model: storage_model.to_string(),
        session_isolation_refs: isolation,
        privacy_policy: CatalogVersionPin {
            id: "bo-privacy".to_string(),
            version: "0.1.0".to_string(),
            artifact_digest: artifact_digest(b"rm-bo-privacy"),
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
        "leased_at": serde_json::to_value(rm_time::MaybeTimePoint::Present(issued)).unwrap(),
        "lease_expires_at": serde_json::to_value(rm_time::MaybeTimePoint::Present(deadline)).unwrap(),
        "retry_count": 0,
        "max_retries_effective": 2,
        "last_failure_reason": serde_json::to_value(TimeMaybeString::Missing(Missing::new("not_applicable"))).unwrap(),
        "journal_prefix": prefix.to_json(),
        "evidence_refs": [evidence.to_json()],
    });
    LeaseRecord::from_json(&value).expect("held lease parses")
}

fn limit() -> DurationLimit {
    DurationLimit {
        kind: "exact".to_string(),
        unit: "ms".to_string(),
        value: 5000.0,
    }
}

fn policy_pin(id: &str, version: &str) -> CatalogVersionPin {
    CatalogVersionPin {
        id: id.to_string(),
        version: version.to_string(),
        artifact_digest: artifact_digest(format!("{id}-{version}").as_bytes()),
    }
}

struct Parts {
    principal: AuthenticatedPrincipal,
    manifest: Manifest,
    lease: LeaseRecord,
    binding: BOBindingDescriptor,
    auth: EvidenceRef,
    limit: DurationLimit,
}

fn session_parts(test: &str, storage: &str, unmapped: &[&str]) -> Parts {
    let (_bw, bprefix, bevidence) = journal_fixture(&format!("{test}-{storage}"));
    let isolation = if storage == "verified_namespaced" {
        vec![bevidence.clone()]
    } else {
        Vec::new()
    };
    let binding = bo_descriptor(&bprefix, &bevidence, storage, isolation, unmapped);
    let princ = principal(&format!("rm-bo-{test}"));
    let run = format!("rm-bo-run-{test}");
    let manifest = session_manifest(&run);
    let admission_envelope =
        rm_evidence::append_event(&princ, &manifest, admission(&manifest)).expect("admit");
    // Real authorization reference: an execution claim in this run.
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
    Parts {
        principal: princ,
        manifest,
        lease,
        binding,
        auth,
        limit: limit(),
    }
}

fn open_parts(parts: Parts) -> (NativeSession, EvidenceRef, DurationLimit) {
    let Parts {
        principal,
        manifest,
        lease,
        binding,
        auth,
        limit,
    } = parts;
    let session = open_native_session(principal, manifest, binding, lease).expect("open session");
    (session, auth, limit)
}

fn profile_pair(
    session: &NativeSession,
    tag: &str,
) -> (ArtifactReference, ArtifactReference) {
    // Install via a scratch principal; public bytes are readable by the session.
    let writer = principal(&format!("rm-bo-writer-{tag}"));
    let profile = {
        let bytes = format!("profile-{tag}").into_bytes();
        let reference = ArtifactReference {
            digest: artifact_digest(&bytes),
            size_bytes: bytes.len() as u64,
            media_type: "application/json".to_string(),
            owner_domain: "execution".to_string(),
            access: AccessClass::Public,
        };
        rm_evidence::install_artifact(&writer, &reference, &bytes).expect("profile");
        reference
    };
    let options = {
        let bytes = format!("options-{tag}").into_bytes();
        let reference = ArtifactReference {
            digest: artifact_digest(&bytes),
            size_bytes: bytes.len() as u64,
            media_type: "application/json".to_string(),
            owner_domain: "execution".to_string(),
            access: AccessClass::Public,
        };
        rm_evidence::install_artifact(&writer, &reference, &bytes).expect("options");
        reference
    };
    let _ = session;
    (profile, options)
}

fn make_page(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    tag: &str,
) -> BOPageRef {
    let (profile, options) = profile_pair(session, tag);
    let out = page_create(
        session,
        &BOPageCreate {
            profile,
            native_options: options,
            client: MaybeClient::Missing(Missing::new("not_applicable")),
        },
        auth,
        limit,
    )
    .expect("page_create ok");
    assert_eq!(out.record.return_state, "returned");
    out.value.expect("page value")
}

fn make_client(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    tag: &str,
    domain: &str,
) -> BOClientRef {
    let writer = principal(&format!("rm-bo-writer-client-{tag}"));
    let profile = install_bytes(&writer, format!("profile-client-{tag}").as_bytes(), "application/json");
    let out = client_create(
        session,
        &BOClientCreate {
            profile,
            mode: "create_retained".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: domain.to_string(),
        },
        auth,
        limit,
    )
    .expect("client_create ok");
    assert_eq!(out.record.return_state, "returned");
    out.value.expect("client value")
}

fn navigate_for_root(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    page: &BOPageRef,
    url: &str,
) -> (BONavigationReturn, BORootRef) {
    let out = navigate(
        session,
        &BONavigate {
            page: page.clone(),
            url: url.to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: policy_pin("navigation", "1"),
        },
        auth,
        limit,
    )
    .expect("navigate ok");
    assert_eq!(out.record.return_state, "returned");
    let nav = out.value.expect("nav value");
    let root = match nav.document_root.clone() {
        MaybeRoot::Present(root) => root,
        MaybeRoot::Missing(_) => panic!("navigate must expose a document root"),
    };
    (nav, root)
}

fn read_node(
    session: &mut NativeSession,
    auth: &EvidenceRef,
    limit: &DurationLimit,
    root: &BORootRef,
) -> BONodeRef {
    let out = dom_read(
        session,
        &BODomRead {
            root: root.clone(),
            selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
            depth_limit: 10,
            byte_limit: 1_000_000,
            include_frames: false,
            include_accessible_shadow_roots: false,
        },
        auth,
        limit,
    )
    .expect("dom_read ok");
    assert_eq!(out.record.return_state, "returned");
    let export = out.value.expect("export");
    export.nodes.first().expect("node").node_ref.clone()
}

fn failure_of(record: &BOPrimitiveRecord) -> BOFailure {
    match &record.error {
        MaybeBOFailure::Present(failure) => failure.clone(),
        MaybeBOFailure::Missing(_) => panic!("expected present failure, got inapplicable"),
    }
}

// ---------------------------------------------------------------------------
// RM-C05: wrong-thread entry refused before native access
// ---------------------------------------------------------------------------

#[test]
fn rm_c05_wrong_thread_entry_reset_destroy_rejected() {
    let parts_a = session_parts("c05a", "verified_namespaced", &[]);
    let parts_b = session_parts("c05b", "verified_namespaced", &[]);
    let (mut session_a, auth_a, limit_a) = open_parts(parts_a);
    // Session B opens on a different OS thread; its page ref travels back.
    let page_b: BOPageRef = std::thread::spawn(move || {
        let (mut session_b, auth_b, limit_b) = open_parts(parts_b);
        let page_b = make_page(&mut session_b, &auth_b, &limit_b, "c05b");
        assert_eq!(native_transport(), "browseroxide_native_direct");
        page_b
    })
    .join()
    .expect("join");
    let page_a = make_page(&mut session_a, &auth_a, &limit_a, "c05a");
    assert_ne!(
        page_a.owner.os_thread_id, page_b.owner.os_thread_id,
        "owners must differ across OS threads"
    );
    // Navigate with a foreign-thread page.
    let nav = navigate(
        &mut session_a,
        &BONavigate {
            page: page_b.clone(),
            url: "https://example.com/".to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: policy_pin("navigation", "1"),
        },
        &auth_a,
        &limit_a,
    )
    .expect("navigate returns record");
    assert!(nav.value.is_none());
    assert_eq!(nav.record.return_state, "failed");
    let failure = failure_of(&nav.record);
    assert_eq!(failure.code, "WRONG_THREAD");
    assert_eq!(failure.native_entry, "not_entered");
    // Reset with a foreign-thread page.
    let reset = reset_for_reuse(&mut session_a, &BOPageArgument { page: page_b.clone() }, &auth_a, &limit_a)
        .expect("reset returns record");
    assert!(reset.value.is_none());
    let failure = failure_of(&reset.record);
    assert_eq!(failure.code, "WRONG_THREAD");
    assert_eq!(failure.native_entry, "not_entered");
    // Destroy with a foreign-thread page.
    let destroy = page_destroy(&mut session_a, &BOPageArgument { page: page_b }, &auth_a, &limit_a)
        .expect("destroy returns record");
    assert!(destroy.value.is_none());
    let failure = failure_of(&destroy.record);
    assert_eq!(failure.code, "WRONG_THREAD");
    assert_eq!(failure.native_entry, "not_entered");
    // Own-thread page still works.
    let ok = navigate(
        &mut session_a,
        &BONavigate {
            page: page_a,
            url: "https://example.com/".to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: policy_pin("navigation", "1"),
        },
        &auth_a,
        &limit_a,
    )
    .expect("own navigate ok");
    assert_eq!(ok.record.return_state, "returned");
    assert!(ok.value.is_some());
}

// ---------------------------------------------------------------------------
// RM-C06: replacement invalidates old references
// ---------------------------------------------------------------------------

#[test]
fn rm_c06_page_node_replacement_rejects_old_mutation() {
    let parts = session_parts("c06", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let page = make_page(&mut session, &auth, &limit, "c06");
    let (_nav1, root1) = navigate_for_root(&mut session, &auth, &limit, &page, "https://example.com/one");
    let node1 = read_node(&mut session, &auth, &limit, &root1);
    // Second navigation replaces the document; old root/node go stale.
    let (_nav2, root2) = navigate_for_root(&mut session, &auth, &limit, &page, "https://example.com/two");
    assert_ne!(root1.root_id, root2.root_id);
    let writer = principal("rm-bo-writer-c06");
    let value = install_bytes(&writer, b"new-value", "text/plain");
    let stale = dom_write(
        &mut session,
        &BODomWrite {
            node: node1,
            property: "value".to_string(),
            value: value.clone(),
        },
        &auth,
        &limit,
    )
    .expect("stale write returns record");
    assert!(stale.value.is_none());
    assert_eq!(stale.record.return_state, "failed");
    let failure = failure_of(&stale.record);
    assert_eq!(failure.code, "STALE_REFERENCE");
    assert_eq!(failure.native_entry, "not_entered");
    // Fresh node from the current document works.
    let node2 = read_node(&mut session, &auth, &limit, &root2);
    let fresh = dom_write(
        &mut session,
        &BODomWrite {
            node: node2.clone(),
            property: "value".to_string(),
            value,
        },
        &auth,
        &limit,
    )
    .expect("fresh write ok");
    assert_eq!(fresh.record.return_state, "returned");
    // Reset invalidates the DOM registry and advances the generation.
    let reset = reset_for_reuse(&mut session, &BOPageArgument { page: page.clone() }, &auth, &limit)
        .expect("reset ok");
    assert_eq!(reset.record.return_state, "returned");
    let reset_value = reset.value.expect("reset value");
    assert_eq!(reset_value.invalidated_generation, 0);
    assert_eq!(reset_value.page.page_generation, 1);
    // Old page reference is now stale.
    let writer2 = principal("rm-bo-writer-c06b");
    let value2 = install_bytes(&writer2, b"after-reset", "text/plain");
    let after_reset = dom_write(
        &mut session,
        &BODomWrite {
            node: node2,
            property: "value".to_string(),
            value: value2,
        },
        &auth,
        &limit,
    )
    .expect("post-reset write returns record");
    assert!(after_reset.value.is_none());
    assert_eq!(failure_of(&after_reset.record).code, "STALE_REFERENCE");
    // Old page generation rejected for navigation.
    let nav_stale = navigate(
        &mut session,
        &BONavigate {
            page,
            url: "https://example.com/three".to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: policy_pin("navigation", "1"),
        },
        &auth,
        &limit,
    )
    .expect("stale navigate returns record");
    assert_eq!(failure_of(&nav_stale.record).code, "STALE_REFERENCE");
    // New generation navigates.
    let nav_fresh = navigate(
        &mut session,
        &BONavigate {
            page: reset_value.page,
            url: "https://example.com/three".to_string(),
            client: MaybeClient::Missing(Missing::new("not_applicable")),
            navigation_policy: policy_pin("navigation", "1"),
        },
        &auth,
        &limit,
    )
    .expect("fresh navigate ok");
    assert_eq!(nav_fresh.record.return_state, "returned");
}

// ---------------------------------------------------------------------------
// RM-C07: direct native DOM/V8 access
// ---------------------------------------------------------------------------

#[test]
fn rm_c07_direct_dom_v8_without_bridge_hop() {
    let parts = session_parts("c07", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    assert_eq!(native_transport(), "browseroxide_native_direct");
    for forbidden in ["cdp", "playwright", "juggler", "camoufox"] {
        assert!(
            !native_transport().contains(forbidden),
            "transport must not route through {forbidden}"
        );
    }
    let page = make_page(&mut session, &auth, &limit, "c07");
    let (_nav, root) = navigate_for_root(&mut session, &auth, &limit, &page, "https://example.com/");
    let read = dom_read(
        &mut session,
        &BODomRead {
            root: root.clone(),
            selector: TimeMaybeString::Missing(Missing::new("not_applicable")),
            depth_limit: 10,
            byte_limit: 1_000_000,
            include_frames: false,
            include_accessible_shadow_roots: false,
        },
        &auth,
        &limit,
    )
    .expect("dom_read ok");
    assert_eq!(read.record.return_state, "returned");
    assert_eq!(read.record.primitive, "bo.dom_read");
    let export = read.value.expect("export");
    assert_eq!(export.root.root_id, root.root_id);
    assert!(!export.nodes.is_empty());
    assert!(!read.record.evidence_refs.is_empty());
    assert_eq!(read.record.elapsed.origin, MeasurementOrigin::SubjectReported);
    assert_eq!(read.record.elapsed.scope.id, read.record.call_id);
    let writer = principal("rm-bo-writer-c07");
    let script = install_bytes(&writer, b"return 42", "text/javascript");
    let evaluated = v8_evaluate(
        &mut session,
        &BOV8Evaluate {
            root: root.clone(),
            script,
            argument: MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        &auth,
        &limit,
    )
    .expect("v8 ok");
    assert_eq!(evaluated.record.return_state, "returned");
    assert_eq!(evaluated.record.primitive, "bo.v8_evaluate");
    let v8 = evaluated.value.expect("v8 value");
    assert_eq!(v8.representation, "json");
    match v8.value {
        MaybeArtifact::Present(reference) => {
            let bytes = rm_evidence::load_artifact(&principal("rm-bo-reader-c07"), &reference)
                .expect("v8 bytes load");
            assert_eq!(bytes, b"42");
        }
        MaybeArtifact::Missing(_) => panic!("json representation must carry a value"),
    }
}

// ---------------------------------------------------------------------------
// RM-C08: clone-independent versus shared-process pools
// ---------------------------------------------------------------------------

#[test]
fn rm_c08_clone_distinct_pool_shared_preserves_pool() {
    let parts = session_parts("c08", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let writer = principal("rm-bo-writer-c08");
    let profile = install_bytes(&writer, b"profile-c08", "application/json");
    let retained = client_create(
        &mut session,
        &BOClientCreate {
            profile: profile.clone(),
            mode: "create_retained".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: "domain-a".to_string(),
        },
        &auth,
        &limit,
    )
    .expect("retained ok");
    let client_a = retained.value.expect("client a");
    // Ordinary clone gets its own pool.
    let cloned = client_create(
        &mut session,
        &BOClientCreate {
            profile: profile.clone(),
            mode: "clone_independent".to_string(),
            source_client: MaybeClient::Present(client_a.clone()),
            session_domain_id: "domain-a".to_string(),
        },
        &auth,
        &limit,
    )
    .expect("clone ok");
    let client_b = cloned.value.expect("client b");
    assert_ne!(client_a.pool_id, client_b.pool_id, "clone must use a distinct pool");
    assert_ne!(client_a.client_id, client_b.client_id);
    // Shared-process handle preserves the actual pool identity.
    let shared = client_create(
        &mut session,
        &BOClientCreate {
            profile,
            mode: "share_process".to_string(),
            source_client: MaybeClient::Present(client_a.clone()),
            session_domain_id: "domain-a".to_string(),
        },
        &auth,
        &limit,
    )
    .expect("share ok");
    let client_c = shared.value.expect("client c");
    assert_eq!(client_a.pool_id, client_c.pool_id, "shared handle preserves pool");
    // Clone without a source is rejected.
    let writer2 = principal("rm-bo-writer-c08b");
    let profile2 = install_bytes(&writer2, b"profile-c08b", "application/json");
    let missing_source = client_create(
        &mut session,
        &BOClientCreate {
            profile: profile2,
            mode: "clone_independent".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: "domain-a".to_string(),
        },
        &auth,
        &limit,
    )
    .expect("missing source returns record");
    assert!(missing_source.value.is_none());
    assert_eq!(failure_of(&missing_source.record).code, "INVALID_INPUT");
}

// ---------------------------------------------------------------------------
// RM-C09: rotating sessions serialize jar-affecting completion
// ---------------------------------------------------------------------------

#[test]
fn rm_c09_rotating_cookie_requests_serialized() {
    let parts = session_parts("c09", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let client = make_client(&mut session, &auth, &limit, "c09", "shop");
    let exchange = |session: &mut NativeSession, seq: u64, gen: u64| {
        http_exchange(
            session,
            &BOHttpExchange {
                client: client.clone(),
                url: "https://shop.example/cart".to_string(),
                method: "GET".to_string(),
                headers: MaybeArtifact::Missing(Missing::new("not_applicable")),
                body: MaybeArtifact::Missing(Missing::new("not_applicable")),
                acquisition_policy: policy_pin("acquisition", "1"),
                session_mode: "rotating".to_string(),
                request_sequence: seq,
                cookie_generation: gen,
            },
            &auth,
            &limit,
        )
        .expect("exchange returns record")
    };
    let first = exchange(&mut session, 1, 0);
    assert_eq!(first.record.return_state, "returned");
    let first_value = first.value.expect("first value");
    assert_eq!(first_value.request_sequence, 1);
    assert_eq!(first_value.cookie_generation, 1);
    // A concurrent replay of the same sequence/generation cannot enter twice.
    let replay = exchange(&mut session, 1, 0);
    assert!(replay.value.is_none());
    assert_eq!(replay.record.return_state, "failed");
    // Correct successor preserves order and advances the jar.
    let second = exchange(&mut session, 2, 1);
    assert_eq!(second.record.return_state, "returned");
    assert_eq!(second.value.expect("second value").cookie_generation, 2);
    // Skipping ahead is rejected; order is preserved.
    let skipped = exchange(&mut session, 4, 2);
    assert!(skipped.value.is_none());
    assert_eq!(failure_of(&skipped.record).code, "INVALID_INPUT");
}

// ---------------------------------------------------------------------------
// RM-C10: process-global storage needs separate processes
// ---------------------------------------------------------------------------

#[test]
fn rm_c10_process_global_requires_separate_processes() {
    let parts_global = session_parts("c10g", "process_global", &[]);
    let (mut global, auth_global, limit_global) = open_parts(parts_global);
    let writer = principal("rm-bo-writer-c10");
    let profile = install_bytes(&writer, b"profile-c10", "application/json");
    let first = client_create(
        &mut global,
        &BOClientCreate {
            profile: profile.clone(),
            mode: "create_retained".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: "domain-a".to_string(),
        },
        &auth_global,
        &limit_global,
    )
    .expect("first domain ok");
    assert_eq!(first.record.return_state, "returned");
    let second = client_create(
        &mut global,
        &BOClientCreate {
            profile,
            mode: "create_retained".to_string(),
            source_client: MaybeClient::Missing(Missing::new("not_applicable")),
            session_domain_id: "domain-b".to_string(),
        },
        &auth_global,
        &limit_global,
    )
    .expect("second domain returns record");
    assert!(second.value.is_none());
    let failure = failure_of(&second.record);
    assert_eq!(failure.code, "INVALID_INPUT");
    assert!(
        failure.detail.contains("separate engine process"),
        "detail must name the process separation requirement: {}",
        failure.detail
    );

    let parts_namespaced = session_parts("c10n", "verified_namespaced", &[]);
    let (mut namespaced, auth_n, limit_n) = open_parts(parts_namespaced);
    let writer2 = principal("rm-bo-writer-c10n");
    let profile2 = install_bytes(&writer2, b"profile-c10n", "application/json");
    for domain in ["domain-a", "domain-b"] {
        let out = client_create(
            &mut namespaced,
            &BOClientCreate {
                profile: profile2.clone(),
                mode: "create_retained".to_string(),
                source_client: MaybeClient::Missing(Missing::new("not_applicable")),
                session_domain_id: domain.to_string(),
            },
            &auth_n,
            &limit_n,
        )
        .expect("namespaced domain ok");
        assert_eq!(out.record.return_state, "returned", "domain {domain} must succeed under verified namespacing");
    }
}

// ---------------------------------------------------------------------------
// RM-C11: offline HTML performs no network acquisition
// ---------------------------------------------------------------------------

#[test]
fn rm_c11_offline_html_no_network_incomplete_explicit() {
    let parts = session_parts("c11", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let page = make_page(&mut session, &auth, &limit, "c11");
    let writer = principal("rm-bo-writer-c11");
    let html = install_bytes(&writer, b"<html><body>hello offline</body></html>", "text/html");
    let complete = from_html(
        &mut session,
        &BOFromHtml {
            page: page.clone(),
            html,
            base_url: TimeMaybeString::Text("https://example.com/".to_string()),
            network: "forbidden".to_string(),
            complete_input_refs: vec![auth.clone()],
        },
        &auth,
        &limit,
    )
    .expect("offline complete ok");
    assert_eq!(complete.record.return_state, "returned");
    assert_eq!(network_attempts(&session), 0);
    let nav = complete.value.expect("nav");
    match nav.response_evidence {
        MaybeArtifact::Missing(_) => {},
        MaybeArtifact::Present(_) => panic!("offline construction must not produce network response evidence"),
    }
    let missing_html = install_bytes(
        &writer,
        b"<html><img src=\"https://cdn.example/missing-resource.png\"></html>",
        "text/html",
    );
    // from_html invalidates the document, so use the latest generation page.
    let current_page = nav.page.clone();
    let incomplete = from_html(
        &mut session,
        &BOFromHtml {
            page: current_page,
            html: missing_html,
            base_url: TimeMaybeString::Text("https://example.com/".to_string()),
            network: "forbidden".to_string(),
            complete_input_refs: vec![auth.clone()],
        },
        &auth,
        &limit,
    )
    .expect("incomplete returns record");
    assert!(incomplete.value.is_none());
    assert_eq!(incomplete.record.return_state, "failed");
    let failure = failure_of(&incomplete.record);
    assert_eq!(failure.code, "INPUTS_INCOMPLETE");
    assert_eq!(failure.native_entry, "not_entered");
    assert_eq!(network_attempts(&session), 0);
}

// ---------------------------------------------------------------------------
// RM-C12: incomplete Page coexists with complete retained HTTP body
// ---------------------------------------------------------------------------

#[test]
fn rm_c12_incomplete_page_and_complete_http_body_preserved() {
    let parts = session_parts("c12", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let client = make_client(&mut session, &auth, &limit, "c12", "content");
    let exchange = http_exchange(
        &mut session,
        &BOHttpExchange {
            client: client.clone(),
            url: "https://content.example/article".to_string(),
            method: "GET".to_string(),
            headers: MaybeArtifact::Missing(Missing::new("not_applicable")),
            body: MaybeArtifact::Missing(Missing::new("not_applicable")),
            acquisition_policy: policy_pin("acquisition", "1"),
            session_mode: "stateful".to_string(),
            request_sequence: 1,
            cookie_generation: 0,
        },
        &auth,
        &limit,
    )
    .expect("http ok");
    assert_eq!(exchange.record.return_state, "returned");
    let http = exchange.value.expect("http value");
    let body_bytes = match &http.body {
        MaybeArtifact::Present(reference) => {
            rm_evidence::load_artifact(&principal("rm-bo-reader-c12"), reference).expect("body loads")
        }
        MaybeArtifact::Missing(_) => panic!("complete HTTP body must be present"),
    };
    assert!(String::from_utf8_lossy(&body_bytes).contains("retained body"));
    let page = make_page(&mut session, &auth, &limit, "c12");
    let (nav, _root) = navigate_for_root(
        &mut session,
        &auth,
        &limit,
        &page,
        "https://content.example/article-incomplete",
    );
    match nav.verdict {
        MaybeVerdictOwned::Present(BORenderVerdict::RenderIncomplete)
        | MaybeVerdictOwned::Present(BORenderVerdict::ThinShell) => {},
        other => panic!("expected an incomplete verdict, found {other:?}"),
    }
    // The retained HTTP body is still complete after the incomplete render.
    let body_again = match &http.body {
        MaybeArtifact::Present(reference) => {
            rm_evidence::load_artifact(&principal("rm-bo-reader-c12b"), reference).expect("body still loads")
        }
        MaybeArtifact::Missing(_) => panic!("http body must stay present"),
    };
    assert_eq!(body_bytes, body_again);
    // The client remains usable; Page is not treated as a superset.
    let second = http_exchange(
        &mut session,
        &BOHttpExchange {
            client,
            url: "https://content.example/article?page=2".to_string(),
            method: "GET".to_string(),
            headers: MaybeArtifact::Missing(Missing::new("not_applicable")),
            body: MaybeArtifact::Missing(Missing::new("not_applicable")),
            acquisition_policy: policy_pin("acquisition", "1"),
            session_mode: "stateful".to_string(),
            request_sequence: 2,
            cookie_generation: 1,
        },
        &auth,
        &limit,
    )
    .expect("second http ok");
    assert_eq!(second.record.return_state, "returned");
}

// ---------------------------------------------------------------------------
// RM-C18: property mutation versus synthetic events
// ---------------------------------------------------------------------------

#[test]
fn rm_c18_property_mutation_and_synthetic_events_disclosed() {
    let parts = session_parts("c18", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let page = make_page(&mut session, &auth, &limit, "c18");
    let (_nav, root) = navigate_for_root(&mut session, &auth, &limit, &page, "https://example.com/form");
    let node = read_node(&mut session, &auth, &limit, &root);
    let writer = principal("rm-bo-writer-c18");
    let value = install_bytes(&writer, b"alice", "text/plain");
    let written = dom_write(
        &mut session,
        &BODomWrite {
            node: node.clone(),
            property: "value".to_string(),
            value,
        },
        &auth,
        &limit,
    )
    .expect("write ok");
    assert_eq!(written.record.return_state, "returned");
    assert_eq!(written.record.primitive, "bo.dom_write");
    let mutation = written.value.expect("mutation");
    // Events are separate and never implicit for a property write.
    assert!(matches!(mutation.event_observation, MaybeArtifact::Missing(_)));
    let record_text = format!("{:?} {:?}", written.record.arguments, mutation.to_json());
    assert!(
        !record_text.to_lowercase().contains("trusted"),
        "property mutation must not be labeled as trusted input"
    );
    let dispatched = event_dispatch(
        &mut session,
        &BOEventDispatch {
            node,
            event_type: "input".to_string(),
            bubbles: true,
            cancelable: false,
            composed: true,
            detail: MaybeArtifact::Missing(Missing::new("not_applicable")),
        },
        &auth,
        &limit,
    )
    .expect("dispatch ok");
    assert_eq!(dispatched.record.return_state, "returned");
    assert_eq!(dispatched.record.primitive, "bo.event_dispatch");
    assert_eq!(dispatched.record.arguments["bubbles"], json!(true));
    assert_eq!(dispatched.record.arguments["cancelable"], json!(false));
    assert_eq!(dispatched.record.arguments["composed"], json!(true));
    let observed = dispatched.value.expect("dispatch value");
    assert!(matches!(observed.event_observation, MaybeArtifact::Present(_)));
    let dispatch_text = format!("{:?} {:?}", dispatched.record.arguments, observed.to_json());
    assert!(
        !dispatch_text.to_lowercase().contains("trusted"),
        "synthetic events must not be labeled as trusted input"
    );
}

// ---------------------------------------------------------------------------
// RM-C19: file assignment is not server acceptance
// ---------------------------------------------------------------------------

#[test]
fn rm_c19_upload_assignment_without_server_acceptance() {
    let parts = session_parts("c19", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let page = make_page(&mut session, &auth, &limit, "c19");
    let (_nav, root) = navigate_for_root(&mut session, &auth, &limit, &page, "https://example.com/upload");
    let node = read_node(&mut session, &auth, &limit, &root);
    let writer = principal("rm-bo-writer-c19");
    let file = install_bytes(&writer, b"resume-bytes", "application/pdf");
    let assigned = assign_files(
        &mut session,
        &BOAssignFiles {
            node: node.clone(),
            files: vec![file],
        },
        &auth,
        &limit,
    )
    .expect("assign ok");
    assert_eq!(assigned.record.return_state, "returned");
    let mutation = assigned.value.expect("mutation");
    let text = format!("{:?} {:?}", assigned.record.arguments, mutation.to_json()).to_lowercase();
    for forbidden in ["accepted", "upload-success", "upload_success", "commitment", "committed"] {
        assert!(
            !text.contains(forbidden),
            "assignment must not claim {forbidden}"
        );
    }
    assert!(matches!(mutation.readback, MaybeArtifact::Missing(_)));
    // Empty assignment is rejected.
    let empty = assign_files(&mut session, &BOAssignFiles { node, files: Vec::new() }, &auth, &limit)
        .expect("empty returns record");
    assert!(empty.value.is_none());
    assert_eq!(failure_of(&empty.record).code, "INVALID_INPUT");
}

// ---------------------------------------------------------------------------
// RM-C42: capture limits are explicit; no invented coordinate primitive
// ---------------------------------------------------------------------------

#[test]
fn rm_c42_capture_limitation_no_invented_coordinate_action() {
    assert!(
        !BO_PRIMITIVES.contains(&"bo.coordinate_click"),
        "no coordinate-click primitive exists"
    );
    // Mapped capture with geometry.
    let parts = session_parts("c42a", "verified_namespaced", &[]);
    let (mut session, auth, limit) = open_parts(parts);
    let page = make_page(&mut session, &auth, &limit, "c42a");
    let writer = principal("rm-bo-writer-c42");
    let options = install_bytes(&writer, b"{\"format\":\"png\",\"crop\":\"viewport\"}", "application/json");
    let captured = capture(&mut session, &BOCapture { page: page.clone(), capture_options: options }, &auth, &limit)
        .expect("capture ok");
    assert_eq!(captured.record.return_state, "returned");
    let with_geometry = captured.value.expect("capture value");
    assert!(!with_geometry.geometry.is_empty(), "geometry present for coordinate grounding");
    // Mapped capture without geometry: explicit limitation, no coordinates.
    let no_geometry = install_bytes(&writer, b"{\"format\":\"png\",\"no-geometry\":true}", "application/json");
    let limited = capture(&mut session, &BOCapture { page, capture_options: no_geometry }, &auth, &limit)
        .expect("limited capture ok");
    assert_eq!(limited.record.return_state, "returned");
    let without = limited.value.expect("limited value");
    assert!(
        without.geometry.is_empty(),
        "missing geometry must stay explicit; coordinate action is not authorized"
    );
    // Unmapped capture: unsupported, not synthesized.
    let parts_unmapped = session_parts("c42b", "verified_namespaced", &["bo.capture"]);
    let (mut session_u, auth_u, limit_u) = open_parts(parts_unmapped);
    let page_u = make_page(&mut session_u, &auth_u, &limit_u, "c42b");
    let writer_u = principal("rm-bo-writer-c42b");
    let options_u = install_bytes(&writer_u, b"{\"format\":\"png\"}", "application/json");
    let unmapped = capture(
        &mut session_u,
        &BOCapture { page: page_u, capture_options: options_u },
        &auth_u,
        &limit_u,
    )
    .expect("unmapped returns record");
    assert!(unmapped.value.is_none());
    assert_eq!(unmapped.record.return_state, "unsupported");
    assert_eq!(failure_of(&unmapped.record).code, "UNMAPPED_PRIMITIVE");
}
