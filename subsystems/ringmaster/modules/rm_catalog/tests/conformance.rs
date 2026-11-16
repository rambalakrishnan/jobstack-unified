//! RM-C51 conformance: connector Describe and native binding catalogs.
//!
//! Every test name contains `rm_c51` so the verification filter
//! `cargo test -p rm_catalog -- rm_c51` selects the whole suite.

use rm_authority::Manifest;
use rm_catalog::{
    AccessClass, ArtifactReference, AuthenticatedPrincipal, BO_CAPABILITIES, BO_PRIMITIVES,
    BOBindingDescriptor, BOMapping, CapabilityDescriptor, CapabilityEvidence, CapabilityRecord,
    ComponentIdentity, ConnectorDescriptor, DescribeRequest, EvidenceRef, JournalPrefix,
    MaybeDigest, MaybeString, MaybeVersionPin, Missing, NINE_OPERATIONS, PositiveInteger,
    SubjectIdentity, VersionPin, BO_RECORD_TYPE, BO_SCHEMA_VERSION, CAPABILITY_RECORD_TYPE,
    CAPABILITY_SCHEMA_VERSION, CONNECTOR_RECORD_TYPE, CONNECTOR_SCHEMA_VERSION,
    EXTERNAL_CATALOG_MIN,
};
use rm_evidence::{EventSubmission, EvidencePayload, MaybeTimePoint};
use serde_json::json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Helpers
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
    rm_authority::authenticate_channel(&mut Cursor::new(bytes)).expect("principal authenticates")
}

fn test_manifest(run: &str, kinds: &[&str]) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: kinds.iter().map(|kind| (*kind).to_string()).collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    manifest.manifest_hash = rm_wire::canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    manifest
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact = rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact");
    EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("positive")),
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

fn observation(kind: &str, sequence: u64, artifacts: Vec<ArtifactReference>) -> EventSubmission {
    let registration = rm_evidence::event_registration(kind).expect("kind is registered");
    EventSubmission {
        producer_sequence: Some(PositiveInteger::new(sequence).expect("positive")),
        event_kind: kind.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: artifacts,
        },
    }
}

/// Retains a journal with an artifact-backed event and returns its prefix plus
/// a reference to the artifact-bearing envelope.
fn journal_fixture(test: &str) -> (AuthenticatedPrincipal, JournalPrefix, EvidenceRef) {
    let writer = principal(&format!("rm-c51-{test}"));
    let run = format!("rm-c51-run-{test}");
    let manifest = test_manifest(
        &run,
        &["manifest_admitted", "artifact_available", "execution_claim"],
    );
    let bytes = format!("rm-c51-evidence-bytes-{test}").into_bytes();
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: "evidence".to_string(),
        access: AccessClass::Public,
    };
    rm_evidence::install_artifact(&writer, &reference, &bytes).expect("artifact installs");
    rm_evidence::append_event(&writer, &manifest, admission(&manifest)).expect("admission");
    let artifact_event =
        rm_evidence::append_event(&writer, &manifest, observation("artifact_available", 2, vec![reference]))
            .expect("artifact event appends");
    rm_evidence::append_event(&writer, &manifest, observation("execution_claim", 3, Vec::new()))
        .expect("claim appends");
    let journal_id = rm_evidence::journal_id_for(&manifest).expect("journal identity");
    let prefix = rm_evidence::journal_head(&writer, &journal_id).expect("journal head");
    let evidence = EvidenceRef {
        journal_id: artifact_event.journal_id.clone(),
        sequence: artifact_event.journal_sequence,
        event_id: artifact_event.event_id.clone(),
        event_hash: artifact_event.event_hash.clone(),
        pointer: String::new(),
    };
    (writer, prefix, evidence)
}

fn synthetic_ref() -> EvidenceRef {
    EvidenceRef {
        journal_id: "journal-synthetic-rm-c51".to_string(),
        sequence: PositiveInteger::new(1).expect("positive"),
        event_id: "event-synthetic".to_string(),
        event_hash: rm_wire::artifact_digest(b"rm-c51-synthetic-event"),
        pointer: String::new(),
    }
}

fn synthetic_prefix() -> JournalPrefix {
    JournalPrefix {
        journal_id: "journal-synthetic-rm-c51".to_string(),
        last_sequence: PositiveInteger::new(1).expect("positive"),
        head_hash: rm_wire::artifact_digest(b"rm-c51-synthetic-head"),
    }
}

fn bo_engine() -> ComponentIdentity {
    ComponentIdentity {
        component: "browseroxide-engine".to_string(),
        reported_version: MaybeString::Text("2.0.0".to_string()),
        build_digest: MaybeDigest::Present(rm_wire::artifact_digest(b"rm-c51-engine-build")),
        configuration_digest: MaybeDigest::Present(rm_wire::artifact_digest(
            b"rm-c51-engine-config",
        )),
    }
}

fn bo_subject(engine: &ComponentIdentity) -> SubjectIdentity {
    SubjectIdentity {
        subject_id: "bo-binding-1".to_string(),
        subject_version: "1.0.0".to_string(),
        revision_basis: "native_revision".to_string(),
        native_revision: MaybeString::Text("native-rev-1".to_string()),
        configured_mode: "default".to_string(),
        interface_surface: "browseroxide-ffi".to_string(),
        configuration_digest: rm_wire::artifact_digest(b"rm-c51-bo-config"),
        stack: vec![engine.clone()],
    }
}

fn bo_record(id: &str, present: bool, evidence: &EvidenceRef) -> CapabilityRecord {
    if present {
        CapabilityRecord {
            capability_id: id.to_string(),
            requirement_refs: Vec::new(),
            availability: "present".to_string(),
            claim_origin: "native".to_string(),
            evidence: vec![CapabilityEvidence {
                basis: "executed_observation".to_string(),
                reference: evidence.clone(),
            }],
            limitations: Vec::new(),
        }
    } else {
        CapabilityRecord {
            capability_id: id.to_string(),
            requirement_refs: Vec::new(),
            availability: "unknown".to_string(),
            claim_origin: "harness".to_string(),
            evidence: Vec::new(),
            limitations: vec![format!("{id} is unassessed")],
        }
    }
}

fn bo_mapped(primitive: &str, evidence: &EvidenceRef) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "mapped".to_string(),
        native_symbol: MaybeString::Text(format!("native_{}", primitive.replace('.', "_"))),
        native_contract: MaybeVersionPin::Present(VersionPin {
            id: "bo-contract".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(primitive.as_bytes()),
        }),
        evidence_refs: vec![evidence.clone()],
    }
}

fn bo_unmapped(primitive: &str) -> BOMapping {
    BOMapping {
        primitive: primitive.to_string(),
        mapping_state: "unmapped".to_string(),
        native_symbol: MaybeString::Missing(Missing::new("not_observed")),
        native_contract: MaybeVersionPin::Missing(Missing::new("not_applicable")),
        evidence_refs: Vec::new(),
    }
}

/// Builds a binding descriptor with the first `present_count` capabilities
/// present (executed observation) and the first `mapped_count` primitives
/// mapped, citing `evidence` under `prefix`.
fn bo_descriptor(
    prefix: &JournalPrefix,
    evidence: &EvidenceRef,
    present_count: usize,
    mapped_count: usize,
    storage_model: &str,
    isolation: Vec<EvidenceRef>,
) -> BOBindingDescriptor {
    let engine = bo_engine();
    let subject = bo_subject(&engine);
    BOBindingDescriptor {
        record_type: BO_RECORD_TYPE.to_string(),
        schema_version: BO_SCHEMA_VERSION.to_string(),
        binding_id: "bo-binding-1".to_string(),
        binding_build: VersionPin {
            id: "bo-binding-1".to_string(),
            version: "1.0.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(b"rm-c51-binding-build"),
        },
        engine,
        capabilities: CapabilityDescriptor {
            record_type: CAPABILITY_RECORD_TYPE.to_string(),
            schema_version: CAPABILITY_SCHEMA_VERSION.to_string(),
            descriptor_id: "bo-capabilities-1".to_string(),
            descriptor_revision: 1,
            declared_by: "bo-binding-1".to_string(),
            subject,
            catalog: VersionPin {
                id: "bo-catalog".to_string(),
                version: "0.1.0".to_string(),
                artifact_digest: rm_wire::artifact_digest(b"rm-c51-bo-catalog"),
            },
            evidence_prefix: prefix.clone(),
            supersedes: MaybeDigest::Missing(Missing::new("not_applicable")),
            capabilities: BO_CAPABILITIES
                .iter()
                .enumerate()
                .map(|(index, id)| bo_record(id, index < present_count, evidence))
                .collect(),
        },
        primitive_mappings: BO_PRIMITIVES
            .iter()
            .enumerate()
            .map(|(index, primitive)| {
                if index < mapped_count {
                    bo_mapped(primitive, evidence)
                } else {
                    bo_unmapped(primitive)
                }
            })
            .collect(),
        session_storage_model: storage_model.to_string(),
        session_isolation_refs: isolation,
        privacy_policy: VersionPin {
            id: "bo-privacy".to_string(),
            version: "0.1.0".to_string(),
            artifact_digest: rm_wire::artifact_digest(b"rm-c51-privacy"),
        },
        evidence_prefix: prefix.clone(),
    }
}

fn connector_ids(descriptor: &ConnectorDescriptor) -> Vec<String> {
    descriptor
        .capabilities
        .capabilities
        .iter()
        .map(|record| record.capability_id.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------------

#[test]
fn rm_c51_describe_returns_complete_connector_descriptor() {
    let caller = principal("rm-c51-describe");
    // No journal exists: Describe is a local read, not a probe.
    let descriptor = rm_catalog::describe(&caller, &DescribeRequest).expect("describe succeeds");

    assert_eq!(descriptor.record_type, CONNECTOR_RECORD_TYPE);
    assert_eq!(descriptor.schema_version, CONNECTOR_SCHEMA_VERSION);
    assert!(!descriptor.connector_id.is_empty());
    assert!(!descriptor.connector_version.is_empty());

    // Exactly nine operations, each verb once.
    assert_eq!(descriptor.operations.len(), NINE_OPERATIONS.len());
    let mut verbs: Vec<&str> = descriptor
        .operations
        .iter()
        .map(|mapping| mapping.operation.as_str())
        .collect();
    verbs.sort_unstable();
    let mut expected = NINE_OPERATIONS.to_vec();
    expected.sort_unstable();
    assert_eq!(verbs, expected);

    // One descriptor, one scope.
    assert_eq!(descriptor.subject, descriptor.capabilities.subject);

    // Minimum external catalog coverage.
    let ids = connector_ids(&descriptor);
    for required in EXTERNAL_CATALOG_MIN {
        assert!(ids.iter().any(|id| id == required), "missing {required}");
    }

    // Task mappings unique by task type; channels unique.
    let mut task_types: Vec<&str> = descriptor
        .task_mappings
        .iter()
        .map(|mapping| mapping.task_type.as_str())
        .collect();
    task_types.sort_unstable();
    let mut deduped = task_types.clone();
    deduped.dedup();
    assert_eq!(task_types, deduped);
    let mut channels = descriptor.observation_channels.clone();
    channels.sort_unstable();
    let mut deduped_channels = channels.clone();
    deduped_channels.dedup();
    assert_eq!(channels, deduped_channels);

    // The served records are wire-valid closed objects.
    let bytes = serde_json::to_vec(&descriptor.to_json()).expect("descriptor serializes");
    rm_wire::validate_record("connector_descriptor/v1", &bytes).expect("wire-valid descriptor");
    let capability_bytes =
        serde_json::to_vec(&descriptor.capabilities.to_json()).expect("capabilities serialize");
    rm_wire::validate_record("capability_descriptor/v1", &capability_bytes)
        .expect("wire-valid capabilities");

    // Declarations only: no qualification or success flag exists on the shape.
    let json = descriptor.to_json();
    let object = json.as_object().expect("descriptor is an object");
    assert!(!object.contains_key("qualification"));
    assert!(!object.contains_key("application_success"));
    assert!(!object.contains_key("requirement_satisfaction"));
}

#[test]
fn rm_c51_describe_is_deterministic_local_read_without_probe() {
    let caller = principal("rm-c51-describe-repeat");
    let first = rm_catalog::describe(&caller, &DescribeRequest).expect("first describe");
    let second = rm_catalog::describe(&caller, &DescribeRequest).expect("second describe");
    // A local descriptor read returns the same pinned bytes every time; no
    // browser launch, endpoint probe, or task execution intervenes.
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first.to_json()).expect("serializes"),
        serde_json::to_vec(&second.to_json()).expect("serializes"),
    );
}

// ---------------------------------------------------------------------------
// Binding validation: positive paths
// ---------------------------------------------------------------------------

#[test]
fn rm_c51_validate_binding_accepts_fully_evidenced_descriptor() {
    let (writer, prefix, evidence) = journal_fixture("accept-evidenced");
    let descriptor = bo_descriptor(&prefix, &evidence, 7, 9, "verified_namespaced", vec![evidence.clone()]);
    rm_catalog::validate_native_binding(&writer, &descriptor).expect("evidenced binding validates");
}

#[test]
fn rm_c51_validate_binding_mapped_does_not_imply_present() {
    // All fourteen primitives mapped, yet every capability unknown: mapping
    // state never establishes availability.
    let (writer, prefix, evidence) = journal_fixture("mapped-unknown");
    let descriptor = bo_descriptor(&prefix, &evidence, 0, 14, "unknown", Vec::new());
    rm_catalog::validate_native_binding(&writer, &descriptor)
        .expect("mapped primitives with unknown capabilities validate");
}

#[test]
fn rm_c51_validate_binding_unmapped_does_not_imply_absent() {
    // Nothing mapped and nothing assessed: unmapped never establishes native
    // absence, and the descriptor validates without resolving any evidence.
    let caller = principal("rm-c51-unmapped-unknown");
    let prefix = synthetic_prefix();
    let unused = synthetic_ref();
    let descriptor = bo_descriptor(&prefix, &unused, 0, 0, "unknown", Vec::new());
    rm_catalog::validate_native_binding(&caller, &descriptor)
        .expect("unmapped primitives with unknown capabilities validate");
}

// ---------------------------------------------------------------------------
// Binding validation: primitive mappings
// ---------------------------------------------------------------------------

#[test]
fn rm_c51_validate_binding_rejects_primitive_count() {
    let caller = principal("rm-c51-primitive-count");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.primitive_mappings.pop();
    let error = rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("count must fail");
    assert!(error.detail.contains("exactly 14"), "unexpected detail: {}", error.detail);
}

#[test]
fn rm_c51_validate_binding_rejects_duplicate_primitive() {
    let caller = principal("rm-c51-primitive-duplicate");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.primitive_mappings[0] = descriptor.primitive_mappings[1].clone();
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("duplicate must fail");
    assert!(
        error.detail.contains("duplicate") || error.detail.contains("omits"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c51_validate_binding_rejects_mapped_without_evidence() {
    let caller = principal("rm-c51-mapped-no-evidence");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    let mut mapped = bo_mapped("bo.navigate", &evidence);
    mapped.evidence_refs.clear();
    descriptor.primitive_mappings[3] = mapped;
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("evidence required");
    assert!(error.detail.contains("evidence"), "unexpected detail: {}", error.detail);
}

#[test]
fn rm_c51_validate_binding_rejects_mapped_without_symbol() {
    let caller = principal("rm-c51-mapped-no-symbol");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    let mut mapped = bo_mapped("bo.navigate", &evidence);
    mapped.native_symbol = MaybeString::Missing(Missing::new("not_observed"));
    descriptor.primitive_mappings[3] = mapped;
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("symbol required");
    assert!(error.detail.contains("symbol"), "unexpected detail: {}", error.detail);
}

#[test]
fn rm_c51_validate_binding_rejects_guessed_symbol_on_unmapped() {
    let caller = principal("rm-c51-unmapped-guess");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    let mut unmapped = bo_unmapped("bo.navigate");
    unmapped.native_symbol = MaybeString::Text("guessed_symbol".to_string());
    descriptor.primitive_mappings[3] = unmapped;
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("guess must fail");
    assert!(error.detail.contains("symbol"), "unexpected detail: {}", error.detail);
}

// ---------------------------------------------------------------------------
// Binding validation: capability catalog and scope pinning
// ---------------------------------------------------------------------------

#[test]
fn rm_c51_validate_binding_rejects_incomplete_capability_catalog() {
    let caller = principal("rm-c51-incomplete-catalog");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.capabilities.capabilities.pop();
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("catalog must fail");
    assert!(
        error.detail.contains("exactly 14") || error.detail.contains("omits"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c51_validate_binding_rejects_subject_mismatch_without_inheritance() {
    // A capability descriptor copied from another binding version never
    // validates: new versions start unknown and nothing inherits.
    let caller = principal("rm-c51-subject-mismatch");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.capabilities.subject.subject_version = "2.0.0".to_string();
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("mismatch must fail");
    assert!(
        error.detail.contains("binding build") || error.detail.contains("unknown"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c51_validate_binding_rejects_present_without_evidence() {
    let caller = principal("rm-c51-present-no-evidence");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.capabilities.capabilities[0].availability = "present".to_string();
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("evidence required");
    assert!(error.detail.contains("evidence"), "unexpected detail: {}", error.detail);
}

#[test]
fn rm_c51_validate_binding_rejects_documentation_only_present() {
    // Documentation supports a declaration, never a run-success finding.
    let caller = principal("rm-c51-present-documentation");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.capabilities.capabilities[0].availability = "present".to_string();
    descriptor.capabilities.capabilities[0].evidence = vec![CapabilityEvidence {
        basis: "documentation".to_string(),
        reference: evidence,
    }];
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("basis must fail");
    assert!(
        error.detail.contains("executed_observation"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c51_validate_binding_rejects_unresolvable_evidence() {
    // Structurally valid but citing a journal that was never retained:
    // resolution through the evidence boundary must fail.
    let caller = principal("rm-c51-unresolvable");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let descriptor = bo_descriptor(&prefix, &evidence, 14, 14, "unknown", Vec::new());
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("resolve must fail");
    assert!(
        error.detail.contains("not retained") || error.detail.contains("journal"),
        "unexpected detail: {}",
        error.detail
    );
}

#[test]
fn rm_c51_validate_binding_rejects_verified_namespaced_without_isolation() {
    let caller = principal("rm-c51-isolation-missing");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "verified_namespaced", Vec::new());
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("isolation required");
    assert!(error.detail.contains("isolation"), "unexpected detail: {}", error.detail);
}

#[test]
fn rm_c51_validate_binding_rejects_bad_discriminators() {
    let caller = principal("rm-c51-discriminator");
    let prefix = synthetic_prefix();
    let evidence = synthetic_ref();
    let mut descriptor = bo_descriptor(&prefix, &evidence, 0, 0, "unknown", Vec::new());
    descriptor.record_type = "connector_descriptor".to_string();
    let error =
        rm_catalog::validate_native_binding(&caller, &descriptor).expect_err("type must fail");
    assert!(error.detail.contains("record_type"), "unexpected detail: {}", error.detail);
}
