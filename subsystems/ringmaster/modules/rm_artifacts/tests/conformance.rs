//! Conformance tests for RM-C47 (named inventory, missing slots, lost bytes)
//! and RM-C48 (chunk bounds, EOF, digest validation).
//!
//! Every test name carries `rm_c47` or `rm_c48` so the verification filter
//! `cargo test -p rm_artifacts -- rm_c47 rm_c48` selects the suite.

use rm_artifacts::{
    collect_chunk, collect_inventory, encode_base64, publish_named_artifact,
    register_expected_digest, register_handle, verify_chunk, verify_slot, AccessClass,
    ArtifactReference, ArtifactSelector, AuthenticatedPrincipal, ConnectorError, ConnectorRequest,
    Digest, EvidenceRef, HandleReference, Manifest, MaybeArtifact, MaybeDigest, Missing,
};
use rm_authority::{authenticate_channel, manifest_wire_bytes};
use rm_evidence::{
    append_event, install_artifact, journal_head, journal_id_for, manifest_artifact_reference,
    resolve_evidence, EventSubmission, EvidencePayload, JournalEnvelope, PositiveInteger,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_id(tag: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("{tag}-{}-{n}", std::process::id())
}

fn principal(id: &str) -> AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": id,
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": format!("binding-{id}"),
        },
    });
    let bytes = serde_json::to_vec(&registration).expect("registration serializes");
    authenticate_channel(&mut Cursor::new(bytes)).expect("test principal authenticates")
}

fn manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: ["manifest_admitted", "artifact_available"]
            .iter()
            .map(|kind| (*kind).to_string())
            .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    manifest
}

fn admit(writer: &AuthenticatedPrincipal, manifest: &Manifest) -> JournalEnvelope {
    let artifact = manifest_artifact_reference(manifest).expect("manifest artifact reference");
    let submission = EventSubmission {
        producer_sequence: Some(PositiveInteger::new(1).expect("positive")),
        event_kind: "manifest_admitted".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: rm_evidence::MaybeTimePoint::Missing(Missing::new("not_applicable")),
        payload: EvidencePayload {
            data: json!({"manifest": artifact.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![artifact],
        },
    };
    append_event(writer, manifest, submission).expect("manifest admission")
}

fn admission_ref(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

fn install(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    access: AccessClass,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: "artifact".to_string(),
        access,
    };
    install_artifact(writer, &reference, bytes).expect("artifact install");
    reference
}

/// Admits a fresh journal and binds a fresh handle to it.
fn setup(tag: &str, writer: &AuthenticatedPrincipal) -> (Manifest, String, HandleReference) {
    let run = unique_id(tag);
    let manifest = manifest(&run);
    let envelope = admit(writer, &manifest);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = HandleReference {
        connector_id: "ringmaster".to_string(),
        local_handle: format!("handle-{run}"),
    };
    register_handle(writer, &handle, &journal_id, &admission_ref(&envelope))
        .expect("handle registration");
    (manifest, journal_id, handle)
}

fn inventory_request(handle: &HandleReference, tag: &str) -> ConnectorRequest {
    ConnectorRequest::new(
        "ringmaster",
        &unique_id(&format!("req-{tag}")),
        handle.clone(),
        ArtifactSelector::Inventory,
    )
}

fn named_request(handle: &HandleReference, tag: &str, names: Vec<String>) -> ConnectorRequest {
    ConnectorRequest::new(
        "ringmaster",
        &unique_id(&format!("req-{tag}")),
        handle.clone(),
        ArtifactSelector::Named { names },
    )
}

fn bytes_request(
    handle: &HandleReference,
    tag: &str,
    digest: Digest,
    offset: u64,
    max_bytes: u64,
) -> ConnectorRequest {
    ConnectorRequest::new(
        "ringmaster",
        &unique_id(&format!("req-{tag}")),
        handle.clone(),
        ArtifactSelector::Bytes {
            digest,
            offset,
            max_bytes,
        },
    )
}

fn assert_error_code(error: &ConnectorError, code: &str) {
    assert_eq!(error.kind, "connector_error", "error: {error:?}");
    assert_eq!(
        error.code, code,
        "expected {code}, got {}: {}",
        error.code, error.detail
    );
}

/// Every JSON null must be the `value` of a reasoned Missing envelope.
fn assert_no_bare_nulls(value: &Value) {
    match value {
        Value::Null => panic!("bare null is never a valid artifact response value"),
        Value::Object(map) => {
            if map.get("value") == Some(&Value::Null) {
                let reason = map.get("reason").and_then(Value::as_str);
                assert!(
                    matches!(
                        reason,
                        Some(
                            "not_enabled"
                                | "not_applicable"
                                | "not_observed"
                                | "observation_lost"
                                | "unsupported_by_subject"
                                | "manual_override"
                        )
                    ),
                    "null carrier without a valid Missing reason: {value}"
                );
                for (key, item) in map {
                    if key != "value" {
                        assert_no_bare_nulls(item);
                    }
                }
            } else {
                for item in map.values() {
                    assert_no_bare_nulls(item);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                assert_no_bare_nulls(item);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// RM-C47: named inventory, missing slots, lost bytes
// ---------------------------------------------------------------------------

#[test]
fn rm_c47_inventory_lists_published_slots_with_matching_digests() {
    let writer = principal(&unique_id("writer-c47-list"));
    let (manifest, journal_id, handle) = setup("c47-list", &writer);
    let alpha_bytes = b"alpha artifact bytes";
    let beta_bytes = b"beta artifact bytes, slightly longer";
    let alpha = install(&writer, alpha_bytes, AccessClass::Public);
    let beta = install(&writer, beta_bytes, AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "alpha", &alpha).expect("publish alpha");
    publish_named_artifact(&writer, &manifest, &handle, "beta", &beta).expect("publish beta");

    let inventory = collect_inventory(&writer, &inventory_request(&handle, "c47-list"))
        .expect("inventory collects");
    assert_eq!(inventory.kind, "artifact_inventory");
    assert_eq!(inventory.handle, handle);
    assert_eq!(inventory.coverage, "complete");
    assert!(inventory.limitations.is_empty());
    assert_eq!(inventory.artifacts.len(), 2);
    assert_eq!(inventory.artifacts[0].name, "alpha");
    assert_eq!(inventory.artifacts[1].name, "beta");
    for slot in &inventory.artifacts {
        verify_slot(slot).expect("slot verifies");
        match (&slot.expected_digest, &slot.content) {
            (MaybeDigest::Present(expected), MaybeArtifact::Present(content)) => {
                assert_eq!(expected, &content.digest);
                let stored = rm_evidence::load_artifact(&writer, content).expect("bytes load");
                assert_eq!(artifact_digest(&stored), *expected);
            }
            other => panic!("published slots must be fully present: {other:?}"),
        }
        assert!(!slot.evidence_refs.is_empty());
    }
    assert_eq!(inventory.evidence_prefix.journal_id, journal_id);
    let head = journal_head(&writer, &journal_id).expect("journal head");
    assert_eq!(inventory.evidence_prefix, head);
    assert_no_bare_nulls(&inventory.to_json());
}

#[test]
fn rm_c47_named_returns_exactly_requested_names_in_requested_order() {
    let writer = principal(&unique_id("writer-c47-named"));
    let (manifest, _, handle) = setup("c47-named", &writer);
    let alpha = install(&writer, b"alpha", AccessClass::Public);
    let beta = install(&writer, b"beta", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "alpha", &alpha).expect("publish alpha");
    publish_named_artifact(&writer, &manifest, &handle, "beta", &beta).expect("publish beta");

    let request = named_request(
        &handle,
        "c47-named",
        vec![
            "beta".to_string(),
            "ghost".to_string(),
            "alpha".to_string(),
        ],
    );
    let inventory = collect_inventory(&writer, &request).expect("named collects");
    assert_eq!(inventory.coverage, "partial");
    assert_eq!(inventory.artifacts.len(), 3);
    assert_eq!(inventory.artifacts[0].name, "beta");
    assert_eq!(inventory.artifacts[1].name, "ghost");
    assert_eq!(inventory.artifacts[2].name, "alpha");
    assert!(matches!(
        inventory.artifacts[0].content,
        MaybeArtifact::Present(_)
    ));
    assert!(matches!(
        inventory.artifacts[1].content,
        MaybeArtifact::Missing(_)
    ));
    assert!(matches!(
        inventory.artifacts[2].content,
        MaybeArtifact::Present(_)
    ));
    assert!(
        !inventory.limitations.is_empty(),
        "partial coverage must be disclosed"
    );
    assert_no_bare_nulls(&inventory.to_json());
}

#[test]
fn rm_c47_missing_slots_use_reasoned_missingness_with_supporting_evidence() {
    let writer = principal(&unique_id("writer-c47-miss"));
    let (_, journal_id, handle) = setup("c47-miss", &writer);
    let request = named_request(&handle, "c47-miss", vec!["never-registered".to_string()]);
    let inventory = collect_inventory(&writer, &request).expect("named collects");
    assert_eq!(inventory.artifacts.len(), 1);
    let slot = &inventory.artifacts[0];
    verify_slot(slot).expect("missing slot verifies");
    match (&slot.expected_digest, &slot.content) {
        (MaybeDigest::Missing(expected), MaybeArtifact::Missing(content)) => {
            assert_eq!(expected.reason, "not_observed");
            assert_eq!(content.reason, "not_observed");
        }
        other => panic!("unknown names must be doubly missing: {other:?}"),
    }
    assert!(
        !slot.evidence_refs.is_empty(),
        "missing slots still carry supporting evidence"
    );
    for reference in &slot.evidence_refs {
        resolve_evidence(&writer, reference, &inventory.evidence_prefix)
            .expect("missing-slot evidence resolves");
    }
    assert_eq!(inventory.evidence_prefix.journal_id, journal_id);
    assert_no_bare_nulls(&slot.to_json());
}

#[test]
fn rm_c47_lost_bytes_preserve_known_digest() {
    let writer = principal(&unique_id("writer-c47-lost"));
    let (_, _, handle) = setup("c47-lost", &writer);
    let lost_digest = artifact_digest(b"bytes that were never installed");
    register_expected_digest(&writer, &handle, "lost-report", &lost_digest)
        .expect("known digest records");

    let request = named_request(&handle, "c47-lost", vec!["lost-report".to_string()]);
    let inventory = collect_inventory(&writer, &request).expect("named collects");
    assert_eq!(inventory.artifacts.len(), 1);
    let slot = &inventory.artifacts[0];
    verify_slot(slot).expect("lost slot verifies");
    match (&slot.expected_digest, &slot.content) {
        (MaybeDigest::Present(expected), MaybeArtifact::Missing(content)) => {
            assert_eq!(expected, &lost_digest, "identity survives loss");
            assert_eq!(content.reason, "observation_lost");
        }
        other => panic!("lost bytes must preserve identity: {other:?}"),
    }
    assert!(!slot.evidence_refs.is_empty());
    assert_no_bare_nulls(&inventory.to_json());
}

#[test]
fn rm_c47_empty_inventory_is_established_empty_with_prefix() {
    let writer = principal(&unique_id("writer-c47-empty"));
    let (_, journal_id, handle) = setup("c47-empty", &writer);
    let inventory = collect_inventory(&writer, &inventory_request(&handle, "c47-empty"))
        .expect("empty inventory collects");
    assert!(inventory.artifacts.is_empty());
    assert_eq!(
        inventory.coverage, "complete",
        "established empty inventory is complete, not a default"
    );
    assert_eq!(inventory.evidence_prefix.journal_id, journal_id);
    assert_eq!(inventory.evidence_prefix.last_sequence.get(), 1);
    let head = journal_head(&writer, &journal_id).expect("head");
    assert_eq!(inventory.evidence_prefix, head);
    assert_no_bare_nulls(&inventory.to_json());
}

#[test]
fn rm_c47_named_rejects_empty_and_duplicate_names() {
    let writer = principal(&unique_id("writer-c47-names"));
    let (_, _, handle) = setup("c47-names", &writer);

    let empty = named_request(&handle, "c47-names-empty", Vec::new());
    let error = collect_inventory(&writer, &empty).expect_err("empty names rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let duplicate = named_request(
        &handle,
        "c47-names-dup",
        vec!["a".to_string(), "a".to_string()],
    );
    let error = collect_inventory(&writer, &duplicate).expect_err("duplicate names rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let blank = named_request(&handle, "c47-names-blank", vec![String::new()]);
    let error = collect_inventory(&writer, &blank).expect_err("blank name rejected");
    assert_error_code(&error, "INVALID_REQUEST");
}

#[test]
fn rm_c47_unknown_handle_is_rejected_without_probe() {
    let writer = principal(&unique_id("writer-c47-unknown"));
    let ghost = HandleReference {
        connector_id: "ringmaster".to_string(),
        local_handle: unique_id("ghost-handle"),
    };
    let request = inventory_request(&ghost, "c47-unknown");
    let error = collect_inventory(&writer, &request).expect_err("unknown handle rejected");
    assert_error_code(&error, "UNKNOWN_HANDLE");
}

#[test]
fn rm_c47_restricted_artifact_is_forbidden_to_other_principals() {
    let installer = principal(&unique_id("writer-c47-restr-a"));
    let stranger = principal(&unique_id("writer-c47-restr-b"));
    let (manifest, _, handle) = setup("c47-restr", &installer);
    let secret = install(&installer, b"restricted bytes", AccessClass::Restricted);
    publish_named_artifact(&installer, &manifest, &handle, "secret", &secret)
        .expect("publish restricted");

    let request = named_request(&handle, "c47-restr", vec!["secret".to_string()]);
    let error = collect_inventory(&stranger, &request).expect_err("stranger is forbidden");
    assert_error_code(&error, "FORBIDDEN");

    let own = collect_inventory(&installer, &named_request(&handle, "c47-restr-own", vec!["secret".to_string()]))
        .expect("installer reads");
    assert!(matches!(
        own.artifacts[0].content,
        MaybeArtifact::Present(_)
    ));
}

#[test]
fn rm_c47_wrong_mode_and_shape_are_rejected() {
    let writer = principal(&unique_id("writer-c47-shape"));
    let (manifest, _, handle) = setup("c47-shape", &writer);
    let reference = install(&writer, b"shaped", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "shaped", &reference)
        .expect("publish shaped");

    let bytes_mode = bytes_request(&handle, "c47-shape", reference.digest.clone(), 0, 4);
    let error = collect_inventory(&writer, &bytes_mode).expect_err("bytes via inventory rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let mut mismatched = inventory_request(&handle, "c47-shape-conn");
    mismatched.connector_id = "other-connector".to_string();
    let error = collect_inventory(&writer, &mismatched).expect_err("connector mismatch rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let mut wrong_op = inventory_request(&handle, "c47-shape-op");
    wrong_op.operation = "Observe".to_string();
    let error = collect_inventory(&writer, &wrong_op).expect_err("wrong verb rejected");
    assert_error_code(&error, "INVALID_REQUEST");
}

#[test]
fn rm_c47_slot_evidence_resolves_within_reported_prefix() {
    let writer = principal(&unique_id("writer-c47-ev"));
    let (manifest, _, handle) = setup("c47-ev", &writer);
    for (name, bytes) in [("one", b"one".as_slice()), ("two", b"two".as_slice())] {
        let reference = install(&writer, bytes, AccessClass::Public);
        publish_named_artifact(&writer, &manifest, &handle, name, &reference)
            .expect("publish");
    }
    let inventory = collect_inventory(&writer, &inventory_request(&handle, "c47-ev"))
        .expect("inventory collects");
    for slot in &inventory.artifacts {
        for reference in &slot.evidence_refs {
            let envelope =
                resolve_evidence(&writer, reference, &inventory.evidence_prefix).expect("resolves");
            assert_eq!(envelope.journal_id, inventory.evidence_prefix.journal_id);
        }
    }
}

#[test]
fn rm_c47_name_rebinding_to_different_digest_is_rejected() {
    let writer = principal(&unique_id("writer-c47-rebind"));
    let (manifest, _, handle) = setup("c47-rebind", &writer);
    let first = install(&writer, b"first bytes", AccessClass::Public);
    let second = install(&writer, b"second bytes", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "pinned", &first).expect("publish first");
    let error = publish_named_artifact(&writer, &manifest, &handle, "pinned", &second)
        .expect_err("rebind rejected");
    assert_error_code(&error, "INTEGRITY_CONFLICT");

    let repeat = publish_named_artifact(&writer, &manifest, &handle, "pinned", &first)
        .expect("same digest republishes idempotently");
    assert!(matches!(repeat.content, MaybeArtifact::Present(_)));
}

// ---------------------------------------------------------------------------
// RM-C48: chunk bounds, EOF, digest validation
// ---------------------------------------------------------------------------

#[test]
fn rm_c48_middle_chunk_verifies_base64_lengths_and_digests() {
    let writer = principal(&unique_id("writer-c48-mid"));
    let (manifest, _, handle) = setup("c48-mid", &writer);
    let bytes: Vec<u8> = (0..200u8).cycle().take(200).collect();
    let reference = install(&writer, &bytes, AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "blob", &reference).expect("publish");

    let chunk = collect_chunk(
        &writer,
        &bytes_request(&handle, "c48-mid", reference.digest.clone(), 50, 60),
    )
    .expect("chunk collects");
    assert_eq!(chunk.kind, "artifact_chunk");
    assert_eq!(chunk.handle, handle);
    assert_eq!(chunk.digest, reference.digest);
    assert_eq!(chunk.size_bytes, 200);
    assert_eq!(chunk.offset, 50);
    assert_eq!(chunk.returned_bytes, 60);
    assert!(!chunk.end_of_artifact);
    assert_eq!(chunk.data_base64, encode_base64(&bytes[50..110]));
    assert_eq!(chunk.chunk_digest, artifact_digest(&bytes[50..110]));
    let decoded = verify_chunk(&chunk).expect("chunk verifies");
    assert_eq!(decoded, bytes[50..110]);
    assert!(!chunk.evidence_refs.is_empty());
    assert_no_bare_nulls(&chunk.to_json());
}

#[test]
fn rm_c48_first_and_final_chunks_assemble_to_full_digest() {
    let writer = principal(&unique_id("writer-c48-asm"));
    let (manifest, _, handle) = setup("c48-asm", &writer);
    let bytes = b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs.";
    let reference = install(&writer, bytes.as_slice(), AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "text", &reference).expect("publish");

    let first = collect_chunk(
        &writer,
        &bytes_request(&handle, "c48-asm", reference.digest.clone(), 0, 40),
    )
    .expect("first chunk");
    assert!(!first.end_of_artifact);
    assert_eq!(first.returned_bytes, 40);
    let rest = collect_chunk(
        &writer,
        &bytes_request(
            &handle,
            "c48-asm",
            reference.digest.clone(),
            40,
            10_000,
        ),
    )
    .expect("final chunk");
    assert!(rest.end_of_artifact);
    assert_eq!(rest.offset + rest.returned_bytes, rest.size_bytes);

    let mut assembled = verify_chunk(&first).expect("first verifies");
    assembled.extend(verify_chunk(&rest).expect("rest verifies"));
    assert_eq!(assembled, bytes);
    assert_eq!(artifact_digest(&assembled), reference.digest);
    assert_eq!(assembled.len() as u64, reference.size_bytes);
}

#[test]
fn rm_c48_offset_at_eof_returns_zero_bytes_with_end_set() {
    let writer = principal(&unique_id("writer-c48-eof"));
    let (manifest, _, handle) = setup("c48-eof", &writer);
    let bytes = b"exactly twelve";
    assert_eq!(bytes.len(), 14);
    let reference = install(&writer, bytes.as_slice(), AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "tiny", &reference).expect("publish");

    let chunk = collect_chunk(
        &writer,
        &bytes_request(&handle, "c48-eof", reference.digest.clone(), 14, 64),
    )
    .expect("EOF chunk collects");
    assert_eq!(chunk.returned_bytes, 0);
    assert_eq!(chunk.data_base64, "");
    assert!(chunk.end_of_artifact);
    assert_eq!(chunk.chunk_digest, artifact_digest(b""));
    let decoded = verify_chunk(&chunk).expect("EOF chunk verifies");
    assert!(decoded.is_empty());
}

#[test]
fn rm_c48_offset_beyond_eof_is_rejected() {
    let writer = principal(&unique_id("writer-c48-past"));
    let (manifest, _, handle) = setup("c48-past", &writer);
    let reference = install(&writer, b"short", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "short", &reference).expect("publish");

    for offset in [6, 100, 9_007_199_254_740_991] {
        let request = bytes_request(&handle, "c48-past", reference.digest.clone(), offset, 8);
        let error = collect_chunk(&writer, &request).expect_err("past-EOF rejected");
        assert_error_code(&error, "INVALID_REQUEST");
    }
}

#[test]
fn rm_c48_zero_max_bytes_and_wrong_modes_are_rejected() {
    let writer = principal(&unique_id("writer-c48-zero"));
    let (manifest, _, handle) = setup("c48-zero", &writer);
    let reference = install(&writer, b"nonempty", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "data", &reference).expect("publish");

    let zero = ConnectorRequest::new(
        "ringmaster",
        &unique_id("req-c48-zero"),
        handle.clone(),
        ArtifactSelector::Bytes {
            digest: reference.digest.clone(),
            offset: 0,
            max_bytes: 0,
        },
    );
    let error = collect_chunk(&writer, &zero).expect_err("zero max_bytes rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let inventory_mode = inventory_request(&handle, "c48-zero-inv");
    let error = collect_chunk(&writer, &inventory_mode).expect_err("inventory via chunk rejected");
    assert_error_code(&error, "INVALID_REQUEST");

    let named_mode = named_request(&handle, "c48-zero-named", vec!["data".to_string()]);
    let error = collect_chunk(&writer, &named_mode).expect_err("named via chunk rejected");
    assert_error_code(&error, "INVALID_REQUEST");
}

#[test]
fn rm_c48_non_eof_chunks_always_advance() {
    let writer = principal(&unique_id("writer-c48-adv"));
    let (manifest, _, handle) = setup("c48-adv", &writer);
    let bytes: Vec<u8> = (0..64u32).map(|n| (n * 7) as u8).collect();
    let reference = install(&writer, &bytes, AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "adv", &reference).expect("publish");

    let mut offset = 0u64;
    let mut progress = 0u64;
    loop {
        let chunk = collect_chunk(
            &writer,
            &bytes_request(&handle, "c48-adv", reference.digest.clone(), offset, 9),
        )
        .expect("chunk collects");
        verify_chunk(&chunk).expect("chunk verifies");
        if chunk.end_of_artifact {
            offset += chunk.returned_bytes;
            break;
        }
        assert!(
            chunk.returned_bytes > 0,
            "non-EOF chunks must advance at offset {offset}"
        );
        assert_eq!(chunk.offset, offset);
        offset += chunk.returned_bytes;
        progress += 1;
        assert!(progress < 100, "chunk walk must terminate");
    }
    assert_eq!(offset, bytes.len() as u64);
}

#[test]
fn rm_c48_tampered_chunks_fail_verification() {
    let writer = principal(&unique_id("writer-c48-tamper"));
    let (manifest, _, handle) = setup("c48-tamper", &writer);
    let reference = install(&writer, b"tamper-evident bytes here", AccessClass::Public);
    publish_named_artifact(&writer, &manifest, &handle, "sealed", &reference).expect("publish");
    let good = collect_chunk(
        &writer,
        &bytes_request(&handle, "c48-tamper", reference.digest.clone(), 0, 10),
    )
    .expect("chunk collects");
    verify_chunk(&good).expect("honest chunk verifies");

    let mut wrong_length = good.clone();
    wrong_length.returned_bytes += 1;
    assert!(verify_chunk(&wrong_length).is_err(), "length lie rejected");

    let mut wrong_digest = good.clone();
    wrong_digest.chunk_digest = artifact_digest(b"something else");
    let error = verify_chunk(&wrong_digest).expect_err("digest lie rejected");
    assert_error_code(&error, "INTEGRITY_CONFLICT");

    let mut wrong_eof = good.clone();
    wrong_eof.end_of_artifact = !wrong_eof.end_of_artifact;
    assert!(verify_chunk(&wrong_eof).is_err(), "EOF lie rejected");

    let mut bad_base64 = good.clone();
    let mut tampered = bad_base64.data_base64.clone().into_bytes();
    tampered[0] = if tampered[0] == b'A' { b'B' } else { b'A' };
    bad_base64.data_base64 = String::from_utf8(tampered).unwrap();
    assert!(
        verify_chunk(&bad_base64).is_err(),
        "base64 tampering rejected"
    );

    let mut noncanonical = good.clone();
    noncanonical.data_base64 = "AB/=".to_string();
    noncanonical.returned_bytes = 2;
    noncanonical.chunk_digest = artifact_digest(&[0, 0x1F]);
    assert!(
        verify_chunk(&noncanonical).is_err(),
        "noncanonical base64 rejected"
    );
}

#[test]
fn rm_c48_unregistered_digest_is_never_fetched() {
    let writer = principal(&unique_id("writer-c48-unreg"));
    let (_, _, handle) = setup("c48-unreg", &writer);
    let outsider = install(&writer, b"installed but never registered here", AccessClass::Public);
    let request = bytes_request(&handle, "c48-unreg", outsider.digest.clone(), 0, 16);
    let error = collect_chunk(&writer, &request).expect_err("unregistered digest rejected");
    assert_error_code(&error, "ARTIFACT_UNAVAILABLE");

    let random = artifact_digest(b"never installed anywhere");
    let request = bytes_request(&handle, "c48-unreg", random, 0, 16);
    let error = collect_chunk(&writer, &request).expect_err("unknown digest rejected");
    assert_error_code(&error, "ARTIFACT_UNAVAILABLE");
}

#[test]
fn rm_c48_chunk_for_lost_bytes_is_unavailable_not_empty() {
    let writer = principal(&unique_id("writer-c48-lost"));
    let (_, _, handle) = setup("c48-lost", &writer);
    let lost = artifact_digest(b"lost before chunking");
    register_expected_digest(&writer, &handle, "lost-blob", &lost).expect("known digest records");
    let request = bytes_request(&handle, "c48-lost", lost, 0, 16);
    let error = collect_chunk(&writer, &request).expect_err("lost bytes unavailable");
    assert_error_code(&error, "ARTIFACT_UNAVAILABLE");
}

#[test]
fn rm_c48_chunk_evidence_resolves_and_restricted_stays_classified() {
    let installer = principal(&unique_id("writer-c48-cls-a"));
    let stranger = principal(&unique_id("writer-c48-cls-b"));
    let (manifest, _, handle) = setup("c48-cls", &installer);
    let secret = install(&installer, b"classified chunk bytes", AccessClass::Restricted);
    publish_named_artifact(&installer, &manifest, &handle, "classified", &secret)
        .expect("publish restricted");

    let chunk = collect_chunk(
        &installer,
        &bytes_request(&handle, "c48-cls", secret.digest.clone(), 0, 7),
    )
    .expect("installer chunks");
    assert!(!chunk.evidence_refs.is_empty());
    let prefix = journal_head(&installer, &journal_id_for(&manifest).expect("journal id"))
        .expect("head");
    for reference in &chunk.evidence_refs {
        resolve_evidence(&installer, reference, &prefix).expect("chunk evidence resolves");
    }

    let request = bytes_request(&handle, "c48-cls", secret.digest.clone(), 0, 7);
    let error = collect_chunk(&stranger, &request).expect_err("stranger forbidden");
    assert_error_code(&error, "FORBIDDEN");
}
