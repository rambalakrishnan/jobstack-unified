//! Conformance tests for RM-C49 (duplicate/conflicting producer sequence) and
//! RM-C58 (artifact/publication registration crash).
//!
//! Every test name carries `rm_c49` or `rm_c58` so the verification filter
//! `cargo test -p rm_evidence -- rm_c49 rm_c58` selects the suite.

use rm_authority::authenticate_channel;
use rm_evidence::*;
use rm_time::{
    Censoring, ClockBasis, Estimate, MaybeNumber, MaybeString, MeasurementOrigin, Method, Quantity,
    Scope, ScopeKind,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
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
    authenticate_channel(&mut Cursor::new(bytes)).expect("test principal authenticates")
}

fn manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "clock_registered",
            "artifact_available",
            "execution_claim",
            "report_published",
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    manifest
}

fn reference(bytes: &[u8], owner: &str, access: AccessClass) -> ArtifactReference {
    ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: owner.to_string(),
        access,
    }
}

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive integer")
}

fn submission(event_kind: &str, producer_sequence: u64) -> EventSubmission {
    let registration = event_registration(event_kind).expect("event kind is registered");
    EventSubmission {
        producer_sequence: Some(seq(producer_sequence)),
        event_kind: event_kind.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: json!({}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: Vec::new(),
        },
    }
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact = manifest_artifact_reference(manifest).expect("manifest artifact reference");
    EventSubmission {
        producer_sequence: Some(seq(1)),
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

fn admit(writer: &AuthenticatedPrincipal, manifest: &Manifest) -> JournalEnvelope {
    append_event(writer, manifest, admission(manifest)).expect("manifest admission")
}

fn head(writer: &AuthenticatedPrincipal, manifest: &Manifest) -> JournalPrefix {
    let journal_id = journal_id_for(manifest).expect("journal identity");
    journal_head(writer, &journal_id).expect("journal head")
}

fn clock(clock_id: &str, boot_id: &str) -> ClockDescriptor {
    ClockDescriptor {
        clock_id: clock_id.to_string(),
        boot_id: boot_id.to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: format!("source-{clock_id}"),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    }
}

fn clock_submission(producer_sequence: u64, descriptor: &ClockDescriptor) -> EventSubmission {
    let mut submission = submission("clock_registered", producer_sequence);
    submission.payload.data =
        serde_json::to_value(descriptor).expect("clock descriptor serializes");
    submission
}

fn measurement(descriptor: &ClockDescriptor, start: f64, end: f64) -> Measurement {
    let point = |offset: f64| TimePoint {
        clock_id: descriptor.clock_id.clone(),
        boot_id: descriptor.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    Measurement {
        measurement_id: format!("measurement-{start}-{end}"),
        name: "elapsed".to_string(),
        scope: Scope {
            kind: ScopeKind::ConnectorCall,
            id: "call-1".to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: descriptor.clock_id.clone(),
        boot_id: descriptor.boot_id.clone(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(point(start)),
        end: MaybeTimePoint::Present(point(end)),
        estimate: Estimate::Exact { value: end - start },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_observed")),
    }
}

fn digest_of(bytes: &[u8]) -> Digest {
    artifact_digest(bytes)
}

fn zero_digest() -> Digest {
    Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("zero digest")
}

fn installed_artifact(
    writer: &AuthenticatedPrincipal,
    label: &str,
    owner: &str,
    access: AccessClass,
) -> (ArtifactReference, Vec<u8>) {
    let bytes = label.as_bytes().to_vec();
    let artifact = reference(&bytes, owner, access);
    let installed = install_artifact(writer, &artifact, &bytes).expect("artifact install");
    assert_eq!(installed, artifact);
    (artifact, bytes)
}

// ---------------------------------------------------------------------------
// RM-C49: duplicate / conflicting producer sequence
// ---------------------------------------------------------------------------

#[test]
fn rm_c49_identical_duplicate_deduplicates_without_effects() {
    let writer = principal("rm-c49-identical-writer");
    let manifest = manifest("run-c49-identical");
    let admission = admit(&writer, &manifest);
    assert_eq!(admission.journal_sequence.get(), 1);
    assert_eq!(admission.event_kind, "manifest_admitted");
    assert!(
        matches!(&admission.previous_event_hash, MaybeDigest::Missing(missing) if missing.reason == "not_applicable"),
        "sequence one must carry not_applicable previous hash"
    );
    assert_eq!(
        admission.event_hash,
        admission.computed_event_hash().expect("hash recomputes")
    );

    let descriptor = clock("clock-identical", "boot-identical");
    let delivery = clock_submission(2, &descriptor);
    let first = append_event(&writer, &manifest, delivery.clone()).expect("first delivery");
    assert_eq!(first.journal_sequence.get(), 2);
    assert_eq!(first.owner_domain, "evidence");
    assert_eq!(first.producer_id, "rm-c49-identical-writer");
    assert_eq!(first.provenance, "server");
    assert_eq!(first.role, EventRole::LifecycleObservation);
    assert_eq!(first.assertion_kind, AssertionKind::Observation);
    assert_eq!(
        first.previous_event_hash,
        MaybeDigest::Present(admission.event_hash.clone())
    );
    assert_eq!(
        first.event_hash,
        first.computed_event_hash().expect("hash recomputes")
    );

    let duplicate = append_event(&writer, &manifest, delivery).expect("duplicate delivery");
    assert_eq!(duplicate, first, "duplicate must return the retained event");

    let prefix = head(&writer, &manifest);
    assert_eq!(prefix.last_sequence.get(), 2);
    assert_eq!(prefix.head_hash, first.event_hash);
    assert_eq!(
        read_event(&writer, &first.journal_id, seq(2)).expect("read retained event"),
        first
    );
}

#[test]
fn rm_c49_conflicting_duplicate_is_integrity_incident() {
    let writer = principal("rm-c49-conflict-writer");
    let manifest = manifest("run-c49-conflict");
    admit(&writer, &manifest);
    let first_delivery = clock_submission(2, &clock("clock-conflict-a", "boot-conflict-a"));
    let first = append_event(&writer, &manifest, first_delivery.clone()).expect("first delivery");

    let conflicting = clock_submission(2, &clock("clock-conflict-b", "boot-conflict-b"));
    let error = append_event(&writer, &manifest, conflicting)
        .expect_err("conflicting producer sequence must be an integrity incident");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");
    assert!(
        error.detail.contains("conflicting content"),
        "unexpected detail: {}",
        error.detail
    );

    let prefix = head(&writer, &manifest);
    assert_eq!(prefix.last_sequence.get(), 2, "head must not advance");
    assert_eq!(prefix.head_hash, first.event_hash);
    assert_eq!(
        read_event(&writer, &first.journal_id, seq(2)).expect("retained event"),
        first,
        "last-write-wins is forbidden; the first event is retained"
    );

    // The original delivery is still a deduplication hit after the incident.
    let replay = append_event(&writer, &manifest, first_delivery).expect("replay original");
    assert_eq!(replay, first);
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 2);
}

#[test]
fn rm_c49_deduplication_is_scoped_to_one_producer_lifetime() {
    let writer_a = principal("rm-c49-scope-a");
    let writer_b = principal("rm-c49-scope-b");
    let manifest = manifest("run-c49-scope");
    admit(&writer_a, &manifest);

    let descriptor = clock("clock-scope", "boot-scope");
    let first = append_event(&writer_a, &manifest, clock_submission(7, &descriptor))
        .expect("producer a delivery");
    let second = append_event(&writer_b, &manifest, clock_submission(7, &descriptor))
        .expect("producer b delivery");

    assert_ne!(first.producer_id, second.producer_id);
    assert_ne!(first.event_id, second.event_id);
    assert_eq!(first.journal_sequence.get(), 2);
    assert_eq!(second.journal_sequence.get(), 3);
    assert_eq!(
        second.previous_event_hash,
        MaybeDigest::Present(first.event_hash.clone())
    );
    assert_eq!(head(&writer_a, &manifest).last_sequence.get(), 3);
    assert_eq!(head(&writer_a, &manifest).head_hash, second.event_hash);
}

#[test]
fn rm_c49_duplicate_after_later_events_returns_the_original() {
    let writer = principal("rm-c49-late-writer");
    let manifest = manifest("run-c49-late");
    let admission = admit(&writer, &manifest);

    let first_delivery = clock_submission(2, &clock("clock-late", "boot-late"));
    let first = append_event(&writer, &manifest, first_delivery.clone()).expect("first event");

    let (artifact, bytes) = installed_artifact(
        &writer,
        "run-c49-late-artifact-available",
        "artifact",
        AccessClass::Public,
    );
    let mut artifact_event = submission("artifact_available", 3);
    artifact_event.payload.artifact_refs = vec![artifact.clone()];
    artifact_event.payload.data = json!({"artifact": artifact.to_json()});
    let second = append_event(&writer, &manifest, artifact_event).expect("second event");
    assert_eq!(second.journal_sequence.get(), 3);
    assert_eq!(
        second.previous_event_hash,
        MaybeDigest::Present(first.event_hash.clone())
    );
    assert_eq!(
        load_artifact(&writer, &artifact).expect("load bytes"),
        bytes
    );

    let replay = append_event(&writer, &manifest, first_delivery).expect("late duplicate");
    assert_eq!(replay, first, "dedup returns the original sequence");
    let prefix = head(&writer, &manifest);
    assert_eq!(prefix.last_sequence.get(), 3);
    assert_eq!(prefix.head_hash, second.event_hash);
    assert_eq!(
        read_event(&writer, &first.journal_id, seq(2)).expect("sequence 2"),
        first
    );
    assert_eq!(
        read_event(&writer, &first.journal_id, seq(3)).expect("sequence 3"),
        second
    );
    assert_eq!(admission.journal_sequence.get(), 1);
}

#[test]
fn rm_c49_measurements_validate_against_registered_clocks_before_dedup() {
    let writer = principal("rm-c49-measurement-writer");
    let manifest = manifest("run-c49-measurement");
    admit(&writer, &manifest);

    let descriptor = clock("clock-measurement", "boot-measurement");
    let mut claim = submission("execution_claim", 3);
    claim.payload.measurements = vec![measurement(&descriptor, 10.0, 25.0)];

    let error = append_event(&writer, &manifest, claim.clone())
        .expect_err("measurement against an unregistered clock is rejected");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("unregistered clock"),
        "unexpected detail: {}",
        error.detail
    );
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 1);

    let registered = append_event(&writer, &manifest, clock_submission(2, &descriptor))
        .expect("clock registration");
    assert_eq!(registered.journal_sequence.get(), 2);

    let first = append_event(&writer, &manifest, claim.clone()).expect("valid claim");
    assert_eq!(first.journal_sequence.get(), 3);
    assert_eq!(first.payload.measurements.len(), 1);

    let duplicate = append_event(&writer, &manifest, claim).expect("duplicate claim");
    assert_eq!(duplicate, first, "identical content deduplicates");
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 3);
}

// ---------------------------------------------------------------------------
// RM-C58: artifact / publication registration crash
// ---------------------------------------------------------------------------

#[test]
fn rm_c58_absent_artifact_bytes_cannot_be_cited() {
    let writer = principal("rm-c58-absent-writer");
    let manifest = manifest("run-c58-absent");
    admit(&writer, &manifest);

    let bytes = b"publication-bytes-never-installed".to_vec();
    let artifact = reference(&bytes, "artifact", AccessClass::Public);
    let mut publication = submission("artifact_available", 2);
    publication.payload.artifact_refs = vec![artifact.clone()];
    publication.payload.data = json!({"artifact": artifact.to_json()});

    let error = append_event(&writer, &manifest, publication.clone())
        .expect_err("absent bytes must not be citable");
    assert_eq!(error.code, "NOT_FOUND");
    assert!(
        error.detail.contains("not installed"),
        "unexpected detail: {}",
        error.detail
    );
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 1);
    assert!(read_event(&writer, &journal_id_for(&manifest).unwrap(), seq(2)).is_err());

    // Installing the exact bytes first makes the same registration valid.
    assert_eq!(
        install_artifact(&writer, &artifact, &bytes).expect("install exact bytes"),
        artifact
    );
    let registered =
        append_event(&writer, &manifest, publication).expect("registration after install");
    assert_eq!(registered.journal_sequence.get(), 2);
    assert_eq!(registered.payload.artifact_refs, vec![artifact.clone()]);
    assert_eq!(
        load_artifact(&writer, &artifact).expect("load bytes"),
        bytes
    );
}

#[test]
fn rm_c58_artifact_identity_rejects_byte_or_metadata_substitution() {
    let writer = principal("rm-c58-identity-writer");
    let reader = principal("rm-c58-identity-reader");
    let bytes = b"identity-bytes".to_vec();
    let artifact = reference(&bytes, "artifact", AccessClass::Public);

    let other_bytes = b"identity-other-bytes".to_vec();
    let error = install_artifact(&writer, &artifact, &other_bytes)
        .expect_err("declared digest must cover the exact stored bytes");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error
        .detail
        .contains("does not match the exact stored bytes"));

    let mut wrong_size = artifact.clone();
    wrong_size.size_bytes = artifact.size_bytes + 1;
    let error = install_artifact(&writer, &wrong_size, &bytes)
        .expect_err("declared size must match the stored byte length");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(error.detail.contains("size_bytes"));

    assert_eq!(
        install_artifact(&writer, &artifact, &bytes).expect("install"),
        artifact
    );
    assert_eq!(
        install_artifact(&writer, &artifact, &bytes).expect("idempotent reinstall"),
        artifact
    );

    let mut restricted_alias = artifact.clone();
    restricted_alias.access = AccessClass::Restricted;
    let error = install_artifact(&writer, &restricted_alias, &bytes)
        .expect_err("metadata must never change under an existing digest");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");
    assert_eq!(
        load_artifact(&writer, &artifact).expect("original metadata retained"),
        bytes
    );

    // Public bytes are readable by another authenticated handle.
    assert_eq!(
        load_artifact(&reader, &artifact).expect("public read"),
        bytes
    );

    // Restricted bytes are readable only by the installer.
    let restricted_bytes = b"restricted-bytes".to_vec();
    let restricted = reference(&restricted_bytes, "artifact", AccessClass::Restricted);
    install_artifact(&writer, &restricted, &restricted_bytes).expect("install restricted");
    assert_eq!(
        load_artifact(&writer, &restricted).expect("installer read"),
        restricted_bytes
    );
    let error = load_artifact(&reader, &restricted)
        .expect_err("reference possession is not read authority");
    assert_eq!(error.code, "FORBIDDEN");

    // A digest that was never installed is not readable merely by naming it.
    let unknown = reference(b"never-installed-bytes", "artifact", AccessClass::Public);
    let error = load_artifact(&writer, &unknown).expect_err("unknown artifact");
    assert_eq!(error.code, "NOT_FOUND");
    assert_eq!(unknown.digest, digest_of(b"never-installed-bytes"));
}

#[test]
fn rm_c58_registration_after_install_recovers_without_external_rerun() {
    let writer = principal("rm-c58-recovery-writer");
    let manifest = manifest("run-c58-recovery");
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission = admit(&writer, &manifest);

    let (effect, effect_bytes) = installed_artifact(
        &writer,
        &format!("effect-{journal_id}"),
        "execution",
        AccessClass::Restricted,
    );
    let (response, _response_bytes) = installed_artifact(
        &writer,
        &format!("response-{journal_id}"),
        "report",
        AccessClass::Restricted,
    );

    // Crash boundary: bytes are installed durably, no registration event yet.
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 1);

    let mut evidence_event = submission("artifact_available", 2);
    evidence_event.payload.data = json!({"artifact": effect.to_json()});
    evidence_event.payload.artifact_refs = vec![effect.clone()];
    let mut publication = submission("report_published", 3);
    publication.payload.data = json!({"response": response.to_json()});
    publication.payload.artifact_refs = vec![response.clone()];
    let submissions = vec![evidence_event, publication];

    let committed = commit_owner_effect(&writer, &manifest, &effect, &submissions, &response)
        .expect("owner-local commit");
    assert_eq!(committed.len(), 2);
    assert_eq!(committed[0].journal_sequence.get(), 2);
    assert_eq!(committed[1].journal_sequence.get(), 3);
    assert_eq!(
        committed[0].previous_event_hash,
        MaybeDigest::Present(admission.event_hash.clone())
    );
    assert_eq!(
        committed[1].previous_event_hash,
        MaybeDigest::Present(committed[0].event_hash.clone())
    );
    for event in &committed {
        assert_eq!(
            event.event_hash,
            event.computed_event_hash().expect("hash recomputes")
        );
    }
    let prefix = head(&writer, &manifest);
    assert_eq!(prefix.last_sequence.get(), 3);
    assert_eq!(prefix.head_hash, committed[1].event_hash);

    // Crash boundary: registration committed, response delivery lost. The same
    // command returns the retained envelopes and reruns nothing.
    let retried = commit_owner_effect(&writer, &manifest, &effect, &submissions, &response)
        .expect("retained receipt");
    assert_eq!(retried, committed);
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 3);
    assert_eq!(
        read_event(&writer, &journal_id, seq(2)).expect("retained evidence event"),
        committed[0]
    );
    assert_eq!(
        read_event(&writer, &journal_id, seq(3)).expect("retained publication"),
        committed[1]
    );
    assert_eq!(
        load_artifact(&writer, &effect).expect("effect bytes retained"),
        effect_bytes
    );
}

#[test]
fn rm_c58_publication_cannot_cite_its_own_registration() {
    let writer = principal("rm-c58-self-reference-writer");
    let manifest = manifest("run-c58-self-reference");
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let admission = admit(&writer, &manifest);
    let (artifact, _bytes) = installed_artifact(
        &writer,
        "run-c58-self-reference-publication",
        "report",
        AccessClass::Public,
    );

    let mut self_citing = submission("report_published", 2);
    self_citing.payload.artifact_refs = vec![artifact.clone()];
    self_citing.payload.evidence_refs = vec![EvidenceRef {
        journal_id: journal_id.clone(),
        sequence: seq(2),
        event_id: format!("{journal_id}:2"),
        event_hash: admission.event_hash.clone(),
        pointer: String::new(),
    }];
    let error = append_event(&writer, &manifest, self_citing)
        .expect_err("an event cannot cite its own future registration");
    assert_eq!(error.code, "INVALID_REQUEST");
    assert!(
        error.detail.contains("cannot cite its own registration"),
        "unexpected detail: {}",
        error.detail
    );
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 1);

    let admission_ref = EvidenceRef {
        journal_id: journal_id.clone(),
        sequence: seq(1),
        event_id: admission.event_id.clone(),
        event_hash: admission.event_hash.clone(),
        pointer: "/payload/data/manifest/digest".to_string(),
    };
    let prefix = JournalPrefix {
        journal_id: journal_id.clone(),
        last_sequence: seq(1),
        head_hash: admission.event_hash.clone(),
    };
    assert_eq!(
        resolve_evidence(&writer, &admission_ref, &prefix).expect("resolve admission pointer"),
        admission
    );

    let mut tampered_prefix = prefix.clone();
    tampered_prefix.head_hash = zero_digest();
    let error = resolve_evidence(&writer, &admission_ref, &tampered_prefix)
        .expect_err("prefix head must match the retained event hash");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");

    let mut unresolved_pointer = admission_ref.clone();
    unresolved_pointer.pointer = "/payload/data/absent".to_string();
    let error = resolve_evidence(&writer, &unresolved_pointer, &prefix)
        .expect_err("pointer must resolve inside the cited event");
    assert_eq!(error.code, "INVALID_REQUEST");

    let mut wrong_hash = admission_ref.clone();
    wrong_hash.event_hash = zero_digest();
    let error = resolve_evidence(&writer, &wrong_hash, &prefix)
        .expect_err("reference hash must agree with the journaled event");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");

    // A publication may cite an earlier event; registration succeeds.
    let mut publication = submission("report_published", 2);
    publication.payload.artifact_refs = vec![artifact.clone()];
    publication.payload.evidence_refs = vec![admission_ref.clone()];
    let appended = append_event(&writer, &manifest, publication)
        .expect("publication citing the admission event");
    assert_eq!(appended.journal_sequence.get(), 2);
    assert_eq!(appended.causal_refs, vec![admission_ref]);
    assert_eq!(head(&writer, &manifest).head_hash, appended.event_hash);

    let publication_ref = EvidenceRef {
        journal_id: journal_id.clone(),
        sequence: seq(2),
        event_id: appended.event_id.clone(),
        event_hash: appended.event_hash.clone(),
        pointer: "/payload/artifact_refs/0/digest".to_string(),
    };
    assert_eq!(
        resolve_evidence(&writer, &publication_ref, &head(&writer, &manifest))
            .expect("resolve publication bytes identity"),
        appended
    );
}

#[test]
fn rm_c58_owner_commit_is_atomic_on_validation_failure() {
    let writer = principal("rm-c58-atomic-writer");
    let manifest = manifest("run-c58-atomic");
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    admit(&writer, &manifest);

    let (effect, _effect_bytes) = installed_artifact(
        &writer,
        "run-c58-atomic-effect",
        "execution",
        AccessClass::Restricted,
    );
    let (response, _response_bytes) = installed_artifact(
        &writer,
        "run-c58-atomic-response",
        "report",
        AccessClass::Restricted,
    );
    let (first_artifact, first_bytes) = installed_artifact(
        &writer,
        "run-c58-atomic-first",
        "artifact",
        AccessClass::Public,
    );

    // This publication cites bytes that are not installed yet.
    let late_bytes = b"run-c58-atomic-late".to_vec();
    let late_artifact = reference(&late_bytes, "report", AccessClass::Public);

    let mut first = submission("artifact_available", 2);
    first.payload.artifact_refs = vec![effect.clone(), first_artifact.clone()];
    first.payload.data = json!({"artifact": first_artifact.to_json()});
    let mut second = submission("report_published", 3);
    second.payload.artifact_refs = vec![late_artifact.clone()];

    let error = commit_owner_effect(
        &writer,
        &manifest,
        &effect,
        &[first.clone(), second.clone()],
        &response,
    )
    .expect_err("one invalid submission fails the whole owner commit");
    assert_eq!(error.code, "NOT_FOUND");
    assert_eq!(head(&writer, &manifest).last_sequence.get(), 1);
    assert!(read_event(&writer, &journal_id, seq(2)).is_err());
    assert!(read_event(&writer, &journal_id, seq(3)).is_err());

    install_artifact(&writer, &late_artifact, &late_bytes).expect("install late bytes");
    let committed = commit_owner_effect(&writer, &manifest, &effect, &[first, second], &response)
        .expect("commit after installing every cited artifact");
    assert_eq!(committed.len(), 2);
    let prefix = head(&writer, &manifest);
    assert_eq!(prefix.last_sequence.get(), 3);
    assert_eq!(prefix.head_hash, committed[1].event_hash);
    assert_eq!(
        read_event(&writer, &journal_id, seq(2)).expect("sequence 2"),
        committed[0]
    );
    assert_eq!(
        read_event(&writer, &journal_id, seq(3)).expect("sequence 3"),
        committed[1]
    );
    assert_eq!(
        load_artifact(&writer, &first_artifact).expect("first artifact retained"),
        first_bytes
    );
}

#[test]
fn rm_c58_submission_parser_rejects_caller_authority_fields() {
    let writer = principal("rm-c58-authority-writer");
    let manifest = manifest("run-c58-authority");
    admit(&writer, &manifest);
    let (artifact, _bytes) = installed_artifact(
        &writer,
        "run-c58-authority-publication",
        "report",
        AccessClass::Public,
    );

    let forged = json!({
        "producer_sequence": 2,
        "event_kind": "report_published",
        "event_schema_version": "owner-separated-write-domains/0.1.0",
        "occurred_at": {"value": null, "reason": "not_observed"},
        "payload": {
            "data": {},
            "measurements": [],
            "evidence_refs": [],
            "artifact_refs": [artifact.to_json()],
        },
        "owner_domain": "report",
        "provenance": "subject",
        "event_hash": zero_digest().as_str(),
        "journal_sequence": 2,
    });
    let error = EventSubmission::parse(&serde_json::to_vec(&forged).expect("forged json"))
        .expect_err("caller-authored authority fields are rejected");
    assert_eq!(error.code, "FORBIDDEN");
    assert!(error.detail.contains("authority field"));

    let mut caller_fields = forged.as_object().expect("object").clone();
    for field in [
        "owner_domain",
        "provenance",
        "event_hash",
        "journal_sequence",
    ] {
        caller_fields.remove(field);
    }
    let parsed = EventSubmission::parse(
        &serde_json::to_vec(&Value::Object(caller_fields)).expect("caller json"),
    )
    .expect("submission with only caller fields parses");
    assert_eq!(parsed.event_kind, "report_published");
    assert_eq!(parsed.producer_sequence.map(PositiveInteger::get), Some(2));

    let envelope = append_event(&writer, &manifest, parsed).expect("append parsed submission");
    assert_eq!(envelope.journal_sequence.get(), 2);
    assert_eq!(envelope.owner_domain, "report");
    assert_eq!(envelope.provenance, "server");
    assert_eq!(envelope.producer_id, "rm-c58-authority-writer");
    assert_eq!(envelope.event_hash, envelope.computed_event_hash().unwrap());
}
