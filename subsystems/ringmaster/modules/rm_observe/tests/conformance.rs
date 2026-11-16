//! Conformance tests for RM-C45 (observation pagination) and RM-C46
//! (oversized single observation item).
//!
//! Every test name carries `rm_c45` or `rm_c46` so the verification filter
//! `cargo test -p rm_observe -- rm_c45 rm_c46` selects the suite.

use rm_authority::{authenticate_channel, Manifest};
use rm_evidence::{
    append_event, event_registration, install_artifact, journal_head, journal_id_for,
    manifest_artifact_reference, resolve_evidence, AccessClass, ArtifactReference,
    AuthenticatedPrincipal, EvidencePayload, EvidenceRef, EventSubmission, JournalEnvelope,
    JournalPrefix, MaybeDigest, PositiveInteger,
};
use rm_observe::{
    HandleReference, MaybeEvidenceRef, ObservationCursor, ObservationPayload, ObserveRequest,
    Through, MAX_RESPONSE_BYTES,
};
use rm_time::{MaybeTimePoint, Missing};
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

fn test_manifest(run: &str) -> Manifest {
    let mut m = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "clock_registered",
            "dispatch_published",
            "observation_opened",
            "observation_closed",
            "context_observation",
            "execution_claim",
            "native_report",
            "task_output",
            "origin_fact",
            "report_published",
            "artifact_available",
            "control_observation",
            "connector_incident",
            "lifecycle_publication",
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&m);
    m.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    m
}

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive integer")
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

fn submission(
    event_kind: &str,
    producer_sequence: u64,
    data: Value,
    artifact_refs: Vec<ArtifactReference>,
) -> EventSubmission {
    let registration = event_registration(event_kind).expect("event kind is registered");
    EventSubmission {
        producer_sequence: Some(seq(producer_sequence)),
        event_kind: event_kind.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data,
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs,
        },
    }
}

fn plain_submission(event_kind: &str, producer_sequence: u64) -> EventSubmission {
    submission(event_kind, producer_sequence, json!({}), Vec::new())
}

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    owner: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/octet-stream".to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    install_artifact(writer, &reference, bytes).expect("artifact install");
    reference
}

fn version_pin(id: &str) -> Value {
    let digest = artifact_digest(id.as_bytes());
    json!({
        "id": id,
        "version": "v1",
        "artifact_digest": digest.as_str(),
    })
}

fn ref_to(envelope: &JournalEnvelope) -> Value {
    json!({
        "journal_id": envelope.journal_id,
        "sequence": envelope.journal_sequence.get(),
        "event_id": envelope.event_id,
        "event_hash": envelope.event_hash.as_str(),
        "pointer": "",
    })
}

fn source_checks(seq1: &Value) -> Value {
    json!({
        "authentication": "verified",
        "correlation": "matched",
        "trace_correlation": "matched",
        "verification_policy": version_pin("verifier-1"),
        "matched_by": ["trace-1"],
        "evidence_refs": [seq1],
    })
}

fn native_report_data(raw: &ArtifactReference, seq1: &Value) -> Value {
    json!({
        "kind": "native_report",
        "channel": "terminal_response",
        "raw": raw.to_json(),
        "source_event": seq1,
        "source_checks": source_checks(seq1),
        "mapping": version_pin("mapping-1"),
        "normalized_claims": [],
        "limitations": [],
    })
}

fn task_output_data(content: &ArtifactReference, seq1: &Value, limitations: Vec<String>) -> Value {
    json!({
        "kind": "task_output",
        "name": "output-1",
        "output_schema": version_pin("schema-1"),
        "content": content.to_json(),
        "completeness": "complete",
        "evidence_refs": [seq1],
        "limitations": limitations,
    })
}

fn context_observation_data(seq1: &Value) -> Value {
    json!({
        "kind": "context_observation",
        "domain": "browser_state",
        "requested_policy_ref": seq1,
        "realization": "fresh",
        "context_ref": "ctx-1",
        "evidence_refs": [seq1],
        "limitations": [],
    })
}

fn connector_incident_data(seq1: &Value) -> Value {
    json!({
        "kind": "connector_incident",
        "code": "observation_lost",
        "scope": {"kind": "run", "id": "run-1"},
        "detail": "lost window",
        "evidence_refs": [seq1],
    })
}

fn handle_for(run: &str) -> HandleReference {
    HandleReference {
        connector_id: "rm-observe-test".to_string(),
        local_handle: format!("handle-{run}"),
    }
}

fn cursor_zero(handle: &HandleReference, journal_id: &str) -> ObservationCursor {
    ObservationCursor {
        handle: handle.clone(),
        journal_id: journal_id.to_string(),
        sequence: 0,
        event_hash: MaybeDigest::Missing(Missing::new("not_applicable")),
    }
}

fn live_through() -> Through {
    Through::Live(Missing::new("not_applicable"))
}

fn zero_wait() -> rm_observe::DurationLimit {
    rm_observe::DurationLimit {
        kind: "exact".to_string(),
        unit: "ms".to_string(),
        value: 0.0,
    }
}

fn request(
    handle: &HandleReference,
    after: ObservationCursor,
    through: Through,
    max_items: u64,
) -> ObserveRequest {
    ObserveRequest {
        handle: handle.clone(),
        after,
        through,
        max_items: seq(max_items),
        wait_limit: zero_wait(),
    }
}

// ---------------------------------------------------------------------------
// RM-C45: pagination across unrelated events
// ---------------------------------------------------------------------------

#[test]
fn rm_c45_pagination_across_unrelated_events() {
    let run = "rm-observe-c45-pagination";
    let writer = principal("writer-c45-pagination");
    let reader = principal("reader-c45-pagination");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = handle_for(run);

    // seq1: admission (non-projection).
    let admission_envelope = admit(&writer, &manifest);
    assert_eq!(admission_envelope.journal_sequence.get(), 1);
    let seq1 = ref_to(&admission_envelope);

    // Install bytes for projection payloads.
    let raw = install_bytes(&writer, b"raw-native-c45", "execution");
    let content = install_bytes(&writer, b"task-bytes-c45", "execution");

    // seq2: native_report (projection).
    let seq2 = append_event(
        &writer,
        &manifest,
        submission(
            "native_report",
            2,
            native_report_data(&raw, &seq1),
            vec![raw.clone()],
        ),
    )
    .expect("seq2 native_report");
    assert_eq!(seq2.journal_sequence.get(), 2);

    // seq3: execution_claim (non-projection).
    let seq3 = append_event(&writer, &manifest, plain_submission("execution_claim", 3))
        .expect("seq3 execution_claim");
    assert_eq!(seq3.journal_sequence.get(), 3);

    // seq4: task_output (projection).
    let seq4 = append_event(
        &writer,
        &manifest,
        submission(
            "task_output",
            4,
            task_output_data(&content, &seq1, Vec::new()),
            vec![content.clone()],
        ),
    )
    .expect("seq4 task_output");
    assert_eq!(seq4.journal_sequence.get(), 4);

    // seq5: origin_fact (non-projection).
    let seq5 = append_event(&writer, &manifest, plain_submission("origin_fact", 5))
        .expect("seq5 origin_fact");
    assert_eq!(seq5.journal_sequence.get(), 5);

    // seq6: context_observation (projection).
    let seq6 = append_event(
        &writer,
        &manifest,
        submission("context_observation", 6, context_observation_data(&seq1), Vec::new()),
    )
    .expect("seq6 context_observation");
    assert_eq!(seq6.journal_sequence.get(), 6);

    // seq7: observation_opened (non-projection trailing).
    let seq7 = append_event(
        &writer,
        &manifest,
        plain_submission("observation_opened", 7),
    )
    .expect("seq7 observation_opened");
    assert_eq!(seq7.journal_sequence.get(), 7);

    // Page 1: live cutoff, max 2. Scans 1..=5 (stops before seq6 projection
    // that would exceed max_items), so next is the scanned non-projection
    // at 5, not the last returned item at 4.
    let after0 = cursor_zero(&handle, &journal_id);
    let page1 = rm_observe::observe(&reader, &request(&handle, after0.clone(), live_through(), 2))
        .expect("page1 observes");
    assert_eq!(page1.kind, "observation_page");
    assert_eq!(page1.handle, handle);
    assert_eq!(page1.after, after0);
    assert_eq!(page1.through.journal_id, journal_id);
    assert_eq!(page1.through.last_sequence.get(), 7);
    assert_eq!(page1.through.head_hash, seq7.event_hash);
    assert_eq!(page1.items.len(), 2);
    assert_eq!(page1.items[0].sequence(), 2);
    assert_eq!(page1.items[1].sequence(), 4);
    // Next is the last scanned position (seq5 non-projection), not seq4.
    assert_eq!(page1.next.sequence, 5);
    assert_eq!(
        page1.next.event_hash,
        MaybeDigest::Present(seq5.event_hash.clone())
    );
    assert_eq!(page1.next.handle, handle);
    assert_eq!(page1.next.journal_id, journal_id);
    assert!(page1.has_more);
    assert_eq!(page1.has_more, page1.next.sequence < page1.through.last_sequence.get());
    // Metadata matches the journal; provenance is copied, not assigned.
    assert_eq!(page1.items[0].provenance, seq2.provenance);
    assert_eq!(page1.items[0].recorded_at, seq2.recorded_at);
    assert_eq!(page1.items[0].event_ref.sequence.get(), 2);
    assert_eq!(page1.items[0].event_ref.event_hash, seq2.event_hash);
    assert_eq!(page1.items[0].event_ref.pointer, "");
    assert!(matches!(
        page1.items[0].payload,
        ObservationPayload::NativeReport(_)
    ));
    assert_eq!(page1.items[0].artifact_refs, vec![raw.clone()]);
    assert!(matches!(
        page1.items[1].payload,
        ObservationPayload::TaskOutput(_)
    ));
    // No closure observed; empty limitations (established empty).
    assert!(matches!(
        page1.observation_close_ref,
        MaybeEvidenceRef::Missing(_)
    ));
    if let MaybeEvidenceRef::Missing(missing) = &page1.observation_close_ref {
        assert_eq!(missing.reason, "not_observed");
    }
    assert!(page1.limitations.is_empty());

    // Page 2: fixed cutoff continuation. Cutoff must not change.
    let fixed = Through::Prefix(page1.through.clone());
    let page2 = rm_observe::observe(
        &reader,
        &request(&handle, page1.next.clone(), fixed, 2),
    )
    .expect("page2 observes");
    assert_eq!(page2.through, page1.through);
    assert_eq!(page2.items.len(), 1);
    assert_eq!(page2.items[0].sequence(), 6);
    assert!(matches!(
        page2.items[0].payload,
        ObservationPayload::ContextObservation(_)
    ));
    // Trailing non-projection at 7 is scanned: next is 7, not 6.
    assert_eq!(page2.next.sequence, 7);
    assert_eq!(
        page2.next.event_hash,
        MaybeDigest::Present(seq7.event_hash.clone())
    );
    assert!(!page2.has_more);
    assert_eq!(page2.has_more, page2.next.sequence < page2.through.last_sequence.get());

    // No skipped history: every projection appears exactly once, in order.
    let mut all: Vec<u64> = page1
        .items
        .iter()
        .chain(page2.items.iter())
        .map(|item| item.sequence())
        .collect();
    all.sort_unstable();
    assert_eq!(all, vec![2, 4, 6]);

    // Empty at cutoff: legitimate, not termination, still pinned.
    let page3 = rm_observe::observe(
        &reader,
        &request(
            &handle,
            page2.next.clone(),
            Through::Prefix(page1.through.clone()),
            2,
        ),
    )
    .expect("page3 empty at cutoff");
    assert!(page3.items.is_empty());
    assert_eq!(page3.next.sequence, 7);
    assert!(!page3.has_more);
    assert_eq!(page3.through, page1.through);
    assert!(matches!(
        page3.observation_close_ref,
        MaybeEvidenceRef::Missing(_)
    ));

    // Late evidence requires a new live cutoff: fixed stays empty, live sees it.
    let raw_late = install_bytes(&writer, b"raw-late-c45", "execution");
    let seq8 = append_event(
        &writer,
        &manifest,
        submission(
            "native_report",
            8,
            native_report_data(&raw_late, &seq1),
            vec![raw_late.clone()],
        ),
    )
    .expect("seq8 late native_report");
    assert_eq!(seq8.journal_sequence.get(), 8);

    let stale = rm_observe::observe(
        &reader,
        &request(
            &handle,
            page2.next.clone(),
            Through::Prefix(page1.through.clone()),
            10,
        ),
    )
    .expect("fixed cutoff stays empty after late evidence");
    assert!(stale.items.is_empty());
    assert_eq!(stale.through.last_sequence.get(), 7);

    let live = rm_observe::observe(
        &reader,
        &request(&handle, page2.next.clone(), live_through(), 10),
    )
    .expect("live cutoff sees late evidence");
    assert_eq!(live.through.last_sequence.get(), 8);
    assert_eq!(live.items.len(), 1);
    assert_eq!(live.items[0].sequence(), 8);
    assert!(!live.has_more);
}

#[test]
fn rm_c45_cursor_validation_and_fixed_cutoff() {
    let run = "rm-observe-c45-cursor";
    let writer = principal("writer-c45-cursor");
    let reader = principal("reader-c45-cursor");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = handle_for(run);

    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let raw = install_bytes(&writer, b"raw-cursor", "execution");
    let seq2 = append_event(
        &writer,
        &manifest,
        submission(
            "native_report",
            2,
            native_report_data(&raw, &seq1),
            vec![raw.clone()],
        ),
    )
    .expect("seq2");
    let head: JournalPrefix = journal_head(&reader, &journal_id).expect("head");

    // Baseline live page pins the cutoff.
    let after0 = cursor_zero(&handle, &journal_id);
    let page1 = rm_observe::observe(&reader, &request(&handle, after0.clone(), live_through(), 10))
        .expect("baseline page");
    assert_eq!(page1.through, head);

    // (a) After hash mismatch is CURSOR_INVALID.
    let wrong_digest = artifact_digest(b"wrong-hash");
    let bad_after = ObservationCursor {
        handle: handle.clone(),
        journal_id: journal_id.clone(),
        sequence: 1,
        event_hash: MaybeDigest::Present(wrong_digest),
    };
    let err = rm_observe::observe(&reader, &request(&handle, bad_after, live_through(), 10))
        .expect_err("hash mismatch must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (b) After beyond cutoff is CURSOR_INVALID.
    let beyond = ObservationCursor {
        handle: handle.clone(),
        journal_id: journal_id.clone(),
        sequence: head.last_sequence.get() + 5,
        event_hash: MaybeDigest::Present(seq2.event_hash.clone()),
    };
    // Bypass request.validate's journal check by using a fixed prefix that
    // ends before `beyond`; observe must still reject after > through.
    let err = rm_observe::observe(
        &reader,
        &request(&handle, beyond, Through::Prefix(head.clone()), 10),
    )
    .expect_err("after beyond cutoff must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (c) Fixed through requires zero wait.
    let mut waited = request(&handle, after0.clone(), Through::Prefix(head.clone()), 10);
    waited.wait_limit.value = 100.0;
    let err = rm_observe::observe(&reader, &waited).expect_err("fixed wait must fail");
    assert_eq!(err.code, "INVALID_REQUEST", "detail: {}", err.detail);

    // (d) Handle mismatch between request and cursor is CURSOR_INVALID.
    let other_handle = HandleReference {
        connector_id: "rm-observe-test".to_string(),
        local_handle: "handle-other".to_string(),
    };
    let mismatched_after = ObservationCursor {
        handle: other_handle,
        journal_id: journal_id.clone(),
        sequence: 0,
        event_hash: MaybeDigest::Missing(Missing::new("not_applicable")),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, mismatched_after, live_through(), 10),
    )
    .expect_err("handle mismatch must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (e) Through journal mismatch is CURSOR_INVALID.
    let other_prefix = JournalPrefix {
        journal_id: "journal-other".to_string(),
        last_sequence: head.last_sequence,
        head_hash: head.head_hash.clone(),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, after0.clone(), Through::Prefix(other_prefix), 10),
    )
    .expect_err("through journal mismatch must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (f) Fixed cutoff head_hash mismatch is CURSOR_INVALID.
    let bad_head = JournalPrefix {
        journal_id: journal_id.clone(),
        last_sequence: head.last_sequence,
        head_hash: artifact_digest(b"bad-head"),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, after0.clone(), Through::Prefix(bad_head), 10),
    )
    .expect_err("head hash mismatch must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (g) Fixed cutoff beyond retained is CURSOR_INVALID.
    let future = JournalPrefix {
        journal_id: journal_id.clone(),
        last_sequence: seq(head.last_sequence.get() + 10),
        head_hash: head.head_hash.clone(),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, after0.clone(), Through::Prefix(future), 10),
    )
    .expect_err("future cutoff must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (h) Live through with the wrong reason is INVALID_REQUEST.
    let err = rm_observe::observe(
        &reader,
        &request(
            &handle,
            after0.clone(),
            Through::Live(Missing::new("not_observed")),
            10,
        ),
    )
    .expect_err("wrong live reason must fail");
    assert_eq!(err.code, "INVALID_REQUEST", "detail: {}", err.detail);

    // (i) Unknown journal history is explicit CURSOR_UNAVAILABLE, never skipped.
    let unknown_after = ObservationCursor {
        handle: handle.clone(),
        journal_id: "journal-does-not-exist".to_string(),
        sequence: 0,
        event_hash: MaybeDigest::Missing(Missing::new("not_applicable")),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, unknown_after, live_through(), 10),
    )
    .expect_err("unknown journal must fail explicitly");
    assert_eq!(err.code, "CURSOR_UNAVAILABLE", "detail: {}", err.detail);

    // (j) Sequence-zero with a present hash is CURSOR_INVALID.
    let zero_present = ObservationCursor {
        handle: handle.clone(),
        journal_id: journal_id.clone(),
        sequence: 0,
        event_hash: MaybeDigest::Present(seq2.event_hash.clone()),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, zero_present, live_through(), 10),
    )
    .expect_err("zero with hash must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (k) Positive sequence with missing hash is CURSOR_INVALID.
    let positive_missing = ObservationCursor {
        handle: handle.clone(),
        journal_id: journal_id.clone(),
        sequence: 1,
        event_hash: MaybeDigest::Missing(Missing::new("not_applicable")),
    };
    let err = rm_observe::observe(
        &reader,
        &request(&handle, positive_missing, live_through(), 10),
    )
    .expect_err("positive with missing must fail");
    assert_eq!(err.code, "CURSOR_INVALID", "detail: {}", err.detail);

    // (l) Continuation never changes the cutoff: append after pinning, then
    // continue with the old fixed prefix and verify the old cutoff is echoed.
    let pinned = page1.through.clone();
    let raw_late = install_bytes(&writer, b"raw-late-cursor", "execution");
    append_event(
        &writer,
        &manifest,
        submission(
            "native_report",
            3,
            native_report_data(&raw_late, &seq1),
            vec![raw_late],
        ),
    )
    .expect("late append");
    let continued = rm_observe::observe(
        &reader,
        &request(&handle, page1.next.clone(), Through::Prefix(pinned.clone()), 10),
    )
    .expect("continuation with fixed cutoff");
    assert_eq!(continued.through, pinned);
    assert_eq!(continued.through.last_sequence.get(), 2);
}

#[test]
fn rm_c45_empty_at_cutoff_and_close_ref() {
    let run = "rm-observe-c45-close";
    let writer = principal("writer-c45-close");
    let reader = principal("reader-c45-close");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = handle_for(run);

    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let raw = install_bytes(&writer, b"raw-close", "execution");
    append_event(
        &writer,
        &manifest,
        submission(
            "native_report",
            2,
            native_report_data(&raw, &seq1),
            vec![raw],
        ),
    )
    .expect("seq2");

    // No observation_closed yet: close ref is not_observed.
    let after0 = cursor_zero(&handle, &journal_id);
    let page = rm_observe::observe(&reader, &request(&handle, after0.clone(), live_through(), 10))
        .expect("page without close");
    assert!(matches!(
        page.observation_close_ref,
        MaybeEvidenceRef::Missing(_)
    ));
    if let MaybeEvidenceRef::Missing(missing) = &page.observation_close_ref {
        assert_eq!(missing.reason, "not_observed");
    }

    // Append a close event (non-projection) plus a trailing incident.
    let close = append_event(&writer, &manifest, plain_submission("observation_closed", 3))
        .expect("seq3 close");
    assert_eq!(close.journal_sequence.get(), 3);
    append_event(
        &writer,
        &manifest,
        submission(
            "connector_incident",
            4,
            connector_incident_data(&seq1),
            Vec::new(),
        ),
    )
    .expect("seq4 incident");

    // Close ref now points at seq3 with an empty pointer, verified against
    // the pinned cutoff. Empty pages at the cutoff keep the same ref.
    let page = rm_observe::observe(&reader, &request(&handle, after0, live_through(), 1))
        .expect("page with close");
    let close_ref = match &page.observation_close_ref {
        MaybeEvidenceRef::Present(reference) => reference.clone(),
        MaybeEvidenceRef::Missing(missing) => {
            panic!("expected close ref, got missing {:?}", missing.reason)
        }
    };
    assert_eq!(close_ref.journal_id, journal_id);
    assert_eq!(close_ref.sequence.get(), 3);
    assert_eq!(close_ref.event_id, close.event_id);
    assert_eq!(close_ref.event_hash, close.event_hash);
    assert_eq!(close_ref.pointer, "");
    // The reference resolves inside the pinned cutoff.
    let resolved = resolve_evidence(&reader, &close_ref, &page.through).expect("close resolves");
    assert_eq!(resolved.event_kind, "observation_closed");

    // Drain to the cutoff, then read the empty page: close ref persists and
    // the empty page does not claim termination.
    let mut after = page.next.clone();
    let fixed = page.through.clone();
    loop {
        let next_page = rm_observe::observe(
            &reader,
            &request(&handle, after, Through::Prefix(fixed.clone()), 1),
        )
        .expect("drain page");
        assert_eq!(next_page.observation_close_ref.to_json_for_test(), close_ref.to_json_for_test());
        if !next_page.has_more {
            assert!(next_page.items.is_empty() || next_page.next.sequence == 4);
            assert_eq!(next_page.through, fixed);
            break;
        }
        after = next_page.next.clone();
    }
}

// ---------------------------------------------------------------------------
// RM-C46: oversized single observation item
// ---------------------------------------------------------------------------

#[test]
fn rm_c46_single_oversized_item_is_explicit_error() {
    let run = "rm-observe-c46-single";
    let writer = principal("writer-c46-single");
    let reader = principal("reader-c46-single");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = handle_for(run);

    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);
    let content_small = install_bytes(&writer, b"small-c46", "execution");

    // seq2: small projection that fits.
    append_event(
        &writer,
        &manifest,
        submission(
            "task_output",
            2,
            task_output_data(&content_small, &seq1, Vec::new()),
            vec![content_small],
        ),
    )
    .expect("seq2 small");

    // seq3: single oversized projection (20KB limitation).
    let content_large = install_bytes(&writer, b"large-c46", "execution");
    let huge = "A".repeat(20_000);
    append_event(
        &writer,
        &manifest,
        submission(
            "task_output",
            3,
            task_output_data(&content_large, &seq1, vec![huge]),
            vec![content_large],
        ),
    )
    .expect("seq3 large");

    // First page fits the small item and stops before the oversized one:
    // the oversized item is never silently dropped or skipped past.
    let after0 = cursor_zero(&handle, &journal_id);
    let page1 = rm_observe::observe(&reader, &request(&handle, after0, live_through(), 10))
        .expect("first page truncates before oversized");
    assert_eq!(page1.items.len(), 1);
    assert_eq!(page1.items[0].sequence(), 2);
    assert_eq!(page1.next.sequence, 2);
    assert!(page1.has_more);
    assert!(
        page1.limitations.iter().any(|entry| entry.contains("response bound")),
        "byte truncation must be disclosed, got {:?}",
        page1.limitations
    );

    // Continuing onto the oversized item alone is an explicit size error.
    let err = rm_observe::observe(
        &reader,
        &request(
            &handle,
            page1.next.clone(),
            Through::Prefix(page1.through.clone()),
            10,
        ),
    )
    .expect_err("oversized single item must error");
    assert_eq!(err.code, "RESPONSE_TOO_LARGE", "detail: {}", err.detail);
    assert!(
        err.detail.contains('3'),
        "error must name the offending sequence, got {}",
        err.detail
    );
    assert!(
        err.detail.contains(&MAX_RESPONSE_BYTES.to_string()),
        "error must name the bound, got {}",
        err.detail
    );

    // A lone oversized journal also errors rather than returning an empty page.
    let run2 = "rm-observe-c46-lone";
    let manifest2 = test_manifest(run2);
    let journal2 = journal_id_for(&manifest2).expect("journal2 identity");
    let handle2 = handle_for(run2);
    let admission2 = admit(&writer, &manifest2);
    let seq1b = ref_to(&admission2);
    let content2 = install_bytes(&writer, b"lone-c46", "execution");
    append_event(
        &writer,
        &manifest2,
        submission(
            "task_output",
            2,
            task_output_data(&content2, &seq1b, vec!["B".repeat(20_000)]),
            vec![content2],
        ),
    )
    .expect("lone large");
    let err = rm_observe::observe(
        &reader,
        &request(&handle2, cursor_zero(&handle2, &journal2), live_through(), 10),
    )
    .expect_err("lone oversized must error");
    assert_eq!(err.code, "RESPONSE_TOO_LARGE");
}

#[test]
fn rm_c46_truncation_returns_fewer_items() {
    let run = "rm-observe-c46-truncate";
    let writer = principal("writer-c46-truncate");
    let reader = principal("reader-c46-truncate");
    let manifest = test_manifest(run);
    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let handle = handle_for(run);

    let admission_envelope = admit(&writer, &manifest);
    let seq1 = ref_to(&admission_envelope);

    // Three medium projections (~3KB each): the first two fit the 8KB bound
    // together, the third forces a disclosed truncation.
    for (index, marker) in ["C", "D", "E"].iter().enumerate() {
        let bytes = format!("medium-c46-{marker}").into_bytes();
        let content = install_bytes(&writer, &bytes, "execution");
        let pad = marker.repeat(3_000);
        append_event(
            &writer,
            &manifest,
            submission(
                "task_output",
                2 + index as u64,
                task_output_data(&content, &seq1, vec![pad]),
                vec![content],
            ),
        )
        .expect("medium append");
    }

    let after0 = cursor_zero(&handle, &journal_id);
    let page1 = rm_observe::observe(&reader, &request(&handle, after0, live_through(), 10))
        .expect("truncated page");
    // Server returns fewer items to honor the byte bound.
    assert!(
        page1.items.len() < 3,
        "expected truncation, got {} items",
        page1.items.len()
    );
    assert!(!page1.items.is_empty());
    assert!(page1.has_more);
    assert!(
        page1.limitations.iter().any(|entry| entry.contains("response bound")),
        "truncation must be disclosed, got {:?}",
        page1.limitations
    );
    // Drain continuations with the pinned cutoff; every projection arrives
    // exactly once, in order, with no loss or duplication.
    let mut all: Vec<u64> = page1.items.iter().map(|item| item.sequence()).collect();
    let mut after = page1.next.clone();
    let fixed = page1.through.clone();
    let mut pages = 1;
    loop {
        let next_page = rm_observe::observe(
            &reader,
            &request(&handle, after.clone(), Through::Prefix(fixed.clone()), 10),
        )
        .expect("remainder page");
        assert_eq!(next_page.through, fixed);
        for item in &next_page.items {
            all.push(item.sequence());
        }
        after = next_page.next.clone();
        pages += 1;
        if !next_page.has_more {
            assert_eq!(after.sequence, 4);
            break;
        }
        assert!(pages < 10, "pagination must terminate");
    }
    all.sort_unstable();
    assert_eq!(all, vec![2, 3, 4]);
}

// ---------------------------------------------------------------------------
// Test-only JSON helpers (avoid exposing internals for production callers).
// ---------------------------------------------------------------------------

trait TestJson {
    fn to_json_for_test(&self) -> Value;
}

impl TestJson for EvidenceRef {
    fn to_json_for_test(&self) -> Value {
        self.to_json()
    }
}

impl TestJson for MaybeEvidenceRef {
    fn to_json_for_test(&self) -> Value {
        match self {
            MaybeEvidenceRef::Present(reference) => reference.to_json(),
            MaybeEvidenceRef::Missing(missing) => json!({
                "value": Value::Null,
                "reason": missing.reason,
            }),
        }
    }
}
