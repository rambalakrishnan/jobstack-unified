//! Conformance tests for RM-C50: lease stale completion, restart, and double
//! recovery — fenced completion and one failed-generation retry increment.
//!
//! Every test name carries the `rm_c50` token so
//! `cargo test -p rm_leases -- rm_c50` selects the suite. The tests drive the
//! real module against the real `rm_evidence` journal, artifact store, and
//! `rm_authority` owner authorization; nothing is mocked.

use rm_authority::{authenticate_channel, manifest_wire_bytes, AuthenticatedPrincipal, Manifest};
use rm_evidence::{
    append_event, install_artifact, journal_head, journal_id_for, manifest_artifact_reference,
    resolve_evidence, AccessClass, ArtifactReference, AssertionKind, EvidencePayload, EventSubmission,
    JournalEnvelope, MaybeTimePoint, Missing, PositiveInteger,
};
use rm_leases::{
    transition_lease, validate_lease, LeaseRecord, LeaseState,
};
use rm_time::{
    boundary_reached, ClockBasis, ClockDescriptor, MeasurementOrigin, MaybeString, TimePoint,
    UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

const CLOCK: &str = "lease-clock";
const BOOT1: &str = "boot-1";
const BOOT2: &str = "boot-2";
const TTL_MS: f64 = 30_000.0;

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

fn install_bytes(
    writer: &AuthenticatedPrincipal,
    bytes: &[u8],
    media_type: &str,
    owner: &str,
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: media_type.to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    install_artifact(writer, &reference, bytes).expect("test artifact installs");
    reference
}

fn policy_bytes(policy_version: &str, ttl_ms: f64, max_retries: u64) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "record_type": "lease_policy",
        "schema_version": "evidence-kernel/0.1.0",
        "policy_id": "execution_lease",
        "policy_version": policy_version,
        "eligible_state": "pending",
        "ttl_ms": ttl_ms,
        "max_retries": max_retries,
    }))
    .expect("policy serializes")
}

fn manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "execution"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "clock_registered",
            "execution_claim",
            "task_output",
        ]
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

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive integer")
}

fn admission_submission(manifest: &Manifest) -> EventSubmission {
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
    append_event(writer, manifest, admission_submission(manifest)).expect("manifest admission")
}

fn clock_descriptor(boot: &str) -> ClockDescriptor {
    ClockDescriptor {
        clock_id: CLOCK.to_string(),
        boot_id: boot.to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: "lease-authority".to_string(),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    }
}

fn clock_submission(producer_sequence: u64, descriptor: &ClockDescriptor) -> EventSubmission {
    EventSubmission {
        producer_sequence: Some(seq(producer_sequence)),
        event_kind: "clock_registered".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data: serde_json::to_value(descriptor).expect("clock descriptor serializes"),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: Vec::new(),
        },
    }
}

fn tp(boot: &str, offset_ms: f64) -> TimePoint {
    TimePoint {
        clock_id: CLOCK.to_string(),
        boot_id: boot.to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset_ms,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn time_json(point: &TimePoint) -> Value {
    serde_json::to_value(point).expect("time point serializes")
}

fn text(value: &str) -> MaybeString {
    MaybeString::Text(value.to_string())
}

fn inapplicable() -> MaybeString {
    MaybeString::Missing(Missing::new("not_applicable"))
}

fn inapplicable_time() -> MaybeTimePoint {
    MaybeTimePoint::Missing(Missing::new("not_applicable"))
}

fn maybe_json(value: &MaybeString) -> Value {
    serde_json::to_value(value).expect("maybe string serializes")
}

fn maybe_time_json(value: &MaybeTimePoint) -> Value {
    serde_json::to_value(value).expect("maybe time serializes")
}

fn evidence_ref_json(envelope: &JournalEnvelope) -> Value {
    json!({
        "journal_id": envelope.journal_id,
        "sequence": envelope.journal_sequence.get(),
        "event_id": envelope.event_id,
        "event_hash": envelope.event_hash.as_str(),
        "pointer": "",
    })
}

fn merge_value(base: &mut Value, overrides: Value) {
    if let Value::Object(overrides) = overrides {
        if let Some(base_object) = base.as_object_mut() {
            for (key, value) in overrides {
                match base_object.get_mut(&key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        merge_value(existing, value);
                    }
                    _ => {
                        base_object.insert(key, value);
                    }
                }
            }
        }
    }
}

fn text_of(value: &MaybeString) -> String {
    match value {
        MaybeString::Text(text) => text.clone(),
        other => panic!("expected present text, found {other:?}"),
    }
}

fn point_of(value: &MaybeTimePoint) -> TimePoint {
    match value {
        MaybeTimePoint::Present(point) => point.clone(),
        other => panic!("expected present time point, found {other:?}"),
    }
}

fn is_inapplicable(value: &MaybeString) -> bool {
    matches!(
        value,
        MaybeString::Missing(missing) if missing.reason == "not_applicable"
    )
}

fn is_inapplicable_time(value: &MaybeTimePoint) -> bool {
    matches!(
        value,
        MaybeTimePoint::Missing(missing) if missing.reason == "not_applicable"
    )
}

/// One admitted resource journal plus the initial unleased lease snapshot.
struct Fixture {
    writer: AuthenticatedPrincipal,
    resource: Value,
    manifest: Manifest,
    journal_id: String,
    policy: ArtifactReference,
    policy_pin: Value,
    initial: LeaseRecord,
    next_sequence: u64,
}

impl Fixture {
    fn new(run: &str, entity_id: &str) -> Fixture {
        Fixture::with_policy(run, entity_id, "1", TTL_MS, 2)
    }

    fn with_policy(
        run: &str,
        entity_id: &str,
        policy_version: &str,
        ttl_ms: f64,
        max_retries: u64,
    ) -> Fixture {
        let writer = principal("lease-authority");
        let manifest = manifest(run);
        admit(&writer, &manifest);
        let clock = clock_descriptor(BOOT1);
        let clock_envelope =
            append_event(&writer, &manifest, clock_submission(2, &clock)).expect("clock registers");
        let policy_bytes = policy_bytes(policy_version, ttl_ms, max_retries);
        let policy = install_bytes(&writer, &policy_bytes, "application/json", "execution");
        let policy_pin = json!({
            "id": "execution_lease",
            "version": policy_version,
            "artifact_digest": policy.digest.as_str(),
        });
        let resource = json!({
            "owner_domain": "execution",
            "entity_type": "connector_task",
            "entity_id": entity_id,
        });
        let journal_id = journal_id_for(&manifest).expect("journal identity");
        let initial_json = json!({
            "record_type": "lease_record",
            "schema_version": "evidence-kernel/0.1.0",
            "resource": resource,
            "policy": policy_pin,
            "issuer_id": "lease-authority",
            "authority_epoch": "authority-epoch-0",
            "entity_revision": 1,
            "input_revision": 1,
            "generation_id": "generation-initial",
            "resource_state": "pending",
            "eligible_state": "pending",
            "lease_state": "unleased",
            "lease_id": maybe_json(&inapplicable()),
            "lease_owner": maybe_json(&inapplicable()),
            "owner_epoch": maybe_json(&inapplicable()),
            "session_epoch": maybe_json(&inapplicable()),
            "leased_at": maybe_time_json(&inapplicable_time()),
            "lease_expires_at": maybe_time_json(&inapplicable_time()),
            "retry_count": 0,
            "max_retries_effective": max_retries,
            "last_failure_reason": maybe_json(&inapplicable()),
            "journal_prefix": {
                "journal_id": clock_envelope.journal_id,
                "last_sequence": clock_envelope.journal_sequence.get(),
                "head_hash": clock_envelope.event_hash.as_str(),
            },
            "evidence_refs": [evidence_ref_json(&clock_envelope)],
        });
        let initial = LeaseRecord::from_json(&initial_json).expect("initial lease record parses");
        Fixture {
            writer,
            resource,
            manifest,
            journal_id,
            policy,
            policy_pin,
            initial,
            next_sequence: 3,
        }
    }

    fn take_sequence(&mut self) -> u64 {
        let value = self.next_sequence;
        self.next_sequence += 1;
        value
    }

    fn receipt(&self, producer_sequence: u64) -> ArtifactReference {
        let bytes = format!(
            "receipt:{}:{}",
            self.manifest.run_id, producer_sequence
        );
        install_bytes(
            &self.writer,
            bytes.as_bytes(),
            "application/json",
            "execution",
        )
    }

    fn intent_json(
        &self,
        operation: &str,
        expected: Value,
        issued_at: &TimePoint,
        producer_sequence: u64,
        overrides: Value,
    ) -> Value {
        let mut base = json!({
            "record_type": "lease_transition_intent",
            "schema_version": "evidence-kernel/0.1.0",
            "operation": operation,
            "resource": self.resource,
            "expected": expected,
            "authority_epoch": "authority-epoch-1",
            "policy": {
                "pin": self.policy_pin,
                "reference": self.policy.to_json(),
            },
            "issued_at": time_json(issued_at),
            "lease_owner": maybe_json(&inapplicable()),
            "session_epoch": maybe_json(&inapplicable()),
            "failure_reason": maybe_json(&inapplicable()),
            "producer_sequence": producer_sequence,
            "manifest": manifest_json(&self.manifest),
            "response": self.receipt(producer_sequence).to_json(),
        });
        merge_value(&mut base, overrides);
        base
    }

    fn intent(
        &self,
        operation: &str,
        expected: Value,
        issued_at: &TimePoint,
        producer_sequence: u64,
        overrides: Value,
    ) -> ArtifactReference {
        let value = self.intent_json(operation, expected, issued_at, producer_sequence, overrides);
        let bytes = serde_json::to_vec(&value).expect("intent serializes");
        install_bytes(&self.writer, &bytes, "application/json", "execution")
    }

    fn head(&self) -> rm_evidence::JournalPrefix {
        journal_head(&self.writer, &self.journal_id).expect("journal head")
    }
}

/// The exact fence currently recorded, as an intent `expected` object.
fn fence_of(current: &LeaseRecord) -> Value {
    json!({
        "entity_revision": current.entity_revision,
        "input_revision": current.input_revision,
        "generation_id": current.generation_id,
        "authority_epoch": current.authority_epoch,
        "lease_id": maybe_json(&current.lease_id),
        "owner_epoch": maybe_json(&current.owner_epoch),
        "session_epoch": maybe_json(&current.session_epoch),
    })
}

#[allow(clippy::too_many_arguments)]
fn attempt_with(
    fixture: &mut Fixture,
    principal: &AuthenticatedPrincipal,
    operation: &str,
    current: &LeaseRecord,
    expected: Value,
    issued_at: &TimePoint,
    now: &TimePoint,
    producer_sequence: u64,
    extra: Value,
) -> Result<LeaseRecord, rm_authority::ConnectorError> {
    let intent = fixture.intent(operation, expected, issued_at, producer_sequence, extra);
    transition_lease(principal, current, &intent, now)
}

fn attempt_boot(
    fixture: &mut Fixture,
    operation: &str,
    current: &LeaseRecord,
    boot: &str,
    issued: f64,
    now: f64,
    expected: Value,
    extra: Value,
) -> Result<LeaseRecord, rm_authority::ConnectorError> {
    let writer = fixture.writer.clone();
    let producer_sequence = fixture.take_sequence();
    attempt_with(
        fixture,
        &writer,
        operation,
        current,
        expected,
        &tp(boot, issued),
        &tp(boot, now),
        producer_sequence,
        extra,
    )
}

fn attempt(
    fixture: &mut Fixture,
    operation: &str,
    current: &LeaseRecord,
    issued: f64,
    now: f64,
    extra: Value,
) -> Result<LeaseRecord, rm_authority::ConnectorError> {
    attempt_boot(
        fixture,
        operation,
        current,
        BOOT1,
        issued,
        now,
        fence_of(current),
        extra,
    )
}

fn claim(
    fixture: &mut Fixture,
    current: &LeaseRecord,
    issued: f64,
    now: f64,
) -> Result<LeaseRecord, rm_authority::ConnectorError> {
    attempt(
        fixture,
        "claim",
        current,
        issued,
        now,
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    )
}

fn claim_with(
    fixture: &mut Fixture,
    current: &LeaseRecord,
    issued: f64,
    now: f64,
    extra: Value,
) -> Result<LeaseRecord, rm_authority::ConnectorError> {
    let mut overrides = json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"});
    merge_value(&mut overrides, extra);
    attempt(fixture, "claim", current, issued, now, overrides)
}

// ---------------------------------------------------------------------------
// RM-C50: claim (EK-LEASE, OWD-REVISION, EK-ATOMICITY)
// ---------------------------------------------------------------------------

#[test]
fn rm_c50_claim_assigns_fenced_identity_and_keeps_resource_state() {
    let mut fixture = Fixture::new("run-c50-claim", "task-c50-claim");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");

    assert_eq!(claimed.lease_state, LeaseState::Held);
    assert_eq!(
        claimed.resource_state, initial.resource_state,
        "claim must not change the owner resource state"
    );
    assert_eq!(claimed.eligible_state, initial.eligible_state);
    assert_eq!(claimed.entity_revision, initial.entity_revision + 1);
    assert_eq!(claimed.input_revision, initial.input_revision);
    assert_eq!(claimed.issuer_id, fixture.writer.principal_id());
    assert_eq!(claimed.authority_epoch, "authority-epoch-1");
    assert_eq!(claimed.retry_count, 0);
    assert!(is_inapplicable(&claimed.last_failure_reason));
    assert_eq!(claimed.lease_owner, text("worker-c50"));
    assert_eq!(claimed.session_epoch, text("session-c50"));

    let lease_id = text_of(&claimed.lease_id);
    assert!(!lease_id.is_empty(), "claim assigns a fence token");
    assert_eq!(text_of(&claimed.owner_epoch).is_empty(), false);

    let issued = point_of(&claimed.leased_at);
    let deadline = point_of(&claimed.lease_expires_at);
    assert_eq!(issued.monotonic_offset_ms, 1_000.0);
    assert_eq!(issued.clock_id, CLOCK);
    assert_eq!(issued.boot_id, BOOT1);
    assert_eq!(deadline.monotonic_offset_ms, 1_000.0 + TTL_MS);
    assert_eq!(
        boundary_reached(&deadline, &issued),
        Ok(true),
        "held expiry is strictly later than issue"
    );

    assert_eq!(
        claimed.evidence_refs.len(),
        initial.evidence_refs.len() + 1,
        "claim appends exactly one durable evidence reference"
    );
    let witness = claimed.evidence_refs.last().expect("new evidence reference");
    let envelope = resolve_evidence(&fixture.writer, witness, &claimed.journal_prefix)
        .expect("claim evidence resolves against the snapshot prefix");
    assert_eq!(envelope.event_kind, "execution_claim");
    assert_eq!(envelope.owner_domain, "execution");
    assert_eq!(envelope.producer_id, fixture.writer.principal_id());
    assert_eq!(envelope.assertion_kind, AssertionKind::Claim);
    assert_eq!(envelope.payload.data["lease"]["lease_id"], json!(lease_id));
    assert_eq!(
        claimed.journal_prefix.last_sequence, witness.sequence,
        "the record prefix advances to its own evidence head"
    );
}

#[test]
fn rm_c50_claim_refuses_unexpired_lease_and_ineligible_state() {
    let mut fixture = Fixture::new("run-c50-busy", "task-c50-busy");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let head = fixture.head();

    let error = claim_with(
        &mut fixture,
        &claimed,
        2_000.0,
        2_000.0,
        json!({"lease_owner": "other-worker", "session_epoch": "other-session"}),
    )
    .expect_err("an unexpired lease blocks a second claim");
    assert_eq!(error.code, "RESOURCE_BUSY");
    assert_eq!(fixture.head(), head, "a refused claim writes no evidence");

    let mut ineligible = fixture.initial.clone();
    ineligible.resource_state = "blocked".to_string();
    let error = claim(&mut fixture, &ineligible, 1_000.0, 1_000.0)
        .expect_err("an ineligible resource state cannot be claimed");
    assert_eq!(error.code, "NOT_ADMITTED");
    assert!(error.detail.contains("eligible"));
    assert_eq!(
        ineligible.resource_state, "blocked",
        "the rejected claim does not rewrite the resource state"
    );
}

#[test]
fn rm_c50_claim_cannot_self_issue_a_fencing_token() {
    let mut fixture = Fixture::new("run-c50-self-issue", "task-c50-self-issue");
    let initial = fixture.initial.clone();

    // A worker-supplied lease_id is not part of the closed intent; it cannot be
    // injected to self-issue ownership.
    let error = claim_with(
        &mut fixture,
        &initial,
        1_000.0,
        1_000.0,
        json!({"lease_id": "lease:forged", "owner_epoch": "owner:forged"}),
    )
    .expect_err("the intent record is closed");
    assert_eq!(error.code, "INVALID_REQUEST");

    // A fence assertion that invents ownership against an unleased record is
    // stale, not accepted.
    let mut forged_fence = fence_of(&initial);
    forged_fence["lease_id"] = json!(maybe_json(&text("lease:forged")));
    let error = attempt_boot(
        &mut fixture,
        "claim",
        &initial,
        BOOT1,
        1_000.0,
        1_000.0,
        forged_fence,
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    )
    .expect_err("a claimed fence cannot equal an unleased record");
    assert_eq!(error.code, "STALE_CONTEXT");

    // A lease on another write axis cannot be claimed through the execution
    // axis: the registered resource authority refuses the mismatch.
    let mut report_lease = initial.clone();
    report_lease.resource.owner_domain = "report".to_string();
    let mut overrides = json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"});
    merge_value(
        &mut overrides,
        json!({"resource": {"owner_domain": "report", "entity_type": "connector_task", "entity_id": "task-c50-self-issue"}}),
    );
    let error = claim_with(&mut fixture, &report_lease, 1_000.0, 1_000.0, overrides)
        .expect_err("only the resource owner axis may issue a lease");
    assert_eq!(error.code, "FORBIDDEN");
}

// ---------------------------------------------------------------------------
// RM-C50: completion fencing (stale completion has no effect)
// ---------------------------------------------------------------------------

#[test]
fn rm_c50_completion_requires_current_fence_and_unexpired_deadline() {
    let mut fixture = Fixture::new("run-c50-complete", "task-c50-complete");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let head = fixture.head();

    // Every stale expectation is rejected before any journal write.
    let mut stale_lease = fence_of(&claimed);
    stale_lease["lease_id"] = json!(maybe_json(&text("lease:superseded")));
    for (label, fence) in [
        ("lease_id", stale_lease),
        (
            "entity_revision",
            {
                let mut fence = fence_of(&claimed);
                fence["entity_revision"] = json!(claimed.entity_revision + 7);
                fence
            },
        ),
        (
            "input_revision",
            {
                let mut fence = fence_of(&claimed);
                fence["input_revision"] = json!(claimed.input_revision + 7);
                fence
            },
        ),
        (
            "owner_epoch",
            {
                let mut fence = fence_of(&claimed);
                fence["owner_epoch"] = json!(maybe_json(&text("owner:superseded")));
                fence
            },
        ),
        (
            "session_epoch",
            {
                let mut fence = fence_of(&claimed);
                fence["session_epoch"] = json!(maybe_json(&text("session:superseded")));
                fence
            },
        ),
        (
            "generation_id",
            {
                let mut fence = fence_of(&claimed);
                fence["generation_id"] = json!("generation:superseded");
                fence
            },
        ),
    ] {
        let error = attempt_boot(
            &mut fixture,
            "complete",
            &claimed,
            BOOT1,
            20_000.0,
            20_000.0,
            fence,
            json!({}),
        )
        .expect_err("a stale completion fence must be rejected");
        assert_eq!(error.code, "STALE_CONTEXT", "stale fence field: {label}");
    }
    assert_eq!(
        fixture.head(),
        head,
        "rejected stale completions have no journal effect"
    );
    assert_eq!(claimed.retry_count, 0, "nothing was counted as a retry");

    // Reaching the authority-clock deadline makes the completion stale.
    let error = attempt(&mut fixture, "complete", &claimed, 31_000.0, 31_000.0, json!({}))
        .expect_err("a completion at the deadline is stale");
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(fixture.head(), head);

    // A current, unexpired completion clears ownership and is not a retry.
    let completed = attempt(&mut fixture, "complete", &claimed, 20_000.0, 20_000.0, json!({}))
        .expect("current completion succeeds");
    assert_eq!(completed.lease_state, LeaseState::Unleased);
    assert!(is_inapplicable(&completed.lease_id));
    assert!(is_inapplicable(&completed.owner_epoch));
    assert!(is_inapplicable(&completed.session_epoch));
    assert_eq!(completed.entity_revision, claimed.entity_revision + 1);
    assert_eq!(completed.input_revision, claimed.input_revision);
    assert_eq!(completed.generation_id, claimed.generation_id);
    assert_eq!(
        completed.retry_count, claimed.retry_count,
        "successful completion is not a failed retry"
    );
    assert!(is_inapplicable(&completed.last_failure_reason));
    assert_eq!(completed.evidence_refs.len(), claimed.evidence_refs.len() + 1);

    let witness = completed.evidence_refs.last().expect("completion evidence");
    let envelope = resolve_evidence(&fixture.writer, witness, &completed.journal_prefix)
        .expect("completion evidence resolves");
    assert_eq!(envelope.event_kind, "task_output");
    assert_eq!(envelope.assertion_kind, AssertionKind::Observation);
}

#[test]
fn rm_c50_validate_lease_rejects_stale_fences_and_incompatible_state() {
    let mut fixture = Fixture::new("run-c50-validate", "task-c50-validate");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let owner_epoch = text_of(&claimed.owner_epoch);
    let session = claimed.session_epoch.clone();

    validate_lease(
        &claimed,
        &tp(BOOT1, 20_000.0),
        claimed.entity_revision,
        claimed.input_revision,
        &owner_epoch,
        &session,
    )
    .expect("a current held lease validates");

    let error = validate_lease(
        &initial,
        &tp(BOOT1, 1_000.0),
        initial.entity_revision,
        initial.input_revision,
        &owner_epoch,
        &session,
    )
    .expect_err("an unleased record grants no commit authority");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT1, 31_000.0),
        claimed.entity_revision,
        claimed.input_revision,
        &owner_epoch,
        &session,
    )
    .expect_err("the authority-clock deadline has been reached");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT1, 20_000.0),
        claimed.entity_revision + 1,
        claimed.input_revision,
        &owner_epoch,
        &session,
    )
    .expect_err("a stale entity revision cannot commit");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT1, 20_000.0),
        claimed.entity_revision,
        claimed.input_revision + 1,
        &owner_epoch,
        &session,
    )
    .expect_err("a stale input revision cannot commit");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT1, 20_000.0),
        claimed.entity_revision,
        claimed.input_revision,
        "owner:superseded",
        &session,
    )
    .expect_err("a stale owner epoch cannot commit");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT1, 20_000.0),
        claimed.entity_revision,
        claimed.input_revision,
        &owner_epoch,
        &text("session:superseded"),
    )
    .expect_err("a stale session epoch cannot commit");
    assert_eq!(error.code, "STALE_CONTEXT");

    let error = validate_lease(
        &claimed,
        &tp(BOOT2, 500.0),
        claimed.entity_revision,
        claimed.input_revision,
        &owner_epoch,
        &session,
    )
    .expect_err("a restarted authority clock cannot be compared");
    assert_eq!(error.code, "PREREQUISITE_UNAVAILABLE");

    let mut incompatible = claimed.clone();
    incompatible.resource_state = "running".to_string();
    let error = validate_lease(
        &incompatible,
        &tp(BOOT1, 20_000.0),
        incompatible.entity_revision,
        incompatible.input_revision,
        &owner_epoch,
        &session,
    )
    .expect_err("a held record requires a compatible owner state");
    assert_eq!(error.code, "NOT_ADMITTED");

    // A session-inapplicable hold validates only with typed inapplicable
    // missingness, never with a bare null or an invented session.
    let detached = claim_with(
        &mut fixture,
        &initial,
        1_000.0,
        1_000.0,
        json!({"session_epoch": maybe_json(&inapplicable())}),
    )
    .expect("a session-inapplicable claim succeeds");
    validate_lease(
        &detached,
        &tp(BOOT1, 2_000.0),
        detached.entity_revision,
        detached.input_revision,
        &text_of(&detached.owner_epoch),
        &inapplicable(),
    )
    .expect("inapplicable session epoch matches");
    let error = validate_lease(
        &detached,
        &tp(BOOT1, 2_000.0),
        detached.entity_revision,
        detached.input_revision,
        &text_of(&detached.owner_epoch),
        &text("session-c50"),
    )
    .expect_err("an invented session epoch cannot satisfy an inapplicable hold");
    assert_eq!(error.code, "STALE_CONTEXT");

    // No in-band nulls: a bare null is not a typed Missing envelope.
    let mut bare_null = fixture.initial.to_json();
    bare_null["lease_id"] = Value::Null;
    let error = LeaseRecord::from_json(&bare_null)
        .expect_err("a bare null is rejected rather than read as missingness");
    assert_eq!(error.code, "INVALID_REQUEST");
}

#[test]
fn rm_c50_release_clears_ownership_without_a_retry() {
    let mut fixture = Fixture::new("run-c50-release", "task-c50-release");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let head = fixture.head();

    // A release with a superseded owner epoch is fenced out with no effect.
    let mut stale = fence_of(&claimed);
    stale["owner_epoch"] = json!(maybe_json(&text("owner:superseded")));
    let error = attempt_boot(
        &mut fixture,
        "release",
        &claimed,
        BOOT1,
        2_000.0,
        2_000.0,
        stale,
        json!({}),
    )
    .expect_err("a superseded owner epoch cannot release");
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(fixture.head(), head);

    let released = attempt(&mut fixture, "release", &claimed, 2_000.0, 2_000.0, json!({}))
        .expect("release clears ownership");
    assert_eq!(released.lease_state, LeaseState::Unleased);
    assert!(is_inapplicable(&released.lease_id));
    assert!(is_inapplicable(&released.owner_epoch));
    assert!(is_inapplicable_time(&released.leased_at));
    assert_eq!(released.entity_revision, claimed.entity_revision + 1);
    assert_eq!(
        released.retry_count, claimed.retry_count,
        "a graceful release is not a failed retry"
    );
    assert!(is_inapplicable(&released.last_failure_reason));
    assert_eq!(released.evidence_refs.len(), claimed.evidence_refs.len() + 1);
    let witness = released.evidence_refs.last().expect("release evidence");
    resolve_evidence(&fixture.writer, witness, &released.journal_prefix)
        .expect("release evidence resolves");

    // A second release against the cleared snapshot is refused.
    let error = attempt(&mut fixture, "release", &released, 2_500.0, 2_500.0, json!({}))
        .expect_err("a cleared record cannot be released again");
    assert_eq!(error.code, "STALE_CONTEXT");
}

// ---------------------------------------------------------------------------
// RM-C50: renewal
// ---------------------------------------------------------------------------

#[test]
fn rm_c50_renewal_requires_current_token_and_never_uses_utc() {
    let mut fixture = Fixture::new("run-c50-renew", "task-c50-renew");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");

    let renewed = attempt(&mut fixture, "renew", &claimed, 20_000.0, 20_000.0, json!({}))
        .expect("renewal succeeds");
    assert_eq!(renewed.lease_id, claimed.lease_id);
    assert_eq!(renewed.owner_epoch, claimed.owner_epoch);
    assert_eq!(renewed.session_epoch, claimed.session_epoch);
    assert_eq!(renewed.entity_revision, claimed.entity_revision + 1);
    assert_eq!(renewed.retry_count, claimed.retry_count);
    let deadline = point_of(&renewed.lease_expires_at);
    assert_eq!(deadline.monotonic_offset_ms, 20_000.0 + TTL_MS);
    assert!(
        deadline.monotonic_offset_ms > point_of(&claimed.lease_expires_at).monotonic_offset_ms,
        "renewal extends the deadline"
    );

    // A superseded token cannot be renewed.
    let mut stale = fence_of(&claimed);
    stale["lease_id"] = json!(maybe_json(&text("lease:superseded")));
    let error = attempt_boot(
        &mut fixture,
        "renew",
        &claimed,
        BOOT1,
        22_000.0,
        22_000.0,
        stale,
        json!({}),
    )
    .expect_err("a superseded token cannot be renewed");
    assert_eq!(error.code, "STALE_CONTEXT");

    // A renewal after the deadline is stale, not a silent re-claim.
    let error = attempt(&mut fixture, "renew", &claimed, 32_000.0, 32_000.0, json!({}))
        .expect_err("an expired hold cannot be renewed");
    assert_eq!(error.code, "STALE_CONTEXT");

    // Renewal must reuse the policy pinned at claim.
    let other_policy_bytes = policy_bytes("2", 60_000.0, 2);
    let other_policy = install_bytes(
        &fixture.writer.clone(),
        &other_policy_bytes,
        "application/json",
        "execution",
    );
    let error = attempt_boot(
        &mut fixture,
        "renew",
        &claimed,
        BOOT1,
        22_000.0,
        22_000.0,
        fence_of(&claimed),
        json!({"policy": {
            "pin": {"id": "execution_lease", "version": "2", "artifact_digest": other_policy.digest.as_str()},
            "reference": other_policy.to_json(),
        }}),
    )
    .expect_err("renewal cannot renegotiate the pinned policy");
    assert_eq!(error.code, "NOT_ADMITTED");

    // Elapsed time comes from the monotonic offset only. A wild UTC annotation
    // on the issue coordinate cannot move the deadline.
    let mut issued = tp(BOOT1, 20_000.0);
    issued.utc_annotation = UtcAnnotation::DateTime("2099-12-31T23:59:59Z".to_string());
    let utc_renewed = attempt_boot(
        &mut fixture,
        "renew",
        &claimed,
        BOOT1,
        20_000.0,
        20_000.0,
        fence_of(&claimed),
        json!({"issued_at": time_json(&issued)}),
    )
    .expect("renewal with a UTC annotation succeeds");
    assert_eq!(
        point_of(&utc_renewed.lease_expires_at).monotonic_offset_ms,
        20_000.0 + TTL_MS,
        "UTC annotations never contribute to elapsed time"
    );
}

// ---------------------------------------------------------------------------
// RM-C50: expiry, restart, and retry accounting
// ---------------------------------------------------------------------------

#[test]
fn rm_c50_expiry_clears_ownership_and_increments_retry_once() {
    let mut fixture = Fixture::new("run-c50-expire", "task-c50-expire");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let head = fixture.head();

    let error = attempt(
        &mut fixture,
        "expire",
        &claimed,
        30_000.0,
        30_000.0,
        json!({"failure_reason": "deadline_missed"}),
    )
    .expect_err("expiry before the deadline is not established");
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(fixture.head(), head);

    let expired = attempt(
        &mut fixture,
        "expire",
        &claimed,
        31_000.0,
        31_000.0,
        json!({"failure_reason": "deadline_missed"}),
    )
    .expect("expiry at the deadline succeeds");
    assert_eq!(expired.lease_state, LeaseState::Unleased);
    assert!(is_inapplicable(&expired.lease_id));
    assert!(is_inapplicable(&expired.owner_epoch));
    assert!(is_inapplicable_time(&expired.leased_at));
    assert_eq!(expired.entity_revision, claimed.entity_revision + 1);
    assert_eq!(
        expired.retry_count,
        claimed.retry_count + 1,
        "an expired generation increments retries exactly once"
    );
    assert_eq!(expired.last_failure_reason, text("deadline_missed"));

    // A second expiry against the cleared record cannot increment again.
    let error = attempt(
        &mut fixture,
        "expire",
        &expired,
        32_000.0,
        32_000.0,
        json!({"failure_reason": "deadline_missed"}),
    )
    .expect_err("a cleared record has no generation to expire");
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(expired.retry_count, 1);
}

#[test]
fn rm_c50_restart_fences_old_epoch_without_comparing_boot_offsets() {
    let mut fixture = Fixture::new("run-c50-restart", "task-c50-restart");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");

    // The old boot cannot be ordered against a new boot: a validation asks for
    // the restarted authority epoch instead of inferring expiry or downtime.
    let error = validate_lease(
        &claimed,
        &tp(BOOT2, 500.0),
        claimed.entity_revision,
        claimed.input_revision,
        &text_of(&claimed.owner_epoch),
        &claimed.session_epoch,
    )
    .expect_err("an old-boot lease cannot be validated on the new boot");
    assert_eq!(error.code, "PREREQUISITE_UNAVAILABLE");

    // Claiming over the old hold is refused until the old epoch is fenced.
    let error = attempt_boot(
        &mut fixture,
        "claim",
        &claimed,
        BOOT2,
        500.0,
        500.0,
        fence_of(&claimed),
        json!({
            "authority_epoch": "authority-epoch-2",
            "lease_owner": "worker-c50",
            "session_epoch": "session-c50",
        }),
    )
    .expect_err("a restarted epoch cannot claim over a held lease");
    assert_eq!(error.code, "PREREQUISITE_UNAVAILABLE");

    // Even keeping the old epoch, the new boot cannot establish old expiry.
    let error = attempt_boot(
        &mut fixture,
        "claim",
        &claimed,
        BOOT2,
        500.0,
        500.0,
        fence_of(&claimed),
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    )
    .expect_err("cross-boot lease expiry is never inferred");
    assert_eq!(error.code, "PREREQUISITE_UNAVAILABLE");

    // The restarted authority registers its own clock and fences the old epoch.
    let new_authority = principal("lease-authority-2");
    append_event(
        &new_authority,
        &fixture.manifest,
        clock_submission(1, &clock_descriptor(BOOT2)),
    )
    .expect("new boot registers its clock");
    let producer_sequence = 2;
    let recovered = attempt_with(
        &mut fixture,
        &new_authority,
        "recover",
        &claimed,
        fence_of(&claimed),
        &tp(BOOT2, 500.0),
        &tp(BOOT2, 500.0),
        producer_sequence,
        json!({"authority_epoch": "authority-epoch-2", "failure_reason": "confirmed_authority_loss"}),
    )
    .expect("recovery fences the restarted epoch");

    assert_eq!(recovered.lease_state, LeaseState::Unleased);
    assert_eq!(recovered.authority_epoch, "authority-epoch-2");
    assert_eq!(recovered.issuer_id, "lease-authority-2");
    assert!(is_inapplicable(&recovered.lease_id));
    assert!(is_inapplicable_time(&recovered.leased_at));
    assert!(is_inapplicable_time(&recovered.lease_expires_at));
    assert_eq!(
        recovered.retry_count,
        claimed.retry_count + 1,
        "the recovered generation is counted once"
    );
    assert_eq!(recovered.last_failure_reason, text("confirmed_authority_loss"));
    assert_eq!(recovered.entity_revision, claimed.entity_revision + 1);
    assert_eq!(
        recovered.resource_state, claimed.resource_state,
        "reclamation revokes local authority only; it infers nothing about external work"
    );
    assert_eq!(
        recovered.generation_id, claimed.generation_id,
        "recovery preserves the same logical resource generation"
    );

    let witness = recovered.evidence_refs.last().expect("recovery evidence");
    let envelope = resolve_evidence(&new_authority, witness, &recovered.journal_prefix)
        .expect("recovery evidence resolves");
    assert_eq!(envelope.event_kind, "execution_claim");
    assert_eq!(envelope.producer_id, "lease-authority-2");
    assert_eq!(envelope.owner_domain, "execution");

    // The reclaimed record can be claimed by the new epoch on its own boot.
    let reclaimed = attempt_boot(
        &mut fixture,
        "claim",
        &recovered,
        BOOT2,
        600.0,
        600.0,
        fence_of(&recovered),
        json!({
            "authority_epoch": "authority-epoch-2",
            "lease_owner": "worker-after-restart",
            "session_epoch": "session-after-restart",
        }),
    )
    .expect("the new epoch can claim the reclaimed resource");
    assert_eq!(reclaimed.lease_state, LeaseState::Held);
    assert_eq!(reclaimed.authority_epoch, "authority-epoch-2");
    assert_eq!(point_of(&reclaimed.lease_expires_at).boot_id, BOOT2);
    assert_ne!(
        reclaimed.lease_id, claimed.lease_id,
        "a fencing token is never reused for a later claim"
    );
}

#[test]
fn rm_c50_double_recovery_increments_retry_at_most_once() {
    let mut fixture = Fixture::new("run-c50-double-recovery", "task-c50-double-recovery");
    let initial = fixture.initial.clone();
    let claimed = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("claim succeeds");
    let new_authority = principal("lease-authority-2");
    append_event(
        &new_authority,
        &fixture.manifest,
        clock_submission(1, &clock_descriptor(BOOT2)),
    )
    .expect("new boot registers its clock");
    let intent = fixture.intent(
        "recover",
        fence_of(&claimed),
        &tp(BOOT2, 500.0),
        2,
        json!({"authority_epoch": "authority-epoch-2", "failure_reason": "confirmed_authority_loss"}),
    );
    let recovered = transition_lease(&new_authority, &claimed, &intent, &tp(BOOT2, 500.0))
        .expect("first recovery succeeds");
    let head = fixture.head();

    // Re-delivering the identical command identity returns the retained
    // transition without a second journal event or a second retry increment.
    let replayed = transition_lease(&new_authority, &claimed, &intent, &tp(BOOT2, 500.0))
        .expect("idempotent recovery reply");
    assert_eq!(replayed, recovered, "the retained response is returned");
    assert_eq!(replayed.retry_count, recovered.retry_count);
    assert_eq!(replayed.retry_count, 1, "one failed generation, one increment");
    assert_eq!(fixture.head(), head, "no second recovery event is appended");

    // Recovering the already-reclaimed snapshot is refused; a reassignment
    // cannot double-count the same failed generation.
    let second = fixture.intent(
        "recover",
        fence_of(&recovered),
        &tp(BOOT2, 700.0),
        3,
        json!({"authority_epoch": "authority-epoch-3", "failure_reason": "confirmed_authority_loss"}),
    );
    let error = transition_lease(&new_authority, &recovered, &second, &tp(BOOT2, 700.0))
        .expect_err("a cleared record cannot be recovered again");
    assert_eq!(error.code, "STALE_CONTEXT");
    assert_eq!(recovered.retry_count, 1);
    assert_eq!(fixture.head(), head);
}

#[test]
fn rm_c50_failed_generations_are_counted_once_and_gate_claims() {
    let mut fixture =
        Fixture::with_policy("run-c50-budget", "task-c50-budget", "budget", TTL_MS, 1);
    let initial = fixture.initial.clone();

    let first = claim(&mut fixture, &initial, 1_000.0, 1_000.0).expect("first claim succeeds");
    let first_deadline = point_of(&first.lease_expires_at);
    let expired_once = attempt(
        &mut fixture,
        "expire",
        &first,
        first_deadline.monotonic_offset_ms,
        first_deadline.monotonic_offset_ms,
        json!({"failure_reason": "deadline_missed"}),
    )
    .expect("first expiry succeeds");
    assert_eq!(expired_once.retry_count, 1);

    // The retry increment is not reapplied when the expired record is claimed.
    let second = claim(
        &mut fixture,
        &expired_once,
        first_deadline.monotonic_offset_ms,
        first_deadline.monotonic_offset_ms,
    )
    .expect("a retry within the policy budget claims");
    assert_eq!(second.retry_count, 1);
    assert_ne!(second.lease_id, first.lease_id);
    assert!(
        point_of(&second.leased_at).monotonic_offset_ms
            >= point_of(&first.lease_expires_at).monotonic_offset_ms,
        "the replacement hold does not overlap the expired generation"
    );

    let second_deadline = point_of(&second.lease_expires_at);
    let expired_twice = attempt(
        &mut fixture,
        "expire",
        &second,
        second_deadline.monotonic_offset_ms,
        second_deadline.monotonic_offset_ms,
        json!({"failure_reason": "deadline_missed"}),
    )
    .expect("second expiry succeeds");
    assert_eq!(expired_twice.retry_count, 2, "each failure is counted once");

    let head = fixture.head();
    let error = claim(
        &mut fixture,
        &expired_twice,
        second_deadline.monotonic_offset_ms,
        second_deadline.monotonic_offset_ms,
    )
    .expect_err("the retry budget is exhausted");
    assert_eq!(error.code, "BUDGET_EXCEEDED");
    assert_eq!(
        fixture.head(),
        head,
        "an exhausted claim writes no evidence and counts nothing further"
    );
}

// ---------------------------------------------------------------------------
// RM-C50: atomicity and idempotency of the evidence commit
// ---------------------------------------------------------------------------

#[test]
fn rm_c50_changed_content_under_command_identity_is_rejected() {
    let mut fixture = Fixture::new("run-c50-idempotent", "task-c50-idempotent");
    let initial = fixture.initial.clone();
    let producer_sequence = fixture.take_sequence();
    let issued = tp(BOOT1, 1_000.0);
    let intent = fixture.intent(
        "claim",
        fence_of(&initial),
        &issued,
        producer_sequence,
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    );
    let first = transition_lease(&fixture.writer.clone(), &initial, &intent, &tp(BOOT1, 1_000.0))
        .expect("claim succeeds");

    // Identical retry at a later `now`: the immutable request determines the
    // snapshot, so the retained result is returned unchanged.
    let replayed = transition_lease(&fixture.writer.clone(), &initial, &intent, &tp(BOOT1, 9_000.0))
        .expect("identical retry returns the retained transition");
    assert_eq!(replayed, first);

    // Changed content under the same producer/sequence is an integrity
    // incident, not last-write-wins.
    let changed = fixture.intent(
        "claim",
        fence_of(&initial),
        &issued,
        producer_sequence,
        json!({"lease_owner": "worker-other", "session_epoch": "session-c50"}),
    );
    let head = fixture.head();
    let error = transition_lease(&fixture.writer.clone(), &initial, &changed, &tp(BOOT1, 1_000.0))
        .expect_err("changed content under one command identity is rejected");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");
    assert_eq!(fixture.head(), head, "the conflicting delivery is not journaled");
}

#[test]
fn rm_c50_evidence_commit_failure_leaves_no_partial_transition() {
    let fixture = Fixture::new("run-c50-atomic", "task-c50-atomic");
    let initial = fixture.initial.clone();
    let mut intent = fixture.intent_json(
        "claim",
        fence_of(&initial),
        &tp(BOOT1, 1_000.0),
        3,
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    );
    // Point the replay receipt at bytes that were never installed.
    intent["response"] = json!({
        "digest": format!("sha256:{}", "0".repeat(64)),
        "size_bytes": 7,
        "media_type": "application/json",
        "owner_domain": "execution",
        "access": "public",
    });
    let bytes = serde_json::to_vec(&intent).expect("intent serializes");
    let broken = install_bytes(&fixture.writer.clone(), &bytes, "application/json", "execution");
    let head = fixture.head();
    let error = transition_lease(&fixture.writer.clone(), &initial, &broken, &tp(BOOT1, 1_000.0))
        .expect_err("an uninstalled response artifact fails the atomic commit");
    assert_eq!(error.code, "NOT_FOUND");
    assert_eq!(fixture.head(), head, "no partial journal event is visible");
    assert_eq!(initial.evidence_refs.len(), 1);

    // The corrected command under the same identity then commits exactly one
    // event; the failed attempt left no durable trace to deduplicate against.
    let repaired = fixture.intent(
        "claim",
        fence_of(&initial),
        &tp(BOOT1, 1_000.0),
        3,
        json!({"lease_owner": "worker-c50", "session_epoch": "session-c50"}),
    );
    let claimed = transition_lease(&fixture.writer.clone(), &initial, &repaired, &tp(BOOT1, 1_000.0))
        .expect("the corrected command commits");
    assert_eq!(claimed.evidence_refs.len(), initial.evidence_refs.len() + 1);
    let head_after = fixture.head();
    assert_eq!(head_after.last_sequence, claimed.journal_prefix.last_sequence);
    resolve_evidence(
        &fixture.writer,
        claimed.evidence_refs.last().expect("claim evidence"),
        &claimed.journal_prefix,
    )
    .expect("the committed evidence resolves");
}
