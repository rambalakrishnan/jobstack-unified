//! Conformance tests for RM-C30, RM-C31, RM-C32, and RM-C57.
//!
//! - RM-C30: late commitment after outcome_unknown is compatible
//!   uncertainty; the close snapshot stays immutable.
//! - RM-C31: late commitment after an entire-attempt no-commit claim is a
//!   retained contradiction.
//! - RM-C32: earlier-boundary no-commit versus later receipt needs temporal
//!   evidence; receipt ordering alone decides nothing.
//! - RM-C57: origin-receipt/subject-claim conflicts reconcile report-only;
//!   sources are preserved and Ringmaster never authors application/report.
//!
//! Every test name carries its assertion token so the verification filter
//! `cargo test -p rm_lifecycle -- rm_c30 rm_c31 rm_c32 rm_c57` selects the
//! suite. Journal-backed tests use real admitted journals; pure
//! reconciliation tests use shape-valid references.

use rm_authority::{
    AttemptCommission, AttemptKind, AuthenticatedPrincipal, EvaluationPartition, Manifest,
    TargetClass,
};
use rm_evidence::{
    append_event, event_registration, install_artifact, journal_head, journal_id_for,
    AccessClass, ArtifactReference, EvidencePayload, EvidenceRef, EventSubmission,
    JournalEnvelope, JournalPrefix, MaybeDigest, PositiveInteger,
};
use rm_lifecycle::*;
use rm_time::{
    Censoring, ClockBasis, ClockDescriptor, Estimate, MaybeNumber, MaybeString, MaybeTimePoint,
    Measurement, MeasurementOrigin, Method, Missing, Quantity, Scope, ScopeKind, TimePoint,
    UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Principals, journals, and commissions
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

fn admitted_manifest(run: &str) -> Manifest {
    let manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}")}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: ["manifest_admitted", "execution_claim"]
            .iter()
            .map(|kind| (*kind).to_string())
            .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    let hash = canonical_digest(&wire).expect("manifest hashes");
    Manifest {
        manifest_hash: hash.as_str().to_string(),
        ..manifest
    }
}

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive sequence")
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact =
        rm_evidence::manifest_artifact_reference(manifest).expect("manifest artifact reference");
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

fn support_event(producer_sequence: u64) -> EventSubmission {
    let registration =
        event_registration("execution_claim").expect("execution_claim is registered");
    EventSubmission {
        producer_sequence: Some(seq(producer_sequence)),
        event_kind: "execution_claim".to_string(),
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

/// Admits a journal and appends one support event; returns the live prefix
/// plus references to sequences 1 and 2.
fn live_journal(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
) -> (JournalPrefix, EvidenceRef, EvidenceRef) {
    let admitted: JournalEnvelope = append_event(writer, manifest, admission(manifest))
        .expect("manifest admission appends");
    assert_eq!(admitted.journal_sequence.get(), 1);
    let support = append_event(writer, manifest, support_event(2)).expect("support event appends");
    assert_eq!(support.journal_sequence.get(), 2);
    let journal_id = journal_id_for(manifest).expect("journal identity");
    let prefix = journal_head(writer, &journal_id).expect("journal head");
    let first = EvidenceRef {
        journal_id: journal_id.clone(),
        sequence: admitted.journal_sequence,
        event_id: admitted.event_id.clone(),
        event_hash: admitted.event_hash.clone(),
        pointer: String::new(),
    };
    let second = EvidenceRef {
        journal_id,
        sequence: support.journal_sequence,
        event_id: support.event_id.clone(),
        event_hash: support.event_hash.clone(),
        pointer: String::new(),
    };
    (prefix, first, second)
}

/// Shape-valid reference for pure reconciliation tests (never resolved).
fn dummy_ref(tag: &str) -> EvidenceRef {
    EvidenceRef {
        journal_id: format!("journal-{tag}"),
        sequence: seq(1),
        event_id: format!("event-{tag}"),
        event_hash: artifact_digest(tag.as_bytes()),
        pointer: String::new(),
    }
}

fn production_commission(manifest: &Manifest, tag: &str) -> AttemptCommission {
    AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        commission_id: format!("commission-{tag}"),
        run_id: manifest.run_id.clone(),
        journal_id: journal_id_for(manifest).expect("journal identity"),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: format!("attempt-{tag}"),
        kind: AttemptKind::Production,
        target_class: TargetClass::Employer,
        evaluation_partition: EvaluationPartition::HeldOut,
        target_id: "employer-1".to_string(),
        derived_from: Vec::new(),
        rehearsal_of: None,
        performance_of: None,
        task_semantic_hash: canonical_digest(br#"{"goal":"apply"}"#)
            .expect("semantic hash")
            .as_str()
            .to_string(),
        idempotency_key: format!("idem-{tag}"),
        imported_evidence: Vec::new(),
    }
}

fn attempt_of(commission: &AttemptCommission) -> AttemptContext {
    AttemptContext {
        attempt_id: commission.attempt_id.clone(),
        kind: commission.kind,
        target_class: commission.target_class,
        target_id: commission.target_id.clone(),
        evaluation_partition: commission.evaluation_partition,
    }
}

fn installed(
    writer: &AuthenticatedPrincipal,
    label: &str,
    owner: &str,
) -> ArtifactReference {
    let bytes = label.as_bytes().to_vec();
    let reference = ArtifactReference {
        digest: artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: owner.to_string(),
        access: AccessClass::Public,
    };
    install_artifact(writer, &reference, &bytes).expect("artifact installs")
}

// ---------------------------------------------------------------------------
// Value fixtures
// ---------------------------------------------------------------------------

fn timepoint(offset: f64) -> TimePoint {
    TimePoint {
        clock_id: "clock-t".to_string(),
        boot_id: "boot-t".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn present_time(offset: f64) -> MaybeTimePoint {
    MaybeTimePoint::Present(timepoint(offset))
}

fn verified_checks(evidence: Vec<EvidenceRef>) -> SourceChecks {
    SourceChecks {
        authentication: AuthStatus::Verified,
        correlation: CorrelationStatus::Matched,
        trace_correlation: TraceStatus::Matched,
        verification_policy: "policy-1".to_string(),
        matched_by: MaybeString::Text("trace".to_string()),
        evidence_refs: evidence,
    }
}

fn claim_with_assertion(
    claim_id: &str,
    assertion_id: &str,
    value: CommitmentValue,
    span: CommitmentSpan,
    native_report: ArtifactReference,
    evidence: EvidenceRef,
) -> ExecutionClaim {
    let boundary_ref = match span {
        CommitmentSpan::EntireAttempt => MaybeString::Missing(Missing::new("not_applicable")),
        CommitmentSpan::AtBoundary | CommitmentSpan::AfterBoundary => {
            MaybeString::Text("boundary-1".to_string())
        }
    };
    ExecutionClaim {
        claim_id: claim_id.to_string(),
        scope: ClaimScope::ApplicationPostcondition,
        state: MaybeNativeState::Present(NativeState::Completed),
        application_assertions: vec![CommitmentAssertion {
            assertion_id: assertion_id.to_string(),
            value,
            span,
            boundary_ref,
            evidence_refs: vec![evidence.clone()],
        }],
        native_run_id: MaybeString::Text("native-run-1".to_string()),
        native_message_id: MaybeString::Text("native-msg-1".to_string()),
        native_report,
        mapping: "normalization/1.0.0".to_string(),
        source_checks: verified_checks(vec![evidence.clone()]),
        made_at: present_time(10.0),
        received_at: timepoint(20.0),
        evidence_available_to_claimant: vec!["native-report".to_string()],
        evidence_refs: vec![evidence],
        limitations: Vec::new(),
    }
}

fn committed_fact(
    fact_id: &str,
    coverage: OriginCoverage,
    receipt: ArtifactReference,
    evidence: EvidenceRef,
) -> OriginFact {
    OriginFact {
        fact_id: fact_id.to_string(),
        origin_id: "origin-1".to_string(),
        candidate_id: "candidate-1".to_string(),
        job_id: "job-1".to_string(),
        state: OriginState::Committed,
        coverage,
        boundary_ref: "boundary-1".to_string(),
        origin_application_id: MaybeString::Text("origin-app-1".to_string()),
        origin_revision: MaybeString::Text("rev-7".to_string()),
        receipt,
        verification_kind: VerificationKind::VerifiedOriginReceipt,
        source_checks: verified_checks(vec![evidence.clone()]),
        authority_seal_ref: "seal-1".to_string(),
        occurred_at: present_time(30.0),
        received_at: timepoint(40.0),
        evidence_refs: vec![evidence],
    }
}

fn absent_fact(
    fact_id: &str,
    receipt: ArtifactReference,
    evidence: EvidenceRef,
) -> OriginFact {
    OriginFact {
        fact_id: fact_id.to_string(),
        origin_id: "origin-1".to_string(),
        candidate_id: "candidate-1".to_string(),
        job_id: "job-1".to_string(),
        state: OriginState::NotCommitted,
        coverage: OriginCoverage::FinalForAttempt,
        boundary_ref: "boundary-final".to_string(),
        origin_application_id: MaybeString::Missing(Missing::new("not_observed")),
        origin_revision: MaybeString::Missing(Missing::new("not_observed")),
        receipt,
        verification_kind: VerificationKind::VerifiedOriginReceipt,
        source_checks: verified_checks(vec![evidence.clone()]),
        authority_seal_ref: "seal-1".to_string(),
        occurred_at: present_time(30.0),
        received_at: timepoint(40.0),
        evidence_refs: vec![evidence],
    }
}

fn zero_pin() -> DomainPin {
    DomainPin {
        revision: 0,
        record_digest: MaybeDigest::Missing(Missing::new("not_applicable")),
    }
}

fn zero_pins() -> ReportInputPins {
    ReportInputPins {
        dispatch: zero_pin(),
        observation: zero_pin(),
        execution: zero_pin(),
        application: zero_pin(),
    }
}

fn comparison(
    claim_id: &str,
    assertion_id: &str,
    fact_ids: Vec<&str>,
    result: ComparisonResult,
    temporal_relation: TemporalRelation,
) -> ClaimComparison {
    ClaimComparison {
        claim_id: claim_id.to_string(),
        assertion_id: assertion_id.to_string(),
        claim_ref: "claim-ref-1".to_string(),
        fact_ids: fact_ids.iter().map(|id| (*id).to_string()).collect(),
        fact_refs: vec!["fact-ref-1".to_string()],
        result,
        temporal_relation,
        rationale: "compared at actual scope and knowledge boundary".to_string(),
        limitations: Vec::new(),
    }
}

fn unknown_temporal() -> TemporalRelation {
    TemporalRelation {
        relation: TemporalRelationKind::Unknown,
        basis: TemporalBasis::Unknown,
        evidence_refs: Vec::new(),
    }
}

fn report_with(
    state: ReportState,
    coverage: ReportCoverage,
    comparisons: Vec<ClaimComparison>,
) -> ReportValue {
    ReportValue {
        state,
        coverage,
        inputs: zero_pins(),
        evaluator: "reconciler-1".to_string(),
        comparisons,
        issues: Vec::new(),
        limitations: Vec::new(),
        diagnostic: "diagnostic-1".to_string(),
    }
}

// ---------------------------------------------------------------------------
// RM-C30: outcome_unknown stays compatible with a later commitment
// ---------------------------------------------------------------------------

#[test]
fn rm_c30_outcome_unknown_compatible_with_late_commitment() {
    let writer = principal("rm-c30-writer");
    let native_report = installed(&writer, "rm-c30-native-report", "execution");
    let receipt = installed(&writer, "rm-c30-origin-receipt", "application");
    let evidence = dummy_ref("c30");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::OutcomeUnknown,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            evidence,
        )],
    };
    let report = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Consistent,
            unknown_temporal(),
        )],
    );
    validate_reconciliation(&execution, &application, &report)
        .expect("outcome_unknown with a later commitment reconciles");
}

#[test]
fn rm_c30_outcome_unknown_contradiction_rejected() {
    let writer = principal("rm-c30-neg-writer");
    let native_report = installed(&writer, "rm-c30-neg-native-report", "execution");
    let receipt = installed(&writer, "rm-c30-neg-origin-receipt", "application");
    let evidence = dummy_ref("c30-neg");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::OutcomeUnknown,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            evidence,
        )],
    };
    let report = report_with(
        ReportState::Contradicted,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    let error = validate_reconciliation(&execution, &application, &report)
        .expect_err("outcome_unknown must never contradict a later commitment");
    assert!(
        error.detail.contains("outcome_unknown"),
        "unexpected detail: {}",
        error.detail
    );
}

fn closed_observation(
    late_evidence: Vec<EvidenceRef>,
    support: &EvidenceRef,
) -> ObservationValue {
    let clock = ClockDescriptor {
        clock_id: "clock-obs".to_string(),
        boot_id: "boot-obs".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        source_id: "source-obs".to_string(),
        basis: ClockBasis::MonotonicOffset,
        unit: "ms".to_string(),
    };
    let point = |offset: f64| TimePoint {
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    };
    let measurement = Measurement {
        measurement_id: "measurement-close".to_string(),
        name: "elapsed".to_string(),
        scope: Scope {
            kind: ScopeKind::ConnectorCall,
            id: "call-1".to_string(),
        },
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: clock.clock_id.clone(),
        boot_id: clock.boot_id.clone(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(point(0.0)),
        end: MaybeTimePoint::Present(point(50.0)),
        estimate: Estimate::Exact { value: 50.0 },
        resolution: MaybeNumber::Missing(Missing::new("not_observed")),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_observed")),
    };
    ObservationValue {
        state: ObservationState::Closed,
        window_id: "window-1".to_string(),
        opened_at: present_time(5.0),
        active_deadline: present_time(100.0),
        drain_started_at: present_time(90.0),
        drain_deadline: present_time(110.0),
        closed_at: present_time(105.0),
        close_reason: MaybeCloseReason::Present(CloseReason::NormalCompletion),
        at_close: MaybeCloseSnapshot::Present(CloseSnapshot {
            closure_id: "closure-1".to_string(),
            boundary_ref: "boundary-close".to_string(),
            known_versions: VersionVector {
                dispatch: 1,
                observation: 1,
                execution: 1,
                application: 0,
                report: 0,
            },
            execution_knowledge: ExecKnowledge::Terminal,
            execution_evidence_refs: vec![support.clone()],
            application_knowledge: AppKnowledge::Unknown,
            application_evidence_refs: Vec::new(),
            limitations: vec!["application outcome not observed at closure".to_string()],
        }),
        control_observations: Vec::new(),
        late_evidence_refs: late_evidence,
        measurements: vec![measurement],
        clocks: vec![clock],
    }
}

fn observation_revision(
    commission: &AttemptCommission,
    attempt: &AttemptContext,
    prefix: &JournalPrefix,
    support: &EvidenceRef,
    revision: u64,
    late_evidence: Vec<EvidenceRef>,
) -> AxisRevision {
    AxisRevision {
        record_type: "attempt_axis_revision".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission_digest: commission_digest(commission).expect("commission digests"),
        axis: Axis::Observation,
        owner_domain: "observation".to_string(),
        writer_id: "observation-writer-1".to_string(),
        revision,
        previous_revision: revision - 1,
        evidence_prefix: prefix.clone(),
        evidence_refs: vec![support.clone()],
        value: AxisValue::Observation(closed_observation(late_evidence, support)),
    }
}

#[test]
fn rm_c30_closed_snapshot_immutable_across_late_evidence() {
    let writer = principal("rm-c30-close-writer");
    let manifest = admitted_manifest("run-c30-close");
    let (prefix, first, second) = live_journal(&writer, &manifest);
    let commission = production_commission(&manifest, "c30-close");
    let attempt = attempt_of(&commission);

    let first_revision = observation_revision(&commission, &attempt, &prefix, &first, 1, Vec::new());
    let first_published =
        publish_axis(&writer, &commission, &first_revision).expect("closed revision publishes");
    assert_eq!(first_published.revision, 1);
    assert!(matches!(
        first_published.registration_ref,
        PublicationRegistration::Pending(_)
    ));

    // Late evidence appends a new revision; the original closure fields stay.
    let second_revision =
        observation_revision(&commission, &attempt, &prefix, &first, 2, vec![second.clone()]);
    let second_published =
        publish_axis(&writer, &commission, &second_revision).expect("late-evidence revision publishes");
    assert_eq!(second_published.revision, 2);
    assert_ne!(
        first_published.content.digest, second_published.content.digest,
        "distinct revisions carry distinct content digests"
    );

    // Every prior publication survives byte-identical.
    let retained = rm_evidence::load_artifact(&writer, &first_published.content)
        .expect("prior publication bytes remain");
    let expected = revision_wire_bytes(&first_revision).expect("revision serializes");
    assert_eq!(retained, expected);

    // A snapshot over the newer revision still validates.
    let unpublished = |reason: &str| AxisSlot {
        revision: 0,
        value: SlotValue::Unpublished(Missing::new(reason)),
    };
    let snapshot = AttemptSnapshot {
        record_type: "application_attempt_snapshot".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission: commission.clone(),
        commission_digest: commission_digest(&commission).expect("commission digests"),
        input_prefix: prefix.clone(),
        dispatch: unpublished("not_applicable"),
        observation: AxisSlot {
            revision: 2,
            value: SlotValue::Published(second_revision),
        },
        execution: unpublished("not_observed"),
        application: unpublished("not_observed"),
        report: unpublished("not_observed"),
        seal_point: SealPoint {
            seal_id: "seal-1".to_string(),
            name: SealName::ObservationClosed,
            versions: VersionVector {
                dispatch: 0,
                observation: 2,
                execution: 0,
                application: 0,
                report: 0,
            },
            evidence_refs: vec![first],
        },
    };
    validate_snapshot(&writer, &snapshot).expect("snapshot over late evidence validates");
}

// ---------------------------------------------------------------------------
// RM-C31: entire-attempt denial contradicted by a verified commitment
// ---------------------------------------------------------------------------

#[test]
fn rm_c31_entire_attempt_denial_contradicted_by_verified_commitment() {
    let writer = principal("rm-c31-writer");
    let native_report = installed(&writer, "rm-c31-native-report", "execution");
    let receipt = installed(&writer, "rm-c31-origin-receipt", "application");
    let evidence = dummy_ref("c31");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::NotCommitted,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            evidence,
        )],
    };
    let report = report_with(
        ReportState::Contradicted,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    validate_reconciliation(&execution, &application, &report)
        .expect("verified commitment contradicts entire-attempt denial");

    // Symmetric case: entire-attempt commitment against verified final absence.
    let writer = principal("rm-c31-sym-writer");
    let native_report = installed(&writer, "rm-c31-sym-native-report", "execution");
    let receipt = installed(&writer, "rm-c31-sym-origin-receipt", "application");
    let evidence = dummy_ref("c31-sym");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-9",
            "assert-9",
            CommitmentValue::Committed,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![absent_fact("fact-9", receipt, evidence)],
    };
    let report = report_with(
        ReportState::Contradicted,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-9",
            "assert-9",
            vec!["fact-9"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    validate_reconciliation(&execution, &application, &report)
        .expect("verified final absence contradicts entire-attempt commitment");
}

#[test]
fn rm_c31_reconciled_report_over_denial_and_commitment_rejected() {
    let writer = principal("rm-c31-neg-writer");
    let native_report = installed(&writer, "rm-c31-neg-native-report", "execution");
    let receipt = installed(&writer, "rm-c31-neg-origin-receipt", "application");
    let evidence = dummy_ref("c31-neg");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::NotCommitted,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            evidence,
        )],
    };
    // A consistent comparison over denial plus verified commitment is rejected.
    let reconciled = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Consistent,
            unknown_temporal(),
        )],
    );
    let error = validate_reconciliation(&execution, &application, &reconciled)
        .expect_err("denial plus verified commitment cannot reconcile");
    assert!(
        error.detail.contains("contradicted by a verified commitment"),
        "unexpected detail: {}",
        error.detail
    );

    // A proved contradiction with a reconciled state is rejected too.
    let mislabeled = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    let error = validate_reconciliation(&execution, &application, &mislabeled)
        .expect_err("contradiction dominance cannot be mislabeled");
    assert!(
        error.detail.contains("contradicted"),
        "unexpected detail: {}",
        error.detail
    );
}

// ---------------------------------------------------------------------------
// RM-C32: boundary claims need temporal evidence, not receipt order
// ---------------------------------------------------------------------------

fn boundary_inputs(
    tag: &str,
) -> (
    AuthenticatedPrincipal,
    ExecutionValue,
    ApplicationValue,
) {
    let writer = principal(&format!("rm-c32-{tag}-writer"));
    let native_report = installed(&writer, &format!("rm-c32-{tag}-native"), "execution");
    let receipt = installed(&writer, &format!("rm-c32-{tag}-receipt"), "application");
    let evidence = dummy_ref(&format!("c32-{tag}"));
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::NotCommitted,
            CommitmentSpan::AtBoundary,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::AtBoundary,
            receipt,
            evidence,
        )],
    };
    (writer, execution, application)
}

#[test]
fn rm_c32_receipt_order_cannot_decide_boundary_claim() {
    let (_writer, execution, application) = boundary_inputs("neg");
    let receipt_ordered = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Consistent,
            TemporalRelation {
                relation: TemporalRelationKind::After,
                basis: TemporalBasis::ReceiptOrder,
                evidence_refs: vec!["receipt-2-after-receipt-1".to_string()],
            },
        )],
    );
    let error = validate_reconciliation(&execution, &application, &receipt_ordered)
        .expect_err("receipt ordering alone decides nothing");
    assert!(
        error.detail.contains("receipt order"),
        "unexpected detail: {}",
        error.detail
    );

    let unevidenced = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Consistent,
            TemporalRelation {
                relation: TemporalRelationKind::After,
                basis: TemporalBasis::SameClock,
                evidence_refs: Vec::new(),
            },
        )],
    );
    validate_reconciliation(&execution, &application, &unevidenced)
        .expect_err("a known relation without evidence decides nothing");
}

#[test]
fn rm_c32_proven_temporal_order_decides_boundary_claim() {
    let (_writer, execution, application) = boundary_inputs("pos");
    let report = report_with(
        ReportState::Reconciled,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Consistent,
            TemporalRelation {
                relation: TemporalRelationKind::After,
                basis: TemporalBasis::OriginSequence,
                evidence_refs: vec!["origin-seq-44-after-boundary-1".to_string()],
            },
        )],
    );
    validate_reconciliation(&execution, &application, &report)
        .expect("origin-sequence temporal evidence decides the boundary comparison");
}

// ---------------------------------------------------------------------------
// RM-C57: conflicts reconcile report-only; sources are preserved
// ---------------------------------------------------------------------------

#[test]
fn rm_c57_conflict_reconciles_report_only_sources_preserved() {
    let writer = principal("rm-c57-writer");
    let native_report = installed(&writer, "rm-c57-native-report", "execution");
    let receipt = installed(&writer, "rm-c57-origin-receipt", "application");
    let evidence = dummy_ref("c57");
    let execution = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::NotCommitted,
            CommitmentSpan::EntireAttempt,
            native_report,
            evidence.clone(),
        )],
    };
    let application = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            evidence,
        )],
    };
    let mut report = report_with(
        ReportState::Contradicted,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    report.issues.push(ReconciliationIssue {
        kind: IssueKind::SubjectClaimConflict,
        detail: "subject denial conflicts with the verified origin receipt".to_string(),
        evidence_refs: vec!["claim-ref-1".to_string(), "fact-ref-1".to_string()],
    });

    let execution_before = execution.clone();
    let application_before = application.clone();
    validate_reconciliation(&execution, &application, &report)
        .expect("verified conflict reconciles as contradicted");
    assert_eq!(
        execution, execution_before,
        "reconciliation never rewrites execution claims"
    );
    assert_eq!(
        application, application_before,
        "reconciliation never rewrites origin facts"
    );
}

#[test]
fn rm_c57_publish_axis_rejects_application_and_report() {
    let writer = principal("rm-c57-axis-writer");
    let manifest = admitted_manifest("run-c57-axis");
    let (prefix, first, _second) = live_journal(&writer, &manifest);
    let commission = production_commission(&manifest, "c57-axis");
    let attempt = attempt_of(&commission);
    let digest = commission_digest(&commission).expect("commission digests");

    let native_report = installed(&writer, "rm-c57-axis-native", "execution");
    let receipt = installed(&writer, "rm-c57-axis-receipt", "application");
    let application_value = ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            first.clone(),
        )],
    };
    let application_revision = AxisRevision {
        record_type: "attempt_axis_revision".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission_digest: digest.clone(),
        axis: Axis::Application,
        owner_domain: "application".to_string(),
        writer_id: "application-writer-1".to_string(),
        revision: 1,
        previous_revision: 0,
        evidence_prefix: prefix.clone(),
        evidence_refs: vec![first.clone()],
        value: AxisValue::Application(application_value),
    };
    let error = publish_axis(&writer, &commission, &application_revision)
        .expect_err("Ringmaster never publishes application facts");
    assert_eq!(error.code, "FORBIDDEN");

    let execution_value = ExecutionValue {
        claims: vec![claim_with_assertion(
            "claim-1",
            "assert-1",
            CommitmentValue::NotCommitted,
            CommitmentSpan::EntireAttempt,
            native_report,
            first.clone(),
        )],
    };
    let report_value = report_with(
        ReportState::Contradicted,
        ReportCoverage::Complete,
        vec![comparison(
            "claim-1",
            "assert-1",
            vec!["fact-1"],
            ComparisonResult::Contradicted,
            unknown_temporal(),
        )],
    );
    validate_reconciliation(
        &execution_value,
        &coherent_application_value(),
        &report_value,
    )
    .expect("report fixture is coherent");
    let report_revision = AxisRevision {
        record_type: "attempt_axis_revision".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission_digest: digest,
        axis: Axis::Report,
        owner_domain: "report".to_string(),
        writer_id: "report-writer-1".to_string(),
        revision: 1,
        previous_revision: 0,
        evidence_prefix: prefix,
        evidence_refs: vec![first],
        value: AxisValue::Report(report_value),
    };
    let error = publish_axis(&writer, &commission, &report_revision)
        .expect_err("report is never published through the connector entry point");
    assert_eq!(error.code, "FORBIDDEN");
}

fn coherent_application_value() -> ApplicationValue {
    let writer = principal("rm-c57-axis-reader");
    let receipt = installed(&writer, "rm-c57-axis-receipt-2", "application");
    ApplicationValue {
        facts: vec![committed_fact(
            "fact-1",
            OriginCoverage::FinalForAttempt,
            receipt,
            dummy_ref("c57-axis-2"),
        )],
    }
}

#[test]
fn rm_c57_connector_axes_publish_through_single_axis_authority() {
    let writer = principal("rm-c57-connector-writer");
    let manifest = admitted_manifest("run-c57-connector");
    let (prefix, first, _second) = live_journal(&writer, &manifest);
    let commission = production_commission(&manifest, "c57-connector");
    let attempt = attempt_of(&commission);
    let digest = commission_digest(&commission).expect("commission digests");

    // Dispatch publishes through its own axis.
    let dispatch = AxisRevision {
        record_type: "attempt_axis_revision".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission_digest: digest.clone(),
        axis: Axis::Dispatch,
        owner_domain: "dispatch".to_string(),
        writer_id: "dispatch-writer-1".to_string(),
        revision: 1,
        previous_revision: 0,
        evidence_prefix: prefix.clone(),
        evidence_refs: vec![first.clone()],
        value: AxisValue::Dispatch(DispatchValue {
            state: DispatchState::Prepared,
            local_handle: MaybeString::Text("handle-1".to_string()),
            native_run_id: MaybeString::Missing(Missing::new("not_observed")),
            request_digest: MaybeDigest::Present(artifact_digest(b"request-1")),
            delivery_refs: Vec::new(),
            acceptance_refs: Vec::new(),
            recovery_authorization_refs: Vec::new(),
            reason: MaybeString::Missing(Missing::new("not_applicable")),
        }),
    };
    let published = publish_axis(&writer, &commission, &dispatch).expect("dispatch publishes");
    assert_eq!(published.axis, Axis::Dispatch);
    assert_eq!(published.owner_domain, "dispatch");
    let wire = revision_wire_bytes(&dispatch).expect("revision serializes");
    assert_eq!(published.content.digest, artifact_digest(&wire));
    assert!(matches!(
        published.registration_ref,
        PublicationRegistration::Pending(_)
    ));

    // Execution publishes through its own axis.
    let native_report = installed(&writer, "rm-c57-connector-native", "execution");
    let execution = AxisRevision {
        record_type: "attempt_axis_revision".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        attempt: attempt.clone(),
        commission_digest: digest.clone(),
        axis: Axis::Execution,
        owner_domain: "execution".to_string(),
        writer_id: "execution-writer-1".to_string(),
        revision: 1,
        previous_revision: 0,
        evidence_prefix: prefix.clone(),
        evidence_refs: vec![first.clone()],
        value: AxisValue::Execution(ExecutionValue {
            claims: vec![claim_with_assertion(
                "claim-1",
                "assert-1",
                CommitmentValue::OutcomeUnknown,
                CommitmentSpan::EntireAttempt,
                native_report,
                first.clone(),
            )],
        }),
    };
    publish_axis(&writer, &commission, &execution).expect("execution publishes");

    // A writer may publish only its axis.
    let crossed = AxisRevision {
        owner_domain: "execution".to_string(),
        ..dispatch.clone()
    };
    let error = publish_axis(&writer, &commission, &crossed)
        .expect_err("cross-axis publication is rejected");
    assert_eq!(error.code, "FORBIDDEN");

    // Revisions advance by exactly one.
    let skipped = AxisRevision {
        revision: 3,
        previous_revision: 1,
        ..dispatch.clone()
    };
    publish_axis(&writer, &commission, &skipped)
        .expect_err("skipped revisions are rejected");

    // The commission binding is exact.
    let rebound = AxisRevision {
        commission_digest: artifact_digest(b"another-commission"),
        ..dispatch.clone()
    };
    publish_axis(&writer, &commission, &rebound)
        .expect_err("a foreign commission binding is rejected");
}
