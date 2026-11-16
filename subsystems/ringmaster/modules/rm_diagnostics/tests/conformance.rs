//! Conformance tests for RM-C52, RM-C55, and RM-C56.
//!
//! - RM-C52: an invalid isolation write control establishes neither
//!   isolation nor non-isolation. Isolation assessments must remain
//!   indeterminate/not_exercised and no isolation finding may conclude.
//! - RM-C55: diagnostic replay with missing bytes yields unavailable, never
//!   matched.
//! - RM-C56: offline replay never invokes a browser, subject, model, or
//!   external write; receipt effect flags are always false.
//!
//! Every test name carries its assertion token so the verification filter
//! `cargo test -p rm_diagnostics -- rm_c52 rm_c55 rm_c56` selects the suite.

use rm_authority::{
    AttemptKind, AuthenticatedPrincipal, EvaluationPartition, Manifest, TargetClass,
};
use rm_diagnostics::*;
use rm_evidence::{
    append_event, event_registration, install_artifact, journal_head, journal_id_for,
    AccessClass, ArtifactReference, EvidencePayload, EvidenceRef, EventSubmission,
    JournalEnvelope, JournalPrefix, PositiveInteger,
};
use rm_time::{
    Censoring, Estimate, MaybeNumber, MaybeString, MaybeTimePoint, Measurement,
    MeasurementOrigin, Method, Missing, Quantity, Scope, ScopeKind, TimePoint, UtcAnnotation,
};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Principals, journals, and pins
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

fn live_journal(
    writer: &AuthenticatedPrincipal,
    manifest: &Manifest,
) -> (JournalPrefix, EvidenceRef, EvidenceRef) {
    let admitted: JournalEnvelope = append_event(writer, manifest, admission(manifest))
        .expect("manifest admission appends");
    assert_eq!(admitted.journal_sequence.get(), 1);
    let support = append_event(writer, manifest, support_event(2)).expect("support appends");
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

fn version_pin(id: &str, version: &str) -> VersionPin {
    let digest = artifact_digest(format!("{id}/{version}").as_bytes());
    VersionPin {
        id: id.to_string(),
        version: version.to_string(),
        artifact_digest: digest,
    }
}

fn scope(id: &str) -> Scope {
    Scope {
        kind: ScopeKind::Run,
        id: id.to_string(),
    }
}

fn timepoint(offset: f64) -> TimePoint {
    TimePoint {
        clock_id: "clock-engine".to_string(),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::Missing(Missing::new("not_observed")),
    }
}

fn valid_measurement(id: &str) -> Measurement {
    Measurement {
        measurement_id: id.to_string(),
        name: "native_elapsed".to_string(),
        scope: scope("run-scope"),
        quantity: Quantity::Duration,
        unit: "ms".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        clock_id: "clock-engine".to_string(),
        boot_id: "boot-1".to_string(),
        method: Method::EndpointDifference,
        start: MaybeTimePoint::Present(timepoint(100.0)),
        end: MaybeTimePoint::Present(timepoint(150.0)),
        estimate: Estimate::Exact { value: 50.0 },
        resolution: MaybeNumber::Missing(Missing::new("not_applicable")),
        censoring: Censoring::None,
        comparability_group: MaybeString::Missing(Missing::new("not_applicable")),
    }
}

// ---------------------------------------------------------------------------
// Diagnostic fixtures
// ---------------------------------------------------------------------------

fn isolation_check(state: ValidityState, support: &EvidenceRef) -> ValidityCheck {
    ValidityCheck {
        check_id: "browser_isolation_write_control".to_string(),
        scope: scope("isolation-scope"),
        state,
        evidence_refs: vec![support.clone()],
        rationale: "write-control check for cross-context isolation".to_string(),
    }
}

fn isolation_assessment(
    result: AssessmentResult,
    support: &EvidenceRef,
) -> RequirementAssessment {
    let opportunity_state = match result {
        AssessmentResult::Satisfied
        | AssessmentResult::Violated
        | AssessmentResult::NativeAbsence => OpportunityState::Exposed,
        AssessmentResult::Indeterminate => OpportunityState::Blocked,
        AssessmentResult::NotExercised => OpportunityState::Unexposed,
    };
    // Native absence needs a capability ref; satisfied/violated need none.
    let capability_refs = if result == AssessmentResult::NativeAbsence {
        vec![CapabilityReference {
            descriptor_digest: artifact_digest(b"descriptor-isolation"),
            capability_id: "browser_isolation".to_string(),
            evidence_ref: support.clone(),
        }]
    } else {
        Vec::new()
    };
    // Unexposed opportunity requires not_exercised; blocked requires
    // not_exercised/indeterminate; exposed allows any definitive result.
    // For the trap test the exposed+satsified combination is the forbidden
    // conclusion under an invalid control.
    RequirementAssessment {
        requirement_id: "browser_isolation".to_string(),
        facet: "isolation".to_string(),
        contract_version: "evidence-kernel/0.1.0".to_string(),
        scope: scope("isolation-scope"),
        capability_refs,
        opportunity: Opportunity {
            state: opportunity_state,
            evidence_refs: vec![support.clone()],
            rationale: "feature was configured and rendered".to_string(),
        },
        result,
        evidence_refs: vec![support.clone()],
        contrary_evidence_refs: Vec::new(),
        finding_refs: Vec::new(),
        rationale: "assessment rationale".to_string(),
    }
}

fn complete_producer(support: &EvidenceRef) -> ProducerCompleteness {
    ProducerCompleteness {
        producer_id: "producer-1".to_string(),
        state: CompletenessState::Complete,
        observed_ranges: vec![SequenceRange { first: 1, last: 2 }],
        missing_ranges: Vec::new(),
        final_sequence: MaybeRevision::Revision(2),
        evidence_refs: vec![support.clone()],
    }
}

#[allow(clippy::too_many_arguments)]
fn valid_diagnostic(
    diagnostic_id: &str,
    run_id: &str,
    manifest_hash: &rm_wire::Digest,
    prefix: &JournalPrefix,
    analysis_ref: &EvidenceRef,
    support: &EvidenceRef,
    check_state: ValidityState,
    assessment_result: AssessmentResult,
) -> DiagnosticDocument {
    DiagnosticDocument {
        record_type: "diagnostic".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        diagnostic_id: diagnostic_id.to_string(),
        analysis_revision: 1,
        run_id: run_id.to_string(),
        manifest_hash: manifest_hash.clone(),
        input_prefix: prefix.clone(),
        analysis_request_ref: analysis_ref.clone(),
        classifier: version_pin("classifier", "1.0.0"),
        requirement_registry: version_pin("requirements", "1.0.0"),
        fix_registry: MaybeVersionPin::Missing(Missing::new("not_enabled")),
        attempt: MaybeAttempt::Present(DiagnosticAttempt {
            attempt_id: format!("attempt-{diagnostic_id}"),
            kind: AttemptKind::Practice,
            target_class: TargetClass::Fixture,
            target_id: "fixture-1".to_string(),
            evaluation_partition: EvaluationPartition::HeldIn,
        }),
        execution: ExecutionDescriptor {
            mode: DiagnosticExecutionMode::Service,
            subject: MaybeString::Missing(Missing::new("not_applicable")),
            connector_version: MaybeString::Missing(Missing::new("not_applicable")),
            binding_version: MaybeString::Missing(Missing::new("not_applicable")),
            assistance_description: "service analysis without a judged subject".to_string(),
        },
        delivered_task_hash: rm_evidence::MaybeDigest::Missing(Missing::new("not_applicable")),
        native_request_hash: rm_evidence::MaybeDigest::Missing(Missing::new("not_applicable")),
        validity: DiagnosticValidity {
            scoped_checks: vec![isolation_check(check_state, support)],
            producer_completeness: vec![complete_producer(support)],
            infrastructure_incidents: Vec::new(),
            limitations: Vec::new(),
        },
        capability_descriptors: Vec::new(),
        requirement_assessments: vec![isolation_assessment(assessment_result, support)],
        observed_actions: Vec::new(),
        feature_exposures: vec![FeatureExposure {
            instance_id: "feat-1".to_string(),
            configured: true,
            rendered_or_armed: true,
            exposed: true,
            activated: false,
            recovery_observed: MaybeBoolean::Missing(Missing::new("not_observed")),
            evidence_refs: vec![support.clone()],
        }],
        steps: vec![StepDiagnostic {
            step_id: "step-1".to_string(),
            contract_id: "contract-1".to_string(),
            status: StepStatus::Passed,
            attempts: vec![StepAttempt {
                ordinal: 1,
                disposition: AttemptDisposition::Accepted,
                evidence_refs: vec![support.clone()],
                postconditions: Vec::new(),
                measurement_refs: Vec::new(),
            }],
            authoritative_postconditions: Vec::new(),
            measurement_refs: Vec::new(),
            finding_refs: Vec::new(),
        }],
        measurements: vec![MeasurementEvidence {
            measurement: valid_measurement(&format!("m-{diagnostic_id}")),
            evidence_refs: vec![support.clone()],
        }],
        claims: Vec::new(),
        findings: Vec::new(),
        observation: ObservationSummary {
            opened_ref: support.clone(),
            closed_ref: MaybeEvidenceRef::Missing(Missing::new("not_applicable")),
            closure_reason: MaybeString::Missing(Missing::new("not_applicable")),
            lifecycle_refs: Vec::new(),
            containment_refs: Vec::new(),
            late_evidence_refs: Vec::new(),
        },
        application: ApplicationSummary {
            goal: ApplicationGoal::Unknown,
            as_of_sequence: prefix.last_sequence.get(),
            postconditions: Vec::new(),
            commitment_refs: Vec::new(),
            confirmation_refs: Vec::new(),
        },
        behavioral_profile: AnalysisSection {
            data: AnalysisData::Missing(Missing::new("not_enabled")),
            evidence_refs: Vec::new(),
        },
        fingerprint_profile: AnalysisSection {
            data: AnalysisData::Missing(Missing::new("not_enabled")),
            evidence_refs: Vec::new(),
        },
        artifacts: Vec::new(),
    }
}

fn isolation_finding(support: &EvidenceRef) -> Finding {
    Finding {
        finding_id: "finding-isolation-1".to_string(),
        kind: FindingKind::RequirementViolation,
        requirement_refs: vec!["browser_isolation".to_string()],
        symptom: "cross-context browser isolation failure observed".to_string(),
        scope: scope("isolation-scope"),
        causal_role: CausalRole::Primary,
        trigger_feature_refs: Vec::new(),
        defect_locus: DefectLocus::Subject,
        attribution: Attribution::Supported,
        evidence_refs: vec![support.clone()],
        contrary_evidence_refs: Vec::new(),
        limitations: Vec::new(),
        suggested_fix: MaybeFix::Missing(Missing::new("not_observed")),
    }
}

fn install_diagnostic_bytes(
    writer: &AuthenticatedPrincipal,
    diagnostic: &DiagnosticDocument,
) -> ArtifactReference {
    let bytes = diagnostic.artifact_bytes().expect("diagnostic serializes");
    let reference = ArtifactReference {
        digest: artifact_digest(&bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "connector".to_string(),
        access: AccessClass::Public,
    };
    install_artifact(writer, &reference, &bytes).expect("diagnostic installs")
}

fn request_for(diagnostic: &DiagnosticDocument) -> AnalysisRequest {
    AnalysisRequest {
        diagnostic_id: diagnostic.diagnostic_id.clone(),
        analysis_revision: diagnostic.analysis_revision,
        classifier: diagnostic.classifier.clone(),
        requirement_registry: diagnostic.requirement_registry.clone(),
        fix_registry: diagnostic.fix_registry.clone(),
    }
}

// ---------------------------------------------------------------------------
// RM-C52: invalid isolation write control
// ---------------------------------------------------------------------------

#[test]
fn rm_c52_invalid_isolation_write_control_forbids_conclusions() {
    let writer = principal("rm-c52-writer");
    let manifest = admitted_manifest("rm-diag-c52");
    let (prefix, _first, support) = live_journal(&writer, &manifest);
    let manifest_hash = rm_wire::Digest::parse(&manifest.manifest_hash).expect("manifest digest");

    // Valid control with a definitive isolation conclusion verifies.
    let valid = valid_diagnostic(
        "diag-c52-valid",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Valid,
        AssessmentResult::Satisfied,
    );
    verify_diagnostic(&writer, &valid).expect("valid isolation conclusion verifies");

    // Invalid control with a satisfied conclusion is rejected: no
    // isolation/non-isolation conclusion is permitted.
    let bad_satisfied = valid_diagnostic(
        "diag-c52-bad",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Invalid,
        AssessmentResult::Satisfied,
    );
    let err = verify_diagnostic(&writer, &bad_satisfied).expect_err(
        "satisfied isolation conclusion under an invalid control must be rejected",
    );
    assert!(
        err.detail.to_lowercase().contains("isolat"),
        "rejection must name isolation, got: {}",
        err.detail
    );

    // Invalid control with a violated conclusion is likewise rejected.
    let bad_violated = valid_diagnostic(
        "diag-c52-bad-violated",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Invalid,
        AssessmentResult::Violated,
    );
    verify_diagnostic(&writer, &bad_violated).expect_err(
        "violated isolation conclusion under an invalid control must be rejected",
    );

    // Invalid control with indeterminate (blocked opportunity) verifies:
    // uncertainty is preserved honestly.
    let uncertain = valid_diagnostic(
        "diag-c52-uncertain",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Invalid,
        AssessmentResult::Indeterminate,
    );
    verify_diagnostic(&writer, &uncertain)
        .expect("indeterminate under an invalid control verifies");

    // Invalid control with an isolation finding is rejected even when the
    // assessment itself is indeterminate.
    let mut finding_trap = valid_diagnostic(
        "diag-c52-finding",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Invalid,
        AssessmentResult::Indeterminate,
    );
    finding_trap.findings = vec![isolation_finding(&support)];
    let err = verify_diagnostic(&writer, &finding_trap)
        .expect_err("isolation finding under an invalid control must be rejected");
    assert!(
        err.detail.to_lowercase().contains("isolat"),
        "finding rejection must name isolation, got: {}",
        err.detail
    );
}

// ---------------------------------------------------------------------------
// RM-C55: diagnostic replay with missing bytes
// ---------------------------------------------------------------------------

#[test]
fn rm_c55_diagnostic_replay_with_missing_bytes_is_unavailable() {
    let writer = principal("rm-c55-writer");
    let manifest = admitted_manifest("rm-diag-c55");
    let (prefix, _first, support) = live_journal(&writer, &manifest);
    let manifest_hash = rm_wire::Digest::parse(&manifest.manifest_hash).expect("manifest digest");

    let diagnostic = valid_diagnostic(
        "diag-c55",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Valid,
        AssessmentResult::Satisfied,
    );
    verify_diagnostic(&writer, &diagnostic).expect("fixture diagnostic verifies");
    let request = request_for(&diagnostic);

    // Missing bytes: reference a digest that was never installed.
    let missing_bytes = b"rm-diagnostics-c55-never-installed".to_vec();
    let missing = ArtifactReference {
        digest: artifact_digest(&missing_bytes),
        size_bytes: missing_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "connector".to_string(),
        access: AccessClass::Public,
    };
    let receipt = replay_diagnostic(&writer, &request, &prefix, &missing)
        .expect("missing-byte replay returns a receipt, not an error");
    assert_eq!(receipt.result, ReplayResult::Unavailable);
    assert_eq!(receipt.mode, ReplayMode::DiagnosticRederivation);
    assert_eq!(receipt.comparisons.len(), 1);
    assert_eq!(receipt.comparisons[0].output, ComparisonOutput::Diagnostic);
    assert_eq!(receipt.comparisons[0].result, ReplayResult::Unavailable);
    assert!(
        matches!(
            receipt.comparisons[0].actual,
            rm_evidence::MaybeDigest::Missing(_)
        ),
        "unavailable comparison must carry a Missing actual"
    );
    assert_ne!(receipt.result, ReplayResult::Matched);
    assert!(
        !receipt.limitations.is_empty(),
        "unavailable replay must record a limitation"
    );
    assert!(!receipt.invoked_browser);
    assert!(!receipt.invoked_subject);
    assert!(!receipt.performed_external_writes);

    // Present bytes with matching inputs re-derive to matched, proving the
    // unavailable above comes from missing bytes rather than a blanket
    // failure.
    let installed = install_diagnostic_bytes(&writer, &diagnostic);
    let matched = replay_diagnostic(&writer, &request, &prefix, &installed)
        .expect("present-byte replay succeeds");
    assert_eq!(matched.result, ReplayResult::Matched);
    assert_eq!(matched.comparisons[0].result, ReplayResult::Matched);
}

// ---------------------------------------------------------------------------
// RM-C56: offline replay effect trap
// ---------------------------------------------------------------------------

#[test]
fn rm_c56_offline_replay_invokes_no_browser_subject_or_write() {
    let writer = principal("rm-c56-writer");
    let manifest = admitted_manifest("rm-diag-c56");
    let (prefix, _first, support) = live_journal(&writer, &manifest);
    let manifest_hash = rm_wire::Digest::parse(&manifest.manifest_hash).expect("manifest digest");

    let diagnostic = valid_diagnostic(
        "diag-c56",
        &manifest.run_id,
        &manifest_hash,
        &prefix,
        &support,
        &support,
        ValidityState::Valid,
        AssessmentResult::Satisfied,
    );
    let request = request_for(&diagnostic);
    let installed = install_diagnostic_bytes(&writer, &diagnostic);

    let journal_id = journal_id_for(&manifest).expect("journal identity");
    let head_before = journal_head(&writer, &journal_id).expect("head before replay");

    let receipt = replay_diagnostic(&writer, &request, &prefix, &installed)
        .expect("offline replay succeeds");

    // No browser, subject, model, or external-write effect.
    assert!(!receipt.invoked_browser, "replay must not invoke a browser");
    assert!(!receipt.invoked_subject, "replay must not invoke a subject");
    assert!(
        !receipt.performed_external_writes,
        "replay must not perform external writes"
    );
    // Diagnostic rederivation carries only the diagnostic comparison with
    // an inapplicable reducer.
    assert_eq!(receipt.mode, ReplayMode::DiagnosticRederivation);
    assert_eq!(receipt.comparisons.len(), 1);
    assert_eq!(receipt.comparisons[0].output, ComparisonOutput::Diagnostic);
    match &receipt.reducer {
        MaybeVersionPin::Missing(missing) => assert_eq!(missing.reason, "not_applicable"),
        MaybeVersionPin::Present(_) => panic!("rederivation reducer must be inapplicable"),
    }
    // The receipt is wire-valid under the closed replay schema.
    let wire = serde_json::to_vec(&receipt.wire_json()).expect("receipt serializes");
    rm_wire::validate_record("replay_receipt/v1", &wire).expect("receipt wire-valid");

    // The journal is untouched: replay is a read-side re-derivation, and a
    // mismatched request still performs no effect.
    let head_after = journal_head(&writer, &journal_id).expect("head after replay");
    assert_eq!(head_before, head_after);

    let mut wrong = request.clone();
    wrong.diagnostic_id = "diag-c56-other".to_string();
    let mismatched = replay_diagnostic(&writer, &wrong, &prefix, &installed)
        .expect("mismatched replay returns a receipt");
    assert_eq!(mismatched.result, ReplayResult::Mismatched);
    assert!(!mismatched.invoked_browser);
    assert!(!mismatched.invoked_subject);
    assert!(!mismatched.performed_external_writes);
    let head_final = journal_head(&writer, &journal_id).expect("head after mismatch");
    assert_eq!(head_before, head_final);
}
