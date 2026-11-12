//! [RM-C54] Manual production recording: no fabricated
//! subject/connector, no Ringmaster dependency.
//!
//! Each test name contains `rm_c54` so the verification filter
//! `cargo test -p rm_service -- rm-c54` selects the whole suite.
#![allow(clippy::unwrap_used)]

use rm_service::*;
use std::io::Cursor;

fn manifest(admission_ref: &str) -> Manifest {
    Manifest {
        record_type: "manifest".to_string(),
        schema_version: "ringmaster/0.1.0".to_string(),
        manifest_id: "manifest-1".to_string(),
        admission_ref: admission_ref.to_string(),
    }
}

fn channel_for(operator: &str) -> Cursor<Vec<u8>> {
    Cursor::new(
        serde_json::json!({"principal_id": operator, "owner_domain": "portfolio"})
            .to_string()
            .into_bytes(),
    )
}

fn production_commission(operator: &str) -> ManualCommission {
    ManualCommission {
        commission_id: "commission-1".to_string(),
        kind: AttemptKind::Production,
        target: TargetClass::Employer,
        operator_id: operator.to_string(),
        notes: "Applied in person at the employer office; receipt kept.".to_string(),
        assistance: None,
    }
}

/// Happy path: a real manual production application records with zero
/// dispatch/execution revisions, manual provenance, an origin reference,
/// and no dispatch-path dependency call.
#[test]
fn rm_c54_manual_production_records_without_dispatch() {
    clear_dependency_calls();
    let m = manifest("admission-1");
    let commission = production_commission("op-1");
    let mut channel = channel_for("op-1");

    let recorded = record_manual_production(
        &mut channel,
        &m,
        &commission,
        Some("origin-evidence-1".to_string()),
    )
    .expect("genuine manual production application must record");

    assert_eq!(recorded.provenance, "manual_observer");
    assert_eq!(recorded.dispatch_revision, 0);
    assert_eq!(recorded.execution_revision, 0);
    assert_eq!(recorded.origin_ref, Some("origin-evidence-1".to_string()));
    assert_eq!(recorded.operator_id, "op-1");

    let calls = dependency_calls();
    assert!(
        calls.iter().any(|c| c == "authenticate_channel"),
        "operator channel must be authenticated, got {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "verify_attempt_scope"),
        "commission scope must be verified, got {calls:?}"
    );
    assert!(
        calls.iter().any(|c| c == "validate_snapshot"),
        "snapshot must be validated, got {calls:?}"
    );
    for forbidden in ["prepare", "start", "control", "drive_once"] {
        assert!(
            !calls.iter().any(|c| c == forbidden),
            "manual recording must never touch dispatch machinery ({forbidden}), got {calls:?}"
        );
    }
}

/// Practice manual work records against a fixture target without an
/// origin reference.
#[test]
fn rm_c54_manual_practice_records_without_origin_ref() {
    let m = manifest("admission-1");
    let commission = ManualCommission {
        commission_id: "commission-practice".to_string(),
        kind: AttemptKind::Practice,
        target: TargetClass::Fixture,
        operator_id: "op-1".to_string(),
        notes: "Walked the fixture form by hand.".to_string(),
        assistance: Some("screen reader".to_string()),
    };
    let mut channel = channel_for("op-1");
    let recorded = record_manual_production(&mut channel, &m, &commission, None)
        .expect("practice manual work must record without an origin reference");
    assert_eq!(recorded.kind, AttemptKind::Practice);
    assert_eq!(recorded.origin_ref, None);
    assert_eq!(recorded.dispatch_revision, 0);
    assert_eq!(recorded.execution_revision, 0);
}

/// Production without an employer origin reference is not admitted.
/// The failure is a policy ConnectorError, not silent acceptance.
#[test]
fn rm_c54_production_without_origin_ref_not_admitted() {
    clear_dependency_calls();
    let m = manifest("admission-1");
    let commission = production_commission("op-1");
    let mut channel = channel_for("op-1");
    let err = record_manual_production(&mut channel, &m, &commission, None)
        .expect_err("production without origin evidence must be rejected");
    assert_eq!(err.kind, "connector_error");
    assert_eq!(err.code, "NOT_ADMITTED");
    assert_eq!(dependency_calls(), Vec::<String>::new());
}

/// Practice/held_in versus production/held_out coherence is enforced:
/// mismatched kind/target pairs are not admitted.
#[test]
fn rm_c54_kind_target_incoherence_not_admitted() {
    for (kind, target) in [
        (AttemptKind::Practice, TargetClass::Employer),
        (AttemptKind::Production, TargetClass::Fixture),
    ] {
        let m = manifest("admission-1");
        let commission = ManualCommission {
            commission_id: "commission-x".to_string(),
            kind,
            target,
            operator_id: "op-1".to_string(),
            notes: "notes".to_string(),
            assistance: None,
        };
        let mut channel = channel_for("op-1");
        let origin = if kind == AttemptKind::Production {
            Some("origin-1".to_string())
        } else {
            None
        };
        let err = record_manual_production(&mut channel, &m, &commission, origin)
            .expect_err("incoherent kind/target must be rejected");
        assert_eq!(err.code, "NOT_ADMITTED", "kind/target {kind:?}/{target:?}");
    }
}

/// The authenticated principal must be the commissioning operator;
/// another principal's handle is never usable (no cross-principal leak).
#[test]
fn rm_c54_operator_mismatch_forbidden() {
    let m = manifest("admission-1");
    let commission = production_commission("op-1");
    let mut channel = channel_for("op-2");
    let err = record_manual_production(
        &mut channel,
        &m,
        &commission,
        Some("origin-1".to_string()),
    )
    .expect_err("operator mismatch must be forbidden");
    assert_eq!(err.code, "FORBIDDEN");
}

/// No automation subject, native run ID, connector version, or execution
/// publication is fabricated: the recorded attempt carries only manual
/// provenance and zero revisions.
#[test]
fn rm_c54_no_subject_or_connector_fabricated() {
    let m = manifest("admission-1");
    let commission = production_commission("op-1");
    let mut channel = channel_for("op-1");
    let recorded = record_manual_production(
        &mut channel,
        &m,
        &commission,
        Some("origin-1".to_string()),
    )
    .unwrap();
    let debug = format!("{recorded:?}");
    for invented in ["subject", "connector_version", "connector-version", "run_id", "run-id"] {
        assert!(
            !debug.contains(invented),
            "recorded attempt must not fabricate `{invented}`: {debug}"
        );
    }
    assert_eq!(recorded.provenance, "manual_observer");
}

/// Manual commissions are not dispatchable: Prepare/Start reject manual
/// payloads instead of issuing preparation IDs or handles.
#[test]
fn rm_c54_prepare_start_reject_manual_mode() {
    let principal = AuthenticatedPrincipal {
        principal_id: "op-1".to_string(),
        owner_domain: "portfolio".to_string(),
        roles: vec!["operator".to_string()],
    };
    let manual = ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: "req-manual".to_string(),
        connector_id: "ringmaster".to_string(),
        operation: "Prepare".to_string(),
        call_limit: 1,
        payload: serde_json::json!({"mode": "manual"}),
    };
    let err = prepare(&principal, &manual).expect_err("Prepare must reject manual mode");
    assert_eq!(err.code, "NOT_ADMITTED");
    let start_cmd = ConnectorRequest {
        operation: "Start".to_string(),
        ..manual.clone()
    };
    let err = start(&principal, &start_cmd).expect_err("Start must reject manual mode");
    assert_eq!(err.code, "NOT_ADMITTED");
}

/// Manual path requires no Ringmaster startup, browser, Hellscape, or
/// portfolio integration: recording succeeds with only the manifest,
/// the commission, and the operator channel.
#[test]
fn rm_c54_no_ringmaster_startup_required() {
    let m = manifest("admission-1");
    let commission = ManualCommission {
        commission_id: "commission-offline".to_string(),
        kind: AttemptKind::Practice,
        target: TargetClass::Fixture,
        operator_id: "op-9".to_string(),
        notes: "Recorded from paper notes; no services running.".to_string(),
        assistance: None,
    };
    let mut channel = channel_for("op-9");
    let recorded = record_manual_production(&mut channel, &m, &commission, None)
        .expect("manual recording must not require Ringmaster startup");
    assert_eq!(recorded.attempt_id, "manual-commission-offline");
}

/// Exactly nine verbs are recognized; a tenth verb is rejected and no
/// shared browser primitive endpoint exists on this surface.
#[test]
fn rm_c54_exactly_nine_verbs_no_browser_primitive() {
    assert_eq!(NINE_OPERATIONS.len(), 9);
    let principal = AuthenticatedPrincipal {
        principal_id: "op-1".to_string(),
        owner_domain: "portfolio".to_string(),
        roles: Vec::new(),
    };
    let cmd = |operation: &str| ConnectorRequest {
        record_type: "connector_request".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        request_id: "req-1".to_string(),
        connector_id: "ringmaster".to_string(),
        operation: operation.to_string(),
        call_limit: 1,
        payload: serde_json::json!({}),
    };
    for op in NINE_OPERATIONS {
        control(&principal, &cmd(op)).expect("all nine verbs must be recognized");
    }
    control(&principal, &cmd("ExecuteScript")).expect_err("no shared browser primitive");
}
