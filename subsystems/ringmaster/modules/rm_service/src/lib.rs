//! `rm_service`: Ringmaster connector service composition root (tier 10).
//!
//! This crate wires the ten lower-tier dependency surfaces into one
//! connector service. It exposes no new connector verb, no shared browser
//! primitive, and no whole-attempt update API (FORBIDDEN). Its one owned
//! behavior is **manual production recording** ([RM-C54]): journaling a
//! real human-executed production application without dispatching it
//! through Prepare/Start, without inventing an automation subject, native
//! run ID, connector version, or execution publication, and without
//! requiring Ringmaster startup, a browser installation, Hellscape, or a
//! completed portfolio integration.
//!
//! Every facade below delegates to the real sibling implementation; the
//! manual path calls exactly `authenticate_channel`, `verify_attempt_scope`,
//! and `validate_snapshot`, and never touches dispatch machinery.
//!
//! Invariants honored here:
//! - EK-MANUAL / LIFE-MANUAL: manual mode carries manual provenance only;
//!   dispatch and execution slots stay at revision zero with
//!   `not_applicable`.
//! - EK-ATTEMPT-SCOPE: kind is immutable; practice is held_in, production
//!   is held_out and requires an employer origin. Origin references are
//!   carried, never promoted into commitments.
//! - EXT-SURFACE: exactly the nine versioned verbs are recognized
//!   (re-exported from `rm_authority`).
//! - EXT-AUTHORITY: identity comes from authenticated channel registration;
//!   handles are never shared across principals.
//! - EXT-TASK: manual commissions are not dispatchable through
//!   Prepare/Start (enforced by the shared `authorize_work` gate).
//! - EXT-DECLARE-NOT-ASSESS: recording journals observations; it never emits
//!   an application-success flag.
//! - EXT-FAILURE: errors carry the full §17 envelope (`ConnectorError`).

#![forbid(unsafe_code)]

use std::cell::RefCell;

// ---------------------------------------------------------------------------
// Shared kernel (canonical definitions live in `rm_authority`)
// ---------------------------------------------------------------------------

pub use rm_authority::{
    AttemptCommission, AttemptKind, AuthenticatedPrincipal, ConnectorError, EvaluationPartition,
    ExecutionMode, Manifest, TargetClass, NINE_OPERATIONS,
};
use rm_evidence::{JournalPrefix, PositiveInteger};
use rm_lifecycle::{
    AttemptContext, AttemptSnapshot, AxisSlot, SealName, SealPoint, SlotValue, VersionVector,
};
use rm_time::Missing;

// ---------------------------------------------------------------------------
// Dependency call log (test observability)
// ---------------------------------------------------------------------------

thread_local! {
    static CALL_LOG: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

fn log_call(name: &'static str) {
    CALL_LOG.with(|log| log.borrow_mut().push(name));
}

/// Names of dependency entry points invoked on this thread, in order.
/// Test observability hook: lets [RM-C54] prove the manual path never
/// touches dispatch machinery.
pub fn dependency_calls() -> Vec<String> {
    CALL_LOG.with(|log| log.borrow().iter().map(|s| s.to_string()).collect())
}

/// Clear this thread's dependency call log.
pub fn clear_dependency_calls() {
    CALL_LOG.with(|log| log.borrow_mut().clear());
}

// ---------------------------------------------------------------------------
// Service-owned errors (§17 envelope, never dispatched)
// ---------------------------------------------------------------------------

fn service_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: "not_applicable".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Composition facades: each delegates to the real sibling implementation
// ---------------------------------------------------------------------------

/// Authenticate the channel from registration bytes (delegates to
/// `rm_authority`). Identity is derived from authenticated registration,
/// never from bare IDs (EXT-AUTHORITY).
pub fn authenticate_channel(
    channel: &mut dyn std::io::Read,
) -> Result<AuthenticatedPrincipal, ConnectorError> {
    log_call("authenticate_channel");
    rm_authority::authenticate_channel(channel)
}

/// Verify the commission binds to the admitted manifest (delegates to
/// `rm_authority`): hash integrity, admission binding, and kind/target
/// coherence (EK-ATTEMPT-SCOPE).
pub fn verify_attempt_scope(
    manifest: &Manifest,
    commission: &AttemptCommission,
) -> Result<(), ConnectorError> {
    log_call("verify_attempt_scope");
    rm_authority::verify_attempt_scope(manifest, commission)
}

/// Describe the connector's declared capabilities (delegates to
/// `rm_catalog`). Declarations never carry assessment
/// (EXT-DECLARE-NOT-ASSESS).
pub fn describe(
    principal: &AuthenticatedPrincipal,
    request: &rm_catalog::DescribeRequest,
) -> Result<rm_catalog::ConnectorDescriptor, ConnectorError> {
    log_call("describe");
    rm_catalog::describe(principal, request)
}

/// Prepare an automated task (delegates to `rm_preparation`). Manual
/// commissions are rejected by the shared authority gate, never prepared
/// (EXT-TASK).
pub fn prepare(
    principal: &AuthenticatedPrincipal,
    command: &rm_preparation::ConnectorRequest,
) -> Result<rm_preparation::PrepareResult, ConnectorError> {
    log_call("prepare");
    rm_preparation::prepare(principal, command)
}

/// Start (dispatch) an automated task (delegates to `rm_delivery`). Manual
/// commissions cannot reach dispatch: Prepare refuses them first, and the
/// shared authority gate refuses them again.
pub fn start(
    principal: &AuthenticatedPrincipal,
    command: &rm_delivery::ConnectorRequest,
) -> Result<rm_delivery::StartResult, ConnectorError> {
    log_call("start");
    rm_delivery::start(principal, command)
}

/// Observe task evidence (delegates to `rm_observe`). Observed native
/// failure arrives here as evidence, never as ConnectorError (EXT-FAILURE).
pub fn observe(
    principal: &AuthenticatedPrincipal,
    request: &rm_observe::ObserveRequest,
) -> Result<rm_observe::ObservationPage, ConnectorError> {
    log_call("observe");
    rm_observe::observe(principal, request)
}

/// Collect the authorized artifact inventory slots (delegates to
/// `rm_artifacts`).
pub fn collect_inventory(
    principal: &AuthenticatedPrincipal,
    command: &rm_artifacts::ConnectorRequest,
) -> Result<rm_artifacts::ArtifactInventory, ConnectorError> {
    log_call("collect_inventory");
    rm_artifacts::collect_inventory(principal, command)
}

/// Collect one authorized artifact chunk (delegates to `rm_artifacts`).
pub fn collect_chunk(
    principal: &AuthenticatedPrincipal,
    command: &rm_artifacts::ConnectorRequest,
) -> Result<rm_artifacts::ArtifactChunk, ConnectorError> {
    log_call("collect_chunk");
    rm_artifacts::collect_chunk(principal, command)
}

/// Apply a transport-level control (delegates to `rm_controls`). Records
/// the effect; never claims a task outcome.
pub fn control(
    principal: &AuthenticatedPrincipal,
    request: &rm_controls::ConnectorRequest,
) -> Result<rm_controls::ControlReceipt, ConnectorError> {
    log_call("control");
    rm_controls::control(principal, request)
}

/// Drive one bounded supervision quantum (delegates to `rm_supervisor`).
pub fn drive_once(
    principal: &AuthenticatedPrincipal,
    now: &rm_time::TimePoint,
) -> Result<(), ConnectorError> {
    log_call("drive_once");
    rm_supervisor::drive_once(principal, now)
}

/// Verify a diagnostic document offline (delegates to `rm_diagnostics`).
/// Maintenance path: separately authorized, never connector-issued
/// qualification.
pub fn verify_diagnostic(
    principal: &AuthenticatedPrincipal,
    diagnostic: &rm_diagnostics::DiagnosticDocument,
) -> Result<(), ConnectorError> {
    log_call("verify_diagnostic");
    rm_diagnostics::verify_diagnostic(principal, diagnostic)
}

/// Replay a diagnostic offline against retained bytes (delegates to
/// `rm_diagnostics`). Never touches a browser, subject, model, or
/// external write.
pub fn replay_diagnostic(
    principal: &AuthenticatedPrincipal,
    request: &rm_diagnostics::AnalysisRequest,
    prefix: &rm_evidence::JournalPrefix,
    source: &rm_evidence::ArtifactReference,
) -> Result<rm_diagnostics::ReplayReceipt, ConnectorError> {
    log_call("replay_diagnostic");
    rm_diagnostics::replay_diagnostic(principal, request, prefix, source)
}

/// Validate a derived attempt snapshot (delegates to `rm_lifecycle`).
/// Read-side only: confers no authority to author or repair any axis.
pub fn validate_snapshot(
    principal: &AuthenticatedPrincipal,
    snapshot: &rm_lifecycle::AttemptSnapshot,
) -> Result<(), ConnectorError> {
    log_call("validate_snapshot");
    rm_lifecycle::validate_snapshot(principal, snapshot)
}

// ---------------------------------------------------------------------------
// Owned behavior: manual production recording [RM-C54]
// ---------------------------------------------------------------------------

/// Provenance carried by every human action and note in a manual record.
/// Manual provenance is never upgraded and never sets an authoritative
/// business predicate on its own.
pub const MANUAL_PROVENANCE: &str = "manual_observer";

/// One human action/note with manual provenance and disclosed assistance
/// context (assistance lives on the commission/record, disclosed once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualNote {
    pub body: String,
    pub provenance: String,
}

/// A manually executed production/practice application, as commissioned
/// by an operator. Carries no automation subject, native run ID,
/// connector version, or binding version (EK-MANUAL, LIFE-MANUAL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualCommission {
    pub commission_id: String,
    pub attempt_id: String,
    pub operator: String,
    pub journal_id: String,
    pub kind: AttemptKind,
    pub target_class: TargetClass,
    pub target_id: String,
    pub notes: Vec<String>,
    pub assistance: Option<String>,
}

/// Journaled record of a manual application. No subject, connector
/// version, native run ID, execution publication, or success flag is
/// fabricated: every axis slot is unpublished at revision zero and
/// provenance is `manual_observer`. Origin facts are preserved as
/// carried references, never promoted into commitments. The embedded
/// commission binds to the admitted manifest run (a binding, not an
/// invented native run) and the embedded snapshot passed real
/// lifecycle validation.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedAttempt {
    pub attempt_id: String,
    pub commission_id: String,
    pub kind: AttemptKind,
    pub target_class: TargetClass,
    pub target_id: String,
    pub operator: String,
    pub provenance: String,
    pub assistance: Option<String>,
    pub notes: Vec<ManualNote>,
    pub origin_refs: Vec<String>,
    pub commission: AttemptCommission,
    pub snapshot: AttemptSnapshot,
}

/// Bind a manual commission to its admitted manifest as a real
/// `AttemptCommission`. The run, manifest hash, and admission reference
/// are copied from the manifest (binding, never invention); the
/// task-semantic hash covers the admitted manifest task; the partition
/// follows the immutable kind.
fn build_attempt_commission(
    manifest: &Manifest,
    commission: &ManualCommission,
) -> Result<AttemptCommission, ConnectorError> {
    let task_bytes = serde_json::to_vec(&manifest.task).map_err(|error| {
        service_error(
            "INVALID_REQUEST",
            "request",
            format!("manifest task cannot be serialized: {error}"),
        )
    })?;
    let task_semantic_hash = rm_wire::canonical_digest(&task_bytes).map_err(|error| {
        service_error(
            "INVALID_REQUEST",
            "request",
            format!("manifest task cannot be hashed: {error}"),
        )
    })?;
    let evaluation_partition = match commission.kind {
        AttemptKind::Practice => EvaluationPartition::HeldIn,
        AttemptKind::Production => EvaluationPartition::HeldOut,
    };
    Ok(AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        commission_id: commission.commission_id.clone(),
        run_id: manifest.run_id.clone(),
        journal_id: commission.journal_id.clone(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: commission.attempt_id.clone(),
        kind: commission.kind,
        target_class: commission.target_class,
        evaluation_partition,
        target_id: commission.target_id.clone(),
        derived_from: Vec::new(),
        rehearsal_of: None,
        performance_of: None,
        task_semantic_hash: task_semantic_hash.as_str().to_string(),
        idempotency_key: format!("manual-record:{}", commission.commission_id),
        imported_evidence: Vec::new(),
    })
}

fn unpublished_slot(reason: &str, detail: &str) -> AxisSlot {
    AxisSlot {
        revision: 0,
        value: SlotValue::Unpublished(Missing::with_detail(reason, detail)),
    }
}

/// Build the manual read composition: every axis unpublished at revision
/// zero (dispatch/execution `not_applicable` per LIFE-MANUAL), sealed at
/// the commissioned view. The input prefix is pinned at the commission
/// digest; no evidence resolves against it while no axis is published.
fn build_manual_snapshot(
    commission: &AttemptCommission,
) -> Result<AttemptSnapshot, ConnectorError> {
    let digest = rm_lifecycle::commission_digest(commission)?;
    Ok(AttemptSnapshot {
        record_type: rm_lifecycle::SNAPSHOT_RECORD_TYPE.to_string(),
        schema_version: rm_lifecycle::LIFECYCLE_SCHEMA_VERSION.to_string(),
        attempt: AttemptContext {
            attempt_id: commission.attempt_id.clone(),
            kind: commission.kind,
            target_class: commission.target_class,
            target_id: commission.target_id.clone(),
            evaluation_partition: commission.evaluation_partition,
        },
        commission: commission.clone(),
        commission_digest: digest.clone(),
        input_prefix: JournalPrefix {
            journal_id: commission.journal_id.clone(),
            last_sequence: PositiveInteger::new(1)?,
            head_hash: digest,
        },
        dispatch: unpublished_slot("not_applicable", "manual mode: no automation dispatch"),
        observation: unpublished_slot(
            "not_observed",
            "manual mode: human actions journaled in the manual record, no connector observation publication",
        ),
        execution: unpublished_slot("not_applicable", "manual mode: no automation subject"),
        application: unpublished_slot(
            "not_observed",
            "manual mode: origin references carried, no origin fact publication",
        ),
        report: unpublished_slot("not_observed", "manual mode: no reconciler report"),
        seal_point: SealPoint {
            seal_id: format!("seal-manual-{}", commission.attempt_id),
            name: SealName::Commissioned,
            versions: VersionVector {
                dispatch: 0,
                observation: 0,
                execution: 0,
                application: 0,
                report: 0,
            },
            evidence_refs: Vec::new(),
        },
    })
}

/// Record a real manually executed application.
///
/// Flow: authenticate the operator channel, confirm the channel principal
/// is the commissioning operator, require an employer origin reference
/// for production, verify commission scope against the admitted manifest,
/// then validate the resulting snapshot. Prepare/Start (and every other
/// dispatch-path entry point) are never invoked: manual work needs no
/// Ringmaster startup, browser, Hellscape, or portfolio integration —
/// only the manifest, the commission, and the operator channel.
pub fn record_manual_production(
    channel: &mut dyn std::io::Read,
    manifest: &Manifest,
    commission: &ManualCommission,
    origin_ref: Option<String>,
) -> Result<RecordedAttempt, ConnectorError> {
    let principal = authenticate_channel(channel)?;
    if principal.principal_id() != commission.operator {
        return Err(service_error(
            "FORBIDDEN",
            "policy",
            format!(
                "operator mismatch: channel principal {:?} is not the commissioning operator {:?}; handles are never shared across principals",
                principal.principal_id(),
                commission.operator
            ),
        ));
    }
    if commission.kind == AttemptKind::Production
        && origin_ref.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(service_error(
            "NOT_ADMITTED",
            "policy",
            "production recording requires an employer origin evidence reference; recording without one is not admitted",
        ));
    }
    let attempt_commission = build_attempt_commission(manifest, commission)?;
    verify_attempt_scope(manifest, &attempt_commission)?;
    let snapshot = build_manual_snapshot(&attempt_commission)?;
    validate_snapshot(&principal, &snapshot)?;
    Ok(RecordedAttempt {
        attempt_id: commission.attempt_id.clone(),
        commission_id: commission.commission_id.clone(),
        kind: commission.kind,
        target_class: commission.target_class,
        target_id: commission.target_id.clone(),
        operator: commission.operator.clone(),
        provenance: MANUAL_PROVENANCE.to_string(),
        assistance: commission.assistance.clone(),
        notes: commission
            .notes
            .iter()
            .map(|body| ManualNote {
                body: body.clone(),
                provenance: MANUAL_PROVENANCE.to_string(),
            })
            .collect(),
        origin_refs: origin_ref.into_iter().collect(),
        commission: attempt_commission,
        snapshot,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rm_c54_error_envelope_carries_section_17_fields() {
        let error = service_error("NOT_ADMITTED", "policy", "unit probe");
        assert_eq!(error.kind, "connector_error");
        assert_eq!(error.code, "NOT_ADMITTED");
        assert_eq!(error.fault_domain, "policy");
        assert_eq!(error.detail, "unit probe");
        assert_eq!(error.operation_delivery, "not_applicable");
        assert_eq!(error.retry_guidance, "operator_review");
        assert_eq!(error.retry_after, None);
        assert_eq!(error.handle, None);
        assert!(error.evidence_refs.is_empty());
    }

    #[test]
    fn rm_c54_nine_verbs_recognized_exactly() {
        assert_eq!(
            NINE_OPERATIONS,
            [
                "Describe",
                "Prepare",
                "Start",
                "Observe",
                "RequestNativeCancel",
                "CloseObservationConnection",
                "CollectArtifacts",
                "ReleaseNativeContext",
                "Contain",
            ]
        );
    }
}
