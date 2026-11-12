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
//! Invariants honored here:
//! - EK-MANUAL / LIFE-MANUAL: manual mode carries manual provenance only.
//! - EK-ATTEMPT-SCOPE: kind is immutable; practice is held_in, production
//!   is held_out and requires an employer origin.
//! - EXT-SURFACE: exactly the nine versioned verbs are recognized.
//! - EXT-AUTHORITY: identity comes from authenticated channel registration.
//! - EXT-TASK: manual commissions are not dispatchable through Prepare/Start.
//! - EXT-DECLARE-NOT-ASSESS: recording journals observations; it never emits
//!   an application-success flag.
//! - EXT-FAILURE: ConnectorError carries the full §17 envelope.
//!
//! Dependency design: the ten `rm_*` modules are sibling crates owned by
//! parallel implementers. Until they land, this crate carries minimal
//! in-crate stubs behind `// <module> (stub)` section headers. Stubs
//! implement the exact declared CONSUMES signatures; several enforce the
//! boundary rules the conformance tests rely on (manual-mode rejection in
//! Prepare/Start, kind/target coherence, manual zero-axis snapshots).

use serde_json::Value;
use std::cell::RefCell;

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
// Shared kernel types
// ---------------------------------------------------------------------------

/// The nine versioned connector verbs (EXT-SURFACE). No tenth verb exists.
pub const NINE_OPERATIONS: [&str; 9] = [
    "Describe",
    "Prepare",
    "Start",
    "Observe",
    "RequestNativeCancel",
    "CloseObservationConnection",
    "CollectArtifacts",
    "ReleaseNativeContext",
    "Contain",
];

/// ConnectorError: full §17 envelope. `kind` is always `connector_error`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorError {
    pub kind: String,
    pub code: String,
    pub fault_domain: String,
    pub detail: String,
    pub operation_delivery: String,
    pub retry_guidance: String,
    pub retry_after: Option<String>,
    pub handle: Option<String>,
    pub evidence_refs: Vec<String>,
}

impl ConnectorError {
    fn new(
        code: &str,
        fault_domain: &str,
        detail: String,
        operation_delivery: &str,
        retry_guidance: &str,
    ) -> Self {
        ConnectorError {
            kind: "connector_error".to_string(),
            code: code.to_string(),
            fault_domain: fault_domain.to_string(),
            detail,
            operation_delivery: operation_delivery.to_string(),
            retry_guidance: retry_guidance.to_string(),
            retry_after: None,
            handle: None,
            evidence_refs: Vec::new(),
        }
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.code, self.fault_domain, self.detail)
    }
}

impl std::error::Error for ConnectorError {}

/// Caller identity derived from authenticated channel registration.
/// IDs and digests are never bearer authority on their own (EXT-AUTHORITY).
#[derive(Debug, Clone, PartialEq)]
pub struct AuthenticatedPrincipal {
    pub principal_id: String,
    pub owner_domain: String,
    pub roles: Vec<String>,
}

/// Admitted work manifest the commission must bind to.
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub record_type: String,
    pub schema_version: String,
    pub manifest_id: String,
    pub admission_ref: String,
}

/// Immutable attempt kind (EK-ATTEMPT-SCOPE).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AttemptKind {
    Practice,
    Production,
}

/// Target class: fixtures are held_in, employer origins held_out.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TargetClass {
    Fixture,
    Employer,
}

/// Execution mode. Manual commissions are not dispatchable (EXT-TASK).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ExecutionMode {
    Manual,
    Subject,
}

/// Immutable commission authorizing an application attempt.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptCommission {
    pub record_type: String,
    pub schema_version: String,
    pub commission_id: String,
    pub kind: AttemptKind,
    pub target: TargetClass,
    pub mode: ExecutionMode,
    pub admission_ref: String,
    pub operator_id: String,
    pub origin_ref: Option<String>,
}

/// Shared task-shaped connector request envelope (§12.1).
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorRequest {
    pub record_type: String,
    pub schema_version: String,
    pub request_id: String,
    pub connector_id: String,
    pub operation: String,
    pub call_limit: u64,
    pub payload: Value,
}

/// Describe input: which connector, which version.
#[derive(Debug, Clone, PartialEq)]
pub struct DescribeRequest {
    pub connector_id: String,
    pub connector_version: String,
}

/// Connector capability declaration. The connector declares; it never
/// assesses (EXT-DECLARE-NOT-ASSESS): no success flag lives here.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorDescriptor {
    pub connector_id: String,
    pub connector_version: String,
    pub operations: Vec<String>,
}

/// Preparation receipt. Never issued for manual commissions.
#[derive(Debug, Clone, PartialEq)]
pub struct PrepareResult {
    pub preparation_id: String,
    pub ready: bool,
}

/// Dispatch receipt: one handle, one logical execution.
#[derive(Debug, Clone, PartialEq)]
pub struct StartResult {
    pub handle: String,
    pub logical_key: String,
}

/// Observation read request.
#[derive(Debug, Clone, PartialEq)]
pub struct ObserveRequest {
    pub handle: String,
    pub cursor: String,
}

/// One observation page. Native failure is evidence here, never a
/// ConnectorError (EXT-FAILURE).
#[derive(Debug, Clone, PartialEq)]
pub struct ObservationPage {
    pub events: Vec<Value>,
    pub next_cursor: String,
    pub more: bool,
}

/// Authorized artifact reference.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactReference {
    pub reference: String,
}

/// Artifact inventory response.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactInventory {
    pub refs: Vec<ArtifactReference>,
}

/// One artifact byte chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactChunk {
    pub bytes: Vec<u8>,
    pub eof: bool,
}

/// Control-plane effect receipt (transport effect only, never a task
/// outcome claim).
#[derive(Debug, Clone, PartialEq)]
pub struct ControlReceipt {
    pub operation: String,
    pub effect: String,
}

/// Monotonic service clock reading.
#[derive(Debug, Clone, PartialEq)]
pub struct TimePoint {
    pub clock_id: String,
    pub tick: u64,
}

/// Offline diagnostic document (maintenance path, separately authorized).
#[derive(Debug, Clone, PartialEq)]
pub struct DiagnosticDocument {
    pub diagnostic_id: String,
    pub digest: String,
}

/// Offline analysis request (never runs through task execution).
#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisRequest {
    pub analysis_id: String,
    pub question: String,
}

/// Journal prefix scoping offline replay reads.
#[derive(Debug, Clone, PartialEq)]
pub struct JournalPrefix {
    pub prefix: String,
}

/// Offline replay receipt. Replay never touches a browser, subject,
/// model, or external write.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayReceipt {
    pub analysis_id: String,
    pub matched: bool,
    pub offline: bool,
}

/// Derived read composition over the five axis slots. Manual
/// dispatch/execution axes stay at revision zero with inapplicable
/// values (LIFE-MANUAL); later evidence cannot erase a publication.
#[derive(Debug, Clone, PartialEq)]
pub struct AttemptSnapshot {
    pub record_type: String,
    pub schema_version: String,
    pub attempt_id: String,
    pub commission_id: String,
    pub mode: ExecutionMode,
    pub dispatch_revision: u64,
    pub execution_revision: u64,
}

// ---------------------------------------------------------------------------
// rm_authority (stub)
// ---------------------------------------------------------------------------

/// Authenticate the channel from registration bytes. Identity is derived
/// from authenticated registration, never from bare IDs (EXT-AUTHORITY).
pub fn authenticate_channel(
    channel: &mut dyn std::io::Read,
) -> Result<AuthenticatedPrincipal, ConnectorError> {
    log_call("authenticate_channel");
    let mut bytes = Vec::new();
    channel.read_to_end(&mut bytes).map_err(|e| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("channel read failed: {e}"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("channel registration is not JSON: {e}"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    let principal_id = value
        .get("principal_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ConnectorError::new(
                "UNAUTHENTICATED",
                "request",
                "channel identity not established: missing principal_id".to_string(),
                "not_dispatched",
                "operator_review",
            )
        })?;
    Ok(AuthenticatedPrincipal {
        principal_id: principal_id.to_string(),
        owner_domain: value
            .get("owner_domain")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        roles: value
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// Verify the commission binds to the admitted manifest with coherent
/// kind/target lineage: practice is held_in, production is held_out and
/// requires an employer origin (EK-ATTEMPT-SCOPE).
pub fn verify_attempt_scope(
    manifest: &Manifest,
    commission: &AttemptCommission,
) -> Result<(), ConnectorError> {
    log_call("verify_attempt_scope");
    if commission.admission_ref != manifest.admission_ref {
        return Err(ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            format!(
                "admission binding mismatch: commission {:?} not admitted under manifest {:?}",
                commission.admission_ref, manifest.admission_ref
            ),
            "not_dispatched",
            "operator_review",
        ));
    }
    let coherent = match (commission.kind, commission.target) {
        (AttemptKind::Practice, TargetClass::Fixture) => true,
        (AttemptKind::Production, TargetClass::Employer) => true,
        _ => false,
    };
    if !coherent {
        return Err(ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            "kind/target incoherence: practice is held_in, production requires an employer origin"
                .to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// rm_catalog (stub)
// ---------------------------------------------------------------------------

/// Describe the connector's declared capabilities. Unknown versions are
/// rejected; declarations never carry assessment (EXT-DECLARE-NOT-ASSESS).
pub fn describe(
    principal: &AuthenticatedPrincipal,
    request: &DescribeRequest,
) -> Result<ConnectorDescriptor, ConnectorError> {
    log_call("describe");
    let _ = principal;
    if request.connector_version.trim().is_empty() {
        return Err(ConnectorError::new(
            "UNSUPPORTED_VERSION",
            "request",
            "unknown contract/version: empty connector_version".to_string(),
            "not_applicable",
            "operator_review",
        ));
    }
    Ok(ConnectorDescriptor {
        connector_id: request.connector_id.clone(),
        connector_version: request.connector_version.clone(),
        operations: NINE_OPERATIONS.iter().map(|s| s.to_string()).collect(),
    })
}

// ---------------------------------------------------------------------------
// rm_preparation (stub)
// ---------------------------------------------------------------------------

/// Prepare an automated task. Manual commissions are not dispatchable
/// through this contract (EXT-TASK): they are rejected, never prepared.
pub fn prepare(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<PrepareResult, ConnectorError> {
    log_call("prepare");
    let _ = principal;
    check_operation(&command.operation)?;
    if is_manual_payload(&command.payload) {
        return Err(ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            "manual commissions are not dispatchable through Prepare".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(PrepareResult {
        preparation_id: format!("prep-{}", command.request_id),
        ready: true,
    })
}

// ---------------------------------------------------------------------------
// rm_delivery (stub)
// ---------------------------------------------------------------------------

/// Start (dispatch) an automated task. Manual commissions are rejected;
/// one handle maps to one logical execution.
pub fn start(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<StartResult, ConnectorError> {
    log_call("start");
    let _ = principal;
    check_operation(&command.operation)?;
    if is_manual_payload(&command.payload) {
        return Err(ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            "manual commissions are not dispatchable through Start".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(StartResult {
        handle: format!("handle-{}", command.request_id),
        logical_key: command.request_id.clone(),
    })
}

// ---------------------------------------------------------------------------
// rm_observe (stub)
// ---------------------------------------------------------------------------

/// Observe task evidence. Returns the (empty) page; observed native
/// failure would arrive here as evidence, not as ConnectorError.
pub fn observe(
    principal: &AuthenticatedPrincipal,
    request: &ObserveRequest,
) -> Result<ObservationPage, ConnectorError> {
    log_call("observe");
    let _ = (principal, request);
    Ok(ObservationPage {
        events: Vec::new(),
        next_cursor: String::new(),
        more: false,
    })
}

// ---------------------------------------------------------------------------
// rm_artifacts (stub)
// ---------------------------------------------------------------------------

/// Collect the authorized artifact inventory slots.
pub fn collect_inventory(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<ArtifactInventory, ConnectorError> {
    log_call("collect_inventory");
    let _ = (principal, command);
    Ok(ArtifactInventory { refs: Vec::new() })
}

/// Collect one authorized artifact chunk.
pub fn collect_chunk(
    principal: &AuthenticatedPrincipal,
    command: &ConnectorRequest,
) -> Result<ArtifactChunk, ConnectorError> {
    log_call("collect_chunk");
    let _ = (principal, command);
    Ok(ArtifactChunk {
        bytes: Vec::new(),
        eof: true,
    })
}

// ---------------------------------------------------------------------------
// rm_controls (stub)
// ---------------------------------------------------------------------------

/// Apply a transport-level control. Records the effect; never claims a
/// task outcome.
pub fn control(
    principal: &AuthenticatedPrincipal,
    request: &ConnectorRequest,
) -> Result<ControlReceipt, ConnectorError> {
    log_call("control");
    let _ = principal;
    check_operation(&request.operation)?;
    Ok(ControlReceipt {
        operation: request.operation.clone(),
        effect: "recorded".to_string(),
    })
}

// ---------------------------------------------------------------------------
// rm_supervisor (stub)
// ---------------------------------------------------------------------------

/// Drive one bounded supervision quantum. Never blocks the local
/// close/control path on an unbounded native call.
pub fn drive_once(
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
) -> Result<(), ConnectorError> {
    log_call("drive_once");
    let _ = (principal, now);
    Ok(())
}

// ---------------------------------------------------------------------------
// rm_diagnostics (stub)
// ---------------------------------------------------------------------------

/// Verify a diagnostic document offline. Maintenance path: separately
/// authorized, never connector-issued qualification.
pub fn verify_diagnostic(
    principal: &AuthenticatedPrincipal,
    diagnostic: &DiagnosticDocument,
) -> Result<(), ConnectorError> {
    log_call("verify_diagnostic");
    let _ = (principal, diagnostic);
    Ok(())
}

/// Replay a diagnostic offline against retained bytes. Never touches a
/// browser, subject, model, or external write.
pub fn replay_diagnostic(
    principal: &AuthenticatedPrincipal,
    request: &AnalysisRequest,
    prefix: &JournalPrefix,
    source: &ArtifactReference,
) -> Result<ReplayReceipt, ConnectorError> {
    log_call("replay_diagnostic");
    let _ = (prefix, source);
    let _ = principal;
    Ok(ReplayReceipt {
        analysis_id: request.analysis_id.clone(),
        matched: false,
        offline: true,
    })
}

// ---------------------------------------------------------------------------
// rm_lifecycle (stub)
// ---------------------------------------------------------------------------

/// Validate a derived attempt snapshot. Manual dispatch/execution axes
/// must remain at revision zero (LIFE-MANUAL).
pub fn validate_snapshot(
    principal: &AuthenticatedPrincipal,
    snapshot: &AttemptSnapshot,
) -> Result<(), ConnectorError> {
    log_call("validate_snapshot");
    let _ = principal;
    if snapshot.record_type != "attempt_snapshot" {
        return Err(ConnectorError::new(
            "INVALID_REQUEST",
            "request",
            "snapshot identity mismatch: expected record_type attempt_snapshot".to_string(),
            "not_applicable",
            "operator_review",
        ));
    }
    if snapshot.mode == ExecutionMode::Manual
        && (snapshot.dispatch_revision != 0 || snapshot.execution_revision != 0)
    {
        return Err(ConnectorError::new(
            "INVALID_REQUEST",
            "request",
            "manual dispatch/execution axes must remain at revision zero".to_string(),
            "not_applicable",
            "operator_review",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn check_operation(operation: &str) -> Result<(), ConnectorError> {
    if !NINE_OPERATIONS.contains(&operation) {
        return Err(ConnectorError::new(
            "INVALID_REQUEST",
            "request",
            format!("unknown connector verb `{operation}`; exactly nine versioned verbs exist"),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(())
}

fn is_manual_payload(payload: &Value) -> bool {
    payload.get("mode").and_then(|v| v.as_str()) == Some("manual")
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

// ---------------------------------------------------------------------------
// EXPOSES: (none declared) — service-owned manual recording composition
// ---------------------------------------------------------------------------
// The DAG declares no new public items for this tier; the composition
// below is the service wiring that [RM-C54] conformance exercises. It is
// not a tenth verb, browser primitive, or whole-attempt update API.

/// A manually executed production/practice application, as commissioned
/// by an operator. Carries no automation subject, native run ID,
/// connector version, or binding version (EK-MANUAL, LIFE-MANUAL).
/// Human notes retain manual provenance and disclosed assistance; a note
/// alone can never set an authoritative business predicate.
#[derive(Debug, Clone, PartialEq)]
pub struct ManualCommission {
    pub commission_id: String,
    pub kind: AttemptKind,
    pub target: TargetClass,
    pub operator_id: String,
    pub notes: String,
    pub assistance: Option<String>,
}

/// Journaled record of a manual application. No subject, connector
/// version, native run ID, execution publication, or success flag is
/// fabricated: dispatch/execution revisions are zero and provenance is
/// `manual_observer`. Origin facts are preserved as references, never
/// promoted into commitments.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordedAttempt {
    pub attempt_id: String,
    pub commission_id: String,
    pub kind: AttemptKind,
    pub target: TargetClass,
    pub operator_id: String,
    pub provenance: String,
    pub origin_ref: Option<String>,
    pub notes_digest: String,
    pub dispatch_revision: u64,
    pub execution_revision: u64,
}

/// Record a real manually executed application.
///
/// Flow: authenticate the operator channel, verify commission scope
/// against the admitted manifest, then validate the resulting snapshot.
/// Prepare/Start (and every other dispatch-path entry point) are never
/// invoked: manual work needs no Ringmaster startup, browser, Hellscape,
/// or portfolio integration. Production recording additionally requires
/// an employer origin evidence reference; without one the commission is
/// not admitted.
pub fn record_manual_production(
    channel: &mut dyn std::io::Read,
    manifest: &Manifest,
    commission: &ManualCommission,
    origin_ref: Option<String>,
) -> Result<RecordedAttempt, ConnectorError> {
    if commission.kind == AttemptKind::Production && origin_ref.is_none() {
        return Err(ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            "production manual recording requires an employer origin evidence reference"
                .to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    let principal = authenticate_channel(channel)?;
    if principal.principal_id != commission.operator_id {
        return Err(ConnectorError::new(
            "FORBIDDEN",
            "policy",
            "operator commission mismatch: authenticated principal is not the commissioning operator"
                .to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    let scope = AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "ringmaster/0.1.0".to_string(),
        commission_id: commission.commission_id.clone(),
        kind: commission.kind,
        target: commission.target,
        mode: ExecutionMode::Manual,
        admission_ref: manifest.admission_ref.clone(),
        operator_id: commission.operator_id.clone(),
        origin_ref: origin_ref.clone(),
    };
    verify_attempt_scope(manifest, &scope)?;
    let snapshot = AttemptSnapshot {
        record_type: "attempt_snapshot".to_string(),
        schema_version: "ringmaster/0.1.0".to_string(),
        attempt_id: format!("manual-{}", commission.commission_id),
        commission_id: commission.commission_id.clone(),
        mode: ExecutionMode::Manual,
        dispatch_revision: 0,
        execution_revision: 0,
    };
    validate_snapshot(&principal, &snapshot)?;
    Ok(RecordedAttempt {
        attempt_id: snapshot.attempt_id,
        commission_id: commission.commission_id.clone(),
        kind: commission.kind,
        target: commission.target,
        operator_id: commission.operator_id.clone(),
        provenance: "manual_observer".to_string(),
        origin_ref,
        notes_digest: fnv1a_hex(commission.notes.as_bytes()),
        dispatch_revision: 0,
        execution_revision: 0,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rm_c54_error_envelope_carries_section_17_fields() {
        let err = ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            "detail".to_string(),
            "not_dispatched",
            "operator_review",
        );
        assert_eq!(err.kind, "connector_error");
        assert!(!err.code.is_empty());
        assert!(!err.fault_domain.is_empty());
        assert!(!err.detail.is_empty());
        assert!(!err.operation_delivery.is_empty());
        assert!(!err.retry_guidance.is_empty());
    }

    #[test]
    fn rm_c54_nine_verbs_recognized_exactly() {
        assert_eq!(NINE_OPERATIONS.len(), 9);
        for op in NINE_OPERATIONS {
            check_operation(op).expect("ninth-verb allow-list must accept all nine");
        }
        check_operation("LaunchRockets").expect_err("tenth verb must be rejected");
    }
}
