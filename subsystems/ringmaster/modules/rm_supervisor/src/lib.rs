//! `rm_supervisor`: tier-9 bounded supervision loop for Ringmaster.
//!
//! The connector front end authenticates, validates, deduplicates, and answers
//! bounded requests. It never runs a long BrowserOxide primitive on the only
//! request/control thread (seam mapping §4.1). This module is the local
//! supervision loop that keeps that promise for work already admitted through
//! `rm_delivery`:
//!
//! - [`drive_once`] advances **one** bounded supervision unit per call and
//!   never awaits a native call. Native entry and execution stay with the
//!   execution owner on its own OS thread (`rm_execution`): a supervisor may
//!   await its owned result ([BO-THREAD], §4.2), so this loop observes entry
//!   and completion only as retained journal evidence.
//! - Reserved local progress is served **before** new work. An observation
//!   closure whose local boundary was reached, a pending publication, and
//!   late-evidence ingestion are all handled ahead of another workflow claim,
//!   so workflow queue pressure never consumes close/control progress
//!   ([EXT-BOUNDS], [LIFE-CLOSE]).
//! - No workflow primitive begins after its active boundary. A claimed task
//!   whose queue time already consumed its active budget is never delivered;
//!   its expiry remains `rm_delivery`'s recorded decision (RM-C24).
//! - A blocked non-interruptible native call does not block local
//!   finalization ([LIFE-CLOSE], RM-C25). The owner stays unresolved: the
//!   supervisor reports the unresolved owner as its own `connector_incident`
//!   observation and never fabricates a timer, completion, failure, or
//!   cancellation. The execution is never replaced by another logical
//!   execution ([EXT-CLOSE], §4.3).
//! - Observation closure is produced by `rm_controls::close_at_boundary` and
//!   published through `rm_lifecycle::publish_axis`. The exact admitted
//!   commission is recovered from the retained Start admission and its
//!   command bytes, and is only accepted when its canonical digest equals the
//!   digest of the attempt's published dispatch revision: a recovered identity
//!   that does not match exactly is an integrity incident, never a rewrite.
//! - Late evidence keeps the window closed: a closed-to-closed revision is
//!   appended at the current journal head, cites the new evidence, and
//!   preserves every prior closure field, publication, and registration
//!   ([LIFE-LATE-EVIDENCE]).
//!
//! The supervision registry is per principal and owner-local. It is a
//! scheduling fence, not a second source of truth: every durable decision is
//! written through the owning module (`rm_delivery`, `rm_controls`,
//! `rm_lifecycle`, `rm_evidence`). Native entry and execution, and the
//! normalization of their native reports, remain the execution owner's
//! synchronous calls on its own OS thread; running or awaiting them here would
//! put an unbounded native call on the local deadline/evidence/control path
//! and is forbidden. The supervisor observes `execution_claim`/`task_output`
//! evidence and never invents the missing pieces.
//!
//! A restart begins with an empty watch list: accepted work is never invented,
//! and every closure that was already registered remains retained evidence.
//! Discovery work carries no application attempt observation axis, so it is
//! admitted but never given a fabricated observation closure.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)] // ConnectorError is the shared §17 envelope.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex, MutexGuard};

use rm_authority::{
    AttemptCommission, AttemptKind, AuthenticatedPrincipal, ConnectorError, EvaluationPartition,
    EvidenceImport, LineageRef, Manifest, TargetClass,
};
use rm_evidence::{
    ArtifactReference, EvidencePayload, EvidenceRef, EventSubmission, JournalEnvelope,
    MaybeTimePoint, Missing, PositiveInteger, TimePoint,
};
use rm_lifecycle::{Axis, AxisRevision, LifecyclePublicationReference};
use rm_preparation::{PreparationReference, PreparedTask};
use serde_json::{json, Value};

/// Finite bound on one journal reconstruction scan.
///
/// The boundary/commission recovery reads at most this many retained events;
/// a journal beyond the bound fails with a typed prerequisite instead of
/// scanning without limit ([EXT-BOUNDS]).
const JOURNAL_SCAN_BOUND: u64 = 4096;
/// Registered connector-owned observation kind used for loss reporting.
const INCIDENT_KIND: &str = "connector_incident";
/// Registered publication-registration kind (owned by any axis).
const PUBLICATION_KIND: &str = "lifecycle_publication";
/// Owner domain of the observation axis.
const OBSERVATION_DOMAIN: &str = "observation";
/// Owner domain of the connector's own observations.
const CONNECTOR_DOMAIN: &str = "connector";
/// Event kind of the admitted Start boundary record.
const DISPATCH_EVENT_KIND: &str = "dispatch_published";

// ---------------------------------------------------------------------------
// Failure envelope helpers (§17 vocabulary)
// ---------------------------------------------------------------------------

fn connector_error(
    code: &str,
    fault_domain: &str,
    detail: impl Into<String>,
    operation_delivery: &str,
    retry_guidance: &str,
) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: operation_delivery.to_string(),
        retry_guidance: retry_guidance.to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "INVALID_REQUEST",
        "request",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "NOT_ADMITTED",
        "policy",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "PREREQUISITE_UNAVAILABLE",
        "local",
        detail,
        "not_dispatched",
        "retry_within_bound",
    )
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error(
        "INTEGRITY_CONFLICT",
        "integrity",
        detail,
        "not_dispatched",
        "operator_review",
    )
}

fn missing_json(reason: &str) -> Value {
    json!({"value": null, "reason": reason})
}

// ---------------------------------------------------------------------------
// Supervision registry (owner-local scheduling fence)
// ---------------------------------------------------------------------------

/// What this supervisor retained about one admitted logical execution.
///
/// The record is a fence, not a second source of truth: the handle, manifest,
/// commission, and boundary come from retained journal bytes and are
/// re-verified against the owning modules before use.
struct ExecutionRecord {
    handle: rm_delivery::ConnectorHandle,
    manifest: Manifest,
    /// Application commission, when the work carries an application attempt
    /// axis. Discovery work has no publication axis and no closure revision.
    commission: Option<AttemptCommission>,
    /// Exact journaled active boundary (queue time included).
    active_deadline: TimePoint,
    /// Admitted input artifact cited by the Start admission.
    input_artifact: ArtifactReference,
    /// Recognized native-entry evidence for this handle.
    entry_observed: bool,
    /// Recognized terminal (return) evidence for this handle.
    terminal_observed: bool,
    /// The unresolved owner was already reported; a later revision of the
    /// same closure does not report the same loss twice.
    loss_reported: bool,
    /// Work was adopted but refused native entry because its boundary passed.
    refused_before_entry: bool,
    /// Control observations cited by the latest published closure.
    cited_observations: usize,
    /// Latest produced observation revision, when the window is closed.
    closed_revision: Option<u64>,
    /// A closure that still needs loss reporting, publication, or registration.
    pending: Option<PendingClosure>,
}

/// A closure revision moving through loss-report → publish → register.
///
/// Each step is idempotent at the journal: the same producer sequence and
/// identical content deduplicate to the retained event (EK-OBSERVATION).
struct PendingClosure {
    revision: AxisRevision,
    loss_sequence: Option<PositiveInteger>,
    publication: Option<LifecyclePublicationReference>,
    registration_sequence: Option<PositiveInteger>,
}

#[derive(Default)]
struct PrincipalState {
    records: Vec<ExecutionRecord>,
    cursor: usize,
}

static REGISTRY: LazyLock<Mutex<BTreeMap<String, PrincipalState>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

fn lock_registry() -> MutexGuard<'static, BTreeMap<String, PrincipalState>> {
    REGISTRY
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

// ---------------------------------------------------------------------------
// EXPOSES: drive_once
// ---------------------------------------------------------------------------

/// Drives one bounded supervision unit for `principal` at local coordinate
/// `now`.
///
/// The quantum is priority ordered and finite:
///
/// 1. Retry an unfinished loss report, publication, or registration.
/// 2. Close one observation window whose local boundary was reached —
///    including a window whose native owner is still blocked — and publish the
///    observation revision.
/// 3. Ingest one closed window's late evidence as a closed-to-closed revision.
/// 4. Only when nothing above was due: claim at most one queued execution,
///    verify its preparation against retained bytes, enforce the active
///    boundary a second time, and adopt it as `entry_pending`.
///
/// It never executes or awaits a native workflow primitive, never fabricates
/// completion, failure, or cancellation when an owner is missing, and never
/// replaces an unresolved execution with another logical execution. It returns
/// `Ok(())` when the quantum had nothing due.
pub fn drive_once(
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
) -> Result<(), ConnectorError> {
    validate_now(now)?;
    let key = principal.principal_id().to_string();
    let mut registry = lock_registry();
    let state = registry.entry(key).or_default();

    // Reserved local progress precedes any new workflow claim.
    if let Some(index) = reserved_index(state, principal, now)? {
        state.cursor = (index + 1) % state.records.len().max(1);
        return serve_record(principal, now, &mut state.records[index]);
    }

    // At most one new admitted execution per quantum.
    let Some(handle) = rm_delivery::claim_work(principal, now)? else {
        return Ok(());
    };
    adopt(principal, now, state, handle)
}

fn validate_now(now: &TimePoint) -> Result<(), ConnectorError> {
    // A self-comparison validates the coordinate shape on one lifetime
    // without inventing a deadline or consulting UTC.
    match rm_time::boundary_reached(now, now) {
        Ok(_) => Ok(()),
        Err(error) => Err(invalid(format!(
            "now is not a usable local coordinate: {error}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Reserved progress: closure, late evidence, pending publication
// ---------------------------------------------------------------------------

/// Picks the next reserved unit in cursor order, if any.
fn reserved_index(
    state: &PrincipalState,
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
) -> Result<Option<usize>, ConnectorError> {
    let len = state.records.len();
    if len == 0 {
        return Ok(None);
    }
    for offset in 0..len {
        let index = (state.cursor + offset) % len;
        if record_due(&state.records[index], principal, now)? {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

fn record_due(
    record: &ExecutionRecord,
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
) -> Result<bool, ConnectorError> {
    if record.pending.is_some() {
        return Ok(true);
    }
    // Discovery work carries no application attempt observation axis; its
    // closure is connector evidence, never an invented lifecycle revision.
    if record.commission.is_none() {
        return Ok(false);
    }
    match record.closed_revision {
        None => {
            let reached =
                rm_time::boundary_reached(now, &record.active_deadline).map_err(|error| {
                    invalid(format!(
                        "the local active boundary cannot be ordered on the caller's clock: {error}"
                    ))
                })?;
            Ok(reached)
        }
        Some(_) => {
            // A closed window is revised only when new control observations
            // were appended after the cited closure; without new evidence the
            // closure is never rewritten or reopened.
            let observed = observed_count(principal, &record.handle)?;
            Ok(observed > record.cited_observations)
        }
    }
}

fn observed_count(
    principal: &AuthenticatedPrincipal,
    handle: &rm_delivery::ConnectorHandle,
) -> Result<usize, ConnectorError> {
    match rm_controls::control_history(principal, handle) {
        Ok(history) => Ok(history.len()),
        // No window means no control observation was ever appended.
        Err(error) if error.code == "UNKNOWN_HANDLE" => Ok(0),
        Err(error) => Err(error),
    }
}

fn serve_record(
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
    record: &mut ExecutionRecord,
) -> Result<(), ConnectorError> {
    if record.pending.is_none() {
        let commission = record.commission.as_ref().ok_or_else(|| {
            not_admitted(
                "discovery work carries no application attempt observation axis; no closure \
                 revision is invented",
            )
        })?;
        // A closure is never attempted unless the recovered commission is
        // byte-identical to the identity the dispatch axis published.
        verify_commission_identity(principal, &record.handle, commission)?;
        // Entry/completion are established only from retained evidence.
        let (entry, terminal) = entry_evidence(principal, &record.handle)?;
        record.entry_observed = record.entry_observed || entry;
        record.terminal_observed = record.terminal_observed || terminal;
        let loss_sequence = if needs_loss_report(record) {
            Some(next_producer_sequence(
                principal,
                record.handle.scope.journal_id.as_str(),
            )?)
        } else {
            None
        };
        let revision = rm_controls::close_at_boundary(principal, &record.handle, now)?;
        validate_closure(&record.handle, commission, &revision)?;
        record.cited_observations = revision.evidence_refs.len();
        record.closed_revision = Some(revision.revision);
        record.pending = Some(PendingClosure {
            revision,
            loss_sequence,
            publication: None,
            registration_sequence: None,
        });
    }
    advance_pending(principal, record)
}

/// A closure with an attempted entry but no terminal evidence is an unresolved
/// owner. Pre-entry expiry is not a lost call and is not reported as one.
fn needs_loss_report(record: &ExecutionRecord) -> bool {
    if record.terminal_observed || record.loss_reported {
        return false;
    }
    !(record.refused_before_entry && !record.entry_observed)
}

fn advance_pending(
    principal: &AuthenticatedPrincipal,
    record: &mut ExecutionRecord,
) -> Result<(), ConnectorError> {
    let Some(mut pending) = record.pending.take() else {
        return Ok(());
    };
    let outcome = publish_pending(principal, record, &mut pending);
    if outcome.is_err() {
        // Keep the exact intermediate state so the next quantum resumes the
        // same producer sequences instead of duplicating journal effects.
        record.pending = Some(pending);
    }
    outcome
}

fn publish_pending(
    principal: &AuthenticatedPrincipal,
    record: &mut ExecutionRecord,
    pending: &mut PendingClosure,
) -> Result<(), ConnectorError> {
    let commission = record
        .commission
        .as_ref()
        .ok_or_else(|| not_admitted("no application attempt commission is retained for this closure"))?;

    // a. Loss reporting for an owner that never established terminal evidence.
    if let Some(sequence) = pending.loss_sequence {
        append_unresolved_owner_incident(principal, record, &pending.revision, &sequence)?;
        pending.loss_sequence = None;
        record.loss_reported = true;
    }

    // b. Publish the immutable observation revision.
    if pending.publication.is_none() {
        let publication = rm_lifecycle::publish_axis(principal, commission, &pending.revision)?;
        if publication.axis != Axis::Observation
            || publication.revision != pending.revision.revision
            || publication.commission_digest != pending.revision.commission_digest
        {
            return Err(integrity(
                "the published reference does not name the observation revision that was closed",
            ));
        }
        pending.publication = Some(publication);
    }

    // c. Register the installed publication in the owned journal so the
    //    closure is discoverable after a restart, without rewriting it.
    if pending.registration_sequence.is_none() {
        pending.registration_sequence = Some(next_producer_sequence(
            principal,
            record.handle.scope.journal_id.as_str(),
        )?);
    }
    let publication = pending
        .publication
        .as_ref()
        .ok_or_else(|| integrity("a pending closure has no installed publication"))?;
    let sequence = pending
        .registration_sequence
        .as_ref()
        .ok_or_else(|| integrity("a pending closure has no registration sequence"))?;
    append_publication_registration(principal, record, &pending.revision, publication, sequence)?;
    Ok(())
}

fn verify_commission_identity(
    principal: &AuthenticatedPrincipal,
    handle: &rm_delivery::ConnectorHandle,
    commission: &AttemptCommission,
) -> Result<(), ConnectorError> {
    // The recovery is only usable when its canonical bytes equal the identity
    // the dispatch axis already published. This runs before any closure state
    // changes, so an unrecoverable identity never closes a window.
    match rm_delivery::lifecycle_publication(principal, handle)? {
        rm_delivery::PublicationState::Published(reference) => {
            if reference.axis != Axis::Dispatch
                || reference.commission_digest != rm_lifecycle::commission_digest(commission)?
            {
                return Err(integrity(
                    "the recovered commission does not match the published dispatch identity",
                ));
            }
            Ok(())
        }
        rm_delivery::PublicationState::Pending(missing) => Err(prerequisite(format!(
            "the dispatch-axis publication is pending ({}: {}); the attempt identity is not \
             recoverable",
            missing.reason,
            missing.detail.unwrap_or_default()
        ))),
        rm_delivery::PublicationState::NotApplicable(missing) => Err(not_admitted(format!(
            "the retained handle carries no application attempt axis ({})",
            missing.reason
        ))),
    }
}

fn validate_closure(
    handle: &rm_delivery::ConnectorHandle,
    commission: &AttemptCommission,
    revision: &AxisRevision,
) -> Result<(), ConnectorError> {
    if revision.axis != Axis::Observation || revision.owner_domain != OBSERVATION_DOMAIN {
        return Err(integrity(
            "the closure did not produce an observation-axis revision",
        ));
    }
    if Some(revision.attempt.attempt_id.clone()) != handle.scope.attempt_id {
        return Err(integrity(
            "the closure names a different attempt than the admitted handle scope",
        ));
    }
    if revision.commission_digest != rm_lifecycle::commission_digest(commission)? {
        return Err(integrity(
            "the closure revision does not carry the admitted commission digest",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// New work admission
// ---------------------------------------------------------------------------

fn adopt(
    principal: &AuthenticatedPrincipal,
    now: &TimePoint,
    state: &mut PrincipalState,
    handle: rm_delivery::ConnectorHandle,
) -> Result<(), ConnectorError> {
    // The preparation is verified against its exact retained bytes before any
    // hand-off; the delivery claim already made the entry intent durable.
    let verified = rm_preparation::verify_preparation(principal, &handle.preparation);
    let (prepared, verification_error) = match verified {
        Ok(prepared) => (Some(prepared), None),
        Err(error) => (None, Some(error)),
    };

    let admission = resolve_admission(principal, &handle, prepared.as_ref())?;
    let reached = rm_time::boundary_reached(now, &admission.active_deadline).map_err(|error| {
        invalid(format!(
            "the admitted active boundary cannot be ordered on the caller's clock: {error}"
        ))
    })?;

    let record = ExecutionRecord {
        handle: handle.clone(),
        manifest: admission.manifest,
        commission: admission.commission,
        active_deadline: admission.active_deadline.clone(),
        input_artifact: admission.input_artifact,
        entry_observed: false,
        terminal_observed: false,
        loss_reported: false,
        refused_before_entry: false,
        cited_observations: 0,
        closed_revision: None,
        pending: None,
    };
    state.records.push(record);
    let index = state.records.len() - 1;
    state.cursor = index;

    if let Some(error) = verification_error {
        // The accepted task is retained for bounded closure; the caller still
        // sees the verification failure that stopped entry.
        state.records[index].refused_before_entry = true;
        return Err(error);
    }

    if reached {
        // No workflow primitive begins after the active boundary. Record the
        // refusal, then close locally in the same bounded quantum: an
        // accepted queued task consumes its observation budget and rejected
        // work is never silently dropped.
        state.records[index].refused_before_entry = true;
        let sequence = next_producer_sequence(principal, handle.scope.journal_id.as_str())?;
        let refusal = json!({
            "reason": "active_boundary_reached_before_native_entry",
            "active_deadline": time_json(&admission.active_deadline)?,
            "workflow_primitive_begun": false,
            "delivery_intent_retained": true,
        });
        append_incident(
            principal,
            occurred_time(now),
            &state.records[index].manifest,
            &handle,
            &state.records[index].input_artifact,
            "entry_refused_before_boundary",
            refusal,
            &sequence,
        )?;
        return serve_record(principal, now, &mut state.records[index]);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Retained evidence recovery (no invented identities)
// ---------------------------------------------------------------------------

struct Admission {
    manifest: Manifest,
    commission: Option<AttemptCommission>,
    active_deadline: TimePoint,
    input_artifact: ArtifactReference,
}

/// Reconstructs one handle's admitted Start record from retained evidence.
///
/// The exact admitted command artifact is loaded through [`rm_evidence`] and
/// the handle's immutable preparation must match it byte-for-byte. The
/// manifest's wire projection is reconstructed with the handle's admitted
/// admission binding and hash, and must hash back to that admitted identity.
/// A recovered commission is cross-checked field by field against the admitted
/// handle scope; its canonical agreement with the published dispatch identity
/// is verified separately before any closure is attempted.
fn resolve_admission(
    principal: &AuthenticatedPrincipal,
    handle: &rm_delivery::ConnectorHandle,
    prepared: Option<&PreparedTask>,
) -> Result<Admission, ConnectorError> {
    let journal_id = handle.scope.journal_id.as_str();
    let envelope = find_start_admission(principal, journal_id, &handle.handle.local_handle)?;
    let data = &envelope.payload.data;

    let input_artifact = ArtifactReference::from_json(
        data.get("input_artifact")
            .ok_or_else(|| integrity("the retained Start admission omits its admitted input"))?,
    )?;
    let bytes = rm_evidence::load_artifact(principal, &input_artifact)?;
    let command: Value = serde_json::from_slice(&bytes)
        .map_err(|error| integrity(format!("the admitted input is not JSON: {error}")))?;
    if command.get("operation").and_then(Value::as_str) != Some("Start") {
        return Err(integrity(
            "the admitted input names a different operation than Start",
        ));
    }
    let payload = command
        .get("payload")
        .ok_or_else(|| integrity("the admitted input has no command payload"))?;
    if payload.get("kind").and_then(Value::as_str) != Some("start") {
        return Err(integrity(
            "the admitted input is not a Start request payload",
        ));
    }

    // The admitted command carries the manifest's wire projection (the
    // admission binding and hash are authority fields the handle scope
    // retains). The reconstructed record must hash to the admitted manifest
    // identity: a changed wire projection is an integrity incident.
    let manifest = parse_manifest(
        payload
            .get("manifest")
            .ok_or_else(|| integrity("the admitted input carries no manifest"))?,
        &handle.scope.admission_ref,
        &handle.scope.manifest_hash,
    )?;
    let manifest_reference = rm_evidence::manifest_artifact_reference(&manifest)?;
    if manifest_reference.digest.as_str() != handle.scope.manifest_hash {
        return Err(integrity(
            "the admitted manifest does not hash to the handle's admitted manifest identity",
        ));
    }
    if manifest.run_id != handle.scope.run_id
        || manifest.admission_ref != handle.scope.admission_ref
    {
        return Err(integrity(
            "the admitted manifest run/admission does not match the handle scope",
        ));
    }

    let prepared_reference = PreparationReference::from_json(
        payload
            .get("preparation")
            .ok_or_else(|| integrity("the admitted input carries no preparation reference"))?,
    )?;
    if prepared_reference != handle.preparation {
        return Err(integrity(
            "the admitted preparation reference differs from the handle's immutable preparation",
        ));
    }

    let commission = match payload.get("commission") {
        None => None,
        Some(value) if is_missing_envelope(value) => None,
        Some(value) => Some(parse_commission(value)?),
    };

    if handle.scope.attempt_id.is_some() != commission.is_some() {
        return Err(integrity(
            "the handle's attempt binding and the admitted commission disagree",
        ));
    }
    if let Some(commission) = &commission {
        if handle.scope.attempt_id.as_deref() != Some(commission.attempt_id.as_str())
            || handle.scope.commission_id.as_deref() != Some(commission.commission_id.as_str())
            || handle.scope.run_id != commission.run_id
            || handle.scope.journal_id != commission.journal_id
            || handle.scope.manifest_hash != commission.manifest_hash
            || handle.scope.admission_ref != commission.admission_ref
            || Some(commission.kind) != handle.scope.attempt_kind
        {
            return Err(integrity(
                "the admitted commission identity does not match the admitted handle scope",
            ));
        }
    }

    let active_deadline: TimePoint = serde_json::from_value(
        data.get("active_deadline")
            .ok_or_else(|| integrity("the retained Start admission omits its active boundary"))?
            .clone(),
    )
    .map_err(|error| integrity(format!("the journaled active boundary is invalid: {error}")))?;
    if active_deadline.clock_id != handle.created_at.clock_id
        || active_deadline.boot_id != handle.created_at.boot_id
        || active_deadline.origin != handle.created_at.origin
    {
        return Err(integrity(
            "the journaled active boundary is not on the handle's admitted lifetime",
        ));
    }

    if let Some(prepared) = prepared {
        if prepared.preparation_id != handle.preparation.preparation_id
            || prepared.scope.journal_id != handle.scope.journal_id
            || prepared.scope.manifest_hash != handle.scope.manifest_hash
        {
            return Err(integrity(
                "the verified preparation does not belong to the admitted handle",
            ));
        }
        let limit = &prepared.task.budgets.active_limit;
        if limit.kind != "exact" || limit.unit != "ms" || !limit.value.is_finite() || limit.value < 0.0
        {
            return Err(integrity(
                "the prepared active limit is not an exact nonnegative millisecond duration",
            ));
        }
        let expected = handle.created_at.monotonic_offset_ms + limit.value;
        if !expected.is_finite() || expected < 0.0 || expected != active_deadline.monotonic_offset_ms
        {
            return Err(integrity(
                "the journaled active boundary is not the admitted creation plus the prepared \
                 active limit; queue time is never restarted",
            ));
        }
    }

    Ok(Admission {
        manifest,
        commission,
        active_deadline,
        input_artifact,
    })
}

fn find_start_admission(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
    local_handle: &str,
) -> Result<JournalEnvelope, ConnectorError> {
    let head = rm_evidence::journal_head(principal, journal_id)?;
    if head.last_sequence.get() > JOURNAL_SCAN_BOUND {
        return Err(prerequisite(format!(
            "the retained journal has {} events, over the finite supervision scan bound of {}",
            head.last_sequence.get(),
            JOURNAL_SCAN_BOUND
        )));
    }
    for sequence in 1..=head.last_sequence.get() {
        let envelope = rm_evidence::read_event(
            principal,
            journal_id,
            PositiveInteger::new(sequence)
                .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?,
        )?;
        if envelope.event_kind != DISPATCH_EVENT_KIND {
            continue;
        }
        let data = &envelope.payload.data;
        if data.get("operation").and_then(Value::as_str) != Some("start") {
            continue;
        }
        if data
            .get("handle")
            .and_then(|handle| handle.get("local_handle"))
            .and_then(Value::as_str)
            != Some(local_handle)
        {
            continue;
        }
        return Ok(envelope);
    }
    Err(integrity(
        "the retained journal holds no Start admission for this handle; the supervisor never \
         invents one",
    ))
}

/// Entry and terminal evidence for one handle, from retained journal events
/// only. `execution_claim` is entry; `task_output` is a returned result.
fn entry_evidence(
    principal: &AuthenticatedPrincipal,
    handle: &rm_delivery::ConnectorHandle,
) -> Result<(bool, bool), ConnectorError> {
    let journal_id = handle.scope.journal_id.as_str();
    let head = rm_evidence::journal_head(principal, journal_id)?;
    if head.last_sequence.get() > JOURNAL_SCAN_BOUND {
        return Err(prerequisite(format!(
            "the retained journal has {} events, over the finite supervision scan bound of {}",
            head.last_sequence.get(),
            JOURNAL_SCAN_BOUND
        )));
    }
    let mut entry = false;
    let mut terminal = false;
    for sequence in 1..=head.last_sequence.get() {
        let envelope = rm_evidence::read_event(
            principal,
            journal_id,
            PositiveInteger::new(sequence)
                .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?,
        )?;
        if !event_names_handle(&envelope.payload.data, &handle.handle.local_handle) {
            continue;
        }
        match envelope.event_kind.as_str() {
            "execution_claim" => entry = true,
            "task_output" => {
                entry = true;
                terminal = true;
            }
            _ => {}
        }
    }
    Ok((entry, terminal))
}

fn event_names_handle(data: &Value, local_handle: &str) -> bool {
    if let Some(handle) = data.get("handle") {
        if handle.get("local_handle").and_then(Value::as_str) == Some(local_handle) {
            return true;
        }
    }
    data.get("local_handle").and_then(Value::as_str) == Some(local_handle)
}

// ---------------------------------------------------------------------------
// Evidence writes owned by this supervisor
// ---------------------------------------------------------------------------

fn append_unresolved_owner_incident(
    principal: &AuthenticatedPrincipal,
    record: &ExecutionRecord,
    revision: &AxisRevision,
    sequence: &PositiveInteger,
) -> Result<EvidenceRef, ConnectorError> {
    let detail = json!({
        "reason": "local_boundary_reached_without_terminal_native_evidence",
        "active_deadline": time_json(&record.active_deadline)?,
        "closed_revision": revision.revision,
        "entry_observed": record.entry_observed,
        "terminal_evidence_observed": false,
        "native_cancel_fabricated": false,
        "worker_replacement_attempted": false,
        "note": "fencing and closure never establish remote termination",
    });
    append_incident(
        principal,
        // The observation is about the local boundary; its stable source
        // coordinate is retained inside the payload.
        MaybeTimePoint::Missing(Missing::with_detail(
            "not_observed",
            "the local boundary coordinate is retained in the incident payload",
        )),
        &record.manifest,
        &record.handle,
        &record.input_artifact,
        "unresolved_native_owner_at_local_boundary",
        detail,
        sequence,
    )
}

#[allow(clippy::too_many_arguments)]
fn append_incident(
    principal: &AuthenticatedPrincipal,
    occurred_at: MaybeTimePoint,
    manifest: &Manifest,
    handle: &rm_delivery::ConnectorHandle,
    input_artifact: &ArtifactReference,
    incident: &str,
    detail: Value,
    producer_sequence: &PositiveInteger,
) -> Result<EvidenceRef, ConnectorError> {
    rm_authority::authorize_owner(principal, CONNECTOR_DOMAIN, INCIDENT_KIND)?;
    let registration = rm_evidence::event_registration(INCIDENT_KIND).ok_or_else(|| {
        not_admitted("connector_incident is not registered with the ingestion authority")
    })?;
    let data = json!({
        "kind": INCIDENT_KIND,
        "incident": incident,
        "handle": handle.handle.to_json(),
        "local_handle": handle.handle.local_handle,
        "attempt_id": match &handle.scope.attempt_id {
            Some(attempt_id) => Value::String(attempt_id.clone()),
            None => missing_json("not_applicable"),
        },
        "detail": detail,
    });
    let submission = EventSubmission {
        producer_sequence: Some(*producer_sequence),
        event_kind: INCIDENT_KIND.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at,
        payload: EvidencePayload {
            data,
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![input_artifact.clone()],
        },
    };
    let envelope = rm_evidence::append_event(principal, manifest, submission)?;
    Ok(evidence_ref(&envelope))
}

fn append_publication_registration(
    principal: &AuthenticatedPrincipal,
    record: &ExecutionRecord,
    revision: &AxisRevision,
    publication: &LifecyclePublicationReference,
    sequence: &PositiveInteger,
) -> Result<EvidenceRef, ConnectorError> {
    // `lifecycle_publication` is registered for any axis; authorize the
    // registered owner domain exactly as the ingestion authority will.
    let registration = rm_evidence::event_registration(PUBLICATION_KIND).ok_or_else(|| {
        not_admitted("lifecycle_publication is not registered with the ingestion authority")
    })?;
    rm_authority::authorize_owner(principal, registration.owner_domain, PUBLICATION_KIND)?;
    let data = json!({
        "kind": PUBLICATION_KIND,
        "axis": revision.axis.as_str(),
        "revision": revision.revision,
        "previous_revision": revision.previous_revision,
        "attempt": attempt_json(&revision.attempt),
        "commission_digest": revision.commission_digest.as_str(),
        "content": publication.content.to_json(),
        "evidence_prefix": revision.evidence_prefix.to_json(),
        "handle": record.handle.handle.to_json(),
        "local_handle": record.handle.handle.local_handle,
    });
    let submission = EventSubmission {
        producer_sequence: Some(*sequence),
        event_kind: PUBLICATION_KIND.to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        // Stable across retries so an interrupted registration deduplicates
        // to its retained event instead of appending a second one.
        occurred_at: MaybeTimePoint::Missing(Missing::with_detail(
            "not_observed",
            "the registration event is stamped by the journal; the publication coordinate is retained on the revision",
        )),
        payload: EvidencePayload {
            data,
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![publication.content.clone()],
        },
    };
    let envelope = rm_evidence::append_event(principal, &record.manifest, submission)?;
    Ok(evidence_ref(&envelope))
}

/// Next producer-lifetime sequence for this principal in one journal.
///
/// The write is retried by the supervisor with the exact same sequence, so a
/// retry deduplicates to the retained event instead of duplicating an effect.
/// Reading the retained maximum keeps the new key ahead of every sequence the
/// same producer already used in this journal.
fn next_producer_sequence(
    principal: &AuthenticatedPrincipal,
    journal_id: &str,
) -> Result<PositiveInteger, ConnectorError> {
    let head = rm_evidence::journal_head(principal, journal_id)?;
    if head.last_sequence.get() > JOURNAL_SCAN_BOUND {
        return Err(prerequisite(format!(
            "the retained journal has {} events, over the finite supervision scan bound of {}",
            head.last_sequence.get(),
            JOURNAL_SCAN_BOUND
        )));
    }
    let mut highest = 0_u64;
    for sequence in 1..=head.last_sequence.get() {
        let envelope = rm_evidence::read_event(
            principal,
            journal_id,
            PositiveInteger::new(sequence)
                .map_err(|error| invalid(format!("journal sequence is invalid: {error}")))?,
        )?;
        if let Some(producer_sequence) = envelope.producer_sequence {
            highest = highest.max(producer_sequence.get());
        }
    }
    PositiveInteger::new(highest + 1)
        .map_err(|error| integrity(format!("producer sequence is exhausted: {error}")))
}

fn evidence_ref(envelope: &JournalEnvelope) -> EvidenceRef {
    EvidenceRef {
        journal_id: envelope.journal_id.clone(),
        sequence: envelope.journal_sequence,
        event_id: envelope.event_id.clone(),
        event_hash: envelope.event_hash.clone(),
        pointer: String::new(),
    }
}

fn occurred_time(now: &TimePoint) -> MaybeTimePoint {
    let clock = rm_evidence::evidence_clock();
    if now.clock_id == clock.clock_id && now.boot_id == clock.boot_id && now.origin == clock.origin
    {
        MaybeTimePoint::Present(now.clone())
    } else {
        MaybeTimePoint::Missing(Missing::with_detail(
            "not_observed",
            "the supervisor's local coordinate is not registered with this evidence journal",
        ))
    }
}

fn time_json(point: &TimePoint) -> Result<Value, ConnectorError> {
    serde_json::to_value(point)
        .map_err(|error| invalid(format!("time point is not serializable: {error}")))
}

// ---------------------------------------------------------------------------
// Closed-evidence parsing (retained bytes are the only source)
// ---------------------------------------------------------------------------

fn is_missing_envelope(value: &Value) -> bool {
    value.get("value").is_some_and(Value::is_null)
}

fn field<'a>(object: &'a Value, name: &str, what: &str) -> Result<&'a Value, ConnectorError> {
    object
        .get(name)
        .ok_or_else(|| integrity(format!("{what} omits required field {name:?}")))
}

fn text_field(object: &Value, name: &str, what: &str) -> Result<String, ConnectorError> {
    field(object, name, what)?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| integrity(format!("{what} field {name:?} must be a string")))
}

fn parse_manifest(
    value: &Value,
    admission_ref: &str,
    manifest_hash: &str,
) -> Result<Manifest, ConnectorError> {
    let what = "admitted manifest";
    let event_kinds = field(value, "event_kinds", what)?
        .as_array()
        .ok_or_else(|| integrity("admitted manifest event_kinds must be an array"))?
        .iter()
        .map(|kind| {
            kind.as_str()
                .map(str::to_string)
                .ok_or_else(|| integrity("admitted manifest event kinds must be strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Manifest {
        record_type: text_field(value, "record_type", what)?,
        schema_version: text_field(value, "schema_version", what)?,
        run_id: text_field(value, "run_id", what)?,
        task: field(value, "task", what)?.clone(),
        subject: field(value, "subject", what)?.clone(),
        event_kinds,
        admission_ref: admission_ref.to_string(),
        manifest_hash: manifest_hash.to_string(),
    })
}

fn parse_commission(value: &Value) -> Result<AttemptCommission, ConnectorError> {
    let what = "admitted commission";
    let derived_from = field(value, "derived_from", what)?
        .as_array()
        .ok_or_else(|| integrity("admitted commission derived_from must be an array"))?
        .iter()
        .map(parse_lineage)
        .collect::<Result<Vec<_>, _>>()?;
    let imported_evidence = field(value, "imported_evidence", what)?
        .as_array()
        .ok_or_else(|| integrity("admitted commission imported_evidence must be an array"))?
        .iter()
        .map(|import| {
            Ok(EvidenceImport {
                source_attempt_id: text_field(import, "source_attempt_id", "evidence import")?,
                source_kind: parse_attempt_kind(&text_field(
                    import,
                    "source_kind",
                    "evidence import",
                )?)?,
                source_digest: text_field(import, "source_digest", "evidence import")?,
                claimed_provenance: text_field(import, "claimed_provenance", "evidence import")?,
                retained_bytes_digest: text_field(
                    import,
                    "retained_bytes_digest",
                    "evidence import",
                )?,
            })
        })
        .collect::<Result<Vec<_>, ConnectorError>>()?;
    Ok(AttemptCommission {
        record_type: text_field(value, "record_type", what)?,
        schema_version: text_field(value, "schema_version", what)?,
        commission_id: text_field(value, "commission_id", what)?,
        run_id: text_field(value, "run_id", what)?,
        journal_id: text_field(value, "journal_id", what)?,
        manifest_hash: text_field(value, "manifest_hash", what)?,
        admission_ref: text_field(value, "admission_ref", what)?,
        attempt_id: text_field(value, "attempt_id", what)?,
        kind: parse_attempt_kind(&text_field(value, "kind", what)?)?,
        target_class: parse_target_class(&text_field(value, "target_class", what)?)?,
        evaluation_partition: parse_evaluation_partition(&text_field(
            value,
            "evaluation_partition",
            what,
        )?)?,
        target_id: text_field(value, "target_id", what)?,
        derived_from,
        rehearsal_of: parse_optional_lineage(field(value, "rehearsal_of", what)?)?,
        performance_of: parse_optional_lineage(field(value, "performance_of", what)?)?,
        task_semantic_hash: text_field(value, "task_semantic_hash", what)?,
        idempotency_key: text_field(value, "idempotency_key", what)?,
        imported_evidence,
    })
}

fn parse_lineage(value: &Value) -> Result<LineageRef, ConnectorError> {
    Ok(LineageRef {
        attempt_id: text_field(value, "attempt_id", "lineage reference")?,
        kind: parse_attempt_kind(&text_field(value, "kind", "lineage reference")?)?,
    })
}

fn parse_optional_lineage(value: &Value) -> Result<Option<LineageRef>, ConnectorError> {
    if is_missing_envelope(value) {
        Ok(None)
    } else {
        parse_lineage(value).map(Some)
    }
}

fn parse_attempt_kind(text: &str) -> Result<AttemptKind, ConnectorError> {
    match text {
        "practice" => Ok(AttemptKind::Practice),
        "production" => Ok(AttemptKind::Production),
        other => Err(integrity(format!(
            "attempt kind {other:?} is not practice or production"
        ))),
    }
}

fn parse_target_class(text: &str) -> Result<TargetClass, ConnectorError> {
    match text {
        "fixture" => Ok(TargetClass::Fixture),
        "employer" => Ok(TargetClass::Employer),
        other => Err(integrity(format!(
            "target class {other:?} is not fixture or employer"
        ))),
    }
}

fn parse_evaluation_partition(text: &str) -> Result<EvaluationPartition, ConnectorError> {
    match text {
        "held_in" => Ok(EvaluationPartition::HeldIn),
        "held_out" => Ok(EvaluationPartition::HeldOut),
        other => Err(integrity(format!(
            "evaluation partition {other:?} is not held_in or held_out"
        ))),
    }
}

fn attempt_kind_str(kind: AttemptKind) -> &'static str {
    match kind {
        AttemptKind::Practice => "practice",
        AttemptKind::Production => "production",
    }
}

fn target_class_str(class: TargetClass) -> &'static str {
    match class {
        TargetClass::Fixture => "fixture",
        TargetClass::Employer => "employer",
    }
}

fn evaluation_partition_str(partition: EvaluationPartition) -> &'static str {
    match partition {
        EvaluationPartition::HeldIn => "held_in",
        EvaluationPartition::HeldOut => "held_out",
    }
}

fn attempt_json(attempt: &rm_lifecycle::AttemptContext) -> Value {
    json!({
        "attempt_id": attempt.attempt_id,
        "kind": attempt_kind_str(attempt.kind),
        "target_class": target_class_str(attempt.target_class),
        "target_id": attempt.target_id,
        "evaluation_partition": evaluation_partition_str(attempt.evaluation_partition),
    })
}
