//! `crawler_admission`: credit-before-wire admission and back-pressure.
//!
//! This module implements the crawler's admission seam (§21.2–§21.3,
//! [C35], [EXT-BOUNDS], [EK-ATOMICITY], [OWD-LOCAL-COMMIT]):
//!
//! * **Credit before wire.** [`Admission::reserve_response`] and
//!   [`Admission::reserve_page`] reserve bounded queue rows, queue bytes,
//!   durable response staging, and observation buffering before an
//!   output-producing request is dispatched. The returned credit carries
//!   that reservation as a checked record; dropping an unsettled credit
//!   releases it.
//! * **Independent control progress.** Control commands reserve from their
//!   own slot, CPU, and cold-bootstrap pools. Data saturation never consumes
//!   them, so a full data queue cannot block reserved control progress.
//! * **No capacity wait on commit.** [`Admission::settle_response`] commits
//!   the admitted input, idempotency key, outcome, and replayable response as
//!   one owner-local durable effect through [`OwnerStore::transact`] before it
//!   acknowledges. It never looks at free queue capacity, so an already
//!   admitted response commits its durable boundary while the data queue is
//!   full.
//! * **Bounded and honest.** Response bounds and admission capacities are
//!   finite and are never raised under pressure. Oversized decoded responses
//!   are rejected; rejected work is recorded with a fault code and bounded
//!   evidence instead of being silently dropped. Prolonged saturation permits
//!   deliberate quiescence after the configured grace period, and resume
//!   requires both row and byte occupancy below the resume watermark with a
//!   fresh generation.
//!
//! All clock observations come from a registered [`ClockAuthority`] on a
//! local monotonic clock. Records produced here validate through the closed
//! `crawler_schema` gate under `audit_log`; absent caller fields use typed
//! `Missing` envelopes, never bare JSON nulls.

use crawler_authority::Grant;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

/// Structural schema id for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Generated-reference staging reserved per admitted row.
pub const REFERENCE_OVERHEAD_BYTES_PER_ROW: u64 = 256;

/// Default data queue row bound (§21.3: 10,000 rows).
pub const DEFAULT_QUEUE_ROWS: u64 = 10_000;
/// Default explicit data queue byte bound.
pub const DEFAULT_QUEUE_BYTES: u64 = 256 * 1024 * 1024;
/// Default aggregate durable response staging bound.
pub const DEFAULT_STAGING_BYTES: u64 = 256 * 1024 * 1024;
/// Default observation buffering bound.
pub const DEFAULT_OBSERVATION_BYTES: u64 = 64 * 1024 * 1024;
/// Default maximum admitted response packet (§21.3: 64 MiB).
pub const DEFAULT_RESPONSE_BOUND_BYTES: u64 = 64 * 1024 * 1024;
/// Default streaming buffer (§21.3: 1 MiB).
pub const DEFAULT_STREAM_BUFFER_BYTES: u64 = 1024 * 1024;
/// Default concurrently admitted control commands per target.
pub const DEFAULT_CONTROL_SLOTS: u64 = 8;
/// Default control CPU capacity (in abstract units).
pub const DEFAULT_CONTROL_CPU_UNITS: u64 = 8;
/// CPU units consumed by one admitted control command.
pub const DEFAULT_CONTROL_CPU_PER_COMMAND: u64 = 1;
/// Default cold-bootstrap memory capacity reserved for control work.
pub const DEFAULT_COLD_BOOTSTRAP_BYTES: u64 = 32 * 1024 * 1024;
/// Cold-bootstrap memory consumed by one admitted control command.
pub const DEFAULT_BOOTSTRAP_BYTES_PER_COMMAND: u64 = 4 * 1024 * 1024;
/// Default deliberate-quiescence grace at prolonged saturation (§21.2).
pub const DEFAULT_SATURATION_GRACE_MS: u64 = 5_000;
/// Occupancy watermark required to resume after quiescence (§21.2).
pub const DEFAULT_RESUME_WATERMARK: f64 = 0.8;
/// Default bound on retained rejection evidence records.
pub const DEFAULT_REJECTION_EVIDENCE_BOUND: usize = 64;
/// Default finite local call bound recorded on every reservation.
pub const DEFAULT_CALL_BOUND_MS: u64 = 30_000;

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when a value is already a schema-gate `Missing` envelope.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn object_of<'a>(record: &'a CheckedRecord, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            format!("admission {what} must be a JSON object"),
        )
    })
}

/// An established nonnegative integer field, or `None` when absent/Missing.
fn u64_field(map: &Map<String, Value>, key: &str, what: &str) -> Result<Option<u64>, Fault> {
    match map.get(key) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::Number(number)) => match number.as_u64() {
            Some(0) | None => Err(fault(
                "invalid_request",
                format!("{what} field {key:?} must be a positive integer"),
            )),
            Some(value) => Ok(Some(value)),
        },
        Some(_) => Err(fault(
            "invalid_request",
            format!("{what} field {key:?} must be an integer or Missing envelope"),
        )),
    }
}

/// An established nonempty text field, or `None` when absent/Missing.
fn text_field<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<&'a str>, Fault> {
    match map.get(key) {
        None => Ok(None),
        Some(value) if is_missing(value) => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.as_str())),
        Some(_) => Err(fault(
            "invalid_request",
            format!("{what} field {key:?} must be a nonempty string or Missing envelope"),
        )),
    }
}

/// Caller identity for evidence: first established id field, else `Missing`.
fn caller_id(map: &Map<String, Value>) -> Result<Value, Fault> {
    for key in ["request_id", "scope_id", "task_id"] {
        if let Some(text) = text_field(map, key, "request")? {
            return Ok(Value::String(text.to_string()));
        }
    }
    Ok(missing(
        "not_observed",
        "caller record carried no request, scope, or task identifier",
    ))
}

fn target_of(map: &Map<String, Value>) -> Result<Value, Fault> {
    match text_field(map, "target", "request")? {
        Some(target) => Ok(Value::String(target.to_string())),
        None => Ok(missing(
            "not_observed",
            "caller record did not identify an active target",
        )),
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Deployment-declared admission bounds (§21.3). Every bound is explicit;
/// pressure never mutates or raises one.
#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionConfig {
    /// Data queue row bound.
    pub queue_rows: u64,
    /// Explicit data queue byte bound.
    pub queue_bytes: u64,
    /// Aggregate durable response staging bound.
    pub staging_bytes: u64,
    /// Aggregate observation buffering bound.
    pub observation_bytes: u64,
    /// Maximum admitted response packet; oversized decoded responses are
    /// rejected rather than raising this bound.
    pub response_bound_bytes: u64,
    /// Streaming buffer unit.
    pub stream_buffer_bytes: u64,
    /// Independently reserved concurrent control commands per target.
    pub control_slots: u64,
    /// Independently reserved control CPU capacity.
    pub control_cpu_units: u64,
    /// CPU units one admitted control command consumes.
    pub control_cpu_per_command: u64,
    /// Independently reserved cold-bootstrap memory capacity.
    pub cold_bootstrap_bytes: u64,
    /// Cold-bootstrap memory one admitted control command consumes.
    pub bootstrap_bytes_per_command: u64,
    /// Deliberate-quiescence grace at prolonged saturation.
    pub saturation_grace_ms: u64,
    /// Occupancy watermark required to resume after quiescence.
    pub resume_watermark: f64,
    /// Retained rejection evidence records (the total counter is unbounded
    /// in the sense that it is a counter, not growth).
    pub rejection_evidence_bound: usize,
    /// Finite local call bound recorded on each reservation.
    pub call_bound_ms: u64,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            queue_rows: DEFAULT_QUEUE_ROWS,
            queue_bytes: DEFAULT_QUEUE_BYTES,
            staging_bytes: DEFAULT_STAGING_BYTES,
            observation_bytes: DEFAULT_OBSERVATION_BYTES,
            response_bound_bytes: DEFAULT_RESPONSE_BOUND_BYTES,
            stream_buffer_bytes: DEFAULT_STREAM_BUFFER_BYTES,
            control_slots: DEFAULT_CONTROL_SLOTS,
            control_cpu_units: DEFAULT_CONTROL_CPU_UNITS,
            control_cpu_per_command: DEFAULT_CONTROL_CPU_PER_COMMAND,
            cold_bootstrap_bytes: DEFAULT_COLD_BOOTSTRAP_BYTES,
            bootstrap_bytes_per_command: DEFAULT_BOOTSTRAP_BYTES_PER_COMMAND,
            saturation_grace_ms: DEFAULT_SATURATION_GRACE_MS,
            resume_watermark: DEFAULT_RESUME_WATERMARK,
            rejection_evidence_bound: DEFAULT_REJECTION_EVIDENCE_BOUND,
            call_bound_ms: DEFAULT_CALL_BOUND_MS,
        }
    }
}

impl AdmissionConfig {
    /// Reject a deployment declaration that cannot express finite bounds.
    pub fn validate(&self) -> Result<(), Fault> {
        for (name, value) in [
            ("queue_rows", self.queue_rows),
            ("queue_bytes", self.queue_bytes),
            ("staging_bytes", self.staging_bytes),
            ("observation_bytes", self.observation_bytes),
            ("response_bound_bytes", self.response_bound_bytes),
            ("stream_buffer_bytes", self.stream_buffer_bytes),
            ("control_slots", self.control_slots),
            ("control_cpu_units", self.control_cpu_units),
            ("control_cpu_per_command", self.control_cpu_per_command),
            ("cold_bootstrap_bytes", self.cold_bootstrap_bytes),
            (
                "bootstrap_bytes_per_command",
                self.bootstrap_bytes_per_command,
            ),
            ("saturation_grace_ms", self.saturation_grace_ms),
            ("call_bound_ms", self.call_bound_ms),
        ] {
            if value == 0 {
                return Err(fault(
                    "invalid_configuration",
                    format!("admission bound {name} must be positive"),
                ));
            }
        }
        if self.rejection_evidence_bound == 0 {
            return Err(fault(
                "invalid_configuration",
                "rejection_evidence_bound must retain at least one record",
            ));
        }
        if !self.resume_watermark.is_finite()
            || self.resume_watermark <= 0.0
            || self.resume_watermark >= 1.0
        {
            return Err(fault(
                "invalid_configuration",
                "resume_watermark must be finite and strictly between 0 and 1",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Credits and permits
// ---------------------------------------------------------------------------

/// Reservation for one output-producing response.
///
/// The reservation record names the reserved rows, bytes, durable staging,
/// observation buffering, registered clock instant, and finite deadline.
/// Dropping an unsettled credit releases its reservation and records a
/// cancellation; [`Admission::settle_response`] consumes it and commits the
/// durable boundary.
#[derive(Debug)]
pub struct ResponseCredit {
    /// The admitted reservation, validated under `audit_log`.
    pub reservation: CheckedRecord,
    ledger: Arc<Mutex<AdmissionState>>,
    released: bool,
}

impl Drop for ResponseCredit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.ledger.lock() {
            release_reservation(&mut state, &self.reservation);
            state.cancelled_total += 1;
        }
        self.released = true;
    }
}

/// Independently reserved control command credit.
#[derive(Debug)]
pub struct ControlCredit {
    /// The admitted reservation, validated under `audit_log`.
    pub reservation: CheckedRecord,
    ledger: Arc<Mutex<AdmissionState>>,
    released: bool,
}

impl Drop for ControlCredit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.ledger.lock() {
            release_reservation(&mut state, &self.reservation);
            state.cancelled_total += 1;
        }
        self.released = true;
    }
}

/// Reservation for one page request, data or control.
#[derive(Debug)]
pub struct PagePermit {
    /// The admitted reservation, validated under `audit_log`.
    pub reservation: CheckedRecord,
    ledger: Arc<Mutex<AdmissionState>>,
    released: bool,
}

impl Drop for PagePermit {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        if let Ok(mut state) = self.ledger.lock() {
            release_reservation(&mut state, &self.reservation);
            state.cancelled_total += 1;
        }
        self.released = true;
    }
}

/// Credit-before-wire admission seam.
pub trait Admission: Send + Sync {
    /// Reserve queue rows, bytes, durable response staging, and observation
    /// buffering for the maximum admitted packet before dispatching an
    /// output-producing request. Rejects when data admission pauses.
    fn reserve_response(&self, request: &CheckedRecord) -> Result<ResponseCredit, Fault>;
    /// Reserve independent control command, CPU, and cold-bootstrap capacity.
    /// Never contends with data queue capacity.
    fn reserve_control(&self, scope: &CheckedRecord) -> Result<ControlCredit, Fault>;
    /// Reserve one page request. `control = true` draws only on the
    /// independent control pools; `control = false` draws on data capacity.
    fn reserve_page(&self, scope: &CheckedRecord, control: bool) -> Result<PagePermit, Fault>;
    /// Commit the admitted response's durable boundary before acknowledging.
    /// The commit never waits for new queue capacity.
    fn settle_response(&self, credit: ResponseCredit, outcome: &CheckedRecord)
        -> Result<(), Fault>;
}

// ---------------------------------------------------------------------------
// Counters and saturation state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct AdmissionState {
    rows_used: u64,
    bytes_used: u64,
    staging_used: u64,
    observation_used: u64,
    control_slots_used: u64,
    control_cpu_used: u64,
    cold_bootstrap_used: u64,
    committed_total: u64,
    cancelled_total: u64,
    rejected_total: u64,
    generation: u64,
    next_credit_id: u64,
    saturated_since_ms: Option<f64>,
    quiescent: bool,
    rejections: VecDeque<Value>,
}

impl Default for AdmissionState {
    fn default() -> Self {
        Self {
            rows_used: 0,
            bytes_used: 0,
            staging_used: 0,
            observation_used: 0,
            control_slots_used: 0,
            control_cpu_used: 0,
            cold_bootstrap_used: 0,
            committed_total: 0,
            cancelled_total: 0,
            rejected_total: 0,
            generation: 0,
            next_credit_id: 0,
            saturated_since_ms: None,
            quiescent: false,
            rejections: VecDeque::new(),
        }
    }
}

/// Snapshot of admission occupancy and evidence counters.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AdmissionStats {
    pub rows_used: u64,
    pub bytes_used: u64,
    pub staging_used: u64,
    pub observation_used: u64,
    pub control_slots_used: u64,
    pub control_cpu_used: u64,
    pub cold_bootstrap_used: u64,
    pub committed_total: u64,
    pub cancelled_total: u64,
    pub rejected_total: u64,
    pub generation: u64,
    pub saturated_since_ms: Option<f64>,
    pub quiescent: bool,
}

fn u64_of(value: &Value, key: &str) -> u64 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn release_reservation(state: &mut AdmissionState, reservation: &CheckedRecord) {
    let value = record_value(reservation);
    state.rows_used = state.rows_used.saturating_sub(u64_of(value, "queue_rows"));
    state.bytes_used = state
        .bytes_used
        .saturating_sub(u64_of(value, "queue_bytes"));
    state.staging_used = state
        .staging_used
        .saturating_sub(u64_of(value, "staging_bytes"));
    state.observation_used = state
        .observation_used
        .saturating_sub(u64_of(value, "observation_bytes"));
    state.control_slots_used = state
        .control_slots_used
        .saturating_sub(u64_of(value, "control_slots"));
    state.control_cpu_used = state
        .control_cpu_used
        .saturating_sub(u64_of(value, "cpu_units"));
    state.cold_bootstrap_used = state
        .cold_bootstrap_used
        .saturating_sub(u64_of(value, "cold_bootstrap_bytes"));
}

fn below_resume_watermark(config: &AdmissionConfig, state: &AdmissionState) -> bool {
    (state.rows_used as f64) < config.queue_rows as f64 * config.resume_watermark
        && (state.bytes_used as f64) < config.queue_bytes as f64 * config.resume_watermark
}

fn refresh_saturation(config: &AdmissionConfig, state: &mut AdmissionState, now_ms: f64) {
    if state.quiescent {
        if below_resume_watermark(config, state) {
            state.generation += 1;
            state.quiescent = false;
            state.saturated_since_ms = None;
        }
        return;
    }

    let rows_full = state.rows_used >= config.queue_rows;
    let bytes_full = state.bytes_used >= config.queue_bytes;
    if rows_full || bytes_full {
        let since = *state.saturated_since_ms.get_or_insert(now_ms);
        if now_ms - since >= config.saturation_grace_ms as f64 {
            state.quiescent = true;
        }
    } else {
        state.saturated_since_ms = None;
    }
}

fn deadline_after(now: &CheckedRecord, bound_ms: u64) -> Result<Value, Fault> {
    let mut value = record_value(now).clone();
    let map = value.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_clock",
            "clock authority must report a TimePoint object",
        )
    })?;
    let offset = map
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite())
        .ok_or_else(|| {
            fault(
                "invalid_clock",
                "clock authority TimePoint has no finite monotonic_offset_ms",
            )
        })?;
    map.insert(
        "monotonic_offset_ms".to_string(),
        json!(offset + bound_ms as f64),
    );
    Ok(value)
}

// ---------------------------------------------------------------------------
// In-memory admission
// ---------------------------------------------------------------------------

/// Owner-local credit-before-wire admission manager.
///
/// One instance belongs to one owner: it holds that owner's [`Grant`] and
/// commits settlements through the owner's [`OwnerStore`]. It holds no peer
/// lock and performs no cross-owner transaction.
pub struct MemoryAdmission {
    config: Arc<AdmissionConfig>,
    clock: Arc<dyn ClockAuthority>,
    store: Arc<dyn OwnerStore>,
    grant: Grant,
    state: Arc<Mutex<AdmissionState>>,
}

impl MemoryAdmission {
    /// Build admission around one admitted owner grant, its durability seam,
    /// and the registered local clock.
    pub fn new(
        config: AdmissionConfig,
        clock: Arc<dyn ClockAuthority>,
        store: Arc<dyn OwnerStore>,
        grant: Grant,
    ) -> Result<Self, Fault> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            clock,
            store,
            grant,
            state: Arc::new(Mutex::new(AdmissionState::default())),
        })
    }

    /// The deployment declaration this admission enforces.
    pub fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, AdmissionState>, Fault> {
        self.state.lock().map_err(|_| {
            fault(
                "internal_error",
                "admission state lock poisoned by an earlier panic",
            )
        })
    }

    fn now(&self) -> Result<(CheckedRecord, f64), Fault> {
        let now = self.clock.now()?;
        let map = record_value(&now).as_object().ok_or_else(|| {
            fault(
                "invalid_clock",
                "clock authority must report a TimePoint object",
            )
        })?;
        for field in [
            "clock_id",
            "boot_id",
            "origin",
            "monotonic_offset_ms",
            "utc_annotation",
        ] {
            if !map.contains_key(field) {
                return Err(fault(
                    "invalid_clock",
                    format!("clock authority TimePoint is missing {field:?}"),
                ));
            }
        }
        let offset = map
            .get("monotonic_offset_ms")
            .and_then(Value::as_f64)
            .filter(|offset| offset.is_finite())
            .ok_or_else(|| {
                fault(
                    "invalid_clock",
                    "clock authority TimePoint has no finite monotonic_offset_ms",
                )
            })?;
        Ok((now, offset))
    }

    /// Occupancy and evidence snapshot.
    pub fn stats(&self) -> Result<AdmissionStats, Fault> {
        let state = self.lock_state()?;
        Ok(AdmissionStats {
            rows_used: state.rows_used,
            bytes_used: state.bytes_used,
            staging_used: state.staging_used,
            observation_used: state.observation_used,
            control_slots_used: state.control_slots_used,
            control_cpu_used: state.control_cpu_used,
            cold_bootstrap_used: state.cold_bootstrap_used,
            committed_total: state.committed_total,
            cancelled_total: state.cancelled_total,
            rejected_total: state.rejected_total,
            generation: state.generation,
            saturated_since_ms: state.saturated_since_ms,
            quiescent: state.quiescent,
        })
    }

    /// Retention-bounded rejection evidence, newest last. The total counter
    /// in [`MemoryAdmission::stats`] is authoritative; retained evidence is
    /// capped at `rejection_evidence_bound`.
    pub fn rejections(&self) -> Result<Vec<CheckedRecord>, Fault> {
        let state = self.lock_state()?;
        state
            .rejections
            .iter()
            .map(|value| {
                validate(OUTPUT_SCHEMA, value.clone()).map_err(|_| {
                    fault(
                        "internal_error",
                        "retained rejection evidence no longer validates",
                    )
                })
            })
            .collect()
    }

    /// Re-evaluate saturation against the registered clock. Marks deliberate
    /// quiescence after the configured grace, and retires quiescence (with a
    /// fresh generation) once both row and byte occupancy fall below the
    /// resume watermark.
    pub fn poll_saturation(&self) -> Result<(), Fault> {
        let (_, now_ms) = self.now()?;
        let mut state = self.lock_state()?;
        refresh_saturation(&self.config, &mut state, now_ms);
        Ok(())
    }

    /// Whether a reservation's recorded finite call bound has elapsed.
    pub fn reservation_expired(&self, reservation: &CheckedRecord) -> Result<bool, Fault> {
        let deadline = record_value(reservation)
            .get("deadline")
            .cloned()
            .ok_or_else(|| fault("invalid_reservation", "reservation carries no deadline"))?;
        let deadline = validate(OUTPUT_SCHEMA, deadline)?;
        let (now, _) = self.now()?;
        Ok(compare_deadline(&now, &deadline)? == Ordering::Greater)
    }

    fn record_rejection(&self, kind: &str, error: &Fault, subject: Option<&CheckedRecord>) {
        let rejected_at = match self.clock.now() {
            Ok(now) => record_value(&now).clone(),
            Err(_) => missing(
                "observation_lost",
                "registered clock unavailable while recording the rejection",
            ),
        };
        let subject = match subject {
            Some(record) => record_value(record).clone(),
            None => missing(
                "not_observed",
                "the rejected call carried no checked record",
            ),
        };
        let evidence = validate(
            OUTPUT_SCHEMA,
            json!({
                "kind": "admission_rejection",
                "reservation_kind": kind,
                "code": error.code,
                "detail": error.detail,
                "subject": subject,
                "rejected_at": rejected_at,
            }),
        );
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        state.rejected_total += 1;
        if let Ok(evidence) = evidence {
            while state.rejections.len() >= self.config.rejection_evidence_bound {
                state.rejections.pop_front();
            }
            state.rejections.push_back(record_value(&evidence).clone());
        }
    }

    /// Reserve bounded data capacity for one output-producing unit.
    fn reserve_data(
        &self,
        kind: &str,
        caller: &Map<String, Value>,
        rows: u64,
        bytes: u64,
        observation: u64,
        subject: Option<&CheckedRecord>,
    ) -> Result<CheckedRecord, Fault> {
        if bytes > self.config.response_bound_bytes {
            let error = fault(
                "response_limit_exceeded",
                format!(
                    "requested packet of {bytes} bytes exceeds the declared response bound of {} bytes; the bound is never raised",
                    self.config.response_bound_bytes
                ),
            );
            self.record_rejection(kind, &error, subject);
            return Err(error);
        }

        let reference_bytes = rows
            .checked_mul(REFERENCE_OVERHEAD_BYTES_PER_ROW)
            .ok_or_else(|| fault("invalid_request", "reference staging reservation overflow"))?;
        let staging = bytes
            .checked_add(reference_bytes)
            .ok_or_else(|| fault("invalid_request", "staging reservation overflow"))?;

        if rows > self.config.queue_rows
            || bytes > self.config.queue_bytes
            || staging > self.config.staging_bytes
            || observation > self.config.observation_bytes
        {
            let error = fault(
                "request_exceeds_capacity",
                format!(
                    "reservation rows={rows} bytes={bytes} staging={staging} observation={observation} cannot fit the declared capacities"
                ),
            );
            self.record_rejection(kind, &error, subject);
            return Err(error);
        }

        let (now, now_ms) = self.now()?;
        let reservation = {
            let mut state = self.lock_state()?;
            refresh_saturation(&self.config, &mut state, now_ms);

            let denial = if state.quiescent {
                Some(fault(
                    "quiescent",
                    "data admission is deliberately quiescent after prolonged saturation",
                ))
            } else if state.rows_used.saturating_add(rows) > self.config.queue_rows {
                Some(fault(
                    "backpressure_rows",
                    format!(
                        "data queue row capacity is reserved: {} of {} rows are in flight",
                        state.rows_used, self.config.queue_rows
                    ),
                ))
            } else if state.bytes_used.saturating_add(bytes) > self.config.queue_bytes {
                Some(fault(
                    "backpressure_bytes",
                    format!(
                        "data queue byte capacity is reserved: {} of {} bytes are in flight",
                        state.bytes_used, self.config.queue_bytes
                    ),
                ))
            } else if state.staging_used.saturating_add(staging) > self.config.staging_bytes {
                Some(fault(
                    "backpressure_staging",
                    format!(
                        "durable response staging is reserved: {} of {} bytes are in flight",
                        state.staging_used, self.config.staging_bytes
                    ),
                ))
            } else if state.observation_used.saturating_add(observation)
                > self.config.observation_bytes
            {
                Some(fault(
                    "backpressure_observation",
                    format!(
                        "observation buffering is reserved: {} of {} bytes are in flight",
                        state.observation_used, self.config.observation_bytes
                    ),
                ))
            } else {
                None
            };

            match denial {
                Some(error) => Err(error),
                None => {
                    let next_id = state.next_credit_id + 1;
                    let reservation = validate(
                        OUTPUT_SCHEMA,
                        json!({
                            "kind": kind,
                            "credit_id": format!("{kind}-{next_id}"),
                            "caller_id": caller_id(caller)?,
                            "target": target_of(caller)?,
                            "queue_rows": rows,
                            "queue_bytes": bytes,
                            "staging_bytes": staging,
                            "observation_bytes": observation,
                            "max_packet_rows": rows,
                            "max_packet_bytes": bytes,
                            "response_bound_bytes": self.config.response_bound_bytes,
                            "stream_buffer_bytes": self.config.stream_buffer_bytes,
                            "generation": state.generation,
                            "reserved_at": record_value(&now),
                            "deadline": deadline_after(&now, self.config.call_bound_ms)?,
                        }),
                    )?;
                    state.next_credit_id = next_id;
                    state.rows_used += rows;
                    state.bytes_used += bytes;
                    state.staging_used += staging;
                    state.observation_used += observation;
                    Ok(reservation)
                }
            }
        };

        match reservation {
            Ok(reservation) => Ok(reservation),
            Err(error) => {
                self.record_rejection(kind, &error, subject);
                Err(error)
            }
        }
    }

    /// Reserve independent control capacity for one command or control page.
    fn reserve_control_pools(
        &self,
        kind: &str,
        caller: &Map<String, Value>,
        subject: Option<&CheckedRecord>,
    ) -> Result<CheckedRecord, Fault> {
        let (now, now_ms) = self.now()?;
        let reservation = {
            let mut state = self.lock_state()?;
            refresh_saturation(&self.config, &mut state, now_ms);

            let denial = if state.control_slots_used.saturating_add(1) > self.config.control_slots {
                Some(fault(
                    "control_capacity_exhausted",
                    format!(
                        "control command capacity is reserved: {} of {} slots are in flight",
                        state.control_slots_used, self.config.control_slots
                    ),
                ))
            } else if state
                .control_cpu_used
                .saturating_add(self.config.control_cpu_per_command)
                > self.config.control_cpu_units
            {
                Some(fault(
                    "control_cpu_capacity_exhausted",
                    "independently reserved control CPU is exhausted",
                ))
            } else if state
                .cold_bootstrap_used
                .saturating_add(self.config.bootstrap_bytes_per_command)
                > self.config.cold_bootstrap_bytes
            {
                Some(fault(
                    "cold_bootstrap_capacity_exhausted",
                    "independently reserved cold-bootstrap memory is exhausted",
                ))
            } else {
                None
            };

            match denial {
                Some(error) => Err(error),
                None => {
                    let next_id = state.next_credit_id + 1;
                    let reservation = validate(
                        OUTPUT_SCHEMA,
                        json!({
                            "kind": kind,
                            "credit_id": format!("{kind}-{next_id}"),
                            "caller_id": caller_id(caller)?,
                            "target": target_of(caller)?,
                            "queue_rows": 0,
                            "queue_bytes": 0,
                            "staging_bytes": 0,
                            "observation_bytes": 0,
                            "control_slots": 1,
                            "cpu_units": self.config.control_cpu_per_command,
                            "cold_bootstrap_bytes": self.config.bootstrap_bytes_per_command,
                            "generation": state.generation,
                            "reserved_at": record_value(&now),
                            "deadline": deadline_after(&now, self.config.call_bound_ms)?,
                        }),
                    )?;
                    state.next_credit_id = next_id;
                    state.control_slots_used += 1;
                    state.control_cpu_used += self.config.control_cpu_per_command;
                    state.cold_bootstrap_used += self.config.bootstrap_bytes_per_command;
                    Ok(reservation)
                }
            }
        };

        match reservation {
            Ok(reservation) => Ok(reservation),
            Err(error) => {
                self.record_rejection(kind, &error, subject);
                Err(error)
            }
        }
    }

    fn settle(&self, mut credit: ResponseCredit, outcome: &CheckedRecord) -> Result<(), Fault> {
        if !Arc::ptr_eq(&credit.ledger, &self.state) {
            let error = fault(
                "foreign_credit",
                "response credit belongs to a different owner-local admission ledger and cannot be settled here",
            );
            self.record_rejection("response", &error, Some(outcome));
            return Err(error);
        }

        let reservation = record_value(&credit.reservation);
        let reserved_bound = reservation
            .get("response_bound_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(self.config.response_bound_bytes);
        let reserved_packet = reservation
            .get("max_packet_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);

        if let Some(outcome_map) = record_value(outcome).as_object() {
            let decoded = match outcome_map.get("decoded_bytes") {
                None => None,
                Some(value) if is_missing(value) => None,
                Some(Value::Number(number)) => number.as_u64(),
                Some(_) => {
                    let error = fault(
                        "invalid_outcome",
                        "outcome decoded_bytes must be an integer or Missing envelope",
                    );
                    self.record_rejection("response", &error, Some(outcome));
                    return Err(error);
                }
            };
            if let Some(decoded) = decoded {
                if decoded > reserved_packet || decoded > reserved_bound {
                    let error = fault(
                        "response_limit_exceeded",
                        format!(
                            "decoded response of {decoded} bytes exceeds the admitted reservation of {reserved_packet} bytes (response bound {reserved_bound}); the response is rejected, not re-reserved"
                        ),
                    );
                    self.record_rejection("response", &error, Some(outcome));
                    return Err(error);
                }
            }
        }

        let (now, now_ms) = match self.now() {
            Ok(point) => point,
            Err(error) => {
                self.record_rejection("response", &error, Some(outcome));
                return Err(error);
            }
        };

        // One owner-local durable effect: admitted input, idempotency key,
        // authoritative outcome, and replayable response. No queue capacity is
        // consulted and no peer lock is acquired.
        let transaction = validate(
            OUTPUT_SCHEMA,
            json!({
                "operation": "settle_response",
                "credit_id": reservation.get("credit_id").cloned().unwrap_or_else(|| {
                    missing("not_observed", "reservation carried no credit identifier")
                }),
                "idempotency_key": reservation.get("credit_id").cloned().unwrap_or_else(|| {
                    missing("not_observed", "reservation carried no credit identifier")
                }),
                "reservation": reservation.clone(),
                "outcome": record_value(outcome),
                "replay": {
                    "reservation": reservation.clone(),
                    "outcome": record_value(outcome),
                },
                "settled_at": record_value(&now),
            }),
        )?;

        let receipt = match self.store.transact(&self.grant, &transaction) {
            Ok(receipt) => receipt,
            Err(error) => {
                self.record_rejection("response", &error, Some(outcome));
                return Err(error);
            }
        };

        if record_value(&receipt).get("durable") == Some(&Value::Bool(false)) {
            let error = fault(
                "not_durable",
                "owner store returned a non-durable receipt; the response boundary is not acknowledged",
            );
            self.record_rejection("response", &error, Some(outcome));
            return Err(error);
        }

        {
            let mut state = self.lock_state()?;
            release_reservation(&mut state, &credit.reservation);
            state.committed_total += 1;
            refresh_saturation(&self.config, &mut state, now_ms);
        }
        credit.released = true;
        Ok(())
    }
}

impl Admission for MemoryAdmission {
    fn reserve_response(&self, request: &CheckedRecord) -> Result<ResponseCredit, Fault> {
        let map = object_of(request, "request")?;
        let rows = u64_field(map, "max_packet_rows", "request")?.unwrap_or(1);
        let bytes = u64_field(map, "max_packet_bytes", "request")?
            .unwrap_or(self.config.response_bound_bytes);
        let observation = u64_field(map, "observation_bytes", "request")?
            .unwrap_or_else(|| bytes.min(self.config.stream_buffer_bytes));
        let reservation =
            self.reserve_data("response", map, rows, bytes, observation, Some(request))?;
        Ok(ResponseCredit {
            reservation,
            ledger: Arc::clone(&self.state),
            released: false,
        })
    }

    fn reserve_control(&self, scope: &CheckedRecord) -> Result<ControlCredit, Fault> {
        let map = object_of(scope, "scope")?;
        let reservation = self.reserve_control_pools("control", map, Some(scope))?;
        Ok(ControlCredit {
            reservation,
            ledger: Arc::clone(&self.state),
            released: false,
        })
    }

    fn reserve_page(&self, scope: &CheckedRecord, control: bool) -> Result<PagePermit, Fault> {
        let map = object_of(scope, "scope")?;
        if control {
            let reservation = self.reserve_control_pools("page_control", map, Some(scope))?;
            return Ok(PagePermit {
                reservation,
                ledger: Arc::clone(&self.state),
                released: false,
            });
        }
        let rows = u64_field(map, "page_rows", "scope")?.unwrap_or(1);
        let bytes =
            u64_field(map, "page_bytes", "scope")?.unwrap_or(self.config.stream_buffer_bytes);
        let observation = u64_field(map, "observation_bytes", "scope")?
            .unwrap_or_else(|| bytes.min(self.config.stream_buffer_bytes));
        let reservation = self.reserve_data("page", map, rows, bytes, observation, Some(scope))?;
        Ok(PagePermit {
            reservation,
            ledger: Arc::clone(&self.state),
            released: false,
        })
    }

    fn settle_response(
        &self,
        credit: ResponseCredit,
        outcome: &CheckedRecord,
    ) -> Result<(), Fault> {
        self.settle(credit, outcome)
    }
}
