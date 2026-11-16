//! `crawler_observe`: fixed-prefix observation pages and native-report normalization.
//!
//! Implements Contract 02 §19.5 (`EXT-OBSERVE`, `EXT-NORMALIZE`, `EXT-EVIDENCE`)
//! over the owner-local journal seam:
//!
//! * [`observe`] returns registered connector observation projections in
//!   journal order for exactly the requested handle, through a fixed prefix:
//!   `after < item.sequence <= next <= through`. `next` names the last
//!   *scanned* journal position, including non-observation events — not merely
//!   the last returned item. `has_more` is exactly
//!   `next.sequence < through.last_sequence`. A fixed `through` requires
//!   `wait_limit.value == 0`; a live (`not_applicable`) `through` pins the
//!   current durable head and returns immediately (zero wait). An empty page
//!   at the cutoff is legitimate and never implies native termination or
//!   absence of future callbacks. Lost/unavailable cursor history is an
//!   explicit fault, never a silent skip. Oversized items are never dropped:
//!   pagination is by `max_items` count only, and a matching item is always
//!   returned whole.
//! * [`normalize_native_report`] retains exact native bytes before
//!   interpretation, then authenticates source and correlates to the attempt
//!   as independent checks. Anything other than `verified` + `matched`
//!   yields zero accepted execution claims. A trace mismatch does not block
//!   an independently evidenced alternate correlation. Discovery claims
//!   never carry application assertions, and lifecycle publications are never
//!   fabricated.
//!
//! # Handle-scoped projection convention
//!
//! The journal seam stores generic `JournalEnvelope`s. An envelope is a
//!! connector observation for a handle iff `payload.data` is an object whose
//!! `handle` equals the requested `{connector_id, local_handle}`. Every
//!! journaled event is registry-validated by construction (the store admits
//!//! only manifest-registered kinds via `authorize_producer`), so the handle
//!//! equality is the only additional projection filter. `manifest_admitted`
//!//! carries no handle and is therefore never an observation; it still
//!//! advances the scanned cursor. [`observe`] copies — never synthesizes —
//!//! the projection: `event_ref`, `recorded_at`, `provenance`, `payload`
//!//! (`payload.data` verbatim), `measurements`, and `artifact_refs` all equal
//!//! the referenced envelope.
//!
//! # Record shapes
//!
//! All inputs are [`CheckedRecord`]s (no bare nulls). The structural envelope
//!//! is `"audit_log"`.
//!
//! * `ObserveRequest`: `{handle, after, through, max_items, wait_limit}`.
//!!  `handle` is `{connector_id, local_handle}`. `after`/`next` are
//!//!  `ObservationCursor`s `{handle, journal_id, sequence, event_hash}` with
//!//!  `sequence == 0` iff `event_hash` is `Missing(not_applicable)`.
//!//!  `through` is a `JournalPrefix` `{journal_id, last_sequence, head_hash}`
//!//!  or `Missing(not_applicable)` for a live cutoff. `max_items` is a
//!//!  positive integer; `wait_limit` is `{kind: exact, unit: ms, value >= 0}`.
//! * `ObservationPage`: `{kind: observation_page, handle, after, through,
//!//!  next, has_more, observation_close_ref, items, limitations}`.
//! * `ObservationItem`: `{event_ref, recorded_at, provenance, payload,
//!//!  measurements, artifact_refs}` with `event_ref.pointer == ""`.
//! * Native report (for [`normalize_native_report`]): `{raw_body, media_type?,
//!//!  restricted?, channel, source_event, source_checks, mapping,
//!//!  limitations?, claim_id?, scope?, native_state?, native_run_id?,
//!//!  native_message_id?, made_at?, received_at?, application_assertions?}`.
//!//!  See the function docs for the claim-derivation rules.
//!
//! Fault codes are snake_case. Store faults (`unknown_journal`,
//!//! `unauthorized_owner`, ...) propagate unchanged; cursor/cutoff faults are
//!//! `handle_mismatch`, `journal_mismatch`, `invalid_cursor`,
//!//! `cursor_mismatch`, `cursor_beyond_cutoff`, `cursor_history_lost`,
//!//! `invalid_through`, `unknown_cutoff`, `cutoff_mismatch`,
//!//! `wait_not_allowed_with_fixed_cutoff`, `invalid_max_items`,
//!//! `invalid_wait_limit`, and `invalid_request`. Normalization faults are
//!//! `invalid_report`, `missing_raw_body`, `unknown_channel`,
//!//! `missing_source_event`, `invalid_evidence_ref`,
//!//! `evidence_not_registered`, `invalid_source_checks`, `invalid_mapping`,
//!//! `missing_claim_field`, and `application_assertions_refused`.

use crawler_artifacts::ArtifactStore;
use crawler_authority::Grant;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Closed vocabularies and constants
// ---------------------------------------------------------------------------

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

const NULL_REASONS: &[&str] = &[
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

const CHANNELS: &[&str] = &["terminal_response", "callback", "native_stream"];

const AUTH_VALUES: &[&str] = &["verified", "failed", "unknown"];
const CORR_VALUES: &[&str] = &["matched", "mismatched", "unknown"];
const TRACE_VALUES: &[&str] = &["matched", "mismatched", "not_observed", "not_applicable"];
const SCOPE_VALUES: &[&str] = &[
    "primitive",
    "application_postcondition",
    "execution_lifecycle",
    "unknown",
];

// Native states that are explicit non-success: they map to an explicit
// `unknown` claim state, never to `completed`.
const NON_SUCCESS_NATIVE: &[&str] = &[
    "none",
    "acknowledged",
    "acknowledgement",
    "ack",
    "http_success",
    "http_ok",
    "http_200",
    "protocol_ack",
];

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
/// The schema gate has already validated the envelope shape.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn missing_reason(value: &Value) -> Option<&str> {
    value
        .as_object()
        .and_then(|map| map.get("reason"))
        .and_then(Value::as_str)
}

fn is_inapplicable(value: &Value) -> bool {
    is_missing(value) && missing_reason(value) == Some("not_applicable")
}

fn missing_envelope(reason: &str, detail: &str) -> Value {
    debug_assert!(NULL_REASONS.contains(&reason));
    serde_json::json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// Canonical digest text: exactly 64 lowercase hex characters.
fn is_digest_text(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// JSON pointer: empty string or `/`-prefixed reference tokens.
fn is_json_pointer(pointer: &str) -> bool {
    if pointer.is_empty() {
        return true;
    }
    if !pointer.starts_with('/') {
        return false;
    }
    let mut chars = pointer.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') | Some('1') => {}
                _ => return false,
            }
        }
    }
    true
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} must be an object"),
        )
    })
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|v| !is_missing(v))
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.as_str()),
        Some(Value::String(_)) => Err(fault(
            code,
            format!("{what}.{field} must be a nonempty string"),
        )),
        Some(_) => Err(fault(
            code,
            format!("{what}.{field} must be a string"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established {field:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(n)) if n.is_u64() => Ok(n.as_u64().unwrap_or(0)),
        Some(Value::Number(_)) => Err(fault(
            code,
            format!("{what}.{field} must be an unsigned integer, not a float or negative"),
        )),
        Some(_) => Err(fault(
            code,
            format!("{what}.{field} must be an unsigned integer"),
        )),
        None => Err(fault(
            code,
            format!("{what} requires established {field:?}"),
        )),
    }
}

fn required_seq_number(value: &Value, what: &str) -> Result<u64, Fault> {
    match value {
        Value::Number(n) if n.is_u64() => Ok(n.as_u64().unwrap_or(0)),
        Value::Number(_) => Err(fault(
            "invalid_request",
            format!("{what} must be an unsigned integer, not a float or negative"),
        )),
        _ => Err(fault(
            "invalid_request",
            format!("{what} must be an unsigned integer"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Observe request parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct Handle {
    connector_id: String,
    local_handle: String,
}

fn parse_handle(value: &Value, what: &str) -> Result<Handle, Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            format!("{what} must be a HandleReference object"),
        )
    })?;
    let connector_id = required_str(map, "connector_id", "invalid_request", what)?.to_string();
    let local_handle = required_str(map, "local_handle", "invalid_request", what)?.to_string();
    Ok(Handle {
        connector_id,
        local_handle,
    })
}

fn handle_value(handle: &Handle) -> Value {
    serde_json::json!({
        "connector_id": handle.connector_id,
        "local_handle": handle.local_handle,
    })
}

struct Cursor {
    handle: Handle,
    journal_id: String,
    sequence: u64,
    /// Established digest when `sequence > 0`; `None` when `sequence == 0`.
    event_hash: Option<String>,
}

fn parse_cursor(value: &Value, what: &str) -> Result<Cursor, Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_cursor",
            format!("{what} must be an ObservationCursor object"),
        )
    })?;
    let handle_value = map.get("handle").ok_or_else(|| {
        fault(
            "invalid_cursor",
            format!("{what} requires handle"),
        )
    })?;
    let handle = parse_handle(handle_value, &format!("{what}.handle")).map_err(|e| {
        fault(
            "invalid_cursor",
            format!("{}: {} ({})", what, e.code, e.detail),
        )
    })?;
    let journal_id = required_str(map, "journal_id", "invalid_cursor", what)?.to_string();
    let sequence_value = map.get("sequence").ok_or_else(|| {
        fault(
            "invalid_cursor",
            format!("{what} requires sequence"),
        )
    })?;
    if is_missing(sequence_value) {
        return Err(fault(
            "invalid_cursor",
            format!("{what}.sequence must be an established revision, never Missing"),
        ));
    }
    let sequence = required_seq_number(sequence_value, &format!("{what}.sequence")).map_err(|_| {
        fault(
            "invalid_cursor",
            format!("{what}.sequence must be an unsigned integer revision"),
        )
    })?;
    let hash_value = map.get("event_hash").ok_or_else(|| {
        fault(
            "invalid_cursor",
            format!("{what} requires event_hash"),
        )
    })?;
    if sequence == 0 {
        if !is_inapplicable(hash_value) {
            return Err(fault(
                "invalid_cursor",
                format!("{what}: sequence 0 requires event_hash Missing(not_applicable)"),
            ));
        }
        Ok(Cursor {
            handle,
            journal_id,
            sequence,
            event_hash: None,
        })
    } else {
        match hash_value {
            Value::String(s) if is_digest_text(s) => Ok(Cursor {
                handle,
                journal_id,
                sequence,
                event_hash: Some(s.clone()),
            }),
            Value::String(s) => Err(fault(
                "invalid_cursor",
                format!(
                    "{what}.event_hash must be 64 lowercase hex for positive sequences, got {s:?}"
                ),
            )),
            _ if is_missing(hash_value) => Err(fault(
                "invalid_cursor",
                format!("{what}: positive sequences require an established digest event_hash"),
            )),
            _ => Err(fault(
                "invalid_cursor",
                format!("{what}.event_hash must be a digest string"),
            )),
        }
    }
}

enum Through {
    Live,
    Fixed {
        journal_id: String,
        last_sequence: u64,
        head_hash: String,
    },
}

fn parse_through(value: &Value) -> Result<Through, Fault> {
    if is_inapplicable(value) {
        return Ok(Through::Live);
    }
    if is_missing(value) {
        return Err(fault(
            "invalid_through",
            format!(
                "through as Missing must use reason not_applicable for a live cutoff, got {:?}",
                missing_reason(value)
            ),
        ));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_through",
            "through must be a JournalPrefix or Missing(not_applicable)".to_string(),
        )
    })?;
    let journal_id = required_str(map, "journal_id", "invalid_through", "through")?.to_string();
    let last_sequence = required_u64(map, "last_sequence", "invalid_through", "through")?;
    if last_sequence == 0 {
        return Err(fault(
            "invalid_through",
            "through.last_sequence must be a positive integer (>= 1)".to_string(),
        ));
    }
    let head_hash = required_str(map, "head_hash", "invalid_through", "through")?;
    if !is_digest_text(head_hash) {
        return Err(fault(
            "invalid_through",
            format!("through.head_hash must be 64 lowercase hex, got {head_hash:?}"),
        ));
    }
    Ok(Through::Fixed {
        journal_id,
        last_sequence,
        head_hash: head_hash.to_string(),
    })
}

fn parse_max_items(value: &Value) -> Result<u64, Fault> {
    if is_missing(value) {
        return Err(fault(
            "invalid_max_items",
            "max_items must be an established positive integer, never Missing".to_string(),
        ));
    }
    match value {
        Value::Number(n) if n.is_u64() => {
            let v = n.as_u64().unwrap_or(0);
            if v == 0 {
                return Err(fault(
                    "invalid_max_items",
                    "max_items must be >= 1".to_string(),
                ));
            }
            Ok(v)
        }
        Value::Number(_) => Err(fault(
            "invalid_max_items",
            "max_items must be an unsigned integer, not a float or negative".to_string(),
        )),
        _ => Err(fault(
            "invalid_max_items",
            "max_items must be a positive integer".to_string(),
        )),
    }
}

fn parse_wait_limit(value: &Value) -> Result<f64, Fault> {
    if is_missing(value) {
        return Err(fault(
            "invalid_wait_limit",
            "wait_limit must be an established DurationLimit, never Missing".to_string(),
        ));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_wait_limit",
            "wait_limit must be a DurationLimit object".to_string(),
        )
    })?;
    let kind = required_str(map, "kind", "invalid_wait_limit", "wait_limit")?;
    if kind != "exact" {
        return Err(fault(
            "invalid_wait_limit",
            format!("wait_limit.kind must be exact, got {kind:?}"),
        ));
    }
    let unit = required_str(map, "unit", "invalid_wait_limit", "wait_limit")?;
    if unit != "ms" {
        return Err(fault(
            "invalid_wait_limit",
            format!("wait_limit.unit must be ms, got {unit:?}"),
        ));
    }
    let raw = established(map, "value").ok_or_else(|| {
        fault(
            "invalid_wait_limit",
            "wait_limit requires established value".to_string(),
        )
    })?;
    let num = raw.as_f64().ok_or_else(|| {
        fault(
            "invalid_wait_limit",
            "wait_limit.value must be a number".to_string(),
        )
    })?;
    if !num.is_finite() || num < 0.0 {
        return Err(fault(
            "invalid_wait_limit",
            format!("wait_limit.value must be finite and >= 0, got {num}"),
        ));
    }
    Ok(num)
}

// ---------------------------------------------------------------------------
// Store helpers
// ---------------------------------------------------------------------------

fn store_query(kind: &str, journal_id: &str) -> Result<CheckedRecord, Fault> {
    validate(
        OUTPUT_SCHEMA,
        serde_json::json!({"query": kind, "journal_id": journal_id}),
    )
}

fn fetch_prefix(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
) -> Result<(u64, String), Fault> {
    let query = store_query("prefix", journal_id)?;
    let view = store.read(grant, &query)?;
    let map = record_value(&view).as_object().ok_or_else(|| {
        fault(
            "invalid_store_view",
            "prefix view must be an object".to_string(),
        )
    })?;
    let last_sequence = required_u64(map, "last_sequence", "invalid_store_view", "prefix")?;
    let head_hash = required_str(map, "head_hash", "invalid_store_view", "prefix")?.to_string();
    Ok((last_sequence, head_hash))
}

fn fetch_journal_view(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
) -> Result<Value, Fault> {
    let query = store_query("journal", journal_id)?;
    let view = store.read(grant, &query)?;
    Ok(record_value(&view).clone())
}

fn journal_events(view: &Value) -> Result<&Vec<Value>, Fault> {
    view.get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| fault("invalid_store_view", "journal view requires events array".to_string()))
}

fn event_at<'a>(events: &'a [Value], sequence: u64) -> Option<&'a Value> {
    if sequence == 0 {
        return None;
    }
    events.get(sequence.saturating_sub(1) as usize)
}

fn envelope_hash(envelope: &Value) -> Option<&str> {
    envelope.get("event_hash").and_then(Value::as_str)
}

fn envelope_sequence(envelope: &Value) -> Option<u64> {
    envelope
        .get("journal_sequence")
        .and_then(Value::as_u64)
}

fn envelope_journal(envelope: &Value) -> Option<&str> {
    envelope.get("journal_id").and_then(Value::as_str)
}

/// Handle equality for a journaled envelope: `payload.data.handle` equals the
/// requested handle. Anything else — missing payload, non-object data,
/// missing/mismatched handle — is a non-observation position that still
/// advances the scanned cursor.
fn envelope_handle_matches(envelope: &Value, handle: &Handle) -> bool {
    let data = envelope
        .get("payload")
        .and_then(|p| p.get("data"));
    let Some(obj) = data.and_then(Value::as_object) else {
        return false;
    };
    let Some(h) = obj.get("handle").and_then(Value::as_object) else {
        return false;
    };
    let connector = h.get("connector_id").and_then(Value::as_str);
    let local = h.get("local_handle").and_then(Value::as_str);
    connector == Some(handle.connector_id.as_str()) && local == Some(handle.local_handle.as_str())
}

fn build_item(envelope: &Value, journal_id: &str, sequence: u64) -> Result<Value, Fault> {
    let event_id = envelope
        .get("event_id")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_store_view", "envelope requires event_id".to_string()))?;
    let event_hash = envelope_hash(envelope).ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope requires event_hash".to_string(),
        )
    })?;
    let recorded_at = envelope.get("recorded_at").cloned().ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope requires recorded_at".to_string(),
        )
    })?;
    let provenance = envelope
        .get("provenance")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_store_view", "envelope requires provenance".to_string()))?;
    let payload = envelope.get("payload").ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope requires payload".to_string(),
        )
    })?;
    let data = payload.get("data").cloned().ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope payload requires data".to_string(),
        )
    })?;
    let measurements = payload.get("measurements").cloned().ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope payload requires measurements".to_string(),
        )
    })?;
    let artifact_refs = payload.get("artifact_refs").cloned().ok_or_else(|| {
        fault(
            "invalid_store_view",
            "envelope payload requires artifact_refs".to_string(),
        )
    })?;
    if !measurements.is_array() || !artifact_refs.is_array() {
        return Err(fault(
            "invalid_store_view",
            "envelope measurements and artifact_refs must be arrays".to_string(),
        ));
    }
    Ok(serde_json::json!({
        "event_ref": {
            "journal_id": journal_id,
            "sequence": sequence,
            "event_id": event_id,
            "event_hash": event_hash,
            "pointer": "",
        },
        "recorded_at": recorded_at,
        "provenance": provenance,
        "payload": data,
        "measurements": measurements,
        "artifact_refs": artifact_refs,
    }))
}

/// Explicit loss limitations from the journal's producer lifetimes: any gap
/// with unresolved sequences at or before the cutoff is reported verbatim.
/// Gaps are producer-lifetime facts, not synthesized observation items.
fn loss_limitations(view: &Value, through_last: u64) -> Vec<String> {
    let mut out = Vec::new();
    let Some(producers) = view.get("producers").and_then(Value::as_array) else {
        return out;
    };
    for producer in producers {
        let producer_id = producer
            .get("producer_id")
            .and_then(Value::as_str)
            .unwrap_or("?");
        let Some(gaps) = producer.get("gaps").and_then(Value::as_array) else {
            continue;
        };
        for gap in gaps {
            let detected_at = gap.get("detected_at").and_then(Value::as_u64).unwrap_or(0);
            if detected_at == 0 || detected_at > through_last {
                continue;
            }
            let unresolved = gap
                .get("unresolved")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if unresolved.is_empty() {
                continue;
            }
            let from = gap
                .get("from_sequence")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let to = gap.get("to_sequence").and_then(Value::as_u64).unwrap_or(0);
            let list: Vec<String> =
                unresolved.iter().map(|v| v.to_string()).collect();
            out.push(format!(
                "producer_gap producer {producer_id:?} sequences {from}..={to} unresolved [{}] detected_at journal {detected_at}; loss is explicit and late evidence requires a new live cutoff",
                list.join(", ")
            ));
        }
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// observe
// ---------------------------------------------------------------------------

/// Return handle-scoped observation projections through a fixed journal prefix.
///
/// `request` is an `ObserveRequest` (`handle`, `after`, `through`,
/// `max_items`, `wait_limit`). `through` as `Missing(not_applicable)`
/// requests a new live cutoff (the current durable head, pinned into the
/// response); an established `JournalPrefix` freezes pagination and requires
/// `wait_limit.value == 0`. The response is an `ObservationPage` with
/// `after < item.sequence <= next <= through` and
/// `has_more == (next.sequence < through.last_sequence)`.
///
/// `next` is the last *scanned* journal position: non-observation events
/// (other handles, `manifest_admitted`, closures without handles, imports)
/// advance it without producing items. When `max_items` fills, scanning
/// stops at the last returned item; otherwise scanning runs to `through`,
/// so a trailing run of non-observations still advances `next` to the
/// cutoff. An empty page at the cutoff (`next == through`, `has_more ==
/// false`) is legitimate and carries `observation_close_ref` as
/// `Missing(not_observed)` unless a handle-scoped `producer_closed` event
/// is journaled at or before the cutoff — never native termination.
///
/// The `clock` is consulted once (a well-formed `TimePoint` is required)
/// to establish the observation time; this implementation performs zero
/// wait for both live and fixed cutoffs and never blocks on future
/// evidence.
pub fn observe(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    // Consult the clock first: a failing or malformed clock fails the call
    // rather than producing an undated observation.
    let now = clock.now()?;
    let now_map = record_value(&now).as_object().ok_or_else(|| {
        fault(
            "invalid_clock",
            "clock authority must report a TimePoint object".to_string(),
        )
    })?;
    for field in [
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    ] {
        if now_map.get(field).is_none() {
            return Err(fault(
                "invalid_clock",
                format!("clock authority TimePoint is missing {field:?}"),
            ));
        }
    }

    let req = as_object(request, "invalid_request", "ObserveRequest")?;
    let handle_raw = req.get("handle").ok_or_else(|| {
        fault("invalid_request", "ObserveRequest requires handle".to_string())
    })?;
    let handle = parse_handle(handle_raw, "ObserveRequest.handle").map_err(|e| {
        fault(
            "invalid_request",
            format!("bad handle: {} ({})", e.code, e.detail),
        )
    })?;
    let after_value = req.get("after").ok_or_else(|| {
        fault("invalid_request", "ObserveRequest requires after".to_string())
    })?;
    let after = parse_cursor(after_value, "after")?;
    let through_value = req.get("through").ok_or_else(|| {
        fault("invalid_request", "ObserveRequest requires through".to_string())
    })?;
    let through = parse_through(through_value)?;
    let max_items_value = req.get("max_items").ok_or_else(|| {
        fault(
            "invalid_max_items",
            "ObserveRequest requires max_items".to_string(),
        )
    })?;
    let max_items = parse_max_items(max_items_value)?;
    let wait_value = req.get("wait_limit").ok_or_else(|| {
        fault(
            "invalid_wait_limit",
            "ObserveRequest requires wait_limit".to_string(),
        )
    })?;
    let wait_ms = parse_wait_limit(wait_value)?;

    // Handle agreement: the request handle and the cursor handle name the
    // same commissioned handle. Cross-handle reads are refused, never
    // silently scoped.
    if after.handle != handle {
        return Err(fault(
            "handle_mismatch",
            "ObserveRequest.handle and after.handle must name the same handle".to_string(),
        ));
    }

    // Live reads run against the cursor's journal; fixed reads additionally
    // pin that same journal.
    let journal_id = after.journal_id.clone();
    let (head_last, head_hash) = fetch_prefix(store, grant, &journal_id)?;
    let view = fetch_journal_view(store, grant, &journal_id)?;
    let events = journal_events(&view)?.clone();

    // Sanity: the prefix and the full view must agree (same durable head).
    if head_last as usize != events.len() {
        return Err(fault(
            "invalid_store_view",
            format!(
                "prefix last_sequence {head_last} disagrees with journal events {}",
                events.len()
            ),
        ));
    }
    if head_last > 0 {
        let head_event_hash = events
            .last()
            .and_then(envelope_hash)
            .unwrap_or_default();
        if head_event_hash != head_hash {
            return Err(fault(
                "invalid_store_view",
                "prefix head_hash disagrees with the last journal event".to_string(),
            ));
        }
    }

    // Resolve the cutoff.
    let (cutoff_last, cutoff_hash) = match &through {
        Through::Live => (head_last, head_hash.clone()),
        Through::Fixed {
            journal_id: through_journal,
            last_sequence,
            head_hash,
        } => {
            if wait_ms != 0.0 {
                return Err(fault(
                    "wait_not_allowed_with_fixed_cutoff",
                    format!(
                        "fixed through requires wait_limit.value == 0, got {wait_ms}"
                    ),
                ));
            }
            if through_journal != &journal_id {
                return Err(fault(
                    "journal_mismatch",
                    format!(
                        "through.journal_id {through_journal:?} must equal after.journal_id {journal_id:?}"
                    ),
                ));
            }
            if *last_sequence > head_last {
                return Err(fault(
                    "unknown_cutoff",
                    format!(
                        "through.last_sequence {last_sequence} is beyond the durable head {head_last}; late evidence requires a new live cutoff"
                    ),
                ));
            }
            let cutoff_event = event_at(&events, *last_sequence).ok_or_else(|| {
                fault(
                    "cutoff_mismatch",
                    format!("through names unavailable history at sequence {last_sequence}"),
                )
            })?;
            let actual = cutoff_event
                .get("event_hash")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if actual != head_hash {
                return Err(fault(
                    "cutoff_mismatch",
                    format!(
                        "through.head_hash does not match the event hash at sequence {last_sequence}"
                    ),
                ));
            }
            (*last_sequence, head_hash.clone())
        }
    };

    // Verify the after cursor against durable history. Every failure is
    // explicit: cursors are never advanced past unavailable history.
    if after.sequence > cutoff_last {
        return Err(fault(
            "cursor_beyond_cutoff",
            format!(
                "after.sequence {} is beyond through.last_sequence {cutoff_last}",
                after.sequence
            ),
        ));
    }
    if after.sequence > 0 {
        let expected = after.event_hash.as_deref().unwrap_or_default();
        let Some(after_event) = event_at(&events, after.sequence) else {
            return Err(fault(
                "cursor_history_lost",
                format!(
                    "after.sequence {} names unavailable history (head {head_last}); loss is explicit, never skipped",
                    after.sequence
                ),
            ));
        };
        // The cursor position must be the claimed event, not merely an
        // occupied sequence number.
        if envelope_journal(after_event) != Some(journal_id.as_str())
            || envelope_sequence(after_event) != Some(after.sequence)
        {
            return Err(fault(
                "cursor_history_lost",
                format!(
                    "after.sequence {} does not address a contiguous journal position",
                    after.sequence
                ),
            ));
        }
        let actual = after_event
            .get("event_hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if actual != expected {
            return Err(fault(
                "cursor_mismatch",
                format!(
                    "after.event_hash does not match the event hash at sequence {}",
                    after.sequence
                ),
            ));
        }
    }

    // Scan (after, through]: collect at most max_items handle-scoped
    // projections in journal order. next is the last scanned position.
    let mut items: Vec<Value> = Vec::new();
    let mut last_scanned: u64 = after.sequence;
    let mut stopped_on_limit = false;
    for seq in (after.sequence + 1)..=cutoff_last {
        let Some(envelope) = event_at(&events, seq) else {
            return Err(fault(
                "cursor_history_lost",
                format!(
                    "journal history unavailable at sequence {seq} within (after, through]; loss is explicit"
                ),
            ));
        };
        if envelope_journal(envelope) != Some(journal_id.as_str())
            || envelope_sequence(envelope) != Some(seq)
        {
            return Err(fault(
                "invalid_store_view",
                format!("journal is not contiguous at sequence {seq}"),
            ));
        }
        last_scanned = seq;
        // Lifecycle kinds are never observation projections, even when they
        // carry a handle: manifest admission pins scope, producer closure is
        // reported via observation_close_ref, and imports are historical
        // evidence. They still advance the scanned cursor.
        let lifecycle = matches!(
            envelope.get("event_kind").and_then(serde_json::Value::as_str),
            Some("manifest_admitted") | Some("producer_closed") | Some("evidence_imported")
        );
        if !lifecycle && envelope_handle_matches(envelope, &handle) {
            // Oversized items are never dropped: a matching item is always
            // copied whole; max_items bounds count only.
            items.push(build_item(envelope, &journal_id, seq)?);
            if items.len() as u64 >= max_items {
                stopped_on_limit = true;
                break;
            }
        }
    }
    // When the limit did not fill, scanning ran to the cutoff (or the range
    // was empty and last_scanned == after == through).
    let next_seq = if stopped_on_limit {
        last_scanned
    } else if cutoff_last >= after.sequence {
        // Scanned everything; next is the cutoff (== after when empty).
        cutoff_last
    } else {
        after.sequence
    };
    // Empty range (after == through): last_scanned == after already.
    let next_seq = if after.sequence == cutoff_last {
        after.sequence
    } else {
        next_seq
    };

    let next_hash_value = if next_seq == 0 {
        missing_envelope(
            "not_applicable",
            "zero cursor starts scanning before admission",
        )
    } else {
        let next_event = event_at(&events, next_seq).ok_or_else(|| {
            fault(
                "cursor_history_lost",
                format!("next.sequence {next_seq} names unavailable history"),
            )
        })?;
        let h = next_event
            .get("event_hash")
            .and_then(Value::as_str)
            .unwrap_or_default();
        Value::String(h.to_string())
    };
    let next = serde_json::json!({
        "handle": handle_value(&handle),
        "journal_id": journal_id,
        "sequence": next_seq,
        "event_hash": next_hash_value,
    });

    let has_more = next_seq < cutoff_last;

    // Locally observed closure at this cutoff: the latest handle-scoped
    // producer_closed event at or before through, else not_observed.
    // A closed connection is never native termination.
    let mut close_ref: Value = missing_envelope(
        "not_observed",
        "no locally observed closure at this cutoff; not native termination",
    );
    for seq in (1..=cutoff_last).rev() {
        let Some(envelope) = event_at(&events, seq) else {
            continue;
        };
        let kind = envelope.get("event_kind").and_then(Value::as_str);
        if kind != Some("producer_closed") {
            continue;
        }
        if !envelope_handle_matches(envelope, &handle) {
            continue;
        }
        let event_id = envelope.get("event_id").and_then(Value::as_str).unwrap_or("");
        let event_hash = envelope_hash(envelope).unwrap_or("");
        close_ref = serde_json::json!({
            "journal_id": journal_id,
            "sequence": seq,
            "event_id": event_id,
            "event_hash": event_hash,
            "pointer": "",
        });
        break;
    }

    let limitations = loss_limitations(&view, cutoff_last);

    let page = serde_json::json!({
        "kind": "observation_page",
        "handle": handle_value(&handle),
        "after": after_value.clone(),
        "through": {
            "journal_id": journal_id,
            "last_sequence": cutoff_last,
            "head_hash": cutoff_hash,
        },
        "next": next,
        "has_more": has_more,
        "observation_close_ref": close_ref,
        "items": items,
        "limitations": limitations,
    });
    validate(OUTPUT_SCHEMA, page)
}

// ---------------------------------------------------------------------------
// normalize_native_report
// ---------------------------------------------------------------------------

struct EvidenceRef {
    journal_id: String,
    sequence: u64,
    event_id: String,
    event_hash: String,
    raw: Value,
}

fn parse_evidence_ref(value: &Value, what: &str) -> Result<EvidenceRef, Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_evidence_ref",
            format!("{what} must be an EvidenceRef object"),
        )
    })?;
    let journal_id = required_str(map, "journal_id", "invalid_evidence_ref", what)?.to_string();
    let sequence = required_u64(map, "sequence", "invalid_evidence_ref", what)?;
    if sequence == 0 {
        return Err(fault(
            "invalid_evidence_ref",
            format!("{what}.sequence must be a positive integer"),
        ));
    }
    let event_id = required_str(map, "event_id", "invalid_evidence_ref", what)?.to_string();
    let event_hash = required_str(map, "event_hash", "invalid_evidence_ref", what)?;
    if !is_digest_text(event_hash) {
        return Err(fault(
            "invalid_evidence_ref",
            format!("{what}.event_hash must be 64 lowercase hex"),
        ));
    }
    let pointer_value = map.get("pointer").ok_or_else(|| {
        fault(
            "invalid_evidence_ref",
            format!("{what} requires pointer"),
        )
    })?;
    let pointer = pointer_value.as_str().ok_or_else(|| {
        fault(
            "invalid_evidence_ref",
            format!("{what}.pointer must be a string"),
        )
    })?;
    if !is_json_pointer(pointer) {
        return Err(fault(
            "invalid_evidence_ref",
            format!("{what}.pointer is not a valid JSON pointer"),
        ));
    }
    Ok(EvidenceRef {
        journal_id,
        sequence,
        event_id,
        event_hash: event_hash.to_string(),
        raw: value.clone(),
    })
}

/// Verify that an `EvidenceRef` names a registered journaled event: journal,
/// sequence, event id, and hash must all agree. Source evidence must be
/// registered/imported before it is cited.
fn verify_evidence_ref(
    store: &dyn OwnerStore,
    grant: &Grant,
    reference: &EvidenceRef,
    what: &str,
) -> Result<(), Fault> {
    let query = validate(
        OUTPUT_SCHEMA,
        serde_json::json!({
            "query": "event",
            "journal_id": reference.journal_id,
            "journal_sequence": reference.sequence,
        }),
    )?;
    let found = store.read(grant, &query).map_err(|e| {
        fault(
            "evidence_not_registered",
            format!(
                "{what} cites unregistered evidence {}:{} ({}: {})",
                reference.journal_id, reference.sequence, e.code, e.detail
            ),
        )
    })?;
    let envelope = record_value(&found);
    let event_id = envelope.get("event_id").and_then(Value::as_str).unwrap_or("");
    let event_hash = envelope_hash(envelope).unwrap_or("");
    if event_id != reference.event_id || event_hash != reference.event_hash {
        return Err(fault(
            "evidence_not_registered",
            format!(
                "{what} does not match the registered event at {}:{}",
                reference.journal_id, reference.sequence
            ),
        ));
    }
    Ok(())
}

struct VersionPin {
    id: String,
    version: String,
    artifact_digest: String,
}

fn parse_version_pin(value: &Value, what: &str) -> Result<VersionPin, Fault> {
    if is_missing(value) {
        return Err(fault(
            "invalid_mapping",
            format!("{what} must be an established VersionPin, never Missing"),
        ));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_mapping",
            format!("{what} must be a VersionPin object"),
        )
    })?;
    let id = required_str(map, "id", "invalid_mapping", what)?.to_string();
    let version = required_str(map, "version", "invalid_mapping", what)?.to_string();
    let digest = required_str(map, "artifact_digest", "invalid_mapping", what)?;
    if !is_digest_text(digest) {
        return Err(fault(
            "invalid_mapping",
            format!("{what}.artifact_digest must be 64 lowercase hex"),
        ));
    }
    Ok(VersionPin {
        id,
        version,
        artifact_digest: digest.to_string(),
    })
}

fn version_pin_value(pin: &VersionPin) -> Value {
    serde_json::json!({
        "id": pin.id,
        "version": pin.version,
        "artifact_digest": pin.artifact_digest,
    })
}

struct SourceChecks {
    authentication: String,
    correlation: String,
    trace_correlation: String,
    matched_by: Vec<String>,
    evidence_refs: Vec<EvidenceRef>,
    raw: Value,
}

fn parse_source_checks(value: &Value) -> Result<SourceChecks, Fault> {
    if is_missing(value) {
        return Err(fault(
            "invalid_source_checks",
            "source_checks must be established, never Missing".to_string(),
        ));
    }
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks must be an object".to_string(),
        )
    })?;
    let authentication = required_str(map, "authentication", "invalid_source_checks", "source_checks")?;
    if !AUTH_VALUES.contains(&authentication) {
        return Err(fault(
            "invalid_source_checks",
            format!("authentication must be one of {AUTH_VALUES:?}, got {authentication:?}"),
        ));
    }
    let correlation = required_str(map, "correlation", "invalid_source_checks", "source_checks")?;
    if !CORR_VALUES.contains(&correlation) {
        return Err(fault(
            "invalid_source_checks",
            format!("correlation must be one of {CORR_VALUES:?}, got {correlation:?}"),
        ));
    }
    let trace = required_str(map, "trace_correlation", "invalid_source_checks", "source_checks")?;
    if !TRACE_VALUES.contains(&trace) {
        return Err(fault(
            "invalid_source_checks",
            format!("trace_correlation must be one of {TRACE_VALUES:?}, got {trace:?}"),
        ));
    }
    let policy_value = map.get("verification_policy").ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks requires verification_policy".to_string(),
        )
    })?;
    parse_version_pin(policy_value, "source_checks.verification_policy").map_err(|e| {
        fault(
            "invalid_source_checks",
            format!("bad verification_policy: {} ({})", e.code, e.detail),
        )
    })?;
    let matched_raw = map.get("matched_by").ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks requires matched_by".to_string(),
        )
    })?;
    if is_missing(matched_raw) {
        return Err(fault(
            "invalid_source_checks",
            "source_checks.matched_by must be an established array".to_string(),
        ));
    }
    let matched_arr = matched_raw.as_array().ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks.matched_by must be an array".to_string(),
        )
    })?;
    let mut matched_by = Vec::new();
    for (i, item) in matched_arr.iter().enumerate() {
        match item {
            Value::String(s) if !s.is_empty() => matched_by.push(s.clone()),
            _ => {
                return Err(fault(
                    "invalid_source_checks",
                    format!("source_checks.matched_by[{i}] must be a nonempty string"),
                ));
            }
        }
    }
    let refs_raw = map.get("evidence_refs").ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks requires evidence_refs".to_string(),
        )
    })?;
    if is_missing(refs_raw) {
        return Err(fault(
            "invalid_source_checks",
            "source_checks.evidence_refs must be an established array".to_string(),
        ));
    }
    let refs_arr = refs_raw.as_array().ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "source_checks.evidence_refs must be an array".to_string(),
        )
    })?;
    if refs_arr.is_empty() {
        return Err(fault(
            "invalid_source_checks",
            "source_checks.evidence_refs must cite at least one supporting event".to_string(),
        ));
    }
    let mut evidence_refs = Vec::new();
    for (i, item) in refs_arr.iter().enumerate() {
        evidence_refs.push(parse_evidence_ref(
            item,
            &format!("source_checks.evidence_refs[{i}]"),
        )?);
    }
    Ok(SourceChecks {
        authentication: authentication.to_string(),
        correlation: correlation.to_string(),
        trace_correlation: trace.to_string(),
        matched_by,
        evidence_refs,
        raw: value.clone(),
    })
}

fn parse_timepoint_shape(value: &Value, what: &str) -> Result<(), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_report",
            format!("{what} must be a TimePoint object or Missing"),
        )
    })?;
    for field in [
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    ] {
        if map.get(field).is_none() {
            return Err(fault(
                "invalid_report",
                format!("{what} TimePoint is missing {field:?}"),
            ));
        }
    }
    Ok(())
}

fn parse_maybe_string(value: &Value, what: &str) -> Result<Value, Fault> {
    if is_missing(value) {
        return Ok(value.clone());
    }
    match value {
        Value::String(s) if !s.is_empty() => Ok(value.clone()),
        Value::String(_) => Err(fault(
            "invalid_report",
            format!("{what} must be a nonempty string or Missing"),
        )),
        _ => Err(fault(
            "invalid_report",
            format!("{what} must be a string or Missing"),
        )),
    }
}

/// Normalize one native report into a `native_report` observation.
///
/// The report carries the exact native body (`raw_body` string) plus the
/// independent `source_checks` (authentication vs. correlation),
/// `source_event`, `mapping`, and proposed native outcome fields. Exact
/// bytes are installed into `artifacts` before any claim is interpreted;
/// `source_event` and every `source_checks.evidence_refs` entry must name
/// already-registered journal events (verified through `store`), otherwise
/// the call fails with `evidence_not_registered`.
///
/// Claim gating is independent and strict: only `authentication ==
/// verified` **and** `correlation == matched` (with nonempty `matched_by`)
/// may yield a normalized claim. `trace_correlation == mismatched` does
/// *not* block when `correlation == matched` via independently evidenced
/// alternate correlation. Anything else yields `normalized_claims: []`
/// with an explanatory limitation — never a fabricated success. `none`,
/// protocol acknowledgements, and HTTP success map to an explicit
/// `unknown` claim state, never to `completed`. Discovery claims always
/// carry `application_assertions: []`; any proposed application assertions
/// are refused with an explanatory limitation. Unrecognized native shapes
/// yield empty claims with an explicit limitation, never a silent drop or
/// an invented mapping.
pub fn normalize_native_report(
    store: &dyn OwnerStore,
    artifacts: &dyn ArtifactStore,
    grant: &Grant,
    report: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let rep = as_object(report, "invalid_report", "NativeReport")?;

    // Exact native body (retained before interpretation).
    let raw_body = match established(rep, "raw_body") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            return Err(fault(
                "missing_raw_body",
                "report.raw_body must be the exact native body string".to_string(),
            ));
        }
        None => {
            return Err(fault(
                "missing_raw_body",
                "report requires established raw_body with the exact native bytes".to_string(),
            ));
        }
    };
    let media_type = match rep.get("media_type") {
        None => "application/octet-stream".to_string(),
        Some(v) if is_missing(v) => "application/octet-stream".to_string(),
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => {
            return Err(fault(
                "invalid_report",
                "report.media_type must be a nonempty string or Missing".to_string(),
            ));
        }
    };
    let restricted = match rep.get("restricted") {
        None => false,
        Some(v) if is_missing(v) => false,
        Some(Value::Bool(b)) => *b,
        _ => {
            return Err(fault(
                "invalid_report",
                "report.restricted must be a boolean or Missing".to_string(),
            ));
        }
    };

    let channel = required_str(rep, "channel", "unknown_channel", "report")?;
    if !CHANNELS.contains(&channel) {
        return Err(fault(
            "unknown_channel",
            format!("channel must be one of {CHANNELS:?}, got {channel:?}"),
        ));
    }
    let channel_owned = channel.to_string();

    let source_event_value = rep.get("source_event").ok_or_else(|| {
        fault(
            "missing_source_event",
            "report requires source_event citing the registered receipt".to_string(),
        )
    })?;
    if is_missing(source_event_value) {
        return Err(fault(
            "missing_source_event",
            "report.source_event must be established, never Missing".to_string(),
        ));
    }
    let source_event = parse_evidence_ref(source_event_value, "source_event")?;

    let checks_value = rep.get("source_checks").ok_or_else(|| {
        fault(
            "invalid_source_checks",
            "report requires source_checks".to_string(),
        )
    })?;
    let checks = parse_source_checks(checks_value)?;

    let mapping_value = rep.get("mapping").ok_or_else(|| {
        fault(
            "invalid_mapping",
            "report requires mapping".to_string(),
        )
    })?;
    let mapping = parse_version_pin(mapping_value, "mapping")?;

    let mut limitations: Vec<String> = match rep.get("limitations") {
        None => Vec::new(),
        Some(v) if is_missing(v) => Vec::new(),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for (i, item) in items.iter().enumerate() {
                match item {
                    Value::String(s) if !s.is_empty() => out.push(s.clone()),
                    _ => {
                        return Err(fault(
                            "invalid_report",
                            format!("report.limitations[{i}] must be a nonempty string"),
                        ));
                    }
                }
            }
            out
        }
        _ => {
            return Err(fault(
                "invalid_report",
                "report.limitations must be an array of strings or Missing".to_string(),
            ));
        }
    };

    // Proposed application assertions are never accepted from discovery
    // native reports; note and drop them rather than failing the whole
    // receipt (the receipt itself remains valid evidence).
    if let Some(app) = established(rep, "application_assertions") {
        match app {
            Value::Array(items) if !items.is_empty() => {
                limitations.push(
                    "application assertions are never accepted from discovery native reports; emitted empty"
                        .to_string(),
                );
            }
            Value::Array(_) => {}
            _ => {
                return Err(fault(
                    "invalid_report",
                    "report.application_assertions must be an array when present".to_string(),
                ));
            }
        }
    }

    // Register/import source evidence before citing it.
    verify_evidence_ref(store, grant, &source_event, "source_event")?;
    for (i, r) in checks.evidence_refs.iter().enumerate() {
        verify_evidence_ref(
            store,
            grant,
            r,
            &format!("source_checks.evidence_refs[{i}]"),
        )?;
    }

    // Retain exact native bytes before normalization.
    let reference = artifacts.install(grant, raw_body.as_bytes(), &media_type, restricted)?;
    let ref_map = record_value(&reference)
        .as_object()
        .ok_or_else(|| fault("invalid_artifact_reference", "artifact install must return an object".to_string()))?;
    let digest = ref_map
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_artifact_reference", "artifact reference requires digest".to_string()))?;
    let size_bytes = ref_map.get("size_bytes").cloned().ok_or_else(|| {
        fault(
            "invalid_artifact_reference",
            "artifact reference requires size_bytes".to_string(),
        )
    })?;
    let ref_media = ref_map
        .get("media_type")
        .and_then(Value::as_str)
        .unwrap_or(&media_type)
        .to_string();
    let owner_domain = ref_map
        .get("owner_domain")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            fault(
                "invalid_artifact_reference",
                "artifact reference requires owner_domain".to_string(),
            )
        })?
        .to_string();
    let access = ref_map
        .get("access")
        .and_then(Value::as_str)
        .ok_or_else(|| fault("invalid_artifact_reference", "artifact reference requires access".to_string()))?
        .to_string();
    let raw = serde_json::json!({
        "digest": digest,
        "size_bytes": size_bytes,
        "media_type": ref_media,
        "owner_domain": owner_domain,
        "access": access,
    });

    // Independent gating: authentication and correlation are separate
    // checks. Only verified + matched yields claims. Trace mismatch
    // coexists with alternate correlation and does not block.
    let authenticated = checks.authentication == "verified";
    let correlated = checks.correlation == "matched";
    if !authenticated || !correlated {
        limitations.push(format!(
            "no accepted execution claims: authentication={} correlation={} (trace_correlation={}); unverified or mismatched reports yield empty normalized_claims",
            checks.authentication, checks.correlation, checks.trace_correlation
        ));
        let obs = serde_json::json!({
            "kind": "native_report",
            "channel": channel_owned,
            "raw": raw,
            "source_event": source_event.raw,
            "source_checks": checks.raw,
            "mapping": version_pin_value(&mapping),
            "normalized_claims": [],
            "limitations": limitations,
        });
        return validate(OUTPUT_SCHEMA, obs);
    }
    if checks.matched_by.is_empty() {
        return Err(fault(
            "invalid_source_checks",
            "verified + matched source_checks require nonempty matched_by".to_string(),
        ));
    }

    // Verified + matched: interpret the native outcome faithfully.
    let scope = match rep.get("scope") {
        None => "execution_lifecycle".to_string(),
        Some(v) if is_missing(v) => "execution_lifecycle".to_string(),
        Some(Value::String(s)) if SCOPE_VALUES.contains(&s.as_str()) => s.clone(),
        Some(Value::String(s)) => {
            return Err(fault(
                "invalid_report",
                format!("report.scope must be one of {SCOPE_VALUES:?}, got {s:?}"),
            ));
        }
        _ => {
            return Err(fault(
                "invalid_report",
                "report.scope must be a string or Missing".to_string(),
            ));
        }
    };

    // Native state mapping. None/ack/HTTP success are explicit non-success.
    let native_state_raw = rep.get("native_state");
    let mut claim_state: Value;
    let mut unmapped: Option<String> = None;
    match native_state_raw {
        None => {
            claim_state = missing_envelope("not_observed", "no native state established");
        }
        Some(v) if is_missing(v) => {
            claim_state = v.clone();
        }
        Some(Value::String(s)) => {
            let lower = s.to_ascii_lowercase();
            if ["running", "completed", "failed", "stopped", "unknown"].contains(&lower.as_str()) {
                // Preserve the canonical lowercase form.
                if lower == "completed" {
                    limitations.push(
                        "native completed maps to execution completion only; no application commitment is established"
                            .to_string(),
                    );
                }
                claim_state = Value::String(lower);
            } else if NON_SUCCESS_NATIVE.contains(&lower.as_str()) {
                claim_state = Value::String("unknown".to_string());
                limitations.push(format!(
                    "native {s:?} is not semantic success; emitted explicit unknown with no application assertions"
                ));
            } else {
                unmapped = Some(s.clone());
                claim_state = Value::Null;
            }
        }
        _ => {
            return Err(fault(
                "invalid_report",
                "report.native_state must be a string or Missing".to_string(),
            ));
        }
    }
    if let Some(shape) = unmapped {
        limitations.push(format!(
            "unsupported_native_shape {shape:?}; no accepted interpreted claim from this message"
        ));
        let obs = serde_json::json!({
            "kind": "native_report",
            "channel": channel_owned,
            "raw": raw,
            "source_event": source_event.raw,
            "source_checks": checks.raw,
            "mapping": version_pin_value(&mapping),
            "normalized_claims": [],
            "limitations": limitations,
        });
        return validate(OUTPUT_SCHEMA, obs);
    }

    // Scope-specific state rules (Contract 02 ExecutionClaim allOf).
    if scope == "primitive" {
        claim_state = missing_envelope(
            "not_applicable",
            "primitive scope carries no lifecycle state",
        );
    } else if scope == "unknown" && !is_missing(&claim_state) {
        claim_state = missing_envelope(
            "not_observed",
            "unknown scope carries no established state",
        );
    }

    let native_run_id = match rep.get("native_run_id") {
        None => missing_envelope("not_observed", "no native run identity reported"),
        Some(v) => parse_maybe_string(v, "report.native_run_id")?,
    };
    let native_message_id = match rep.get("native_message_id") {
        None => missing_envelope("not_observed", "no native message identity reported"),
        Some(v) => parse_maybe_string(v, "report.native_message_id")?,
    };
    let made_at = match rep.get("made_at") {
        None => missing_envelope("not_observed", "no source time established"),
        Some(v) if is_missing(v) => v.clone(),
        Some(v) => {
            parse_timepoint_shape(v, "report.made_at")?;
            v.clone()
        }
    };
    let received_at_value = rep.get("received_at").ok_or_else(|| {
        fault(
            "missing_claim_field",
            "verified reports require established received_at TimePoint".to_string(),
        )
    })?;
    if is_missing(received_at_value) {
        return Err(fault(
            "missing_claim_field",
            "verified reports require established received_at TimePoint, never Missing".to_string(),
        ));
    }
    parse_timepoint_shape(received_at_value, "report.received_at")?;
    let received_at = received_at_value.clone();

    let claim_id = match established(rep, "claim_id") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        Some(_) => {
            return Err(fault(
                "missing_claim_field",
                "report.claim_id must be a nonempty string when present".to_string(),
            ));
        }
        None => format!("claim-{}", &digest[..16.min(digest.len())]),
    };

    let evidence_refs_raw: Vec<Value> = checks
        .evidence_refs
        .iter()
        .map(|r| r.raw.clone())
        .collect();

    let claim_limitations = vec![
        "discovery execution claim carries no application assertions".to_string(),
    ];

    let claim = serde_json::json!({
        "claim_id": claim_id,
        "scope": scope,
        "state": claim_state,
        "application_assertions": [],
        "native_run_id": native_run_id,
        "native_message_id": native_message_id,
        "native_report": raw,
        "mapping": version_pin_value(&mapping),
        "source_checks": checks.raw,
        "made_at": made_at,
        "received_at": received_at,
        "evidence_available_to_claimant": evidence_refs_raw,
        "evidence_refs": evidence_refs_raw_for_claim(&checks),
        "limitations": claim_limitations,
    });

    let obs = serde_json::json!({
        "kind": "native_report",
        "channel": channel_owned,
        "raw": raw,
        "source_event": source_event.raw,
        "source_checks": checks.raw,
        "mapping": version_pin_value(&mapping),
        "normalized_claims": [claim],
        "limitations": limitations,
    });
    validate(OUTPUT_SCHEMA, obs)
}

fn evidence_refs_raw_for_claim(checks: &SourceChecks) -> Vec<Value> {
    checks.evidence_refs.iter().map(|r| r.raw.clone()).collect()
}
