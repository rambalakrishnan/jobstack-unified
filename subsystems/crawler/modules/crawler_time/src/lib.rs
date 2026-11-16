//! `crawler_time`: monotonic-clock timestamps and duration validation.
//!
//! Temporal semantics on top of the structural [`crawler_schema`] gate,
//! enforcing EK-TIME, EK-TIMING-INTERPRETATION, EK-LEASE-RESTART,
//! EXT-TIME-NULL, and OWD-TIME-PROVENANCE (seam map §§3.4–3.5, §16.6):
//!
//! * Every record that reaches this module already satisfies the
//!   Missing-envelope discipline (no bare JSON nulls). This module adds the
//!   temporal layer: registered clocks, monotonic coordinates, and
//!   estimate/method coherence.
//! * UTC is annotation only. It is retained verbatim as evidence but is never
//!   converted into monotonic coordinates and never subtracted.
//! * [`normalize_timestamp`] maps a legacy timestamp field to an established
//!   `TimePoint` or to `Missing`, preserving the original UTC and recording
//!   import receipt independently. A required nonmissing `TimePoint` (for
//!   example a held kernel lease) can never be rebuilt from UTC alone.
//! * [`validate_measurement`] checks a Contract 00 `Measurement` — all
//!   fourteen fields — against the registered clocks.
//! * [`compare_deadline`] orders two `TimePoint`s that share one clock and
//!   boot; cross-clock and cross-boot ordering is rejected.
//!
//! Records produced here are validated through [`validate`] under the
//! `"audit_log"` schema id, which the schema gate treats as a structural
//! envelope only; temporal meaning is established by this module.
//!
//! Usage prohibitions this module cannot detect structurally, and which
//! callers must therefore never attempt: dividing an aggregate runtime into
//! invented step durations, treating a configured limit or a scheduled
//! deadline as evidence that time elapsed, and comparing independently
//! derived durations across mismatched semantic boundaries.

use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;

/// Authority able to report the current time as a checked `TimePoint` record.
///
/// Implementations must return a record whose value is a well-formed
/// `TimePoint` on a registered clock; any UTC annotation remains advisory.
pub trait ClockAuthority: Send + Sync {
    fn now(&self) -> Result<CheckedRecord, Fault>;
}

/// Schema id used for records produced by this module (structural envelope).
const OUTPUT_SCHEMA: &str = "audit_log";

const ORIGINS: &[&str] = &[
    "engine_measured",
    "browser_measured",
    "subject_reported",
    "manual_reference",
];

const METHODS: &[&str] = &[
    "endpoint_difference",
    "source_value",
    "evidence_bound",
    "unavailable",
];

const CENSORINGS: &[&str] = &["none", "left", "right", "both", "unavailable"];

const SCOPE_KINDS: &[&str] = &[
    "run",
    "session",
    "connector_call",
    "workflow_step",
    "application_operation",
    "native_primitive",
    "recovery",
    "discovery",
    "capability",
    "resource",
];

const MEASUREMENT_FIELDS: &[&str] = &[
    "measurement_id",
    "name",
    "scope",
    "quantity",
    "unit",
    "origin",
    "clock_id",
    "boot_id",
    "method",
    "start",
    "end",
    "estimate",
    "resolution",
    "censoring",
    "comparability_group",
];

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": null, "reason": reason, "detail": detail})
}

/// True when `value` is a Missing envelope (gate-validated shape).
fn is_missing(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("value").is_some_and(Value::is_null)
                && map.get("reason").is_some_and(Value::is_string)
        }
        _ => false,
    }
}

fn missing_reason(value: &Value) -> Option<&str> {
    match value {
        Value::Object(map) if is_missing(value) => map.get("reason").and_then(Value::as_str),
        _ => None,
    }
}

/// A strictly validated monotonic coordinate.
struct ParsedTimePoint {
    clock_id: String,
    boot_id: String,
    origin: String,
    offset_ms: f64,
}

/// Strictly parse an established `TimePoint` (all five fields present).
fn parse_timepoint(value: &Value) -> Result<ParsedTimePoint, Fault> {
    if is_missing(value) {
        return Err(fault(
            "missing_timepoint",
            "expected an established TimePoint but found Missing; UTC annotation alone is not a coordinate"
                .to_string(),
        ));
    }
    let obj = value.as_object().ok_or_else(|| {
        fault(
            "invalid_timepoint",
            "TimePoint must be an object with clock_id, boot_id, origin, monotonic_offset_ms, and utc_annotation"
                .to_string(),
        )
    })?;
    let clock_id = obj
        .get("clock_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            fault(
                "unestablished_timepoint",
                "TimePoint requires a nonempty clock_id; never invent one".to_string(),
            )
        })?;
    let boot_id = obj
        .get("boot_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            fault(
                "unestablished_timepoint",
                "TimePoint requires a nonempty boot_id; never invent one".to_string(),
            )
        })?;
    let origin = obj.get("origin").and_then(Value::as_str).ok_or_else(|| {
        fault(
            "invalid_origin",
            "TimePoint requires an origin from the closed set".to_string(),
        )
    })?;
    if !ORIGINS.contains(&origin) {
        return Err(fault(
            "invalid_origin",
            format!("unknown TimePoint origin {origin:?}"),
        ));
    }
    let offset_ms = obj
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|f| f.is_finite() && *f >= 0.0)
        .ok_or_else(|| {
            fault(
                "invalid_offset",
                "monotonic_offset_ms must be a finite nonnegative number".to_string(),
            )
        })?;
    match obj.get("utc_annotation") {
        Some(Value::String(_)) => {}
        Some(v) if is_missing(v) => {}
        _ => {
            return Err(fault(
                "invalid_utc_annotation",
                "utc_annotation must be a date-time string or Missing".to_string(),
            ));
        }
    }
    Ok(ParsedTimePoint {
        clock_id: clock_id.to_string(),
        boot_id: boot_id.to_string(),
        origin: origin.to_string(),
        offset_ms,
    })
}

/// Lenient identifier extraction for legacy sources: strings count only when
/// nonempty; Missing/absent counts as unknown; wrong types are corrupt.
fn legacy_id(obj: &Map<String, Value>, key: &str) -> Result<Option<String>, Fault> {
    match obj.get(key) {
        None => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(v) if is_missing(v) => Ok(None),
        Some(_) => Err(fault(
            "invalid_source",
            format!("{key} must be an identifier string or Missing"),
        )),
    }
}

struct ClockEntry {
    clock_id: String,
    boot_id: String,
    basis: Option<String>,
}

struct Registry {
    clocks: Vec<ClockEntry>,
    receipt: Value,
}

impl Registry {
    fn is_registered(&self, clock_id: &str, boot_id: &str) -> bool {
        self.clocks
            .iter()
            .any(|c| c.clock_id == clock_id && c.boot_id == boot_id)
    }

    fn basis_of(&self, clock_id: &str, boot_id: &str) -> Option<&str> {
        self.clocks
            .iter()
            .find(|c| c.clock_id == clock_id && c.boot_id == boot_id)
            .and_then(|c| c.basis.as_deref())
    }
}

/// Parse clock evidence: `{"clocks": [...], "receipt"?: TimePoint|Missing}`.
/// A bare array is tolerated as the clock list with no receipt.
fn parse_registry(value: &Value) -> Result<Registry, Fault> {
    let (entries, receipt) = match value {
        Value::Array(items) => (items.as_slice(), None),
        Value::Object(map) => {
            let items = match map.get("clocks") {
                None => &[],
                Some(Value::Array(items)) => items.as_slice(),
                Some(_) => {
                    return Err(fault(
                        "invalid_clock_evidence",
                        "clock evidence 'clocks' must be an array of clock descriptors".to_string(),
                    ));
                }
            };
            (items, map.get("receipt"))
        }
        _ => {
            return Err(fault(
                "invalid_clock_evidence",
                "clock evidence must be an object with 'clocks' or a bare clock array".to_string(),
            ));
        }
    };
    let mut clocks = Vec::with_capacity(entries.len());
    for entry in entries {
        let obj = entry.as_object().ok_or_else(|| {
            fault(
                "invalid_clock_evidence",
                "each clock descriptor must be an object with clock_id and boot_id".to_string(),
            )
        })?;
        let clock_id = obj
            .get("clock_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                fault(
                    "invalid_clock_evidence",
                    "each clock descriptor requires a nonempty clock_id".to_string(),
                )
            })?;
        let boot_id = obj
            .get("boot_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                fault(
                    "invalid_clock_evidence",
                    "each clock descriptor requires a nonempty boot_id".to_string(),
                )
            })?;
        let basis = obj
            .get("basis")
            .and_then(Value::as_str)
            .map(str::to_string);
        clocks.push(ClockEntry {
            clock_id: clock_id.to_string(),
            boot_id: boot_id.to_string(),
            basis,
        });
    }
    let receipt = match receipt {
        None => missing(
            "not_observed",
            "no import receipt accompanied this clock evidence",
        ),
        Some(v) if is_missing(v) => v.clone(),
        Some(v) => {
            parse_timepoint(v).map_err(|_| {
                fault(
                    "invalid_receipt",
                    "import receipt must be a TimePoint or Missing".to_string(),
                )
            })?;
            v.clone()
        }
    };
    Ok(Registry { clocks, receipt })
}

/// Normalize one legacy timestamp field to a `TimePoint` or `Missing`.
///
/// * Established coordinates (clock, boot, origin, offset) on a registered
///   clock are emitted unchanged with the original UTC preserved.
/// * UTC-only (or partial) history yields `Missing(not_observed)` — or
///   `Missing(observation_lost)` when established coordinates were lost —
///   with the exact UTC retained in `utc_evidence`. Offset zero, a boot, an
///   origin, and a source time are never invented, and the import receipt is
///   recorded independently, never substituted for the source occurrence.
/// * A required nonmissing `TimePoint` (a held kernel lease) cannot be
///   reconstructed from UTC alone; normalization fails instead of publishing
///   a fabricated lease.
///
/// The returned record value is
/// `{"timepoint": TimePoint|Missing, "utc_evidence": string|Missing,
/// "receipt": TimePoint|Missing}`.
pub fn normalize_timestamp(
    source: &CheckedRecord,
    clock_evidence: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let src = record_value(source);
    let src_obj = src.as_object().ok_or_else(|| {
        fault(
            "invalid_source",
            "timestamp source must be an object of legacy timestamp fields".to_string(),
        )
    })?;
    let registry = parse_registry(record_value(clock_evidence))?;

    let clock_id = legacy_id(src_obj, "clock_id")?;
    let boot_id = legacy_id(src_obj, "boot_id")?;
    let origin: Option<String> = match src_obj.get("origin") {
        None => None,
        Some(Value::String(s)) if ORIGINS.contains(&s.as_str()) => Some(s.clone()),
        Some(Value::String(s)) => {
            return Err(fault(
                "invalid_origin",
                format!("unknown timestamp origin {s:?}"),
            ));
        }
        Some(v) if is_missing(v) => None,
        Some(_) => {
            return Err(fault(
                "invalid_origin",
                "timestamp origin must be a string or Missing".to_string(),
            ));
        }
    };
    let offset_number: Option<Value> = match src_obj.get("monotonic_offset_ms") {
        None => None,
        Some(Value::Number(n)) => {
            let f = n.as_f64().ok_or_else(|| {
                fault(
                    "invalid_offset",
                    "monotonic_offset_ms must be a finite nonnegative number".to_string(),
                )
            })?;
            if !f.is_finite() || f < 0.0 {
                return Err(fault(
                    "invalid_offset",
                    "monotonic_offset_ms must be a finite nonnegative number".to_string(),
                ));
            }
            Some(Value::Number(n.clone()))
        }
        Some(v) if is_missing(v) => None,
        Some(_) => {
            return Err(fault(
                "invalid_offset",
                "monotonic_offset_ms must be a number or Missing".to_string(),
            ));
        }
    };

    // Original UTC: modern `utc_annotation` string first, legacy `utc` second.
    let utc_original: Option<&str> = src_obj
        .get("utc_annotation")
        .and_then(Value::as_str)
        .or_else(|| src_obj.get("utc").and_then(Value::as_str));
    let utc_missing_original: Option<&Value> = src_obj
        .get("utc_annotation")
        .filter(|v| is_missing(v));

    let required = src_obj
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || src_obj
            .get("lease")
            .and_then(Value::as_str)
            .is_some_and(|s| s == "held");
    let lost = ["clock_id", "boot_id", "origin", "monotonic_offset_ms"]
        .iter()
        .any(|k| {
            src_obj
                .get(*k)
                .and_then(missing_reason)
                .is_some_and(|r| r == "observation_lost")
        });

    let utc_evidence = match (utc_original, utc_missing_original) {
        (Some(u), _) => json!(u),
        (None, Some(m)) => (*m).clone(),
        (None, None) => missing(
            "not_observed",
            "no UTC annotation survived for this timestamp field",
        ),
    };

    if let (Some(clock_id), Some(boot_id), Some(origin), Some(offset)) =
        (clock_id, boot_id, origin, offset_number)
    {
        if !registry.is_registered(&clock_id, &boot_id) {
            return Err(fault(
                "unregistered_clock",
                format!(
                    "clock {clock_id:?} boot {boot_id:?} is not registered; register clocks before use"
                ),
            ));
        }
        let utc_annotation = match (utc_original, utc_missing_original) {
            (Some(u), _) => json!(u),
            (None, Some(m)) => (*m).clone(),
            (None, None) => missing(
                "not_observed",
                "no UTC annotation accompanied the established coordinates",
            ),
        };
        let timepoint = json!({
            "clock_id": clock_id,
            "boot_id": boot_id,
            "origin": origin,
            "monotonic_offset_ms": offset,
            "utc_annotation": utc_annotation,
        });
        let out = json!({
            "timepoint": timepoint,
            "utc_evidence": utc_evidence,
            "receipt": registry.receipt,
        });
        return validate(OUTPUT_SCHEMA, out);
    }

    // UTC-only or partial history: never invent the missing coordinates.
    if required {
        return Err(fault(
            "required_timepoint_unrecoverable",
            "required nonmissing TimePoint cannot be reconstructed from UTC alone; \
             held-lease publication is blocked until authority-clock coordinates \
             are established under an explicit migration/restart policy"
                .to_string(),
        ));
    }
    let (reason, detail) = if lost {
        (
            "observation_lost",
            "established coordinates were lost; emitting Missing without inventing offset, boot, or origin",
        )
    } else {
        (
            "not_observed",
            "only UTC survives; emitting Missing without inventing offset, boot, or origin",
        )
    };
    let out = json!({
        "timepoint": missing(reason, detail),
        "utc_evidence": utc_evidence,
        "receipt": registry.receipt,
    });
    validate(OUTPUT_SCHEMA, out)
}

/// Unwrap a `TimePoint` from a raw `TimePoint` record or a
/// [`normalize_timestamp`] envelope (`{"timepoint": ...}`).
fn endpoint_of(value: &Value) -> Result<ParsedTimePoint, Fault> {
    match value {
        Value::Object(map) if map.contains_key("timepoint") => {
            parse_timepoint(&value["timepoint"])
        }
        _ => parse_timepoint(value),
    }
}

/// Order two `TimePoint`s on one clock and boot by monotonic offset.
///
/// Cross-clock and cross-boot ordering is rejected: offsets from different
/// clocks or boots are never subtracted or compared. UTC annotations are
/// ignored entirely — they are annotation only, even when they disagree with
/// the monotonic order. Accepts raw `TimePoint` records or
/// [`normalize_timestamp`] envelopes.
pub fn compare_deadline(
    now: &CheckedRecord,
    deadline: &CheckedRecord,
) -> Result<Ordering, Fault> {
    let a = endpoint_of(record_value(now))?;
    let b = endpoint_of(record_value(deadline))?;
    if a.clock_id != b.clock_id {
        return Err(fault(
            "cross_clock",
            format!(
                "refusing to order monotonic offsets across clock IDs {:?} and {:?}",
                a.clock_id, b.clock_id
            ),
        ));
    }
    if a.boot_id != b.boot_id {
        return Err(fault(
            "cross_boot",
            format!(
                "refusing to order monotonic offsets across boots {:?} and {:?} of clock {:?}",
                a.boot_id, b.boot_id, a.clock_id
            ),
        ));
    }
    a.offset_ms.partial_cmp(&b.offset_ms).ok_or_else(|| {
        fault(
            "invalid_offset",
            "monotonic offsets are not comparable".to_string(),
        )
    })
}

fn text_field(obj: &Map<String, Value>, key: &str) -> Result<String, Fault> {
    obj.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            fault(
                "invalid_measurement",
                format!("measurement requires a nonempty string {key:?}"),
            )
        })
}

/// Parse one endpoint: `Missing` yields `None`, otherwise strict `TimePoint`.
fn optional_endpoint(value: &Value, name: &str) -> Result<Option<ParsedTimePoint>, Fault> {
    if is_missing(value) {
        return Ok(None);
    }
    parse_timepoint(value).map(Some).map_err(|e| {
        fault(
            e.code.as_str(),
            format!("measurement {name} endpoint: {}", e.detail),
        )
    })
}

/// Parse one estimate bound: numeric or Missing (key must be present).
fn bound_number(
    estimate: &Map<String, Value>,
    key: &str,
) -> Result<Option<f64>, Fault> {
    match estimate.get(key) {
        None => Err(fault(
            "invalid_estimate",
            format!("bounded estimate requires a {key:?} key holding a number or Missing"),
        )),
        Some(Value::Number(n)) => {
            let f = n.as_f64().ok_or_else(|| {
                fault(
                    "invalid_estimate",
                    format!("bounded estimate {key:?} must be finite"),
                )
            })?;
            if !f.is_finite() {
                return Err(fault(
                    "invalid_estimate",
                    format!("bounded estimate {key:?} must be finite"),
                ));
            }
            Ok(Some(f))
        }
        Some(v) if is_missing(v) => Ok(None),
        Some(_) => Err(fault(
            "invalid_estimate",
            format!("bounded estimate {key:?} must be a number or Missing"),
        )),
    }
}

/// Validate a Contract 00 `Measurement` against the registered clocks.
///
/// Enforces the complete fourteen-field shape, clock registration, duration
/// units (`ms`) with nonnegative values/bounds, and estimate/method/censoring
/// coherence:
///
/// * `exact` carries a numeric value (source-reported zero stays exact zero),
///   uses `censoring=none`, and pairs with `endpoint_difference`/`source_value`.
/// * `bounded` carries at least one numeric bound, uses a non-`unavailable`
///   censoring, and pairs with `evidence_bound`.
/// * `unavailable` carries `value=Missing`, uses the `unavailable` method and
///   censoring, and carries no established endpoints — zero must never
///   replace it.
/// * `endpoint_difference` requires established start/end on the
///   measurement's own clock, boot, and origin with `value == end - start`;
///   cross-clock/cross-boot subtraction is rejected.
/// * `source_value` and `evidence_bound` never recompute the value from
///   endpoints; an opaque-report clock forbids native endpoints entirely.
///
/// Accepts a bare `Measurement` record or a `MeasurementEvidence` envelope
/// (`{"measurement": ..., ...}`); support refs are another module's business.
pub fn validate_measurement(
    measurement: &CheckedRecord,
    registered_clocks: &CheckedRecord,
) -> Result<(), Fault> {
    let root = record_value(measurement);
    let inner = match root {
        Value::Object(map) if map.contains_key("measurement") => &root["measurement"],
        _ => root,
    };
    let m = inner.as_object().ok_or_else(|| {
        fault(
            "invalid_measurement",
            "measurement must be an object with the fourteen Contract 00 fields".to_string(),
        )
    })?;
    for key in MEASUREMENT_FIELDS {
        if !m.contains_key(*key) {
            return Err(fault(
                "missing_field",
                format!("measurement is missing required field {key:?}"),
            ));
        }
    }

    let _measurement_id = text_field(m, "measurement_id")?;
    let _name = text_field(m, "name")?;
    let scope = m.get("scope").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_scope",
            "measurement scope must be an object with kind and id".to_string(),
        )
    })?;
    let scope_kind = scope.get("kind").and_then(Value::as_str).unwrap_or("");
    if !SCOPE_KINDS.contains(&scope_kind) {
        return Err(fault(
            "invalid_scope",
            format!("unknown measurement scope kind {scope_kind:?}"),
        ));
    }
    if scope
        .get("id")
        .and_then(Value::as_str)
        .is_none_or(|s| s.is_empty())
    {
        return Err(fault(
            "invalid_scope",
            "measurement scope requires a nonempty id".to_string(),
        ));
    }
    let quantity = text_field(m, "quantity")?;
    if quantity != "duration" && quantity != "scalar" {
        return Err(fault(
            "invalid_measurement",
            format!("measurement quantity must be duration or scalar, got {quantity:?}"),
        ));
    }
    let unit = text_field(m, "unit")?;
    if quantity == "duration" && unit != "ms" {
        return Err(fault(
            "invalid_unit",
            format!("duration measurements use unit ms, got {unit:?}"),
        ));
    }
    let origin = text_field(m, "origin")?;
    if !ORIGINS.contains(&origin.as_str()) {
        return Err(fault(
            "invalid_origin",
            format!("unknown measurement origin {origin:?}"),
        ));
    }
    let clock_id = text_field(m, "clock_id")?;
    let boot_id = text_field(m, "boot_id")?;
    let method = text_field(m, "method")?;
    if !METHODS.contains(&method.as_str()) {
        return Err(fault(
            "invalid_method",
            format!("unknown measurement method {method:?}"),
        ));
    }
    let censoring = text_field(m, "censoring")?;
    if !CENSORINGS.contains(&censoring.as_str()) {
        return Err(fault(
            "invalid_censoring",
            format!("unknown measurement censoring {censoring:?}"),
        ));
    }

    let registry = parse_registry(record_value(registered_clocks))?;
    if !registry.is_registered(&clock_id, &boot_id) {
        return Err(fault(
            "unregistered_clock",
            format!("measurement clock {clock_id:?} boot {boot_id:?} is not registered"),
        ));
    }
    let basis = registry.basis_of(&clock_id, &boot_id);

    match m.get("resolution") {
        Some(Value::Number(n)) => {
            let ok = n.as_f64().is_some_and(|f| f.is_finite() && f >= 0.0);
            if !ok {
                return Err(fault(
                    "invalid_resolution",
                    "measurement resolution must be a nonnegative number or Missing".to_string(),
                ));
            }
        }
        Some(v) if is_missing(v) => {}
        _ => {
            return Err(fault(
                "invalid_resolution",
                "measurement resolution must be a nonnegative number or Missing".to_string(),
            ));
        }
    }
    match m.get("comparability_group") {
        Some(Value::String(s)) if !s.is_empty() => {}
        Some(v) if is_missing(v) => {}
        _ => {
            return Err(fault(
                "invalid_comparability",
                "comparability_group must be a nonempty string or Missing".to_string(),
            ));
        }
    }

    let estimate = m.get("estimate").and_then(Value::as_object).ok_or_else(|| {
        fault(
            "invalid_estimate",
            "measurement estimate must be an object with a kind".to_string(),
        )
    })?;
    let est_kind = estimate
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut exact_value: Option<f64> = None;
    let mut lower_bound: Option<f64> = None;
    let mut upper_bound: Option<f64> = None;
    match est_kind {
        "exact" => {
            let v = estimate
                .get("value")
                .and_then(Value::as_f64)
                .filter(|f| f.is_finite())
                .ok_or_else(|| {
                    fault(
                        "invalid_estimate",
                        "exact estimate requires a numeric value; Missing or unavailable must not masquerade as exact"
                            .to_string(),
                    )
                })?;
            if quantity == "duration" && v < 0.0 {
                return Err(fault(
                    "invalid_estimate",
                    "exact duration estimates must be nonnegative".to_string(),
                ));
            }
            if censoring != "none" {
                return Err(fault(
                    "invalid_censoring",
                    "exact estimates require censoring=none".to_string(),
                ));
            }
            if method != "endpoint_difference" && method != "source_value" {
                return Err(fault(
                    "estimate_method_mismatch",
                    format!("exact estimates pair with endpoint_difference or source_value, not {method:?}"),
                ));
            }
            exact_value = Some(v);
        }
        "bounded" => {
            let lo = bound_number(estimate, "lower_bound")?;
            let hi = bound_number(estimate, "upper_bound")?;
            if lo.is_none() && hi.is_none() {
                return Err(fault(
                    "invalid_estimate",
                    "bounded estimate requires at least one numeric bound".to_string(),
                ));
            }
            if quantity == "duration" {
                for b in [lo, hi].into_iter().flatten() {
                    if b < 0.0 {
                        return Err(fault(
                            "invalid_estimate",
                            "bounded duration estimates must be nonnegative".to_string(),
                        ));
                    }
                }
            }
            if let (Some(l), Some(h)) = (lo, hi) {
                if l > h {
                    return Err(fault(
                        "invalid_estimate",
                        "bounded estimate lower_bound must not exceed upper_bound".to_string(),
                    ));
                }
            }
            if censoring == "unavailable" {
                return Err(fault(
                    "invalid_censoring",
                    "bounded estimates must not use censoring=unavailable".to_string(),
                ));
            }
            if method != "evidence_bound" {
                return Err(fault(
                    "estimate_method_mismatch",
                    format!("bounded estimates pair with evidence_bound, not {method:?}"),
                ));
            }
            lower_bound = lo;
            upper_bound = hi;
        }
        "unavailable" => {
            match estimate.get("value") {
                Some(v) if is_missing(v) => {}
                _ => {
                    return Err(fault(
                        "invalid_estimate",
                        "unavailable estimate requires value=Missing; zero or any numeric value must not replace unavailable"
                            .to_string(),
                    ));
                }
            }
            if censoring != "unavailable" {
                return Err(fault(
                    "invalid_censoring",
                    "unavailable estimates require censoring=unavailable".to_string(),
                ));
            }
            if method != "unavailable" {
                return Err(fault(
                    "estimate_method_mismatch",
                    format!("unavailable estimates pair with the unavailable method, not {method:?}"),
                ));
            }
        }
        other => {
            return Err(fault(
                "invalid_estimate",
                format!("unknown estimate kind {other:?}"),
            ));
        }
    }
    // Reverse direction: the method must agree with the estimate kind.
    let method_ok = match method.as_str() {
        "endpoint_difference" => est_kind == "exact" && quantity == "duration",
        "source_value" => est_kind == "exact",
        "evidence_bound" => est_kind == "bounded",
        "unavailable" => est_kind == "unavailable",
        _ => false,
    };
    if !method_ok {
        return Err(fault(
            "estimate_method_mismatch",
            format!("method {method:?} disagrees with {est_kind:?} estimate"),
        ));
    }

    let start_raw = m.get("start").ok_or_else(|| {
        fault(
            "missing_field",
            "measurement is missing required field \"start\"".to_string(),
        )
    })?;
    let end_raw = m.get("end").ok_or_else(|| {
        fault(
            "missing_field",
            "measurement is missing required field \"end\"".to_string(),
        )
    })?;
    let start_tp = optional_endpoint(start_raw, "start")?;
    let end_tp = optional_endpoint(end_raw, "end")?;
    for tp in [&start_tp, &end_tp].into_iter().flatten() {
        if !registry.is_registered(&tp.clock_id, &tp.boot_id) {
            return Err(fault(
                "unregistered_clock",
                format!(
                    "measurement endpoint clock {:?} boot {:?} is not registered",
                    tp.clock_id, tp.boot_id
                ),
            ));
        }
    }
    // An opaque-report clock identifies a reporting lifetime, not a native
    // epoch: it never justifies native endpoints.
    if basis == Some("opaque_report") && (start_tp.is_some() || end_tp.is_some()) {
        return Err(fault(
            "invented_endpoints",
            "opaque-report clocks carry no native endpoints; established endpoints on such a clock are invented"
                .to_string(),
        ));
    }

    match method.as_str() {
        "endpoint_difference" => {
            let (Some(s), Some(e)) = (start_tp.as_ref(), end_tp.as_ref()) else {
                return Err(fault(
                    "missing_endpoint",
                    "endpoint_difference requires established start and end TimePoints".to_string(),
                ));
            };
            if s.clock_id != clock_id || e.clock_id != clock_id {
                return Err(fault(
                    "cross_clock",
                    "endpoint_difference endpoints must share the measurement clock; cross-clock subtraction is rejected"
                        .to_string(),
                ));
            }
            if s.boot_id != boot_id || e.boot_id != boot_id {
                return Err(fault(
                    "cross_boot",
                    "endpoint_difference endpoints must share the measurement boot; cross-boot subtraction is rejected"
                        .to_string(),
                ));
            }
            if s.origin != origin || e.origin != origin {
                return Err(fault(
                    "origin_mismatch",
                    "endpoint_difference endpoints must share the measurement origin".to_string(),
                ));
            }
            if e.offset_ms < s.offset_ms {
                return Err(fault(
                    "negative_duration",
                    "endpoint_difference end must not precede start".to_string(),
                ));
            }
            let diff = e.offset_ms - s.offset_ms;
            let v = exact_value.ok_or_else(|| {
                fault(
                    "estimate_method_mismatch",
                    "endpoint_difference requires an exact estimate".to_string(),
                )
            })?;
            let tolerance = 1e-9 * diff.abs().max(1.0);
            if (v - diff).abs() > tolerance {
                return Err(fault(
                    "estimate_mismatch",
                    format!("endpoint_difference value {v} does not equal end minus start ({diff})"),
                ));
            }
        }
        "source_value" => {
            // No arithmetic by design: the subject/system report is preserved
            // unchanged and never recomputed from endpoints.
        }
        "evidence_bound" => {
            // Kernel arithmetic applies only where subtraction is legal: both
            // endpoints established on one clock and boot.
            if let (Some(s), Some(e)) = (start_tp.as_ref(), end_tp.as_ref()) {
                if s.clock_id == e.clock_id && s.boot_id == e.boot_id {
                    if e.offset_ms < s.offset_ms {
                        return Err(fault(
                            "negative_duration",
                            "measurement end must not precede start".to_string(),
                        ));
                    }
                    let diff = e.offset_ms - s.offset_ms;
                    let tolerance = 1e-9 * diff.abs().max(1.0);
                    if let Some(l) = lower_bound {
                        if diff + tolerance < l {
                            return Err(fault(
                                "bound_violation",
                                format!("endpoint span {diff} undercuts the lower bound {l}"),
                            ));
                        }
                    }
                    if let Some(h) = upper_bound {
                        if diff - tolerance > h {
                            return Err(fault(
                                "bound_violation",
                                format!("endpoint span {diff} exceeds the upper bound {h}"),
                            ));
                        }
                    }
                }
            }
        }
        "unavailable" => {
            if start_tp.is_some() || end_tp.is_some() {
                return Err(fault(
                    "invalid_estimate",
                    "unavailable durations carry no established endpoints; established endpoints would evidence an exact or bounded value"
                        .to_string(),
                ));
            }
        }
        _ => {}
    }
    Ok(())
}
