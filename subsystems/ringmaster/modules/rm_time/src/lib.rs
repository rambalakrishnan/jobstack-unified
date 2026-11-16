//! `rm_time`: tier-1 clock and measurement semantics for Ringmaster.
//!
//! Implements the Common evidence time rules (§3.3 clocks/`TimePoint`,
//! §3.4 `Measurement`):
//!
//! - [`validate_measurement`] enforces registration, estimate/method/censoring
//!   coherence, endpoint lifetime matching, endpoint ordering, and exact
//!   endpoint arithmetic (RM-C03, RM-C04).
//! - [`boundary_reached`] orders two [`TimePoint`]s within one registered
//!   clock/boot/origin lifetime only (RM-C04).
//!
//! Hard rules, from the kernel and seam invariants:
//!
//! - Every measurement and time point identifies its origin, clock, and boot.
//! - Clocks are registered before use (manifest or `clock_registered` event;
//!   a `clock_registered` event may atomically introduce the clock used for
//!   its own receipt timestamp — the caller passes that clock in `clocks`).
//! - Never subtract or order monotonic coordinates across clock IDs, boots,
//!   or origins. UTC annotations are annotation only and are never consulted
//!   for elapsed time, ordering, or downtime.
//! - Exact zero is a valid measurement, never a missing-value sentinel.
//!   Missing durations use the unavailable estimate form, never zero.
//! - All missing fields use typed [`Missing`] envelopes; there are no
//!   in-band nulls. The envelope shape agrees with the `rm_wire` tier.
//!
//! Serialization matches the contract JSON exactly (closed objects,
//! `Missing` as `{"value": null, "reason", "detail"?}`), so validated
//! measurements embed into wire records without bare nulls.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

// ---------------------------------------------------------------------------
// Missingness
// ---------------------------------------------------------------------------

/// The six permitted `Missing.reason` values (kernel §3.2).
pub const NULL_REASONS: &[&str] = &[
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

/// Returns true when `reason` is one of the six kernel null reasons.
pub fn is_valid_reason(reason: &str) -> bool {
    NULL_REASONS.contains(&reason)
}

/// A reasoned null: `{"value": null, "reason", "detail"?}`.
///
/// `detail`, when present, must be nonempty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Missing {
    /// One of the six kernel null reasons (see [`NULL_REASONS`]).
    pub reason: String,
    /// Optional nonempty detail.
    pub detail: Option<String>,
}

impl Missing {
    /// Builds a reasoned null without detail.
    pub fn new(reason: impl Into<String>) -> Self {
        Missing {
            reason: reason.into(),
            detail: None,
        }
    }

    /// Builds a reasoned null with detail.
    pub fn with_detail(reason: impl Into<String>, detail: impl Into<String>) -> Self {
        Missing {
            reason: reason.into(),
            detail: Some(detail.into()),
        }
    }
}

impl Serialize for Missing {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let len = if self.detail.is_some() { 3 } else { 2 };
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry("value", &())?;
        map.serialize_entry("reason", &self.reason)?;
        if let Some(detail) = &self.detail {
            map.serialize_entry("detail", detail)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Missing {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::{Error as _, MapAccess, Visitor};

        struct MissingVisitor;

        impl<'de> Visitor<'de> for MissingVisitor {
            type Value = Missing;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter<'_>,
            ) -> std::fmt::Result {
                formatter.write_str("a Missing envelope {value: null, reason, detail?}")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Missing, A::Error> {
                let mut seen_value = false;
                let mut reason: Option<String> = None;
                let mut detail: Option<String> = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "value" => {
                            if seen_value {
                                return Err(A::Error::duplicate_field("value"));
                            }
                            seen_value = true;
                            // Unit only deserializes from JSON null.
                            map.next_value::<()>()?;
                        }
                        "reason" => {
                            if reason.is_some() {
                                return Err(A::Error::duplicate_field("reason"));
                            }
                            reason = Some(map.next_value()?);
                        }
                        "detail" => {
                            if detail.is_some() {
                                return Err(A::Error::duplicate_field("detail"));
                            }
                            detail = Some(map.next_value()?);
                        }
                        other => {
                            return Err(A::Error::unknown_field(
                                other,
                                &["value", "reason", "detail"],
                            ));
                        }
                    }
                }
                if !seen_value {
                    return Err(A::Error::missing_field("value"));
                }
                let reason = reason.ok_or_else(|| A::Error::missing_field("reason"))?;
                if !is_valid_reason(&reason) {
                    return Err(A::Error::invalid_value(
                        serde::de::Unexpected::Str(&reason),
                        &"one of the six kernel null reasons",
                    ));
                }
                if let Some(detail) = &detail {
                    if detail.is_empty() {
                        return Err(A::Error::invalid_length(
                            0,
                            &"Missing detail must be nonempty",
                        ));
                    }
                }
                Ok(Missing { reason, detail })
            }
        }

        deserializer.deserialize_map(MissingVisitor)
    }
}

// ---------------------------------------------------------------------------
// Shared enums and small types
// ---------------------------------------------------------------------------

/// Actual measurement source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeasurementOrigin {
    EngineMeasured,
    BrowserMeasured,
    SubjectReported,
    ManualReference,
}

/// Clock coordinate basis: a known monotonic epoch, or an opaque report
/// lifetime (which identifies a reporting source and its lifetime, not a
/// known native monotonic epoch).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockBasis {
    MonotonicOffset,
    OpaqueReport,
}

/// A registered clock lifetime (§3.3). Always `unit: ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockDescriptor {
    pub clock_id: String,
    pub boot_id: String,
    pub origin: MeasurementOrigin,
    pub source_id: String,
    pub basis: ClockBasis,
    pub unit: String,
}

/// UTC annotation: a date-time string, or reasoned missingness.
/// Annotation only — never consulted for elapsed time or ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum UtcAnnotation {
    DateTime(String),
    Missing(Missing),
}

/// A coordinate in a registered monotonic clock (§3.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimePoint {
    pub clock_id: String,
    pub boot_id: String,
    pub origin: MeasurementOrigin,
    pub monotonic_offset_ms: f64,
    pub utc_annotation: UtcAnnotation,
}

/// `TimePoint` or reasoned missingness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaybeTimePoint {
    Present(TimePoint),
    Missing(Missing),
}

/// Number or reasoned missingness (bounds, resolution).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaybeNumber {
    Num(f64),
    Missing(Missing),
}

/// String or reasoned missingness (comparability groups).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MaybeString {
    Text(String),
    Missing(Missing),
}

/// Exact measured scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub kind: ScopeKind,
    pub id: String,
}

/// Kernel scope kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Run,
    Session,
    ConnectorCall,
    WorkflowStep,
    ApplicationOperation,
    NativePrimitive,
    Recovery,
    Discovery,
    Capability,
    Resource,
}

/// `duration` (unit `ms`) or `scalar` (explicit unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Quantity {
    Duration,
    Scalar,
}

/// How the estimate was derived.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    EndpointDifference,
    SourceValue,
    EvidenceBound,
    Unavailable,
}

/// Explicit censoring flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Censoring {
    None,
    Left,
    Right,
    Both,
    Unavailable,
}

/// Exact, bounded, or unavailable estimate (§3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Estimate {
    /// Numeric value; method is endpoint difference or source value;
    /// censoring is none. Exact zero is valid.
    Exact {
        value: f64,
    },
    /// Bounds, each numeric or Missing, at least one numeric, ordered when
    /// both numeric; method is evidence bound.
    Bounded {
        lower_bound: MaybeNumber,
        upper_bound: MaybeNumber,
    },
    /// Missing value; method and censoring are unavailable.
    Unavailable {
        value: Missing,
    },
}

/// A measured duration or scalar metric with full provenance (§3.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Measurement {
    pub measurement_id: String,
    pub name: String,
    pub scope: Scope,
    pub quantity: Quantity,
    pub unit: String,
    pub origin: MeasurementOrigin,
    pub clock_id: String,
    pub boot_id: String,
    pub method: Method,
    pub start: MaybeTimePoint,
    pub end: MaybeTimePoint,
    pub estimate: Estimate,
    pub resolution: MaybeNumber,
    pub censoring: Censoring,
    pub comparability_group: MaybeString,
}

// ---------------------------------------------------------------------------
// Field validators
// ---------------------------------------------------------------------------

fn validate_identifier(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("invalid identifier at {what}: must be nonempty"));
    }
    Ok(())
}

fn validate_missing(missing: &Missing, what: &str) -> Result<(), String> {
    if !is_valid_reason(&missing.reason) {
        return Err(format!(
            "invalid Missing reason at {what}: {:?}",
            missing.reason
        ));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(format!(
                "invalid Missing detail at {what}: detail must be nonempty"
            ));
        }
    }
    Ok(())
}

fn validate_offset(value: f64, what: &str) -> Result<(), String> {
    if !value.is_finite() {
        return Err(format!(
            "invalid offset at {what}: {value:?} is not finite"
        ));
    }
    if value < 0.0 {
        return Err(format!("invalid offset at {what}: {value} is negative"));
    }
    Ok(())
}

fn validate_clock_descriptor(descriptor: &ClockDescriptor) -> Result<(), String> {
    validate_identifier(&descriptor.clock_id, "clock.clock_id")?;
    validate_identifier(&descriptor.boot_id, "clock.boot_id")?;
    validate_identifier(&descriptor.source_id, "clock.source_id")?;
    if descriptor.unit != "ms" {
        return Err(format!(
            "invalid clock unit: expected \"ms\", found {:?}",
            descriptor.unit
        ));
    }
    Ok(())
}

fn validate_utc(annotation: &UtcAnnotation, what: &str) -> Result<(), String> {
    match annotation {
        UtcAnnotation::DateTime(text) => validate_rfc3339(text)
            .map_err(|_| format!("invalid utc_annotation date-time at {what}: {text:?}")),
        UtcAnnotation::Missing(missing) => validate_missing(missing, what),
    }
}

fn validate_timepoint_shape(point: &TimePoint, what: &str) -> Result<(), String> {
    validate_identifier(&point.clock_id, &format!("{what}.clock_id"))?;
    validate_identifier(&point.boot_id, &format!("{what}.boot_id"))?;
    validate_offset(
        point.monotonic_offset_ms,
        &format!("{what}.monotonic_offset_ms"),
    )?;
    validate_utc(&point.utc_annotation, &format!("{what}.utc_annotation"))?;
    Ok(())
}

fn validate_scope(scope: &Scope) -> Result<(), String> {
    // `kind` is a closed enum, so only the id needs a shape check.
    validate_identifier(&scope.id, "scope.id")
}

/// Validates an RFC 3339 date-time profile:
/// `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)` with coherent calendar ranges.
fn validate_rfc3339(value: &str) -> Result<(), String> {
    let err = || format!("invalid date-time: {value:?}");
    let bytes = value.as_bytes();
    // Shortest accepted form is `YYYY-MM-DDTHH:MM:SSZ` (20 chars).
    if bytes.len() < 20 {
        return Err(err());
    }
    let is_digit = |i: usize| bytes.get(i).is_some_and(|b| b.is_ascii_digit());
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !is_digit(i) {
            return Err(err());
        }
    }
    if bytes.get(4) != Some(&b'-') || bytes.get(7) != Some(&b'-') {
        return Err(err());
    }
    if !bytes.get(10).is_some_and(|b| b.eq_ignore_ascii_case(&b't')) {
        return Err(err());
    }
    if bytes.get(13) != Some(&b':') || bytes.get(16) != Some(&b':') {
        return Err(err());
    }
    let pair = |a: usize, b: usize| -> u32 {
        (bytes[a] - b'0') as u32 * 10 + (bytes[b] - b'0') as u32
    };
    let year = pair(0, 1) * 100 + pair(2, 3);
    let month = pair(5, 6);
    let day = pair(8, 9);
    let hour = pair(11, 12);
    let minute = pair(14, 15);
    let second = pair(17, 18);
    if !(1..=12).contains(&month) {
        return Err(err());
    }
    if day == 0 || day > days_in_month(year, month) {
        return Err(err());
    }
    if hour > 23 || minute > 59 || second > 60 {
        return Err(err());
    }
    let mut i = 19;
    if bytes.get(i) == Some(&b'.') {
        i += 1;
        let frac_start = i;
        while bytes.get(i).is_some_and(|b| b.is_ascii_digit()) {
            i += 1;
        }
        if i == frac_start {
            return Err(err());
        }
    }
    match bytes.get(i) {
        Some(b) if b.eq_ignore_ascii_case(&b'z') => {
            i += 1;
        }
        Some(b'+') | Some(b'-') => {
            // `±HH:MM`: exactly five more chars, then end of string.
            if bytes.len() != i + 6 {
                return Err(err());
            }
            for j in [i + 1, i + 2, i + 4, i + 5] {
                if !is_digit(j) {
                    return Err(err());
                }
            }
            if bytes.get(i + 3) != Some(&b':') {
                return Err(err());
            }
            let tz_hour = pair(i + 1, i + 2);
            let tz_minute = pair(i + 4, i + 5);
            if tz_hour > 23 || tz_minute > 59 {
                return Err(err());
            }
            i += 6;
        }
        _ => return Err(err()),
    }
    if i != bytes.len() {
        return Err(err());
    }
    Ok(())
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: u32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Validates a [`Measurement`] against the registered `clocks` (§3.3–§3.4).
///
/// Enforces, in order: identifier shapes; `ms` unit for durations; clock
/// registration (the measurement's `clock_id`/`boot_id` must be registered,
/// and the registered descriptor's origin must match); endpoint shapes and
/// lifetime coherence (present endpoints share the measurement's clock, boot,
/// and origin); estimate/method/censoring coherence; endpoint-difference
/// requirements (duration quantity, present ordered endpoints, exact
/// `end - start` arithmetic — exact zero is valid); and resolution and
/// comparability-group shapes.
///
/// UTC annotations are shape-checked only; they never establish elapsed
/// time, ordering, or cross-clock occurrence order.
pub fn validate_measurement(
    measurement: &Measurement,
    clocks: &[ClockDescriptor],
) -> Result<(), String> {
    validate_identifier(&measurement.measurement_id, "measurement_id")?;
    validate_identifier(&measurement.name, "name")?;
    validate_scope(&measurement.scope)?;
    validate_identifier(&measurement.clock_id, "clock_id")?;
    validate_identifier(&measurement.boot_id, "boot_id")?;
    validate_identifier(&measurement.unit, "unit")?;
    if measurement.quantity == Quantity::Duration && measurement.unit != "ms" {
        return Err(format!(
            "duration measurement requires unit \"ms\", found {:?}",
            measurement.unit
        ));
    }

    let clock = clocks
        .iter()
        .find(|c| c.clock_id == measurement.clock_id && c.boot_id == measurement.boot_id)
        .ok_or_else(|| {
            format!(
                "unregistered clock/boot: clock_id {:?} boot_id {:?}",
                measurement.clock_id, measurement.boot_id
            )
        })?;
    validate_clock_descriptor(clock)?;
    if clock.origin != measurement.origin {
        return Err(
            "measurement origin does not match the registered clock origin".to_string(),
        );
    }

    let start = check_endpoint(&measurement.start, measurement, "start")?;
    let end = check_endpoint(&measurement.end, measurement, "end")?;

    let is_duration = measurement.quantity == Quantity::Duration;
    match &measurement.estimate {
        Estimate::Exact { value } => {
            if !matches!(
                measurement.method,
                Method::EndpointDifference | Method::SourceValue
            ) {
                return Err(
                    "exact estimate requires method endpoint_difference or source_value"
                        .to_string(),
                );
            }
            if measurement.censoring != Censoring::None {
                return Err("exact estimate requires censoring none".to_string());
            }
            if !value.is_finite() {
                return Err(format!("exact estimate value {value:?} is not finite"));
            }
            if is_duration && *value < 0.0 {
                return Err(format!("duration estimate value {value} is negative"));
            }
        }
        Estimate::Bounded {
            lower_bound,
            upper_bound,
        } => {
            if measurement.method != Method::EvidenceBound {
                return Err("bounded estimate requires method evidence_bound".to_string());
            }
            if measurement.censoring == Censoring::Unavailable {
                return Err(
                    "bounded estimate requires censoring none, left, right, or both"
                        .to_string(),
                );
            }
            let lower = check_bound(lower_bound, "lower_bound", is_duration)?;
            let upper = check_bound(upper_bound, "upper_bound", is_duration)?;
            match (lower, upper) {
                (None, None) => {
                    return Err(
                        "bounded estimate requires at least one numeric bound".to_string()
                    );
                }
                (Some(lo), Some(hi)) if lo > hi => {
                    return Err(format!(
                        "bounded estimate has lower_bound {lo} above upper_bound {hi}"
                    ));
                }
                _ => {}
            }
        }
        Estimate::Unavailable { value } => {
            validate_missing(value, "estimate.value")?;
            if measurement.method != Method::Unavailable {
                return Err("unavailable estimate requires method unavailable".to_string());
            }
            if measurement.censoring != Censoring::Unavailable {
                return Err("unavailable estimate requires censoring unavailable".to_string());
            }
        }
    }

    if measurement.method == Method::EndpointDifference {
        if !is_duration {
            return Err("endpoint_difference requires quantity duration".to_string());
        }
        let (Some(start), Some(end)) = (start, end) else {
            return Err(
                "endpoint_difference requires present start and end TimePoints".to_string(),
            );
        };
        if end.monotonic_offset_ms < start.monotonic_offset_ms {
            return Err("endpoint_difference requires ordered endpoints".to_string());
        }
        match &measurement.estimate {
            Estimate::Exact { value }
                if *value == end.monotonic_offset_ms - start.monotonic_offset_ms => {}
            _ => {
                return Err(
                    "endpoint_difference estimate must equal end - start exactly".to_string(),
                );
            }
        }
    }

    match &measurement.resolution {
        MaybeNumber::Num(value) => {
            if !value.is_finite() {
                return Err(format!("resolution {value:?} is not finite"));
            }
            if *value < 0.0 {
                return Err(format!("resolution {value} is negative"));
            }
        }
        MaybeNumber::Missing(missing) => validate_missing(missing, "resolution")?,
    }

    match &measurement.comparability_group {
        MaybeString::Text(group) => validate_identifier(group, "comparability_group")?,
        MaybeString::Missing(missing) => validate_missing(missing, "comparability_group")?,
    }

    Ok(())
}

/// Validates one endpoint: shape-checks a present [`TimePoint`] and requires
/// it to share the measurement's clock, boot, and origin; validates a
/// [`Missing`] envelope otherwise. Returns the present point, if any.
fn check_endpoint<'a>(
    endpoint: &'a MaybeTimePoint,
    measurement: &Measurement,
    what: &str,
) -> Result<Option<&'a TimePoint>, String> {
    match endpoint {
        MaybeTimePoint::Missing(missing) => {
            validate_missing(missing, what)?;
            Ok(None)
        }
        MaybeTimePoint::Present(point) => {
            validate_timepoint_shape(point, what)?;
            if point.clock_id != measurement.clock_id || point.boot_id != measurement.boot_id {
                return Err(format!(
                    "{what} uses clock_id {:?} boot_id {:?}, outside the measurement lifetime \
                     clock_id {:?} boot_id {:?}: cross-clock and cross-boot use is forbidden",
                    point.clock_id, point.boot_id, measurement.clock_id, measurement.boot_id
                ));
            }
            if point.origin != measurement.origin {
                return Err(format!(
                    "{what} origin does not match the measurement origin"
                ));
            }
            Ok(Some(point))
        }
    }
}

/// Validates one estimate bound: a finite number (nonnegative for durations)
/// or a valid [`Missing`] envelope. Returns the numeric bound, if any.
fn check_bound(
    bound: &MaybeNumber,
    what: &str,
    is_duration: bool,
) -> Result<Option<f64>, String> {
    match bound {
        MaybeNumber::Missing(missing) => {
            validate_missing(missing, &format!("estimate.{what}"))?;
            Ok(None)
        }
        MaybeNumber::Num(value) => {
            if !value.is_finite() {
                return Err(format!("estimate.{what} {value:?} is not finite"));
            }
            if is_duration && *value < 0.0 {
                return Err(format!("duration estimate.{what} {value} is negative"));
            }
            Ok(Some(*value))
        }
    }
}

/// Reports whether `now` has reached the `deadline` coordinate.
///
/// Both points must share one clock ID, boot ID, and origin; ordering
/// across clocks, boots, or origins is forbidden and returns `Err`.
/// Comparison uses monotonic offsets only — UTC annotations are validated
/// for shape but never consulted. Callers must use registered clocks.
pub fn boundary_reached(now: &TimePoint, deadline: &TimePoint) -> Result<bool, String> {
    validate_timepoint_shape(now, "now")?;
    validate_timepoint_shape(deadline, "deadline")?;
    if now.clock_id != deadline.clock_id {
        return Err("cannot order TimePoints across clock_id".to_string());
    }
    if now.boot_id != deadline.boot_id {
        return Err("cannot order TimePoints across boot_id".to_string());
    }
    if now.origin != deadline.origin {
        return Err("cannot order TimePoints across origin".to_string());
    }
    Ok(now.monotonic_offset_ms >= deadline.monotonic_offset_ms)
}
