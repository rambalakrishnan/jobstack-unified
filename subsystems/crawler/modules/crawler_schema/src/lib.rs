//! `crawler_schema`: closed schema gate for crawler records.
//!
//! Every value admitted through [`validate`] satisfies the EK-NULL /
//! EXT-TIME-NULL missingness invariant: no bare JSON `null` survives.
//! Each null is a `Missing` envelope (`{"value": null, "reason": ...}`
//! with an optional nonempty `detail`) whose reason is one of the six
//! kernel reasons. Empty arrays stay established empty collections;
//! `false`, `0`, and `""` remain real values.
//!
//! The gate is structural only: it never authorizes, verifies digests,
//! certifies capability, or enforces cross-record semantic rules.
//! Duplicate mapping keys cannot reach this gate: `serde_json::Value`
//! cannot represent them, so any value presented here has unique keys
//! by construction.

use serde_json::{Map, Value};

/// Closed registry of schema ids this gate admits.
///
/// The eleven operational entities plus the four closed crawler-profile
/// artifact shapes (§4). Anything else is an unknown version and is
/// rejected.
const KNOWN_SCHEMAS: &[&str] = &[
    "listing",
    "classifier_result",
    "work_item",
    "job_detail",
    "coverage_ledger",
    "cursor_state",
    "session_state",
    "audit_log",
    "state_mutation_record",
    "dead_letter",
    "seen_ids",
    "crawler_operational_snapshot",
    "crawler_coverage_export",
    "crawler_uncertified_traversal_observation",
    "crawler_job_feed",
];

/// The six and only six null reasons (§3.2).
const NULL_REASONS: &[&str] = &[
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

#[derive(Debug)]
pub struct CheckedRecord {
    schema_id: String,
    value: Value,
}

#[derive(Debug)]
pub struct Fault {
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceEntity {
    Listing,
    ClassifierResult,
    WorkItem,
    JobDetail,
    CoverageLedger,
    CursorState,
    SessionState,
    AuditLog,
    StateMutationRecord,
    DeadLetter,
    SeenIds,
}

impl SourceEntity {
    /// Registry id this entity validates under.
    pub fn schema_id(self) -> &'static str {
        match self {
            SourceEntity::Listing => "listing",
            SourceEntity::ClassifierResult => "classifier_result",
            SourceEntity::WorkItem => "work_item",
            SourceEntity::JobDetail => "job_detail",
            SourceEntity::CoverageLedger => "coverage_ledger",
            SourceEntity::CursorState => "cursor_state",
            SourceEntity::SessionState => "session_state",
            SourceEntity::AuditLog => "audit_log",
            SourceEntity::StateMutationRecord => "state_mutation_record",
            SourceEntity::DeadLetter => "dead_letter",
            SourceEntity::SeenIds => "seen_ids",
        }
    }
}

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

/// Validate `value` under the closed schema `schema_id`.
///
/// Rejects unknown schema ids, non-finite numbers, bare or recursive
/// nulls, malformed `Missing` envelopes, unknown null reasons, and
/// undeclared envelope fields. On success the value is returned
/// untouched inside a [`CheckedRecord`].
pub fn validate(schema_id: &str, value: Value) -> Result<CheckedRecord, Fault> {
    if !KNOWN_SCHEMAS.contains(&schema_id) {
        return Err(fault(
            "unknown_schema",
            format!("unknown schema id {schema_id:?}; gate admits only the closed registry"),
        ));
    }
    check_value("$", &value)?;
    Ok(CheckedRecord {
        schema_id: schema_id.to_string(),
        value,
    })
}

pub fn record_value(record: &CheckedRecord) -> &Value {
    &record.value
}

pub fn record_schema(record: &CheckedRecord) -> &str {
    &record.schema_id
}

fn check_value(path: &str, value: &Value) -> Result<(), Fault> {
    match value {
        Value::Null => Err(fault(
            "bare_null",
            format!("{path}: bare null; every null must be a Missing envelope with one of the six reasons"),
        )),
        Value::Bool(_) | Value::String(_) => Ok(()),
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    return Err(fault(
                        "non_finite_number",
                        format!("{path}: non-finite number is not a valid normalized value"),
                    ));
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_value(&format!("{path}[{i}]"), item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            let null_valued = map.get("value").is_some_and(Value::is_null);
            if null_valued || map.contains_key("reason") {
                check_missing(path, map)
            } else {
                for (key, item) in map {
                    check_value(&format!("{path}.{key}"), item)?;
                }
                Ok(())
            }
        }
    }
}

fn check_missing(path: &str, map: &Map<String, Value>) -> Result<(), Fault> {
    if !map.get("value").is_some_and(Value::is_null) {
        return Err(fault(
            "malformed_missing",
            format!("{path}: 'reason' outside a Missing envelope; envelope requires value:null"),
        ));
    }
    match map.get("reason") {
        Some(Value::String(r)) if NULL_REASONS.contains(&r.as_str()) => {}
        Some(Value::String(r)) => {
            return Err(fault(
                "unknown_reason",
                format!("{path}: unknown null reason {r:?}; only the six kernel reasons are admitted"),
            ));
        }
        _ => {
            return Err(fault(
                "missing_reason",
                format!("{path}: Missing envelope requires a reason from the six kernel reasons"),
            ));
        }
    }
    if let Some(detail) = map.get("detail") {
        match detail {
            Value::String(s) if !s.is_empty() => {}
            _ => {
                return Err(fault(
                    "invalid_detail",
                    format!("{path}: Missing detail must be a nonempty string when present"),
                ));
            }
        }
    }
    for key in map.keys() {
        if key != "value" && key != "reason" && key != "detail" {
            return Err(fault(
                "undeclared_field",
                format!("{path}: undeclared Missing envelope field {key:?}; envelope is closed"),
            ));
        }
    }
    Ok(())
}
