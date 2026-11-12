//! `rm_wire`: tier-0 structural validation and canonical hashing for Ringmaster.
//!
//! Implements the Common evidence and wire rules (§3.1 scalar/reference types,
//! §3.2 missingness, §3.5 hashing and storage):
//!
//! - [`validate_record`] structurally rejects unknown versions, extra
//!   (undeclared closed-object) fields, duplicate mapping keys, non-finite
//!   numbers, and normalized bare nulls (RM-C01), while accepting reasoned
//!   [`Missing`] envelopes and rejecting bare `null` at any depth (RM-C02).
//! - [`canonical_digest`] hashes the RFC 8785 canonical JSON form with SHA-256.
//! - [`artifact_digest`] hashes exact stored bytes with SHA-256.
//!
//! Structural validation is not authentication and not semantic conformance.

use sha2::{Digest as ShaDigest, Sha256};
use std::collections::BTreeMap;

/// A content digest: `sha256:` followed by 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Digest(pub String);

impl Digest {
    /// Parses and validates the exact `sha256:<64 lowercase hex>` form.
    pub fn parse(s: &str) -> Result<Self, String> {
        if !is_valid_digest(s) {
            return Err(format!("invalid digest: {s:?}"));
        }
        Ok(Digest(s.to_owned()))
    }

    /// Returns the digest string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Returns true when `s` is `sha256:` followed by exactly 64 lowercase hex digits.
pub fn is_valid_digest(s: &str) -> bool {
    let rest = match s.strip_prefix("sha256:") {
        Some(rest) => rest,
        None => return false,
    };
    rest.len() == 64
        && rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Formats a SHA-256 byte digest in the `sha256:<hex>` representation.
pub fn format_digest(sum: &[u8; 32]) -> Digest {
    let mut s = String::with_capacity(7 + 64);
    s.push_str("sha256:");
    for b in sum {
        s.push(hex_digit(b >> 4));
        s.push(hex_digit(b & 0x0f));
    }
    Digest(s)
}

fn hex_digit(n: u8) -> char {
    (b'0' + n + if n > 9 { b'a' - b'0' - 10 } else { 0 }) as char
}

/// Record schema registry entry: the expected `record_type`/`schema_version`.
#[derive(Debug, Clone, Copy)]
struct RecordSchema {
    schema_id: &'static str,
    record_type: &'static str,
    schema_version: &'static str,
}

/// Schemas accepted by [`validate_record`], grounded in the wire contracts.
const RECORD_SCHEMAS: &[RecordSchema] = &[
    RecordSchema {
        schema_id: "connector_request/v1",
        record_type: "connector_request",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "connector_response/v1",
        record_type: "connector_response",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "capability_descriptor/v1",
        record_type: "capability_descriptor",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "browseroxide_dom_export/v1",
        record_type: "browseroxide_dom_export",
        schema_version: "internal-browser-binding.browseroxide/0.1.0",
    },
    RecordSchema {
        schema_id: "browseroxide_primitive_record/v1",
        record_type: "browseroxide_primitive_record",
        schema_version: "internal-browser-binding.browseroxide/0.1.0",
    },
    RecordSchema {
        schema_id: "browseroxide_binding_descriptor/v1",
        record_type: "browseroxide_binding_descriptor",
        schema_version: "internal-browser-binding.browseroxide/0.1.0",
    },
    RecordSchema {
        schema_id: "ringmaster_plan/v1",
        record_type: "ringmaster_plan",
        schema_version: "ringmaster-plan/0.1.0",
    },
    RecordSchema {
        schema_id: "ringmaster_dom_reduction/v1",
        record_type: "ringmaster_dom_reduction",
        schema_version: "ringmaster-reduction/0.1.0",
    },
    RecordSchema {
        schema_id: "manifest/v1",
        record_type: "manifest",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "journal_event/v1",
        record_type: "journal_event",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "connector_task/v1",
        record_type: "connector_task",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "connector_descriptor/v1",
        record_type: "connector_descriptor",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "connector_preparation/v1",
        record_type: "connector_preparation",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "connector_handle/v1",
        record_type: "connector_handle",
        schema_version: "external-connector/0.1.0",
    },
    RecordSchema {
        schema_id: "diagnostic/v1",
        record_type: "diagnostic",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "replay_receipt/v1",
        record_type: "replay_receipt",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "lease_record/v1",
        record_type: "lease_record",
        schema_version: "evidence-kernel/0.1.0",
    },
    RecordSchema {
        schema_id: "attempt_commission/v1",
        record_type: "attempt_commission",
        schema_version: "application-attempt-lifecycle/0.1.0",
    },
    RecordSchema {
        schema_id: "attempt_axis_revision/v1",
        record_type: "attempt_axis_revision",
        schema_version: "application-attempt-lifecycle/0.1.0",
    },
    RecordSchema {
        schema_id: "application_attempt_snapshot/v1",
        record_type: "application_attempt_snapshot",
        schema_version: "application-attempt-lifecycle/0.1.0",
    },
    RecordSchema {
        schema_id: "owned_domain_revision/v1",
        record_type: "owned_domain_revision",
        schema_version: "owner-separated-write-domains/0.1.0",
    },
    RecordSchema {
        schema_id: "domain_publication_receipt/v1",
        record_type: "domain_publication_receipt",
        schema_version: "owner-separated-write-domains/0.1.0",
    },
    RecordSchema {
        schema_id: "logical_row/v1",
        record_type: "logical_row",
        schema_version: "owner-separated-write-domains/0.1.0",
    },
    RecordSchema {
        schema_id: "logical_row_archive/v1",
        record_type: "logical_row_archive",
        schema_version: "owner-separated-write-domains/0.1.0",
    },
    RecordSchema {
        schema_id: "write_domain_entity/v1",
        record_type: "write_domain_entity",
        schema_version: "owner-separated-write-domains/0.1.0",
    },
];

/// Structural cases for [`validate_record`].
const NONFINITE_TOKENS: &[&str] = &["NaN", "Infinity", "-Infinity", "inf", "-inf", "nan"];

/// The six permitted `Missing.reason` values (§3.2).
const MISSING_REASONS: &[&str] = &[
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
];

/// Closed top-level fields each schema accepts. Undeclared fields are rejected.
fn allowed_fields(schema: &RecordSchema) -> &'static [&'static str] {
    match schema.schema_id {
        "connector_request/v1" => &[
            "record_type",
            "schema_version",
            "request_id",
            "connector_id",
            "operation",
            "call_limit",
            "payload",
        ],
        "connector_response/v1" => &[
            "record_type",
            "schema_version",
            "request_id",
            "connector_id",
            "operation",
            "result",
        ],
        "capability_descriptor/v1" => &[
            "record_type",
            "schema_version",
            "descriptor_id",
            "descriptor_revision",
            "declared_by",
            "subject",
            "catalog",
            "evidence_prefix",
            "supersedes",
            "capabilities",
        ],
        "browseroxide_dom_export/v1" => &[
            "record_type",
            "schema_version",
            "root",
            "nodes",
            "boundaries",
            "completeness",
            "limitations",
        ],
        "browseroxide_primitive_record/v1" => &[
            "record_type",
            "schema_version",
            "primitive",
            "arguments",
            "authorization_ref",
            "limit",
            "result",
        ],
        "browseroxide_binding_descriptor/v1" => &[
            "record_type",
            "schema_version",
            "descriptor_id",
            "subject",
            "capabilities",
            "operations",
            "evidence_prefix",
        ],
        "ringmaster_plan/v1" => &["record_type", "schema_version", "steps"],
        "ringmaster_dom_reduction/v1" => &[
            "record_type",
            "schema_version",
            "source_root",
            "profile",
            "profile_policy",
            "byte_budget",
            "sections",
            "boundaries",
            "stabilization",
            "completeness",
            "limitations",
            "source_refs",
        ],
        "manifest/v1" => &[
            "record_type",
            "schema_version",
            "run_id",
            "task",
            "subject",
            "event_kinds",
        ],
        "journal_event/v1" => &[
            "record_type",
            "schema_version",
            "journal_id",
            "journal_sequence",
            "event_id",
            "event_kind",
            "event_schema_version",
            "recorded_at",
            "occurred_at",
            "causal_refs",
            "payload",
            "previous_event_hash",
            "event_hash",
        ],
        "connector_task/v1" => &[
            "record_type",
            "schema_version",
            "task_id",
            "task_type",
            "entry",
            "goal",
        ],
        "connector_descriptor/v1" => &[
            "record_type",
            "schema_version",
            "connector_id",
            "connector_version",
            "build",
            "binding",
            "subject",
            "capabilities",
            "operations",
            "task_mappings",
            "observation_channels",
            "action_grounding",
            "execution_substrate",
            "limits",
            "budget_accounting",
            "evidence_prefix",
        ],
        "connector_preparation/v1" => &[
            "record_type",
            "schema_version",
            "preparation_id",
            "task_semantic_hash",
            "delivered_task",
            "delivered_task_hash",
            "native_request",
            "native_request_hash",
        ],
        "connector_handle/v1" => &[
            "record_type",
            "schema_version",
            "handle",
            "preparation",
            "scope",
            "idempotency_key",
            "created_at",
        ],
        "diagnostic/v1" => &[
            "record_type",
            "schema_version",
            "diagnostic_id",
            "run_id",
            "comparisons",
            "result",
        ],
        "replay_receipt/v1" => &[
            "record_type",
            "schema_version",
            "replay_id",
            "mode",
            "run_id",
            "manifest_hash",
            "result",
        ],
        _ => &["record_type", "schema_version"],
    }
}

/// Validates `bytes` as a UTF-8 JSON record of schema `schema_id`.
///
/// Accepts exactly the registry entry whose `schema_id` matches, requiring the
/// declared `record_type`/`schema_version` discriminator pair. Rejects:
/// unknown `schema_id` or `schema_version` values (`Err`), duplicate mapping
/// keys, non-finite numbers, undeclared closed-object fields (extra fields),
/// and normalized bare `null`s at any depth. A required missing field must be
/// a `Missing` envelope (`value: null`, permitted `reason`, optional nonempty
/// `detail`); bare `null` is rejected.
///
/// Validation is structural only: success is not authentication and not
/// semantic conformance.
pub fn validate_record(schema_id: &str, bytes: &[u8]) -> Result<(), String> {
    let schema = RECORD_SCHEMAS
        .iter()
        .find(|s| s.schema_id == schema_id)
        .ok_or_else(|| format!("unknown schema: {schema_id:?}"))?;

    let text = std::str::from_utf8(bytes).map_err(|e| format!("invalid utf-8: {e}"))?;
    reject_nonfinite_literals(text)?;

    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid json: {e}"))?;

    let object = value
        .as_object()
        .ok_or_else(|| "record must be a JSON object".to_string())?;

    check_duplicate_keys(text)?;
    check_record(object, schema)
}

/// Computes the SHA-256 digest of the RFC 8785 canonical JSON form of `bytes`.
///
/// The input must be valid JSON; object keys are sorted lexicographically,
/// insignificant whitespace is removed, and strings/numbers are re-encoded in
/// canonical form. Array order and string contents are preserved. No defaults
/// are inserted, Unicode is not normalized, arrays are not reordered, and no
/// bytes are redacted. Returns `Err` for invalid JSON or non-UTF-8 input.
pub fn canonical_digest(bytes: &[u8]) -> Result<Digest, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("invalid utf-8: {e}"))?;
    reject_nonfinite_literals(text)?;
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid json: {e}"))?;
    check_duplicate_keys(text)?;
    check_no_bare_null(&value)?;
    let canonical = canonical_json(&value);
    Ok(sha256_hex(canonical.as_bytes()))
}

/// Computes the SHA-256 digest of the exact stored `bytes`.
///
/// Unlike [`canonical_digest`], no JSON parsing or canonicalization is
/// applied: the digest covers the bytes verbatim.
pub fn artifact_digest(bytes: &[u8]) -> Digest {
    sha256_hex(bytes)
}

fn sha256_hex(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let sum = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&sum);
    format_digest(&out)
}

fn find_schema(schema_version: &str) -> Option<&'static RecordSchema> {
    RECORD_SCHEMAS.iter().find(|s| {
        s.schema_version == schema_version
            || s.record_type == schema_version
            || s.schema_id == schema_version
    })
}

fn check_record(
    object: &serde_json::Map<String, serde_json::Value>,
    schema: &RecordSchema,
) -> Result<(), String> {
    match object.get("record_type") {
        Some(serde_json::Value::String(got)) if got == schema.record_type => {}
        Some(serde_json::Value::String(got)) => {
            return Err(format!(
                "record_type mismatch: expected {:?}, found {got:?}",
                schema.record_type
            ));
        }
        Some(_) => return Err("record_type must be a string".to_string()),
        None => return Err("missing required field: record_type".to_string()),
    }
    match object.get("schema_version") {
        Some(serde_json::Value::String(got)) if got == schema.schema_version => {}
        Some(serde_json::Value::String(got)) => {
            if find_schema(got).is_some() {
                return Err(format!(
                    "schema_version mismatch: expected {:?}, found {got:?}",
                    schema.schema_version
                ));
            }
            return Err(format!("unknown schema_version: {got:?}"));
        }
        Some(_) => return Err("schema_version must be a string".to_string()),
        None => return Err("missing required field: schema_version".to_string()),
    }
    let allowed = allowed_fields(schema);
    let mut unknown: Vec<&str> = Vec::new();
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            unknown.push(key.as_str());
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(format!("undeclared field(s): {}", unknown.join(", ")));
    }
    check_no_bare_null(&serde_json::Value::Object(object.clone()))?;
    check_missing_envelopes_deep(&serde_json::Value::Object(object.clone()), "$")?;
    check_scalars(object)?;
    Ok(())
}

/// Rejects `Missing`-shaped envelopes with bad reasons or details anywhere.
///
/// Any object whose `value` is `null` is a missing carrier: it must be
/// exactly the `Missing` envelope (`value`, `reason`, optional `detail`).
/// A bare `"value": null` without `reason` is a bare null, rejected here so
/// `check_no_bare_null` and this check agree at every depth.
fn check_missing_envelopes_deep(value: &serde_json::Value, path: &str) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            if map.get("value") == Some(&serde_json::Value::Null) {
                validate_missing_envelope(map, path)?;
            }
            for (key, item) in map {
                let child = format!("{path}.{key}");
                check_missing_envelopes_deep(item, &child)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_missing_envelopes_deep(item, &format!("{path}[{index}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_missing_envelope(
    map: &serde_json::Map<String, serde_json::Value>,
    path: &str,
) -> Result<(), String> {
    if map.len() > 3 {
        return Err(format!(
            "invalid Missing envelope at {path}: undeclared field"
        ));
    }
    for key in map.keys() {
        if key != "value" && key != "reason" && key != "detail" {
            return Err(format!(
                "invalid Missing envelope at {path}: undeclared field {key:?}"
            ));
        }
    }
    match map.get("reason") {
        Some(serde_json::Value::String(reason)) if MISSING_REASONS.contains(&reason.as_str()) => {}
        Some(serde_json::Value::String(reason)) => {
            return Err(format!("invalid Missing reason at {path}: {reason:?}"));
        }
        _ => {
            return Err(format!(
                "invalid Missing envelope at {path}: reason is required"
            ))
        }
    }
    match map.get("detail") {
        None => {}
        Some(serde_json::Value::String(detail)) if !detail.is_empty() => {}
        Some(serde_json::Value::String(_)) => {
            return Err(format!(
                "invalid Missing detail at {path}: detail must be nonempty"
            ));
        }
        Some(_) => {
            return Err(format!(
                "invalid Missing detail at {path}: detail must be a string"
            ))
        }
    }
    Ok(())
}

/// Rejects bare `null` at any depth: every null must be a `Missing` envelope.
///
/// A JSON object whose `value` is `null` is only accepted when it is exactly
/// the `Missing` envelope shape (`value`, `reason`, optional `detail`);
/// the envelope itself is the accepted carrier of the null.
fn check_no_bare_null(value: &serde_json::Value) -> Result<(), String> {
    match value {
        serde_json::Value::Null => {
            Err("bare null is not allowed; use a Missing envelope".to_string())
        }
        serde_json::Value::Array(items) => {
            for item in items {
                check_no_bare_null(item)?;
            }
            Ok(())
        }
        serde_json::Value::Object(map) => {
            if map.get("value") == Some(&serde_json::Value::Null) {
                // A null-carrying object must be exactly the Missing envelope.
                // Well-formed envelopes validate here; malformed ones were
                // already rejected by `check_missing_envelopes_deep`, so
                // re-validating keeps both passes in agreement.
                validate_missing_envelope(map, "$")?;
                if let Some(detail) = map.get("detail") {
                    check_no_bare_null(detail)?;
                }
                return Ok(());
            }
            for item in map.values() {
                check_no_bare_null(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Validates identifier/digest-shaped scalar fields present in the record.
fn check_scalars(object: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    for (key, value) in object {
        let name = key.as_str();
        if name == "digest" || name.ends_with("_digest") || name.ends_with("_hash") {
            if let serde_json::Value::String(s) = value {
                if !is_valid_digest(s) {
                    return Err(format!("invalid digest at {name:?}: {s:?}"));
                }
            }
        }
        if (name == "record_type" || name == "schema_version" || name.ends_with("_id"))
            && matches!(value, serde_json::Value::String(s) if s.is_empty())
        {
            return Err(format!("invalid identifier at {name:?}: must be nonempty"));
        }
    }
    Ok(())
}

/// Rejects non-finite JSON number literals before parsing.
///
/// `serde_json` rejects these by default; this pre-scan keeps the rejection
/// explicit (and deterministic) rather than relying on a parser error.
fn reject_nonfinite_literals(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let b = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if b == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if b == b'-' || b.is_ascii_alphabetic() {
            for token in NONFINITE_TOKENS {
                if text[index..].starts_with(token) {
                    let before = index.checked_sub(1).map(|i| bytes[i]).unwrap_or(b' ');
                    let after = text[index + token.len()..].bytes().next().unwrap_or(b' ');
                    let boundary_before =
                        !(before.is_ascii_alphanumeric() || before == b'_' || before == b'.');
                    let boundary_after =
                        !(after.is_ascii_alphanumeric() || after == b'_' || after == b'.');
                    if boundary_before && boundary_after {
                        return Err(format!("non-finite number is not allowed: {token}"));
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}

/// Detects duplicate keys within any single JSON object level.
///
/// Operates on the raw text with a minimal JSON scanner so duplicates are
/// observed even though `serde_json` keeps only the last occurrence. String
/// contents are compared by exact bytes; no Unicode normalization is applied.
fn check_duplicate_keys(text: &str) -> Result<(), String> {
    let bytes = text.as_bytes();
    let mut index = 0;
    // Each stack entry holds the keys seen at that object level.
    let mut stack: Vec<Vec<Vec<u8>>> = Vec::new();
    // Parallel stack: true while the current container level is an object.
    let mut is_object: Vec<bool> = Vec::new();
    // True when the next string token is a value rather than a key.
    let mut expect_value = false;

    let skip_string = |index: &mut usize| {
        // `bytes[*index] == b'"'` on entry; consumes through the closing quote.
        let start = *index;
        *index += 1;
        let mut escaped = false;
        while *index < bytes.len() {
            let b = bytes[*index];
            *index += 1;
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                break;
            }
        }
        start..*index
    };

    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let range = skip_string(&mut index);
                let raw = &bytes[range.start + 1..range.end - 1];
                let is_key = !expect_value
                    && is_object.last().copied().unwrap_or(false)
                    && peek_expects_colon(bytes, index);
                if is_key {
                    let level = stack.last_mut().expect("object level");
                    if level.iter().any(|k| k.as_slice() == raw) {
                        let key = String::from_utf8_lossy(raw);
                        return Err(format!("duplicate key: {key:?}"));
                    }
                    level.push(raw.to_vec());
                }
                expect_value = false;
            }
            b'{' => {
                stack.push(Vec::new());
                is_object.push(true);
                expect_value = false;
                index += 1;
            }
            b'[' => {
                stack.push(Vec::new());
                is_object.push(false);
                expect_value = false;
                index += 1;
            }
            b'}' | b']' => {
                stack.pop();
                is_object.pop();
                expect_value = false;
                index += 1;
            }
            b':' => {
                expect_value = true;
                index += 1;
            }
            b',' => {
                // Inside an object a comma returns to key position; inside an
                // array the next value is still a value.
                let in_object = is_object.last().copied().unwrap_or(false);
                expect_value = !in_object;
                index += 1;
            }
            b'\\' => {
                // Outside strings only `\/` line continuations are relevant;
                // advance conservatively.
                index += 1;
            }
            _ => {
                index += 1;
            }
        }
    }
    Ok(())
}

fn peek_expects_colon(bytes: &[u8], mut index: usize) -> bool {
    while index < bytes.len() {
        match bytes[index] {
            b' ' | b'\t' | b'\n' | b'\r' => index += 1,
            b':' => return true,
            _ => return false,
        }
    }
    false
}

/// Renders `value` as RFC 8785 canonical JSON.
///
/// Object keys are sorted by UTF-16 code-unit lexicographic order (which
/// coincides with byte order for the valid UTF-8 produced by `serde_json`),
/// no whitespace is emitted, numbers use their shortest round-trip form, and
/// array order plus string contents are preserved exactly.
fn canonical_json(value: &serde_json::Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &serde_json::Value, out: &mut String) {
    match value {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(true) => out.push_str("true"),
        serde_json::Value::Bool(false) => out.push_str("false"),
        serde_json::Value::Number(number) => {
            if let Some(n) = number.as_i64() {
                out.push_str(&n.to_string());
            } else if let Some(n) = number.as_u64() {
                out.push_str(&n.to_string());
            } else if let Some(n) = number.as_f64() {
                out.push_str(ryu::Buffer::new().format(n));
            } else {
                out.push_str(&number.to_string());
            }
        }
        serde_json::Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\u{08}' => out.push_str("\\b"),
                    '\u{0C}' => out.push_str("\\f"),
                    '\u{0A}' => out.push_str("\\n"),
                    '\u{0D}' => out.push_str("\\r"),
                    '\u{09}' => out.push_str("\\t"),
                    c if (c as u32) < 0x20 => {
                        out.push_str(&format!("\\u{:04x}", c as u32));
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        serde_json::Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| utf16_order(a, b));
            // RFC 8785 duplicate-key rejection happens before canonicalization;
            // a BTreeMap cannot hold duplicates, so reaching this point means
            // `check_duplicate_keys` already passed.
            let _ = BTreeMap::<&str, ()>::new();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(&serde_json::Value::String((*key).clone()), out);
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

fn utf16_order(a: &str, b: &str) -> std::cmp::Ordering {
    let au: Vec<u16> = a.encode_utf16().collect();
    let bu: Vec<u16> = b.encode_utf16().collect();
    au.cmp(&bu)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_format_is_lowercase_hex() {
        let d = artifact_digest(b"abc");
        assert_eq!(
            d.as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
