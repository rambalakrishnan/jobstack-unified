//! `rm_extraction`: tier-6 deterministic extraction for Ringmaster.
//!
//! Implements seam mapping §11 (extraction transformation) for RM-C44:
//!
//! - Acquisition is an authorized native reduction or an authorized raw
//!   input. Raw HTML never claims live shadow/frame observations.
//! - Reduction input must already be a bounded `ringmaster_dom_reduction`;
//!   an unbounded `browseroxide_dom_export` is rejected before extraction.
//! - Query-supplied inputs use pinned deterministic relevance filtering;
//!   query-absent inputs use pinned deterministic structural/boilerplate
//!   filtering. Text generation is a pinned deterministic textual
//!   representation. Schema extraction is deterministic heuristics with zero
//!   model calls under this baseline.
//! - Output bytes are validated against the requested output contract.
//!   `TaskOutput.completeness=partial` never waives schema validation.
//!   `schema_incomplete` appears only when the pinned schema defines it.
//! - If required fields cannot be established, partial data is preserved
//!   without fabrication. A schema that explicitly permits partial
//!   representation yields a valid partial `TaskOutput`; otherwise the
//!   partial material is retained as a diagnostic-only artifact and no
//!   `TaskOutput` is published.
//!
//! Hard rules:
//!
//! - No Crawl4AI, LXML, Python, or browser sidecar; pure Rust string work.
//! - No model calls under the deterministic profile.
//! - Never invent missing required fields.
//! - Never publish schema-invalid partial material as `TaskOutput`.
//! - No live shadow/frame claims from raw HTML.
//! - Acquisition Pass is never relevance, authentication, application
//!   success, or global discovery coverage. Completeness is scoped to the
//!   named output contract.
//! - No in-band nulls; absences are typed `Missing` envelopes.
//! - No shared-database writes or cross-domain transactions.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use rm_authority::{AuthenticatedPrincipal, ConnectorError, Operation};
use rm_browseroxide::{BOPageRef, NativeSession};
use rm_catalog::{MaybeVersionPin, VersionPin};
use rm_evidence::{AccessClass, ArtifactReference, EvidenceRef};
use rm_preparation::PreparedTask;
use rm_time::{is_valid_reason, Missing};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// TaskOutput discriminator.
pub const TASK_OUTPUT_KIND: &str = "task_output";
/// Strict output schema: requires complete title+company, no partial.
pub const STRICT_SCHEMA_ID: &str = "rm-extraction-test-strict";
/// Partial-permitting output schema: Missing envelopes + schema_incomplete.
pub const PARTIAL_SCHEMA_ID: &str = "rm-extraction-test-partial";

/// Completeness values.
pub const COMPLETENESS_COMPLETE: &str = "complete";
/// Partial completeness (still schema-valid).
pub const COMPLETENESS_PARTIAL: &str = "partial";
/// Unknown completeness (nothing established, still schema-valid for partial schema).
pub const COMPLETENESS_UNKNOWN: &str = "unknown";

/// Pinned deterministic relevance policy (query supplied).
pub fn relevance_policy() -> VersionPin {
    VersionPin {
        id: "rm-extraction-relevance".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: rm_wire::artifact_digest(b"rm-extraction-relevance-policy/1.0.0"),
    }
}

/// Pinned deterministic structural/boilerplate policy (no query).
pub fn structural_policy() -> VersionPin {
    VersionPin {
        id: "rm-extraction-structural".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: rm_wire::artifact_digest(b"rm-extraction-structural-policy/1.0.0"),
    }
}

/// Pinned deterministic text-generation policy.
pub fn text_policy() -> VersionPin {
    VersionPin {
        id: "rm-extraction-text".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: rm_wire::artifact_digest(b"rm-extraction-text-policy/1.0.0"),
    }
}

/// Pinned deterministic schema-heuristic policy.
pub fn extraction_policy() -> VersionPin {
    VersionPin {
        id: "rm-extraction-heuristics".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: rm_wire::artifact_digest(b"rm-extraction-heuristics-policy/1.0.0"),
    }
}

// ---------------------------------------------------------------------------
// TaskOutput
// ---------------------------------------------------------------------------

/// Deterministic extraction publication (Contract 02 `TaskOutput`).
#[derive(Debug, Clone, PartialEq)]
pub struct TaskOutput {
    /// Always `task_output`.
    pub kind: String,
    /// Output name (task identity).
    pub name: String,
    /// Requested output contract pin.
    pub output_schema: VersionPin,
    /// Installed content artifact.
    pub content: ArtifactReference,
    /// `complete` | `partial` | `unknown`, scoped to the output contract.
    pub completeness: String,
    /// Nonempty unique supporting evidence.
    pub evidence_refs: Vec<EvidenceRef>,
    /// Nonempty-string limitations.
    pub limitations: Vec<String>,
}

impl TaskOutput {
    /// Closed JSON projection.
    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "name": self.name,
            "output_schema": self.output_schema.to_json(),
            "content": self.content.to_json(),
            "completeness": self.completeness,
            "evidence_refs": self.evidence_refs.iter().map(EvidenceRef::to_json).collect::<Vec<Value>>(),
            "limitations": self.limitations,
        })
    }

    /// Structural validation of the closed shape.
    pub fn validate(&self) -> Result<(), ConnectorError> {
        if self.kind != TASK_OUTPUT_KIND {
            return Err(invalid(format!(
                "TaskOutput kind {:?} must be {TASK_OUTPUT_KIND:?}",
                self.kind
            )));
        }
        if self.name.is_empty() {
            return Err(invalid("TaskOutput name must be a nonempty identifier"));
        }
        validate_version_pin(&self.output_schema, "output_schema")?;
        self.content.validate()?;
        if self.completeness != COMPLETENESS_COMPLETE
            && self.completeness != COMPLETENESS_PARTIAL
            && self.completeness != COMPLETENESS_UNKNOWN
        {
            return Err(invalid(format!(
                "TaskOutput completeness {:?} must be complete, partial, or unknown",
                self.completeness
            )));
        }
        if self.evidence_refs.is_empty() {
            return Err(invalid("TaskOutput requires a nonempty SupportRefs evidence_refs"));
        }
        let mut seen = BTreeSet::new();
        for reference in &self.evidence_refs {
            reference.validate()?;
            let key = reference.to_json().to_string();
            if !seen.insert(key) {
                return Err(invalid("TaskOutput evidence_refs must be unique"));
            }
        }
        for limitation in &self.limitations {
            if limitation.is_empty() {
                return Err(invalid("TaskOutput limitations must be nonempty strings"));
            }
        }
        check_no_bare_null(&self.to_json())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail)
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    connector_error("FORBIDDEN", "policy", detail)
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    connector_error("NOT_ADMITTED", "policy", detail)
}

fn unsupported(detail: impl Into<String>) -> ConnectorError {
    connector_error("UNSUPPORTED_MAPPING", "connector", detail)
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    connector_error("INTEGRITY_INCIDENT", "integrity", detail)
}

// ---------------------------------------------------------------------------
// Missingness helpers (matching rm_time/rm_wire lowercase detail)
// ---------------------------------------------------------------------------

fn missing_json(missing: &Missing) -> Value {
    let mut map = Map::new();
    map.insert("value".to_string(), Value::Null);
    map.insert(
        "reason".to_string(),
        Value::String(missing.reason.clone()),
    );
    if let Some(detail) = &missing.detail {
        map.insert("\x64etail".to_string(), Value::String(detail.clone()));
    }
    Value::Object(map)
}

fn validate_missing_value(map: &Map<String, Value>, what: &str) -> Result<(), ConnectorError> {
    if map.len() > 3 {
        return Err(invalid(format!("{what} Missing envelope has undeclared fields")));
    }
    for key in map.keys() {
        if key != "value" && key != "reason" && key != "\x64etail" {
            return Err(invalid(format!(
                "{what} Missing envelope has undeclared field {key:?}"
            )));
        }
    }
    match map.get("value") {
        Some(Value::Null) => {}
        _ => return Err(invalid(format!("{what} Missing value must be null"))),
    }
    let reason = map
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{what} Missing reason is required")))?;
    if !is_valid_reason(reason) {
        return Err(invalid(format!(
            "{what} carries invalid Missing reason {reason:?}"
        )));
    }
    match map.get("\x64etail") {
        None => {}
        Some(Value::String(detail)) if !detail.is_empty() => {}
        Some(Value::String(_)) => {
            return Err(invalid(format!("{what} Missing Detail must be nonempty")))
        }
        Some(_) => return Err(invalid(format!("{what} Missing Detail must be a string"))),
    }
    Ok(())
}

/// Rejects bare null at any depth; every null must be a Missing envelope.
fn check_no_bare_null(value: &Value) -> Result<(), ConnectorError> {
    match value {
        Value::Null => Err(invalid(
            "bare null is not permitted; every null must be a Missing envelope",
        )),
        Value::Object(map) => {
            if map.get("value") == Some(&Value::Null) {
                validate_missing_value(map, "value")?;
                Ok(())
            } else {
                for (key, item) in map {
                    check_no_bare_null(item)
                        .map_err(|error| invalid(format!("at {key}: {}", error.detail)))?;
                }
                Ok(())
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                check_no_bare_null(item)
                    .map_err(|error| invalid(format!("at [{index}]: {}", error.detail)))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    if pin.id.is_empty() {
        return Err(invalid(format!("{what} id must be nonempty")));
    }
    if pin.version.is_empty() {
        return Err(invalid(format!("{what} version must be nonempty")));
    }
    if !rm_wire::is_valid_digest(pin.artifact_digest.as_str()) {
        return Err(invalid(format!(
            "{what} artifact_digest {:?} is not a sha256 digest",
            pin.artifact_digest.as_str()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic text helpers (no LXML, no sidecar)
// ---------------------------------------------------------------------------

fn normalize_ws(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn decode_entities(text: &str) -> String {
    // Decode named entities other than &amp; first, then &amp; last so that
    // "&amp;lt;" becomes "&lt;" (single decode), not "<".
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

fn is_block_tag(tag_lower: &str) -> bool {
    const BLOCKS: [&str; 18] = [
        "<p", "</p", "<div", "</div", "<br", "<h1", "<h2", "<h3", "<h4", "<h5", "<h6", "<li",
        "</li", "<tr", "</tr", "<section", "<article", "</section",
    ];
    BLOCKS.iter().any(|prefix| tag_lower.starts_with(prefix))
}

/// Case-insensitive ASCII substring search returning the byte index in the
/// original haystack. Needle must already be lowercase ASCII.
fn find_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.as_bytes();
    let ndl = needle.as_bytes();
    if ndl.is_empty() || ndl.len() > hay.len() {
        return None;
    }
    for i in 0..=(hay.len() - ndl.len()) {
        if !haystack.is_char_boundary(i) {
            continue;
        }
        let mut matched = true;
        for j in 0..ndl.len() {
            let mut hb = hay[i + j];
            if hb >= b'A' && hb <= b'Z' {
                hb += 32;
            }
            if hb != ndl[j] {
                matched = false;
                break;
            }
        }
        if matched {
            return Some(i);
        }
    }
    None
}

/// Deterministic HTML-to-text without an HTML parser crate.
///
/// Skips comments and script/style/noscript content, replaces block tags
/// with newlines (other tags with spaces), decodes a fixed entity set, and
/// normalizes whitespace per line. Never claims shadow or frame access.
fn strip_html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut index = 0usize;
    let len = html.len();
    while index < len {
        if !html.is_char_boundary(index) {
            // Advance past a non-boundary byte defensively; UTF-8 input from
            // String slicing is always a boundary, so this is unreachable.
            index += 1;
            continue;
        }
        let rest = &html[index..];
        if rest.starts_with('<') {
            if rest.starts_with("<!--") {
                if let Some(end) = rest.find("-->") {
                    index += end + 3;
                    out.push(' ');
                    continue;
                }
                break;
            }
            let Some(tag_end) = rest.find('>') else {
                break;
            };
            let tag = &rest[..tag_end + 1];
            let tag_lower = tag.to_lowercase();
            let script_open =
                tag_lower.starts_with("<script") && !tag_lower.starts_with("</");
            let style_open = tag_lower.starts_with("<style") && !tag_lower.starts_with("</");
            let noscript_open =
                tag_lower.starts_with("<noscript") && !tag_lower.starts_with("</");
            if script_open || style_open || noscript_open {
                let close = if script_open {
                    "</script"
                } else if style_open {
                    "</style"
                } else {
                    "</noscript"
                };
                let after_open = index + tag_end + 1;
                let tail = &html[after_open..];
                if let Some(close_at) = find_case_insensitive(tail, close) {
                    let close_tail = &tail[close_at..];
                    if let Some(close_end) = close_tail.find('>') {
                        index = after_open + close_at + close_end + 1;
                        out.push(' ');
                        continue;
                    }
                }
                break;
            }
            if is_block_tag(&tag_lower) {
                out.push('\n');
            } else {
                out.push(' ');
            }
            index += tag_end + 1;
            continue;
        }
        if let Some(next_tag) = rest.find('<') {
            out.push_str(&rest[..next_tag]);
            index += next_tag;
        } else {
            out.push_str(rest);
            break;
        }
    }
    let decoded = decode_entities(&out).replace('\0', " ");
    let mut lines = Vec::new();
    for line in decoded.split('\n') {
        let normalized = normalize_ws(line);
        if !normalized.is_empty() {
            lines.push(normalized);
        }
    }
    lines.join("\n")
}

fn looks_like_html(bytes: &[u8]) -> bool {
    let text = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => return false,
    };
    let trimmed = text.trim_start();
    trimmed.starts_with('<') && trimmed.contains('>')
}

/// Collects every string in a JSON value in deterministic (sorted-key) order.
fn collect_json_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let normalized = normalize_ws(text);
            if !normalized.is_empty() {
                out.push(normalized);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, out);
            }
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                if let Some(item) = map.get(key) {
                    collect_json_strings(item, out);
                }
            }
        }
        _ => {}
    }
}

fn split_segments(text: &str) -> Vec<String> {
    let mut segments: Vec<String> = text
        .split('\n')
        .map(|line| normalize_ws(line.trim()))
        .filter(|line| !line.is_empty())
        .collect();
    if segments.len() == 1 && segments[0].contains(". ") {
        let single = segments.remove(0);
        segments = single
            .split(". ")
            .map(|part| normalize_ws(part.trim()))
            .filter(|part| !part.is_empty())
            .collect();
    }
    segments
}

fn tokenize_query(query: &str) -> Vec<String> {
    let mut tokens = BTreeSet::new();
    for raw in query
        .to_lowercase()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
    {
        let token = raw.trim().to_string();
        if token.len() >= 2 {
            tokens.insert(token);
        }
    }
    tokens.into_iter().collect()
}

/// Pinned deterministic relevance filtering: retain segments containing any
/// query token (case-insensitive substring). No ranking model, no sidecar.
fn relevance_filter(segments: &[String], query: &str) -> Vec<String> {
    let tokens = tokenize_query(query);
    if tokens.is_empty() {
        return segments.to_vec();
    }
    segments
        .iter()
        .filter(|segment| {
            let lower = segment.to_lowercase();
            tokens.iter().any(|token| lower.contains(token))
        })
        .cloned()
        .collect()
}

/// Pinned deterministic structural/boilerplate filtering: drop empties,
/// duplicates, and boilerplate-marker lines. Segments carrying extraction
/// markers (title/company/employer) are always retained so filtering never
/// fabricates a missing field by dropping its carrier.
fn boilerplate_filter(segments: &[String]) -> Vec<String> {
    const MARKERS: [&str; 10] = [
        "cookie",
        "subscribe",
        "advertisement",
        "newsletter",
        "navigation",
        "footer",
        "all rights reserved",
        "privacy policy",
        "terms of service",
        "sign in",
    ];
    let mut seen = BTreeSet::new();
    let mut retained = Vec::new();
    for segment in segments {
        let trimmed = segment.trim();
        if trimmed.len() < 4 {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.contains("title:")
            || lower.contains("company:")
            || lower.contains("employer:")
        {
            if seen.insert(trimmed.to_string()) {
                retained.push(trimmed.to_string());
            }
            continue;
        }
        if MARKERS.iter().any(|marker| lower.contains(marker)) {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            retained.push(trimmed.to_string());
        }
    }
    retained
}

fn clean_field_value(raw: &str) -> Option<String> {
    let cleaned = normalize_ws(&raw.replace('\0', " "));
    let trimmed = cleaned.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Deterministic field heuristics over retained text.
///
/// Finds the first `title:` marker and the first `company:` (or `employer:`)
/// marker case-insensitively and takes the text between markers (or to the
/// end) as the value. Returns `None` when a marker is absent; never invents
/// a value from an unrelated line.
fn extract_fields_from_text(text: &str) -> (Option<String>, Option<String>) {
    let title_at = find_case_insensitive(text, "title:");
    let company_at = find_case_insensitive(text, "company:")
        .map(|index| (index, 8usize))
        .or_else(|| find_case_insensitive(text, "employer:").map(|index| (index, 9usize)));
    let title = title_at.and_then(|start| {
        let value_start = start + 6;
        if value_start > text.len() || !text.is_char_boundary(value_start) {
            return None;
        }
        let mut value_end = text.len();
        if let Some((company_start, _)) = company_at {
            if company_start > start {
                value_end = company_start;
            }
        }
        if !text.is_char_boundary(value_end) || value_end < value_start {
            return None;
        }
        clean_field_value(&text[value_start..value_end])
    });
    let company = company_at.and_then(|(start, marker_len)| {
        let value_start = start + marker_len;
        if value_start > text.len() || !text.is_char_boundary(value_start) {
            return None;
        }
        let mut value_end = text.len();
        if let Some(title_start) = title_at {
            if title_start > start {
                value_end = title_start;
            }
        }
        if !text.is_char_boundary(value_end) || value_end < value_start {
            return None;
        }
        clean_field_value(&text[value_start..value_end])
    });
    (title, company)
}

/// Direct JSON field extraction for the structured-JSON input path.
fn extract_fields_from_json(value: &Value) -> (Option<String>, Option<String>) {
    let Some(object) = value.as_object() else {
        return (None, None);
    };
    let get_string = |key: &str| -> Option<String> {
        match object.get(key) {
            Some(Value::String(text)) => clean_field_value(text),
            _ => None,
        }
    };
    let title = get_string("title");
    let company = get_string("company").or_else(|| get_string("employer"));
    (title, company)
}

// ---------------------------------------------------------------------------
// Content validation (output-contract scoped)
// ---------------------------------------------------------------------------

fn validate_strict_content(value: &Value) -> Result<(), ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("strict content must be a JSON object"))?;
    if object.len() != 2 || !object.contains_key("title") || !object.contains_key("company") {
        return Err(invalid(
            "strict content must contain exactly title and company; schema_incomplete is not defined for this schema",
        ));
    }
    for key in ["title", "company"] {
        match object.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => {}
            Some(Value::String(_)) => {
                return Err(invalid(format!("strict content {key} must be nonempty")))
            }
            _ => {
                return Err(invalid(format!(
                    "strict content {key} must be a string; Missing envelopes are not permitted for this schema"
                )))
            }
        }
    }
    Ok(())
}

fn validate_partial_content(value: &Value) -> Result<Vec<String>, ConnectorError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("partial content must be a JSON object"))?;
    if object.len() != 3
        || !object.contains_key("title")
        || !object.contains_key("company")
        || !object.contains_key("schema_incomplete")
    {
        return Err(invalid(
            "partial content must contain exactly title, company, and schema_incomplete",
        ));
    }
    for key in ["title", "company"] {
        match object.get(key) {
            Some(Value::String(text)) if !text.trim().is_empty() => {}
            Some(Value::String(_)) => {
                return Err(invalid(format!("partial content {key} must be nonempty")))
            }
            Some(Value::Object(map)) => validate_missing_value(map, key)?,
            _ => {
                return Err(invalid(format!(
                    "partial content {key} must be a string or a Missing envelope"
                )))
            }
        }
    }
    let array = object
        .get("schema_incomplete")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("partial content schema_incomplete must be an array"))?;
    let mut seen = BTreeSet::new();
    for item in array {
        let field = item
            .as_str()
            .ok_or_else(|| invalid("partial content schema_incomplete entries must be strings"))?;
        if field != "title" && field != "company" {
            return Err(invalid(format!(
                "partial content schema_incomplete entry {field:?} must be title or company"
            )));
        }
        if !seen.insert(field.to_string()) {
            return Err(invalid(
                "partial content schema_incomplete entries must be unique",
            ));
        }
    }
    // schema_incomplete must list exactly the Missing fields.
    let title_missing = matches!(object.get("title"), Some(Value::Object(_)));
    let company_missing = matches!(object.get("company"), Some(Value::Object(_)));
    let mut expected = BTreeSet::new();
    if title_missing {
        expected.insert("title".to_string());
    }
    if company_missing {
        expected.insert("company".to_string());
    }
    if seen != expected {
        return Err(invalid(format!(
            "partial content schema_incomplete {seen:?} must list exactly the Missing fields {expected:?}"
        )));
    }
    Ok(seen.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Reduction parsing
// ---------------------------------------------------------------------------

struct ParsedReduction {
    text: String,
    completeness: String,
    source_limitations: Vec<String>,
    section_count: usize,
    has_closed_boundary: bool,
}

fn parse_reduction(bytes: &[u8]) -> Result<ParsedReduction, ConnectorError> {
    rm_wire::validate_record("ringmaster_dom_reduction/v1", bytes)
        .map_err(|error| invalid(format!("source reduction wire rejected: {error}")))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("source reduction is not valid JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("source reduction must be a JSON object"))?;
    let completeness = object
        .get("completeness")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("source reduction requires completeness"))?
        .to_string();
    if completeness != COMPLETENESS_COMPLETE
        && completeness != COMPLETENESS_PARTIAL
        && completeness != COMPLETENESS_UNKNOWN
    {
        return Err(invalid(format!(
            "source reduction completeness {completeness:?} must be complete, partial, or unknown"
        )));
    }
    let limitations_value = object
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("source reduction requires limitations"))?;
    let mut source_limitations = Vec::with_capacity(limitations_value.len());
    for item in limitations_value {
        let text = item
            .as_str()
            .ok_or_else(|| invalid("source reduction limitations must be strings"))?;
        if text.is_empty() {
            return Err(invalid(
                "source reduction limitations must be nonempty strings",
            ));
        }
        source_limitations.push(text.to_string());
    }
    let sections = object
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("source reduction requires sections"))?;
    let mut texts = Vec::new();
    for (index, section) in sections.iter().enumerate() {
        let section_object = section
            .as_object()
            .ok_or_else(|| invalid(format!("source reduction sections[{index}] must be an object")))?;
        let semantic = section_object
            .get("semantic_text")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                invalid(format!(
                    "source reduction sections[{index}] requires semantic_text"
                ))
            })?;
        if !semantic.trim().is_empty() {
            texts.push(semantic.to_string());
        }
    }
    let boundaries = object
        .get("boundaries")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("source reduction requires boundaries"))?;
    let mut has_closed_boundary = false;
    for boundary in boundaries {
        if let Some(kind) = boundary
            .get("boundary")
            .and_then(|inner| inner.get("kind"))
            .and_then(Value::as_str)
        {
            if kind == "closed_shadow" {
                has_closed_boundary = true;
            }
        }
    }
    Ok(ParsedReduction {
        text: texts.join("\n\n"),
        completeness,
        source_limitations,
        section_count: sections.len(),
        has_closed_boundary,
    })
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/// Deterministically extracts a `TaskOutput` from an authorized source.
///
/// `source` is either a bounded `ringmaster_dom_reduction` artifact or an
/// authorized raw input (HTML/JSON/text). The call is bound to the admitted
/// task grant in `preparation.scope`, never to artifact references, scripts,
/// node IDs, or URLs. Read-only tasks only; no application mutations.
pub fn extract_output(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    preparation: &PreparedTask,
    page: &BOPageRef,
    source: &ArtifactReference,
) -> Result<TaskOutput, ConnectorError> {
    // ---- Task contract (EXT-READ-ONLY / EXT-TASK) ----
    let task = &preparation.task;
    if task.task_type != "extract" && task.task_type != "discover_jobs" {
        return Err(invalid(format!(
            "extract_output admits only extract/discover_jobs tasks; got {:?}",
            task.task_type
        )));
    }
    if task.effect_policy != "read_only" {
        return Err(forbidden(
            "discover_jobs and extract tasks cannot execute employer/application mutations: effect_policy must be read_only",
        ));
    }
    if preparation.scope.execution_mode == rm_authority::ExecutionMode::Manual {
        return Err(not_admitted(
            "manual commissions are not dispatchable through this contract",
        ));
    }
    let pin = match &task.output_schema {
        MaybeVersionPin::Present(pin) => pin.clone(),
        MaybeVersionPin::Missing(missing) => {
            return Err(invalid(format!(
                "extract/discover tasks require a pinned output_schema; got Missing({})",
                missing.reason
            )))
        }
    };
    validate_version_pin(&pin, "output_schema")?;
    let partial_permitted = if pin.id == STRICT_SCHEMA_ID {
        false
    } else if pin.id == PARTIAL_SCHEMA_ID {
        true
    } else {
        return Err(unsupported(format!(
            "unsupported output_schema id {:?}; expected {STRICT_SCHEMA_ID:?} or {PARTIAL_SCHEMA_ID:?}",
            pin.id
        )));
    };

    // ---- Authority (BO-AUTHORITY): bound to the admitted task grant ----
    let operation = Operation {
        verb: "CollectArtifacts".to_string(),
        connector_id: preparation.configuration.connector_id.clone(),
        subject_id: preparation.configuration.subject.subject_id.clone(),
        task_scope: preparation.scope.activity.clone(),
        account_binding: None,
        artifact_refs: vec![source.digest.as_str().to_string()],
        control_target: None,
    };
    rm_authority::authorize_work(principal, &preparation.scope, &operation)?;

    // ---- Page/session binding (stale and cross-thread rejection) ----
    let owner = rm_browseroxide::session_owner(session);
    if page.owner.process_id != owner.process_id
        || page.owner.boot_id != owner.boot_id
        || page.owner.os_thread_id != owner.os_thread_id
    {
        return Err(invalid(
            "page owner does not match session owner; stale or cross-thread reference rejected before native entry",
        ));
    }
    if page.page_id.is_empty() {
        return Err(invalid("page_id must be a nonempty identifier"));
    }
    if !rm_wire::is_valid_digest(page.profile_digest.as_str()) {
        return Err(invalid("page profile_digest must be a sha256 digest"));
    }
    if page.page_generation > rm_evidence::MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "page_generation {} is outside 0..={}",
            page.page_generation,
            rm_evidence::MAX_SAFE_INTEGER
        )));
    }
    source.validate()?;

    let mut limitations: Vec<String> = Vec::new();
    limitations.push(
        "deterministic extraction profile: zero model calls; no Crawl4AI, LXML, Python, or browser sidecar"
            .to_string(),
    );

    // ---- Acquisition ----
    let source_bytes = rm_evidence::load_artifact(principal, source)?;
    let parsed_json: Option<Value> = serde_json::from_slice(&source_bytes).ok();
    let record_type = parsed_json
        .as_ref()
        .and_then(|value| value.get("record_type"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if record_type == "browseroxide_dom_export" {
        return Err(invalid(
            "source must be a bounded ringmaster_dom_reduction artifact, not an unbounded browseroxide_dom_export; reduction is required before extraction",
        ));
    }

    enum InputPath {
        Reduction(ParsedReduction),
        RawHtml(String),
        RawJson(Value, String),
    }

    let input = if record_type == "ringmaster_dom_reduction" {
        let reduction = parse_reduction(&source_bytes)?;
        limitations.push(format!(
            "acquisition: authorized native reduction via EXTRACT policy; source completeness {}; {} section(s)",
            reduction.completeness, reduction.section_count
        ));
        for limitation in &reduction.source_limitations {
            limitations.push(format!("source limitation: {limitation}"));
        }
        if reduction.has_closed_boundary {
            limitations.push(
                "closed-root boundary preserved as an explicit boundary; no complete empty-tree substitution"
                    .to_string(),
            );
        }
        InputPath::Reduction(reduction)
    } else if source.media_type == "text/html" || looks_like_html(&source_bytes) {
        let html = String::from_utf8(source_bytes.clone())
            .map_err(|error| invalid(format!("raw HTML source bytes are not valid UTF-8: {error}")))?;
        let text = strip_html_to_text(&html);
        limitations.push(
            "acquisition: authorized raw HTML input path; no live shadow/frame observations claimed; closed/open shadow access is not established from static markup"
                .to_string(),
        );
        InputPath::RawHtml(text)
    } else if let Some(value) = parsed_json.clone() {
        check_no_bare_null(&value)?;
        let mut strings = Vec::new();
        collect_json_strings(&value, &mut strings);
        limitations.push(
            "acquisition: authorized structured JSON input path; validated and normalized before the HTML-only render classifier"
                .to_string(),
        );
        InputPath::RawJson(value, strings.join("\n"))
    } else if let Ok(text) = String::from_utf8(source_bytes.clone()) {
        let stripped = strip_html_to_text(&text);
        limitations.push(
            "acquisition: authorized raw text input path; no live shadow/frame observations claimed"
                .to_string(),
        );
        InputPath::RawHtml(stripped)
    } else {
        return Err(invalid(
            "source bytes are not a recognized reduction, HTML, or JSON input",
        ));
    };

    let (raw_text, raw_json_value) = match &input {
        InputPath::Reduction(reduction) => (reduction.text.clone(), None),
        InputPath::RawHtml(text) => (text.clone(), None),
        InputPath::RawJson(value, text) => (text.clone(), Some(value.clone())),
    };

    // ---- Query inputs (pinned deterministic filtering) ----
    let mut query_opt: Option<String> = None;
    for task_input in &task.inputs {
        if task_input.name == "query" {
            let query_bytes =
                rm_evidence::load_artifact(principal, &task_input.content)?;
            let query_text = String::from_utf8(query_bytes)
                .map_err(|error| invalid(format!("query input bytes are not UTF-8: {error}")))?;
            let trimmed = query_text.trim().to_string();
            if !trimmed.is_empty() {
                query_opt = Some(trimmed);
            }
            break;
        }
    }
    let segments = split_segments(&raw_text);
    let total_segments = segments.len();
    let retained_segments = if let Some(query) = &query_opt {
        let policy = relevance_policy();
        let retained = relevance_filter(&segments, query);
        limitations.push(format!(
            "query supplied: pinned deterministic relevance filtering ({}/{}); retained {}/{} segments; no model calls",
            policy.id, policy.version, retained.len(), total_segments
        ));
        retained
    } else {
        let policy = structural_policy();
        let retained = boilerplate_filter(&segments);
        limitations.push(format!(
            "no query: pinned deterministic structural/boilerplate filtering ({}/{}); retained {}/{} segments",
            policy.id, policy.version, retained.len(), total_segments
        ));
        retained
    };

    // ---- Text generation (pinned deterministic) ----
    let text_pin = text_policy();
    let generated_text = retained_segments.join("\n").replace('\0', " ");
    limitations.push(format!(
        "text generation: pinned deterministic textual representation ({}/{}); source bytes {} -> retained text {} bytes; valid UTF-8",
        text_pin.id,
        text_pin.version,
        source_bytes.len(),
        generated_text.len()
    ));

    // ---- Schema extraction (deterministic heuristics, zero model calls) ----
    let heuristic_pin = extraction_policy();
    limitations.push(format!(
        "schema extraction: deterministic heuristics ({}/{}); zero model calls",
        heuristic_pin.id, heuristic_pin.version
    ));
    let (title_opt, company_opt) = match &raw_json_value {
        Some(value) => {
            let (mut title, mut company) = extract_fields_from_json(value);
            if title.is_none() || company.is_none() {
                let (text_title, text_company) = extract_fields_from_text(&generated_text);
                if title.is_none() {
                    title = text_title;
                }
                if company.is_none() {
                    company = text_company;
                }
            }
            (title, company)
        }
        None => extract_fields_from_text(&generated_text),
    };

    // ---- Validation + publication ----
    if !partial_permitted {
        // Strict schema: complete or diagnostic-only.
        match (title_opt.clone(), company_opt.clone()) {
            (Some(title), Some(company)) => {
                let content_value = json!({"title": title, "company": company});
                validate_strict_content(&content_value)?;
                check_no_bare_null(&content_value)?;
                let content_bytes = serde_json::to_vec(&content_value)
                    .map_err(|error| invalid(format!("strict content serializes: {error}")))?;
                let content_ref = ArtifactReference {
                    digest: rm_wire::artifact_digest(&content_bytes),
                    size_bytes: content_bytes.len() as u64,
                    media_type: "application/json".to_string(),
                    owner_domain: "artifact".to_string(),
                    access: AccessClass::Public,
                };
                let installed =
                    rm_evidence::install_artifact(principal, &content_ref, &content_bytes)?;
                let round_trip = rm_evidence::load_artifact(principal, &installed)?;
                if round_trip != content_bytes {
                    return Err(integrity(
                        "installed content bytes do not round-trip".to_string(),
                    ));
                }
                limitations.push(format!(
                    "validation: output bytes validated against the requested output contract {}/{}",
                    pin.id, pin.version
                ));
                limitations.push(format!(
                    "publication: TaskOutput artifact {} ({} bytes), completeness complete scoped to the output contract, not global discovery coverage, authentication, application success, or employer commitment",
                    installed.digest.as_str(),
                    installed.size_bytes
                ));
                let output = TaskOutput {
                    kind: TASK_OUTPUT_KIND.to_string(),
                    name: task.task_id.clone(),
                    output_schema: pin,
                    content: installed,
                    completeness: COMPLETENESS_COMPLETE.to_string(),
                    evidence_refs: collect_evidence(preparation)?,
                    limitations,
                };
                output.validate()?;
                Ok(output)
            }
            _ => {
                let mut missing = Vec::new();
                if title_opt.is_none() {
                    missing.push("title".to_string());
                }
                if company_opt.is_none() {
                    missing.push("company".to_string());
                }
                let excerpt: String =
                    generated_text.chars().take(500).collect();
                let title_value = match &title_opt {
                    Some(title) => Value::String(title.clone()),
                    None => missing_json(&Missing::with_detail(
                        "not_observed",
                        "title was not established; value not fabricated",
                    )),
                };
                let company_value = match &company_opt {
                    Some(company) => Value::String(company.clone()),
                    None => missing_json(&Missing::with_detail(
                        "not_observed",
                        "company was not established; value not fabricated",
                    )),
                };
                let diagnostic = json!({
                    "record_type": "diagnostic",
                    "schema_version": "evidence-kernel/0.1.0",
                    "diagnostic_id": format!("{}-extraction-diagnostic", task.task_id),
                    "run_id": preparation.scope.run_id,
                    "comparisons": [],
                    "result": {
                        "partial_title": title_value,
                        "partial_company": company_value,
                        "missing_fields": missing,
                        "retained_text_excerpt": excerpt,
                        "reason": "required fields could not be established; strict output_schema does not permit partial TaskOutput; partial material retained as diagnostic-only artifact",
                    },
                });
                check_no_bare_null(&diagnostic)?;
                let diagnostic_bytes = serde_json::to_vec(&diagnostic)
                    .map_err(|error| invalid(format!("diagnostic serializes: {error}")))?;
                rm_wire::validate_record("diagnostic/v1", &diagnostic_bytes)
                    .map_err(|error| invalid(format!("diagnostic wire rejected: {error}")))?;
                let diagnostic_ref = ArtifactReference {
                    digest: rm_wire::artifact_digest(&diagnostic_bytes),
                    size_bytes: diagnostic_bytes.len() as u64,
                    media_type: "application/json".to_string(),
                    owner_domain: "artifact".to_string(),
                    access: AccessClass::Public,
                };
                let installed = rm_evidence::install_artifact(
                    principal,
                    &diagnostic_ref,
                    &diagnostic_bytes,
                )?;
                let round_trip = rm_evidence::load_artifact(principal, &installed)?;
                if round_trip != diagnostic_bytes {
                    return Err(integrity(
                        "installed diagnostic bytes do not round-trip".to_string(),
                    ));
                }
                let mut error = connector_error(
                    "SCHEMA_INCOMPLETE",
                    "content",
                    format!(
                        "strict output_schema {:?} does not permit partial representation (missing: {}); partial material retained as diagnostic-only artifact {} ({} bytes); TaskOutput not published; completeness=partial does not waive schema validation",
                        pin.id,
                        missing.join(","),
                        installed.digest.as_str(),
                        installed.size_bytes
                    ),
                );
                error.handle =
                    Some(installed.to_json().to_string());
                Err(error)
            }
        }
    } else {
        // Partial-permitting schema: valid partial contract.
        let title_value = match &title_opt {
            Some(title) => Value::String(title.clone()),
            None => missing_json(&Missing::with_detail(
                "not_observed",
                "title was not established in retained text; value not fabricated",
            )),
        };
        let company_value = match &company_opt {
            Some(company) => Value::String(company.clone()),
            None => missing_json(&Missing::with_detail(
                "not_observed",
                "company was not established in retained text; value not fabricated",
            )),
        };
        let mut missing_fields = Vec::new();
        if title_opt.is_none() {
            missing_fields.push("title".to_string());
        }
        if company_opt.is_none() {
            missing_fields.push("company".to_string());
        }
        let content_value = json!({
            "title": title_value,
            "company": company_value,
            "schema_incomplete": missing_fields,
        });
        validate_partial_content(&content_value)?;
        check_no_bare_null(&content_value)?;
        let content_bytes = serde_json::to_vec(&content_value)
            .map_err(|error| invalid(format!("partial content serializes: {error}")))?;
        let content_ref = ArtifactReference {
            digest: rm_wire::artifact_digest(&content_bytes),
            size_bytes: content_bytes.len() as u64,
            media_type: "application/json".to_string(),
            owner_domain: "artifact".to_string(),
            access: AccessClass::Public,
        };
        let installed = rm_evidence::install_artifact(principal, &content_ref, &content_bytes)?;
        let round_trip = rm_evidence::load_artifact(principal, &installed)?;
        if round_trip != content_bytes {
            return Err(integrity(
                "installed content bytes do not round-trip".to_string(),
            ));
        }
        let completeness = if missing_fields.is_empty() {
            COMPLETENESS_COMPLETE
        } else if missing_fields.len() == 2 {
            COMPLETENESS_UNKNOWN
        } else {
            COMPLETENESS_PARTIAL
        };
        limitations.push(format!(
            "validation: output bytes validated against the requested output contract {}/{}; completeness={} does not waive schema validation",
            pin.id, pin.version, completeness
        ));
        limitations.push(format!(
            "publication: TaskOutput artifact {} ({} bytes), completeness {} scoped to the output contract, not global discovery coverage, authentication, application success, or employer commitment",
            installed.digest.as_str(),
            installed.size_bytes,
            completeness
        ));
        let output = TaskOutput {
            kind: TASK_OUTPUT_KIND.to_string(),
            name: task.task_id.clone(),
            output_schema: pin,
            content: installed,
            completeness: completeness.to_string(),
            evidence_refs: collect_evidence(preparation)?,
            limitations,
        };
        output.validate()?;
        Ok(output)
    }
}

fn collect_evidence(preparation: &PreparedTask) -> Result<Vec<EvidenceRef>, ConnectorError> {
    let mut candidates = Vec::new();
    candidates.push(preparation.configuration.descriptor_ref.clone());
    candidates.extend(preparation.planning_evidence_refs.iter().cloned());
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    for reference in candidates {
        reference.validate()?;
        let key = reference.to_json().to_string();
        if seen.insert(key) {
            unique.push(reference);
        }
    }
    if unique.is_empty() {
        return Err(invalid("TaskOutput requires a nonempty SupportRefs evidence_refs"));
    }
    Ok(unique)
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn html_stripping_skips_script_and_decodes() {
        let html = "<div>Title: Engineer</div><script>alert(1)</script><p>Company: Acme &amp; Co</p>";
        let text = strip_html_to_text(html);
        assert!(text.contains("Title: Engineer"));
        assert!(text.contains("Company: Acme & Co"));
        assert!(!text.contains("alert"));
    }

    #[test]
    fn field_markers_extract_across_joined_text() {
        let (title, company) =
            extract_fields_from_text("Title: Senior Engineer Company: Acme");
        assert_eq!(title.as_deref(), Some("Senior Engineer"));
        assert_eq!(company.as_deref(), Some("Acme"));
    }
}
