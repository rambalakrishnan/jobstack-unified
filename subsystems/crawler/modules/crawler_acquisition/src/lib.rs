//! `crawler_acquisition`: render-case content acceptance and structured-response normalization.
//!
//! This module owns the acquisition seam between transport evidence and
//! materialized crawler content (seam map §§9.1–9.3, §18.2):
//!
//! * [`Acquisition`] declares the hybrid acquisition contract: one admitted
//!   read-only request is executed within its response credit and navigation
//!   ceiling, and the returned record carries ordered transport attempts, the
//!   final render verdict, render history, response hash/bytes, and accepted
//!   content only when content was accepted. The escalation ladder (§18.2) is
//!   part of the trait contract: HTTP `Pass` processes immediately;
//!   `ThinShell`/`RenderIncomplete` with all rendering inputs dispatches the
//!   fetched HTML to `Page::from_html` with no network; missing required
//!   subresources skip `from_html` for cold navigation;
//!   `EdgeBlock`/`SensorFail`/`ChallengeIncomplete` cold-navigate; a failed
//!   `from_html` cold-navigates; harvest success with incomplete browser
//!   content verifies through the live HTTP client; a final non-`Pass` or an
//!   expired deadline takes the failed-render route. A clearance/bootstrap
//!   success is never a render `Pass`, and aggregate acquisition time is never
//!   divided into invented attempt durations. Concrete executors compose the
//!   session, browser, and artifact seams above this trait; this crate ships
//!   the seam plus the two pure acceptance gates below.
//! * [`extract_accepted_content`] enforces the §9.2 render cases
//!   ([OWD-RENDER], [C13]). A `Pass` acquisition is accepted only when every
//!   declared required content field is present, non-`Missing`, and correctly
//!   typed; anything less is `incomplete_extraction` — never materialized as
//!   a valid job and never reclassified as failed rendering. A non-`Pass`
//!   acquisition is accepted only as `render_failed` with reasoned
//!   `Missing` for every core and declared extended content value, no current
//!   classifier results, no final genuine result, and no seen membership;
//!   earlier snippet results survive only as historical evidence.
//! * [`normalize_structured_response`] validates structured (IL JSON)
//!   endpoint responses ([C14]): media type, top-level structure, posting
//!   IDs, and the configured required structured fields. HTML challenge
//!   bodies masquerading as successful JSON are rejected as
//!   `challenge_masquerade`. Validated payloads yield deterministic escaped
//!   HTML evidence for engine classification, `render_basis` of
//!   `validated_structured_payload`, the raw payload hash, and the raw fields
//!   retained for extraction. The normalizer never manufactures description
//!   text, never overrides the engine verdict, and never treats an empty
//!   valid result as positive coverage (`empty_unproven`).
//!
//! # Record shapes
//!
//! All inputs and outputs are [`CheckedRecord`]s under the structural
//! `"audit_log"` envelope (no bare nulls; absent fields are typed `Missing`
//! envelopes and are treated as absent).
//!
//! The declaration record carries `declarations`, an array of content
//! contracts. Each entry holds `name` (nonempty string), `type` (exactly one
//! of the seven declared types below), `required` and `nullable` (booleans;
//! required implies nonnullable), and `extraction` (a `VersionPin` object
//! with nonempty `name` and `version`). For structured responses the
//! declaration additionally carries `postings_field` (default `"postings"`),
//! `id_field` (default `"posting_id"`), and `required_structured_fields`
//! (default `[id_field]`).
//!
//! The seven declared content types are `string`, `integer`, `number`,
//! `boolean`, `object`, `array`, and `timestamp`. `timestamp` accepts
//! preserved source text (a string; closing-date text keeps no invented
//! timezone) or a structured time object. There is no `null` type: nulls are
//! `Missing` envelopes, never in-band values.
//!
//! The acquisition record carries `render_verdict`, `pipeline_state`, and a
//! `content` object with the ten core slots (`title`, `employer`, `snippet`,
//! `description`, `posted_date`, `location`, `direct_apply_url`,
//! `portal_type`, `closing_date`, `extended`). Extended entries are objects
//! with `name`, `type`, and `value` (typed or `Missing`); extended names
//! cannot shadow core slots.
//!
//! Fault codes: `invalid_acquisition`, `invalid_declaration`,
//! `invalid_structured_response`, `invalid_structured_payload`,
//! `invalid_media_type`, `challenge_masquerade`, `incomplete_extraction`,
//! `invalid_render_case`.

use crawler_admission::ResponseCredit;
use crawler_authority::Grant;
use crawler_hashing::digest_bytes;
use crawler_readonly::ReadOnlyRequest;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Map, Value};

/// Structural schema id for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Pinned structured-payload normalizer version recorded on every normalized
/// response (`render_basis='validated_structured_payload'`).
pub const NORMALIZER_VERSION: &str = "crawler-acquisition-structured/1";

/// Core content slots other than `extended`, in canonical output order.
const CORE_SLOTS: &[&str] = &[
    "title",
    "employer",
    "snippet",
    "description",
    "posted_date",
    "location",
    "direct_apply_url",
    "portal_type",
    "closing_date",
];

/// The exact seven-type declaration vocabulary (§9.1). There is no `null`
/// type: missing values are reasoned `Missing` envelopes.
const DECLARED_TYPES: &[&str] = &[
    "string",
    "integer",
    "number",
    "boolean",
    "object",
    "array",
    "timestamp",
];

/// Detail states a `Pass` verdict may carry (Case A, §9.2): pending
/// classification, ready, vetoed, or a later operational failure. A `Pass`
/// with `render_failed` is `incomplete_extraction`, never Case B.
const PASS_PIPELINE_STATES: &[&str] = &["pending_classification", "ready", "vetoed", "failed"];

/// Current-result references a Case B detail must not carry (§9.2).
const CURRENT_RESULT_REFS: &[&str] = &[
    "snippet_classifier_result_ref",
    "description_classifier_result_ref",
    "final_genuine_result_ref",
];

/// Full-document HTML markers: a JSON-declared body carrying these is markup
/// masquerading as structured content, never a payload.
const DOCUMENT_MARKERS: &[&str] = &["<!doctype", "<html"];

/// Challenge-platform markers. Bare words such as "challenge" are deliberately
/// absent: legitimate posting text ("new challenges await") must not trip the
/// masquerade gate.
const CHALLENGE_MARKERS: &[&str] = &[
    "captcha",
    "cloudflare",
    "cf-challenge",
    "__cf_",
    "cf_clearance",
    "just a moment",
    "verify you are human",
    "access denied",
    "attention required",
];

/// Envelope-level markup markers. Inline formatting tags inside posting text
/// (`<p>`, `<b>`) are legitimate content and are never scanned; only the
/// top-level envelope strings are checked.
const ENVELOPE_MARKUP_MARKERS: &[&str] = &["<head", "<body", "<script", "<title"];

// ---------------------------------------------------------------------------
// Acquisition seam
// ---------------------------------------------------------------------------

/// Hybrid acquisition seam: execute one admitted read-only request within its
/// response credit and the target navigation ceiling (§18.2).
///
/// Implementors honor credit-before-wire (the `credit` already reserves rows,
/// bytes, durable staging, and observation buffering for the maximum admitted
/// packet), read-only enforcement (the `request` was authorized as
/// `effect_policy: read_only`; no acquisition step may execute an
/// employer/application mutation), the §18.2 escalation ladder, and the
/// failed-render routing contract on a final non-`Pass` or an expired
/// deadline. The returned record preserves request identity, ordered
/// transport attempts, the final render verdict, render history, response
/// hash/bytes, and accepted content only when content was accepted.
pub trait Acquisition: Send + Sync {
    fn acquire(
        &self,
        grant: &Grant,
        request: &ReadOnlyRequest,
        credit: ResponseCredit,
    ) -> Result<CheckedRecord, Fault>;
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a schema-gate `Missing` envelope.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(
            code,
            format!("{what} must be a JSON object"),
        )
    })
}

/// The established (non-`Missing`) string value of `field`, if any.
fn established_str<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    map.get(field)
        .filter(|value| !is_missing(value))
        .and_then(Value::as_str)
}

/// Echo `field` verbatim when present, else a reasoned `Missing` placeholder.
/// Presence (even as `Missing`) is evidence and is preserved untouched.
fn echo_or_missing(map: &Map<String, Value>, field: &str, reason: &str, detail: &str) -> Value {
    map.get(field)
        .cloned()
        .unwrap_or_else(|| missing(reason, detail))
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// True when an established value satisfies the declared type. `Missing`
/// envelopes never satisfy a type: they are missingness, not values.
fn check_typed(kind: &str, value: &Value) -> bool {
    match kind {
        "string" => value.is_string(),
        "integer" => value
            .as_number()
            .is_some_and(|n| n.is_i64() || n.is_u64()),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "object" => !is_missing(value) && value.is_object(),
        // An empty array is an established empty collection (EK-NULL), so it
        // satisfies a required `array` field.
        "array" => value.is_array(),
        // Extraction preserves source timestamp text verbatim (no invented
        // timezone); structured time objects are accepted as well.
        "timestamp" => value.is_string() || (!is_missing(value) && value.is_object()),
        _ => false,
    }
}

/// One parsed content declaration: `name`, seven-vocabulary `type`,
/// `required`, and (validated but informational here) nullability plus the
/// extraction pin, which are checked during parsing.
struct FieldDecl {
    name: String,
    kind: String,
    required: bool,
}

/// Parse and validate the `declarations` array of a declaration record.
/// Absent or `Missing` declarations mean no declared contract (the caller
/// applies its documented fallback); a present array must be fully valid.
fn parse_declarations(declaration: &CheckedRecord) -> Result<Vec<FieldDecl>, Fault> {
    let map = as_object(declaration, "invalid_declaration", "declaration")?;
    let entries = match map.get("declarations") {
        None => return Ok(Vec::new()),
        Some(value) if is_missing(value) => return Ok(Vec::new()),
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(fault(
                "invalid_declaration",
                "declaration `declarations` must be an array of content contracts",
            ))
        }
    };
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let where_it = format!("declaration entry {index}");
        if is_missing(entry) {
            return Err(fault(
                "invalid_declaration",
                format!("{where_it} must be an established contract, not Missing"),
            ));
        }
        let entry_map = entry.as_object().ok_or_else(|| {
            fault(
                "invalid_declaration",
                format!("{where_it} must be an object"),
            )
        })?;
        let name = match entry_map.get("name") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => {
                return Err(fault(
                    "invalid_declaration",
                    format!("{where_it} requires a nonempty string `name`"),
                ))
            }
        };
        let kind = match entry_map.get("type").filter(|v| !is_missing(v)) {
            Some(Value::String(text)) if DECLARED_TYPES.contains(&text.as_str()) => text.clone(),
            Some(Value::String(text)) => {
                return Err(fault(
                    "invalid_declaration",
                    format!(
                        "{where_it} for field {name:?} names unknown type {text:?}; \
                         the seven declared types are string, integer, number, \
                         boolean, object, array, timestamp"
                    ),
                ))
            }
            _ => {
                return Err(fault(
                    "invalid_declaration",
                    format!("{where_it} for field {name:?} requires an established `type`"),
                ))
            }
        };
        let required = match entry_map.get("required") {
            Some(Value::Bool(required)) => *required,
            _ => {
                return Err(fault(
                    "invalid_declaration",
                    format!("{where_it} for field {name:?} requires a boolean `required`"),
                ))
            }
        };
        let nullable = match entry_map.get("nullable") {
            Some(Value::Bool(nullable)) => *nullable,
            _ => {
                return Err(fault(
                    "invalid_declaration",
                    format!("{where_it} for field {name:?} requires a boolean `nullable`"),
                ))
            }
        };
        if required && nullable {
            return Err(fault(
                "invalid_declaration",
                format!("declared field {name:?}: required implies nonnullable"),
            ));
        }
        match entry_map.get("extraction").filter(|v| !is_missing(v)) {
            Some(Value::Object(pin))
                if matches!(pin.get("name"), Some(Value::String(n)) if !n.is_empty())
                    && matches!(pin.get("version"), Some(Value::String(v)) if !v.is_empty()) => {}
            _ => {
                return Err(fault(
                    "invalid_declaration",
                    format!(
                        "{where_it} for field {name:?} requires an extraction \
                         VersionPin with nonempty `name` and `version`"
                    ),
                ))
            }
        }
        if out.iter().any(|seen: &FieldDecl| seen.name == name) {
            return Err(fault(
                "invalid_declaration",
                format!("declared field {name:?} appears more than once"),
            ));
        }
        out.push(FieldDecl {
            name,
            kind,
            required,
        });
    }
    Ok(out)
}

/// Validate one extended content entry `{name, type, value}` and return its
/// parts. Extended names cannot shadow core slots (§9.1).
fn parse_extended_entry(entry: &Value, index: usize) -> Result<(&str, &str, &Value), Fault> {
    let where_it = format!("extended entry {index}");
    if is_missing(entry) {
        return Err(fault(
            "invalid_acquisition",
            format!("{where_it} must be established; missingness belongs on its `value`"),
        ));
    }
    let map = entry.as_object().ok_or_else(|| {
        fault(
            "invalid_acquisition",
            format!("{where_it} must be an object with `name`, `type`, and `value`"),
        )
    })?;
    let name = match map.get("name") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_acquisition",
                format!("{where_it} requires a nonempty string `name`"),
            ))
        }
    };
    if name == "extended" || CORE_SLOTS.contains(&name) {
        return Err(fault(
            "invalid_acquisition",
            format!("extended entry name {name:?} shadows a core content slot"),
        ));
    }
    let kind = match map.get("type").filter(|v| !is_missing(v)) {
        Some(Value::String(text)) if DECLARED_TYPES.contains(&text.as_str()) => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_acquisition",
                format!("{where_it} for {name:?} requires a seven-vocabulary `type`"),
            ))
        }
    };
    let value = map.get("value").ok_or_else(|| {
        fault(
            "invalid_acquisition",
            format!("{where_it} for {name:?} requires a `value` (typed or Missing)"),
        )
    })?;
    Ok((name, kind, value))
}

/// The `extended` slot as an entry slice. Absent means no extended entries;
/// `Missing` means the collection itself was unobserved; anything else must
/// be an array.
fn extended_entries(content: &Map<String, Value>) -> Result<Vec<&Value>, Fault> {
    match content.get("extended") {
        None => Ok(Vec::new()),
        Some(value) if is_missing(value) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.iter().collect()),
        Some(other) => Err(fault(
            "invalid_acquisition",
            format!(
                "content `extended` must be an array or Missing, found {}",
                json_kind(other)
            ),
        )),
    }
}

// ---------------------------------------------------------------------------
// Render-case content acceptance (C13)
// ---------------------------------------------------------------------------

/// Accept or reject extracted content under the §9.2 render cases.
///
/// * `Pass` (Case A): every declared required field must be present,
///   non-`Missing`, and correctly typed, and `pipeline_state` must be pending
///   classification, ready, vetoed, or a later operational failure.
///   Otherwise the successful-content write is rejected as
///   `incomplete_extraction` — never materialized and never reclassified as
///   failed rendering. With no declarations, the core `title` is required.
/// * Non-`Pass` (Case B): `pipeline_state` must be `render_failed`, every
///   core and declared extended content value must be reasoned `Missing`,
///   and no current classifier result, final genuine result, or seen
///   membership may be established. Earlier snippet results remain valid
///   historical evidence. Violations fail as `invalid_render_case`.
///
/// Established values under an optional declaration must still be correctly
/// typed; undeclared slots pass through verbatim as evidenced extraction
/// output. Malformed inputs fail as `invalid_acquisition` or
/// `invalid_declaration`.
pub fn extract_accepted_content(
    acquisition: &CheckedRecord,
    declaration: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let decls = parse_declarations(declaration)?;
    let map = as_object(acquisition, "invalid_acquisition", "acquisition")?;
    let verdict = match established_str(map, "render_verdict") {
        Some(text) if !text.is_empty() => text,
        _ => {
            return Err(fault(
                "invalid_acquisition",
                "acquisition requires an established nonempty `render_verdict`",
            ))
        }
    };
    let pipeline = match established_str(map, "pipeline_state") {
        Some(text) if !text.is_empty() => text,
        _ => {
            return Err(fault(
                "invalid_acquisition",
                "acquisition requires an established nonempty `pipeline_state`",
            ))
        }
    };
    let content = match map.get("content").filter(|v| !is_missing(v)) {
        Some(Value::Object(content)) => content,
        _ => {
            return Err(fault(
                "invalid_acquisition",
                "acquisition requires an established `content` object; Case B \
                 carries reasoned Missing per slot, not a Missing content shell",
            ))
        }
    };
    if verdict == "Pass" {
        accept_pass(map, content, pipeline, &decls)
    } else {
        accept_failed(map, content, verdict, pipeline, &decls)
    }
}

/// Find the extended entry named `name`, if any.
fn find_extended<'a>(entries: &[&'a Value], name: &str) -> Option<(usize, &'a Value)> {
    entries.iter().enumerate().find_map(|(index, entry)| {
        entry
            .as_object()
            .and_then(|map| map.get("name"))
            .and_then(Value::as_str)
            .filter(|candidate| *candidate == name)
            .map(|_| (index, *entry))
    })
}

fn accept_pass(
    acquisition: &Map<String, Value>,
    content: &Map<String, Value>,
    pipeline: &str,
    decls: &[FieldDecl],
) -> Result<CheckedRecord, Fault> {
    if !PASS_PIPELINE_STATES.contains(&pipeline) {
        return Err(fault(
            "incomplete_extraction",
            format!(
                "Pass with pipeline_state {pipeline:?} is not a valid successful \
                 write; expected pending_classification, ready, vetoed, or failed"
            ),
        ));
    }
    let entries = extended_entries(content)?;
    // Validate every extended entry shape up front so malformed entries fail
    // as malformed input rather than as extraction gaps.
    for (position, entry) in entries.iter().enumerate() {
        parse_extended_entry(entry, position)?;
    }

    let mut missing_fields: Vec<String> = Vec::new();
    if decls.is_empty() {
        // No declared contract: the core title is the required floor.
        match content.get("title").filter(|v| !is_missing(v)) {
            Some(_) => {}
            _ => {
                return Err(fault(
                    "incomplete_extraction",
                    "Pass with no declarations requires established core `title` content",
                ))
            }
        }
    }
    for decl in decls {
        if decl.name == "extended" {
            match content.get("extended").filter(|v| !is_missing(v)) {
                Some(value) if check_typed(&decl.kind, value) => {}
                Some(value) => {
                    return Err(fault(
                        "incomplete_extraction",
                        format!(
                            "Pass requires declared field `extended` as {}; found {}",
                            decl.kind,
                            json_kind(value)
                        ),
                    ))
                }
                None if decl.required => {
                    return Err(fault(
                        "incomplete_extraction",
                        "Pass requires established content for declared field `extended`",
                    ))
                }
                None => missing_fields.push(decl.name.clone()),
            }
            continue;
        }
        if CORE_SLOTS.contains(&decl.name.as_str()) {
            match content.get(&decl.name).filter(|v| !is_missing(v)) {
                Some(value) if check_typed(&decl.kind, value) => {}
                Some(value) => {
                    return Err(fault(
                        "incomplete_extraction",
                        format!(
                            "Pass requires declared field {:?} as {}; found {}",
                            decl.name,
                            decl.kind,
                            json_kind(value)
                        ),
                    ))
                }
                None if decl.required => {
                    return Err(fault(
                        "incomplete_extraction",
                        format!(
                            "Pass requires established content for declared field {:?}",
                            decl.name
                        ),
                    ))
                }
                None => missing_fields.push(decl.name.clone()),
            }
            continue;
        }
        // Declared extended field: the entry must agree with the declaration.
        match find_extended(&entries, &decl.name) {
            Some((position, entry)) => {
                let (_, entry_kind, value) = parse_extended_entry(entry, position)?;
                if !is_missing(value) {
                    if entry_kind != decl.kind {
                        return Err(fault(
                            "incomplete_extraction",
                            format!(
                                "declared field {:?} as {} conflicts with extended \
                                 entry type {}",
                                decl.name, decl.kind, entry_kind
                            ),
                        ));
                    }
                    if !check_typed(&decl.kind, value) {
                        return Err(fault(
                            "incomplete_extraction",
                            format!(
                                "Pass requires declared field {:?} as {}; found {}",
                                decl.name,
                                decl.kind,
                                json_kind(value)
                            ),
                        ));
                    }
                } else if decl.required {
                    return Err(fault(
                        "incomplete_extraction",
                        format!(
                            "Pass requires established content for declared field {:?}",
                            decl.name
                        ),
                    ));
                } else {
                    missing_fields.push(decl.name.clone());
                }
            }
            None if decl.required => {
                return Err(fault(
                    "incomplete_extraction",
                    format!(
                        "Pass requires established content for declared field {:?}",
                        decl.name
                    ),
                ))
            }
            None => missing_fields.push(decl.name.clone()),
        }
    }
    // Established extended values must match their own entry type even when
    // the field is undeclared: mistyped content is never accepted.
    for (position, entry) in entries.iter().enumerate() {
        let (name, entry_kind, value) = parse_extended_entry(entry, position)?;
        if !is_missing(value) && !check_typed(entry_kind, value) {
            return Err(fault(
                "incomplete_extraction",
                format!(
                    "Pass requires extended field {name:?} as {entry_kind}; found {}",
                    json_kind(value)
                ),
            ));
        }
    }

    let mut out_content = Map::with_capacity(content.len() + 1);
    for (key, value) in content {
        out_content.insert(key.clone(), value.clone());
    }
    // Complete the ten-slot content object: absent optional slots are
    // reasoned `not_observed`, never invented values.
    for slot in CORE_SLOTS {
        if !out_content.contains_key(*slot) {
            out_content.insert(
                slot.to_string(),
                missing(
                    "not_observed",
                    &format!("optional content slot {slot} had no extracted value"),
                ),
            );
        }
    }
    if !out_content.contains_key("extended") {
        out_content.insert(
            "extended".to_string(),
            Value::Array(Vec::new()),
        );
    }
    let value = json!({
        "acceptance": "accepted",
        "render_verdict": "Pass",
        "pipeline_state": pipeline,
        "render_basis": echo_or_missing(acquisition, "render_basis", "not_observed", "acquisition carried no render basis"),
        "content": Value::Object(out_content),
        "declarations": acquisition_declarations_echo(acquisition),
        "missing_fields": missing_fields,
        "evidence_refs": echo_or_missing(acquisition, "evidence_refs", "not_observed", "acquisition carried no supporting references"),
    });
    validate(OUTPUT_SCHEMA, value)
}

/// Echo the declaration array when the acquisition record pins it; acquisition
/// records normally travel beside their declaration, not inside it.
fn acquisition_declarations_echo(acquisition: &Map<String, Value>) -> Value {
    acquisition
        .get("declarations")
        .cloned()
        .unwrap_or_else(|| json!([]))
}

fn accept_failed(
    acquisition: &Map<String, Value>,
    content: &Map<String, Value>,
    verdict: &str,
    pipeline: &str,
    decls: &[FieldDecl],
) -> Result<CheckedRecord, Fault> {
    if pipeline != "render_failed" {
        return Err(fault(
            "invalid_render_case",
            format!(
                "non-Pass verdict {verdict:?} requires pipeline_state render_failed, \
                 found {pipeline:?}"
            ),
        ));
    }
    let mut missing_fields: Vec<String> = Vec::new();
    for slot in CORE_SLOTS {
        match content.get(*slot) {
            Some(value) if is_missing(value) => missing_fields.push(slot.to_string()),
            Some(value) => {
                return Err(fault(
                    "invalid_render_case",
                    format!(
                        "non-Pass Case B requires Missing content for {slot}; \
                         found established {}",
                        json_kind(value)
                    ),
                ))
            }
            None => {
                return Err(fault(
                    "invalid_render_case",
                    format!(
                        "non-Pass Case B requires reasoned Missing for {slot}; \
                         absence is not reasoned missingness"
                    ),
                ))
            }
        }
    }
    let entries = extended_entries(content)?;
    for (position, entry) in entries.iter().enumerate() {
        let (name, _, value) = parse_extended_entry(entry, position)?;
        if !is_missing(value) {
            return Err(fault(
                "invalid_render_case",
                format!(
                    "non-Pass Case B requires Missing content for extended \
                     field {name:?}; found established {}",
                    json_kind(value)
                ),
            ));
        }
    }
    for decl in decls {
        if decl.name != "extended" && !CORE_SLOTS.contains(&decl.name.as_str()) {
            missing_fields.push(decl.name.clone());
        }
    }
    for field in CURRENT_RESULT_REFS {
        if acquisition.get(*field).is_some_and(|v| !is_missing(v)) {
            return Err(fault(
                "invalid_render_case",
                format!("non-Pass Case B carries no current classifier result ({field})"),
            ));
        }
    }
    if acquisition
        .get("seen_membership")
        .is_some_and(|v| !is_missing(v))
    {
        return Err(fault(
            "invalid_render_case",
            "non-Pass Case B carries no seen membership",
        ));
    }
    // Any other acquisition field (snippet history, prior verdicts, attempt
    // evidence) passes through as historical evidence; only current results
    // and membership are barred.

    let value = json!({
        "acceptance": "render_failed",
        "render_verdict": verdict,
        "pipeline_state": "render_failed",
        "render_basis": echo_or_missing(acquisition, "render_basis", "not_observed", "acquisition carried no render basis"),
        "content": Value::Object(content.clone()),
        "declarations": acquisition_declarations_echo(acquisition),
        "missing_fields": missing_fields,
        "evidence_refs": echo_or_missing(acquisition, "evidence_refs", "not_observed", "acquisition carried no supporting references"),
    });
    validate(OUTPUT_SCHEMA, value)
}

// ---------------------------------------------------------------------------
// Structured-response normalization (C14)
// ---------------------------------------------------------------------------

/// True when `media_type` names a JSON representation: `application/json`
/// (parameters such as `charset` ignored, ASCII case ignored) or any
/// `*+json` structured-syntax suffix.
fn is_json_media_type(media_type: &str) -> bool {
    let base = media_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if base == "application/json" {
        return true;
    }
    match base.split_once('/') {
        Some((_, subtype)) => subtype.ends_with("+json"),
        None => false,
    }
}

/// True when `text` carries full-document HTML or challenge-platform markers.
/// Used only to classify bodies that already failed JSON parsing (and,
/// separately, top-level envelope strings of parsed payloads); posting text
/// inside entries is never scanned, so inline formatting and ordinary words
/// cannot trip the gate.
fn carries_masquerade_markers(lowercased: &str) -> bool {
    DOCUMENT_MARKERS
        .iter()
        .chain(CHALLENGE_MARKERS.iter())
        .chain(ENVELOPE_MARKUP_MARKERS.iter())
        .any(|marker| lowercased.contains(marker))
}

/// Deterministic HTML escape for classifier evidence (`&`, `<`, `>`, `"`,
/// `'`). Byte order is preserved, so identical canonical payloads always
/// yield identical evidence.
fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Convert parsed-payload JSON nulls into reasoned `Missing(not_observed)`
/// envelopes so the retained payload validates under the schema gate. Field
/// names and all other values are preserved verbatim.
fn denull_payload(value: &Value, path: &str) -> Value {
    match value {
        Value::Null => missing(
            "not_observed",
            &format!("structured field {path} was JSON null"),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, item)| denull_payload(item, &format!("{path}[{index}]")))
                .collect(),
        ),
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (key, item) in map {
                out.insert(key.clone(), denull_payload(item, &format!("{path}.{key}")));
            }
            Value::Object(out)
        }
        _ => value.clone(),
    }
}

/// Validate and normalize one structured (IL JSON) endpoint response.
///
/// The response must declare a JSON media type and carry a `body` string that
/// parses to a top-level object. HTML challenge bodies masquerading as
/// successful JSON — unparsable markup, or a parsed envelope whose top-level
/// strings carry document/challenge markers — are rejected as
/// `challenge_masquerade`. Structural violations (non-object top level,
/// missing/non-array postings, missing posting IDs, missing configured
/// required structured fields) fail as `invalid_structured_payload`.
///
/// On success the returned record carries `render_basis` of
/// `validated_structured_payload`, the raw-body SHA-256 (`payload_hash`), the
/// pinned [`NORMALIZER_VERSION`], deterministic escaped HTML evidence for
/// engine classification, the raw body and raw fields retained for
/// extraction, and coverage that is never proven here: an empty valid result
/// records `empty_unproven` under the zero-observation rule, and a nonempty
/// result stays `open` for the coverage seam to prove. The engine verdict
/// passes through untouched — a non-`Pass` verdict is never upgraded — and
/// no description text is ever manufactured.
pub fn normalize_structured_response(
    response: &CheckedRecord,
    declaration: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let response_map = as_object(response, "invalid_structured_response", "response")?;
    // A declaration that pins content contracts must pin valid ones.
    let _ = parse_declarations(declaration)?;
    let decl_map = as_object(declaration, "invalid_declaration", "declaration")?;

    let media_type = match established_str(response_map, "media_type") {
        Some(text) if !text.is_empty() => text,
        _ => {
            return Err(fault(
                "invalid_media_type",
                "structured response requires an established nonempty `media_type`",
            ))
        }
    };
    if !is_json_media_type(media_type) {
        return Err(fault(
            "invalid_media_type",
            format!(
                "structured response media type {media_type:?} is not JSON; \
                 expected application/json or a *+json suffix"
            ),
        ));
    }
    let body = match response_map.get("body").filter(|v| !is_missing(v)) {
        Some(Value::String(text)) if !text.trim().is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_structured_payload",
                "structured response requires an established non-blank string `body`",
            ))
        }
    };

    let payload: Value = match serde_json::from_str(body) {
        Ok(payload) => payload,
        Err(_) => {
            if body.trim_start().starts_with('<')
                || carries_masquerade_markers(&body.to_ascii_lowercase())
            {
                return Err(fault(
                    "challenge_masquerade",
                    "response body declares JSON but carries HTML/challenge markup; \
                     rejected as a masquerading challenge, not a structured payload",
                ));
            }
            return Err(fault(
                "invalid_structured_payload",
                "response body is not valid JSON",
            ));
        }
    };
    let payload_obj = match payload.as_object() {
        Some(obj) => obj,
        None => {
            return Err(fault(
                "invalid_structured_payload",
                format!(
                    "structured payload top level must be an object, found {}",
                    json_kind(&payload)
                ),
            ))
        }
    };
    // A parsed envelope can still masquerade: top-level strings carrying
    // document/challenge markers are a challenge dressed as success. Only
    // envelope strings are scanned; posting text is never screened.
    for (key, value) in payload_obj {
        if let Value::String(text) = value {
            if carries_masquerade_markers(&text.to_ascii_lowercase()) {
                return Err(fault(
                    "challenge_masquerade",
                    format!(
                        "structured envelope field {key:?} carries HTML/challenge \
                         markup; rejected as a masquerading challenge"
                    ),
                ));
            }
        }
    }

    let postings_field = match decl_map.get("postings_field").filter(|v| !is_missing(v)) {
        None => "postings",
        Some(Value::String(field)) if !field.is_empty() => field.as_str(),
        _ => {
            return Err(fault(
                "invalid_declaration",
                "declaration `postings_field` must be a nonempty string when present",
            ))
        }
    };
    let id_field = match decl_map.get("id_field").filter(|v| !is_missing(v)) {
        None => "posting_id",
        Some(Value::String(field)) if !field.is_empty() => field.as_str(),
        _ => {
            return Err(fault(
                "invalid_declaration",
                "declaration `id_field` must be a nonempty string when present",
            ))
        }
    };
    let required_fields: Vec<&str> = match decl_map
        .get("required_structured_fields")
        .filter(|v| !is_missing(v))
    {
        None => vec![id_field],
        Some(Value::Array(fields)) => {
            let mut out = Vec::with_capacity(fields.len());
            for (index, field) in fields.iter().enumerate() {
                match field {
                    Value::String(text) if !text.is_empty() => out.push(text.as_str()),
                    _ => {
                        return Err(fault(
                            "invalid_declaration",
                            format!(
                                "declaration `required_structured_fields[{index}]` \
                                 must be a nonempty string"
                            ),
                        ))
                    }
                }
            }
            out
        }
        Some(_) => {
            return Err(fault(
                "invalid_declaration",
                "declaration `required_structured_fields` must be an array when present",
            ))
        }
    };

    let postings = match payload_obj.get(postings_field) {
        Some(Value::Array(postings)) => postings,
        Some(other) => {
            return Err(fault(
                "invalid_structured_payload",
                format!(
                    "structured payload field {postings_field:?} must be an array, found {}",
                    json_kind(other)
                ),
            ))
        }
        None => {
            return Err(fault(
                "invalid_structured_payload",
                format!("structured payload is missing required array {postings_field:?}"),
            ))
        }
    };
    for (index, entry) in postings.iter().enumerate() {
        let entry_obj = match entry.as_object() {
            Some(obj) => obj,
            None => {
                return Err(fault(
                    "invalid_structured_payload",
                    format!(
                        "structured entry {index} must be an object, found {}",
                        json_kind(entry)
                    ),
                ))
            }
        };
        // Posting IDs are always validated: a nonempty string or a number.
        match entry_obj.get(id_field) {
            Some(Value::String(text)) if !text.is_empty() => {}
            Some(Value::Number(_)) => {}
            _ => {
                return Err(fault(
                    "invalid_structured_payload",
                    format!("structured entry {index} is missing posting ID {id_field:?}"),
                ))
            }
        }
        for field in &required_fields {
            match entry_obj.get(*field) {
                Some(value) if !value.is_null() => {}
                _ => {
                    return Err(fault(
                        "invalid_structured_payload",
                        format!(
                            "structured entry {index} is missing required field {field:?}"
                        ),
                    ))
                }
            }
        }
    }

    // Canonical re-serialization (sorted keys) feeds the escaped evidence, so
    // key order never perturbs engine classification input; the hash binds
    // the exact raw bytes instead.
    let canonical = serde_json::to_string(&payload).unwrap_or_else(|_| body.to_string());
    let evidence_html = format!(
        "<div class=\"structured-evidence\" data-normalizer=\"{NORMALIZER_VERSION}\">{}</div>",
        html_escape(&canonical)
    );
    let coverage = if postings.is_empty() {
        // Zero-observation rule: an empty valid result stays unproven; render
        // coverage is null (a reasoned Missing), never manufactured.
        json!({
            "status": "empty_unproven",
            "pagination_coverage_proven": false,
            "observed_total": 0,
            "render_coverage": missing("not_observed", "empty valid result proves no pagination coverage"),
        })
    } else {
        json!({
            "status": "open",
            "pagination_coverage_proven": false,
            "observed_total": postings.len(),
            "render_coverage": missing("not_observed", "render coverage is a health indicator; this module never proves pagination"),
        })
    };
    let value = json!({
        "render_basis": "validated_structured_payload",
        "normalizer_version": NORMALIZER_VERSION,
        "media_type": media_type,
        "endpoint": echo_or_missing(response_map, "endpoint", "not_observed", "response carried no endpoint"),
        "engine_verdict": response_map.get("engine_verdict").cloned().unwrap_or_else(|| missing("not_observed", "response carried no engine verdict")),
        "raw_body": body,
        "payload": denull_payload(&payload, "$"),
        "payload_hash": digest_bytes(body.as_bytes()),
        "classifier_evidence_html": evidence_html,
        "posting_count": postings.len(),
        "coverage": coverage,
        "evidence_refs": echo_or_missing(response_map, "evidence_refs", "not_observed", "response carried no supporting references"),
    });
    validate(OUTPUT_SCHEMA, value)
}
