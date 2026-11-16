//! `crawler_readonly`: read-only acquisition gate for crawler tasks.
//!
//! `discover_jobs` and `extract` tasks cannot execute employer/application
//! mutations (Contract 02, EXT-READ-ONLY; seam map §19.6). HTTP method alone
//! never determines read-only status: an MI query `POST` or WI postback may be
//! acquisition, while OR `self-refer-step1-validate.cfm` remains a mutation
//! even with `usemyssn=No`. Task text, redirects, plan artifacts, extraction
//! callbacks, transport overrides, and write-action handlers cannot expand
//! authority: any nested mutation fails the whole request before wire.
//!
//! No crawler transition inserts a `state_mutation_record` row; all four
//! statuses (`requested|confirmed|rejected|indeterminate`) are reserved and
//! non-executing in Phase 1. This module produces no such rows: every
//! [`ReadOnlyRequest`] validates under `"audit_log"`, and any record shaped
//! as a mutation record is rejected.
//!
//! # Record shapes
//!
//! All inputs are [`CheckedRecord`]s (no bare nulls; absent fields are typed
//! `Missing` envelopes and are treated as absent). The usual envelope schema
//! is `"audit_log"`; a record whose schema is `"state_mutation_record"` is
//! rejected outright.
//!
//! * `endpoint` (for [`authorize_acquisition`]) and `redirect` (for
//!   [`authorize_redirect`]) are artifact/evidence references exercised under
//!   the grant with `authorize_reference(grant, reference, "read")`: they
//!   carry `grant_digest`, `digest`, `access`, `owner_domain`, and
//!   `provenance`, plus an absolute acquisition `url` (fallbacks: `location`,
//!   `target_url`, `redirect_url`, `endpoint_url`, `actual_url`, `action_url`,
//!   `href`). An endpoint whose origin is outside the request's
//!   `permitted_origins` fails with `scope_violation`.
//! * `request` carries the TaskEnvelope read-only fields: `task_type` (when
//!   established, `discover_jobs` or `extract`; never `apply`),
//!   `effect_policy` (when established, `read_only`), required
//!   `permitted_origins` (a nonempty array of absolute origins or
//!   `{logical_id, origin}` objects), `permitted_interfaces` (when
//!   established, only `ordinary_browser` / `read_only_acquisition`), and
//!   free-text intent (`goal`, `task_text`, ...).
//! * `action` (for [`reject_write_action`]) is a write-action stub call: any
//!   application/employer mutation fails with `mutation_rejected`, otherwise
//!   the record passes through re-validated under its own schema.
//!
//! `method` / `http_method` fields are always ignored: they neither authorize
//! nor forbid. Query parameters (including `usemyssn=No`) never downgrade a
//! mutation endpoint to acquisition.
//!
//! Fault codes: `invalid_endpoint`, `invalid_request`, `invalid_redirect`,
//! `invalid_action` (malformed records), `mutation_rejected` (any
//! application/employer mutation or unauthorized policy value, rejected
//! before wire), `scope_violation` (endpoint/redirect origin outside the
//! admitted `permitted_origins`). Authority faults from `authorize_reference`
//! (`missing_grant_binding`, `digest_mismatch`, ...) propagate unchanged.

use crawler_authority::{authorize_reference, Grant};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord, Fault};
use serde_json::{Map, Value};

/// An acquisition authorized as read-only. The wrapped record pins the
/// authorized `endpoint` and `request` values with `effect_policy: read_only`.
#[derive(Debug)]
pub struct ReadOnlyRequest {
    pub record: CheckedRecord,
}

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// `task_type` values admitted for crawler acquisition (never `apply`).
const READONLY_TASK_TYPES: &[&str] = &["discover_jobs", "extract"];

/// `permitted_interfaces` values admitted for crawler tasks.
const READONLY_INTERFACES: &[&str] = &["ordinary_browser", "read_only_acquisition"];

/// Fields read (in order) as the operative acquisition/redirect URL.
const URL_FIELDS: &[&str] = &[
    "url",
    "location",
    "target_url",
    "redirect_url",
    "endpoint_url",
    "actual_url",
    "action_url",
    "href",
    "endpoint",
];

/// Fields whose string values are scanned as controlled-vocabulary operations.
const OP_FIELDS: &[&str] = &[
    "operation",
    "action",
    "action_name",
    "verb",
    "effect",
    "kind",
    "command",
    "handler",
    "task",
    "activity",
    "mutation",
    "write",
    "writes",
];

/// Fields whose string values are scanned as free-text intent. Instruction
/// containers (`success_criteria`, `steps`, ...) count as text: a mutation
/// instruction fails closed no matter which text field carries it.
const TEXT_FIELDS: &[&str] = &[
    "goal",
    "task_text",
    "text",
    "instruction",
    "instructions",
    "description",
    "intent",
    "objective",
    "objectives",
    "criterion",
    "criteria",
    "success_criteria",
    "steps",
    "step",
];

/// Boolean fields that assert a mutation when established `true`.
const FLAG_FIELDS: &[&str] = &[
    "mutating",
    "is_mutation",
    "writes",
    "write",
    "mutation",
    "is_application",
    "requires_application",
    "application_authority",
    "executes_mutation",
    "is_write",
];

/// Known mutation-endpoint markers (lowercase substrings). Every established
/// string anywhere in an endpoint/request/redirect/action containing one of
/// these fails with `mutation_rejected`, regardless of HTTP method or query
/// parameters. Bare `apply` is deliberately absent: fetching a page from an
/// `apply.` host is acquisition; the mutation is determined by semantic
/// fields (`task_type`, `operation`, ...), except for these endpoints which
/// are mutations by identity.
const ENDPOINT_MUTATION_MARKERS: &[&str] = &[
    "self-refer",
    "self_refer",
    "selfrefer",
    "contact-reveal",
    "contact_reveal",
    "contactreveal",
    "reveal-contact",
    "reveal_contact",
    "submit-application",
    "submit_application",
    "submitapplication",
    "application/submit",
    "application-submit",
    "application_submit",
];

/// Mutation word markers (lowercase substrings) for operation and free-text
/// fields. Fail-closed: read-only operations and intent must not be named
/// with these substrings (e.g. write "discover listings", not "apply to
/// listings").
const WORD_MUTATION_MARKERS: &[&str] = &[
    "apply",
    "applied",
    "applies",
    "applying",
    "application",
    "self-refer",
    "self_refer",
    "selfrefer",
    "contact-reveal",
    "contact_reveal",
    "contactreveal",
    "reveal-contact",
    "reveal_contact",
    "submit-application",
    "submit_application",
    "submitapplication",
    "submit application",
    "application/submit",
    "commissioned_application",
];

/// Whole-value operation names that are always mutations.
const OP_MUTATION_EXACT: &[&str] = &["write", "writes", "mutate", "mutation", "mutations", "submit"];

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

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
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

fn is_op_field(lower_key: &str) -> bool {
    OP_FIELDS.contains(&lower_key)
}

fn is_text_field(lower_key: &str) -> bool {
    TEXT_FIELDS.contains(&lower_key)
}

fn is_flag_field(lower_key: &str) -> bool {
    FLAG_FIELDS.contains(&lower_key)
}

fn check_endpoint_markers(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    ENDPOINT_MUTATION_MARKERS
        .iter()
        .find(|marker| lower.contains(**marker))
        .map(|marker| {
            format!(
                "mutation endpoint marker {marker:?} in {text:?}; HTTP method and query parameters (including usemyssn=No) never downgrade a mutation to acquisition"
            )
        })
}

fn check_word_markers(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    WORD_MUTATION_MARKERS
        .iter()
        .find(|marker| lower.contains(**marker))
        .map(|marker| {
            format!(
                "mutation marker {marker:?} in {text:?}; task text cannot grant application authority"
            )
        })
}

fn check_op_markers(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if OP_MUTATION_EXACT.contains(&lower.as_str()) {
        return Some(format!(
            "mutating operation {text:?}; the crawler write-action stub never executes"
        ));
    }
    check_word_markers(text)
}

/// Strict per-object policy checks, applied at every object level so nested
/// plan artifacts, callbacks, and overrides cannot smuggle mutations.
fn check_strict_fields(map: &Map<String, Value>) -> Option<String> {
    if let Some(value) = established(map, "task_type") {
        match value {
            Value::String(task_type) if READONLY_TASK_TYPES.contains(&task_type.as_str()) => {}
            Value::String(task_type) => {
                return Some(format!(
                    "task_type {task_type:?} is not read-only; crawler tasks are discover_jobs or extract, never apply"
                ));
            }
            _ => {
                return Some(
                    "established task_type must be a discover_jobs/extract string".to_string(),
                );
            }
        }
    }
    if let Some(value) = established(map, "effect_policy") {
        match value {
            Value::String(policy) if policy == "read_only" => {}
            Value::String(policy) => {
                return Some(format!(
                    "effect_policy {policy:?} is not read-only; the crawler cannot gain application authority"
                ));
            }
            _ => {
                return Some("established effect_policy must be the string read_only".to_string());
            }
        }
    }
    for field in ["record_type", "table", "entity", "schema"] {
        if let Some(Value::String(name)) = established(map, field) {
            if name.to_lowercase() == "state_mutation_record" {
                return Some(format!(
                    "{field} is state_mutation_record; all four statuses are reserved and non-executing, and no crawler transition inserts this record"
                ));
            }
        }
    }
    if let Some(value) = established(map, "permitted_interfaces") {
        match value {
            Value::Array(entries) => {
                for entry in entries {
                    if is_missing(entry) {
                        continue;
                    }
                    match entry {
                        Value::String(interface)
                            if READONLY_INTERFACES.contains(&interface.as_str()) => {}
                        Value::String(interface) => {
                            return Some(format!(
                                "permitted interface {interface:?} is not admitted; crawler interfaces are ordinary_browser and read_only_acquisition"
                            ));
                        }
                        _ => {
                            return Some(
                                "permitted_interfaces entries must be interface name strings"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
            _ => {
                return Some("established permitted_interfaces must be an array".to_string());
            }
        }
    }
    None
}

/// Scan one object for read-only violations. Returns the rejection reason, or
/// `None` when clean. Recurses into every nested object/array so mutations
/// arriving through task text, plans, extraction callbacks, or transport
/// overrides fail the whole request before wire.
fn scan_object(map: &Map<String, Value>, path: &str) -> Option<String> {
    if let Some(reason) = check_strict_fields(map) {
        return Some(format!("{path}: {reason}"));
    }
    for (key, value) in map {
        if is_missing(value) {
            continue;
        }
        let field_path = format!("{path}.{key}");
        let lower_key = key.to_lowercase();
        match value {
            Value::String(text) => {
                if let Some(reason) = check_endpoint_markers(text) {
                    return Some(format!("{field_path}: {reason}"));
                }
                if is_op_field(&lower_key) {
                    if let Some(reason) = check_op_markers(text) {
                        return Some(format!("{field_path}: {reason}"));
                    }
                }
                if is_text_field(&lower_key) {
                    if let Some(reason) = check_word_markers(text) {
                        return Some(format!("{field_path}: {reason}"));
                    }
                }
            }
            Value::Bool(true) if is_flag_field(&lower_key) => {
                return Some(format!(
                    "{field_path}: boolean flag {key:?} is set; crawler tasks cannot execute mutations"
                ));
            }
            Value::Object(_) | Value::Array(_) => {
                if let Some(reason) = scan_value(value, Some(&lower_key), &field_path) {
                    return Some(reason);
                }
            }
            _ => {}
        }
    }
    None
}

fn scan_value(value: &Value, field: Option<&str>, path: &str) -> Option<String> {
    match value {
        Value::Object(map) => scan_object(map, path),
        Value::Array(items) => {
            let text_context = field.is_some_and(is_text_field);
            for (index, item) in items.iter().enumerate() {
                if is_missing(item) {
                    continue;
                }
                let item_path = format!("{path}[{index}]");
                if let Value::String(text) = item {
                    if let Some(reason) = check_endpoint_markers(text) {
                        return Some(format!("{item_path}: {reason}"));
                    }
                    if text_context {
                        if let Some(reason) = check_word_markers(text) {
                            return Some(format!("{item_path}: {reason}"));
                        }
                    }
                } else if let Some(reason) = scan_value(item, None, &item_path) {
                    return Some(reason);
                }
            }
            None
        }
        Value::String(text) => {
            if let Some(reason) = check_endpoint_markers(text) {
                return Some(format!("{path}: {reason}"));
            }
            if field.is_some_and(is_op_field) {
                if let Some(reason) = check_op_markers(text) {
                    return Some(format!("{path}: {reason}"));
                }
            }
            if field.is_some_and(is_text_field) {
                if let Some(reason) = check_word_markers(text) {
                    return Some(format!("{path}: {reason}"));
                }
            }
            None
        }
        _ => None,
    }
}

/// First established URL string among the known URL fields.
fn extract_url(map: &Map<String, Value>) -> Option<String> {
    URL_FIELDS.iter().find_map(|field| match established(map, field) {
        Some(Value::String(url)) if !url.is_empty() => Some(url.clone()),
        _ => None,
    })
}

/// Lowercased `scheme://host[:port]` origin of an absolute URL, or `None`
/// for relative URLs.
fn extract_origin(url: &str) -> Option<String> {
    let lower = url.to_lowercase();
    let scheme_end = lower.find("://")?;
    let rest = &lower[scheme_end + 3..];
    let host_end = rest
        .find(|c| c == '/' || c == '?' || c == '#')
        .unwrap_or(rest.len());
    let host = &rest[..host_end];
    if host.is_empty() {
        return None;
    }
    Some(format!("{}://{host}", &lower[..scheme_end]))
}

/// Parse a `permitted_origins` value into lowercased origins. Entries may be
/// absolute origin strings or `{logical_id, origin}` objects.
fn parse_origins(value: &Value) -> Vec<String> {
    let mut origins = Vec::new();
    let Value::Array(entries) = value else {
        return origins;
    };
    for entry in entries {
        if is_missing(entry) {
            continue;
        }
        match entry {
            Value::String(text) => {
                if let Some(origin) = extract_origin(text) {
                    origins.push(origin);
                }
            }
            Value::Object(object) => {
                for key in ["origin", "actual", "actual_origin", "url"] {
                    if let Some(Value::String(text)) = established(object, key) {
                        if let Some(origin) = extract_origin(text) {
                            origins.push(origin);
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    origins
}

/// Required admitted origins of an acquisition request.
fn request_permitted_origins(map: &Map<String, Value>) -> Result<Vec<String>, Fault> {
    match established(map, "permitted_origins") {
        Some(Value::Array(entries)) if !entries.is_empty() => {
            let origins = parse_origins(&Value::Array(entries.clone()));
            if origins.is_empty() {
                return Err(fault(
                    "invalid_request",
                    "request permitted_origins carries no parseable absolute origin".to_string(),
                ));
            }
            Ok(origins)
        }
        _ => Err(fault(
            "invalid_request",
            "request requires an established nonempty permitted_origins array".to_string(),
        )),
    }
}

/// Entry URL of a TaskEnvelope-shaped request, when established.
fn entry_url(map: &Map<String, Value>) -> Option<String> {
    match established(map, "entry") {
        Some(Value::String(url)) if !url.is_empty() => Some(url.clone()),
        Some(Value::Object(entry)) => extract_url(entry),
        _ => match established(map, "entry_url") {
            Some(Value::String(url)) if !url.is_empty() => Some(url.clone()),
            _ => None,
        },
    }
}

/// Admitted origins carried by a previous authorization.
fn previous_permitted_origins(previous: &Value) -> Result<Vec<String>, Fault> {
    let missing = || {
        fault(
            "scope_violation",
            "previous authorization carries no admitted permitted_origins; a redirect cannot be scoped"
                .to_string(),
        )
    };
    let Value::Object(top) = previous else {
        return Err(missing());
    };
    if let Some(Value::Object(request)) = top.get("request").filter(|v| !is_missing(v)) {
        if let Some(origins) = established(request, "permitted_origins") {
            let parsed = parse_origins(origins);
            if !parsed.is_empty() {
                return Ok(parsed);
            }
        }
    }
    if let Some(origins) = established(top, "permitted_origins") {
        let parsed = parse_origins(origins);
        if !parsed.is_empty() {
            return Ok(parsed);
        }
    }
    if let Some(Value::Object(endpoint)) = top.get("endpoint").filter(|v| !is_missing(v)) {
        if let Some(origins) = established(endpoint, "permitted_origins") {
            let parsed = parse_origins(origins);
            if !parsed.is_empty() {
                return Ok(parsed);
            }
        }
    }
    Err(missing())
}

/// Absolute endpoint URL carried by a previous authorization, when present.
fn previous_endpoint_url(previous: &Value) -> Option<String> {
    if let Some(endpoint) = previous.get("endpoint").filter(|v| !is_missing(v)) {
        match endpoint {
            Value::String(url) if !url.is_empty() => return Some(url.clone()),
            Value::Object(map) => {
                if let Some(url) = extract_url(map) {
                    return Some(url);
                }
            }
            _ => {}
        }
    }
    if let Some(Value::Object(request)) = previous.get("request").filter(|v| !is_missing(v)) {
        if let Some(url) = entry_url(request) {
            return Some(url);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Authorize a read-only acquisition under `grant`.
///
/// The `endpoint` is exercised as a `"read"` under the grant (a digest alone
/// is never bearer authority); both records are then scanned for mutations
/// through any vector (task text, plans, extraction callbacks, transport
/// overrides, write-action fields). The endpoint origin — and the request
/// entry URL when present — must sit inside the request's admitted
/// `permitted_origins`. The HTTP method is ignored entirely.
///
/// On success returns a [`ReadOnlyRequest`] pinning the authorized endpoint
/// and request with `effect_policy: read_only`.
pub fn authorize_acquisition(
    grant: &Grant,
    endpoint: &CheckedRecord,
    request: &CheckedRecord,
) -> Result<ReadOnlyRequest, Fault> {
    if record_schema(endpoint) == "state_mutation_record"
        || record_schema(request) == "state_mutation_record"
    {
        return Err(fault(
            "mutation_rejected",
            "state_mutation_record is reserved and non-executing; no crawler transition inserts this record"
                .to_string(),
        ));
    }
    let endpoint_map = as_object(endpoint, "invalid_endpoint", "endpoint")?;
    let request_map = as_object(request, "invalid_request", "request")?;
    authorize_reference(grant, endpoint, "read")?;
    if let Some(reason) = scan_object(endpoint_map, "endpoint") {
        return Err(fault("mutation_rejected", reason));
    }
    if let Some(reason) = scan_object(request_map, "request") {
        return Err(fault("mutation_rejected", reason));
    }
    let url = extract_url(endpoint_map).ok_or_else(|| {
        fault(
            "invalid_endpoint",
            "endpoint requires an established absolute url".to_string(),
        )
    })?;
    let origin = extract_origin(&url).ok_or_else(|| {
        fault(
            "invalid_endpoint",
            format!("endpoint url {url:?} is not absolute"),
        )
    })?;
    let permitted = request_permitted_origins(request_map)?;
    if !permitted.iter().any(|allowed| allowed == &origin) {
        return Err(fault(
            "scope_violation",
            format!("endpoint origin {origin:?} is outside the admitted permitted_origins"),
        ));
    }
    if let Some(entry) = entry_url(request_map) {
        match extract_origin(&entry) {
            Some(entry_origin) if permitted.iter().any(|allowed| allowed == &entry_origin) => {}
            Some(entry_origin) => {
                return Err(fault(
                    "scope_violation",
                    format!(
                        "request entry origin {entry_origin:?} is outside the admitted permitted_origins"
                    ),
                ));
            }
            None => {
                return Err(fault(
                    "invalid_request",
                    format!("request entry url {entry:?} is not absolute"),
                ));
            }
        }
    }
    let record = validate(
        "audit_log",
        serde_json::json!({
            "endpoint": record_value(endpoint),
            "request": record_value(request),
            "effect_policy": "read_only",
        }),
    )?;
    Ok(ReadOnlyRequest { record })
}

/// Authorize a redirect under `grant`, chaining off a previous read-only
/// authorization.
///
/// The `redirect` is exercised as a `"read"` under the grant and scanned for
/// mutations exactly like an acquisition endpoint. Its origin must stay
/// inside the previous authorization's admitted `permitted_origins`; a
/// relative redirect inherits the previous endpoint origin. A redirect to a
/// mutation endpoint — including OR `self-refer-step1-validate.cfm` with
/// `usemyssn=No` — fails with `mutation_rejected` before wire.
///
/// On success returns a new [`ReadOnlyRequest`] carrying the redirect as its
/// endpoint and the previous request forward, so redirects chain.
pub fn authorize_redirect(
    grant: &Grant,
    previous: &ReadOnlyRequest,
    redirect: &CheckedRecord,
) -> Result<ReadOnlyRequest, Fault> {
    if record_schema(redirect) == "state_mutation_record" {
        return Err(fault(
            "mutation_rejected",
            "state_mutation_record is reserved and non-executing; no crawler transition inserts this record"
                .to_string(),
        ));
    }
    let redirect_map = as_object(redirect, "invalid_redirect", "redirect")?;
    authorize_reference(grant, redirect, "read")?;
    if let Some(reason) = scan_object(redirect_map, "redirect") {
        return Err(fault("mutation_rejected", reason));
    }
    let target = extract_url(redirect_map).ok_or_else(|| {
        fault(
            "invalid_redirect",
            "redirect requires an established url".to_string(),
        )
    })?;
    let previous_value = record_value(&previous.record);
    let permitted = previous_permitted_origins(previous_value)?;
    match extract_origin(&target) {
        Some(target_origin) => {
            if !permitted.iter().any(|allowed| allowed == &target_origin) {
                return Err(fault(
                    "scope_violation",
                    format!(
                        "redirect origin {target_origin:?} escapes the admitted permitted_origins"
                    ),
                ));
            }
        }
        None => {
            let previous_url = previous_endpoint_url(previous_value).ok_or_else(|| {
                fault(
                    "scope_violation",
                    "relative redirect without a previous absolute endpoint url".to_string(),
                )
            })?;
            let previous_origin = extract_origin(&previous_url).ok_or_else(|| {
                fault(
                    "scope_violation",
                    "relative redirect without a previous absolute endpoint url".to_string(),
                )
            })?;
            if !permitted.iter().any(|allowed| allowed == &previous_origin) {
                return Err(fault(
                    "scope_violation",
                    format!(
                        "previous endpoint origin {previous_origin:?} is outside the admitted permitted_origins"
                    ),
                ));
            }
        }
    }
    let carried_request = previous_value
        .get("request")
        .cloned()
        .unwrap_or_else(|| previous_value.clone());
    let mut combined = serde_json::json!({
        "endpoint": record_value(redirect),
        "request": carried_request,
        "effect_policy": "read_only",
    });
    if let Some(previous_endpoint) = previous_value.get("endpoint") {
        combined["previous_endpoint"] = previous_endpoint.clone();
    }
    let record = validate("audit_log", combined)?;
    Ok(ReadOnlyRequest { record })
}

/// Classify a write-action stub call. Any application/employer mutation —
/// apply, self-referral, contact reveal, submit-application, a
/// `state_mutation_record` shape, or a `mutating` flag — fails with
/// `mutation_rejected` before wire; the stub never executes. A record with no
/// mutation indicators passes through re-validated under its own schema.
pub fn reject_write_action(action: &CheckedRecord) -> Result<CheckedRecord, Fault> {
    if record_schema(action) == "state_mutation_record" {
        return Err(fault(
            "mutation_rejected",
            "write-action stub never handles state_mutation_record; the crawler inserts zero mutation rows"
                .to_string(),
        ));
    }
    let map = as_object(action, "invalid_action", "action")?;
    if let Some(reason) = scan_object(map, "action") {
        return Err(fault("mutation_rejected", reason));
    }
    Ok(validate(
        record_schema(action),
        record_value(action).clone(),
    )?)
}
