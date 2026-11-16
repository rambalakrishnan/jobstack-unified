//! `crawler_capabilities`: honest capability descriptors for crawler subjects.
//!
//! [`describe_configuration`] implements the `Describe` verb's declaration half:
//! it pins one `subject_id`/`subject_version`/`configured_mode`/`interface_surface`
//! scope, enumerates a complete capability catalog (the ten shared minimum IDs
//! plus the five crawler evidence-honesty IDs), nine operation mappings, task
//! mappings, channels, grounding/substrate, limits, accounting, and evidence
//! prefix. It performs no target probes, browser start, or task execution.
//!
//! [`check_capability`] answers one scoped capability question without inheritance:
//! the scope must match the descriptor pin exactly, omission is neither presence
//! nor absence, and unsupported connector mapping is never reported as native
//! absence.
//!
//! # Evidence honesty (C46)
//!
//! The five crawler IDs — solver, independent counts, certified cursor, session
//! lifetime, and measured performance — require `executed_observation` evidence
//! in the exact subject version before any non-`unknown` availability is emitted.
//! Documentation alone, deployment declarations, memory exceptions, connector
//! acknowledgements, renamed cursors, and predecessor-version evidence keep them
//! `unknown`. The Oregon placeholder solver additionally stays `unknown` while
//! `solver_names` names a placeholder (or names nothing for `OR`).

use crawler_authority::{grant_record, Grant};
use crawler_hashing::verify_record_digest;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Evidence-kernel record schema version stamped on descriptors.
const SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";

/// The ten shared minimum capability IDs (Contract 02 `x-minimum-capability-ids`).
const MINIMUM_CAPABILITY_IDS: &[&str] = &[
    "native_goal_task",
    "native_plan_execution",
    "native_cancel",
    "native_context_release",
    "native_artifact_retrieval",
    "native_revision",
    "native_dom_access",
    "browser_state_isolation",
    "browser_state_persistence",
    "learning_state_control",
];

/// Crawler evidence-honesty IDs (C46): solver, counts, cursor, lifetime, performance.
const HONESTY_CAPABILITY_IDS: &[&str] = &[
    "crawler_solver_availability",
    "crawler_independent_counts",
    "crawler_certified_cursor",
    "crawler_session_lifetime",
    "crawler_measured_performance",
];

/// The nine and only nine external connector verbs.
const NINE_VERBS: &[&str] = &[
    "Describe",
    "Prepare",
    "Start",
    "Observe",
    "RequestNativeCancel",
    "CloseObservationConnection",
    "CollectArtifacts",
    "ReleaseNativeContext",
    "Contain",
];

const AVAILABILITIES: &[&str] = &["present", "absent", "unknown", "not_applicable"];
const EVIDENCE_BASES: &[&str] = &[
    "documentation",
    "executed_observation",
    "source_diagnosis",
    "operator_attestation",
];
const CLAIM_ORIGINS: &[&str] = &["native", "composed_subject", "harness"];
const TARGETS: &[&str] = &["MN", "IL", "WI", "MI", "OR"];
const GROUNDINGS: &[&str] = &[
    "semantic",
    "recorded_selectors",
    "coordinates",
    "hybrid",
    "not_applicable",
    "unknown",
];
const SUBSTRATES: &[&str] = &["browser", "non_browser", "hybrid", "unknown"];
const IMPLEMENTATIONS: &[&str] = &["connector_local", "native_mapping", "unmapped"];
const TASK_TYPES: &[&str] = &["discover_jobs", "extract"];
const INPUT_FORMS: &[&str] = &["goal", "recorded_plan", "extraction_request", "crawl_declaration"];
const PLANNING_OWNERS: &[&str] = &["subject", "external_planner", "operator", "none"];

/// Fields that would turn a declaration into an assessment (EXT-DECLARE-NOT-ASSESS).
const QUALIFICATION_FIELDS: &[&str] = &[
    "qualification",
    "requirement_satisfaction",
    "application_success",
    "authoritative_success",
    "assessment_result",
    "requirement_result",
    "satisfaction",
    "success_flag",
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

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
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
        fault(code, format!("{what} must be an object"))
    })
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty string {field:?}"),
        )),
    }
}

fn is_64hex(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn is_digest_or_prefixed(text: &str) -> bool {
    if is_64hex(text) {
        return true;
    }
    text.strip_prefix("sha256:")
        .is_some_and(is_64hex)
}

fn strip_digest_prefix(text: &str) -> &str {
    text.strip_prefix("sha256:").unwrap_or(text)
}

fn is_honesty_id(id: &str) -> bool {
    HONESTY_CAPABILITY_IDS.contains(&id)
}

fn honesty_limitation(id: &str) -> &'static str {
    match id {
        "crawler_solver_availability" => {
            "placeholder solver remains unavailable until implemented and tested; unverified solver stays unknown"
        }
        "crawler_independent_counts" => {
            "independent total/floor proof source absent; counts remain unverified"
        }
        "crawler_certified_cursor" => {
            "permitted non-offset traversal unverified; positional page/start/postback coordinates are not certified continuation"
        }
        "crawler_session_lifetime" => {
            "session lifetime unknown; unknown lifetime does not justify invented keepalive requests"
        }
        "crawler_measured_performance" => {
            "performance unmeasured; deployment declarations are not measured benchmarks"
        }
        _ => "unverified capability is emitted explicitly as unknown",
    }
}

/// True while the configuration still names the placeholder solver.
fn is_placeholder_solver(target: Option<&str>, cfg: &Map<String, Value>) -> bool {
    let names: Vec<String> = match established(cfg, "solver_names") {
        None => Vec::new(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(|text| text.to_lowercase()))
            .collect(),
        Some(_) => return true,
    };
    if names.iter().any(|name| name.contains("placeholder")) {
        return true;
    }
    // OR ships no solver at all: missing/empty names are the blocked placeholder.
    target == Some("OR") && names.is_empty()
}

/// True when the configuration proposes positional pagination outside the only
/// certified scope (`ordering_model=Deterministic` with `coverage_scope=per_run`).
fn is_uncertified_positional_claim(cfg: &Map<String, Value>) -> bool {
    let ordering = established(cfg, "ordering_model")
        .and_then(Value::as_str)
        .unwrap_or("");
    let scope = established(cfg, "coverage_scope")
        .and_then(Value::as_str)
        .unwrap_or("");
    let kind = established(cfg, "cursor_kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let proposed = established(cfg, "proposed_cursor_kind")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_lowercase();
    let combined = format!("{kind} {proposed}");
    let looks_positional = combined.contains("page$")
        || combined.contains("page=")
        || combined.contains("positional")
        || combined.contains("offset")
        || combined.contains("numeric")
        || combined.contains("page$n");
    looks_positional && !(ordering == "Deterministic" && scope == "per_run")
}

fn parse_pin(map: &Map<String, Value>, field: &str) -> Result<Value, Fault> {
    let pin = match established(map, field) {
        Some(Value::Object(pin)) => pin,
        _ => {
            return Err(fault(
                "missing_pin",
                format!("configuration requires an established {field:?} pin with id and version"),
            ))
        }
    };
    let id = required_str(pin, "id", "missing_pin", &format!("{field} pin"))?.to_string();
    let version =
        required_str(pin, "version", "missing_pin", &format!("{field} pin"))?.to_string();
    let digest = match established(pin, "artifact_digest") {
        None => missing("not_observed", "pin digest not supplied"),
        Some(Value::String(text)) if is_digest_or_prefixed(text) => {
            Value::String(text.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_pin_digest",
                format!("{field} pin artifact_digest must be a digest or Missing"),
            ))
        }
    };
    Ok(json!({"id": id, "version": version, "artifact_digest": digest}))
}

fn parse_positive(map: &Map<String, Value>, field: &str) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(value) if value >= 1 && value <= 9_007_199_254_740_991 => Ok(value),
            _ => Err(fault(
                "invalid_limits",
                format!("limits {field:?} must be an integer in 1..=9007199254740991"),
            )),
        },
        _ => Err(fault(
            "invalid_limits",
            format!("limits requires an established integer {field:?}"),
        )),
    }
}

fn parse_revision(map: &Map<String, Value>, field: &str) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => match number.as_u64() {
            Some(value) if value <= 9_007_199_254_740_991 => Ok(value),
            _ => Err(fault(
                "invalid_limits",
                format!("limits {field:?} must be an integer in 0..=9007199254740991"),
            )),
        },
        _ => Err(fault(
            "invalid_limits",
            format!("limits requires an established integer {field:?}"),
        )),
    }
}

fn parse_limits(cfg: &Map<String, Value>) -> Result<Value, Fault> {
    let limits = match established(cfg, "limits") {
        Some(Value::Object(limits)) => limits,
        _ => {
            return Err(fault(
                "missing_limits",
                "configuration requires established local limits; no portfolio default is selected"
                    .to_string(),
            ))
        }
    };
    let wait = match established(limits, "max_call_wait") {
        Some(Value::Object(wait)) => wait,
        _ => {
            return Err(fault(
                "invalid_limits",
                "limits max_call_wait must be an established {kind, unit, value} object".to_string(),
            ))
        }
    };
    let kind = required_str(wait, "kind", "invalid_limits", "limits max_call_wait")?;
    if kind != "exact" {
        return Err(fault(
            "invalid_limits",
            "limits max_call_wait kind must be exactly \"exact\"".to_string(),
        ));
    }
    let unit = required_str(wait, "unit", "invalid_limits", "limits max_call_wait")?;
    if unit != "ms" {
        return Err(fault(
            "invalid_limits",
            "limits max_call_wait unit must be exactly \"ms\"".to_string(),
        ));
    }
    let wait_value = match established(wait, "value") {
        Some(Value::Number(number)) => match number.as_f64() {
            Some(value) if value.is_finite() && value >= 0.0 => number.clone(),
            _ => {
                return Err(fault(
                    "invalid_limits",
                    "limits max_call_wait value must be a finite number >= 0".to_string(),
                ))
            }
        },
        _ => {
            return Err(fault(
                "invalid_limits",
                "limits max_call_wait requires an established numeric value".to_string(),
            ))
        }
    };
    let max_observe_items = parse_positive(limits, "max_observe_items")?;
    let max_request_bytes = parse_positive(limits, "max_request_bytes")?;
    let max_response_bytes = parse_positive(limits, "max_response_bytes")?;
    let max_artifact_chunk_bytes = parse_positive(limits, "max_artifact_chunk_bytes")?;
    let max_queued_tasks = parse_revision(limits, "max_queued_tasks")?;
    let max_active_tasks = parse_positive(limits, "max_active_tasks")?;
    Ok(json!({
        "max_call_wait": {"kind": "exact", "unit": "ms", "value": wait_value},
        "max_observe_items": max_observe_items,
        "max_request_bytes": max_request_bytes,
        "max_response_bytes": max_response_bytes,
        "max_artifact_chunk_bytes": max_artifact_chunk_bytes,
        "max_queued_tasks": max_queued_tasks,
        "max_active_tasks": max_active_tasks,
    }))
}

fn default_task_mappings() -> Value {
    let mapping = || {
        json!({
            "id": "crawler-task-mapping",
            "version": "1",
            "artifact_digest": missing("not_observed", "task mapping digest not supplied"),
        })
    };
    json!([
        {
            "task_type": "discover_jobs",
            "input_form": "crawl_declaration",
            "mapping": mapping(),
            "planning_owner": "none",
            "recovery_owner": "none",
            "limitations": ["read-only discovery; no application authority"],
        },
        {
            "task_type": "extract",
            "input_form": "extraction_request",
            "mapping": mapping(),
            "planning_owner": "none",
            "recovery_owner": "none",
            "limitations": ["read-only extraction; no application authority"],
        },
    ])
}

fn parse_task_mappings(cfg: &Map<String, Value>) -> Result<Value, Fault> {
    let claimed = match established(cfg, "task_mappings") {
        None => return Ok(default_task_mappings()),
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(fault(
                "invalid_task_mapping",
                "task_mappings must be an array when present".to_string(),
            ))
        }
    };
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(claimed.len());
    for (index, item) in claimed.iter().enumerate() {
        let entry = item.as_object().ok_or_else(|| {
            fault(
                "invalid_task_mapping",
                format!("task_mappings[{index}] must be an object"),
            )
        })?;
        let task_type = match established(entry, "task_type") {
            Some(Value::String(text)) => text.as_str(),
            _ => {
                return Err(fault(
                    "invalid_task_mapping",
                    format!("task_mappings[{index}] requires an established task_type"),
                ))
            }
        };
        if task_type == "apply" {
            return Err(fault(
                "invalid_task_mapping",
                "crawler task mappings never include apply; discovery/extraction are read-only"
                    .to_string(),
            ));
        }
        if !TASK_TYPES.contains(&task_type) {
            return Err(fault(
                "invalid_task_mapping",
                format!("task_mappings[{index}] task_type {task_type:?} is not discover_jobs or extract"),
            ));
        }
        if !seen.insert(task_type.to_string()) {
            return Err(fault(
                "duplicate_task_mapping",
                format!("task_type {task_type:?} appears more than once"),
            ));
        }
        let input_form = match established(entry, "input_form") {
            Some(Value::String(text)) if INPUT_FORMS.contains(&text.as_str()) => text.clone(),
            _ => {
                return Err(fault(
                    "invalid_task_mapping",
                    format!(
                        "task_mappings[{index}] input_form must be one of goal, recorded_plan, extraction_request, crawl_declaration"
                    ),
                ))
            }
        };
        let mapping = parse_pin(entry, "mapping").map_err(|_| {
            fault(
                "invalid_task_mapping",
                format!("task_mappings[{index}] mapping must be an established pin"),
            )
        })?;
        let planning_owner = match established(entry, "planning_owner") {
            Some(Value::String(text)) if PLANNING_OWNERS.contains(&text.as_str()) => {
                text.clone()
            }
            _ => {
                return Err(fault(
                    "invalid_task_mapping",
                    format!(
                        "task_mappings[{index}] planning_owner must be one of subject, external_planner, operator, none"
                    ),
                ))
            }
        };
        let recovery_owner = match established(entry, "recovery_owner") {
            Some(Value::String(text)) if PLANNING_OWNERS.contains(&text.as_str()) => {
                text.clone()
            }
            _ => {
                return Err(fault(
                    "invalid_task_mapping",
                    format!(
                        "task_mappings[{index}] recovery_owner must be one of subject, external_planner, operator, none"
                    ),
                ))
            }
        };
        let limitations = match established(entry, "limitations") {
            Some(Value::Array(items)) => {
                for item in items {
                    match item {
                        Value::String(text) if !text.is_empty() => {}
                        _ => {
                            return Err(fault(
                                "invalid_task_mapping",
                                format!(
                                    "task_mappings[{index}] limitations must be nonempty strings"
                                ),
                            ))
                        }
                    }
                }
                Value::Array(items.clone())
            }
            _ => {
                return Err(fault(
                    "invalid_task_mapping",
                    format!("task_mappings[{index}] requires established limitations"),
                ))
            }
        };
        out.push(json!({
            "task_type": task_type,
            "input_form": input_form,
            "mapping": mapping,
            "planning_owner": planning_owner,
            "recovery_owner": recovery_owner,
            "limitations": limitations,
        }));
    }
    Ok(Value::Array(out))
}

fn default_operation(verb: &str) -> Value {
    match verb {
        "RequestNativeCancel" | "ReleaseNativeContext" | "Contain" => json!({
            "operation": verb,
            "implementation": "unmapped",
            "native_contract": missing("not_observed", "no evidenced native contract for this operation"),
            "capability_refs": [],
            "evidence_refs": [],
            "limitations": ["unsupported mapping is not native absence"],
        }),
        _ => json!({
            "operation": verb,
            "implementation": "connector_local",
            "native_contract": missing("not_applicable", "connector-local operation has no native contract"),
            "capability_refs": [],
            "evidence_refs": [],
            "limitations": ["describe performs no probes, browser start, or task execution"],
        }),
    }
}

fn parse_operations(cfg: &Map<String, Value>) -> Result<Value, Fault> {
    let mut claimed: HashMap<&str, &Map<String, Value>> = HashMap::new();
    if let Some(value) = established(cfg, "claimed_operations") {
        let items = value.as_array().ok_or_else(|| {
            fault(
                "invalid_operation",
                "claimed_operations must be an array when present".to_string(),
            )
        })?;
        for (index, item) in items.iter().enumerate() {
            let entry = item.as_object().ok_or_else(|| {
                fault(
                    "invalid_operation",
                    format!("claimed_operations[{index}] must be an object"),
                )
            })?;
            let operation = match established(entry, "operation") {
                Some(Value::String(text)) => text.as_str(),
                _ => {
                    return Err(fault(
                        "invalid_operation",
                        format!("claimed_operations[{index}] requires an established operation"),
                    ))
                }
            };
            if !NINE_VERBS.contains(&operation) {
                return Err(fault(
                    "unknown_verb",
                    format!("claimed_operations[{index}] operation {operation:?} is not one of the nine verbs"),
                ));
            }
            if claimed.insert(operation, entry).is_some() {
                return Err(fault(
                    "duplicate_operation",
                    format!("operation {operation:?} appears more than once"),
                ));
            }
            match established(entry, "implementation") {
                Some(Value::String(text)) if IMPLEMENTATIONS.contains(&text.as_str()) => {}
                _ => {
                    return Err(fault(
                        "invalid_operation",
                        format!(
                            "claimed_operations[{index}] implementation must be one of connector_local, native_mapping, unmapped"
                        ),
                    ))
                }
            }
            for array_field in ["capability_refs", "evidence_refs", "limitations"] {
                match established(entry, array_field) {
                    None => {}
                    Some(Value::Array(_)) => {}
                    Some(_) => {
                        return Err(fault(
                            "invalid_operation",
                            format!("claimed_operations[{index}] {array_field:?} must be an array"),
                        ))
                    }
                }
            }
            if let Some(Value::Array(limitations)) = established(entry, "limitations") {
                for limitation in limitations {
                    match limitation {
                        Value::String(text) if !text.is_empty() => {}
                        _ => {
                            return Err(fault(
                                "invalid_operation",
                                format!(
                                    "claimed_operations[{index}] limitations must be nonempty strings"
                                ),
                            ))
                        }
                    }
                }
            }
        }
    }

    let mut out = Vec::with_capacity(NINE_VERBS.len());
    for verb in NINE_VERBS {
        match claimed.get(verb) {
            None => out.push(default_operation(verb)),
            Some(entry) => {
                let implementation = established(entry, "implementation")
                    .and_then(Value::as_str)
                    .unwrap_or("unmapped");
                let mut limitations: Vec<Value> = match established(entry, "limitations") {
                    Some(Value::Array(items)) => items.clone(),
                    _ => Vec::new(),
                };
                let evidence_refs = match established(entry, "evidence_refs") {
                    Some(Value::Array(items)) => Value::Array(items.clone()),
                    _ => Value::Array(Vec::new()),
                };
                let capability_refs = match established(entry, "capability_refs") {
                    Some(Value::Array(items)) => Value::Array(items.clone()),
                    _ => Value::Array(Vec::new()),
                };
                if implementation == "native_mapping" {
                    let has_contract = established(entry, "native_contract")
                        .and_then(Value::as_object)
                        .is_some_and(|pin| {
                            established(pin, "id")
                                .and_then(Value::as_str)
                                .is_some_and(|text| !text.is_empty())
                                && established(pin, "version")
                                    .and_then(Value::as_str)
                                    .is_some_and(|text| !text.is_empty())
                        });
                    let has_evidence = evidence_refs
                        .as_array()
                        .is_some_and(|items| !items.is_empty());
                    if !has_contract || !has_evidence {
                        limitations.push(Value::String(
                            "claimed native mapping lacks an evidenced contract; emitted as unmapped, which is not native absence".to_string(),
                        ));
                        out.push(json!({
                            "operation": verb,
                            "implementation": "unmapped",
                            "native_contract": missing("not_observed", "no evidenced native contract for this operation"),
                            "capability_refs": capability_refs,
                            "evidence_refs": evidence_refs,
                            "limitations": limitations,
                        }));
                    } else {
                        let contract = established(entry, "native_contract")
                            .cloned()
                            .unwrap_or_else(|| {
                                missing("not_observed", "no evidenced native contract")
                            });
                        out.push(json!({
                            "operation": verb,
                            "implementation": "native_mapping",
                            "native_contract": contract,
                            "capability_refs": capability_refs,
                            "evidence_refs": evidence_refs,
                            "limitations": limitations,
                        }));
                    }
                } else if implementation == "connector_local" {
                    if established(entry, "native_contract")
                        .and_then(Value::as_object)
                        .is_some()
                    {
                        return Err(fault(
                            "invalid_operation",
                            format!(
                                "operation {verb:?} is connector-local and must not carry an established native contract"
                            ),
                        ));
                    }
                    out.push(json!({
                        "operation": verb,
                        "implementation": "connector_local",
                        "native_contract": missing("not_applicable", "connector-local operation has no native contract"),
                        "capability_refs": capability_refs,
                        "evidence_refs": evidence_refs,
                        "limitations": limitations,
                    }));
                } else {
                    if limitations.is_empty() {
                        limitations.push(Value::String(
                            "unsupported mapping is not native absence".to_string(),
                        ));
                    }
                    out.push(json!({
                        "operation": verb,
                        "implementation": "unmapped",
                        "native_contract": missing("not_observed", "no evidenced native contract for this operation"),
                        "capability_refs": capability_refs,
                        "evidence_refs": evidence_refs,
                        "limitations": limitations,
                    }));
                }
            }
        }
    }
    Ok(Value::Array(out))
}

struct ClaimedCapability {
    availability: String,
    requirement_refs: Vec<Value>,
    claim_origin: String,
    evidence: Vec<Value>,
    evidence_versions: Vec<Option<String>>,
    has_executed_in_scope: bool,
    limitations: Vec<Value>,
}

fn parse_claimed_capability(
    entry: &Map<String, Value>,
    index: usize,
    current_version: &str,
) -> Result<(String, ClaimedCapability), Fault> {
    let capability_id = match established(entry, "capability_id") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => {
            return Err(fault(
                "invalid_capability",
                format!("claimed_capabilities[{index}] requires an established capability_id"),
            ))
        }
    };
    for field in QUALIFICATION_FIELDS {
        if established(entry, field).is_some() {
            return Err(fault(
                "qualification_forbidden",
                format!(
                    "claimed_capabilities[{index}] must not carry {field:?}; the connector declares, it does not assess"
                ),
            ));
        }
    }
    let availability = match established(entry, "availability") {
        None => "unknown".to_string(),
        Some(Value::String(text)) if AVAILABILITIES.contains(&text.as_str()) => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_availability",
                format!(
                    "claimed_capabilities[{index}] availability must be one of present, absent, unknown, not_applicable"
                ),
            ))
        }
    };
    let requirement_refs = match established(entry, "requirement_refs") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(text) if !text.is_empty() => {}
                    _ => {
                        return Err(fault(
                            "invalid_capability",
                            format!(
                                "claimed_capabilities[{index}] requirement_refs must be nonempty strings"
                            ),
                        ))
                    }
                }
            }
            items.clone()
        }
        Some(_) => {
            return Err(fault(
                "invalid_capability",
                format!("claimed_capabilities[{index}] requirement_refs must be an array"),
            ))
        }
    };
    let claim_origin = match established(entry, "claim_origin") {
        None => "native".to_string(),
        Some(Value::String(text)) if CLAIM_ORIGINS.contains(&text.as_str()) => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_capability",
                format!(
                    "claimed_capabilities[{index}] claim_origin must be one of native, composed_subject, harness"
                ),
            ))
        }
    };
    let mut evidence = Vec::new();
    let mut evidence_versions: Vec<Option<String>> = Vec::new();
    let mut has_executed_in_scope = false;
    match established(entry, "evidence") {
        None => {}
        Some(Value::Array(items)) => {
            for (evidence_index, item) in items.iter().enumerate() {
                let evidence_entry = item.as_object().ok_or_else(|| {
                    fault(
                        "invalid_evidence",
                        format!(
                            "claimed_capabilities[{index}] evidence[{evidence_index}] must be an object"
                        ),
                    )
                })?;
                let basis = match established(evidence_entry, "basis") {
                    Some(Value::String(text)) if EVIDENCE_BASES.contains(&text.as_str()) => {
                        text.as_str()
                    }
                    _ => {
                        return Err(fault(
                            "invalid_evidence",
                            format!(
                                "claimed_capabilities[{index}] evidence[{evidence_index}] basis must be one of documentation, executed_observation, source_diagnosis, operator_attestation"
                            ),
                        ))
                    }
                };
                match established(evidence_entry, "ref") {
                    Some(Value::Object(_)) => {}
                    _ => {
                        return Err(fault(
                            "invalid_evidence",
                            format!(
                                "claimed_capabilities[{index}] evidence[{evidence_index}] requires an established ref object"
                            ),
                        ))
                    }
                }
                let version = match established(evidence_entry, "subject_version") {
                    None => None,
                    Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
                    Some(_) => {
                        return Err(fault(
                            "invalid_evidence",
                            format!(
                                "claimed_capabilities[{index}] evidence[{evidence_index}] subject_version must be a nonempty string"
                            ),
                        ))
                    }
                };
                let in_scope = version.as_deref().is_none_or(|text| text == current_version);
                if basis == "executed_observation" && in_scope {
                    has_executed_in_scope = true;
                }
                evidence_versions.push(version);
                evidence.push(item.clone());
            }
        }
        Some(_) => {
            return Err(fault(
                "invalid_evidence",
                format!("claimed_capabilities[{index}] evidence must be an array"),
            ))
        }
    }
    let limitations = match established(entry, "limitations") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            for item in items {
                match item {
                    Value::String(text) if !text.is_empty() => {}
                    _ => {
                        return Err(fault(
                            "invalid_capability",
                            format!(
                                "claimed_capabilities[{index}] limitations must be nonempty strings"
                            ),
                        ))
                    }
                }
            }
            items.clone()
        }
        Some(_) => {
            return Err(fault(
                "invalid_capability",
                format!("claimed_capabilities[{index}] limitations must be an array"),
            ))
        }
    };
    Ok((
        capability_id,
        ClaimedCapability {
            availability,
            requirement_refs,
            claim_origin,
            evidence,
            evidence_versions,
            has_executed_in_scope,
            limitations,
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn resolve_capability(
    capability_id: &str,
    claimed: Option<ClaimedCapability>,
    current_version: &str,
    target: Option<&str>,
    cfg: &Map<String, Value>,
) -> Value {
    let Some(claimed) = claimed else {
        let limitation = if is_honesty_id(capability_id) {
            honesty_limitation(capability_id).to_string()
        } else {
            "no version-specific evidence supplied; new subject version starts unknown"
                .to_string()
        };
        return json!({
            "capability_id": capability_id,
            "requirement_refs": [],
            "availability": "unknown",
            "claim_origin": "native",
            "evidence": [],
            "limitations": [limitation],
        });
    };

    let mut availability = claimed.availability;
    let mut limitations = claimed.limitations;
    let mut downgraded = false;
    let mut push_limitation = |text: String| {
        if !limitations.iter().any(|item| item.as_str() == Some(text.as_str())) {
            limitations.push(Value::String(text));
        }
    };

    // Non-unknown availability requires journaled evidence in the exact scope.
    if availability != "unknown" && claimed.evidence.is_empty() {
        availability = "unknown".to_string();
        downgraded = true;
        push_limitation(
            "non-unknown availability requires journaled evidence in the exact scope; emitted as unknown"
                .to_string(),
        );
    }

    // Predecessor evidence does not inherit across subject versions.
    if availability != "unknown" && !claimed.evidence.is_empty() {
        let has_versioned = claimed.evidence_versions.iter().any(|version| version.is_some());
        if has_versioned {
            let has_current = claimed
                .evidence_versions
                .iter()
                .any(|version| version.as_deref() == Some(current_version));
            if !has_current {
                availability = "unknown".to_string();
                downgraded = true;
                push_limitation(
                    "new subject version starts unknown until its own evidence establishes another availability; predecessor evidence does not inherit"
                        .to_string(),
                );
            }
        }
    }

    // C46 honesty: the five crawler IDs need executed observation in scope.
    if availability != "unknown" && is_honesty_id(capability_id) && !claimed.has_executed_in_scope
    {
        availability = "unknown".to_string();
        downgraded = true;
        push_limitation(format!(
            "{}; documentation alone does not establish it",
            honesty_limitation(capability_id)
        ));
    }

    // Oregon placeholder solver stays unknown while a placeholder is named.
    if availability != "unknown"
        && capability_id == "crawler_solver_availability"
        && is_placeholder_solver(target, cfg)
    {
        availability = "unknown".to_string();
        downgraded = true;
        push_limitation(honesty_limitation(capability_id).to_string());
    }

    // Positional pagination outside deterministic per-run scope is uncertified.
    if availability != "unknown"
        && capability_id == "crawler_certified_cursor"
        && is_uncertified_positional_claim(cfg)
    {
        availability = "unknown".to_string();
        downgraded = true;
        push_limitation(honesty_limitation(capability_id).to_string());
    }

    if downgraded && limitations.is_empty() {
        limitations.push(Value::String(
            "unverified capability is emitted explicitly as unknown".to_string(),
        ));
    }

    json!({
        "capability_id": capability_id,
        "requirement_refs": claimed.requirement_refs,
        "availability": availability,
        "claim_origin": claimed.claim_origin,
        "evidence": claimed.evidence,
        "limitations": limitations,
    })
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Describe one configured subject as a connector descriptor.
///
/// The `configuration` pins `connector_id`, `connector_version`, `build`,
/// `binding`, an exact `subject` (`subject_id`, `subject_version`,
/// `configured_mode`, `interface_surface`), local `limits`, and
/// `budget_accounting`, with optional `target`, `journal_id`, `observation_channels`,
/// `action_grounding`, `execution_substrate`, `task_mappings`,
/// `claimed_capabilities`, and `claimed_operations`. Claimed presence/absence is
/// honesty-checked: non-`unknown` availability needs evidence in the exact
/// subject version, and the five C46 IDs additionally need `executed_observation`
/// (the Oregon placeholder solver stays `unknown` while a placeholder is named).
/// When `journal_id` is established, the descriptor's evidence prefix is grounded
/// through an owner-local [`OwnerStore::read`] of that journal's prefix; otherwise
/// it is `Missing(not_observed)`. No target request, probe, or qualification is
/// performed: configurations carrying qualification fields are rejected and the
/// descriptor never carries them.
pub fn describe_configuration(
    store: &dyn OwnerStore,
    grant: &Grant,
    configuration: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let cfg = as_object(configuration, "invalid_configuration", "configuration")?.clone();
    for field in QUALIFICATION_FIELDS {
        if established(&cfg, field).is_some() {
            return Err(fault(
                "qualification_forbidden",
                format!(
                    "configuration must not carry {field:?}; the connector declares, it does not assess"
                ),
            ));
        }
    }

    let connector_id = required_str(&cfg, "connector_id", "missing_connector", "configuration")?
        .to_string();
    let connector_version = required_str(
        &cfg,
        "connector_version",
        "missing_connector",
        "configuration",
    )?
    .to_string();
    let build = parse_pin(&cfg, "build")?;
    let binding = parse_pin(&cfg, "binding")?;

    let subject_map = match established(&cfg, "subject") {
        Some(Value::Object(subject)) => subject.clone(),
        _ => {
            return Err(fault(
                "missing_subject",
                "configuration requires an established subject pin with subject_id, subject_version, configured_mode, interface_surface"
                    .to_string(),
            ))
        }
    };
    let subject_id =
        required_str(&subject_map, "subject_id", "missing_subject", "subject")?.to_string();
    let subject_version =
        required_str(&subject_map, "subject_version", "missing_subject", "subject")?.to_string();
    let configured_mode =
        required_str(&subject_map, "configured_mode", "missing_subject", "subject")?.to_string();
    let interface_surface = required_str(
        &subject_map,
        "interface_surface",
        "missing_subject",
        "subject",
    )?
    .to_string();
    let subject_value = json!({
        "subject_id": subject_id,
        "subject_version": subject_version,
        "configured_mode": configured_mode,
        "interface_surface": interface_surface,
    });

    let grant_map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let grant_owner = required_str(grant_map, "owner_domain", "grant_without_owner", "grant")?;
    if let Some(Value::String(cfg_owner)) = established(&cfg, "owner_domain") {
        if cfg_owner != grant_owner {
            return Err(fault(
                "owner_mismatch",
                format!(
                    "configuration owner {cfg_owner:?} does not match grant owner {grant_owner:?}"
                ),
            ));
        }
    }

    let target: Option<String> = match established(&cfg, "target") {
        None => None,
        Some(Value::String(text)) if TARGETS.contains(&text.as_str()) => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_target",
                "target must be one of MN, IL, WI, MI, OR when present".to_string(),
            ))
        }
    };

    if let Some(value) = established(&cfg, "solver_names") {
        match value {
            Value::Array(items) => {
                for item in items {
                    if !matches!(item, Value::String(text) if !text.is_empty()) {
                        return Err(fault(
                            "invalid_configuration",
                            "solver_names must be nonempty strings".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(fault(
                    "invalid_configuration",
                    "solver_names must be an array when present".to_string(),
                ))
            }
        }
    }
    for field in ["ordering_model", "coverage_scope", "cursor_kind", "proposed_cursor_kind"] {
        if let Some(value) = established(&cfg, field) {
            if !matches!(value, Value::String(text) if !text.is_empty()) {
                return Err(fault(
                    "invalid_configuration",
                    format!("{field:?} must be a nonempty string when present"),
                ));
            }
        }
    }

    let limits_value = parse_limits(&cfg)?;
    let budget_accounting = parse_pin(&cfg, "budget_accounting")?;

    let channels_value = match established(&cfg, "observation_channels") {
        None => json!(["journal_observations"]),
        Some(Value::Array(items)) => {
            let mut seen = HashSet::new();
            for item in items {
                match item {
                    Value::String(text) if !text.is_empty() => {
                        if !seen.insert(text.clone()) {
                            return Err(fault(
                                "invalid_channels",
                                "observation_channels must not repeat a channel".to_string(),
                            ));
                        }
                    }
                    _ => {
                        return Err(fault(
                            "invalid_channels",
                            "observation_channels must be nonempty strings".to_string(),
                        ))
                    }
                }
            }
            Value::Array(items.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_channels",
                "observation_channels must be an array when present".to_string(),
            ))
        }
    };

    let grounding = match established(&cfg, "action_grounding") {
        None => "unknown".to_string(),
        Some(Value::String(text)) if GROUNDINGS.contains(&text.as_str()) => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_grounding",
                "action_grounding must be one of semantic, recorded_selectors, coordinates, hybrid, not_applicable, unknown"
                    .to_string(),
            ))
        }
    };
    let substrate = match established(&cfg, "execution_substrate") {
        None => "unknown".to_string(),
        Some(Value::String(text)) if SUBSTRATES.contains(&text.as_str()) => text.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_substrate",
                "execution_substrate must be one of browser, non_browser, hybrid, unknown"
                    .to_string(),
            ))
        }
    };

    let task_mappings_value = parse_task_mappings(&cfg)?;
    let operations_value = parse_operations(&cfg)?;

    let evidence_prefix_value = match established(&cfg, "journal_id") {
        None => missing(
            "not_observed",
            "no journal_id supplied; descriptor evidence is not grounded to a journal prefix",
        ),
        Some(Value::String(journal_id)) if !journal_id.is_empty() => {
            let query = validate(
                OUTPUT_SCHEMA,
                json!({"query": "prefix", "journal_id": journal_id}),
            )?;
            let prefix_record = store.read(grant, &query)?;
            let prefix_map = as_object(&prefix_record, "invalid_prefix", "store prefix")?;
            let prefix_journal =
                required_str(prefix_map, "journal_id", "invalid_prefix", "store prefix")?
                    .to_string();
            let last_sequence = match established(prefix_map, "last_sequence") {
                Some(Value::Number(number)) => match number.as_u64() {
                    Some(value) => value,
                    None => {
                        return Err(fault(
                            "invalid_prefix",
                            "store prefix last_sequence must be an unsigned integer".to_string(),
                        ))
                    }
                },
                _ => {
                    return Err(fault(
                        "invalid_prefix",
                        "store prefix requires an established last_sequence".to_string(),
                    ))
                }
            };
            let head_hash =
                required_str(prefix_map, "head_hash", "invalid_prefix", "store prefix")?
                    .to_string();
            json!({
                "journal_id": prefix_journal,
                "last_sequence": last_sequence,
                "head_hash": head_hash,
            })
        }
        Some(_) => {
            return Err(fault(
                "invalid_journal_id",
                "journal_id must be a nonempty string when present".to_string(),
            ))
        }
    };

    let mut claimed: HashMap<String, ClaimedCapability> = HashMap::new();
    if let Some(value) = established(&cfg, "claimed_capabilities") {
        let items = value.as_array().ok_or_else(|| {
            fault(
                "invalid_capability",
                "claimed_capabilities must be an array when present".to_string(),
            )
        })?;
        for (index, item) in items.iter().enumerate() {
            let entry = item.as_object().ok_or_else(|| {
                fault(
                    "invalid_capability",
                    format!("claimed_capabilities[{index}] must be an object"),
                )
            })?;
            let (capability_id, parsed) =
                parse_claimed_capability(entry, index, &subject_version)?;
            if claimed.insert(capability_id.clone(), parsed).is_some() {
                return Err(fault(
                    "duplicate_capability",
                    format!("capability {capability_id:?} appears more than once"),
                ));
            }
        }
    }

    let mut catalog = Vec::new();
    for id in MINIMUM_CAPABILITY_IDS
        .iter()
        .chain(HONESTY_CAPABILITY_IDS.iter())
    {
        let parsed = claimed.remove(*id);
        catalog.push(resolve_capability(
            id,
            parsed,
            &subject_version,
            target.as_deref(),
            &cfg,
        ));
    }
    // Additional versioned capabilities are preserved after the same honesty pass.
    let mut extra_ids: Vec<String> = claimed.keys().cloned().collect();
    extra_ids.sort();
    for id in extra_ids {
        let parsed = claimed.remove(&id);
        catalog.push(resolve_capability(
            &id,
            parsed,
            &subject_version,
            target.as_deref(),
            &cfg,
        ));
    }

    let descriptor_id = format!("{connector_id}:{subject_id}:{subject_version}");
    let capabilities_value = json!({
        "record_type": "capability_descriptor",
        "schema_version": SCHEMA_VERSION,
        "descriptor_id": descriptor_id,
        "descriptor_revision": 1,
        "declared_by": connector_id,
        "subject": subject_value,
        "catalog": {
            "id": "crawler-capability-catalog",
            "version": "1",
            "artifact_digest": missing("not_observed", "catalog digest tracked by descriptor evidence prefix"),
        },
        "evidence_prefix": evidence_prefix_value.clone(),
        "supersedes": missing("not_applicable", "descriptors do not supersede across subject versions; each version starts unknown"),
        "capabilities": catalog,
    });

    let descriptor_value = json!({
        "record_type": "connector_descriptor",
        "schema_version": SCHEMA_VERSION,
        "connector_id": connector_id,
        "connector_version": connector_version,
        "build": build,
        "binding": binding,
        "subject": subject_value,
        "capabilities": capabilities_value,
        "operations": operations_value,
        "task_mappings": task_mappings_value,
        "observation_channels": channels_value,
        "action_grounding": grounding,
        "execution_substrate": substrate,
        "limits": limits_value,
        "budget_accounting": budget_accounting,
        "evidence_prefix": evidence_prefix_value,
    });
    validate(OUTPUT_SCHEMA, descriptor_value)
}

/// Check one capability in a descriptor against an exact scope.
///
/// `scope` carries `subject_id`, `subject_version`, `configured_mode`, and
/// `interface_surface`, with an optional `descriptor_digest` (64 hex or
/// `sha256:`-prefixed) verified through [`verify_record_digest`]. The scope must
/// equal the descriptor pin exactly: a different version, mode, or surface is a
/// `scope_mismatch`, never an inherited finding. A `capability_id` absent from
/// the catalog is `unknown_capability`: omission implies neither presence nor
/// absence. Non-`unknown` availability without evidence in the exact scope — or,
/// for the five C46 IDs, without `executed_observation` — is `unverified_claim`.
/// The returned record restates the catalog entry with its subject pin; it never
/// equates an unmapped connector operation with native absence and never carries
/// qualification or result fields.
pub fn check_capability(
    descriptor: &CheckedRecord,
    capability_id: &str,
    scope: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    if capability_id.is_empty() {
        return Err(fault(
            "invalid_capability_id",
            "capability_id must be a nonempty string".to_string(),
        ));
    }
    let desc_map = as_object(descriptor, "invalid_descriptor", "descriptor")?;
    match established(desc_map, "record_type") {
        Some(Value::String(record_type)) if record_type == "connector_descriptor" => {}
        _ => {
            return Err(fault(
                "invalid_descriptor",
                "descriptor record_type must be exactly \"connector_descriptor\"".to_string(),
            ))
        }
    }
    let caps_obj = match established(desc_map, "capabilities") {
        Some(Value::Object(caps)) => caps,
        _ => {
            return Err(fault(
                "invalid_descriptor",
                "descriptor requires an established capabilities object".to_string(),
            ))
        }
    };
    let catalog = match established(caps_obj, "capabilities") {
        Some(Value::Array(catalog)) => catalog,
        _ => {
            return Err(fault(
                "invalid_descriptor",
                "descriptor capabilities require an established capabilities array".to_string(),
            ))
        }
    };
    let desc_subject = match established(desc_map, "subject") {
        Some(Value::Object(subject)) => subject,
        _ => {
            return Err(fault(
                "invalid_descriptor",
                "descriptor requires an established subject pin".to_string(),
            ))
        }
    };
    let desc_id = required_str(desc_subject, "subject_id", "invalid_descriptor", "subject")?;
    let desc_version = required_str(
        desc_subject,
        "subject_version",
        "invalid_descriptor",
        "subject",
    )?;
    let desc_mode = required_str(
        desc_subject,
        "configured_mode",
        "invalid_descriptor",
        "subject",
    )?;
    let desc_surface = required_str(
        desc_subject,
        "interface_surface",
        "invalid_descriptor",
        "subject",
    )?;
    if let Some(Value::Object(cap_subject)) = established(caps_obj, "subject") {
        let same = ["subject_id", "subject_version", "configured_mode", "interface_surface"]
            .iter()
            .all(|field| {
                established(cap_subject, field).and_then(Value::as_str)
                    == established(desc_subject, field).and_then(Value::as_str)
            });
        if !same {
            return Err(fault(
                "subject_mismatch",
                "descriptor subject and capabilities.subject must be the same exact pin"
                    .to_string(),
            ));
        }
    }

    let scope_map = as_object(scope, "invalid_scope", "scope")?;
    let scope_id = required_str(scope_map, "subject_id", "missing_scope", "scope")?;
    let scope_version = required_str(scope_map, "subject_version", "missing_scope", "scope")?;
    let scope_mode = required_str(scope_map, "configured_mode", "missing_scope", "scope")?;
    let scope_surface = required_str(scope_map, "interface_surface", "missing_scope", "scope")?;

    if let Some(Value::String(digest)) = established(scope_map, "descriptor_digest") {
        if digest.is_empty() {
            return Err(fault(
                "invalid_expected_digest",
                "scope descriptor_digest must be nonempty when present".to_string(),
            ));
        }
        verify_record_digest(descriptor, strip_digest_prefix(digest))?;
    }

    if scope_id != desc_id
        || scope_version != desc_version
        || scope_mode != desc_mode
        || scope_surface != desc_surface
    {
        return Err(fault(
            "scope_mismatch",
            "descriptor applies to exactly one subject/version/mode/surface; another scope does not inherit its findings"
                .to_string(),
        ));
    }

    let mut seen = HashSet::new();
    for entry in catalog.iter() {
        let entry_map = entry.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                "descriptor catalog entries must be objects".to_string(),
            )
        })?;
        let entry_id = match established(entry_map, "capability_id") {
            Some(Value::String(text)) if !text.is_empty() => text.as_str(),
            _ => {
                return Err(fault(
                    "invalid_descriptor",
                    "descriptor catalog entries require an established capability_id".to_string(),
                ))
            }
        };
        if !seen.insert(entry_id.to_string()) {
            return Err(fault(
                "duplicate_capability",
                format!("capability {entry_id:?} appears more than once in the catalog"),
            ));
        }
    }
    for minimum in MINIMUM_CAPABILITY_IDS {
        if !seen.contains(*minimum) {
            return Err(fault(
                "incomplete_catalog",
                format!("descriptor catalog omits required capability {minimum:?}"),
            ));
        }
    }

    let found = catalog.iter().find(|entry| {
        entry
            .as_object()
            .and_then(|map| established(map, "capability_id"))
            .and_then(Value::as_str)
            == Some(capability_id)
    });
    let Some(found) = found else {
        return Err(fault(
            "unknown_capability",
            format!(
                "capability {capability_id:?} is not in this descriptor catalog; omission implies neither presence nor absence"
            ),
        ));
    };
    let found_map = found.as_object().ok_or_else(|| {
        fault(
            "invalid_descriptor",
            "descriptor catalog entries must be objects".to_string(),
        )
    })?;
    let availability = match established(found_map, "availability") {
        Some(Value::String(text)) if AVAILABILITIES.contains(&text.as_str()) => text.clone(),
        _ => {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} requires an established availability"),
            ))
        }
    };
    let requirement_refs = match established(found_map, "requirement_refs") {
        None => Value::Array(Vec::new()),
        Some(Value::Array(items)) => Value::Array(items.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} requirement_refs must be an array"),
            ))
        }
    };
    let claim_origin = match established(found_map, "claim_origin") {
        Some(Value::String(text)) if CLAIM_ORIGINS.contains(&text.as_str()) => {
            Value::String(text.clone())
        }
        _ => {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} requires an established claim_origin"),
            ))
        }
    };
    let evidence_items: Vec<Value> = match established(found_map, "evidence") {
        None => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} evidence must be an array"),
            ))
        }
    };
    for (evidence_index, item) in evidence_items.iter().enumerate() {
        let evidence_entry = item.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} evidence[{evidence_index}] must be an object"),
            )
        })?;
        match established(evidence_entry, "basis") {
            Some(Value::String(text)) if EVIDENCE_BASES.contains(&text.as_str()) => {}
            _ => {
                return Err(fault(
                    "invalid_descriptor",
                    format!(
                        "capability {capability_id:?} evidence[{evidence_index}] basis is not a known basis"
                    ),
                ))
            }
        }
        if !matches!(
            established(evidence_entry, "ref"),
            Some(Value::Object(_))
        ) {
            return Err(fault(
                "invalid_descriptor",
                format!(
                    "capability {capability_id:?} evidence[{evidence_index}] requires an established ref object"
                ),
            ));
        }
    }
    let limitations = match established(found_map, "limitations") {
        None => Value::Array(Vec::new()),
        Some(Value::Array(items)) => Value::Array(items.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} limitations must be an array"),
            ))
        }
    };

    if availability != "unknown" {
        if evidence_items.is_empty() {
            return Err(fault(
                "unverified_claim",
                format!(
                    "capability {capability_id:?} claims {availability:?} without evidence in the exact scope"
                ),
            ));
        }
        let has_versioned = evidence_items.iter().any(|item| {
            item.as_object()
                .and_then(|map| established(map, "subject_version"))
                .is_some()
        });
        if has_versioned {
            let has_current = evidence_items.iter().any(|item| {
                item.as_object()
                    .and_then(|map| established(map, "subject_version"))
                    .and_then(Value::as_str)
                    == Some(desc_version)
            });
            if !has_current {
                return Err(fault(
                    "unverified_claim",
                    format!(
                        "capability {capability_id:?} cites only predecessor-version evidence; version {desc_version:?} starts unknown"
                    ),
                ));
            }
        }
        if is_honesty_id(capability_id) {
            let has_executed = evidence_items.iter().any(|item| {
                let Some(map) = item.as_object() else {
                    return false;
                };
                if map.get("basis").and_then(Value::as_str) != Some("executed_observation") {
                    return false;
                }
                match established(map, "subject_version") {
                    None => true,
                    Some(Value::String(version)) => version == desc_version,
                    Some(_) => false,
                }
            });
            if !has_executed {
                return Err(fault(
                    "unverified_claim",
                    format!(
                        "capability {capability_id:?}: {}; documentation alone does not establish it",
                        honesty_limitation(capability_id)
                    ),
                ));
            }
        }
    }

    let result_value = json!({
        "capability_id": capability_id,
        "availability": availability,
        "requirement_refs": requirement_refs,
        "claim_origin": claim_origin,
        "evidence": evidence_items,
        "limitations": limitations,
        "subject": {
            "subject_id": desc_id,
            "subject_version": desc_version,
            "configured_mode": desc_mode,
            "interface_surface": desc_surface,
        },
        "scope_match": true,
    });
    validate(OUTPUT_SCHEMA, result_value)
}
