//! `crawler_normalization`: exhaustive source-column preservation and
//! crawler-domain publication assembly.
//!
//! Implements seam map §§4.1, 5–15 (field inventories) and §9.1
//! (`JobCrawlerValue` construction) on top of the structural
//! [`crawler_schema`] gate:
//!
//! * [`normalize_row`] converts one source row object into a
//!   `crawler_operational_snapshot` record. Every source column survives
//!   under the same column name in `row` (§1.3). Bare JSON nulls become
//!   typed `Missing` envelopes (`not_observed`); legacy UTC timestamp
//!   strings and partial timestamp objects are normalized through
//!   [`crawler_time::normalize_timestamp`] with the original UTC retained
//!   in field evidence. Integer/string identities are never coerced.
//! * [`assemble_crawler_value`] builds a `JobCrawlerValue` (`acquisition`,
//!   `processing`, `discovery`, `replacement_lineage`) from normalized
//!   snapshots. It never packs whole operational rows into undeclared
//!   properties, never converts legacy product fields, never treats
//!   `semantic_state` as a shared write target, and requires a durable
//!   source-response artifact for `Pass` publications.
//!
//! Pure normalization: no storage writes, no hidden artifact retrieval.

use crawler_hashing::frame_reference;
use crawler_schema::{record_value, validate, CheckedRecord, Fault, SourceEntity};
use crawler_time::{normalize_timestamp, validate_measurement};
use serde_json::{json, Map, Value};

const RECORD_TYPE: &str = "crawler_operational_snapshot";
const SCHEMA_VERSION: &str = "crawler-seam/0.1.0";
const OUTPUT_SCHEMA: &str = "crawler_operational_snapshot";
const ASSEMBLY_SCHEMA: &str = "audit_log";

/// Fields whose normalized type is `M(TP)` (timestamp rule, §3.4).
const TIMESTAMP_FIELDS: &[&str] = &[
    "leased_at",
    "lease_expires_at",
    "created_at",
    "updated_at",
    "first_seen_at",
    "last_seen_at",
    "classified_at",
    "last_applied_at",
    "expires_at",
    "completed_at",
    "rendered_at",
    "last_evaluated_at",
    "bootstrap_started_at",
    "bootstrap_completed_at",
    "handoff_timestamp",
    "verified_session_birth",
    "session_expires_at",
    "replacement_deadline",
    "last_success_at",
    "requested_at",
    "confirmed_at",
    "first_completed_at",
    "last_completed_at",
    "first_failed_at",
    "last_failed_at",
];

/// Fields whose normalized type is `ME` (Contract 00 measurement evidence).
const MEASUREMENT_FIELDS: &[&str] = &[
    "latency_ms",
    "bootstrap_elapsed_ms",
    "acquisition_elapsed_ms",
];

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.get("value").is_some_and(Value::is_null))
}

fn escape_pointer(field: &str) -> String {
    field.replace('~', "~0").replace('/', "~1")
}

/// Recursively normalize an evidence value: bare nulls become
/// `Missing(not_observed)`. Returns the normalized value and whether any
/// conversion occurred. Integers, strings, booleans, and empty arrays are
/// preserved verbatim; `Missing` envelopes pass through untouched.
fn normalize_evalue(value: &Value, field: &str) -> (Value, bool) {
    match value {
        Value::Null => (
            missing(
                "not_observed",
                &format!("source column {field} contained JSON null; normalized per EK-NULL"),
            ),
            true,
        ),
        Value::Bool(_) | Value::String(_) | Value::Number(_) => (value.clone(), false),
        Value::Array(items) => {
            let mut converted = false;
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let (n, c) = normalize_evalue(item, field);
                converted |= c;
                out.push(n);
            }
            (Value::Array(out), converted)
        }
        Value::Object(map) => {
            if is_missing(value) {
                return (value.clone(), false);
            }
            let mut converted = false;
            let mut out = Map::with_capacity(map.len());
            for (k, v) in map {
                let (n, c) = normalize_evalue(v, field);
                converted |= c;
                out.insert(k.clone(), n);
            }
            (Value::Object(out), converted)
        }
    }
}

fn field_evidence(
    field: &str,
    source_value: Value,
    normalization: &str,
    evidence_refs: &Value,
) -> Value {
    json!({
        "pointer": format!("/row/{}", escape_pointer(field)),
        "source_pointer": format!("/{}", escape_pointer(field)),
        "source_value": source_value,
        "normalization": normalization,
        "evidence_refs": evidence_refs.clone(),
    })
}

fn require_evidence_object<'a>(
    evidence: &'a Value,
    key: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    evidence
        .as_object()
        .and_then(|m| m.get(key))
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "missing_evidence",
                format!("evidence must carry {key} for snapshot registration"),
            )
        })
}

/// Build the clock-evidence record consumed by `crawler_time` from the
/// normalization evidence envelope (`clocks` + `receipt`, both optional).
fn clock_evidence(evidence: &Value) -> Result<(CheckedRecord, bool), Fault> {
    let obj = evidence.as_object().ok_or_else(|| {
        fault(
            "invalid_evidence",
            "normalization evidence must be an object".to_string(),
        )
    })?;
    let clocks = obj.get("clocks").cloned().unwrap_or_else(|| json!([]));
    if !clocks.is_array() {
        return Err(fault(
            "invalid_evidence",
            "evidence 'clocks' must be an array of clock descriptors".to_string(),
        ));
    }
    let has_clocks = !clocks.as_array().is_some_and(Vec::is_empty);
    let receipt = obj.get("receipt").cloned().unwrap_or_else(|| {
        missing(
            "not_observed",
            "no import receipt accompanied this normalization evidence",
        )
    });
    let record = validate("audit_log", json!({"clocks": clocks, "receipt": receipt}))?;
    Ok((record, has_clocks))
}

fn is_full_timepoint_shape(obj: &Map<String, Value>) -> bool {
    obj.get("clock_id").and_then(Value::as_str).is_some()
        && obj.get("boot_id").and_then(Value::as_str).is_some()
        && obj.get("origin").and_then(Value::as_str).is_some()
        && obj.get("monotonic_offset_ms").is_some_and(|v| v.is_number())
}

fn normalize_timestamp_field(
    field: &str,
    value: &Value,
    clocks: &CheckedRecord,
    has_clocks: bool,
    evidence_refs: &Value,
) -> Result<(Value, Vec<Value>), Fault> {
    if is_missing(value) {
        return Ok((value.clone(), Vec::new()));
    }
    if value.is_null() {
        let normalized = missing(
            "not_observed",
            &format!("source column {field} was JSON null; normalized per EK-NULL"),
        );
        let ev = field_evidence(field, json!("null"), "missingness", evidence_refs);
        return Ok((normalized, vec![ev]));
    }
    if let Some(text) = value.as_str() {
        let source = validate("audit_log", json!({"utc": text}))?;
        let out = normalize_timestamp(&source, clocks)?;
        let out_value = record_value(&out);
        let normalized = out_value
            .get("timepoint")
            .cloned()
            .ok_or_else(|| fault("internal", "timestamp envelope lacks timepoint".to_string()))?;
        let ev = field_evidence(field, json!(text), "timestamp", evidence_refs);
        return Ok((normalized, vec![ev]));
    }
    if let Some(obj) = value.as_object() {
        let (cleaned, nested) = normalize_evalue(value, field);
        let cleaned_obj = cleaned.as_object().cloned().unwrap_or_else(Map::new);
        // Lenient path: an established TimePoint with no clock registry to
        // verify against is preserved verbatim (identity); verification
        // requires registered clocks and must not invent them.
        if !has_clocks && is_full_timepoint_shape(&cleaned_obj) {
            let mut evidences = Vec::new();
            if nested {
                evidences.push(field_evidence(
                    field,
                    cleaned.clone(),
                    "missingness",
                    evidence_refs,
                ));
            }
            let _ = obj;
            return Ok((cleaned, evidences));
        }
        let source = validate("audit_log", cleaned.clone())?;
        let out = normalize_timestamp(&source, clocks)?;
        let out_value = record_value(&out);
        let normalized = out_value
            .get("timepoint")
            .cloned()
            .ok_or_else(|| fault("internal", "timestamp envelope lacks timepoint".to_string()))?;
        let mut evidences = Vec::new();
        if nested {
            evidences.push(field_evidence(
                field,
                cleaned.clone(),
                "missingness",
                evidence_refs,
            ));
        }
        if normalized != cleaned {
            evidences.push(field_evidence(field, cleaned, "timestamp", evidence_refs));
        }
        return Ok((normalized, evidences));
    }
    Err(fault(
        "invalid_timestamp",
        format!("timestamp column {field} must be a TimePoint, Missing, legacy object, or UTC string"),
    ))
}

fn normalize_measurement_field(
    field: &str,
    value: &Value,
    clocks: &CheckedRecord,
    has_clocks: bool,
    evidence_refs: &Value,
) -> Result<(Value, Vec<Value>), Fault> {
    if is_missing(value) {
        return Ok((value.clone(), Vec::new()));
    }
    if value.is_null() {
        let normalized = missing(
            "not_observed",
            &format!("source column {field} was JSON null; normalized per EK-NULL"),
        );
        let ev = field_evidence(field, json!("null"), "missingness", evidence_refs);
        return Ok((normalized, vec![ev]));
    }
    if value.is_object() {
        let (cleaned, nested) = normalize_evalue(value, field);
        if has_clocks {
            let candidate = validate("audit_log", cleaned.clone())?;
            validate_measurement(&candidate, clocks)?;
        }
        let mut evidences = Vec::new();
        if nested {
            evidences.push(field_evidence(
                field,
                cleaned.clone(),
                "missingness",
                evidence_refs,
            ));
        }
        return Ok((cleaned, evidences));
    }
    Err(fault(
        "invalid_measurement",
        format!("measurement column {field} must be a Measurement object or Missing"),
    ))
}

fn require_id(row: &Map<String, Value>, field: &str) -> Result<String, Fault> {
    match row.get(field) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(Value::String(_)) => Err(fault(
            "missing_identity",
            format!("identity column {field} must be a nonempty string"),
        )),
        Some(Value::Number(_)) => Err(fault(
            "type_mismatch",
            format!("identity column {field} is a string ID; integer source is never coerced"),
        )),
        Some(v) if is_missing(v) => Err(fault(
            "missing_identity",
            format!("identity column {field} is Missing; canonical reference requires establishment"),
        )),
        _ => Err(fault(
            "missing_identity",
            format!("identity column {field} is absent; canonical reference requires it"),
        )),
    }
}

/// Type-discriminated SID component (`i:7` vs `s:7`); integers and strings
/// are never conflated (§3.6).
fn sid_component(value: Option<&Value>, field: &str) -> Result<String, Fault> {
    match value {
        Some(Value::String(s)) if !s.is_empty() => Ok(format!("s:{s}")),
        Some(Value::Number(n)) if n.is_i64() || n.is_u64() => Ok(format!("i:{n}")),
        Some(v) if is_missing(v) => Err(fault(
            "missing_identity",
            format!("identity column {field} is Missing; canonical reference requires establishment"),
        )),
        _ => Err(fault(
            "type_mismatch",
            format!("identity column {field} must be an integer-or-string SID"),
        )),
    }
}

fn input_hash_component(row: &Map<String, Value>) -> Result<String, Fault> {
    match row.get("input_hash") {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        Some(Value::Object(map)) => match map.get("value") {
            Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
            _ => Err(fault(
                "missing_identity",
                "classifier input_hash lacks established digest text".to_string(),
            )),
        },
        Some(v) if is_missing(v) => Err(fault(
            "missing_identity",
            "classifier input_hash is Missing; canonical reference requires establishment".to_string(),
        )),
        _ => Err(fault(
            "missing_identity",
            "classifier input_hash is absent; canonical reference requires it".to_string(),
        )),
    }
}

fn entity_components(entity: SourceEntity, row: &Map<String, Value>) -> Result<Vec<String>, Fault> {
    match entity {
        SourceEntity::Listing | SourceEntity::WorkItem | SourceEntity::JobDetail | SourceEntity::SeenIds => {
            Ok(vec![require_id(row, "target")?, require_id(row, "job_id")?])
        }
        SourceEntity::ClassifierResult => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "job_id")?,
            require_id(row, "stage")?,
            require_id(row, "model_version")?,
            input_hash_component(row)?,
        ]),
        SourceEntity::CoverageLedger => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "run_id")?,
            require_id(row, "partition_id")?,
        ]),
        SourceEntity::CursorState => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "run_id")?,
            require_id(row, "partition_id")?,
            require_id(row, "walk_id")?,
        ]),
        SourceEntity::SessionState => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "run_id")?,
            require_id(row, "phase")?,
            require_id(row, "shard_id")?,
            sid_component(row.get("session_epoch"), "session_epoch")?,
        ]),
        SourceEntity::StateMutationRecord => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "job_id")?,
            require_id(row, "mutation_id")?,
        ]),
        SourceEntity::AuditLog => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "owner_domain")?,
            require_id(row, "event_id")?,
        ]),
        SourceEntity::DeadLetter => Ok(vec![
            require_id(row, "target")?,
            require_id(row, "entity_type")?,
            require_id(row, "entity_id")?,
            require_id(row, "failure_reason")?,
        ]),
    }
}

/// Normalize one source row into a `crawler_operational_snapshot`.
///
/// Every key of `source` (which must be a JSON object) survives in `row`
/// under the same column name, including source-only fields. Bare nulls
/// become `Missing(not_observed)`; timestamp strings/objects normalize via
/// `crawler_time` with source UTC retained in `field_evidence`.
///
/// `evidence` must carry `captured_at` (established `TimePoint`),
/// `evidence_prefix` (`JournalPrefix`), and `evidence_refs` (nonempty
/// `SUPPORT`). It may additionally carry `clocks`/`receipt` (clock
/// registry for timestamp/measurement verification), `source_schema`
/// (`VersionPin`), and `source_record` (`M(AR)`).
pub fn normalize_row(
    entity: SourceEntity,
    source: Value,
    evidence: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let source_obj = source.as_object().ok_or_else(|| {
        fault(
            "invalid_source",
            "normalization source must be an object of source columns".to_string(),
        )
    })?;
    let evidence_value = record_value(evidence);
    let evidence_obj = evidence_value.as_object().ok_or_else(|| {
        fault(
            "invalid_evidence",
            "normalization evidence must be an object".to_string(),
        )
    })?;

    let captured_at = evidence_obj.get("captured_at").ok_or_else(|| {
        fault(
            "missing_evidence",
            "evidence must carry captured_at for snapshot registration".to_string(),
        )
    })?;
    if is_missing(captured_at) || !captured_at.is_object() {
        return Err(fault(
            "missing_evidence",
            "snapshot captured_at must be an established TimePoint".to_string(),
        ));
    }
    let prefix = require_evidence_object(evidence_value, "evidence_prefix")?.clone();
    let evidence_refs = evidence_obj.get("evidence_refs").ok_or_else(|| {
        fault(
            "missing_evidence",
            "evidence must carry evidence_refs for snapshot registration".to_string(),
        )
    })?;
    if !evidence_refs
        .as_array()
        .is_some_and(|refs| !refs.is_empty())
    {
        return Err(fault(
            "missing_evidence",
            "snapshot evidence_refs must be nonempty SUPPORT".to_string(),
        ));
    }

    let (clocks, has_clocks) = clock_evidence(evidence_value)?;

    let mut row = Map::with_capacity(source_obj.len());
    let mut evidences_out: Vec<Value> = Vec::new();
    for (field, value) in source_obj {
        if TIMESTAMP_FIELDS.contains(&field.as_str()) {
            let (normalized, mut evidences) =
                normalize_timestamp_field(field, value, &clocks, has_clocks, evidence_refs)?;
            row.insert(field.clone(), normalized);
            evidences_out.append(&mut evidences);
        } else if MEASUREMENT_FIELDS.contains(&field.as_str()) {
            let (normalized, mut evidences) =
                normalize_measurement_field(field, value, &clocks, has_clocks, evidence_refs)?;
            row.insert(field.clone(), normalized);
            evidences_out.append(&mut evidences);
        } else {
            if value.is_null() {
                let normalized = missing(
                    "not_observed",
                    &format!("source column {field} was JSON null; normalized per EK-NULL"),
                );
                evidences_out.push(field_evidence(field, json!("null"), "missingness", evidence_refs));
                row.insert(field.clone(), normalized);
            } else {
                let (normalized, converted) = normalize_evalue(value, field);
                if converted {
                    evidences_out.push(field_evidence(
                        field,
                        normalized.clone(),
                        "missingness",
                        evidence_refs,
                    ));
                }
                row.insert(field.clone(), normalized);
            }
        }
    }

    let components = entity_components(entity, &row)?;
    let entity_id = frame_reference(entity.schema_id(), &components.iter().map(|s| s.clone()).collect::<Vec<_>>())?;

    let source_schema = evidence_obj
        .get("source_schema")
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "id": entity.schema_id(),
                "version": SCHEMA_VERSION,
                "artifact_digest": format!("sha256:{}", "0".repeat(64)),
            })
        });
    let source_record = evidence_obj.get("source_record").cloned().unwrap_or_else(|| {
        missing(
            "not_observed",
            "no source artifact supplied in normalization evidence",
        )
    });

    let snapshot = json!({
        "record_type": RECORD_TYPE,
        "schema_version": SCHEMA_VERSION,
        "entity_type": entity.schema_id(),
        "entity_id": entity_id,
        "source_schema": source_schema,
        "row": Value::Object(row),
        "source_record": source_record,
        "field_evidence": Value::Array(evidences_out),
        "captured_at": captured_at.clone(),
        "evidence_prefix": Value::Object(prefix),
        "evidence_refs": evidence_refs.clone(),
    });
    validate(OUTPUT_SCHEMA, snapshot)
}

// ---------------------------------------------------------------------------
// JobCrawlerValue assembly (§9.1)
// ---------------------------------------------------------------------------

fn snapshot_row<'a>(snapshot: &'a CheckedRecord, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    record_value(snapshot)
        .as_object()
        .and_then(|o| o.get("row"))
        .and_then(Value::as_object)
        .ok_or_else(|| fault("invalid_snapshot", format!("{what} snapshot lacks a normalized row object")))
}

fn find_snapshot<'a>(snapshots: &'a [CheckedRecord], entity_type: &str) -> Option<&'a CheckedRecord> {
    snapshots.iter().find(|s| {
        record_value(s)
            .as_object()
            .and_then(|o| o.get("entity_type"))
            .and_then(Value::as_str)
            .is_some_and(|t| t == entity_type)
    })
}

fn established_str<'a>(row: &'a Map<String, Value>, field: &str) -> Result<&'a str, Fault> {
    match row.get(field) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.as_str()),
        _ => Err(fault(
            "incomplete_extraction",
            format!("required acquisition column {field} is not established"),
        )),
    }
}

fn content_slot(row: &Map<String, Value>, field: &str) -> Value {
    row.get(field).cloned().unwrap_or_else(|| {
        missing(
            "not_observed",
            &format!("content column {field} had no source value"),
        )
    })
}

fn extended_slot(extra: Option<&Map<String, Value>>, field: &str) -> Value {
    extra
        .and_then(|m| m.get(field))
        .cloned()
        .unwrap_or_else(|| {
            missing(
                "not_observed",
                &format!("optional content column {field} was not established"),
            )
        })
}

fn is_established(value: &Value) -> bool {
    !is_missing(value)
}

/// Assemble a `JobCrawlerValue` from normalized operational snapshots.
///
/// `snapshots` must include the `job_detail` snapshot; a `listing` snapshot
/// supplies discovery, and `classifier_result` snapshots supply genuine
/// results. `evidence` must carry `evidence_prefix`, `evidence_refs`, and
/// `coverage_refs` (nonempty), and may carry `source_response` (durable
/// response artifact), `replacement_link`, `generation_id`, and
/// `declarations`.
///
/// Enforces §9.2 render cases and §9.4 retention: a `Pass` verdict requires
/// every required content field established and a durable source-response
/// artifact; a non-`Pass` verdict requires `render_failed` with all content
/// Missing and no current classifier results.
pub fn assemble_crawler_value(
    snapshots: &[CheckedRecord],
    evidence: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let evidence_value = record_value(evidence);
    let evidence_obj = evidence_value.as_object().ok_or_else(|| {
        fault(
            "invalid_evidence",
            "assembly evidence must be an object".to_string(),
        )
    })?;
    let prefix = require_evidence_object(evidence_value, "evidence_prefix")?.clone();
    let evidence_refs = evidence_obj.get("evidence_refs").ok_or_else(|| {
        fault(
            "missing_evidence",
            "assembly evidence must carry evidence_refs".to_string(),
        )
    })?;
    if !evidence_refs
        .as_array()
        .is_some_and(|refs| !refs.is_empty())
    {
        return Err(fault(
            "missing_evidence",
            "assembly evidence_refs must be nonempty SUPPORT".to_string(),
        ));
    }
    let coverage_refs = evidence_obj.get("coverage_refs").ok_or_else(|| {
        fault(
            "missing_coverage",
            "discovery requires a nonempty exact coverage-reference array".to_string(),
        )
    })?;
    if !coverage_refs.as_array().is_some_and(|r| !r.is_empty()) {
        return Err(fault(
            "missing_coverage",
            "discovery requires a nonempty exact coverage-reference array".to_string(),
        ));
    }

    let detail = find_snapshot(snapshots, "job_detail").ok_or_else(|| {
        fault(
            "missing_detail",
            "assembly requires the job_detail operational snapshot".to_string(),
        )
    })?;
    let row = snapshot_row(detail, "job_detail")?.clone();

    let listing_row = find_snapshot(snapshots, "listing")
        .and_then(|s| snapshot_row(s, "listing").ok())
        .cloned();

    // --- Render-case inputs (OWD-RENDER) ---
    let render_verdict = established_str(&row, "render_verdict")?.to_string();
    let pipeline_state = established_str(&row, "pipeline_state")?.to_string();
    let is_pass = render_verdict == "Pass";

    // --- Content object (ten core slots; never invent direct-apply URLs) ---
    let extra = row
        .get("content_fields_json")
        .and_then(Value::as_object);
    let title = content_slot(&row, "title");
    let employer = content_slot(&row, "employer");
    let snippet = content_slot(&row, "snippet");
    let description = content_slot(&row, "description");
    let posted_date = content_slot(&row, "posted_date");
    let location = extended_slot(extra, "location");
    let direct_apply_url = extended_slot(extra, "direct_apply_url");
    let portal_type = extended_slot(extra, "portal_type");
    let closing_date = extended_slot(extra, "closing_date");
    let extended = extra
        .and_then(|m| m.get("extended"))
        .cloned()
        .unwrap_or_else(|| json!([]));
    let content = json!({
        "title": title.clone(),
        "employer": employer.clone(),
        "snippet": snippet.clone(),
        "description": description.clone(),
        "posted_date": posted_date.clone(),
        "location": location.clone(),
        "direct_apply_url": direct_apply_url.clone(),
        "portal_type": portal_type.clone(),
        "closing_date": closing_date.clone(),
        "extended": extended.clone(),
    });

    let declarations = evidence_obj
        .get("declarations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    if is_pass {
        if pipeline_state == "render_failed" {
            return Err(fault(
                "incomplete_extraction",
                "Pass with render_failed pipeline state is not a valid successful write".to_string(),
            ));
        }
        if !matches!(
            pipeline_state.as_str(),
            "pending_classification" | "ready" | "vetoed" | "failed"
        ) {
            return Err(fault(
                "incomplete_extraction",
                format!("Pass with unexpected detail state {pipeline_state:?}"),
            ));
        }
        // Required content: declared required fields, else core title.
        if declarations.is_empty() {
            if !is_established(&title) {
                return Err(fault(
                    "incomplete_extraction",
                    "Pass requires established title content".to_string(),
                ));
            }
        } else {
            for decl in &declarations {
                let name = decl.get("name").and_then(Value::as_str).unwrap_or("");
                let required = decl.get("required").and_then(Value::as_bool).unwrap_or(false);
                if required {
                    let slot = content.get(name).unwrap_or(&title);
                    let established = match slot {
                        Value::Array(items) => !items.is_empty() || is_established(slot),
                        _ => is_established(slot),
                    };
                    if name.is_empty() || !established {
                        return Err(fault(
                            "incomplete_extraction",
                            format!("Pass requires established content for declared field {name:?}"),
                        ));
                    }
                }
            }
        }
        // Durable source-response artifact (digest alone insufficient, §9.4).
        let from_evidence = evidence_obj.get("source_response").filter(|v| is_established(v));
        let from_snapshot = record_value(detail)
            .as_object()
            .and_then(|o| o.get("source_record"))
            .filter(|v| is_established(v));
        if from_evidence.is_none() && from_snapshot.is_none() {
            return Err(fault(
                "missing_artifact",
                "Pass publication requires a durable source-response artifact".to_string(),
            ));
        }
    } else {
        // Case B: non-Pass requires render_failed (or a later operational
        // failure), all content Missing, and no current classifier results.
        if !matches!(pipeline_state.as_str(), "render_failed" | "failed") {
            return Err(fault(
                "invalid_render_case",
                format!("non-Pass verdict {render_verdict:?} requires pipeline_state render_failed"),
            ));
        }
        for (name, slot) in [
            ("title", &title),
            ("employer", &employer),
            ("snippet", &snippet),
            ("description", &description),
            ("posted_date", &posted_date),
            ("location", &location),
            ("direct_apply_url", &direct_apply_url),
            ("portal_type", &portal_type),
            ("closing_date", &closing_date),
        ] {
            if is_established(slot) {
                return Err(fault(
                    "invalid_render_case",
                    format!("non-Pass Case B requires Missing content for {name}"),
                ));
            }
        }
        if extended.as_array().is_some_and(|e| !e.is_empty()) {
            return Err(fault(
                "invalid_render_case",
                "non-Pass Case B requires empty extended content".to_string(),
            ));
        }
        for field in [
            "snippet_classifier_result_ref",
            "description_classifier_result_ref",
            "final_genuine_result_ref",
        ] {
            if row.get(field).is_some_and(is_established) {
                return Err(fault(
                    "invalid_render_case",
                    format!("non-Pass Case B carries no current classifier result ({field})"),
                ));
            }
        }
    }

    // --- Acquisition (mapped fields only; never whole rows) ---
    let source_url = established_str(&row, "source_url")?.to_string();
    let listing_page_url = listing_row
        .as_ref()
        .and_then(|l| l.get("listing_page_url"))
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied acquisition listing URL"));
    let source_response = evidence_obj
        .get("source_response")
        .cloned()
        .or_else(|| {
            record_value(detail)
                .as_object()
                .and_then(|o| o.get("source_record"))
                .cloned()
        })
        .unwrap_or_else(|| missing("not_observed", "no durable source-response artifact evidenced"));
    let acquisition = json!({
        "source_url": source_url,
        "listing_page_url": listing_page_url,
        "fetch_key": row.get("fetch_key").cloned().unwrap_or_else(|| missing("not_observed", "fetch_key had no source value")),
        "fetch_identity": {
            "phase_token": row.get("fetch_phase_token").cloned().unwrap_or_else(|| missing("not_observed", "fetch phase token had no source value")),
            "request_params": row.get("request_params_json").cloned().unwrap_or_else(|| missing("not_observed", "request params had no source value")),
        },
        "source_response": source_response,
        "source_response_hash": row.get("source_response_hash").cloned().unwrap_or_else(|| missing("not_observed", "response hash had no source value")),
        "extractor": row.get("extractor_version").cloned().unwrap_or_else(|| missing("not_observed", "extractor pin had no source value")),
        "declarations": Value::Array(declarations),
        "content": content,
        "render_verdict": render_verdict,
        "render_basis": row.get("render_basis").cloned().unwrap_or_else(|| missing("not_observed", "render basis had no source value")),
        "render_history": row.get("render_history").cloned().unwrap_or_else(|| json!([])),
        "rendered_at": row.get("rendered_at").cloned().unwrap_or_else(|| missing("not_observed", "render time had no source value")),
        "evidence_refs": evidence_refs.clone(),
    });

    // --- Processing (operational; semantic_state stays source evidence) ---
    let mut genuine_results = Vec::new();
    for snapshot in snapshots {
        let value = record_value(snapshot);
        let is_classifier = value
            .as_object()
            .and_then(|o| o.get("entity_type"))
            .and_then(Value::as_str)
            .is_some_and(|t| t == "classifier_result");
        if !is_classifier {
            continue;
        }
        let crow = match snapshot_row(snapshot, "classifier_result") {
            Ok(r) => r,
            Err(_) => continue,
        };
        let entity_ref = value
            .as_object()
            .and_then(|o| o.get("entity_id"))
            .cloned()
            .unwrap_or_else(|| missing("not_observed", "classifier snapshot lacked entity_id"));
        genuine_results.push(json!({
            "ref": entity_ref,
            "stage": crow.get("stage").cloned().unwrap_or_else(|| missing("not_observed", "classifier stage missing")),
            "verdict": crow.get("verdict").cloned().unwrap_or_else(|| missing("not_observed", "classifier verdict missing")),
            "model_version": crow.get("model_version").cloned().unwrap_or_else(|| missing("not_observed", "classifier model version missing")),
        }));
    }
    let surface = listing_row
        .as_ref()
        .and_then(|l| l.get("classification_surface"))
        .cloned()
        .unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied classification surface"));
    let lease = match row.get("lease_id") {
        Some(v) if is_established(v) => json!({
            "lease_id": v.clone(),
            "lease_owner": row.get("lease_owner").cloned().unwrap_or_else(|| missing("not_observed", "lease owner missing")),
            "leased_at": row.get("leased_at").cloned().unwrap_or_else(|| missing("not_observed", "lease issue time missing")),
            "lease_expires_at": row.get("lease_expires_at").cloned().unwrap_or_else(|| missing("not_observed", "lease expiry missing")),
        }),
        _ => missing("not_applicable", "detail is unleased"),
    };
    let processing = json!({
        "pipeline_state": pipeline_state,
        "surface": surface,
        "active_run_id": row.get("active_run_id").cloned().unwrap_or_else(|| missing("not_observed", "active run had no source value")),
        "input_revision": row.get("input_revision").cloned().unwrap_or_else(|| missing("not_observed", "input revision had no source value")),
        "generation_id": evidence_obj.get("generation_id").cloned().unwrap_or_else(|| missing("not_observed", "no journaled generation ID evidenced")),
        "lease": lease,
        "retry_count": row.get("retry_count").cloned().unwrap_or_else(|| missing("not_observed", "retry count had no source value")),
        "failure": row.get("last_failure_reason").cloned().unwrap_or_else(|| missing("not_applicable", "no failure recorded")),
        "genuine_results": Value::Array(genuine_results),
        "final_genuine_result_id": row.get("final_genuine_result_ref").cloned().unwrap_or_else(|| missing("not_applicable", "no final genuine result")),
        "bypass": row.get("bypass_reason").cloned().unwrap_or_else(|| missing("not_applicable", "no bypass recorded")),
        "semantic_candidate": row.get("semantic_candidate").cloned().unwrap_or_else(|| missing("not_observed", "semantic candidate had no source value")),
        "semantic_evidence": row.get("semantic_evidence_json").cloned().unwrap_or_else(|| missing("not_observed", "semantic evidence had no source value")),
        "evidence_refs": evidence_refs.clone(),
    });

    // --- Discovery (listing evidence + exact coverage references) ---
    let discovery = json!({
        "first_seen_run_id": listing_row.as_ref().and_then(|l| l.get("first_seen_run_id")).cloned().unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied first-seen run")),
        "first_seen_at": listing_row.as_ref().and_then(|l| l.get("first_seen_at")).cloned().unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied first-seen time")),
        "last_seen_run_id": listing_row.as_ref().and_then(|l| l.get("last_seen_run_id")).cloned().unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied last-seen run")),
        "last_seen_at": listing_row.as_ref().and_then(|l| l.get("last_seen_at")).cloned().unwrap_or_else(|| missing("not_observed", "no listing snapshot supplied last-seen time")),
        "coverage_refs": coverage_refs.clone(),
        "evidence_refs": evidence_refs.clone(),
    });

    // --- Replacement lineage (latest committed link or Inapplicable) ---
    let replacement_lineage = evidence_obj.get("replacement_link").cloned().unwrap_or_else(|| {
        json!({"status": "Inapplicable", "detail": "no replacement committed"})
    });

    let value = json!({
        "record_type": "JobCrawlerValue",
        "schema_version": SCHEMA_VERSION,
        "acquisition": acquisition,
        "processing": processing,
        "discovery": discovery,
        "replacement_lineage": replacement_lineage,
        "evidence_prefix": Value::Object(prefix),
        "evidence_refs": evidence_refs.clone(),
    });
    validate(ASSEMBLY_SCHEMA, value)
}
