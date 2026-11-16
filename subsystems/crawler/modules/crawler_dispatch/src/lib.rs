//! `crawler_dispatch`: owner-local Start dispatch with command idempotency.
//!
//! Implements the Start half of Contract 02 §19.3–19.4, §19.7 and the
//! EXT-START / EXT-IDEMPOTENCY / EXT-RESUME / EXT-PREPARATION-PIN /
//! EXT-BOUNDS / EK-ATOMICITY invariants:
//!
//! * **[EXT-START]** Before wire delivery, durably commit the local handle,
//!   immutable request binding, idempotency association, and dispatch intent
//!   under owner-local fencing. [`start`] returns a local receipt without
//!   awaiting task completion. A native run ID is attached only in later
//!   source-backed observations (here it is always `Missing(not_observed)`).
//! * **[EXT-IDEMPOTENCY]** `(authenticated principal, connector_id,
//!   request_id)` identifies one command. The same command with identical
//!   content returns its retained receipt without another effect;
//!   conflicting content under that key is rejected with
//!   `integrity_conflict`. Logical execution deduplication independently
//!   uses `(principal, connector_id, idempotency_key)` bound to the
//!   immutable preparation: the same logical key with different
//!   preparation bytes is also `integrity_conflict`.
//! * **[EXT-RESUME]** Resume requires a new command identity, the existing
//!   logical idempotency key/handle, explicit recovery authority, and an
//!   evidenced native checkpoint or idempotency contract for the same
//!   request and context. [`authorize_resume`] journals the authorization;
//!   [`start`] with that authorization preserves the same logical handle
//!   while journaling an additional delivery.
//! * **[EXT-PREPARATION-PIN]** The preparation is revalidated on every
//!   Start via [`crawler_prepare::verify_preparation`]: exact descriptor /
//!   subject / mapping / task pinning, hash integrity, budget completeness,
//!   concern-ID uniqueness, and acceptance coverage for every
//!   `requires_acceptance` concern under actual task authority (a `Start`
//!   grant for the same connector).
//! * **[EXT-BOUNDS]** Every fresh dispatch reserves bounded queue / staging
//!   / observation capacity via [`Admission::reserve_response`] before any
//!   durable effect, and records a finite call deadline from the registered
//!   [`ClockAuthority`]. Admission rejection propagates without a store
//!   write; rejected work is recorded by admission, never silently lost.
//!   The reservation is held (not released) so an accepted queued task
//!   consumes its active observation budget.
//! * **[EK-ATOMICITY]** One owner-local [`OwnerStore::transact`] commits the
//!   admitted input, idempotency record, handle, dispatch intent, and
//!   replayable receipt as a single durable effect before acknowledgement.
//!   No peer lock is acquired and no cross-owner transaction is attempted.
//!
//! # Start request shape
//!
//! `request` is an `"audit_log"`-wrapped object:
//!
//! ```text
//! {
//!   "connector_id": "<must equal the Start grant connector>",
//!   "request_id": "<command identity, nonempty>",
//!   "idempotency_key": "<logical execution key, nonempty>",
//!   "preparation": {<connector_preparation>},
//!   "configuration": {<exact pinned configuration>},
//!   "authorization": {"accepted_concerns": [...], "authorization_refs": [...]},
//!   "recovery": Missing(not_applicable) | {<resume_authorization from authorize_resume>}
//! }
//! ```
//!
//! `recovery` must be present: fresh starts carry
//! `Missing(not_applicable)`; resumed starts carry the established
//! authorization produced by [`authorize_resume`].
//!
//! # Receipt shape
//!
//! The returned `"audit_log"` record carries `record_type:
//! "dispatch_receipt"`, the `ConnectorHandle` (`record_type:
//! "connector_handle"`, handle reference, preparation reference, scope,
//! idempotency key, real creation `TimePoint`, and `Missing(not_observed)`
//! native run ID), the command triple, the admission reservation, the
//! owner-store receipt, and the dispatch intent. Duplicate deliveries
//! return the retained receipt byte-for-byte.
//!
//! # Resume authorization shape
//!
//! [`authorize_resume`] takes:
//!
//! ```text
//! {
//!   "connector_id": "<must equal the grant connector>",
//!   "request_id": "<NEW command identity, never previously committed>",
//!   "idempotency_key": "<EXISTING logical key>",
//!   "handle_ref": "<EXISTING handle reference>",
//!   "recovery_authority": [<nonempty explicit authority refs>],
//!   "checkpoint": {
//!     "idempotency_key": "<same logical key>",
//!     "handle_ref": "<same handle>",
//!     "native_checkpoint" | "idempotency_contract": {<evidenced contract>},
//!     "evidence_refs": [<nonempty>]
//!   }
//! }
//! ```
//!
//! Lease expiry alone, a changed context, or a draining/closed observation
//! never satisfies this contract.

use crawler_admission::Admission;
use crawler_authority::{grant_record, Grant};
use crawler_prepare::verify_preparation;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// External-connector record version stamped on handles and receipts.
const SCHEMA_VERSION: &str = "external-connector/0.1.0";

/// Owner-store operation for one fresh dispatch commit.
const TRANSACTION_OPERATION: &str = "dispatch_start";
/// Owner-store operation for one resumed additional delivery.
const RESUME_DELIVERY_OPERATION: &str = "dispatch_resume_delivery";
/// Owner-store operation for one resume authorization.
const RESUME_AUTHORIZATION_OPERATION: &str = "dispatch_resume_authorization";

/// Minimal bounded reservation for one dispatch (rows, bytes, observation).
const DISPATCH_ROWS: u64 = 1;
const DISPATCH_BYTES: u64 = 4096;
const DISPATCH_OBSERVATION_BYTES: u64 = 4096;

// ---------------------------------------------------------------------------
// Helpers
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

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
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

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record)
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be an object")))
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, field).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Ok(text),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty {field:?}"),
        )),
    }
}

fn check_timepoint(value: &Value) -> Result<(), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(
            "invalid_clock",
            "clock authority must report a TimePoint object",
        )
    })?;
    for field in [
        "clock_id",
        "boot_id",
        "origin",
        "monotonic_offset_ms",
        "utc_annotation",
    ] {
        if !map.contains_key(field) {
            return Err(fault(
                "invalid_clock",
                format!("clock authority TimePoint is missing {field:?}"),
            ));
        }
    }
    match map.get("monotonic_offset_ms").and_then(Value::as_f64) {
        Some(offset) if offset.is_finite() => Ok(()),
        _ => Err(fault(
            "invalid_clock",
            "clock authority TimePoint has no finite monotonic_offset_ms",
        )),
    }
}

// ---------------------------------------------------------------------------
// Durable-identity registry (owner-local, process-held)
// ---------------------------------------------------------------------------

/// Retained receipt for one command key.
struct CommandEntry {
    request: Value,
    receipt: Value,
}

/// Retained receipt for one logical execution key.
struct LogicalEntry {
    preparation: Value,
    receipt: Value,
}

#[derive(Default)]
struct Registry {
    commands: HashMap<String, CommandEntry>,
    logical: HashMap<String, LogicalEntry>,
}

static REGISTRY: LazyLock<Mutex<Registry>> =
    LazyLock::new(|| Mutex::new(Registry::default()));

fn registry() -> &'static Mutex<Registry> {
    &REGISTRY
}

fn lock_registry() -> Result<std::sync::MutexGuard<'static, Registry>, Fault> {
    registry().lock().map_err(|_| {
        fault(
            "internal_error",
            "dispatch registry lock poisoned by an earlier panic",
        )
    })
}

fn command_key(principal: &str, connector: &str, request_id: &str) -> String {
    format!("{principal}|{connector}|{request_id}")
}

fn logical_key(principal: &str, connector: &str, idempotency_key: &str) -> String {
    format!("{principal}|{connector}|{idempotency_key}")
}

// ---------------------------------------------------------------------------
// Grant + request parsing
// ---------------------------------------------------------------------------

struct GrantFacts {
    principal_id: String,
    connector: String,
    verb: String,
}

fn grant_facts(grant: &Grant) -> Result<GrantFacts, Fault> {
    let map = as_object(grant_record(grant), "forbidden", "grant")?;
    let principal_id = required_str(map, "principal_id", "forbidden", "grant")?.to_string();
    let connector = required_str(map, "connector", "forbidden", "grant")?.to_string();
    let verb = required_str(map, "verb", "forbidden", "grant")?.to_string();
    Ok(GrantFacts {
        principal_id,
        connector,
        verb,
    })
}

enum Recovery {
    Fresh,
    Resumed(Value),
}

struct StartRequest {
    connector_id: String,
    request_id: String,
    idempotency_key: String,
    preparation: Value,
    configuration: Value,
    authorization: Value,
    recovery: Recovery,
    recovery_value: Value,
}

fn parse_start(request: &CheckedRecord) -> Result<StartRequest, Fault> {
    let map = as_object(request, "invalid_request", "request")?;
    let connector_id =
        required_str(map, "connector_id", "invalid_request", "request")?.to_string();
    let request_id =
        required_str(map, "request_id", "invalid_request", "request")?.to_string();
    let idempotency_key =
        required_str(map, "idempotency_key", "invalid_request", "request")?.to_string();
    let preparation = match established(map, "preparation") {
        Some(Value::Object(_)) => map.get("preparation").cloned().unwrap_or(Value::Null),
        _ => {
            return Err(fault(
                "invalid_request",
                "request requires an established preparation object",
            ))
        }
    };
    let configuration = match established(map, "configuration") {
        Some(Value::Object(_)) => map.get("configuration").cloned().unwrap_or(Value::Null),
        _ => {
            return Err(fault(
                "invalid_request",
                "request requires an established configuration object",
            ))
        }
    };
    let authorization = match established(map, "authorization") {
        Some(Value::Object(_)) => map.get("authorization").cloned().unwrap_or(Value::Null),
        _ => {
            return Err(fault(
                "invalid_request",
                "request requires an established authorization object",
            ))
        }
    };
    let recovery_value = map.get("recovery").cloned().ok_or_else(|| {
        fault(
            "invalid_request",
            "request requires an explicit recovery field: Missing(not_applicable) for a fresh Start or an established resume authorization",
        )
    })?;
    let recovery = if is_missing(&recovery_value) {
        match missing_reason(&recovery_value) {
            Some("not_applicable") => Recovery::Fresh,
            Some(reason) => {
                return Err(fault(
                    "invalid_request",
                    format!("fresh Start recovery must be Missing(not_applicable); found Missing({reason:?})"),
                ))
            }
            None => {
                return Err(fault(
                    "invalid_request",
                    "fresh Start recovery must be Missing(not_applicable)",
                ))
            }
        }
    } else if recovery_value.is_object() {
        Recovery::Resumed(recovery_value.clone())
    } else {
        return Err(fault(
            "invalid_request",
            "request recovery must be Missing(not_applicable) or an established resume authorization object",
        ));
    };
    Ok(StartRequest {
        connector_id,
        request_id,
        idempotency_key,
        preparation,
        configuration,
        authorization,
        recovery,
        recovery_value,
    })
}

/// Validate the established resume authorization carried in a resumed Start.
fn check_resume_authorization(
    auth: &Value,
    idempotency_key: &str,
    handle_ref: &str,
) -> Result<(), Fault> {
    let map = auth.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            "resume authorization must be an object produced by authorize_resume",
        )
    })?;
    match established(map, "authorized").and_then(Value::as_bool) {
        Some(true) => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume authorization is not authorized; Start accepts only an authorized same-handle resume",
            ))
        }
    }
    let auth_key = required_str(
        map,
        "idempotency_key",
        "invalid_request",
        "resume authorization",
    )?;
    if auth_key != idempotency_key {
        return Err(fault(
            "integrity_conflict",
            "resume authorization idempotency_key does not match the Start request",
        ));
    }
    let auth_handle = required_str(map, "handle_ref", "invalid_request", "resume authorization")?;
    if auth_handle != handle_ref {
        return Err(fault(
            "integrity_conflict",
            "resume authorization handle does not match the existing logical dispatch",
        ));
    }
    match established(map, "recovery_authority") {
        Some(Value::Array(refs)) if !refs.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume authorization requires a nonempty recovery_authority",
            ))
        }
    }
    match established(map, "checkpoint") {
        Some(Value::Object(_)) => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume authorization requires an established checkpoint",
            ))
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// Start one prepared task: durably commit the handle, immutable request
/// binding, idempotency association, and dispatch intent, then return the
/// local receipt without awaiting task completion.
///
/// Idempotency: the same `(principal, connector, request_id)` with
/// identical content returns the retained receipt without another
/// admission reservation or store effect; conflicting content under that
/// key — or the same logical `idempotency_key` with different preparation
/// bytes — is rejected with `integrity_conflict`.
pub fn start(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    admission: &dyn Admission,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let facts = grant_facts(grant)?;
    if facts.verb != "Start" {
        return Err(fault(
            "forbidden",
            format!(
                "Start requires a Start grant; grant carries verb {:?}",
                facts.verb
            ),
        ));
    }
    let parsed = parse_start(request)?;
    if parsed.connector_id != facts.connector {
        return Err(fault(
            "forbidden",
            format!(
                "request connector {:?} does not match the Start grant connector {:?}",
                parsed.connector_id, facts.connector
            ),
        ));
    }

    // Immutable preparation pin: exact descriptor/subject/mapping/task,
    // hash integrity, budget completeness, and acceptance coverage for
    // every requires_acceptance concern under actual task authority.
    let preparation_record = validate(OUTPUT_SCHEMA, parsed.preparation.clone())?;
    let configuration_record = validate(OUTPUT_SCHEMA, parsed.configuration.clone())?;
    let authorization_record = validate(OUTPUT_SCHEMA, parsed.authorization.clone())?;
    verify_preparation(
        &preparation_record,
        &configuration_record,
        &authorization_record,
    )?;

    // The pinned configuration must name the same connector as the command.
    let configuration_map = preparation_record_value_config(&parsed.configuration)?;
    if let Some(connector) = configuration_map
        .get("connector_id")
        .and_then(Value::as_str)
    {
        if connector != parsed.connector_id {
            return Err(fault(
                "stale_configuration",
                format!(
                    "configuration connector_id {connector:?} does not match the Start connector {:?}",
                    parsed.connector_id
                ),
            ));
        }
    }
    // Preparation reference + scope for the handle.
    let preparation_map = parsed
        .preparation
        .as_object()
        .ok_or_else(|| fault("invalid_request", "preparation must be an object"))?;
    let preparation_id =
        required_str(preparation_map, "preparation_id", "invalid_request", "preparation")?
            .to_string();
    let scope = preparation_map
        .get("scope")
        .cloned()
        .ok_or_else(|| fault("invalid_request", "preparation carries no scope"))?;

    let cmd_key = command_key(&facts.principal_id, &parsed.connector_id, &parsed.request_id);
    let log_key = logical_key(
        &facts.principal_id,
        &parsed.connector_id,
        &parsed.idempotency_key,
    );
    // Deterministic logical handle: the same logical execution preserves
    // the same handle across command retries and resumed deliveries.
    let handle_ref = format!(
        "handle:{}:{}:{}",
        facts.principal_id, parsed.connector_id, parsed.idempotency_key
    );
    let request_value = record_value(request).clone();

    // Owner-local fencing: hold the registry across the idempotency
    // decision and the single durable commit so concurrent duplicates
    // cannot both commit.
    let mut registry = lock_registry()?;

    // --- Command deduplication: identical returns retained, conflict rejects.
    if let Some(entry) = registry.commands.get(&cmd_key) {
        if entry.request == request_value {
            let retained = entry.receipt.clone();
            drop(registry);
            return validate(OUTPUT_SCHEMA, retained);
        }
        return Err(fault(
            "integrity_conflict",
            format!(
                "command ({:?}, {:?}, {:?}) already carries different content; conflicting content under one command key is rejected without another effect",
                facts.principal_id, parsed.connector_id, parsed.request_id
            ),
        ));
    }

    // --- Logical deduplication.
    if let Some(entry) = registry.logical.get(&log_key) {
        match &parsed.recovery {
            Recovery::Fresh => {
                if entry.preparation == parsed.preparation {
                    // Same logical execution, same immutable preparation:
                    // idempotent without another effect.
                    let retained = entry.receipt.clone();
                    registry.commands.insert(
                        cmd_key,
                        CommandEntry {
                            request: request_value,
                            receipt: retained.clone(),
                        },
                    );
                    drop(registry);
                    return validate(OUTPUT_SCHEMA, retained);
                }
                return Err(fault(
                    "integrity_conflict",
                    "idempotency_key is already bound to different preparation bytes; conflicting content under one logical key is rejected",
                ));
            }
            Recovery::Resumed(auth) => {
                // Resumed additional delivery: same logical handle, new
                // durable delivery. Validate the authorization below, then
                // fall through to the commit path with disposition resumed.
                check_resume_authorization(auth, &parsed.idempotency_key, &handle_ref)?;
                if entry.preparation != parsed.preparation {
                    return Err(fault(
                        "integrity_conflict",
                        "resumed Start preparation does not match the existing logical dispatch",
                    ));
                }
            }
        }
    } else {
        // Unknown logical execution with an established recovery is a
        // resume for an unknown handle, never a fresh dispatch.
        if let Recovery::Resumed(_) = &parsed.recovery {
            return Err(fault(
                "unknown_handle",
                "resume authorization names an unknown logical dispatch; Start cannot resume a handle it never committed",
            ));
        }
    }

    let resumed = matches!(parsed.recovery, Recovery::Resumed(_));

    // --- Bounded admission before any durable effect.
    let reservation_request = validate(
        OUTPUT_SCHEMA,
        json!({
            "request_id": parsed.request_id,
            "target": parsed.connector_id,
            "max_packet_rows": DISPATCH_ROWS,
            "max_packet_bytes": DISPATCH_BYTES,
            "observation_bytes": DISPATCH_OBSERVATION_BYTES,
        }),
    )?;
    let credit = admission.reserve_response(&reservation_request)?;
    let reservation_value = record_value(&credit.reservation).clone();

    // --- Real creation TimePoint from the registered local clock.
    let created_at_record = clock.now().map_err(|err| {
        // Dropping `credit` releases the reservation on failure.
        fault(
            err.code.as_str(),
            format!("registered clock failed before dispatch commit: {}", err.detail),
        )
    })?;
    let created_at_value = record_value(&created_at_record).clone();
    if let Err(err) = check_timepoint(&created_at_value) {
        return Err(err);
    }

    // --- ConnectorHandle: no native run ID yet; those arrive only as
    // later source-backed observations.
    let handle = json!({
        "record_type": "connector_handle",
        "record_version": SCHEMA_VERSION,
        "handle_ref": handle_ref,
        "preparation_ref": preparation_id,
        "scope": scope,
        "idempotency_key": parsed.idempotency_key,
        "created_at": created_at_value,
        "native_run_id": missing("not_observed", "native run ID attaches only in later source-backed observations"),
    });

    // --- One owner-local durable effect: admitted input, idempotency
    // record, handle, dispatch intent, and replayable receipt.
    let operation = if resumed {
        RESUME_DELIVERY_OPERATION
    } else {
        TRANSACTION_OPERATION
    };
    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": operation,
            "command": {
                "principal_id": facts.principal_id,
                "connector_id": parsed.connector_id,
                "request_id": parsed.request_id,
            },
            "idempotency_key": parsed.idempotency_key,
            "handle": handle,
            "preparation": parsed.preparation,
            "preparation_ref": preparation_id,
            "configuration": parsed.configuration,
            "authorization": parsed.authorization,
            "request_binding": request_value,
            "recovery": parsed.recovery_value,
            "dispatch_intent": {
                "created_at": created_at_value,
                "reservation": reservation_value,
                "preparation_ref": preparation_id,
                "resumed": resumed,
            },
            "replay": {
                "handle": handle,
                "idempotency_key": parsed.idempotency_key,
                "preparation_ref": preparation_id,
            },
            "created_at": created_at_value,
        }),
    )?;
    let store_receipt = match store.transact(grant, &transaction) {
        Ok(receipt) => receipt,
        Err(err) => return Err(err),
    };
    let store_receipt_value = record_value(&store_receipt).clone();
    if store_receipt_value.get("durable") == Some(&Value::Bool(false)) {
        return Err(fault(
            "not_durable",
            "owner store returned a non-durable receipt; the dispatch boundary is not acknowledged",
        ));
    }

    let receipt_value = json!({
        "record_type": "dispatch_receipt",
        "record_version": SCHEMA_VERSION,
        "handle": handle,
        "command": {
            "principal_id": facts.principal_id,
            "connector_id": parsed.connector_id,
            "request_id": parsed.request_id,
        },
        "idempotency_key": parsed.idempotency_key,
        "preparation_ref": preparation_id,
        "dispatch_intent": {
            "created_at": created_at_value,
            "reservation": reservation_value,
            "preparation_ref": preparation_id,
            "resumed": resumed,
        },
        "reservation": reservation_value,
        "store_receipt": store_receipt_value,
        "created_at": created_at_value,
        "disposition": if resumed { "resumed" } else { "committed" },
    });
    let receipt = validate(OUTPUT_SCHEMA, receipt_value.clone())?;

    // Retain for idempotent replay. Resume preserves the original logical
    // receipt; the new command maps to the resumed delivery.
    registry.commands.insert(
        cmd_key,
        CommandEntry {
            request: request_value,
            receipt: receipt_value.clone(),
        },
    );
    if !resumed {
        registry.logical.insert(
            log_key,
            LogicalEntry {
                preparation: parsed.preparation.clone(),
                receipt: receipt_value,
            },
        );
    }
    drop(registry);

    // Hold the observation budget: an accepted queued task consumes its
    // active observation budget until observation closes it. Forgetting
    // (rather than dropping) keeps the admission ledger charged.
    std::mem::forget(credit);
    Ok(receipt)
}

fn preparation_record_value_config(value: &Value) -> Result<Map<String, Value>, Fault> {
    value.as_object().cloned().ok_or_else(|| {
        fault(
            "invalid_request",
            "configuration must be an object",
        )
    })
}

/// Authorize a resume for an existing logical dispatch.
///
/// Requires a new command identity, the existing logical idempotency
/// key/handle, explicit recovery authority, and an evidenced native
/// checkpoint or idempotency contract for the same request and context.
/// The returned authorization is consumed as the `recovery` field of a
/// resumed [`start`]. Lease expiry alone is insufficient.
pub fn authorize_resume(
    store: &dyn OwnerStore,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let facts = grant_facts(grant)?;
    if facts.verb != "Start" {
        return Err(fault(
            "forbidden",
            format!(
                "resume authorization requires a Start grant; grant carries verb {:?}",
                facts.verb
            ),
        ));
    }
    let map = as_object(request, "invalid_request", "request")?;
    let connector_id =
        required_str(map, "connector_id", "invalid_request", "request")?.to_string();
    if connector_id != facts.connector {
        return Err(fault(
            "forbidden",
            format!(
                "request connector {connector_id:?} does not match the grant connector {:?}",
                facts.connector
            ),
        ));
    }
    let request_id =
        required_str(map, "request_id", "invalid_request", "request")?.to_string();
    let idempotency_key =
        required_str(map, "idempotency_key", "invalid_request", "request")?.to_string();
    let handle_ref =
        required_str(map, "handle_ref", "invalid_request", "request")?.to_string();
    let recovery_authority = match established(map, "recovery_authority") {
        Some(Value::Array(refs)) if !refs.is_empty() => Value::Array(refs.clone()),
        _ => {
            return Err(fault(
                "invalid_request",
                "resume requires an explicit nonempty recovery_authority; lease expiry alone is insufficient",
            ))
        }
    };
    let checkpoint = match established(map, "checkpoint") {
        Some(Value::Object(_)) => map.get("checkpoint").cloned().unwrap_or(Value::Null),
        _ => {
            return Err(fault(
                "invalid_request",
                "resume requires an evidenced native checkpoint or idempotency contract",
            ))
        }
    };
    let checkpoint_map = checkpoint.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            "resume checkpoint must be an object",
        )
    })?;
    // The checkpoint must evidence the same request and context.
    match checkpoint_map.get("idempotency_key").and_then(Value::as_str) {
        Some(key) if key == idempotency_key => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume checkpoint must name the same idempotency_key as the request",
            ))
        }
    }
    match checkpoint_map.get("handle_ref").and_then(Value::as_str) {
        Some(handle) if handle == handle_ref => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume checkpoint must name the same handle_ref as the request",
            ))
        }
    }
    let has_native = established(checkpoint_map, "native_checkpoint").is_some();
    let has_contract = established(checkpoint_map, "idempotency_contract").is_some();
    if !has_native && !has_contract {
        return Err(fault(
            "invalid_request",
            "resume checkpoint must carry an evidenced native_checkpoint or idempotency_contract",
        ));
    }
    match established(checkpoint_map, "evidence_refs") {
        Some(Value::Array(refs)) if !refs.is_empty() => {}
        _ => {
            return Err(fault(
                "invalid_request",
                "resume checkpoint requires nonempty evidence_refs",
            ))
        }
    }

    let cmd_key = command_key(&facts.principal_id, &connector_id, &request_id);
    let log_key = logical_key(&facts.principal_id, &connector_id, &idempotency_key);
    let expected_handle = format!(
        "handle:{}:{}:{}",
        facts.principal_id, connector_id, idempotency_key
    );

    let registry = lock_registry()?;
    // New command identity is mandatory for resume.
    if registry.commands.contains_key(&cmd_key) {
        return Err(fault(
            "invalid_request",
            "resume requires a new command identity; this request_id is already committed",
        ));
    }
    // The logical dispatch must already exist with the same handle.
    match registry.logical.get(&log_key) {
        Some(entry) => {
            let retained_handle = entry
                .receipt
                .get("handle")
                .and_then(|handle| handle.get("handle_ref"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if retained_handle != handle_ref || handle_ref != expected_handle {
                return Err(fault(
                    "unknown_handle",
                    "resume handle does not match the existing logical dispatch",
                ));
            }
        }
        None => {
            return Err(fault(
                "unknown_handle",
                "resume names an unknown logical dispatch; Start must commit the handle before it can be resumed",
            ))
        }
    }
    drop(registry);

    let transaction = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation": RESUME_AUTHORIZATION_OPERATION,
            "command": {
                "principal_id": facts.principal_id,
                "connector_id": connector_id,
                "request_id": request_id,
            },
            "idempotency_key": idempotency_key,
            "handle_ref": handle_ref,
            "recovery_authority": recovery_authority,
            "checkpoint": checkpoint,
            "replay": {
                "handle_ref": handle_ref,
                "idempotency_key": idempotency_key,
                "request_id": request_id,
            },
        }),
    )?;
    let store_receipt = store.transact(grant, &transaction)?;
    let store_receipt_value = record_value(&store_receipt).clone();
    if store_receipt_value.get("durable") == Some(&Value::Bool(false)) {
        return Err(fault(
            "not_durable",
            "owner store returned a non-durable receipt; the resume authorization is not acknowledged",
        ));
    }

    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": "resume_authorization",
            "record_version": SCHEMA_VERSION,
            "authorized": true,
            "connector_id": connector_id,
            "request_id": request_id,
            "idempotency_key": idempotency_key,
            "handle_ref": handle_ref,
            "recovery_authority": recovery_authority,
            "checkpoint": checkpoint,
            "store_receipt": store_receipt_value,
        }),
    )
}
