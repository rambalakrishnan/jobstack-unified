//! `crawler_leases`: authority-clock fencing leases over claimable crawler rows.
//!
//! This module owns the lease half of the crawler state machines
//! (`seam-mappings/crawler-seam-mapping.md` §5, §16.6, §21.4 and the
//! evidence-kernel lease invariants):
//!
//! * **[EK-LEASE]** Claim checks the eligible pending state and the absence of
//!   a lease, assigns a unique fencing token plus the authority/owner epochs
//!   supplied by the authority journal, advances the entity revision, clears
//!   `last_failure_reason`, and commits the new row together with its audit
//!   evidence as one owner-local effect. The operational `pipeline_state` is
//!   never rewritten by claim or renewal.
//! * **[EK-LEASE-RESTART]** `leased_at` and `lease_expires_at` are built from
//!   one registered authority clock and boot; the deadline is strictly later
//!   than the issue. Expiry is decided only with
//!   [`crawler_time::compare_deadline`], so offsets are never compared across
//!   clocks or boots. Confirmed-death recovery requires a *new* authority
//!   epoch to fence the old one, and it deliberately never compares the old
//!   deadline with the new boot.
//! * **[EK-ATOMICITY] / [OWD-LOCAL-COMMIT]** Every accepted transition is
//!   submitted to the owner store as one `lease_transition` transaction that
//!   carries the fencing preconditions, the post-transition row, the audit
//!   evidence, and any dead-letter occurrence. The function returns only
//!   after the store acknowledged that effect; a rejected transaction returns
//!   the store's fault and no row. The composing `OwnerStore` implementation
//!   interprets that operation, so this module never reaches into journal
//!   internals, issues a second write, or waits for a peer owner.
//! * **[OWD-REVISION]** Every transition produces a complete immutable
//!   snapshot with `entity_revision = previous + 1` (starting at 1) and names
//!   both the revision and the held lease generation it fences. A stale
//!   snapshot or stale lease/epoch/revision cannot commit: the module rejects
//!   it before any store call, and the emitted transaction also names the
//!   expected `entity_revision` so the owner store can apply its own
//!   compare-and-swap.
//!
//! ## Request contract
//!
//! All four operations take one gate-validated [`CheckedRecord`] whose value
//! is an object:
//!
//! ```text
//! {
//!   "operation": "claim" | "renew" | "complete" | "reclaim",
//!   "entity_type": "listing" | "work_item" | "job_detail",
//!   "row": { ...normalized claimable row (§5)... },
//!   "lease": {
//!     "issuer": "<id>",                 // lease authority identity
//!     "authority_epoch": <u64>,         // authority lifetime that issued/owns the generation
//!     "owner": "<id>",                  // holder identity from the authority journal
//!     "owner_epoch": <u64>,             // holder generation
//!     "generation_id": "<id>",          // held claim generation
//!     "policy_pin": "<id>",             // TTL/retry/routing pin
//!     "session_epoch": <u64> | Missing, // applicable session epoch, else not_applicable
//!     "ttl_ms": <finite number > 0>,    // claim/renew only
//!     "lease_id": "<token>" | Missing   // Missing(not_applicable) for claim
//!   },
//!   "expected": {                       // renew/complete/reclaim
//!     "entity_revision": <u64>, "input_revision": <u64>,
//!     "lease_id": "<token>", "authority_epoch": <u64>,
//!     "owner_epoch": <u64>, "session_epoch": <u64> | Missing
//!   },
//!   "reclaim": {                        // reclaim only
//!     "trigger": "release" | "expiry" | "death_recovery",
//!     "failure_reason": "<id>" | Missing, "stage": "<id>"   // stage optional
//!   }
//! }
//! ```
//!
//! `row` is the current complete normalized row. When unleased, the four lease
//! fields (`lease_id`, `lease_owner`, `leased_at`, `lease_expires_at`) must be
//! `Missing(not_applicable)` together; when held, all four are established on
//! one clock/boot with `lease_expires_at > leased_at`. `lease` is the
//! authority-journal evidence for the generation; `expected` is the fenced
//! belief carried by the command. Both must agree with the row before any
//! effect is attempted.
//!
//! ## Result contract
//!
//! The returned record is a gate-validated `audit_log` envelope:
//!
//! ```text
//! {
//!   "record_type": "lease_transition", "operation": ..., "entity_type": ...,
//!   "row": <complete post-transition row>,
//!   "transition": { trigger, lease_id, authority_epoch, previous_authority_epoch,
//!                   owner_epoch, generation_id, session_epoch, input_revision,
//!                   failure_reason, bypass_reason, policy_revision,
//!                   field_changes, failed_generation_charged,
//!                   commit_authority_revoked, exhausted, limitation },
//!   "audit": { event_kind, owner_domain, producer_id, role, provenance,
//!              assertion_kind, entity_type, target, job_id, lease_id, issuer,
//!              authority_epoch, owner, owner_epoch, generation_id, policy_pin,
//!              session_epoch, occurred_at, idempotency_key },
//!   "dead_letter": <occurrence> | Missing(not_applicable),
//!   "store_receipt": <the owner store's receipt value>
//! }
//! ```
//!
//! Successful completion is a lease release, not a failed retry: it neither
//! increments `retry_count` nor records a failure. Reclamation always clears
//! ownership and charges the failed generation exactly once; when the charge
//! exceeds `max_retries_effective` the row is routed to `failed` and one
//! dead-letter occurrence is emitted with the recorded reason or
//! `retry_exhausted`. Reclamation revokes local commit authority only; it is
//! never evidence that remote execution stopped.
//!
//! Claim requires a row with no lease at all. An expired-but-unreclaimed lease
//! must go through [`reclaim`] (`trigger = "expiry"` or `"death_recovery"`)
//! first, so the failed generation is charged exactly once and cannot be
//! silently replaced by a fresh claim.

use crawler_authority::{grant_record, Grant};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;

/// Structural envelope used for every record produced here.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Operation name the owner store receives for one atomic lease transition.
const TRANSACTION_OPERATION: &str = "lease_transition";

const ENTITY_TYPES: &[&str] = &["listing", "work_item", "job_detail"];

/// Closed listing vocabulary (§16.1). Unknown values are rejected.
const LISTING_STATES: &[&str] = &[
    "pending_snippet_classify",
    "pending_enrich",
    "pending_description_classify",
    "pending_finalize",
    "enqueued",
    "finalized",
    "deduped",
    "vetoed",
    "render_failed",
    "failed",
];

/// Listing states that may hold a lease (§16.3 "Any pending state").
const LISTING_PENDING: &[&str] = &[
    "pending_snippet_classify",
    "pending_enrich",
    "pending_description_classify",
    "pending_finalize",
    "enqueued",
];

const WORK_STATES: &[&str] = &["pending", "done", "failed"];
const WORK_PENDING: &[&str] = &["pending"];

const DETAIL_STATES: &[&str] = &[
    "pending_classification",
    "ready",
    "vetoed",
    "render_failed",
    "failed",
];
const DETAIL_PENDING: &[&str] = &["pending_classification"];

const RECLAIM_TRIGGERS: &[&str] = &["release", "expiry", "death_recovery"];

/// Fields only the authenticated ingestion authority may assign. A lease
/// request that carries one of these is a spoof, never an input.
const AUTHORITY_FIELDS: &[&str] = &[
    "owner_domain",
    "producer_id",
    "role",
    "provenance",
    "assertion_kind",
    "event_kind",
    "journal_sequence",
    "event_id",
    "event_hash",
    "manifest_hash",
];

/// The four §5 lease fields, which are established or inapplicable together.
const LEASE_FIELDS: &[&str] = &[
    "lease_id",
    "lease_owner",
    "leased_at",
    "lease_expires_at",
];

const DEFAULT_DEAD_LETTER_REASON: &str = "retry_exhausted";
const DEFAULT_STAGE: &str = "lease_reclamation";
const RECLAIM_LIMITATION: &str =
    "reclamation revokes local commit authority only; it does not prove remote execution stopped";

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

/// Typed Missing envelope; no bare JSON null ever leaves this module.
fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

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

fn established<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|value| !is_missing(value))
}

fn required_object<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    established(object, key)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            fault(
                "missing_field",
                format!("{what} requires an established object {key:?}"),
            )
        })
}

fn required_str<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    established(object, key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            fault(
                "missing_field",
                format!("{what} requires a nonempty string {key:?}"),
            )
        })
}

fn required_u64(object: &Map<String, Value>, key: &str, what: &str) -> Result<u64, Fault> {
    established(object, key)
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_field",
                format!("{what} requires a nonnegative integer {key:?}"),
            )
        })
}

/// A required `M(u64)` epoch: `Missing(not_applicable)` or an integer.
fn optional_epoch(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Option<u64>, Fault> {
    match object.get(key) {
        Some(value) if is_missing(value) => {
            if missing_reason(value) != Some("not_applicable") {
                return Err(fault(
                    "invalid_field",
                    format!(
                        "{what} {key:?} missingness reason must be not_applicable, got {:?}",
                        missing_reason(value)
                    ),
                ));
            }
            Ok(None)
        }
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            fault(
                "invalid_field",
                format!("{what} {key:?} must be a nonnegative integer or not_applicable"),
            )
        }),
        None => Err(fault(
            "missing_field",
            format!("{what} requires {key:?} as a nonnegative integer or not_applicable"),
        )),
    }
}

/// An optional identifier carried as a string or a typed Missing envelope.
fn maybe_identifier(
    object: &Map<String, Value>,
    key: &str,
    what: &str,
) -> Result<Value, Fault> {
    match object.get(key) {
        Some(value) if is_missing(value) => Ok(value.clone()),
        Some(Value::String(text)) if !text.is_empty() => Ok(Value::String(text.clone())),
        Some(_) => Err(fault(
            "invalid_field",
            format!("{what} {key:?} must be a nonempty string or Missing"),
        )),
        None => Ok(missing(
            "not_observed",
            &format!("{what} carries no recorded {key:?}"),
        )),
    }
}

fn session_value(epoch: Option<u64>) -> Value {
    match epoch {
        Some(epoch) => json!(epoch),
        None => missing("not_applicable", "the lease is sessionless"),
    }
}

fn maybe_epoch_value(epoch: Option<u64>, detail: &str) -> Value {
    match epoch {
        Some(epoch) => json!(epoch),
        None => missing("not_applicable", detail),
    }
}

/// A full §5 claimable row parsed into its lease and operational facts.
struct RowFacts {
    target: String,
    job_id: String,
    active_run_id: String,
    entity_revision: u64,
    input_revision: u64,
    retry_count: u64,
    max_retries_effective: u64,
    pipeline_state: String,
    lease_id: Option<String>,
    lease_owner: Option<String>,
    leased_at: Option<Value>,
    lease_expires_at: Option<Value>,
    last_failure_reason: Value,
}

struct Vocabulary {
    all: &'static [&'static str],
    pending: &'static [&'static str],
}

fn vocabulary(entity_type: &str) -> Result<Vocabulary, Fault> {
    match entity_type {
        "listing" => Ok(Vocabulary {
            all: LISTING_STATES,
            pending: LISTING_PENDING,
        }),
        "work_item" => Ok(Vocabulary {
            all: WORK_STATES,
            pending: WORK_PENDING,
        }),
        "job_detail" => Ok(Vocabulary {
            all: DETAIL_STATES,
            pending: DETAIL_PENDING,
        }),
        other => Err(fault(
            "invalid_entity_type",
            format!(
                "entity type {other:?} is not one of listing, work_item, job_detail"
            ),
        )),
    }
}

fn require_timepoint(value: &Value, field: &str) -> Result<CheckedRecord, Fault> {
    validate(OUTPUT_SCHEMA, value.clone())
        .map_err(|error| fault(error.code.as_str(), format!("{field}: {}", error.detail)))
}

impl RowFacts {
    fn parse(row: &Map<String, Value>, entity_type: &str) -> Result<Self, Fault> {
        let vocabulary = vocabulary(entity_type)?;
        let pipeline_state = required_str(row, "pipeline_state", "row")?.to_string();
        if !vocabulary.all.contains(&pipeline_state.as_str()) {
            return Err(fault(
                "unknown_pipeline_state",
                format!(
                    "row pipeline_state {pipeline_state:?} is not a registered {entity_type} state"
                ),
            ));
        }

        let last_failure_reason = match row.get("last_failure_reason") {
            Some(value) if is_missing(value) => value.clone(),
            Some(Value::String(text)) if !text.is_empty() => Value::String(text.clone()),
            Some(_) => {
                return Err(fault(
                    "invalid_row",
                    "row last_failure_reason must be a nonempty identifier or Missing".to_string(),
                ))
            }
            None => missing(
                "not_observed",
                "row carries no last_failure_reason; an unreclaimed row has none",
            ),
        };

        let mut lease_values: [Option<Value>; 4] = [None, None, None, None];
        for (index, field) in LEASE_FIELDS.iter().enumerate() {
            match row.get(*field) {
                None => {
                    return Err(fault(
                        "missing_field",
                        format!(
                            "row is missing {field:?}; unleased rows must carry typed Missing(not_applicable)"
                        ),
                    ))
                }
                Some(value) if is_missing(value) => {
                    if missing_reason(value) != Some("not_applicable") {
                        return Err(fault(
                            "invalid_lease_fields",
                            format!(
                                "row {field:?} is unleased and must be Missing(not_applicable), got reason {:?}",
                                missing_reason(value)
                            ),
                        ));
                    }
                }
                Some(value) => lease_values[index] = Some(value.clone()),
            }
        }

        let established_count = lease_values.iter().filter(|value| value.is_some()).count();
        if established_count != 0 && established_count != LEASE_FIELDS.len() {
            return Err(fault(
                "invalid_lease_fields",
                "row lease fields must be established together or inapplicable together".to_string(),
            ));
        }

        let (lease_id, lease_owner, leased_at, lease_expires_at) = if established_count == 0 {
            (None, None, None, None)
        } else {
            let lease_id = lease_values[0]
                .as_ref()
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| {
                    fault(
                        "invalid_lease_fields",
                        "held row requires a nonempty lease_id".to_string(),
                    )
                })?
                .to_string();
            let lease_owner = lease_values[1]
                .as_ref()
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| {
                    fault(
                        "invalid_lease_fields",
                        "held row requires a nonempty lease_owner".to_string(),
                    )
                })?
                .to_string();
            let leased_at = lease_values[2].clone().ok_or_else(|| {
                fault(
                    "invalid_lease_fields",
                    "held row requires leased_at".to_string(),
                )
            })?;
            let lease_expires_at = lease_values[3].clone().ok_or_else(|| {
                fault(
                    "invalid_lease_fields",
                    "held row requires lease_expires_at".to_string(),
                )
            })?;
            let issued = require_timepoint(&leased_at, "row leased_at")?;
            let expires = require_timepoint(&lease_expires_at, "row lease_expires_at")?;
            match compare_deadline(&expires, &issued) {
                Ok(Ordering::Greater) => {}
                Ok(_) => {
                    return Err(fault(
                        "invalid_lease_fields",
                        "leased_at/lease_expires_at must share one authority clock and boot with expiry later than issue"
                            .to_string(),
                    ))
                }
                Err(error) => {
                    return Err(fault(
                        error.code.as_str(),
                        format!("held lease timestamps: {}", error.detail),
                    ))
                }
            }
            if !is_missing(&last_failure_reason) {
                return Err(fault(
                    "invalid_held_lease",
                    "a held lease cannot carry last_failure_reason; claim clears it and reclamation clears ownership"
                        .to_string(),
                ));
            }
            (
                Some(lease_id),
                Some(lease_owner),
                Some(leased_at),
                Some(lease_expires_at),
            )
        };

        Ok(Self {
            target: required_str(row, "target", "row")?.to_string(),
            job_id: required_str(row, "job_id", "row")?.to_string(),
            active_run_id: required_str(row, "active_run_id", "row")?.to_string(),
            entity_revision: {
                let revision = required_u64(row, "entity_revision", "row")?;
                if revision == 0 {
                    return Err(fault(
                        "invalid_revision",
                        "entity_revision 0 is not a domain revision; the first revision is 1"
                            .to_string(),
                    ));
                }
                revision
            },
            input_revision: required_u64(row, "input_revision", "row")?,
            retry_count: required_u64(row, "retry_count", "row")?,
            max_retries_effective: required_u64(row, "max_retries_effective", "row")?,
            pipeline_state,
            lease_id,
            lease_owner,
            leased_at,
            lease_expires_at,
            last_failure_reason,
        })
    }

    fn is_pending(&self, entity_type: &str) -> Result<bool, Fault> {
        let vocabulary = vocabulary(entity_type)?;
        Ok(vocabulary.pending.contains(&self.pipeline_state.as_str()))
    }
}

/// The authority-journal evidence for the held (or assigned) generation.
struct LeaseFacts {
    issuer: String,
    authority_epoch: u64,
    owner: String,
    owner_epoch: u64,
    generation_id: String,
    policy_pin: String,
    session_epoch: Option<u64>,
    ttl_ms: Option<f64>,
    lease_id: Option<String>,
}

impl LeaseFacts {
    fn parse(lease: &Map<String, Value>, assignment: bool) -> Result<Self, Fault> {
        let ttl_ms = match lease.get("ttl_ms") {
            Some(Value::Number(number)) => match number.as_f64() {
                Some(ttl) if ttl.is_finite() && ttl > 0.0 => Some(ttl),
                _ => {
                    return Err(fault(
                        "invalid_ttl",
                        "lease ttl_ms must be a finite positive number".to_string(),
                    ))
                }
            },
            Some(value) if is_missing(value) => None,
            Some(_) => {
                return Err(fault(
                    "invalid_ttl",
                    "lease ttl_ms must be a finite positive number or Missing".to_string(),
                ))
            }
            None => None,
        };

        let lease_id = match lease.get("lease_id") {
            Some(value) if is_missing(value) => {
                if !assignment {
                    return Err(fault(
                        "stale_lease",
                        "a held-generation request requires an established lease_id".to_string(),
                    ));
                }
                if missing_reason(value) != Some("not_applicable") {
                    return Err(fault(
                        "invalid_field",
                        "claim lease_id must be Missing(not_applicable); the module assigns the token"
                            .to_string(),
                    ));
                }
                None
            }
            Some(Value::String(text)) if !text.is_empty() => {
                if assignment {
                    return Err(fault(
                        "self_issued_lease",
                        "claim must not carry a lease_id; ownership tokens are authority-assigned"
                            .to_string(),
                    ));
                }
                Some(text.clone())
            }
            Some(_) => {
                return Err(fault(
                    "invalid_field",
                    "lease lease_id must be a nonempty string or Missing(not_applicable)".to_string(),
                ))
            }
            None => {
                if assignment {
                    None
                } else {
                    return Err(fault(
                        "missing_field",
                        "held-generation request requires lease.lease_id".to_string(),
                    ));
                }
            }
        };

        Ok(Self {
            issuer: required_str(lease, "issuer", "lease")?.to_string(),
            authority_epoch: required_u64(lease, "authority_epoch", "lease")?,
            owner: required_str(lease, "owner", "lease")?.to_string(),
            owner_epoch: required_u64(lease, "owner_epoch", "lease")?,
            generation_id: required_str(lease, "generation_id", "lease")?.to_string(),
            policy_pin: required_str(lease, "policy_pin", "lease")?.to_string(),
            session_epoch: optional_epoch(lease, "session_epoch", "lease")?,
            ttl_ms,
            lease_id,
        })
    }

    fn require_ttl(&self, operation: &str) -> Result<f64, Fault> {
        self.ttl_ms.ok_or_else(|| {
            fault(
                "missing_field",
                format!("{operation} requires lease.ttl_ms so the deadline can be issued"),
            )
        })
    }
}

/// The fenced belief carried by a renewal, completion, or reclamation command.
struct Expected {
    entity_revision: u64,
    input_revision: u64,
    lease_id: String,
    authority_epoch: u64,
    owner_epoch: u64,
    session_epoch: Option<u64>,
}

impl Expected {
    fn parse(expected: &Map<String, Value>) -> Result<Self, Fault> {
        Ok(Self {
            entity_revision: required_u64(expected, "entity_revision", "expected")?,
            input_revision: required_u64(expected, "input_revision", "expected")?,
            lease_id: required_str(expected, "lease_id", "expected")?.to_string(),
            authority_epoch: required_u64(expected, "authority_epoch", "expected")?,
            owner_epoch: required_u64(expected, "owner_epoch", "expected")?,
            session_epoch: optional_epoch(expected, "session_epoch", "expected")?,
        })
    }
}

struct ReclaimFacts {
    trigger: String,
    failure_reason: Value,
    stage: String,
}

impl ReclaimFacts {
    fn parse(reclaim: &Map<String, Value>) -> Result<Self, Fault> {
        let trigger = required_str(reclaim, "trigger", "reclaim")?.to_string();
        if !RECLAIM_TRIGGERS.contains(&trigger.as_str()) {
            return Err(fault(
                "invalid_trigger",
                format!(
                    "reclaim trigger {trigger:?} is not one of release, expiry, death_recovery"
                ),
            ));
        }
        let failure_reason = maybe_identifier(reclaim, "failure_reason", "reclaim")?;
        let stage = match established(reclaim, "stage").and_then(Value::as_str) {
            Some(text) if !text.is_empty() => text.to_string(),
            Some(_) => {
                return Err(fault(
                    "invalid_field",
                    "reclaim stage must be a nonempty identifier".to_string(),
                ))
            }
            None => DEFAULT_STAGE.to_string(),
        };
        Ok(Self {
            trigger,
            failure_reason,
            stage,
        })
    }

    fn recorded_reason(&self) -> Option<&str> {
        self.failure_reason.as_str()
    }
}

/// One parsed request envelope. Every key is owned so it can be inspected
/// without borrowing the caller's record beyond this frame.
struct ParsedRequest {
    entity_type: String,
    row: Map<String, Value>,
    lease: Map<String, Value>,
    expected: Option<Map<String, Value>>,
    reclaim: Option<Map<String, Value>>,
}

impl ParsedRequest {
    fn parse(request: &CheckedRecord, operation: &str) -> Result<Self, Fault> {
        let root = record_value(request).as_object().ok_or_else(|| {
            fault(
                "invalid_request",
                "a lease request must be a gate-validated object".to_string(),
            )
        })?;
        for field in AUTHORITY_FIELDS {
            if established(root, field).is_some() {
                return Err(fault(
                    "spoofed_authority_field",
                    format!(
                        "lease request carries {field:?}; authority identity and journal coordinates are assigned by ingestion, never by the caller"
                    ),
                ));
            }
        }
        let seen_operation = required_str(root, "operation", "request")?;
        if seen_operation != operation {
            return Err(fault(
                "operation_mismatch",
                format!(
                    "request names operation {seen_operation:?} but {operation:?} was invoked"
                ),
            ));
        }
        let entity_type = required_str(root, "entity_type", "request")?.to_string();
        if !ENTITY_TYPES.contains(&entity_type.as_str()) {
            return Err(fault(
                "invalid_entity_type",
                format!("entity type {entity_type:?} is not a claimable crawler row"),
            ));
        }
        let row = required_object(root, "row", "request")?.clone();
        let lease = required_object(root, "lease", "request")?.clone();
        let expected = match established(root, "expected") {
            Some(value) => Some(value.as_object().cloned().ok_or_else(|| {
                fault(
                    "invalid_request",
                    "request expected must be an object".to_string(),
                )
            })?),
            None => None,
        };
        let reclaim = match established(root, "reclaim") {
            Some(value) => Some(value.as_object().cloned().ok_or_else(|| {
                fault(
                    "invalid_request",
                    "request reclaim must be an object".to_string(),
                )
            })?),
            None => None,
        };
        Ok(Self {
            entity_type,
            row,
            lease,
            expected,
            reclaim,
        })
    }

    fn require_expected(&self) -> Result<Expected, Fault> {
        let expected = self.expected.as_ref().ok_or_else(|| {
            fault(
                "missing_field",
                "a held-generation transition requires the command's expected fencing values"
                    .to_string(),
            )
        })?;
        Expected::parse(expected)
    }
}

/// Authenticated facts the grant contributes to the audit record.
struct GrantFacts {
    owner_domain: String,
    producer_id: Option<String>,
    provenance: Value,
    role: Value,
    assertion_kind: Value,
}

fn optional_grant_text(object: &Map<String, Value>, field: &str) -> Value {
    match established(object, field).and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Value::String(text.to_string()),
        _ => missing(
            "not_observed",
            &format!("grant carries no {field}; the audit records the absence"),
        ),
    }
}

fn grant_facts(grant: &Grant) -> Result<GrantFacts, Fault> {
    let map = record_value(grant_record(grant)).as_object().ok_or_else(|| {
        fault(
            "invalid_grant",
            "grant must carry a gate-validated authority record".to_string(),
        )
    })?;
    let producer_id = match map.get("producer_id") {
        Some(value) if is_missing(value) => None,
        Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
        Some(_) => {
            return Err(fault(
                "invalid_grant",
                "grant producer_id must be a nonempty identifier when present".to_string(),
            ))
        }
        None => None,
    };
    Ok(GrantFacts {
        owner_domain: required_str(map, "owner_domain", "grant")?.to_string(),
        producer_id,
        provenance: optional_grant_text(map, "provenance"),
        role: optional_grant_text(map, "role"),
        assertion_kind: optional_grant_text(map, "assertion_kind"),
    })
}

/// Strictly parsed authority-clock reading.
struct NowFields {
    clock_id: String,
    boot_id: String,
    origin: String,
    offset_ms: f64,
    value: Value,
}

impl NowFields {
    fn parse(record: &CheckedRecord) -> Result<Self, Fault> {
        // `compare_deadline` is the registered TimePoint authority: ordering a
        // reading with itself validates the complete coordinate shape without
        // inventing a second parser.
        compare_deadline(record, record).map_err(|error| {
            fault(
                error.code.as_str(),
                format!("lease authority clock: {}", error.detail),
            )
        })?;
        let object = record_value(record).as_object().ok_or_else(|| {
            fault(
                "invalid_clock",
                "lease authority clock must report a TimePoint object".to_string(),
            )
        })?;
        Ok(Self {
            clock_id: object
                .get("clock_id")
                .and_then(Value::as_str)
                .ok_or_else(|| fault("invalid_clock", "clock reading has no clock_id".to_string()))?
                .to_string(),
            boot_id: object
                .get("boot_id")
                .and_then(Value::as_str)
                .ok_or_else(|| fault("invalid_clock", "clock reading has no boot_id".to_string()))?
                .to_string(),
            origin: object
                .get("origin")
                .and_then(Value::as_str)
                .ok_or_else(|| fault("invalid_clock", "clock reading has no origin".to_string()))?
                .to_string(),
            offset_ms: object
                .get("monotonic_offset_ms")
                .and_then(Value::as_f64)
                .ok_or_else(|| {
                    fault(
                        "invalid_clock",
                        "clock reading has no monotonic_offset_ms".to_string(),
                    )
                })?,
            value: record_value(record).clone(),
        })
    }

    /// Deadline on the same clock and boot, strictly later than the issue.
    fn issue_deadline(&self, ttl_ms: f64) -> Result<Value, Fault> {
        let offset = self.offset_ms + ttl_ms;
        if !offset.is_finite() || offset <= self.offset_ms {
            return Err(fault(
                "invalid_ttl",
                "lease ttl_ms must produce a finite deadline strictly after the issue"
                    .to_string(),
            ));
        }
        let number = serde_json::Number::from_f64(offset).ok_or_else(|| {
            fault(
                "invalid_ttl",
                "lease deadline is not a finite monotonic coordinate".to_string(),
            )
        })?;
        Ok(json!({
            "clock_id": self.clock_id,
            "boot_id": self.boot_id,
            "origin": self.origin,
            "monotonic_offset_ms": Value::Number(number),
            "utc_annotation": missing(
                "not_observed",
                "monotonic lease deadlines carry no UTC annotation; UTC is never subtracted",
            ),
        }))
    }
}

fn advance_revision(current: u64) -> Result<u64, Fault> {
    current
        .checked_add(1)
        .ok_or_else(|| fault("revision_overflow", "entity revision cannot advance further"))
}

fn deadline_order(
    now: &CheckedRecord,
    deadline: &Value,
    what: &str,
) -> Result<Ordering, Fault> {
    let deadline = require_timepoint(deadline, "lease_expires_at")?;
    compare_deadline(now, &deadline).map_err(|error| {
        fault(
            error.code.as_str(),
            format!("{what}: {}", error.detail),
        )
    })
}

/// A reading on the held generation's clock/boot cannot precede its issue.
fn require_not_before_issue(
    now: &CheckedRecord,
    issued: &Value,
    operation: &str,
) -> Result<(), Fault> {
    let issued = require_timepoint(issued, "held leased_at")?;
    match compare_deadline(now, &issued) {
        Ok(Ordering::Greater) | Ok(Ordering::Equal) => Ok(()),
        Ok(Ordering::Less) => Err(fault(
            "invalid_clock",
            format!("{operation} cannot precede the lease issue coordinate"),
        )),
        Err(error) => Err(fault(
            error.code.as_str(),
            format!("{operation}: {}", error.detail),
        )),
    }
}

fn require_pending(row: &RowFacts, entity_type: &str, operation: &str) -> Result<(), Fault> {
    if !row.is_pending(entity_type)? {
        return Err(fault(
            "ineligible_state",
            format!(
                "{operation} refused: pipeline_state {:?} is not a pending state for {entity_type}",
                row.pipeline_state
            ),
        ));
    }
    Ok(())
}

fn require_active_retry_budget(row: &RowFacts, operation: &str) -> Result<(), Fault> {
    if row.retry_count > row.max_retries_effective {
        return Err(fault(
            "retry_exhausted",
            format!(
                "{operation} refused: {} failed generations exceed the effective limit {}; exhausted work is never resurrected",
                row.retry_count, row.max_retries_effective
            ),
        ));
    }
    Ok(())
}

fn require_authenticated_owner(lease: &LeaseFacts, grant: &GrantFacts) -> Result<(), Fault> {
    if lease.owner == grant.owner_domain
        || grant.producer_id.as_deref() == Some(lease.owner.as_str())
    {
        return Ok(());
    }
    Err(fault(
        "unauthenticated_lease_owner",
        format!(
            "claim owner {:?} is neither the authenticated producer {:?} nor its owner domain {:?}; ownership is never self-issued",
            lease.owner, grant.producer_id, grant.owner_domain
        ),
    ))
}

/// Fence a held-generation command against the current row.
///
/// `allow_new_authority_epoch` is set only for confirmed-death recovery, where
/// the command must carry a *strictly newer* authority epoch that fences the
/// old one before reclamation. Every other operation requires the epoch under
/// which the generation was issued.
fn require_current(
    row: &RowFacts,
    lease: &LeaseFacts,
    expected: &Expected,
    operation: &str,
    allow_new_authority_epoch: bool,
) -> Result<(), Fault> {
    let held_id = row.lease_id.as_deref().ok_or_else(|| {
        fault(
            "lease_not_held",
            format!(
                "{operation} refused: the row holds no lease; a failed generation is cleared exactly once"
            ),
        )
    })?;
    if lease.lease_id.as_deref() != Some(held_id) {
        return Err(fault(
            "stale_lease",
            format!(
                "{operation} refused: authority evidence names lease {:?} but the row holds {held_id:?}",
                lease.lease_id
            ),
        ));
    }
    if expected.lease_id != held_id {
        return Err(fault(
            "stale_lease",
            format!(
                "{operation} refused: command expects lease {:?} but the row holds {held_id:?}",
                expected.lease_id
            ),
        ));
    }
    if row.lease_owner.as_deref() != Some(lease.owner.as_str()) {
        return Err(fault(
            "stale_lease",
            format!(
                "{operation} refused: authority evidence names owner {:?} but the row is held by {:?}",
                lease.owner, row.lease_owner
            ),
        ));
    }
    if expected.entity_revision != row.entity_revision {
        return Err(fault(
            "stale_revision",
            format!(
                "{operation} refused: command expects entity_revision {} but the row is at {}",
                expected.entity_revision, row.entity_revision
            ),
        ));
    }
    if expected.input_revision != row.input_revision {
        return Err(fault(
            "stale_input_revision",
            format!(
                "{operation} refused: command expects input_revision {} but the row is at {}",
                expected.input_revision, row.input_revision
            ),
        ));
    }
    if expected.owner_epoch != lease.owner_epoch {
        return Err(fault(
            "stale_owner_epoch",
            format!(
                "{operation} refused: command expects owner epoch {} but the generation carries {}",
                expected.owner_epoch, lease.owner_epoch
            ),
        ));
    }
    if expected.session_epoch != lease.session_epoch {
        return Err(fault(
            "stale_session_epoch",
            format!(
                "{operation} refused: command expects session epoch {:?} but the generation carries {:?}",
                expected.session_epoch, lease.session_epoch
            ),
        ));
    }
    if allow_new_authority_epoch {
        if expected.authority_epoch <= lease.authority_epoch {
            return Err(if expected.authority_epoch == lease.authority_epoch {
                fault(
                    "restart_not_fenced",
                    format!(
                        "{operation} refused: confirmed-death recovery must fence the old authority epoch {} with a newer one, not reuse it",
                        lease.authority_epoch
                    ),
                )
            } else {
                fault(
                    "stale_authority_epoch",
                    format!(
                        "{operation} refused: fencing authority epoch {} is older than the generation's epoch {}",
                        expected.authority_epoch, lease.authority_epoch
                    ),
                )
            });
        }
    } else if expected.authority_epoch != lease.authority_epoch {
        return Err(fault(
            "stale_authority_epoch",
            format!(
                "{operation} refused: command expects authority epoch {} but the generation was issued under {}",
                expected.authority_epoch, lease.authority_epoch
            ),
        ));
    }
    Ok(())
}

fn fence_token(
    lease: &LeaseFacts,
    entity_type: &str,
    target: &str,
    job_id: &str,
    revision: u64,
) -> String {
    // The authority journal's generation identity plus the new entity revision
    // and owner epoch make the token unique per assignment without a random
    // source: identical command retries reproduce it, and no other assignment
    // can.
    format!(
        "lease:{}:{}:{}:{}:{}:{}:{}:{}",
        lease.issuer,
        lease.authority_epoch,
        lease.generation_id,
        lease.owner_epoch,
        entity_type,
        target,
        job_id,
        revision
    )
}

fn with_updates(row: &Map<String, Value>, updates: &[(&str, Value)]) -> Value {
    let mut updated = row.clone();
    for (field, value) in updates {
        updated.insert(field.to_string(), value.clone());
    }
    Value::Object(updated)
}

fn original(row: &Map<String, Value>, field: &str) -> Value {
    row.get(field).cloned().unwrap_or_else(|| {
        missing(
            "not_observed",
            &format!("row carried no {field} before the transition"),
        )
    })
}

fn change(field: &str, old: Value, new: Value) -> Value {
    json!({"field": field, "old": old, "new": new})
}

fn lease_field_change(field: &str, old: Option<Value>, new: Value) -> Value {
    change(
        field,
        old.unwrap_or_else(|| {
            missing(
                "not_applicable",
                "the field is inapplicable while the row is unleased",
            )
        }),
        new,
    )
}

struct TransitionSeed {
    trigger: &'static str,
    lease_id: String,
    authority_epoch: u64,
    previous_authority_epoch: Option<u64>,
    owner_epoch: u64,
    generation_id: String,
    session_epoch: Option<u64>,
    input_revision: u64,
    failure_reason: Value,
    policy_revision: String,
    field_changes: Vec<Value>,
    failed_generation_charged: bool,
    commit_authority_revoked: bool,
    exhausted: bool,
    limitation: Value,
}

fn transition_value(seed: TransitionSeed) -> Value {
    json!({
        "trigger": seed.trigger,
        "lease_id": seed.lease_id,
        "authority_epoch": seed.authority_epoch,
        "previous_authority_epoch": maybe_epoch_value(
            seed.previous_authority_epoch,
            "no previous lease held this row",
        ),
        "owner_epoch": seed.owner_epoch,
        "generation_id": seed.generation_id,
        "session_epoch": session_value(seed.session_epoch),
        "input_revision": seed.input_revision,
        "failure_reason": seed.failure_reason,
        "bypass_reason": missing(
            "not_applicable",
            "lease transitions never bypass a failed retry",
        ),
        "policy_revision": seed.policy_revision,
        "field_changes": seed.field_changes,
        "failed_generation_charged": seed.failed_generation_charged,
        "commit_authority_revoked": seed.commit_authority_revoked,
        "exhausted": seed.exhausted,
        "limitation": seed.limitation,
    })
}

fn audit_value(
    grant: &GrantFacts,
    event_kind: &str,
    entity_type: &str,
    target: &str,
    job_id: &str,
    lease: &LeaseFacts,
    lease_id: &str,
    occurred_at: &Value,
    idempotency_key: &str,
) -> Value {
    json!({
        "event_kind": event_kind,
        "owner_domain": grant.owner_domain,
        "producer_id": match &grant.producer_id {
            Some(producer) => Value::String(producer.clone()),
            None => missing("not_observed", "grant carries no producer identity"),
        },
        "role": grant.role,
        "provenance": grant.provenance,
        "assertion_kind": grant.assertion_kind,
        "entity_type": entity_type,
        "target": target,
        "job_id": job_id,
        "lease_id": lease_id,
        "issuer": lease.issuer,
        "authority_epoch": lease.authority_epoch,
        "owner": lease.owner,
        "owner_epoch": lease.owner_epoch,
        "generation_id": lease.generation_id,
        "policy_pin": lease.policy_pin,
        "session_epoch": session_value(lease.session_epoch),
        "occurred_at": occurred_at,
        "idempotency_key": idempotency_key,
    })
}

fn idempotency_key(
    grant: &GrantFacts,
    operation: &str,
    entity_type: &str,
    row: &RowFacts,
) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        grant.owner_domain,
        entity_type,
        row.target,
        row.job_id,
        operation,
        row.entity_revision,
        row.lease_id.as_deref().unwrap_or("unleased")
    )
}

#[allow(clippy::too_many_arguments)]
fn transaction_value(
    request: &ParsedRequest,
    grant: &GrantFacts,
    before: &RowFacts,
    held: &LeaseFacts,
    authority_epoch: u64,
    event_kind: &str,
    row: &Value,
    transition: &Value,
    audit: &Value,
    dead_letter: &Value,
) -> Value {
    json!({
        "operation": TRANSACTION_OPERATION,
        "event_kind": event_kind,
        "entity_type": request.entity_type,
        "entity": {"target": before.target, "job_id": before.job_id},
        "owner_domain": grant.owner_domain,
        "producer_id": match &grant.producer_id {
            Some(producer) => Value::String(producer.clone()),
            None => missing("not_observed", "grant carries no producer identity"),
        },
        "expected": {
            "entity_revision": before.entity_revision,
            "input_revision": before.input_revision,
            "lease_id": match &before.lease_id {
                Some(lease_id) => Value::String(lease_id.clone()),
                None => missing("not_applicable", "the row was unleased before this transition"),
            },
            "authority_epoch": authority_epoch,
            "owner_epoch": held.owner_epoch,
            "session_epoch": session_value(held.session_epoch),
        },
        "previous_authority_epoch": match &before.lease_id {
            Some(_) => json!(held.authority_epoch),
            None => missing("not_applicable", "no previous lease held this row"),
        },
        "fenced_authority_epoch": authority_epoch,
        "row": row,
        "transition": transition,
        "audit": audit,
        "dead_letter": dead_letter,
    })
}

fn commit(
    store: &dyn OwnerStore,
    grant: &Grant,
    transaction: Value,
) -> Result<CheckedRecord, Fault> {
    let transaction = validate(OUTPUT_SCHEMA, transaction)?;
    store.transact(grant, &transaction)
}

fn build_result(
    operation: &str,
    entity_type: &str,
    row: Value,
    transition: Value,
    audit: Value,
    dead_letter: Value,
    receipt: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": "lease_transition",
            "operation": operation,
            "entity_type": entity_type,
            "row": row,
            "transition": transition,
            "audit": audit,
            "dead_letter": dead_letter,
            "store_receipt": record_value(receipt).clone(),
        }),
    )
}

fn not_a_reclamation() -> Value {
    missing(
        "not_applicable",
        "only a reclamation can exhaust the retry budget and emit a dead letter",
    )
}

fn dead_letter_value(
    request: &ParsedRequest,
    row: &RowFacts,
    lease: &LeaseFacts,
    reclaim: &ReclaimFacts,
    observed_at: &Value,
    retry_after: u64,
    lease_id: &str,
) -> Value {
    let failure_reason = reclaim
        .recorded_reason()
        .map(|text| Value::String(text.to_string()))
        .unwrap_or_else(|| Value::String(DEFAULT_DEAD_LETTER_REASON.to_string()));
    let partition = match established(&request.row, "partition_id").and_then(Value::as_str) {
        Some(text) if !text.is_empty() => Value::String(text.to_string()),
        _ => missing(
            "not_applicable",
            "the reclaimed row carries no partition lineage",
        ),
    };
    let diagnostic = json!({
        "trigger": reclaim.trigger,
        "failure_reason": failure_reason,
        "retry_count_before": row.retry_count,
        "retry_count_after": retry_after,
        "lease_id": lease_id,
        "generation_id": lease.generation_id,
        "authority_epoch": lease.authority_epoch,
        "observed_at": observed_at,
    });
    json!({
        "target": row.target,
        "entity_type": request.entity_type,
        "entity_id": row.job_id,
        "failure_reason": failure_reason,
        "run_id": row.active_run_id,
        "stage": reclaim.stage,
        "partition_id": partition,
        "retry_count": 1,
        "first_failed_at": observed_at,
        "last_failed_at": observed_at,
        "last_entity_revision": row.entity_revision,
        "last_lease_id": lease_id,
        "diagnostic_json": diagnostic,
        "audit_event_refs": [format!("lease_reclaimed:{lease_id}")],
        "resolution_status": "open",
    })
}

/// Claim a pending row under the authority clock.
///
/// The row must be unleased and pending for its entity type, the authenticated
/// grant must own the assignment, and the retry budget must still be active.
/// The returned row advances `entity_revision` once, keeps `pipeline_state`
/// and `input_revision`, clears `last_failure_reason`, and carries the unique
/// authority-assigned `lease_id` with its authority/owner/session epochs in the
/// same atomic store transaction as the audit evidence.
pub fn claim(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let parsed = ParsedRequest::parse(request, "claim")?;
    let facts = grant_facts(grant)?;
    let row = RowFacts::parse(&parsed.row, &parsed.entity_type)?;
    let lease = LeaseFacts::parse(&parsed.lease, true)?;

    require_pending(&row, &parsed.entity_type, "claim")?;
    require_active_retry_budget(&row, "claim")?;
    if row.lease_id.is_some() {
        return Err(fault(
            "lease_busy",
            "claim refused: the row still holds a lease; an expired or failed generation must be reclaimed first so it is charged exactly once"
                .to_string(),
        ));
    }
    require_authenticated_owner(&lease, &facts)?;
    let ttl_ms = lease.require_ttl("claim")?;

    let now_record = clock.now().map_err(|error| {
        fault(
            error.code.as_str(),
            format!("lease authority clock: {}", error.detail),
        )
    })?;
    let now = NowFields::parse(&now_record)?;
    let deadline = now.issue_deadline(ttl_ms)?;
    match deadline_order(&now_record, &deadline, "claim deadline")? {
        Ordering::Less => {}
        _ => {
            return Err(fault(
                "invalid_ttl",
                "claim deadline must be strictly later than the lease issue".to_string(),
            ))
        }
    }

    let next_revision = advance_revision(row.entity_revision)?;
    let lease_id = fence_token(
        &lease,
        &parsed.entity_type,
        &row.target,
        &row.job_id,
        next_revision,
    );
    let cleared_reason = missing("not_applicable", "claim clears last_failure_reason");
    let row_after = with_updates(
        &parsed.row,
        &[
            ("entity_revision", json!(next_revision)),
            ("lease_id", json!(lease_id)),
            ("lease_owner", json!(lease.owner)),
            ("leased_at", now.value.clone()),
            ("lease_expires_at", deadline.clone()),
            ("last_failure_reason", cleared_reason.clone()),
            ("updated_at", now.value.clone()),
        ],
    );

    let changes = vec![
        change("entity_revision", json!(row.entity_revision), json!(next_revision)),
        lease_field_change("lease_id", None, json!(lease_id)),
        lease_field_change("lease_owner", None, json!(lease.owner)),
        lease_field_change("leased_at", None, now.value.clone()),
        lease_field_change("lease_expires_at", None, deadline.clone()),
        change(
            "last_failure_reason",
            row.last_failure_reason.clone(),
            cleared_reason,
        ),
        change(
            "updated_at",
            original(&parsed.row, "updated_at"),
            now.value.clone(),
        ),
    ];
    let transition = transition_value(TransitionSeed {
        trigger: "claim",
        lease_id: lease_id.clone(),
        authority_epoch: lease.authority_epoch,
        previous_authority_epoch: None,
        owner_epoch: lease.owner_epoch,
        generation_id: lease.generation_id.clone(),
        session_epoch: lease.session_epoch,
        input_revision: row.input_revision,
        failure_reason: missing("not_applicable", "a successful claim records no failure"),
        policy_revision: lease.policy_pin.clone(),
        field_changes: changes,
        failed_generation_charged: false,
        commit_authority_revoked: false,
        exhausted: false,
        limitation: missing("not_applicable", "claim grants ownership; it revokes nothing"),
    });
    let key = idempotency_key(&facts, "claim", &parsed.entity_type, &row);
    let audit = audit_value(
        &facts,
        "lease_claimed",
        &parsed.entity_type,
        &row.target,
        &row.job_id,
        &lease,
        &lease_id,
        &now.value,
        &key,
    );
    let dead_letter = not_a_reclamation();
    let transaction = transaction_value(
        &parsed,
        &facts,
        &row,
        &lease,
        lease.authority_epoch,
        "lease_claimed",
        &row_after,
        &transition,
        &audit,
        &dead_letter,
    );
    let receipt = commit(store, grant, transaction)?;
    build_result(
        "claim",
        &parsed.entity_type,
        row_after,
        transition,
        audit,
        dead_letter,
        &receipt,
    )
}

/// Renew the currently held generation.
///
/// Renewal requires the current token, owner/session/revision fences, and an
/// unexpired authority-clock deadline; it extends the deadline on the same
/// issue clock/boot and advances `entity_revision`. It cannot resurrect an
/// expired lease, and it never rewrites the operational state.
pub fn renew(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let parsed = ParsedRequest::parse(request, "renew")?;
    let facts = grant_facts(grant)?;
    let row = RowFacts::parse(&parsed.row, &parsed.entity_type)?;
    let lease = LeaseFacts::parse(&parsed.lease, false)?;
    let expected = parsed.require_expected()?;
    let ttl_ms = lease.require_ttl("renew")?;

    require_pending(&row, &parsed.entity_type, "renew")?;
    require_active_retry_budget(&row, "renew")?;
    require_current(&row, &lease, &expected, "renewal", false)?;

    let now_record = clock.now().map_err(|error| {
        fault(
            error.code.as_str(),
            format!("lease authority clock: {}", error.detail),
        )
    })?;
    let now = NowFields::parse(&now_record)?;
    let issued = row.leased_at.clone().ok_or_else(|| {
        fault("lease_not_held", "renewal requires the held issue timestamp".to_string())
    })?;
    require_not_before_issue(&now_record, &issued, "renewal")?;
    let held_deadline = row.lease_expires_at.clone().ok_or_else(|| {
        fault("lease_not_held", "renewal requires a held lease deadline".to_string())
    })?;
    match deadline_order(&now_record, &held_deadline, "renewal")? {
        Ordering::Less => {}
        _ => {
            return Err(fault(
                "lease_expired",
                "renewal refused: the authority-clock deadline has been reached; an expired lease is reclaimed, never resurrected"
                    .to_string(),
            ))
        }
    }
    let next_deadline = now.issue_deadline(ttl_ms)?;
    match deadline_order(&now_record, &next_deadline, "renewed deadline")? {
        Ordering::Less => {}
        _ => {
            return Err(fault(
                "invalid_ttl",
                "renewed deadline must be strictly later than the authority reading".to_string(),
            ))
        }
    }
    let next_deadline_record = require_timepoint(&next_deadline, "renewed lease_expires_at")?;
    let held_deadline_record = require_timepoint(&held_deadline, "held lease_expires_at")?;
    match compare_deadline(&next_deadline_record, &held_deadline_record) {
        Ok(Ordering::Greater) => {}
        Ok(_) => {
            return Err(fault(
                "renewal_not_extended",
                "renewal must extend lease_expires_at beyond the current deadline".to_string(),
            ))
        }
        Err(error) => {
            return Err(fault(
                error.code.as_str(),
                format!("renewal deadline: {}", error.detail),
            ))
        }
    }

    let next_revision = advance_revision(row.entity_revision)?;
    let row_after = with_updates(
        &parsed.row,
        &[
            ("entity_revision", json!(next_revision)),
            ("lease_expires_at", next_deadline.clone()),
            ("updated_at", now.value.clone()),
        ],
    );
    let changes = vec![
        change("entity_revision", json!(row.entity_revision), json!(next_revision)),
        change(
            "lease_expires_at",
            held_deadline,
            next_deadline.clone(),
        ),
        change(
            "updated_at",
            original(&parsed.row, "updated_at"),
            now.value.clone(),
        ),
    ];
    let lease_id = lease.lease_id.clone().ok_or_else(|| {
        fault("stale_lease", "renewal requires the held lease token".to_string())
    })?;
    let transition = transition_value(TransitionSeed {
        trigger: "renewal",
        lease_id: lease_id.clone(),
        authority_epoch: lease.authority_epoch,
        previous_authority_epoch: Some(lease.authority_epoch),
        owner_epoch: lease.owner_epoch,
        generation_id: lease.generation_id.clone(),
        session_epoch: lease.session_epoch,
        input_revision: row.input_revision,
        failure_reason: missing("not_applicable", "a successful renewal records no failure"),
        policy_revision: lease.policy_pin.clone(),
        field_changes: changes,
        failed_generation_charged: false,
        commit_authority_revoked: false,
        exhausted: false,
        limitation: missing("not_applicable", "renewal revokes nothing"),
    });
    let key = idempotency_key(&facts, "renew", &parsed.entity_type, &row);
    let audit = audit_value(
        &facts,
        "lease_renewed",
        &parsed.entity_type,
        &row.target,
        &row.job_id,
        &lease,
        &lease_id,
        &now.value,
        &key,
    );
    let dead_letter = not_a_reclamation();
    let transaction = transaction_value(
        &parsed,
        &facts,
        &row,
        &lease,
        lease.authority_epoch,
        "lease_renewed",
        &row_after,
        &transition,
        &audit,
        &dead_letter,
    );
    let receipt = commit(store, grant, transaction)?;
    build_result(
        "renew",
        &parsed.entity_type,
        row_after,
        transition,
        audit,
        dead_letter,
        &receipt,
    )
}

/// Complete the currently held generation.
///
/// Completion requires the current token, epochs, input/entity revisions, and
/// an unexpired authority-clock deadline on the issue clock/boot. A stale,
/// expired, cross-boot, or already-cleared completion returns a fault before
/// any store call, so it has no row, cursor, classifier, membership, or
/// downstream effect. Success releases the lease and advances the revision; it
/// is not a failed retry and never increments `retry_count`.
pub fn complete(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let parsed = ParsedRequest::parse(request, "complete")?;
    let facts = grant_facts(grant)?;
    let row = RowFacts::parse(&parsed.row, &parsed.entity_type)?;
    let lease = LeaseFacts::parse(&parsed.lease, false)?;
    let expected = parsed.require_expected()?;

    require_pending(&row, &parsed.entity_type, "completion")?;
    require_active_retry_budget(&row, "completion")?;
    require_current(&row, &lease, &expected, "completion", false)?;

    let now_record = clock.now().map_err(|error| {
        fault(
            error.code.as_str(),
            format!("lease authority clock: {}", error.detail),
        )
    })?;
    let now = NowFields::parse(&now_record)?;
    let issued = row.leased_at.clone().ok_or_else(|| {
        fault(
            "lease_not_held",
            "completion requires the held issue timestamp".to_string(),
        )
    })?;
    require_not_before_issue(&now_record, &issued, "completion")?;
    let held_deadline = row.lease_expires_at.clone().ok_or_else(|| {
        fault(
            "lease_not_held",
            "completion requires a held lease deadline".to_string(),
        )
    })?;
    match deadline_order(&now_record, &held_deadline, "completion")? {
        Ordering::Less => {}
        _ => {
            return Err(fault(
                "stale_completion",
                "completion refused: the authority-clock deadline has been reached; a stale completion has no entity effect"
                    .to_string(),
            ))
        }
    }

    let next_revision = advance_revision(row.entity_revision)?;
    let lease_cleared = missing("not_applicable", "completion releases ownership");
    let row_after = with_updates(
        &parsed.row,
        &[
            ("entity_revision", json!(next_revision)),
            ("lease_id", lease_cleared.clone()),
            ("lease_owner", lease_cleared.clone()),
            ("leased_at", lease_cleared.clone()),
            ("lease_expires_at", lease_cleared.clone()),
            ("updated_at", now.value.clone()),
        ],
    );
    let changes = vec![
        change("entity_revision", json!(row.entity_revision), json!(next_revision)),
        lease_field_change("lease_id", row.lease_id.as_ref().map(|id| json!(id)), lease_cleared.clone()),
        lease_field_change("lease_owner", row.lease_owner.as_ref().map(|owner| json!(owner)), lease_cleared.clone()),
        lease_field_change("leased_at", row.leased_at.clone(), lease_cleared.clone()),
        lease_field_change(
            "lease_expires_at",
            row.lease_expires_at.clone(),
            lease_cleared.clone(),
        ),
        change(
            "updated_at",
            original(&parsed.row, "updated_at"),
            now.value.clone(),
        ),
    ];
    let lease_id = lease.lease_id.clone().ok_or_else(|| {
        fault("stale_lease", "completion requires the held lease token".to_string())
    })?;
    let transition = transition_value(TransitionSeed {
        trigger: "completion",
        lease_id: lease_id.clone(),
        authority_epoch: lease.authority_epoch,
        previous_authority_epoch: Some(lease.authority_epoch),
        owner_epoch: lease.owner_epoch,
        generation_id: lease.generation_id.clone(),
        session_epoch: lease.session_epoch,
        input_revision: row.input_revision,
        failure_reason: missing(
            "not_applicable",
            "successful completion is not a failed retry",
        ),
        policy_revision: lease.policy_pin.clone(),
        field_changes: changes,
        failed_generation_charged: false,
        commit_authority_revoked: false,
        exhausted: false,
        limitation: missing(
            "not_applicable",
            "completion releases a lease; it does not fence remote execution",
        ),
    });
    let key = idempotency_key(&facts, "complete", &parsed.entity_type, &row);
    let audit = audit_value(
        &facts,
        "lease_completed",
        &parsed.entity_type,
        &row.target,
        &row.job_id,
        &lease,
        &lease_id,
        &now.value,
        &key,
    );
    let dead_letter = not_a_reclamation();
    let transaction = transaction_value(
        &parsed,
        &facts,
        &row,
        &lease,
        lease.authority_epoch,
        "lease_completed",
        &row_after,
        &transition,
        &audit,
        &dead_letter,
    );
    let receipt = commit(store, grant, transaction)?;
    build_result(
        "complete",
        &parsed.entity_type,
        row_after,
        transition,
        audit,
        dead_letter,
        &receipt,
    )
}

/// Reclaim a failed claim generation by release, expiry, or confirmed death.
///
/// Every trigger clears the held ownership and increments `retry_count`
/// exactly once. `release` is the holder's early bookkeeping release; `expiry`
/// requires the authority-clock deadline to have been reached on the same
/// clock/boot; `death_recovery` requires a strictly newer authority epoch that
/// durably fences the old one and deliberately never compares the old
/// deadline with the new boot. If the charge exceeds `max_retries_effective`
/// the row routes to `failed` and one dead-letter occurrence is emitted with
/// the recorded reason or `retry_exhausted`.
///
/// Reclamation revokes local commit authority only. It is not evidence that
/// any remote execution stopped.
pub fn reclaim(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let parsed = ParsedRequest::parse(request, "reclaim")?;
    let facts = grant_facts(grant)?;
    let row = RowFacts::parse(&parsed.row, &parsed.entity_type)?;
    let lease = LeaseFacts::parse(&parsed.lease, false)?;
    let expected = parsed.require_expected()?;
    let reclaim = parsed
        .reclaim
        .as_ref()
        .ok_or_else(|| {
            fault(
                "missing_field",
                "reclaim requires a reclaim object naming its trigger".to_string(),
            )
        })
        .and_then(ReclaimFacts::parse)?;

    require_pending(&row, &parsed.entity_type, "reclamation")?;
    let allow_new_epoch = reclaim.trigger == "death_recovery";
    require_current(&row, &lease, &expected, "reclamation", allow_new_epoch)?;

    let now_record = clock.now().map_err(|error| {
        fault(
            error.code.as_str(),
            format!("lease authority clock: {}", error.detail),
        )
    })?;
    let now = NowFields::parse(&now_record)?;

    match reclaim.trigger.as_str() {
        "release" => {
            // Bookkeeping release by the current holder: same authority clock
            // and boot, never a statement about remote execution.
            let issued = row.leased_at.clone().ok_or_else(|| {
                fault(
                    "lease_not_held",
                    "release requires the held issue timestamp".to_string(),
                )
            })?;
            require_not_before_issue(&now_record, &issued, "release")?;
        }
        "expiry" => {
            let deadline = row.lease_expires_at.clone().ok_or_else(|| {
                fault(
                    "lease_not_held",
                    "expiry reclamation requires the held deadline".to_string(),
                )
            })?;
            match deadline_order(&now_record, &deadline, "expiry reclamation")? {
                Ordering::Greater | Ordering::Equal => {}
                Ordering::Less => {
                    return Err(fault(
                        "lease_unexpired",
                        "expiry reclamation refused: the authority-clock deadline has not been reached"
                            .to_string(),
                    ))
                }
            }
        }
        "death_recovery" => {
            // Never compare the old deadline with the new boot; the newer
            // authority epoch already fenced the old generation above.
        }
        other => {
            return Err(fault(
                "invalid_trigger",
                format!("reclaim trigger {other:?} is not registered"),
            ))
        }
    }

    let retry_after = row.retry_count.checked_add(1).ok_or_else(|| {
        fault(
            "retry_exhausted",
            "the failed-generation counter cannot advance further".to_string(),
        )
    })?;
    let exhausted = retry_after > row.max_retries_effective;
    let failure_reason = if is_missing(&reclaim.failure_reason) {
        missing(
            "not_observed",
            "the reclamation recorded no failure reason for this generation",
        )
    } else {
        reclaim.failure_reason.clone()
    };

    let next_revision = advance_revision(row.entity_revision)?;
    let lease_cleared = missing("not_applicable", "reclamation clears ownership");
    let mut updates: Vec<(&str, Value)> = vec![
        ("entity_revision", json!(next_revision)),
        ("retry_count", json!(retry_after)),
        ("last_failure_reason", failure_reason.clone()),
        ("lease_id", lease_cleared.clone()),
        ("lease_owner", lease_cleared.clone()),
        ("leased_at", lease_cleared.clone()),
        ("lease_expires_at", lease_cleared.clone()),
        ("updated_at", now.value.clone()),
    ];
    if exhausted {
        updates.push(("pipeline_state", json!("failed")));
    }
    let row_after = with_updates(&parsed.row, &updates);

    let lease_id = lease.lease_id.clone().ok_or_else(|| {
        fault("stale_lease", "reclamation requires the held lease token".to_string())
    })?;
    let mut changes = vec![
        change("entity_revision", json!(row.entity_revision), json!(next_revision)),
        change("retry_count", json!(row.retry_count), json!(retry_after)),
        change(
            "last_failure_reason",
            row.last_failure_reason.clone(),
            failure_reason.clone(),
        ),
        lease_field_change("lease_id", row.lease_id.as_ref().map(|id| json!(id)), lease_cleared.clone()),
        lease_field_change("lease_owner", row.lease_owner.as_ref().map(|owner| json!(owner)), lease_cleared.clone()),
        lease_field_change("leased_at", row.leased_at.clone(), lease_cleared.clone()),
        lease_field_change(
            "lease_expires_at",
            row.lease_expires_at.clone(),
            lease_cleared.clone(),
        ),
        change(
            "updated_at",
            original(&parsed.row, "updated_at"),
            now.value.clone(),
        ),
    ];
    if exhausted {
        changes.push(change(
            "pipeline_state",
            json!(row.pipeline_state),
            json!("failed"),
        ));
    }

    let dead_letter = if exhausted {
        dead_letter_value(&parsed, &row, &lease, &reclaim, &now.value, retry_after, &lease_id)
    } else {
        missing(
            "not_applicable",
            "reclamation left retry budget, so no terminal occurrence was recorded",
        )
    };
    let transition = transition_value(TransitionSeed {
        trigger: match reclaim.trigger.as_str() {
            "release" => "release",
            "expiry" => "expiry",
            _ => "death_recovery",
        },
        lease_id: lease_id.clone(),
        authority_epoch: expected.authority_epoch,
        previous_authority_epoch: Some(lease.authority_epoch),
        owner_epoch: lease.owner_epoch,
        generation_id: lease.generation_id.clone(),
        session_epoch: lease.session_epoch,
        input_revision: row.input_revision,
        failure_reason: failure_reason.clone(),
        policy_revision: lease.policy_pin.clone(),
        field_changes: changes,
        failed_generation_charged: true,
        commit_authority_revoked: true,
        exhausted,
        limitation: Value::String(RECLAIM_LIMITATION.to_string()),
    });
    let key = idempotency_key(&facts, "reclaim", &parsed.entity_type, &row);
    let audit = audit_value(
        &facts,
        "lease_reclaimed",
        &parsed.entity_type,
        &row.target,
        &row.job_id,
        &lease,
        &lease_id,
        &now.value,
        &key,
    );
    let transaction = transaction_value(
        &parsed,
        &facts,
        &row,
        &lease,
        expected.authority_epoch,
        "lease_reclaimed",
        &row_after,
        &transition,
        &audit,
        &dead_letter,
    );
    let receipt = commit(store, grant, transaction)?;
    build_result(
        "reclaim",
        &parsed.entity_type,
        row_after,
        transition,
        audit,
        dead_letter,
        &receipt,
    )
}
