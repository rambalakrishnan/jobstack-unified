#![recursion_limit = "256"]

//! `crawler_controls`: scoped connector control with distinct evidence states.
//!
//! [`control`] handles the four control verbs —
//! `RequestNativeCancel`, `CloseObservationConnection`,
//! `ReleaseNativeContext`, and `Contain` — while keeping *request*,
//! *acknowledgement*, *subject stop claim*, and *observed effect* separate.
//! Closing a transport never implies ending observation; ending observation
//! never implies native cancellation; releasing a context never implies
//! containment; containment is never forced termination, rollback, or proof
//! that no remote effect occurred (EXT-CLOSE, EXT-CONTROLS).
//!
//! # Request shape
//!
//! `request` is an `"audit_log"`-wrapped object:
//!
//! * `verb`: one of the four control verbs. Other connector verbs are rejected:
//!   this module is the control seam, not a general connector router.
//! * `operation_id`: nonempty stable idempotency/evidence key.
//! * `connector`, `subject`, `journal_id`: immutable scope. `journal_id` is
//!   ground through the owner-local [`OwnerStore::read`] prefix query, so a
//!   grant can act only on its own journal (EXT-AUTHORITY).
//! * `handle`: `{ "handle_id": ..., "journal_id"?: ..., "subject_id"?: ... }`.
//! * `descriptor`: the exact `connector_descriptor` for this subject version.
//!   Operation mappings are read from its `operations` array. A
//!   `native_mapping` is usable only with an evidenced `native_contract`
//!   (`id` + `version`) and nonempty `evidence_refs`; otherwise it is treated
//!   as an unsupported mapping, which is not native absence (EK-CAPABILITY).
//! * `bounds` (optional): `call_bound_ms`, `drain_bound_ms`,
//!   `cancellation_wait_ms`, `cleanup_wait_ms`. Every bound is a finite local
//!   monotonic value; omission uses the finite defaults below. `0` means
//!   immediate, never absent. The call bound is checked on the registered
//!   clock before the receipt is emitted.
//! * Verb-specific parameters:
//!   - cancel: `reason`;
//!   - close: `reason` (`operator_stop`, `local_deadline`, `normal_completion`)
//!     and mandatory `end_observation`;
//!   - release: `context_ref` (an identity or a reasoned `Missing`);
//!   - contain: `target` (`kind` from the containment scopes plus
//!     `resource_id`), `policy` (`id` + `version`), `affected_attempts`, and
//!     nonempty `unresolved_impact`.
//!
//! Requests may carry `authorization_refs` (support evidence), but never
//! authority facts (`control`, `principal_id`, `owner_domain`, digests) or
//! outcome assertions (`acknowledged`, `effect_refs`, `stop_claim`). Those are
//! rejected as spoofs/assertions rather than believed.
//!
//! # Native response shape
//!
//! [`NativeControls::invoke`] receives the exact operation record (verb,
//! handle, contract pin, capability reference, parameters, immutable evidence
//! prefix, admission reservation, timestamps) and returns a checked record:
//!
//! ```json
//! {
//!   "operation_id": "...",
//!   "outcome": "requested|acknowledged|effect_observed|unsupported|unknown",
//!   "acknowledgement": {"verified": true, "response_ref": <EvidenceRef>},
//!   "subject_claim": {"source": "subject", "claim_ref": <EvidenceRef>},
//!   "effect": {"effect_kind": "...", "effect_refs": [<EvidenceRef>]},
//!   "timing": {"observed_elapsed_ms": 12},
//!   "limitations": ["..."]
//! }
//! ```
//!
//! `acknowledged` requires a verified acknowledgement with a response
//! reference. `effect_observed` requires effect evidence of the matching kind
//! (`native_cancellation`, `observation_closed`, `context_released`, or
//! `containment_applied`). A subject stop claim is evidence about what the
//! subject said; it never upgrades a disposition and never counts as an
//! effect. An outcome that claims acknowledgement or effect without evidence
//! is a fault, not a receipt.
//!
//! # Receipt
//!
//! The returned `control_receipt` keeps an immutable `events` list: the
//! `requested` attempt first, then at most one `acknowledged` event, then at
//! most one `effect_observed` event (or one `unsupported`/`unknown` event).
//! Separate booleans such as `cancel_requested`, `cancel_acknowledged`,
//! `cancel_effect_observed`, `transport_closed`, `observation_ended`,
//! `drain_started`, and `containment_effect_observed` make accidental
//! equivalence impossible. `forced_termination`, `rollback_established`,
//! `no_remote_effect_established`, and `native_absence_established` stay
//! `false` by construction.
//!
//! # Faults
//!
//! `invalid_request`, `missing_verb`, `unknown_control_verb`,
//! `missing_operation_id`, `missing_connector`, `missing_subject`,
//! `missing_journal_id`, `missing_handle`, `missing_handle_id`,
//! `handle_scope_mismatch`, `spoofed_authority_field`,
//! `control_assertion_forbidden`, `control_not_granted`, `verb_not_granted`,
//! `connector_not_granted`, `subject_not_granted`, `missing_descriptor`,
//! `invalid_descriptor`, `stale_descriptor`, `subject_mismatch`,
//! `duplicate_operation_mapping`, `unknown_operation_mapping`,
//! `integrity_conflict`, `implication_forbidden`,
//! `forced_termination_forbidden`, `implicit_effect_forbidden`,
//! `arbitrary_execution_forbidden`, `invalid_bounds`, `invalid_scope`,
//! `scope_mismatch`, `missing_containment_impact`,
//! `invalid_containment_target`, `invalid_context_ref`, `invalid_prefix`,
//! `invalid_native_response`, `unknown_native_outcome`,
//! `unverified_acknowledgement`, `unevidenced_effect`,
//! `effect_scope_mismatch`, `call_bound_exceeded`, plus capability and store
//! faults propagated unchanged. No error path silently reclassifies one
//! control state as another.

use crawler_admission::{Admission, ControlCredit};
use crawler_authority::{grant_record, Grant};
use crawler_capabilities::check_capability;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::HashSet;

/// Structural envelope used for every record produced here.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Receipt discriminator (Contract 02 `ControlReceipt.kind`).
const RECEIPT_KIND: &str = "control_receipt";

const DESCRIPTOR_RECORD_TYPE: &str = "connector_descriptor";

const CLOSE_REASONS: &[&str] = &["operator_stop", "local_deadline", "normal_completion"];

const NATIVE_OUTCOMES: &[&str] = &[
    "requested",
    "acknowledged",
    "effect_observed",
    "unsupported",
    "unknown",
];

const CONTAINMENT_SCOPES: &[&str] = &[
    "fixture_mutation_authority",
    "local_process",
    "deployment_slot",
    "harness_resources",
];

/// Contract 02 shared minimum capability IDs; a control descriptor must
/// enumerate every one for the exact subject scope.
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

const CAPABILITY_AVAILABILITIES: &[&str] = &["present", "absent", "unknown", "not_applicable"];
const CAPABILITY_CLAIM_ORIGINS: &[&str] = &["native", "composed_subject", "harness"];

/// Finite local defaults; a configured bound is never inferred from absence.
const DEFAULT_CALL_BOUND_MS: u64 = 30_000;
const DEFAULT_DRAIN_BOUND_MS: u64 = 30_000;
const DEFAULT_CANCELLATION_WAIT_MS: u64 = 30_000;
const DEFAULT_CLEANUP_WAIT_MS: u64 = 30_000;

/// Fields that only authenticated registration may establish.
const REQUEST_AUTHORITY_FIELDS: &[&str] = &[
    "principal_id",
    "control",
    "owner_domain",
    "registration_digest",
    "grant",
    "grants",
    "producer_id",
    "access_token",
    "bearer_token",
];

/// Fields that would turn a request into a claimed result.
const REQUEST_ASSERTION_FIELDS: &[&str] = &[
    "acknowledged",
    "acknowledgement",
    "effect_observed",
    "effect_refs",
    "effect",
    "stop_claim",
    "subject_claim",
    "response_ref",
    "response_checks",
    "no_remote_effect",
    "rollback",
];

const CLOSE_IMPLICATION_FIELDS: &[&str] = &[
    "cancel",
    "cancel_request",
    "request_native_cancel",
    "release_context",
    "release_native_context",
    "contain",
    "containment",
    "reopen",
    "resume_observation",
    "resume",
];

const CANCEL_FORCED_FIELDS: &[&str] = &[
    "force",
    "forced",
    "forced_termination",
    "terminate",
    "terminate_process",
    "kill",
    "kill_process",
    "sigkill",
    "rollback",
];

const RELEASE_IMPLICATION_FIELDS: &[&str] = &[
    "logout",
    "log_out",
    "purge",
    "purge_profile",
    "global_reset",
    "reset_all",
    "contain",
    "containment",
    "terminate",
    "force",
];

const EXECUTION_FIELDS: &[&str] = &[
    "command",
    "shell",
    "script",
    "executable",
    "code",
    "argv",
    "args",
    "pid",
    "kill",
    "sigkill",
    "terminate",
];

// ---------------------------------------------------------------------------
// Public seam
// ---------------------------------------------------------------------------

/// Native control endpoint invoked by [`control`].
///
/// Implementations receive only an already authorized, descriptor-mapped
/// operation record. They must not invent a mapping, must not treat an absent
/// mapping as native absence, and must report acknowledgement and effect
/// evidence separately.
pub trait NativeControls: Send + Sync {
    fn invoke(&self, grant: &Grant, operation: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

/// Perform one scoped control operation.
///
/// The request is authorized against the grant's authenticated channel
/// registration, its descriptor pin and operation mapping are checked, the
/// target journal prefix is read through the owner store, independent control
/// capacity is reserved from [`Admission`], and a single native invocation is
/// made only for a supported mapping. See the module documentation for the
/// exact request, response, and receipt shapes.
pub fn control(
    store: &dyn OwnerStore,
    clock: &dyn ClockAuthority,
    admission: &dyn Admission,
    native: &dyn NativeControls,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = as_object(request, "invalid_request", "control request")?;
    reject_established(
        req,
        REQUEST_AUTHORITY_FIELDS,
        "spoofed_authority_field",
        "control request",
    )?;
    reject_established(
        req,
        REQUEST_ASSERTION_FIELDS,
        "control_assertion_forbidden",
        "control request",
    )?;

    let verb_text = required_str(req, "verb", "missing_verb", "control request")?;
    let verb = ControlVerb::parse(verb_text)?;
    let operation_id = required_str(
        req,
        "operation_id",
        "missing_operation_id",
        "control request",
    )?;
    let connector = required_str(req, "connector", "missing_connector", "control request")?;
    let subject = required_str(req, "subject", "missing_subject", "control request")?;
    let journal_id = required_str(req, "journal_id", "missing_journal_id", "control request")?;

    let handle = required_object(req, "handle", "missing_handle", "control request")?.clone();
    let handle_id = required_str(&handle, "handle_id", "missing_handle_id", "handle")?;
    if let Some(handle_journal) = established(&handle, "journal_id").and_then(Value::as_str) {
        if handle_journal != journal_id {
            return Err(fault(
                "handle_scope_mismatch",
                format!(
                    "handle journal {handle_journal:?} does not match request journal {journal_id:?}"
                ),
            ));
        }
    }
    if let Some(handle_subject) = established(&handle, "subject_id").and_then(Value::as_str) {
        if handle_subject != subject {
            return Err(fault(
                "handle_scope_mismatch",
                format!(
                    "handle subject {handle_subject:?} does not match request subject {subject:?}"
                ),
            ));
        }
    }

    let authorization =
        authorize_control(grant, verb_text, connector, subject, req)?;
    reject_verb_implications(req, verb)?;

    // ---- descriptor pin + operation mapping ----
    let descriptor_value = match req.get("descriptor").filter(|value| !is_missing(value)) {
        Some(Value::Object(_)) => req["descriptor"].clone(),
        _ => {
            return Err(fault(
                "missing_descriptor",
                "a control request requires the exact connector descriptor; an absent descriptor is not native absence"
                    .to_string(),
            ))
        }
    };
    let descriptor = validate(OUTPUT_SCHEMA, descriptor_value)?;
    validate_descriptor_pin(&descriptor, connector, subject)?;
    let scope_value = descriptor_scope(&descriptor, req)?;
    let scope_record = validate(OUTPUT_SCHEMA, scope_value)?;

    let capability = match verb.capability_id() {
        Some(capability_id) => Some(check_capability(
            &descriptor,
            capability_id,
            &scope_record,
        )?),
        None => None,
    };
    if let Some(capability_record) = &capability {
        let availability = record_value(capability_record)
            .get("availability")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if availability == "absent" || availability == "not_applicable" {
            let capability_id = verb.capability_id().unwrap_or("unknown");
            return Err(fault(
                "integrity_conflict",
                format!(
                    "capability {capability_id:?} is declared {availability:?} with evidence while the descriptor also claims a native mapping; the declaration cannot be both"
                ),
            ));
        }
    }
    let mapping = operation_mapping(&descriptor, verb)?;

    let parameters = verb_parameters(req, verb)?;
    let bounds = parse_bounds(req)?;
    let close_end_observation = parameters_end_observation(verb, req)?;
    let prefix = ground_prefix(store, grant, journal_id)?;
    let target_scope = resolve_target_scope(req, verb, &parameters)?;

    let capability_value = capability
        .map(|record| record_value(&record).clone())
        .unwrap_or_else(|| {
            missing(
                "not_applicable",
                "this control verb has no matching capability catalog entry",
            )
        });
    let affected_attempts = parameters
        .get("affected_attempts")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let unresolved_impact = parameters
        .get("unresolved_impact")
        .cloned()
        .unwrap_or_else(|| json!([]));

    // ---- unsupported mapping: handled, never invoked, never called absence ----
    if !mapping.supported {
        let requested_at = clock.now()?;
        let requested_value = record_value(&requested_at).clone();
        let observed_at = clock.now()?;
        let observed_value = record_value(&observed_at).clone();
        let mut limitations = mapping.limitations.clone();
        if limitations.is_empty() {
            limitations.push(Value::String(
                "unsupported mapping is not native absence".to_string(),
            ));
        }
        let request_ref = missing(
            "not_observed",
            "this control attempt was not journaled; the receipt event is the request evidence",
        );
        let events = vec![
            json!({
                "control_event_id": format!("{operation_id}:requested"),
                "disposition": "requested",
                "at": requested_value,
                "request_ref": request_ref,
            }),
            json!({
                "control_event_id": format!("{operation_id}:unsupported"),
                "disposition": "unsupported",
                "at": observed_value,
                "native_invoked": false,
                "limitations": limitations,
            }),
        ];
        let call_deadline = add_bound(&requested_at, bounds.call_bound_ms)?;
        let drain_deadline = add_bound(&requested_at, bounds.drain_bound_ms)?;
        let cancellation_deadline = add_bound(&requested_at, bounds.cancellation_wait_ms)?;
        let cleanup_deadline = add_bound(&requested_at, bounds.cleanup_wait_ms)?;
        return build_receipt(ReceiptInput {
            verb,
            operation_id: operation_id.to_string(),
            connector: connector.to_string(),
            subject: subject.to_string(),
            handle,
            target_scope,
            authorization,
            capability: capability_value,
            mapping,
            parameters,
            bounds,
            prefix,
            requested_at: requested_value,
            observed_at: observed_value,
            events,
            disposition: "unsupported",
            acknowledgement: missing(
                "not_observed",
                "no native acknowledgement exists for an unsupported mapping",
            ),
            response_ref: missing(
                "not_observed",
                "no native response exists for an unsupported mapping",
            ),
            subject_claim: missing("not_observed", "no subject claim was reported"),
            effect: missing("not_observed", "no effect evidence was observed"),
            has_ack: false,
            has_effect: false,
            stop_claim_recorded: false,
            invoked: false,
            elapsed_ms: missing("not_observed", "no native call was made"),
            native_elapsed_ms: missing("not_observed", "no native call was made"),
            call_deadline: record_value(&call_deadline).clone(),
            drain_deadline: record_value(&drain_deadline).clone(),
            cancellation_deadline: record_value(&cancellation_deadline).clone(),
            cleanup_deadline: record_value(&cleanup_deadline).clone(),
            limitations,
            affected_attempts,
            unresolved_impact,
            end_observation: close_end_observation,
        });
    }

    // ---- credit-before-wire, then the single native invocation ----
    let admission_scope = validate(
        OUTPUT_SCHEMA,
        json!({"request_id": operation_id, "target": handle_id}),
    )?;
    let credit: ControlCredit = admission.reserve_control(&admission_scope)?;
    let admission_deadline = record_value(&credit.reservation)
        .get("deadline")
        .cloned();

    let started = clock.now()?;
    let started_value = record_value(&started).clone();
    let call_deadline = add_bound(&started, bounds.call_bound_ms)?;
    let drain_deadline = add_bound(&started, bounds.drain_bound_ms)?;
    let cancellation_deadline = add_bound(&started, bounds.cancellation_wait_ms)?;
    let cleanup_deadline = add_bound(&started, bounds.cleanup_wait_ms)?;
    let request_ref = missing(
        "not_observed",
        "this control attempt was not journaled; the receipt event is the request evidence",
    );

    let native_operation = validate(
        OUTPUT_SCHEMA,
        json!({
            "operation_id": operation_id,
            "verb": verb.as_str(),
            "connector": connector,
            "subject": subject,
            "journal_id": journal_id,
            "handle": handle,
            "target_scope": target_scope,
            "native_contract": mapping.native_contract.clone(),
            "capability_ref": capability_value,
            "parameters": parameters,
            "bounds": bounds.to_json(),
            "evidence_prefix": prefix,
            "authorization": authorization,
            "requested_at": started_value,
            "admission_reservation": record_value(&credit.reservation).clone(),
        }),
    )?;

    let response = native.invoke(grant, &native_operation)?;
    drop(credit);

    let finished = clock.now()?;
    let finished_value = record_value(&finished).clone();
    if compare_deadline(&finished, &call_deadline)? == Ordering::Greater {
        return Err(fault(
            "call_bound_exceeded",
            format!(
                "native control call exceeded its declared local bound of {} ms; the bound is not raised and the response is not acknowledged",
                bounds.call_bound_ms
            ),
        ));
    }
    if let Some(deadline_value) = admission_deadline {
        let reservation_deadline = validate(OUTPUT_SCHEMA, deadline_value)?;
        if compare_deadline(&finished, &reservation_deadline)? == Ordering::Greater {
            return Err(fault(
                "call_bound_exceeded",
                "native control call exceeded the admission reservation deadline; the reserved bound is never raised"
                    .to_string(),
            ));
        }
    }
    let elapsed_ms = elapsed_between(&started, &finished)?;
    let outcome = interpret_native_response(&response, operation_id, verb)?;

    let mut events = vec![json!({
        "control_event_id": format!("{operation_id}:requested"),
        "disposition": "requested",
        "at": started_value,
        "request_ref": request_ref,
    })];
    if outcome.has_ack {
        events.push(json!({
            "control_event_id": format!("{operation_id}:acknowledged"),
            "disposition": "acknowledged",
            "at": finished_value,
            "response_ref": outcome.response_ref,
            "acknowledgement": outcome.acknowledgement,
            "subject_claim": outcome.subject_claim,
        }));
    }
    if outcome.has_effect {
        events.push(json!({
            "control_event_id": format!("{operation_id}:effect-observed"),
            "disposition": "effect_observed",
            "at": finished_value,
            "effect": outcome.effect,
            "subject_claim": outcome.subject_claim,
        }));
    }
    if !outcome.has_ack && !outcome.has_effect && outcome.disposition != "requested" {
        events.push(json!({
            "control_event_id": format!("{operation_id}:{}", outcome.disposition),
            "disposition": outcome.disposition,
            "at": finished_value,
            "subject_claim": outcome.subject_claim,
            "limitations": outcome.limitations,
        }));
    }

    let mut limitations = mapping.limitations.clone();
    limitations.extend(outcome.limitations.iter().cloned());

    build_receipt(ReceiptInput {
        verb,
        operation_id: operation_id.to_string(),
        connector: connector.to_string(),
        subject: subject.to_string(),
        handle: handle.clone(),
        target_scope,
        authorization,
        capability: capability_value,
        mapping,
        parameters: parameters.clone(),
        bounds,
        prefix,
        requested_at: started_value,
        observed_at: finished_value,
        events,
        disposition: outcome.disposition,
        acknowledgement: outcome.acknowledgement,
        response_ref: outcome.response_ref,
        subject_claim: outcome.subject_claim,
        effect: outcome.effect,
        has_ack: outcome.has_ack,
        has_effect: outcome.has_effect,
        stop_claim_recorded: outcome.stop_claim_recorded,
        invoked: true,
        elapsed_ms: json!(elapsed_ms),
        native_elapsed_ms: outcome.native_elapsed_ms,
        call_deadline: record_value(&call_deadline).clone(),
        drain_deadline: record_value(&drain_deadline).clone(),
        cancellation_deadline: record_value(&cancellation_deadline).clone(),
        cleanup_deadline: record_value(&cleanup_deadline).clone(),
        limitations,
        affected_attempts,
        unresolved_impact,
        end_observation: close_end_observation,
    })
}

// ---------------------------------------------------------------------------
// Verb vocabulary
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlVerb {
    RequestNativeCancel,
    CloseObservationConnection,
    ReleaseNativeContext,
    Contain,
}

impl ControlVerb {
    fn parse(text: &str) -> Result<Self, Fault> {
        match text {
            "RequestNativeCancel" => Ok(ControlVerb::RequestNativeCancel),
            "CloseObservationConnection" => Ok(ControlVerb::CloseObservationConnection),
            "ReleaseNativeContext" => Ok(ControlVerb::ReleaseNativeContext),
            "Contain" => Ok(ControlVerb::Contain),
            other => Err(fault(
                "unknown_control_verb",
                format!(
                    "verb {other:?} is not a control verb; expected RequestNativeCancel, CloseObservationConnection, ReleaseNativeContext, or Contain"
                ),
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            ControlVerb::RequestNativeCancel => "RequestNativeCancel",
            ControlVerb::CloseObservationConnection => "CloseObservationConnection",
            ControlVerb::ReleaseNativeContext => "ReleaseNativeContext",
            ControlVerb::Contain => "Contain",
        }
    }

    fn capability_id(self) -> Option<&'static str> {
        match self {
            ControlVerb::RequestNativeCancel => Some("native_cancel"),
            ControlVerb::ReleaseNativeContext => Some("native_context_release"),
            ControlVerb::CloseObservationConnection | ControlVerb::Contain => None,
        }
    }

    fn expected_effect_kind(self) -> &'static str {
        match self {
            ControlVerb::RequestNativeCancel => "native_cancellation",
            ControlVerb::CloseObservationConnection => "observation_closed",
            ControlVerb::ReleaseNativeContext => "context_released",
            ControlVerb::Contain => "containment_applied",
        }
    }
}

// ---------------------------------------------------------------------------
// Internal input/outcome records
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct Bounds {
    call_bound_ms: u64,
    drain_bound_ms: u64,
    cancellation_wait_ms: u64,
    cleanup_wait_ms: u64,
}

impl Bounds {
    fn to_json(self) -> Value {
        json!({
            "call_bound_ms": self.call_bound_ms,
            "drain_bound_ms": self.drain_bound_ms,
            "cancellation_wait_ms": self.cancellation_wait_ms,
            "cleanup_wait_ms": self.cleanup_wait_ms,
        })
    }
}

#[derive(Debug, Clone)]
struct OperationMapping {
    declared: bool,
    implementation: String,
    native_contract: Value,
    evidence_refs: Value,
    limitations: Vec<Value>,
    supported: bool,
}

impl OperationMapping {
    fn to_json(&self) -> Value {
        json!({
            "declared": self.declared,
            "implementation": self.implementation,
            "native_contract": self.native_contract,
            "evidence_refs": self.evidence_refs,
            "supported": self.supported,
            "limitations": self.limitations,
        })
    }
}

struct NativeOutcome {
    disposition: &'static str,
    acknowledgement: Value,
    response_ref: Value,
    subject_claim: Value,
    effect: Value,
    has_ack: bool,
    has_effect: bool,
    stop_claim_recorded: bool,
    native_elapsed_ms: Value,
    limitations: Vec<Value>,
}

struct ReceiptInput {
    verb: ControlVerb,
    operation_id: String,
    connector: String,
    subject: String,
    handle: Map<String, Value>,
    target_scope: String,
    authorization: Value,
    capability: Value,
    mapping: OperationMapping,
    parameters: Value,
    bounds: Bounds,
    prefix: Value,
    requested_at: Value,
    observed_at: Value,
    events: Vec<Value>,
    disposition: &'static str,
    acknowledgement: Value,
    response_ref: Value,
    subject_claim: Value,
    effect: Value,
    has_ack: bool,
    has_effect: bool,
    stop_claim_recorded: bool,
    invoked: bool,
    elapsed_ms: Value,
    native_elapsed_ms: Value,
    call_deadline: Value,
    drain_deadline: Value,
    cancellation_deadline: Value,
    cleanup_deadline: Value,
    limitations: Vec<Value>,
    affected_attempts: Value,
    unresolved_impact: Value,
    end_observation: bool,
}

// ---------------------------------------------------------------------------
// Authorization and request-shape gates
// ---------------------------------------------------------------------------

fn authorize_control(
    grant: &Grant,
    verb: &str,
    connector: &str,
    subject: &str,
    request: &Map<String, Value>,
) -> Result<Value, Fault> {
    let grant_map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let control = required_bool(grant_map, "control", "invalid_grant", "grant")?;
    if !control {
        return Err(fault(
            "control_not_granted",
            format!(
                "control verb {verb:?} requires an explicit control grant; credentials, digests, and identifiers are not bearer authority"
            ),
        ));
    }
    let grant_verb = required_str(grant_map, "verb", "invalid_grant", "grant")?;
    if grant_verb != verb {
        return Err(fault(
            "verb_not_granted",
            format!("grant verb {grant_verb:?} does not authorize control verb {verb:?}"),
        ));
    }
    let grant_connector = required_str(grant_map, "connector", "invalid_grant", "grant")?;
    if grant_connector != connector {
        return Err(fault(
            "connector_not_granted",
            format!(
                "grant connector {grant_connector:?} does not authorize connector {connector:?}"
            ),
        ));
    }
    let grant_subject = required_str(grant_map, "subject", "subject_not_granted", "grant")?;
    if grant_subject != subject {
        return Err(fault(
            "subject_not_granted",
            format!(
                "grant subject {grant_subject:?} does not authorize control target {subject:?}"
            ),
        ));
    }
    let principal_id = required_str(grant_map, "principal_id", "invalid_grant", "grant")?;
    let owner_domain = required_str(grant_map, "owner_domain", "invalid_grant", "grant")?;
    let registration_digest =
        required_str(grant_map, "registration_digest", "invalid_grant", "grant")?;
    let restricted_access = match established(grant_map, "restricted_access") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(fault(
                "invalid_grant",
                "grant restricted_access must be a boolean".to_string(),
            ))
        }
    };
    let authorization_refs = match established(request, "authorization_refs") {
        None => json!([]),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                check_evidence_ref(
                    item,
                    &format!("authorization_refs[{index}]"),
                    "invalid_request",
                )?;
            }
            Value::Array(items.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_request",
                "authorization_refs must be an array of evidence references".to_string(),
            ))
        }
    };
    Ok(json!({
        "principal_id": principal_id,
        "grant_verb": grant_verb,
        "control": control,
        "owner_domain": owner_domain,
        "restricted_access": restricted_access,
        "registration_digest": registration_digest,
        "authorization_refs": authorization_refs,
    }))
}

fn reject_verb_implications(map: &Map<String, Value>, verb: ControlVerb) -> Result<(), Fault> {
    let (fields, code, message): (&[&str], &str, &str) = match verb {
        ControlVerb::RequestNativeCancel => (
            CANCEL_FORCED_FIELDS,
            "forced_termination_forbidden",
            "native cancellation is cooperative; forced termination, kill, or rollback fields are forbidden",
        ),
        ControlVerb::CloseObservationConnection => (
            CLOSE_IMPLICATION_FIELDS,
            "implication_forbidden",
            "closing an observation transport must not carry cancel, release, containment, or reopen instructions",
        ),
        ControlVerb::ReleaseNativeContext => (
            RELEASE_IMPLICATION_FIELDS,
            "implicit_effect_forbidden",
            "native context release must not imply logout, profile purge, global reset, containment, or termination",
        ),
        ControlVerb::Contain => (
            EXECUTION_FIELDS,
            "arbitrary_execution_forbidden",
            "containment accepts an installed versioned policy and authorized resource identity, never an arbitrary command or PID",
        ),
    };
    reject_established(map, fields, code, message)
}

fn verb_parameters(request: &Map<String, Value>, verb: ControlVerb) -> Result<Value, Fault> {
    match verb {
        ControlVerb::RequestNativeCancel => {
            let reason = required_str(request, "reason", "invalid_request", "cancel request")?;
            Ok(json!({"kind": "cooperative_cancel", "reason": reason}))
        }
        ControlVerb::CloseObservationConnection => {
            let reason = required_str(request, "reason", "invalid_request", "close request")?;
            if !CLOSE_REASONS.contains(&reason) {
                return Err(fault(
                    "invalid_request",
                    format!("close reason {reason:?} must be operator_stop, local_deadline, or normal_completion"),
                ));
            }
            let end_observation =
                required_bool(request, "end_observation", "invalid_request", "close request")?;
            Ok(json!({"reason": reason, "end_observation": end_observation}))
        }
        ControlVerb::ReleaseNativeContext => {
            let context_ref = request.get("context_ref").ok_or_else(|| {
                fault(
                    "invalid_context_ref",
                    "release requires a context_ref identity or a reasoned Missing envelope"
                        .to_string(),
                )
            })?;
            if !is_missing(context_ref) {
                match context_ref {
                    Value::String(text) if !text.is_empty() => {}
                    _ => {
                        return Err(fault(
                            "invalid_context_ref",
                            "context_ref must be a nonempty string or a reasoned Missing envelope"
                                .to_string(),
                        ))
                    }
                }
            }
            Ok(json!({"context_ref": context_ref}))
        }
        ControlVerb::Contain => {
            let reason = required_str(request, "reason", "invalid_request", "contain request")?;
            let target = required_object(request, "target", "invalid_containment_target", "contain request")?
                .clone();
            reject_established(
                &target,
                EXECUTION_FIELDS,
                "arbitrary_execution_forbidden",
                "containment target",
            )?;
            let kind = required_str(
                &target,
                "kind",
                "invalid_containment_target",
                "containment target",
            )?;
            if !CONTAINMENT_SCOPES.contains(&kind) {
                return Err(fault(
                    "invalid_containment_target",
                    format!(
                        "containment target kind {kind:?} is not an authorized resource-registry scope"
                    ),
                ));
            }
            let resource_id = required_str(
                &target,
                "resource_id",
                "invalid_containment_target",
                "containment target",
            )?;

            let policy = required_object(request, "policy", "invalid_containment_policy", "contain request")?
                .clone();
            reject_established(
                &policy,
                EXECUTION_FIELDS,
                "arbitrary_execution_forbidden",
                "containment policy",
            )?;
            let policy_id =
                required_str(&policy, "id", "invalid_containment_policy", "policy")?;
            let policy_version =
                required_str(&policy, "version", "invalid_containment_policy", "policy")?;

            let attempts = required_array(
                request,
                "affected_attempts",
                "missing_containment_impact",
                "contain request",
            )?;
            for (index, attempt) in attempts.iter().enumerate() {
                let entry = attempt.as_object().ok_or_else(|| {
                    fault(
                        "missing_containment_impact",
                        format!("affected_attempts[{index}] must be an attempt reference object"),
                    )
                })?;
                if entry.is_empty() {
                    return Err(fault(
                        "missing_containment_impact",
                        format!("affected_attempts[{index}] must identify affected work"),
                    ));
                }
            }
            let unresolved = required_array(
                request,
                "unresolved_impact",
                "missing_containment_impact",
                "contain request",
            )?;
            if unresolved.is_empty() {
                return Err(fault(
                    "missing_containment_impact",
                    "contain must record unresolved impact; an empty list would hide it"
                        .to_string(),
                ));
            }
            for (index, item) in unresolved.iter().enumerate() {
                match item {
                    Value::String(text) if !text.is_empty() => {}
                    _ => {
                        return Err(fault(
                            "missing_containment_impact",
                            format!("unresolved_impact[{index}] must be a nonempty string"),
                        ))
                    }
                }
            }
            Ok(json!({
                "reason": reason,
                "target": {"kind": kind, "resource_id": resource_id},
                "policy": {"id": policy_id, "version": policy_version},
                "affected_attempts": attempts,
                "unresolved_impact": unresolved,
            }))
        }
    }
}

fn parameters_end_observation(
    verb: ControlVerb,
    request: &Map<String, Value>,
) -> Result<bool, Fault> {
    if verb != ControlVerb::CloseObservationConnection {
        if established(request, "end_observation").is_some() {
            return Err(fault(
                "invalid_request",
                "end_observation belongs only to CloseObservationConnection; other control verbs must not carry it"
                    .to_string(),
            ));
        }
        return Ok(false);
    }
    required_bool(request, "end_observation", "invalid_request", "close request")
}

fn parse_bounds(request: &Map<String, Value>) -> Result<Bounds, Fault> {
    match established(request, "bounds") {
        None => Ok(Bounds {
            call_bound_ms: DEFAULT_CALL_BOUND_MS,
            drain_bound_ms: DEFAULT_DRAIN_BOUND_MS,
            cancellation_wait_ms: DEFAULT_CANCELLATION_WAIT_MS,
            cleanup_wait_ms: DEFAULT_CLEANUP_WAIT_MS,
        }),
        Some(Value::Object(bounds)) => Ok(Bounds {
            call_bound_ms: required_u64(bounds, "call_bound_ms", "invalid_bounds", "bounds")?,
            drain_bound_ms: required_u64(bounds, "drain_bound_ms", "invalid_bounds", "bounds")?,
            cancellation_wait_ms: required_u64(
                bounds,
                "cancellation_wait_ms",
                "invalid_bounds",
                "bounds",
            )?,
            cleanup_wait_ms: required_u64(
                bounds,
                "cleanup_wait_ms",
                "invalid_bounds",
                "bounds",
            )?,
        }),
        Some(_) => Err(fault(
            "invalid_bounds",
            "bounds must be an object carrying all four finite local bounds".to_string(),
        )),
    }
}

fn resolve_target_scope(
    request: &Map<String, Value>,
    verb: ControlVerb,
    parameters: &Value,
) -> Result<String, Fault> {
    let fixed = match verb {
        ControlVerb::RequestNativeCancel => Some("native_execution"),
        ControlVerb::CloseObservationConnection => Some("observation_connection"),
        ControlVerb::ReleaseNativeContext => Some("native_context"),
        ControlVerb::Contain => None,
    };
    let derived = match fixed {
        Some(scope) => scope.to_string(),
        None => parameters
            .get("target")
            .and_then(|target| target.get("kind"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                fault(
                    "invalid_containment_target",
                    "containment target kind is required for target scope".to_string(),
                )
            })?
            .to_string(),
    };
    if let Some(claimed) = established(request, "target_scope") {
        match claimed {
            Value::String(text) if text == &derived => {}
            Value::String(text) => {
                return Err(fault(
                    "scope_mismatch",
                    format!(
                        "request target_scope {text:?} does not match the {derived:?} scope implied by the control operation"
                    ),
                ))
            }
            _ => {
                return Err(fault(
                    "invalid_scope",
                    "target_scope must be a nonempty string when present".to_string(),
                ))
            }
        }
    }
    Ok(derived)
}

fn ground_prefix(
    store: &dyn OwnerStore,
    grant: &Grant,
    journal_id: &str,
) -> Result<Value, Fault> {
    let query = validate(
        OUTPUT_SCHEMA,
        json!({"query": "prefix", "journal_id": journal_id}),
    )?;
    let prefix = store.read(grant, &query)?;
    let map = as_object(&prefix, "invalid_prefix", "store prefix")?;
    let prefix_journal = required_str(map, "journal_id", "invalid_prefix", "store prefix")?;
    if prefix_journal != journal_id {
        return Err(fault(
            "invalid_prefix",
            format!(
                "store prefix journal {prefix_journal:?} does not match requested journal {journal_id:?}"
            ),
        ));
    }
    let last_sequence = required_u64(map, "last_sequence", "invalid_prefix", "store prefix")?;
    let head_hash = required_str(map, "head_hash", "invalid_prefix", "store prefix")?;
    Ok(json!({
        "journal_id": prefix_journal,
        "last_sequence": last_sequence,
        "head_hash": head_hash,
    }))
}

fn validate_descriptor_pin(
    descriptor: &CheckedRecord,
    connector: &str,
    subject: &str,
) -> Result<(), Fault> {
    let map = as_object(descriptor, "invalid_descriptor", "descriptor")?;
    match established(map, "record_type") {
        Some(Value::String(record_type)) if record_type == DESCRIPTOR_RECORD_TYPE => {}
        _ => {
            return Err(fault(
                "invalid_descriptor",
                format!("descriptor record_type must be exactly {DESCRIPTOR_RECORD_TYPE:?}"),
            ))
        }
    }
    let descriptor_connector = required_str(map, "connector_id", "invalid_descriptor", "descriptor")?;
    if descriptor_connector != connector {
        return Err(fault(
            "stale_descriptor",
            format!(
                "descriptor connector {descriptor_connector:?} does not match control connector {connector:?}"
            ),
        ));
    }
    let desc_subject = required_object(map, "subject", "invalid_descriptor", "descriptor")?;
    let desc_subject_id = required_str(desc_subject, "subject_id", "invalid_descriptor", "subject")?;
    if desc_subject_id != subject {
        return Err(fault(
            "subject_mismatch",
            format!(
                "descriptor subject {desc_subject_id:?} does not match control subject {subject:?}"
            ),
        ));
    }
    for field in ["subject_version", "configured_mode", "interface_surface"] {
        required_str(desc_subject, field, "invalid_descriptor", "subject")?;
    }
    let capabilities = required_object(map, "capabilities", "invalid_descriptor", "descriptor")?;
    let catalog = required_array(
        capabilities,
        "capabilities",
        "invalid_descriptor",
        "descriptor capabilities",
    )?;
    let mut seen = HashSet::new();
    for (index, entry) in catalog.iter().enumerate() {
        let entry = entry.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                format!("descriptor capabilities[{index}] must be an object"),
            )
        })?;
        let capability_id = required_str(
            entry,
            "capability_id",
            "invalid_descriptor",
            "descriptor capability",
        )?;
        if !seen.insert(capability_id.to_string()) {
            return Err(fault(
                "invalid_descriptor",
                format!("capability {capability_id:?} appears more than once in the descriptor"),
            ));
        }
        match established(entry, "availability") {
            Some(Value::String(value)) if CAPABILITY_AVAILABILITIES.contains(&value.as_str()) => {}
            _ => {
                return Err(fault(
                    "invalid_descriptor",
                    format!(
                        "capability {capability_id:?} requires an availability from the closed set"
                    ),
                ))
            }
        }
        match established(entry, "claim_origin") {
            Some(Value::String(value)) if CAPABILITY_CLAIM_ORIGINS.contains(&value.as_str()) => {}
            _ => {
                return Err(fault(
                    "invalid_descriptor",
                    format!(
                        "capability {capability_id:?} requires a claim_origin from the closed set"
                    ),
                ))
            }
        }
    }
    for minimum in MINIMUM_CAPABILITY_IDS {
        if !seen.contains(*minimum) {
            return Err(fault(
                "incomplete_catalog",
                format!(
                    "descriptor omits required capability {minimum:?}; omission implies neither presence nor absence"
                ),
            ));
        }
    }
    if let Some(Value::Object(cap_subject)) = established(capabilities, "subject") {
        for field in ["subject_id", "subject_version", "configured_mode", "interface_surface"] {
            if established(cap_subject, field).and_then(Value::as_str)
                != established(desc_subject, field).and_then(Value::as_str)
            {
                return Err(fault(
                    "subject_mismatch",
                    "descriptor subject and capabilities.subject must be the same exact pin"
                        .to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn descriptor_scope(
    descriptor: &CheckedRecord,
    request: &Map<String, Value>,
) -> Result<Value, Fault> {
    let map = as_object(descriptor, "invalid_descriptor", "descriptor")?;
    let subject = required_object(map, "subject", "invalid_descriptor", "descriptor")?;
    let mut scope = json!({
        "subject_id": required_str(subject, "subject_id", "invalid_descriptor", "subject")?,
        "subject_version": required_str(subject, "subject_version", "invalid_descriptor", "subject")?,
        "configured_mode": required_str(subject, "configured_mode", "invalid_descriptor", "subject")?,
        "interface_surface": required_str(subject, "interface_surface", "invalid_descriptor", "subject")?,
    });
    if let Some(digest) = established(request, "descriptor_digest") {
        match digest {
            Value::String(text) if !text.is_empty() => {
                scope["descriptor_digest"] = Value::String(text.clone());
            }
            _ => {
                return Err(fault(
                    "invalid_expected_digest",
                    "descriptor_digest must be a nonempty string when present".to_string(),
                ))
            }
        }
    }
    Ok(scope)
}

fn operation_mapping(
    descriptor: &CheckedRecord,
    verb: ControlVerb,
) -> Result<OperationMapping, Fault> {
    let map = as_object(descriptor, "invalid_descriptor", "descriptor")?;
    let entries = match map.get("operations") {
        None => {
            return Ok(OperationMapping {
                declared: false,
                implementation: "unmapped".to_string(),
                native_contract: missing(
                    "not_observed",
                    "descriptor declares no operation mappings",
                ),
                evidence_refs: json!([]),
                limitations: vec![Value::String(
                    "operation mapping is absent from the descriptor; omission is not evidenced native absence"
                        .to_string(),
                )],
                supported: false,
            })
        }
        Some(value) if is_missing(value) => {
            return Ok(OperationMapping {
                declared: false,
                implementation: "unmapped".to_string(),
                native_contract: missing(
                    "not_observed",
                    "descriptor claims no operation mapping for this verb",
                ),
                evidence_refs: json!([]),
                limitations: vec![Value::String(
                    "operation mapping is missing from the descriptor; missingness is not native absence"
                        .to_string(),
                )],
                supported: false,
            })
        }
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                "descriptor operations must be an array".to_string(),
            ))
        }
    };

    let mut found: Option<&Map<String, Value>> = None;
    for (index, item) in entries.iter().enumerate() {
        let entry = item.as_object().ok_or_else(|| {
            fault(
                "invalid_descriptor",
                format!("descriptor operations[{index}] must be an object"),
            )
        })?;
        let operation = match established(entry, "operation") {
            Some(Value::String(text)) => text.as_str(),
            _ => {
                return Err(fault(
                    "invalid_descriptor",
                    format!("descriptor operations[{index}] requires an operation name"),
                ))
            }
        };
        if operation == verb.as_str() {
            if found.is_some() {
                return Err(fault(
                    "duplicate_operation_mapping",
                    format!("operation {:?} appears more than once in the descriptor", verb.as_str()),
                ));
            }
            found = Some(entry);
        }
    }

    let Some(entry) = found else {
        return Ok(OperationMapping {
            declared: false,
            implementation: "unmapped".to_string(),
            native_contract: missing(
                "not_observed",
                "descriptor has no entry for this operation",
            ),
            evidence_refs: json!([]),
            limitations: vec![Value::String(
                "operation mapping is absent from the descriptor; omission is not evidenced native absence"
                    .to_string(),
            )],
            supported: false,
        });
    };

    let implementation = required_str(
        entry,
        "implementation",
        "invalid_descriptor",
        "operation mapping",
    )?;
    let mut limitations: Vec<Value> = match established(entry, "limitations") {
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                "operation mapping limitations must be an array".to_string(),
            ))
        }
        None => Vec::new(),
    };
    let evidence_refs = match established(entry, "evidence_refs") {
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                check_evidence_ref(
                    item,
                    &format!("operation evidence_refs[{index}]"),
                    "invalid_descriptor",
                )?;
            }
            Value::Array(items.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_descriptor",
                "operation mapping evidence_refs must be an array".to_string(),
            ))
        }
        None => json!([]),
    };

    match implementation {
        "native_mapping" => {
            let contract = established(entry, "native_contract").cloned();
            let contract_ok = contract
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|pin| {
                    established(pin, "id")
                        .and_then(Value::as_str)
                        .is_some_and(|text| !text.is_empty())
                        && established(pin, "version")
                            .and_then(Value::as_str)
                            .is_some_and(|text| !text.is_empty())
                });
            let evidence_ok = evidence_refs
                .as_array()
                .is_some_and(|items| !items.is_empty());
            if !contract_ok || !evidence_ok {
                limitations.push(Value::String(
                    "claimed native mapping lacks an evidenced contract; emitted as unsupported mapping, which is not native absence"
                        .to_string(),
                ));
                Ok(OperationMapping {
                    declared: true,
                    implementation: "unmapped".to_string(),
                    native_contract: missing(
                        "not_observed",
                        "no evidenced native contract for this operation",
                    ),
                    evidence_refs,
                    limitations,
                    supported: false,
                })
            } else {
                Ok(OperationMapping {
                    declared: true,
                    implementation: "native_mapping".to_string(),
                    native_contract: contract.unwrap_or_else(|| {
                        missing("not_observed", "no evidenced native contract")
                    }),
                    evidence_refs,
                    limitations,
                    supported: true,
                })
            }
        }
        "connector_local" => {
            if established(entry, "native_contract").is_some() {
                return Err(fault(
                    "invalid_descriptor",
                    format!(
                        "operation {:?} is connector-local and must not carry an established native contract",
                        verb.as_str()
                    ),
                ));
            }
            Ok(OperationMapping {
                declared: true,
                implementation: "connector_local".to_string(),
                native_contract: missing(
                    "not_applicable",
                    "connector-local operation has no native contract",
                ),
                evidence_refs,
                limitations,
                supported: true,
            })
        }
        "unmapped" => {
            if limitations.is_empty() {
                limitations.push(Value::String(
                    "unsupported mapping is not native absence".to_string(),
                ));
            }
            Ok(OperationMapping {
                declared: true,
                implementation: "unmapped".to_string(),
                native_contract: missing(
                    "not_observed",
                    "no evidenced native contract for this operation",
                ),
                evidence_refs,
                limitations,
                supported: false,
            })
        }
        other => Err(fault(
            "unknown_operation_mapping",
            format!(
                "operation mapping implementation {other:?} must be native_mapping, connector_local, or unmapped"
            ),
        )),
    }
}

fn interpret_native_response(
    response: &CheckedRecord,
    operation_id: &str,
    verb: ControlVerb,
) -> Result<NativeOutcome, Fault> {
    let map = as_object(response, "invalid_native_response", "native response")?;
    let response_operation = required_str(
        map,
        "operation_id",
        "invalid_native_response",
        "native response",
    )?;
    if response_operation != operation_id {
        return Err(fault(
            "invalid_native_response",
            format!(
                "native response operation_id {response_operation:?} does not correlate to request {operation_id:?}"
            ),
        ));
    }
    let claimed = required_str(map, "outcome", "invalid_native_response", "native response")?;
    if !NATIVE_OUTCOMES.contains(&claimed) {
        return Err(fault(
            "unknown_native_outcome",
            format!("native outcome {claimed:?} is not one of the closed outcome states"),
        ));
    }

    let acknowledgement = match established(map, "acknowledgement") {
        None => missing(
            "not_observed",
            "native response carries no acknowledgement",
        ),
        Some(Value::Object(ack)) => {
            let verified = match ack.get("verified") {
                Some(Value::Bool(flag)) => *flag,
                _ => false,
            };
            if !verified {
                return Err(fault(
                    "unverified_acknowledgement",
                    "acknowledged requires a verified native response; an unverified claim is not acknowledgement"
                        .to_string(),
                ));
            }
            let response_ref = ack.get("response_ref").ok_or_else(|| {
                fault(
                    "unverified_acknowledgement",
                    "acknowledged requires a response reference".to_string(),
                )
            })?;
            check_evidence_ref(
                response_ref,
                "acknowledgement response_ref",
                "unverified_acknowledgement",
            )?;
            Value::Object(ack.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_native_response",
                "acknowledgement must be an object or a Missing envelope".to_string(),
            ))
        }
    };
    let has_ack = !is_missing(&acknowledgement);
    let response_ref = acknowledgement
        .get("response_ref")
        .cloned()
        .unwrap_or_else(|| {
            missing(
                "not_observed",
                "no verified native response reference was supplied",
            )
        });

    let subject_claim = match established(map, "subject_claim") {
        None => missing("not_observed", "no subject claim was reported"),
        Some(Value::Object(claim)) => {
            match claim.get("source").and_then(Value::as_str) {
                Some("subject") => {}
                _ => {
                    return Err(fault(
                        "invalid_subject_claim",
                        "subject_claim source must be exactly \"subject\"; a subject stop report is a subject claim"
                            .to_string(),
                    ))
                }
            }
            let claim_ref = claim.get("claim_ref").ok_or_else(|| {
                fault(
                    "invalid_subject_claim",
                    "subject_claim requires a claim reference".to_string(),
                )
            })?;
            check_evidence_ref(claim_ref, "subject_claim claim_ref", "invalid_subject_claim")?;
            Value::Object(claim.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_subject_claim",
                "subject_claim must be an object or a Missing envelope".to_string(),
            ))
        }
    };
    let stop_claim_recorded = !is_missing(&subject_claim);

    let effect = match established(map, "effect") {
        None => missing("not_observed", "no effect evidence was observed"),
        Some(Value::Object(effect)) => {
            let effect_kind = required_str(
                effect,
                "effect_kind",
                "invalid_native_response",
                "effect",
            )?;
            if effect_kind != verb.expected_effect_kind() {
                return Err(fault(
                    "effect_scope_mismatch",
                    format!(
                        "effect kind {effect_kind:?} cannot establish {:?}; each control verb has its own observed effect",
                        verb.expected_effect_kind()
                    ),
                ));
            }
            let effect_refs = required_array(
                effect,
                "effect_refs",
                "invalid_native_response",
                "effect",
            )?;
            if effect_refs.is_empty() {
                return Err(fault(
                    "unevidenced_effect",
                    "effect_observed requires effect evidence; a claim alone is not an effect"
                        .to_string(),
                ));
            }
            for (index, item) in effect_refs.iter().enumerate() {
                check_evidence_ref(
                    item,
                    &format!("effect_refs[{index}]"),
                    "invalid_native_response",
                )?;
            }
            Value::Object(effect.clone())
        }
        Some(_) => {
            return Err(fault(
                "invalid_native_response",
                "effect must be an object or a Missing envelope".to_string(),
            ))
        }
    };
    let has_effect = !is_missing(&effect);

    let limitations = match established(map, "limitations") {
        None => Vec::new(),
        Some(Value::Array(items)) => {
            for (index, item) in items.iter().enumerate() {
                match item {
                    Value::String(text) if !text.is_empty() => {}
                    _ => {
                        return Err(fault(
                            "invalid_native_response",
                            format!("limitations[{index}] must be a nonempty string"),
                        ))
                    }
                }
            }
            items.clone()
        }
        Some(_) => {
            return Err(fault(
                "invalid_native_response",
                "limitations must be an array".to_string(),
            ))
        }
    };

    let native_elapsed_ms = match map
        .get("timing")
        .and_then(Value::as_object)
        .and_then(|timing| timing.get("observed_elapsed_ms"))
    {
        Some(Value::Number(number)) => {
            let elapsed = number.as_f64().ok_or_else(|| {
                fault(
                    "invalid_native_response",
                    "native timing must be a finite number".to_string(),
                )
            })?;
            if !elapsed.is_finite() || elapsed < 0.0 {
                return Err(fault(
                    "invalid_native_response",
                    "native timing must be finite and nonnegative".to_string(),
                ));
            }
            json!(elapsed)
        }
        None => missing(
            "not_observed",
            "native response carries no timing observation",
        ),
        Some(_) => {
            return Err(fault(
                "invalid_native_response",
                "native timing observed_elapsed_ms must be a number".to_string(),
            ))
        }
    };

    let disposition = match claimed {
        "acknowledged" => {
            if !has_ack {
                return Err(fault(
                    "unverified_acknowledgement",
                    "outcome acknowledged requires a verified acknowledgement".to_string(),
                ));
            }
            if has_effect {
                "effect_observed"
            } else {
                "acknowledged"
            }
        }
        "effect_observed" => {
            if !has_effect {
                return Err(fault(
                    "unevidenced_effect",
                    "outcome effect_observed requires effect evidence".to_string(),
                ));
            }
            "effect_observed"
        }
        "unsupported" => {
            if has_ack || has_effect {
                return Err(fault(
                    "invalid_native_response",
                    "unsupported cannot carry acknowledgement or effect evidence".to_string(),
                ));
            }
            "unsupported"
        }
        "unknown" => {
            if has_ack || has_effect {
                return Err(fault(
                    "invalid_native_response",
                    "unknown delivery cannot carry acknowledgement or effect evidence".to_string(),
                ));
            }
            "unknown"
        }
        "requested" => {
            if has_ack || has_effect {
                return Err(fault(
                    "invalid_native_response",
                    "requested-only cannot carry acknowledgement or effect evidence; those are separate states"
                        .to_string(),
                ));
            }
            "requested"
        }
        _ => unreachable!("outcome membership was checked above"),
    };

    Ok(NativeOutcome {
        disposition,
        acknowledgement,
        response_ref,
        subject_claim,
        effect,
        has_ack,
        has_effect,
        stop_claim_recorded,
        native_elapsed_ms,
        limitations,
    })
}

// ---------------------------------------------------------------------------
// Receipt construction
// ---------------------------------------------------------------------------

fn build_receipt(input: ReceiptInput) -> Result<CheckedRecord, Fault> {
    let close = input.verb == ControlVerb::CloseObservationConnection;
    let cancel = input.verb == ControlVerb::RequestNativeCancel;
    let release = input.verb == ControlVerb::ReleaseNativeContext;
    let contain = input.verb == ControlVerb::Contain;
    let verified_execution = input.has_ack || input.has_effect;

    let transport_close_requested = close && input.invoked;
    let transport_closed = transport_close_requested && verified_execution;
    // `end_observation` is a local finalization request: it stops new workflow
    // delivery and starts the commissioned bounded drain even when the native
    // transport close is unsupported or its delivery remains unknown. A native
    // acknowledgement is not required to truthfully finalize locally.
    let workflow_delivery_stop_requested = close && input.end_observation;
    let observation_ended = close && input.end_observation;
    let workflow_delivery_stopped = observation_ended;
    let drain_started = observation_ended;

    let cancel_requested = cancel && input.invoked;
    let cancel_acknowledged = cancel && input.has_ack;
    let cancel_effect_observed = cancel && input.has_effect;

    let release_requested = release && input.invoked;
    let release_acknowledged = release && input.has_ack;
    let context_release_effect_observed = release && input.has_effect;

    let containment_requested = contain && input.invoked;
    let containment_acknowledged = contain && input.has_ack;
    let containment_effect_observed = contain && input.has_effect;

    let receipt = json!({
        "kind": RECEIPT_KIND,
        "record_type": RECEIPT_KIND,
        "operation_id": input.operation_id,
        "verb": input.verb.as_str(),
        "connector": input.connector,
        "subject": input.subject,
        "handle": Value::Object(input.handle),
        "target_scope": input.target_scope,
        "evidence_prefix": input.prefix,
        "registration_ref": missing(
            "not_observed",
            "the grant's registration digest is recorded under authorization; no journal-backed registration coordinate was supplied",
        ),
        "authorization": input.authorization,
        "capability_ref": input.capability,
        "native_mapping": input.mapping.to_json(),
        "native_invoked": input.invoked,
        "parameters": input.parameters,
        "observation": {
            "control_event_id": format!("{}:{}", input.operation_id, input.disposition),
            "operation": input.verb.as_str(),
            "target_scope": input.target_scope,
            "disposition": input.disposition,
            "at": input.observed_at,
            "requested_at": input.requested_at,
            "request_ref": missing(
                "not_observed",
                "this control attempt was not journaled; the receipt event is the request evidence",
            ),
            "response_ref": input.response_ref,
            "acknowledgement": input.acknowledgement,
            "subject_claim": input.subject_claim,
            "effect": input.effect,
            "events": input.events,
            "stop_claim_recorded": input.stop_claim_recorded,
            "end_observation": input.end_observation,
            "transport_close_requested": transport_close_requested,
            "transport_closed": transport_closed,
            "observation_ended": observation_ended,
            "workflow_delivery_stop_requested": workflow_delivery_stop_requested,
            "workflow_delivery_stopped": workflow_delivery_stopped,
            "drain_started": drain_started,
            "drain_completed": false,
            "cancel_requested": cancel_requested,
            "cancel_acknowledged": cancel_acknowledged,
            "cancel_effect_observed": cancel_effect_observed,
            "release_requested": release_requested,
            "release_acknowledged": release_acknowledged,
            "context_release_effect_observed": context_release_effect_observed,
            "implicit_logout": false,
            "profile_purged": false,
            "global_reset": false,
            "containment_requested": containment_requested,
            "containment_acknowledged": containment_acknowledged,
            "containment_effect_observed": containment_effect_observed,
            "containment_triggered_by_release": false,
            "affected_attempts": input.affected_attempts,
            "unresolved_impact": input.unresolved_impact,
            "forced_termination": false,
            "rollback_established": false,
            "no_remote_effect_established": false,
            "native_absence_established": false,
            "limitations": input.limitations,
            "timing": {
                "call_bound_ms": input.bounds.call_bound_ms,
                "drain_bound_ms": input.bounds.drain_bound_ms,
                "cancellation_wait_ms": input.bounds.cancellation_wait_ms,
                "cleanup_wait_ms": input.bounds.cleanup_wait_ms,
                "observed_elapsed_ms": input.elapsed_ms,
                "native_reported_elapsed_ms": input.native_elapsed_ms,
                "call_deadline": input.call_deadline,
                "drain_deadline": input.drain_deadline,
                "cancellation_wait_deadline": input.cancellation_deadline,
                "cleanup_wait_deadline": input.cleanup_deadline,
            },
        },
    });
    validate(OUTPUT_SCHEMA, receipt)
}

// ---------------------------------------------------------------------------
// Shared helpers
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

/// True when `value` is a `Missing` envelope (already gate-validated).
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

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

fn required_bool(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<bool, Fault> {
    match established(map, field) {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(fault(
            code,
            format!("{what} requires an established boolean {field:?}"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    match established(map, field) {
        Some(Value::Number(number)) => number.as_u64().ok_or_else(|| {
            fault(
                code,
                format!("{what} requires an unsigned integer {field:?}"),
            )
        }),
        _ => Err(fault(
            code,
            format!("{what} requires an established unsigned integer {field:?}"),
        )),
    }
}

fn required_object<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    match established(map, field) {
        Some(Value::Object(object)) => Ok(object),
        _ => Err(fault(
            code,
            format!("{what} requires an established object {field:?}"),
        )),
    }
}

fn required_array<'a>(
    map: &'a Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<&'a Vec<Value>, Fault> {
    match established(map, field) {
        Some(Value::Array(items)) => Ok(items),
        _ => Err(fault(
            code,
            format!("{what} requires an established array {field:?}"),
        )),
    }
}

fn reject_established(
    map: &Map<String, Value>,
    fields: &[&str],
    code: &str,
    what: &str,
) -> Result<(), Fault> {
    for field in fields {
        if established(map, field).is_some() {
            return Err(fault(
                code,
                format!("{what} must not carry {field:?}; that state is established by evidence, not by request data"),
            ));
        }
    }
    Ok(())
}

fn check_evidence_ref(value: &Value, what: &str, code: &str) -> Result<(), Fault> {
    let map = value.as_object().ok_or_else(|| {
        fault(code, format!("{what} must be an evidence-reference object"))
    })?;
    required_str(map, "journal_id", code, what)?;
    match map.get("sequence") {
        Some(Value::Number(number)) if number.as_u64().is_some_and(|value| value >= 1) => {}
        _ => {
            return Err(fault(
                code,
                format!("{what} requires an integer sequence >= 1"),
            ))
        }
    }
    required_str(map, "event_id", code, what)?;
    let event_hash = required_str(map, "event_hash", code, what)?;
    if !is_digest(event_hash) {
        return Err(fault(
            code,
            format!("{what} requires a 64-hex or sha256:-prefixed event_hash digest"),
        ));
    }
    match map.get("pointer") {
        Some(Value::String(_)) => {}
        _ => {
            return Err(fault(
                code,
                format!("{what} requires an established pointer string"),
            ))
        }
    }
    Ok(())
}

fn is_64hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn is_digest(text: &str) -> bool {
    if is_64hex(text) {
        return true;
    }
    text.strip_prefix("sha256:").is_some_and(is_64hex)
}

fn add_bound(now: &CheckedRecord, bound_ms: u64) -> Result<CheckedRecord, Fault> {
    let mut value = record_value(now).clone();
    let map = value.as_object_mut().ok_or_else(|| {
        fault(
            "invalid_clock",
            "clock authority must report a TimePoint object".to_string(),
        )
    })?;
    let offset = map
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite())
        .ok_or_else(|| {
            fault(
                "invalid_clock",
                "clock authority TimePoint has no finite monotonic_offset_ms".to_string(),
            )
        })?;
    map.insert(
        "monotonic_offset_ms".to_string(),
        json!(offset + bound_ms as f64),
    );
    validate(OUTPUT_SCHEMA, value)
}

fn elapsed_between(
    started: &CheckedRecord,
    finished: &CheckedRecord,
) -> Result<f64, Fault> {
    let start_map = record_value(started).as_object().ok_or_else(|| {
        fault("invalid_clock", "start TimePoint must be an object".to_string())
    })?;
    let end_map = record_value(finished).as_object().ok_or_else(|| {
        fault("invalid_clock", "end TimePoint must be an object".to_string())
    })?;
    let start_clock = required_str(start_map, "clock_id", "invalid_clock", "start TimePoint")?;
    let end_clock = required_str(end_map, "clock_id", "invalid_clock", "end TimePoint")?;
    if start_clock != end_clock {
        return Err(fault(
            "cross_clock",
            "control timing must be measured on one registered clock".to_string(),
        ));
    }
    let start_boot = required_str(start_map, "boot_id", "invalid_clock", "start TimePoint")?;
    let end_boot = required_str(end_map, "boot_id", "invalid_clock", "end TimePoint")?;
    if start_boot != end_boot {
        return Err(fault(
            "cross_boot",
            "control timing must be measured on one boot".to_string(),
        ));
    }
    let start = start_map
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite())
        .ok_or_else(|| {
            fault(
                "invalid_clock",
                "start TimePoint lacks a finite monotonic_offset_ms".to_string(),
            )
        })?;
    let end = end_map
        .get("monotonic_offset_ms")
        .and_then(Value::as_f64)
        .filter(|offset| offset.is_finite())
        .ok_or_else(|| {
            fault(
                "invalid_clock",
                "end TimePoint lacks a finite monotonic_offset_ms".to_string(),
            )
        })?;
    let elapsed = end - start;
    if !elapsed.is_finite() || elapsed < 0.0 {
        return Err(fault(
            "invalid_clock",
            "monotonic clock moved backwards across the control call".to_string(),
        ));
    }
    Ok(elapsed)
}
