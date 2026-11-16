//! `crawler_runtime`: Illinois-slice connector surface + committed-work driver.
//!
//! Tier 11 composed runtime over owner-local siblings. Recognizes exactly the
//! nine versioned connector verbs; unknown verbs are rejected as
//! `unsupported_mapping`. All work is owner-local and synchronous: no
//! orchestrator, browser executor, Hellscape, or cross-owner transaction is
//! required. Replies are normal connector responses (`{verb, ok, detail}`);
//! no composite task-success flag is fabricated.

use crawler_admission::Admission;
use crawler_artifacts::ArtifactStore;
use crawler_authority::{grant_record, Grant};
use crawler_controls::NativeControls;
use crawler_pipeline::Pipeline;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_sessions::SessionManager;
use crawler_store::OwnerStore;
use crawler_time::ClockAuthority;
use serde_json::{json, Value};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn established_str<'a>(map: &'a serde_json::Map<String, Value>, field: &str) -> Option<&'a str> {
    map.get(field).filter(|v| !is_missing(v)).and_then(Value::as_str)
}

// ---------------------------------------------------------------------------
// EXPOSES: Runtime
// ---------------------------------------------------------------------------

/// The nine and only nine versioned connector verbs.
const NINE_VERBS: [&str; 9] = [
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

/// Composed Illinois-slice runtime: one manifest plus owner-local seams.
pub struct Runtime {
    pub manifest: CheckedRecord,
    pub store: Arc<dyn OwnerStore>,
    pub artifacts: Arc<dyn ArtifactStore>,
    pub admission: Arc<dyn Admission>,
    pub clock: Arc<dyn ClockAuthority>,
    pub sessions: Arc<dyn SessionManager>,
    pub pipeline: Arc<dyn Pipeline>,
    pub native_controls: Arc<dyn NativeControls>,
}

fn verb_of(request: &CheckedRecord) -> Option<String> {
    record_value(request)
        .as_object()
        .and_then(|map| established_str(map, "verb"))
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

fn ok_response(verb: &str, detail: Value) -> Result<CheckedRecord, Fault> {
    validate(
        "audit_log",
        json!({"verb": verb, "ok": true, "detail": detail}),
    )
}

/// Enforce that the supplied grant authorizes this connector verb/target.
///
/// Siblings already enforce verb scoping for Start and control verbs; this
/// gate extends the same discipline to every verb so a grant issued for one
/// verb cannot be replayed against another through this surface.
fn check_grant_scope(grant: &Grant, request_map: &serde_json::Map<String, Value>, verb: &str) -> Result<(), Fault> {
    let grant_value = record_value(grant_record(grant));
    let Some(grant_map) = grant_value.as_object() else {
        return Err(fault("invalid_grant", "grant must carry an object record".to_string()));
    };
    if let Some(grant_verb) = established_str(grant_map, "verb") {
        if grant_verb != verb {
            return Err(fault(
                "verb_not_granted",
                format!("grant verb {grant_verb:?} does not authorize connector verb {verb:?}"),
            ));
        }
    }
    if let (Some(grant_connector), Some(request_connector)) = (
        established_str(grant_map, "connector"),
        established_str(request_map, "connector"),
    ) {
        if grant_connector != request_connector {
            return Err(fault(
                "connector_not_granted",
                format!(
                    "grant connector {grant_connector:?} does not authorize connector {request_connector:?}"
                ),
            ));
        }
    }
    Ok(())
}

/// Route one connector request to its verb handler.
///
/// Every one of the nine verbs has a handler even when no native mapping
/// exists; unknown verbs are rejected as `unsupported_mapping`, never
/// silently accepted. The connector request carries the verb-specific
/// sibling payload top-level (plus `verb`/`connector` for authorization);
/// `Prepare` additionally nests its immutable `descriptor` and
/// `CollectArtifacts` nests its authorized `inventory`.
pub fn serve_connector(
    runtime: &Runtime,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let request_map = record_value(request).as_object().ok_or_else(|| {
        fault("invalid_record", "connector request must be a JSON object".to_string())
    })?;
    let verb = verb_of(request).ok_or_else(|| {
        fault("invalid_record", "connector request missing string field `verb`".to_string())
    })?;
    if !NINE_VERBS.contains(&verb.as_str()) {
        return Err(fault(
            "unsupported_mapping",
            format!("unknown connector verb `{verb}`; expected one of the nine versioned verbs"),
        ));
    }
    check_grant_scope(grant, request_map, &verb)?;

    let now = runtime.clock.now()?;
    let now_value = record_value(&now).clone();
    let detail = match verb.as_str() {
        "Describe" => {
            let cfg = crawler_capabilities::describe_configuration(
                runtime.store.as_ref(),
                grant,
                &runtime.manifest,
            )?;
            json!({"configuration": record_value(&cfg), "at": now_value})
        }
        "Prepare" => {
            let descriptor_value = request_map.get("descriptor").ok_or_else(|| {
                fault(
                    "invalid_request",
                    "Prepare connector request requires an established `descriptor` object".to_string(),
                )
            })?;
            if is_missing(descriptor_value) {
                return Err(fault(
                    "invalid_request",
                    "Prepare connector request requires an established `descriptor` object".to_string(),
                ));
            }
            let descriptor = validate("audit_log", descriptor_value.clone())?;
            let prep = crawler_prepare::prepare(
                runtime.store.as_ref(),
                grant,
                request,
                &descriptor,
            )?;
            json!({"preparation": record_value(&prep), "at": now_value})
        }
        "Start" => {
            let handle = crawler_dispatch::start(
                runtime.store.as_ref(),
                runtime.clock.as_ref(),
                runtime.admission.as_ref(),
                grant,
                request,
            )?;
            json!({"handle": record_value(&handle), "at": now_value})
        }
        "Observe" => {
            let projection = crawler_observe::observe(
                runtime.store.as_ref(),
                runtime.clock.as_ref(),
                grant,
                request,
            )?;
            json!({"projection": record_value(&projection), "at": now_value})
        }
        "RequestNativeCancel" | "CloseObservationConnection" | "ReleaseNativeContext" | "Contain" => {
            let effect = crawler_controls::control(
                runtime.store.as_ref(),
                runtime.clock.as_ref(),
                runtime.admission.as_ref(),
                runtime.native_controls.as_ref(),
                grant,
                request,
            )?;
            json!({"effect": record_value(&effect), "at": now_value})
        }
        "CollectArtifacts" => {
            let inventory_value = request_map.get("inventory").ok_or_else(|| {
                fault(
                    "invalid_request",
                    "CollectArtifacts connector request requires an established `inventory` object".to_string(),
                )
            })?;
            if is_missing(inventory_value) {
                return Err(fault(
                    "invalid_request",
                    "CollectArtifacts connector request requires an established `inventory` object".to_string(),
                ));
            }
            let inventory = validate("audit_log", inventory_value.clone())?;
            let collection = crawler_artifacts::collect_artifacts(
                runtime.artifacts.as_ref(),
                grant,
                request,
                &inventory,
            )?;
            json!({"collection": record_value(&collection), "at": now_value})
        }
        _ => unreachable!("verb allow-list checked above"),
    };
    ok_response(&verb, detail)
}

/// Drive already-committed work: settle one unit of admitted scope through
/// the pipeline without creating new authority or a cross-owner transaction.
///
/// `scope` is the pipeline command (`{surface|declaration, before,
/// transaction}`); it is advanced under the supplied grant and wrapped with
/// the local clock instant.
pub fn drive_committed_work(
    runtime: &Runtime,
    grant: &Grant,
    scope: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let outcome = runtime.pipeline.advance(grant, scope)?;
    let now = runtime.clock.now()?;
    ok_response(
        "DriveCommittedWork",
        json!({
            "advance": record_value(&outcome),
            "scope": record_value(scope),
            "at": record_value(&now),
        }),
    )
}
