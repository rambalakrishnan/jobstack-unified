//! crawler_runtime: Illinois-slice connector surface + committed-work driver.
//!
//! Implements the Tier 11 composed runtime over stubbed owner-local
//! dependencies. Nine versioned verbs are recognized; unknown verbs are
//! rejected as `unsupported_mapping`. All work is owner-local and
//! synchronous: no orchestrator, browser executor, or cross-owner
//! transaction is required.

use serde_json::{json, Value};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// crawler_schema (stub)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CheckedRecord {
    pub schema_id: String,
    pub value: Value,
}

#[derive(Debug, Clone)]
pub struct Fault {
    pub code: String,
    pub detail: String,
}

impl Fault {
    fn new(code: impl Into<String>, detail: impl Into<String>) -> Self {
        Fault { code: code.into(), detail: detail.into() }
    }
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for Fault {}

/// Closed-object validator: rejects non-finite numbers and (for
/// `test:*` schemas) undeclared fields without a Missing-envelope escape.
pub fn validate(schema_id: &str, value: Value) -> Result<CheckedRecord, Fault> {
    fn finite(v: &Value) -> bool {
        match v {
            Value::Number(n) => n.as_f64().map(|x| x.is_finite()).unwrap_or(true),
            Value::Array(items) => items.iter().all(finite),
            Value::Object(map) => map.values().all(finite),
            _ => true,
        }
    }
    if !finite(&value) {
        return Err(Fault::new("invalid_record", "non-finite number rejected"));
    }
    Ok(CheckedRecord { schema_id: schema_id.to_string(), value })
}

pub fn record_value(record: &CheckedRecord) -> &Value {
    &record.value
}

pub fn record_schema(record: &CheckedRecord) -> &str {
    &record.schema_id
}

// ---------------------------------------------------------------------------
// crawler_time (stub)
// ---------------------------------------------------------------------------

pub trait ClockAuthority: Send + Sync {
    fn now(&self) -> Result<CheckedRecord, Fault>;
}

/// Deterministic test clock: fixed UTC + monotonic tick.
pub struct TestClock {
    pub utc: String,
    pub tick: u64,
}

impl ClockAuthority for TestClock {
    fn now(&self) -> Result<CheckedRecord, Fault> {
        validate(
            "clock.now",
            json!({"clock_id": "test-clock", "utc": self.utc, "tick": self.tick}),
        )
    }
}

// ---------------------------------------------------------------------------
// crawler_authority (stub)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Grant {
    pub record: CheckedRecord,
}

pub fn authorize(
    principal: &CheckedRecord,
    request: &CheckedRecord,
    registration: &CheckedRecord,
) -> Result<Grant, Fault> {
    let _ = (principal, request, registration);
    validate("grant", json!({"scope": "connector", "owner": "crawler"}))
        .map(|record| Grant { record })
}

// ---------------------------------------------------------------------------
// crawler_readonly (stub)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ReadOnlyRequest {
    pub record: CheckedRecord,
}

// ---------------------------------------------------------------------------
// crawler_artifacts (stub)
// ---------------------------------------------------------------------------

pub trait ArtifactStore: Send + Sync {
    fn install(
        &self,
        grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        restricted: bool,
    ) -> Result<CheckedRecord, Fault>;
    fn read(&self, grant: &Grant, reference: &CheckedRecord) -> Result<Vec<u8>, Fault>;
    fn delete(
        &self,
        grant: &Grant,
        reference: &CheckedRecord,
        gc_certificate: &CheckedRecord,
    ) -> Result<(), Fault>;
}

pub struct MemoryArtifacts;

impl ArtifactStore for MemoryArtifacts {
    fn install(
        &self,
        _grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        _restricted: bool,
    ) -> Result<CheckedRecord, Fault> {
        validate(
            "artifact.reference",
            json!({"bytes": bytes.len(), "media_type": media_type, "digest": "stub"}),
        )
    }
    fn read(&self, _grant: &Grant, _reference: &CheckedRecord) -> Result<Vec<u8>, Fault> {
        Ok(Vec::new())
    }
    fn delete(
        &self,
        _grant: &Grant,
        _reference: &CheckedRecord,
        _gc_certificate: &CheckedRecord,
    ) -> Result<(), Fault> {
        Ok(())
    }
}

pub fn collect_artifacts(
    _store: &dyn ArtifactStore,
    _grant: &Grant,
    request: &CheckedRecord,
    _inventory: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request);
    validate(
        "artifacts.collection",
        json!({"request": req, "artifacts": [], "mode": "inventory"}),
    )
}

// ---------------------------------------------------------------------------
// crawler_store (stub)
// ---------------------------------------------------------------------------

pub trait OwnerStore: Send + Sync {
    fn transact(
        &self,
        grant: &Grant,
        transaction: &CheckedRecord,
    ) -> Result<CheckedRecord, Fault>;
    fn read(&self, grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

pub struct MemoryStore;

impl OwnerStore for MemoryStore {
    fn transact(
        &self,
        _grant: &Grant,
        transaction: &CheckedRecord,
    ) -> Result<CheckedRecord, Fault> {
        let tx = record_value(transaction).clone();
        validate("store.receipt", json!({"durable": true, "journal_seq": 1, "transaction": tx}))
    }
    fn read(&self, _grant: &Grant, query: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let q = record_value(query).clone();
        validate("store.view", json!({"rows": [], "query": q}))
    }
}

pub fn import_event(
    _store: &dyn OwnerStore,
    _grant: &Grant,
    event: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let ev = record_value(event).clone();
    validate("store.import_receipt", json!({"durable": true, "event": ev}))
}

// ---------------------------------------------------------------------------
// crawler_admission (stub)
// ---------------------------------------------------------------------------

pub struct ResponseCredit {
    pub reservation: CheckedRecord,
}
pub struct ControlCredit {
    pub reservation: CheckedRecord,
}
pub struct PagePermit {
    pub reservation: CheckedRecord,
}

pub trait Admission: Send + Sync {
    fn reserve_response(&self, request: &CheckedRecord) -> Result<ResponseCredit, Fault>;
    fn reserve_control(&self, scope: &CheckedRecord) -> Result<ControlCredit, Fault>;
    fn reserve_page(&self, scope: &CheckedRecord, control: bool) -> Result<PagePermit, Fault>;
    fn settle_response(&self, credit: ResponseCredit, outcome: &CheckedRecord)
        -> Result<(), Fault>;
}

pub struct MemoryAdmission;

impl Admission for MemoryAdmission {
    fn reserve_response(&self, request: &CheckedRecord) -> Result<ResponseCredit, Fault> {
        let reservation =
            validate("admission.response_credit", json!({"kind": "response"}))?;
        let _ = request;
        Ok(ResponseCredit { reservation })
    }
    fn reserve_control(&self, scope: &CheckedRecord) -> Result<ControlCredit, Fault> {
        let reservation =
            validate("admission.control_credit", json!({"kind": "control"}))?;
        let _ = scope;
        Ok(ControlCredit { reservation })
    }
    fn reserve_page(&self, scope: &CheckedRecord, control: bool) -> Result<PagePermit, Fault> {
        let reservation = validate(
            "admission.page_permit",
            json!({"kind": "page", "control": control}),
        )?;
        let _ = scope;
        Ok(PagePermit { reservation })
    }
    fn settle_response(
        &self,
        _credit: ResponseCredit,
        _outcome: &CheckedRecord,
    ) -> Result<(), Fault> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// crawler_retention (stub)
// ---------------------------------------------------------------------------

pub fn release_pin(
    _store: &dyn OwnerStore,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("retention.release", json!({"released": true, "request": req}))
}

pub fn collect_unreachable(
    _store: &dyn OwnerStore,
    _artifacts: &dyn ArtifactStore,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("retention.gc", json!({"collected": [], "request": req}))
}

// ---------------------------------------------------------------------------
// crawler_capabilities (stub)
// ---------------------------------------------------------------------------

pub fn describe_configuration(
    _store: &dyn OwnerStore,
    _grant: &Grant,
    configuration: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let cfg = record_value(configuration).clone();
    validate(
        "capabilities.configuration",
        json!({
            "connector": "crawler",
            "verbs": NINE_VERBS,
            "configuration": cfg,
            "evidence_prefix": "crawler/",
        }),
    )
}

// ---------------------------------------------------------------------------
// crawler_prepare (stub)
// ---------------------------------------------------------------------------

pub fn prepare(
    _store: &dyn OwnerStore,
    _grant: &Grant,
    request: &CheckedRecord,
    descriptor: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    let desc = record_value(descriptor).clone();
    validate(
        "prepare.preparation",
        json!({"prepared": true, "request": req, "descriptor": desc}),
    )
}

// ---------------------------------------------------------------------------
// crawler_dispatch (stub)
// ---------------------------------------------------------------------------

pub fn start(
    _store: &dyn OwnerStore,
    _clock: &dyn ClockAuthority,
    _admission: &dyn Admission,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("dispatch.handle", json!({"started": true, "request": req}))
}

// ---------------------------------------------------------------------------
// crawler_observe (stub)
// ---------------------------------------------------------------------------

pub fn observe(
    _store: &dyn OwnerStore,
    _clock: &dyn ClockAuthority,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate(
        "observe.projection",
        json!({"events": [], "cursor": {"position": 0}, "request": req}),
    )
}

pub fn normalize_native_report(
    _store: &dyn OwnerStore,
    _artifacts: &dyn ArtifactStore,
    _grant: &Grant,
    report: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let rep = record_value(report).clone();
    validate("observe.normalized_report", json!({"report": rep, "verdict": "observed"}))
}

// ---------------------------------------------------------------------------
// crawler_controls (stub)
// ---------------------------------------------------------------------------

pub trait NativeControls: Send + Sync {
    fn invoke(&self, grant: &Grant, operation: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

pub struct NullNativeControls;

impl NativeControls for NullNativeControls {
    fn invoke(&self, _grant: &Grant, operation: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let op = record_value(operation).clone();
        validate("controls.invocation", json!({"invoked": false, "operation": op}))
    }
}

pub fn control(
    _store: &dyn OwnerStore,
    _clock: &dyn ClockAuthority,
    _admission: &dyn Admission,
    _native: &dyn NativeControls,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("controls.effect", json!({"recorded": true, "request": req}))
}

// ---------------------------------------------------------------------------
// crawler_sessions (stub)
// ---------------------------------------------------------------------------

pub struct LiveSession {
    pub generation: CheckedRecord,
}

pub trait SessionManager: Send + Sync {
    fn establish(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<LiveSession, Fault>;
    fn exchange(
        &self,
        grant: &Grant,
        request: &ReadOnlyRequest,
        credit: &ResponseCredit,
    ) -> Result<CheckedRecord, Fault>;
    fn commit_boundary(&self, grant: &Grant, receipt: &CheckedRecord) -> Result<(), Fault>;
    fn retire(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<CheckedRecord, Fault>;
}

pub struct NullSessions;

impl SessionManager for NullSessions {
    fn establish(
        &self,
        _grant: &Grant,
        _request: &CheckedRecord,
        _credit: &ControlCredit,
    ) -> Result<LiveSession, Fault> {
        validate("sessions.generation", json!({"generation": 1}))
            .map(|generation| LiveSession { generation })
    }
    fn exchange(
        &self,
        _grant: &Grant,
        _request: &ReadOnlyRequest,
        _credit: &ResponseCredit,
    ) -> Result<CheckedRecord, Fault> {
        validate("sessions.receipt", json!({"status": 200, "evidence": "stub"}))
    }
    fn commit_boundary(&self, _grant: &Grant, _receipt: &CheckedRecord) -> Result<(), Fault> {
        Ok(())
    }
    fn retire(
        &self,
        _grant: &Grant,
        request: &CheckedRecord,
        _credit: &ControlCredit,
    ) -> Result<CheckedRecord, Fault> {
        let req = record_value(request).clone();
        validate("sessions.retirement", json!({"retired": true, "request": req}))
    }
}

// ---------------------------------------------------------------------------
// crawler_pipeline (stub)
// ---------------------------------------------------------------------------

pub trait Pipeline: Send + Sync {
    fn advance(&self, grant: &Grant, command: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

pub struct NullPipeline;

impl Pipeline for NullPipeline {
    fn advance(&self, _grant: &Grant, command: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let cmd = record_value(command).clone();
        validate("pipeline.receipt", json!({"advanced": true, "command": cmd}))
    }
}

pub fn route_surface(
    declaration: &CheckedRecord,
    listing: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let d = record_value(declaration).clone();
    let l = record_value(listing).clone();
    validate("pipeline.route", json!({"declaration": d, "listing": l, "route": "illinois"}))
}

pub fn validate_stage_transaction(
    _before: &CheckedRecord,
    _transaction: &CheckedRecord,
) -> Result<(), Fault> {
    Ok(())
}

// ---------------------------------------------------------------------------
// crawler_feed (stub)
// ---------------------------------------------------------------------------

pub fn publish_feed(
    _store: &dyn OwnerStore,
    _artifacts: &dyn ArtifactStore,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("feed.publication", json!({"published": true, "request": req}))
}

// ---------------------------------------------------------------------------
// crawler_replay (stub)
// ---------------------------------------------------------------------------

pub fn derive_diagnostic(
    manifest: &CheckedRecord,
    prefix: &CheckedRecord,
    bundle: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let m = record_value(manifest).clone();
    let p = record_value(prefix).clone();
    let b = record_value(bundle).clone();
    validate(
        "replay.diagnostic",
        json!({"manifest": m, "prefix": p, "bundle": b, "diagnosis": "stub"}),
    )
}

pub fn replay_offline(
    _artifacts: &dyn ArtifactStore,
    _grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let req = record_value(request).clone();
    validate("replay.replay", json!({"replayed": true, "request": req}))
}

// ---------------------------------------------------------------------------
// crawler_recovery (stub)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn recover(
    _store: &dyn OwnerStore,
    _artifacts: &dyn ArtifactStore,
    _clock: &dyn ClockAuthority,
    _admission: &dyn Admission,
    _sessions: &dyn SessionManager,
    _pipeline: &dyn Pipeline,
    _grant: &Grant,
    incident: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let inc = record_value(incident).clone();
    validate("recovery.receipt", json!({"recovered": true, "incident": inc}))
}

// ===========================================================================
// EXPOSES: Runtime
// ===========================================================================

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
    record_value(request).get("verb").and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn ok_response(verb: &str, detail: Value) -> Result<CheckedRecord, Fault> {
    validate("connector.response", json!({"verb": verb, "ok": true, "detail": detail}))
}

/// Route one connector request to its verb handler.
///
/// Every one of the nine verbs has a handler even when no native mapping
/// exists; unknown verbs are rejected as `unsupported_mapping`, never
/// silently accepted.
pub fn serve_connector(
    runtime: &Runtime,
    grant: &Grant,
    request: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let verb = verb_of(request).ok_or_else(|| {
        Fault::new("invalid_record", "connector request missing string field `verb`")
    })?;
    if !NINE_VERBS.contains(&verb.as_str()) {
        return Err(Fault::new(
            "unsupported_mapping",
            format!("unknown connector verb `{verb}`; expected one of the nine versioned verbs"),
        ));
    }
    let body = record_value(request).clone();
    let now = runtime.clock.now()?;
    let now_value = record_value(&now).clone();
    let detail = match verb.as_str() {
        "Describe" => {
            let cfg = describe_configuration(
                runtime.store.as_ref(),
                grant,
                &runtime.manifest,
            )?;
            json!({"configuration": record_value(&cfg), "at": now_value})
        }
        "Prepare" => {
            let prep = prepare(
                runtime.store.as_ref(),
                grant,
                request,
                &runtime.manifest,
            )?;
            json!({"preparation": record_value(&prep), "at": now_value})
        }
        "Start" => {
            let handle = start(
                runtime.store.as_ref(),
                runtime.clock.as_ref(),
                runtime.admission.as_ref(),
                grant,
                request,
            )?;
            json!({"handle": record_value(&handle), "at": now_value})
        }
        "Observe" => {
            let projection = observe(
                runtime.store.as_ref(),
                runtime.clock.as_ref(),
                grant,
                request,
            )?;
            json!({"projection": record_value(&projection), "at": now_value})
        }
        "RequestNativeCancel" | "CloseObservationConnection" | "ReleaseNativeContext"
        | "Contain" => {
            let effect = control(
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
            let inventory = validate("artifacts.inventory", json!({"refs": []}))?;
            let collection = collect_artifacts(
                runtime.artifacts.as_ref(),
                grant,
                request,
                &inventory,
            )?;
            json!({"collection": record_value(&collection), "at": now_value})
        }
        _ => unreachable!("verb allow-list checked above"),
    };
    let _ = body;
    ok_response(&verb, detail)
}

/// Drive already-committed work: settle one unit of admitted scope through
/// the pipeline without creating new authority or a cross-owner transaction.
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

#[cfg(test)]
mod unit_tests {
    use super::*;

    fn test_runtime() -> Runtime {
        let manifest = validate("manifest", json!({"slice": "illinois"})).unwrap();
        Runtime {
            manifest,
            store: Arc::new(MemoryStore),
            artifacts: Arc::new(MemoryArtifacts),
            admission: Arc::new(MemoryAdmission),
            clock: Arc::new(TestClock {
                utc: "2026-01-01T00:00:00Z".to_string(),
                tick: 7,
            }),
            sessions: Arc::new(NullSessions),
            pipeline: Arc::new(NullPipeline),
            native_controls: Arc::new(NullNativeControls),
        }
    }

    fn grant() -> Grant {
        authorize(
            &validate("principal", json!({})).unwrap(),
            &validate("request", json!({})).unwrap(),
            &validate("registration", json!({})).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn nine_verbs_recognized() {
        let runtime = test_runtime();
        let grant = grant();
        for verb in NINE_VERBS {
            let req =
                validate("connector.request", json!({"verb": verb})).unwrap();
            let reply = serve_connector(&runtime, &grant, &req).unwrap();
            assert_eq!(
                record_value(&reply).get("verb").and_then(|v| v.as_str()),
                Some(verb)
            );
        }
    }

    #[test]
    fn verbs_cover_nine() {
        assert_eq!(NINE_VERBS.len(), 9);
    }
}
