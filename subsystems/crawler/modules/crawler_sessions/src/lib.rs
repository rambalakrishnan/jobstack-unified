//! `crawler_sessions`: stateful HTTP session generations, cookie rotation,
//! and cold crash recovery.
//!
//! The module owns the session lifecycle seam of the crawler (seam map §12,
//! §16.8, §18.3, §21.2; [C32], [C33]):
//!
//! * **No row for `none` topology.** Slots MN-A/MN-B, IL-A/IL-B, and WI-A have
//!   no durable session. [`SessionManager::establish`] for a none-topology
//!   request fails with `topology_none` and writes **zero** rows; stateless
//!   acquisition never routes through this module.
//! * **One current owner per generation.** A stateful session is journaled as
//!   an immutable [`session_state`](SESSION_SCHEMA) row whose identity is
//!   `(target, run_id, phase, shard_id)`. A second `establish` for a live
//!   generation fails with `session_exists`; a new generation always advances
//!   `session_epoch` and only exists once its row is durable.
//! * **Serialized stateful exchange.** One in-flight request per session. A
//!   concurrent [`SessionManager::exchange`] fails with `session_busy`; the
//!   request is only *prepared* after every staged rotating cookie has been
//!   applied to the retained live client, so request and cookie sequences
//!   advance monotonically. Redirect and solver hops are admitted by
//!   [`SessionManager::commit_boundary`] inside the same serialization window:
//!   a redirect hop is re-authorized through
//!   [`crawler_readonly::authorize_redirect`] (mutation endpoints stay
//!   rejected before wire), and solver cookie mutations are staged and applied
//!   exactly like response rotations.
//! * **Durable boundary, volatile cookies.** Each acknowledged exchange is
//!   committed as a `session_boundary` journal event carrying the request
//!   sequence, cookie generation, and live-client identity. Cookie bytes never
//!   enter the journal (`cookie_jar_snapshot` is a typed
//!   `Missing(not_observed)`); the jar snapshot type is restricted evidence
//!   and this module never has artifact bytes to promise.
//! * **Cold crash recovery.** A manager process that finds a non-retired prior
//!   generation journals `session_recovered` with `session_epoch + 1` and a
//!   **fresh** client. Unacknowledged rotating snapshots are never replayed;
//!   the acknowledged cookie *generation counter* survives as evidence while
//!   the cookie jar starts empty. Recovery establishes a new epoch; it never
//!   resumes an old client.
//! * **Independent shards.** The session key includes `shard_id`, and every
//!   generation builds its own `HttpClient` with an explicitly constructed
//!   cookie jar. Nothing is taken from the process-global shared session, so
//!   independent rotating A/B shards cannot bleed cookies or pooled
//!   connections across one another. The returned [`LiveSession`] publishes
//!   the retained live client handle and its generation row — a live
//!   continuation, never a frozen snapshot.
//! * **Time and bounds.** Every deadline is an authority-clock `TimePoint`
//!   ordered through [`crawler_time::compare_deadline`]; cross-clock and
//!   cross-boot ordering is refused. Bootstrap control credit and response
//!   credit reservations must be unexpired, target-matched, and of the right
//!   kind before any effect. Expiry is journaled as `session_expired`; a
//!   rejected (stale) boundary has no effect at all.
//!
//! All records produced here validate through the closed
//! [`crawler_schema`] gate. Absent fields are typed `Missing` envelopes; no
//! bare JSON null is ever emitted.
//!
//! # Record shapes
//!
//! `establish` request (checked `audit_log` record; `request`/`endpoint`
//! nesting is tolerated for identity fields):
//!
//! * `slot` (`MN-A`, …, `OR-B`) **or** `session_topology`
//!   (`none|per_worker|per_crawl_run|per_shard`).
//! * `target`, `run_id`, `phase` (`A|B`), `shard_id` — the durable session
//!   identity. `shard_id` is never missing in a durable row.
//! * `journal_id` — the admitted owner journal receiving the session rows.
//! * `preset` / `profile.preset` — a versioned stealth preset (default
//!   `chrome_148_linux`); `profile_ref` pins it (default `profile:<preset>`).
//! * optional `owner_epoch`, `bootstrap_attempt`, `bootstrap_kind`
//!   (`cold|warm|handoff`), `deadline` (session `TimePoint`; defaults to the
//!   control-credit deadline), `handoff` (receipt **evidence**, never session
//!   birth), `session_expires_at`, `session_absolute_lifetime_seconds`,
//!   `replacement_deadline`, `authenticated_state_evidence`,
//!   `last_authenticated_url`, `worker_identity`.
//!
//! `exchange` consumes a [`crawler_readonly::ReadOnlyRequest`]; its session
//! identity is read from the wrapper, the authorized request, or the endpoint.
//!
//! `commit_boundary` receipt (the caller's wire evidence for the prepared
//! exchange): the exchange record echoed back plus optional
//! `rotations: [{source: response|redirect|solver, url, cookies: [raw]}]`,
//! `redirect` (a reference record re-authorized with `authorize_redirect`),
//! and `solver: {capability_id, …}` evidence.
//!
//! `retire` request: `session_id` or the full identity, optional
//! `expected_epoch` / `session_epoch`, optional `reason`.
//!
//! Lifecycle faults are stable codes; the principal ones are
//! `topology_none`, `missing_topology`, `invalid_topology`,
//! `missing_session_identity`, `invalid_phase`, `missing_journal_id`,
//! `invalid_preset`, `session_exists`, `bootstrap_deadline_exceeded`,
//! `invalid_credit`, `credit_target_mismatch`, `control_credit_expired`,
//! `response_credit_expired`, `unknown_session`, `no_live_session`,
//! `unauthorized_owner`, `needs_handoff`, `session_expired`, `session_busy`,
//! `cookie_application_failed`, `invalid_rotations`,
//! `missing_redirect_evidence`, `invalid_solver_evidence`, `stale_boundary`,
//! `session_mismatch`, `no_in_flight_exchange`, `stale_generation`,
//! `missing_principal`, and `session_not_durable`. Malformed request or
//! receipt shapes fail with the matching `invalid_*` code, and
//! `crawler_readonly` / `crawler_authority` / `crawler_store` faults
//! propagate unchanged.

use browser_oxide::net::alt_svc::AltSvcCache;
use browser_oxide::net::cookies::CookieJar;
use browser_oxide::net::tcp::DnsCache;
use browser_oxide::net::HttpClient;
use browser_oxide::stealth::{presets, StealthProfile};
use crawler_admission::{ControlCredit, ResponseCredit};
use crawler_authority::{grant_record, Grant};
use crawler_readonly::{authorize_redirect, ReadOnlyRequest};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use crawler_store::OwnerStore;
use crawler_time::{compare_deadline, ClockAuthority};
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

/// Structural schema id for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";
/// Durable entity schema id for session generations (§12).
const SESSION_SCHEMA: &str = "session_state";
/// Closed crawler `session_state` schema version.
const SESSION_RECORD_VERSION: u64 = 5;
/// Evidence-kernel event schema version stamped on journal submissions.
const EVIDENCE_SCHEMA_VERSION: &str = "evidence-kernel/0.1.0";

const EVENT_ESTABLISHED: &str = "session_established";
const EVENT_RECOVERED: &str = "session_recovered";
const EVENT_BOUNDARY: &str = "session_boundary_committed";
const EVENT_EXPIRED: &str = "session_expired";
const EVENT_RETIRED: &str = "session_retired";

const RECORD_SESSION_STATE: &str = "session_state";
const RECORD_SESSION_BOUNDARY: &str = "session_boundary";

/// A none-topology slot has no durable session row at all.
const TOPOLOGY_NONE: &str = "none";
/// Stateful shard topologies (§12: `per_worker|per_crawl_run|per_shard`).
const STATEFUL_TOPOLOGIES: &[&str] = &["per_worker", "per_crawl_run", "per_shard"];
/// Fleets phases.
const PHASES: &[&str] = &["A", "B"];
/// Bootstrap-kind values admitted into a session row.
const BOOTSTRAP_KINDS: &[&str] = &["cold", "warm", "handoff"];
/// Rotating-cookie hop sources; all are serialized in one session window.
const ROTATION_SOURCES: &[&str] = &["response", "redirect", "solver"];
/// The one failure reason this module records for a lapsed generation.
const EXPIRY_FAILURE_REASON: &str = "session_lapse";

const STATUS_ACTIVE: &str = "active";
const STATUS_NEEDS_HANDOFF: &str = "needs_handoff";
const STATUS_EXPIRED: &str = "expired";
const STATUS_RETIRED: &str = "retired";

/// Versioned stealth presets the crawler may pin. The set is closed: an
/// unknown preset is an invalid declaration, not a nearest match.
const PRESET_NAMES: &[&str] = &[
    "chrome_148_linux",
    "chrome_148_windows",
    "chrome_148_macos",
    "chrome_148_ru",
    "chrome_148_cn",
    "chrome_148_de",
    "chrome_148_jp",
    "firefox_135_linux",
    "firefox_135_macos",
    "firefox_135_windows",
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
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

fn established<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !is_missing(value))
}

fn as_object<'a>(
    record: &'a CheckedRecord,
    code: &str,
    what: &str,
) -> Result<&'a Map<String, Value>, Fault> {
    record_value(record).as_object().ok_or_else(|| {
        fault(code, format!("{what} must be a JSON object"))
    })
}

fn value_object<'a>(value: &'a Value, code: &str, what: &str) -> Result<&'a Map<String, Value>, Fault> {
    value
        .as_object()
        .ok_or_else(|| fault(code, format!("{what} must be a JSON object")))
}

fn required_str<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    code: &str,
    what: &str,
) -> Result<&'a str, Fault> {
    match established(map, key) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.as_str()),
        _ => Err(fault(
            code,
            format!("{what} requires an established nonempty string {key:?}"),
        )),
    }
}

fn optional_str<'a>(
    map: &'a Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Option<&'a str>, Fault> {
    match established(map, key) {
        None => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.as_str())),
        Some(_) => Err(fault(
            code,
            format!("field {key:?} must be a nonempty string when established"),
        )),
    }
}

fn optional_u64(map: &Map<String, Value>, key: &str, code: &str) -> Result<Option<u64>, Fault> {
    match established(map, key) {
        None => Ok(None),
        Some(Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            fault(
                code,
                format!("field {key:?} must be a nonnegative integer"),
            )
        }),
        Some(_) => Err(fault(
            code,
            format!("field {key:?} must be a nonnegative integer"),
        )),
    }
}

fn required_u64(
    map: &Map<String, Value>,
    key: &str,
    code: &str,
    what: &str,
) -> Result<u64, Fault> {
    optional_u64(map, key, code)?.ok_or_else(|| {
        fault(
            code,
            format!("{what} requires an established nonnegative integer {key:?}"),
        )
    })
}

/// Objects searched for session identity, in priority order: the record
/// itself, an authorized request, and an authorized endpoint. Read-only
/// acquisition wraps the caller's task record under `request`, so a session
/// identity carried on the task stays reachable here.
fn containers(value: &Value) -> Vec<&Map<String, Value>> {
    let mut out = Vec::new();
    let Some(root) = value.as_object() else {
        return out;
    };
    out.push(root);
    for key in ["request", "endpoint"] {
        if let Some(inner) = root.get(key).and_then(Value::as_object) {
            out.push(inner);
        }
    }
    out
}

fn session_text(value: &Value, names: &[&str]) -> Option<String> {
    for container in containers(value) {
        for name in names {
            match container.get(*name) {
                Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
                Some(other) if is_missing(other) => continue,
                _ => continue,
            }
        }
    }
    None
}

fn session_u64(value: &Value, names: &[&str]) -> Result<Option<u64>, Fault> {
    for container in containers(value) {
        for name in names {
            match container.get(*name) {
                None => continue,
                Some(other) if is_missing(other) => continue,
                Some(Value::Number(number)) => match number.as_u64() {
                    Some(number) => return Ok(Some(number)),
                    None => {
                        return Err(fault(
                            "invalid_session_identity",
                            format!("session field {name:?} must be a nonnegative integer"),
                        ))
                    }
                },
                Some(_) => {
                    return Err(fault(
                        "invalid_session_identity",
                        format!("session field {name:?} must be a nonnegative integer"),
                    ))
                }
            }
        }
    }
    Ok(None)
}

/// Durable session identity. The shard ID namespaces independent rotating
/// shards: two shards with the same target never share a slot, epoch, client,
/// or cookie jar.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionKey {
    target: String,
    run_id: String,
    phase: String,
    shard_id: String,
}

impl SessionKey {
    fn session_id(&self, epoch: u64) -> String {
        format!(
            "session:{}:{}:{}:{}#{epoch}",
            self.target, self.run_id, self.phase, self.shard_id
        )
    }
}

fn identity_of(value: &Value) -> Result<SessionKey, Fault> {
    let target = session_text(value, &["target"]).ok_or_else(|| {
        fault(
            "missing_session_identity",
            "session identity requires an established target",
        )
    })?;
    let run_id = session_text(value, &["run_id"]).ok_or_else(|| {
        fault(
            "missing_session_identity",
            "session identity requires an established run_id",
        )
    })?;
    let phase = session_text(value, &["phase"]).ok_or_else(|| {
        fault(
            "missing_session_identity",
            "session identity requires an established phase",
        )
    })?;
    if !PHASES.contains(&phase.as_str()) {
        return Err(fault(
            "invalid_phase",
            format!("phase {phase:?} is not one of A or B"),
        ));
    }
    let shard_id = session_text(value, &["shard_id", "shard"]).ok_or_else(|| {
        fault(
            "missing_session_identity",
            "a durable session row requires an established shard_id",
        )
    })?;
    Ok(SessionKey {
        target,
        run_id,
        phase,
        shard_id,
    })
}

/// §18.3 slot → session topology.
fn topology_for_slot(slot: &str) -> Option<&'static str> {
    Some(match slot {
        "MN-A" | "MN-B" | "IL-A" | "IL-B" | "WI-A" => TOPOLOGY_NONE,
        "WI-B" | "MI-B" => "per_worker",
        "MI-A" => "per_crawl_run",
        "OR-A" | "OR-B" => "per_shard",
        _ => return None,
    })
}

fn topology_of(map: &Map<String, Value>) -> Result<&'static str, Fault> {
    let declared = optional_str(map, "session_topology", "invalid_topology")?
        .or(optional_str(map, "shard_topology", "invalid_topology")?)
        .or(optional_str(map, "topology", "invalid_topology")?);
    let from_slot = match optional_str(map, "slot", "invalid_slot")? {
        None => None,
        Some(slot) => match topology_for_slot(slot) {
            Some(topology) => Some(topology),
            None => {
                return Err(fault(
                    "invalid_slot",
                    format!("slot {slot:?} is not one of the ten declared crawler slots"),
                ))
            }
        },
    };
    match (declared, from_slot) {
        (None, None) => Err(fault(
            "missing_topology",
            "session establishment requires an explicit session_topology or slot declaration",
        )),
        (Some(topology), None) => validate_topology(topology),
        (None, Some(topology)) => Ok(topology),
        (Some(declared), Some(from_slot)) => {
            let declared = validate_topology(declared)?;
            if declared == from_slot {
                Ok(from_slot)
            } else {
                Err(fault(
                    "invalid_topology",
                    format!(
                        "declared session topology {declared:?} disagrees with slot topology {from_slot:?}"
                    ),
                ))
            }
        }
    }
}

fn validate_topology(topology: &str) -> Result<&'static str, Fault> {
    if topology == TOPOLOGY_NONE {
        return Ok(TOPOLOGY_NONE);
    }
    for candidate in STATEFUL_TOPOLOGIES {
        if *candidate == topology {
            return Ok(candidate);
        }
    }
    Err(fault(
        "invalid_topology",
        format!(
            "session topology {topology:?} is not one of none, per_worker, per_crawl_run, or per_shard"
        ),
    ))
}

fn stealth_profile(preset: &str) -> Result<StealthProfile, Fault> {
    Ok(match preset {
        "chrome_148_linux" => presets::chrome_148_linux(),
        "chrome_148_windows" => presets::chrome_148_windows(),
        "chrome_148_macos" => presets::chrome_148_macos(),
        "chrome_148_ru" => presets::chrome_148_ru(),
        "chrome_148_cn" => presets::chrome_148_cn(),
        "chrome_148_de" => presets::chrome_148_de(),
        "chrome_148_jp" => presets::chrome_148_jp(),
        "firefox_135_linux" => presets::firefox_135_linux(),
        "firefox_135_macos" => presets::firefox_135_macos(),
        "firefox_135_windows" => presets::firefox_135_windows(),
        other => {
            return Err(fault(
                "invalid_preset",
                format!(
                    "stealth preset {other:?} is not one of the closed crawler preset set: {}",
                    PRESET_NAMES.join(", ")
                ),
            ))
        }
    })
}

fn preset_of(map: &Map<String, Value>) -> Result<String, Fault> {
    if let Some(preset) = optional_str(map, "preset", "invalid_preset")? {
        return Ok(preset.to_string());
    }
    if let Some(profile) = established(map, "profile") {
        let profile = value_object(profile, "invalid_preset", "profile")?;
        if let Some(preset) = optional_str(profile, "preset", "invalid_preset")? {
            return Ok(preset.to_string());
        }
    }
    Ok("chrome_148_linux".to_string())
}

fn grant_owner(grant: &Grant) -> Result<String, Fault> {
    let map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    Ok(required_str(map, "owner_domain", "grant_without_owner", "grant")?.to_string())
}

fn grant_principal(grant: &Grant) -> Result<Value, Fault> {
    let map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    if let Some(producer) = optional_str(map, "producer_id", "invalid_grant")? {
        return Ok(Value::String(producer.to_string()));
    }
    if let Some(principal) = optional_str(map, "principal_id", "invalid_grant")? {
        return Ok(Value::String(principal.to_string()));
    }
    Ok(missing(
        "not_observed",
        "the grant carries no producer or principal identity",
    ))
}

fn producer_identity(grant: &Grant) -> Result<(String, String), Fault> {
    let map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let producer_id = optional_str(map, "producer_id", "invalid_grant")?.ok_or_else(|| {
        fault(
            "missing_principal",
            "durable journal appends require a producer grant carrying producer_id",
        )
    })?;
    let manifest_digest = optional_str(map, "manifest_digest", "invalid_grant")?.ok_or_else(|| {
        fault(
            "missing_principal",
            "durable journal appends require a producer grant bound to a manifest_digest",
        )
    })?;
    Ok((producer_id.to_string(), manifest_digest.to_string()))
}

fn event_reference(event: &Value) -> Result<Value, Fault> {
    let map = value_object(event, "invalid_journal_view", "journal event")?;
    let journal_id = required_str(map, "journal_id", "invalid_journal_view", "journal event")?;
    let sequence = map
        .get("journal_sequence")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            fault(
                "invalid_journal_view",
                "journal event requires an integer journal_sequence",
            )
        })?;
    let event_id = required_str(map, "event_id", "invalid_journal_view", "journal event")?;
    let event_hash = required_str(map, "event_hash", "invalid_journal_view", "journal event")?;
    Ok(json!({
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": event_hash,
        "pointer": "",
    }))
}

fn receipt_event_ref(receipt: &Value) -> Result<Value, Fault> {
    let event = receipt.get("event").ok_or_else(|| {
        fault(
            "invalid_store_receipt",
            "a durable commit receipt must carry the appended event",
        )
    })?;
    event_reference(event)
}

fn absolute_url(text: &str) -> Option<Url> {
    let url = Url::parse(text).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    Some(url)
}

fn jar_cookie_evidence(client: &HttpClient) -> Value {
    match client.cookies().try_lock() {
        Ok(jar) => json!(jar.cookie_count()),
        Err(_) => missing(
            "not_observed",
            "cookie jar was busy while preparing the request",
        ),
    }
}

fn endpoint_url(value: &Value) -> Option<String> {
    for container in containers(value) {
        for key in [
            "url",
            "location",
            "target_url",
            "redirect_url",
            "endpoint_url",
            "actual_url",
            "action_url",
            "href",
        ] {
            match container.get(key) {
                Some(Value::String(text)) if !text.is_empty() => return Some(text.clone()),
                _ => continue,
            }
        }
        if let Some(endpoint) = container.get("endpoint").and_then(Value::as_object) {
            if let Some(Value::String(text)) = endpoint.get("url") {
                if !text.is_empty() {
                    return Some(text.clone());
                }
            }
        }
    }
    None
}

fn hop_kind(value: &Value) -> &'static str {
    for container in containers(value) {
        if container
            .get("previous_endpoint")
            .is_some_and(|previous| !is_missing(previous))
        {
            return "redirect";
        }
    }
    "request"
}

fn check_timepoint(now: &CheckedRecord, value: &Value, what: &str) -> Result<(), Fault> {
    let record = validate(OUTPUT_SCHEMA, value.clone()).map_err(|error| {
        fault(
            "invalid_timepoint",
            format!("{what} must be a schema-valid TimePoint: {}", error.detail),
        )
    })?;
    compare_deadline(now, &record).map(|_| ()).map_err(|error| {
        fault(
            "invalid_timepoint",
            format!(
                "{what} must share the session clock and boot: {} ({})",
                error.detail, error.code
            ),
        )
    })
}

/// A live session handle: the retained live client plus its generation row.
///
/// The client is a live continuation of the generation's connection pool and
/// cookie jar — not a frozen snapshot and not a process-global session. Only a
/// permitted `Send` handle and the epoch are published; no native page, DOM,
/// or solver handle crosses this seam.
pub struct LiveSession {
    pub client: HttpClient,
    pub generation: CheckedRecord,
}

/// Session lifecycle seam.
pub trait SessionManager: Send + Sync {
    /// Establish one stateful generation under a reserved control credit.
    fn establish(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<LiveSession, Fault>;
    /// Prepare the session's single in-flight request under a response credit.
    fn exchange(
        &self,
        grant: &Grant,
        request: &ReadOnlyRequest,
        credit: &ResponseCredit,
    ) -> Result<CheckedRecord, Fault>;
    /// Durably commit the acknowledged exchange boundary (and its hop cookies).
    fn commit_boundary(&self, grant: &Grant, receipt: &CheckedRecord) -> Result<(), Fault>;
    /// Retire the current generation and release its live client.
    fn retire(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<CheckedRecord, Fault>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Active,
    NeedsHandoff,
    Expired,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Active => STATUS_ACTIVE,
            Status::NeedsHandoff => STATUS_NEEDS_HANDOFF,
            Status::Expired => STATUS_EXPIRED,
        }
    }
}

struct Rotation {
    source: String,
    url: String,
    cookie: String,
}

struct InFlight {
    request_sequence: u64,
    credit_id: String,
    previous_request: Value,
    prepared_at: Value,
}

struct Slot {
    key: SessionKey,
    journal_id: String,
    session_id: String,
    owner_domain: String,
    topology: &'static str,
    status: Status,
    session_epoch: u64,
    owner_epoch: u64,
    revision: u64,
    deadline: Option<CheckedRecord>,
    client: Arc<HttpClient>,
    profile_ref: String,
    client_generation: String,
    bootstrap_kind: String,
    bootstrap_started_at: Value,
    bootstrap_completed_at: Value,
    bootstrap_attempt: u64,
    worker_identity: Value,
    created_at: Value,
    handoff_timestamp: Value,
    authenticated_state_evidence: Value,
    last_authenticated_url: Value,
    session_absolute_lifetime_seconds: Value,
    session_expires_at: Value,
    replacement_deadline: Value,
    last_committed_request_sequence: u64,
    cookie_generation: u64,
    last_success_at: Value,
    last_failure_reason: Value,
    request_sequence: u64,
    in_flight: Option<InFlight>,
    pending_rotations: Vec<Rotation>,
    establishment_ref: Value,
    last_boundary_ref: Option<Value>,
}

#[derive(Default)]
struct Registry {
    slots: HashMap<SessionKey, Slot>,
}

impl Registry {
    fn key_of_session_id(&self, session_id: &str) -> Option<SessionKey> {
        self.slots
            .iter()
            .find(|(_, slot)| slot.session_id == session_id)
            .map(|(key, _)| key.clone())
    }
}

/// Owner-local in-memory session manager.
///
/// One manager belongs to one owner and its durable journal. Session identity
/// is namespaced by `(target, run_id, phase, shard_id)`, so independent
/// rotating shards may share the process without sharing state.
pub struct MemorySessionManager {
    store: Arc<dyn OwnerStore>,
    clock: Arc<dyn ClockAuthority>,
    state: Mutex<Registry>,
    client_counter: AtomicU64,
}

impl MemorySessionManager {
    /// Build sessions around one owner store and one registered local clock.
    pub fn new(store: Arc<dyn OwnerStore>, clock: Arc<dyn ClockAuthority>) -> Self {
        Self {
            store,
            clock,
            state: Mutex::new(Registry::default()),
            client_counter: AtomicU64::new(0),
        }
    }

    fn lock(&self) -> Result<MutexGuard<'_, Registry>, Fault> {
        self.state.lock().map_err(|_| {
            fault(
                "internal_error",
                "session registry lock was poisoned by an earlier panic",
            )
        })
    }

    fn now(&self) -> Result<CheckedRecord, Fault> {
        self.clock.now()
    }

    /// Reserve-free read of one journal view. A journal that has not yet
    /// admitted a manifest is reported as absent so the first establishment
    /// surfaces the store's own `unknown_journal` fault without pretending a
    /// generation exists.
    fn journal_view(
        &self,
        grant: &Grant,
        journal_id: &str,
    ) -> Result<Option<Map<String, Value>>, Fault> {
        let query = validate(
            OUTPUT_SCHEMA,
            json!({"query": "journal", "journal_id": journal_id}),
        )?;
        match self.store.read(grant, &query) {
            Ok(view) => {
                let map = value_object(record_value(&view), "invalid_journal_view", "journal view")?;
                Ok(Some(map.clone()))
            }
            Err(error) if error.code == "unknown_journal" => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Latest durable generation for one session identity, if any.
    fn read_head(
        &self,
        grant: &Grant,
        journal_id: &str,
        key: &SessionKey,
    ) -> Result<Option<JournalHead>, Fault> {
        let Some(view) = self.journal_view(grant, journal_id)? else {
            return Ok(None);
        };
        let events = match view.get("events") {
            Some(Value::Array(events)) => events,
            _ => {
                return Err(fault(
                    "invalid_journal_view",
                    "journal view requires an established events array",
                ))
            }
        };
        let mut head: Option<JournalHead> = None;
        for event in events {
            let Some(data) = event
                .get("payload")
                .and_then(|payload| payload.get("data"))
                .and_then(Value::as_object)
            else {
                continue;
            };
            if let Some(row) = data.get(RECORD_SESSION_STATE) {
                let row = value_object(row, "invalid_journal_view", "session_state row")?;
                if !row_matches_key(row, key) {
                    continue;
                }
                let epoch = row
                    .get("session_epoch")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        fault(
                            "invalid_session_state",
                            "journaled session_state rows require an integer session_epoch",
                        )
                    })?;
                let status = row
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or(STATUS_ACTIVE)
                    .to_string();
                let revision = row.get("entity_revision").and_then(Value::as_u64).unwrap_or(1);
                let cookie_generation = row
                    .get("cookie_generation")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let last_committed = row
                    .get("last_committed_request_sequence")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let last_success_at = row.get("last_success_at").cloned().unwrap_or_else(|| {
                    missing("not_observed", "no accepted response has been observed")
                });
                match head.as_mut() {
                    Some(current) if epoch == current.session_epoch => {
                        current.previous_generation_status = Some(current.status.clone());
                        current.status = status;
                        current.revision = revision;
                        current.last_success_at = last_success_at;
                        current.row = Value::Object(row.clone());
                    }
                    Some(current) if epoch < current.session_epoch => {}
                    _ => {
                        let previous_generation_status =
                            head.as_ref().map(|current| current.status.clone());
                        head = Some(JournalHead {
                            session_epoch: epoch,
                            status,
                            revision,
                            cookie_generation,
                            last_committed_request_sequence: last_committed,
                            last_success_at,
                            last_boundary_ref: None,
                            previous_generation_status,
                            row: Value::Object(row.clone()),
                            establishment_ref: event_reference(event)?,
                        });
                    }
                }
            } else if let Some(boundary) = data.get(RECORD_SESSION_BOUNDARY) {
                let boundary = value_object(boundary, "invalid_journal_view", "session boundary")?;
                if !row_matches_key(boundary, key) {
                    continue;
                }
                let Some(current) = head.as_mut() else {
                    continue;
                };
                if boundary.get("session_epoch").and_then(Value::as_u64)
                    != Some(current.session_epoch)
                {
                    continue;
                }
                current.last_committed_request_sequence = current
                    .last_committed_request_sequence
                    .max(
                        boundary
                            .get("request_sequence")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                    );
                current.cookie_generation = current.cookie_generation.max(
                    boundary
                        .get("cookie_generation")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                );
                if let Some(committed_at) = boundary.get("committed_at") {
                    if !is_missing(committed_at) {
                        current.last_success_at = committed_at.clone();
                    }
                }
                current.last_boundary_ref = Some(event_reference(event)?);
            }
        }
        Ok(head)
    }

    /// Append one session lifecycle event through the owner-local journal.
    fn append(
        &self,
        grant: &Grant,
        journal_id: &str,
        event_kind: &str,
        data: Value,
        causal_refs: Vec<Value>,
    ) -> Result<CheckedRecord, Fault> {
        let (producer_id, manifest_digest) = producer_identity(grant)?;
        let transaction = validate(
            OUTPUT_SCHEMA,
            json!({
                "operation": "append_event",
                "journal_id": journal_id,
                "principal": {
                    "producer_id": producer_id,
                    "manifest_digest": manifest_digest,
                },
                "submission": {
                    "producer_sequence": missing(
                        "not_applicable",
                        "session lifecycle effects are unsequenced owner effects",
                    ),
                    "event_kind": event_kind,
                    "event_schema_version": EVIDENCE_SCHEMA_VERSION,
                    "occurred_at": missing(
                        "not_observed",
                        "session lifecycle effects have no source occurrence",
                    ),
                    "payload": {
                        "data": data,
                        "measurements": [],
                        "evidence_refs": [],
                        "artifact_refs": [],
                    },
                },
                "causal_refs": Value::Array(causal_refs),
            }),
        )?;
        let receipt = self.store.transact(grant, &transaction)?;
        let map = value_object(record_value(&receipt), "invalid_store_receipt", "commit receipt")?;
        match established(map, "durable") {
            Some(Value::Bool(true)) => Ok(receipt),
            _ => Err(fault(
                "session_not_durable",
                "the owner store did not acknowledge the session effect as durable",
            )),
        }
    }

    fn control_deadline(
        &self,
        credit: &ControlCredit,
        target: &str,
        now: &CheckedRecord,
    ) -> Result<CheckedRecord, Fault> {
        let reservation = record_value(&credit.reservation);
        let map = value_object(reservation, "invalid_credit", "control credit reservation")?;
        let kind = required_str(map, "kind", "invalid_credit", "control credit")?;
        if kind != "control" && kind != "page_control" {
            return Err(fault(
                "invalid_credit",
                format!(
                    "control credit kind {kind:?} is not a control or page_control reservation"
                ),
            ));
        }
        check_credit_target(map, target)?;
        let deadline = established(map, "deadline").cloned().ok_or_else(|| {
            fault(
                "invalid_credit",
                "control credit reservation carries no deadline",
            )
        })?;
        let deadline = validate(OUTPUT_SCHEMA, deadline)?;
        if compare_deadline(now, &deadline)? == Ordering::Greater {
            return Err(fault(
                "control_credit_expired",
                "the control credit's finite call bound elapsed before the session effect",
            ));
        }
        Ok(deadline)
    }

    fn response_credit(
        &self,
        credit: &ResponseCredit,
        target: &str,
        now: &CheckedRecord,
    ) -> Result<(String, CheckedRecord), Fault> {
        let reservation = record_value(&credit.reservation);
        let map = value_object(reservation, "invalid_credit", "response credit reservation")?;
        let kind = required_str(map, "kind", "invalid_credit", "response credit")?;
        if kind != "response" {
            return Err(fault(
                "invalid_credit",
                format!("credit kind {kind:?} is not a response reservation"),
            ));
        }
        check_credit_target(map, target)?;
        let credit_id = required_str(map, "credit_id", "invalid_credit", "response credit")?;
        let deadline = established(map, "deadline").cloned().ok_or_else(|| {
            fault(
                "invalid_credit",
                "response credit reservation carries no deadline",
            )
        })?;
        let deadline = validate(OUTPUT_SCHEMA, deadline)?;
        if compare_deadline(now, &deadline)? == Ordering::Greater {
            return Err(fault(
                "response_credit_expired",
                "the response credit's finite call bound elapsed before the request was prepared",
            ));
        }
        Ok((credit_id.to_string(), deadline))
    }

    /// Apply every staged rotating cookie to the retained live client.
    ///
    /// Returns `(applied, still_pending)`. Application happens only through the
    /// generation's own client jar, never a process-global session.
    fn apply_pending(slot: &mut Slot) -> (usize, usize) {
        let mut applied = 0usize;
        let mut remaining = Vec::new();
        for rotation in slot.pending_rotations.drain(..) {
            match absolute_url(&rotation.url) {
                Some(url) if slot.client.set_cookie_str_sync(&url, &rotation.cookie) => {
                    applied += 1;
                }
                _ => remaining.push(rotation),
            }
        }
        slot.pending_rotations = remaining;
        (applied, slot.pending_rotations.len())
    }

    /// Journal the expiry of a live generation (active → expired) once.
    fn expire_slot(
        &self,
        grant: &Grant,
        slot: &mut Slot,
        now: &Value,
    ) -> Result<(), Fault> {
        if slot.status == Status::Expired {
            return Ok(());
        }
        let row = build_session_row(RowSpec {
            key: &slot.key,
            topology: slot.topology,
            session_epoch: slot.session_epoch,
            owner_epoch: slot.owner_epoch,
            status: STATUS_EXPIRED,
            bootstrap_kind: &slot.bootstrap_kind,
            bootstrap_started_at: slot.bootstrap_started_at.clone(),
            bootstrap_completed_at: slot.bootstrap_completed_at.clone(),
            bootstrap_attempt: slot.bootstrap_attempt,
            cookie_generation: slot.cookie_generation,
            last_committed_request_sequence: slot.last_committed_request_sequence,
            profile_ref: &slot.profile_ref,
            client_generation: &slot.client_generation,
            worker_identity: slot.worker_identity.clone(),
            handoff_timestamp: slot.handoff_timestamp.clone(),
            authenticated_state_evidence: slot.authenticated_state_evidence.clone(),
            last_authenticated_url: slot.last_authenticated_url.clone(),
            verified_session_birth: missing(
                "not_observed",
                "no verified session birth has been established",
            ),
            session_absolute_lifetime_seconds: slot.session_absolute_lifetime_seconds.clone(),
            session_expires_at: slot.session_expires_at.clone(),
            replacement_deadline: slot.replacement_deadline.clone(),
            last_success_at: slot.last_success_at.clone(),
            last_failure_reason: Value::String(EXPIRY_FAILURE_REASON.to_string()),
            redacted_solver_harvest_evidence: missing(
                "not_applicable",
                "no solver mechanism was evidenced for this generation",
            ),
            entity_revision: slot.revision + 1,
            created_at: slot.created_at.clone(),
            updated_at: now.clone(),
        })?;
        let mut refs = vec![slot.establishment_ref.clone()];
        if let Some(boundary) = &slot.last_boundary_ref {
            refs.push(boundary.clone());
        }
        self.append(
            grant,
            &slot.journal_id,
            EVENT_EXPIRED,
            json!({
                "session_state": record_value(&row).clone(),
                "failure_reason": EXPIRY_FAILURE_REASON,
            }),
            refs,
        )?;
        slot.status = Status::Expired;
        slot.revision += 1;
        slot.last_failure_reason = Value::String(EXPIRY_FAILURE_REASON.to_string());
        Ok(())
    }

    fn session_deadline_elapsed(
        &self,
        slot: &Slot,
        now: &CheckedRecord,
    ) -> Result<bool, Fault> {
        match &slot.deadline {
            None => Ok(false),
            Some(deadline) => Ok(compare_deadline(now, deadline)? == Ordering::Greater),
        }
    }
}

struct JournalHead {
    session_epoch: u64,
    status: String,
    revision: u64,
    cookie_generation: u64,
    last_committed_request_sequence: u64,
    last_success_at: Value,
    last_boundary_ref: Option<Value>,
    previous_generation_status: Option<String>,
    row: Value,
    establishment_ref: Value,
}

fn row_matches_key(row: &Map<String, Value>, key: &SessionKey) -> bool {
    let text = |field: &str| row.get(field).and_then(Value::as_str);
    text("target") == Some(key.target.as_str())
        && text("run_id") == Some(key.run_id.as_str())
        && text("phase") == Some(key.phase.as_str())
        && text("shard_id") == Some(key.shard_id.as_str())
}

fn check_credit_target(map: &Map<String, Value>, target: &str) -> Result<(), Fault> {
    let credit_target = established(map, "target").ok_or_else(|| {
        fault(
            "invalid_credit",
            "admission credits must name the active target they were admitted for",
        )
    })?;
    match credit_target {
        Value::String(text) if text == target => Ok(()),
        Value::String(text) => Err(fault(
            "credit_target_mismatch",
            format!("credit is admitted for target {text:?}, not {target:?}"),
        )),
        _ => Err(fault(
            "invalid_credit",
            "credit target must be an established string",
        )),
    }
}

struct RowSpec<'a> {
    key: &'a SessionKey,
    topology: &'a str,
    session_epoch: u64,
    owner_epoch: u64,
    status: &'a str,
    bootstrap_kind: &'a str,
    bootstrap_started_at: Value,
    bootstrap_completed_at: Value,
    bootstrap_attempt: u64,
    cookie_generation: u64,
    last_committed_request_sequence: u64,
    profile_ref: &'a str,
    client_generation: &'a str,
    worker_identity: Value,
    handoff_timestamp: Value,
    authenticated_state_evidence: Value,
    last_authenticated_url: Value,
    verified_session_birth: Value,
    session_absolute_lifetime_seconds: Value,
    session_expires_at: Value,
    replacement_deadline: Value,
    last_success_at: Value,
    last_failure_reason: Value,
    redacted_solver_harvest_evidence: Value,
    entity_revision: u64,
    created_at: Value,
    updated_at: Value,
}

/// Complete §12 `session_state` row. No field is ever omitted: unobserved
/// values are typed `Missing` envelopes, and the restricted cookie snapshot is
/// never represented by a substituted locator or hash.
fn build_session_row(spec: RowSpec<'_>) -> Result<CheckedRecord, Fault> {
    validate(
        SESSION_SCHEMA,
        json!({
            "record_type": RECORD_SESSION_STATE,
            "schema_version": SESSION_RECORD_VERSION,
            "target": spec.key.target,
            "run_id": spec.key.run_id,
            "phase": spec.key.phase,
            "shard_id": spec.key.shard_id,
            "session_epoch": spec.session_epoch,
            "shard_topology": spec.topology,
            "worker_identity": spec.worker_identity,
            "owner_epoch": spec.owner_epoch,
            "status": spec.status,
            "bootstrap_kind": spec.bootstrap_kind,
            "bootstrap_started_at": spec.bootstrap_started_at,
            "bootstrap_completed_at": spec.bootstrap_completed_at,
            "bootstrap_attempt": spec.bootstrap_attempt,
            "cookie_jar_snapshot": missing(
                "not_observed",
                "cookie bytes are restricted evidence and never enter ordinary journal payloads; recovery is cold",
            ),
            "cookie_generation": spec.cookie_generation,
            "last_committed_request_sequence": spec.last_committed_request_sequence,
            "profile_ref": spec.profile_ref,
            "client_generation": spec.client_generation,
            "last_authenticated_url": spec.last_authenticated_url,
            "handoff_timestamp": spec.handoff_timestamp,
            "authenticated_state_evidence": spec.authenticated_state_evidence,
            "verified_session_birth": spec.verified_session_birth,
            "session_absolute_lifetime_seconds": spec.session_absolute_lifetime_seconds,
            "session_expires_at": spec.session_expires_at,
            "replacement_deadline": spec.replacement_deadline,
            "last_success_at": spec.last_success_at,
            "last_failure_reason": spec.last_failure_reason,
            "redacted_solver_harvest_evidence": spec.redacted_solver_harvest_evidence,
            "entity_revision": spec.entity_revision,
            "created_at": spec.created_at,
            "updated_at": spec.updated_at,
        }),
    )
}

/// Rewrite the latest nonactive generation row as `retired`, preserving its
/// identity and evidence while advancing the entity revision. §16.8 requires
/// a nonactive generation to be retired before a new epoch supersedes it.
fn retire_prior_row(current: &JournalHead, now: &Value) -> Result<CheckedRecord, Fault> {
    let mut row = current.row.as_object().cloned().ok_or_else(|| {
        fault(
            "invalid_session_state",
            "journaled session_state row must be an object",
        )
    })?;
    row.insert("status".to_string(), json!(STATUS_RETIRED));
    row.insert("entity_revision".to_string(), json!(current.revision + 1));
    row.insert("updated_at".to_string(), now.clone());
    row.insert(
        "last_committed_request_sequence".to_string(),
        json!(current.last_committed_request_sequence),
    );
    row.insert("cookie_generation".to_string(), json!(current.cookie_generation));
    row.insert("last_success_at".to_string(), current.last_success_at.clone());
    validate(SESSION_SCHEMA, Value::Object(row))
}

fn boundary_row(slot: &Slot, request_sequence: u64, now: &Value, pending: usize) -> Result<CheckedRecord, Fault> {
    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": RECORD_SESSION_BOUNDARY,
            "target": slot.key.target,
            "run_id": slot.key.run_id,
            "phase": slot.key.phase,
            "shard_id": slot.key.shard_id,
            "session_id": slot.session_id,
            "session_epoch": slot.session_epoch,
            "owner_epoch": slot.owner_epoch,
            "request_sequence": request_sequence,
            "cookie_generation": slot.cookie_generation,
            "profile_ref": slot.profile_ref,
            "client_generation": slot.client_generation,
            "pending_rotations": pending as u64,
            "committed_at": now.clone(),
        }),
    )
}

fn parse_rotations(map: &Map<String, Value>) -> Result<Vec<Rotation>, Fault> {
    let items = match established(map, "rotations") {
        None => return Ok(Vec::new()),
        Some(Value::Array(items)) => items.clone(),
        Some(_) => {
            return Err(fault(
                "invalid_rotations",
                "rotations must be an established array of rotating cookie hops",
            ))
        }
    };
    let mut rotations = Vec::new();
    for item in items {
        let hop = value_object(&item, "invalid_rotations", "rotation")?;
        let source = required_str(hop, "source", "invalid_rotations", "rotation")?;
        if !ROTATION_SOURCES.contains(&source) {
            return Err(fault(
                "invalid_rotations",
                format!(
                    "rotation source {source:?} is not one of response, redirect, or solver; every hop is serialized"
                ),
            ));
        }
        let url = required_str(hop, "url", "invalid_rotations", "rotation")?;
        if absolute_url(url).is_none() {
            return Err(fault(
                "invalid_rotations",
                format!("rotation url {url:?} is not an absolute http(s) URL"),
            ));
        }
        let cookies = match established(hop, "cookies") {
            Some(Value::Array(cookies)) if !cookies.is_empty() => cookies.clone(),
            _ => {
                return Err(fault(
                    "invalid_rotations",
                    "rotation requires a nonempty cookies array of raw cookie strings",
                ))
            }
        };
        for cookie in cookies {
            let raw = match cookie {
                Value::String(text) if !text.is_empty() => text,
                _ => {
                    return Err(fault(
                        "invalid_rotations",
                        "rotation cookies must be nonempty raw cookie strings",
                    ))
                }
            };
            rotations.push(Rotation {
                source: source.to_string(),
                url: url.to_string(),
                cookie: raw,
            });
        }
    }
    if rotations.iter().any(|hop| hop.source == "redirect")
        && established(map, "redirect").is_none()
    {
        return Err(fault(
            "missing_redirect_evidence",
            "a redirect rotation requires the redirect record that evidences the hop",
        ));
    }
    if rotations.iter().any(|hop| hop.source == "solver")
        && established(map, "solver").is_none()
    {
        return Err(fault(
            "invalid_solver_evidence",
            "a solver rotation requires the solver evidence record that evidences the hop",
        ));
    }
    Ok(rotations)
}

impl SessionManager for MemorySessionManager {
    fn establish(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<LiveSession, Fault> {
        let map = as_object(request, "invalid_request", "session request")?;
        let topology = validate_topology(topology_of(map)?)?;
        if topology == TOPOLOGY_NONE {
            return Err(fault(
                "topology_none",
                "a none-topology slot has no durable session; no session_state row is written and stateless acquisition does not use a session",
            ));
        }
        let key = identity_of(record_value(request))?;
        let journal_id =
            required_str(map, "journal_id", "missing_journal_id", "session request")?.to_string();
        let owner_domain = grant_owner(grant)?;
        let preset = preset_of(map)?;
        stealth_profile(&preset)?;
        let profile_ref = optional_str(map, "profile_ref", "invalid_profile_ref")?
            .map(str::to_string)
            .unwrap_or_else(|| format!("profile:{preset}"));
        let owner_epoch = optional_u64(map, "owner_epoch", "invalid_owner_epoch")?.unwrap_or(1);
        let bootstrap_attempt =
            optional_u64(map, "bootstrap_attempt", "invalid_bootstrap_attempt")?.unwrap_or(0);
        let handoff_timestamp = establish_handoff(map)?;
        let bootstrap_kind = bootstrap_kind_of(map, &handoff_timestamp)?;
        let authenticated_state_evidence =
            optional_evidence(map, "authenticated_state_evidence", "invalid_authenticated_state")?;
        let last_authenticated_url =
            optional_established(map, "last_authenticated_url", "invalid_last_authenticated_url")?;
        let session_absolute_lifetime_seconds = optional_established(
            map,
            "session_absolute_lifetime_seconds",
            "invalid_session_lifetime",
        )?;
        let replacement_deadline =
            optional_established(map, "replacement_deadline", "invalid_replacement_deadline")?;
        let worker_identity = match established(map, "worker_identity") {
            Some(Value::String(text)) if !text.is_empty() => Value::String(text.clone()),
            Some(_) => {
                return Err(fault(
                    "invalid_request",
                    "worker_identity must be a nonempty string when established",
                ))
            }
            None => grant_principal(grant)?,
        };

        let now = self.now()?;
        let credit_deadline = self.control_deadline(credit, &key.target, &now)?;
        let session_deadline = match established(map, "deadline") {
            Some(value) => validate(OUTPUT_SCHEMA, value.clone()).map_err(|error| {
                fault(
                    "invalid_timepoint",
                    format!("session deadline must be a TimePoint: {}", error.detail),
                )
            })?,
            None => credit_deadline,
        };
        if compare_deadline(&now, &session_deadline)? == Ordering::Greater {
            return Err(fault(
                "bootstrap_deadline_exceeded",
                "the declared bootstrap deadline elapsed before the session was established",
            ));
        }
        let session_expires_at = optional_established(map, "session_expires_at", "invalid_session_expires_at")?;
        if !is_missing(&session_expires_at) {
            check_timepoint(&now, &session_expires_at, "session_expires_at")?;
        }
        if !is_missing(&replacement_deadline) {
            check_timepoint(&now, &replacement_deadline, "replacement_deadline")?;
        }
        if !is_missing(&handoff_timestamp) {
            check_timepoint(&now, &handoff_timestamp, "handoff_timestamp")?;
        }

        let mut registry = self.lock()?;
        if let Some(status) = registry.slots.get(&key).map(|slot| slot.status) {
            if status != Status::Expired {
                return Err(fault(
                    "session_exists",
                    format!(
                        "a live generation already owns session identity {:?}; one generation has exactly one current owner",
                        key
                    ),
                ));
            }
            // A previously expired generation is nonactive: its expiry is
            // already journaled, so it is dropped before the new epoch.
            registry.slots.remove(&key);
        }

        let head = self.read_head(grant, &journal_id, &key)?;
        let (session_epoch, event_kind, recovered) = match &head {
            None => (1, EVENT_ESTABLISHED, false),
            Some(current) => {
                let next = current.session_epoch.saturating_add(1);
                let crashed = matches!(
                    current.status.as_str(),
                    STATUS_ACTIVE | STATUS_NEEDS_HANDOFF | "establishing" | "quiescent"
                );
                (
                    next,
                    if crashed { EVENT_RECOVERED } else { EVENT_ESTABLISHED },
                    crashed,
                )
            }
        };
        // §16.8: a nonactive generation is retired before a new epoch. A
        // crashed (still-active) generation is not rewritten here; recovery
        // fences it by advancing the epoch instead.
        if let Some(current) = &head {
            if matches!(current.status.as_str(), STATUS_EXPIRED | "failed") {
                let retired = retire_prior_row(current, &record_value(&now).clone())?;
                let mut refs = vec![current.establishment_ref.clone()];
                if let Some(boundary) = &current.last_boundary_ref {
                    refs.push(boundary.clone());
                }
                self.append(
                    grant,
                    &journal_id,
                    EVENT_RETIRED,
                    json!({
                        "session_state": record_value(&retired).clone(),
                        "superseded_by_session_epoch": session_epoch,
                        "retire_reason": "superseded_by_new_generation",
                    }),
                    refs,
                )?;
            }
        }
        let status = if bootstrap_kind == "handoff"
            && is_missing(&authenticated_state_evidence)
        {
            Status::NeedsHandoff
        } else {
            Status::Active
        };

        let client = build_client(&preset)?;
        let client_generation = format!(
            "client-{}-{}",
            session_epoch,
            self.client_counter.fetch_add(1, AtomicOrdering::SeqCst)
        );
        let row = build_session_row(RowSpec {
            key: &key,
            topology,
            session_epoch,
            owner_epoch,
            status: status.as_str(),
            bootstrap_kind: &bootstrap_kind,
            bootstrap_started_at: record_value(&now).clone(),
            bootstrap_completed_at: match status {
                Status::Active => record_value(&now).clone(),
                _ => missing(
                    "not_observed",
                    "bootstrap has not completed; an authenticated handoff is still required",
                ),
            },
            bootstrap_attempt,
            cookie_generation: 0,
            last_committed_request_sequence: 0,
            profile_ref: &profile_ref,
            client_generation: &client_generation,
            worker_identity: worker_identity.clone(),
            handoff_timestamp: handoff_timestamp.clone(),
            authenticated_state_evidence: authenticated_state_evidence.clone(),
            last_authenticated_url: last_authenticated_url.clone(),
            verified_session_birth: missing(
                "not_observed",
                "a fresh client and a handoff receipt do not establish original session birth",
            ),
            session_absolute_lifetime_seconds: session_absolute_lifetime_seconds.clone(),
            session_expires_at: session_expires_at.clone(),
            replacement_deadline: replacement_deadline.clone(),
            last_success_at: missing(
                "not_observed",
                "no accepted response has been observed for this generation",
            ),
            last_failure_reason: missing(
                "not_applicable",
                "a newly established generation has no failure",
            ),
            redacted_solver_harvest_evidence: missing(
                "not_applicable",
                "no solver mechanism was evidenced for this generation",
            ),
            entity_revision: 1,
            created_at: record_value(&now).clone(),
            updated_at: record_value(&now).clone(),
        })?;
        let receipt = self.append(
            grant,
            &journal_id,
            event_kind,
            json!({
                "session_state": record_value(&row).clone(),
                "recovered_from_crash": recovered,
                "previous_session_epoch": match &head {
                    Some(current) => json!(current.session_epoch),
                    None => missing(
                        "not_applicable",
                        "this is the first generation for the session identity",
                    ),
                },
                "previous_generation_status": match &head {
                    Some(current) => Value::String(current.status.clone()),
                    None => missing(
                        "not_applicable",
                        "this is the first generation for the session identity",
                    ),
                },
                "previous_entity_revision": match &head {
                    Some(current) => json!(current.revision),
                    None => missing(
                        "not_applicable",
                        "this is the first generation for the session identity",
                    ),
                },
                "previous_last_success_at": match &head {
                    Some(current) => current.last_success_at.clone(),
                    None => missing(
                        "not_applicable",
                        "this is the first generation for the session identity",
                    ),
                },
                "control_credit_id": record_value(&credit.reservation)
                    .get("credit_id")
                    .cloned()
                    .unwrap_or_else(|| missing(
                        "not_observed",
                        "control credit carried no identifier",
                    )),
            }),
            Vec::new(),
        )?;
        let slot = Slot {
            key: key.clone(),
            journal_id,
            session_id: key.session_id(session_epoch),
            owner_domain,
            topology,
            status,
            session_epoch,
            owner_epoch,
            revision: 1,
            deadline: Some(session_deadline),
            client: Arc::new(client.clone()),
            profile_ref,
            client_generation,
            bootstrap_kind,
            bootstrap_started_at: record_value(&now).clone(),
            bootstrap_completed_at: match status {
                Status::Active => record_value(&now).clone(),
                _ => missing(
                    "not_observed",
                    "bootstrap has not completed; an authenticated handoff is still required",
                ),
            },
            bootstrap_attempt,
            worker_identity,
            created_at: record_value(&now).clone(),
            handoff_timestamp,
            authenticated_state_evidence,
            last_authenticated_url,
            session_absolute_lifetime_seconds,
            session_expires_at,
            replacement_deadline,
            last_committed_request_sequence: 0,
            cookie_generation: 0,
            last_success_at: missing(
                "not_observed",
                "no accepted response has been observed for this generation",
            ),
            last_failure_reason: missing(
                "not_applicable",
                "a newly established generation has no failure",
            ),
            request_sequence: 0,
            in_flight: None,
            pending_rotations: Vec::new(),
            establishment_ref: receipt_event_ref(record_value(&receipt))?,
            last_boundary_ref: None,
        };
        registry.slots.insert(key, slot);
        Ok(LiveSession {
            client,
            generation: row,
        })
    }

    fn exchange(
        &self,
        grant: &Grant,
        request: &ReadOnlyRequest,
        credit: &ResponseCredit,
    ) -> Result<CheckedRecord, Fault> {
        let wrapper = record_value(&request.record);
        let now = self.now()?;
        let mut registry = self.lock()?;
        let resolved = resolve_key(&registry, wrapper)?;
        let key = resolved.clone();
        let slot = registry.slots.get_mut(&key).ok_or_else(|| {
            fault(
                "no_live_session",
                format!("no live generation owns session identity {key:?}"),
            )
        })?;
        if slot.owner_domain != grant_owner(grant)? {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "session belongs to {:?}; the presented grant is another owner",
                    slot.owner_domain
                ),
            ));
        }
        if slot.status == Status::NeedsHandoff {
            return Err(fault(
                "needs_handoff",
                "the generation is waiting for an authenticated handoff; a handoff receipt is not a live session",
            ));
        }
        if slot.status == Status::Expired {
            return Err(fault(
                "session_expired",
                "the generation expired; retire it and establish a new epoch",
            ));
        }
        if self.session_deadline_elapsed(slot, &now)? {
            self.expire_slot(grant, slot, &record_value(&now).clone())?;
            return Err(fault(
                "session_expired",
                "the session deadline elapsed on the authority clock before the request was prepared",
            ));
        }
        let (credit_id, credit_deadline) = self.response_credit(credit, &key.target, &now)?;
        if slot.in_flight.is_some() {
            return Err(fault(
                "session_busy",
                "one stateful request is already in flight; concurrent stateful requests are serialized",
            ));
        }
        let url = endpoint_url(wrapper).ok_or_else(|| {
            fault(
                "invalid_request",
                "the authorized read-only request carries no endpoint url",
            )
        })?;
        if absolute_url(&url).is_none() {
            return Err(fault(
                "invalid_request",
                format!("endpoint url {url:?} is not an absolute http(s) URL"),
            ));
        }

        // Rotating cookies are applied before the next request is prepared.
        let (applied, still_pending) = Self::apply_pending(slot);
        slot.cookie_generation += applied as u64;
        if still_pending > 0 {
            return Err(fault(
                "cookie_application_failed",
                "a staged rotating cookie could not be applied to the live client; no request is prepared before cookie application succeeds",
            ));
        }

        let request_sequence = slot.request_sequence + 1;
        let receipt = validate(
            OUTPUT_SCHEMA,
            json!({
                "record_type": "session_exchange",
                "session_id": slot.session_id,
                "target": slot.key.target,
                "run_id": slot.key.run_id,
                "phase": slot.key.phase,
                "shard_id": slot.key.shard_id,
                "shard_topology": slot.topology,
                "session_epoch": slot.session_epoch,
                "owner_epoch": slot.owner_epoch,
                "request_sequence": request_sequence,
                "cookie_sequence": slot.cookie_generation,
                "cookies_applied": applied as u64,
                "cookie_count": jar_cookie_evidence(&slot.client),
                "endpoint_url": url,
                "hop": hop_kind(wrapper),
                "effect_policy": "read_only",
                "max_inflight_per_session": 1,
                "serialized": true,
                "credit_id": credit_id,
                "credit_deadline": record_value(&credit_deadline).clone(),
                "prepared_at": record_value(&now).clone(),
            }),
        )?;
        slot.request_sequence = request_sequence;
        slot.in_flight = Some(InFlight {
            request_sequence,
            credit_id,
            previous_request: wrapper.clone(),
            prepared_at: record_value(&now).clone(),
        });
        Ok(receipt)
    }

    fn commit_boundary(&self, grant: &Grant, receipt: &CheckedRecord) -> Result<(), Fault> {
        let map = as_object(receipt, "invalid_receipt", "session exchange receipt")?;
        let session_id = required_str(map, "session_id", "invalid_receipt", "exchange receipt")?;
        let request_sequence =
            required_u64(map, "request_sequence", "invalid_receipt", "exchange receipt")?;
        let epoch_claim =
            required_u64(map, "session_epoch", "invalid_receipt", "exchange receipt")?;
        let credit_id = required_str(map, "credit_id", "invalid_receipt", "exchange receipt")?;
        let now = self.now()?;
        let mut registry = self.lock()?;
        let key = registry.key_of_session_id(session_id).ok_or_else(|| {
            fault(
                "no_live_session",
                format!("no live generation has session_id {session_id:?}"),
            )
        })?;
        let slot = registry.slots.get_mut(&key).ok_or_else(|| {
            fault(
                "no_live_session",
                "the session generation ended before the boundary was committed",
            )
        })?;
        if slot.owner_domain != grant_owner(grant)? {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "session belongs to {:?}; the presented grant is another owner",
                    slot.owner_domain
                ),
            ));
        }
        for (field, expected) in [
            ("target", slot.key.target.as_str()),
            ("run_id", slot.key.run_id.as_str()),
            ("phase", slot.key.phase.as_str()),
            ("shard_id", slot.key.shard_id.as_str()),
        ] {
            if let Some(claimed) = optional_str(map, field, "invalid_receipt")? {
                if claimed != expected {
                    return Err(fault(
                        "session_mismatch",
                        format!(
                            "receipt claims {field}={claimed:?} but session {session_id:?} is {expected:?}"
                        ),
                    ));
                }
            }
        }
        if epoch_claim != slot.session_epoch {
            return Err(fault(
                "stale_boundary",
                format!(
                    "boundary claims session_epoch {epoch_claim} but the current generation is {}; a stale completion has no effect",
                    slot.session_epoch
                ),
            ));
        }
        if slot.status == Status::Expired {
            return Err(fault(
                "session_expired",
                "the generation expired before the response boundary was committed",
            ));
        }
        if self.session_deadline_elapsed(slot, &now)? {
            self.expire_slot(grant, slot, &record_value(&now).clone())?;
            return Err(fault(
                "session_expired",
                "completion requires an unexpired authority-clock deadline",
            ));
        }
        let Some(in_flight) = slot.in_flight.as_ref() else {
            return Err(fault(
                "no_in_flight_exchange",
                "no prepared exchange awaits a durable boundary for this session",
            ));
        };
        if in_flight.request_sequence != request_sequence || in_flight.credit_id != credit_id {
            return Err(fault(
                "stale_boundary",
                "the receipt does not match the prepared exchange's sequence and credit; a stale completion has no effect",
            ));
        }
        let prepared_at = in_flight.prepared_at.clone();
        let previous_request = in_flight.previous_request.clone();

        // Every hop is admitted inside this serialization window: the redirect
        // is re-authorized as read-only and in scope, and the solver evidence
        // names its capability. Cookie mutations from both are staged below.
        if let Some(redirect) = established(map, "redirect") {
            let redirect = validate(OUTPUT_SCHEMA, redirect.clone())?;
            let previous = ReadOnlyRequest {
                record: validate(OUTPUT_SCHEMA, previous_request)?,
            };
            authorize_redirect(grant, &previous, &redirect)?;
        }
        if let Some(solver) = established(map, "solver") {
            let solver = value_object(solver, "invalid_solver_evidence", "solver evidence")?;
            required_str(
                solver,
                "capability_id",
                "invalid_solver_evidence",
                "solver evidence",
            )?;
        }
        let rotations = parse_rotations(map)?;

        let mut applied = 0usize;
        for rotation in rotations {
            match absolute_url(&rotation.url) {
                Some(url) if slot.client.set_cookie_str_sync(&url, &rotation.cookie) => {
                    applied += 1;
                }
                _ => slot.pending_rotations.push(rotation),
            }
        }
        slot.cookie_generation += applied as u64;
        let pending = slot.pending_rotations.len();
        let boundary = boundary_row(slot, request_sequence, &record_value(&now).clone(), pending)?;
        let mut refs = vec![slot.establishment_ref.clone()];
        if let Some(previous) = &slot.last_boundary_ref {
            refs.push(previous.clone());
        }
        let committed = self.append(
            grant,
            &slot.journal_id,
            EVENT_BOUNDARY,
            json!({
                "session_boundary": record_value(&boundary).clone(),
                "redirect_hop": established(map, "redirect").is_some(),
                "solver_hop": established(map, "solver").is_some(),
                "prepared_at": prepared_at,
            }),
            refs,
        )?;
        slot.last_committed_request_sequence = request_sequence;
        slot.last_boundary_ref = Some(receipt_event_ref(record_value(&committed))?);
        slot.last_success_at = record_value(&now).clone();
        slot.in_flight = None;
        Ok(())
    }

    fn retire(
        &self,
        grant: &Grant,
        request: &CheckedRecord,
        credit: &ControlCredit,
    ) -> Result<CheckedRecord, Fault> {
        let map = as_object(request, "invalid_request", "retire request")?;
        let now = self.now()?;
        let mut registry = self.lock()?;
        let key = resolve_key(&registry, record_value(request))?;
        let slot = registry.slots.get_mut(&key).ok_or_else(|| {
            fault(
                "no_live_session",
                format!("no live generation owns session identity {key:?}"),
            )
        })?;
        if slot.owner_domain != grant_owner(grant)? {
            return Err(fault(
                "unauthorized_owner",
                format!(
                    "session belongs to {:?}; the presented grant is another owner",
                    slot.owner_domain
                ),
            ));
        }
        self.control_deadline(credit, &key.target, &now)?;
        if let Some(expected) =
            session_u64(record_value(request), &["expected_epoch", "session_epoch"])?
        {
            if expected != slot.session_epoch {
                return Err(fault(
                    "stale_generation",
                    format!(
                        "retire names generation {expected} but the current generation is {}; a stale retirement has no effect",
                        slot.session_epoch
                    ),
                ));
            }
        }
        if slot.status == Status::Expired {
            self.expire_slot(grant, slot, &record_value(&now).clone())?;
        }
        let reason = optional_established(map, "reason", "invalid_retire_reason")?;
        let uncommitted = slot.in_flight.is_some();
        let discarded = slot.pending_rotations.len() + usize::from(uncommitted);
        let row = build_session_row(RowSpec {
            key: &slot.key,
            topology: slot.topology,
            session_epoch: slot.session_epoch,
            owner_epoch: slot.owner_epoch,
            status: STATUS_RETIRED,
            bootstrap_kind: &slot.bootstrap_kind,
            bootstrap_started_at: slot.bootstrap_started_at.clone(),
            bootstrap_completed_at: slot.bootstrap_completed_at.clone(),
            bootstrap_attempt: slot.bootstrap_attempt,
            cookie_generation: slot.cookie_generation,
            last_committed_request_sequence: slot.last_committed_request_sequence,
            profile_ref: &slot.profile_ref,
            client_generation: &slot.client_generation,
            worker_identity: slot.worker_identity.clone(),
            handoff_timestamp: slot.handoff_timestamp.clone(),
            authenticated_state_evidence: slot.authenticated_state_evidence.clone(),
            last_authenticated_url: slot.last_authenticated_url.clone(),
            verified_session_birth: missing(
                "not_observed",
                "no verified session birth has been established",
            ),
            session_absolute_lifetime_seconds: slot.session_absolute_lifetime_seconds.clone(),
            session_expires_at: slot.session_expires_at.clone(),
            replacement_deadline: slot.replacement_deadline.clone(),
            last_success_at: slot.last_success_at.clone(),
            last_failure_reason: slot.last_failure_reason.clone(),
            redacted_solver_harvest_evidence: missing(
                "not_applicable",
                "no solver mechanism was evidenced for this generation",
            ),
            entity_revision: slot.revision + 1,
            created_at: slot.created_at.clone(),
            updated_at: record_value(&now).clone(),
        })?;
        let mut refs = vec![slot.establishment_ref.clone()];
        if let Some(boundary) = &slot.last_boundary_ref {
            refs.push(boundary.clone());
        }
        let committed = self.append(
            grant,
            &slot.journal_id,
            EVENT_RETIRED,
            json!({
                "session_state": record_value(&row).clone(),
                "uncommitted_exchange": uncommitted,
                "pending_rotations_discarded": discarded as u64,
                "retire_reason": reason.clone(),
            }),
            refs,
        )?;
        let session_epoch = slot.session_epoch;
        let owner_epoch = slot.owner_epoch;
        registry.slots.remove(&key);
        validate(
            OUTPUT_SCHEMA,
            json!({
                "record_type": "session_retired",
                "session_id": key.session_id(session_epoch),
                "target": key.target,
                "run_id": key.run_id,
                "phase": key.phase,
                "shard_id": key.shard_id,
                "session_epoch": session_epoch,
                "owner_epoch": owner_epoch,
                "status": STATUS_RETIRED,
                "uncommitted_exchange": uncommitted,
                "pending_rotations_discarded": discarded as u64,
                "retire_reason": reason,
                "retired_at": record_value(&now).clone(),
                "store_receipt": record_value(&committed).clone(),
            }),
        )
    }
}

fn resolve_key(registry: &Registry, value: &Value) -> Result<SessionKey, Fault> {
    if let Some(session_id) = session_text(value, &["session_id"]) {
        return registry.key_of_session_id(&session_id).ok_or_else(|| {
            fault(
                "unknown_session",
                format!("no live generation has session_id {session_id:?}"),
            )
        });
    }
    identity_of(value)
}

fn establish_handoff(map: &Map<String, Value>) -> Result<Value, Fault> {
    if let Some(handoff) = established(map, "handoff") {
        let handoff = value_object(handoff, "invalid_handoff", "handoff evidence")?;
        match established(handoff, "timestamp") {
            Some(timestamp) => return Ok(timestamp.clone()),
            None => {
                return Err(fault(
                    "invalid_handoff",
                    "handoff evidence requires the receipt timestamp it was performed under; the receipt is not session birth",
                ))
            }
        }
    }
    optional_established(map, "handoff_timestamp", "invalid_handoff")
}

fn bootstrap_kind_of(map: &Map<String, Value>, handoff: &Value) -> Result<String, Fault> {
    let declared = optional_str(map, "bootstrap_kind", "invalid_bootstrap_kind")?;
    let warm = matches!(established(map, "warm"), Some(Value::Bool(true)));
    let kind = match declared {
        Some(kind) => kind.to_string(),
        None if !is_missing(handoff) => "handoff".to_string(),
        None if warm => "warm".to_string(),
        None => "cold".to_string(),
    };
    if !BOOTSTRAP_KINDS.contains(&kind.as_str()) {
        return Err(fault(
            "invalid_bootstrap_kind",
            format!("bootstrap_kind {kind:?} is not one of cold, warm, or handoff"),
        ));
    }
    if kind == "handoff" && is_missing(handoff) {
        return Err(fault(
            "invalid_handoff",
            "a handoff bootstrap requires the handoff receipt it was performed under",
        ));
    }
    Ok(kind)
}

fn optional_established(
    map: &Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Value, Fault> {
    match established(map, key) {
        None => Ok(missing(
            "not_observed",
            "the request did not establish this value",
        )),
        Some(value) => {
            if value.is_null() {
                return Err(fault(code, format!("field {key:?} must not be a bare null")));
            }
            Ok(value.clone())
        }
    }
}

fn optional_evidence(
    map: &Map<String, Value>,
    key: &str,
    code: &str,
) -> Result<Value, Fault> {
    match established(map, key) {
        None => Ok(missing(
            "not_applicable",
            "no authenticated handoff evidence was presented",
        )),
        Some(value) => {
            if !value.is_object() && !value.is_string() {
                return Err(fault(
                    code,
                    format!("field {key:?} must be an evidence object or redacted string"),
                ));
            }
            Ok(value.clone())
        }
    }
}

/// Build the generation's retained live client with an explicitly constructed
/// jar. Never the process-global shared session: independent shards must not
/// inherit each other's cookies or pooled connections.
fn build_client(preset: &str) -> Result<HttpClient, Fault> {
    let profile = stealth_profile(preset)?;
    HttpClient::new_with_shared_state(
        &profile,
        Arc::new(AsyncMutex::new(CookieJar::new())),
        Arc::new(AsyncMutex::new(HashSet::new())),
        DnsCache::new(),
        AltSvcCache::new(),
    )
    .map_err(|error| {
        fault(
            "session_client_failed",
            format!("retained live client could not be created: {error}"),
        )
    })
}
