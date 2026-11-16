//! `rm_models`: tier-3 bounded Tier-2 recovery proposal conduit for Ringmaster.
//!
//! Implements seam mapping §10.3 (Tier 2 closed proposal), §10.6 (independent
//! Rust model conduit), §10.7 (breaker + five budget dimensions), and §20
//! security/data-flow restrictions relevant to model recovery.
//!
//! [`propose_recovery`] is the only entry point. It never imports a Python
//! LiteLLM runtime or Circus Tent provider code; provider calls are served by
//! an independent Rust conduit driven by the pinned [`VersionPin`] policy.
//! Every call verifies authority, open observation, allowances, token
//! reservation, session limits, breaker state, input size, and disclosure
//! permission *before* any provider byte is consumed.
//!
//! Raw provider output is retained before repair. The pinned repair only
//! fixes JSON syntax (surrounding whitespace, trailing commas); it never
//! invents `selector`/`strategy`/`confidence`/`reason`. Repaired bytes are
//! retained as a separate restricted artifact. Duplicate keys and
//! non-finite values are rejected. The baseline permits at most one
//! additional candidate after an invalid first candidate (two provider calls
//! total); repair and failover cannot extend the bound.

#![forbid(unsafe_code)]

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError, Manifest, Operation, WorkScope};
pub use rm_evidence::{AccessClass, ArtifactReference};
pub use rm_time::{MeasurementOrigin, TimePoint};

use rm_evidence::{EventSubmission, EvidencePayload};
use rm_time::{MaybeTimePoint, Missing};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    LazyLock, Mutex,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Largest exactly representable integer (§3.1).
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Pinned HEAL reduction ceiling in decimal UTF-8 bytes (§9.4).
pub const HEAL_CEILING_BYTES: usize = 50_000;
/// Baseline bound: one retry after the first invalid candidate (§10.3).
pub const MAX_CANDIDATE_ATTEMPTS: usize = 2;
/// Source-derived breaker threshold: heal rate above 30% disables Tier 2/3.
pub const HEAL_RATE_THRESHOLD: f64 = 0.30;
/// Truthful Ringmaster user-agent prefix (§10.6).
pub const RINGMASTER_USER_AGENT_PREFIX: &str = "ringmaster/";
/// Required session header when the `opencode-go` provider is selected.
/// Implemented under the pinned provider contract (§10.6).
pub const OPENCODE_SESSION_HEADER: &str = "x-opencode-session";

/// Closed Tier-2 strategy vocabulary (§10.3).
pub const PROPOSAL_STRATEGIES: [&str; 5] = ["css", "xpath", "text", "role", "testid"];
/// Closed Tier-2 proposal fields (§10.3).
const PROPOSAL_FIELDS: [&str; 4] = ["selector", "strategy", "confidence", "reason"];

/// Exactly the 14 `BOPrimitive` vocabulary entries (Contract 03).
pub const BO_PRIMITIVES: [&str; 14] = [
    "bo.client_create",
    "bo.http_exchange",
    "bo.page_create",
    "bo.navigate",
    "bo.from_html",
    "bo.dom_read",
    "bo.dom_write",
    "bo.event_dispatch",
    "bo.v8_evaluate",
    "bo.assign_files",
    "bo.capture",
    "bo.render_verdict",
    "bo.reset_for_reuse",
    "bo.page_destroy",
];

const NONFINITE_TOKENS: &[&str] = &["NaN", "Infinity", "-Infinity", "inf", "-inf", "nan"];

// ---------------------------------------------------------------------------
// Error constructors (ConnectorError::new is private to rm_authority)
// ---------------------------------------------------------------------------

fn invalid(detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: "INVALID_REQUEST".to_string(),
        fault_domain: "request".to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: "FORBIDDEN".to_string(),
        fault_domain: "policy".to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn not_admitted(detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: "NOT_ADMITTED".to_string(),
        fault_domain: "policy".to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn integrity(detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: "INTEGRITY_INCIDENT".to_string(),
        fault_domain: "integrity".to_string(),
        detail: detail.into(),
        operation_delivery: "not_dispatched".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Public types (EXPOSES signature)
// ---------------------------------------------------------------------------

/// Pinned provider policy pin plus its decoded enforcement fields.
///
/// The `id`/`version`/`artifact_digest` triple is the contract `VersionPin`
/// identity; the remaining fields are the pinned policy decoded for
/// enforcement (role, ordered providers, model identity, protocol, endpoint
/// and credential references, headers, timeout, failover, retention, privacy,
/// user-agent identity, and disclosure permission per §10.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionPin {
    pub id: String,
    pub version: String,
    pub artifact_digest: String,
    pub role: String,
    pub providers: Vec<String>,
    pub model: String,
    pub protocol: String,
    pub endpoint_ref: String,
    pub credential_ref: String,
    pub headers: Vec<Header>,
    pub timeout_ms: u64,
    pub failover_enabled: bool,
    pub retention: String,
    pub privacy: String,
    pub user_agent: String,
    pub disclosure_allowed: bool,
}

/// One pinned provider header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// Five budget dimensions with their disclosed enforcers (§10.7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BudgetEnforcers {
    pub active_observation: String,
    pub action_count: String,
    pub observation_bytes: String,
    pub recovery_count: String,
    pub model_tokens: String,
}

/// Circuit-breaker policy (§10.7). Missing numerator/denominator is unknown,
/// never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakerPolicy {
    pub shard: String,
    pub numerator: Option<u64>,
    pub denominator: Option<u64>,
    pub window_clock_id: String,
    pub sample_minimum: u64,
    pub tripped: bool,
    pub reset_authority: String,
}

/// Configured task budgets plus the live allowances and token accounting
/// needed to gate one recovery proposal. Limits are configuration, never
/// measurements.
#[derive(Debug, Clone, PartialEq)]
pub struct TaskBudgets {
    pub active_limit_ms: f64,
    pub action_limit: u64,
    pub observation_byte_limit: u64,
    pub recovery_limit: u64,
    pub model_token_limit: u64,
    pub enforcers: BudgetEnforcers,
    /// Finite reservation for this recovery. `None` means no reservation.
    pub tokens_reserved: Option<u64>,
    /// Observed usage so far. `None` means unknown, never zero.
    pub tokens_used: Option<u64>,
    /// Estimated token cost of one provider call under the pinned accounting.
    pub tokens_per_call: u64,
    pub breaker: BreakerPolicy,
    pub session_limit: u64,
    pub sessions_used: u64,
    pub observation_open: bool,
    pub active_allowance_remaining: u64,
    pub recovery_allowance_remaining: u64,
}

/// One BrowserOxide primitive mapping entry (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOMapping {
    pub primitive: String,
    pub mapping_state: String,
    pub native_symbol: Option<String>,
    pub evidence_refs: Vec<String>,
}

/// Binding descriptor view enforced before recovery (§5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BOBindingDescriptor {
    pub record_type: String,
    pub schema_version: String,
    pub binding_id: String,
    pub primitive_mappings: Vec<BOMapping>,
    pub session_storage_model: String,
    pub session_isolation_refs: Vec<String>,
}

/// Durable local handle plus the authority, manifest, and clock bindings
/// needed to gate recovery. The wire projection validates as
/// `connector_handle/v1`.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectorHandle {
    pub record_type: String,
    pub schema_version: String,
    pub connector_id: String,
    pub local_handle: String,
    pub preparation_id: String,
    pub scope: WorkScope,
    pub operation: Operation,
    pub manifest: Manifest,
    pub idempotency_key: String,
    pub created_at: TimePoint,
    pub active_deadline: TimePoint,
    pub now: TimePoint,
}

/// Validated Tier-2 closed proposal (§10.3). A tentative candidate, never a
/// verified selector.
#[derive(Debug, Clone, PartialEq)]
pub struct Proposal {
    pub selector: String,
    pub strategy: String,
    pub confidence: f64,
    pub reason: String,
}

// ---------------------------------------------------------------------------
// Provider stub (independent Rust conduit test double)
// ---------------------------------------------------------------------------

struct StubState {
    responses: HashMap<String, VecDeque<Vec<u8>>>,
    calls: HashMap<String, usize>,
}

static STUB_STATE: LazyLock<Mutex<StubState>> = LazyLock::new(|| {
    Mutex::new(StubState {
        responses: HashMap::new(),
        calls: HashMap::new(),
    })
});

fn stub_state() -> &'static Mutex<StubState> {
    &STUB_STATE
}

fn lock_stub() -> std::sync::MutexGuard<'static, StubState> {
    stub_state().lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Stages canned provider response bytes for the prompt digest.
///
/// Each [`propose_recovery`] provider call pops one entry and counts against
/// budgets. Keying by prompt digest keeps parallel tests isolated.
pub fn stub_provider_responses(prompt_digest: &str, responses: Vec<Vec<u8>>) {
    let mut state = lock_stub();
    state
        .responses
        .insert(prompt_digest.to_string(), responses.into());
    state.calls.insert(prompt_digest.to_string(), 0);
}

/// Returns the number of provider calls consumed for the prompt digest.
pub fn provider_call_count(prompt_digest: &str) -> usize {
    lock_stub().calls.get(prompt_digest).copied().unwrap_or(0)
}

/// Clears staged responses and the call counter for the prompt digest.
pub fn clear_provider_stub(prompt_digest: &str) {
    let mut state = lock_stub();
    state.responses.remove(prompt_digest);
    state.calls.remove(prompt_digest);
}

fn take_provider_response(prompt_digest: &str) -> Option<Vec<u8>> {
    let mut state = lock_stub();
    let queue = state.responses.get_mut(prompt_digest)?;
    let bytes = queue.pop_front()?;
    *state.calls.entry(prompt_digest.to_string()).or_insert(0) += 1;
    Some(bytes)
}

static NEXT_PRODUCER_SEQUENCE: AtomicU64 = AtomicU64::new(1_000_000);

fn next_producer_sequence() -> u64 {
    // Unique across journals so parallel tests never collide on the
    // (producer_id, producer_sequence) dedup key.
    let seq = NEXT_PRODUCER_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    seq.min(MAX_SAFE_INTEGER)
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_owner_domain(field: &str, value: &str) -> Result<(), ConnectorError> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid {
        return Err(invalid(format!(
            "{field} {value:?} must be a single identity of letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

fn validate_version_pin(policy: &VersionPin) -> Result<(), ConnectorError> {
    require_nonempty("provider_policy.id", &policy.id)?;
    require_nonempty("provider_policy.version", &policy.version)?;
    if !rm_wire::is_valid_digest(&policy.artifact_digest) {
        return Err(invalid(format!(
            "provider_policy.artifact_digest {:?} is not a sha256 digest",
            policy.artifact_digest
        )));
    }
    require_nonempty("provider_policy.role", &policy.role)?;
    if policy.providers.is_empty() {
        return Err(invalid("provider_policy.providers must be a nonempty ordered list"));
    }
    let mut seen = HashSet::new();
    for provider in &policy.providers {
        require_nonempty("provider_policy.providers[]", provider)?;
        if !seen.insert(provider.clone()) {
            return Err(invalid(format!(
                "provider_policy.providers contains duplicate provider {provider:?}"
            )));
        }
        let lower = provider.to_ascii_lowercase();
        if lower.contains("litellm") {
            return Err(forbidden(
                "provider_policy selects a Python LiteLLM runtime: Ringmaster uses an independent Rust-compatible conduit",
            ));
        }
        if lower.contains("circus") {
            return Err(forbidden(
                "provider_policy imports Circus Tent provider implementations: Ringmaster uses an independent Rust-compatible conduit",
            ));
        }
    }
    require_nonempty("provider_policy.model", &policy.model)?;
    require_nonempty("provider_policy.protocol", &policy.protocol)?;
    require_nonempty("provider_policy.endpoint_ref", &policy.endpoint_ref)?;
    require_nonempty("provider_policy.credential_ref", &policy.credential_ref)?;
    for header in &policy.headers {
        require_nonempty("provider_policy.headers[].name", &header.name)?;
        require_nonempty("provider_policy.headers[].value", &header.value)?;
    }
    if policy.timeout_ms == 0 {
        return Err(invalid("provider_policy.timeout_ms must be a finite positive bound"));
    }
    require_nonempty("provider_policy.retention", &policy.retention)?;
    require_nonempty("provider_policy.privacy", &policy.privacy)?;
    if !policy.user_agent.starts_with(RINGMASTER_USER_AGENT_PREFIX) {
        return Err(invalid(format!(
            "provider_policy.user_agent {:?} must carry truthful Ringmaster identity with prefix {:?}",
            policy.user_agent, RINGMASTER_USER_AGENT_PREFIX
        )));
    }
    let ua_lower = policy.user_agent.to_ascii_lowercase();
    if ua_lower.contains("litellm") || ua_lower.contains("circus") {
        return Err(forbidden(
            "provider_policy.user_agent must be truthful Ringmaster identity, not LiteLLM/Circus Tent",
        ));
    }
    if policy
        .providers
        .iter()
        .any(|p| p.eq_ignore_ascii_case("opencode-go") || p.eq_ignore_ascii_case("opencode_go"))
    {
        let present = policy.headers.iter().any(|h| {
            h.name.eq_ignore_ascii_case(OPENCODE_SESSION_HEADER) && !h.value.is_empty()
        });
        if !present {
            return Err(invalid(format!(
                "provider_policy selects OpenCode Go but misses its required session header {OPENCODE_SESSION_HEADER:?} under the pinned provider contract"
            )));
        }
    }
    Ok(())
}

fn validate_enforcers(enforcers: &BudgetEnforcers) -> Result<(), ConnectorError> {
    if enforcers.active_observation != "connector" {
        return Err(not_admitted(format!(
            "budget dimension active_observation must be connector-enforced, found {:?}",
            enforcers.active_observation
        )));
    }
    for (dimension, enforcer) in [
        ("action_count", &enforcers.action_count),
        ("observation_bytes", &enforcers.observation_bytes),
        ("recovery_count", &enforcers.recovery_count),
        ("model_tokens", &enforcers.model_tokens),
    ] {
        match enforcer.as_str() {
            "connector" | "subject" => {}
            other => {
                return Err(not_admitted(format!(
                    "budget dimension {dimension} discloses unenforceable enforcer {other:?}: required unenforceable bounds reject preparation"
                )))
            }
        }
    }
    Ok(())
}

fn validate_revision(field: &str, value: u64) -> Result<(), ConnectorError> {
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{field} {value} is outside 0..={MAX_SAFE_INTEGER}"
        )));
    }
    Ok(())
}

/// Returns the breaker heal rate, or `None` when the sample is below minimum.
/// Missing numerator/denominator (or a zero denominator) is unknown, never a
/// zero rate.
pub fn breaker_heal_rate(breaker: &BreakerPolicy) -> Result<Option<f64>, ConnectorError> {
    require_nonempty("breaker.shard", &breaker.shard)?;
    require_nonempty("breaker.window_clock_id", &breaker.window_clock_id)?;
    require_nonempty("breaker.reset_authority", &breaker.reset_authority)?;
    let numerator = breaker.numerator.ok_or_else(|| {
        invalid("missing breaker numerator cannot produce a heal rate; unknown usage is not zero")
    })?;
    let denominator = breaker.denominator.ok_or_else(|| {
        invalid("missing breaker denominator cannot produce zero rate")
    })?;
    if denominator == 0 {
        return Err(invalid(
            "missing breaker denominator cannot produce zero rate: denominator is zero",
        ));
    }
    if numerator > denominator {
        return Err(invalid(format!(
            "breaker numerator {numerator} exceeds denominator {denominator}"
        )));
    }
    if denominator < breaker.sample_minimum {
        return Ok(None);
    }
    Ok(Some(numerator as f64 / denominator as f64))
}

fn check_breaker(breaker: &BreakerPolicy) -> Result<(), ConnectorError> {
    if breaker.tripped {
        return Err(forbidden(
            "circuit breaker is open: Tier 2/3 model recovery is disabled",
        ));
    }
    match breaker_heal_rate(breaker)? {
        Some(rate) if rate > HEAL_RATE_THRESHOLD => Err(forbidden(format!(
            "circuit breaker trips: heal rate {rate:.4} exceeds 30% in the rolling window"
        ))),
        _ => Ok(()),
    }
}

fn check_token_accounting(budgets: &TaskBudgets) -> Result<(), ConnectorError> {
    if budgets.model_token_limit == 0 {
        return Err(forbidden(
            "zero model tokens forbids a model call where the limit is enforceable",
        ));
    }
    if budgets.tokens_per_call == 0 {
        return Err(invalid(
            "tokens_per_call must be a positive estimate: unknown cost is not zero",
        ));
    }
    let reserved = budgets.tokens_reserved.ok_or_else(|| {
        forbidden("token reservation is required before every model call")
    })?;
    validate_revision("tokens_reserved", reserved)?;
    if reserved > budgets.model_token_limit {
        return Err(forbidden(format!(
            "token reservation {reserved} exceeds model_token_limit {}",
            budgets.model_token_limit
        )));
    }
    if reserved < budgets.tokens_per_call {
        return Err(forbidden(format!(
            "token reservation {reserved} does not cover one provider call costing {}",
            budgets.tokens_per_call
        )));
    }
    match budgets.tokens_used {
        Some(used) => {
            validate_revision("tokens_used", used)?;
            if used > budgets.model_token_limit {
                return Err(forbidden(format!(
                    "observed token usage {used} already exceeds model_token_limit {}",
                    budgets.model_token_limit
                )));
            }
            let worst = used
                .checked_add(
                    budgets
                        .tokens_per_call
                        .checked_mul(MAX_CANDIDATE_ATTEMPTS as u64)
                        .ok_or_else(|| invalid("token estimate overflows Revision"))?,
                )
                .ok_or_else(|| invalid("token estimate overflows Revision"))?;
            if worst > budgets.model_token_limit {
                return Err(forbidden(format!(
                    "token budget cannot cover the bounded retry allowance: used {used} + {} attempts exceeds model_token_limit {}",
                    MAX_CANDIDATE_ATTEMPTS, budgets.model_token_limit
                )));
            }
            let reconciled = used
                .checked_add(reserved)
                .ok_or_else(|| invalid("token reservation reconciles past Revision"))?;
            if reconciled > budgets.model_token_limit {
                return Err(forbidden(format!(
                    "token reservation {reserved} does not reconcile with observed usage {used} under model_token_limit {}",
                    budgets.model_token_limit
                )));
            }
        }
        None => {
            // Unknown usage is not zero: only a full-limit reservation covers it.
            if reserved != budgets.model_token_limit {
                return Err(forbidden(
                    "unknown usage is not zero: without observed usage the reservation must cover the full model_token_limit",
                ));
            }
        }
    }
    Ok(())
}

fn validate_budgets_shape(budgets: &TaskBudgets) -> Result<(), ConnectorError> {
    if !budgets.active_limit_ms.is_finite() || budgets.active_limit_ms < 0.0 {
        return Err(invalid(format!(
            "active_limit {:?} must be a finite nonnegative ms configuration",
            budgets.active_limit_ms
        )));
    }
    validate_revision("action_limit", budgets.action_limit)?;
    validate_revision("observation_byte_limit", budgets.observation_byte_limit)?;
    validate_revision("recovery_limit", budgets.recovery_limit)?;
    validate_revision("model_token_limit", budgets.model_token_limit)?;
    validate_enforcers(&budgets.enforcers)?;
    validate_revision("session_limit", budgets.session_limit)?;
    validate_revision("sessions_used", budgets.sessions_used)?;
    validate_revision(
        "active_allowance_remaining",
        budgets.active_allowance_remaining,
    )?;
    validate_revision(
        "recovery_allowance_remaining",
        budgets.recovery_allowance_remaining,
    )?;
    Ok(())
}

fn validate_binding(binding: &BOBindingDescriptor) -> Result<(), ConnectorError> {
    if binding.record_type != "browseroxide_binding_descriptor" {
        return Err(invalid(format!(
            "binding record_type {:?} must be browseroxide_binding_descriptor",
            binding.record_type
        )));
    }
    if binding.schema_version != "internal-browser-binding.browseroxide/0.1.0" {
        return Err(invalid(format!(
            "binding schema_version {:?} is unknown",
            binding.schema_version
        )));
    }
    require_nonempty("binding.binding_id", &binding.binding_id)?;
    if binding.primitive_mappings.len() != BO_PRIMITIVES.len() {
        return Err(invalid(format!(
            "binding primitive_mappings has {} entries, exactly 14 required",
            binding.primitive_mappings.len()
        )));
    }
    let mut seen = HashSet::new();
    for mapping in &binding.primitive_mappings {
        if !BO_PRIMITIVES.contains(&mapping.primitive.as_str()) {
            return Err(invalid(format!(
                "binding primitive {:?} is not in the 14-entry BOPrimitive vocabulary",
                mapping.primitive
            )));
        }
        if !seen.insert(mapping.primitive.clone()) {
            return Err(invalid(format!(
                "binding primitive {:?} appears twice: each primitive appears exactly once",
                mapping.primitive
            )));
        }
        match mapping.mapping_state.as_str() {
            "mapped" => {
                match &mapping.native_symbol {
                    Some(symbol) if !symbol.is_empty() => {}
                    _ => {
                        return Err(invalid(format!(
                            "mapped binding primitive {:?} requires an actual native_symbol",
                            mapping.primitive
                        )))
                    }
                }
                if mapping.evidence_refs.is_empty() {
                    return Err(invalid(format!(
                        "mapped binding primitive {:?} requires nonempty evidence_refs",
                        mapping.primitive
                    )));
                }
            }
            "unmapped" => {
                if mapping.native_symbol.is_some() {
                    return Err(invalid(format!(
                        "unmapped binding primitive {:?} must not guess a native_symbol",
                        mapping.primitive
                    )));
                }
            }
            other => {
                return Err(invalid(format!(
                    "binding mapping_state {other:?} must be mapped or unmapped"
                )))
            }
        }
        for reference in &mapping.evidence_refs {
            require_nonempty("binding evidence_ref", reference)?;
        }
    }
    match binding.session_storage_model.as_str() {
        "process_global" | "verified_namespaced" | "unknown" => {}
        other => {
            return Err(invalid(format!(
                "binding session_storage_model {other:?} is unknown"
            )))
        }
    }
    if binding.session_storage_model == "verified_namespaced"
        && binding.session_isolation_refs.is_empty()
    {
        return Err(invalid(
            "verified_namespaced session storage requires nonempty session_isolation_refs",
        ));
    }
    for reference in &binding.session_isolation_refs {
        require_nonempty("binding session_isolation_ref", reference)?;
    }
    Ok(())
}

fn validate_handle_shape(handle: &ConnectorHandle) -> Result<(), ConnectorError> {
    if handle.record_type != "connector_handle" {
        return Err(invalid(format!(
            "handle record_type {:?} must be connector_handle",
            handle.record_type
        )));
    }
    if handle.schema_version != "external-connector/0.1.0" {
        return Err(invalid(format!(
            "handle schema_version {:?} is unknown",
            handle.schema_version
        )));
    }
    require_nonempty("handle.connector_id", &handle.connector_id)?;
    require_nonempty("handle.local_handle", &handle.local_handle)?;
    require_nonempty("handle.preparation_id", &handle.preparation_id)?;
    require_nonempty("handle.idempotency_key", &handle.idempotency_key)?;
    Ok(())
}

/// Closed wire projection validated structurally as `connector_handle/v1`.
fn handle_wire_bytes(handle: &ConnectorHandle) -> Result<Vec<u8>, ConnectorError> {
    let created_at =
        serde_json::to_value(&handle.created_at).map_err(|e| invalid(format!("created_at: {e}")))?;
    let mut scope = serde_json::Map::new();
    scope.insert("activity".to_string(), json!(handle.scope.activity));
    scope.insert("run_id".to_string(), json!(handle.scope.run_id));
    scope.insert("journal_id".to_string(), json!(handle.scope.journal_id));
    scope.insert(
        "manifest_hash".to_string(),
        json!(handle.scope.manifest_hash),
    );
    scope.insert(
        "admission_ref".to_string(),
        json!(handle.scope.admission_ref),
    );
    scope.insert(
        "observation_policy".to_string(),
        json!(handle.scope.observation_policy),
    );
    scope.insert(
        "owner_domain".to_string(),
        json!(handle.scope.owner_domain),
    );
    let wire = json!({
        "record_type": handle.record_type,
        "schema_version": handle.schema_version,
        "handle": {
            "connector_id": handle.connector_id,
            "local_handle": handle.local_handle,
        },
        "preparation": {
            "preparation_id": handle.preparation_id,
        },
        "scope": scope,
        "idempotency_key": handle.idempotency_key,
        "created_at": created_at,
    });
    serde_json::to_vec(&wire).map_err(|e| invalid(format!("handle wire bytes: {e}")))
}

// ---------------------------------------------------------------------------
// Prompt validation (§10.3 inputs)
// ---------------------------------------------------------------------------

fn validate_prompt_bytes(bytes: &[u8]) -> Result<Value, ConnectorError> {
    if bytes.len() > HEAL_CEILING_BYTES {
        return Err(forbidden(format!(
            "prompt input has {} bytes, exceeding the bounded HEAL ceiling of {HEAL_CEILING_BYTES}",
            bytes.len()
        )));
    }
    let text =
        std::str::from_utf8(bytes).map_err(|e| invalid(format!("prompt is not utf-8: {e}")))?;
    let value: Value =
        serde_json::from_str(text).map_err(|e| invalid(format!("prompt is not JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("prompt must be a JSON object"))?;
    for field in [
        "heal_reduction",
        "fallback_text",
        "failed_selector",
        "failed_recipe",
        "section_labels",
        "limitations",
        "commissioned_job",
        "commissioned_target",
        "current_root",
    ] {
        if !object.contains_key(field) {
            return Err(invalid(format!("prompt is missing required field {field:?}")));
        }
    }
    let heal = object
        .get("heal_reduction")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("prompt heal_reduction must be a string"))?;
    if heal.as_bytes().len() > HEAL_CEILING_BYTES {
        return Err(forbidden(format!(
            "heal_reduction has {} bytes, exceeding the {HEAL_CEILING_BYTES}-byte HEAL ceiling",
            heal.as_bytes().len()
        )));
    }
    for field in [
        "fallback_text",
        "failed_selector",
        "failed_recipe",
        "commissioned_job",
        "commissioned_target",
        "current_root",
    ] {
        let text = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("prompt {field} must be a string")))?;
        if text.is_empty() {
            return Err(invalid(format!("prompt {field} must be nonempty")));
        }
    }
    let labels = object
        .get("section_labels")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("prompt section_labels must be an array"))?;
    if labels.is_empty() {
        return Err(invalid("prompt section_labels must carry scoped section labels"));
    }
    for label in labels {
        match label.as_str() {
            Some(text) if !text.is_empty() => {}
            _ => return Err(invalid("prompt section_labels must be nonempty strings")),
        }
    }
    if !object
        .get("limitations")
        .map(Value::is_array)
        .unwrap_or(false)
    {
        return Err(invalid("prompt limitations must be an array"));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Proposal wire checks (duplicate keys, non-finite, closed schema)
// ---------------------------------------------------------------------------

fn reject_nonfinite_literals(text: &str) -> Result<(), ConnectorError> {
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_alphabetic() {
            for token in NONFINITE_TOKENS {
                if text[index..].starts_with(token) {
                    let before = index.checked_sub(1).map(|i| bytes[i]).unwrap_or(b' ');
                    let after = text[index + token.len()..].bytes().next().unwrap_or(b' ');
                    let boundary_before =
                        !(before.is_ascii_alphanumeric() || before == b'_' || before == b'.');
                    let boundary_after =
                        !(after.is_ascii_alphanumeric() || after == b'_' || after == b'.');
                    if boundary_before && boundary_after {
                        return Err(invalid(format!(
                            "non-finite number is not allowed: {token}"
                        )));
                    }
                }
            }
        }
        index += 1;
    }
    Ok(())
}

fn check_duplicate_keys(text: &str) -> Result<(), ConnectorError> {
    let bytes = text.as_bytes();
    let mut index = 0usize;
    let mut stack: Vec<HashSet<String>> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();

    // Minimal scanner: track object levels and the keys observed at each.
    // Only keys (strings immediately followed by `:`) participate.

    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            if escaped {
                current.push(byte as char);
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
                current.push('\\');
            } else if byte == b'"' {
                in_string = false;
                // Look ahead past whitespace for `:` to decide key vs value.
                let mut look = index + 1;
                while look < bytes.len()
                    && (bytes[look] == b' '
                        || bytes[look] == b'\t'
                        || bytes[look] == b'\n'
                        || bytes[look] == b'\r')
                {
                    look += 1;
                }
                let is_key_candidate = look < bytes.len() && bytes[look] == b':';
                if is_key_candidate {
                    if let Some(level) = stack.last_mut() {
                        if !level.insert(current.clone()) {
                            return Err(invalid(format!(
                                "duplicate mapping key {current:?} is rejected"
                            )));
                        }
                    }
                }
                current.clear();
            } else {
                current.push(byte as char);
            }
            index += 1;
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                current.clear();
            }
            b'{' => stack.push(HashSet::new()),
            b'}' => {
                stack.pop();
            }
            _ => {}
        }
        index += 1;
    }
    Ok(())
}

fn contains_executable_script(selector: &str) -> bool {
    let lower = selector.to_ascii_lowercase();
    lower.contains("<script")
        || lower.contains("javascript:")
        || lower.contains("vbscript:")
        || lower.contains("data:text/html")
        || lower.contains("onerror=")
        || lower.contains("onload=")
}

/// Validates the closed Tier-2 proposal schema. Rejects duplicate keys,
/// non-finite values, undeclared fields, and executable-script selectors.
/// Model content is untrusted data (§20): it cannot supply scripts or alter
/// permissions, values, files, destinations, or action order — the closed
/// four-field schema admits none of those.
pub fn validate_proposal_bytes(bytes: &[u8]) -> Result<Proposal, ConnectorError> {
    let text =
        std::str::from_utf8(bytes).map_err(|e| invalid(format!("proposal is not utf-8: {e}")))?;
    reject_nonfinite_literals(text)?;
    let value: Value =
        serde_json::from_str(text).map_err(|e| invalid(format!("proposal is not JSON: {e}")))?;
    check_duplicate_keys(text)?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("proposal must be a JSON object"))?;
    let mut unknown = Vec::new();
    for key in object.keys() {
        if !PROPOSAL_FIELDS.contains(&key.as_str()) {
            unknown.push(key.as_str());
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        return Err(forbidden(format!(
            "proposal carries undeclared field(s) {}: no model response may change candidate identity, job, target, input values, files, action order, or budget",
            unknown.join(", ")
        )));
    }
    for field in PROPOSAL_FIELDS {
        if !object.contains_key(field) {
            return Err(invalid(format!("proposal is missing required field {field:?}")));
        }
    }
    let selector = object
        .get("selector")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("proposal selector must be a string"))?;
    if selector.is_empty() {
        return Err(invalid("proposal selector must be nonempty"));
    }
    if contains_executable_script(selector) {
        return Err(forbidden(
            "proposal selector carries executable script: page/model content is untrusted data and cannot supply executable scripts",
        ));
    }
    let strategy = object
        .get("strategy")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("proposal strategy must be a string"))?;
    if !PROPOSAL_STRATEGIES.contains(&strategy) {
        return Err(invalid(format!(
            "proposal strategy {strategy:?} must be one of css, xpath, text, role, testid"
        )));
    }
    let confidence = object.get("confidence").ok_or_else(|| {
        invalid("proposal is missing required field \"confidence\"")
    })?;
    let confidence = match confidence {
        Value::Number(number) => number.as_f64().ok_or_else(|| {
            invalid("proposal confidence must be a finite number from zero through one")
        })?,
        _ => {
            return Err(invalid(
                "proposal confidence must be a finite number from zero through one",
            ))
        }
    };
    if !confidence.is_finite() || confidence < 0.0 || confidence > 1.0 {
        return Err(invalid(format!(
            "proposal confidence {confidence:?} must be finite from zero through one"
        )));
    }
    let reason = object
        .get("reason")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("proposal reason must be a string"))?;
    if reason.is_empty() {
        return Err(invalid("proposal reason must be nonempty"));
    }
    Ok(Proposal {
        selector: selector.to_string(),
        strategy: strategy.to_string(),
        confidence,
        reason: reason.to_string(),
    })
}

/// Pinned syntax-only repair: trims surrounding whitespace and removes
/// trailing commas before `}`/`]`. Never adds, removes, or rewrites semantic
/// fields. Returns `None` when no syntactic repair applies.
pub fn repair_json_bytes(raw: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(raw).ok()?;
    if serde_json::from_str::<Value>(text).is_ok() {
        return None;
    }
    let trimmed = text.trim();
    let bytes = trimmed.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            out.push(byte);
            index += 1;
            continue;
        }
        if byte == b',' {
            // Look ahead past whitespace: a trailing comma directly before
            // `}` or `]` is a repairable syntax error.
            let mut look = index + 1;
            while look < bytes.len()
                && (bytes[look] == b' '
                    || bytes[look] == b'\t'
                    || bytes[look] == b'\n'
                    || bytes[look] == b'\r')
            {
                look += 1;
            }
            if look < bytes.len() && (bytes[look] == b'}' || bytes[look] == b']') {
                index += 1;
                continue;
            }
            out.push(byte);
            index += 1;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    if out.as_slice() == raw {
        return None;
    }
    // Only accept the repair when it yields parseable JSON; semantic
    // validation still runs on the repaired bytes afterwards.
    let repaired = String::from_utf8(out.clone()).ok()?;
    if serde_json::from_str::<Value>(&repaired).is_ok() {
        Some(out)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Artifact + journal helpers
// ---------------------------------------------------------------------------

fn restricted_reference(bytes: &[u8], owner_domain: &str) -> Result<ArtifactReference, ConnectorError> {
    require_owner_domain("artifact owner_domain", owner_domain)?;
    Ok(ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: owner_domain.to_string(),
        access: AccessClass::Restricted,
    })
}

fn journal_proposal(
    principal: &AuthenticatedPrincipal,
    manifest: &Manifest,
    proposal: &ArtifactReference,
    raws: &[ArtifactReference],
) -> Result<(), ConnectorError> {
    let mut refs: Vec<ArtifactReference> = Vec::new();
    for reference in std::iter::once(proposal).chain(raws.iter()) {
        if !refs.contains(reference) {
            refs.push(reference.clone());
        }
    }
    let data = json!({
        "proposal": proposal.to_json(),
        "retained": refs.iter().map(ArtifactReference::to_json).collect::<Vec<Value>>(),
    });
    let registration = rm_evidence::event_registration("artifact_available").ok_or_else(|| {
        integrity("event kind artifact_available is not registered with the ingestion authority")
    })?;
    let sequence = rm_evidence::PositiveInteger::new(next_producer_sequence())
        .map_err(|e| invalid(format!("producer_sequence: {e}")))?;
    let submission = EventSubmission {
        producer_sequence: Some(sequence),
        event_kind: "artifact_available".to_string(),
        event_schema_version: registration.event_schema_version.to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_observed")),
        payload: EvidencePayload {
            data,
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: refs,
        },
    };
    rm_evidence::append_event(principal, manifest, submission)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Proposes one bounded Tier-2 recovery selector.
///
/// Flow: validate the pinned provider policy, budgets, binding, and handle
/// shape; validate the handle wire record (`rm_wire`); enforce disclosure,
/// open observation, allowances, token reservation/reconciliation, session
/// limits, and breaker state; authorize the call (`rm_authority`); enforce
/// the active deadline (`rm_time`); load the bounded prompt
/// (`rm_evidence`); then consume at most [`MAX_CANDIDATE_ATTEMPTS`] provider
/// responses. Each raw response is installed before repair; a pinned
/// syntax-only repair may produce separately retained bytes; duplicate
/// keys/non-finite values are rejected; the closed four-field schema is
/// validated; executable scripts and identity/job/target/value/file/order/
/// budget mutations are rejected. The validated proposal is journaled
/// (`rm_evidence`) and its restricted artifact reference returned.
///
/// A tentative candidate is returned, never a verified selector: cache
/// replacement still requires the configured operation/readback criterion.
pub fn propose_recovery(
    principal: &AuthenticatedPrincipal,
    handle: &ConnectorHandle,
    binding: &BOBindingDescriptor,
    prompt: &ArtifactReference,
    provider_policy: &VersionPin,
    budgets: &TaskBudgets,
) -> Result<ArtifactReference, ConnectorError> {
    // Pinned policy, budgets, binding, and handle shape first. No provider
    // byte is touched before every gate below passes.
    validate_version_pin(provider_policy)?;
    validate_budgets_shape(budgets)?;
    validate_binding(binding)?;
    validate_handle_shape(handle)?;

    // Structural handle record (rm_wire).
    let wire = handle_wire_bytes(handle)?;
    rm_wire::validate_record("connector_handle/v1", &wire)
        .map_err(|e| invalid(format!("handle is not a valid connector_handle record: {e}")))?;

    // Disclosure permission (§10.6, §20.5).
    if !provider_policy.disclosure_allowed {
        return Err(forbidden(
            "model call lacks disclosure permission for prompt content",
        ));
    }

    // Open observation and finite allowances (§10.6, EXT-BOUNDS).
    if !budgets.observation_open {
        return Err(not_admitted(
            "model call requires open task observation",
        ));
    }
    if budgets.active_allowance_remaining == 0 {
        return Err(forbidden("active allowance is exhausted: no model call"));
    }
    if budgets.recovery_allowance_remaining == 0 {
        return Err(forbidden("recovery allowance is exhausted: no model call"));
    }

    // Token reservation + reconciliation: unknown usage is not zero (§10.6).
    check_token_accounting(budgets)?;

    // Session/shard limits (§10.6).
    if budgets.sessions_used >= budgets.session_limit {
        return Err(forbidden(format!(
            "session limit reached: used {} of {}",
            budgets.sessions_used, budgets.session_limit
        )));
    }

    // Breaker state (§10.7): missing denominator cannot be zero rate.
    check_breaker(&budgets.breaker)?;

    // Task authority: every call is bound to an admitted grant (rm_authority).
    rm_authority::authorize_work(principal, &handle.scope, &handle.operation)?;

    // Active deadline on the registered local clock (rm_time). UTC is
    // annotation only; cross-clock/boot/origin ordering is rejected.
    let expired = rm_time::boundary_reached(&handle.now, &handle.active_deadline)
        .map_err(|e| invalid(format!("active deadline cannot be ordered: {e}")))?;
    if expired {
        return Err(not_admitted(
            "active boundary reached before model delivery: no workflow delivery",
        ));
    }

    // Bounded prompt inputs (§10.3): HEAL reduction, fallback text, failed
    // selector/recipe, scoped labels, limitations, commissioned intent, root.
    let prompt_bytes = rm_evidence::load_artifact(principal, prompt)?;
    let prompt_value = validate_prompt_bytes(&prompt_bytes)?;
    let _commissioned_job = prompt_value
        .get("commissioned_job")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let _current_root = prompt_value
        .get("current_root")
        .and_then(Value::as_str)
        .unwrap_or_default();

    if budgets.observation_byte_limit == 0 {
        return Err(not_admitted(
            "observation_byte_limit of zero cannot carry a model response",
        ));
    }

    let prompt_digest = prompt.digest.to_string();
    let owner_domain = handle.scope.owner_domain.clone();

    // Bounded candidate loop: one retry after an invalid first candidate.
    // Every provider call counts; repair and failover never extend the bound.
    let mut retained_raws: Vec<ArtifactReference> = Vec::new();
    let mut last_error: Option<ConnectorError> = None;

    for attempt in 0..MAX_CANDIDATE_ATTEMPTS {
        // Per-attempt budget enforcement so failover/repair cannot bypass
        // aggregate limits.
        if (attempt as u64) >= budgets.recovery_limit {
            last_error = Some(forbidden(format!(
                "recovery_limit of {} forbids candidate attempt {}",
                budgets.recovery_limit,
                attempt + 1
            )));
            break;
        }
        if (attempt as u64) >= budgets.recovery_allowance_remaining {
            last_error = Some(forbidden(
                "recovery allowance is exhausted: no further candidate attempt",
            ));
            break;
        }
        let attempt_cost = budgets
            .tokens_per_call
            .checked_mul((attempt as u64) + 1)
            .ok_or_else(|| invalid("token estimate overflows Revision"))?;
        let reserved = budgets.tokens_reserved.unwrap_or(0);
        if attempt_cost > reserved {
            last_error = Some(forbidden(format!(
                "token reservation {reserved} does not cover candidate attempt {} costing {attempt_cost}",
                attempt + 1
            )));
            break;
        }

        let raw = match take_provider_response(&prompt_digest) {
            Some(bytes) => bytes,
            None => {
                last_error = Some(integrity(format!(
                    "provider conduit has no retained response for candidate attempt {}",
                    attempt + 1
                )));
                break;
            }
        };
        if raw.len() as u64 > budgets.observation_byte_limit {
            last_error = Some(forbidden(format!(
                "provider response has {} bytes, exceeding observation_byte_limit {}",
                raw.len(),
                budgets.observation_byte_limit
            )));
            continue;
        }

        // Raw output is retained before repair (restricted: §20.4).
        let raw_ref = restricted_reference(&raw, &owner_domain)?;
        let raw_ref = rm_evidence::install_artifact(principal, &raw_ref, &raw)?;
        if !retained_raws.contains(&raw_ref) {
            retained_raws.push(raw_ref.clone());
        }

        // Pinned syntax-only repair; repaired bytes retained separately.
        let mut candidate_bytes = raw.clone();
        let mut candidate_ref = raw_ref.clone();
        if let Some(repaired) = repair_json_bytes(&raw) {
            if repaired != raw {
                let repaired_ref = restricted_reference(&repaired, &owner_domain)?;
                let repaired_ref =
                    rm_evidence::install_artifact(principal, &repaired_ref, &repaired)?;
                if !retained_raws.contains(&repaired_ref) {
                    retained_raws.push(repaired_ref.clone());
                }
                candidate_bytes = repaired;
                candidate_ref = repaired_ref;
            }
        }

        match validate_proposal_bytes(&candidate_bytes) {
            Ok(_proposal) => {
                // Re-resolution against the current root is represented by
                // the commissioned prompt binding: the proposal is closed
                // (no identity/job/target/value/file/order/budget fields),
                // carries no executable script, and names no new control.
                // Verified cache replacement still requires the configured
                // operation/readback criterion; this tentative candidate is
                // not a verified selector.
                journal_proposal(principal, &handle.manifest, &candidate_ref, &retained_raws)?;
                return Ok(candidate_ref);
            }
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        integrity("model conduit produced no usable candidate within the bounded retry allowance")
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repair_only_fixes_syntax() {
        let raw = br##"{"selector": "#a", "strategy": "css", "confidence": 0.5, "reason": "x", }"##;
        let repaired = repair_json_bytes(raw).expect("trailing comma repairs");
        assert!(serde_json::from_slice::<Value>(&repaired).is_ok());
        // Missing semantic fields are never invented.
        let missing = br##"{"selector": "#a"}"##;
        if let Some(repaired) = repair_json_bytes(missing) {
            let value: Value = serde_json::from_slice(&repaired).expect("json");
            assert!(!value.as_object().unwrap().contains_key("reason"));
        }
    }
}
