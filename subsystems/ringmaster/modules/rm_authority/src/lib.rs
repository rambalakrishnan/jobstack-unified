//! `rm_authority`: tier-1 authentication and authorization for Ringmaster.
//!
//! This crate is the authority boundary between untrusted callers and the
//! journaled evidence core. It owns four decisions:
//!
//! - Channel authentication (`authenticate_channel`): derive caller identity
//!   exclusively from authenticated channel registration. Request IDs, source
//!   addresses, bare digests, serialized roles, and application credentials
//!   are never sufficient alone (EXT-AUTHORITY).
//! - Work authorization (`authorize_work`): bind every connector call to an
//!   admitted task or resource grant. Artifact references, scripts, node IDs,
//!   and URLs never grant authority, and application credentials never grant
//!   connector control access (EXT-AUTHORITY, BO-AUTHORITY).
//! - Owner authorization (`authorize_owner`): bind every journal event to the
//!   single owning writer domain for its axis. A writer may publish only its
//!   axis; in particular the report writer holds no execution or application
//!   write authority (LIFE-AXES, OWD-OWNER).
//! - Attempt scope verification (`verify_attempt_scope`): check that an
//!   application attempt commission agrees with its admitted manifest with
//!   coherent kind, target, partition, and lineage - and that imported
//!   practice, historical, or synthetic evidence is carried as a marked
//!   import reference, never promoted into current production evidence
//!   (RM-C53; EK-ATTEMPT-SCOPE, LIFE-COMMISSION, LIFE-LINEAGE).
//!
//! All server-assigned fields (producer identity, provenance, owner domain,
//! role, assertion kind) are assigned here from authenticated inputs; no
//! caller-supplied authority field is trusted (EK-PROVENANCE). The crate
//! performs no I/O beyond reading the registration channel, keeps no
//! cross-call state, and issues no shared-database writes or
//! cross-domain transactions.

use serde_json::{json, Value};

pub use rm_wire::Digest;

// ---------------------------------------------------------------------------
// ConnectorError (§17 envelope)
// ---------------------------------------------------------------------------

/// Connector failure envelope. `kind` is always `connector_error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorError {
    pub kind: String,
    pub code: String,
    pub fault_domain: String,
    pub detail: String,
    pub operation_delivery: String,
    pub retry_guidance: String,
    pub retry_after: Option<String>,
    pub handle: Option<String>,
    pub evidence_refs: Vec<String>,
}

impl ConnectorError {
    fn new(
        code: &str,
        fault_domain: &str,
        detail: String,
        operation_delivery: &str,
        retry_guidance: &str,
    ) -> Self {
        ConnectorError {
            kind: "connector_error".to_string(),
            code: code.to_string(),
            fault_domain: fault_domain.to_string(),
            detail,
            operation_delivery: operation_delivery.to_string(),
            retry_guidance: retry_guidance.to_string(),
            retry_after: None,
            handle: None,
            evidence_refs: Vec::new(),
        }
    }
}

impl std::fmt::Display for ConnectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} [{}]: {}", self.code, self.fault_domain, self.detail)
    }
}

impl std::error::Error for ConnectorError {}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    ConnectorError::new(
        "INVALID_REQUEST",
        "request",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn forbidden(detail: impl Into<String>) -> ConnectorError {
    ConnectorError::new(
        "FORBIDDEN",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

fn not_admitted_dispatch(detail: impl Into<String>) -> ConnectorError {
    ConnectorError::new(
        "NOT_ADMITTED",
        "policy",
        detail.into(),
        "not_dispatched",
        "operator_review",
    )
}

/// Pure scope-verification failures never dispatch, so they carry
/// `not_applicable` delivery rather than `not_dispatched`.
fn verify_err(code: &str, detail: impl Into<String>) -> ConnectorError {
    let fault = match code {
        "INVALID_REQUEST" | "UNSUPPORTED_VERSION" => "request",
        _ => "policy",
    };
    ConnectorError::new(code, fault, detail.into(), "not_applicable", "operator_review")
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Exactly the nine versioned connector verbs. No tenth verb exists.
pub const NINE_OPERATIONS: [&str; 9] = [
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

fn is_known_verb(verb: &str) -> bool {
    NINE_OPERATIONS.contains(&verb)
}

/// Control verbs act on execution/observation resources rather than tasks.
/// Cancel, close, release, and contain remain distinct operations.
fn is_control_verb(verb: &str) -> bool {
    matches!(
        verb,
        "RequestNativeCancel" | "CloseObservationConnection" | "ReleaseNativeContext" | "Contain"
    )
}

// ---------------------------------------------------------------------------
// AuthenticatedPrincipal
// ---------------------------------------------------------------------------

/// Caller identity derived from authenticated channel registration.
///
/// The struct is public but its fields are private and it exposes no
/// constructor, `Default`, or deserialization: the only way to obtain one
/// is `authenticate_channel`. IDs and digests are never bearer authority
/// on their own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPrincipal {
    principal_id: String,
    registration_digest: Digest,
}

impl AuthenticatedPrincipal {
    /// The authenticated principal identity.
    pub fn principal_id(&self) -> &str {
        &self.principal_id
    }

    /// Canonical digest of the exact registration bytes that authenticated
    /// this principal.
    pub fn registration_digest(&self) -> &Digest {
        &self.registration_digest
    }
}

/// Channel-binding mechanisms accepted as authenticated registration.
/// Anything else (including a bare ID, address, digest, role list, or
/// application credential) is insufficient alone.
const CHANNEL_MECHANISMS: [&str; 3] = ["mtls", "unix-peercred", "test-harness"];

/// Derive caller identity from authenticated channel registration bytes.
///
/// Reads the full channel, requires a JSON object carrying a nonempty
/// `principal_id` plus a `channel_binding` object with a recognized
/// `mechanism` and a nonempty `binding`, and binds the resulting principal
/// to the canonical digest of the exact registration bytes. In-band nulls,
/// unknown mechanisms, and registration attempts built from a request ID,
/// source address, digest, serialized role, or application credential alone
/// are rejected as unauthenticated.
pub fn authenticate_channel(
    channel: &mut dyn std::io::Read,
) -> Result<AuthenticatedPrincipal, ConnectorError> {
    let mut bytes = Vec::new();
    channel.read_to_end(&mut bytes).map_err(|e| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("channel read failed: {e}"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    if bytes.is_empty() {
        return Err(ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            "channel identity not established: empty registration".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("channel registration is not JSON: {e}"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    let object = value.as_object().ok_or_else(|| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            "channel registration must be a JSON object".to_string(),
            "not_dispatched",
            "operator_review",
        )
    })?;
    if contains_null(&value) {
        return Err(ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            "channel registration carries in-band nulls".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    let principal_id = object
        .get("principal_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            ConnectorError::new(
                "UNAUTHENTICATED",
                "request",
                "channel identity not established: missing principal_id".to_string(),
                "not_dispatched",
                "operator_review",
            )
        })?;
    let binding = object.get("channel_binding").and_then(Value::as_object);
    let (mechanism, proof) = binding
        .and_then(|b| {
            let mechanism = b.get("mechanism").and_then(Value::as_str)?;
            let proof = b.get("binding").and_then(Value::as_str)?;
            Some((mechanism, proof))
        })
        .ok_or_else(|| {
            ConnectorError::new(
                "UNAUTHENTICATED",
                "request",
                "authenticated channel registration required: request IDs, source addresses, digests, roles, and application credentials are not bearer authority"
                    .to_string(),
                "not_dispatched",
                "operator_review",
            )
        })?;
    if mechanism.is_empty() || proof.is_empty() || !CHANNEL_MECHANISMS.contains(&mechanism) {
        return Err(ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("unknown or empty channel binding mechanism: {mechanism:?}"),
            "not_dispatched",
            "operator_review",
        ));
    }
    let registration_digest = rm_wire::canonical_digest(&bytes).map_err(|e| {
        ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            format!("registration bytes not canonicalizable: {e}"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    Ok(AuthenticatedPrincipal {
        principal_id: principal_id.to_string(),
        registration_digest,
    })
}

fn contains_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().any(contains_null),
        Value::Object(map) => map.values().any(contains_null),
        _ => false,
    }
}

/// Defense-in-depth: principals can only be built by `authenticate_channel`,
/// so this always passes for honestly obtained values.
fn check_principal(principal: &AuthenticatedPrincipal) -> Result<(), ConnectorError> {
    if principal.principal_id.is_empty()
        || !rm_wire::is_valid_digest(principal.registration_digest.as_str())
    {
        return Err(ConnectorError::new(
            "UNAUTHENTICATED",
            "request",
            "channel identity not established".to_string(),
            "not_dispatched",
            "operator_review",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Shared attempt vocabulary
// ---------------------------------------------------------------------------

/// Immutable application-attempt kind. Practice is held-in laboratory work;
/// production is held-out employer work requiring an employer origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptKind {
    Practice,
    Production,
}

/// Commissioned target class. Fixtures are held in; employer origins are
/// held out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetClass {
    Fixture,
    Employer,
}

/// Evaluation partition. Laboratory fixtures are held in; employer origins
/// are held out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvaluationPartition {
    HeldIn,
    HeldOut,
}

/// Execution mode. Manual commissions are never dispatchable through
/// Prepare/Start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Manual,
    Automated,
}

// ---------------------------------------------------------------------------
// WorkScope, Operation, ProducerDescriptor
// ---------------------------------------------------------------------------

/// Authority view of admitted work: the admitted manifest binding, the
/// attempt/commission binding (absent, i.e. inapplicable, for non-application
/// discovery work), and the task/resource grants authorizing this call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkScope {
    pub activity: String,
    pub run_id: String,
    pub journal_id: String,
    pub manifest_hash: String,
    pub admission_ref: String,
    /// Attempt binding; `None` is inapplicable (discovery work).
    pub attempt_id: Option<String>,
    /// Commission binding; `None` is inapplicable (discovery work).
    pub commission_id: Option<String>,
    /// Admitted commission reference; `None` is inapplicable.
    pub commission_ref: Option<String>,
    /// Attempt kind; `None` is inapplicable (discovery work).
    pub attempt_kind: Option<AttemptKind>,
    /// Admitted task/resource grants. Must be nonempty: every call is bound
    /// to a grant. Control grants carry the `control:` scope prefix.
    pub authorization_refs: Vec<String>,
    pub observation_policy: String,
    pub owner_domain: String,
    pub execution_mode: ExecutionMode,
}

/// Requested connector operation: verb, connector, subject, task scope,
/// account/runtime access, artifact references, and control target, each
/// authorized separately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    pub verb: String,
    pub connector_id: String,
    pub subject_id: String,
    /// Admitted task-scope identity. References (URLs, scripts, node IDs,
    /// artifact IDs) are never valid scopes and never grant authority.
    pub task_scope: String,
    /// Scoped account/runtime binding reference, if applicable.
    pub account_binding: Option<String>,
    /// Artifact references carried with the call. Recorded, never
    /// authoritative: they cannot satisfy the grant requirement.
    pub artifact_refs: Vec<String>,
    /// Control target, required for control verbs.
    pub control_target: Option<String>,
}

/// Authority-assigned producer description. Every field is assigned here
/// from authenticated inputs; callers supply no authority fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerDescriptor {
    pub producer_id: String,
    pub provenance: String,
    pub owner_domain: String,
    pub role: String,
    pub assertion_kind: String,
}

/// Provenance assigned to fresh practice work. Never upgraded.
pub const PROVENANCE_PRACTICE_DIRECT: &str = "practice_direct";
/// Provenance assigned to fresh production work. Never granted to imports.
pub const PROVENANCE_PRODUCTION_DIRECT: &str = "production_direct";
/// Provenance assigned to work without an attempt binding (discovery).
pub const PROVENANCE_TASK_DIRECT: &str = "task_direct";
/// Provenance assigned to owner-domain event submission.
pub const PROVENANCE_OWNER_DIRECT: &str = "owner_direct";
/// Required claimed provenance for practice evidence imported elsewhere.
pub const PROVENANCE_IMPORTED_PRACTICE: &str = "imported_practice_reference";
/// Required claimed provenance for production evidence imported elsewhere.
pub const PROVENANCE_IMPORTED_PRODUCTION: &str = "imported_production_reference";

fn role_for_verb(verb: &str) -> &'static str {
    if is_control_verb(verb) {
        "control_agent"
    } else {
        "connector_agent"
    }
}

fn assertion_for_verb(verb: &str) -> &'static str {
    if is_control_verb(verb) {
        "control_evidence"
    } else {
        "task_evidence"
    }
}

fn is_reference_shape(scope: &str) -> bool {
    scope.starts_with("http://")
        || scope.starts_with("https://")
        || scope.starts_with("script:")
        || scope.starts_with("node:")
        || scope.starts_with("artifact:")
        || scope.starts_with('/')
}

fn require_owner_domain(owner_domain: &str) -> Result<(), ConnectorError> {
    let valid = !owner_domain.is_empty()
        && owner_domain.len() <= 64
        && owner_domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !valid {
        return Err(invalid(format!(
            "owner_domain {owner_domain:?} must be a single identity of letters, digits, '_' or '-'"
        )));
    }
    Ok(())
}

/// Authorize a connector call against its admitted work scope.
///
/// Checks, in order: principal validity; scope shape (all bindings present,
/// manifest hash well-formed, owner domain a single identity); presence of
/// an admitted task/resource grant; verb membership in the nine operations;
/// operation shape; application-work commission binding; manual-mode
/// exclusion from Prepare/Start; task-scope coverage (references never
/// qualify); and, for control verbs, control-target presence, a scoped
/// control grant, and exclusion of application credentials. On success
/// returns the authority-assigned producer descriptor.
pub fn authorize_work(
    principal: &AuthenticatedPrincipal,
    scope: &WorkScope,
    operation: &Operation,
) -> Result<ProducerDescriptor, ConnectorError> {
    check_principal(principal)?;
    require_nonempty("activity", &scope.activity)?;
    require_nonempty("run_id", &scope.run_id)?;
    require_nonempty("journal_id", &scope.journal_id)?;
    require_nonempty("manifest_hash", &scope.manifest_hash)?;
    if !rm_wire::is_valid_digest(&scope.manifest_hash) {
        return Err(invalid("manifest_hash must be a sha256 digest"));
    }
    require_nonempty("admission_ref", &scope.admission_ref)?;
    require_nonempty("observation_policy", &scope.observation_policy)?;
    require_owner_domain(&scope.owner_domain)?;
    if scope.authorization_refs.is_empty() {
        return Err(forbidden(
            "every call is bound to an admitted task/resource grant: authorization_refs is empty; artifact references, scripts, node IDs, and URLs do not grant authority",
        ));
    }
    if !is_known_verb(&operation.verb) {
        return Err(invalid(format!(
            "unknown operation {:?}: exactly the nine versioned verbs exist",
            operation.verb
        )));
    }
    require_nonempty("connector_id", &operation.connector_id)?;
    require_nonempty("subject_id", &operation.subject_id)?;
    require_nonempty("task_scope", &operation.task_scope)?;
    if scope.activity == "apply" {
        match (
            &scope.attempt_id,
            &scope.commission_id,
            &scope.commission_ref,
            &scope.attempt_kind,
        ) {
            (Some(a), Some(c), Some(r), Some(_))
                if !a.is_empty() && !c.is_empty() && !r.is_empty() => {}
            _ => {
                return Err(not_admitted_dispatch(
                    "application work requires its immutable attempt commission",
                ))
            }
        }
    }
    if scope.execution_mode == ExecutionMode::Manual
        && matches!(operation.verb.as_str(), "Prepare" | "Start")
    {
        return Err(not_admitted_dispatch(
            "manual commissions are not dispatchable through Prepare/Start",
        ));
    }
    if is_reference_shape(&operation.task_scope) {
        return Err(forbidden(
            "task_scope must be an admitted scope identity; artifact references, scripts, node IDs, and URLs do not grant authority",
        ));
    }
    if operation.task_scope != scope.activity
        && !operation
            .task_scope
            .starts_with(&format!("{}:", scope.activity))
    {
        return Err(forbidden(format!(
            "task_scope {:?} is not covered by admitted activity {:?}",
            operation.task_scope, scope.activity
        )));
    }
    if is_control_verb(&operation.verb) {
        match &operation.control_target {
            Some(target) if !target.is_empty() => {}
            _ => return Err(invalid("control operations require a control_target")),
        }
        if !scope
            .authorization_refs
            .iter()
            .any(|grant| grant.starts_with("control:"))
        {
            return Err(forbidden(
                "control operations require a scoped control grant; task grants do not authorize control",
            ));
        }
        if let Some(binding) = &operation.account_binding {
            if binding.starts_with("app-cred:") {
                return Err(forbidden(
                    "application credentials do not grant connector control access",
                ));
            }
        }
    }
    let provenance = match scope.attempt_kind {
        Some(AttemptKind::Practice) => PROVENANCE_PRACTICE_DIRECT,
        Some(AttemptKind::Production) => PROVENANCE_PRODUCTION_DIRECT,
        None => PROVENANCE_TASK_DIRECT,
    };
    Ok(ProducerDescriptor {
        producer_id: principal.principal_id().to_string(),
        provenance: provenance.to_string(),
        owner_domain: scope.owner_domain.clone(),
        role: role_for_verb(&operation.verb).to_string(),
        assertion_kind: assertion_for_verb(&operation.verb).to_string(),
    })
}

// ---------------------------------------------------------------------------
// Owner authorization (LIFE-AXES, OWD-OWNER)
// ---------------------------------------------------------------------------

/// The five publication axes. Exactly one authority role owns each.
pub const FIVE_AXES: [&str; 5] = [
    "dispatch",
    "observation",
    "execution",
    "application",
    "report",
];

enum OwnerRequirement {
    Exact(&'static str),
    AnyAxis,
}

/// Manifest event registry: the owner domain each event kind must be
/// published under. `None` means the kind is not registered.
fn required_owner_for_event(event_kind: &str) -> Option<OwnerRequirement> {
    match event_kind {
        "dispatch_published" => Some(OwnerRequirement::Exact("dispatch")),
        "observation_opened" | "observation_closed" | "context_observation" => {
            Some(OwnerRequirement::Exact("observation"))
        }
        "execution_claim" | "native_report" | "task_output" => {
            Some(OwnerRequirement::Exact("execution"))
        }
        "origin_fact" => Some(OwnerRequirement::Exact("application")),
        "report_published" => Some(OwnerRequirement::Exact("report")),
        "manifest_admitted" | "clock_registered" => Some(OwnerRequirement::Exact("evidence")),
        "artifact_available" => Some(OwnerRequirement::Exact("artifact")),
        "control_observation" => Some(OwnerRequirement::Exact("control")),
        "connector_incident" => Some(OwnerRequirement::Exact("connector")),
        "lifecycle_publication" => Some(OwnerRequirement::AnyAxis),
        _ => None,
    }
}

fn role_for_owner(owner_domain: &str) -> &'static str {
    match owner_domain {
        "dispatch" => "dispatch_writer",
        "observation" => "observation_writer",
        "execution" => "execution_writer",
        "application" => "application_writer",
        "report" => "report_writer",
        "evidence" => "evidence_writer",
        "artifact" => "artifact_writer",
        "control" => "control_writer",
        "connector" => "connector_writer",
        _ => "domain_writer",
    }
}

/// Authorize the principal as the logical writer submitting `event_kind`
/// under `owner_domain`.
///
/// The owner domain must be a single valid identity, the event kind must be
/// manifest-registered, and the domain must own that kind's axis: a writer
/// may publish only its axis. The report writer in particular holds no
/// execution or application write authority. The returned producer
/// descriptor (identity, provenance, domain, role, assertion kind) is
/// assigned by the authority, preserving the authoritative source identity.
pub fn authorize_owner(
    principal: &AuthenticatedPrincipal,
    owner_domain: &str,
    event_kind: &str,
) -> Result<ProducerDescriptor, ConnectorError> {
    check_principal(principal)?;
    require_owner_domain(owner_domain)?;
    if event_kind.is_empty() {
        return Err(invalid("event_kind must be nonempty"));
    }
    let requirement = required_owner_for_event(event_kind).ok_or_else(|| {
        ConnectorError::new(
            "NOT_ADMITTED",
            "policy",
            format!("event kind {event_kind:?} is not manifest-registered"),
            "not_dispatched",
            "operator_review",
        )
    })?;
    let allowed = match requirement {
        OwnerRequirement::Exact(axis) => owner_domain == axis,
        OwnerRequirement::AnyAxis => FIVE_AXES.contains(&owner_domain),
    };
    if !allowed {
        let detail = if owner_domain == "report"
            && matches!(
                event_kind,
                "execution_claim" | "native_report" | "task_output" | "origin_fact"
            ) {
            format!(
                "report writer holds no execution/application write authority: cannot publish {event_kind:?}"
            )
        } else {
            format!(
                "writer for {owner_domain:?} may publish only its axis: cannot publish {event_kind:?}"
            )
        };
        return Err(forbidden(detail));
    }
    Ok(ProducerDescriptor {
        producer_id: principal.principal_id().to_string(),
        provenance: PROVENANCE_OWNER_DIRECT.to_string(),
        owner_domain: owner_domain.to_string(),
        role: role_for_owner(owner_domain).to_string(),
        assertion_kind: event_kind.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Manifest and AttemptCommission
// ---------------------------------------------------------------------------

/// Authority view of the admitted manifest: the wire record fields plus the
/// admission binding and the canonical hash of the wire record.
///
/// `manifest_hash` covers exactly the wire projection emitted by
/// `manifest_wire_bytes` (record_type, schema_version, run_id, task,
/// subject, event_kinds).
#[derive(Debug, Clone, PartialEq)]
pub struct Manifest {
    pub record_type: String,
    pub schema_version: String,
    pub run_id: String,
    pub task: Value,
    pub subject: Value,
    pub event_kinds: Vec<String>,
    pub admission_ref: String,
    pub manifest_hash: String,
}

/// Canonical wire bytes of the manifest record: the closed projection
/// validated structurally before any semantic scope check.
pub fn manifest_wire_bytes(manifest: &Manifest) -> Vec<u8> {
    let wire = json!({
        "record_type": manifest.record_type,
        "schema_version": manifest.schema_version,
        "run_id": manifest.run_id,
        "task": manifest.task,
        "subject": manifest.subject,
        "event_kinds": manifest.event_kinds,
    });
    serde_json::to_vec(&wire).unwrap_or_default()
}

/// Lineage link to an already-commissioned attempt identity. Lineage links
/// record derivation history only; they never promote evidence across
/// attempts or partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageRef {
    pub attempt_id: String,
    pub kind: AttemptKind,
}

/// Imported evidence carried with a commission: original bytes retained
/// under their source digest with explicit import provenance. Imports are
/// references to foreign evidence, never current evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceImport {
    pub source_attempt_id: String,
    pub source_kind: AttemptKind,
    pub source_digest: String,
    pub claimed_provenance: String,
    pub retained_bytes_digest: String,
}

/// Immutable application-attempt commission authorizing exact task, subject,
/// kind, target, lineage, and evidence imports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptCommission {
    pub record_type: String,
    pub schema_version: String,
    pub commission_id: String,
    pub run_id: String,
    pub journal_id: String,
    pub manifest_hash: String,
    pub admission_ref: String,
    pub attempt_id: String,
    pub kind: AttemptKind,
    pub target_class: TargetClass,
    pub evaluation_partition: EvaluationPartition,
    pub target_id: String,
    pub derived_from: Vec<LineageRef>,
    pub rehearsal_of: Option<LineageRef>,
    pub performance_of: Option<LineageRef>,
    pub task_semantic_hash: String,
    pub idempotency_key: String,
    pub imported_evidence: Vec<EvidenceImport>,
}

/// Verify that a commission agrees with its admitted manifest and carries a
/// coherent, promotion-free scope.
///
/// Checks: manifest wire-record structural validity and hash integrity;
/// commission admission binding (manifest hash, admission reference, run);
/// contract identity; kind/target/partition coherence (practice is
/// fixture/held-in, production is employer/held-out); same-kind acyclic
/// derivation; rehearsal/performance direction (practice rehearses
/// production, production performs against practice); and, for every
/// import, original-byte preservation plus import provenance matching the
/// source kind - so practice evidence imported into a production commission
/// stays a marked import reference and is never promoted into current
/// production evidence (RM-C53).
pub fn verify_attempt_scope(
    manifest: &Manifest,
    commission: &AttemptCommission,
) -> Result<(), ConnectorError> {
    // 1. Manifest wire-record structural validity (closed fields, no bare
    //    nulls, valid scalars) via the wire contract.
    let wire_bytes = manifest_wire_bytes(manifest);
    rm_wire::validate_record("manifest/v1", &wire_bytes)
        .map_err(|e| verify_err("INVALID_REQUEST", format!("manifest wire record invalid: {e}")))?;
    // 2. Manifest hash integrity: the admitted hash must cover these bytes.
    let actual = rm_wire::canonical_digest(&wire_bytes)
        .map_err(|e| verify_err("INVALID_REQUEST", format!("manifest bytes not hashable: {e}")))?;
    if manifest.manifest_hash != actual.as_str() {
        return Err(verify_err(
            "NOT_ADMITTED",
            "manifest hash mismatch: admitted bytes changed",
        ));
    }
    // 3. Commission admission binding.
    if commission.manifest_hash != manifest.manifest_hash {
        return Err(verify_err(
            "NOT_ADMITTED",
            "commission manifest binding mismatch: not admitted under this manifest",
        ));
    }
    if commission.admission_ref != manifest.admission_ref {
        return Err(verify_err(
            "NOT_ADMITTED",
            "commission admission binding mismatch: admission reference differs",
        ));
    }
    if commission.run_id != manifest.run_id {
        return Err(verify_err(
            "NOT_ADMITTED",
            "commission run binding mismatch: run differs from admitted manifest",
        ));
    }
    // 4. Contract identity and required bindings.
    if commission.record_type != "attempt_commission" {
        return Err(verify_err(
            "INVALID_REQUEST",
            format!(
                "commission record_type must be \"attempt_commission\", found {:?}",
                commission.record_type
            ),
        ));
    }
    if commission.schema_version != "application-attempt-lifecycle/0.1.0" {
        return Err(verify_err(
            "UNSUPPORTED_VERSION",
            format!(
                "unknown commission schema_version {:?}",
                commission.schema_version
            ),
        ));
    }
    for (field, value) in [
        ("commission_id", commission.commission_id.as_str()),
        ("journal_id", commission.journal_id.as_str()),
        ("attempt_id", commission.attempt_id.as_str()),
        ("target_id", commission.target_id.as_str()),
        ("idempotency_key", commission.idempotency_key.as_str()),
    ] {
        if value.is_empty() {
            return Err(verify_err(
                "INVALID_REQUEST",
                format!("commission {field} must be nonempty"),
            ));
        }
    }
    if !rm_wire::is_valid_digest(&commission.task_semantic_hash) {
        return Err(verify_err(
            "INVALID_REQUEST",
            "commission task_semantic_hash must be a sha256 digest",
        ));
    }
    // 5. Kind/target/partition coherence: kind is immutable and determines
    //    the rest. Practice is fixture/held-in; production is
    //    employer/held-out and requires an employer origin.
    let coherent = matches!(
        (
            commission.kind,
            commission.target_class,
            commission.evaluation_partition
        ),
        (
            AttemptKind::Practice,
            TargetClass::Fixture,
            EvaluationPartition::HeldIn
        ) | (
            AttemptKind::Production,
            TargetClass::Employer,
            EvaluationPartition::HeldOut
        )
    );
    if !coherent {
        return Err(verify_err(
            "NOT_ADMITTED",
            "kind/target/partition incoherence: practice is fixture/held-in, production is employer/held-out",
        ));
    }
    // 6. derived_from: same-kind, acyclic, unique.
    {
        let mut seen = std::collections::HashSet::new();
        for link in &commission.derived_from {
            if link.attempt_id.is_empty() {
                return Err(verify_err(
                    "INVALID_REQUEST",
                    "derived_from attempt_id must be nonempty",
                ));
            }
            if link.attempt_id == commission.attempt_id {
                return Err(verify_err(
                    "INVALID_REQUEST",
                    "derived_from must be acyclic: self-derivation rejected",
                ));
            }
            if link.kind != commission.kind {
                return Err(verify_err(
                    "NOT_ADMITTED",
                    "derived_from is same-kind only: cross-kind derivation would promote foreign evidence",
                ));
            }
            if !seen.insert(link.attempt_id.as_str()) {
                return Err(verify_err(
                    "INVALID_REQUEST",
                    format!(
                        "derived_from attempt {:?} listed twice",
                        link.attempt_id
                    ),
                ));
            }
        }
    }
    // 7. rehearsal_of (practice -> production) and performance_of
    //    (production -> practice): direction-checked lineage, never evidence.
    match (&commission.rehearsal_of, &commission.performance_of) {
        (Some(_), Some(_)) => {
            return Err(verify_err(
                "NOT_ADMITTED",
                "an attempt has one immutable kind: rehearsal_of and performance_of are mutually exclusive",
            ))
        }
        _ => {}
    }
    if let Some(link) = &commission.rehearsal_of {
        if commission.kind != AttemptKind::Practice {
            return Err(verify_err(
                "NOT_ADMITTED",
                "rehearsal_of links practice to production: only practice attempts rehearse",
            ));
        }
        if link.kind != AttemptKind::Production {
            return Err(verify_err(
                "NOT_ADMITTED",
                "rehearsal_of must point to an already-commissioned production identity",
            ));
        }
        if link.attempt_id.is_empty() || link.attempt_id == commission.attempt_id {
            return Err(verify_err(
                "INVALID_REQUEST",
                "rehearsal_of must name a different already-commissioned attempt",
            ));
        }
    }
    if let Some(link) = &commission.performance_of {
        if commission.kind != AttemptKind::Production {
            return Err(verify_err(
                "NOT_ADMITTED",
                "performance_of links production to practice: only production attempts perform",
            ));
        }
        if link.kind != AttemptKind::Practice {
            return Err(verify_err(
                "NOT_ADMITTED",
                "performance_of must point to an already-commissioned practice identity",
            ));
        }
        if link.attempt_id.is_empty() || link.attempt_id == commission.attempt_id {
            return Err(verify_err(
                "INVALID_REQUEST",
                "performance_of must name a different already-commissioned attempt",
            ));
        }
    }
    // 8. Imported evidence (RM-C53): original bytes preserved under their
    //    source digest, claimed provenance an import marker for the source
    //    kind. Any direct/current claim over foreign bytes is promotion.
    for import in &commission.imported_evidence {
        if import.source_attempt_id.is_empty() {
            return Err(verify_err(
                "INVALID_REQUEST",
                "import source_attempt_id must be nonempty",
            ));
        }
        if import.source_attempt_id == commission.attempt_id {
            return Err(verify_err(
                "INVALID_REQUEST",
                "an attempt cannot import its own evidence as foreign bytes",
            ));
        }
        if !rm_wire::is_valid_digest(&import.source_digest)
            || !rm_wire::is_valid_digest(&import.retained_bytes_digest)
        {
            return Err(verify_err(
                "INVALID_REQUEST",
                "import digests must be sha256 digests",
            ));
        }
        if import.retained_bytes_digest != import.source_digest {
            return Err(verify_err(
                "NOT_ADMITTED",
                "import must preserve original bytes: retained digest differs from source digest",
            ));
        }
        let required = match import.source_kind {
            AttemptKind::Practice => PROVENANCE_IMPORTED_PRACTICE,
            AttemptKind::Production => PROVENANCE_IMPORTED_PRODUCTION,
        };
        if import.claimed_provenance != required {
            return Err(verify_err(
                "NOT_ADMITTED",
                format!(
                    "no promotion: {:?} bytes must retain {:?}, found {:?}",
                    match import.source_kind {
                        AttemptKind::Practice => "practice",
                        AttemptKind::Production => "production",
                    },
                    required,
                    import.claimed_provenance
                ),
            ));
        }
    }
    Ok(())
}
