//! `crawler_pipeline`: surface routing and stage-atomicity gate.
//!
//! This module owns the pipeline half of the crawler state machines
//! (seam map §§16.1–16.5):
//!
//! * **[C08]** Four wire surfaces route to exact stage participation and
//!   initial listing states (§16.2). [`route_surface`] enforces the 3/4/3/2
//!   stage lists verbatim. Enrich (dispatch + fetch) counts as one logical
//!   stage; Finalize runs only on the full-description surface.
//! * **[C12]** Every stage commits as one owner-local atomic effect (§16.5).
//!   [`validate_stage_transaction`] rejects orphan downstream rows, cursors
//!   advanced beyond the durable packet, transactions held across network /
//!   inference / signal / human waiting, same-key failures reused as success,
//!   adapter commits, and Finalize synthesis outside the four-field mapping
//!   (title, employer, snippet, full_description).
//! * [`Pipeline::advance`] binds the two: it checks the grant, checks the
//!   requested stage participates in the declared surface, checks stage
//!   atomicity, and only then returns the committed effect record.
//!
//! # Record shapes
//!
//! All inputs and outputs are gate-validated [`CheckedRecord`]s (no bare
//! nulls; absent fields are typed `Missing` envelopes treated as absent).
//!
//! The declaration record carries `surface`, one of the four exact wire
//! names `phase_a_full_description`, `phase_a_snippet_phase_b_description`,
//! `phase_b_description_only`, `none`. Unknown surfaces are rejected, never
//! mapped to a nearest match.
//!
//! The listing record is an object; when it carries an established
//! `listing_state` that state must be in the §16.1 listing vocabulary.
//! `job_id`, when established, is echoed as `listing_ref`.
//!
//! `before` (durable state) carries:
//!
//! ```text
//! {
//!   "durable_packet_id": "<id>",          // certified durable packet boundary
//!   "durable_packets": ["<id>", ...],     // optional full durable set
//!   "listings": ["<id>", ...],            // durably committed listing ids
//!   "works": ["<id>", ...],               // durably committed work ids
//!   "details": ["<id>", ...],             // durably committed detail ids
//!   "cursor": {"certified_packet_id": "<id>"} | Missing,
//!   "listing_state": "<state>" | Missing  // current listing state for transition checks
//! }
//! ```
//!
//! `transaction` (proposed atomic stage effect) carries:
//!
//! ```text
//! {
//!   "stage": "extract" | "snippet_classify" | "dispatch" | "fetch" | "enrich"
//!          | "description_classify" | "finalize" | "failure_reclamation",
//!   "packet_id": "<id>",                 // packet this effect belongs to
//!   "creates_listings": ["<id>", ...],
//!   "creates_works": ["<id>", ...],
//!   "creates_details": ["<id>", ...],
//!   "completes_works": ["<id>", ...],    // work ids completed in this effect
//!   "cursor_advance": {"certified_packet_id": "<id>"} | Missing,
//!   "holds_across": [],                  // must not name network/inference/signal/human
//!   "reuses_detail": {"detail_id": "<id>", "detail_state": "ready"|"vetoed"} | Missing,
//!   "listing_transition": {"from": "<state>"|"absent", "to": "<state>"} | Missing,
//!   "reset_authorized": <bool>,           // required for nonactive -> initial reset
//!   "synthesis": {"title": ..., "employer": ..., "snippet": ..., "full_description": ...} // finalize only
//! }
//! ```
//!
//! Fault codes: `unknown_surface`, `unknown_stage`, `unknown_listing_state`,
//! `invalid_declaration`, `invalid_listing`, `invalid_before`,
//! `invalid_transaction`, `invalid_command`, `invalid_grant`,
//! `orphan_packet`, `cursor_beyond_packet`, `orphan_work`, `orphan_detail`,
//! `spans_forbidden_boundary`, `invalid_reuse`, `invalid_transition`,
//! `invalid_synthesis`, `adapter_forbidden`, `stage_not_in_surface`.

use crawler_authority::{grant_record, Grant};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Map, Value};

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

// ---------------------------------------------------------------------------
// Closed vocabularies (§16.1–16.2)
// ---------------------------------------------------------------------------

/// Exact wire surface names (§16.2). No other value is admitted.
const SURFACE_FULL: &str = "phase_a_full_description";
/// Snippet-then-B-description surface.
const SURFACE_SNIPPET_THEN_B: &str = "phase_a_snippet_phase_b_description";
/// B-description-only surface.
const SURFACE_B_ONLY: &str = "phase_b_description_only";
/// No-description surface.
const SURFACE_NONE: &str = "none";

const SURFACES: &[&str] = &[
    SURFACE_FULL,
    SURFACE_SNIPPET_THEN_B,
    SURFACE_B_ONLY,
    SURFACE_NONE,
];

/// Complete listing vocabulary (§16.1).
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

/// Pending listing states: the only states that hold leases and advance.
const PENDING_LISTING: &[&str] = &[
    "pending_snippet_classify",
    "pending_enrich",
    "pending_description_classify",
    "pending_finalize",
];

/// Eligible initial states that admit the exact-success short circuit (§16.3).
const INITIAL_STATES: &[&str] = &[
    "pending_snippet_classify",
    "pending_enrich",
    "pending_description_classify",
];

/// Logical stage names. `enrich` is one logical stage whose two execution
/// boundaries are `dispatch` and `fetch`.
const STAGE_EXTRACT: &str = "extract";
const STAGE_SNIPPET_CLASSIFY: &str = "snippet_classify";
const STAGE_ENRICH: &str = "enrich";
const STAGE_DESCRIPTION_CLASSIFY: &str = "description_classify";
const STAGE_FINALIZE: &str = "finalize";
/// Execution boundaries inside the logical `enrich` stage.
const STAGE_DISPATCH: &str = "dispatch";
const STAGE_FETCH: &str = "fetch";
/// Terminal/maintenance boundary (§16.5).
const STAGE_FAILURE: &str = "failure_reclamation";

/// Every executable stage boundary. Anything else is a hidden stage.
const EXECUTION_STAGES: &[&str] = &[
    STAGE_EXTRACT,
    STAGE_SNIPPET_CLASSIFY,
    STAGE_DISPATCH,
    STAGE_FETCH,
    STAGE_ENRICH,
    STAGE_DESCRIPTION_CLASSIFY,
    STAGE_FINALIZE,
    STAGE_FAILURE,
];

/// Exact logical stage participation per surface (§16.2): 3/4/3/2.
const STAGES_FULL: &[&str] = &[STAGE_EXTRACT, STAGE_DESCRIPTION_CLASSIFY, STAGE_FINALIZE];
const STAGES_SNIPPET_THEN_B: &[&str] = &[
    STAGE_EXTRACT,
    STAGE_SNIPPET_CLASSIFY,
    STAGE_ENRICH,
    STAGE_DESCRIPTION_CLASSIFY,
];
const STAGES_B_ONLY: &[&str] = &[STAGE_EXTRACT, STAGE_ENRICH, STAGE_DESCRIPTION_CLASSIFY];
const STAGES_NONE: &[&str] = &[STAGE_EXTRACT, STAGE_ENRICH];

/// Finalize synthesis mapping (§6): only these four fields.
const SYNTHESIS_FIELDS: &[&str] = &["title", "employer", "snippet", "full_description"];

/// Boundaries a transaction must never be held across (§16.5).
const FORBIDDEN_SPANS: &[&str] = &[
    "network",
    "acquisition",
    "inference",
    "model",
    "model_inference",
    "signal",
    "signal_emission",
    "human",
    "human_waiting",
];

/// Detail states that count as existing success for reuse (§16.4).
const SUCCESS_DETAIL_STATES: &[&str] = &["ready", "vetoed"];

// ---------------------------------------------------------------------------
// Private helpers
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

/// True when `value` is a schema-gate `Missing` envelope.
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
        fault(
            code,
            format!("{what} must be a JSON object"),
        )
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

/// String array field; absent or `Missing` means empty. Established values
/// must be an array of nonempty strings.
fn str_array(
    map: &Map<String, Value>,
    field: &str,
    code: &str,
    what: &str,
) -> Result<Vec<String>, Fault> {
    let Some(value) = established(map, field) else {
        return Ok(Vec::new());
    };
    let array = value.as_array().ok_or_else(|| {
        fault(
            code,
            format!("{what} field {field:?} must be an array of nonempty strings"),
        )
    })?;
    let mut out = Vec::with_capacity(array.len());
    for (index, entry) in array.iter().enumerate() {
        match entry {
            Value::String(text) if !text.is_empty() => out.push(text.clone()),
            _ => {
                return Err(fault(
                    code,
                    format!(
                        "{what} field {field:?} entry {index} must be a nonempty string"
                    ),
                ))
            }
        }
    }
    Ok(out)
}

/// Initial listing state and exact logical stages for a wire surface.
fn stages_for_surface(surface: &str) -> Option<(&'static str, &'static [&'static str])> {
    match surface {
        SURFACE_FULL => Some(("pending_description_classify", STAGES_FULL)),
        SURFACE_SNIPPET_THEN_B => Some(("pending_snippet_classify", STAGES_SNIPPET_THEN_B)),
        SURFACE_B_ONLY => Some(("pending_enrich", STAGES_B_ONLY)),
        SURFACE_NONE => Some(("pending_enrich", STAGES_NONE)),
        _ => None,
    }
}

/// True when `stage` is an execution boundary of logical `enrich`.
fn is_enrich_boundary(stage: &str) -> bool {
    matches!(stage, "enrich" | "dispatch" | "fetch")
}

/// True when `stage` may execute on `surface`. Dispatch/fetch satisfy the
/// single logical enrich stage; failure/reclamation is surface-independent.
fn stage_participates(surface: &str, stage: &str) -> bool {
    if stage == STAGE_FAILURE {
        return true;
    }
    let Some((_, stages)) = stages_for_surface(surface) else {
        return false;
    };
    if stages.contains(&stage) {
        return true;
    }
    // The two enrich execution boundaries satisfy the one logical stage.
    if is_enrich_boundary(stage) && stages.contains(&STAGE_ENRICH) {
        return true;
    }
    false
}

fn is_pending_listing(state: &str) -> bool {
    PENDING_LISTING.contains(&state)
}

/// Allowed listing transitions (§16.3). `from` is `"absent"` when no row
/// exists yet. Claim/renew and nonexhausted release/reclamation hold the
/// same pending state. Reset from a prior-run nonactive state requires
/// `reset_authorized`.
fn listing_transition_allowed(from: &str, to: &str, reset_authorized: bool) -> bool {
    if from == to && (from == "absent" || is_pending_listing(from)) {
        // Absent-to-absent is vacuous; pending self-hold is claim/renew.
        return from != "absent";
    }
    if from == "absent" {
        return INITIAL_STATES.contains(&to);
    }
    // Same-state hold for pending rows (claim/renew/nonexhausted release).
    if from == to && is_pending_listing(from) {
        return true;
    }
    match (from, to) {
        // Pending snippet (§16.3 rows 2–3).
        ("pending_snippet_classify", "pending_enrich")
        | ("pending_snippet_classify", "vetoed") => true,
        // Pending enrich delegates to work (§16.3 row 4).
        ("pending_enrich", "enqueued") => true,
        // Exact successful-detail short circuit from any eligible initial.
        (f, "deduped") if INITIAL_STATES.contains(&f) => true,
        // Full-description classification (§16.3 rows 6–7).
        ("pending_description_classify", "pending_finalize")
        | ("pending_finalize", "finalized") => true,
        // Exhausted operational/extraction failure from any pending.
        (f, "failed") if is_pending_listing(f) => true,
        // Final non-Pass on a known row renders the listing failed.
        (f, "render_failed") if is_pending_listing(f) => true,
        // Authorized fenced reset from a prior-run nonactive state.
        (f, t)
            if !is_pending_listing(f)
                && f != "absent"
                && INITIAL_STATES.contains(&t)
                && reset_authorized =>
        {
            true
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Surface routing (C08)
// ---------------------------------------------------------------------------

/// Route a declaration/listing pair to its surface, initial listing state,
/// and exact logical stage list (§16.2).
///
/// The declaration must carry an established `surface` in the exact
/// four-value wire vocabulary. The listing must be an object; an established
/// `listing_state` must be in the §16.1 listing vocabulary. The returned
/// `audit_log` record carries `surface`, `initial_state`, `stages`,
/// `stage_count`, `enrich_is_single_stage`, `finalize_present`, and the
/// echoed `listing_ref`.
pub fn route_surface(
    declaration: &CheckedRecord,
    listing: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let declaration_map = as_object(declaration, "invalid_declaration", "declaration")?;
    let listing_map = as_object(listing, "invalid_listing", "listing")?;

    let surface = match established(declaration_map, "surface") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_declaration",
                "declaration requires an established nonempty string \"surface\"".to_string(),
            ))
        }
    };
    let Some((initial_state, stages)) = stages_for_surface(surface) else {
        return Err(fault(
            "unknown_surface",
            format!(
                "unknown surface {surface:?}; expected one of {}",
                SURFACES.join(", ")
            ),
        ));
    };

    if let Some(state) = established(listing_map, "listing_state") {
        match state {
            Value::String(text) if LISTING_STATES.contains(&text.as_str()) => {}
            Value::String(text) => {
                return Err(fault(
                    "unknown_listing_state",
                    format!(
                        "unknown listing_state {text:?}; expected the §16.1 listing vocabulary"
                    ),
                ))
            }
            _ => {
                return Err(fault(
                    "invalid_listing",
                    "listing_state must be a string in the §16.1 listing vocabulary".to_string(),
                ))
            }
        }
    }

    let listing_ref = match established(listing_map, "job_id") {
        Some(Value::String(text)) if !text.is_empty() => Value::String(text.clone()),
        _ => missing(
            "not_observed",
            "listing carries no established job_id; route holds no row reference",
        ),
    };

    let stage_values: Vec<Value> = stages.iter().map(|stage| json!(stage)).collect();
    let finalize_present = stages.contains(&STAGE_FINALIZE);
    validate(
        OUTPUT_SCHEMA,
        json!({
            "record_type": "surface_route",
            "surface": surface,
            "initial_state": initial_state,
            "stages": stage_values,
            "stage_count": stage_values.len(),
            "enrich_is_single_stage": true,
            "finalize_present": finalize_present,
            "listing_ref": listing_ref,
        }),
    )
    .map_err(|inner| {
        fault(
            inner.code.as_str(),
            format!("surface route output: {}", inner.detail),
        )
    })
}

// ---------------------------------------------------------------------------
// Stage atomicity (C12)
// ---------------------------------------------------------------------------

/// Parsed durable boundary for atomicity checks.
struct BeforeFacts {
    durable_packet_id: String,
    durable_packets: Vec<String>,
    listings: Vec<String>,
    works: Vec<String>,
    details: Vec<String>,
    listing_state: Option<String>,
}

impl BeforeFacts {
    fn parse(map: &Map<String, Value>) -> Result<Self, Fault> {
        let durable_packet_id =
            required_str(map, "durable_packet_id", "invalid_before", "before")?.to_string();
        let mut durable_packets = str_array(map, "durable_packets", "invalid_before", "before")?;
        if durable_packets.is_empty() {
            durable_packets.push(durable_packet_id.clone());
        }
        if !durable_packets.contains(&durable_packet_id) {
            return Err(fault(
                "invalid_before",
                "before durable_packets must contain durable_packet_id".to_string(),
            ));
        }
        let cursor_certified = match established(map, "cursor") {
            None => None,
            Some(Value::Object(cursor)) => match established(cursor, "certified_packet_id") {
                None => None,
                Some(Value::String(text)) if !text.is_empty() => Some(text.clone()),
                _ => {
                    return Err(fault(
                        "invalid_before",
                        "before cursor.certified_packet_id must be a nonempty string".to_string(),
                    ))
                }
            },
            Some(_) => {
                return Err(fault(
                    "invalid_before",
                    "before cursor must be an object".to_string(),
                ))
            }
        };
        if let Some(certified) = cursor_certified.as_ref() {
            if !durable_packets.contains(certified) {
                return Err(fault(
                    "invalid_before",
                    format!(
                        "durable cursor certifies packet {certified:?} beyond the durable packet set"
                    ),
                ));
            }
        }
        let listing_state = match established(map, "listing_state") {
            None => None,
            Some(Value::String(text)) if LISTING_STATES.contains(&text.as_str()) => {
                Some(text.clone())
            }
            Some(Value::String(text)) => {
                return Err(fault(
                    "unknown_listing_state",
                    format!("unknown before listing_state {text:?}"),
                ))
            }
            Some(_) => {
                return Err(fault(
                    "invalid_before",
                    "before listing_state must be a string".to_string(),
                ))
            }
        };
        Ok(Self {
            durable_packet_id,
            durable_packets,
            listings: str_array(map, "listings", "invalid_before", "before")?,
            works: str_array(map, "works", "invalid_before", "before")?,
            details: str_array(map, "details", "invalid_before", "before")?,
            listing_state,
        })
    }

    fn packet_is_durable(&self, packet_id: &str) -> bool {
        self.durable_packets.iter().any(|id| id == packet_id)
    }
}

/// Validate that a proposed stage effect commits atomically inside the
/// durable packet boundary (§16.5, C12).
///
/// The transaction's `packet_id` and any `cursor_advance` must stay within
/// the durable packet set. Created work requires listing delegation in the
/// durable state or the same effect; created detail requires work in the
/// durable state, the same effect, or a same-effect work completion.
/// Transactions held across network, inference, signal, or human waiting,
/// same-key failures reused as success, adapter commits, proof/fencing
/// overrides, and Finalize synthesis outside the four-field mapping are
/// rejected.
pub fn validate_stage_transaction(
    before: &CheckedRecord,
    transaction: &CheckedRecord,
) -> Result<(), Fault> {
    let before_map = as_object(before, "invalid_before", "before")?;
    let transaction_map = as_object(transaction, "invalid_transaction", "transaction")?;
    validate_maps(before_map, transaction_map)
}

fn validate_maps(
    before_map: &Map<String, Value>,
    transaction_map: &Map<String, Value>,
) -> Result<(), Fault> {
    let before = BeforeFacts::parse(before_map)?;

    let stage = required_str(transaction_map, "stage", "invalid_transaction", "transaction")?;
    if !EXECUTION_STAGES.contains(&stage) {
        return Err(fault(
            "unknown_stage",
            format!(
                "unknown stage {stage:?}; expected one of {}",
                EXECUTION_STAGES.join(", ")
            ),
        ));
    }
    let packet_id = required_str(
        transaction_map,
        "packet_id",
        "invalid_transaction",
        "transaction",
    )?;
    if !before.packet_is_durable(packet_id) {
        return Err(fault(
            "orphan_packet",
            format!(
                "packet {packet_id:?} is beyond durable packet {:?}; no effect commits outside the durable boundary",
                before.durable_packet_id
            ),
        ));
    }

    check_forbidden_span(transaction_map)?;
    check_adapter_forbidden(transaction_map)?;
    check_cursor_advance(transaction_map, &before)?;
    check_delegation(transaction_map, &before)?;
    check_reuse(transaction_map, &before)?;
    check_listing_transition(transaction_map, &before)?;
    check_finalize_synthesis(transaction_map, stage)?;
    Ok(())
}

/// Reject transactions held across network, inference, signal, or human
/// waiting (§16.5). Both the `holds_across` array and the explicit
/// `spans_*` booleans are checked.
fn check_forbidden_span(transaction: &Map<String, Value>) -> Result<(), Fault> {
    let holds = str_array(
        transaction,
        "holds_across",
        "invalid_transaction",
        "transaction",
    )?;
    for entry in &holds {
        let normalized = entry.to_ascii_lowercase();
        if FORBIDDEN_SPANS.contains(&normalized.as_str()) {
            return Err(fault(
                "spans_forbidden_boundary",
                format!(
                    "transaction holds across {entry:?}; no database transaction spans network, model inference, signal emission, or human waiting"
                ),
            ));
        }
    }
    for (field, boundary) in [
        ("spans_network", "network"),
        ("spans_inference", "model inference"),
        ("spans_signal", "signal emission"),
        ("spans_human", "human waiting"),
    ] {
        if matches!(established(transaction, field), Some(Value::Bool(true))) {
            return Err(fault(
                "spans_forbidden_boundary",
                format!(
                    "transaction sets {field}; no database transaction spans {boundary}"
                ),
            ));
        }
    }
    Ok(())
}

/// Adapters never commit tables, alter fencing, or override proofs.
fn check_adapter_forbidden(transaction: &Map<String, Value>) -> Result<(), Fault> {
    for field in [
        "adapter_commit",
        "adapter_tables",
        "fencing_override",
        "proof_override",
        "cross_domain_write",
        "shared_write",
    ] {
        let forbidden = match established(transaction, field) {
            Some(Value::Bool(true)) => true,
            Some(Value::String(text)) if !text.is_empty() => true,
            Some(Value::Array(entries)) if !entries.is_empty() => true,
            Some(Value::Object(map)) if !map.is_empty() => true,
            _ => false,
        };
        if forbidden {
            return Err(fault(
                "adapter_forbidden",
                format!(
                    "transaction field {field:?} is forbidden; adapters do not commit tables, alter fencing, override proofs, or perform cross-domain writes"
                ),
            ));
        }
    }
    Ok(())
}

/// The certified cursor boundary never advances beyond the durable packet.
fn check_cursor_advance(
    transaction: &Map<String, Value>,
    before: &BeforeFacts,
) -> Result<(), Fault> {
    let advance = match established(transaction, "cursor_advance") {
        None => return Ok(()),
        Some(Value::Object(cursor)) => cursor,
        Some(_) => {
            return Err(fault(
                "invalid_transaction",
                "transaction cursor_advance must be an object".to_string(),
            ))
        }
    };
    let Some(certified) = established(advance, "certified_packet_id") else {
        return Ok(());
    };
    let Value::String(certified) = certified else {
        return Err(fault(
            "invalid_transaction",
            "transaction cursor_advance.certified_packet_id must be a nonempty string".to_string(),
        ));
    };
    if certified.is_empty() {
        return Err(fault(
            "invalid_transaction",
            "transaction cursor_advance.certified_packet_id must be a nonempty string".to_string(),
        ));
    }
    if !before.packet_is_durable(certified) {
        return Err(fault(
            "cursor_beyond_packet",
            format!(
                "cursor advances to packet {certified:?} beyond durable packet {:?}; cursors never advance past the durable packet",
                before.durable_packet_id
            ),
        ));
    }
    Ok(())
}

/// Downstream rows require upstream delegation/completion in the durable
/// state or the same atomic effect. Work without a listing is orphaned;
/// detail without work is orphaned.
fn check_delegation(
    transaction: &Map<String, Value>,
    before: &BeforeFacts,
) -> Result<(), Fault> {
    let creates_listings = str_array(
        transaction,
        "creates_listings",
        "invalid_transaction",
        "transaction",
    )?;
    let creates_works = str_array(
        transaction,
        "creates_works",
        "invalid_transaction",
        "transaction",
    )?;
    let creates_details = str_array(
        transaction,
        "creates_details",
        "invalid_transaction",
        "transaction",
    )?;
    let completes_works = str_array(
        transaction,
        "completes_works",
        "invalid_transaction",
        "transaction",
    )?;

    if !creates_works.is_empty() {
        let listings_available =
            !before.listings.is_empty() || !creates_listings.is_empty();
        if !listings_available {
            return Err(fault(
                "orphan_work",
                "work materialization without listing delegation; no listing exists durably or in this effect"
                    .to_string(),
            ));
        }
    }

    if !creates_details.is_empty() {
        let work_available = !before.works.is_empty()
            || !creates_works.is_empty()
            || !completes_works.is_empty();
        if !work_available {
            return Err(fault(
                "orphan_detail",
                "detail materialization without work completion; no work exists durably, is created, or is completed in this effect"
                    .to_string(),
            ));
        }
    }

    Ok(())
}

/// A same-key failed-render row is never existing success (§16.4). Reuse
/// requires an established ready/vetoed detail that already exists durably.
fn check_reuse(
    transaction: &Map<String, Value>,
    before: &BeforeFacts,
) -> Result<(), Fault> {
    let reuse = match established(transaction, "reuses_detail") {
        None => return Ok(()),
        Some(Value::Object(reuse)) => reuse,
        Some(_) => {
            return Err(fault(
                "invalid_transaction",
                "transaction reuses_detail must be an object".to_string(),
            ))
        }
    };
    let detail_id = match established(reuse, "detail_id") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_transaction",
                "reuses_detail requires an established nonempty string \"detail_id\"".to_string(),
            ))
        }
    };
    let detail_state = match established(reuse, "detail_state") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_transaction",
                "reuses_detail requires an established nonempty string \"detail_state\""
                    .to_string(),
            ))
        }
    };
    if !SUCCESS_DETAIL_STATES.contains(&detail_state) {
        return Err(fault(
            "invalid_reuse",
            format!(
                "detail {detail_id:?} in state {detail_state:?} is not existing success; only ready/vetoed details satisfy the completion contract"
            ),
        ));
    }
    if !before.details.contains(&detail_id.to_string()) {
        return Err(fault(
            "orphan_detail",
            format!(
                "reused detail {detail_id:?} has no durable row; reuse never invents success"
            ),
        ));
    }
    Ok(())
}

/// Listing transitions follow §16.3 exactly.
fn check_listing_transition(
    transaction: &Map<String, Value>,
    before: &BeforeFacts,
) -> Result<(), Fault> {
    let transition = match established(transaction, "listing_transition") {
        None => return Ok(()),
        Some(Value::Object(transition)) => transition,
        Some(_) => {
            return Err(fault(
                "invalid_transaction",
                "transaction listing_transition must be an object".to_string(),
            ))
        }
    };
    let from = match established(transition, "from") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_transaction",
                "listing_transition requires an established nonempty string \"from\"".to_string(),
            ))
        }
    };
    let to = match established(transition, "to") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_transaction",
                "listing_transition requires an established nonempty string \"to\"".to_string(),
            ))
        }
    };
    if from != "absent" && !LISTING_STATES.contains(&from) {
        return Err(fault(
            "unknown_listing_state",
            format!("unknown listing_transition from state {from:?}"),
        ));
    }
    if !LISTING_STATES.contains(&to) {
        return Err(fault(
            "unknown_listing_state",
            format!("unknown listing_transition to state {to:?}"),
        ));
    }
    if let Some(current) = before.listing_state.as_ref() {
        if from != "absent" && from != current.as_str() {
            return Err(fault(
                "invalid_transition",
                format!(
                    "listing_transition from {from:?} does not match durable listing state {current:?}"
                ),
            ));
        }
    }
    let reset_authorized =
        matches!(established(transaction, "reset_authorized"), Some(Value::Bool(true)));
    if !listing_transition_allowed(from, to, reset_authorized) {
        return Err(fault(
            "invalid_transition",
            format!(
                "listing_transition {from:?} -> {to:?} is not an allowed §16.3 transition"
            ),
        ));
    }
    Ok(())
}

/// Finalize maps only title, employer, snippet, and full description (§6).
/// Synthesis outside that mapping — or a required content field outside it —
/// rejects Finalize instead of inventing content.
fn check_finalize_synthesis(transaction: &Map<String, Value>, stage: &str) -> Result<(), Fault> {
    if stage != STAGE_FINALIZE {
        return Ok(());
    }
    let synthesis = match established(transaction, "synthesis") {
        None => return Ok(()),
        Some(Value::Object(synthesis)) => synthesis,
        Some(_) => {
            return Err(fault(
                "invalid_transaction",
                "finalize synthesis must be an object".to_string(),
            ))
        }
    };
    for key in synthesis.keys() {
        if !SYNTHESIS_FIELDS.contains(&key.as_str()) {
            return Err(fault(
                "invalid_synthesis",
                format!(
                    "finalize synthesis field {key:?} is outside the four-field mapping (title, employer, snippet, full_description)"
                ),
            ));
        }
    }
    let required_outside = str_array(
        transaction,
        "required_content",
        "invalid_transaction",
        "transaction",
    )?;
    for field in &required_outside {
        if !SYNTHESIS_FIELDS.contains(&field.as_str()) {
            return Err(fault(
                "invalid_synthesis",
                format!(
                    "required content field {field:?} is outside the four-field Finalize mapping; Finalize is rejected as incomplete_extraction"
                ),
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pipeline seam
// ---------------------------------------------------------------------------

/// Stage execution seam: advance one authorized stage command as a single
/// owner-local atomic effect.
///
/// Implementors check the grant, check surface participation, check stage
/// atomicity via [`validate_stage_transaction`], and return the committed
/// effect record only when every check passes. No implementation holds a
/// transaction across network acquisition, model inference, signal emission,
/// or human waiting.
pub trait Pipeline: Send + Sync {
    fn advance(&self, grant: &Grant, command: &CheckedRecord) -> Result<CheckedRecord, Fault>;
}

/// Owner-local [`Pipeline`] that enforces surface participation and stage
/// atomicity before acknowledging any effect.
///
/// The command is an object with `before` and `transaction` (the shapes
/// accepted by [`validate_stage_transaction`); both are validated here
/// without re-entering the schema gate since the command envelope is
/// already gate-validated), plus either `surface` (wire name) or
/// `declaration` (`{"surface": ...}`) and an optional `listing` object.
/// When a surface is named, the transaction stage must participate in that
/// surface (§16.2); dispatch/fetch satisfy the single logical enrich stage
/// and failure/reclamation is allowed on every surface.
#[derive(Debug, Default)]
pub struct LocalPipeline;

impl LocalPipeline {
    /// New owner-local pipeline.
    pub fn new() -> Self {
        Self
    }
}

impl Pipeline for LocalPipeline {
    fn advance(&self, grant: &Grant, command: &CheckedRecord) -> Result<CheckedRecord, Fault> {
        let grant_map = record_value(grant_record(grant)).as_object().ok_or_else(|| {
            fault(
                "invalid_grant",
                "grant must carry a gate-validated authority record".to_string(),
            )
        })?;
        let owner_domain = match established(grant_map, "owner_domain") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => {
                return Err(fault(
                    "invalid_grant",
                    "grant requires an established nonempty string \"owner_domain\"".to_string(),
                ))
            }
        };

        let command_map = as_object(command, "invalid_command", "command")?;
        let before_map = match established(command_map, "before") {
            Some(Value::Object(map)) => map,
            _ => {
                return Err(fault(
                    "invalid_command",
                    "command requires an established object \"before\"".to_string(),
                ))
            }
        };
        let transaction_map = match established(command_map, "transaction") {
            Some(Value::Object(map)) => map,
            _ => {
                return Err(fault(
                    "invalid_command",
                    "command requires an established object \"transaction\"".to_string(),
                ))
            }
        };

        // Surface participation (§16.2) when the command names a surface.
        let surface = surface_of_command(command_map)?;
        if let Some(surface) = surface.as_ref() {
            let stage = required_str(
                transaction_map,
                "stage",
                "invalid_transaction",
                "transaction",
            )?;
            if !EXECUTION_STAGES.contains(&stage) {
                return Err(fault(
                    "unknown_stage",
                    format!("unknown stage {stage:?}"),
                ));
            }
            if !stage_participates(surface, stage) {
                return Err(fault(
                    "stage_not_in_surface",
                    format!(
                        "stage {stage:?} does not participate in surface {surface:?}; exact 3/4/3/2 participation is enforced"
                    ),
                ));
            }
        }

        validate_maps(before_map, transaction_map)?;

        let stage = required_str(
            transaction_map,
            "stage",
            "invalid_transaction",
            "transaction",
        )?;
        let packet_id = required_str(
            transaction_map,
            "packet_id",
            "invalid_transaction",
            "transaction",
        )?;
        let surface_value = match surface {
            Some(name) => Value::String(name),
            None => missing(
                "not_observed",
                "command names no surface; stage committed on atomicity alone",
            ),
        };
        validate(
            OUTPUT_SCHEMA,
            json!({
                "record_type": "stage_commit",
                "stage": stage,
                "surface": surface_value,
                "packet_id": packet_id,
                "owner_domain": owner_domain,
                "applied": true,
            }),
        )
        .map_err(|inner| {
            fault(
                inner.code.as_str(),
                format!("stage commit output: {}", inner.detail),
            )
        })
    }
}

/// The wire surface named by a command, if any. Accepts either a direct
/// `surface` string or a `declaration` object carrying `surface`.
fn surface_of_command(command: &Map<String, Value>) -> Result<Option<String>, Fault> {
    if let Some(value) = established(command, "surface") {
        let Value::String(text) = value else {
            return Err(fault(
                "invalid_command",
                "command surface must be a string".to_string(),
            ));
        };
        if text.is_empty() {
            return Err(fault(
                "invalid_command",
                "command surface must be a nonempty string".to_string(),
            ));
        }
        if !SURFACES.contains(&text.as_str()) {
            return Err(fault(
                "unknown_surface",
                format!("unknown surface {text:?}"),
            ));
        }
        return Ok(Some(text.clone()));
    }
    let Some(declaration) = established(command, "declaration") else {
        return Ok(None);
    };
    let Value::Object(declaration) = declaration else {
        return Err(fault(
            "invalid_command",
            "command declaration must be an object".to_string(),
        ));
    };
    let Some(value) = established(declaration, "surface") else {
        return Ok(None);
    };
    let Value::String(text) = value else {
        return Err(fault(
            "invalid_command",
            "command declaration.surface must be a string".to_string(),
        ));
    };
    if text.is_empty() || !SURFACES.contains(&text.as_str()) {
        return Err(fault(
            "unknown_surface",
            format!("unknown surface {text:?}"),
        ));
    }
    Ok(Some(text.clone()))
}
