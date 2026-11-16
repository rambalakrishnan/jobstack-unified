//! `crawler_authority`: ingestion and connector authorization from authenticated registration.
//!
//! Identity and grants are derived from authenticated channel registration,
//! never from caller-supplied fields:
//!
//! - [`authorize_producer`] admits an `EventSubmission` (never a journal
//!   envelope) from a producer registered in the kernel manifest. Any
//!   submitted server/provenance/authority field (`owner_domain`,
//!   `producer_id`, `provenance`, `role`, `assertion_kind`, journal
//!   coordinates, hashes, receipt time, manifest hash) is rejected as a
//!   spoof rather than trusted. The grant carries the registry-derived
//!   owner, role, provenance, and assertion kind.
//! - [`authorize`] admits a connector request under a channel registration.
//!   Caller-supplied identity, grants, owner, provenance, or control flags
//!   are rejected. The verb must be one of the nine connector verbs and be
//!   granted to the principal along with the connector; control verbs
//!   additionally require an explicit control grant. Identifiers, digests,
//!   application credentials, and HTTP success never confer control.
//! - [`authorize_reference`] exercises an artifact/evidence reference under a
//!   grant. The reference must name the grant digest (a digest alone is not
//!   bearer authority), publication must stay inside the grant's owner
//!   domain, restricted access requires an explicit grant flag, and imported
//!   (non-origin) evidence is never upgraded into origin facts.
//!
//! Principals are bound to the exact registration bytes they were issued
//! against through [`crawler_hashing::verify_record_digest`]: a principal
//! naming a stale or foreign manifest/registration digest fails closed.

use crawler_hashing::verify_record_digest;
use crawler_schema::{CheckedRecord, Fault, record_value, validate};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Closed vocabularies
// ---------------------------------------------------------------------------

/// The nine and only nine external connector verbs (Contract 02, §19.3).
const VERBS: &[&str] = &[
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

/// Verbs that exercise connector control and need an explicit control grant.
const CONTROL_VERBS: &[&str] = &["RequestNativeCancel", "ReleaseNativeContext", "Contain"];

/// Operations [`authorize_reference`] admits over a reference.
const OPERATIONS: &[&str] = &["read", "collect", "publish", "assert_origin"];

/// Server-assigned fields an `EventSubmission` must never carry (S06, §13.1).
const SUBMISSION_FORBIDDEN: &[&str] = &[
    "owner_domain",
    "producer_id",
    "provenance",
    "role",
    "assertion_kind",
    "journal_sequence",
    "event_id",
    "event_hash",
    "previous_event_hash",
    "producer_sequence",
    "recorded_at",
    "manifest_hash",
];

/// Authority fields a connector request must never carry (S01, §19.4).
const REQUEST_FORBIDDEN: &[&str] = &[
    "principal_id",
    "caller",
    "caller_identity",
    "grant",
    "grants",
    "authorized",
    "owner_domain",
    "provenance",
    "control",
    "control_authority",
    "restricted_access",
    "registration_digest",
];

// ---------------------------------------------------------------------------
// Grant
// ---------------------------------------------------------------------------

/// An authorization derived from authenticated registration.
///
/// The wrapped record holds only registry-derived facts (identity, owner
/// domain, grants, provenance); nothing in it was copied from a caller
/// assertion.
#[derive(Debug)]
pub struct Grant {
    record: CheckedRecord,
}

/// Borrow the registry-derived record inside a [`Grant`].
pub fn grant_record(grant: &Grant) -> &CheckedRecord {
    &grant.record
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

fn fault(code: &str, detail: String) -> Fault {
    Fault {
        code: code.to_string(),
        detail,
    }
}

fn is_digest_text(text: &str) -> bool {
    text.len() == 64
        && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// True when `value` is a `Missing` envelope (`{"value": null, ...}`).
/// The schema gate has already validated the envelope shape.
fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.get("value").is_some_and(Value::is_null))
}

/// The established (non-`Missing`) value of `field`, if any.
fn established<'a>(map: &'a Map<String, Value>, field: &str) -> Option<&'a Value> {
    map.get(field).filter(|value| !is_missing(value))
}

fn as_object<'a>(record: &'a CheckedRecord, code: &str, what: &str) -> Result<&'a Map<String, Value>, Fault> {
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

/// Reject any established caller-supplied authority field as a spoof.
/// Present-but-`Missing` fields assert nothing and are treated as absent.
fn reject_forbidden(map: &Map<String, Value>, fields: &[&str]) -> Result<(), Fault> {
    for field in fields {
        if established(map, field).is_some() {
            return Err(fault(
                "spoofed_authority_field",
                format!("caller-supplied authority field {field:?} is rejected; identity and provenance come from authenticated registration"),
            ));
        }
    }
    Ok(())
}

fn find_entry<'a>(entries: &'a [Value], key: &str, id: &str) -> Option<&'a Map<String, Value>> {
    entries.iter().filter_map(Value::as_object).find(|entry| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate == id)
    })
}

// ---------------------------------------------------------------------------
// Producer authorization (S06 ingestion)
// ---------------------------------------------------------------------------

/// Authorize a producer's `EventSubmission` under a kernel manifest.
///
/// The principal supplies only its authenticated `producer_id` plus the
/// `manifest_digest` binding it to these exact manifest bytes. Owner domain,
/// role, provenance, and assertion kind are taken from the manifest's
/// producer registry; the event kind must be registered and must permit the
/// producer's provenance. Imported evidence can never satisfy an
/// origin-only event or claim current origin scope.
///
/// Faults: `invalid_submission`, `spoofed_authority_field`,
/// `invalid_principal`, `unknown_principal`, `invalid_manifest`,
/// `missing_registry`, `missing_manifest_binding`, `invalid_expected_digest`,
/// `digest_mismatch`, `unregistered_producer`, `missing_event_kind`,
/// `unregistered_event_kind`, `missing_provenance`,
/// `missing_provenance_policy`, `missing_authority`, `missing_owner_domain`,
/// `provenance_upgrade_refused`.
pub fn authorize_producer(
    principal: &CheckedRecord,
    submission: &CheckedRecord,
    manifest: &CheckedRecord,
) -> Result<Grant, Fault> {
    let submission = as_object(submission, "invalid_submission", "submission")?;
    reject_forbidden(submission, SUBMISSION_FORBIDDEN)?;

    let principal = as_object(principal, "invalid_principal", "principal")?;
    let producer_id = required_str(principal, "producer_id", "unknown_principal", "principal")?;

    let manifest_map = as_object(manifest, "invalid_manifest", "manifest")?;
    let registry = match established(manifest_map, "producer_registry") {
        Some(Value::Array(entries)) => entries,
        _ => {
            return Err(fault(
                "missing_registry",
                "manifest requires an established producer_registry array".to_string(),
            ))
        }
    };

    let binding = required_str(
        principal,
        "manifest_digest",
        "missing_manifest_binding",
        "principal",
    )?;
    verify_record_digest(manifest, binding)?;

    let entry = find_entry(registry, "producer_id", producer_id).ok_or_else(|| {
        fault(
            "unregistered_producer",
            format!("producer {producer_id:?} is not registered in the manifest"),
        )
    })?;
    let owner_domain = match established(entry, "owner_domain") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "missing_owner_domain",
                format!("registry entry for producer {producer_id:?} has no established owner_domain"),
            ))
        }
    };
    let provenance = match established(entry, "provenance") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "missing_provenance",
                format!("registry entry for producer {producer_id:?} has no established provenance"),
            ))
        }
    };
    let role = match established(entry, "role") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "missing_authority",
                format!("registry entry for producer {producer_id:?} has no established role"),
            ))
        }
    };
    let assertion_kind = match established(entry, "assertion_kind") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "missing_authority",
                format!(
                    "registry entry for producer {producer_id:?} has no established assertion_kind"
                ),
            ))
        }
    };

    let event_kind = required_str(submission, "event_kind", "missing_event_kind", "submission")?;
    let event_registry = match established(manifest_map, "event_registry") {
        Some(Value::Array(entries)) => entries,
        _ => {
            return Err(fault(
                "missing_registry",
                "manifest requires an established event_registry array".to_string(),
            ))
        }
    };
    let event_entry = find_entry(event_registry, "event_kind", event_kind).ok_or_else(|| {
        fault(
            "unregistered_event_kind",
            format!("event kind {event_kind:?} is not registered in the manifest"),
        )
    })?;
    let permitted = match established(event_entry, "permitted_provenance") {
        Some(Value::Array(values)) => values,
        _ => {
            return Err(fault(
                "missing_provenance_policy",
                format!("event kind {event_kind:?} has no established permitted_provenance"),
            ))
        }
    };
    if !permitted
        .iter()
        .filter_map(Value::as_str)
        .any(|allowed| allowed == provenance)
    {
        return Err(fault(
            "provenance_upgrade_refused",
            format!(
                "producer {producer_id:?} with provenance {provenance:?} cannot submit origin-scoped event kind {event_kind:?}; imported evidence is never upgraded"
            ),
        ));
    }
    // An origin-scope claim inside the payload needs origin provenance too.
    if provenance != "origin" {
        if let Some(Value::Object(payload)) = established(submission, "payload") {
            let claims_current = established(payload, "evidence_scope")
                .and_then(Value::as_str)
                .is_some_and(|scope| scope == "current");
            let claims_origin = established(payload, "origin_assertion")
                .is_some_and(|claim| claim == &Value::Bool(true));
            if claims_current || claims_origin {
                return Err(fault(
                    "provenance_upgrade_refused",
                    format!(
                        "producer {producer_id:?} with provenance {provenance:?} cannot claim current origin scope; imported evidence is never upgraded"
                    ),
                ));
            }
        }
    }

    let record = validate(
        "audit_log",
        serde_json::json!({
            "producer_id": producer_id,
            "owner_domain": owner_domain,
            "role": role,
            "assertion_kind": assertion_kind,
            "provenance": provenance,
            "event_kind": event_kind,
            "manifest_digest": binding,
        }),
    )?;
    Ok(Grant { record })
}

// ---------------------------------------------------------------------------
// Connector authorization (S01 intake)
// ---------------------------------------------------------------------------

/// Authorize a connector request under an authenticated channel registration.
///
/// The principal supplies only its authenticated `principal_id` plus the
/// `registration_digest` binding it to these exact registration bytes. The
/// verb must be one of the nine connector verbs and be granted to the
/// principal along with the connector; control verbs additionally require an
/// explicit control grant. Caller-supplied identity, grants, credentials,
/// digests, and HTTP outcomes never confer authority.
///
/// Faults: `invalid_request`, `spoofed_authority_field`, `invalid_principal`,
/// `unknown_principal`, `invalid_registration`, `missing_registry`,
/// `missing_registration_binding`, `invalid_expected_digest`,
/// `digest_mismatch`, `unregistered_principal`, `missing_verb`,
/// `unknown_verb`, `verb_not_granted`, `missing_connector`,
/// `connector_not_granted`, `invalid_subject`, `control_not_granted`,
/// `missing_owner_domain`, `invalid_registration`.
pub fn authorize(
    principal: &CheckedRecord,
    request: &CheckedRecord,
    registration: &CheckedRecord,
) -> Result<Grant, Fault> {
    let request = as_object(request, "invalid_request", "request")?;
    reject_forbidden(request, REQUEST_FORBIDDEN)?;

    let principal = as_object(principal, "invalid_principal", "principal")?;
    let principal_id = required_str(principal, "principal_id", "unknown_principal", "principal")?;

    let registration_map = as_object(registration, "invalid_registration", "registration")?;
    let principals = match established(registration_map, "principals") {
        Some(Value::Array(entries)) => entries,
        _ => {
            return Err(fault(
                "missing_registry",
                "registration requires an established principals array".to_string(),
            ))
        }
    };

    let binding = required_str(
        principal,
        "registration_digest",
        "missing_registration_binding",
        "principal",
    )?;
    verify_record_digest(registration, binding)?;

    let entry = find_entry(principals, "principal_id", principal_id).ok_or_else(|| {
        fault(
            "unregistered_principal",
            format!("principal {principal_id:?} is not registered on the channel"),
        )
    })?;

    let verb = required_str(request, "verb", "missing_verb", "request")?;
    if !VERBS.contains(&verb) {
        return Err(fault(
            "unknown_verb",
            format!("verb {verb:?} is not one of the nine connector verbs"),
        ));
    }
    let granted_verbs = match established(entry, "verbs") {
        Some(Value::Array(values)) => values,
        _ => {
            return Err(fault(
                "invalid_registration",
                format!("registration entry for principal {principal_id:?} has no established verbs"),
            ))
        }
    };
    if !granted_verbs
        .iter()
        .filter_map(Value::as_str)
        .any(|granted| granted == verb)
    {
        return Err(fault(
            "verb_not_granted",
            format!("verb {verb:?} is not granted to principal {principal_id:?}"),
        ));
    }

    let connector = required_str(request, "connector", "missing_connector", "request")?;
    let granted_connectors = match established(entry, "connectors") {
        Some(Value::Array(values)) => values,
        _ => {
            return Err(fault(
                "invalid_registration",
                format!(
                    "registration entry for principal {principal_id:?} has no established connectors"
                ),
            ))
        }
    };
    if !granted_connectors
        .iter()
        .filter_map(Value::as_str)
        .any(|granted| granted == connector)
    {
        return Err(fault(
            "connector_not_granted",
            format!("connector {connector:?} is not granted to principal {principal_id:?}"),
        ));
    }

    let subject = match established(request, "subject") {
        None => None,
        Some(Value::String(text)) if !text.is_empty() => Some(text.as_str()),
        Some(_) => {
            return Err(fault(
                "invalid_subject",
                "request subject must be a nonempty string when established".to_string(),
            ))
        }
    };

    // Control verbs need an explicit control grant. Application credentials,
    // bearer tokens, digests, and HTTP outcomes carried in the request are
    // never consulted here and cannot satisfy this check.
    let control_granted = established(entry, "control").is_some_and(|flag| flag == &Value::Bool(true));
    if CONTROL_VERBS.contains(&verb) && !control_granted {
        return Err(fault(
            "control_not_granted",
            format!(
                "control verb {verb:?} requires an explicit control grant for principal {principal_id:?}; credentials, digests, and identifiers are not control authority"
            ),
        ));
    }

    let owner_domain = match established(entry, "owner_domain") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        _ => {
            return Err(fault(
                "missing_owner_domain",
                format!("registration entry for principal {principal_id:?} has no established owner_domain"),
            ))
        }
    };
    let restricted_access = match established(entry, "restricted_access") {
        None => false,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => {
            return Err(fault(
                "invalid_registration",
                format!(
                    "registration entry for principal {principal_id:?} has a non-boolean restricted_access"
                ),
            ))
        }
    };

    let mut grant = serde_json::json!({
        "principal_id": principal_id,
        "verb": verb,
        "connector": connector,
        "control": control_granted,
        "owner_domain": owner_domain,
        "restricted_access": restricted_access,
        "registration_digest": binding,
    });
    if let Some(subject) = subject {
        grant["subject"] = Value::String(subject.to_string());
    }
    Ok(Grant {
        record: validate("audit_log", grant)?,
    })
}

// ---------------------------------------------------------------------------
// Reference authorization (artifact/evidence exercise)
// ---------------------------------------------------------------------------

/// Exercise an artifact/evidence reference under a grant.
///
/// The reference must name this grant's digest: a digest or identifier alone
/// is never bearer authority. Publication must stay inside the grant's owner
/// domain, restricted access requires an explicit grant flag, and imported
/// (non-origin) evidence can never be published as owner-authored content or
/// asserted as an origin fact.
///
/// Faults: `unknown_operation`, `invalid_reference`, `missing_grant_binding`,
/// `invalid_grant_binding`, `invalid_expected_digest`, `digest_mismatch`,
/// `missing_digest`, `invalid_digest`, `invalid_access`, `missing_owner_domain`,
/// `missing_provenance`, `grant_without_owner`, `owner_mismatch`,
/// `access_denied`, `provenance_upgrade_refused`.
pub fn authorize_reference(
    grant: &Grant,
    reference: &CheckedRecord,
    operation: &str,
) -> Result<(), Fault> {
    if !OPERATIONS.contains(&operation) {
        return Err(fault(
            "unknown_operation",
            format!("operation {operation:?} is not one of read, collect, publish, or assert_origin"),
        ));
    }

    let reference = as_object(reference, "invalid_reference", "reference")?;

    let binding = match established(reference, "grant_digest") {
        Some(Value::String(text)) if !text.is_empty() => text.as_str(),
        Some(_) => {
            return Err(fault(
                "invalid_grant_binding",
                "reference grant_digest must be a nonempty string".to_string(),
            ))
        }
        None => {
            return Err(fault(
                "missing_grant_binding",
                "reference must name the grant digest it is exercised under; a digest alone is not bearer authority"
                    .to_string(),
            ))
        }
    };
    verify_record_digest(&grant.record, binding)?;

    match established(reference, "digest") {
        Some(Value::String(text)) if is_digest_text(text) => {}
        Some(_) => {
            return Err(fault(
                "invalid_digest",
                "reference digest must be 64 lowercase hex characters".to_string(),
            ))
        }
        None => {
            return Err(fault(
                "missing_digest",
                "reference requires an established digest".to_string(),
            ))
        }
    }
    let access = match established(reference, "access") {
        Some(Value::String(text)) if text == "public" || text == "restricted" => text.as_str(),
        _ => {
            return Err(fault(
                "invalid_access",
                "reference requires an established access of public or restricted".to_string(),
            ))
        }
    };
    let owner_domain = required_str(reference, "owner_domain", "missing_owner_domain", "reference")?;
    let provenance = required_str(reference, "provenance", "missing_provenance", "reference")?;

    let grant_map = as_object(&grant.record, "invalid_reference", "grant")?;
    match operation {
        "read" | "collect" => {
            if access == "restricted"
                && !established(grant_map, "restricted_access")
                    .is_some_and(|flag| flag == &Value::Bool(true))
            {
                return Err(fault(
                    "access_denied",
                    "restricted references require an explicit restricted_access grant".to_string(),
                ));
            }
            Ok(())
        }
        "publish" => {
            let grant_owner = match established(grant_map, "owner_domain") {
                Some(Value::String(text)) if !text.is_empty() => text.as_str(),
                _ => {
                    return Err(fault(
                        "grant_without_owner",
                        "grant carries no owner domain to publish under".to_string(),
                    ))
                }
            };
            if grant_owner != owner_domain {
                return Err(fault(
                    "owner_mismatch",
                    format!(
                        "reference owner {owner_domain:?} is outside the grant owner domain {grant_owner:?}"
                    ),
                ));
            }
            if provenance != "origin" {
                return Err(fault(
                    "provenance_upgrade_refused",
                    format!(
                        "reference with provenance {provenance:?} cannot be published as owner-authored content; imported evidence is never upgraded"
                    ),
                ));
            }
            Ok(())
        }
        "assert_origin" => {
            if provenance != "origin" {
                return Err(fault(
                    "provenance_upgrade_refused",
                    format!(
                        "reference with provenance {provenance:?} cannot be asserted as an origin fact; imported evidence is never upgraded"
                    ),
                ));
            }
            Ok(())
        }
        _ => unreachable!("operation vocabulary checked above"),
    }
}
