//! `crawler_artifacts`: immutable content-addressed artifact bytes.
//!
//! Citable artifacts are immutable, content-addressed, access-classified,
//! and registered by journal events. Bytes are installed durably before
//! any reference is issued; a digest alone is never bearer authority and
//! never a mutable locator.
//!
//! - [`ArtifactStore::install`] persists bytes under `artifact-sha256/1`
//!   ([`digest_bytes`]) and returns an [`ArtifactReference`]-shaped
//!   [`CheckedRecord`] (`digest`, `size_bytes`, `media_type`,
//!   `owner_domain`, `access`, plus `provenance` and `grant_digest` for
//!   [`authorize_reference`]). Reinstalling identical bytes with identical
//!   metadata is idempotent (a fresh binding to the installing grant);
//!   different bytes or different metadata under an existing digest fail
//!   rather than mutate.
//! - [`ArtifactStore::read`] authorizes via
//!   [`authorize_reference`] (`read`), then verifies the full size and
//!   digest against stored bytes plus media/owner/access/provenance
//!   agreement. Missing bytes are an integrity incident
//!   (`bytes_unavailable`); the known digest is preserved, never erased
//!   or refabricated.
//! - [`ArtifactStore::delete`] removes bytes only under an authorized,
//!   current, concurrency-fenced GC certificate bound to the same grant
//!   and digest with `decision: collect`.
//! - [`collect_artifacts`] inventories or transfers already produced,
//!   authorized, immutable artifacts. Names and digests resolve only
//!   within the supplied handle inventory; arbitrary caller URLs or
//!   filesystem paths are refused and workflow work is never rerun.

use crawler_authority::{authorize_reference, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::RwLock;

/// Structural envelope for records produced by this module.
const OUTPUT_SCHEMA: &str = "audit_log";

/// Caller locator fields that must never be resolved through
/// [`collect_artifacts`].
const FORBIDDEN_LOCATORS: &[&str] = &[
    "url",
    "urls",
    "path",
    "paths",
    "filesystem_path",
    "filesystem_paths",
    "file_path",
    "local_path",
    "uri",
    "uris",
    "location",
    "href",
    "hrefs",
    "fetch_url",
];

/// Immutable artifact bytes with their registered metadata.
#[derive(Debug, Clone)]
struct StoredArtifact {
    bytes: Vec<u8>,
    media_type: String,
    size_bytes: u64,
    owner_domain: String,
    access: String,
    provenance: String,
}

/// In-memory [`ArtifactStore`].
///
/// Durability here is process-local (the map is written before any
/// reference is returned); production deployments back the same trait
/// with a durable extent store. Immutability, authorization, and
/// verification semantics are identical.
#[derive(Debug, Default)]
pub struct MemoryArtifactStore {
    inner: RwLock<HashMap<String, StoredArtifact>>,
}

impl MemoryArtifactStore {
    /// Empty store.
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

/// Immutable content-addressed byte store.
pub trait ArtifactStore: Send + Sync {
    /// Durably install `bytes` and return their content-addressed reference.
    fn install(
        &self,
        grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        restricted: bool,
    ) -> Result<CheckedRecord, Fault>;
    /// Return a copy of the bytes named by `reference` after authorization
    /// and full size/digest verification.
    fn read(&self, grant: &Grant, reference: &CheckedRecord) -> Result<Vec<u8>, Fault>;
    /// Delete the bytes named by `reference` under a fenced GC certificate.
    fn delete(
        &self,
        grant: &Grant,
        reference: &CheckedRecord,
        gc_certificate: &CheckedRecord,
    ) -> Result<(), Fault>;
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

/// Digest binding a reference/certificate to the exact bytes of `grant`.
fn binding_of(grant: &Grant) -> Result<String, Fault> {
    Ok(digest_bytes(&canonical_bytes(grant_record(grant))?))
}

fn missing_envelope(reason: &str, detail: &str) -> Value {
    serde_json::json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn lock_read(
    store: &MemoryArtifactStore,
) -> Result<std::sync::RwLockReadGuard<'_, HashMap<String, StoredArtifact>>, Fault> {
    store.inner.read().map_err(|_| {
        fault(
            "internal_error",
            "artifact store lock poisoned".to_string(),
        )
    })
}

fn lock_write(
    store: &MemoryArtifactStore,
) -> Result<std::sync::RwLockWriteGuard<'_, HashMap<String, StoredArtifact>>, Fault> {
    store.inner.write().map_err(|_| {
        fault(
            "internal_error",
            "artifact store lock poisoned".to_string(),
        )
    })
}

fn grant_owner_and_provenance(grant: &Grant) -> Result<(String, String), Fault> {
    let map = as_object(grant_record(grant), "invalid_grant", "grant")?;
    let owner = match established(map, "owner_domain") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => {
            return Err(fault(
                "grant_without_owner",
                "grant carries no established owner_domain to register artifacts under"
                    .to_string(),
            ))
        }
    };
    let provenance = match established(map, "provenance") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        // Connector grants carry no provenance; connector-authorized
        // artifacts are owner-authored origin content.
        _ => "origin".to_string(),
    };
    Ok((owner, provenance))
}

struct ParsedReference {
    digest: String,
    size_bytes: u64,
    media_type: String,
    owner_domain: String,
    access: String,
    provenance: String,
}

/// Extract the artifact identity fields from an authorized reference.
/// Authorization itself (binding, digest shape, access vocabulary,
/// owner/provenance presence, restricted flag) is enforced by
/// [`authorize_reference`]; here we only extract the remaining
/// established fields the store must verify.
fn parse_reference(map: &Map<String, Value>) -> Result<ParsedReference, Fault> {
    let digest = match established(map, "digest") {
        Some(Value::String(text)) if is_digest_text(text) => text.clone(),
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires an established 64 lowercase hex digest".to_string(),
            ))
        }
    };
    let size_bytes = match established(map, "size_bytes") {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
            fault(
                "invalid_reference",
                "reference size_bytes must be an unsigned integer".to_string(),
            )
        })?,
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires an established size_bytes".to_string(),
            ))
        }
    };
    let media_type = match established(map, "media_type") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires an established nonempty media_type".to_string(),
            ))
        }
    };
    let owner_domain = match established(map, "owner_domain") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires an established owner_domain".to_string(),
            ))
        }
    };
    let access = match established(map, "access") {
        Some(Value::String(text)) if text == "public" || text == "restricted" => text.clone(),
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires access of public or restricted".to_string(),
            ))
        }
    };
    let provenance = match established(map, "provenance") {
        Some(Value::String(text)) if !text.is_empty() => text.clone(),
        _ => {
            return Err(fault(
                "invalid_reference",
                "reference requires an established provenance".to_string(),
            ))
        }
    };
    Ok(ParsedReference {
        digest,
        size_bytes,
        media_type,
        owner_domain,
        access,
        provenance,
    })
}

/// Verify stored bytes against a parsed reference: full digest, full
/// size, and immutable metadata agreement. Downgrading a restricted
/// artifact to public is refused explicitly.
fn verify_stored(stored: &StoredArtifact, parsed: &ParsedReference) -> Result<(), Fault> {
    if digest_bytes(&stored.bytes) != parsed.digest {
        return Err(fault(
            "digest_mismatch",
            "stored bytes do not match the reference digest; integrity incident, bytes are not refabricated"
                .to_string(),
        ));
    }
    if stored.bytes.len() as u64 != parsed.size_bytes || stored.size_bytes != parsed.size_bytes {
        return Err(fault(
            "size_mismatch",
            format!(
                "reference size_bytes {} does not match stored size {}",
                parsed.size_bytes,
                stored.bytes.len()
            ),
        ));
    }
    if stored.media_type != parsed.media_type {
        return Err(fault(
            "metadata_mismatch",
            format!(
                "reference media_type {:?} does not match stored {:?}; artifact metadata is immutable",
                parsed.media_type, stored.media_type
            ),
        ));
    }
    if stored.owner_domain != parsed.owner_domain {
        return Err(fault(
            "metadata_mismatch",
            format!(
                "reference owner {:?} does not match stored {:?}; artifact metadata is immutable",
                parsed.owner_domain, stored.owner_domain
            ),
        ));
    }
    if stored.provenance != parsed.provenance {
        return Err(fault(
            "metadata_mismatch",
            format!(
                "reference provenance {:?} does not match stored {:?}; artifact metadata is immutable",
                parsed.provenance, stored.provenance
            ),
        ));
    }
    if stored.access != parsed.access {
        if stored.access == "restricted" && parsed.access == "public" {
            return Err(fault(
                "access_downgrade_refused",
                "restricted artifact cannot be referenced as public; access classification never downgrades"
                    .to_string(),
            ));
        }
        return Err(fault(
            "metadata_mismatch",
            format!(
                "reference access {:?} does not match stored {:?}; artifact metadata is immutable",
                parsed.access, stored.access
            ),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ArtifactStore implementation
// ---------------------------------------------------------------------------

impl ArtifactStore for MemoryArtifactStore {
    fn install(
        &self,
        grant: &Grant,
        bytes: &[u8],
        media_type: &str,
        restricted: bool,
    ) -> Result<CheckedRecord, Fault> {
        if media_type.is_empty() || media_type.contains('\0') {
            return Err(fault(
                "invalid_media_type",
                "media_type must be a nonempty string with no in-band nulls".to_string(),
            ));
        }
        let (owner_domain, provenance) = grant_owner_and_provenance(grant)?;
        let digest = digest_bytes(bytes);
        let size_bytes = bytes.len() as u64;
        let access = if restricted { "restricted" } else { "public" };
        let binding = binding_of(grant)?;

        {
            let mut guard = lock_write(self)?;
            if let Some(stored) = guard.get(&digest) {
                if stored.bytes.as_slice() != bytes {
                    return Err(fault(
                        "integrity_conflict",
                        "different bytes under an existing digest; artifacts are immutable and bytes are never replaced"
                            .to_string(),
                    ));
                }
                if stored.media_type != media_type
                    || stored.access != access
                    || stored.owner_domain != owner_domain
                    || stored.provenance != provenance
                {
                    return Err(fault(
                        "immutable_conflict",
                        "artifact metadata under an existing digest is immutable; reinstall with identical media_type, access, owner, and provenance"
                            .to_string(),
                    ));
                }
            } else {
                guard.insert(
                    digest.clone(),
                    StoredArtifact {
                        bytes: bytes.to_vec(),
                        media_type: media_type.to_string(),
                        size_bytes,
                        owner_domain: owner_domain.clone(),
                        access: access.to_string(),
                        provenance: provenance.clone(),
                    },
                );
            }
        }

        // Bytes are durably installed above; only now is the reference
        // registered.
        validate(
            OUTPUT_SCHEMA,
            serde_json::json!({
                "digest": digest,
                "size_bytes": size_bytes,
                "media_type": media_type,
                "owner_domain": owner_domain,
                "access": access,
                "provenance": provenance,
                "grant_digest": binding,
            }),
        )
    }

    fn read(&self, grant: &Grant, reference: &CheckedRecord) -> Result<Vec<u8>, Fault> {
        authorize_reference(grant, reference, "read")?;
        let map = as_object(reference, "invalid_reference", "reference")?;
        let parsed = parse_reference(map)?;
        let guard = lock_read(self)?;
        let stored = guard.get(&parsed.digest).ok_or_else(|| {
            fault(
                "bytes_unavailable",
                format!(
                    "no bytes for known digest {}; digest is preserved, retrieval never reruns acquisition or fabricates content",
                    parsed.digest
                ),
            )
        })?;
        verify_stored(stored, &parsed)?;
        Ok(stored.bytes.clone())
    }

    fn delete(
        &self,
        grant: &Grant,
        reference: &CheckedRecord,
        gc_certificate: &CheckedRecord,
    ) -> Result<(), Fault> {
        // GC collects already produced artifacts; authorize as a collect.
        authorize_reference(grant, reference, "collect")?;
        let map = as_object(reference, "invalid_reference", "reference")?;
        let parsed = parse_reference(map)?;
        let cert = as_object(gc_certificate, "invalid_gc_certificate", "gc_certificate")?;

        match established(cert, "digest") {
            Some(Value::String(text)) if *text == parsed.digest => {}
            _ => {
                return Err(fault(
                    "invalid_gc_certificate",
                    "gc certificate must name the reference digest it authorizes".to_string(),
                ))
            }
        }
        let binding = binding_of(grant)?;
        match established(cert, "grant_digest") {
            Some(Value::String(text)) if *text == binding => {}
            _ => {
                return Err(fault(
                    "invalid_gc_certificate",
                    "gc certificate is not authorized under this grant; a certificate alone is not bearer authority"
                        .to_string(),
                ))
            }
        }
        match established(cert, "owner_domain") {
            Some(Value::String(text)) if *text == parsed.owner_domain => {}
            _ => {
                return Err(fault(
                    "invalid_gc_certificate",
                    "gc certificate owner must match the reference owner domain".to_string(),
                ))
            }
        }
        match established(cert, "fence") {
            Some(Value::String(text)) if !text.is_empty() => {}
            _ => {
                return Err(fault(
                    "gc_fence_required",
                    "gc certificate requires an established concurrency fence; unfenced collection races with pin creation"
                        .to_string(),
                ))
            }
        }
        match established(cert, "decision") {
            Some(Value::String(text)) if text == "collect" => {}
            _ => {
                return Err(fault(
                    "gc_decision_required",
                    "gc certificate decision must be collect; TTL, cache eviction, and newer rows never authorize deletion"
                        .to_string(),
                ))
            }
        }

        let mut guard = lock_write(self)?;
        let stored = guard.get(&parsed.digest).ok_or_else(|| {
            fault(
                "bytes_unavailable",
                format!(
                    "no bytes for known digest {}; lost bytes are an integrity incident, not successful GC",
                    parsed.digest
                ),
            )
        })?;
        verify_stored(stored, &parsed)?;
        guard.remove(&parsed.digest);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CollectArtifacts
// ---------------------------------------------------------------------------

/// Reject any established caller locator field in `map`.
fn reject_locators(map: &Map<String, Value>) -> Result<(), Fault> {
    for field in FORBIDDEN_LOCATORS {
        if established(map, field).is_some() {
            return Err(fault(
                "arbitrary_locator_refused",
                format!(
                    "field {field:?} names an arbitrary caller URL or filesystem path; CollectArtifacts resolves only digests already registered in the authorized handle inventory"
                ),
            ));
        }
    }
    Ok(())
}

struct InventorySlot {
    name: String,
    /// Raw slot value, preserved for Missing slots.
    raw: Value,
    /// Established content object, if the slot is available.
    content: Option<Map<String, Value>>,
    /// Established expected digest text, if any.
    expected_digest: Option<String>,
}

fn parse_inventory(inventory: &CheckedRecord) -> Result<Vec<InventorySlot>, Fault> {
    let map = as_object(inventory, "invalid_inventory", "inventory")?;
    let artifacts = match established(map, "artifacts") {
        Some(Value::Array(items)) => items,
        _ => {
            return Err(fault(
                "missing_inventory",
                "inventory requires an established artifacts array".to_string(),
            ))
        }
    };
    let mut slots = Vec::with_capacity(artifacts.len());
    let mut names = std::collections::HashSet::new();
    for (index, slot) in artifacts.iter().enumerate() {
        let slot_map = slot.as_object().ok_or_else(|| {
            fault(
                "invalid_inventory",
                format!("inventory slot {index} must be an object"),
            )
        })?;
        let name = match established(slot_map, "name") {
            Some(Value::String(text)) if !text.is_empty() => text.clone(),
            _ => {
                return Err(fault(
                    "invalid_inventory",
                    format!("inventory slot {index} requires an established nonempty name"),
                ))
            }
        };
        if !names.insert(name.clone()) {
            return Err(fault(
                "invalid_inventory",
                format!("duplicate inventory name {name:?}; names are unique"),
            ));
        }
        // Slots must never smuggle caller locators.
        reject_locators(slot_map)?;
        let content_value = slot_map.get("content").ok_or_else(|| {
            fault(
                "invalid_inventory",
                format!("inventory slot {name:?} requires content or reasoned Missing"),
            )
        })?;
        let content = if is_missing(content_value) {
            None
        } else if let Some(obj) = content_value.as_object() {
            reject_locators(obj)?;
            Some(obj.clone())
        } else {
            return Err(fault(
                "invalid_inventory",
                format!(
                    "inventory slot {name:?} content must be an artifact reference or Missing"
                ),
            ));
        };
        let expected_digest = match slot_map.get("expected_digest") {
            None => None,
            Some(value) if is_missing(value) => None,
            Some(Value::String(text)) if is_digest_text(text) => Some(text.clone()),
            Some(Value::String(_)) => {
                return Err(fault(
                    "invalid_inventory",
                    format!("inventory slot {name:?} expected_digest must be a digest or Missing"),
                ))
            }
            Some(_) => {
                return Err(fault(
                    "invalid_inventory",
                    format!("inventory slot {name:?} expected_digest must be a digest or Missing"),
                ))
            }
        };
        if let (Some(expected), Some(content)) = (expected_digest.as_ref(), content.as_ref()) {
            if let Some(Value::String(actual)) = content.get("digest").filter(|v| !is_missing(v)) {
                if actual != expected {
                    return Err(fault(
                        "digest_conflict",
                        format!(
                            "inventory slot {name:?} expected_digest does not equal content.digest"
                        ),
                    ));
                }
            }
        }
        slots.push(InventorySlot {
            name,
            raw: slot.clone(),
            content,
            expected_digest,
        });
    }
    Ok(slots)
}

/// Bind an inventory content object to `grant` (injecting `grant_digest`
/// when the inventory carries a bare reference) and validate it.
fn bind_content(
    content: &Map<String, Value>,
    grant_binding: &str,
) -> Result<CheckedRecord, Fault> {
    let mut bound = content.clone();
    match bound.get("grant_digest") {
        Some(value) if !is_missing(value) => {}
        _ => {
            bound.insert(
                "grant_digest".to_string(),
                Value::String(grant_binding.to_string()),
            );
        }
    }
    validate(OUTPUT_SCHEMA, Value::Object(bound))
}

/// Verify one available slot: authorize a collect, then read and verify
/// the full bytes. Returns the verified slot value to emit, or `None`
/// when the slot degrades to reasoned Missing (restricted without a
/// grant flag, or bytes unavailable with the known digest preserved).
fn verify_slot(
    store: &dyn ArtifactStore,
    grant: &Grant,
    grant_binding: &str,
    slot: &InventorySlot,
    content: &Map<String, Value>,
    missing_on_denied: bool,
) -> Result<Option<Value>, Fault> {
    let record = bind_content(content, grant_binding).map_err(|err| {
        fault(
            "invalid_inventory",
            format!("inventory slot {:?} holds an invalid reference: {}", slot.name, err.detail),
        )
    })?;
    match authorize_reference(grant, &record, "collect") {
        Ok(()) => {}
        Err(err) if err.code == "access_denied" && missing_on_denied => {
            let digest = content
                .get("digest")
                .and_then(Value::as_str)
                .unwrap_or_default();
            return Ok(Some(serde_json::json!({
                "name": slot.name,
                "expected_digest": digest,
                "content": missing_envelope("not_applicable", "restricted artifact requires an explicit restricted_access grant; access never downgrades"),
            })));
        }
        Err(err) => return Err(err),
    }
    match store.read(grant, &record) {
        Ok(_) => {
            // Available: emit the bound, verified reference.
            Ok(Some(serde_json::json!({
                "name": slot.name,
                "expected_digest": record_value(&record).get("digest").cloned().unwrap_or(Value::String(String::new())),
                "content": record_value(&record).clone(),
            })))
        }
        Err(err) if err.code == "bytes_unavailable" => {
            let digest = content
                .get("digest")
                .and_then(Value::as_str)
                .unwrap_or_default();
            Ok(Some(serde_json::json!({
                "name": slot.name,
                "expected_digest": digest,
                "content": missing_envelope("observation_lost", "bytes unavailable for a known digest; digest is preserved, content is never refabricated"),
            })))
        }
        Err(err) => Err(err),
    }
}

/// Inventory or transfer already produced authorized immutable artifacts.
///
/// `request` selects `inventory` (`{mode: inventory}`), `named`
/// (`{mode: named, names: [...]}`), or `bytes`
/// (`{mode: bytes, digest, offset, max_bytes}`), either flat or under a
/// `selector` object. `inventory` is the handle's retained evidence
/// (`{artifacts: [ArtifactSlot...]}`).
///
/// Names and digests resolve only within `inventory`. Arbitrary caller
/// URLs or filesystem paths are refused, unknown digests are never
/// fetched, missing bytes degrade to reasoned Missing with the known
/// digest preserved (or `bytes_unavailable` for `bytes` mode), and
/// restricted access never downgrades.
///
/// Faults: `invalid_request`, `missing_mode`, `unknown_mode`,
/// `arbitrary_locator_refused`, `missing_names`, `invalid_names`,
/// `invalid_inventory`, `missing_inventory`, `digest_conflict`,
/// `unknown_artifact`, `bytes_unavailable`, `invalid_offset`,
/// `offset_beyond_eof`, `invalid_max_bytes`, plus authorization and
/// integrity faults from [`authorize_reference`] and
/// [`ArtifactStore::read`].
pub fn collect_artifacts(
    store: &dyn ArtifactStore,
    grant: &Grant,
    request: &CheckedRecord,
    inventory: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let request_map = as_object(request, "invalid_request", "request")?;
    reject_locators(request_map)?;
    // Selector may carry the locator smuggle instead of the top level.
    let selector_map: Option<&Map<String, Value>> = match established(request_map, "selector") {
        Some(Value::Object(sel)) => {
            reject_locators(sel)?;
            Some(sel)
        }
        Some(_) => {
            return Err(fault(
                "invalid_request",
                "request selector must be an object when established".to_string(),
            ))
        }
        None => None,
    };
    // Flat fields win only when no established selector object exists;
    // otherwise the selector is authoritative.
    let active: &Map<String, Value> = selector_map.unwrap_or(request_map);

    let mode = match established(active, "mode") {
        Some(Value::String(text)) => text.as_str(),
        _ => {
            return Err(fault(
                "missing_mode",
                "request requires an established mode of inventory, named, or bytes".to_string(),
            ))
        }
    };
    if mode != "inventory" && mode != "named" && mode != "bytes" {
        return Err(fault(
            "unknown_mode",
            format!("mode {mode:?} is not one of inventory, named, or bytes"),
        ));
    }

    let slots = parse_inventory(inventory)?;
    let grant_binding = binding_of(grant)?;

    match mode {
        "inventory" => {
            let mut emitted = Vec::with_capacity(slots.len());
            for slot in &slots {
                match &slot.content {
                    None => emitted.push(slot.raw.clone()),
                    Some(content) => {
                        match verify_slot(store, grant, &grant_binding, slot, content, true)? {
                            Some(value) => emitted.push(value),
                            None => emitted.push(slot.raw.clone()),
                        }
                    }
                }
            }
            validate(
                OUTPUT_SCHEMA,
                serde_json::json!({
                    "kind": "artifact_inventory",
                    "artifacts": emitted,
                    "coverage": "complete",
                }),
            )
        }
        "named" => {
            let names = match established(active, "names") {
                Some(Value::Array(names)) => names,
                _ => {
                    return Err(fault(
                        "missing_names",
                        "named mode requires an established names array".to_string(),
                    ))
                }
            };
            if names.is_empty() {
                return Err(fault(
                    "invalid_names",
                    "named mode requires at least one name".to_string(),
                ));
            }
            let mut seen = std::collections::HashSet::new();
            let mut requested = Vec::with_capacity(names.len());
            for name in names {
                match name {
                    Value::String(text) if !text.is_empty() => {
                        if !seen.insert(text.clone()) {
                            return Err(fault(
                                "invalid_names",
                                "requested names must be unique".to_string(),
                            ));
                        }
                        requested.push(text.clone());
                    }
                    _ => {
                        return Err(fault(
                            "invalid_names",
                            "every requested name must be a nonempty string".to_string(),
                        ))
                    }
                }
            }
            let mut emitted = Vec::with_capacity(requested.len());
            let mut all_available = true;
            for name in &requested {
                match slots.iter().find(|slot| &slot.name == name) {
                    None => {
                        all_available = false;
                        emitted.push(serde_json::json!({
                            "name": name,
                            "expected_digest": missing_envelope("not_observed", "name is not in the authorized handle inventory; arbitrary names are never fetched"),
                            "content": missing_envelope("not_observed", "name is not in the authorized handle inventory; arbitrary names are never fetched"),
                        }));
                    }
                    Some(slot) => match &slot.content {
                        None => {
                            all_available = false;
                            emitted.push(slot.raw.clone());
                        }
                        Some(content) => {
                            // Explicit requests fail loudly on denied
                            // access; unavailable bytes degrade to
                            // Missing with the digest preserved.
                            match verify_slot(store, grant, &grant_binding, slot, content, false)? {
                                Some(value) => {
                                    let unavailable = value
                                        .get("content")
                                        .is_some_and(is_missing);
                                    if unavailable {
                                        all_available = false;
                                    }
                                    emitted.push(value);
                                }
                                None => {
                                    all_available = false;
                                    emitted.push(slot.raw.clone());
                                }
                            }
                        }
                    },
                }
            }
            validate(
                OUTPUT_SCHEMA,
                serde_json::json!({
                    "kind": "artifact_inventory",
                    "artifacts": emitted,
                    "coverage": if all_available { "complete" } else { "partial" },
                }),
            )
        }
        "bytes" => {
            let digest = match established(active, "digest") {
                Some(Value::String(text)) if is_digest_text(text) => text.clone(),
                _ => {
                    return Err(fault(
                        "invalid_request",
                        "bytes mode requires an established 64 lowercase hex digest".to_string(),
                    ))
                }
            };
            let offset = match established(active, "offset") {
                Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    fault(
                        "invalid_offset",
                        "bytes offset must be an unsigned integer".to_string(),
                    )
                })?,
                _ => {
                    return Err(fault(
                        "invalid_offset",
                        "bytes mode requires an established offset".to_string(),
                    ))
                }
            };
            let max_bytes = match established(active, "max_bytes") {
                Some(Value::Number(n)) => n.as_u64().ok_or_else(|| {
                    fault(
                        "invalid_max_bytes",
                        "bytes max_bytes must be an unsigned integer".to_string(),
                    )
                })?,
                _ => {
                    return Err(fault(
                        "invalid_max_bytes",
                        "bytes mode requires an established max_bytes".to_string(),
                    ))
                }
            };
            if max_bytes == 0 {
                return Err(fault(
                    "invalid_max_bytes",
                    "bytes max_bytes must be positive".to_string(),
                ));
            }
            // The digest must already be registered in the handle
            // inventory; arbitrary digests are never fetched.
            let slot = slots.iter().find(|slot| {
                slot.content.as_ref().is_some_and(|content| {
                    content
                        .get("digest")
                        .and_then(Value::as_str)
                        .is_some_and(|candidate| candidate == digest)
                }) || slot.expected_digest.as_deref() == Some(digest.as_str())
            });
            let slot = slot.ok_or_else(|| {
                fault(
                    "unknown_artifact",
                    "digest is not registered in the authorized handle inventory; arbitrary digests are never fetched"
                        .to_string(),
                )
            })?;
            let content = slot.content.as_ref().ok_or_else(|| {
                fault(
                    "bytes_unavailable",
                    format!(
                        "no bytes for known digest {digest}; digest is preserved, retrieval never reruns acquisition"
                    ),
                )
            })?;
            let record = bind_content(content, &grant_binding).map_err(|err| {
                fault(
                    "invalid_inventory",
                    format!("inventory slot {:?} holds an invalid reference: {}", slot.name, err.detail),
                )
            })?;
            authorize_reference(grant, &record, "collect")?;
            let bytes = store.read(grant, &record)?;
            let size = bytes.len() as u64;
            if offset > size {
                return Err(fault(
                    "offset_beyond_eof",
                    format!("offset {offset} is beyond end of artifact of size {size}"),
                ));
            }
            let end = offset.saturating_add(max_bytes).min(size);
            let chunk = &bytes[offset as usize..end as usize];
            let returned = chunk.len() as u64;
            let chunk_digest = digest_bytes(chunk);
            let data_base64 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, chunk);
            let end_of_artifact = offset + returned == size;
            validate(
                OUTPUT_SCHEMA,
                serde_json::json!({
                    "kind": "artifact_chunk",
                    "digest": digest,
                    "size_bytes": size,
                    "offset": offset,
                    "returned_bytes": returned,
                    "data_base64": data_base64,
                    "chunk_digest": chunk_digest,
                    "end_of_artifact": end_of_artifact,
                }),
            )
        }
        _ => unreachable!("mode vocabulary checked above"),
    }
}
