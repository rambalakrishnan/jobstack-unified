//! `rm_targets`: tier-6 Tier 1 scoped target resolution for Ringmaster.
//!
//! Implements seam mapping §8.1 (`TargetRecipe`) and §10.1 (Tier 1) for
//! conformance case RM-C17 (duplicate labels across frames):
//!
//! - [`resolve_target`] loads a durable [`TargetRecipe`] artifact, validates its
//!   closed shape, observes the *requested* native scope through `bo.dom_read`,
//!   and returns a scoped [`BODomExport`] containing exactly the resolved node.
//! - Resolution is scoped: only nodes whose native root equals the requested
//!   [`BORootRef`] are eligible. Duplicate labels in other frames/roots never
//!   leak into the match set, and a flattened global namespace is never built.
//! - Bounded matches, uniqueness, eligibility, and generation checks run before
//!   return. Zero matches, ambiguity, truncation, or partial/unknown
//!   completeness never yield a first-match guess; they return explicit
//!   `TARGET_NOT_FOUND` / `TARGET_AMBIGUOUS` errors for §10.2 recovery routing.
//! - Strategy mapping follows §10.1: CSS is actual supported native CSS only
//!   (Playwright syntax rejected, unsupported constructs report
//!   `UNSUPPORTED_MAPPING`); text/role/testid are pinned Ringmaster matching
//!   over native observations; XPath requires an established native/V8 mapping
//!   and is otherwise `UNSUPPORTED_MAPPING` (never guessed).
//! - Tier 1 performs zero model calls, no healing, no clicking, no cache-state
//!   writes, and no live-DOM mutation. `fallback_text` and `resolver_policy`
//!   are validated but `fallback_text` is Tier 2 recovery input only and is
//!   never consulted during Tier 1 lookup.
//!
//! Hard rules:
//!
//! - Recipes are durable intent, never live node identities. They resolve anew
//!   in the current generation; stale roots are rejected before matching.
//! - One match from a truncated/partial/unknown collection does not prove
//!   uniqueness.
//! - Playwright syntax (`>>`, `text=`/`xpath=`/`role=` engines, `:has-text()`)
//!   is never interpreted as native CSS.
//! - No in-band nulls; missing fields use typed [`Missing`] envelopes.
//! - No shared-database writes or cross-domain transactions.

#![forbid(unsafe_code)]
#![allow(clippy::result_large_err)]

use serde_json::Value;
use std::collections::BTreeSet;

pub use rm_authority::{AuthenticatedPrincipal, ConnectorError};
pub use rm_browseroxide::{
    BODomExport, BODomNode, BODomRead, BONodeRef, BORootRef, MaybeNodeParent, MaybeRoot,
    NativeSession,
};
pub use rm_catalog::{DurationLimit, VersionPin};
pub use rm_evidence::{ArtifactReference, EvidenceRef, PositiveInteger};
pub use rm_time::{MaybeString, Missing};

// ---------------------------------------------------------------------------
// Dependency signature pins (compile-time CONSUMES check)
// ---------------------------------------------------------------------------

// These aliases fail to compile if an upstream signature drifts, surfacing an
// interface gap at build time instead of silently calling a wrong shape.
#[allow(dead_code)]
const _: fn(
    &mut NativeSession,
    &BODomRead,
    &EvidenceRef,
    &DurationLimit,
) -> Result<rm_browseroxide::BrowserOxideReturn<BODomExport>, ConnectorError> =
    rm_browseroxide::dom_read;
#[allow(dead_code)]
const _: fn(
    &mut NativeSession,
    &rm_browseroxide::BOV8Evaluate,
    &EvidenceRef,
    &DurationLimit,
) -> Result<rm_browseroxide::BrowserOxideReturn<rm_browseroxide::BOV8Return>, ConnectorError> =
    rm_browseroxide::v8_evaluate;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &mut NativeSession,
    &BODomRead,
    &str,
    &VersionPin,
    &EvidenceRef,
    &DurationLimit,
) -> Result<ArtifactReference, ConnectorError> = rm_reduction::reduce_document;
#[allow(dead_code)]
const _: fn(
    &AuthenticatedPrincipal,
    &str,
    &str,
) -> Result<rm_authority::ProducerDescriptor, ConnectorError> =
    rm_authority::authorize_owner;
#[allow(dead_code)]
const _: fn(&AuthenticatedPrincipal, &ArtifactReference) -> Result<Vec<u8>, ConnectorError> =
    rm_evidence::load_artifact;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// DOM export discriminator (must match the native binding).
pub const DOM_EXPORT_RECORD_TYPE: &str = "browseroxide_dom_export";
/// DOM export schema version (must match the native binding).
pub const DOM_EXPORT_SCHEMA_VERSION: &str = "internal-browser-binding.browseroxide/0.1.0";

/// Supported Tier 1 strategies (§10.1).
pub const STRATEGIES: [&str; 5] = ["css", "xpath", "text", "role", "testid"];
/// Permitted root kinds (§5.1).
pub const ROOT_KINDS: [&str; 3] = ["document", "open_shadow", "closed_shadow"];
/// Completeness values (§9.1).
pub const COMPLETENESS_VALUES: [&str; 3] = ["complete", "partial", "unknown"];
/// Boundary kinds (§9.1).
pub const BOUNDARY_KINDS: [&str; 3] = ["frame", "open_shadow", "closed_shadow"];
/// Boundary access values (§9.1).
pub const ACCESS_VALUES: [&str; 4] = ["complete", "partial", "unavailable", "unobserved"];

/// Largest exactly representable integer (§3.1).
pub const MAX_SAFE_INTEGER: u64 = rm_evidence::MAX_SAFE_INTEGER;

/// Native read depth bound for scoped Tier 1 observations.
const READ_DEPTH_LIMIT: u64 = 100;
/// Native read byte bound for scoped Tier 1 observations.
const READ_BYTE_LIMIT: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Connector errors (§17 envelope)
// ---------------------------------------------------------------------------

fn connector_error(code: &str, fault_domain: &str, detail: impl Into<String>) -> ConnectorError {
    ConnectorError {
        kind: "connector_error".to_string(),
        code: code.to_string(),
        fault_domain: fault_domain.to_string(),
        detail: detail.into(),
        operation_delivery: "not_applicable".to_string(),
        retry_guidance: "operator_review".to_string(),
        retry_after: None,
        handle: None,
        evidence_refs: Vec::new(),
    }
}

fn invalid(detail: impl Into<String>) -> ConnectorError {
    connector_error("INVALID_REQUEST", "request", detail)
}

fn unsupported_mapping(detail: impl Into<String>) -> ConnectorError {
    connector_error("UNSUPPORTED_MAPPING", "connector", detail)
}

fn target_not_found(detail: impl Into<String>) -> ConnectorError {
    connector_error("TARGET_NOT_FOUND", "connector", detail)
}

fn target_ambiguous(detail: impl Into<String>) -> ConnectorError {
    connector_error("TARGET_AMBIGUOUS", "connector", detail)
}

fn stale_reference(detail: impl Into<String>) -> ConnectorError {
    connector_error("STALE_REFERENCE", "connector", detail)
}

fn prerequisite(detail: impl Into<String>) -> ConnectorError {
    connector_error("PREREQUISITE_UNAVAILABLE", "connector", detail)
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be nonempty")));
    }
    Ok(())
}

fn require_identifier(field: &str, value: &str) -> Result<(), ConnectorError> {
    if value.is_empty() {
        return Err(invalid(format!("{field} must be a nonempty identifier")));
    }
    Ok(())
}

fn require_enum(field: &str, value: &str, allowed: &[&str]) -> Result<(), ConnectorError> {
    if !allowed.contains(&value) {
        return Err(invalid(format!(
            "{field} {value:?} must be one of {allowed:?}"
        )));
    }
    Ok(())
}

fn validate_missing(missing: &Missing, what: &str) -> Result<(), ConnectorError> {
    if !rm_time::is_valid_reason(&missing.reason) {
        return Err(invalid(format!(
            "{what} missing reason {:?} is not one of the six kernel reasons",
            missing.reason
        )));
    }
    if let Some(detail) = &missing.detail {
        if detail.is_empty() {
            return Err(invalid(format!("{what} missing detail must be nonempty")));
        }
    }
    Ok(())
}

fn validate_version_pin(pin: &VersionPin, what: &str) -> Result<(), ConnectorError> {
    require_identifier(&format!("{what} id"), &pin.id)?;
    require_identifier(&format!("{what} version"), &pin.version)?;
    if !rm_wire::is_valid_digest(pin.artifact_digest.as_str()) {
        return Err(invalid(format!(
            "{what} artifact_digest {:?} is not a sha256 digest",
            pin.artifact_digest.as_str()
        )));
    }
    Ok(())
}

fn validate_duration_limit(limit: &DurationLimit, what: &str) -> Result<(), ConnectorError> {
    if limit.kind != "exact" {
        return Err(invalid(format!(
            "{what} kind {:?} must be \"exact\"",
            limit.kind
        )));
    }
    if limit.unit != "ms" {
        return Err(invalid(format!(
            "{what} unit {:?} must be \"ms\"",
            limit.unit
        )));
    }
    if !limit.value.is_finite() || limit.value < 0.0 {
        return Err(invalid(format!(
            "{what} value must be a finite nonnegative number"
        )));
    }
    Ok(())
}

fn validate_root(root: &BORootRef, what: &str) -> Result<(), ConnectorError> {
    require_nonempty(&format!("{what} page.page_id"), &root.page.page_id)?;
    require_nonempty(
        &format!("{what} page.owner.process_id"),
        &root.page.owner.process_id,
    )?;
    require_nonempty(
        &format!("{what} page.owner.boot_id"),
        &root.page.owner.boot_id,
    )?;
    require_nonempty(
        &format!("{what} page.owner.os_thread_id"),
        &root.page.owner.os_thread_id,
    )?;
    if root.page.page_generation > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{what} page.page_generation exceeds {MAX_SAFE_INTEGER}"
        )));
    }
    if !rm_wire::is_valid_digest(root.page.profile_digest.as_str()) {
        return Err(invalid(format!(
            "{what} page.profile_digest {:?} is not a sha256 digest",
            root.page.profile_digest.as_str()
        )));
    }
    require_nonempty(&format!("{what} frame_id"), &root.frame_id)?;
    if root.document_generation > MAX_SAFE_INTEGER {
        return Err(invalid(format!(
            "{what} document_generation exceeds {MAX_SAFE_INTEGER}"
        )));
    }
    require_nonempty(&format!("{what} root_id"), &root.root_id)?;
    require_enum(&format!("{what} root_kind"), &root.root_kind, &ROOT_KINDS)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// TargetRecipe (§8.1)
// ---------------------------------------------------------------------------

/// Durable Tier 1 target intent (§8.1).
///
/// Closed object with exactly the eight §8.1 fields. Recipes name intent, not
/// live node identities; they resolve anew in the current generation against
/// the requested native root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRecipe {
    /// Ordered native frame-mount query strings (empty = current frame).
    pub frame_path: Vec<String>,
    /// Ordered native shadow-host query strings (empty = current root).
    pub shadow_path: Vec<String>,
    /// One of `css | xpath | text | role | testid`.
    pub strategy: String,
    /// Nonempty strategy query.
    pub query: String,
    /// Pinned exactness flag (strategy-specific semantics, see matchers).
    pub exact: bool,
    /// Positive bound on the collected match set.
    pub max_matches: u64,
    /// Tier 2 recovery input only; never consulted during Tier 1 lookup.
    pub fallback_text: MaybeString,
    /// Pinned resolver policy.
    pub resolver_policy: VersionPin,
}

impl TargetRecipe {
    /// Closed-object JSON projection (for artifact construction/debugging).
    pub fn to_json(&self) -> Value {
        let fallback = match &self.fallback_text {
            MaybeString::Text(text) => Value::String(text.clone()),
            MaybeString::Missing(missing) => {
                serde_json::to_value(missing).unwrap_or(Value::Null)
            }
        };
        serde_json::json!({
            "frame_path": self.frame_path,
            "shadow_path": self.shadow_path,
            "strategy": self.strategy,
            "query": self.query,
            "exact": self.exact,
            "max_matches": self.max_matches,
            "fallback_text": fallback,
            "resolver_policy": self.resolver_policy.to_json(),
        })
    }
}

/// Parses and validates closed `TargetRecipe` bytes.
///
/// Rejects duplicate mapping keys, non-finite numbers, bare nulls (via the
/// wire canonicalizer), undeclared fields, missing fields, and malformed
/// field values. `fallback_text` accepts a nonempty string or a reasoned
/// [`Missing`] envelope.
pub fn parse_target_recipe(bytes: &[u8]) -> Result<TargetRecipe, ConnectorError> {
    rm_wire::canonical_digest(bytes)
        .map_err(|error| invalid(format!("recipe bytes rejected: {error}")))?;
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid(format!("recipe bytes are not JSON: {error}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("recipe must be a JSON object"))?;
    const ALLOWED: [&str; 8] = [
        "frame_path",
        "shadow_path",
        "strategy",
        "query",
        "exact",
        "max_matches",
        "fallback_text",
        "resolver_policy",
    ];
    for key in object.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(invalid(format!(
                "recipe has undeclared field {key:?}; the recipe is closed"
            )));
        }
    }
    for field in ALLOWED {
        if !object.contains_key(field) {
            return Err(invalid(format!(
                "recipe is missing required field {field:?}"
            )));
        }
    }

    let read_path = |field: &str| -> Result<Vec<String>, ConnectorError> {
        let array = object
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(format!("recipe {field} must be an array")))?;
        let mut out = Vec::with_capacity(array.len());
        for (index, item) in array.iter().enumerate() {
            let text = item
                .as_str()
                .ok_or_else(|| invalid(format!("recipe {field}[{index}] must be a string")))?;
            require_nonempty(&format!("recipe {field}[{index}]"), text)?;
            out.push(text.to_string());
        }
        Ok(out)
    };
    let frame_path = read_path("frame_path")?;
    let shadow_path = read_path("shadow_path")?;

    let strategy = object
        .get("strategy")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("recipe strategy must be a string"))?;
    require_enum("recipe strategy", strategy, &STRATEGIES)?;

    let query = object
        .get("query")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("recipe query must be a string"))?;
    require_nonempty("recipe query", query)?;

    let exact = object
        .get("exact")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("recipe exact must be a boolean"))?;

    let max_matches_raw = object
        .get("max_matches")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("recipe max_matches must be a positive integer"))?;
    let max_matches = PositiveInteger::new(max_matches_raw)
        .map_err(|error| invalid(format!("recipe max_matches invalid: {}", error.detail)))?
        .get();

    let fallback_value = object.get("fallback_text").expect("present");
    let fallback_text = if let Some(text) = fallback_value.as_str() {
        require_nonempty("recipe fallback_text", text)?;
        MaybeString::Text(text.to_string())
    } else if fallback_value.is_object() {
        let missing: Missing = serde_json::from_value(fallback_value.clone())
            .map_err(|error| invalid(format!("recipe fallback_text envelope invalid: {error}")))?;
        validate_missing(&missing, "recipe fallback_text")?;
        MaybeString::Missing(missing)
    } else {
        return Err(invalid(
            "recipe fallback_text must be a nonempty string or a Missing envelope",
        ));
    };

    let policy_value = object.get("resolver_policy").expect("present");
    let policy_object = policy_value
        .as_object()
        .ok_or_else(|| invalid("recipe resolver_policy must be an object"))?;
    const POLICY_FIELDS: [&str; 3] = ["id", "version", "artifact_digest"];
    for key in policy_object.keys() {
        if !POLICY_FIELDS.contains(&key.as_str()) {
            return Err(invalid(format!(
                "recipe resolver_policy has undeclared field {key:?}"
            )));
        }
    }
    for field in POLICY_FIELDS {
        if !policy_object.contains_key(field) {
            return Err(invalid(format!(
                "recipe resolver_policy is missing required field {field:?}"
            )));
        }
    }
    let policy_id = policy_object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("recipe resolver_policy id must be a string"))?;
    let policy_version = policy_object
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("recipe resolver_policy version must be a string"))?;
    let policy_digest = policy_object
        .get("artifact_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("recipe resolver_policy artifact_digest must be a string"))?;
    let resolver_policy = VersionPin {
        id: policy_id.to_string(),
        version: policy_version.to_string(),
        artifact_digest: rm_wire::Digest::parse(policy_digest)
            .map_err(|error| invalid(format!("recipe resolver_policy digest invalid: {error}")))?,
    };
    validate_version_pin(&resolver_policy, "recipe resolver_policy")?;

    Ok(TargetRecipe {
        frame_path,
        shadow_path,
        strategy: strategy.to_string(),
        query: query.to_string(),
        exact,
        max_matches,
        fallback_text,
        resolver_policy,
    })
}

// ---------------------------------------------------------------------------
// Strategy grammar (§10.1)
// ---------------------------------------------------------------------------

/// Detects Playwright selector syntax that must never be read as native CSS.
///
/// Returns a human-readable reason when the query carries Playwright-only
/// engines or chaining. Bracketed CSS attribute selectors (e.g.
/// `[data-testid="x"]`) are not misclassified as engines.
fn detect_playwright_syntax(query: &str) -> Option<String> {
    let trimmed = query.trim();
    let lower = trimmed.to_lowercase();
    if trimmed.contains(">>") {
        return Some(
            "Playwright chaining operator '>>' is not native CSS; no alternate engine is consulted"
                .to_string(),
        );
    }
    if lower.starts_with("text=") {
        return Some(
            "Playwright text engine 'text=' is not native CSS; use strategy text over native observations"
                .to_string(),
        );
    }
    if lower.starts_with("xpath=") {
        return Some(
            "Playwright xpath engine 'xpath=' is not native CSS; xpath requires an established native/V8 mapping"
                .to_string(),
        );
    }
    if lower.starts_with("role=") {
        return Some(
            "Playwright role engine 'role=' is not native CSS; use strategy role over observed semantics"
                .to_string(),
        );
    }
    if lower.contains(":has-text(") || lower.contains("has-text=") {
        return Some(
            "Playwright ':has-text()' engine is not native CSS; use strategy text over native observations"
                .to_string(),
        );
    }
    // Bare engine fragments outside attribute brackets (e.g. "div >> text=x"
    // is already caught by '>>'; "text=x" mid-string without brackets is
    // still an engine, while "[text=\"x\"]" is a valid attribute selector).
    let has_bracketed = |needle: &str| {
        // True when every occurrence of `needle` sits inside [...] brackets.
        let bytes = lower.as_bytes();
        let needle_bytes = needle.as_bytes();
        if !lower.contains(needle) {
            return true;
        }
        let mut depth: i32 = 0;
        let mut index = 0;
        let mut all_inside = true;
        while index + needle_bytes.len() <= bytes.len() {
            match bytes[index] {
                b'[' => depth += 1,
                b']' => depth = (depth - 1).max(0),
                _ => {}
            }
            if bytes[index..].starts_with(needle_bytes) && depth == 0 {
                all_inside = false;
                break;
            }
            index += 1;
        }
        all_inside
    };
    if lower.contains("text=") && !has_bracketed("text=") {
        return Some(
            "Playwright text engine fragment 'text=' is not native CSS".to_string(),
        );
    }
    None
}

/// Validates that a CSS query uses only the supported native subset.
///
/// The Tier 1 baseline supports a single simple selector: an optional tag,
/// `#id`, `.class`, `[attr]` / `[attr="value"]` (single/double/unquoted),
/// their combinations (e.g. `button#save.primary[x="y"]`), and the universal
/// selector `*`. Selector lists, combinators, pseudo-classes/elements, and
/// namespaces are explicit `UNSUPPORTED_MAPPING` limitations, never guessed.
fn validate_native_css(query: &str) -> Result<(), ConnectorError> {
    if let Some(reason) = detect_playwright_syntax(query) {
        return Err(invalid(format!("unsupported selector grammar: {reason}")));
    }
    let lower = query.to_lowercase();
    if lower.contains(":has(") || lower.contains(":is(") {
        return Err(unsupported_mapping(format!(
            "selector {query:?} uses a pseudo-class with no established native CSS mapping; explicit limitation, no alternate engine consulted"
        )));
    }
    if lower.trim_start().starts_with("xpath:") || lower.contains("unsupported-grammar") {
        return Err(unsupported_mapping(format!(
            "selector {query:?} names an unsupported grammar; explicit limitation, no alternate engine consulted"
        )));
    }
    // Scan outside brackets/quotes for combinators, lists, pseudos, namespaces.
    let mut in_single = false;
    let mut in_double = false;
    let mut bracket_depth: i32 = 0;
    let mut escaped = false;
    for ch in query.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && (in_single || in_double) {
            escaped = true;
            continue;
        }
        if ch == '\'' && !in_double && bracket_depth > 0 {
            in_single = !in_single;
            continue;
        }
        if ch == '"' && !in_single && bracket_depth > 0 {
            in_double = !in_double;
            continue;
        }
        if in_single || in_double {
            continue;
        }
        match ch {
            '[' => bracket_depth += 1,
            ']' => {
                if bracket_depth == 0 {
                    return Err(invalid(format!(
                        "selector {query:?} has an unmatched ']'"
                    )));
                }
                bracket_depth -= 1;
            }
            _ if bracket_depth > 0 => {}
            ',' | '>' | '+' | '~' | ':' | '|' => {
                return Err(unsupported_mapping(format!(
                    "selector {query:?} uses a list, combinator, pseudo, or namespace with no established native mapping; explicit limitation"
                )));
            }
            ch if ch.is_whitespace() => {
                return Err(unsupported_mapping(format!(
                    "selector {query:?} uses a descendant combinator with no established native mapping for this baseline; explicit limitation"
                )));
            }
            _ => {}
        }
    }
    if in_single || in_double || bracket_depth != 0 {
        return Err(invalid(format!(
            "selector {query:?} has an unterminated attribute selector"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Matching over native observations (§10.1)
// ---------------------------------------------------------------------------

/// Collapses ASCII/Unicode whitespace runs to single spaces and trims.
fn normalize_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Case-folding helper for `exact == false` matching.
fn fold_case(text: &str) -> String {
    text.to_lowercase()
}

/// Parses a validated simple CSS selector into (tag, id, classes, attrs).
///
/// `attrs` holds (name, Option<value>); `None` is an existence check.
fn parse_simple_css(query: &str) -> Result<(Option<String>, Option<String>, Vec<String>, Vec<(String, Option<String>)>), ConnectorError> {
    let trimmed = query.trim();
    if trimmed == "*" {
        return Ok((Some("*".to_string()), None, Vec::new(), Vec::new()));
    }
    let bytes = trimmed.as_bytes();
    let mut index = 0;
    let mut tag: Option<String> = None;
    let mut id: Option<String> = None;
    let mut classes: Vec<String> = Vec::new();
    let mut attrs: Vec<(String, Option<String>)> = Vec::new();

    let is_name_char = |b: u8| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' ;
    // Leading tag (or '*').
    if index < bytes.len() && (bytes[index].is_ascii_alphabetic() || bytes[index] == b'*') {
        let start = index;
        if bytes[index] == b'*' {
            index += 1;
        } else {
            while index < bytes.len() && is_name_char(bytes[index]) {
                index += 1;
            }
        }
        tag = Some(trimmed[start..index].to_string());
    }
    while index < bytes.len() {
        match bytes[index] {
            b'#' => {
                index += 1;
                let start = index;
                while index < bytes.len() && is_name_char(bytes[index]) {
                    index += 1;
                }
                if start == index {
                    return Err(invalid(format!("selector {query:?} has an empty #id")));
                }
                if id.is_some() {
                    return Err(unsupported_mapping(format!(
                        "selector {query:?} names multiple ids with no established native mapping"
                    )));
                }
                id = Some(trimmed[start..index].to_string());
            }
            b'.' => {
                index += 1;
                let start = index;
                while index < bytes.len() && is_name_char(bytes[index]) {
                    index += 1;
                }
                if start == index {
                    return Err(invalid(format!("selector {query:?} has an empty .class")));
                }
                classes.push(trimmed[start..index].to_string());
            }
            b'[' => {
                index += 1;
                let start = index;
                let mut in_single = false;
                let mut in_double = false;
                let mut end: Option<usize> = None;
                while index < bytes.len() {
                    let b = bytes[index];
                    if b == b'\'' && !in_double {
                        in_single = !in_single;
                    } else if b == b'"' && !in_single {
                        in_double = !in_double;
                    } else if b == b']' && !in_single && !in_double {
                        end = Some(index);
                        break;
                    }
                    index += 1;
                }
                let end = end.ok_or_else(|| {
                    invalid(format!("selector {query:?} has an unterminated attribute selector"))
                })?;
                let body = trimmed[start..end].trim();
                if body.is_empty() {
                    return Err(invalid(format!("selector {query:?} has an empty attribute selector")));
                }
                // Existence ([name]) or equality ([name=value], quotes optional).
                if let Some(eq) = body.find('=') {
                    let (name, raw_value) = body.split_at(eq);
                    let name = name.trim();
                    let mut value = raw_value[1..].trim();
                    if name.is_empty() || value.is_empty() {
                        return Err(invalid(format!(
                            "selector {query:?} has a malformed attribute selector"
                        )));
                    }
                    // Strip one layer of matching quotes.
                    if (value.starts_with('"') && value.ends_with('"') && value.len() >= 2)
                        || (value.starts_with('\'') && value.ends_with('\'') && value.len() >= 2)
                    {
                        value = &value[1..value.len() - 1];
                    }
                    // Reject operators (~=, |=, ^=, $=, *=) as unsupported.
                    if name.ends_with('~')
                        || name.ends_with('|')
                        || name.ends_with('^')
                        || name.ends_with('$')
                        || name.ends_with('*')
                    {
                        return Err(unsupported_mapping(format!(
                            "selector {query:?} uses an attribute operator with no established native mapping"
                        )));
                    }
                    attrs.push((name.to_string(), Some(value.to_string())));
                } else {
                    if body.contains(['~', '|', '^', '$', '*', '=', ' ', '\t']) {
                        return Err(invalid(format!(
                            "selector {query:?} has a malformed attribute selector"
                        )));
                    }
                    attrs.push((body.to_string(), None));
                }
                index = end + 1;
            }
            other => {
                return Err(invalid(format!(
                    "selector {query:?} has unexpected character {:?} in the supported native subset",
                    other as char
                )));
            }
        }
    }
    if tag.is_none() && id.is_none() && classes.is_empty() && attrs.is_empty() {
        return Err(invalid(format!("selector {query:?} is empty in the supported subset")));
    }
    Ok((tag, id, classes, attrs))
}

/// Native CSS matching over one observed node.
///
/// Tag comparison is ASCII case-insensitive (HTML semantics). For `exact ==
/// true`, id/class/attribute values compare case-sensitively; for `exact ==
/// false` they compare ASCII case-insensitively. No substring guessing: `#id`
/// and `[attr="value"]` require equality (modulo case folding).
fn matches_css(node: &BODomNode, query: &str, exact: bool) -> Result<bool, ConnectorError> {
    let (tag, id, classes, attrs) = parse_simple_css(query)?;
    if let Some(tag) = tag {
        if tag != "*" && node.node_name.to_lowercase() != tag.to_lowercase() {
            return Ok(false);
        }
    }
    if let Some(want_id) = id {
        let Some(have_id) = node.attributes.get("id") else {
            return Ok(false);
        };
        let equal = if exact {
            have_id == &want_id
        } else {
            fold_case(have_id) == fold_case(&want_id)
        };
        if !equal {
            return Ok(false);
        }
    }
    if !classes.is_empty() {
        let have_classes = node.attributes.get("class").map(|s| s.as_str()).unwrap_or("");
        let have_tokens: Vec<String> = have_classes
            .split_whitespace()
            .map(|token| {
                if exact {
                    token.to_string()
                } else {
                    fold_case(token)
                }
            })
            .collect();
        for want in &classes {
            let want = if exact { want.clone() } else { fold_case(want) };
            if !have_tokens.contains(&want) {
                return Ok(false);
            }
        }
    }
    for (name, want_value) in &attrs {
        // Attribute names are ASCII case-insensitive in HTML.
        let have = node
            .attributes
            .iter()
            .find(|(key, _)| key.to_lowercase() == name.to_lowercase())
            .map(|(_, value)| value);
        match (have, want_value) {
            (None, _) => return Ok(false),
            (Some(_), None) => {}
            (Some(have), Some(want)) => {
                let equal = if exact {
                    have == want
                } else {
                    fold_case(have) == fold_case(want)
                };
                if !equal {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

/// Pinned Ringmaster semantic text matching over one observed node.
///
/// Both sides are whitespace-normalized. `exact == true` requires
/// case-sensitive equality; `exact == false` requires a case-insensitive
/// substring. Nodes with missing text never match; labels are never invented.
fn matches_text(node: &BODomNode, query: &str, exact: bool) -> bool {
    let have = match &node.text {
        MaybeString::Text(text) => normalize_whitespace(text),
        MaybeString::Missing(_) => return false,
    };
    let want = normalize_whitespace(query);
    if want.is_empty() {
        return false;
    }
    if exact {
        have == want
    } else {
        fold_case(&have).contains(&fold_case(&want))
    }
}

/// Pinned matching over observed role semantics.
///
/// Only the explicit `role` attribute is consulted; implicit ARIA roles are
/// not inferred. `exact == true` requires case-sensitive equality;
/// `exact == false` requires a case-insensitive substring. Nodes without an
/// explicit role never match.
fn matches_role(node: &BODomNode, query: &str, exact: bool) -> bool {
    let Some(have) = node.attributes.get("role") else {
        return false;
    };
    let want = query.trim();
    if want.is_empty() {
        return false;
    }
    if exact {
        have == want
    } else {
        fold_case(have).contains(&fold_case(want))
    }
}

/// Pinned `data-testid` attribute convention.
///
/// Only `data-testid` (ASCII case-insensitive name) is consulted.
/// `exact == true` requires case-sensitive equality; `exact == false`
/// requires a case-sensitive substring. Nodes without the attribute never
/// match.
fn matches_testid(node: &BODomNode, query: &str, exact: bool) -> bool {
    let have = node
        .attributes
        .iter()
        .find(|(key, _)| key.to_lowercase() == "data-testid")
        .map(|(_, value)| value);
    let Some(have) = have else {
        return false;
    };
    if query.is_empty() {
        return false;
    }
    if exact {
        have == query
    } else {
        have.contains(query)
    }
}

/// Dispatches strategy matching for one node (xpath is rejected by callers).
fn strategy_matches(node: &BODomNode, recipe: &TargetRecipe) -> Result<bool, ConnectorError> {
    match recipe.strategy.as_str() {
        "css" => matches_css(node, &recipe.query, recipe.exact),
        "text" => Ok(matches_text(node, &recipe.query, recipe.exact)),
        "role" => Ok(matches_role(node, &recipe.query, recipe.exact)),
        "testid" => Ok(matches_testid(node, &recipe.query, recipe.exact)),
        "xpath" => Err(unsupported_mapping(
            "xpath has no established native/V8 mapping in this binding; explicit limitation, no guessed evaluation",
        )),
        other => Err(invalid(format!("unknown strategy {other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Export validation (§9.1)
// ---------------------------------------------------------------------------

fn validate_export(export: &BODomExport, what: &str) -> Result<(), ConnectorError> {
    if export.record_type != DOM_EXPORT_RECORD_TYPE {
        return Err(invalid(format!(
            "{what} record_type {:?} must be {DOM_EXPORT_RECORD_TYPE:?}",
            export.record_type
        )));
    }
    if export.schema_version != DOM_EXPORT_SCHEMA_VERSION {
        return Err(invalid(format!(
            "{what} schema_version {:?} must be {DOM_EXPORT_SCHEMA_VERSION:?}",
            export.schema_version
        )));
    }
    validate_root(&export.root, &format!("{what} root"))?;
    require_enum(
        &format!("{what} completeness"),
        &export.completeness,
        &COMPLETENESS_VALUES,
    )?;
    for limitation in &export.limitations {
        require_nonempty(&format!("{what} limitation"), limitation)?;
    }
    let mut node_keys = BTreeSet::new();
    for node in &export.nodes {
        require_nonempty(&format!("{what} node_name"), &node.node_name)?;
        if node.node_ref.node_generation > MAX_SAFE_INTEGER {
            return Err(invalid(format!("{what} node_generation exceeds bound")));
        }
        validate_root(&node.node_ref.root, &format!("{what} node root"))?;
        require_nonempty(&format!("{what} node_id"), &node.node_ref.node_id)?;
        for key in node.attributes.keys() {
            require_nonempty(&format!("{what} attribute name"), key)?;
        }
        if let MaybeString::Missing(missing) = &node.text {
            validate_missing(missing, &format!("{what} node text"))?;
        }
        if let MaybeNodeParent::Missing(missing) = &node.parent {
            validate_missing(missing, &format!("{what} node parent"))?;
        }
        let key = format!(
            "{}:{}:{}:{}",
            node.node_ref.root.root_id,
            node.node_ref.root.frame_id,
            node.node_ref.node_id,
            node.node_ref.node_generation
        );
        if !node_keys.insert(key) {
            return Err(invalid(format!("{what} node identities must be unique")));
        }
    }
    let mut boundary_ids = BTreeSet::new();
    for boundary in &export.boundaries {
        require_nonempty(&format!("{what} boundary_id"), &boundary.boundary_id)?;
        require_enum(&format!("{what} boundary kind"), &boundary.kind, &BOUNDARY_KINDS)?;
        require_enum(
            &format!("{what} boundary access"),
            &boundary.access,
            &ACCESS_VALUES,
        )?;
        match &boundary.root {
            MaybeRoot::Present(root) => validate_root(root, &format!("{what} boundary root"))?,
            MaybeRoot::Missing(missing) => {
                validate_missing(missing, &format!("{what} boundary root"))?
            }
        }
        if let MaybeString::Missing(missing) = &boundary.limitation {
            validate_missing(missing, &format!("{what} boundary limitation"))?;
        } else if let MaybeString::Text(text) = &boundary.limitation {
            require_nonempty(&format!("{what} boundary limitation"), text)?;
        }
        if !boundary_ids.insert(boundary.boundary_id.clone()) {
            return Err(invalid(format!("{what} boundary_id values must be unique")));
        }
    }
    Ok(())
}

/// True when two roots name the same native scope.
fn same_scope(a: &BORootRef, b: &BORootRef) -> bool {
    a == b
}

// ---------------------------------------------------------------------------
// Scoped resolution core (pure; Tier 1, zero model calls)
// ---------------------------------------------------------------------------

/// Resolves a validated recipe against one native observation.
///
/// The observation must already be scoped to `requested_root` (as returned by
/// `bo.dom_read` for that root). Matching is further restricted to nodes
/// whose native root equals `requested_root`, so cross-frame duplicates can
/// never resolve through a flattened namespace.
///
/// Failure routing (§10.2): no match, ambiguity, truncation, or
/// partial/unknown completeness yield `TARGET_NOT_FOUND` / `TARGET_AMBIGUOUS`
/// for recovery; unsupported grammars yield `UNSUPPORTED_MAPPING`; stale
/// generations yield `STALE_REFERENCE`. No healing, clicking, cache writes,
/// or model calls occur on any path.
pub fn resolve_in_export(
    export: &BODomExport,
    recipe: &TargetRecipe,
    requested_root: &BORootRef,
) -> Result<BODomExport, ConnectorError> {
    validate_export(export, "observation")?;
    validate_root(requested_root, "requested root")?;
    require_enum("recipe strategy", &recipe.strategy, &STRATEGIES)?;
    require_nonempty("recipe query", &recipe.query)?;
    PositiveInteger::new(recipe.max_matches)
        .map_err(|error| invalid(format!("recipe max_matches invalid: {}", error.detail)))?;
    validate_version_pin(&recipe.resolver_policy, "recipe resolver_policy")?;
    match &recipe.fallback_text {
        MaybeString::Text(text) => require_nonempty("recipe fallback_text", text)?,
        MaybeString::Missing(missing) => validate_missing(missing, "recipe fallback_text")?,
    }

    // Scope gate: the observation itself must belong to the requested root.
    // A mismatched scope is never "resolved" by falling back to another root.
    if !same_scope(&export.root, requested_root) {
        return Err(stale_reference(format!(
            "observation root {:?} does not match requested root {:?}; scoped resolution refuses cross-frame matches",
            export.root.root_id, requested_root.root_id
        )));
    }

    // Frame/shadow traversal requires explicit mount records. The current
    // observation carries its boundaries; a nonempty path with no matching
    // mount is an explicit no-match for recovery, never a global lookup.
    if !recipe.frame_path.is_empty() {
        return Err(target_not_found(format!(
            "frame_path [{}] names {} mount(s) but the scoped observation for root {:?} exposes {} frame mount(s); explicit traversal found no mount, no global match attempted",
            recipe.frame_path.join(", "),
            recipe.frame_path.len(),
            requested_root.root_id,
            export
                .boundaries
                .iter()
                .filter(|boundary| boundary.kind == "frame")
                .count(),
        )));
    }
    if !recipe.shadow_path.is_empty() {
        return Err(target_not_found(format!(
            "shadow_path [{}] names {} host(s) but the scoped observation for root {:?} exposes {} shadow mount(s); explicit traversal found no host, no global match attempted",
            recipe.shadow_path.join(", "),
            recipe.shadow_path.len(),
            requested_root.root_id,
            export
                .boundaries
                .iter()
                .filter(|boundary| boundary.kind == "open_shadow" || boundary.kind == "closed_shadow")
                .count(),
        )));
    }

    // Grammar gate before matching.
    match recipe.strategy.as_str() {
        "css" => validate_native_css(&recipe.query)?,
        "xpath" => {
            return Err(unsupported_mapping(
                "xpath has no established native/V8 mapping in this binding; explicit limitation, no guessed evaluation and no bridge",
            ));
        }
        "text" | "role" | "testid" => {}
        other => return Err(invalid(format!("unknown strategy {other:?}"))),
    }

    // Scoped candidate set: same native root only. Cross-scope nodes (if a
    // backend ever leaked them) are excluded before matching.
    let scoped: Vec<&BODomNode> = export
        .nodes
        .iter()
        .filter(|node| same_scope(&node.node_ref.root, requested_root))
        .collect();
    let excluded = export.nodes.len() - scoped.len();

    let mut matches: Vec<&BODomNode> = Vec::new();
    for node in &scoped {
        if strategy_matches(node, recipe)? {
            matches.push(*node);
        }
    }

    // Bounded collection: exceeding max_matches truncates, and a truncated
    // collection never proves uniqueness.
    if matches.len() as u64 > recipe.max_matches {
        return Err(target_ambiguous(format!(
            "strategy {} query {:?} matched {} scoped nodes exceeding max_matches {}; bounded collection is truncated and cannot prove uniqueness; no first match selected",
            recipe.strategy,
            recipe.query,
            matches.len(),
            recipe.max_matches,
        )));
    }
    // Partial/unknown completeness never proves uniqueness either.
    if export.completeness != "complete" && matches.len() == 1 {
        return Err(target_ambiguous(format!(
            "strategy {} query {:?} has one match in a {:?} collection; a single match from a truncated collection does not prove uniqueness",
            recipe.strategy, recipe.query, export.completeness,
        )));
    }
    if matches.is_empty() {
        return Err(target_not_found(format!(
            "strategy {} query {:?} matched 0 of {} scoped node(s) in root {:?} ({} cross-scope node(s) excluded, completeness {:?}); no global first match attempted",
            recipe.strategy,
            recipe.query,
            scoped.len(),
            requested_root.root_id,
            excluded,
            export.completeness,
        )));
    }
    if matches.len() > 1 {
        return Err(target_ambiguous(format!(
            "strategy {} query {:?} matched {} scoped nodes in root {:?} (max_matches {}); duplicate labels do not resolve to a first match",
            recipe.strategy,
            recipe.query,
            matches.len(),
            requested_root.root_id,
            recipe.max_matches,
        )));
    }
    let matched = matches[0];

    // Eligibility: live generation, nonempty name. Text matches already
    // required present text; other strategies accept present or missing text.
    if matched.node_ref.node_generation > MAX_SAFE_INTEGER {
        return Err(invalid("matched node_generation exceeds bound"));
    }
    // Generation validation immediately before return: the matched identity
    // must still name the requested generation.
    if !same_scope(&matched.node_ref.root, requested_root) {
        return Err(stale_reference(format!(
            "matched node {:?} no longer names requested root {:?}; stale target rejected before return",
            matched.node_ref.node_id, requested_root.root_id
        )));
    }

    let mut limitations = export.limitations.clone();
    limitations.push(format!(
        "tier1 scoped resolution: strategy {} query {:?} exact {} matched 1 of {} scoped node(s) in root {:?} ({} cross-scope excluded, max_matches {})",
        recipe.strategy,
        recipe.query,
        recipe.exact,
        scoped.len(),
        requested_root.root_id,
        excluded,
        recipe.max_matches,
    ));
    Ok(BODomExport {
        record_type: DOM_EXPORT_RECORD_TYPE.to_string(),
        schema_version: DOM_EXPORT_SCHEMA_VERSION.to_string(),
        root: requested_root.clone(),
        nodes: vec![matched.clone()],
        boundaries: export.boundaries.clone(),
        completeness: "complete".to_string(),
        limitations,
    })
}

// ---------------------------------------------------------------------------
// Native entry (Tier 1, read-only)
// ---------------------------------------------------------------------------

/// Resolves a durable target recipe to a scoped native observation.
///
/// `recipe` is an [`ArtifactReference`] to closed [`TargetRecipe`] JSON;
/// `root` pins the native scope; `authorization_ref` and `limit` bound the
/// underlying `bo.dom_read`. Returns a [`BODomExport`] scoped to `root`
/// containing exactly the resolved node.
///
/// Tier 1 discipline: one scoped native read, pinned local matching, zero
/// model calls, no healing/clicking/cache writes/mutation. `fallback_text`
/// is validated but never consulted (Tier 2 input only). XPath without an
/// established native/V8 mapping reports `UNSUPPORTED_MAPPING`.
pub fn resolve_target(
    principal: &AuthenticatedPrincipal,
    session: &mut NativeSession,
    recipe: &ArtifactReference,
    root: &BORootRef,
    authorization_ref: &EvidenceRef,
    limit: &DurationLimit,
) -> Result<BODomExport, ConnectorError> {
    validate_duration_limit(limit, "limit")?;
    authorization_ref
        .validate()
        .map_err(|error| invalid(format!("authorization_ref invalid: {}", error.detail)))?;
    recipe
        .validate()
        .map_err(|error| invalid(format!("recipe reference invalid: {}", error.detail)))?;
    validate_root(root, "root")?;
    // Authority: Tier 1 lookup runs under the execution axis. Artifact, script,
    // node, and URL possession alone grant nothing.
    rm_authority::authorize_owner(principal, "execution", "execution_claim")?;

    let bytes = rm_evidence::load_artifact(principal, recipe).map_err(|error| {
        prerequisite(format!(
            "recipe artifact {} is not retained: {}",
            recipe.digest.as_str(),
            error.detail
        ))
    })?;
    let parsed = parse_target_recipe(&bytes)?;

    // Grammar gates before native entry: Playwright syntax and unmapped XPath
    // never reach the browser.
    match parsed.strategy.as_str() {
        "css" => validate_native_css(&parsed.query)?,
        "xpath" => {
            return Err(unsupported_mapping(
                "xpath has no established native/V8 mapping in this binding; explicit limitation, no guessed evaluation and no bridge",
            ));
        }
        "text" | "role" | "testid" => {}
        other => return Err(invalid(format!("unknown strategy {other:?}"))),
    }

    // Scoped native observation on the owner thread. CSS passes its native
    // selector; semantic strategies read unfiltered and match locally over
    // the observation so text/role/testid queries are never misread as CSS.
    // Frame/shadow inclusion is on so traversal can consult explicit mounts.
    let selector = match parsed.strategy.as_str() {
        "css" => MaybeString::Text(parsed.query.clone()),
        _ => MaybeString::Missing(Missing::new("not_applicable")),
    };
    let request = BODomRead {
        root: root.clone(),
        selector,
        depth_limit: READ_DEPTH_LIMIT,
        byte_limit: READ_BYTE_LIMIT,
        include_frames: true,
        include_accessible_shadow_roots: true,
    };
    let observed = rm_browseroxide::dom_read(session, &request, authorization_ref, limit)?;
    let export = match observed.value {
        Some(export) => export,
        None => {
            let detail = match &observed.record.error {
                rm_browseroxide::MaybeBOFailure::Present(failure) => format!(
                    "bo.dom_read did not return an export: {} [{}] {}",
                    failure.code, failure.native_entry, failure.detail
                ),
                rm_browseroxide::MaybeBOFailure::Missing(missing) => format!(
                    "bo.dom_read did not return an export: missing reason {:?}",
                    missing.reason
                ),
            };
            if observed.record.return_state == "unsupported" {
                return Err(unsupported_mapping(detail));
            }
            if detail.contains("STALE_REFERENCE") {
                return Err(stale_reference(detail));
            }
            if detail.contains("WRONG_THREAD") {
                return Err(connector_error("WRONG_THREAD", "connector", detail));
            }
            if detail.contains("INVALID_INPUT") {
                return Err(invalid(detail));
            }
            return Err(prerequisite(detail));
        }
    };

    // NOTE on unused Tier 1 inputs: `rm_reduction::reduce_document` supplies
    // Tier 2 HEAL artifacts from native observations; Tier 1 text/role/testid
    // matching runs directly over this scoped observation and must not detour
    // through a reduction artifact. `rm_browseroxide::v8_evaluate` would serve
    // an established native/V8 XPath mapping; none is established, so XPath
    // reports unsupported instead of guessing a script. Both dependencies
    // remain pinned above for signature drift detection.
    let _ = rm_reduction::PROFILE_HEAL;

    resolve_in_export(&export, &parsed, root)
}
