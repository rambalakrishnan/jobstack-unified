//! `crawler_fetch_identity`: fetch-key computation and same-key no-op decisions.
//!
//! Implements seam map §20.1 (fetch identity) and §20.2 (same-key rule) on top
//! of the structural [`crawler_schema`] gate:
//!
//! * [`compute_fetch_key`] implements the closed `crawler-fetch-key/1` profile:
//!   `B = SHA256(JCS([target, "B", job_id, canonical_request]))` and
//!   `A_full = SHA256(JCS([target, "A_full", job_id, listing_source_url]))`.
//!   URLs are canonicalized (lowercase scheme/host, default-port stripping,
//!   fragment removal, query order preserved); methods must already be
//!   uppercase; body digests are normalized to `sha256:` form; representation
//!   headers are sorted by name with values preserved in order. Ephemeral
//!   identity/session headers are rejected, never silently dropped or hashed.
//!   Run, crawl date, response digest, extractor version, and nonces are never
//!   inputs: extra fields on the identity record are rejected.
//! * [`decide_acquisition_write`] enforces the same-key no-op: an absent root
//!   (a `Missing` record) accepts an initial complete candidate; an existing
//!   identical fetch key returns the candidate with `acquisition` and
//!   `replacement_lineage` restored exactly from the existing record, so
//!   changed response/extractor/run bytes cannot become replacement content.
//!   A changed key faults with `fetch_key_changed` so the caller routes through
//!   `crawler_archives` (complete prior-row archive + retention) instead of
//!   committing a bare acquisition overwrite.
//! * [`validate_metadata_only`] proves a transition touched only permitted
//!   metadata: `acquisition` and `replacement_lineage` must be byte-identical
//!   (JSON value equality); discovery, lease, classification, and semantic
//!   slots may advance freely.
//!
//! Pure functions: no storage reads, no writes, no archive creation. Returned
//! keys are 64 lowercase hex characters; `Digest` framing is `sha256:<key>`.
//! Callers framing `SH` objects use profile `crawler-fetch-key/1`.
//!
//! Consumed: `crawler_normalization::assemble_crawler_value` builds the
//! `JobCrawlerValue` fixtures exercised by `tests/conformance.rs`.

use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord, Fault};
use serde_json::{Map, Value};

// Static interface assertion: the `JobCrawlerValue` fixtures exercised by
// `decide_acquisition_write` / `validate_metadata_only` are assembled via
// `crawler_normalization::assemble_crawler_value` (see tests/conformance.rs).
// This also pins the consumed signature so upstream drift fails the build.
const _: fn(&[CheckedRecord], &CheckedRecord) -> Result<CheckedRecord, Fault> =
    crawler_normalization::assemble_crawler_value;

/// Fetch-key profile id (informational; the digest framing is fixed here).
const FETCH_KEY_PROFILE: &str = "crawler-fetch-key/1";

/// Ephemeral identity/session headers. Presence in `header_identity_set` is a
/// fault (`ephemeral_header`); these are never hashed into the fetch key and
/// never silently dropped to inflate cache hits.
const EPHEMERAL_HEADERS: &[&str] = &[
    "cookie",
    "set-cookie",
    "cookie2",
    "set-cookie2",
    "authorization",
    "proxy-authorization",
    "proxy-authenticate",
    "www-authenticate",
    "session-id",
    "x-session-id",
    "session-token",
    "x-session-token",
    "x-auth-token",
    "x-csrf-token",
];

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

fn is_missing(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|m| m.get("value").is_some_and(Value::is_null))
}

fn is_64hex(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Normalize a digest text (`64hex` or `sha256:64hex`) to `sha256:64hex`.
fn normalize_digest(text: &str, what: &str) -> Result<String, Fault> {
    let hex = text.strip_prefix("sha256:").unwrap_or(text);
    if !is_64hex(hex) {
        return Err(fault(
            "invalid_digest",
            format!("{what} must be sha256: plus 64 lowercase hex characters"),
        ));
    }
    Ok(format!("sha256:{hex}"))
}

/// Extract raw hex (without `sha256:` prefix) from an established digest text.
fn digest_hex(text: &str) -> Option<&str> {
    let hex = text.strip_prefix("sha256:").unwrap_or(text);
    if is_64hex(hex) {
        Some(hex)
    } else {
        None
    }
}

fn established_str<'a>(obj: &'a Map<String, Value>, key: &str, what: &str) -> Result<&'a str, Fault> {
    match obj.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.as_str()),
        Some(v) if is_missing(v) => Err(fault(
            "missing_field",
            format!("{what} is Missing; {key:?} requires an established value"),
        )),
        _ => Err(fault(
            "missing_field",
            format!("{what} requires an established nonempty string {key:?}"),
        )),
    }
}

fn is_valid_method(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_uppercase())
}

fn is_valid_header_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.bytes().all(|b| {
        matches!(b, b'a'..=b'z' | b'0'..=b'9')
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'-'
            )
    })
}

/// Canonicalize an HTTP(S) URL: lowercase scheme/host, strip default ports
/// (80/443), remove the fragment, preserve path and query order verbatim.
fn canonicalize_url(url: &str, what: &str) -> Result<String, Fault> {
    let invalid = |why: &str| fault("invalid_url", format!("{what}: {why}"));
    let sep = url
        .find("://")
        .ok_or_else(|| invalid("URL must be http:// or https://"))?;
    let (scheme_raw, rest) = (&url[..sep], &url[sep + 3..]);
    if scheme_raw.is_empty() || rest.is_empty() {
        return Err(invalid("URL must be http:// or https://"));
    }
    let scheme = scheme_raw.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid("URL scheme must be http or https"));
    }
    // Strip fragment.
    let without_fragment = rest.split('#').next().unwrap_or(rest);
    // Split authority from path/query.
    let split = without_fragment
        .find(|c| c == '/' || c == '?')
        .unwrap_or(without_fragment.len());
    let (authority, path_query) = (&without_fragment[..split], &without_fragment[split..]);
    if authority.is_empty() {
        return Err(invalid("URL must carry an authority"));
    }
    if authority.contains('@') {
        return Err(invalid("URL must not carry userinfo"));
    }
    // Split host and port (IPv6-aware).
    let (host_raw, port_raw): (&str, Option<&str>) = if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| invalid("malformed IPv6 authority"))?;
        let host = &authority[..end + 1];
        let rest = &authority[end + 1..];
        if rest.is_empty() {
            (host, None)
        } else if let Some(port) = rest.strip_prefix(':') {
            if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
                return Err(invalid("URL port must be numeric"));
            }
            (host, Some(port))
        } else {
            return Err(invalid("malformed authority"));
        }
    } else if let Some(colon) = authority.rfind(':') {
        let (h, p) = (&authority[..colon], &authority[colon + 1..]);
        if h.is_empty() || p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid("malformed authority"));
        }
        (h, Some(p))
    } else {
        (authority, None)
    };
    if host_raw.is_empty() {
        return Err(invalid("URL must carry a host"));
    }
    let host = host_raw.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => "80",
        "https" => "443",
        _ => unreachable!(),
    };
    let mut out = format!("{scheme}://{host}");
    if let Some(port) = port_raw {
        if port != default_port {
            out.push(':');
            out.push_str(port);
        }
    }
    out.push_str(path_query);
    Ok(out)
}

/// Validate and sort a `header_identity_set` into canonical order (by name,
/// values preserved). Rejects ephemeral/duplicate/malformed entries.
fn canonicalize_headers(value: &Value) -> Result<Vec<Value>, Fault> {
    let items = match value {
        Value::Array(items) => items,
        v if is_missing(v) => {
            return Err(fault(
                "missing_field",
                "canonical_request.header_identity_set is Missing; an (possibly empty) array is required",
            ));
        }
        _ => {
            return Err(fault(
                "invalid_headers",
                "canonical_request.header_identity_set must be an array",
            ));
        }
    };
    let mut entries: Vec<(String, Vec<String>)> = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let obj = item.as_object().ok_or_else(|| {
            fault(
                "invalid_headers",
                format!("header_identity_set[{i}] must be an object"),
            )
        })?;
        if obj.len() != 2 || !obj.contains_key("name") || !obj.contains_key("values") {
            return Err(fault(
                "undeclared_field",
                format!("header_identity_set[{i}] must contain exactly name and values"),
            ));
        }
        let name = obj.get("name").and_then(Value::as_str).ok_or_else(|| {
            fault(
                "invalid_header_name",
                format!("header_identity_set[{i}].name must be a string"),
            )
        })?;
        if !is_valid_header_name(name) {
            return Err(fault(
                "invalid_header_name",
                format!("header_identity_set[{i}].name {name:?} must be a lowercase token"),
            ));
        }
        if EPHEMERAL_HEADERS.contains(&name) {
            return Err(fault(
                "ephemeral_header",
                format!("header {name:?} is ephemeral identity/session state, never fetch identity"),
            ));
        }
        let values = obj.get("values").and_then(Value::as_array).ok_or_else(|| {
            fault(
                "invalid_headers",
                format!("header_identity_set[{i}].values must be a nonempty string array"),
            )
        })?;
        if values.is_empty() {
            return Err(fault(
                "invalid_headers",
                format!("header_identity_set[{i}].values must carry at least one value"),
            ));
        }
        let mut vals = Vec::with_capacity(values.len());
        for v in values {
            match v {
                Value::String(s) => vals.push(s.clone()),
                _ => {
                    return Err(fault(
                        "invalid_headers",
                        format!("header_identity_set[{i}].values must be strings"),
                    ));
                }
            }
        }
        if entries.iter().any(|(n, _)| n == name) {
            return Err(fault(
                "duplicate_header",
                format!("header {name:?} appears twice; frame multivalue headers deterministically"),
            ));
        }
        entries.push((name.to_string(), vals));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(entries
        .into_iter()
        .map(|(name, vals)| {
            serde_json::json!({
                "name": name,
                "values": Value::Array(vals.into_iter().map(Value::String).collect()),
            })
        })
        .collect())
}

/// Extract the raw fetch-key hex from an `acquisition` object. Accepts a
/// `Digest` string (`sha256:hex` or bare hex) or an `SH` object carrying the
/// digest text under `value`.
fn fetch_hex(acquisition: &Value) -> Result<String, Fault> {
    let obj = acquisition.as_object().ok_or_else(|| {
        fault(
            "missing_acquisition",
            "record must carry an established acquisition object",
        )
    })?;
    match obj.get("fetch_key") {
        Some(Value::String(s)) => digest_hex(s)
            .map(str::to_string)
            .ok_or_else(|| fault("invalid_fetch_key", "acquisition.fetch_key must be sha256 hex")),
        Some(Value::Object(sh)) => match sh.get("value") {
            Some(Value::String(s)) => digest_hex(s)
                .map(str::to_string)
                .ok_or_else(|| {
                    fault("invalid_fetch_key", "acquisition.fetch_key.value must be sha256 hex")
                }),
            Some(v) if is_missing(v) => Err(fault(
                "missing_fetch_key",
                "acquisition.fetch_key is Missing; no fetch identity established",
            )),
            _ => Err(fault(
                "invalid_fetch_key",
                "acquisition.fetch_key object must carry digest text under value",
            )),
        },
        Some(v) if is_missing(v) => Err(fault(
            "missing_fetch_key",
            "acquisition.fetch_key is Missing; no fetch identity established",
        )),
        _ => Err(fault(
            "missing_fetch_key",
            "acquisition must carry an established fetch_key",
        )),
    }
}

fn require_complete_candidate(obj: &Map<String, Value>) -> Result<(), Fault> {
    let acquisition = obj.get("acquisition").ok_or_else(|| {
        fault(
            "incomplete_acquisition",
            "candidate must carry a complete acquisition",
        )
    })?;
    if is_missing(acquisition) || !acquisition.is_object() {
        return Err(fault(
            "incomplete_acquisition",
            "candidate acquisition must be an established object",
        ));
    }
    // Fetch key must be established.
    fetch_hex(acquisition).map_err(|_| {
        fault(
            "incomplete_acquisition",
            "candidate acquisition must carry an established fetch_key",
        )
    })?;
    // Fetch identity must be established.
    let has_identity = acquisition
        .as_object()
        .and_then(|a| a.get("fetch_identity"))
        .is_some_and(|v| !is_missing(v) && v.is_object());
    if !has_identity {
        return Err(fault(
            "incomplete_acquisition",
            "candidate acquisition must carry an established fetch_identity",
        ));
    }
    if !obj.contains_key("replacement_lineage") {
        return Err(fault(
            "incomplete_acquisition",
            "candidate must carry replacement_lineage",
        ));
    }
    Ok(())
}

/// Compute the `crawler-fetch-key/1` digest for (`root`, `identity`).
///
/// `root` carries `target` and `job_id` (extra fields are ignored, never
/// hashed). `identity` is a closed `FetchIdentity`: `phase_token` of `B` with
/// `canonical_request {url, method, body_hash, header_identity_set}`, or
/// `A_full` with `listing_source_url`. Any extra identity field — run, date,
/// response digest, extractor version, nonce — faults with `undeclared_field`.
///
/// Returns 64 lowercase hex characters (`sha256:<key>` is the `Digest`
/// framing). URL/method/body/header faults name the offending input.
pub fn compute_fetch_key(root: &CheckedRecord, identity: &CheckedRecord) -> Result<String, Fault> {
    let _ = FETCH_KEY_PROFILE;
    let root_obj = record_value(root).as_object().ok_or_else(|| {
        fault("invalid_root", "root must be an object carrying target and job_id")
    })?;
    let target = established_str(root_obj, "target", "fetch root")?.to_string();
    let job_id = established_str(root_obj, "job_id", "fetch root")?.to_string();

    let id_value = record_value(identity);
    if is_missing(id_value) {
        return Err(fault(
            "missing_identity",
            "fetch identity is Missing; no fetch key can be established",
        ));
    }
    let id_obj = id_value.as_object().ok_or_else(|| {
        fault("invalid_identity", "fetch identity must be an object")
    })?;
    let phase = match id_obj.get("phase_token") {
        Some(Value::String(p)) => p.as_str(),
        Some(v) if is_missing(v) => {
            return Err(fault(
                "missing_field",
                "fetch identity phase_token is Missing",
            ));
        }
        _ => {
            return Err(fault(
                "invalid_phase_token",
                "fetch identity phase_token must be B or A_full",
            ));
        }
    };

    let payload = match phase {
        "B" => {
            if id_obj.len() != 2
                || !id_obj.contains_key("phase_token")
                || !id_obj.contains_key("canonical_request")
            {
                return Err(fault(
                    "undeclared_field",
                    "B fetch identity must contain exactly phase_token and canonical_request; run, date, response digest, extractor version, and nonces are not fetch inputs",
                ));
            }
            let cr = id_obj.get("canonical_request").ok_or_else(|| {
                fault("missing_field", "B fetch identity requires canonical_request")
            })?;
            if is_missing(cr) {
                return Err(fault(
                    "missing_field",
                    "B canonical_request is Missing",
                ));
            }
            let cr_obj = cr.as_object().ok_or_else(|| {
                fault(
                    "invalid_canonical_request",
                    "B canonical_request must be an object",
                )
            })?;
            if cr_obj.len() != 4
                || !cr_obj.contains_key("url")
                || !cr_obj.contains_key("method")
                || !cr_obj.contains_key("body_hash")
                || !cr_obj.contains_key("header_identity_set")
            {
                return Err(fault(
                    "undeclared_field",
                    "canonical_request must contain exactly url, method, body_hash, and header_identity_set",
                ));
            }
            let url_raw = cr_obj.get("url").and_then(Value::as_str).ok_or_else(|| {
                fault(
                    "invalid_url",
                    "canonical_request.url must be an established HTTP(S) URL string",
                )
            })?;
            let url = canonicalize_url(url_raw, "canonical_request.url")?;
            let method = cr_obj.get("method").and_then(Value::as_str).ok_or_else(|| {
                fault(
                    "invalid_method",
                    "canonical_request.method must be an established string",
                )
            })?;
            if !is_valid_method(method) {
                return Err(fault(
                    "invalid_method",
                    "canonical_request.method must be uppercase A-Z",
                ));
            }
            let body_raw = cr_obj
                .get("body_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fault(
                        "invalid_digest",
                        "canonical_request.body_hash must be an established digest string",
                    )
                })?;
            let body_hash = normalize_digest(body_raw, "canonical_request.body_hash")?;
            let headers = canonicalize_headers(
                cr_obj
                    .get("header_identity_set")
                    .unwrap_or(&Value::Null),
            )?;
            let canonical_request = serde_json::json!({
                "url": url,
                "method": method,
                "body_hash": body_hash,
                "header_identity_set": Value::Array(headers),
            });
            Value::Array(vec![
                Value::String(target),
                Value::String("B".to_string()),
                Value::String(job_id),
                canonical_request,
            ])
        }
        "A_full" => {
            if id_obj.len() != 2
                || !id_obj.contains_key("phase_token")
                || !id_obj.contains_key("listing_source_url")
            {
                return Err(fault(
                    "undeclared_field",
                    "A_full fetch identity must contain exactly phase_token and listing_source_url; run, date, response digest, extractor version, and nonces are not fetch inputs",
                ));
            }
            let url_raw = id_obj
                .get("listing_source_url")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    fault(
                        "invalid_url",
                        "listing_source_url must be an established HTTP(S) URL string",
                    )
                })?;
            let url = canonicalize_url(url_raw, "listing_source_url")?;
            Value::Array(vec![
                Value::String(target),
                Value::String("A_full".to_string()),
                Value::String(job_id),
                Value::String(url),
            ])
        }
        _ => {
            return Err(fault(
                "invalid_phase_token",
                "fetch identity phase_token must be B or A_full",
            ));
        }
    };

    let framed =
        validate("audit_log", payload).map_err(|e| fault("framing_failed", e.detail))?;
    let bytes = canonical_bytes(&framed)?;
    Ok(digest_bytes(&bytes))
}

/// Decide the acquisition write for (`existing`, `candidate`).
///
/// * Absent `existing` (a `Missing` record) accepts an initial complete
///   candidate and returns it unchanged (no predecessor archive).
/// * An identical fetch key is an acquisition no-op: the returned record is
///   the candidate with `acquisition` and `replacement_lineage` restored
///   exactly from `existing`. Changed response/extractor/run bytes, repaired
///   renders, and lineage rewrites are discarded, never authorized; all other
///   (discovery/lease/classification/semantic) slots come from the candidate.
/// * A changed key faults with `fetch_key_changed`: the caller must archive
///   the complete prior row through `crawler_archives` before installing the
///   new revision. This function never creates an archive.
pub fn decide_acquisition_write(
    existing: &CheckedRecord,
    candidate: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    let existing_value = record_value(existing);
    let candidate_value = record_value(candidate);

    // Absent root accepts the initial complete domain.
    if is_missing(existing_value) {
        let cand_obj = candidate_value.as_object().ok_or_else(|| {
            fault(
                "invalid_candidate",
                "candidate must be an object carrying a complete crawler domain",
            )
        })?;
        require_complete_candidate(cand_obj)?;
        return validate(record_schema(candidate), candidate_value.clone());
    }
    if is_missing(candidate_value) {
        return Err(fault(
            "invalid_candidate",
            "candidate is Missing; no crawler domain to install",
        ));
    }
    let exist_obj = existing_value.as_object().ok_or_else(|| {
        fault(
            "invalid_existing",
            "existing must be an object carrying acquisition and replacement_lineage",
        )
    })?;
    let cand_obj = candidate_value.as_object().ok_or_else(|| {
        fault(
            "invalid_candidate",
            "candidate must be an object carrying acquisition and replacement_lineage",
        )
    })?;
    let exist_acq = exist_obj.get("acquisition").ok_or_else(|| {
        fault(
            "missing_acquisition",
            "existing must carry acquisition",
        )
    })?;
    let cand_acq = cand_obj.get("acquisition").ok_or_else(|| {
        fault(
            "missing_acquisition",
            "candidate must carry acquisition",
        )
    })?;
    if is_missing(exist_acq) || !exist_acq.is_object() {
        return Err(fault(
            "missing_acquisition",
            "existing acquisition must be an established object",
        ));
    }
    if is_missing(cand_acq) || !cand_acq.is_object() {
        return Err(fault(
            "missing_acquisition",
            "candidate acquisition must be an established object",
        ));
    }
    if !exist_obj.contains_key("replacement_lineage") {
        return Err(fault(
            "missing_lineage",
            "existing must carry replacement_lineage",
        ));
    }
    if !cand_obj.contains_key("replacement_lineage") {
        return Err(fault(
            "missing_lineage",
            "candidate must carry replacement_lineage",
        ));
    }

    let old_hex = fetch_hex(exist_acq)?;
    let new_hex = fetch_hex(cand_acq)?;
    if old_hex != new_hex {
        return Err(fault(
            "fetch_key_changed",
            "fetch key changed; archive the complete prior logical row via crawler_archives before installing the new crawler revision",
        ));
    }

    // Same key: acquisition no-op. Preserve both slots exactly from existing;
    // every other slot comes from the candidate so independent metadata
    // transitions (discovery, lease, classification, semantic, coverage refs)
    // may commit in the same write.
    let mut merged = cand_obj.clone();
    merged.insert(
        "acquisition".to_string(),
        exist_obj.get("acquisition").cloned().unwrap_or(Value::Null),
    );
    merged.insert(
        "replacement_lineage".to_string(),
        exist_obj
            .get("replacement_lineage")
            .cloned()
            .unwrap_or(Value::Null),
    );
    validate(record_schema(candidate), Value::Object(merged))
}

/// Prove `before -> after` touched only permitted metadata.
///
/// `acquisition` and `replacement_lineage` must be exactly equal; any rewrite
/// — including a same-key repaired render — faults (`acquisition_rewrite` /
/// `lineage_rewrite`). All other slots may change. Both records must be
/// established objects; a `Missing` root faults with `absent_root`.
pub fn validate_metadata_only(before: &CheckedRecord, after: &CheckedRecord) -> Result<(), Fault> {
    let b = record_value(before);
    let a = record_value(after);
    if is_missing(b) || is_missing(a) {
        return Err(fault(
            "absent_root",
            "metadata-only transition requires established before and after roots",
        ));
    }
    let b_obj = b.as_object().ok_or_else(|| {
        fault("invalid_record", "before must be an object")
    })?;
    let a_obj = a.as_object().ok_or_else(|| {
        fault("invalid_record", "after must be an object")
    })?;
    let b_acq = b_obj.get("acquisition").ok_or_else(|| {
        fault("missing_acquisition", "before must carry acquisition")
    })?;
    let a_acq = a_obj.get("acquisition").ok_or_else(|| {
        fault("missing_acquisition", "after must carry acquisition")
    })?;
    if b_acq != a_acq {
        return Err(fault(
            "acquisition_rewrite",
            "acquisition must remain exactly unchanged in a metadata-only transition; same-key acquisition rewrites including repaired failed renders are not authorized",
        ));
    }
    let b_lin = b_obj.get("replacement_lineage").ok_or_else(|| {
        fault("missing_lineage", "before must carry replacement_lineage")
    })?;
    let a_lin = a_obj.get("replacement_lineage").ok_or_else(|| {
        fault("missing_lineage", "after must carry replacement_lineage")
    })?;
    if b_lin != a_lin {
        return Err(fault(
            "lineage_rewrite",
            "replacement_lineage must remain exactly unchanged in a metadata-only transition",
        ));
    }
    Ok(())
}
