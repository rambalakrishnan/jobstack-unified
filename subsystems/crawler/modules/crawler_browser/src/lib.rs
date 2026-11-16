//! `crawler_browser`: thread-confined `Page` executor.
//!
//! Wraps a native [`browser_oxide::Page`] so it never crosses its allocating
//! OS thread (Contract 03, BO-THREAD; [C34]):
//!
//! * [`PageExecutor`] is `!Send` and `!Sync` (via `PhantomData<Rc<()>>` plus
//!   the native `Page`). Safe code cannot move it, its `Page`, solver
//!   instances, DOM borrows, V8 handles, or capturing closures across threads.
//! * Every entry point ([`create_page`], [`execute_page`], [`reset_page`])
//!   records or checks the owning [`std::thread::ThreadId`] and rejects
//!   wrong-thread use with `wrong_thread` *before* entering the engine.
//! * Destruction is also owner-confined: `Drop` asserts the current thread is
//!   the owner.
//! * Cross-thread messages contain only owned bytes and immutable
//!   descriptions: [`execute_page`] returns a checked `audit_log` record with
//!   URL, title, content length, and render verdict. No live `Page`, DOM, or
//!   V8 handle is exposed.
//! * `Page::from_html` inputs are inline-only (no external subresources, no
//!   network). Deadlines are echoed, never extended. Resets reject
//!   incompatible session ownership (`session_mismatch`).
//! * Page permits must be page reservations (`kind` of `page` or
//!   `page_control`); other credit kinds are rejected as `invalid_permit`.
//!
//! All output records validate through the closed `crawler_schema` gate under
//! `audit_log`; absent fields use typed `Missing` envelopes, never bare nulls.

use browser_oxide::Page;
use crawler_admission::PagePermit;
use crawler_readonly::ReadOnlyRequest;
use crawler_schema::{record_value, validate, CheckedRecord, Fault};
use serde_json::{json, Value};
use std::marker::PhantomData;
use std::rc::Rc;
use std::thread::ThreadId;

/// Thread-confined native page executor.
///
/// The native [`Page`] is allocated on [`create_page`]'s calling thread and
/// must be entered, reset, and destroyed on that same thread. The
/// [`PhantomData<Rc<()>>`] marker makes this type `!Send` and `!Sync`, so
/// safe code cannot move it across threads; the runtime [`ThreadId`] check
/// in [`execute_page`]/[`reset_page`] (and `Drop`) defends against `unsafe`
/// misuse.
pub struct PageExecutor {
    page: Page,
    owner: ThreadId,
    permit: PagePermit,
    confinement: PhantomData<Rc<()>>,
}

impl Drop for PageExecutor {
    fn drop(&mut self) {
        // Destroy on the owning OS thread. Safe code cannot violate this
        // (!Send), so a mismatch indicates unsafe misuse elsewhere.
        assert!(
            std::thread::current().id() == self.owner,
            "PageExecutor dropped on non-owning thread"
        );
    }
}

impl PageExecutor {
    /// Owning thread recorded at creation. Returns a plain [`ThreadId`]
    /// (owned, `Send`) without touching the native engine.
    pub fn owner_thread(&self) -> ThreadId {
        self.owner
    }
}

fn fault(code: &str, detail: impl Into<String>) -> Fault {
    Fault {
        code: code.to_string(),
        detail: detail.into(),
    }
}

/// True when `value` is a schema-gate `Missing` envelope.
fn is_missing(value: &Value) -> bool {
    value.get("value").is_some_and(Value::is_null) && value.get("reason").is_some()
}

/// Established (non-`Missing`) string field, if any.
fn established_str(value: Option<&Value>) -> Option<&str> {
    value.filter(|v| !is_missing(v)).and_then(Value::as_str)
}

fn missing(reason: &str, detail: &str) -> Value {
    json!({"value": Value::Null, "reason": reason, "detail": detail})
}

fn stealth_preset(name: &str) -> Option<browser_oxide::stealth::StealthProfile> {
    use browser_oxide::stealth::presets::*;
    Some(match name {
        "chrome_148_linux" => chrome_148_linux(),
        "chrome_148_windows" => chrome_148_windows(),
        "chrome_148_macos" => chrome_148_macos(),
        "chrome_148_ru" => chrome_148_ru(),
        "chrome_148_cn" => chrome_148_cn(),
        "chrome_148_de" => chrome_148_de(),
        "chrome_148_jp" => chrome_148_jp(),
        "firefox_135_linux" => firefox_135_linux(),
        "firefox_135_macos" => firefox_135_macos(),
        "firefox_135_windows" => firefox_135_windows(),
        _ => return None,
    })
}

/// Allocate a thread-confined [`Page`] on the calling thread.
///
/// The `profile` must be an object; its established `preset` field (when
/// present) selects a versioned stealth preset, defaulting to
/// `chrome_148_linux`. Unknown presets fail with `invalid_profile`.
///
/// The `permit` must be a page reservation (`kind` of `page` or
/// `page_control`); any other credit kind fails with `invalid_permit`
/// without allocating.
///
/// Allocation uses inline-only HTML with no external subresources, so
/// `Page::from_html` performs no network acquisition. The returned executor
/// records the calling thread as its exclusive owner.
pub fn create_page(profile: &CheckedRecord, permit: PagePermit) -> Result<PageExecutor, Fault> {
    let profile_value = record_value(profile);
    let profile_map = profile_value.as_object().ok_or_else(|| {
        fault(
            "invalid_profile",
            "browser profile must be an object",
        )
    })?;

    let reservation = record_value(&permit.reservation);
    match reservation.get("kind").and_then(Value::as_str) {
        Some("page") | Some("page_control") => {}
        other => {
            return Err(fault(
                "invalid_permit",
                format!(
                    "PagePermit kind {other:?} is not a page reservation; expected \"page\" or \"page_control\""
                ),
            ));
        }
    }

    let preset_name = profile_map
        .get("preset")
        .filter(|v| !is_missing(v))
        .and_then(Value::as_str)
        .unwrap_or("chrome_148_linux");
    let stealth = stealth_preset(preset_name).ok_or_else(|| {
        fault(
            "invalid_profile",
            format!("unknown stealth preset {preset_name:?}"),
        )
    })?;

    // Inline-only document: no external scripts, stylesheets, or frames, so
    // from-HTML rendering issues no network requests.
    let html = "<!doctype html><html><head><title>blank</title></head><body></body></html>";

    // Current-thread runtime: the Page (and its V8 isolate) is created on
    // the calling OS thread, which becomes the exclusive owner.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| fault("page_create_failed", format!("page runtime failed: {e}")))?;
    let page = rt
        .block_on(Page::from_html(html, Some(stealth)))
        .map_err(|e| fault("page_create_failed", format!("Page::from_html failed: {e}")))?;

    Ok(PageExecutor {
        page,
        owner: std::thread::current().id(),
        permit,
        confinement: PhantomData,
    })
}

/// Execute a read-only request on the owning thread.
///
/// Rejects wrong-thread use with `wrong_thread` before entering the engine.
/// The request must carry `effect_policy: read_only`; anything else fails
/// with `mutation_rejected`. The `deadline` must be an object and is echoed
/// into the output verbatim — never extended.
///
/// Engine access is synchronous and offline-only (`url`, `title`,
/// `content`, `challenge_verdict`): no navigation, no script fetch, no
/// solver network. The returned `audit_log` record carries owned bytes and
/// descriptions only — never a live `Page`, DOM, or V8 handle.
pub fn execute_page(
    page: &mut PageExecutor,
    request: &ReadOnlyRequest,
    deadline: &CheckedRecord,
) -> Result<CheckedRecord, Fault> {
    if std::thread::current().id() != page.owner {
        return Err(fault(
            "wrong_thread",
            "PageExecutor used on non-owning thread; Page handles never cross threads",
        ));
    }

    let deadline_value = record_value(deadline);
    if !deadline_value.is_object() {
        return Err(fault(
            "invalid_deadline",
            "deadline must be an object",
        ));
    }

    let req_value = record_value(&request.record);
    let req_map = req_value.as_object().ok_or_else(|| {
        fault(
            "invalid_request",
            "ReadOnlyRequest record must be an object",
        )
    })?;
    match req_map.get("effect_policy").and_then(Value::as_str) {
        Some("read_only") => {}
        other => {
            return Err(fault(
                "mutation_rejected",
                format!("ReadOnlyRequest effect_policy must be read_only, got {other:?}"),
            ));
        }
    }

    let endpoint_url = req_map
        .get("endpoint")
        .and_then(|e| e.as_object())
        .and_then(|m| {
            m.get("url")
                .or_else(|| m.get("location"))
                .or_else(|| m.get("target_url"))
                .or_else(|| m.get("href"))
        })
        .filter(|v| !is_missing(v))
        .and_then(Value::as_str)
        .unwrap_or("");
    let task_id = req_map
        .get("request")
        .and_then(|r| r.as_object())
        .and_then(|m| m.get("task_id"))
        .filter(|v| !is_missing(v))
        .and_then(Value::as_str)
        .unwrap_or("");

    // Same-thread, offline-only engine access. No navigation, no fetch.
    let page_url = page.page.url().to_string();
    let verdict = page.page.challenge_verdict();
    let title = page.page.title();
    let content_length = page.page.content().len() as u64;

    let endpoint_evidence = if endpoint_url.is_empty() {
        missing("not_observed", "request carried no endpoint url")
    } else {
        Value::String(endpoint_url.to_string())
    };
    let task_evidence = if task_id.is_empty() {
        missing("not_observed", "request carried no task id")
    } else {
        Value::String(task_id.to_string())
    };
    let permit_credit = record_value(&page.permit.reservation)
        .get("credit_id")
        .cloned()
        .filter(|v| !is_missing(v))
        .unwrap_or_else(|| missing("not_observed", "permit carried no credit identifier"));

    validate(
        "audit_log",
        json!({
            "kind": "page_execution",
            "page_url": page_url,
            "page_title": title,
            "content_length": content_length,
            "render_verdict": verdict.as_str(),
            "endpoint_url": endpoint_evidence,
            "task_id": task_evidence,
            "effect_policy": "read_only",
            "permit_credit": permit_credit,
            "deadline": deadline_value.clone(),
        }),
    )
}

/// Reset the page for reuse within a compatible session, on the owner thread.
///
/// Rejects wrong-thread use with `wrong_thread` before entering the engine.
/// The `session` must be an object whose established `target` (when present
/// alongside the permit's established `target`) equals the permit
/// reservation's `target`; a mismatch fails with `session_mismatch` and the
/// native page is left untouched. A successful reset clears the native DOM
/// registry and invalidates old DOM references via `reset_for_reuse`
/// (synchronous, same-thread, no network) while preserving the intended jar.
pub fn reset_page(page: &mut PageExecutor, session: &CheckedRecord) -> Result<(), Fault> {
    if std::thread::current().id() != page.owner {
        return Err(fault(
            "wrong_thread",
            "PageExecutor reset on non-owning thread; Page handles never cross threads",
        ));
    }

    let session_value = record_value(session);
    let session_map = session_value.as_object().ok_or_else(|| {
        fault("invalid_session", "session must be an object")
    })?;

    let permit_target =
        established_str(record_value(&page.permit.reservation).get("target"));
    let session_target = established_str(session_map.get("target"));
    if let (Some(expected), Some(actual)) = (permit_target, session_target) {
        if expected != actual {
            return Err(fault(
                "session_mismatch",
                format!(
                    "reset session target {actual:?} does not match permit target {expected:?}; resetting across incompatible session ownership is forbidden"
                ),
            ));
        }
    }

    page.page.reset_for_reuse();
    Ok(())
}
