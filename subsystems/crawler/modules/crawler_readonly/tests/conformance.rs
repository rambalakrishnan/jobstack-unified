//! [C40] read-only conformance: OR self-referral and every application
//! mutation is rejected before wire; the crawler inserts zero mutation rows.

use crawler_authority::{authorize, grant_record, Grant};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_readonly::{authorize_acquisition, authorize_redirect, reject_write_action};
use crawler_schema::{record_schema, record_value, validate, CheckedRecord};
use serde_json::{json, Value};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

/// Digest binding a principal/reference to the exact bytes of a record.
fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn dummy_digest() -> Value {
    Value::String("0123456789abcdef".repeat(4))
}

fn registration_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "registration_id": "channel-1",
            "principals": [{
                "principal_id": "reader",
                "verbs": ["Describe", "Prepare", "Observe", "CollectArtifacts"],
                "connectors": ["jobs-connector"],
                "control": false,
                "owner_domain": "crawler",
                "restricted_access": false,
            }],
        }),
    )
}

fn test_grant() -> Grant {
    let registration = registration_fixture();
    let principal = check(
        "audit_log",
        json!({
            "principal_id": "reader",
            "registration_digest": binding_of(&registration),
        }),
    );
    let request = check(
        "audit_log",
        json!({
            "verb": "Observe",
            "connector": "jobs-connector",
            "subject": "jobs",
        }),
    );
    authorize(&principal, &request, &registration).expect("grant must issue")
}

fn merge(mut base: serde_json::Map<String, Value>, extra: Value) -> Value {
    if let Value::Object(overlay) = extra {
        for (key, value) in overlay {
            base.insert(key, value);
        }
    }
    Value::Object(base)
}

/// Reference-shaped acquisition endpoint (or redirect) under `grant`.
fn endpoint(grant: &Grant, url: &str, extra: Value) -> CheckedRecord {
    let mut base = serde_json::Map::new();
    base.insert(
        "grant_digest".to_string(),
        Value::String(binding_of(grant_record(grant))),
    );
    base.insert("digest".to_string(), dummy_digest());
    base.insert("access".to_string(), json!("public"));
    base.insert("owner_domain".to_string(), json!("crawler"));
    base.insert("provenance".to_string(), json!("origin"));
    base.insert("url".to_string(), Value::String(url.to_string()));
    check("audit_log", merge(base, extra))
}

/// TaskEnvelope-shaped read-only request.
fn request(task_type: &str, origins: Vec<&str>, extra: Value) -> CheckedRecord {
    let mut base = serde_json::Map::new();
    base.insert("record_type".to_string(), json!("connector_task"));
    base.insert("task_id".to_string(), json!("task-1"));
    base.insert(
        "task_type".to_string(),
        Value::String(task_type.to_string()),
    );
    base.insert("goal".to_string(), json!("discover listings"));
    base.insert("effect_policy".to_string(), json!("read_only"));
    base.insert(
        "permitted_origins".to_string(),
        Value::Array(origins.into_iter().map(|o| json!(o)).collect()),
    );
    base.insert(
        "permitted_interfaces".to_string(),
        json!(["read_only_acquisition"]),
    );
    check("audit_log", merge(base, extra))
}

fn or_request(grant_extra: Value) -> CheckedRecord {
    let _ = grant_extra;
    request("discover_jobs", vec!["https://jobs.oregon.gov"], json!({}))
}

fn action(value: Value) -> CheckedRecord {
    check("audit_log", value)
}

// ---------------------------------------------------------------------------
// C40: OR self-referral rejected before wire
// ---------------------------------------------------------------------------

#[test]
fn c40_or_self_referral_rejected_before_wire() {
    let grant = test_grant();
    let req = or_request(json!({}));
    // `usemyssn=No` never excuses the mutation; neither does the HTTP method.
    for (url, method) in [
        (
            "https://jobs.oregon.gov/self-refer-step1-validate.cfm?usemyssn=No",
            "GET",
        ),
        (
            "https://jobs.oregon.gov/self-refer-step1-validate.cfm?usemyssn=No",
            "POST",
        ),
        ("https://jobs.oregon.gov/self-refer-step1-validate.cfm", "GET"),
        (
            "https://jobs.oregon.gov/Self-Refer-Step1-Validate.cfm?usemyssn=No&x=1",
            "POST",
        ),
    ] {
        let ep = endpoint(&grant, url, json!({"method": method}));
        let err = authorize_acquisition(&grant, &ep, &req)
            .expect_err("OR self-referral must be rejected before wire");
        assert_eq!(err.code, "mutation_rejected", "url {url:?}");
    }
    // The write-action stub refuses it too.
    let err = reject_write_action(&action(json!({
        "action": "self-refer",
        "url": "https://jobs.oregon.gov/self-refer-step1-validate.cfm?usemyssn=No",
    })))
    .expect_err("self-referral write action must be rejected");
    assert_eq!(err.code, "mutation_rejected");
    // A redirect onto the mutation endpoint is rejected as a mutation.
    let clean = endpoint(&grant, "https://jobs.oregon.gov/search", json!({}));
    let previous =
        authorize_acquisition(&grant, &clean, &req).expect("clean acquisition must pass");
    let bad = endpoint(
        &grant,
        "https://jobs.oregon.gov/self-refer-step1-validate.cfm?usemyssn=No",
        json!({}),
    );
    let err = authorize_redirect(&grant, &previous, &bad)
        .expect_err("self-referral redirect must be rejected");
    assert_eq!(err.code, "mutation_rejected");
}

// ---------------------------------------------------------------------------
// C40: every application mutation rejected before wire
// ---------------------------------------------------------------------------

#[test]
fn c40_application_mutations_rejected_before_wire() {
    let grant = test_grant();
    let clean_url = "https://jobs.illinois.gov/search";
    let origins = vec!["https://jobs.illinois.gov"];

    // Requests carrying application authority.
    for req in [
        request("apply", origins.clone(), json!({})),
        request(
            "discover_jobs",
            origins.clone(),
            json!({"effect_policy": "commissioned_application"}),
        ),
        request("crawl", origins.clone(), json!({})),
        request(
            "discover_jobs",
            origins.clone(),
            json!({"operation": "apply"}),
        ),
        request(
            "extract",
            origins.clone(),
            json!({"permitted_interfaces": ["write_access"]}),
        ),
        request(
            "discover_jobs",
            origins.clone(),
            json!({"record_type": "state_mutation_record", "status": "requested"}),
        ),
    ] {
        let ep = endpoint(&grant, clean_url, json!({}));
        let err = authorize_acquisition(&grant, &ep, &req)
            .expect_err("application-shaped request must be rejected");
        assert_eq!(err.code, "mutation_rejected");
    }

    // Endpoints carrying mutations.
    for ep in [
        endpoint(
            &grant,
            "https://jobs.illinois.gov/contact-reveal?job=7",
            json!({}),
        ),
        endpoint(
            &grant,
            "https://jobs.illinois.gov/jobs/submit-application",
            json!({}),
        ),
        endpoint(&grant, clean_url, json!({"operation": "apply"})),
        endpoint(&grant, clean_url, json!({"action_name": "apply_to_job"})),
        endpoint(&grant, clean_url, json!({"mutating": true})),
        endpoint(
            &grant,
            clean_url,
            json!({"effect_policy": "commissioned_application"}),
        ),
    ] {
        let req = request("discover_jobs", origins.clone(), json!({}));
        let err = authorize_acquisition(&grant, &ep, &req)
            .expect_err("mutation-shaped endpoint must be rejected");
        assert_eq!(err.code, "mutation_rejected");
    }

    // A record validated as a mutation record is rejected by schema alone.
    let mutation_schema = check(
        "state_mutation_record",
        json!({
            "target": "OR-A",
            "job_id": "job-1",
            "mutation_id": "m-1",
            "action_name": "self-refer",
            "status": "requested",
        }),
    );
    let req = request("discover_jobs", origins.clone(), json!({}));
    let err = authorize_acquisition(&grant, &mutation_schema, &req)
        .expect_err("state_mutation_record endpoint must be rejected");
    assert_eq!(err.code, "mutation_rejected");
}

// ---------------------------------------------------------------------------
// C40: HTTP method alone never determines read-only status
// ---------------------------------------------------------------------------

#[test]
fn c40_http_method_does_not_determine_readonly() {
    let grant = test_grant();
    // MI query POST and WI postback are acquisition; the method is ignored in
    // both directions, so even PUT/DELETE on a clean endpoint pass.
    for (url, method, origins) in [
        (
            "https://mitalent.org/query",
            "POST",
            vec!["https://mitalent.org"],
        ),
        (
            "https://jobcenterofwisconsin.com/search",
            "POST",
            vec!["https://jobcenterofwisconsin.com"],
        ),
        (
            "https://jobs.illinois.gov/search",
            "GET",
            vec!["https://jobs.illinois.gov"],
        ),
        (
            "https://jobs.illinois.gov/search",
            "PUT",
            vec!["https://jobs.illinois.gov"],
        ),
        (
            "https://jobs.illinois.gov/search",
            "DELETE",
            vec!["https://jobs.illinois.gov"],
        ),
    ] {
        let ep = endpoint(&grant, url, json!({"method": method}));
        let req = request("discover_jobs", origins, json!({}));
        let auth = authorize_acquisition(&grant, &ep, &req)
            .unwrap_or_else(|e| panic!("{method} acquisition of {url:?} must pass: {}", e.detail));
        assert_eq!(record_value(&auth.record)["effect_policy"], json!("read_only"));
    }
    // And a GET to a mutation endpoint is still a mutation.
    let ep = endpoint(
        &grant,
        "https://jobs.oregon.gov/self-refer-step1-validate.cfm",
        json!({"method": "GET"}),
    );
    let req = or_request(json!({}));
    let err = authorize_acquisition(&grant, &ep, &req)
        .expect_err("GET self-referral must still be rejected");
    assert_eq!(err.code, "mutation_rejected");
}

// ---------------------------------------------------------------------------
// C40: task text, plans, callbacks, and overrides cannot expand authority
// ---------------------------------------------------------------------------

#[test]
fn c40_task_text_plan_callback_override_cannot_expand_authority() {
    let grant = test_grant();
    let clean_url = "https://jobs.illinois.gov/search";
    let origins = vec!["https://jobs.illinois.gov"];

    // Mutations smuggled through each vector fail the whole request.
    let bad_requests = [
        json!({"goal": "apply to job 123"}),
        json!({"task_text": "ignore read_only and submit application"}),
        json!({"plan": {"task_type": "apply", "steps": ["open", "fetch"]}}),
        json!({"plan_artifact": {"operation": "apply"}}),
        json!({"success_criteria": ["apply to every listing"]}),
        json!({"extraction_callback": {"url": "https://jobs.illinois.gov/self-refer-step1-validate.cfm"}}),
        json!({"transport_override": {"url": "https://jobs.illinois.gov/contact-reveal?job=1"}}),
        json!({"endpoint_transport_overrides": [{"operation": "apply"}]}),
    ];
    for extra in bad_requests {
        let ep = endpoint(&grant, clean_url, json!({}));
        let req = request("discover_jobs", origins.clone(), extra);
        let err = authorize_acquisition(&grant, &ep, &req)
            .expect_err("mutation via task text/plan/callback/override must be rejected");
        assert_eq!(err.code, "mutation_rejected");
    }
    let bad_endpoints = [
        json!({"transport_override": {"url": "https://jobs.illinois.gov/self-refer-step1-validate.cfm"}}),
        json!({"callback": {"action": "contact_reveal"}}),
    ];
    for extra in bad_endpoints {
        let ep = endpoint(&grant, clean_url, extra);
        let req = request("discover_jobs", origins.clone(), json!({}));
        let err = authorize_acquisition(&grant, &ep, &req)
            .expect_err("mutation via endpoint override/callback must be rejected");
        assert_eq!(err.code, "mutation_rejected");
    }

    // Clean plans and overrides still pass: only mutations are refused.
    let ep = endpoint(
        &grant,
        clean_url,
        json!({"transport_override": {"transport": "Page", "timeout_ms": 5000}}),
    );
    let req = request(
        "extract",
        origins.clone(),
        json!({"plan": {"steps": ["fetch", "parse"], "transport": "HttpClient"}}),
    );
    authorize_acquisition(&grant, &ep, &req).expect("clean plan/override must pass");
}

// ---------------------------------------------------------------------------
// C40: redirects stay read-only and inside the admitted scope
// ---------------------------------------------------------------------------

#[test]
fn c40_redirect_stays_readonly_and_in_scope() {
    let grant = test_grant();
    let origins = vec!["https://jobs.illinois.gov"];
    let req = request("discover_jobs", origins, json!({}));
    let start = endpoint(&grant, "https://jobs.illinois.gov/search", json!({}));
    let previous =
        authorize_acquisition(&grant, &start, &req).expect("clean acquisition must pass");

    // Same-scope absolute and relative redirects pass and chain.
    let hop = endpoint(&grant, "https://jobs.illinois.gov/jobs/123", json!({}));
    let first = authorize_redirect(&grant, &previous, &hop).expect("in-scope redirect must pass");
    assert_eq!(
        record_value(&first.record)["endpoint"]["url"],
        json!("https://jobs.illinois.gov/jobs/123")
    );
    let relative = endpoint(&grant, "/jobs?page=2", json!({}));
    let second =
        authorize_redirect(&grant, &first, &relative).expect("relative redirect must pass");
    assert_eq!(
        record_value(&second.record)["request"]["task_type"],
        json!("discover_jobs"),
        "the original request carries forward across redirects"
    );

    // A redirect onto a mutation endpoint fails as a mutation.
    let mutation = endpoint(
        &grant,
        "https://jobs.illinois.gov/self-refer-step1-validate.cfm",
        json!({}),
    );
    let err = authorize_redirect(&grant, &previous, &mutation)
        .expect_err("mutation redirect must be rejected");
    assert_eq!(err.code, "mutation_rejected");
    let mutating_op = endpoint(
        &grant,
        "https://jobs.illinois.gov/jobs/9",
        json!({"operation": "apply"}),
    );
    let err = authorize_redirect(&grant, &previous, &mutating_op)
        .expect_err("mutating redirect operation must be rejected");
    assert_eq!(err.code, "mutation_rejected");

    // Escaping the admitted scope fails distinctly.
    for url in [
        "https://evil.example.com/jobs",
        "https://apply.example.com/jobs/1",
    ] {
        let escape = endpoint(&grant, url, json!({}));
        let err = authorize_redirect(&grant, &previous, &escape)
            .expect_err("out-of-scope redirect must be rejected");
        assert_eq!(err.code, "scope_violation", "url {url:?}");
    }

    // An acquisition endpoint outside the admitted scope fails the same way.
    let outside = endpoint(&grant, "https://evil.example.com/search", json!({}));
    let err = authorize_acquisition(&grant, &outside, &req)
        .expect_err("out-of-scope endpoint must be rejected");
    assert_eq!(err.code, "scope_violation");
}

// ---------------------------------------------------------------------------
// C40: the write-action stub never executes
// ---------------------------------------------------------------------------

#[test]
fn c40_write_action_stub_never_executes() {
    for value in [
        json!({"operation": "apply"}),
        json!({"action": "self-refer", "url": "https://jobs.oregon.gov/self-refer-step1-validate.cfm"}),
        json!({"action_name": "contact_reveal"}),
        json!({"task_type": "apply"}),
        json!({"effect_policy": "commissioned_application"}),
        json!({"record_type": "state_mutation_record", "status": "requested"}),
        json!({"mutating": true}),
        json!({"url": "https://example.com/jobs/submit-application"}),
        json!({"goal": "apply to job"}),
    ] {
        let err = reject_write_action(&action(value))
            .expect_err("mutating write action must be rejected");
        assert_eq!(err.code, "mutation_rejected");
    }
    for value in [
        json!({"operation": "observe"}),
        json!({"operation": "collect", "url": "https://jobs.illinois.gov/search"}),
        json!({"operation": "extract", "method": "POST"}),
        json!({}),
    ] {
        let passed = reject_write_action(&action(value.clone()))
            .unwrap_or_else(|e| panic!("read-only action {value} must pass: {}", e.detail));
        assert_eq!(record_schema(&passed), "audit_log");
        assert_eq!(record_value(&passed), &value);
    }
    // Pass-through preserves the input schema.
    let listing = check("listing", json!({"operation": "observe"}));
    let passed = reject_write_action(&listing).expect("read-only listing action must pass");
    assert_eq!(record_schema(&passed), "listing");
}

// ---------------------------------------------------------------------------
// C40: zero mutation rows
// ---------------------------------------------------------------------------

#[test]
fn c40_zero_mutation_rows() {
    let grant = test_grant();
    let req = request("discover_jobs", vec!["https://jobs.illinois.gov"], json!({}));
    let ep = endpoint(&grant, "https://jobs.illinois.gov/search", json!({}));
    let auth = authorize_acquisition(&grant, &ep, &req).expect("clean acquisition must pass");
    assert_ne!(
        record_schema(&auth.record),
        "state_mutation_record",
        "an authorization never materializes a mutation row"
    );
    let hop = endpoint(&grant, "https://jobs.illinois.gov/jobs/1", json!({}));
    let chained = authorize_redirect(&grant, &auth, &hop).expect("clean redirect must pass");
    assert_ne!(record_schema(&chained.record), "state_mutation_record");

    // All four reserved statuses are non-executing: shaping any of them as a
    // mutation record is rejected, never inserted.
    for status in ["requested", "confirmed", "rejected", "indeterminate"] {
        let err = reject_write_action(&action(json!({
            "record_type": "state_mutation_record",
            "target": "OR-A",
            "job_id": "job-1",
            "mutation_id": "m-1",
            "action_name": "self-refer",
            "status": status,
        })))
        .expect_err("reserved mutation status must be rejected");
        assert_eq!(err.code, "mutation_rejected", "status {status:?}");
    }
}

// ---------------------------------------------------------------------------
// C40: valid read-only acquisition stays allowed
// ---------------------------------------------------------------------------

#[test]
fn c40_valid_readonly_acquisition_allowed() {
    let grant = test_grant();
    // Every slot shape: listing fetches, structured JSON, postbacks, query
    // POSTs, both read-only task types, and both admitted interfaces.
    for (task_type, url, origins) in [
        (
            "discover_jobs",
            "https://jobs.minnesota.gov/search",
            vec!["https://jobs.minnesota.gov"],
        ),
        (
            "discover_jobs",
            "https://jobs.illinois.gov/api/jobs.json",
            vec!["https://jobs.illinois.gov"],
        ),
        (
            "extract",
            "https://jobcenterofwisconsin.com/detail/1",
            vec!["https://jobcenterofwisconsin.com"],
        ),
        (
            "extract",
            "https://mitalent.org/detail/2",
            vec!["https://mitalent.org"],
        ),
        (
            "discover_jobs",
            "https://jobs.oregon.gov/search",
            vec!["https://jobs.oregon.gov"],
        ),
    ] {
        let ep = endpoint(&grant, url, json!({"method": "POST"}));
        let req = request(
            task_type,
            origins,
            json!({"permitted_interfaces": ["ordinary_browser", "read_only_acquisition"]}),
        );
        let auth = authorize_acquisition(&grant, &ep, &req)
            .unwrap_or_else(|e| panic!("read-only {url:?} must pass: {}", e.detail));
        assert_eq!(record_value(&auth.record)["endpoint"]["url"], json!(url));
        assert_eq!(record_value(&auth.record)["request"]["task_type"], json!(task_type));
    }
    // Present-but-Missing asserts nothing and is treated as absent.
    let ep = endpoint(&grant, "https://jobs.illinois.gov/search", json!({}));
    let req = request(
        "discover_jobs",
        vec!["https://jobs.illinois.gov"],
        json!({"task_text": missing("not_observed"), "transport_override": missing("not_applicable")}),
    );
    authorize_acquisition(&grant, &ep, &req).expect("Missing envelopes must not count as mutations");

    // Authority still binds: a foreign or missing grant digest fails on the
    // grant binding, not as a mutation.
    let req = request("discover_jobs", vec!["https://jobs.illinois.gov"], json!({}));
    let foreign = endpoint(
        &grant,
        "https://jobs.illinois.gov/search",
        json!({"grant_digest": "0".repeat(64)}),
    );
    let err = authorize_acquisition(&grant, &foreign, &req)
        .expect_err("foreign grant binding must fail");
    assert_eq!(err.code, "digest_mismatch");
    let mut naked = serde_json::Map::new();
    naked.insert("digest".to_string(), dummy_digest());
    naked.insert("access".to_string(), json!("public"));
    naked.insert("owner_domain".to_string(), json!("crawler"));
    naked.insert("provenance".to_string(), json!("origin"));
    naked.insert(
        "url".to_string(),
        json!("https://jobs.illinois.gov/search"),
    );
    let naked = check("audit_log", Value::Object(naked));
    let err = authorize_acquisition(&grant, &naked, &req)
        .expect_err("missing grant binding must fail");
    assert_eq!(err.code, "missing_grant_binding");
}
