//! Conformance tests for [C06]: authority.
//!
//! Caller provenance/owner spoof rejected; imported evidence not upgraded.

use crawler_authority::{
    authorize, authorize_producer, authorize_reference, grant_record,
};
use crawler_hashing::{canonical_bytes, digest_bytes};
use crawler_schema::{CheckedRecord, record_value, validate};
use serde_json::{Value, json};

fn check(schema: &str, value: Value) -> CheckedRecord {
    validate(schema, value).expect("test fixture must validate")
}

fn missing(reason: &str) -> Value {
    json!({"value": Value::Null, "reason": reason})
}

/// Digest binding a principal/reference to the exact bytes of a record.
fn binding_of(record: &CheckedRecord) -> String {
    digest_bytes(&canonical_bytes(record).expect("canonical bytes must exist"))
}

fn manifest_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "manifest_id": "manifest-1",
            "producer_registry": [
                {
                    "producer_id": "origin-crawler",
                    "owner_domain": "crawler",
                    "role": "crawler_producer",
                    "provenance": "origin",
                    "assertion_kind": "observation",
                },
                {
                    "producer_id": "history-importer",
                    "owner_domain": "import",
                    "role": "import_producer",
                    "provenance": "imported",
                    "assertion_kind": "observation",
                },
            ],
            "event_registry": [
                {
                    "event_kind": "listing_observed",
                    "permitted_provenance": ["origin"],
                },
                {
                    "event_kind": "history_imported",
                    "permitted_provenance": ["origin", "imported"],
                },
            ],
        }),
    )
}

fn producer_principal(manifest: &CheckedRecord, producer_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "producer_id": producer_id,
            "manifest_digest": binding_of(manifest),
        }),
    )
}

fn registration_fixture() -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "registration_id": "channel-1",
            "principals": [
                {
                    "principal_id": "reader",
                    "verbs": ["Describe", "Prepare", "Observe", "CollectArtifacts"],
                    "connectors": ["jobs-connector"],
                    "control": false,
                    "owner_domain": "crawler",
                    "restricted_access": false,
                },
                {
                    "principal_id": "driver",
                    "verbs": ["Describe", "Prepare", "Start", "Observe", "RequestNativeCancel", "CloseObservationConnection", "CollectArtifacts", "ReleaseNativeContext", "Contain"],
                    "connectors": ["jobs-connector"],
                    "control": false,
                    "owner_domain": "crawler",
                    "restricted_access": false,
                },
                {
                    "principal_id": "operator",
                    "verbs": ["Describe", "Prepare", "Start", "Observe", "RequestNativeCancel", "CloseObservationConnection", "CollectArtifacts", "ReleaseNativeContext", "Contain"],
                    "connectors": ["jobs-connector", "admin-connector"],
                    "control": true,
                    "owner_domain": "crawler",
                    "restricted_access": true,
                },
            ],
        }),
    )
}

fn connector_principal(registration: &CheckedRecord, principal_id: &str) -> CheckedRecord {
    check(
        "audit_log",
        json!({
            "principal_id": principal_id,
            "registration_digest": binding_of(registration),
        }),
    )
}

fn origin_grant() -> crawler_authority::Grant {
    let manifest = manifest_fixture();
    let principal = producer_principal(&manifest, "origin-crawler");
    let submission = check(
        "audit_log",
        json!({"event_kind": "listing_observed", "payload": {"evidence_scope": "current"}}),
    );
    authorize_producer(&principal, &submission, &manifest).expect("origin grant must issue")
}

// ---------------------------------------------------------------------------
// Producer ingestion: spoof rejection
// ---------------------------------------------------------------------------

#[test]
fn c06_producer_spoofed_server_fields_rejected() {
    let manifest = manifest_fixture();
    let principal = producer_principal(&manifest, "origin-crawler");
    // Every server/provenance/authority field is rejected when submitted.
    for (field, value) in [
        ("owner_domain", json!("crawler")),
        ("producer_id", json!("origin-crawler")),
        ("provenance", json!("origin")),
        ("role", json!("crawler_producer")),
        ("assertion_kind", json!("observation")),
        ("journal_sequence", json!(7)),
        ("event_id", json!("event-7")),
        ("event_hash", json!("ab")),
        ("previous_event_hash", json!("cd")),
        ("producer_sequence", json!(3)),
        ("recorded_at", json!("2026-01-01T00:00:00Z")),
        ("manifest_hash", json!("ef")),
    ] {
        let mut submission = serde_json::Map::new();
        submission.insert("event_kind".to_string(), json!("listing_observed"));
        submission.insert(field.to_string(), value);
        let submission = check("audit_log", Value::Object(submission));
        let err = authorize_producer(&principal, &submission, &manifest)
            .expect_err("submitted authority field must be rejected");
        assert_eq!(err.code, "spoofed_authority_field", "field {field:?}");
    }
}

#[test]
fn c06_producer_missing_envelope_is_not_a_spoof() {
    let manifest = manifest_fixture();
    let principal = producer_principal(&manifest, "origin-crawler");
    // Present-but-Missing asserts nothing and passes the spoof check.
    let submission = check(
        "audit_log",
        json!({
            "event_kind": "listing_observed",
            "owner_domain": missing("not_applicable"),
            "payload": {"evidence_scope": "current"},
        }),
    );
    let grant = authorize_producer(&principal, &submission, &manifest)
        .expect("Missing envelope must not count as a spoofed value");
    assert_eq!(record_value(grant_record(&grant))["owner_domain"], json!("crawler"));
}

#[test]
fn c06_producer_grant_derives_authority_from_registry() {
    let manifest = manifest_fixture();
    let principal = producer_principal(&manifest, "history-importer");
    let submission = check(
        "audit_log",
        json!({"event_kind": "history_imported", "payload": {}}),
    );
    let grant = authorize_producer(&principal, &submission, &manifest).expect("grant must issue");
    let record = record_value(grant_record(&grant));
    assert_eq!(record["producer_id"], json!("history-importer"));
    assert_eq!(record["owner_domain"], json!("import"));
    assert_eq!(record["role"], json!("import_producer"));
    assert_eq!(record["provenance"], json!("imported"));
    assert_eq!(record["assertion_kind"], json!("observation"));
    assert_eq!(record["event_kind"], json!("history_imported"));
}

#[test]
fn c06_producer_registration_and_binding_enforced() {
    let manifest = manifest_fixture();
    let submission = check("audit_log", json!({"event_kind": "listing_observed"}));

    // Unknown producer.
    let ghost = producer_principal(&manifest, "ghost");
    let err = authorize_producer(&ghost, &submission, &manifest).expect_err("ghost must fail");
    assert_eq!(err.code, "unregistered_producer");

    // Principal bound to a different manifest.
    let other = check("audit_log", json!({"manifest_id": "other", "producer_registry": []}));
    let stale = producer_principal(&other, "origin-crawler");
    let err = authorize_producer(&stale, &submission, &manifest).expect_err("stale binding must fail");
    assert_eq!(err.code, "digest_mismatch");

    // Malformed binding digest.
    let bad_binding = check(
        "audit_log",
        json!({"producer_id": "origin-crawler", "manifest_digest": "not-a-digest"}),
    );
    let err = authorize_producer(&bad_binding, &submission, &manifest)
        .expect_err("malformed binding must fail");
    assert_eq!(err.code, "invalid_expected_digest");

    // Unregistered event kind.
    let principal = producer_principal(&manifest, "origin-crawler");
    let bad_kind = check("audit_log", json!({"event_kind": "apply_submitted"}));
    let err = authorize_producer(&principal, &bad_kind, &manifest).expect_err("unknown kind must fail");
    assert_eq!(err.code, "unregistered_event_kind");
}

#[test]
fn c06_producer_imported_evidence_not_upgraded() {
    let manifest = manifest_fixture();
    let importer = producer_principal(&manifest, "history-importer");

    // Imported producer cannot submit an origin-only event kind.
    let origin_only = check("audit_log", json!({"event_kind": "listing_observed"}));
    let err = authorize_producer(&importer, &origin_only, &manifest)
        .expect_err("imported producer must not take the origin path");
    assert_eq!(err.code, "provenance_upgrade_refused");

    // Imported producer cannot claim current origin scope in the payload
    // even for an event kind that admits imported provenance.
    for payload in [
        json!({"evidence_scope": "current"}),
        json!({"origin_assertion": true}),
    ] {
        let submission = check(
            "audit_log",
            json!({"event_kind": "history_imported", "payload": payload}),
        );
        let err = authorize_producer(&importer, &submission, &manifest)
            .expect_err("origin-scope claim by an importer must fail");
        assert_eq!(err.code, "provenance_upgrade_refused");
    }

    // The origin producer on the same inputs succeeds.
    let origin = producer_principal(&manifest, "origin-crawler");
    authorize_producer(&origin, &origin_only, &manifest).expect("origin producer must succeed");
    let scoped = check(
        "audit_log",
        json!({"event_kind": "history_imported", "payload": {"evidence_scope": "current"}}),
    );
    authorize_producer(&origin, &scoped, &manifest).expect("origin scope claim must succeed");
}

// ---------------------------------------------------------------------------
// Connector intake: spoof rejection and grants
// ---------------------------------------------------------------------------

#[test]
fn c06_connector_spoofed_identity_rejected() {
    let registration = registration_fixture();
    let principal = connector_principal(&registration, "reader");
    for (field, value) in [
        ("principal_id", json!("operator")),
        ("caller", json!("operator")),
        ("caller_identity", json!("operator")),
        ("grants", json!(["Contain"])),
        ("grant", json!("all")),
        ("authorized", json!(true)),
        ("owner_domain", json!("crawler")),
        ("provenance", json!("origin")),
        ("control", json!(true)),
        ("control_authority", json!(true)),
        ("restricted_access", json!(true)),
        ("registration_digest", json!("00")),
    ] {
        let mut request = serde_json::Map::new();
        request.insert("verb".to_string(), json!("Observe"));
        request.insert("connector".to_string(), json!("jobs-connector"));
        request.insert(field.to_string(), value);
        let request = check("audit_log", Value::Object(request));
        let err = authorize(&principal, &request, &registration)
            .expect_err("caller-supplied authority must be rejected");
        assert_eq!(err.code, "spoofed_authority_field", "field {field:?}");
    }
}

#[test]
fn c06_connector_verb_and_connector_grants_enforced() {
    let registration = registration_fixture();
    let reader = connector_principal(&registration, "reader");

    // Granted verb + connector succeeds and derives the grant.
    let ok = check(
        "audit_log",
        json!({"verb": "Observe", "connector": "jobs-connector", "subject": "jobs"}),
    );
    let grant = authorize(&reader, &ok, &registration).expect("granted request must succeed");
    let record = record_value(grant_record(&grant));
    assert_eq!(record["principal_id"], json!("reader"));
    assert_eq!(record["verb"], json!("Observe"));
    assert_eq!(record["connector"], json!("jobs-connector"));
    assert_eq!(record["owner_domain"], json!("crawler"));

    // Tenth verb does not exist.
    let tenth = check(
        "audit_log",
        json!({"verb": "Execute", "connector": "jobs-connector"}),
    );
    let err = authorize(&reader, &tenth, &registration).expect_err("tenth verb must fail");
    assert_eq!(err.code, "unknown_verb");

    // Known but ungranted verb.
    let ungranted = check(
        "audit_log",
        json!({"verb": "Start", "connector": "jobs-connector"}),
    );
    let err = authorize(&reader, &ungranted, &registration).expect_err("ungranted verb must fail");
    assert_eq!(err.code, "verb_not_granted");

    // Ungranted connector.
    let foreign = check(
        "audit_log",
        json!({"verb": "Observe", "connector": "admin-connector"}),
    );
    let err = authorize(&reader, &foreign, &registration).expect_err("foreign connector must fail");
    assert_eq!(err.code, "connector_not_granted");

    // Unregistered principal.
    let ghost = connector_principal(&registration, "ghost");
    let err = authorize(&ghost, &ok, &registration).expect_err("ghost principal must fail");
    assert_eq!(err.code, "unregistered_principal");

    // Stale registration binding.
    let other = check("audit_log", json!({"registration_id": "other", "principals": []}));
    let stale = connector_principal(&other, "reader");
    let err = authorize(&stale, &ok, &registration).expect_err("stale binding must fail");
    assert_eq!(err.code, "digest_mismatch");
}

#[test]
fn c06_connector_control_requires_explicit_grant() {
    let registration = registration_fixture();
    // The driver holds every verb grant but no control grant, isolating the
    // control check from verb authorization.
    let driver = connector_principal(&registration, "driver");
    let operator = connector_principal(&registration, "operator");

    // Credentials, digests, identifiers, and HTTP success do not confer
    // control: every control verb fails for the driver even when the
    // request carries them.
    for verb in ["Contain", "RequestNativeCancel", "ReleaseNativeContext"] {
        let request = check(
            "audit_log",
            json!({
                "verb": verb,
                "connector": "jobs-connector",
                "application_credential": "user-password",
                "bearer_token": "tok-123",
                "task_digest": "0".repeat(64),
                "http_status": 200,
            }),
        );
        let err = authorize(&driver, &request, &registration)
            .expect_err("control without a grant must fail");
        assert_eq!(err.code, "control_not_granted", "verb {verb:?}");
    }

    // The operator holds the explicit control grant and succeeds.
    let request = check(
        "audit_log",
        json!({"verb": "Contain", "connector": "admin-connector"}),
    );
    let grant = authorize(&operator, &request, &registration).expect("operator control must succeed");
    assert_eq!(record_value(grant_record(&grant))["control"], json!(true));
}

// ---------------------------------------------------------------------------
// Reference exercise: binding, owner, access, provenance
// ---------------------------------------------------------------------------

fn reference_fixture(grant: &crawler_authority::Grant, patch: Value) -> CheckedRecord {
    let mut base = serde_json::Map::new();
    base.insert(
        "grant_digest".to_string(),
        Value::String(binding_of(grant_record(grant))),
    );
    base.insert("digest".to_string(), Value::String("a".repeat(64)));
    base.insert("owner_domain".to_string(), json!("crawler"));
    base.insert("provenance".to_string(), json!("origin"));
    base.insert("access".to_string(), json!("public"));
    if let Value::Object(extra) = patch {
        for (key, value) in extra {
            base.insert(key, value);
        }
    }
    check("audit_log", Value::Object(base))
}

#[test]
fn c06_reference_binding_and_access_enforced() {
    let grant = origin_grant();

    // Public read under the bound grant succeeds.
    let reference = reference_fixture(&grant, json!({}));
    authorize_reference(&grant, &reference, "read").expect("bound public read must succeed");
    authorize_reference(&grant, &reference, "collect").expect("bound collect must succeed");

    // A reference naming a different grant fails: the digest alone is not
    // bearer authority. The importer grant is a distinct record, so its
    // digest cannot satisfy this grant's binding.
    let manifest = manifest_fixture();
    let importer = producer_principal(&manifest, "history-importer");
    let import_submission = check("audit_log", json!({"event_kind": "history_imported"}));
    let other = authorize_producer(&importer, &import_submission, &manifest)
        .expect("importer grant must issue");
    let foreign = reference_fixture(&other, json!({}));
    let err = authorize_reference(&grant, &foreign, "read").expect_err("foreign binding must fail");
    assert_eq!(err.code, "digest_mismatch");

    // Missing binding fails closed.
    let unbound = check(
        "audit_log",
        json!({
            "digest": "a".repeat(64),
            "owner_domain": "crawler",
            "provenance": "origin",
            "access": "public",
        }),
    );
    let err = authorize_reference(&grant, &unbound, "read").expect_err("unbound ref must fail");
    assert_eq!(err.code, "missing_grant_binding");

    // Restricted access requires the explicit grant flag. The producer
    // grant carries none, so restricted reads fail.
    let restricted = reference_fixture(&grant, json!({"access": "restricted"}));
    let err = authorize_reference(&grant, &restricted, "read").expect_err("restricted must fail");
    assert_eq!(err.code, "access_denied");

    // A connector grant carrying restricted_access succeeds.
    let registration = registration_fixture();
    let operator = connector_principal(&registration, "operator");
    let request = check(
        "audit_log",
        json!({"verb": "CollectArtifacts", "connector": "jobs-connector"}),
    );
    let privileged = authorize(&operator, &request, &registration).expect("operator grant must issue");
    let restricted = reference_fixture(&privileged, json!({"access": "restricted"}));
    authorize_reference(&privileged, &restricted, "read").expect("privileged read must succeed");

    // Malformed content digest is rejected, not trusted.
    let bad_digest = reference_fixture(&grant, json!({"digest": "not-a-digest"}));
    let err = authorize_reference(&grant, &bad_digest, "read").expect_err("bad digest must fail");
    assert_eq!(err.code, "invalid_digest");

    // Unknown operation.
    let err = authorize_reference(&grant, &reference, "delete").expect_err("unknown op must fail");
    assert_eq!(err.code, "unknown_operation");
}

#[test]
fn c06_reference_publish_owner_and_origin_enforced() {
    let grant = origin_grant();

    // Origin content inside the grant owner domain publishes.
    let reference = reference_fixture(&grant, json!({}));
    authorize_reference(&grant, &reference, "publish").expect("owner publish must succeed");
    authorize_reference(&grant, &reference, "assert_origin").expect("origin assertion must succeed");

    // Publication outside the grant owner domain is rejected.
    let foreign_owner = reference_fixture(&grant, json!({"owner_domain": "product"}));
    let err = authorize_reference(&grant, &foreign_owner, "publish").expect_err("foreign owner must fail");
    assert_eq!(err.code, "owner_mismatch");

    // Imported evidence is never upgraded: it cannot publish as
    // owner-authored content nor be asserted as an origin fact.
    let imported = reference_fixture(&grant, json!({"provenance": "imported"}));
    let err = authorize_reference(&grant, &imported, "publish").expect_err("imported publish must fail");
    assert_eq!(err.code, "provenance_upgrade_refused");
    let err = authorize_reference(&grant, &imported, "assert_origin")
        .expect_err("imported origin assertion must fail");
    assert_eq!(err.code, "provenance_upgrade_refused");

    // Reading imported evidence is fine; only the upgrade is refused.
    authorize_reference(&grant, &imported, "read").expect("imported read must succeed");
}
