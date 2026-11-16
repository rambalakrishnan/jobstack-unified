//! RM-C53 conformance: practice evidence imported into production is never
//! promoted into current production evidence, and the surrounding authority
//! boundary (channel authentication, work/owner authorization, attempt scope)
//! holds.
//!
//! Every test name contains `rm_c53` so the verification filter
//! `cargo test -p rm_authority -- rm_c53` selects the whole suite.

use rm_authority::*;
use serde_json::json;
use std::io::Cursor;

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn channel_bytes(value: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("test JSON must serialize")
}

fn channel_for(principal: &str) -> Cursor<Vec<u8>> {
    Cursor::new(channel_bytes(json!({
        "principal_id": principal,
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": format!("binding-{principal}"),
        },
    })))
}

fn principal_for(name: &str) -> AuthenticatedPrincipal {
    authenticate_channel(&mut channel_for(name)).expect("valid registration must authenticate")
}

fn digest_of(bytes: &[u8]) -> String {
    rm_wire::canonical_digest(bytes)
        .expect("test bytes must hash")
        .as_str()
        .to_owned()
}

fn semantic_hash() -> String {
    digest_of(br#"{"goal":"apply"}"#)
}

fn valid_manifest() -> Manifest {
    Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: "run-1".to_string(),
        task: json!({"activity": "apply", "entry": {"logical_id": "entry-1"}}),
        subject: json!({"subject_id": "subject-1"}),
        event_kinds: vec![
            "execution_claim".to_string(),
            "origin_fact".to_string(),
            "report_published".to_string(),
        ],
        admission_ref: "admission-1".to_string(),
        manifest_hash: String::new(),
    }
}

/// A manifest whose `manifest_hash` covers its wire bytes.
fn admitted_manifest() -> Manifest {
    let bare = valid_manifest();
    let hash = digest_of(&manifest_wire_bytes(&bare));
    Manifest {
        manifest_hash: hash,
        ..bare
    }
}

fn production_commission(manifest: &Manifest) -> AttemptCommission {
    AttemptCommission {
        record_type: "attempt_commission".to_string(),
        schema_version: "application-attempt-lifecycle/0.1.0".to_string(),
        commission_id: "commission-prod-1".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id: "journal-1".to_string(),
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: "attempt-prod-1".to_string(),
        kind: AttemptKind::Production,
        target_class: TargetClass::Employer,
        evaluation_partition: EvaluationPartition::HeldOut,
        target_id: "employer-1".to_string(),
        derived_from: Vec::new(),
        rehearsal_of: None,
        performance_of: None,
        task_semantic_hash: semantic_hash(),
        idempotency_key: "idem-prod-1".to_string(),
        imported_evidence: Vec::new(),
    }
}

fn practice_commission(manifest: &Manifest) -> AttemptCommission {
    AttemptCommission {
        commission_id: "commission-practice-1".to_string(),
        attempt_id: "attempt-practice-1".to_string(),
        kind: AttemptKind::Practice,
        target_class: TargetClass::Fixture,
        evaluation_partition: EvaluationPartition::HeldIn,
        target_id: "fixture-1".to_string(),
        idempotency_key: "idem-practice-1".to_string(),
        ..production_commission(manifest)
    }
}

fn practice_import(claimed_provenance: &str) -> EvidenceImport {
    let digest = digest_of(br##"{"selector":"#apply","confidence":0.9}"##);
    EvidenceImport {
        source_attempt_id: "attempt-practice-1".to_string(),
        source_kind: AttemptKind::Practice,
        source_digest: digest.clone(),
        claimed_provenance: claimed_provenance.to_string(),
        retained_bytes_digest: digest,
    }
}

fn apply_scope(owner: &str) -> WorkScope {
    WorkScope {
        activity: "apply".to_string(),
        run_id: "run-1".to_string(),
        journal_id: "journal-1".to_string(),
        manifest_hash: semantic_hash(),
        admission_ref: "admission-1".to_string(),
        attempt_id: Some("attempt-prod-1".to_string()),
        commission_id: Some("commission-prod-1".to_string()),
        commission_ref: Some("commission-ref-1".to_string()),
        attempt_kind: Some(AttemptKind::Production),
        authorization_refs: vec!["task:apply-1".to_string()],
        observation_policy: "bounded".to_string(),
        owner_domain: owner.to_string(),
        execution_mode: ExecutionMode::Automated,
    }
}

fn operation(verb: &str) -> Operation {
    Operation {
        verb: verb.to_string(),
        connector_id: "ringmaster".to_string(),
        subject_id: "subject-1".to_string(),
        task_scope: "apply".to_string(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    }
}

// ---------------------------------------------------------------------------
// channel authentication
// ---------------------------------------------------------------------------

#[test]
fn rm_c53_authenticate_channel_binds_identity_to_registration() {
    let bytes = channel_bytes(json!({
        "principal_id": "op-1",
        "channel_binding": {"mechanism": "mtls", "binding": "cert-fingerprint-1"},
    }));
    let expected = digest_of(&bytes);
    let mut channel = Cursor::new(bytes);
    let principal =
        authenticate_channel(&mut channel).expect("authenticated registration must succeed");
    assert_eq!(principal.principal_id(), "op-1");
    assert_eq!(principal.registration_digest().as_str(), expected);

    // Each insufficient credential alone is rejected: request ID, source
    // address, bare digest, serialized roles, application credential, and a
    // bare principal ID without channel binding.
    let bare_digest = semantic_hash();
    let insufficient = vec![
        json!({"request_id": "req-1", "principal_id": "op-1"}),
        json!({"source_address": "10.0.0.9", "principal_id": "op-1"}),
        json!({"digest": bare_digest, "principal_id": "op-1"}),
        json!({"roles": ["admin"], "principal_id": "op-1"}),
        json!({"credential": "app-token-1", "principal_id": "op-1"}),
        json!({"principal_id": "op-1"}),
        json!({
            "principal_id": "op-1",
            "channel_binding": {"mechanism": "self-asserted", "binding": "trust-me"},
        }),
        json!({
            "principal_id": "op-1",
            "channel_binding": {"mechanism": "mtls", "binding": ""},
        }),
    ];
    for candidate in insufficient {
        let mut channel = Cursor::new(channel_bytes(candidate.clone()));
        let err = authenticate_channel(&mut channel)
            .expect_err("insufficient registration must be rejected");
        assert_eq!(err.kind, "connector_error");
        assert_eq!(err.code, "UNAUTHENTICATED", "candidate: {candidate}");
    }

    // In-band nulls, non-objects, invalid JSON, and empty channels fail.
    for raw in [
        channel_bytes(json!({"principal_id": "op-1", "note": None::<&str>})),
        channel_bytes(json!(["principal_id"])),
        b"{not json".to_vec(),
        Vec::new(),
    ] {
        let mut channel = Cursor::new(raw);
        let err =
            authenticate_channel(&mut channel).expect_err("malformed channel must be rejected");
        assert_eq!(err.code, "UNAUTHENTICATED");
    }
}

// ---------------------------------------------------------------------------
// attempt scope coherence
// ---------------------------------------------------------------------------

#[test]
fn rm_c53_verify_accepts_coherent_practice_and_production() {
    let manifest = admitted_manifest();
    verify_attempt_scope(&manifest, &production_commission(&manifest))
        .expect("coherent production commission must verify");
    verify_attempt_scope(&manifest, &practice_commission(&manifest))
        .expect("coherent practice commission must verify");
}

#[test]
fn rm_c53_verify_rejects_kind_target_incoherence() {
    let manifest = admitted_manifest();
    // Practice/employer, production/fixture, and partition mismatches.
    let mutations: Vec<(
        AttemptKind,
        TargetClass,
        EvaluationPartition,
    )> = vec![
        (
            AttemptKind::Practice,
            TargetClass::Employer,
            EvaluationPartition::HeldOut,
        ),
        (
            AttemptKind::Production,
            TargetClass::Fixture,
            EvaluationPartition::HeldIn,
        ),
        (
            AttemptKind::Practice,
            TargetClass::Fixture,
            EvaluationPartition::HeldOut,
        ),
        (
            AttemptKind::Production,
            TargetClass::Employer,
            EvaluationPartition::HeldIn,
        ),
    ];
    for (kind, target, partition) in mutations {
        let mut commission = production_commission(&manifest);
        commission.kind = kind;
        commission.target_class = target;
        commission.evaluation_partition = partition;
        let err = verify_attempt_scope(&manifest, &commission)
            .expect_err("incoherent kind/target/partition must be rejected");
        assert_eq!(err.kind, "connector_error");
        assert_eq!(err.code, "NOT_ADMITTED");
    }
}

#[test]
fn rm_c53_verify_rejects_admission_binding_mismatch() {
    let manifest = admitted_manifest();

    let mut commission = production_commission(&manifest);
    commission.admission_ref = "admission-other".to_string();
    assert_eq!(
        verify_attempt_scope(&manifest, &commission)
            .expect_err("admission mismatch must fail")
            .code,
        "NOT_ADMITTED"
    );

    let mut commission = production_commission(&manifest);
    commission.manifest_hash = semantic_hash();
    assert_eq!(
        verify_attempt_scope(&manifest, &commission)
            .expect_err("manifest binding mismatch must fail")
            .code,
        "NOT_ADMITTED"
    );

    let mut commission = production_commission(&manifest);
    commission.run_id = "run-other".to_string();
    assert_eq!(
        verify_attempt_scope(&manifest, &commission)
            .expect_err("run mismatch must fail")
            .code,
        "NOT_ADMITTED"
    );

    // Tampering with admitted manifest bytes after hashing is detected.
    let mut tampered = manifest.clone();
    tampered.run_id = "run-tampered".to_string();
    let commission = production_commission(&manifest);
    assert_eq!(
        verify_attempt_scope(&tampered, &commission)
            .expect_err("tampered manifest must fail")
            .code,
        "NOT_ADMITTED"
    );

    // A manifest wire record carrying a bare null is structurally invalid.
    let mut null_manifest = valid_manifest();
    null_manifest.task = json!({"activity": None::<&str>});
    // Structural validation runs before the hash check, so any well-formed
    // digest reaches the INVALID_REQUEST path.
    null_manifest.manifest_hash = semantic_hash();
    let commission = production_commission(&null_manifest);
    assert_eq!(
        verify_attempt_scope(&null_manifest, &commission)
            .expect_err("null-carrying manifest must fail")
            .code,
        "INVALID_REQUEST"
    );
}

// ---------------------------------------------------------------------------
// RM-C53 core: no promotion of imported practice evidence
// ---------------------------------------------------------------------------

#[test]
fn rm_c53_production_rejects_practice_evidence_promotion() {
    let manifest = admitted_manifest();
    for claimed in [
        PROVENANCE_PRODUCTION_DIRECT,
        PROVENANCE_PRACTICE_DIRECT,
        "curated",
    ] {
        let mut commission = production_commission(&manifest);
        commission.imported_evidence = vec![practice_import(claimed)];
        let err = verify_attempt_scope(&manifest, &commission)
            .expect_err("promoted practice evidence must be rejected");
        assert_eq!(err.kind, "connector_error");
        assert_eq!(err.code, "NOT_ADMITTED", "claimed: {claimed}");
        assert!(
            err.detail.contains("no promotion"),
            "detail must name the rule: {}",
            err.detail
        );
    }
}

#[test]
fn rm_c53_production_accepts_practice_import_as_reference() {
    let manifest = admitted_manifest();
    // The same practice bytes carried as a marked import reference verify.
    let mut commission = production_commission(&manifest);
    commission.imported_evidence = vec![practice_import(PROVENANCE_IMPORTED_PRACTICE)];
    verify_attempt_scope(&manifest, &commission)
        .expect("marked practice import must verify in production");

    // Symmetric case: production bytes referenced from practice stay marked.
    let digest = digest_of(br#"{"origin":"employer-receipt"}"#);
    let mut practice = practice_commission(&manifest);
    practice.imported_evidence = vec![EvidenceImport {
        source_attempt_id: "attempt-prod-9".to_string(),
        source_kind: AttemptKind::Production,
        source_digest: digest.clone(),
        claimed_provenance: PROVENANCE_IMPORTED_PRODUCTION.to_string(),
        retained_bytes_digest: digest,
    }];
    verify_attempt_scope(&manifest, &practice)
        .expect("marked production import must verify in practice");
}

#[test]
fn rm_c53_import_must_preserve_original_bytes() {
    let manifest = admitted_manifest();
    // Retained bytes differing from the source digest: replaced bytes.
    let mut commission = production_commission(&manifest);
    let mut import = practice_import(PROVENANCE_IMPORTED_PRACTICE);
    import.retained_bytes_digest = digest_of(br##"{"selector":"#other"}"##);
    commission.imported_evidence = vec![import];
    assert_eq!(
        verify_attempt_scope(&manifest, &commission)
            .expect_err("byte-replacing import must fail")
            .code,
        "NOT_ADMITTED"
    );

    // Malformed digests are structural failures.
    let mut commission = production_commission(&manifest);
    let mut import = practice_import(PROVENANCE_IMPORTED_PRACTICE);
    import.source_digest = "not-a-digest".to_string();
    import.retained_bytes_digest = "not-a-digest".to_string();
    commission.imported_evidence = vec![import];
    assert_eq!(
        verify_attempt_scope(&manifest, &commission)
            .expect_err("malformed import digest must fail")
            .code,
        "INVALID_REQUEST"
    );
}

#[test]
fn rm_c53_lineage_links_are_never_evidence_promotion() {
    let manifest = admitted_manifest();
    // A production attempt performing against a practice identity verifies
    // with lineage alone: the link is history, not evidence.
    let mut commission = production_commission(&manifest);
    commission.performance_of = Some(LineageRef {
        attempt_id: "attempt-practice-1".to_string(),
        kind: AttemptKind::Practice,
    });
    verify_attempt_scope(&manifest, &commission)
        .expect("lineage-only production commission must verify");

    // But the linked practice attempt's bytes still cannot be claimed as
    // current production evidence through the lineage link.
    let mut promoted = commission.clone();
    promoted.imported_evidence = vec![practice_import(PROVENANCE_PRODUCTION_DIRECT)];
    assert_eq!(
        verify_attempt_scope(&manifest, &promoted)
            .expect_err("lineage-backed promotion must fail")
            .code,
        "NOT_ADMITTED"
    );

    // Referencing the same lineage target as a marked import is fine.
    let mut referenced = commission;
    referenced.imported_evidence = vec![practice_import(PROVENANCE_IMPORTED_PRACTICE)];
    verify_attempt_scope(&manifest, &referenced)
        .expect("lineage plus marked import must verify");

    // Practice rehearsing production verifies symmetrically.
    let mut practice = practice_commission(&manifest);
    practice.rehearsal_of = Some(LineageRef {
        attempt_id: "attempt-prod-1".to_string(),
        kind: AttemptKind::Production,
    });
    verify_attempt_scope(&manifest, &practice)
        .expect("rehearsing practice commission must verify");
}

#[test]
fn rm_c53_lineage_direction_and_same_kind() {
    let manifest = admitted_manifest();

    // Wrong-direction links are rejected.
    let mut practice = practice_commission(&manifest);
    practice.performance_of = Some(LineageRef {
        attempt_id: "attempt-prod-1".to_string(),
        kind: AttemptKind::Practice,
    });
    assert_eq!(
        verify_attempt_scope(&manifest, &practice)
            .expect_err("practice performance_of must fail")
            .code,
        "NOT_ADMITTED"
    );
    let mut production = production_commission(&manifest);
    production.rehearsal_of = Some(LineageRef {
        attempt_id: "attempt-practice-1".to_string(),
        kind: AttemptKind::Production,
    });
    assert_eq!(
        verify_attempt_scope(&manifest, &production)
            .expect_err("production rehearsal_of must fail")
            .code,
        "NOT_ADMITTED"
    );

    // Links must point at the opposite kind.
    let mut practice = practice_commission(&manifest);
    practice.rehearsal_of = Some(LineageRef {
        attempt_id: "attempt-practice-2".to_string(),
        kind: AttemptKind::Practice,
    });
    assert_eq!(
        verify_attempt_scope(&manifest, &practice)
            .expect_err("same-kind rehearsal_of must fail")
            .code,
        "NOT_ADMITTED"
    );

    // derived_from is same-kind only: cross-kind derivation fails.
    let mut production = production_commission(&manifest);
    production.derived_from = vec![LineageRef {
        attempt_id: "attempt-practice-1".to_string(),
        kind: AttemptKind::Practice,
    }];
    assert_eq!(
        verify_attempt_scope(&manifest, &production)
            .expect_err("cross-kind derived_from must fail")
            .code,
        "NOT_ADMITTED"
    );

    // Self-derivation and duplicates are structural failures.
    let mut production = production_commission(&manifest);
    production.derived_from = vec![LineageRef {
        attempt_id: "attempt-prod-1".to_string(),
        kind: AttemptKind::Production,
    }];
    assert_eq!(
        verify_attempt_scope(&manifest, &production)
            .expect_err("self derivation must fail")
            .code,
        "INVALID_REQUEST"
    );
    let mut production = production_commission(&manifest);
    production.derived_from = vec![
        LineageRef {
            attempt_id: "attempt-prod-0".to_string(),
            kind: AttemptKind::Production,
        },
        LineageRef {
            attempt_id: "attempt-prod-0".to_string(),
            kind: AttemptKind::Production,
        },
    ];
    assert_eq!(
        verify_attempt_scope(&manifest, &production)
            .expect_err("duplicate derived_from must fail")
            .code,
        "INVALID_REQUEST"
    );

    // Same-kind derivation verifies.
    let mut production = production_commission(&manifest);
    production.derived_from = vec![LineageRef {
        attempt_id: "attempt-prod-0".to_string(),
        kind: AttemptKind::Production,
    }];
    verify_attempt_scope(&manifest, &production)
        .expect("same-kind derived_from must verify");
}

// ---------------------------------------------------------------------------
// work authorization
// ---------------------------------------------------------------------------

#[test]
fn rm_c53_authorize_work_requires_admitted_grant() {
    let principal = principal_for("op-1");

    // No grant: artifact references alongside do not authorize.
    let scope = WorkScope {
        authorization_refs: Vec::new(),
        ..apply_scope("execution")
    };
    let op = Operation {
        artifact_refs: vec!["artifact:bytes-1".to_string()],
        ..operation("Start")
    };
    let err = authorize_work(&principal, &scope, &op).expect_err("grantless call must fail");
    assert_eq!(err.kind, "connector_error");
    assert_eq!(err.code, "FORBIDDEN");

    // Unknown verbs do not exist.
    let err = authorize_work(&principal, &apply_scope("execution"), &operation("ExecuteScript"))
        .expect_err("tenth verb must fail");
    assert_eq!(err.code, "INVALID_REQUEST");

    // Task scope outside the admitted activity is not covered.
    let err = authorize_work(
        &principal,
        &apply_scope("execution"),
        &Operation {
            task_scope: "extract".to_string(),
            ..operation("Start")
        },
    )
    .expect_err("out-of-scope task must fail");
    assert_eq!(err.code, "FORBIDDEN");

    // URLs, scripts, and node IDs are references, never scopes.
    for scope_id in [
        "https://employer.example/apply",
        "script:submit.js",
        "node:42",
        "artifact:bytes-1",
    ] {
        let err = authorize_work(
            &principal,
            &apply_scope("execution"),
            &Operation {
                task_scope: scope_id.to_string(),
                ..operation("Start")
            },
        )
        .expect_err("reference-shaped scope must fail");
        assert_eq!(err.code, "FORBIDDEN", "scope: {scope_id}");
    }

    // Application work without its commission is not admitted.
    let scope = WorkScope {
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        ..apply_scope("execution")
    };
    assert_eq!(
        authorize_work(&principal, &scope, &operation("Start"))
            .expect_err("commissionless apply must fail")
            .code,
        "NOT_ADMITTED"
    );

    // The admitted call authorizes with authority-assigned fields.
    let descriptor = authorize_work(&principal, &apply_scope("execution"), &operation("Start"))
        .expect("admitted call must authorize");
    assert_eq!(descriptor.producer_id, "op-1");
    assert_eq!(descriptor.provenance, PROVENANCE_PRODUCTION_DIRECT);
    assert_eq!(descriptor.owner_domain, "execution");
    assert_eq!(descriptor.role, "connector_agent");
    assert_eq!(descriptor.assertion_kind, "task_evidence");
}

#[test]
fn rm_c53_authorize_work_separates_control_authority() {
    let principal = principal_for("op-1");

    // Control without a target is malformed.
    let err = authorize_work(&principal, &apply_scope("control"), &operation("Contain"))
        .expect_err("targetless control must fail");
    assert_eq!(err.code, "INVALID_REQUEST");

    // Task grants alone do not authorize control.
    let op = Operation {
        task_scope: "apply".to_string(),
        control_target: Some("deployment-slot-1".to_string()),
        ..operation("Contain")
    };
    let err = authorize_work(&principal, &apply_scope("control"), &op)
        .expect_err("task-granted control must fail");
    assert_eq!(err.code, "FORBIDDEN");

    // Application credentials never grant control access.
    let scope = WorkScope {
        authorization_refs: vec!["control:deployment-slot-1".to_string()],
        ..apply_scope("control")
    };
    let op = Operation {
        control_target: Some("deployment-slot-1".to_string()),
        account_binding: Some("app-cred:session-1".to_string()),
        ..operation("Contain")
    };
    assert_eq!(
        authorize_work(&principal, &scope, &op)
            .expect_err("app-credential control must fail")
            .code,
        "FORBIDDEN"
    );

    // Scoped control grant authorizes with control role/kind.
    let op = Operation {
        control_target: Some("deployment-slot-1".to_string()),
        ..operation("Contain")
    };
    let descriptor = authorize_work(&principal, &scope, &op)
        .expect("control-granted containment must authorize");
    assert_eq!(descriptor.role, "control_agent");
    assert_eq!(descriptor.assertion_kind, "control_evidence");
}

#[test]
fn rm_c53_manual_commissions_not_dispatchable() {
    let principal = principal_for("op-1");
    let manual = WorkScope {
        execution_mode: ExecutionMode::Manual,
        ..apply_scope("execution")
    };
    for verb in ["Prepare", "Start"] {
        let err = authorize_work(&principal, &manual, &operation(verb))
            .expect_err("manual dispatch must fail");
        assert_eq!(err.code, "NOT_ADMITTED", "verb: {verb}");
    }
    // Manual work may still be observed through the local projection.
    authorize_work(&principal, &manual, &operation("Observe"))
        .expect("manual observation must authorize");
}

// ---------------------------------------------------------------------------
// owner authorization and producer assignment
// ---------------------------------------------------------------------------

#[test]
fn rm_c53_report_writer_cannot_hold_execution_or_application_authority() {
    let principal = principal_for("writer-1");

    // The report writer cannot publish execution or application events.
    for event_kind in [
        "execution_claim",
        "native_report",
        "task_output",
        "origin_fact",
    ] {
        let err = authorize_owner(&principal, "report", event_kind)
            .expect_err("report execution/application write must fail");
        assert_eq!(err.kind, "connector_error");
        assert_eq!(err.code, "FORBIDDEN", "kind: {event_kind}");
    }

    // Writers may publish only their own axis.
    let err = authorize_owner(&principal, "execution", "report_published")
        .expect_err("cross-axis write must fail");
    assert_eq!(err.code, "FORBIDDEN");

    // Each axis writer publishes its own events with source identity kept.
    for (domain, event_kind, role) in [
        ("dispatch", "dispatch_published", "dispatch_writer"),
        ("observation", "observation_closed", "observation_writer"),
        ("execution", "execution_claim", "execution_writer"),
        ("application", "origin_fact", "application_writer"),
        ("report", "report_published", "report_writer"),
    ] {
        let descriptor = authorize_owner(&principal, domain, event_kind)
            .expect("own-axis write must authorize");
        assert_eq!(descriptor.producer_id, "writer-1");
        assert_eq!(descriptor.owner_domain, domain);
        assert_eq!(descriptor.role, role);
        assert_eq!(descriptor.assertion_kind, event_kind);
    }

    // Unregistered event kinds and malformed domains fail.
    assert_eq!(
        authorize_owner(&principal, "execution", "bo.dom_write")
            .expect_err("unregistered kind must fail")
            .code,
        "NOT_ADMITTED"
    );
    for domain in ["", "has space", "a,b", "execution/prod"] {
        assert_eq!(
            authorize_owner(&principal, domain, "execution_claim")
                .expect_err("malformed domain must fail")
                .code,
            "INVALID_REQUEST",
            "domain: {domain:?}"
        );
    }
}

#[test]
fn rm_c53_producer_identity_assigned_by_authority_not_caller() {
    // Fresh authorizations always carry direct (current-partition)
    // provenance: imports can only ever enter as marked references via the
    // commission, never as freshly authorized direct evidence.
    let principal = principal_for("producer-7");
    let descriptor = authorize_work(&principal, &apply_scope("execution"), &operation("Start"))
        .expect("admitted call must authorize");
    assert_eq!(descriptor.producer_id, "producer-7");
    assert!(
        [PROVENANCE_PRACTICE_DIRECT, PROVENANCE_PRODUCTION_DIRECT]
            .contains(&descriptor.provenance.as_str()),
        "work provenance must be a direct marker: {}",
        descriptor.provenance
    );

    let mut practice_scope = apply_scope("execution");
    practice_scope.attempt_kind = Some(AttemptKind::Practice);
    let descriptor = authorize_work(&principal, &practice_scope, &operation("Start"))
        .expect("practice call must authorize");
    assert_eq!(descriptor.provenance, PROVENANCE_PRACTICE_DIRECT);

    let descriptor = authorize_owner(&principal, "execution", "execution_claim")
        .expect("owner call must authorize");
    assert_eq!(descriptor.producer_id, "producer-7");
    assert_eq!(descriptor.provenance, PROVENANCE_OWNER_DIRECT);

    // Exactly nine operations exist on this surface.
    assert_eq!(NINE_OPERATIONS.len(), 9);
}
