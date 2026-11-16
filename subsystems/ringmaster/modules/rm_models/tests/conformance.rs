//! Conformance tests for rm_models RM-C36..RM-C40.
//!
//! Every test name carries its `rm_c36`..`rm_c40` token so the verification
//! filter `cargo test -p rm_models -- rm_c36 rm_c37 rm_c38 rm_c39 rm_c40`
//! selects the suite.

use rm_authority::{authenticate_channel, ExecutionMode, Manifest, Operation, WorkScope};
use rm_evidence::{
    append_event, event_registration, install_artifact, journal_id_for, load_artifact,
    manifest_artifact_reference, AccessClass, ArtifactReference, EventSubmission, EvidencePayload,
    PositiveInteger,
};
use rm_models::{
    propose_recovery, provider_call_count, repair_json_bytes, stub_provider_responses,
    validate_proposal_bytes, BOBindingDescriptor, BOMapping, BreakerPolicy, BudgetEnforcers,
    ConnectorHandle, Header, TaskBudgets, VersionPin,
};
use rm_time::{MaybeTimePoint, MeasurementOrigin, Missing, TimePoint, UtcAnnotation};
use rm_wire::{artifact_digest, canonical_digest};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn principal() -> rm_authority::AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": "rm-models-tester",
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": "binding-rm-models-tester",
        },
    });
    let bytes = serde_json::to_vec(&registration).expect("registration serializes");
    authenticate_channel(&mut Cursor::new(bytes)).expect("test principal authenticates")
}

fn manifest(run: &str) -> Manifest {
    let mut manifest = Manifest {
        record_type: "manifest".to_string(),
        schema_version: "evidence-kernel/0.1.0".to_string(),
        run_id: run.to_string(),
        task: json!({"task_id": format!("task-{run}"), "kind": "discovery"}),
        subject: json!({"subject_id": format!("subject-{run}")}),
        event_kinds: [
            "manifest_admitted",
            "clock_registered",
            "artifact_available",
            "execution_claim",
            "report_published",
        ]
        .iter()
        .map(|kind| (*kind).to_string())
        .collect(),
        admission_ref: format!("admission-{run}"),
        manifest_hash: String::new(),
    };
    let wire = rm_authority::manifest_wire_bytes(&manifest);
    manifest.manifest_hash = canonical_digest(&wire)
        .expect("manifest hashes")
        .as_str()
        .to_string();
    manifest
}

fn seq(value: u64) -> PositiveInteger {
    PositiveInteger::new(value).expect("positive integer")
}

fn admission(manifest: &Manifest) -> EventSubmission {
    let artifact = manifest_artifact_reference(manifest).expect("manifest artifact reference");
    EventSubmission {
        producer_sequence: Some(seq(1)),
        event_kind: "manifest_admitted".to_string(),
        event_schema_version: "evidence-kernel/0.1.0".to_string(),
        occurred_at: MaybeTimePoint::Missing(Missing::new("not_applicable")),
        payload: EvidencePayload {
            data: json!({"manifest": artifact.to_json()}),
            measurements: Vec::new(),
            evidence_refs: Vec::new(),
            artifact_refs: vec![artifact],
        },
    }
}

fn admit(writer: &rm_authority::AuthenticatedPrincipal, manifest: &Manifest) {
    append_event(writer, manifest, admission(manifest)).expect("manifest admission");
}

fn point(offset: f64) -> TimePoint {
    TimePoint {
        clock_id: "clock-rm-models".to_string(),
        boot_id: "boot-1".to_string(),
        origin: MeasurementOrigin::EngineMeasured,
        monotonic_offset_ms: offset,
        utc_annotation: UtcAnnotation::DateTime("2026-01-01T00:00:00Z".to_string()),
    }
}

fn prompt_bytes(suffix: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "heal_reduction": format!("heal reduction interactive nodes for {suffix}"),
        "fallback_text": format!("fallback text for {suffix}"),
        "failed_selector": "#old-selector",
        "failed_recipe": "css:#old-selector",
        "section_labels": ["main", "header"],
        "limitations": ["truncated-collection"],
        "commissioned_job": format!("job-{suffix}"),
        "commissioned_target": format!("target-{suffix}"),
        "current_root": format!("root-{suffix}"),
        "effect_policy": "commissioned_application",
    }))
    .expect("prompt serializes")
}

fn install_prompt(
    principal: &rm_authority::AuthenticatedPrincipal,
    bytes: &[u8],
) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "testowner".to_string(),
        access: AccessClass::Restricted,
    };
    install_artifact(principal, &reference, bytes).expect("prompt installs")
}

fn make_binding() -> BOBindingDescriptor {
    let primitives = [
        "bo.client_create",
        "bo.http_exchange",
        "bo.page_create",
        "bo.navigate",
        "bo.from_html",
        "bo.dom_read",
        "bo.dom_write",
        "bo.event_dispatch",
        "bo.v8_evaluate",
        "bo.assign_files",
        "bo.capture",
        "bo.render_verdict",
        "bo.reset_for_reuse",
        "bo.page_destroy",
    ];
    BOBindingDescriptor {
        record_type: "browseroxide_binding_descriptor".to_string(),
        schema_version: "internal-browser-binding.browseroxide/0.1.0".to_string(),
        binding_id: "binding-1".to_string(),
        primitive_mappings: primitives
            .iter()
            .map(|prim| BOMapping {
                primitive: (*prim).to_string(),
                mapping_state: "mapped".to_string(),
                native_symbol: Some(format!("sym-{prim}")),
                evidence_refs: vec!["ev-1".to_string()],
            })
            .collect(),
        session_storage_model: "process_global".to_string(),
        session_isolation_refs: Vec::new(),
    }
}

fn make_policy() -> VersionPin {
    VersionPin {
        id: "provider-policy".to_string(),
        version: "1.0.0".to_string(),
        artifact_digest: artifact_digest(b"rm-models-provider-policy")
            .as_str()
            .to_string(),
        role: "recovery".to_string(),
        providers: vec!["provider-a".to_string()],
        model: "model-1".to_string(),
        protocol: "https".to_string(),
        endpoint_ref: "endpoint-1".to_string(),
        credential_ref: "cred-1".to_string(),
        headers: Vec::new(),
        timeout_ms: 5000,
        failover_enabled: true,
        retention: "none".to_string(),
        privacy: "restricted".to_string(),
        user_agent: "ringmaster/0.1.0".to_string(),
        disclosure_allowed: true,
    }
}

fn make_budgets() -> TaskBudgets {
    TaskBudgets {
        active_limit_ms: 1000.0,
        action_limit: 100,
        observation_byte_limit: 1_000_000,
        recovery_limit: 5,
        model_token_limit: 1000,
        enforcers: BudgetEnforcers {
            active_observation: "connector".to_string(),
            action_count: "connector".to_string(),
            observation_bytes: "connector".to_string(),
            recovery_count: "connector".to_string(),
            model_tokens: "connector".to_string(),
        },
        tokens_reserved: Some(100),
        tokens_used: Some(10),
        tokens_per_call: 10,
        breaker: BreakerPolicy {
            shard: "shard-1".to_string(),
            numerator: Some(1),
            denominator: Some(100),
            window_clock_id: "clock-rm-models".to_string(),
            sample_minimum: 10,
            tripped: false,
            reset_authority: "operator".to_string(),
        },
        session_limit: 10,
        sessions_used: 1,
        observation_open: true,
        active_allowance_remaining: 5,
        recovery_allowance_remaining: 5,
    }
}

struct Fixtures {
    principal: rm_authority::AuthenticatedPrincipal,
    handle: ConnectorHandle,
    binding: BOBindingDescriptor,
    prompt: ArtifactReference,
    policy: VersionPin,
    budgets: TaskBudgets,
}

fn setup(suffix: &str) -> Fixtures {
    let principal = principal();
    let run = format!("rm-models-{suffix}");
    let manifest = manifest(&run);
    admit(&principal, &manifest);
    let bytes = prompt_bytes(suffix);
    let prompt = install_prompt(&principal, &bytes);
    let journal_id = journal_id_for(&manifest).expect("journal id");
    let scope = WorkScope {
        activity: "discovery".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id,
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec!["grant-task-1".to_string()],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    };
    let operation = Operation {
        verb: "Observe".to_string(),
        connector_id: "connector-1".to_string(),
        subject_id: "subject-1".to_string(),
        task_scope: "discovery".to_string(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    };
    let handle = ConnectorHandle {
        record_type: "connector_handle".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        connector_id: "connector-1".to_string(),
        local_handle: format!("handle-{suffix}"),
        preparation_id: format!("prep-{suffix}"),
        scope,
        operation,
        manifest,
        idempotency_key: format!("idem-{suffix}"),
        created_at: point(0.0),
        now: point(100.0),
        active_deadline: point(1000.0),
    };
    Fixtures {
        principal,
        handle,
        binding: make_binding(),
        prompt,
        policy: make_policy(),
        budgets: make_budgets(),
    }
}

fn valid_proposal_bytes(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "selector": "#main-content",
        "strategy": "css",
        "confidence": 0.8,
        "reason": reason,
    }))
    .expect("proposal serializes")
}

fn restricted_ref_for(bytes: &[u8]) -> ArtifactReference {
    ArtifactReference {
        digest: artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "testowner".to_string(),
        access: AccessClass::Restricted,
    }
}

// ---------------------------------------------------------------------------
// RM-C36: Tier-2 closed proposal schema
// ---------------------------------------------------------------------------

#[test]
fn rm_c36_closed_proposal_schema() {
    // Valid closed proposal succeeds end to end.
    let f = setup("c36-valid");
    let raw = valid_proposal_bytes("heal c36 valid");
    stub_provider_responses(f.prompt.digest.as_str(), vec![raw.clone()]);
    let proposal_ref = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("valid closed proposal is accepted");
    assert_eq!(proposal_ref.access, AccessClass::Restricted);
    let stored = load_artifact(&f.principal, &proposal_ref).expect("proposal retained");
    assert_eq!(stored, raw);
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 1);
    let parsed = validate_proposal_bytes(&stored).expect("stored proposal validates");
    assert_eq!(parsed.selector, "#main-content");
    assert_eq!(parsed.strategy, "css");
    assert!((parsed.confidence - 0.8).abs() < f64::EPSILON);
    assert_eq!(parsed.reason, "heal c36 valid");

    // Each strategy in the closed vocabulary is accepted.
    for (index, strategy) in ["css", "xpath", "text", "role", "testid"]
        .iter()
        .enumerate()
    {
        let f = setup(&format!("c36-strategy-{index}"));
        let raw = serde_json::to_vec(&json!({
            "selector": format!("#node-{strategy}"),
            "strategy": strategy,
            "confidence": 0.5,
            "reason": format!("strategy {strategy}"),
        }))
        .unwrap();
        stub_provider_responses(f.prompt.digest.as_str(), vec![raw]);
        propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &f.budgets,
        )
        .unwrap_or_else(|e| panic!("strategy {strategy} must be accepted: {e}"));
    }

    // Invalid proposals are rejected even after the one permitted retry: both
    // attempts carry the same invalid shape so no usable candidate exists.
    let invalid_cases: Vec<(&str, Vec<u8>)> = vec![
        (
            "empty-selector",
            serde_json::to_vec(&json!({
                "selector": "",
                "strategy": "css",
                "confidence": 0.5,
                "reason": "x",
            }))
            .unwrap(),
        ),
        (
            "bad-strategy",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "jquery",
                "confidence": 0.5,
                "reason": "x",
            }))
            .unwrap(),
        ),
        (
            "confidence-high",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "css",
                "confidence": 1.5,
                "reason": "x",
            }))
            .unwrap(),
        ),
        (
            "confidence-negative",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "css",
                "confidence": -0.1,
                "reason": "x",
            }))
            .unwrap(),
        ),
        (
            "empty-reason",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "css",
                "confidence": 0.5,
                "reason": "",
            }))
            .unwrap(),
        ),
        (
            "missing-field",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "css",
                "confidence": 0.5,
            }))
            .unwrap(),
        ),
        (
            "extra-field",
            serde_json::to_vec(&json!({
                "selector": "#a",
                "strategy": "css",
                "confidence": 0.5,
                "reason": "x",
                "job": "evil",
            }))
            .unwrap(),
        ),
        (
            "nonfinite-literal",
            br##"{"selector": "#a", "strategy": "css", "confidence": NaN, "reason": "x"}"##
                .to_vec(),
        ),
        (
            "not-json",
            b"this is not json at all".to_vec(),
        ),
    ];
    for (case, bytes) in invalid_cases {
        let f = setup(&format!("c36-invalid-{case}"));
        stub_provider_responses(
            f.prompt.digest.as_str(),
            vec![bytes.clone(), bytes.clone()],
        );
        let result = propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &f.budgets,
        );
        assert!(
            result.is_err(),
            "invalid proposal case {case} must be rejected"
        );
        assert_eq!(
            provider_call_count(f.prompt.digest.as_str()),
            2,
            "invalid case {case} must consume the bounded two attempts"
        );
    }
}

// ---------------------------------------------------------------------------
// RM-C37: raw retained before repair; repair never invents; duplicates reject
// ---------------------------------------------------------------------------

#[test]
fn rm_c37_raw_retained_and_syntax_only_repair() {
    // Trailing-comma syntax repairs: raw retained, repaired retained
    // separately, proposal equals the repaired bytes.
    let f = setup("c37-repair");
    let raw =
        br##"{"selector": "#repaired", "strategy": "css", "confidence": 0.5, "reason": "fix", }"##
            .to_vec();
    assert!(validate_proposal_bytes(&raw).is_err());
    let repaired = repair_json_bytes(&raw).expect("pinned repair fixes trailing comma");
    assert!(validate_proposal_bytes(&repaired).is_ok());
    stub_provider_responses(f.prompt.digest.as_str(), vec![raw.clone()]);
    let proposal_ref = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("repairable syntax succeeds");
    let stored = load_artifact(&f.principal, &proposal_ref).expect("proposal retained");
    assert_eq!(stored, repaired);
    // Raw bytes are retained before repair under their own digest.
    let raw_ref = restricted_ref_for(&raw);
    let raw_stored = load_artifact(&f.principal, &raw_ref).expect("raw retained before repair");
    assert_eq!(raw_stored, raw);
    assert_ne!(raw_ref.digest, proposal_ref.digest);

    // Repair never invents missing semantic fields.
    let f = setup("c37-no-invent");
    let missing =
        br##"{"selector": "#a", "strategy": "css", "confidence": 0.5}"##.to_vec();
    if let Some(repaired) = repair_json_bytes(&missing) {
        let value: Value = serde_json::from_slice(&repaired).expect("repaired is json");
        assert!(
            !value.as_object().unwrap().contains_key("reason"),
            "repair must not invent reason"
        );
    }
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![missing.clone(), missing.clone()],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .is_err());

    // Duplicate keys are rejected, never repaired away.
    let f = setup("c37-duplicate");
    let duplicate = br##"{"selector": "#a", "selector": "#b", "strategy": "css", "confidence": 0.5, "reason": "x"}"##.to_vec();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![duplicate.clone(), duplicate],
    );
    let error = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect_err("duplicate keys must be rejected");
    assert!(
        error.detail.contains("duplicate"),
        "duplicate error must name the cause: {}",
        error.detail
    );

    // Non-finite values are rejected.
    let f = setup("c37-nonfinite");
    let nonfinite = br##"{"selector": "#a", "strategy": "css", "confidence": Infinity, "reason": "x"}"##.to_vec();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![nonfinite.clone(), nonfinite],
    );
    let error = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect_err("non-finite must be rejected");
    assert!(
        error.detail.contains("non-finite") || error.detail.contains("finite"),
        "non-finite error must name the cause: {}",
        error.detail
    );

    // Already-valid output needs no repair: raw and proposal coincide.
    let f = setup("c37-no-repair-needed");
    let raw = valid_proposal_bytes("no repair needed");
    assert!(repair_json_bytes(&raw).is_none());
    stub_provider_responses(f.prompt.digest.as_str(), vec![raw.clone()]);
    let proposal_ref = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("valid output succeeds without repair");
    let stored = load_artifact(&f.principal, &proposal_ref).expect("proposal retained");
    assert_eq!(stored, raw);
}

// ---------------------------------------------------------------------------
// RM-C38: one retry; every call counts; no unbounded loop
// ---------------------------------------------------------------------------

#[test]
fn rm_c38_bounded_retry_and_budget_counting() {
    // One invalid first candidate followed by a valid second succeeds, and
    // both provider calls count.
    let f = setup("c38-retry-success");
    let invalid = serde_json::to_vec(&json!({
        "selector": "",
        "strategy": "css",
        "confidence": 0.5,
        "reason": "bad",
    }))
    .unwrap();
    let valid = valid_proposal_bytes("second attempt heals");
    stub_provider_responses(f.prompt.digest.as_str(), vec![invalid.clone(), valid.clone()]);
    let proposal_ref = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("one retry after invalid first candidate succeeds");
    let stored = load_artifact(&f.principal, &proposal_ref).expect("proposal retained");
    assert_eq!(stored, valid);
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 2);
    // The invalid first raw is still retained.
    let invalid_ref = restricted_ref_for(&invalid);
    assert_eq!(
        load_artifact(&f.principal, &invalid_ref).expect("first raw retained"),
        invalid
    );

    // Two invalid candidates exhaust the baseline: no third attempt even when
    // a third response is staged and failover is enabled.
    let f = setup("c38-exhausted");
    let bad = serde_json::to_vec(&json!({
        "selector": "#a",
        "strategy": "nope",
        "confidence": 0.5,
        "reason": "x",
    }))
    .unwrap();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![bad.clone(), bad.clone(), valid_proposal_bytes("never reached")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .is_err());
    assert_eq!(
        provider_call_count(f.prompt.digest.as_str()),
        2,
        "repair and failover cannot create an unbounded retry loop"
    );

    // A recovery_limit of one forbids the second attempt.
    let f = setup("c38-recovery-limit");
    let mut budgets = f.budgets.clone();
    budgets.recovery_limit = 1;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![invalid.clone(), valid_proposal_bytes("blocked by limit")],
    );
    let error = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect_err("recovery_limit must bound attempts");
    assert!(
        error.detail.contains("recovery"),
        "limit error must name recovery: {}",
        error.detail
    );
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 1);

    // Token reservation must cover the bounded attempts.
    let f = setup("c38-token-cover");
    let mut budgets = f.budgets.clone();
    budgets.tokens_reserved = Some(10);
    budgets.tokens_used = Some(0);
    budgets.tokens_per_call = 10;
    budgets.model_token_limit = 100;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![invalid.clone(), valid_proposal_bytes("blocked by tokens")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());
    // With a reservation covering both attempts the same inputs succeed.
    let f = setup("c38-token-cover-ok");
    let mut budgets = f.budgets.clone();
    budgets.tokens_reserved = Some(30);
    budgets.tokens_used = Some(0);
    budgets.tokens_per_call = 10;
    budgets.model_token_limit = 100;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![invalid, valid_proposal_bytes("covered retry")],
    );
    propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect("covered retry succeeds");
}

// ---------------------------------------------------------------------------
// RM-C39: conduit pre-call gates; unknown usage is not zero
// ---------------------------------------------------------------------------

#[test]
fn rm_c39_conduit_gates_before_every_call() {
    // Baseline succeeds so each gate mutation below is the single cause.
    let f = setup("c39-baseline");
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("baseline")],
    );
    propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("baseline must succeed");

    // Closed observation blocks the call and consumes no provider response.
    let f = setup("c39-closed-observation");
    let mut budgets = f.budgets.clone();
    budgets.observation_open = false;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Exhausted allowances block the call.
    for (case, mutate) in [
        ("active", {
            let mut b = make_budgets();
            b.active_allowance_remaining = 0;
            b
        }),
        ("recovery", {
            let mut b = make_budgets();
            b.recovery_allowance_remaining = 0;
            b
        }),
    ] {
        let f = setup(&format!("c39-allowance-{case}"));
        stub_provider_responses(
            f.prompt.digest.as_str(),
            vec![valid_proposal_bytes("never called")],
        );
        assert!(propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &mutate,
        )
        .is_err());
        assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);
    }

    // Missing token reservation blocks the call.
    let f = setup("c39-no-reservation");
    let mut budgets = f.budgets.clone();
    budgets.tokens_reserved = None;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Unknown usage is not zero: a partial reservation is rejected.
    let f = setup("c39-unknown-partial");
    let mut budgets = f.budgets.clone();
    budgets.tokens_used = None;
    budgets.tokens_reserved = Some(100);
    budgets.model_token_limit = 1000;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    let error = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect_err("unknown usage with partial reservation must be rejected");
    assert!(
        error.detail.contains("unknown usage is not zero"),
        "must not treat unknown as zero: {}",
        error.detail
    );
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Unknown usage with a full-limit reservation reconciles and succeeds.
    let f = setup("c39-unknown-full");
    let mut budgets = f.budgets.clone();
    budgets.tokens_used = None;
    budgets.tokens_reserved = Some(1000);
    budgets.model_token_limit = 1000;
    budgets.tokens_per_call = 10;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("unknown reconciled")],
    );
    propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect("unknown usage with full reservation reconciles");

    // Zero model tokens forbids the call.
    let f = setup("c39-zero-tokens");
    let mut budgets = f.budgets.clone();
    budgets.model_token_limit = 0;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());

    // Session limit blocks the call.
    let f = setup("c39-session-limit");
    let mut budgets = f.budgets.clone();
    budgets.sessions_used = 10;
    budgets.session_limit = 10;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());

    // Missing disclosure permission blocks the call.
    let f = setup("c39-disclosure");
    let mut policy = f.policy.clone();
    policy.disclosure_allowed = false;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &policy,
        &f.budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Missing task authority blocks the call: artifact references and bare
    // scopes never grant authority.
    let f = setup("c39-authority");
    let mut handle = f.handle.clone();
    handle.scope.authorization_refs.clear();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // An expired active boundary blocks delivery.
    let f = setup("c39-deadline");
    let mut handle = f.handle.clone();
    handle.now = point(2000.0);
    handle.active_deadline = point(1000.0);
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Oversized prompt input is rejected before any provider call.
    let principal = principal();
    let run = "rm-models-c39-oversize";
    let manifest = manifest(run);
    admit(&principal, &manifest);
    let big = "x".repeat(60_000);
    let bytes = serde_json::to_vec(&json!({
        "heal_reduction": big,
        "fallback_text": "fallback",
        "failed_selector": "#old",
        "failed_recipe": "css:#old",
        "section_labels": ["main"],
        "limitations": [],
        "commissioned_job": "job-big",
        "commissioned_target": "target-big",
        "current_root": "root-big",
        "effect_policy": "commissioned_application",
    }))
    .unwrap();
    assert!(bytes.len() > 50_000);
    let prompt = install_prompt(&principal, &bytes);
    let journal_id = journal_id_for(&manifest).expect("journal id");
    let scope = WorkScope {
        activity: "discovery".to_string(),
        run_id: manifest.run_id.clone(),
        journal_id,
        manifest_hash: manifest.manifest_hash.clone(),
        admission_ref: manifest.admission_ref.clone(),
        attempt_id: None,
        commission_id: None,
        commission_ref: None,
        attempt_kind: None,
        authorization_refs: vec!["grant-task-1".to_string()],
        observation_policy: "policy-1".to_string(),
        owner_domain: "testowner".to_string(),
        execution_mode: ExecutionMode::Automated,
    };
    let operation = Operation {
        verb: "Observe".to_string(),
        connector_id: "connector-1".to_string(),
        subject_id: "subject-1".to_string(),
        task_scope: "discovery".to_string(),
        account_binding: None,
        artifact_refs: Vec::new(),
        control_target: None,
    };
    let handle = ConnectorHandle {
        record_type: "connector_handle".to_string(),
        schema_version: "external-connector/0.1.0".to_string(),
        connector_id: "connector-1".to_string(),
        local_handle: "handle-big".to_string(),
        preparation_id: "prep-big".to_string(),
        scope,
        operation,
        manifest,
        idempotency_key: "idem-big".to_string(),
        created_at: point(0.0),
        now: point(100.0),
        active_deadline: point(1000.0),
    };
    stub_provider_responses(prompt.digest.as_str(), vec![valid_proposal_bytes("x")]);
    assert!(propose_recovery(
        &principal,
        &handle,
        &make_binding(),
        &prompt,
        &make_policy(),
        &make_budgets(),
    )
    .is_err());
    assert_eq!(provider_call_count(prompt.digest.as_str()), 0);

    // No Python LiteLLM runtime and truthful Ringmaster user-agent.
    let f = setup("c39-litellm");
    let mut policy = f.policy.clone();
    policy.providers = vec!["litellm".to_string()];
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &policy,
        &f.budgets,
    )
    .is_err());

    let f = setup("c39-user-agent");
    let mut policy = f.policy.clone();
    policy.user_agent = "litellm/1.0".to_string();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &policy,
        &f.budgets,
    )
    .is_err());

    // OpenCode Go requires its pinned session header.
    let f = setup("c39-opencode-missing");
    let mut policy = f.policy.clone();
    policy.providers = vec!["opencode-go".to_string()];
    policy.headers = Vec::new();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &policy,
        &f.budgets,
    )
    .is_err());

    let f = setup("c39-opencode-ok");
    let mut policy = f.policy.clone();
    policy.providers = vec!["opencode-go".to_string()];
    policy.headers = vec![Header {
        name: "x-opencode-session".to_string(),
        value: "session-1".to_string(),
    }];
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("opencode ok")],
    );
    propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &policy,
        &f.budgets,
    )
    .expect("opencode-go with pinned session header succeeds");
}

// ---------------------------------------------------------------------------
// RM-C40: breaker, five budget dimensions, model-content security
// ---------------------------------------------------------------------------

#[test]
fn rm_c40_breaker_budgets_and_model_security() {
    // Missing breaker denominator cannot produce zero rate.
    let f = setup("c40-missing-denominator");
    let mut budgets = f.budgets.clone();
    budgets.breaker.denominator = None;
    budgets.breaker.numerator = Some(0);
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    let error = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect_err("missing denominator must be rejected");
    assert!(
        error.detail.contains("denominator"),
        "must name denominator: {}",
        error.detail
    );
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // Zero denominator is likewise not a zero rate.
    let f = setup("c40-zero-denominator");
    let mut budgets = f.budgets.clone();
    budgets.breaker.denominator = Some(0);
    budgets.breaker.numerator = Some(0);
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());

    // Heal rate above 30% with a sufficient sample trips the breaker.
    let f = setup("c40-tripped-rate");
    let mut budgets = f.budgets.clone();
    budgets.breaker.numerator = Some(40);
    budgets.breaker.denominator = Some(100);
    budgets.breaker.sample_minimum = 10;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());
    assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);

    // A high rate below the sample minimum does not trip.
    let f = setup("c40-small-sample");
    let mut budgets = f.budgets.clone();
    budgets.breaker.numerator = Some(4);
    budgets.breaker.denominator = Some(5);
    budgets.breaker.sample_minimum = 10;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("small sample ok")],
    );
    propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .expect("insufficient sample does not trip");

    // An explicitly tripped breaker disables Tier 2/3.
    let f = setup("c40-open");
    let mut budgets = f.budgets.clone();
    budgets.breaker.tripped = true;
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());

    // Five dimensions must map exactly with a connector-enforced active
    // observation; unenforceable bounds reject preparation.
    let f = setup("c40-active-enforcer");
    let mut budgets = f.budgets.clone();
    budgets.enforcers.active_observation = "subject".to_string();
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("never called")],
    );
    assert!(propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &budgets,
    )
    .is_err());

    for (case, dimension) in [
        ("action", "action_count"),
        ("bytes", "observation_bytes"),
        ("recovery", "recovery_count"),
        ("tokens", "model_tokens"),
    ] {
        let f = setup(&format!("c40-unenforceable-{case}"));
        let mut budgets = f.budgets.clone();
        match dimension {
            "action_count" => budgets.enforcers.action_count = "not_enforced".to_string(),
            "observation_bytes" => {
                budgets.enforcers.observation_bytes = "not_applicable".to_string()
            }
            "recovery_count" => budgets.enforcers.recovery_count = "unknown".to_string(),
            "model_tokens" => budgets.enforcers.model_tokens = "not_enforced".to_string(),
            _ => unreachable!(),
        }
        stub_provider_responses(
            f.prompt.digest.as_str(),
            vec![valid_proposal_bytes("never called")],
        );
        assert!(propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &budgets,
        )
        .is_err());
        assert_eq!(provider_call_count(f.prompt.digest.as_str()), 0);
    }

    // No model response may change identity, job, target, values, files,
    // order, or budget: undeclared fields are rejected.
    for field in [
        "candidate_identity",
        "job",
        "target",
        "input_values",
        "files",
        "action_order",
        "budget",
        "permissions",
        "script",
    ] {
        let f = setup(&format!("c40-mutation-{field}"));
        let mut map = serde_json::Map::new();
        map.insert("selector".to_string(), json!("#a"));
        map.insert("strategy".to_string(), json!("css"));
        map.insert("confidence".to_string(), json!(0.5));
        map.insert("reason".to_string(), json!("x"));
        map.insert(field.to_string(), json!("evil"));
        let raw = serde_json::to_vec(&Value::Object(map)).unwrap();
        stub_provider_responses(f.prompt.digest.as_str(), vec![raw.clone(), raw]);
        assert!(propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &f.budgets,
        )
        .is_err());
    }

    // Executable scripts in model content are rejected.
    for (case, selector) in [
        ("script-tag", "#a<script>alert(1)</script>"),
        ("javascript-url", "javascript:alert(1)"),
        ("onerror", "#a\" onerror=\"alert(1)"),
    ] {
        let f = setup(&format!("c40-script-{case}"));
        let raw = serde_json::to_vec(&json!({
            "selector": selector,
            "strategy": "css",
            "confidence": 0.5,
            "reason": "x",
        }))
        .unwrap();
        stub_provider_responses(f.prompt.digest.as_str(), vec![raw.clone(), raw]);
        let error = propose_recovery(
            &f.principal,
            &f.handle,
            &f.binding,
            &f.prompt,
            &f.policy,
            &f.budgets,
        )
        .expect_err("script selector must be rejected");
        assert!(
            error.detail.contains("script") || error.detail.contains("untrusted"),
            "script error must name the cause: {}",
            error.detail
        );
    }

    // Event registration sanity: the journaled proposal cites retained
    // restricted artifacts, and the returned reference stays restricted.
    let f = setup("c40-restricted");
    stub_provider_responses(
        f.prompt.digest.as_str(),
        vec![valid_proposal_bytes("restricted")],
    );
    let proposal_ref = propose_recovery(
        &f.principal,
        &f.handle,
        &f.binding,
        &f.prompt,
        &f.policy,
        &f.budgets,
    )
    .expect("restricted proposal succeeds");
    assert_eq!(proposal_ref.access, AccessClass::Restricted);
    assert!(event_registration("artifact_available").is_some());
}
