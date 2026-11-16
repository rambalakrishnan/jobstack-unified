//! Conformance tests for `rm_learning` RM-C43.
//!
//! Every test name carries the `rm_c43` token so the verification filter
//! `cargo test -p rm_learning -- rm_c43` selects the suite.

use rm_authority::{authenticate_channel, AuthenticatedPrincipal};
use rm_evidence::{
    install_artifact, load_artifact, AccessClass, ArtifactReference, EvidenceRef, PositiveInteger,
};
use rm_learning::{
    commit_verified_learning, select_learning_state, ContextPolicy, MaybeArtifact, StatePolicy,
    SubjectIdentity, SupportRefs,
};
use rm_time::{MaybeString, Missing};
use serde_json::{json, Value};
use std::io::Cursor;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn principal() -> AuthenticatedPrincipal {
    let registration = json!({
        "principal_id": "rm-learning-tester",
        "channel_binding": {
            "mechanism": "test-harness",
            "binding": "binding-rm-learning-tester",
        },
    });
    let bytes = serde_json::to_vec(&registration).expect("registration serializes");
    authenticate_channel(&mut Cursor::new(bytes)).expect("test principal authenticates")
}

fn test_digest(seed: &str) -> rm_wire::Digest {
    rm_wire::artifact_digest(seed.as_bytes())
}

fn subject(id: &str, version: &str) -> SubjectIdentity {
    subject_with_mode(id, version, "goal", "dom")
}

fn subject_with_mode(id: &str, version: &str, mode: &str, surface: &str) -> SubjectIdentity {
    SubjectIdentity {
        subject_id: id.to_string(),
        subject_version: version.to_string(),
        revision_basis: "unknown".to_string(),
        native_revision: MaybeString::Missing(Missing::new("not_applicable")),
        configured_mode: mode.to_string(),
        interface_surface: surface.to_string(),
        configuration_digest: test_digest(&format!("config:{id}:{version}:{mode}:{surface}")),
        stack: Vec::new(),
    }
}

fn evidence_ref(tag: &str) -> EvidenceRef {
    EvidenceRef {
        journal_id: format!("journal-{tag}"),
        sequence: PositiveInteger::new(1).expect("positive"),
        event_id: format!("event-{tag}"),
        event_hash: test_digest(&format!("event:{tag}")),
        pointer: String::new(),
    }
}

fn install_learning(principal: &AuthenticatedPrincipal, bytes: &[u8]) -> ArtifactReference {
    let reference = ArtifactReference {
        digest: rm_wire::artifact_digest(bytes),
        size_bytes: bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "learning".to_string(),
        access: AccessClass::Public,
    };
    install_artifact(principal, &reference, bytes).expect("learning bytes install")
}

fn learning_json(
    subject: &SubjectIdentity,
    revision: u64,
    selectors: Value,
    coordinates: Value,
    imports: Value,
) -> Vec<u8> {
    let value = json!({
        "record_type": "learning_state",
        "schema_version": "ringmaster-learning/0.1.0",
        "subject": subject.to_json(),
        "learning_revision": revision,
        "selector_entries": selectors,
        "coordinate_entries": coordinates,
        "imports": imports,
    });
    serde_json::to_vec(&value).expect("learning serializes")
}

#[allow(clippy::too_many_arguments)]
fn selector_entry(
    step: &str,
    strategy: &str,
    query: &str,
    confidence: Value,
    hit: u64,
    heal: u64,
    refs: &[EvidenceRef],
    stale: bool,
    revision: u64,
) -> Value {
    json!({
        "step_id": step,
        "target_recipe": {"strategy": strategy, "query": query},
        "subject_scope": "scope-subject",
        "resolver_scope": "scope-resolver",
        "confidence": confidence,
        "hit_count": hit,
        "heal_count": heal,
        "verification_refs": refs.iter().map(|r| r.to_json()).collect::<Vec<Value>>(),
        "stale": stale,
        "learning_revision": revision,
    })
}

fn coordinate_entry(step: &str, image_seed: &str, geometry: &[EvidenceRef], rev: u64) -> Value {
    json!({
        "step_id": step,
        "hash_algorithm": "dhash",
        "hash_version": "v1",
        "image_digest": test_digest(image_seed).as_str(),
        "perceptual_hash": format!("ph-{image_seed}"),
        "box": {"x": 10.0, "y": 20.0, "width": 100.0, "height": 50.0},
        "coordinate_space": "viewport-css-800x600-scale1",
        "geometry_evidence": geometry.iter().map(|r| r.to_json()).collect::<Vec<Value>>(),
        "target_applicability": format!("target-{step}"),
        "creation_evidence": evidence_ref(&format!("create-{step}-{image_seed}")).to_json(),
        "hit_count": 1,
        "learning_revision": rev,
    })
}

fn import_entry(source_seed: &str, provenance: &str, byte_length: u64) -> Value {
    json!({
        "source_digest": test_digest(source_seed).as_str(),
        "provenance": provenance,
        "byte_length": byte_length,
    })
}

fn state_policy(
    mode: &str,
    requirement: &str,
    resource_ref: MaybeString,
    baseline: MaybeArtifact,
) -> StatePolicy {
    StatePolicy {
        mode: mode.to_string(),
        requirement: requirement.to_string(),
        resource_ref,
        baseline,
    }
}

fn missing_string(reason: &str) -> MaybeString {
    MaybeString::Missing(Missing::new(reason))
}

fn missing_baseline(reason: &str) -> MaybeArtifact {
    MaybeArtifact::Missing(Missing::new(reason))
}

fn context_policy(browser: StatePolicy, learning: StatePolicy) -> ContextPolicy {
    ContextPolicy {
        browser_state: browser,
        learning_state: learning,
    }
}

fn fresh_browser() -> StatePolicy {
    state_policy(
        "fresh",
        "required",
        missing_string("not_applicable"),
        missing_baseline("not_applicable"),
    )
}

fn learning_revision_of(principal: &AuthenticatedPrincipal, reference: &ArtifactReference) -> Value {
    let bytes = load_artifact(principal, reference).expect("selected bytes load");
    serde_json::from_slice(&bytes).expect("selected bytes are JSON")
}

// ---------------------------------------------------------------------------
// RM-C43: frozen learning with successful healing
// ---------------------------------------------------------------------------

#[test]
fn rm_c43_frozen_healing_retains_evidence_and_leaves_cache_unchanged() {
    let p = principal();
    let sub = subject("rm-c43-frozen", "v1");
    let verify = evidence_ref("rm-c43-frozen-verify");

    // Baseline: fresh empty revision 1.
    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let baseline = select_learning_state(&p, &fresh, &sub).expect("fresh selects");
    let baseline_value = learning_revision_of(&p, &baseline);
    assert_eq!(baseline_value["learning_revision"], json!(1));
    assert_eq!(baseline_value["selector_entries"], json!([]));

    // Candidate: verified healing successor, revision 2.
    let entry = selector_entry(
        "step-1",
        "css",
        "#submit",
        json!(0.9),
        1,
        1,
        &[verify.clone()],
        false,
        2,
    );
    let candidate_bytes = learning_json(&sub, 2, json!([entry]), json!([]), json!([]));
    let candidate = install_learning(&p, &candidate_bytes);

    // Frozen commit suppresses operational write-back.
    let frozen = state_policy(
        "frozen",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(baseline.clone()),
    );
    let verification = SupportRefs(vec![verify.clone()]);
    let result =
        commit_verified_learning(&p, &baseline, &candidate, &verification, &frozen)
            .expect("frozen commit succeeds");
    assert_eq!(
        result.digest, baseline.digest,
        "frozen commit returns the baseline unchanged"
    );
    assert_ne!(
        result.digest, candidate.digest,
        "frozen commit must not promote the healing candidate"
    );

    // Healing evidence stays retained and loadable.
    let retained = load_artifact(&p, &candidate).expect("healing bytes retained");
    assert_eq!(retained, candidate_bytes);
    let retained_value: Value = serde_json::from_slice(&retained).expect("retained JSON");
    assert_eq!(retained_value["learning_revision"], json!(2));

    // Operational cache is unchanged: still revision 1, still empty.
    let operational = learning_revision_of(&p, &result);
    assert_eq!(operational["learning_revision"], json!(1));
    assert_eq!(operational["selector_entries"], json!([]));

    // Frozen selection reads the pinned snapshot.
    let frozen_select = context_policy(
        fresh_browser(),
        state_policy(
            "frozen",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(baseline.clone()),
        ),
    );
    let selected = select_learning_state(&p, &frozen_select, &sub).expect("frozen selects");
    assert_eq!(selected.digest, baseline.digest);
}

#[test]
fn rm_c43_frozen_commit_still_requires_pin_verification_and_subject_scope() {
    let p = principal();
    let sub = subject("rm-c43-frozen-gates", "v1");
    let verify = evidence_ref("rm-c43-frozen-gates-verify");

    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let baseline = select_learning_state(&p, &fresh, &sub).expect("fresh selects");
    let entry = selector_entry(
        "step-1", "css", "#go", json!(0.8), 1, 0, &[verify.clone()], false, 2,
    );
    let candidate = install_learning(&p, &learning_json(&sub, 2, json!([entry]), json!([]), json!([])));
    let verification = SupportRefs(vec![verify.clone()]);

    // Missing transition-policy pin is forbidden even when frozen.
    let no_pin = state_policy(
        "frozen",
        "required",
        missing_string("not_applicable"),
        MaybeArtifact::Present(baseline.clone()),
    );
    let error = commit_verified_learning(&p, &baseline, &candidate, &verification, &no_pin)
        .expect_err("frozen without a pinned policy must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Empty verification is rejected even when frozen.
    let frozen = || {
        state_policy(
            "frozen",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(baseline.clone()),
        )
    };
    let error = commit_verified_learning(&p, &baseline, &candidate, &SupportRefs(vec![]), &frozen())
        .expect_err("frozen without verification must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Wrong pin is stale even when frozen.
    let wrong_pin = state_policy(
        "frozen",
        "required",
        MaybeString::Text("99".to_string()),
        MaybeArtifact::Present(baseline.clone()),
    );
    let error = commit_verified_learning(&p, &baseline, &candidate, &verification, &wrong_pin)
        .expect_err("frozen with wrong pin must fail");
    assert_eq!(error.code, "STALE_CONTEXT");

    // Cross-subject healing never promotes, even silently under frozen.
    let other = subject("rm-c43-frozen-gates", "v2");
    let foreign_entry = selector_entry(
        "step-1", "css", "#go", json!(0.8), 1, 0, &[verify.clone()], false, 2,
    );
    let foreign =
        install_learning(&p, &learning_json(&other, 2, json!([foreign_entry]), json!([]), json!([])));
    let error = commit_verified_learning(&p, &baseline, &foreign, &verification, &frozen())
        .expect_err("frozen cross-subject healing must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Non-frozen control: the same valid healing promotes under reuse.
    let reuse = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(baseline.clone()),
    );
    let promoted = commit_verified_learning(&p, &baseline, &candidate, &verification, &reuse)
        .expect("reuse commit promotes verified healing");
    assert_eq!(promoted.digest, candidate.digest);
}

// ---------------------------------------------------------------------------
// Selection modes and browser/learning separation
// ---------------------------------------------------------------------------

#[test]
fn rm_c43_select_modes_browser_separation_and_required_vs_best_effort() {
    let p = principal();

    // Fresh mints an evidenced empty namespace for exactly the requested subject.
    let sub = subject("rm-c43-select", "v1");
    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let empty = select_learning_state(&p, &fresh, &sub).expect("fresh selects");
    let value = learning_revision_of(&p, &empty);
    assert_eq!(value["learning_revision"], json!(1));
    assert_eq!(value["subject"]["subject_id"], json!("rm-c43-select"));
    assert_eq!(value["subject"]["subject_version"], json!("v1"));

    // Fresh pins no prior baseline and no revision binding.
    let bad_baseline = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            MaybeArtifact::Present(empty.clone()),
        ),
    );
    assert!(select_learning_state(&p, &bad_baseline, &sub).is_err());
    let bad_pin = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            MaybeString::Text("1".to_string()),
            missing_baseline("not_applicable"),
        ),
    );
    assert!(select_learning_state(&p, &bad_pin, &sub).is_err());

    // Reuse reads the pinned snapshot; frozen is rejected for browser state.
    let verify = evidence_ref("rm-c43-select-verify");
    let entry = selector_entry(
        "step-9", "text", "Submit", json!(0.95), 3, 0, &[verify.clone()], false, 1,
    );
    // Baseline revision 1 with an entry (still revision 1, non-empty).
    let rev1 = install_learning(&p, &learning_json(&sub, 1, json!([entry]), json!([]), json!([])));
    let reuse = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let selected = select_learning_state(&p, &reuse, &sub).expect("reuse selects");
    assert_eq!(selected.digest, rev1.digest);

    // Browser `frozen` is a shape violation: frozen is learning-only.
    let browser_frozen = context_policy(
        state_policy(
            "frozen",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let error = select_learning_state(&p, &browser_frozen, &sub)
        .expect_err("browser frozen must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Fresh browser state never implies fresh learning state: a fresh
    // browser policy alongside a reuse learning policy returns the reused
    // snapshot with its entries intact.
    let mixed = context_policy(
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let mixed_selected = select_learning_state(&p, &mixed, &sub).expect("mixed selects");
    let mixed_value = learning_revision_of(&p, &mixed_selected);
    assert_eq!(mixed_value["selector_entries"].as_array().unwrap().len(), 1);

    // Reuse requires both a baseline and a pin.
    let no_baseline = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            missing_baseline("not_applicable"),
        ),
    );
    let error = select_learning_state(&p, &no_baseline, &sub)
        .expect_err("reuse without baseline must fail");
    assert_eq!(error.code, "NOT_ADMITTED");
    let no_pin = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            missing_string("not_applicable"),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let error = select_learning_state(&p, &no_pin, &sub)
        .expect_err("reuse without pin must fail");
    assert_eq!(error.code, "NOT_ADMITTED");

    // Wrong pin: required rejects, best-effort falls back to a fresh empty
    // namespace for the requested subject.
    let wrong_pin_required = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("7".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let error = select_learning_state(&p, &wrong_pin_required, &sub)
        .expect_err("wrong pin required must fail");
    assert_eq!(error.code, "STALE_CONTEXT");

    // Best-effort fallback is observable via a cross-subject baseline: the
    // fallback carries the requested subject, not the cited one.
    let other = subject("rm-c43-select-other", "v1");
    let cross_required = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let error = select_learning_state(&p, &cross_required, &other)
        .expect_err("cross-subject reuse required must fail");
    assert_eq!(error.code, "STALE_CONTEXT");
    let cross_best_effort = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "best_effort",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let fallback = select_learning_state(&p, &cross_best_effort, &other)
        .expect("best-effort cross-subject falls back");
    let fallback_value = learning_revision_of(&p, &fallback);
    assert_eq!(fallback_value["learning_revision"], json!(1));
    assert_eq!(fallback_value["subject"]["subject_id"], json!("rm-c43-select-other"));
    assert_eq!(fallback_value["selector_entries"], json!([]));

    // Missing bytes: required rejects, best-effort falls back.
    // Ensure distinct digest from anything installed: mutate with a unique import.
    let ghost_unique = learning_json(
        &sub,
        1,
        json!([]),
        json!([]),
        json!([import_entry("ghost-unique-seed-42", "imported_practice_reference", 10)]),
    );
    let ghost = ArtifactReference {
        digest: rm_wire::artifact_digest(&ghost_unique),
        size_bytes: ghost_unique.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "learning".to_string(),
        access: AccessClass::Public,
    };
    let ghost_required = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(ghost.clone()),
        ),
    );
    assert!(select_learning_state(&p, &ghost_required, &sub).is_err());
    let ghost_best_effort = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "best_effort",
            MaybeString::Text("1".to_string()),
            MaybeArtifact::Present(ghost.clone()),
        ),
    );
    let ghost_fallback = select_learning_state(&p, &ghost_best_effort, &sub)
        .expect("best-effort missing bytes fall back");
    let ghost_value = learning_revision_of(&p, &ghost_fallback);
    assert_eq!(ghost_value["learning_revision"], json!(1));

    // Subject default: missing baseline yields the default empty namespace;
    // a cited baseline is returned when valid.
    let default_missing = context_policy(
        fresh_browser(),
        state_policy(
            "subject_default",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let defaulted = select_learning_state(&p, &default_missing, &sub).expect("default selects");
    assert_eq!(learning_revision_of(&p, &defaulted)["learning_revision"], json!(1));
    let default_present = context_policy(
        fresh_browser(),
        state_policy(
            "subject_default",
            "required",
            missing_string("not_applicable"),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    let defaulted_present =
        select_learning_state(&p, &default_present, &sub).expect("default present selects");
    assert_eq!(defaulted_present.digest, rev1.digest);

    // Not-applicable carries no material and yields an empty placeholder.
    let na = context_policy(
        fresh_browser(),
        state_policy(
            "not_applicable",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let na_selected = select_learning_state(&p, &na, &sub).expect("n/a selects");
    assert_eq!(learning_revision_of(&p, &na_selected)["learning_revision"], json!(1));
    let na_bad = context_policy(
        fresh_browser(),
        state_policy(
            "not_applicable",
            "required",
            missing_string("not_applicable"),
            MaybeArtifact::Present(rev1.clone()),
        ),
    );
    assert!(select_learning_state(&p, &na_bad, &sub).is_err());
}

// ---------------------------------------------------------------------------
// Verified commit: owner-separated revisions
// ---------------------------------------------------------------------------

#[test]
fn rm_c43_commit_advances_revision_and_enforces_owner_revision_rules() {
    let p = principal();
    let sub = subject("rm-c43-commit", "v1");
    let verify = evidence_ref("rm-c43-commit-verify");
    let verification = SupportRefs(vec![verify.clone()]);

    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let baseline = select_learning_state(&p, &fresh, &sub).expect("fresh selects");
    let policy_for = |mode: &str, pin: &str| {
        state_policy(
            mode,
            "required",
            MaybeString::Text(pin.to_string()),
            MaybeArtifact::Present(baseline.clone()),
        )
    };

    // Verified successor advances exactly one revision.
    let entry = selector_entry(
        "step-1", "css", "#ok", json!(0.9), 1, 0, &[verify.clone()], false, 2,
    );
    let candidate = install_learning(&p, &learning_json(&sub, 2, json!([entry]), json!([]), json!([])));
    let advanced = commit_verified_learning(&p, &baseline, &candidate, &verification, &policy_for("reuse", "1"))
        .expect("verified commit advances");
    assert_eq!(advanced.digest, candidate.digest);

    // Identical retry is idempotent.
    let idempotent = commit_verified_learning(&p, &baseline, &baseline, &verification, &policy_for("reuse", "1"))
        .expect("identical retry returns the baseline");
    assert_eq!(idempotent.digest, baseline.digest);

    // Same revision with different bytes is an integrity conflict.
    let conflicting_entry = selector_entry(
        "step-1", "css", "#other", json!(0.7), 1, 0, &[verify.clone()], false, 1,
    );
    let conflicting = install_learning(
        &p,
        &learning_json(&sub, 1, json!([conflicting_entry]), json!([]), json!([])),
    );
    let error = commit_verified_learning(&p, &baseline, &conflicting, &verification, &policy_for("reuse", "1"))
        .expect_err("same-revision different bytes must conflict");
    assert_eq!(error.code, "INTEGRITY_INCIDENT");

    // Gapped revisions cannot commit.
    let gapped_entry = selector_entry(
        "step-1", "css", "#ok", json!(0.9), 1, 0, &[verify.clone()], false, 3,
    );
    let gapped = install_learning(&p, &learning_json(&sub, 3, json!([gapped_entry]), json!([]), json!([])));
    let error = commit_verified_learning(&p, &baseline, &gapped, &verification, &policy_for("reuse", "1"))
        .expect_err("gapped revision must be stale");
    assert_eq!(error.code, "STALE_CONTEXT");

    // Stale pins cannot commit.
    let error = commit_verified_learning(&p, &baseline, &candidate, &verification, &policy_for("reuse", "99"))
        .expect_err("stale pin must fail");
    assert_eq!(error.code, "STALE_CONTEXT");

    // A policy baseline that names a different snapshot cannot commit.
    let other_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(candidate.clone()),
    );
    let error = commit_verified_learning(&p, &baseline, &candidate, &verification, &other_policy)
        .expect_err("mismatched policy baseline must fail");
    assert_eq!(error.code, "STALE_CONTEXT");

    // Commits are not applicable under a not-applicable policy.
    let na_policy = state_policy(
        "not_applicable",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(baseline.clone()),
    );
    let error = commit_verified_learning(&p, &baseline, &candidate, &verification, &na_policy)
        .expect_err("not-applicable commit must fail");
    assert_eq!(error.code, "NOT_ADMITTED");

    // Snapshots commit under the learning owner with the pinned media type.
    let baseline_bytes = load_artifact(&p, &baseline).expect("baseline loads");
    let wrong_owner = ArtifactReference {
        digest: rm_wire::artifact_digest(&baseline_bytes),
        size_bytes: baseline_bytes.len() as u64,
        media_type: "application/json".to_string(),
        owner_domain: "evidence".to_string(),
        access: AccessClass::Public,
    };
    // Install under the wrong owner would collide on digest; instead pass a
    // reference whose metadata disagrees with the learning contract, with a
    // policy that pins no baseline so the owner check is reached.
    let owner_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        missing_baseline("not_applicable"),
    );
    let error = commit_verified_learning(&p, &wrong_owner, &candidate, &verification, &owner_policy)
        .expect_err("wrong-owner baseline must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Counts advance monotonically: silent decrements are rejected.
    let counted = selector_entry(
        "step-2", "role", "button", json!(0.6), 4, 2, &[verify.clone()], false, 1,
    );
    let counted_base =
        install_learning(&p, &learning_json(&sub, 1, json!([counted]), json!([]), json!([])));
    let decreased = selector_entry(
        "step-2", "role", "button", json!(0.6), 1, 2, &[verify.clone()], false, 2,
    );
    let decreased_candidate =
        install_learning(&p, &learning_json(&sub, 2, json!([decreased]), json!([]), json!([])));
    let counted_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(counted_base.clone()),
    );
    let error = commit_verified_learning(
        &p,
        &counted_base,
        &decreased_candidate,
        &verification,
        &counted_policy,
    )
    .expect_err("decreased counts must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Stale clearing requires verification evidence.
    let unknown_confidence = json!({"value": null, "reason": "not_observed"});
    let stale_entry =
        selector_entry("step-3", "css", "#stale", unknown_confidence.clone(), 0, 0, &[], true, 1);
    let stale_base =
        install_learning(&p, &learning_json(&sub, 1, json!([stale_entry]), json!([]), json!([])));
    let cleared_entry =
        selector_entry("step-3", "css", "#stale", unknown_confidence, 0, 0, &[], false, 2);
    let cleared_candidate =
        install_learning(&p, &learning_json(&sub, 2, json!([cleared_entry]), json!([]), json!([])));
    let stale_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(stale_base.clone()),
    );
    let error = commit_verified_learning(
        &p,
        &stale_base,
        &cleared_candidate,
        &verification,
        &stale_policy,
    )
    .expect_err("unevidenced stale clearing must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Revisions are complete snapshots: retained imports carry forward.
    let with_import = install_learning(
        &p,
        &learning_json(
            &sub,
            1,
            json!([]),
            json!([]),
            json!([import_entry("seed-carry", "imported_practice_reference", 32)]),
        ),
    );
    let dropped = install_learning(&p, &learning_json(&sub, 2, json!([]), json!([]), json!([])));
    let import_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(with_import.clone()),
    );
    let error = commit_verified_learning(&p, &with_import, &dropped, &verification, &import_policy)
        .expect_err("dropped import must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Counts without verification evidence are never promoted.
    let unevidenced =
        selector_entry("step-4", "css", "#new", json!(0.9), 2, 0, &[], false, 2);
    let unevidenced_candidate =
        install_learning(&p, &learning_json(&sub, 2, json!([unevidenced]), json!([]), json!([])));
    let error = commit_verified_learning(
        &p,
        &baseline,
        &unevidenced_candidate,
        &verification,
        &policy_for("reuse", "1"),
    )
    .expect_err("unevidenced counts must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Operational review thresholds are not capability judgments: low
    // confidence and high heal counts are accepted when evidenced.
    let low = selector_entry(
        "step-5", "css", "#flaky", json!(0.3), 1, 15, &[verify.clone()], false, 2,
    );
    let low_candidate =
        install_learning(&p, &learning_json(&sub, 2, json!([low]), json!([]), json!([])));
    let accepted = commit_verified_learning(
        &p,
        &baseline,
        &low_candidate,
        &verification,
        &policy_for("reuse", "1"),
    )
    .expect("low-confidence high-heal entries are accepted when evidenced");
    assert_eq!(accepted.digest, low_candidate.digest);

    // Coordinate entries commit with geometry evidence.
    let coord = coordinate_entry("step-6", "img-seed-1", &[verify.clone()], 2);
    let coord_candidate =
        install_learning(&p, &learning_json(&sub, 2, json!([]), json!([coord]), json!([])));
    let accepted = commit_verified_learning(
        &p,
        &baseline,
        &coord_candidate,
        &verification,
        &policy_for("reuse", "1"),
    )
    .expect("coordinate entries commit with geometry evidence");
    assert_eq!(accepted.digest, coord_candidate.digest);
}

// ---------------------------------------------------------------------------
// Pinned encoding: closed, null-free, and Circus-free
// ---------------------------------------------------------------------------

#[test]
fn rm_c43_pinned_encoding_rejects_bare_nulls_undeclared_fields_and_circus_shapes() {
    let p = principal();
    let sub = subject("rm-c43-encoding", "v1");
    let verify = evidence_ref("rm-c43-encoding-verify");
    let verification = SupportRefs(vec![verify.clone()]);

    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let baseline = select_learning_state(&p, &fresh, &sub).expect("fresh selects");
    let policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(baseline.clone()),
    );

    // Bare nulls are rejected: staleness is a boolean, never null.
    let bare_null = json!({
        "record_type": "learning_state",
        "schema_version": "ringmaster-learning/0.1.0",
        "subject": sub.to_json(),
        "learning_revision": 2,
        "selector_entries": [{
            "step_id": "s",
            "target_recipe": {"strategy": "css", "query": "#a"},
            "subject_scope": "scope-subject",
            "resolver_scope": "scope-resolver",
            "confidence": 0.9,
            "hit_count": 0,
            "heal_count": 0,
            "verification_refs": [verify.to_json()],
            "stale": null,
            "learning_revision": 2,
        }],
        "coordinate_entries": [],
        "imports": [],
    });
    let bare_null = install_learning(&p, &serde_json::to_vec(&bare_null).unwrap());
    let error = commit_verified_learning(&p, &baseline, &bare_null, &verification, &policy)
        .expect_err("bare null must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Duplicate mapping keys are rejected.
    let mut text = serde_json::to_string(&json!({
        "record_type": "learning_state",
        "schema_version": "ringmaster-learning/0.1.0",
        "subject": sub.to_json(),
        "learning_revision": 2,
        "selector_entries": [],
        "coordinate_entries": [],
        "imports": [],
    }))
    .unwrap();
    text = text.replacen(
        "\"learning_revision\":2",
        "\"learning_revision\":2,\"learning_revision\":2",
        1,
    );
    let dupe = install_learning(&p, text.as_bytes());
    let error = commit_verified_learning(&p, &baseline, &dupe, &verification, &policy)
        .expect_err("duplicate keys must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Tentative model markers are undeclared in the verified contract.
    let tentative = json!({
        "step_id": "s",
        "target_recipe": {"strategy": "css", "query": "#t"},
        "subject_scope": "scope-subject",
        "resolver_scope": "scope-resolver",
        "confidence": 0.9,
        "hit_count": 0,
        "heal_count": 0,
        "verification_refs": [verify.to_json()],
        "stale": false,
        "learning_revision": 2,
        "tentative": true,
    });
    let tentative =
        install_learning(&p, &learning_json(&sub, 2, json!([tentative]), json!([]), json!([])));
    let error = commit_verified_learning(&p, &baseline, &tentative, &verification, &policy)
        .expect_err("tentative markers must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Circus Tent filesystem shapes are never the native storage contract.
    let circus = selector_entry(
        "s", "css", "circus_tent_cache.json", json!(0.9), 0, 0, &[verify.clone()], false, 2,
    );
    let circus =
        install_learning(&p, &learning_json(&sub, 2, json!([circus]), json!([]), json!([])));
    let error = commit_verified_learning(&p, &baseline, &circus, &verification, &policy)
        .expect_err("circus shapes must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Non-finite literals are rejected before parsing.
    let nonfinite = br#"{"record_type":"learning_state","schema_version":"ringmaster-learning/0.1.0","subject":{"subject_id":"x"},"learning_revision":2,"selector_entries":[],"coordinate_entries":[],"imports":[],"probe":NaN}"#;
    let nonfinite = install_learning(&p, nonfinite);
    let error = commit_verified_learning(&p, &baseline, &nonfinite, &verification, &policy)
        .expect_err("non-finite literals must fail");
    assert_eq!(error.code, "INVALID_REQUEST");

    // Imports carry no counts or confidence.
    let counted_import = json!({
        "source_digest": test_digest("counted-import").as_str(),
        "provenance": "imported_practice_reference",
        "byte_length": 8,
        "hit_count": 5,
    });
    let counted_import = install_learning(
        &p,
        &learning_json(&sub, 2, json!([]), json!([]), json!([counted_import])),
    );
    let error = commit_verified_learning(&p, &baseline, &counted_import, &verification, &policy)
        .expect_err("counted imports must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Imports must be marked import references.
    let unmarked = install_learning(
        &p,
        &learning_json(
            &sub,
            2,
            json!([]),
            json!([]),
            json!([import_entry("seed-unmarked", "production_direct", 8)]),
        ),
    );
    let error = commit_verified_learning(&p, &baseline, &unmarked, &verification, &policy)
        .expect_err("unmarked imports must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Perceptual-hash similarity alone never authorizes reuse: geometry
    // evidence is mandatory.
    let no_geometry = json!({
        "step_id": "s",
        "hash_algorithm": "dhash",
        "hash_version": "v1",
        "image_digest": test_digest("img-no-geometry").as_str(),
        "perceptual_hash": "ph-no-geometry",
        "box": {"x": 1.0, "y": 1.0, "width": 10.0, "height": 10.0},
        "coordinate_space": "viewport-css-800x600-scale1",
        "geometry_evidence": [],
        "target_applicability": "target-s",
        "creation_evidence": verify.to_json(),
        "hit_count": 0,
        "learning_revision": 2,
    });
    let no_geometry =
        install_learning(&p, &learning_json(&sub, 2, json!([]), json!([no_geometry]), json!([])));
    let error = commit_verified_learning(&p, &baseline, &no_geometry, &verification, &policy)
        .expect_err("geometry-free coordinates must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Geometry must be finite, nonnegative origins with positive extents.
    let bad_box = json!({
        "step_id": "s",
        "hash_algorithm": "dhash",
        "hash_version": "v1",
        "image_digest": test_digest("img-bad-box").as_str(),
        "perceptual_hash": "ph-bad-box",
        "box": {"x": 1.0, "y": 1.0, "width": 0.0, "height": 10.0},
        "coordinate_space": "viewport-css-800x600-scale1",
        "geometry_evidence": [verify.to_json()],
        "target_applicability": "target-s",
        "creation_evidence": verify.to_json(),
        "hit_count": 0,
        "learning_revision": 2,
    });
    let bad_box =
        install_learning(&p, &learning_json(&sub, 2, json!([]), json!([bad_box]), json!([])));
    assert!(commit_verified_learning(&p, &baseline, &bad_box, &verification, &policy).is_err());

    // Unknown record discriminators are rejected.
    let wrong_record = json!({
        "record_type": "selector_cache",
        "schema_version": "ringmaster-learning/0.1.0",
        "subject": sub.to_json(),
        "learning_revision": 2,
        "selector_entries": [],
        "coordinate_entries": [],
        "imports": [],
    });
    let wrong_record = install_learning(&p, &serde_json::to_vec(&wrong_record).unwrap());
    assert!(commit_verified_learning(&p, &baseline, &wrong_record, &verification, &policy).is_err());
}

// ---------------------------------------------------------------------------
// Subject scoping: new versions start unknown
// ---------------------------------------------------------------------------

#[test]
fn rm_c43_subject_scoping_new_versions_start_unknown_without_inheritance() {
    let p = principal();
    let v1 = subject("rm-c43-scoping", "v1");
    let v2 = subject("rm-c43-scoping", "v2");
    let verify = evidence_ref("rm-c43-scoping-verify");
    let verification = SupportRefs(vec![verify.clone()]);

    // Version 1 establishes its own learned findings.
    let fresh = context_policy(
        fresh_browser(),
        state_policy(
            "fresh",
            "required",
            missing_string("not_applicable"),
            missing_baseline("not_applicable"),
        ),
    );
    let v1_empty = select_learning_state(&p, &fresh, &v1).expect("v1 fresh selects");
    let entry = selector_entry(
        "step-1", "css", "#v1", json!(0.95), 5, 1, &[verify.clone()], false, 2,
    );
    let v1_learned =
        install_learning(&p, &learning_json(&v1, 2, json!([entry]), json!([]), json!([])));
    let v1_policy = state_policy(
        "reuse",
        "required",
        MaybeString::Text("1".to_string()),
        MaybeArtifact::Present(v1_empty.clone()),
    );
    let v1_committed =
        commit_verified_learning(&p, &v1_empty, &v1_learned, &verification, &v1_policy)
            .expect("v1 commits its own findings");
    assert_eq!(v1_committed.digest, v1_learned.digest);

    // Version 2 citing the version-1 snapshot is a scope mismatch: required
    // rejects, best-effort falls back to an unknown (empty) baseline that
    // inherits nothing.
    let cross_required = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("2".to_string()),
            MaybeArtifact::Present(v1_committed.clone()),
        ),
    );
    let error = select_learning_state(&p, &cross_required, &v2)
        .expect_err("cross-version reuse required must fail");
    assert_eq!(error.code, "STALE_CONTEXT");
    let cross_best_effort = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "best_effort",
            MaybeString::Text("2".to_string()),
            MaybeArtifact::Present(v1_committed.clone()),
        ),
    );
    let v2_unknown = select_learning_state(&p, &cross_best_effort, &v2)
        .expect("cross-version best-effort falls back to unknown");
    let v2_value = learning_revision_of(&p, &v2_unknown);
    assert_eq!(v2_value["learning_revision"], json!(1));
    assert_eq!(v2_value["subject"]["subject_version"], json!("v2"));
    assert_eq!(v2_value["selector_entries"], json!([]));

    // A commit that crosses versions is rejected outright.
    let v2_entry = selector_entry(
        "step-1", "css", "#v1", json!(0.95), 5, 1, &[verify.clone()], false, 3,
    );
    let v2_candidate =
        install_learning(&p, &learning_json(&v2, 3, json!([v2_entry]), json!([]), json!([])));
    let cross_commit = state_policy(
        "reuse",
        "required",
        MaybeString::Text("2".to_string()),
        MaybeArtifact::Present(v1_committed.clone()),
    );
    let error = commit_verified_learning(
        &p,
        &v1_committed,
        &v2_candidate,
        &verification,
        &cross_commit,
    )
    .expect_err("cross-version commit must fail");
    assert_eq!(error.code, "FORBIDDEN");

    // Mode and interface surface are part of the scope: a mode change is a
    // different subject and starts unknown as well.
    let other_mode = subject_with_mode("rm-c43-scoping", "v1", "recorded_plan", "dom");
    let mode_cross = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "required",
            MaybeString::Text("2".to_string()),
            MaybeArtifact::Present(v1_committed.clone()),
        ),
    );
    assert!(select_learning_state(&p, &mode_cross, &other_mode).is_err());
    let mode_fallback = context_policy(
        fresh_browser(),
        state_policy(
            "reuse",
            "best_effort",
            MaybeString::Text("2".to_string()),
            MaybeArtifact::Present(v1_committed.clone()),
        ),
    );
    let mode_unknown = select_learning_state(&p, &mode_fallback, &other_mode)
        .expect("mode change falls back to unknown");
    let mode_value = learning_revision_of(&p, &mode_unknown);
    assert_eq!(mode_value["selector_entries"], json!([]));
    assert_eq!(mode_value["subject"]["configured_mode"], json!("recorded_plan"));
}
