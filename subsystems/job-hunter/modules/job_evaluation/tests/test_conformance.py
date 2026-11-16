"""Conformance tests for job_evaluation (tier 7).

Covers exactly the ``-k`` filter named in the module spec:

- ``evaluation_pin_differing_from_logical_row_crawler_slot_is_rejected``
- ``profile_pin_mismatch_between_reference_and_evaluation_artifact_is_rejected``
- ``unknown_playbook_label_retains_raw_response_and_surfaces_issue``
- ``unknown_pay_requires_automatic_review``
- ``missing_scoring_rubric_prevents_invented_score_semantics``
- ``embedding_model_or_dimension_mismatch_invalidates_similarity_comparison``

Every check exercises the real module with real siblings: authenticated
channels, retained artifacts, admitted journals, verified prefixes, loaded
candidate profiles and playbook catalogs.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, rel: Path):
    if name in sys.modules:
        return sys.modules[name]
    try:
        return __import__(name)
    except ModuleNotFoundError:
        pass
    here = Path(__file__).resolve()
    if rel.is_absolute():
        path = rel
    else:
        # tests/ -> module dir -> modules/ -> sibling src
        path = (
            here.parents[1] / rel
            if name == "job_evaluation"
            else here.parents[2] / rel
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("access_policy", Path("access_policy/src/__init__.py"))
cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
ci = _load("candidate_inputs", Path("candidate_inputs/src/__init__.py"))
je = _load("job_evaluation", Path("src/__init__.py"))

CHANNEL = "ch_job_evaluation_0001"
PRODUCER = "prod_job_evaluation"
OWNER = "job.downstream"
JOURNAL = "journal_job_evaluation_0001"
RUN = "run_job_evaluation_0001"
KIND = "product.published"
KIND_VERSION = "1"
CLOCK_ID = "clock_job_evaluation_engine"
BOOT_ID = "boot_job_evaluation_engine"


@pytest.fixture(autouse=True)
def _fresh_state():
    je.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    je.reset_for_tests()


def _register_writer():
    return ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id="principal_job_evaluation",
        sequence_required=True,
        allowed_event_kinds=(KIND,),
    )


def _register_event_kind() -> None:
    ap.register_event_kind(
        KIND,
        KIND_VERSION,
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain=OWNER,
        writer_roles=("kernel",),
    )


def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _retain_json(obj) -> store.ArtifactReference:
    return store.retain_artifact(
        CHANNEL, OWNER, "application/json", _canonical(obj), "restricted"
    )


def _manifest(task, config) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_job_evaluation_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_job_evaluation",
        activity="kernel_conformance",
        attempt=ev.NOT_APPLICABLE,
        execution={
            "mode": "service",
            "subject": ev.NOT_APPLICABLE,
            "connector_version": ev.NOT_APPLICABLE,
            "binding_version": ev.NOT_APPLICABLE,
            "assistance": {
                "planning_owner": "none",
                "assistance_track": "no_assistance",
                "planner_identity": ev.NOT_APPLICABLE,
                "plan": ev.NOT_APPLICABLE,
                "online_replanning": False,
                "description": "No assistance is declared at admission.",
            },
        },
        task=task,
        task_semantic_hash="sha256:" + "e" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=[
            {
                "event_kind": KIND,
                "event_schema_version": KIND_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "owner_domain": OWNER,
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": "principal_job_evaluation",
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": True,
                "allowed_event_kinds": [KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_job_evaluation_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup():
    _register_writer()
    _register_event_kind()
    task = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"task"}', "restricted"
    )
    config = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"config"}', "restricted"
    )
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    assert admission.journal_sequence == 1
    return admission


def _submission(producer_sequence, note: str) -> ev.EventSubmission:
    return ev.EventSubmission(
        producer_sequence=producer_sequence,
        event_kind=KIND,
        event_schema_version=KIND_VERSION,
        occurred_at=ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=1000.0,
        ),
        payload=ev.EvidencePayload(
            data={"note": note},
            measurements=[],
            evidence_refs=[],
            artifact_refs=[],
        ),
    )


def _head_ref(sequence_event) -> ev.EvidenceRef:
    return ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=sequence_event.journal_sequence,
        event_id=sequence_event.event_id,
        event_hash=sequence_event.event_hash,
        pointer="",
    )


def _valid_catalog_dict() -> dict:
    specs = [
        ("pb01_structural_deconstruction",
         "Recursive Structural Deconstruction & Isomorphic Mapping",
         ["decompose systems", "identify invariants", "normalize mismatches"],
         ["complex system mismatch"], ["requires system access"]),
        ("pb02_human_asset_optimization",
         "Human Asset Optimization & Reverse-Pyramid Leadership",
         ["train", "coach", "remove obstacles", "delegate", "measure cohorts"],
         ["team performance gap"], ["requires cohort consent"]),
        ("pb03_compliance_automation",
         "Compliance-to-Automation Pipeline",
         ["interpret rules", "author SOPs", "automate checks", "remediate"],
         ["regulatory update"], ["requires legal review"]),
        ("pb04_field_triage",
         "High-Stakes De-escalation & Autonomous Field Triage",
         ["de-escalate", "apply policy", "preserve safety", "document"],
         ["field incident"], ["safety takes precedence"]),
        ("pb05_hardware_software_integration",
         "Cross-Domain Hardware/Software Integration",
         ["integrate hardware", "firmware", "sensors", "actuators", "software"],
         ["cross-domain build"], ["requires hardware access"]),
        ("pb06_cognitive_offloading",
         "Latency-Aware Cognitive Offloading",
         ["route local reasoning", "retrieve context", "preserve responsiveness"],
         ["latency budget exceeded"], ["requires connectivity plan"]),
        ("pb07_public_governance",
         "Public/Community Governance & Parliamentary Procedure",
         ["parliamentary procedure", "reporting", "consensus", "public presentation"],
         ["governance session"], ["requires quorum"]),
        ("pb08_campaign_engineering",
         "Data-Driven Campaign Engineering",
         ["BI", "demographic targeting", "conversion", "budget optimization"],
         ["campaign launch"], ["requires budget approval"]),
    ]
    entries = []
    for pid, name, actions, triggers, limits in specs:
        entries.append({
            "playbook_id": pid,
            "name": name,
            "primitive_actions": actions,
            "trigger_conditions": triggers,
            "limitations": limits,
            "source_refs": [f"inventory:{pid}:source", "corpus:doc-042"],
        })
    return {
        "record_type": "playbook_catalog",
        "schema_version": "job-hunter-playbooks/0.1.0",
        "entries": entries,
    }


def _make_profile(candidate_id="cand_eval_0001"):
    """Retain a clean profile + catalog and return (profile_ref, catalog, head, ref)."""
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "candidate source observed"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = _head_ref(first)
    catalog_ref = _retain_json(_valid_catalog_dict())
    disclosure_ref = _retain_json({"policy": "restricted", "version": "1"})
    capability_ref = _retain_json({
        "analysis_kind": "analytical_interpretation",
        "note": "clean skills summary",
    })
    source_doc_ref = _retain_json({"resume": "raw history text", "classification": "restricted"})
    prefix_dict = {
        "journal_id": JOURNAL,
        "last_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }
    profile = {
        "record_type": "candidate_profile_artifact",
        "schema_version": "job-hunter-candidate-profile/0.1.0",
        "candidate_id": candidate_id,
        "source_documents": [source_doc_ref.to_dict()],
        "source_evidence_refs": [ref.to_dict()],
        "employment_history": {"value": None, "reason": "not_observed"},
        "capability_profile": capability_ref.to_dict(),
        "playbook_catalog": {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": catalog_ref.digest,
        },
        "constraints": {"value": None, "reason": "not_observed"},
        "disclosure_policy": {
            "id": "disclosure_policy", "version": "1",
            "artifact_digest": disclosure_ref.digest,
        },
        "unresolved_items": [],
        "evidence_prefix": prefix_dict,
    }
    profile_ref = _retain_json(profile)
    loaded = ci.load_candidate_profile(CHANNEL, profile_ref)
    catalog = ci.load_playbook_catalog(CHANNEL, loaded.playbook_catalog)
    return profile_ref, catalog, head, ref, loaded


def _pin(policy_id: str, version: str = "1") -> dict:
    ref = _retain_json({"policy": policy_id, "version": version})
    return {"id": policy_id, "version": version, "artifact_digest": ref.digest}


def _policies(overrides: dict | None = None) -> dict:
    base = {
        "rubric": _pin("scoring_rubric"),
        "eligibility": _pin("eligibility_policy"),
        "tolerance": _pin("tolerance_policy"),
        "pay": _pin("pay_policy"),
        "veto": _pin("veto_policy"),
        "normalizer": _pin("reranker_normalizer"),
        "prompt": _pin("reranker_prompt"),
    }
    if overrides:
        base.update(overrides)
    return base


def _make_row(
    crawler_revision=3,
    seal_id="seal_eval_0001",
    target="target_test",
    job_id="job_001",
):
    first_extra = ev.append_event(
        CHANNEL, OWNER, _submission(100 + crawler_revision, f"crawler rev {crawler_revision}")
    )
    pub_ref = _head_ref(first_extra)
    head = ev.journal_head(CHANNEL, JOURNAL)
    seal_ref = _head_ref(first_extra)
    crawler_doc = {"document": {"revision": crawler_revision}, "crawler": None}
    # Canonical crawler document: revision + job identity.
    crawler_doc = {"revision": crawler_revision, "job": job_id, "crawler": "document"}
    crawler_doc_ref = _retain_json(crawler_doc)
    entity = {"entity_type": "job", "target": target, "job_id": job_id}
    row = {
        "record_type": "logical_row",
        "schema_version": "owner-separated-write-domains/0.1.0",
        "entity": entity,
        "registration_digest": "sha256:" + "a" * 64,
        "registration": {"registration_id": "reg_eval_0001", "entity": entity},
        "domains": {
            "crawler": {
                "revision": crawler_revision,
                "document": crawler_doc_ref.to_dict(),
                "publication_ref": pub_ref.to_dict(),
                "snapshot": {"revision": crawler_revision, "entity": entity},
            },
            "downstream": {
                "revision": 0,
                "value": {"value": None, "reason": "not_observed"},
            },
        },
        "seal_point": {
            "seal_id": seal_id,
            "name": "published",
            "view_id": "view_eval_0001",
            "versions": {"crawler": crawler_revision, "downstream": 0},
            "sealed_at": {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "monotonic_offset_ms": 2000.0,
                "utc_annotation": {"value": None, "reason": "not_observed"},
            },
            "input_prefix": {
                "journal_id": JOURNAL,
                "last_sequence": head.last_sequence,
                "head_hash": head.head_hash,
            },
            "evidence_refs": [seal_ref.to_dict()],
        },
    }
    return row, crawler_doc_ref, head, seal_ref


# ---------------------------------------------------------------------------
# 1. evaluation pin vs logical-row crawler slot
# ---------------------------------------------------------------------------


def test_evaluation_pin_differing_from_logical_row_crawler_slot_is_rejected():
    _setup()
    profile_ref, catalog, head, ref, loaded = _make_profile()
    row, doc_ref, row_head, seal_ref = _make_row(crawler_revision=3)
    policies = _policies()

    evaluation = asyncio.run(
        je.evaluate_job(CHANNEL, row, profile_ref, policies, "deterministic")
    )
    assert evaluation.job_input.crawler_input.revision == 3
    assert evaluation.job_input.crawler_input.record_digest == doc_ref.digest

    # Agreement validates.
    je.validate_crawler_pin(row, evaluation.job_input.crawler_input)
    je.validate_crawler_pin(row, evaluation.job_input.crawler_input.to_dict())

    # Differing revision is rejected.
    with pytest.raises(je.PinMismatchError):
        je.validate_crawler_pin(
            row, {"revision": 4, "record_digest": doc_ref.digest}
        )
    # Differing digest is rejected.
    with pytest.raises(je.PinMismatchError):
        je.validate_crawler_pin(
            row,
            {
                "revision": 3,
                "record_digest": "sha256:" + "f" * 64,
            },
        )
    # Zero revision pin is malformed/rejected.
    with pytest.raises((je.PinMismatchError, ValueError)):
        je.validate_crawler_pin(
            row,
            {
                "revision": 0,
                "record_digest": "sha256:" + "0" * 64,
            },
        )

    # Reference linkage mirrors the evaluation exactly.
    eval_bytes = _canonical(evaluation.to_dict())
    eval_ref_artifact = store.retain_artifact(
        CHANNEL, OWNER, "application/json", eval_bytes, "restricted"
    )
    eval_ref = je.build_evaluation_reference(
        evaluation, eval_ref_artifact, [seal_ref.to_dict()]
    )
    je.check_evaluation_reference(row, evaluation, eval_ref)

    # A tampered reference pin no longer matches the row slot.
    tampered = je.EvaluationReference(
        evaluation_id=eval_ref.evaluation_id,
        crawler_input=je.NonzeroDomainPin(
            revision=3,
            record_digest="sha256:" + "b" * 64,
        ),
        candidate_profile=eval_ref.candidate_profile,
        evaluation=eval_ref.evaluation,
        evidence_refs=eval_ref.evidence_refs,
    )
    with pytest.raises((je.EvaluationLinkageError, je.PinMismatchError)):
        je.check_evaluation_reference(row, evaluation, tampered)

    # A tampered evaluation job-input pin is rejected against the row.
    tampered_input = je.EvaluationJobInput(
        portfolio_job_id=evaluation.job_input.portfolio_job_id,
        source_key=evaluation.job_input.source_key,
        logical_row=evaluation.job_input.logical_row,
        logical_row_ref=evaluation.job_input.logical_row_ref,
        seal_id=evaluation.job_input.seal_id,
        crawler_input=je.NonzeroDomainPin(
            revision=9, record_digest=doc_ref.digest
        ),
    )
    with pytest.raises(je.PinMismatchError):
        je.validate_crawler_pin(row, tampered_input.crawler_input)


# ---------------------------------------------------------------------------
# 2. profile pin mismatch
# ---------------------------------------------------------------------------


def test_profile_pin_mismatch_between_reference_and_evaluation_artifact_is_rejected():
    _setup()
    profile_a, catalog_a, head_a, ref_a, loaded_a = _make_profile("cand_eval_A")
    profile_b, catalog_b, head_b, ref_b, loaded_b = _make_profile("cand_eval_B")
    assert profile_a.digest != profile_b.digest

    row, doc_ref, row_head, seal_ref = _make_row()
    policies = _policies()
    evaluation = asyncio.run(
        je.evaluate_job(CHANNEL, row, profile_a, policies, "deterministic")
    )
    assert evaluation.candidate_id == "cand_eval_A"

    # Agreement validates and returns the agreed digest.
    agreed = je.validate_profile_pin(profile_a, evaluation.candidate_profile)
    assert agreed == profile_a.digest
    agreed_dict = je.validate_profile_pin(
        profile_a.to_dict(), evaluation.candidate_profile.to_dict()
    )
    assert agreed_dict == profile_a.digest

    # Mismatch is rejected.
    with pytest.raises(je.ProfilePinMismatchError):
        je.validate_profile_pin(profile_b, evaluation.candidate_profile)

    eval_bytes = _canonical(evaluation.to_dict())
    eval_ref_artifact = store.retain_artifact(
        CHANNEL, OWNER, "application/json", eval_bytes, "restricted"
    )
    good_ref = je.EvaluationReference(
        evaluation_id=evaluation.evaluation_id,
        crawler_input=evaluation.job_input.crawler_input,
        candidate_profile=profile_a,
        evaluation=eval_ref_artifact,
        evidence_refs=(seal_ref,),
    )
    je.check_evaluation_reference(row, evaluation, good_ref)

    bad_ref = je.EvaluationReference(
        evaluation_id=evaluation.evaluation_id,
        crawler_input=evaluation.job_input.crawler_input,
        candidate_profile=profile_b,
        evaluation=eval_ref_artifact,
        evidence_refs=(seal_ref,),
    )
    with pytest.raises(je.ProfilePinMismatchError):
        je.check_evaluation_reference(row, evaluation, bad_ref)

    # A second evaluation bound to profile B cannot be cross-linked to A.
    evaluation_b = asyncio.run(
        je.evaluate_job(CHANNEL, row, profile_b, policies, "human_assessment")
    )
    cross_ref = je.EvaluationReference(
        evaluation_id=evaluation_b.evaluation_id,
        crawler_input=evaluation_b.job_input.crawler_input,
        candidate_profile=profile_a,
        evaluation=eval_ref_artifact,
        evidence_refs=(seal_ref,),
    )
    with pytest.raises(je.ProfilePinMismatchError):
        je.check_evaluation_reference(row, evaluation_b, cross_ref)


# ---------------------------------------------------------------------------
# 3. unknown playbook label
# ---------------------------------------------------------------------------


def test_unknown_playbook_label_retains_raw_response_and_surfaces_issue():
    _setup()
    profile_ref, catalog, head, ref, loaded = _make_profile()
    policies = _policies()
    rubric = je.VersionPin.from_dict(policies["rubric"])
    normalizer = je.VersionPin.from_dict(policies["normalizer"])

    raw = {
        "can_do_70_percent": True,
        "hard_blockers": [],
        "playbooks_matched": [
            "pb01_structural_deconstruction",
            "mystery_playbook_xyz",
        ],
        "would_tolerate": True,
        "pay_ok": "unknown",
        "legibility_gap": "none observed",
        "resume_translation": ["use systems vocabulary"],
        "score": 78,
    }
    raw_bytes = _canonical(raw)
    raw_ref = store.retain_artifact(
        CHANNEL, OWNER, "application/json", raw_bytes, "restricted"
    )
    roundtrip = store.resolve_artifact(CHANNEL, raw_ref)
    assert roundtrip == raw_bytes
    assert json.loads(roundtrip.decode("utf-8")) == raw
    assert "mystery_playbook_xyz" in roundtrip.decode("utf-8")

    normalized, issues = je.normalize_reranker_response(
        raw_bytes, catalog, rubric, normalizer, [ref.to_dict()]
    )
    assert normalized.playbooks_matched == ("pb01_structural_deconstruction",)
    assert "mystery_playbook_xyz" not in normalized.playbooks_matched
    codes = [item.code for item in issues]
    assert "unknown_playbook_label" in codes
    playbook_issues = [i for i in issues if i.code == "unknown_playbook_label"]
    assert len(playbook_issues) == 1
    assert "mystery_playbook_xyz" in playbook_issues[0].detail
    assert playbook_issues[0].affected_fields == ("playbooks_matched",)
    assert playbook_issues[0].detail != ""

    # Established fields are preserved; raw is not mutated.
    assert normalized.can_do_70_percent is True
    assert normalized.hard_blockers == ()
    assert normalized.pay_ok == "unknown"
    assert normalized.score == 78
    assert raw["playbooks_matched"] == [
        "pb01_structural_deconstruction",
        "mystery_playbook_xyz",
    ]
    raw_copy = dict(raw)
    raw_copy["playbooks_matched"] = list(raw["playbooks_matched"])
    normalized2, issues2 = je.normalize_reranker_response(
        _canonical(raw_copy), catalog, rubric, normalizer, [ref.to_dict()]
    )
    assert normalized2.playbooks_matched == ("pb01_structural_deconstruction",)
    assert any(i.code == "unknown_playbook_label" for i in issues2)

    # All-unknown labels: nothing known is invented, every label is surfaced.
    raw_all_unknown = dict(raw)
    raw_all_unknown["playbooks_matched"] = ["nope_one", "nope_two"]
    normalized3, issues3 = je.normalize_reranker_response(
        _canonical(raw_all_unknown), catalog, rubric, normalizer, [ref.to_dict()]
    )
    assert normalized3.playbooks_matched == ()
    assert sum(1 for i in issues3 if i.code == "unknown_playbook_label") == 2


# ---------------------------------------------------------------------------
# 4. unknown pay -> review
# ---------------------------------------------------------------------------


def test_unknown_pay_requires_automatic_review():
    _setup()
    profile_ref, catalog, head, ref, loaded = _make_profile()
    policies = _policies()
    rubric = je.VersionPin.from_dict(policies["rubric"])
    normalizer = je.VersionPin.from_dict(policies["normalizer"])
    pins = je.EvaluationPolicyPins.from_dict(policies)

    raw = {
        "can_do_70_percent": True,
        "hard_blockers": [],
        "playbooks_matched": ["pb02_human_asset_optimization"],
        "would_tolerate": True,
        "pay_ok": "unknown",
        "legibility_gap": "none",
        "resume_translation": [],
        "score": 78,
    }
    normalized, issues = je.normalize_reranker_response(
        _canonical(raw), catalog, rubric, normalizer, [ref.to_dict()]
    )
    assert normalized.pay_ok == "unknown"

    stage_one, stage_two, pay_decision, recommended = je.decide_stages(
        normalized, pins, [ref.to_dict()]
    )
    assert stage_one.result == "pass"
    assert stage_two.result == "pass"
    assert pay_decision == "unknown"
    assert recommended == "review"
    assert recommended != "go"

    # Acceptable pay with passing stages is the only automatic go.
    raw_go = dict(raw, pay_ok="acceptable")
    normalized_go, _ = je.normalize_reranker_response(
        _canonical(raw_go), catalog, rubric, normalizer, [ref.to_dict()]
    )
    pay_go = je.decide_stages(normalized_go, pins, [ref.to_dict()])
    assert pay_go[2] == "acceptable"
    assert pay_go[3] == "go"

    # Unacceptable pay is an automatic no-go even with passing stages.
    raw_nogo = dict(raw, pay_ok="unacceptable")
    normalized_nogo, _ = je.normalize_reranker_response(
        _canonical(raw_nogo), catalog, rubric, normalizer, [ref.to_dict()]
    )
    pay_nogo = je.decide_stages(normalized_nogo, pins, [ref.to_dict()])
    assert pay_nogo[2] == "unacceptable"
    assert pay_nogo[3] == "no_go"

    # End to end: an evaluation without an established pay assessment
    # stays at review and never becomes an automatic go.
    row, doc_ref, row_head, seal_ref = _make_row()
    evaluation = asyncio.run(
        je.evaluate_job(CHANNEL, row, profile_ref, policies, "deterministic")
    )
    assert evaluation.pay_decision == "unknown"
    assert evaluation.recommended_selection == "review"
    assert evaluation.recommended_selection != "go"

    # The decision table never emits go for unknown pay: the observed
    # recommendation contradicts any hand-built go claim.
    assert (stage_one.result, stage_two.result, pay_decision, recommended) == (
        "pass",
        "pass",
        "unknown",
        "review",
    )
    assert recommended != "go"


# ---------------------------------------------------------------------------
# 5. missing scoring rubric
# ---------------------------------------------------------------------------


def test_missing_scoring_rubric_prevents_invented_score_semantics():
    _setup()
    profile_ref, catalog, head, ref, loaded = _make_profile()
    normalizer = je.VersionPin.from_dict(_pin("reranker_normalizer"))
    rubric_present = je.VersionPin.from_dict(_pin("scoring_rubric"))
    rubric_missing = je.Missing(
        reason="not_observed", detail="No scoring rubric is pinned."
    )

    raw = {
        "can_do_70_percent": True,
        "hard_blockers": [],
        "playbooks_matched": [],
        "would_tolerate": True,
        "pay_ok": "acceptable",
        "legibility_gap": "none",
        "resume_translation": [],
        "score": 78,
    }
    raw_bytes = _canonical(raw)
    raw_ref = store.retain_artifact(
        CHANNEL, OWNER, "application/json", raw_bytes, "restricted"
    )
    assert store.resolve_artifact(CHANNEL, raw_ref) == raw_bytes

    # With a pinned rubric the numeric score is preserved without invention.
    normalized_with, issues_with = je.normalize_reranker_response(
        raw_bytes, catalog, rubric_present, normalizer, [ref.to_dict()]
    )
    assert normalized_with.score == 78
    assert not any(i.code == "missing_scoring_rubric" for i in issues_with)

    # Without a rubric the score stays Missing and an issue is surfaced.
    normalized_without, issues_without = je.normalize_reranker_response(
        raw_bytes, catalog, rubric_missing, normalizer, [ref.to_dict()]
    )
    assert je._is_missing_value(normalized_without.score)
    assert normalized_without.score.reason == "not_observed"
    codes = [i.code for i in issues_without]
    assert "missing_scoring_rubric" in codes
    rubric_issue = [i for i in issues_without if i.code == "missing_scoring_rubric"][0]
    assert rubric_issue.affected_fields == ("score",)
    assert rubric_issue.detail != ""
    assert "78" in raw_bytes.decode("utf-8")
    assert json.loads(raw_bytes.decode("utf-8"))["score"] == 78

    # Scores never drive stage semantics: low vs high scores decide alike.
    pins_missing_rubric = je.EvaluationPolicyPins.from_dict(
        _policies({"rubric": rubric_missing.to_dict()})
    )
    raw_bare = dict(raw)
    normalized_bare, _ = je.normalize_reranker_response(
        _canonical(raw_bare), catalog, rubric_missing, normalizer, [ref.to_dict()]
    )
    assert je._is_missing_value(normalized_bare.score)
    stage_one, stage_two, pay, recommended = je.decide_stages(
        normalized_bare, pins_missing_rubric, [ref.to_dict()]
    )
    assert (stage_one.result, stage_two.result) == ("pass", "pass")

    raw_low = dict(raw, score=5)
    normalized_low, _ = je.normalize_reranker_response(
        _canonical(raw_low), catalog, rubric_present, normalizer, [ref.to_dict()]
    )
    assert normalized_low.score == 5
    pins_full = je.EvaluationPolicyPins.from_dict(_policies())
    s1, s2, pay2, rec = je.decide_stages(normalized_low, pins_full, [ref.to_dict()])
    s1b, s2b, _, recb = je.decide_stages(normalized_with, pins_full, [ref.to_dict()])
    assert (s1.result, s2.result, rec) == (s1b.result, s2b.result, recb)
    assert (s1.result, s2.result, rec) == ("pass", "pass", "go")


# ---------------------------------------------------------------------------
# 6. embedding model / dimension mismatch
# ---------------------------------------------------------------------------


def test_embedding_model_or_dimension_mismatch_invalidates_similarity_comparison():
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(7, "embedding evidence"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = _head_ref(first)
    profile_snap = _retain_json({"profile": "snapshot"})
    job_snap = _retain_json({"job": "snapshot"})

    def _embedding(
        model="embed-model-v1", dim=3, profile_len=3, job_len=3, method="cosine"
    ):
        return {
            "record_type": "job_profile_embedding_comparison",
            "schema_version": "job-hunter-embedding/0.1.0",
            "comparison_id": "cmp_eval_0001",
            "candidate_profile": profile_snap.to_dict(),
            "job_snapshot": job_snap.to_dict(),
            "chunking_policy": {
                "id": "chunking",
                "version": "1",
                "artifact_digest": _retain_json({"chunk": 1}).digest,
            },
            "model": model,
            "vector_dimension": dim,
            "profile_vectors": [
                {"chunk_id": "c1", "values": [0.1] * profile_len},
                {"chunk_id": "c2", "values": [0.2] * profile_len},
            ],
            "job_vector": {"chunk_id": "job", "values": [0.3] * job_len},
            "similarity_method": method,
            "similarities": [
                {"chunk_id": "c1", "score": 0.9},
                {"chunk_id": "c2", "score": 0.8},
            ],
            "evidence_refs": [ref.to_dict()],
        }

    valid = _embedding()
    summary = je.validate_embedding_comparison(
        valid, expected_model="embed-model-v1", expected_dimension=3
    )
    assert summary["status"] == "valid"
    assert summary["vector_dimension"] == 3

    # Expected-model mismatch invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            valid, expected_model="embed-model-v2", expected_dimension=3
        )
    # Artifact-model mismatch invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            _embedding(model="embed-model-v2"),
            expected_model="embed-model-v1",
            expected_dimension=3,
        )
    # Expected-dimension mismatch invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            valid, expected_model="embed-model-v1", expected_dimension=4
        )
    # Profile vector length mismatch invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            _embedding(dim=3, profile_len=4), expected_dimension=3
        )
    # Job vector length mismatch invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            _embedding(dim=3, job_len=2), expected_dimension=3
        )
    # Non-cosine method invalidates.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(
            _embedding(method="dot"), expected_dimension=3
        )
    # Declared dimension must match vectors even without expectations.
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison(_embedding(dim=3, profile_len=2))
    with pytest.raises((je.EmbeddingMismatchError, TypeError, ValueError)):
        je.validate_embedding_comparison({"record_type": "wrong"})

    # Disabled embedding is Missing(not_enabled), never zero similarity.
    disabled = {"value": None, "reason": "not_enabled"}
    summary_disabled = je.validate_embedding_comparison(disabled)
    assert summary_disabled["status"] == "disabled"
    assert summary_disabled["reason"] == "not_enabled"
    disabled_obj = je.Missing(reason="not_enabled")
    assert je.validate_embedding_comparison(disabled_obj)["status"] == "disabled"
    # Other missing reasons are not "disabled".
    with pytest.raises(je.EmbeddingMismatchError):
        je.validate_embedding_comparison({"value": None, "reason": "not_observed"})
    # Bytes round-trip validates identically.
    summary_bytes = je.validate_embedding_comparison(
        _canonical(valid), expected_model="embed-model-v1", expected_dimension=3
    )
    assert summary_bytes["status"] == "valid"
