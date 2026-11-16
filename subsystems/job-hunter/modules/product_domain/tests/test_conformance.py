"""Conformance tests for product_domain (tier 7).

Covers exactly the ``-k`` filter named in the module spec:

- ``job_hunter_writing_crawler_fields_rejects_entire_write``
- ``selection_transitions_require_new_authorized_rationale_and_preserve_history``
- ``product_attempt_links_require_registered_commissions_without_inheriting_outcomes``

Every check exercises the real module: strict downstream shape validation,
crawler-field rejection with no revision advance, stale-revision rejection,
authorized selection transitions with history preservation, and durable
commission verification without outcome inheritance.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "product_domain":
        path = here.parents[1] / "src" / "__init__.py"
    else:
        path = here.parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


pd = _load("product_domain")
ap = _load("access_policy")
store = _load("artifact_store")
ev = _load("evidence_journal")
orv = _load("owner_revisions")

try:
    la = _load("lease_authority")
except Exception:
    la = None

D0 = "sha256:" + "0" * 64
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
D9 = "sha256:" + "9" * 64
POLICY = {"id": "policy_product_test", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_product_test"
BOOT_ID = "boot_product_test"


@pytest.fixture(autouse=True)
def _fresh_state():
    pd.reset_for_tests()
    orv.reset_for_tests()
    ev.reset_for_tests()
    if la is not None:
        try:
            la.reset_for_tests()
        except Exception:
            pass
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    if la is not None:
        try:
            la.reset_for_tests()
        except Exception:
            pass
    ev.reset_for_tests()
    orv.reset_for_tests()
    pd.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _evidence_ref(tag: str, sequence: int = 1) -> dict[str, Any]:
    return {
        "journal_id": f"journal_{tag}",
        "sequence": sequence,
        "event_id": f"event_{tag}",
        "event_hash": D1,
        "pointer": "",
    }


def _artifact_dict(
    digest: str = D1,
    owner_domain: str = "job.downstream",
    access: str = "public",
    size: int = 1,
) -> dict[str, Any]:
    return {
        "digest": digest,
        "size_bytes": size,
        "media_type": "application/json",
        "owner_domain": owner_domain,
        "access": access,
    }


def _register(
    actor: str,
    channel_id: str,
    axis: str,
    producer_id: str,
    principal_id: str,
    *,
    kinds: tuple[str, ...] | None = None,
) -> Any:
    return ap.register_channel(
        actor=actor,
        channel_id=channel_id,
        axis=axis,
        producer_id=producer_id,
        principal_id=principal_id,
        sequence_required=False,
        allowed_event_kinds=kinds or (f"{axis}.published",),
    )


def _product_journal(
    suffix: str = "0001",
    *,
    kind: str = "product.published",
) -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    channel = f"ch_product_{suffix}"
    producer = f"prod_product_{suffix}"
    principal = f"principal_product_{suffix}"
    _register("product_writer", channel, "job.downstream", producer, principal, kinds=(kind,))
    ap.register_event_kind(
        kind,
        "1",
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain="job.downstream",
        writer_roles=("kernel",),
    )
    task = store.retain_artifact(
        channel, "job.downstream", "application/json", b'{"task":"product-task"}', "restricted"
    )
    config = store.retain_artifact(
        channel, "job.downstream", "application/json", b'{"config":"product-config"}', "restricted"
    )
    manifest = ev.Manifest(
        manifest_id=f"manifest_product_{suffix}",
        run_id=f"run_product_{suffix}",
        journal_id=f"journal_product_{suffix}",
        owner_domain="job.downstream",
        commissioner_id="commissioner_product",
        activity="discovery",
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
        task_semantic_hash=D0,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[{"id": "build_task", "version": "1", "artifact_digest": task.digest}],
        event_registry=[
            {
                "event_kind": kind,
                "event_schema_version": "1",
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": producer,
                "principal_id": principal,
                "owner_domain": "job.downstream",
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": [kind],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_product_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    admission = ev.admit_manifest(channel, manifest)
    prefix = {
        "journal_id": admission.journal_id,
        "last_sequence": 1,
        "head_hash": admission.event_hash,
    }
    first_ref = {
        "journal_id": admission.journal_id,
        "sequence": 1,
        "event_id": admission.event_id,
        "event_hash": admission.event_hash,
        "pointer": "",
    }
    return channel, producer, prefix, first_ref


def _job_registration(
    producer: str,
    prefix: dict[str, Any],
    first_ref: dict[str, Any],
    *,
    target: str = "target_product",
    job_id: str = "job_product",
    portfolio_job_id: str = "portfolio_product_1",
    reg_id: str = "reg_product_job_0001",
) -> Any:
    return orv.EntityRegistration(
        registration_id=reg_id,
        entity={"entity_type": "job", "target": target, "job_id": job_id},
        identity={
            "portfolio_job_id": portfolio_job_id,
            "first_discovery_ref": first_ref,
        },
        owners={
            "crawler": {
                "role": "crawler",
                "source_id": "src_product_crawler",
                "writer_id": "prod_product_crawler",
                "owner_domain": "job.crawler",
                "publication_policy": POLICY,
            },
            "downstream": {
                "role": "product",
                "source_id": "src_product_downstream",
                "writer_id": producer,
                "owner_domain": "job.downstream",
                "publication_policy": POLICY,
            },
        },
        evidence_prefix=prefix,
        evidence_refs=[first_ref],
    )


def _selection(
    decision: str,
    rationale: str,
    tag: str,
    *,
    evaluation_id: Any = None,
) -> dict[str, Any]:
    if evaluation_id is None:
        evaluation_id = _missing("not_observed")
    return {
        "decision": decision,
        "evaluation_id": evaluation_id,
        "rationale": rationale,
        "evidence_refs": [_evidence_ref(tag)],
    }


def _ownership_unclaimed(tag: str = "ownership") -> dict[str, Any]:
    return {
        "state": "unclaimed",
        "claimant": _missing("not_applicable"),
        "lease": _missing("not_applicable"),
        "evidence_refs": [_evidence_ref(tag)],
    }


def _evaluation(eval_id: str, digest: str = D2) -> dict[str, Any]:
    return {
        "evaluation_id": eval_id,
        "crawler_input": {"revision": 1, "record_digest": digest},
        "candidate_profile": _artifact_dict(digest=D2),
        "evaluation": _artifact_dict(digest=D3),
        "evidence_refs": [_evidence_ref(eval_id)],
    }


def _material(material_id: str, digest: str = D2) -> dict[str, Any]:
    return {
        "artifact_id": material_id,
        "role": "resume",
        "content": _artifact_dict(digest=digest),
        "evidence_refs": [_evidence_ref(material_id)],
    }


def _attempt_link(attempt_id: str, kind: str, commission_digest: str, tag: str) -> dict[str, Any]:
    return {
        "attempt": {"attempt_id": attempt_id, "kind": kind},
        "commission_digest": commission_digest,
        "evidence_refs": [_evidence_ref(tag)],
    }


def _downstream_value(
    *,
    track: Any = "review",
    priority: Any = 0.5,
    selection: Any = None,
    ownership: Any = None,
    evaluations: list[dict[str, Any]] | None = None,
    materials: list[dict[str, Any]] | None = None,
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if selection is None:
        selection = _missing("not_observed")
    if ownership is None:
        ownership = _ownership_unclaimed()
    return {
        "track": track,
        "priority_hint": priority,
        "selection": selection,
        "ownership": ownership,
        "evaluations": list(evaluations or []),
        "materials": list(materials or []),
        "application_attempts": list(attempts or []),
    }


def _commission_dict(
    *,
    attempt_id: str,
    kind: str,
    portfolio_job_id: str,
    source_target: Any,
    source_job_id: Any,
) -> dict[str, Any]:
    return {
        "record_type": "attempt_commission",
        "schema_version": "application-attempt-lifecycle/0.1.0",
        "kernel_version": "evidence-kernel/0.1.0",
        "commission_id": f"commission_{attempt_id}",
        "run_id": f"run_{attempt_id}",
        "journal_id": f"journal_{attempt_id}",
        "manifest_hash": D0,
        "admission_ref": _evidence_ref(f"admission_{attempt_id}"),
        "commissioned_by": "operator_product_test",
        "commissioned_at": {
            "clock_id": CLOCK_ID,
            "boot_id": BOOT_ID,
            "origin": "engine_measured",
            "monotonic_offset_ms": 10.0,
            "utc_annotation": _missing("not_observed"),
        },
        "attempt": {
            "attempt_id": attempt_id,
            "kind": kind,
            "target_class": "employer_origin" if kind == "production" else "laboratory_fixture",
            "target_id": "target_product_origin",
            "evaluation_partition": "held_out" if kind == "production" else "held_in",
            "rehearsal_of": [],
            "performance_of": [],
            "derived_from": [],
        },
        "candidate_id": "candidate_product_1",
        "candidate_profile": _missing("not_observed"),
        "job": {
            "job_id": portfolio_job_id,
            "source_target": source_target,
            "source_job_id": source_job_id,
            "snapshot": _artifact_dict(digest=D2),
        },
        "selection_evidence": _missing("not_observed"),
        "task": _artifact_dict(digest=D3),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": {"mode": "manual"},
        "owners": {},
        "idempotency_key": f"idem_{attempt_id}",
        "authorization_refs": [_evidence_ref(f"auth_{attempt_id}")],
        "recovery_review_refs": [],
        "observation_policy": {},
        "origin_policy": POLICY,
    }


def _retain_and_register_commission(
    channel: str, commission: dict[str, Any]
) -> tuple[Any, str, bytes]:
    payload = json.dumps(commission, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ref = store.retain_artifact(channel, "job.downstream", "application/json", payload, "public")
    pd.register_commission_reference(ref)
    return ref, ref.digest, payload


# ---------------------------------------------------------------------------
# 1. Crawler fields reject the entire write
# ---------------------------------------------------------------------------


def test_job_hunter_writing_crawler_fields_rejects_entire_write():
    channel, producer, prefix, first_ref = _product_journal("crawler1")
    registration = _job_registration(producer, prefix, first_ref)
    orv.register_entity(channel, registration)
    entity = {"entity_type": "job", "target": "target_product", "job_id": "job_product"}

    base_value = _downstream_value(
        track="review", priority=0.5, materials=[_material("mat_crawler_base")]
    )
    rev1 = pd.publish_product_revision(
        channel, registration, 0, "cmd_pd_crawler_base", base_value, _missing()
    )
    assert rev1.revision == 1
    assert rev1.previous_revision == 0
    assert rev1.domain == "downstream"
    assert rev1.owner_domain == "job.downstream"
    assert rev1.writer_id == producer
    assert set(rev1.value.keys()) == {
        "track",
        "priority_hint",
        "selection",
        "ownership",
        "evaluations",
        "materials",
        "application_attempts",
    }
    assert orv.domain_head(channel, entity, "downstream") == 1

    # A top-level crawler acquisition field rejects the entire write.
    bad_value = copy.deepcopy(base_value)
    bad_value["track"] = "go"
    bad_value["source_url"] = "https://example.com/job/1"
    with pytest.raises(pd.CrawlerFieldRejectedError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_crawler_bad1", bad_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # Crawler fetch/content/classification groups are equally rejected.
    for crawler_field in ("fetch_key", "content", "classifier_results", "acquisition", "coverage"):
        smuggled = copy.deepcopy(base_value)
        smuggled["track"] = "go"
        smuggled[crawler_field] = {"smuggled": True}
        with pytest.raises(pd.CrawlerFieldRejectedError):
            pd.publish_product_revision(
                channel, registration, 1, f"cmd_pd_crawler_{crawler_field}", smuggled, _missing()
            )
        assert orv.domain_head(channel, entity, "downstream") == 1

    # An undeclared field outside both domains is also a cross-domain write.
    unknown = copy.deepcopy(base_value)
    unknown["tracker_status"] = "APPLIED"
    with pytest.raises((pd.CrawlerFieldRejectedError, pd.InvalidDownstreamValueError)):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_crawler_unknown", unknown, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # A stale expected revision rejects the entire write without lost fields.
    stale_value = copy.deepcopy(base_value)
    stale_value["track"] = "go"
    stale_value["priority_hint"] = 0.9
    with pytest.raises((orv.StaleRevisionError, orv.RevisionIntegrityError)):
        pd.publish_product_revision(
            channel, registration, 0, "cmd_pd_crawler_stale", stale_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1
    head = orv.read_domain(channel, entity, "downstream")
    assert not isinstance(head, dict)
    assert head.value == base_value

    # The clean retry at the correct base succeeds with no crawler residue.
    good_value = copy.deepcopy(base_value)
    good_value["track"] = "go"
    good_value["priority_hint"] = 0.9
    rev2 = pd.publish_product_revision(
        channel, registration, 1, "cmd_pd_crawler_good", good_value, _missing()
    )
    assert rev2.revision == 2
    assert rev2.previous_revision == 1
    assert orv.domain_head(channel, entity, "downstream") == 2
    for key in pd.CRAWLER_FIELDS:
        assert key not in rev2.value
    assert rev2.value["track"] == "go"
    assert rev2.value["materials"] == base_value["materials"]

    # Prior revisions remain byte-identical; nothing was merged or lost.
    first = orv.read_revision(channel, entity, "downstream", 1)
    second = orv.read_revision(channel, entity, "downstream", 2)
    assert not isinstance(first, dict) and not isinstance(second, dict)
    assert first.value == base_value
    assert second.value == good_value

    # A crawler refresh preserves the separately published downstream domain:
    # commit a crawler revision directly and verify downstream is untouched.
    _register(
        "crawler_writer",
        "ch_product_crawler_peer",
        "job.crawler",
        "prod_product_crawler",
        "principal_product_crawler",
    )
    crawler_prefix = {
        "journal_id": "journal_crawler_peer_unadmitted",
        "last_sequence": 1,
        "head_hash": D1,
    }
    crawler_revision = orv.DataDomainRevision(
        entity={"entity_type": "job", "target": "target_product", "job_id": "job_product"},
        registration_digest=second.record["registration_digest"],
        domain="crawler",
        owner_domain="job.crawler",
        writer_id="prod_product_crawler",
        revision=1,
        previous_revision=0,
        evidence_prefix=crawler_prefix,
        evidence_refs=[_evidence_ref("crawler_peer")],
        value={
            "acquisition": {"fetch_key": "key_peer_1"},
            "processing": {"pipeline_state": "ready"},
            "discovery": {"coverage": []},
            "replacement_lineage": _missing("not_observed"),
        },
    )
    orv.commit_domain(
        "ch_product_crawler_peer", registration, crawler_revision, "cmd_crawler_peer", _missing()
    )
    assert orv.domain_head(channel, entity, "downstream") == 2
    downstream_after = orv.read_domain(channel, entity, "downstream")
    assert not isinstance(downstream_after, dict)
    assert downstream_after.value == good_value


# ---------------------------------------------------------------------------
# 2. Selection transitions require new authorized rationale + history
# ---------------------------------------------------------------------------


def test_selection_transitions_require_new_authorized_rationale_and_preserve_history():
    channel, producer, prefix, first_ref = _product_journal("select1")
    registration = _job_registration(producer, prefix, first_ref)
    orv.register_entity(channel, registration)
    entity = {"entity_type": "job", "target": "target_product", "job_id": "job_product"}

    seed_value = _downstream_value(
        track="review",
        priority=0.5,
        evaluations=[_evaluation("eval_select_1")],
        materials=[_material("mat_select_1")],
    )
    rev1 = pd.publish_product_revision(
        channel, registration, 0, "cmd_pd_select_base", seed_value, _missing()
    )
    assert rev1.revision == 1
    assert pd.selection_history(entity) == ()

    # Initial selection may become go with evidence.
    go_value = copy.deepcopy(seed_value)
    go_value["selection"] = _selection("go", "initial go: strong skill match, verified scope", "sel_go_1")
    rev2 = pd.publish_product_revision(
        channel, registration, 1, "cmd_pd_select_go", go_value, _missing()
    )
    assert rev2.revision == 2
    history = pd.selection_history(entity)
    assert len(history) == 1
    assert history[0]["decision"] == "go"
    assert history[0]["revision"] == 2

    # Reusing the prior rationale for a new decision is rejected.
    veto_reuse = copy.deepcopy(go_value)
    veto_reuse["selection"] = _selection(
        "no_go", "initial go: strong skill match, verified scope", "sel_veto_reuse"
    )
    with pytest.raises(pd.SelectionTransitionError):
        pd.publish_product_revision(
            channel, registration, 2, "cmd_pd_select_reuse", veto_reuse, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 2

    # A transition without support evidence is rejected (shape-level).
    veto_no_evidence = copy.deepcopy(go_value)
    veto_no_evidence["selection"] = {
        "decision": "no_go",
        "evaluation_id": _missing("not_observed"),
        "rationale": "new veto: compensation band mismatch",
        "evidence_refs": [],
    }
    with pytest.raises((pd.SelectionTransitionError, pd.InvalidDownstreamValueError)):
        pd.publish_product_revision(
            channel, registration, 2, "cmd_pd_select_noev", veto_no_evidence, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 2

    # An unauthorized channel cannot author a selection transition.
    _register(
        "dashboard",
        "ch_product_dashboard",
        "presentation.dashboard",
        "prod_product_dashboard",
        "principal_product_dashboard",
    )
    veto_value = copy.deepcopy(go_value)
    veto_value["selection"] = _selection(
        "no_go", "new veto: compensation band mismatch, evidenced posting text", "sel_veto_1"
    )
    with pytest.raises(Exception):
        pd.publish_product_revision(
            "ch_product_dashboard", registration, 2, "cmd_pd_select_unauth", veto_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 2

    # Go becomes no-go with a new authorized rationale.
    rev3 = pd.publish_product_revision(
        channel, registration, 2, "cmd_pd_select_veto", veto_value, _missing()
    )
    assert rev3.revision == 3
    assert rev3.value["selection"]["decision"] == "no_go"

    # No-go returns to review for reconsideration with new rationale.
    review_value = copy.deepcopy(veto_value)
    review_value["selection"] = _selection(
        "review", "reconsideration: new salary disclosure, re-evaluate scope", "sel_review_1"
    )
    rev4 = pd.publish_product_revision(
        channel, registration, 3, "cmd_pd_select_review", review_value, _missing()
    )
    assert rev4.revision == 4

    # No-go/review becomes go only with explicit new rationale.
    go2_value = copy.deepcopy(review_value)
    go2_value["selection"] = _selection(
        "go", "explicit new rationale: veto resolved, hiring manager confirmed band", "sel_go_2"
    )
    rev5 = pd.publish_product_revision(
        channel, registration, 4, "cmd_pd_select_go2", go2_value, _missing()
    )
    assert rev5.revision == 5

    # Same-state revisions may add support with a new rationale.
    go3_value = copy.deepcopy(go2_value)
    go3_value["selection"] = _selection(
        "go", "additional support: second evaluation corroborates fit", "sel_go_3"
    )
    rev6 = pd.publish_product_revision(
        channel, registration, 5, "cmd_pd_select_go3", go3_value, _missing()
    )
    assert rev6.revision == 6

    # Clearing a concrete selection back to Missing is rejected.
    cleared = copy.deepcopy(go3_value)
    cleared["selection"] = _missing("not_observed")
    with pytest.raises(pd.SelectionTransitionError):
        pd.publish_product_revision(
            channel, registration, 6, "cmd_pd_select_clear", cleared, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 6

    # History preserves every authorized decision in order without rewrites.
    history = pd.selection_history(entity)
    assert [h["decision"] for h in history] == ["go", "no_go", "review", "go", "go"]
    assert [h["revision"] for h in history] == [2, 3, 4, 5, 6]
    rationales = [h["rationale"] for h in history]
    assert len(set(rationales)) == 5
    assert history[0]["rationale"].startswith("initial go")
    assert history[1]["rationale"].startswith("new veto")

    # Unrelated downstream fields are preserved across every transition.
    for revision_no in (2, 3, 4, 5, 6):
        published = orv.read_revision(channel, entity, "downstream", revision_no)
        assert not isinstance(published, dict)
        assert published.value["evaluations"] == seed_value["evaluations"]
        assert published.value["materials"] == seed_value["materials"]
        assert published.value["track"] == "review"
        assert published.value["ownership"] == seed_value["ownership"]

    # Prior decisions remain journaled at their original revisions.
    second = orv.read_revision(channel, entity, "downstream", 2)
    third = orv.read_revision(channel, entity, "downstream", 3)
    assert not isinstance(second, dict) and not isinstance(third, dict)
    assert second.value["selection"]["decision"] == "go"
    assert third.value["selection"]["decision"] == "no_go"
    assert second.value["selection"]["rationale"] != third.value["selection"]["rationale"]


# ---------------------------------------------------------------------------
# 3. Attempt links require registered commissions without outcome inheritance
# ---------------------------------------------------------------------------


def test_product_attempt_links_require_registered_commissions_without_inheriting_outcomes():
    channel, producer, prefix, first_ref = _product_journal("attempt1")
    portfolio_job_id = "portfolio_product_attempt"
    registration = _job_registration(
        producer, prefix, first_ref, portfolio_job_id=portfolio_job_id
    )
    orv.register_entity(channel, registration)
    entity = {"entity_type": "job", "target": "target_product", "job_id": "job_product"}

    base_value = _downstream_value(
        track="review", priority=0.5, materials=[_material("mat_attempt_base")]
    )
    pd.publish_product_revision(
        channel, registration, 0, "cmd_pd_attempt_base", base_value, _missing()
    )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # A durable registered commission identifying this portfolio job.
    good_commission = _commission_dict(
        attempt_id="attempt_product_1",
        kind="production",
        portfolio_job_id=portfolio_job_id,
        source_target="target_product",
        source_job_id="job_product",
    )
    good_ref, good_digest, good_bytes = _retain_and_register_commission(channel, good_commission)

    # A durable commission for a different portfolio job.
    other_commission = _commission_dict(
        attempt_id="attempt_product_2",
        kind="production",
        portfolio_job_id="portfolio_product_other",
        source_target="target_product",
        source_job_id="job_other",
    )
    _, other_digest, _ = _retain_and_register_commission(channel, other_commission)

    # An unknown (never retained/registered) commission digest is rejected.
    unknown_link = _attempt_link("attempt_product_9", "production", D9, "link_unknown")
    unknown_value = copy.deepcopy(base_value)
    unknown_value["application_attempts"] = [unknown_link]
    with pytest.raises(pd.CommissionNotDurableError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_attempt_unknown", unknown_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # A cross-job commission is rejected even though it is durable.
    cross_link = _attempt_link("attempt_product_2", "production", other_digest, "link_cross")
    cross_value = copy.deepcopy(base_value)
    cross_value["application_attempts"] = [cross_link]
    with pytest.raises(pd.CommissionNotDurableError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_attempt_cross", cross_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # A mismatched attempt identity against the same digest is rejected.
    mismatch_link = _attempt_link("attempt_product_WRONG", "production", good_digest, "link_mismatch")
    mismatch_value = copy.deepcopy(base_value)
    mismatch_value["application_attempts"] = [mismatch_link]
    with pytest.raises(pd.CommissionNotDurableError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_attempt_mismatch", mismatch_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # An outcome-inheriting link (extra status/outcome field) is rejected.
    outcome_link = _attempt_link("attempt_product_1", "production", good_digest, "link_outcome")
    outcome_link["outcome"] = "hired"
    outcome_value = copy.deepcopy(base_value)
    outcome_value["application_attempts"] = [outcome_link]
    with pytest.raises(pd.AttemptLinkError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_attempt_outcome", outcome_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    status_link = _attempt_link("attempt_product_1", "production", good_digest, "link_status")
    status_link["status"] = "applied"
    status_value = copy.deepcopy(base_value)
    status_value["application_attempts"] = [status_link]
    with pytest.raises(pd.AttemptLinkError):
        pd.publish_product_revision(
            channel, registration, 1, "cmd_pd_attempt_status", status_value, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 1

    # The valid link commits, preserving unrelated fields and carrying no outcome.
    valid_link = _attempt_link("attempt_product_1", "production", good_digest, "link_valid")
    linked_value = copy.deepcopy(base_value)
    linked_value["application_attempts"] = [valid_link]
    rev2 = pd.publish_product_revision(
        channel, registration, 1, "cmd_pd_attempt_link", linked_value, _missing()
    )
    assert rev2.revision == 2
    assert rev2.value["application_attempts"] == [valid_link]
    assert set(rev2.value["application_attempts"][0].keys()) == {
        "attempt",
        "commission_digest",
        "evidence_refs",
    }
    assert rev2.value["track"] == base_value["track"]
    assert rev2.value["materials"] == base_value["materials"]
    assert orv.domain_head(channel, entity, "downstream") == 2

    # A selection change preserves the link and never mutates the commission.
    before = store.resolve_artifact(channel, good_ref)
    assert before == good_bytes
    selected = copy.deepcopy(linked_value)
    selected["selection"] = _selection(
        "go", "go with commissioned attempt: evidence-backed fit", "sel_attempt_go"
    )
    rev3 = pd.publish_product_revision(
        channel, registration, 2, "cmd_pd_attempt_select", selected, _missing()
    )
    assert rev3.revision == 3
    assert rev3.value["application_attempts"] == [valid_link]
    after = store.resolve_artifact(channel, good_ref)
    assert after == good_bytes
    assert after == before

    # Attempt history is append-only: dropping the link is rejected.
    dropped = copy.deepcopy(selected)
    dropped["application_attempts"] = []
    with pytest.raises(pd.InvalidDownstreamValueError):
        pd.publish_product_revision(
            channel, registration, 3, "cmd_pd_attempt_drop", dropped, _missing()
        )
    assert orv.domain_head(channel, entity, "downstream") == 3

    # A second commissioned attempt appends without rewriting the first.
    second_commission = _commission_dict(
        attempt_id="attempt_product_3",
        kind="production",
        portfolio_job_id=portfolio_job_id,
        source_target="target_product",
        source_job_id="job_product",
    )
    _, second_digest, _ = _retain_and_register_commission(channel, second_commission)
    second_link = _attempt_link("attempt_product_3", "production", second_digest, "link_valid_2")
    appended = copy.deepcopy(selected)
    appended["application_attempts"] = [valid_link, second_link]
    rev4 = pd.publish_product_revision(
        channel, registration, 3, "cmd_pd_attempt_append", appended, _missing()
    )
    assert rev4.revision == 4
    assert rev4.value["application_attempts"] == [valid_link, second_link]
