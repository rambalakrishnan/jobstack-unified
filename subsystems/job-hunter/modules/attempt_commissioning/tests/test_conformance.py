"""Conformance tests for attempt_commissioning (tier 5)."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "attempt_commissioning":
        path = here.parents[1] / "src" / "__init__.py"
    else:
        path = here.parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("access_policy")
store = _load("artifact_store")
ev = _load("evidence_journal")
orv = _load("owner_revisions")
ac = _load("attempt_commissioning")

D0 = "sha256:" + "0" * 64
POLICY = {"id": "policy_test", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_comm_test"
BOOT_ID = "boot_comm_test"


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    store.reset_for_tests()
    ev.reset_for_tests()
    orv.reset_for_tests()
    ac.reset_for_tests()
    yield
    ac.reset_for_tests()
    orv.reset_for_tests()
    ev.reset_for_tests()
    store.reset_for_tests()
    ap.reset_for_tests()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _missing_observed() -> dict[str, Any]:
    return {"value": None, "reason": "not_observed"}


def _timepoint(offset: float = 1.0) -> dict[str, Any]:
    return {
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing_observed(),
    }


def _register_app_channel(
    channel: str = "ch_comm_app",
    producer: str = "prod_comm_app",
    principal: str = "principal_comm",
) -> None:
    ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=channel,
        axis="attempt.application",
        producer_id=producer,
        principal_id=principal,
        sequence_required=False,
        allowed_event_kinds=("attempt.commissioned",),
        binding="bind_comm_app",
    )
    ap.register_event_kind(
        "attempt.commissioned",
        "1",
        role="lifecycle_observation",
        assertion_kind="authoritative_effect",
        owner_domain="attempt.application",
        writer_roles=("application_origin",),
    )


def _retain(channel: str, content: bytes, access: str = "restricted") -> Any:
    return store.retain_artifact(
        channel, "attempt.application", "application/json", content, access
    )


def _attempt(
    attempt_id: str,
    kind: str,
    target_class: str,
    target_id: str,
    partition: str,
    rehearsal: list | None = None,
    performance: list | None = None,
    derived: list | None = None,
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "kind": kind,
        "target_class": target_class,
        "target_id": target_id,
        "evaluation_partition": partition,
        "rehearsal_of": rehearsal or [],
        "performance_of": performance or [],
        "derived_from": derived or [],
    }


def _assistance() -> dict[str, Any]:
    return {
        "planning_owner": "none",
        "assistance_track": "no_assistance",
        "planner_identity": _missing(),
        "plan": _missing(),
        "online_replanning": False,
        "description": "No assistance is declared.",
    }


def _manual_execution() -> dict[str, Any]:
    return {
        "mode": "manual",
        "subject": _missing(),
        "connector_version": _missing(),
        "binding_version": _missing(),
        "assistance": _assistance(),
    }


def _subject(subject_id: str, version: str) -> dict[str, Any]:
    return {
        "subject_id": subject_id,
        "subject_version": version,
        "revision_basis": "native_revision",
        "native_revision": "rev_1",
        "configured_mode": "mode_apply",
        "interface_surface": "surface_browser",
        "configuration_digest": D0,
        "stack": [],
    }


def _subject_execution(subject_id: str, version: str) -> dict[str, Any]:
    return {
        "mode": "subject",
        "subject": _subject(subject_id, version),
        "connector_version": "conn_v1",
        "binding_version": "bind_v1",
        "assistance": _assistance(),
    }


def _manifest_execution_for(execution: dict[str, Any]) -> dict[str, Any]:
    if execution["mode"] == "manual":
        return {
            "mode": "manual",
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
        }
    return {
        "mode": "subject",
        "subject": execution["subject"],
        "connector_version": execution["connector_version"],
        "binding_version": execution["binding_version"],
        "assistance": {
            "planning_owner": "none",
            "assistance_track": "no_assistance",
            "planner_identity": ev.NOT_APPLICABLE,
            "plan": ev.NOT_APPLICABLE,
            "online_replanning": False,
            "description": "No assistance is declared at admission.",
        },
    }


def _admit(
    channel: str,
    producer: str,
    principal: str,
    run_id: str,
    journal_id: str,
    manifest_id: str,
    attempt: dict[str, Any],
    execution: dict[str, Any],
    task_ref: Any,
    config_ref: Any,
) -> tuple[Any, dict[str, Any]]:
    manifest = ev.Manifest(
        manifest_id=manifest_id,
        run_id=run_id,
        journal_id=journal_id,
        owner_domain="attempt.application",
        commissioner_id=principal,
        activity="application_attempt",
        attempt=dict(attempt),
        execution=_manifest_execution_for(execution),
        task=task_ref,
        task_semantic_hash=D0,
        effective_configuration=config_ref,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task_ref.digest}
        ],
        event_registry=[
            {
                "event_kind": "attempt.commissioned",
                "event_schema_version": "1",
                "role": "lifecycle_observation",
                "assertion_kind": "authoritative_effect",
                "writer_roles": ["application_origin"],
            }
        ],
        producers=[
            {
                "producer_id": producer,
                "principal_id": principal,
                "owner_domain": "attempt.application",
                "role": "application_origin",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": ["attempt.commissioned"],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_comm_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    admission = ev.admit_manifest(channel, manifest)
    admission_ref = {
        "journal_id": admission.journal_id,
        "sequence": 1,
        "event_id": admission.event_id,
        "event_hash": admission.event_hash,
        "pointer": "",
    }
    return admission, admission_ref


def _obs_policy(action: str = "not_applicable", value: int = 0) -> dict[str, Any]:
    def _limit() -> dict[str, Any]:
        return {"kind": "exact", "unit": "ms", "value": value}

    return {
        "active_limit": _limit(),
        "drain_limit": _limit(),
        "native_cancel_wait_limit": _limit(),
        "cleanup_wait_limit": _limit(),
        "fixture_close_action": action,
    }


def _manual_owners(
    app_producer: str, obs_writer: str, report_writer: str, target_id: str
) -> dict[str, Any]:
    return {
        "dispatch": {
            "role": "connector",
            "source_id": _missing(),
            "writer_id": _missing(),
            "owner_domain": "attempt.dispatch",
            "publication_policy": dict(POLICY),
        },
        "observation": {
            "role": "connector",
            "source_id": "src_manual_recorder",
            "writer_id": obs_writer,
            "owner_domain": "attempt.observation",
            "publication_policy": dict(POLICY),
        },
        "execution": {
            "role": "subject",
            "source_id": _missing(),
            "writer_id": _missing(),
            "owner_domain": "attempt.execution",
            "publication_policy": dict(POLICY),
        },
        "application": {
            "role": "origin",
            "source_id": target_id,
            "writer_id": app_producer,
            "owner_domain": "attempt.application",
            "publication_policy": dict(POLICY),
        },
        "report": {
            "role": "reconciler",
            "source_id": "src_manual_reconciler",
            "writer_id": report_writer,
            "owner_domain": "attempt.report",
            "publication_policy": dict(POLICY),
        },
    }


def _subject_owners(
    app_producer: str,
    target_id: str,
    subject_id: str,
    tag: str,
) -> dict[str, Any]:
    return {
        "dispatch": {
            "role": "connector",
            "source_id": "src_conn_1",
            "writer_id": f"prod_{tag}_dispatch",
            "owner_domain": "attempt.dispatch",
            "publication_policy": dict(POLICY),
        },
        "observation": {
            "role": "connector",
            "source_id": "src_conn_1",
            "writer_id": f"prod_{tag}_observation",
            "owner_domain": "attempt.observation",
            "publication_policy": dict(POLICY),
        },
        "execution": {
            "role": "subject",
            "source_id": subject_id,
            "writer_id": f"prod_{tag}_execution",
            "owner_domain": "attempt.execution",
            "publication_policy": dict(POLICY),
        },
        "application": {
            "role": "origin",
            "source_id": target_id,
            "writer_id": app_producer,
            "owner_domain": "attempt.application",
            "publication_policy": dict(POLICY),
        },
        "report": {
            "role": "reconciler",
            "source_id": "src_reconciler_1",
            "writer_id": f"prod_{tag}_report",
            "owner_domain": "attempt.report",
            "publication_policy": dict(POLICY),
        },
    }


def _commission(
    *,
    commission_id: str,
    run_id: str,
    journal_id: str,
    manifest_hash: str,
    admission_ref: dict[str, Any],
    commissioned_by: str,
    attempt: dict[str, Any],
    candidate_id: str,
    job_id: str,
    snapshot_ref: Any,
    task_ref: Any,
    execution: dict[str, Any],
    owners: dict[str, Any],
    idempotency_key: str,
    authorization_refs: list[dict[str, Any]],
    source_target: Any = None,
    source_job_id: Any = None,
    candidate_profile: Any = None,
    selection_evidence: Any = None,
    recovery_refs: list[dict[str, Any]] | None = None,
    observation_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if source_target is None:
        source_target = _missing_observed()
    if source_job_id is None:
        source_job_id = _missing_observed()
    if candidate_profile is None:
        candidate_profile = _missing_observed()
    if selection_evidence is None:
        selection_evidence = _missing_observed()
    return {
        "record_type": "attempt_commission",
        "schema_version": "application-attempt-lifecycle/0.1.0",
        "kernel_version": "evidence-kernel/0.1.0",
        "commission_id": commission_id,
        "run_id": run_id,
        "journal_id": journal_id,
        "manifest_hash": manifest_hash,
        "admission_ref": dict(admission_ref),
        "commissioned_by": commissioned_by,
        "commissioned_at": _timepoint(),
        "attempt": dict(attempt),
        "candidate_id": candidate_id,
        "candidate_profile": candidate_profile,
        "job": {
            "job_id": job_id,
            "source_target": source_target,
            "source_job_id": source_job_id,
            "snapshot": snapshot_ref.to_dict(),
        },
        "selection_evidence": selection_evidence,
        "task": task_ref.to_dict(),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": dict(execution),
        "owners": {k: dict(v) for k, v in owners.items()},
        "idempotency_key": idempotency_key,
        "authorization_refs": [dict(r) for r in authorization_refs],
        "recovery_review_refs": [dict(r) for r in (recovery_refs or [])],
        "observation_policy": dict(observation_policy or _obs_policy()),
        "origin_policy": dict(POLICY),
    }


def _no_crawler_keys(node: Any, path: str = "$") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = key.lower()
            assert "crawler" not in lowered, f"crawler key at {path}.{key}"
            assert "coverage" not in lowered, f"coverage key at {path}.{key}"
            assert "render_verdict" not in lowered, f"render verdict at {path}.{key}"
            assert "job_entity_key" not in lowered, f"entity key at {path}.{key}"
            assert "evaluation_reference" not in lowered, (
                f"evaluation reference at {path}.{key}"
            )
            _no_crawler_keys(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _no_crawler_keys(value, f"{path}[{index}]")


# ---------------------------------------------------------------------------
# 1. Manual discovery without fabricated crawler evidence
# ---------------------------------------------------------------------------


def test_manual_job_without_crawler_commissions_without_fabricated_crawler_evidence():
    channel = "ch_comm_manual_app"
    producer = "prod_comm_manual_app"
    principal = "principal_comm_manual"
    _register_app_channel(channel, producer, principal)

    task_ref = _retain(channel, b'{"goal":"manual apply intent"}')
    config_ref = _retain(channel, b'{"policy":"manual"}')
    snapshot_ref = _retain(channel, b'{"job":"manual snapshot v1"}', "public")
    human_ref = _retain(
        channel, b'{"decision":"human go","rationale":"fit"}', "public"
    )

    target_id = "target_manual_employer_1"
    attempt = _attempt(
        "attempt_manual_1", "production", "employer_origin", target_id, "held_out"
    )
    execution = _manual_execution()
    admission, admission_ref = _admit(
        channel,
        producer,
        principal,
        "run_manual_1",
        "journal_manual_1",
        "manifest_manual_1",
        attempt,
        execution,
        task_ref,
        config_ref,
    )

    owners = _manual_owners(
        producer, "prod_manual_obs_1", "prod_manual_report_1", target_id
    )
    commission = _commission(
        commission_id="comm_manual_1",
        run_id="run_manual_1",
        journal_id="journal_manual_1",
        manifest_hash=admission.manifest_hash,
        admission_ref=admission_ref,
        commissioned_by=principal,
        attempt=attempt,
        candidate_id="candidate_manual_1",
        job_id="portfolio_manual_1",
        snapshot_ref=snapshot_ref,
        task_ref=task_ref,
        execution=execution,
        owners=owners,
        idempotency_key="idem_manual_1",
        authorization_refs=[admission_ref],
        selection_evidence=human_ref.to_dict(),
    )

    ref = ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission))
    assert ref.digest.startswith("sha256:")
    assert ref.owner_domain == "attempt.application"

    loaded = ac.load_commission(channel, ref)
    assert loaded.job["source_target"] == _missing_observed()
    assert loaded.job["source_job_id"] == _missing_observed()
    assert set(loaded.job.keys()) == {
        "job_id",
        "source_target",
        "source_job_id",
        "snapshot",
    }
    assert loaded.execution["mode"] == "manual"
    assert loaded.execution["subject"] == _missing()
    assert loaded.owners["dispatch"]["writer_id"] == _missing()
    assert loaded.owners["execution"]["writer_id"] == _missing()
    assert loaded.candidate_profile == _missing_observed()
    assert loaded.selection_evidence["digest"] == human_ref.digest
    _no_crawler_keys(loaded.to_dict())

    # Idempotent retry returns the same handle.
    ref2 = ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission))
    assert ref2.digest == ref.digest

    # Later crawler association is a new relation, never a rewrite: the same
    # attempt identity cannot be mutated to carry crawler roots.
    rewrite = dict(commission)
    rewrite["commission_id"] = "comm_manual_1_rewrite"
    rewrite["idempotency_key"] = "idem_manual_1_rewrite"
    rewrite["job"] = dict(commission["job"])
    rewrite["job"]["source_target"] = "crawler_target_1"
    rewrite["job"]["source_job_id"] = "crawler_job_1"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(rewrite))


# ---------------------------------------------------------------------------
# 2. Immutable changes need a new identity + evidenced duplicate-risk review
# ---------------------------------------------------------------------------


def test_commission_changes_require_new_identity_and_evidenced_duplicate_risk_review():
    channel = "ch_comm_dup_app"
    producer = "prod_comm_dup_app"
    principal = "principal_comm_dup"
    _register_app_channel(channel, producer, principal)

    task_ref = _retain(channel, b'{"goal":"subject apply v1"}')
    config_ref = _retain(channel, b'{"policy":"subject"}')
    snapshot_ref = _retain(channel, b'{"job":"dup snapshot v1"}', "public")

    target_id = "target_dup_employer_1"
    candidate_id = "candidate_dup_1"
    job_id = "portfolio_dup_1"
    subject_id = "subject_dup_1"

    attempt_a = _attempt(
        "attempt_dup_A1", "production", "employer_origin", target_id, "held_out"
    )
    execution_a = _subject_execution(subject_id, "v1")
    admission_a, admission_ref_a = _admit(
        channel,
        producer,
        principal,
        "run_dup_1",
        "journal_dup_1",
        "manifest_dup_1",
        attempt_a,
        execution_a,
        task_ref,
        config_ref,
    )
    owners_a = _subject_owners(producer, target_id, subject_id, "dup_a")
    commission_a = _commission(
        commission_id="comm_dup_A1",
        run_id="run_dup_1",
        journal_id="journal_dup_1",
        manifest_hash=admission_a.manifest_hash,
        admission_ref=admission_ref_a,
        commissioned_by=principal,
        attempt=attempt_a,
        candidate_id=candidate_id,
        job_id=job_id,
        snapshot_ref=snapshot_ref,
        task_ref=task_ref,
        execution=execution_a,
        owners=owners_a,
        idempotency_key="idem_dup_A1",
        authorization_refs=[admission_ref_a],
    )
    ref_a = ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission_a))

    # Same key + same request returns the same handle.
    replay = ac.register_attempt(
        channel, ac.AttemptCommission.from_dict(commission_a)
    )
    assert replay.digest == ref_a.digest

    # Changed content under the reused key is rejected.
    changed_key = dict(commission_a)
    changed_key["execution"] = _subject_execution(subject_id, "v2")
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(changed_key))

    # Same attempt identity with a changed subject version requires a new
    # attempt, even under fresh commission/key identities.
    same_attempt = dict(commission_a)
    same_attempt["commission_id"] = "comm_dup_A1c"
    same_attempt["idempotency_key"] = "idem_dup_A1c"
    same_attempt["execution"] = _subject_execution(subject_id, "v2")
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(same_attempt))

    # Same attempt identity with a changed target also requires a new attempt.
    moved_target = dict(commission_a)
    moved_target["commission_id"] = "comm_dup_A1d"
    moved_target["idempotency_key"] = "idem_dup_A1d"
    moved_attempt = dict(attempt_a)
    moved_attempt["target_id"] = "target_dup_employer_2"
    moved_target["attempt"] = moved_attempt
    moved_owners = {k: dict(v) for k, v in owners_a.items()}
    moved_owners["application"] = dict(moved_owners["application"])
    moved_owners["application"]["source_id"] = "target_dup_employer_2"
    moved_target["owners"] = moved_owners
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(moved_target))

    # A new attempt over the same candidate + job requires evidenced
    # duplicate-risk review.
    attempt_b = _attempt(
        "attempt_dup_A2", "production", "employer_origin", target_id, "held_out"
    )
    execution_b = _subject_execution(subject_id, "v2")
    admission_b, admission_ref_b = _admit(
        channel,
        producer,
        principal,
        "run_dup_2",
        "journal_dup_2",
        "manifest_dup_2",
        attempt_b,
        execution_b,
        task_ref,
        config_ref,
    )
    owners_b = _subject_owners(producer, target_id, subject_id, "dup_b")
    commission_b = _commission(
        commission_id="comm_dup_A2",
        run_id="run_dup_2",
        journal_id="journal_dup_2",
        manifest_hash=admission_b.manifest_hash,
        admission_ref=admission_ref_b,
        commissioned_by=principal,
        attempt=attempt_b,
        candidate_id=candidate_id,
        job_id=job_id,
        snapshot_ref=snapshot_ref,
        task_ref=task_ref,
        execution=execution_b,
        owners=owners_b,
        idempotency_key="idem_dup_A2",
        authorization_refs=[admission_ref_b],
        recovery_refs=[],
    )
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission_b))

    commission_b_ok = dict(commission_b)
    commission_b_ok["recovery_review_refs"] = [dict(admission_ref_b)]
    ref_b = ac.register_attempt(
        channel, ac.AttemptCommission.from_dict(commission_b_ok)
    )
    assert ref_b.digest != ref_a.digest

    # The new attempt preserves prior uncertainty: the original commission is
    # unchanged and still loads with its own identity and review state.
    loaded_a = ac.load_commission(channel, ref_a)
    assert loaded_a.attempt["attempt_id"] == "attempt_dup_A1"
    assert loaded_a.execution["subject"]["subject_version"] == "v1"
    assert list(loaded_a.recovery_review_refs) == []
    loaded_b = ac.load_commission(channel, ref_b)
    assert loaded_b.attempt["attempt_id"] == "attempt_dup_A2"
    assert loaded_b.execution["subject"]["subject_version"] == "v2"
    assert len(list(loaded_b.recovery_review_refs)) == 1


# ---------------------------------------------------------------------------
# 3. Practice lineage never promotes commitment nor authorizes production
# ---------------------------------------------------------------------------


def test_practice_lineage_links_never_promote_commitment_or_authorize_production():
    channel = "ch_comm_lineage_app"
    producer = "prod_comm_lineage_app"
    principal = "principal_comm_lineage"
    _register_app_channel(channel, producer, principal)

    candidate_id = "candidate_lineage_1"
    task_ref = _retain(channel, b'{"goal":"lineage task"}')
    config_ref = _retain(channel, b'{"policy":"lineage"}')
    snapshot_practice = _retain(channel, b'{"job":"practice snapshot"}', "public")
    snapshot_prod = _retain(channel, b'{"job":"production snapshot"}', "public")
    snapshot_practice2 = _retain(channel, b'{"job":"practice snapshot 2"}', "public")

    # Practice fixture: held_in laboratory work commissions first.
    practice_target = "target_practice_fixture_1"
    attempt_p1 = _attempt(
        "attempt_practice_1",
        "practice",
        "laboratory_fixture",
        practice_target,
        "held_in",
    )
    execution_p1 = _manual_execution()
    admission_p1, admission_ref_p1 = _admit(
        channel,
        producer,
        principal,
        "run_lineage_p1",
        "journal_lineage_p1",
        "manifest_lineage_p1",
        attempt_p1,
        execution_p1,
        task_ref,
        config_ref,
    )
    owners_p1 = _manual_owners(
        producer, "prod_lineage_obs_p1", "prod_lineage_report_p1", practice_target
    )
    commission_p1 = _commission(
        commission_id="comm_lineage_p1",
        run_id="run_lineage_p1",
        journal_id="journal_lineage_p1",
        manifest_hash=admission_p1.manifest_hash,
        admission_ref=admission_ref_p1,
        commissioned_by=principal,
        attempt=attempt_p1,
        candidate_id=candidate_id,
        job_id="portfolio_practice_1",
        snapshot_ref=snapshot_practice,
        task_ref=task_ref,
        execution=execution_p1,
        owners=owners_p1,
        idempotency_key="idem_lineage_p1",
        authorization_refs=[admission_ref_p1],
        observation_policy=_obs_policy("seal_after_drain"),
    )
    ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission_p1))

    # Production links performance_of to the commissioned practice identity.
    prod_target = "target_lineage_employer_1"
    attempt_a1 = _attempt(
        "attempt_prod_1",
        "production",
        "employer_origin",
        prod_target,
        "held_out",
        performance=[{"attempt_id": "attempt_practice_1", "kind": "practice"}],
    )
    execution_a1 = _manual_execution()
    admission_a1, admission_ref_a1 = _admit(
        channel,
        producer,
        principal,
        "run_lineage_a1",
        "journal_lineage_a1",
        "manifest_lineage_a1",
        attempt_a1,
        execution_a1,
        task_ref,
        config_ref,
    )
    owners_a1 = _manual_owners(
        producer, "prod_lineage_obs_a1", "prod_lineage_report_a1", prod_target
    )
    commission_a1 = _commission(
        commission_id="comm_lineage_a1",
        run_id="run_lineage_a1",
        journal_id="journal_lineage_a1",
        manifest_hash=admission_a1.manifest_hash,
        admission_ref=admission_ref_a1,
        commissioned_by=principal,
        attempt=attempt_a1,
        candidate_id=candidate_id,
        job_id="portfolio_prod_1",
        snapshot_ref=snapshot_prod,
        task_ref=task_ref,
        execution=execution_a1,
        owners=owners_a1,
        idempotency_key="idem_lineage_a1",
        authorization_refs=[admission_ref_a1],
    )
    ref_a1 = ac.register_attempt(
        channel, ac.AttemptCommission.from_dict(commission_a1)
    )
    loaded_a1 = ac.load_commission(channel, ref_a1)
    assert loaded_a1.attempt["performance_of"] == [
        {"attempt_id": "attempt_practice_1", "kind": "practice"}
    ]

    # Lineage confers no outcome: no axis holds a publication for either
    # attempt, and the production attempt keeps its own authorization.
    assert list(loaded_a1.authorization_refs) != []
    for entity in (
        {
            "entity_type": "application_attempt",
            "attempt_id": "attempt_practice_1",
            "kind": "practice",
        },
        {
            "entity_type": "application_attempt",
            "attempt_id": "attempt_prod_1",
            "kind": "production",
        },
    ):
        for axis in (
            "dispatch",
            "observation",
            "execution",
            "application",
            "report",
        ):
            assert orv.domain_head(channel, entity, axis) == 0
            unread = orv.read_domain(channel, entity, axis)
            assert isinstance(unread, dict) and unread.get("reason") == "not_observed"

    # A production commission without its own authorization is rejected even
    # when it names a valid practice lineage link.
    no_auth = dict(commission_a1)
    no_auth["commission_id"] = "comm_lineage_noauth"
    no_auth["idempotency_key"] = "idem_lineage_noauth"
    moved = dict(attempt_a1)
    moved["attempt_id"] = "attempt_prod_noauth"
    no_auth["attempt"] = moved
    no_auth["authorization_refs"] = []
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(no_auth))

    # Cross-kind derivation is rejected.
    cross_kind = dict(commission_p1)
    cross_kind["commission_id"] = "comm_lineage_cross"
    cross_kind["idempotency_key"] = "idem_lineage_cross"
    bad_attempt = dict(attempt_p1)
    bad_attempt["attempt_id"] = "attempt_practice_cross"
    bad_attempt["derived_from"] = [
        {"attempt_id": "attempt_prod_1", "kind": "production"}
    ]
    cross_kind["attempt"] = bad_attempt
    cross_kind["job"] = dict(commission_p1["job"])
    cross_kind["job"]["job_id"] = "portfolio_practice_cross"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(cross_kind))

    # Rehearsal links run practice -> production only.
    rehearsal_on_prod = dict(commission_a1)
    rehearsal_on_prod["commission_id"] = "comm_lineage_rehearsal"
    rehearsal_on_prod["idempotency_key"] = "idem_lineage_rehearsal"
    bad_prod = dict(attempt_a1)
    bad_prod["attempt_id"] = "attempt_prod_rehearsal"
    bad_prod["rehearsal_of"] = [
        {"attempt_id": "attempt_practice_1", "kind": "practice"}
    ]
    rehearsal_on_prod["attempt"] = bad_prod
    rehearsal_on_prod["job"] = dict(commission_a1["job"])
    rehearsal_on_prod["job"]["job_id"] = "portfolio_prod_rehearsal"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(rehearsal_on_prod))

    # Performance links run production -> practice only.
    performance_on_practice = dict(commission_p1)
    performance_on_practice["commission_id"] = "comm_lineage_perf"
    performance_on_practice["idempotency_key"] = "idem_lineage_perf"
    bad_practice = dict(attempt_p1)
    bad_practice["attempt_id"] = "attempt_practice_perf"
    bad_practice["performance_of"] = [
        {"attempt_id": "attempt_prod_1", "kind": "production"}
    ]
    performance_on_practice["attempt"] = bad_practice
    performance_on_practice["job"] = dict(commission_p1["job"])
    performance_on_practice["job"]["job_id"] = "portfolio_practice_perf"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(
            channel, ac.AttemptCommission.from_dict(performance_on_practice)
        )

    # Forward references to uncommissioned identities are rejected.
    forward = dict(commission_a1)
    forward["commission_id"] = "comm_lineage_forward"
    forward["idempotency_key"] = "idem_lineage_forward"
    forward_attempt = dict(attempt_a1)
    forward_attempt["attempt_id"] = "attempt_prod_forward"
    forward_attempt["performance_of"] = [
        {"attempt_id": "attempt_ghost", "kind": "practice"}
    ]
    forward["attempt"] = forward_attempt
    forward["job"] = dict(commission_a1["job"])
    forward["job"]["job_id"] = "portfolio_prod_forward"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(forward))

    # Self derivation is a cycle.
    cyclic = dict(commission_p1)
    cyclic["commission_id"] = "comm_lineage_cycle"
    cyclic["idempotency_key"] = "idem_lineage_cycle"
    cyclic_attempt = dict(attempt_p1)
    cyclic_attempt["attempt_id"] = "attempt_practice_cycle"
    cyclic_attempt["derived_from"] = [
        {"attempt_id": "attempt_practice_cycle", "kind": "practice"}
    ]
    cyclic["attempt"] = cyclic_attempt
    cyclic["job"] = dict(commission_p1["job"])
    cyclic["job"]["job_id"] = "portfolio_practice_cycle"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(cyclic))

    # Production requires an employer origin.
    lab_prod = dict(commission_a1)
    lab_prod["commission_id"] = "comm_lineage_labprod"
    lab_prod["idempotency_key"] = "idem_lineage_labprod"
    lab_attempt = dict(attempt_a1)
    lab_attempt["attempt_id"] = "attempt_prod_lab"
    lab_attempt["target_class"] = "laboratory_fixture"
    lab_attempt["evaluation_partition"] = "held_in"
    lab_attempt["performance_of"] = []
    lab_prod["attempt"] = lab_attempt
    lab_prod["job"] = dict(commission_a1["job"])
    lab_prod["job"]["job_id"] = "portfolio_prod_lab"
    with pytest.raises(ac.CommissionError):
        ac.register_attempt(channel, ac.AttemptCommission.from_dict(lab_prod))

    # A later practice rehearsal of the commissioned production identity
    # succeeds and still promotes no commitment.
    attempt_p2 = _attempt(
        "attempt_practice_2",
        "practice",
        "laboratory_fixture",
        practice_target,
        "held_in",
        rehearsal=[{"attempt_id": "attempt_prod_1", "kind": "production"}],
    )
    admission_p2, admission_ref_p2 = _admit(
        channel,
        producer,
        principal,
        "run_lineage_p2",
        "journal_lineage_p2",
        "manifest_lineage_p2",
        attempt_p2,
        execution_p1,
        task_ref,
        config_ref,
    )
    owners_p2 = _manual_owners(
        producer, "prod_lineage_obs_p2", "prod_lineage_report_p2", practice_target
    )
    commission_p2 = _commission(
        commission_id="comm_lineage_p2",
        run_id="run_lineage_p2",
        journal_id="journal_lineage_p2",
        manifest_hash=admission_p2.manifest_hash,
        admission_ref=admission_ref_p2,
        commissioned_by=principal,
        attempt=attempt_p2,
        candidate_id=candidate_id,
        job_id="portfolio_practice_2",
        snapshot_ref=snapshot_practice2,
        task_ref=task_ref,
        execution=execution_p1,
        owners=owners_p2,
        idempotency_key="idem_lineage_p2",
        authorization_refs=[admission_ref_p2],
        observation_policy=_obs_policy("seal_after_drain"),
    )
    ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission_p2))
    entity_p2 = {
        "entity_type": "application_attempt",
        "attempt_id": "attempt_practice_2",
        "kind": "practice",
    }
    for axis in ("dispatch", "observation", "execution", "application", "report"):
        assert orv.domain_head(channel, entity_p2, axis) == 0
