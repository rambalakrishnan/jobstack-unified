"""Conformance tests for claim_reconciliation (tier 6).

Covers exactly the ``-k`` filter named in the module spec:

- ``late_commitment_after_close_time_unknown_preserves_snapshot_and_compatibility``
- ``late_commitment_against_entire_attempt_no_commit_claim_is_contradicted``
- ``receipt_arrival_order_without_temporal_evidence_keeps_relation_unknown``
- ``reconciled_narrow_claim_does_not_imply_application_success``

Every check exercises the real module: pinned execution claims and
origin facts are committed through ``owner_revisions``, evidence is
journaled through ``evidence_journal``, commissions load through
``attempt_commissioning``, and reports derive/publish through
``claim_reconciliation`` with strict-JSON gating.
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
    if name == "claim_reconciliation":
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
cr = _load("claim_reconciliation")

D0 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
D1 = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
D2 = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
D3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
POLICY = {"id": "policy_test", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_rec_test"
BOOT_ID = "boot_rec_test"
KIND = "report.evidence"
KIND_VERSION = "1"
CHANNELS = {
    "dispatch": "ch_rec_dispatch",
    "observation": "ch_rec_observation",
    "execution": "ch_rec_execution",
    "application": "ch_rec_application",
    "report": "ch_rec_report",
}
WRITERS = {
    "dispatch": "prod_rec_dispatch",
    "observation": "prod_rec_observation",
    "execution": "prod_rec_execution",
    "application": "prod_rec_application",
    "report": "prod_rec_report",
}
OWNER_DOMAINS = {
    "dispatch": "attempt.dispatch",
    "observation": "attempt.observation",
    "execution": "attempt.execution",
    "application": "attempt.application",
    "report": "attempt.report",
}
FAKE_PREFIX = {
    "journal_id": "journal_rec_unadmitted",
    "last_sequence": 1,
    "head_hash": D1,
}


@pytest.fixture(autouse=True)
def _fresh_state():
    orv.reset_for_tests()
    ev.reset_for_tests()
    ac.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    cr.reset_for_tests()
    yield
    cr.reset_for_tests()
    store.reset_for_tests()
    ap.reset_for_tests()
    ac.reset_for_tests()
    ev.reset_for_tests()
    orv.reset_for_tests()


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _missing_observed() -> dict[str, Any]:
    return {"value": None, "reason": "not_observed"}


def _timepoint(
    offset: float,
    *,
    clock: str = CLOCK_ID,
    boot: str = BOOT_ID,
    origin: str = "engine_measured",
    utc: Any = None,
) -> dict[str, Any]:
    return {
        "clock_id": clock,
        "boot_id": boot,
        "origin": origin,
        "monotonic_offset_ms": offset,
        "utc_annotation": utc if utc is not None else _missing_observed(),
    }


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
    owner_domain: str = "attempt.application",
    access: str = "public",
) -> dict[str, Any]:
    return {
        "digest": digest,
        "size_bytes": 1,
        "media_type": "application/json",
        "owner_domain": owner_domain,
        "access": access,
    }


def _register_channels() -> None:
    ap.register_channel(
        actor="connector",
        channel_id=CHANNELS["dispatch"],
        axis=OWNER_DOMAINS["dispatch"],
        producer_id=WRITERS["dispatch"],
        principal_id="principal_rec_dispatch",
        sequence_required=False,
        allowed_event_kinds=("attempt.dispatch.published",),
        binding="bind_rec_dispatch",
    )
    ap.register_channel(
        actor="connector",
        channel_id=CHANNELS["observation"],
        axis=OWNER_DOMAINS["observation"],
        producer_id=WRITERS["observation"],
        principal_id="principal_rec_observation",
        sequence_required=False,
        allowed_event_kinds=("attempt.observation.published",),
        binding="bind_rec_observation",
    )
    ap.register_channel(
        actor="subject_adapter",
        channel_id=CHANNELS["execution"],
        axis=OWNER_DOMAINS["execution"],
        producer_id=WRITERS["execution"],
        principal_id="principal_rec_execution",
        sequence_required=False,
        allowed_event_kinds=("attempt.execution.published",),
    )
    ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=CHANNELS["application"],
        axis=OWNER_DOMAINS["application"],
        producer_id=WRITERS["application"],
        principal_id="principal_rec_application",
        sequence_required=False,
        allowed_event_kinds=("attempt.application.published",),
        binding="bind_rec_application",
    )
    ap.register_channel(
        actor="reconciler",
        channel_id=CHANNELS["report"],
        axis=OWNER_DOMAINS["report"],
        producer_id=WRITERS["report"],
        principal_id="principal_rec_report",
        sequence_required=False,
        allowed_event_kinds=(KIND,),
    )
    ap.register_event_kind(
        KIND,
        KIND_VERSION,
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain=OWNER_DOMAINS["report"],
        writer_roles=("analyzer",),
    )


def _admit_report_journal():
    task = store.retain_artifact(
        CHANNELS["report"],
        OWNER_DOMAINS["report"],
        "application/json",
        b'{"task":"rec-report-task"}',
        "restricted",
    )
    config = store.retain_artifact(
        CHANNELS["report"],
        OWNER_DOMAINS["report"],
        "application/json",
        b'{"config":"rec-report-config"}',
        "restricted",
    )
    manifest = ev.Manifest(
        manifest_id="manifest_rec_report",
        run_id="run_rec_report",
        journal_id="journal_rec_report",
        owner_domain=OWNER_DOMAINS["report"],
        commissioner_id="principal_rec_report",
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
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=[
            {
                "event_kind": KIND,
                "event_schema_version": KIND_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "writer_roles": ["analyzer"],
            }
        ],
        producers=[
            {
                "producer_id": WRITERS["report"],
                "principal_id": "principal_rec_report",
                "owner_domain": OWNER_DOMAINS["report"],
                "role": "analyzer",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": [KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_rec_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    return ev.admit_manifest(CHANNELS["report"], manifest)


_seq = {"next": 0}


def _append(
    data: dict[str, Any],
    *,
    occurred: Any = None,
    evidence_refs: list | None = None,
):
    _seq["next"] += 1
    if occurred is None:
        occurred = ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=float(1000 + _seq["next"] * 10),
        )
    submission = ev.EventSubmission(
        producer_sequence=_seq["next"],
        event_kind=KIND,
        event_schema_version=KIND_VERSION,
        occurred_at=occurred,
        payload=ev.EvidencePayload(
            data=dict(data),
            measurements=[],
            evidence_refs=list(evidence_refs or []),
            artifact_refs=[],
        ),
    )
    return ev.append_event(
        CHANNELS["report"], OWNER_DOMAINS["report"], submission
    )


def _ref(envelope: Any, pointer: str = "") -> dict[str, Any]:
    return {
        "journal_id": envelope.journal_id,
        "sequence": envelope.journal_sequence,
        "event_id": envelope.event_id,
        "event_hash": envelope.event_hash,
        "pointer": pointer,
    }


def _attempt_dict() -> dict[str, Any]:
    return {
        "attempt_id": "attempt_rec_1",
        "kind": "production",
        "target_class": "employer_origin",
        "target_id": "target_rec_1",
        "evaluation_partition": "held_out",
        "rehearsal_of": [],
        "performance_of": [],
        "derived_from": [],
    }


def _subject_dict() -> dict[str, Any]:
    return {
        "subject_id": "subject_rec_1",
        "subject_version": "v1",
        "revision_basis": "native_revision",
        "native_revision": "rev_1",
        "configured_mode": "mode_apply",
        "interface_surface": "surface_browser",
        "configuration_digest": D0,
        "stack": [],
    }


def _execution_dict() -> dict[str, Any]:
    return {
        "mode": "subject",
        "subject": _subject_dict(),
        "connector_version": "conn_v1",
        "binding_version": "bind_v1",
        "assistance": {
            "planning_owner": "none",
            "assistance_track": "no_assistance",
            "planner_identity": _missing(),
            "plan": _missing(),
            "online_replanning": False,
            "description": "No assistance is declared.",
        },
    }


def _owners_dict() -> dict[str, Any]:
    return {
        "dispatch": {
            "role": "connector",
            "source_id": "src_conn_1",
            "writer_id": WRITERS["dispatch"],
            "owner_domain": OWNER_DOMAINS["dispatch"],
            "publication_policy": dict(POLICY),
        },
        "observation": {
            "role": "connector",
            "source_id": "src_conn_1",
            "writer_id": WRITERS["observation"],
            "owner_domain": OWNER_DOMAINS["observation"],
            "publication_policy": dict(POLICY),
        },
        "execution": {
            "role": "subject",
            "source_id": "subject_rec_1",
            "writer_id": WRITERS["execution"],
            "owner_domain": OWNER_DOMAINS["execution"],
            "publication_policy": dict(POLICY),
        },
        "application": {
            "role": "origin",
            "source_id": "target_rec_1",
            "writer_id": WRITERS["application"],
            "owner_domain": OWNER_DOMAINS["application"],
            "publication_policy": dict(POLICY),
        },
        "report": {
            "role": "reconciler",
            "source_id": "src_reconciler_1",
            "writer_id": WRITERS["report"],
            "owner_domain": OWNER_DOMAINS["report"],
            "publication_policy": dict(POLICY),
        },
    }


def _commission_dict() -> dict[str, Any]:
    return {
        "record_type": "attempt_commission",
        "schema_version": "application-attempt-lifecycle/0.1.0",
        "kernel_version": "evidence-kernel/0.1.0",
        "commission_id": "commission_rec_1",
        "run_id": "run_rec_1",
        "journal_id": "journal_rec_commission",
        "manifest_hash": D0,
        "admission_ref": _evidence_ref("rec_admission"),
        "commissioned_by": "principal_rec_application",
        "commissioned_at": _timepoint(1.0),
        "attempt": _attempt_dict(),
        "candidate_id": "candidate_rec_1",
        "candidate_profile": _missing_observed(),
        "job": {
            "job_id": "job_rec_1",
            "source_target": _missing_observed(),
            "source_job_id": _missing_observed(),
            "snapshot": _artifact_dict(D2, "attempt.application", "public"),
        },
        "selection_evidence": _missing_observed(),
        "task": _artifact_dict(D3, "attempt.application", "public"),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": _execution_dict(),
        "owners": _owners_dict(),
        "idempotency_key": "idem_rec_1",
        "authorization_refs": [_evidence_ref("rec_authz")],
        "recovery_review_refs": [],
        "observation_policy": {
            "active_limit": {"kind": "exact", "unit": "ms", "value": 0},
            "drain_limit": {"kind": "exact", "unit": "ms", "value": 0},
            "native_cancel_wait_limit": {
                "kind": "exact",
                "unit": "ms",
                "value": 0,
            },
            "cleanup_wait_limit": {
                "kind": "exact",
                "unit": "ms",
                "value": 0,
            },
            "fixture_close_action": "not_applicable",
        },
        "origin_policy": dict(POLICY),
    }


def _retain_commission(commission: dict[str, Any]):
    payload = json.dumps(
        commission, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return store.retain_artifact(
        CHANNELS["dispatch"],
        OWNER_DOMAINS["dispatch"],
        "application/json",
        payload,
        "public",
    )


def _register_attempt(commission_ref):
    commission = _commission_dict()
    return orv.EntityRegistration(
        registration_id="reg_rec_attempt_1",
        entity={
            "entity_type": "application_attempt",
            "attempt_id": "attempt_rec_1",
            "kind": "production",
        },
        identity={
            "commission": commission_ref.to_dict(),
            "attempt": commission["attempt"],
            "execution": commission["execution"],
        },
        owners=_owners_dict(),
        evidence_prefix=dict(FAKE_PREFIX),
        evidence_refs=[_evidence_ref("rec_registration")],
    )


def _setup_base() -> dict[str, Any]:
    _seq["next"] = 0
    _register_channels()
    admission = _admit_report_journal()
    commission = _commission_dict()
    commission_ref = _retain_commission(commission)
    loaded = ac.load_commission(CHANNELS["report"], commission_ref)
    assert loaded.attempt["attempt_id"] == "attempt_rec_1"
    registration = _register_attempt(commission_ref)
    orv.register_entity(CHANNELS["dispatch"], registration)
    return {
        "admission": admission,
        "commission": commission,
        "commission_ref": commission_ref,
        "registration": registration,
        "entity": {
            "entity_type": "application_attempt",
            "attempt_id": "attempt_rec_1",
            "kind": "production",
        },
    }


def _dispatch_prepared() -> dict[str, Any]:
    return {
        "state": "prepared",
        "local_handle": _missing(),
        "native_run_id": _missing_observed(),
        "request_digest": D1,
        "delivery_refs": [],
        "acceptance_refs": [],
        "recovery_authorization_refs": [],
        "reason": _missing(),
    }


def _close_snapshot(
    boundary_ref: dict[str, Any],
    *,
    dispatch_rev: int = 1,
    dispatch_digest: Any = D1,
    execution_rev: int = 1,
    execution_digest: Any = D1,
    application_rev: int = 0,
    application_digest: Any = None,
    report_rev: int = 0,
    report_digest: Any = None,
):
    def _pin(rev: int, digest: Any) -> dict[str, Any]:
        if rev == 0:
            return {"revision": 0, "record_digest": _missing_observed()}
        return {"revision": rev, "record_digest": digest}

    return {
        "closure_id": "closure_rec_1",
        "boundary_ref": dict(boundary_ref),
        "known_versions": {
            "dispatch": _pin(dispatch_rev, dispatch_digest),
            "execution": _pin(execution_rev, execution_digest),
            "application": _pin(
                application_rev,
                application_digest if application_digest else _missing_observed(),
            ),
            "report": _pin(
                report_rev, report_digest if report_digest else _missing_observed()
            ),
        },
        "execution_knowledge": "unknown",
        "execution_evidence_refs": [],
        "application_knowledge": "unknown",
        "application_evidence_refs": [],
        "limitations": ["Close-time application outcome is unknown."],
    }


def _observation_closed(
    closed_at: dict[str, Any],
    at_close: dict[str, Any],
    late_refs: list[dict[str, Any]] | None = None,
):
    return {
        "state": "closed",
        "window_id": "window_rec_1",
        "opened_at": _timepoint(100.0),
        "active_deadline": _timepoint(200.0),
        "drain_started_at": _missing(),
        "drain_deadline": _missing(),
        "closed_at": dict(closed_at),
        "close_reason": "normal_completion",
        "at_close": dict(at_close),
        "control_observations": [],
        "late_evidence_refs": list(late_refs or []),
        "measurements": [],
    }


def _claim(
    claim_id: str,
    *,
    scope: str,
    state: Any,
    assertions: list[dict[str, Any]],
    evidence: dict[str, Any],
    received_offset: float = 120.0,
    received_utc: Any = None,
    made_offset: float | None = 110.0,
):
    made = (
        _missing_observed() if made_offset is None else _timepoint(made_offset)
    )
    return {
        "claim_id": claim_id,
        "scope": scope,
        "state": state,
        "application_assertions": list(assertions),
        "native_run_id": _missing_observed(),
        "native_message_id": _missing_observed(),
        "native_report": _artifact_dict(D1, "attempt.execution", "public"),
        "mapping": dict(POLICY),
        "source_checks": {
            "source_identity": "verified",
            "receipt_semantics": "verified",
            "correlation": "verified",
        },
        "made_at": made,
        "received_at": _timepoint(
            received_offset,
            utc=received_utc
            if received_utc
            else _missing_observed(),
        ),
        "evidence_available_to_claimant": [dict(evidence)],
        "evidence_refs": [dict(evidence)],
        "limitations": [f"Claim {claim_id} is preserved verbatim."],
    }


def _assertion(
    assertion_id: str,
    value: str,
    span: str,
    boundary_ref: Any,
    evidence: dict[str, Any],
):
    return {
        "assertion_id": assertion_id,
        "value": value,
        "span": span,
        "boundary_ref": dict(boundary_ref)
        if isinstance(boundary_ref, dict)
        else boundary_ref,
        "evidence_refs": [dict(evidence)],
    }


def _fact(
    fact_id: str,
    *,
    state: str,
    coverage: str,
    boundary_ref: dict[str, Any],
    evidence: dict[str, Any],
    occurred: Any = None,
    occurred_missing: bool = False,
    received_offset: float = 5000.0,
    received_utc: Any = None,
    origin_revision: Any = None,
):
    if occurred_missing:
        occurred_at = _missing_observed()
    elif occurred is not None:
        occurred_at = occurred
    else:
        occurred_at = _missing_observed()
    return {
        "fact_id": fact_id,
        "origin_id": "target_rec_1",
        "candidate_id": "candidate_rec_1",
        "job_id": "job_rec_1",
        "state": state,
        "coverage": coverage,
        "boundary_ref": dict(boundary_ref),
        "origin_application_id": "app_rec_1",
        "origin_revision": origin_revision
        if origin_revision is not None
        else _missing_observed(),
        "receipt": _artifact_dict(D2, "attempt.application", "public"),
        "verification_kind": "verified_origin_receipt",
        "source_checks": {
            "source_identity": "verified",
            "receipt_semantics": "verified",
            "correlation": "verified",
        },
        "authority_seal_ref": _missing(),
        "occurred_at": occurred_at,
        "received_at": _timepoint(
            received_offset,
            utc=received_utc
            if received_utc
            else _missing_observed(),
        ),
        "evidence_refs": [dict(evidence)],
    }


def _commit(ctx: dict[str, Any], axis: str, revision: int, value, command: str):
    attempt = {"attempt_id": "attempt_rec_1", "kind": "production"}
    axis_revision = orv.AxisRevision(
        attempt=attempt,
        commission_digest=ctx["commission_ref"].digest,
        axis=axis,
        owner_domain=OWNER_DOMAINS[axis],
        writer_id=WRITERS[axis],
        revision=revision,
        previous_revision=revision - 1,
        evidence_prefix=dict(FAKE_PREFIX),
        evidence_refs=[
            _evidence_ref(f"rec_{axis}_{revision}", revision + 10)
        ],
        value=copy.deepcopy(value),
    )
    return orv.commit_domain(
        CHANNELS[axis],
        ctx["registration"],
        axis_revision,
        command,
        _missing(),
    )


def _pins(
    *,
    dispatch: tuple[int, Any] | None = None,
    observation: tuple[int, Any] | None = None,
    execution: tuple[int, Any] | None = None,
    application: tuple[int, Any] | None = None,
) -> dict[str, Any]:
    def _pin(spec: tuple[int, Any] | None) -> dict[str, Any]:
        if spec is None:
            return {"revision": 0, "record_digest": _missing_observed()}
        rev, digest = spec
        if rev == 0:
            return {"revision": 0, "record_digest": _missing_observed()}
        return {"revision": rev, "record_digest": digest}

    return {
        "dispatch": _pin(dispatch),
        "observation": _pin(observation),
        "execution": _pin(execution),
        "application": _pin(application),
    }


def _evaluator() -> dict[str, Any]:
    return {"id": "evaluator_rec", "version": "1", "artifact_digest": D0}


def _head():
    return ev.journal_head(CHANNELS["report"], "journal_rec_report")


def test_late_commitment_after_close_time_unknown_preserves_snapshot_and_compatibility():
    ctx = _setup_base()
    boundary_env = _append(
        {"note": "close boundary", "boundary_id": "b_close_1"},
        occurred=ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=1000.0,
        ),
    )
    boundary_ref = _ref(boundary_env)
    claim_env = _append(
        {"note": "claim evidence", "claim_id": "claim_unknown_1"}
    )
    claim_ref = _ref(claim_env)
    prefix1 = _head()

    dispatch_ref = _commit(
        ctx, "dispatch", 1, _dispatch_prepared(), "cmd-rec-dispatch-1"
    )
    closed_at = _timepoint(300.0)
    snapshot = _close_snapshot(boundary_ref)
    obs_value = _observation_closed(closed_at, snapshot)
    observation_ref = _commit(
        ctx, "observation", 1, obs_value, "cmd-rec-obs-1"
    )
    assertion = _assertion(
        "assert_unknown_1",
        "outcome_unknown",
        "at_boundary",
        boundary_ref,
        claim_ref,
    )
    claim = _claim(
        "claim_unknown_1",
        scope="application_postcondition",
        state="completed",
        assertions=[assertion],
        evidence=claim_ref,
    )
    execution_ref = _commit(
        ctx, "execution", 1, {"claims": [claim]}, "cmd-rec-exec-1"
    )
    inputs1 = _pins(
        dispatch=(1, dispatch_ref.digest),
        observation=(1, observation_ref.digest),
        execution=(1, execution_ref.digest),
        application=None,
    )
    report1 = cr.derive_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        inputs1,
        _evaluator(),
        prefix1,
    )
    assert report1.coverage == "incomplete"
    assert report1.state["reason"] == "not_observed"
    assert len(report1.comparisons) == 1
    first = report1.comparisons[0]
    assert first.claim_id == "claim_unknown_1"
    assert first.assertion_id == "assert_unknown_1"
    assert first.result == "indeterminate"
    assert tuple(first.fact_ids) == ()
    cr.publish_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        report1,
        0,
        "cmd-rec-report-1",
    )
    stored1 = orv.read_revision(
        CHANNELS["report"], ctx["entity"], "report", 1
    )
    assert stored1.record["value"]["coverage"] == "incomplete"

    # Late commitment arrives after closure; it must not rewrite the
    # close-time snapshot, and the unknown outcome stays compatible.
    fact_env = _append(
        {"note": "late fact evidence", "fact_id": "fact_late_1"}
    )
    fact_ref = _ref(fact_env)
    prefix2 = _head()
    fact = _fact(
        "fact_late_1",
        state="committed",
        coverage="at_boundary",
        boundary_ref=boundary_ref,
        evidence=fact_ref,
        occurred_missing=True,
        received_offset=8000.0,
    )
    application_ref = _commit(
        ctx, "application", 1, {"facts": [fact]}, "cmd-rec-app-1"
    )
    obs_head = orv.read_revision(
        CHANNELS["observation"], ctx["entity"], "observation", 1
    )
    obs_value2 = copy.deepcopy(obs_head.record["value"])
    obs_value2["late_evidence_refs"] = [dict(fact_ref)]
    observation_ref2 = _commit(
        ctx, "observation", 2, obs_value2, "cmd-rec-obs-2"
    )
    inputs2 = _pins(
        dispatch=(1, dispatch_ref.digest),
        observation=(2, observation_ref2.digest),
        execution=(1, execution_ref.digest),
        application=(1, application_ref.digest),
    )
    report2 = cr.derive_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        inputs2,
        _evaluator(),
        prefix2,
    )
    assert report2.state == "reconciled"
    assert report2.coverage == "complete"
    assert len(report2.comparisons) == 1
    second = report2.comparisons[0]
    assert second.claim_id == "claim_unknown_1"
    assert second.assertion_id == "assert_unknown_1"
    assert second.result == "consistent"
    assert tuple(second.fact_ids) == ("fact_late_1",)
    assert second.claim_ref == claim_ref
    assert fact_ref in [dict(r) for r in second.fact_refs]
    assert any(
        "Close-time outcome unknown is preserved" in text
        for text in second.limitations
    )
    cr.publish_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        report2,
        1,
        "cmd-rec-report-2",
    )
    # Both reports are preserved; the close-time snapshot still says unknown.
    assert orv.domain_head(CHANNELS["report"], ctx["entity"], "report") == 2
    assert (
        orv.domain_head(CHANNELS["observation"], ctx["entity"], "observation")
        == 2
    )
    closed_again = orv.read_revision(
        CHANNELS["observation"], ctx["entity"], "observation", 1
    )
    assert (
        closed_again.record["value"]["at_close"]["application_knowledge"]
        == "unknown"
    )
    latest_obs = orv.read_revision(
        CHANNELS["observation"], ctx["entity"], "observation", 2
    )
    assert (
        latest_obs.record["value"]["at_close"]["application_knowledge"]
        == "unknown"
    )
    assert latest_obs.record["value"]["late_evidence_refs"] == [fact_ref]


def test_late_commitment_against_entire_attempt_no_commit_claim_is_contradicted():
    ctx = _setup_base()
    boundary_env = _append(
        {"note": "close boundary", "boundary_id": "b_close_2"}
    )
    boundary_ref = _ref(boundary_env)
    claim_env = _append(
        {"note": "claim evidence", "claim_id": "claim_cancel_1"}
    )
    claim_ref = _ref(claim_env)
    fact_env = _append(
        {"note": "fact evidence", "fact_id": "fact_commit_1"}
    )
    fact_ref = _ref(fact_env)
    prefix = _head()

    dispatch_ref = _commit(
        ctx, "dispatch", 1, _dispatch_prepared(), "cmd-rec2-dispatch-1"
    )
    closed_at = _timepoint(300.0)
    snapshot = _close_snapshot(boundary_ref)
    obs_value = _observation_closed(closed_at, snapshot)
    observation_ref = _commit(
        ctx, "observation", 1, obs_value, "cmd-rec2-obs-1"
    )
    assertion = _assertion(
        "assert_cancel_1",
        "not_committed",
        "entire_attempt",
        _missing("not_applicable"),
        claim_ref,
    )
    claim = _claim(
        "claim_cancel_1",
        scope="execution_lifecycle",
        state="stopped",
        assertions=[assertion],
        evidence=claim_ref,
    )
    execution_ref = _commit(
        ctx, "execution", 1, {"claims": [claim]}, "cmd-rec2-exec-1"
    )
    fact = _fact(
        "fact_commit_1",
        state="committed",
        coverage="at_boundary",
        boundary_ref=boundary_ref,
        evidence=fact_ref,
        occurred_missing=True,
        received_offset=8000.0,
    )
    application_ref = _commit(
        ctx, "application", 1, {"facts": [fact]}, "cmd-rec2-app-1"
    )
    inputs = _pins(
        dispatch=(1, dispatch_ref.digest),
        observation=(1, observation_ref.digest),
        execution=(1, execution_ref.digest),
        application=(1, application_ref.digest),
    )
    report = cr.derive_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        inputs,
        _evaluator(),
        prefix,
    )
    assert report.state == "contradicted"
    assert report.coverage == "complete"
    assert len(report.comparisons) == 1
    comp = report.comparisons[0]
    assert comp.claim_id == "claim_cancel_1"
    assert comp.assertion_id == "assert_cancel_1"
    assert comp.result == "contradicted"
    assert tuple(comp.fact_ids) == ("fact_commit_1",)
    assert comp.claim_ref == claim_ref
    assert [dict(r) for r in comp.fact_refs] == [fact_ref]
    assert comp.temporal_relation.relation == "not_applicable"
    assert comp.temporal_relation.basis == "not_applicable"
    cr.publish_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        report,
        0,
        "cmd-rec2-report-1",
    )
    # Both sources are preserved verbatim; nothing is rewritten.
    stored_claim = orv.read_revision(
        CHANNELS["execution"], ctx["entity"], "execution", 1
    ).record["value"]["claims"][0]
    assert stored_claim["claim_id"] == "claim_cancel_1"
    assert stored_claim["state"] == "stopped"
    assert stored_claim["application_assertions"][0]["value"] == "not_committed"
    stored_fact = orv.read_revision(
        CHANNELS["application"], ctx["entity"], "application", 1
    ).record["value"]["facts"][0]
    assert stored_fact["fact_id"] == "fact_commit_1"
    assert stored_fact["state"] == "committed"
    stored_report = orv.read_revision(
        CHANNELS["report"], ctx["entity"], "report", 1
    ).record["value"]
    assert stored_report["comparisons"][0]["result"] == "contradicted"
    assert stored_report["comparisons"][0]["fact_ids"] == ["fact_commit_1"]


def test_receipt_arrival_order_without_temporal_evidence_keeps_relation_unknown():
    ctx = _setup_base()
    boundary_env = _append(
        {"note": "close boundary", "boundary_id": "b_temporal_1"},
        occurred=ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=1000.0,
        ),
    )
    boundary_ref = _ref(boundary_env)
    claim_env = _append(
        {"note": "claim evidence", "claim_id": "claim_bounded_1"}
    )
    claim_ref = _ref(claim_env)
    # The receipt arrives later in journal order (higher sequence) but its
    # occurrence clock is unknown; arrival order must not order it.
    fact_env = _append(
        {"note": "late receipt evidence", "fact_id": "fact_receipt_1"}
    )
    fact_ref = _ref(fact_env)
    assert fact_env.journal_sequence > boundary_env.journal_sequence
    prefix = _head()

    dispatch_ref = _commit(
        ctx, "dispatch", 1, _dispatch_prepared(), "cmd-rec3-dispatch-1"
    )
    closed_at = _timepoint(300.0)
    snapshot = _close_snapshot(boundary_ref)
    obs_value = _observation_closed(closed_at, snapshot)
    observation_ref = _commit(
        ctx, "observation", 1, obs_value, "cmd-rec3-obs-1"
    )
    assertion = _assertion(
        "assert_bounded_1",
        "committed",
        "at_boundary",
        boundary_ref,
        claim_ref,
    )
    claim = _claim(
        "claim_bounded_1",
        scope="application_postcondition",
        state="completed",
        assertions=[assertion],
        evidence=claim_ref,
        received_offset=120.0,
        received_utc="2026-01-01T00:00:00.000Z",
    )
    execution_ref = _commit(
        ctx, "execution", 1, {"claims": [claim]}, "cmd-rec3-exec-1"
    )
    fact = _fact(
        "fact_receipt_1",
        state="committed",
        coverage="at_boundary",
        boundary_ref=boundary_ref,
        evidence=fact_ref,
        occurred_missing=True,
        received_offset=9000.0,
        received_utc="2026-06-01T00:00:00.000Z",
        origin_revision="rev-zzz-late",
    )
    application_ref = _commit(
        ctx, "application", 1, {"facts": [fact]}, "cmd-rec3-app-1"
    )
    inputs = _pins(
        dispatch=(1, dispatch_ref.digest),
        observation=(1, observation_ref.digest),
        execution=(1, execution_ref.digest),
        application=(1, application_ref.digest),
    )
    report = cr.derive_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        inputs,
        _evaluator(),
        prefix,
    )
    assert len(report.comparisons) == 1
    comp = report.comparisons[0]
    assert comp.result == "consistent"
    assert comp.temporal_relation.relation == "unknown"
    assert comp.temporal_relation.basis == "not_established"
    assert tuple(comp.temporal_relation.evidence_refs) == ()
    assert tuple(comp.fact_ids) == ("fact_receipt_1",)
    cr.publish_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        report,
        0,
        "cmd-rec3-report-1",
    )
    stored = orv.read_revision(
        CHANNELS["report"], ctx["entity"], "report", 1
    ).record["value"]
    assert stored["comparisons"][0]["temporal_relation"]["relation"] == "unknown"
    assert (
        stored["comparisons"][0]["temporal_relation"]["basis"]
        == "not_established"
    )


def test_reconciled_narrow_claim_does_not_imply_application_success():
    ctx = _setup_base()
    boundary_env = _append(
        {"note": "close boundary", "boundary_id": "b_narrow_1"}
    )
    boundary_ref = _ref(boundary_env)
    narrow_env = _append(
        {"note": "narrow evidence", "claim_id": "claim_narrow_1"}
    )
    narrow_ref = _ref(narrow_env)
    stopped_env = _append(
        {"note": "stopped evidence", "claim_id": "claim_narrow_2"}
    )
    stopped_ref = _ref(stopped_env)
    fact_env = _append(
        {"note": "fact evidence", "fact_id": "fact_commit_narrow"}
    )
    fact_ref = _ref(fact_env)
    prefix = _head()

    dispatch_ref = _commit(
        ctx, "dispatch", 1, _dispatch_prepared(), "cmd-rec4-dispatch-1"
    )
    closed_at = _timepoint(300.0)
    snapshot = _close_snapshot(boundary_ref)
    obs_value = _observation_closed(closed_at, snapshot)
    observation_ref = _commit(
        ctx, "observation", 1, obs_value, "cmd-rec4-obs-1"
    )
    narrow1 = _claim(
        "claim_narrow_1",
        scope="execution_lifecycle",
        state="completed",
        assertions=[],
        evidence=narrow_ref,
    )
    narrow2 = _claim(
        "claim_narrow_2",
        scope="execution_lifecycle",
        state="stopped",
        assertions=[],
        evidence=stopped_ref,
    )
    execution_ref = _commit(
        ctx,
        "execution",
        1,
        {"claims": [narrow1, narrow2]},
        "cmd-rec4-exec-1",
    )
    fact = _fact(
        "fact_commit_narrow",
        state="committed",
        coverage="at_boundary",
        boundary_ref=boundary_ref,
        evidence=fact_ref,
        occurred_missing=True,
    )
    application_ref = _commit(
        ctx, "application", 1, {"facts": [fact]}, "cmd-rec4-app-1"
    )
    inputs = _pins(
        dispatch=(1, dispatch_ref.digest),
        observation=(1, observation_ref.digest),
        execution=(1, execution_ref.digest),
        application=(1, application_ref.digest),
    )
    report = cr.derive_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        inputs,
        _evaluator(),
        prefix,
    )
    assert report.state == "reconciled"
    assert report.coverage == "complete"
    assert len(report.comparisons) == 2
    by_id = {c.claim_id: c for c in report.comparisons}
    assert set(by_id) == {"claim_narrow_1", "claim_narrow_2"}
    for comp in report.comparisons:
        assert comp.result == "not_comparable"
        assert comp.assertion_id["reason"] == "not_applicable"
        assert tuple(comp.fact_ids) == ()
        assert tuple(comp.fact_refs) == ()
        assert comp.temporal_relation.relation == "not_applicable"
        assert comp.temporal_relation.basis == "not_applicable"
    stopped = by_id["claim_narrow_2"]
    assert any("Stopped alone" in text for text in stopped.limitations)
    assert any(
        "never asserts application success" in text
        for text in report.limitations
    )
    # A reconciled narrow report proves no application outcome.
    assert report.state == "reconciled"
    assert all(c.result == "not_comparable" for c in report.comparisons)
    cr.publish_report(
        CHANNELS["report"],
        ctx["commission_ref"],
        report,
        0,
        "cmd-rec4-report-1",
    )
    stored = orv.read_revision(
        CHANNELS["report"], ctx["entity"], "report", 1
    ).record["value"]
    assert stored["state"] == "reconciled"
    assert all(
        c["result"] == "not_comparable" for c in stored["comparisons"]
    )
    assert all(c["fact_ids"] == [] for c in stored["comparisons"])
    # The committed origin fact is still there, but the report claims no
    # application success from the narrow execution findings.
    app_value = orv.read_revision(
        CHANNELS["application"], ctx["entity"], "application", 1
    ).record["value"]
    assert app_value["facts"][0]["state"] == "committed"
