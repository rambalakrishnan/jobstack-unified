"""Conformance tests for manual_observation (tier 6)."""
from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "manual_observation":
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
mo = _load("manual_observation")

D0 = "sha256:" + "0" * 64
D1 = "sha256:" + "1" * 64
POLICY = {"id": "policy_test", "version": "1", "artifact_digest": D0}
APP_CLOCK = "clock_manobs_app"
APP_BOOT = "boot_manobs_app"
OBS_CLOCK = "clock_manobs_obs"
OBS_BOOT = "boot_manobs_obs"

MANUAL_KINDS = (
    "manual.action",
    "manual.pause",
    "manual.assistance",
    "manual.note",
    "manual.receipt",
)


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


def _app_timepoint(offset: float = 1.0) -> dict[str, Any]:
    return {
        "clock_id": APP_CLOCK,
        "boot_id": APP_BOOT,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing_observed(),
    }


def _obs_timepoint(offset: float) -> dict[str, Any]:
    return {
        "clock_id": OBS_CLOCK,
        "boot_id": OBS_BOOT,
        "origin": "manual_reference",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing_observed(),
    }


def _register_app_channel(
    channel: str, producer: str, principal: str
) -> None:
    ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=channel,
        axis="attempt.application",
        producer_id=producer,
        principal_id=principal,
        sequence_required=False,
        allowed_event_kinds=("attempt.commissioned",),
        binding=f"bind_{channel}",
    )
    try:
        ap.register_event_kind(
            "attempt.commissioned",
            "1",
            role="lifecycle_observation",
            assertion_kind="authoritative_effect",
            owner_domain="attempt.application",
            writer_roles=("application_origin",),
        )
    except Exception:
        pass


def _retain_app(channel: str, content: bytes, access: str = "restricted") -> Any:
    return store.retain_artifact(
        channel, "attempt.application", "application/json", content, access
    )


def _attempt(
    attempt_id: str,
    kind: str,
    target_class: str,
    target_id: str,
    partition: str,
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "kind": kind,
        "target_class": target_class,
        "target_id": target_id,
        "evaluation_partition": partition,
        "rehearsal_of": [],
        "performance_of": [],
        "derived_from": [],
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


def _manifest_execution_for(execution: dict[str, Any]) -> dict[str, Any]:
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


def _admit_app(
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
                "clock_id": APP_CLOCK,
                "boot_id": APP_BOOT,
                "origin": "engine_measured",
                "source_id": "src_manobs_engine",
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


def _obs_policy() -> dict[str, Any]:
    def _limit() -> dict[str, Any]:
        return {"kind": "exact", "unit": "ms", "value": 0}

    return {
        "active_limit": _limit(),
        "drain_limit": _limit(),
        "native_cancel_wait_limit": _limit(),
        "cleanup_wait_limit": _limit(),
        "fixture_close_action": "not_applicable",
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
    selection_evidence: Any = None,
) -> dict[str, Any]:
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
        "commissioned_at": _app_timepoint(),
        "attempt": dict(attempt),
        "candidate_id": candidate_id,
        "candidate_profile": _missing_observed(),
        "job": {
            "job_id": job_id,
            "source_target": _missing_observed(),
            "source_job_id": _missing_observed(),
            "snapshot": snapshot_ref.to_dict(),
        },
        "selection_evidence": selection_evidence
        if selection_evidence is not None
        else _missing_observed(),
        "task": task_ref.to_dict(),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": dict(execution),
        "owners": {k: dict(v) for k, v in owners.items()},
        "idempotency_key": idempotency_key,
        "authorization_refs": [dict(r) for r in authorization_refs],
        "recovery_review_refs": [],
        "observation_policy": _obs_policy(),
        "origin_policy": dict(POLICY),
    }


def _close_snapshot(boundary_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "closure_id": "closure_manobs_1",
        "boundary_ref": dict(boundary_ref),
        "known_versions": [],
        "execution_knowledge": "not_applicable",
        "execution_evidence_refs": [],
        "application_knowledge": "unknown",
        "application_evidence_refs": [],
        "limitations": ["Close-time application outcome is unknown."],
    }


def _observation_value(
    state: str,
    *,
    boundary_ref: dict[str, Any] | None = None,
    late_refs: list[dict[str, Any]] | None = None,
    measurements: list[dict[str, Any]] | None = None,
    closed_offset: float = 300.0,
) -> dict[str, Any]:
    opened = state in ("open", "draining", "closed")
    draining_or_closed = state in ("draining", "closed")
    closed = state == "closed"
    at_close: Any = _missing()
    closed_at: Any = _missing()
    close_reason: Any = _missing()
    if draining_or_closed:
        close_reason = "normal_completion"
    if closed:
        assert boundary_ref is not None
        closed_at = _obs_timepoint(closed_offset)
        at_close = _close_snapshot(boundary_ref)
    return {
        "state": state,
        "window_id": "window_manobs_1",
        "opened_at": _obs_timepoint(100.0) if opened else _missing(),
        "active_deadline": _obs_timepoint(200.0) if opened else _missing(),
        "drain_started_at": _obs_timepoint(150.0)
        if draining_or_closed
        else _missing(),
        "drain_deadline": _obs_timepoint(250.0)
        if draining_or_closed
        else _missing(),
        "closed_at": closed_at,
        "close_reason": close_reason,
        "at_close": at_close,
        "control_observations": [],
        "late_evidence_refs": list(late_refs or []),
        "measurements": list(measurements or []),
    }


def _manual_submission(
    kind: str, sequence: int, offset: float, data: dict[str, Any]
) -> Any:
    return ev.EventSubmission(
        producer_sequence=sequence,
        event_kind=kind,
        event_schema_version="1",
        occurred_at=ev.TimePoint(
            clock_id=OBS_CLOCK,
            boot_id=OBS_BOOT,
            origin="manual_reference",
            monotonic_offset_ms=offset,
        ),
        payload=ev.EvidencePayload(
            data=dict(data),
            measurements=[],
            evidence_refs=[],
            artifact_refs=[],
        ),
    )


def _setup_manual_attempt(tag: str) -> dict[str, Any]:
    """Commission a manual production attempt; return harness handles."""
    channel = f"ch_manobs_app_{tag}"
    producer = f"prod_manobs_app_{tag}"
    principal = f"principal_manobs_{tag}"
    _register_app_channel(channel, producer, principal)

    task_ref = _retain_app(channel, b'{"goal":"manual apply intent"}')
    config_ref = _retain_app(channel, b'{"policy":"manual"}')
    snapshot_ref = _retain_app(channel, b'{"job":"manual snapshot"}', "public")
    human_ref = _retain_app(
        channel, b'{"decision":"human go","rationale":"fit"}', "public"
    )

    target_id = f"target_manobs_{tag}"
    attempt = _attempt(
        f"attempt_manobs_{tag}", "production", "employer_origin", target_id, "held_out"
    )
    execution = _manual_execution()
    admission, admission_ref = _admit_app(
        channel,
        producer,
        principal,
        f"run_manobs_{tag}",
        f"journal_manobs_app_{tag}",
        f"manifest_manobs_app_{tag}",
        attempt,
        execution,
        task_ref,
        config_ref,
    )
    obs_writer = f"prod_manobs_obs_{tag}"
    report_writer = f"prod_manobs_report_{tag}"
    owners = _manual_owners(producer, obs_writer, report_writer, target_id)
    commission = _commission(
        commission_id=f"comm_manobs_{tag}",
        run_id=f"run_manobs_{tag}",
        journal_id=f"journal_manobs_app_{tag}",
        manifest_hash=admission.manifest_hash,
        admission_ref=admission_ref,
        commissioned_by=principal,
        attempt=attempt,
        candidate_id=f"candidate_manobs_{tag}",
        job_id=f"portfolio_manobs_{tag}",
        snapshot_ref=snapshot_ref,
        task_ref=task_ref,
        execution=execution,
        owners=owners,
        idempotency_key=f"idem_manobs_{tag}",
        authorization_refs=[admission_ref],
        selection_evidence=human_ref.to_dict(),
    )
    ref = ac.register_attempt(channel, ac.AttemptCommission.from_dict(commission))
    return {
        "channel": channel,
        "producer": producer,
        "principal": principal,
        "attempt": attempt,
        "admission": admission,
        "admission_ref": admission_ref,
        "owners": owners,
        "obs_writer": obs_writer,
        "commission_ref": ref,
        "entity": {
            "entity_type": "application_attempt",
            "attempt_id": attempt["attempt_id"],
            "kind": attempt["kind"],
        },
    }


def _register_observation_channels(
    tag: str, obs_writer: str
) -> dict[str, str]:
    obs_channel = f"ch_manobs_obs_{tag}"
    ap.register_channel(
        actor="connector",
        channel_id=obs_channel,
        axis="attempt.observation",
        producer_id=obs_writer,
        principal_id=f"principal_manobs_obs_{tag}",
        sequence_required=False,
        allowed_event_kinds=(f"attempt.observation.published",),
        binding=f"bind_manobs_obs_{tag}",
    )
    manual_channel = f"ch_manobs_manual_{tag}"
    manual_producer = f"prod_manobs_manual_{tag}"
    manual_principal = f"principal_manobs_manual_{tag}"
    ap.register_channel(
        actor="manual_recorder",
        channel_id=manual_channel,
        axis="attempt.observation",
        producer_id=manual_producer,
        principal_id=manual_principal,
        sequence_required=False,
        allowed_event_kinds=MANUAL_KINDS,
    )
    for kind in MANUAL_KINDS:
        try:
            ap.register_event_kind(
                kind,
                "1",
                role="lifecycle_observation",
                assertion_kind="observation",
                owner_domain="attempt.observation",
                writer_roles=("observer",),
            )
        except Exception:
            pass
    return {
        "obs_channel": obs_channel,
        "manual_channel": manual_channel,
        "manual_producer": manual_producer,
        "manual_principal": manual_principal,
    }


def _admit_observation_journal(
    tag: str,
    attempt: dict[str, Any],
    manual_channel: str,
    manual_producer: str,
    manual_principal: str,
) -> Any:
    # Observation task/config live in the observation owner domain.
    obs_task = store.retain_artifact(
        manual_channel,
        "attempt.observation",
        "application/json",
        b'{"task":"manual observation"}',
        "restricted",
    )
    obs_config = store.retain_artifact(
        manual_channel,
        "attempt.observation",
        "application/json",
        b'{"config":"manual observation"}',
        "restricted",
    )
    # The access policy provides no server-provenance actor for the
    # observation axis, so admission through the public control plane is
    # impossible.  Inject a bounded server channel for admission only; all
    # manual appends use the real manual_recorder channel above.
    server_channel = f"ch_manobs_server_{tag}"
    server_producer = f"prod_manobs_server_{tag}"
    server_principal = f"principal_manobs_server_{tag}"
    descriptor = ap.ProducerDescriptor(
        producer_id=server_producer,
        principal_id=server_principal,
        owner_domain="attempt.observation",
        role="kernel",
        provenance="server",
        sequence_required=False,
        allowed_event_kinds=MANUAL_KINDS,
    )
    binding = ap._ChannelBinding(  # type: ignore[attr-defined]
        channel_id=server_channel,
        actor="product_writer",
        descriptor=descriptor,
        grants=frozenset({"attempt.observation.write"}),
        axis="attempt.observation",
        binding=ap.NOT_APPLICABLE,
        registered_ns=time.time_ns(),
    )
    ap._CHANNELS[server_channel] = binding  # type: ignore[attr-defined]
    try:
        ap._PRODUCER_IDENTITIES[server_producer] = (  # type: ignore[attr-defined]
            server_principal,
            "product_writer",
        )
        ap._AXIS_OWNERS[("attempt.observation", "server")] = (  # type: ignore[attr-defined]
            server_producer
        )
    except Exception:
        pass
    manifest = ev.Manifest(
        manifest_id=f"manifest_manobs_obs_{tag}",
        run_id=f"run_manobs_{tag}",
        journal_id=f"journal_manobs_obs_{tag}",
        owner_domain="attempt.observation",
        commissioner_id=server_principal,
        activity="application_attempt",
        attempt=dict(attempt),
        execution=_manifest_execution_for(_manual_execution()),
        task=obs_task,
        task_semantic_hash=D0,
        effective_configuration=obs_config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": obs_task.digest}
        ],
        event_registry=[
            {
                "event_kind": kind,
                "event_schema_version": "1",
                "role": "lifecycle_observation",
                "assertion_kind": "observation",
                "writer_roles": ["observer"],
            }
            for kind in MANUAL_KINDS
        ],
        producers=[
            {
                "producer_id": server_producer,
                "principal_id": server_principal,
                "owner_domain": "attempt.observation",
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": list(MANUAL_KINDS),
            },
            {
                "producer_id": manual_producer,
                "principal_id": manual_principal,
                "owner_domain": "attempt.observation",
                "role": "observer",
                "provenance": "manual_observer",
                "sequence_required": False,
                "allowed_event_kinds": list(MANUAL_KINDS),
            },
        ],
        clocks=[
            {
                "clock_id": OBS_CLOCK + "_engine",
                "boot_id": OBS_BOOT + "_engine",
                "origin": "engine_measured",
                "source_id": "src_manobs_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            },
            {
                "clock_id": OBS_CLOCK,
                "boot_id": OBS_BOOT,
                "origin": "manual_reference",
                "source_id": "src_manobs_manual",
                "basis": "monotonic_offset",
                "unit": "ms",
            },
        ],
    )
    return ev.admit_manifest(server_channel, manifest)


# ---------------------------------------------------------------------------
# 1. Manual dispatch/execution publication is rejected
# ---------------------------------------------------------------------------


def test_manual_dispatch_or_execution_publication_is_rejected():
    harness = _setup_manual_attempt("rej")
    entity = harness["entity"]
    app_channel = harness["channel"]

    # Dispatch and execution stay unpublished for manual attempts.
    assert orv.domain_head(app_channel, entity, "dispatch") == 0
    assert orv.domain_head(app_channel, entity, "execution") == 0

    # The manual module exposes observation recording only.
    assert hasattr(mo, "record_manual_event")
    assert hasattr(mo, "publish_manual_observation")
    assert not hasattr(mo, "publish_manual_dispatch")
    assert not hasattr(mo, "publish_manual_execution")

    # Any direct dispatch publication for a manual attempt is rejected.
    entity_id = f"attempt.{entity['attempt_id']}.{entity['kind']}"
    stored = orv._REGISTRATIONS[entity_id]  # type: ignore[attr-defined]
    registration = orv.EntityRegistration.from_dict(dict(stored.record))
    prefix = {
        "journal_id": f"journal_rej_evidence",
        "last_sequence": 1,
        "head_hash": D1,
    }
    dispatch_value = {
        "state": "not_started",
        "local_handle": _missing(),
        "native_run_id": _missing(),
        "request_digest": _missing(),
        "delivery_refs": [],
        "acceptance_refs": [],
        "recovery_authorization_refs": [],
        "reason": _missing(),
    }
    dispatch_rev = orv.AxisRevision(
        attempt={
            "attempt_id": entity["attempt_id"],
            "kind": entity["kind"],
        },
        commission_digest=harness["commission_ref"].digest,
        axis="dispatch",
        owner_domain="attempt.dispatch",
        writer_id="prod_rej_spoof",
        revision=1,
        previous_revision=0,
        evidence_prefix=prefix,
        evidence_refs=[dict(harness["admission_ref"])],
        value=dispatch_value,
    )
    with pytest.raises(orv.OwnerRevisionError):
        orv.commit_domain(
            app_channel, registration, dispatch_rev, "cmd_rej_dispatch", _missing()
        )
    assert orv.domain_head(app_channel, entity, "dispatch") == 0

    execution_value = {
        "claims": [
            {
                "claim_id": "claim_rej_1",
                "scope": "primitive",
                "state": _missing(),
                "evidence_refs": [dict(harness["admission_ref"])],
            }
        ]
    }
    execution_rev = orv.AxisRevision(
        attempt={
            "attempt_id": entity["attempt_id"],
            "kind": entity["kind"],
        },
        commission_digest=harness["commission_ref"].digest,
        axis="execution",
        owner_domain="attempt.execution",
        writer_id="prod_rej_spoof_exec",
        revision=1,
        previous_revision=0,
        evidence_prefix=prefix,
        evidence_refs=[dict(harness["admission_ref"])],
        value=execution_value,
    )
    with pytest.raises(orv.OwnerRevisionError):
        orv.commit_domain(
            app_channel, registration, execution_rev, "cmd_rej_exec", _missing()
        )
    assert orv.domain_head(app_channel, entity, "execution") == 0

    # Observation remains publishable while dispatch/execution stay at zero.
    channels = _register_observation_channels("rej", harness["obs_writer"])
    _admit_observation_journal(
        "rej",
        harness["attempt"],
        channels["manual_channel"],
        channels["manual_producer"],
        channels["manual_principal"],
    )
    opened = mo.ObservationValue.from_dict(_observation_value("open"))
    published = mo.publish_manual_observation(
        channels["obs_channel"],
        harness["commission_ref"],
        opened,
        0,
        "cmd_rej_obs_open",
    )
    assert published.axis == "observation"
    assert published.revision == 1
    assert orv.domain_head(channels["obs_channel"], entity, "observation") == 1
    assert orv.domain_head(channels["obs_channel"], entity, "dispatch") == 0
    assert orv.domain_head(channels["obs_channel"], entity, "execution") == 0


# ---------------------------------------------------------------------------
# 2. Manual actions, pauses, and assistance keep manual provenance
# ---------------------------------------------------------------------------


def test_manual_actions_pauses_and_assistance_keep_manual_provenance():
    harness = _setup_manual_attempt("prov")
    channels = _register_observation_channels("prov", harness["obs_writer"])
    _admit_observation_journal(
        "prov",
        harness["attempt"],
        channels["manual_channel"],
        channels["manual_producer"],
        channels["manual_principal"],
    )
    manual_channel = channels["manual_channel"]
    commission_ref = harness["commission_ref"]

    action = mo.record_manual_event(
        manual_channel,
        commission_ref,
        _manual_submission(
            "manual.action",
            1,
            110.0,
            {
                "actor": "manual",
                "action": "human_click",
                "target": "apply_button",
                "assistance": {
                    "planning_owner": "none",
                    "assistance_track": "no_assistance",
                    "description": "Operator acted without automation.",
                },
            },
        ),
    )
    assert action.provenance == "manual_observer"
    assert action.producer_id == channels["manual_producer"]
    assert action.payload["data"]["actor"] == "manual"
    assert action.payload["data"]["action"] == "human_click"
    assert (
        action.payload["data"]["assistance"]["assistance_track"] == "no_assistance"
    )

    pause = mo.record_manual_event(
        manual_channel,
        commission_ref,
        _manual_submission(
            "manual.pause",
            2,
            130.0,
            {
                "actor": "manual",
                "pause_reason": "operator_review",
                "resumed": True,
            },
        ),
    )
    assert pause.provenance == "manual_observer"
    assert pause.payload["data"]["pause_reason"] == "operator_review"
    assert pause.journal_sequence == action.journal_sequence + 1

    assistance = mo.record_manual_event(
        manual_channel,
        commission_ref,
        _manual_submission(
            "manual.assistance",
            3,
            140.0,
            {
                "actor": "manual",
                "assistance_track": "operator_guided",
                "planner_identity": _missing(),
                "description": "Operator disclosed drafting help.",
            },
        ),
    )
    assert assistance.provenance == "manual_observer"
    assert assistance.payload["data"]["assistance_track"] == "operator_guided"

    # A human submit note is journaled with manual provenance but alone
    # establishes no authoritative application fact.
    note = mo.record_manual_event(
        manual_channel,
        commission_ref,
        _manual_submission(
            "manual.note",
            4,
            150.0,
            {"actor": "manual", "note": "operator clicked submit"},
        ),
    )
    assert note.provenance == "manual_observer"
    assert orv.domain_head(manual_channel, harness["entity"], "application") == 0

    # A non-manual channel cannot record manual events.
    with pytest.raises(mo.ManualObservationError):
        mo.record_manual_event(
            channels["obs_channel"],
            commission_ref,
            _manual_submission(
                "manual.action", 5, 160.0, {"actor": "manual", "action": "spoof"}
            ),
        )

    # A subject-mode commission is not a manual commission.
    subject_commission = _commission(
        commission_id="comm_prov_subject",
        run_id="run_prov_subject",
        journal_id="journal_prov_subject",
        manifest_hash=D0,
        admission_ref=dict(harness["admission_ref"]),
        commissioned_by=harness["principal"],
        attempt=_attempt(
            "attempt_prov_subject",
            "production",
            "employer_origin",
            "target_prov_subject",
            "held_out",
        ),
        candidate_id="candidate_prov_subject",
        job_id="portfolio_prov_subject",
        snapshot_ref=store.retain_artifact(
            harness["channel"],
            "attempt.application",
            "application/json",
            b'{"job":"subject snapshot"}',
            "public",
        ),
        task_ref=store.retain_artifact(
            harness["channel"],
            "attempt.application",
            "application/json",
            b'{"goal":"subject"}',
            "restricted",
        ),
        execution={
            "mode": "subject",
            "subject": {
                "subject_id": "subject_prov_1",
                "subject_version": "v1",
                "revision_basis": "native_revision",
                "native_revision": "rev_1",
                "configured_mode": "mode_apply",
                "interface_surface": "surface_browser",
                "configuration_digest": D0,
                "stack": [],
            },
            "connector_version": "conn_v1",
            "binding_version": "bind_v1",
            "assistance": _assistance(),
        },
        owners={
            "dispatch": {
                "role": "connector",
                "source_id": "src_conn_1",
                "writer_id": "prod_prov_subject_dispatch",
                "owner_domain": "attempt.dispatch",
                "publication_policy": dict(POLICY),
            },
            "observation": {
                "role": "connector",
                "source_id": "src_conn_1",
                "writer_id": "prod_prov_subject_obs",
                "owner_domain": "attempt.observation",
                "publication_policy": dict(POLICY),
            },
            "execution": {
                "role": "subject",
                "source_id": "subject_prov_1",
                "writer_id": "prod_prov_subject_exec",
                "owner_domain": "attempt.execution",
                "publication_policy": dict(POLICY),
            },
            "application": {
                "role": "origin",
                "source_id": "target_prov_subject",
                "writer_id": harness["producer"],
                "owner_domain": "attempt.application",
                "publication_policy": dict(POLICY),
            },
            "report": {
                "role": "reconciler",
                "source_id": "src_reconciler_1",
                "writer_id": "prod_prov_subject_report",
                "owner_domain": "attempt.report",
                "publication_policy": dict(POLICY),
            },
        },
        idempotency_key="idem_prov_subject",
        authorization_refs=[dict(harness["admission_ref"])],
    )
    import json as _json

    import json as _json2

    _ = _json2
    subject_bytes = _json.dumps(subject_commission, sort_keys=True).encode("utf-8")
    # Retain through the observation axis so the manual channel can resolve
    # it for the manual-mode guard without crossing owner domains.
    subject_ref = store.retain_artifact(
        manual_channel,
        "attempt.observation",
        "application/json",
        subject_bytes,
        "public",
    )
    with pytest.raises(mo.ManualObservationError):
        mo.record_manual_event(
            manual_channel,
            subject_ref,
            _manual_submission(
                "manual.action", 6, 170.0, {"actor": "manual", "action": "x"}
            ),
        )


# ---------------------------------------------------------------------------
# 3. Observation closure is immutable when late evidence arrives
# ---------------------------------------------------------------------------


def test_manual_observation_closure_is_immutable_when_late_evidence_arrives():
    harness = _setup_manual_attempt("close")
    channels = _register_observation_channels("close", harness["obs_writer"])
    _admit_observation_journal(
        "close",
        harness["attempt"],
        channels["manual_channel"],
        channels["manual_producer"],
        channels["manual_principal"],
    )
    obs_channel = channels["obs_channel"]
    manual_channel = channels["manual_channel"]
    commission_ref = harness["commission_ref"]
    entity = harness["entity"]

    boundary_ref = dict(harness["admission_ref"])
    rev1 = mo.publish_manual_observation(
        obs_channel,
        commission_ref,
        mo.ObservationValue.from_dict(_observation_value("open")),
        0,
        "cmd_close_open",
    )
    assert rev1.revision == 1
    rev2 = mo.publish_manual_observation(
        obs_channel,
        commission_ref,
        mo.ObservationValue.from_dict(
            _observation_value("draining", boundary_ref=boundary_ref)
        ),
        1,
        "cmd_close_draining",
    )
    assert rev2.revision == 2
    closed_value = _observation_value("closed", boundary_ref=boundary_ref)
    rev3 = mo.publish_manual_observation(
        obs_channel,
        commission_ref,
        mo.ObservationValue.from_dict(closed_value),
        2,
        "cmd_close_closed",
    )
    assert rev3.revision == 3
    assert rev3.value["close_reason"] == "normal_completion"
    original_closed_at = dict(rev3.value["closed_at"])
    original_at_close = dict(rev3.value["at_close"])

    # Late evidence arrives after closure and is journaled at the head.
    late = mo.record_manual_event(
        manual_channel,
        commission_ref,
        _manual_submission(
            "manual.receipt",
            10,
            400.0,
            {"actor": "manual", "receipt": "employer confirmation observed"},
        ),
    )
    assert late.provenance == "manual_observer"
    late_ref = {
        "journal_id": late.journal_id,
        "sequence": late.journal_sequence,
        "event_id": late.event_id,
        "event_hash": late.event_hash,
        "pointer": "",
    }

    # Closed-to-closed appends late evidence while preserving closure.
    appended_value = _observation_value(
        "closed",
        boundary_ref=boundary_ref,
        late_refs=[late_ref],
        measurements=[{"name": "late_evidence_count", "count": 1}],
    )
    # Preserve the exact original closure coordinates.
    appended_value["closed_at"] = dict(original_closed_at)
    appended_value["at_close"] = dict(original_at_close)
    rev4 = mo.publish_manual_observation(
        obs_channel, commission_ref, appended_value, 3, "cmd_close_late"
    )
    assert rev4.revision == 4
    assert rev4.value["closed_at"] == original_closed_at
    assert rev4.value["at_close"] == original_at_close
    assert rev4.value["close_reason"] == "normal_completion"
    assert rev4.value["late_evidence_refs"] == [late_ref]

    # Rewriting closure fields after late evidence is rejected.
    rewritten = _observation_value(
        "closed",
        boundary_ref=boundary_ref,
        late_refs=[late_ref],
    )
    rewritten["closed_at"] = _obs_timepoint(999.0)
    rewritten["at_close"] = dict(original_at_close)
    with pytest.raises(orv.OwnerRevisionError):
        mo.publish_manual_observation(
            obs_channel, commission_ref, rewritten, 4, "cmd_close_rewrite_at"
        )
    rewritten2 = _observation_value(
        "closed",
        boundary_ref=boundary_ref,
        late_refs=[late_ref],
    )
    rewritten2["closed_at"] = dict(original_closed_at)
    tampered_close = dict(original_at_close)
    tampered_close["application_knowledge"] = "committed"
    rewritten2["at_close"] = tampered_close
    with pytest.raises(orv.OwnerRevisionError):
        mo.publish_manual_observation(
            obs_channel, commission_ref, rewritten2, 4, "cmd_close_rewrite_snap"
        )
    assert orv.domain_head(obs_channel, entity, "observation") == 4

    # Every prior seal/publication is preserved; the snapshot may be newer
    # than the close-time report inputs.
    prior = orv.read_revision(obs_channel, entity, "observation", 3)
    assert not isinstance(prior, dict)
    assert prior.value["closed_at"] == original_closed_at
    assert prior.value["at_close"] == original_at_close
    assert prior.value["late_evidence_refs"] == []
    head = orv.read_revision(obs_channel, entity, "observation", 4)
    assert not isinstance(head, dict)
    assert head.value["late_evidence_refs"] == [late_ref]
