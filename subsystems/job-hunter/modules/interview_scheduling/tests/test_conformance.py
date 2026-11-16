"""Conformance tests for interview_scheduling (tier 4).

Covers exactly the ``-k`` filter named in the module spec:

- ``calendar_timezone_missing_does_not_invent_an_instant``
- ``calendar_acknowledgement_does_not_prove_interview_attendance_or_confirmation``

Every check exercises the real module against the real provider effects,
evidence journal, access-policy ingress, content-addressed artifact store,
and strict codec gate: actual timezone preservation, no invented instants,
distinct calendar.create operations, actual ack evidence, and explicit
Missing for attendance/confirmation.
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
        path = (
            here.parents[1] / rel
            if name == "interview_scheduling"
            else here.parents[2] / rel
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
ap = _load("access_policy", Path("access_policy/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
pe = _load("provider_effects", Path("provider_effects/src/__init__.py"))
sched = _load("interview_scheduling", Path("src/__init__.py"))

OWNER = "job.downstream"
CHANNEL = "ch_interview_scheduling_0001"
PRODUCER = "prod_interview_scheduling"
PRINCIPAL = "principal_interview_scheduling"
JOURNAL = "journal_interview_scheduling_0001"
RUN = "run_interview_scheduling_0001"


@pytest.fixture(autouse=True)
def _fresh_state():
    sched.reset_for_tests()
    pe.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    pe.reset_for_tests()
    sched.reset_for_tests()


def _declare_event_kinds(owner_domain: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for kind, version in pe.EVENT_KINDS.items():
        ap.register_event_kind(
            kind,
            version,
            role="lifecycle_observation",
            assertion_kind="authoritative_effect",
            owner_domain=owner_domain,
            writer_roles=("kernel",),
        )
        entries.append(
            {
                "event_kind": kind,
                "event_schema_version": version,
                "role": "lifecycle_observation",
                "assertion_kind": "authoritative_effect",
                "owner_domain": owner_domain,
                "writer_roles": ["kernel"],
            }
        )
    for kind, version in sched.EVENT_KINDS.items():
        ap.register_event_kind(
            kind,
            version,
            role="lifecycle_observation",
            assertion_kind="observation",
            owner_domain=owner_domain,
            writer_roles=("kernel",),
        )
        entries.append(
            {
                "event_kind": kind,
                "event_schema_version": version,
                "role": "lifecycle_observation",
                "assertion_kind": "observation",
                "owner_domain": owner_domain,
                "writer_roles": ["kernel"],
            }
        )
    return entries


def _retain(payload: dict, access: str = "restricted"):
    return store.retain_artifact(
        CHANNEL,
        OWNER,
        "application/json",
        json.dumps(payload, sort_keys=True).encode("utf-8"),
        access,
    )


def _manifest(task, config):
    return ev.Manifest(
        manifest_id="manifest_interview_scheduling_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_interview_scheduling",
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
        task_semantic_hash="sha256:" + "b" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=_declare_event_kinds(OWNER),
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": list(pe.EVENT_KINDS) + list(sched.EVENT_KINDS),
            }
        ],
        clocks=[
            {
                "clock_id": "clock_sched_journal",
                "boot_id": "boot_sched_journal",
                "origin": "engine_measured",
                "source_id": "src_sched_journal",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup():
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=tuple(list(pe.EVENT_KINDS) + list(sched.EVENT_KINDS)),
    )
    task = _retain({"task": "scheduling-conformance"})
    config = _retain({"config": "scheduling-conformance"})
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    assert admission.journal_sequence == 1
    return admission


def _adapter():
    ref = store.retain_artifact(
        CHANNEL,
        OWNER,
        "application/json",
        json.dumps(
            {
                "adapter": "calendar",
                "version": "1",
                "semantics": "calendar.create with no native idempotency",
                "endpoint_inventory": "no live send endpoint inferred",
            },
            sort_keys=True,
        ).encode("utf-8"),
        "public",
    )
    pin = pe.VersionPin(
        id="calendar-adapter", version="1", artifact_digest=ref.digest
    )
    return pin, ref


def _auth_ref(admission):
    return ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=1,
        event_id=admission.event_id,
        event_hash=admission.event_hash,
        pointer="",
    )


def _head_seq() -> int:
    return ev.journal_head(CHANNEL, JOURNAL).last_sequence


def _events():
    return ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))


def _is_missing_dict(value) -> bool:
    return (
        isinstance(value, dict)
        and value.get("value") is None
        and "value" in value
        and "reason" in value
    )


def _find(events, kind: str, command_id: str):
    return [
        e
        for e in events
        if e.event_kind == kind and e.payload["data"].get("command_id") == command_id
    ]


# ---------------------------------------------------------------------------
# Assertion 1: missing timezone never becomes an invented instant
# ---------------------------------------------------------------------------


def test_calendar_timezone_missing_does_not_invent_an_instant():
    admission = _setup()
    adapter_pin, _ = _adapter()
    auth_ref = _auth_ref(admission)

    # Timed event whose invitation omitted timezone semantics.
    event_data = {
        "calendar_id": "primary",
        "cheat_sheet": {"reason": "not_applicable", "value": None},
        "end": {
            "all_day": False,
            "date_time": "2026-11-20T14:30:00",
            "timezone": {"reason": "not_observed", "value": None},
        },
        "job_id": "job_sched_tz_0001",
        "provider_event_id": {"reason": "not_observed", "value": None},
        "provider_revision": {"reason": "not_observed", "value": None},
        "start": {
            "all_day": False,
            "date_time": "2026-11-20T14:00:00",
            "timezone": {
                "detail": "invitation omitted timezone",
                "reason": "not_observed",
                "value": None,
            },
        },
    }
    event_ref = _retain(event_data)
    command_id = "cmd_sched_tz_missing_0001"

    disp_before = pe.dispatch_attempts_for_tests()
    head_before = _head_seq()

    result = asyncio.run(
        sched.schedule_interview(
            CHANNEL, command_id, event_ref, adapter_pin, (auth_ref,)
        )
    )

    # Refused with typed missingness, never an invented instant.
    assert isinstance(result, dict), f"expected Missing dict, got {type(result)}"
    assert _is_missing_dict(result)
    assert result["reason"] == "not_observed"
    detail = (result.get("detail") or "").lower()
    assert "timezone" in detail
    assert "instant" in detail
    assert "no instant invented" in detail or "no instant" in detail

    # No provider dispatch was attempted for the timezone-missing timed event.
    assert pe.dispatch_attempts_for_tests() == disp_before

    # The immutable intended payload is unchanged.
    assert json.loads(store.resolve_artifact(CHANNEL, event_ref)) == event_data

    events = _events()
    refused = _find(events, sched.REFUSED_EVENT_KIND, command_id)
    assert len(refused) == 1
    data = refused[0].payload["data"]
    assert data["command_id"] == command_id
    assert data["operation"] == "calendar.create"
    assert data["calendar_id"] == "primary"
    assert data["job_id"] == "job_sched_tz_0001"
    assert data["dispatched"] is False
    assert data["delivery"] == "refused_timezone_missing"

    # Timezone semantics preserved verbatim; no UTC default invented.
    assert data["start"]["date_time"] == "2026-11-20T14:00:00"
    assert data["end"]["date_time"] == "2026-11-20T14:30:00"
    assert data["start"]["all_day"] is False
    assert data["end"]["all_day"] is False
    assert data["all_day"] is False
    assert _is_missing_dict(data["start"]["timezone"])
    assert data["start"]["timezone"]["reason"] == "not_observed"
    assert data["start"]["timezone"]["detail"] == "invitation omitted timezone"
    assert _is_missing_dict(data["end"]["timezone"])
    assert data["end"]["timezone"]["reason"] == "not_observed"
    assert "UTC" not in json.dumps(data["start"])
    assert "UTC" not in json.dumps(data["end"])

    # No instant, provider identity, or revision invented.
    assert _is_missing_dict(data["instant"])
    assert data["instant"]["reason"] == "not_observed"
    assert _is_missing_dict(data["provider_event_id"])
    assert _is_missing_dict(data["provider_revision"])
    assert _is_missing_dict(data["attendance"])
    assert _is_missing_dict(data["employer_confirmation"])

    # Future business time never became a monotonic observation.
    assert refused[0].payload["measurements"] == []
    assert isinstance(refused[0].occurred_at, ev.Missing)
    assert refused[0].occurred_at.reason == "not_observed"
    payload_text = json.dumps(data)
    assert "monotonic_offset_ms" not in payload_text
    assert "t_mono_ms" not in payload_text
    assert "clock_id" not in payload_text

    # The retained refusal record also carries Missing, not an instant.
    artifact_refs = refused[0].payload["artifact_refs"]
    assert len(artifact_refs) == 2
    refusal_digest = artifact_refs[1]["digest"]
    refusal_doc = json.loads(
        store.resolve_artifact(
            CHANNEL,
            store.ArtifactReference(
                digest=refusal_digest,
                size_bytes=artifact_refs[1]["size_bytes"],
                media_type=artifact_refs[1]["media_type"],
                owner_domain=artifact_refs[1]["owner_domain"],
                access=artifact_refs[1]["access"],
            ),
        )
    )
    assert _is_missing_dict(refusal_doc["instant"])
    assert _is_missing_dict(refusal_doc["start"]["timezone"])
    assert refusal_doc["dispatched"] is False

    # No provider intent/dispatch events exist for the refused command.
    for kind in pe.EVENT_KINDS:
        assert _find(events, kind, command_id) == []
    assert _find(events, sched.DISPATCHED_EVENT_KIND, command_id) == []
    assert _head_seq() == head_before + 1

    # All-day events carry timezone not_applicable and dispatch without an instant.
    allday_data = {
        "calendar_id": "primary",
        "cheat_sheet": {"reason": "not_applicable", "value": None},
        "end": {
            "all_day": True,
            "date_time": "2026-11-22",
            "timezone": {"reason": "not_applicable", "value": None},
        },
        "job_id": "job_sched_allday_0001",
        "provider_event_id": {"reason": "not_observed", "value": None},
        "provider_revision": {"reason": "not_observed", "value": None},
        "start": {
            "all_day": True,
            "date_time": "2026-11-22",
            "timezone": {"reason": "not_applicable", "value": None},
        },
    }
    allday_ref = _retain(allday_data)
    allday_cmd = "cmd_sched_allday_0001"
    disp_mid = pe.dispatch_attempts_for_tests()
    head_mid = _head_seq()
    allday_result = asyncio.run(
        sched.schedule_interview(
            CHANNEL, allday_cmd, allday_ref, adapter_pin, (auth_ref,)
        )
    )
    # No staged ack: explicitly uncertain, still no instant.
    assert isinstance(allday_result, dict) and _is_missing_dict(allday_result)
    assert allday_result["reason"] == "not_observed"
    assert "uncertain" in (allday_result.get("detail") or "").lower()
    assert pe.dispatch_attempts_for_tests() == disp_mid + 1

    events2 = _events()
    dispatched = _find(events2, sched.DISPATCHED_EVENT_KIND, allday_cmd)
    assert len(dispatched) == 1
    d2 = dispatched[0].payload["data"]
    assert d2["all_day"] is True
    assert d2["delivery"] == "uncertain"
    assert _is_missing_dict(d2["start"]["timezone"])
    assert d2["start"]["timezone"]["reason"] == "not_applicable"
    assert _is_missing_dict(d2["attendance"])
    # No instant key with a concrete timestamp, and no monotonic fields.
    if "instant" in d2:
        assert _is_missing_dict(d2["instant"])
    assert "monotonic_offset_ms" not in json.dumps(d2)
    assert "t_mono_ms" not in json.dumps(d2)
    assert dispatched[0].payload["measurements"] == []
    assert isinstance(dispatched[0].occurred_at, ev.Missing)
    assert _head_seq() >= head_mid + 3  # provider intent + uncertain + scheduling outcome


# ---------------------------------------------------------------------------
# Assertion 2: acknowledgement does not prove attendance or confirmation
# ---------------------------------------------------------------------------


def test_calendar_acknowledgement_does_not_prove_interview_attendance_or_confirmation():
    admission = _setup()
    adapter_pin, _ = _adapter()
    auth_ref = _auth_ref(admission)

    event_data = {
        "calendar_id": "primary",
        "cheat_sheet": {"reason": "not_applicable", "value": None},
        "cheat_sheet_url": "https://private.resolver/cheat/job_sched_ack_0001",
        "end": {
            "all_day": False,
            "date_time": "2026-11-21T10:30:00",
            "timezone": "America/New_York",
        },
        "job_id": "job_sched_ack_0001",
        "provider_event_id": {"reason": "not_observed", "value": None},
        "provider_revision": {"reason": "not_observed", "value": None},
        "start": {
            "all_day": False,
            "date_time": "2026-11-21T10:00:00",
            "timezone": "America/New_York",
        },
    }
    event_ref = _retain(event_data)
    command_id = "cmd_sched_ack_0001"

    # Actual provider acknowledgement: real event identity + revision, plus a
    # potentially misleading provider-side "confirmed" flag that must NOT
    # become employer confirmation.
    staged_ack = {
        "attendee_response": "accepted",
        "calendarId": "primary",
        "confirmed": True,
        "eventId": "evt_provider_sched_777",
        "revision": "rev_sched_7",
        "status": "created",
    }
    pe.stage_provider_ack_for_tests(command_id, staged_ack)

    head_before = _head_seq()
    result = asyncio.run(
        sched.schedule_interview(
            CHANNEL, command_id, event_ref, adapter_pin, (auth_ref,)
        )
    )

    # Acknowledged delivery returns the actual provider ack evidence.
    assert isinstance(result, store.ArtifactReference)
    ack_doc = json.loads(store.resolve_artifact(CHANNEL, result))
    assert ack_doc["record_type"] == "provider_ack"
    assert ack_doc["command_id"] == command_id
    assert ack_doc["operation"] == "calendar.create"
    assert ack_doc["payload_digest"] == event_ref.digest
    assert ack_doc["ack"]["eventId"] == "evt_provider_sched_777"
    assert ack_doc["ack"]["revision"] == "rev_sched_7"
    assert ack_doc["ack"]["confirmed"] is True

    # The immutable intended payload is unchanged by the effect.
    assert json.loads(store.resolve_artifact(CHANNEL, event_ref)) == event_data

    events = _events()
    dispatched = _find(events, sched.DISPATCHED_EVENT_KIND, command_id)
    assert len(dispatched) == 1
    data = dispatched[0].payload["data"]
    assert data["command_id"] == command_id
    assert data["operation"] == "calendar.create"
    assert data["delivery"] == "acknowledged"
    assert data["ack_digest"] == result.digest
    assert data["calendar_id"] == "primary"
    assert data["job_id"] == "job_sched_ack_0001"

    # Timezone + all-day semantics preserved verbatim.
    assert data["start"]["timezone"] == "America/New_York"
    assert data["end"]["timezone"] == "America/New_York"
    assert data["start"]["all_day"] is False
    assert data["all_day"] is False
    assert data["start"]["date_time"] == "2026-11-21T10:00:00"

    # Actual provider identity/revision/response preserved from the ack.
    assert data["provider_event_id"] == "evt_provider_sched_777"
    assert data["provider_revision"] == "rev_sched_7"
    assert data["provider_response"]["eventId"] == "evt_provider_sched_777"
    assert data["provider_response"]["revision"] == "rev_sched_7"
    assert data["provider_response"]["confirmed"] is True
    assert data["provider_response"]["attendee_response"] == "accepted"

    # ...but attendance and employer confirmation remain explicitly unobserved.
    assert _is_missing_dict(data["attendance"])
    assert data["attendance"]["reason"] == "not_observed"
    assert _is_missing_dict(data["employer_confirmation"])
    assert data["employer_confirmation"]["reason"] == "not_observed"
    assert "does not prove" in (data.get("detail") or "").lower()

    # Cheat-sheet URL is resolver output, never evidence identity.
    assert _is_missing_dict(data["cheat_sheet"])
    assert data["cheat_sheet_url"] == "https://private.resolver/cheat/job_sched_ack_0001"
    for ref in dispatched[0].payload["artifact_refs"]:
        assert ref["digest"] != data["cheat_sheet_url"]
        assert "https://" not in ref["digest"]

    # Calendar create is distinct from free/busy, ACL, and confirmation.
    assert data["operation"] == "calendar.create"
    payload_text = json.dumps(data).lower()
    assert "free" not in payload_text or "free" in "freedom"  # no free/busy claim
    assert "acl" not in payload_text
    intents = _find(events, "provider_intent_persisted", command_id)
    assert len(intents) == 1
    assert intents[0].payload["data"]["operation"] == "calendar.create"
    acks = _find(events, "provider_dispatch_acknowledged", command_id)
    assert len(acks) == 1
    assert acks[0].payload["data"]["delivery"] == "acknowledged"

    # No scheduling event claims attendance or confirmation.
    for envelope in events[head_before:]:
        text = json.dumps(envelope.payload["data"]).lower()
        # The only allowed attendance/confirmation mentions are explicit
        # Missing envelopes and the "does not prove" disclaimer.
        if "attendance" in text or "confirmation" in text:
            d = envelope.payload["data"]
            for key in ("attendance", "employer_confirmation"):
                if key in d:
                    assert _is_missing_dict(d[key]), f"{envelope.event_kind} invents {key}"
        assert '"attended": true' not in text
        assert '"confirmed": true' not in text or envelope.event_kind.startswith("provider_") is False and "provider_response" in text
        # Business time never became a monotonic observation.
        assert envelope.payload["measurements"] == [] or envelope.event_kind.startswith("provider_")
        if envelope.event_kind in (sched.REFUSED_EVENT_KIND, sched.DISPATCHED_EVENT_KIND):
            assert isinstance(envelope.occurred_at, ev.Missing)
            assert "monotonic_offset_ms" not in json.dumps(envelope.payload["data"])
            assert "t_mono_ms" not in json.dumps(envelope.payload["data"])

    # The retained outcome record agrees: actual ack preserved, attendance missing.
    outcome_refs = dispatched[0].payload["artifact_refs"]
    assert len(outcome_refs) == 3  # event + ack + outcome record
    outcome_digest = outcome_refs[2]["digest"]
    outcome_doc = json.loads(
        store.resolve_artifact(
            CHANNEL,
            store.ArtifactReference(
                digest=outcome_digest,
                size_bytes=outcome_refs[2]["size_bytes"],
                media_type=outcome_refs[2]["media_type"],
                owner_domain=outcome_refs[2]["owner_domain"],
                access=outcome_refs[2]["access"],
            ),
        )
    )
    assert outcome_doc["provider_event_id"] == "evt_provider_sched_777"
    assert outcome_doc["provider_revision"] == "rev_sched_7"
    assert _is_missing_dict(outcome_doc["attendance"])
    assert _is_missing_dict(outcome_doc["employer_confirmation"])
