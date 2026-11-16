"""Conformance tests for provider_effects (tier 3).

Covers exactly the ``-k`` filter named in the module spec:

- ``provider_effects_persist_authorized_intent_before_external_dispatch``
- ``uncertain_outbound_send_is_not_blindly_retried``

Every check exercises the real module against the real evidence journal,
access-policy ingress, content-addressed artifact store, and strict codec
gate: authenticated owner-local intent commits, immutable payload preservation,
pinned adapter semantics, explicit uncertain delivery, stable command
identity, and duplicate-risk blocking without inferred idempotency.
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
            if name == "provider_effects"
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
pe = _load("provider_effects", Path("src/__init__.py"))

OWNER = "job.downstream"
CHANNEL = "ch_provider_effects_0001"
PRODUCER = "prod_provider_effects"
PRINCIPAL = "principal_provider_effects"
JOURNAL = "journal_provider_effects_0001"
RUN = "run_provider_effects_0001"


@pytest.fixture(autouse=True)
def _fresh_state():
    pe.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    pe.reset_for_tests()


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
        manifest_id="manifest_provider_effects_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_provider_effects",
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
        task_semantic_hash="sha256:" + "a" * 64,
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
                "allowed_event_kinds": list(pe.EVENT_KINDS),
            }
        ],
        clocks=[
            {
                "clock_id": "clock_provider_journal",
                "boot_id": "boot_provider_journal",
                "origin": "engine_measured",
                "source_id": "src_provider_journal",
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
        allowed_event_kinds=tuple(pe.EVENT_KINDS),
    )
    task = _retain({"task": "provider-conformance"})
    config = _retain({"config": "provider-conformance"})
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
                "adapter": "gmail",
                "version": "1",
                "semantics": "send with no native idempotency",
                "endpoint_inventory": "no live send endpoint inferred",
            },
            sort_keys=True,
        ).encode("utf-8"),
        "public",
    )
    pin = pe.VersionPin(
        id="gmail-adapter", version="1", artifact_digest=ref.digest
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


# ---------------------------------------------------------------------------
# Assertion 1: authorized intent is persisted before external dispatch
# ---------------------------------------------------------------------------


def test_provider_effects_persist_authorized_intent_before_external_dispatch():
    admission = _setup()
    adapter_pin, _adapter_ref = _adapter()
    payload_data = {
        "to": "candidate@example.com",
        "subject": "Interview follow-up",
        "body": "Hello, confirming our conversation.",
        "timezone": "UTC",
        "all_day": False,
        "provider_revision": "rev-mail-001",
    }
    payload_ref = _retain(payload_data)
    auth_ref = _auth_ref(admission)

    head_before = _head_seq()
    assert head_before == 1
    known_before = set(store.known_digests())

    command_id = "cmd_provider_intent_0001"
    operation = "gmail.send"
    result = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, command_id, operation, payload_ref, adapter_pin, (auth_ref,)
        )
    )

    # No live endpoint: the dispatch is explicitly uncertain, never a
    # fabricated success.
    assert isinstance(result, pe.Missing)
    assert result.reason == "not_observed"
    assert "uncertain" in (result.detail or "").lower()

    # Durable intent: atomic commit advanced the owner-local entity and the
    # journal carries both the intent and the uncertain-outcome observation.
    head_after = _head_seq()
    assert head_after >= head_before + 2
    events = _events()
    intents = [
        e
        for e in events
        if e.event_kind == "provider_intent_persisted"
        and e.payload["data"].get("command_id") == command_id
    ]
    assert len(intents) == 1
    intent_data = intents[0].payload["data"]
    assert intent_data["operation"] == operation
    assert intent_data["payload_digest"] == payload_ref.digest
    assert intent_data["adapter_id"] == adapter_pin.id
    assert intent_data["adapter_version"] == adapter_pin.version
    assert intent_data["adapter_digest"] == adapter_pin.artifact_digest
    # Calendar/mail payload semantics are preserved by the intent.
    assert intent_data["payload_timezone"] == "UTC"
    assert intent_data["payload_all_day"] is False
    assert intent_data["payload_provider_revision"] == "rev-mail-001"

    outcomes = [
        e
        for e in events
        if e.event_kind == "provider_dispatch_uncertain"
        and e.payload["data"].get("command_id") == command_id
    ]
    assert len(outcomes) == 1
    assert outcomes[0].payload["data"]["delivery"] == "uncertain"

    entity_id = f"provider_effect_{command_id}"
    state = ev.entity_state(CHANNEL, OWNER, entity_id)
    assert state.revision == 1
    assert isinstance(state.state, store.ArtifactReference)
    intent_ref = state.state
    assert intent_ref.owner_domain == OWNER
    intent_doc = json.loads(store.resolve_artifact(CHANNEL, intent_ref))
    assert intent_doc["command_id"] == command_id
    assert intent_doc["operation"] == operation
    assert intent_doc["payload_digest"] == payload_ref.digest

    known_after = set(store.known_digests())
    assert payload_ref.digest in known_after
    assert intent_ref.digest in known_after
    assert len(known_after) > len(known_before)

    # The immutable intended payload is unchanged by the effect.
    assert json.loads(store.resolve_artifact(CHANNEL, payload_ref)) == payload_data
    assert pe.dispatch_attempts_for_tests() == 1

    # Correspondence/calendar work never fabricates an application attempt.
    allowed_kinds = {"manifest_admitted"} | set(pe.EVENT_KINDS)
    for envelope in events:
        assert envelope.event_kind in allowed_kinds

    # Negative cases: rejected calls persist nothing and dispatch nothing.
    head_neg = _head_seq()
    disp_neg = pe.dispatch_attempts_for_tests()

    for forbidden in (
        "application.submit",
        "browser.navigate",
        "https://evil.example/send",
        "exec.run",
        "attempt.dispatch",
    ):
        with pytest.raises(ValueError):
            asyncio.run(
                pe.execute_provider_effect(
                    CHANNEL,
                    "cmd_forbidden_001",
                    forbidden,
                    payload_ref,
                    adapter_pin,
                    (auth_ref,),
                )
            )
        assert _head_seq() == head_neg
        assert pe.dispatch_attempts_for_tests() == disp_neg

    with pytest.raises(PermissionError):
        asyncio.run(
            pe.execute_provider_effect(
                CHANNEL, "cmd_noauth_001", operation, payload_ref, adapter_pin, ()
            )
        )
    assert _head_seq() == head_neg

    with pytest.raises(PermissionError):
        asyncio.run(
            pe.execute_provider_effect(
                "ch_unknown_999",
                "cmd_noauth_002",
                operation,
                payload_ref,
                adapter_pin,
                (auth_ref,),
            )
        )
    assert _head_seq() == head_neg

    bad_pin = pe.VersionPin(
        id="gmail-adapter", version="1", artifact_digest="sha256:" + "b" * 64
    )
    with pytest.raises(ValueError):
        asyncio.run(
            pe.execute_provider_effect(
                CHANNEL, "cmd_badadapter_001", operation, payload_ref, bad_pin,
                (auth_ref,),
            )
        )
    assert _head_seq() == head_neg

    fake_ref = store.ArtifactReference(
        digest="sha256:" + "c" * 64,
        size_bytes=10,
        media_type="application/json",
        owner_domain=OWNER,
        access="restricted",
    )
    with pytest.raises(ValueError):
        asyncio.run(
            pe.execute_provider_effect(
                CHANNEL, "cmd_badpayload_001", operation, fake_ref, adapter_pin,
                (auth_ref,),
            )
        )
    assert _head_seq() == head_neg
    assert pe.dispatch_attempts_for_tests() == disp_neg


# ---------------------------------------------------------------------------
# Assertion 2: uncertain sends are never blindly retried
# ---------------------------------------------------------------------------


def test_uncertain_outbound_send_is_not_blindly_retried():
    admission = _setup()
    adapter_pin, _ = _adapter()
    payload_data = {
        "title": "Interview",
        "timezone": "America/New_York",
        "all_day": False,
        "attendees": ["candidate@example.com"],
        "provider_revision": "rev-cal-001",
    }
    payload_ref = _retain(payload_data)
    auth_ref = _auth_ref(admission)

    command_id = "cmd_provider_uncertain_0001"
    operation = "calendar.create"

    first = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, command_id, operation, payload_ref, adapter_pin, (auth_ref,)
        )
    )
    assert isinstance(first, pe.Missing)
    assert first.reason == "not_observed"
    assert "uncertain" in (first.detail or "").lower()
    head1 = _head_seq()
    assert pe.dispatch_attempts_for_tests() == 1

    # Same command + identical content replays without a new dispatch.
    second = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, command_id, operation, payload_ref, adapter_pin, (auth_ref,)
        )
    )
    assert isinstance(second, pe.Missing)
    assert second.reason == first.reason
    assert second.detail == first.detail
    assert _head_seq() == head1
    assert pe.dispatch_attempts_for_tests() == 1

    # Same command + changed content is a stable-identity conflict.
    with pytest.raises(ValueError):
        asyncio.run(
            pe.execute_provider_effect(
                CHANNEL, command_id, "calendar.update", payload_ref, adapter_pin,
                (auth_ref,),
            )
        )
    other_payload = _retain({"title": "Other", "timezone": "UTC"})
    with pytest.raises(ValueError):
        asyncio.run(
            pe.execute_provider_effect(
                CHANNEL, command_id, operation, other_payload, adapter_pin,
                (auth_ref,),
            )
        )
    assert _head_seq() == head1
    assert pe.dispatch_attempts_for_tests() == 1

    # New command + same payload is duplicate-risk blocked, not resent.
    dup_command = "cmd_provider_uncertain_0002"
    blocked = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, dup_command, operation, payload_ref, adapter_pin, (auth_ref,)
        )
    )
    assert isinstance(blocked, pe.Missing)
    assert blocked.reason == "not_observed"
    assert "duplicate-risk" in (blocked.detail or "").lower()
    assert "review" in (blocked.detail or "").lower()
    assert _head_seq() == head1
    assert pe.dispatch_attempts_for_tests() == 1

    # A staged ack for the duplicate command does not authorize a resend:
    # native idempotency is never inferred.
    dup_command2 = "cmd_provider_uncertain_0003"
    pe.stage_provider_ack_for_tests(
        dup_command2, {"ok": True, "provider_message_id": "msg-123"}
    )
    blocked2 = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, dup_command2, operation, payload_ref, adapter_pin, (auth_ref,)
        )
    )
    assert isinstance(blocked2, pe.Missing)
    assert "duplicate-risk" in (blocked2.detail or "").lower()
    assert _head_seq() == head1
    assert pe.dispatch_attempts_for_tests() == 1

    # A fresh payload with staged provider evidence acknowledges normally.
    fresh_payload = _retain(
        {"to": "other@example.com", "subject": "Hi", "body": "Hello"}
    )
    ack_command = "cmd_provider_ack_0001"
    pe.stage_provider_ack_for_tests(
        ack_command, {"provider_message_id": "msg-ack-001", "accepted": True}
    )
    acked = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, ack_command, "gmail.send", fresh_payload, adapter_pin,
            (auth_ref,),
        )
    )
    assert isinstance(acked, store.ArtifactReference)
    ack_doc = json.loads(store.resolve_artifact(CHANNEL, acked))
    assert ack_doc["command_id"] == ack_command
    assert ack_doc["payload_digest"] == fresh_payload.digest
    head_ack = _head_seq()
    assert head_ack > head1
    assert pe.dispatch_attempts_for_tests() == 2
    ack_events = [
        e
        for e in _events()
        if e.event_kind == "provider_dispatch_acknowledged"
        and e.payload["data"].get("command_id") == ack_command
    ]
    assert len(ack_events) == 1
    assert ack_events[0].payload["data"]["delivery"] == "acknowledged"

    # The acknowledged command replays its retained evidence, never resends.
    acked2 = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, ack_command, "gmail.send", fresh_payload, adapter_pin,
            (auth_ref,),
        )
    )
    assert isinstance(acked2, store.ArtifactReference)
    assert acked2.digest == acked.digest
    assert _head_seq() == head_ack
    assert pe.dispatch_attempts_for_tests() == 2

    # The acknowledged payload is also duplicate-protected under a new command.
    dup_ack = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, "cmd_provider_dup_ack_0002", "gmail.send", fresh_payload,
            adapter_pin, (auth_ref,),
        )
    )
    assert isinstance(dup_ack, pe.Missing)
    assert "duplicate-risk" in (dup_ack.detail or "").lower()
    assert _head_seq() == head_ack

    # Malformed provider output is non-evidence: the dispatch stays uncertain.
    bad_payload = _retain({"to": "bad@example.com", "subject": "Bad"})
    bad_command = "cmd_provider_badack_0001"
    pe.stage_provider_ack_for_tests(bad_command, b"\x00\x01 not json")
    bad_result = asyncio.run(
        pe.execute_provider_effect(
            CHANNEL, bad_command, "gmail.send", bad_payload, adapter_pin,
            (auth_ref,),
        )
    )
    assert isinstance(bad_result, pe.Missing)
    assert bad_result.reason == "not_observed"
    assert "uncertain" in (bad_result.detail or "").lower()
