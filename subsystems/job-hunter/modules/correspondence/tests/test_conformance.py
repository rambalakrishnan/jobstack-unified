"""Conformance tests for correspondence (tier 5)."""
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
            if name == "correspondence"
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
mg = _load("model_gateway", Path("model_gateway/src/__init__.py"))
corr = _load("correspondence", Path("src/__init__.py"))

OWNER = "job.downstream"
CHANNEL = "ch_correspondence_0001"
PRODUCER = "prod_correspondence"
PRINCIPAL = "principal_correspondence"
JOURNAL = "journal_correspondence_0001"
RUN = "run_correspondence_0001"


@pytest.fixture(autouse=True)
def _fresh_state():
    corr.reset_for_tests()
    mg.reset_for_tests()
    pe.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    pe.reset_for_tests()
    mg.reset_for_tests()
    corr.reset_for_tests()


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
    for kind, version in corr.EVENT_KINDS.items():
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
        manifest_id="manifest_correspondence_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_correspondence",
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
                "allowed_event_kinds": list(pe.EVENT_KINDS) + list(corr.EVENT_KINDS),
            }
        ],
        clocks=[
            {
                "clock_id": "clock_corr_journal",
                "boot_id": "boot_corr_journal",
                "origin": "engine_measured",
                "source_id": "src_corr_journal",
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
        allowed_event_kinds=tuple(list(pe.EVENT_KINDS) + list(corr.EVENT_KINDS)),
    )
    task = _retain({"task": "correspondence-conformance"})
    config = _retain({"config": "correspondence-conformance"})
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
                "semantics": (
                    "Users.messages/history/watch are adapter surfaces, not "
                    "receipt guarantees; notifications trigger retrieval"
                ),
                "endpoint_inventory": "no live send endpoint inferred",
            },
            sort_keys=True,
        ).encode("utf-8"),
        "public",
    )
    pin = corr.VersionPin(
        id="gmail-adapter", version="1", artifact_digest=ref.digest
    )
    return pin, ref


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


# ---------------------------------------------------------------------------
# Assertion 1: company/title similarity never creates an attempt fact
# ---------------------------------------------------------------------------


def test_email_company_title_only_match_creates_no_automatic_attempt_fact():
    _setup()
    adapter_pin, _ = _adapter()
    raw = (
        b"From: hiring@acme.example\r\n"
        b"To: candidate@example\r\n"
        b"Subject: Interview invitation - Backend Engineer at Acme Corp\r\n"
        b"\r\n"
        b"We invite you to interview for Backend Engineer at Acme Corp."
    )
    corr.stage_mailbox_for_tests(
        OWNER,
        "mailbox_company_title_001",
        messages=[
            {
                "provider_id": "gmail",
                "message_id": "msg_acme_001",
                "thread_id": "thread_acme_001",
                "raw_bytes": raw,
                "category": "interview_invite",
                "company_match": "Acme Corp",
                "title_match": "Backend Engineer",
                "action_required": True,
            }
        ],
        history_complete=True,
        classification_version="classifier/3",
    )
    head_before = _head_seq()

    report_ref = asyncio.run(
        corr.synchronize_mail(CHANNEL, "mailbox_company_title_001", adapter_pin)
    )

    assert isinstance(report_ref, store.ArtifactReference)
    report = json.loads(store.resolve_artifact(CHANNEL, report_ref))
    assert report["record_type"] == "mail_sync_report"
    assert report["mailbox_id"] == "mailbox_company_title_001"
    assert report["classification_version"] == "classifier/3"
    assert report["observed_count"] == 1
    assert report["attempt_facts_created"] == 0
    assert _is_missing_dict(report["attempt_fact"])
    assert "similarity" in (report["attempt_fact"].get("detail") or "").lower()
    assert len(report["messages"]) == 1
    entry = report["messages"][0]
    assert entry["provider_id"] == "gmail"
    assert entry["message_id"] == "msg_acme_001"
    assert entry["company_match"] == "Acme Corp"
    assert entry["title_match"] == "Backend Engineer"
    assert entry["category"] == "interview_invite"
    assert entry["action_required"] is True
    assert _is_missing_dict(entry["attempt_binding"])
    assert "company/title" in (entry["attempt_binding"].get("detail") or "").lower()
    assert report["history_completeness"] == "complete"

    # Retained message bytes are exact and content-addressed.
    msg_ref = store.ArtifactReference(
        digest=entry["digest"],
        size_bytes=entry["size_bytes"],
        media_type="message/rfc822",
        owner_domain=OWNER,
        access="restricted",
    )
    assert store.resolve_artifact(CHANNEL, msg_ref) == raw

    events = _events()[head_before:]
    assert events, "expected new journal events from mail sync"
    for envelope in events:
        assert "attempt" not in envelope.event_kind
        assert envelope.owner_domain == OWNER
        assert envelope.owner_domain not in ("attempt.application", "attempt.report")
        data = envelope.payload["data"]
        if "attempt_facts_created" in data:
            assert data["attempt_facts_created"] == 0
        for key in ("attempt_fact", "attempt_binding"):
            if key in data:
                assert _is_missing_dict(data[key]), f"{key} must stay missing"
        assert "attempt_id" not in data

    observed = [
        e
        for e in events
        if e.event_kind == corr.MESSAGE_OBSERVED_EVENT_KIND
        and e.payload["data"].get("message_id") == "msg_acme_001"
    ]
    assert len(observed) == 1
    odata = observed[0].payload["data"]
    assert odata["company_match"] == "Acme Corp"
    assert odata["title_match"] == "Backend Engineer"
    assert odata["category"] == "interview_invite"
    assert odata["classification_version"] == "classifier/3"
    assert _is_missing_dict(odata["attempt_binding"])
    assert _is_missing_dict(odata["attempt_fact"])

    syncs = [e for e in events if e.event_kind == corr.SYNC_COMPLETED_EVENT_KIND]
    assert len(syncs) == 1
    assert syncs[0].payload["data"]["attempt_facts_created"] == 0
    assert _is_missing_dict(syncs[0].payload["data"]["attempt_fact"])


# ---------------------------------------------------------------------------
# Assertion 2: history gaps are explicit incomplete observations
# ---------------------------------------------------------------------------


def test_mail_history_gap_is_recorded_as_incomplete_observation():
    _setup()
    adapter_pin, _ = _adapter()
    gap_detail = (
        "historyId 98765 expired; Users.history returned 404; "
        "resynchronization required"
    )
    corr.stage_mailbox_for_tests(
        OWNER,
        "mailbox_gap_001",
        messages=[
            {
                "provider_id": "gmail",
                "message_id": "msg_gap_001",
                "thread_id": "thread_gap_001",
                "raw_bytes": b"From: a@example\r\nSubject: gap window\r\n\r\nbody",
                "category": "ambiguous",
                "company_match": "Acme Corp",
                "title_match": "Backend Engineer",
                "action_required": False,
            }
        ],
        history_complete=False,
        history_gap_detail=gap_detail,
        classification_version="classifier/3",
    )
    head_before = _head_seq()

    report_ref = asyncio.run(
        corr.synchronize_mail(CHANNEL, "mailbox_gap_001", adapter_pin)
    )

    report = json.loads(store.resolve_artifact(CHANNEL, report_ref))
    assert _is_missing_dict(report["history_completeness"])
    assert report["history_completeness"]["reason"] == "not_observed"
    detail = (report["history_completeness"].get("detail") or "").lower()
    assert "resynchronization" in detail
    assert "98765" in (report["history_completeness"].get("detail") or "")
    assert report["history_gap"]["status"] == "gap"
    assert gap_detail in report["history_gap"]["detail"]
    assert report["history_completeness"] != "complete"
    assert "complete" not in json.dumps(report["history_completeness"])

    events = _events()[head_before:]
    gaps = [e for e in events if e.event_kind == corr.HISTORY_GAP_EVENT_KIND]
    assert len(gaps) == 1
    gdata = gaps[0].payload["data"]
    assert _is_missing_dict(gdata["history_completeness"])
    assert gdata["resynchronization_required"] is True
    assert gap_detail in gdata["history_gap"]["detail"]
    assert gap_detail in gdata["history_completeness"]["detail"]

    syncs = [e for e in events if e.event_kind == corr.SYNC_COMPLETED_EVENT_KIND]
    assert len(syncs) == 1
    sdata = syncs[0].payload["data"]
    assert _is_missing_dict(sdata["history_completeness"])
    assert sdata["history_completeness"] != "complete"

    # No event may claim complete history while the gap is unresolved.
    for envelope in events:
        data = envelope.payload["data"]
        if "history_completeness" in data:
            assert data["history_completeness"] != "complete"


# ---------------------------------------------------------------------------
# Assertion 3: duplicate notifications do not duplicate message evidence
# ---------------------------------------------------------------------------


def test_duplicate_mail_notifications_do_not_duplicate_message_evidence():
    _setup()
    adapter_pin, _ = _adapter()
    raw = (
        b"From: hiring@example\r\n"
        b"To: candidate@example\r\n"
        b"Subject: duplicate notification test\r\n"
        b"\r\n"
        b"Same bytes delivered twice."
    )
    corr.stage_mailbox_for_tests(
        OWNER,
        "mailbox_dup_001",
        messages=[
            {
                "provider_id": "gmail",
                "message_id": "msg_dup_001",
                "thread_id": "thread_dup_001",
                "raw_bytes": raw,
                "category": "acknowledgement",
                "company_match": "Acme Corp",
                "title_match": "Backend Engineer",
                "action_required": False,
            }
        ],
        history_complete=True,
        classification_version="classifier/3",
    )
    corr.stage_mail_notification_for_tests(
        OWNER, "mailbox_dup_001", {"provider_id": "gmail", "message_id": "msg_dup_001"}
    )
    corr.stage_mail_notification_for_tests(
        OWNER, "mailbox_dup_001", {"provider_id": "gmail", "message_id": "msg_dup_001"}
    )
    head_before = _head_seq()

    report1_ref = asyncio.run(
        corr.synchronize_mail(CHANNEL, "mailbox_dup_001", adapter_pin)
    )
    report1 = json.loads(store.resolve_artifact(CHANNEL, report1_ref))
    assert report1["observed_count"] == 1
    assert report1["deduplicated_count"] >= 1
    assert report1["total_candidates"] == 3
    assert len(report1["messages"]) == 1
    digest_first = report1["messages"][0]["digest"]

    after_first = _events()[head_before:]
    observed_first = [
        e
        for e in after_first
        if e.event_kind == corr.MESSAGE_OBSERVED_EVENT_KIND
        and e.payload["data"].get("message_id") == "msg_dup_001"
    ]
    assert len(observed_first) == 1

    head_mid = _head_seq()

    # A duplicate notification triggering a second retrieval must not create
    # a second message observation.
    report2_ref = asyncio.run(
        corr.synchronize_mail(CHANNEL, "mailbox_dup_001", adapter_pin)
    )
    report2 = json.loads(store.resolve_artifact(CHANNEL, report2_ref))
    assert report2["observed_count"] == 0
    assert report2["deduplicated_count"] >= 1
    assert report2["total_candidates"] == 1
    assert report2["messages"] == []

    after_second = _events()[head_mid:]
    observed_second = [
        e for e in after_second if e.event_kind == corr.MESSAGE_OBSERVED_EVENT_KIND
    ]
    assert observed_second == []

    total_observed = [
        e
        for e in _events()
        if e.event_kind == corr.MESSAGE_OBSERVED_EVENT_KIND
        and e.payload["data"].get("message_id") == "msg_dup_001"
    ]
    assert len(total_observed) == 1

    assert digest_first in store.known_digests()
    assert (
        store.resolve_artifact(
            CHANNEL,
            store.ArtifactReference(
                digest=digest_first,
                size_bytes=report1["messages"][0]["size_bytes"],
                media_type="message/rfc822",
                owner_domain=OWNER,
                access="restricted",
            ),
        )
        == raw
    )

    syncs = [
        e
        for e in _events()[head_before:]
        if e.event_kind == corr.SYNC_COMPLETED_EVENT_KIND
    ]
    assert len(syncs) == 2
