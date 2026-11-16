"""Conformance tests for evidence_journal (tier 2).

Covers exactly the ``-k`` filter named in the module spec:

- ``invalid_evidence_pointer_or_hash_is_rejected``
- ``same_producer_sequence_same_content_is_deduplicated``
- ``same_producer_sequence_different_content_records_integrity_incident``
- ``owner_effect_journal_and_idempotency_receipt_commit_before_acknowledgement``

Every check exercises the real module: authenticated admission, hash-chained
append, producer-sequence deduplication and conflict retention, JSON-Pointer
citation verification, and the owner-local atomic commit of state, revision,
journal events, and the replayable idempotency receipt.
"""

from __future__ import annotations

import dataclasses
import importlib.util
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
        path = here.parents[1] / rel if name == "evidence_journal" else here.parents[2] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ap = _load("access_policy", Path("access_policy/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("src/__init__.py"))


CHANNEL = "ch_journal_product_0001"
PRODUCER = "prod_journal_product"
OWNER = "job.downstream"
JOURNAL = "journal_conformance_0001"
RUN = "run_conformance_0001"
KIND = "product.published"
KIND_VERSION = "1"
CLOCK_ID = "clock_journal_engine"
BOOT_ID = "boot_journal_engine"


@pytest.fixture(autouse=True)
def _fresh_state():
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()


def _register_writer(sequence_required: bool = True):
    return ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id="principal_journal_product",
        sequence_required=sequence_required,
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


def _retain(name: str) -> store.ArtifactReference:
    return store.retain_artifact(
        CHANNEL,
        OWNER,
        "application/json",
        ('{"fixture":"%s"}' % name).encode("utf-8"),
        "restricted",
    )


def _manifest(task: store.ArtifactReference, config: store.ArtifactReference) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_conformance_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_conformance",
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
                "principal_id": "principal_journal_product",
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
                "source_id": "src_journal_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup(sequence_required: bool = True):
    _register_writer(sequence_required=sequence_required)
    _register_event_kind()
    task = _retain("task")
    config = _retain("config")
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    return admission, task, config


def _submission(
    producer_sequence,
    note: str,
    *,
    evidence_refs=(),
    artifact_refs=(),
    occurred_offset_ms: float = 1000.0,
) -> ev.EventSubmission:
    return ev.EventSubmission(
        producer_sequence=producer_sequence,
        event_kind=KIND,
        event_schema_version=KIND_VERSION,
        occurred_at=ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=occurred_offset_ms,
        ),
        payload=ev.EvidencePayload(
            data={"note": note},
            measurements=[],
            evidence_refs=list(evidence_refs),
            artifact_refs=list(artifact_refs),
        ),
    )


# ---------------------------------------------------------------------------
# Assertion 1: invalid evidence pointer or hash is rejected
# ---------------------------------------------------------------------------


def test_invalid_evidence_pointer_or_hash_is_rejected():
    admission, _task, _config = _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "first"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    assert head.last_sequence == 2
    assert head.head_hash == first.event_hash
    assert admission.journal_sequence == 1

    good = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=first.journal_sequence,
        event_id=first.event_id,
        event_hash=first.event_hash,
        pointer="/payload/data/note",
    )
    # The same resolver path that rejects bad citations resolves good ones.
    assert first.payload["data"]["note"] == "first"

    bad_citations = [
        dataclasses.replace(good, event_hash="sha256:" + "0" * 64),
        dataclasses.replace(good, pointer="/payload/data/missing"),
        dataclasses.replace(good, pointer="/payload/data/note/nested"),
        dataclasses.replace(good, pointer="/payload/measurements/3"),
        dataclasses.replace(good, event_id="evt_not_the_event"),
        dataclasses.replace(good, sequence=1),
    ]
    for index, ref in enumerate(bad_citations):
        with pytest.raises(ev.InvalidEvidenceRefError):
            ev.append_event(
                CHANNEL, OWNER, _submission(2, f"bad-{index}", evidence_refs=[ref])
            )
        # A rejected citation appends nothing.
        assert ev.journal_head(CHANNEL, JOURNAL) == head

    # Malformed pointers never even construct a citation.
    for pointer in ("payload/data", "/payload/data/~2", "/payload/~3/data"):
        with pytest.raises(ValueError):
            ev.EvidenceRef(
                journal_id=JOURNAL,
                sequence=first.journal_sequence,
                event_id=first.event_id,
                event_hash=first.event_hash,
                pointer=pointer,
            )

    # A forged prefix head hash is rejected, as is a head beyond the tail.
    with pytest.raises(ev.JournalIntegrityError):
        ev.read_prefix(
            CHANNEL,
            ev.JournalPrefix(JOURNAL, head.last_sequence, "sha256:" + "0" * 64),
        )
    with pytest.raises(ev.JournalIntegrityError):
        ev.read_prefix(
            CHANNEL,
            ev.JournalPrefix(
                JOURNAL, head.last_sequence + 1, head.head_hash
            ),
        )

    # Stored-content tampering is detected by recomputing the event hash.
    journal = ev._JOURNALS[JOURNAL]
    tampered_payload = dataclasses.replace(
        journal.events[1],
        payload_json=journal.events[1].payload_json.replace("first", "tampered"),
    )
    ev._JOURNALS[JOURNAL] = dataclasses.replace(
        journal, events=(journal.events[0], tampered_payload)
    )
    with pytest.raises(ev.JournalIntegrityError):
        ev.read_prefix(CHANNEL, head)

    tampered_id = dataclasses.replace(journal.events[1], event_id="evt_forged")
    ev._JOURNALS[JOURNAL] = dataclasses.replace(
        journal, events=(journal.events[0], tampered_id)
    )
    with pytest.raises(ev.JournalIntegrityError):
        ev.read_prefix(CHANNEL, head)

    tampered_sequence = dataclasses.replace(journal.events[1], journal_sequence=7)
    ev._JOURNALS[JOURNAL] = dataclasses.replace(
        journal, events=(journal.events[0], tampered_sequence)
    )
    with pytest.raises(ev.JournalIntegrityError):
        ev.read_prefix(CHANNEL, head)

    # Restore the authentic record; the journal is intact.
    ev._JOURNALS[JOURNAL] = journal
    assert ev.read_prefix(CHANNEL, head)[-1].to_dict() == first.to_dict()

    # Rejected citations consumed no producer sequence: sequence 2 still works.
    second = ev.append_event(CHANNEL, OWNER, _submission(2, "second", evidence_refs=[good]))
    assert second.journal_sequence == 3
    events = ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))
    assert [event.journal_sequence for event in events] == [1, 2, 3]
    assert events[-1].payload["evidence_refs"][0]["event_hash"] == first.event_hash


# ---------------------------------------------------------------------------
# Assertion 2: identical producer sequence + content deduplicates
# ---------------------------------------------------------------------------


def test_same_producer_sequence_same_content_is_deduplicated():
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "same"))
    head_before = ev.journal_head(CHANNEL, JOURNAL)

    retry = ev.append_event(CHANNEL, OWNER, _submission(1, "same"))

    assert retry.event_id == first.event_id
    assert retry.journal_sequence == first.journal_sequence
    assert retry.event_hash == first.event_hash
    assert retry.to_dict() == first.to_dict()
    assert ev.journal_head(CHANNEL, JOURNAL) == head_before
    assert ev.integrity_incidents(CHANNEL, JOURNAL) == ()
    # A deduplicated delivery applies no second effect: no extra event exists.
    assert len(ev.read_prefix(CHANNEL, head_before)) == 2

    # The next sequence is still 2 and lands at journal sequence 3.
    second = ev.append_event(CHANNEL, OWNER, _submission(2, "next"))
    assert second.journal_sequence == 3
    events = ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))
    assert [event.journal_sequence for event in events] == [1, 2, 3]
    assert [event.event_id for event in events].count(first.event_id) == 1


# ---------------------------------------------------------------------------
# Assertion 3: conflicting content under one producer sequence is an incident
# ---------------------------------------------------------------------------


def test_same_producer_sequence_different_content_records_integrity_incident():
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "original"))
    head_before = ev.journal_head(CHANNEL, JOURNAL)
    original_record = first.to_dict()

    with pytest.raises(ev.IntegrityIncidentError) as excinfo:
        ev.append_event(CHANNEL, OWNER, _submission(1, "conflicting"))
    incident = excinfo.value.incident
    assert incident.journal_id == JOURNAL
    assert incident.producer_id == PRODUCER
    assert incident.producer_sequence == 1
    assert incident.accepted_event_id == first.event_id
    assert incident.accepted_event_hash == first.event_hash
    assert incident.accepted_content_digest != incident.observed_content_digest

    # Retained without replacing the acknowledged event or moving the head.
    incidents = ev.integrity_incidents(CHANNEL, JOURNAL)
    assert len(incidents) == 1
    assert incidents[0].to_dict() == incident.to_dict()
    assert ev.journal_head(CHANNEL, JOURNAL) == head_before
    assert first.to_dict() == original_record

    # The journal remains usable and strictly increasing.
    second = ev.append_event(CHANNEL, OWNER, _submission(2, "second"))
    assert second.journal_sequence == 3

    # A conflict under an inspected sequence never rewrites the earlier prefix.
    with pytest.raises(ev.IntegrityIncidentError):
        ev.append_event(CHANNEL, OWNER, _submission(1, "third"))
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == 3
    assert len(ev.integrity_incidents(CHANNEL, JOURNAL)) == 2

    with pytest.raises(ev.IntegrityIncidentError):
        ev.append_event(CHANNEL, OWNER, _submission(2, "replace-second"))
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == 3
    assert len(ev.integrity_incidents(CHANNEL, JOURNAL)) == 3

    events = ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))
    assert [event.event_id for event in events] == [
        events[0].event_id,
        first.event_id,
        second.event_id,
    ]
    assert events[1].to_dict() == original_record


# ---------------------------------------------------------------------------
# Assertion 4: owner effect, revision, journal, and receipt commit atomically
# ---------------------------------------------------------------------------


def test_owner_effect_journal_and_idempotency_receipt_commit_before_acknowledgement():
    _setup()
    entity = "entity_conformance_0001"
    command = "command_conformance_0001"
    state = _retain("state-1")
    submissions = (_submission(1, "first"), _submission(2, "second"))

    prefix = ev.commit_effect(
        CHANNEL, OWNER, entity, command, 0, state, submissions
    )
    assert prefix.last_sequence == 3
    assert prefix.head_hash == ev.journal_head(CHANNEL, JOURNAL).head_hash

    # The acknowledged response is durable and replayable immediately.
    events = ev.read_prefix(CHANNEL, prefix)
    assert [event.journal_sequence for event in events] == [1, 2, 3]
    assert [event.payload["data"]["note"] for event in events[1:]] == [
        "first",
        "second",
    ]
    snapshot = ev.entity_state(CHANNEL, OWNER, entity)
    assert snapshot.revision == 1
    assert snapshot.state == state

    # A retried command replays the stored prefix without new events.
    replay = ev.commit_effect(
        CHANNEL, OWNER, entity, command, 0, state, submissions
    )
    assert replay == prefix
    assert ev.journal_head(CHANNEL, JOURNAL) == ev.JournalPrefix(
        JOURNAL, 3, prefix.head_hash
    )
    assert ev.entity_state(CHANNEL, OWNER, entity) == snapshot
    assert len(ev.read_prefix(CHANNEL, replay)) == 3

    other_state = _retain("state-2")
    # Reusing one idempotency key with different content is a conflict.
    with pytest.raises(ev.CommandConflictError):
        ev.commit_effect(
            CHANNEL, OWNER, entity, command, 1, other_state, ()
        )
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == 3
    assert ev.entity_state(CHANNEL, OWNER, entity) == snapshot

    # A stale expected revision commits nothing and records no receipt.
    with pytest.raises(ev.RevisionConflictError) as revision_error:
        ev.commit_effect(
            CHANNEL,
            OWNER,
            entity,
            "command_conformance_stale",
            0,
            other_state,
            (_submission(3, "third"),),
        )
    assert revision_error.value.current_revision == 1
    assert revision_error.value.expected_revision == 0
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == 3
    assert ev.entity_state(CHANNEL, OWNER, entity) == snapshot

    # Because no receipt was recorded, the retry with the right revision runs
    # the real operation (and the same producer sequence was not consumed).
    accepted = ev.commit_effect(
        CHANNEL,
        OWNER,
        entity,
        "command_conformance_stale",
        1,
        other_state,
        (_submission(3, "third"),),
    )
    assert accepted.last_sequence == 4
    later = ev.entity_state(CHANNEL, OWNER, entity)
    assert later.revision == 2
    assert later.state == other_state

    # One invalid event in a batch leaves state, revision, journal, and receipt
    # untouched and consumes no producer sequence.
    third_state = _retain("state-3")
    bad_ref = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=1,
        event_id="evt_not_the_admission",
        event_hash=events[0].event_hash,
        pointer="",
    )
    with pytest.raises(ev.InvalidEvidenceRefError):
        ev.commit_effect(
            CHANNEL,
            OWNER,
            entity,
            "command_conformance_atomic",
            2,
            third_state,
            (
                _submission(4, "fourth"),
                _submission(5, "fifth", evidence_refs=[bad_ref]),
            ),
        )
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == 4
    assert ev.entity_state(CHANNEL, OWNER, entity) == later
    assert len(ev.read_prefix(CHANNEL, accepted)) == 4

    # The rejected batch consumed no producer sequence: the same sequences work.
    atomic = ev.commit_effect(
        CHANNEL,
        OWNER,
        entity,
        "command_conformance_atomic",
        2,
        third_state,
        (_submission(4, "fourth"), _submission(5, "fifth")),
    )
    assert atomic.last_sequence == 6
    final = ev.entity_state(CHANNEL, OWNER, entity)
    assert final.revision == 3
    assert final.state == third_state
    assert [event.payload["data"]["note"] for event in ev.read_prefix(CHANNEL, atomic)[4:]] == [
        "fourth",
        "fifth",
    ]

    # The earlier replayable responses still verify after later commits.
    assert ev.commit_effect(
        CHANNEL, OWNER, entity, command, 0, state, submissions
    ) == prefix
    assert ev.commit_effect(
        CHANNEL,
        OWNER,
        entity,
        "command_conformance_stale",
        1,
        other_state,
        (_submission(3, "third"),),
    ) == accepted
