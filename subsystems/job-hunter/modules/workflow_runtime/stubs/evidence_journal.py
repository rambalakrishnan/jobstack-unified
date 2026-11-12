"""Stub for CONSUMES dependency ``evidence_journal`` (declared signatures only)."""
from __future__ import annotations

import itertools

from .models import EventSubmission, JournalEnvelope, JournalPrefix, Manifest

_counter = itertools.count(1)


def admit_manifest(channel_id: str, manifest: Manifest) -> JournalEnvelope:
    return JournalEnvelope(
        sequence=next(_counter),
        owner_domain="evidence",
        event_type="manifest_admitted",
        payload=manifest.manifest_id,
    )


def append_event(channel_id: str, owner_domain: str, submission: EventSubmission) -> JournalEnvelope:
    return JournalEnvelope(
        sequence=next(_counter),
        owner_domain=owner_domain,
        event_type=submission.event_type,
        payload=submission.payload,
    )


def read_prefix(channel_id: str, prefix: JournalPrefix) -> tuple[JournalEnvelope, ...]:
    return ()
