"""Stub for CONSUMES dependency ``manual_observation`` (declared signatures only)."""
from __future__ import annotations

import itertools

from .models import ArtifactReference, AxisRevision, EventSubmission, JournalEnvelope, ObservationValue

_counter = itertools.count(1)


def record_manual_event(channel_id: str, commission: ArtifactReference, submission: EventSubmission) -> JournalEnvelope:
    return JournalEnvelope(
        sequence=next(_counter),
        owner_domain="manual",
        event_type=submission.event_type,
        payload=submission.payload,
    )


def publish_manual_observation(channel_id: str, commission: ArtifactReference, value: ObservationValue, expected_revision: int, command_id: str) -> AxisRevision:
    return AxisRevision(axis=value.axis, revision=expected_revision, value=value.value)
