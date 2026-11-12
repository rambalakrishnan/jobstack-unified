"""Stub for CONSUMES dependency ``attempt_commissioning`` (declared signatures only)."""
from __future__ import annotations

import itertools

from .models import ArtifactReference, AttemptCommission

_counter = itertools.count(1)


def register_attempt(channel_id: str, commission: AttemptCommission) -> ArtifactReference:
    return ArtifactReference(
        artifact_id="attempt/%s" % commission.attempt_id,
        channel_id=channel_id,
        media_type="application/json",
        digest=commission.attempt_id,
        access="restricted",
    )


def load_commission(channel_id: str, content: ArtifactReference) -> AttemptCommission:
    return AttemptCommission(attempt_id=content.digest or content.artifact_id, kind="production")
