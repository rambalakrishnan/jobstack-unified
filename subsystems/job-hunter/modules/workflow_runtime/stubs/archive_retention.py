"""Stub for CONSUMES dependency ``archive_retention`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, RetentionPinRevision


def revise_retention(channel_id: str, pin: RetentionPinRevision) -> ArtifactReference:
    return ArtifactReference(artifact_id="retention/%s/%d" % (pin.pin_id, pin.revision), channel_id=channel_id)
