"""Stub for CONSUMES dependency ``legacy_collections`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, VersionPin


def import_legacy_document(channel_id: str, collection: str, source: ArtifactReference, mapping: VersionPin) -> ArtifactReference:
    return ArtifactReference(
        artifact_id="%s/%s" % (collection, source.artifact_id),
        channel_id=channel_id,
        media_type=source.media_type,
        digest=source.digest,
        access=source.access,
    )
