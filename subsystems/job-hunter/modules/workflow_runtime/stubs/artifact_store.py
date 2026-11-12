"""Stub for CONSUMES dependency ``artifact_store`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference


def retain_artifact(channel_id: str, owner_domain: str, media_type: str, content: bytes, access: str) -> ArtifactReference:
    digest = "%08x" % (len(content) & 0xFFFFFFFF)
    return ArtifactReference(
        artifact_id="%s/%s" % (owner_domain, digest),
        channel_id=channel_id,
        media_type=media_type,
        digest=digest,
        access=access,
    )


def resolve_artifact(channel_id: str, reference: ArtifactReference) -> bytes:
    return b"{}"
