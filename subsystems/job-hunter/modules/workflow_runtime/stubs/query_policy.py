"""Stub for CONSUMES dependency ``query_policy`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, QueryArtifact, VersionPin


def build_query(channel_id: str, query_id: str, profile: ArtifactReference, catalog: VersionPin, veto_policy: VersionPin, syntax_mapping: VersionPin, family: str, board: str) -> QueryArtifact:
    return QueryArtifact(query_id=query_id, family=family, board=board)
