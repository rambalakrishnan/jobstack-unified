"""Stub for CONSUMES dependency ``read_publications`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, EntityRegistration, LogicalRow, PublicationReceipt


def install_publication(channel_id: str, registration: EntityRegistration, document: ArtifactReference, view_id: str) -> PublicationReceipt:
    return PublicationReceipt(
        publication_id="%s/%s" % (view_id, document.artifact_id),
        view_id=view_id,
    )


def seal_row(channel_id: str, registration: EntityRegistration, view_id: str, seal_name: str) -> LogicalRow:
    return LogicalRow(
        row_id="%s:%s" % (view_id, seal_name),
        seal_name=seal_name,
        view_id=view_id,
        payload="{}",
    )
