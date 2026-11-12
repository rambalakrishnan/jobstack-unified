"""Stub for CONSUMES dependency ``correspondence`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import MISSING, ArtifactReference, EvidenceRef, Missing, VersionPin


async def synchronize_mail(channel_id: str, mailbox_id: str, adapter: VersionPin) -> ArtifactReference:
    return ArtifactReference(artifact_id="mail/%s" % mailbox_id, channel_id=channel_id)


async def send_followup(channel_id: str, command_id: str, payload: ArtifactReference, adapter: VersionPin, authorization_refs: tuple[EvidenceRef, ...]) -> Union[ArtifactReference, Missing]:
    return MISSING
