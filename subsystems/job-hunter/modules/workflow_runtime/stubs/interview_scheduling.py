"""Stub for CONSUMES dependency ``interview_scheduling`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import MISSING, ArtifactReference, EvidenceRef, Missing, VersionPin


async def schedule_interview(channel_id: str, command_id: str, event: ArtifactReference, adapter: VersionPin, authorization_refs: tuple[EvidenceRef, ...]) -> Union[ArtifactReference, Missing]:
    return MISSING
