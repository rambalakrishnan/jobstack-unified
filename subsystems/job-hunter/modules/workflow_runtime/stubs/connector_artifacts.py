"""Stub for CONSUMES dependency ``connector_artifacts`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import ArtifactChunk, ArtifactInventory, ConnectorError, ConnectorRequest


async def collect_task_artifacts(channel_id: str, request: ConnectorRequest) -> Union[ArtifactInventory, ArtifactChunk, ConnectorError]:
    return ArtifactInventory(items=())
