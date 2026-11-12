"""Stub for CONSUMES dependency ``connector_observation`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import ConnectorError, ConnectorRequest, ObservationPage


async def observe_task(channel_id: str, request: ConnectorRequest) -> Union[ObservationPage, ConnectorError]:
    return ObservationPage(handle="handle/%s" % request.attempt_id, events=(), complete=False)
