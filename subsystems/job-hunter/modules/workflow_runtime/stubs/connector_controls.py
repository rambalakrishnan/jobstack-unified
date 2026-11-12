"""Stub for CONSUMES dependency ``connector_controls`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import ConnectorError, ConnectorRequest, ControlReceipt


async def control_task(channel_id: str, request: ConnectorRequest) -> Union[ControlReceipt, ConnectorError]:
    return ControlReceipt(control=request.verb, accepted=True)
