"""Stub for CONSUMES dependency ``connector_dispatch`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import ConnectorDescriptor, ConnectorError, ConnectorRequest, PrepareResult, StartResult


async def describe_subject(channel_id: str, request: ConnectorRequest) -> Union[ConnectorDescriptor, ConnectorError]:
    return ConnectorDescriptor(subject=request.task, version="stub")


async def prepare_task(channel_id: str, request: ConnectorRequest) -> Union[PrepareResult, ConnectorError]:
    return PrepareResult(handle="handle/%s" % request.attempt_id, ready=True)


async def start_task(channel_id: str, request: ConnectorRequest) -> Union[StartResult, ConnectorError]:
    return StartResult(handle="handle/%s" % request.attempt_id, dispatch_revision=0)
