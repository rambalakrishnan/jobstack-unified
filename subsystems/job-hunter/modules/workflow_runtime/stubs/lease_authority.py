"""Stub for CONSUMES dependency ``lease_authority`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import LeaseRecord, Missing, ResourceReference, VersionPin


def transition_lease(channel_id: str, resource: ResourceReference, operation: str, expected: Union[LeaseRecord, Missing], policy: VersionPin) -> LeaseRecord:
    return LeaseRecord(
        lease_id="%s:%s" % (resource.resource_id, operation),
        resource_id=resource.resource_id,
        holder=channel_id,
        state="held",
    )
