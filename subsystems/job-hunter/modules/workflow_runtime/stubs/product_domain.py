"""Stub for CONSUMES dependency ``product_domain`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import DataDomainRevision, EntityRegistration, JobDownstreamValue, LeaseRecord, Missing


def publish_product_revision(channel_id: str, registration: EntityRegistration, expected_revision: int, command_id: str, value: JobDownstreamValue, lease: Union[LeaseRecord, Missing]) -> DataDomainRevision:
    return DataDomainRevision(revision=expected_revision, value_id=value.value_id)
