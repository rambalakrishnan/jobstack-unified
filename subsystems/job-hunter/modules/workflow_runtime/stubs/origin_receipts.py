"""Stub for CONSUMES dependency ``origin_receipts`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import MISSING, ArtifactReference, AxisRevision, Missing


def record_origin_receipt(channel_id: str, commission: ArtifactReference, receipt: ArtifactReference, expected_revision: int, command_id: str) -> Union[AxisRevision, Missing]:
    if not receipt.artifact_id:
        return MISSING
    return AxisRevision(axis="origin_fact", revision=expected_revision, value=receipt.artifact_id)
