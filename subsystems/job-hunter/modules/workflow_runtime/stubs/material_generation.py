"""Stub for CONSUMES dependency ``material_generation`` (declared signatures only)."""
from __future__ import annotations

from typing import Union

from .models import ArtifactReference, MaterialPackage, Missing, VersionPin


async def generate_materials(channel_id: str, candidate_profile: ArtifactReference, job_snapshot: ArtifactReference, evaluation: Union[ArtifactReference, Missing], policy: VersionPin) -> MaterialPackage:
    return MaterialPackage(package_id="materials/%s" % candidate_profile.artifact_id)
