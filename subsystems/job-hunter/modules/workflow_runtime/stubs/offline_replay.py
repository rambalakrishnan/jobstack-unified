"""Stub for CONSUMES dependency ``offline_replay`` (declared signatures only)."""
from __future__ import annotations

from .models import ArtifactReference, DiagnosticDocument, Manifest, ReplayReceipt, VersionPin


def replay_diagnostic(channel_id: str, manifest: Manifest, source: DiagnosticDocument, input_bundle: ArtifactReference, replay_engine: VersionPin) -> ReplayReceipt:
    return ReplayReceipt(replay_id="replay/%s" % source.diagnostic_id, matched=True)
