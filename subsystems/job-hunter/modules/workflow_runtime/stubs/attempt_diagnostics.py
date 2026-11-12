"""Stub for CONSUMES dependency ``attempt_diagnostics`` (declared signatures only)."""
from __future__ import annotations

from .models import AnalysisRequest, DiagnosticDocument, JournalPrefix, Manifest


def derive_diagnostic(channel_id: str, manifest: Manifest, prefix: JournalPrefix, request: AnalysisRequest) -> DiagnosticDocument:
    return DiagnosticDocument(diagnostic_id="diag/%s" % manifest.manifest_id, findings=())
