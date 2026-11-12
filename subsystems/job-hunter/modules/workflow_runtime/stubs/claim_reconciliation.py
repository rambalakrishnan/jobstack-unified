"""Stub for CONSUMES dependency ``claim_reconciliation`` (declared signatures only)."""
from __future__ import annotations

from .models import MISSING, ArtifactReference, AxisRevision, JournalPrefix, ReportInputPins, ReportValue, VersionPin


def derive_report(channel_id: str, commission: ArtifactReference, inputs: ReportInputPins, evaluator: VersionPin, prefix: JournalPrefix) -> ReportValue:
    return ReportValue(
        report_id="report/%s" % commission.artifact_id,
        content="{}",
        stale=False,
        subject_comparison=MISSING,
    )


def publish_report(channel_id: str, commission: ArtifactReference, value: ReportValue, expected_revision: int, command_id: str) -> AxisRevision:
    return AxisRevision(axis="report", revision=expected_revision, value=value.report_id)
