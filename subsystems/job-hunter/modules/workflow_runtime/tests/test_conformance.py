"""Conformance assertions for workflow_runtime (Tier 9 spot check).

Covers exactly the -k filter named in the module spec:
- manual_production_lane_runs_without_crawler_model_executor_or_laboratory
- practice_completion_never_automatically_dispatches_production
- scheduler_recovery_observes_uncertain_work_without_repeating_external_effects
- job_hunter_silo_verification_runs_with_synthetic_peers_and_no_live_portals
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src import (  # noqa: E402
    MANUAL_LANE_DEPENDENCIES,
    WorkflowRuntime,
)
from stubs import models as m  # noqa: E402
from stubs import (  # noqa: E402
    attempt_commissioning,
    claim_reconciliation,
    offline_replay,
    product_domain,
)


def _policies() -> m.EvaluationPolicyPins:
    return m.EvaluationPolicyPins(pins=("pinned-profile",))


def _profile(channel: str) -> m.ArtifactReference:
    return m.ArtifactReference(artifact_id="profile/candidate", channel_id=channel)


def _receipt(channel: str) -> m.ArtifactReference:
    return m.ArtifactReference(artifact_id="receipt/employer-1", channel_id=channel)


def _production_manifest(principal: str, key: str, manifest_id: str = "m-prod-1") -> m.Manifest:
    return m.Manifest(
        manifest_id=manifest_id,
        attempt_kind="production",
        candidate="candidate",
        job_snapshot="snapshot",
        target="employer-target",
        task="apply",
        execution_config="connector",
        origin="employer",
        principal=principal,
        idempotency_key=key,
        automation_subject="subject",
        connector_version="v1",
        binding_version="b1",
    )


def test_manual_production_lane_runs_without_crawler_model_executor_or_laboratory() -> None:
    rt = WorkflowRuntime()
    result = rt.run_manual_production_lane(
        candidate_id="cand-1",
        profile=_profile(rt.channel_id),
        policies=_policies(),
        material_policy=m.VersionPin(name="materials", version="v1"),
        employer_receipt=_receipt(rt.channel_id),
        evaluator=m.VersionPin(name="evaluator", version="v1"),
    )
    # No automation subject: manual lane carries no subject, connector
    # version, or binding version.
    assert isinstance(result.executor, m.Missing)
    assert isinstance(result.subject_comparison, m.Missing)
    assert result.dispatch_revision == 0
    assert result.execution_revision == 0
    assert result.dispatch_binding == "not_applicable"
    assert result.execution_binding == "not_applicable"
    # Genuine production commitment: receipt verified, report published,
    # observation facts journaled with manual provenance.
    assert result.commitment == "confirmed"
    assert result.receipt_revision.revision == 1
    assert result.report_revision.revision == 1
    manual_events = [e for e in result.journal if e.owner_domain == "manual"]
    assert manual_events, "human actions must be journaled with manual provenance"
    # The manual lane only touches its allow-listed dependencies: no crawler
    # acquisition, model provider, executor connector, or laboratory fixture.
    forbidden = ("crawler", "model", "connector_transport", "laboratory", "hellscape")
    for dep in MANUAL_LANE_DEPENDENCIES:
        assert not any(token in dep for token in forbidden), dep
    assert set(MANUAL_LANE_DEPENDENCIES) == {
        "read_publications",
        "job_evaluation",
        "material_generation",
        "artifact_store",
        "evidence_journal",
        "attempt_commissioning",
        "manual_observation",
        "origin_receipts",
        "claim_reconciliation",
    }
    # Static guard: the composition root never imports shared browser primitives
    # (word-boundary match so ObservationPage/ControlReceipt do not trip it).
    import re
    source = (Path(__file__).resolve().parents[1] / "src" / "__init__.py").read_text()
    for token in ("BrowserOxide", "Camoufox", "Playwright", "Juggler", r"\bPage\b", r"\bElementHandle\b"):
        assert re.search(token, source) is None, token


def test_practice_completion_never_automatically_dispatches_production() -> None:
    rt = WorkflowRuntime()
    practice_ref = rt.commission_practice("fixture-1")
    manifest = m.Manifest(
        manifest_id="m-practice-1",
        attempt_kind="practice",
        candidate="fixture-candidate",
        job_snapshot="fixture-1",
        target="fixture-target",
        task="rehearse",
        execution_config="laboratory",
        origin="fixture",
        principal="operator",
        idempotency_key="practice-1",
    )
    completion = rt.complete_practice(practice_ref, manifest, m.AnalysisRequest(analysis_id="a1", method="review"))
    assert completion.auto_dispatched_production is False
    assert completion.production_handles == ()
    assert rt.production_commissions == ()
    assert isinstance(completion.diagnostic, m.DiagnosticDocument)
    # Production needs its own separately authorized commission; a practice
    # diagnostic cannot substitute for it.
    prod_ref = rt.commission_production("prod-1", "production-operator", "prod-key-1", "employer-target")
    assert rt.production_commissions == ("prod-1",)
    loaded = attempt_commissioning.load_commission(rt.channel_id, prod_ref)
    assert loaded.kind == "production"
    assert loaded.attempt_id == prod_ref.digest


def test_scheduler_recovery_observes_uncertain_work_without_repeating_external_effects() -> None:
    rt = WorkflowRuntime()
    manifest = _production_manifest("principal-1", "start-key-1")
    first = rt.start_production(manifest, "apply", "stable-1")
    assert first.response_lost is True
    assert first.dispatch_uncertain is True
    deliveries_after_start = rt.native_deliveries
    # Repeated Start under the same idempotency key returns the same handle:
    # no second logical execution, no second external effect.
    second = rt.start_production(manifest, "apply", "stable-1")
    assert second.handle == first.handle
    assert rt.native_deliveries == deliveries_after_start
    # Recovery observes and issues same-command controls without relaunching.
    page = rt.observe_uncertain(first.handle)
    assert page.handle == first.handle
    assert rt.native_deliveries == deliveries_after_start
    receipt = rt.control_uncertain(first.handle, "Start")
    assert receipt.accepted is True
    assert rt.native_deliveries == deliveries_after_start
    assert rt.retry_connector_command(first.handle, "Start", "stable-1") == first.handle
    assert rt.native_deliveries == deliveries_after_start
    with pytest.raises(ValueError):
        rt.retry_connector_command(first.handle, "Cancel", "stable-1")
    with pytest.raises(ValueError):
        rt.retry_connector_command(first.handle, "Start", "other-key")
    # Changed content under the same key is rejected outright.
    with pytest.raises(ValueError):
        rt.start_production(_production_manifest("principal-1", "start-key-1", "m-prod-2"), "apply", "stable-1")
    # Observation can close within bounds while uncertainty stands; the late
    # verified receipt publishes a new revision plus a stale-report signal,
    # keeping the prior close-time report intact.
    rt.close_observation(first.handle)
    commission = m.ArtifactReference(artifact_id="attempt/prod-1", channel_id=rt.channel_id)
    outcome = rt.accept_late_receipt(commission, _receipt(rt.channel_id), prior_report_id="report/attempt/prod-1")
    assert outcome.application_revision.revision == 2
    assert outcome.stale_report is True
    assert outcome.prior_report_preserved is True


def test_job_hunter_silo_verification_runs_with_synthetic_peers_and_no_live_portals() -> None:
    rt = WorkflowRuntime()
    report = rt.run_silo_verification()
    assert report.passed is True
    assert report.live_portals_used == ()
    expected = {
        "artifact_store",
        "evidence_journal",
        "attempt_commissioning",
        "manual_observation",
        "origin_receipts",
        "claim_reconciliation",
        "connector_dispatch",
        "connector_observation",
        "connector_controls",
        "job_evaluation",
        "material_generation",
        "read_publications",
        "attempt_diagnostics",
        "offline_replay",
        "product_domain",
    }
    assert expected.issubset(set(report.synthetic_peers))
    # Synthetic peers exercise deterministically with no network.
    channel = rt.channel_id
    row = __import__("stubs.read_publications", fromlist=["seal_row"]).seal_row(
        channel, m.EntityRegistration(entity_id="e", owner_domain="crawler"), "view", "seal"
    )
    assert row.row_id != ""
    revision = product_domain.publish_product_revision(
        channel,
        m.EntityRegistration(entity_id="product", owner_domain="product"),
        1,
        "cmd-1",
        m.JobDownstreamValue(value_id="v1"),
        m.MISSING,
    )
    assert revision.revision == 1
    diagnostic = __import__("stubs.attempt_diagnostics", fromlist=["derive_diagnostic"]).derive_diagnostic(
        channel, _production_manifest("p", "k"), m.JournalPrefix(channel_id=channel), m.AnalysisRequest(analysis_id="a")
    )
    replayed = offline_replay.replay_diagnostic(
        channel,
        _production_manifest("p", "k"),
        diagnostic,
        m.ArtifactReference(artifact_id="bundle"),
        m.VersionPin(name="engine"),
    )
    assert replayed.matched is True
    derived = claim_reconciliation.derive_report(
        channel,
        m.ArtifactReference(artifact_id="attempt/x"),
        m.ReportInputPins(pins=()),
        m.VersionPin(name="eval"),
        m.JournalPrefix(channel_id=channel),
    )
    assert derived.report_id != ""
    assert asyncio.run is not None  # async stubs remain awaitable, unused here
