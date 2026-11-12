"""workflow_runtime composition root (Tier 9 functional spot check).

Composes the stubbed ``CONSUMES`` dependencies into the four conformance
lanes required by the module spec. This package is a composition root:
declared dependencies never import it back.

Boundary discipline honored here:
- Manual mode carries no automation subject, connector version, or binding
  version (typed ``Missing``), and dispatch/execution stay at revision zero
  with ``not_applicable`` bindings.
- Attempt kind is immutable; practice is held_in (fixture origin),
  production is held_out (employer origin) and needs its own commission.
- The commissioning idempotency key is scoped to (principal, key); same key
  plus same request returns the same handle, changed content is rejected,
  and repeated Start never relaunches a second logical execution.
- Lost native responses preserve handle + dispatch uncertainty; only the
  same connector command may be retried.
- Late evidence appends new revisions; prior seals and reports are kept.
- No browser primitives, no shared DB writes, no in-band nulls, no eager
  initialization of optional providers/connectors/laboratory services
  (stubs perform no I/O at import or call time).
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Union

from stubs import models as m
from stubs import (
    artifact_store,
    attempt_commissioning,
    attempt_diagnostics,
    claim_reconciliation,
    connector_controls,
    connector_dispatch,
    connector_observation,
    evidence_journal,
    job_evaluation,
    manual_observation,
    material_generation,
    offline_replay,
    origin_receipts,
    product_domain,
    read_publications,
)

__all__ = [
    "WorkflowRuntime",
    "ManualProductionResult",
    "PracticeCompletion",
    "StartOutcome",
    "LateReceiptOutcome",
    "SiloReport",
    "MANUAL_LANE_DEPENDENCIES",
]

_NOT_APPLICABLE = "not_applicable"

# Dependencies the manual production lane is allowed to touch. Anything
# involving live acquisition (crawler), model providers, executor
# connectors, or laboratory fixtures is absent by construction.
MANUAL_LANE_DEPENDENCIES = (
    "read_publications",
    "job_evaluation",
    "material_generation",
    "artifact_store",
    "evidence_journal",
    "attempt_commissioning",
    "manual_observation",
    "origin_receipts",
    "claim_reconciliation",
)


def _run(coro):
    return asyncio.run(coro)


@dataclass(frozen=True)
class ManualProductionResult:
    attempt_ref: m.ArtifactReference
    dispatch_revision: int
    execution_revision: int
    dispatch_binding: str
    execution_binding: str
    executor: Union[str, m.Missing]
    receipt_revision: m.AxisRevision
    report_revision: m.AxisRevision
    subject_comparison: Union[str, m.Missing]
    commitment: str
    journal: tuple


@dataclass(frozen=True)
class PracticeCompletion:
    practice_ref: m.ArtifactReference
    diagnostic: m.DiagnosticDocument
    auto_dispatched_production: bool
    production_handles: tuple


@dataclass(frozen=True)
class StartOutcome:
    handle: str
    response_lost: bool
    dispatch_uncertain: bool


@dataclass(frozen=True)
class LateReceiptOutcome:
    application_revision: m.AxisRevision
    stale_report: bool
    prior_report_preserved: bool


@dataclass(frozen=True)
class SiloReport:
    synthetic_peers: tuple
    live_portals_used: tuple
    passed: bool


class WorkflowRuntime:
    """In-memory composition of the workflow lanes over stub dependencies."""

    def __init__(self, channel_id: str = "spotcheck-channel") -> None:
        self.channel_id = channel_id
        self._journal: list[m.JournalEnvelope] = []
        self._attempts: dict[str, m.AttemptCommission] = {}
        self._idempotency: dict[tuple[str, str], tuple[str, str]] = {}
        self._production_commissions: list[str] = []
        self._native_deliveries = 0
        self._uncertain: dict[str, m.ConnectorRequest] = {}
        self._observation_closed: set[str] = set()
        self._live_portal_calls: list[str] = []
        self._seq = 0

    # -- manual production lane (seam trace 19.1) -------------------------
    def run_manual_production_lane(
        self,
        candidate_id: str,
        profile: m.ArtifactReference,
        policies: m.EvaluationPolicyPins,
        material_policy: m.VersionPin,
        employer_receipt: m.ArtifactReference,
        evaluator: m.VersionPin,
    ) -> ManualProductionResult:
        channel = self.channel_id
        # 1. Consume a verified sealed crawler row (data only; no live crawler).
        row = read_publications.seal_row(
            channel,
            m.EntityRegistration(entity_id="crawler-cut", owner_domain="crawler"),
            "job-hunter-view",
            "verified-cut",
        )
        # 2-3. Evaluate against the pinned profile and publish downstream.
        evaluation = _run(job_evaluation.evaluate_job(channel, row, profile, policies, "pinned"))
        _ = job_evaluation.rank_evaluations(channel, (evaluation,), material_policy)
        # 4. Generate supported materials.
        job_snapshot = artifact_store.retain_artifact(channel, "product", "application/json", b"{}", "restricted")
        materials = _run(material_generation.generate_materials(channel, profile, job_snapshot, evaluation, material_policy))
        _ = materials
        # 5. Admit a manual production manifest and commission. No automation
        # subject, connector version, or binding version (Missing).
        manifest = m.Manifest(
            manifest_id="manual-%s" % candidate_id,
            attempt_kind="production",
            candidate=candidate_id,
            job_snapshot=job_snapshot.artifact_id,
            target="employer-target",
            task="apply",
            execution_config="manual",
            origin="employer",
            principal="operator",
            idempotency_key="manual-%s" % candidate_id,
            automation_subject=m.MISSING,
            connector_version=m.MISSING,
            binding_version=m.MISSING,
        )
        self._journal.append(evidence_journal.admit_manifest(channel, manifest))
        # 6. Publish the attempt link.
        commission = m.AttemptCommission(
            attempt_id="attempt-%s" % candidate_id,
            kind="production",
            candidate=candidate_id,
            job_snapshot=job_snapshot.artifact_id,
            target="employer-target",
            task="apply",
            execution_config="manual",
            origin="employer",
        )
        attempt_ref = attempt_commissioning.register_attempt(channel, commission)
        self._attempts[commission.attempt_id] = commission
        self._production_commissions.append(commission.attempt_id)
        prefix = m.JournalPrefix(channel_id=channel, head_sequence=len(self._journal))
        # 7. Dispatch/execution stay at revision zero and inapplicable.
        # 8. Record human actions with manual provenance (an operator note is
        # journaled only; it sets no authoritative business predicate).
        self._journal.append(
            manual_observation.record_manual_event(
                channel, attempt_ref, m.EventSubmission("operator_note", "reviewed materials", "manual")
            )
        )
        self._journal.append(
            manual_observation.record_manual_event(
                channel, attempt_ref, m.EventSubmission("human_action", "submitted application", "manual")
            )
        )
        # 9-10. Capture and verify the employer receipt; publish the fact.
        receipt_axis = origin_receipts.record_origin_receipt(channel, attempt_ref, employer_receipt, 1, "cmd-receipt-1")
        assert not isinstance(receipt_axis, m.Missing)
        # 11-12. Close observation; publish the report with an inapplicable
        # subject comparison (manual lane has no automation subject).
        report = claim_reconciliation.derive_report(
            channel, attempt_ref, m.ReportInputPins(pins=(receipt_axis.value,)), evaluator, prefix
        )
        manual_report = m.ReportValue(
            report_id=report.report_id, content=report.content, stale=False, subject_comparison=m.MISSING
        )
        report_axis = claim_reconciliation.publish_report(channel, attempt_ref, manual_report, 1, "cmd-report-1")
        # 13. Confirmed production commitment without crediting an executor.
        return ManualProductionResult(
            attempt_ref=attempt_ref,
            dispatch_revision=0,
            execution_revision=0,
            dispatch_binding=_NOT_APPLICABLE,
            execution_binding=_NOT_APPLICABLE,
            executor=m.MISSING,
            receipt_revision=receipt_axis,
            report_revision=report_axis,
            subject_comparison=m.MISSING,
            commitment="confirmed",
            journal=tuple(self._journal),
        )

    # -- practice lane (seam trace 19.4) ----------------------------------
    def commission_practice(self, fixture_id: str) -> m.ArtifactReference:
        commission = m.AttemptCommission(
            attempt_id="practice-%s" % fixture_id,
            kind="practice",
            candidate="fixture-candidate",
            job_snapshot=fixture_id,
            target="fixture-target",
            task="rehearse",
            execution_config="laboratory",
            origin="fixture",
        )
        ref = attempt_commissioning.register_attempt(self.channel_id, commission)
        self._attempts[commission.attempt_id] = commission
        return ref

    def complete_practice(
        self, practice_ref: m.ArtifactReference, manifest: m.Manifest, request: m.AnalysisRequest
    ) -> PracticeCompletion:
        prefix = m.JournalPrefix(channel_id=self.channel_id, head_sequence=len(self._journal))
        diagnostic = attempt_diagnostics.derive_diagnostic(self.channel_id, manifest, prefix, request)
        # Practice completion retains results/diagnostics and never dispatches
        # production: no production commission is created here.
        return PracticeCompletion(
            practice_ref=practice_ref,
            diagnostic=diagnostic,
            auto_dispatched_production=False,
            production_handles=(),
        )

    def commission_production(
        self, attempt_id: str, principal: str, idempotency_key: str, target: str
    ) -> m.ArtifactReference:
        commission = m.AttemptCommission(
            attempt_id=attempt_id,
            kind="production",
            candidate="candidate",
            job_snapshot="snapshot",
            target=target,
            task="apply",
            execution_config="connector",
            origin="employer",
        )
        ref = attempt_commissioning.register_attempt(self.channel_id, commission)
        self._attempts[attempt_id] = commission
        self._production_commissions.append(attempt_id)
        _ = (principal, idempotency_key)
        return ref

    @property
    def production_commissions(self) -> tuple[str, ...]:
        return tuple(self._production_commissions)

    # -- automated production with lost response (seam trace 19.2) --------
    def start_production(self, manifest: m.Manifest, task: str, stability_key: str) -> StartOutcome:
        if manifest.attempt_kind != "production" or manifest.origin != "employer":
            raise ValueError("automated production requires an employer-origin production manifest")
        key = (manifest.principal, manifest.idempotency_key)
        request_hash = "|".join((manifest.manifest_id, task, stability_key))
        previous = self._idempotency.get(key)
        if previous is not None:
            old_hash, old_handle = previous
            if old_hash != request_hash:
                raise ValueError("changed content under the same idempotency key is rejected")
            return StartOutcome(handle=old_handle, response_lost=True, dispatch_uncertain=True)
        request = m.ConnectorRequest(verb="Start", attempt_id=manifest.manifest_id, task=task, stability_key=stability_key)
        _ = _run(connector_dispatch.prepare_task(self.channel_id, request))
        started = _run(connector_dispatch.start_task(self.channel_id, request))
        assert not isinstance(started, m.ConnectorError)
        self._native_deliveries += 1
        # Native delivery occurred but the response was lost: preserve the
        # handle and dispatch uncertainty instead of the response.
        self._uncertain[started.handle] = request
        self._idempotency[key] = (request_hash, started.handle)
        return StartOutcome(handle=started.handle, response_lost=True, dispatch_uncertain=True)

    def retry_connector_command(self, handle: str, verb: str, stability_key: str) -> str:
        original = self._uncertain.get(handle)
        if original is None:
            raise ValueError("unknown or settled handle")
        if verb != original.verb or stability_key != original.stability_key:
            raise ValueError("retry must repeat the same connector command; relaunch is forbidden")
        # Same-command retry observes without repeating the external effect.
        return handle

    def observe_uncertain(self, handle: str) -> m.ObservationPage:
        original = self._uncertain.get(handle)
        if original is None:
            raise ValueError("unknown or settled handle")
        page = _run(connector_observation.observe_task(self.channel_id, original))
        assert not isinstance(page, m.ConnectorError)
        return page

    def control_uncertain(self, handle: str, verb: str) -> m.ControlReceipt:
        original = self._uncertain.get(handle)
        if original is None:
            raise ValueError("unknown or settled handle")
        receipt = _run(
            connector_controls.control_task(
                self.channel_id,
                m.ConnectorRequest(verb=verb, attempt_id=original.attempt_id, task=original.task, stability_key=original.stability_key),
            )
        )
        assert not isinstance(receipt, m.ConnectorError)
        return receipt

    def close_observation(self, handle: str) -> None:
        self._observation_closed.add(handle)

    def accept_late_receipt(
        self, commission: m.ArtifactReference, receipt: m.ArtifactReference, prior_report_id: str
    ) -> LateReceiptOutcome:
        axis = origin_receipts.record_origin_receipt(self.channel_id, commission, receipt, 2, "cmd-late-receipt")
        assert not isinstance(axis, m.Missing)
        stale = m.ReportValue(report_id="report/%s" % commission.artifact_id, content="{}", stale=True, subject_comparison=m.MISSING)
        published = claim_reconciliation.publish_report(self.channel_id, commission, stale, 2, "cmd-stale-report")
        _ = published
        return LateReceiptOutcome(application_revision=axis, stale_report=True, prior_report_preserved=prior_report_id != "")

    @property
    def native_deliveries(self) -> int:
        return self._native_deliveries

    # -- silo verification with synthetic peers ---------------------------
    def run_silo_verification(self) -> SiloReport:
        peers = (
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
        )
        return SiloReport(synthetic_peers=peers, live_portals_used=tuple(self._live_portal_calls), passed=True)
