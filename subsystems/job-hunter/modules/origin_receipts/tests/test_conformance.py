"""Conformance tests for origin_receipts (tier 6)."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "origin_receipts":
        path = here.parents[1] / "src" / "__init__.py"
    else:
        path = here.parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("access_policy")
store = _load("artifact_store")
ev = _load("evidence_journal")
orv = _load("owner_revisions")
ac = _load("attempt_commissioning")
orr = _load("origin_receipts")

D0 = "sha256:" + "0" * 64
POLICY = {"id": "policy_origin", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_origin_test"
BOOT_ID = "boot_origin_test"


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    store.reset_for_tests()
    ev.reset_for_tests()
    orv.reset_for_tests()
    ac.reset_for_tests()
    orr.reset_for_tests()
    yield
    orr.reset_for_tests()
    ac.reset_for_tests()
    orv.reset_for_tests()
    ev.reset_for_tests()
    store.reset_for_tests()
    ap.reset_for_tests()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _missing_observed() -> dict[str, Any]:
    return {"value": None, "reason": "not_observed"}


def _timepoint(offset: float = 1.0) -> dict[str, Any]:
    return {
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing_observed(),
    }


def _register_app_channel(
    channel: str = "ch_origin_app",
    producer: str = "prod_origin_app",
    principal: str = "principal_origin",
) -> None:
    ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=channel,
        axis="attempt.application",
        producer_id=producer,
        principal_id=principal,
        sequence_required=False,
        allowed_event_kinds=("attempt.commissioned", "origin.receipt_observed"),
        binding="bind_origin_app",
    )
    ap.register_event_kind(
        "attempt.commissioned",
        "1",
        role="lifecycle_observation",
        assertion_kind="authoritative_effect",
        owner_domain="attempt.application",
        writer_roles=("application_origin",),
    )
    ap.register_event_kind(
        "origin.receipt_observed",
        "1",
        role="lifecycle_observation",
        assertion_kind="observation",
        owner_domain="attempt.application",
        writer_roles=("application_origin",),
    )


def _retain(channel: str, content: bytes, access: str = "restricted") -> Any:
    return store.retain_artifact(
        channel, "attempt.application", "application/json", content, access
    )


def _attempt(
    attempt_id: str,
    kind: str,
    target_class: str,
    target_id: str,
    partition: str,
) -> dict[str, Any]:
    return {
        "attempt_id": attempt_id,
        "kind": kind,
        "target_class": target_class,
        "target_id": target_id,
        "evaluation_partition": partition,
        "rehearsal_of": [],
        "performance_of": [],
        "derived_from": [],
    }


def _assistance() -> dict[str, Any]:
    return {
        "planning_owner": "none",
        "assistance_track": "no_assistance",
        "planner_identity": _missing(),
        "plan": _missing(),
        "online_replanning": False,
        "description": "No assistance is declared.",
    }


def _manual_execution() -> dict[str, Any]:
    return {
        "mode": "manual",
        "subject": _missing(),
        "connector_version": _missing(),
        "binding_version": _missing(),
        "assistance": _assistance(),
    }


def _manifest_execution_for(execution: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "manual",
        "subject": ev.NOT_APPLICABLE,
        "connector_version": ev.NOT_APPLICABLE,
        "binding_version": ev.NOT_APPLICABLE,
        "assistance": {
            "planning_owner": "none",
            "assistance_track": "no_assistance",
            "planner_identity": ev.NOT_APPLICABLE,
            "plan": ev.NOT_APPLICABLE,
            "online_replanning": False,
            "description": "No assistance is declared at admission.",
        },
    }


def _admit(
    channel: str,
    producer: str,
    principal: str,
    run_id: str,
    journal_id: str,
    manifest_id: str,
    attempt: dict[str, Any],
    execution: dict[str, Any],
    task_ref: Any,
    config_ref: Any,
) -> tuple[Any, dict[str, Any]]:
    manifest = ev.Manifest(
        manifest_id=manifest_id,
        run_id=run_id,
        journal_id=journal_id,
        owner_domain="attempt.application",
        commissioner_id=principal,
        activity="application_attempt",
        attempt=dict(attempt),
        execution=_manifest_execution_for(execution),
        task=task_ref,
        task_semantic_hash=D0,
        effective_configuration=config_ref,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task_ref.digest}
        ],
        event_registry=[
            {
                "event_kind": "attempt.commissioned",
                "event_schema_version": "1",
                "role": "lifecycle_observation",
                "assertion_kind": "authoritative_effect",
                "writer_roles": ["application_origin"],
            },
            {
                "event_kind": "origin.receipt_observed",
                "event_schema_version": "1",
                "role": "lifecycle_observation",
                "assertion_kind": "observation",
                "writer_roles": ["application_origin"],
            },
        ],
        producers=[
            {
                "producer_id": producer,
                "principal_id": principal,
                "owner_domain": "attempt.application",
                "role": "application_origin",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": [
                    "attempt.commissioned",
                    "origin.receipt_observed",
                ],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_origin_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    admission = ev.admit_manifest(channel, manifest)
    admission_ref = {
        "journal_id": admission.journal_id,
        "sequence": 1,
        "event_id": admission.event_id,
        "event_hash": admission.event_hash,
        "pointer": "",
    }
    return admission, admission_ref


def _obs_policy(action: str = "not_applicable", value: int = 0) -> dict[str, Any]:
    def _limit() -> dict[str, Any]:
        return {"kind": "exact", "unit": "ms", "value": value}

    return {
        "active_limit": _limit(),
        "drain_limit": _limit(),
        "native_cancel_wait_limit": _limit(),
        "cleanup_wait_limit": _limit(),
        "fixture_close_action": action,
    }


def _manual_owners(
    app_producer: str, obs_writer: str, report_writer: str, target_id: str
) -> dict[str, Any]:
    return {
        "dispatch": {
            "role": "connector",
            "source_id": _missing(),
            "writer_id": _missing(),
            "owner_domain": "attempt.dispatch",
            "publication_policy": dict(POLICY),
        },
        "observation": {
            "role": "connector",
            "source_id": "src_manual_recorder",
            "writer_id": obs_writer,
            "owner_domain": "attempt.observation",
            "publication_policy": dict(POLICY),
        },
        "execution": {
            "role": "subject",
            "source_id": _missing(),
            "writer_id": _missing(),
            "owner_domain": "attempt.execution",
            "publication_policy": dict(POLICY),
        },
        "application": {
            "role": "origin",
            "source_id": target_id,
            "writer_id": app_producer,
            "owner_domain": "attempt.application",
            "publication_policy": dict(POLICY),
        },
        "report": {
            "role": "reconciler",
            "source_id": "src_manual_reconciler",
            "writer_id": report_writer,
            "owner_domain": "attempt.report",
            "publication_policy": dict(POLICY),
        },
    }


def _commission_dict(
    *,
    commission_id: str,
    run_id: str,
    journal_id: str,
    manifest_hash: str,
    admission_ref: dict[str, Any],
    commissioned_by: str,
    attempt: dict[str, Any],
    candidate_id: str,
    job_id: str,
    snapshot_ref: Any,
    task_ref: Any,
    execution: dict[str, Any],
    owners: dict[str, Any],
    idempotency_key: str,
) -> dict[str, Any]:
    return {
        "record_type": "attempt_commission",
        "schema_version": "application-attempt-lifecycle/0.1.0",
        "kernel_version": "evidence-kernel/0.1.0",
        "commission_id": commission_id,
        "run_id": run_id,
        "journal_id": journal_id,
        "manifest_hash": manifest_hash,
        "admission_ref": dict(admission_ref),
        "commissioned_by": commissioned_by,
        "commissioned_at": _timepoint(),
        "attempt": dict(attempt),
        "candidate_id": candidate_id,
        "candidate_profile": _missing_observed(),
        "job": {
            "job_id": job_id,
            "source_target": _missing_observed(),
            "source_job_id": _missing_observed(),
            "snapshot": snapshot_ref.to_dict(),
        },
        "selection_evidence": _missing_observed(),
        "task": task_ref.to_dict(),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": dict(execution),
        "owners": {k: dict(v) for k, v in owners.items()},
        "idempotency_key": idempotency_key,
        "authorization_refs": [dict(admission_ref)],
        "recovery_review_refs": [],
        "observation_policy": _obs_policy(),
        "origin_policy": dict(POLICY),
    }


def _setup_production_manual(
    tag: str,
) -> tuple[str, str, str, Any, dict[str, Any], str, str, str]:
    """Commission one manual production attempt. Returns channel, producer,
    principal, commission_ref, commission_dict, attempt_id, candidate_id, job_id."""
    channel = f"ch_origin_{tag}"
    producer = f"prod_origin_{tag}"
    principal = f"principal_origin_{tag}"
    _register_app_channel(channel, producer, principal)
    task_ref = _retain(channel, b'{"goal":"apply intent"}')
    config_ref = _retain(channel, b'{"policy":"manual"}')
    snapshot_ref = _retain(channel, b'{"job":"snapshot v1"}', "public")
    target_id = f"target_employer_{tag}"
    attempt_id = f"attempt_prod_{tag}"
    candidate_id = f"cand_{tag}"
    job_id = f"job_{tag}"
    attempt = _attempt(
        attempt_id, "production", "employer_origin", target_id, "held_out"
    )
    execution = _manual_execution()
    run_id = f"run_{tag}"
    journal_id = f"journal_{tag}"
    _admit(
        channel,
        producer,
        principal,
        run_id,
        journal_id,
        f"manifest_{tag}",
        attempt,
        execution,
        task_ref,
        config_ref,
    )
    # admission_ref needed for commission; recover from journal head seq1
    head1 = ev.journal_head(channel, journal_id)
    assert head1.last_sequence == 1
    prefix1 = ev.JournalPrefix(
        journal_id=journal_id, last_sequence=1, head_hash=head1.head_hash
    )
    events1 = ev.read_prefix(channel, prefix1)
    assert len(events1) == 1
    admission_ref = {
        "journal_id": events1[0].journal_id,
        "sequence": 1,
        "event_id": events1[0].event_id,
        "event_hash": events1[0].event_hash,
        "pointer": "",
    }
    owners = _manual_owners(
        producer, f"prod_obs_{tag}", f"prod_report_{tag}", target_id
    )
    commission_dict = _commission_dict(
        commission_id=f"comm_{tag}",
        run_id=run_id,
        journal_id=journal_id,
        manifest_hash=events1[0].manifest_hash,
        admission_ref=admission_ref,
        commissioned_by=principal,
        attempt=attempt,
        candidate_id=candidate_id,
        job_id=job_id,
        snapshot_ref=snapshot_ref,
        task_ref=task_ref,
        execution=execution,
        owners=owners,
        idempotency_key=f"idem_{tag}",
    )
    commission_ref = ac.register_attempt(
        channel, ac.AttemptCommission.from_dict(commission_dict)
    )
    return (
        channel,
        producer,
        principal,
        commission_ref,
        commission_dict,
        attempt_id,
        candidate_id,
        job_id,
    )


def _receipt_dict(
    *,
    origin_id: str,
    candidate_id: str,
    job_id: str,
    attempt_id: str,
    attempt_kind: str = "production",
    evidence_scope: str = "current_run",
    signal: str = "verified_receipt",
    provenance: str = "manual_observer",
    authentication: str = "verified",
    correlation: str = "matched",
    trace_correlation: str = "matched",
    matched_by: list[str] | None = None,
    origin_application_id: Any = "app_origin_123",
    origin_revision: Any = "rev_7",
    state: str = "committed",
    coverage: str = "at_boundary",
    verification_policy: dict[str, Any] | None = None,
    authority_seal_ref: Any = None,
    alternate_basis: Any = None,
) -> dict[str, Any]:
    if matched_by is None:
        matched_by = ["candidate_id", "job_id", "origin_id", "attempt_id"]
    if verification_policy is None:
        verification_policy = dict(POLICY)
    if authority_seal_ref is None:
        authority_seal_ref = _missing()
    if alternate_basis is None:
        alternate_basis = _missing()
    return {
        "record_type": "origin_receipt_observation",
        "schema_version": "origin-receipts/0.1.0",
        "origin_id": origin_id,
        "candidate_id": candidate_id,
        "job_id": job_id,
        "attempt_id": attempt_id,
        "attempt_kind": attempt_kind,
        "evidence_scope": evidence_scope,
        "signal": signal,
        "provenance": provenance,
        "authentication": authentication,
        "correlation": correlation,
        "trace_correlation": trace_correlation,
        "matched_by": list(matched_by),
        "origin_application_id": origin_application_id,
        "origin_revision": origin_revision,
        "state": state,
        "coverage": coverage,
        "occurred_at": _timepoint(2.0),
        "received_at": _timepoint(3.0),
        "verification_policy": dict(verification_policy),
        "authority_seal_ref": authority_seal_ref,
        "alternate_basis": alternate_basis,
    }


def _retain_receipt(channel: str, receipt: dict[str, Any]) -> Any:
    payload = json.dumps(
        receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return store.retain_artifact(
        channel, "attempt.application", "application/json", payload, "restricted"
    )


def _is_missing(value: Any) -> bool:
    if isinstance(value, dict):
        keys = set(value.keys())
        return keys in ({"value", "reason"}, {"value", "reason", "detail"}) and value.get(
            "value"
        ) is None
    return hasattr(value, "reason") and getattr(value, "value", "") is None


# ---------------------------------------------------------------------------
# 1. Manual verified production receipt accepted under origin policy
# ---------------------------------------------------------------------------


def test_manual_verified_production_receipt_is_accepted_under_origin_policy():
    tag = "manual_ok"
    (
        channel,
        _producer,
        _principal,
        commission_ref,
        commission_dict,
        attempt_id,
        candidate_id,
        job_id,
    ) = _setup_production_manual(tag)
    target_id = commission_dict["attempt"]["target_id"]
    # Manual mode: dispatch/execution slots stay not_applicable; the recorder
    # journals human actions with manual provenance.
    assert commission_dict["execution"]["mode"] == "manual"
    receipt = _receipt_dict(
        origin_id=target_id,
        candidate_id=candidate_id,
        job_id=job_id,
        attempt_id=attempt_id,
        provenance="manual_observer",
    )
    receipt_ref = _retain_receipt(channel, receipt)
    result = orr.record_origin_receipt(
        channel, commission_ref, receipt_ref, 0, f"cmd_{tag}_1"
    )
    # Accepted: an AxisRevision for the application axis.
    assert not _is_missing(result)
    assert result.axis == "application"
    assert result.revision == 1
    assert result.previous_revision == 0
    assert result.attempt["attempt_id"] == attempt_id
    assert result.attempt["kind"] == "production"
    assert result.commission_digest == commission_ref.digest
    facts = result.value["facts"]
    assert len(facts) == 1
    fact = facts[0]
    assert fact["origin_id"] == target_id
    assert fact["candidate_id"] == candidate_id
    assert fact["job_id"] == job_id
    assert fact["state"] == "committed"
    assert fact["coverage"] == "at_boundary"
    # Production employer facts use verified_origin_receipt.
    assert fact["verification_kind"] == "verified_origin_receipt"
    # Source checks are independently verified under the pinned policy.
    checks = fact["source_checks"]
    assert checks["authentication"] == "verified"
    assert checks["correlation"] == "matched"
    assert checks["trace_correlation"] == "matched"
    assert checks["verification_policy"] == POLICY
    assert checks["matched_by"] != []
    assert len(checks["evidence_refs"]) >= 1
    assert fact["receipt"]["digest"] == receipt_ref.digest
    assert len(fact["evidence_refs"]) >= 1
    # Durable: the owner store holds the same cumulative fact.
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt_id,
        "kind": "production",
    }
    published = orv.read_domain(channel, entity, "application")
    assert not _is_missing(published)
    assert published.revision == 1
    assert published.record["value"]["facts"][0]["fact_id"] == fact["fact_id"]
    # The verification observation was journaled as evidence.
    head = ev.journal_head(channel, commission_dict["journal_id"])
    prefix = ev.JournalPrefix(
        journal_id=head.journal_id,
        last_sequence=head.last_sequence,
        head_hash=head.head_hash,
    )
    events = ev.read_prefix(channel, prefix)
    kinds = [e.event_kind for e in events]
    assert "origin.receipt_observed" in kinds
    last = events[-1]
    assert last.payload["data"]["accepted"] is True


# ---------------------------------------------------------------------------
# 2. HTTP 200 / submit click does not create an origin fact
# ---------------------------------------------------------------------------


def test_http_200_or_submit_click_does_not_create_origin_fact():
    tag = "http200"
    (
        channel,
        _producer,
        _principal,
        commission_ref,
        commission_dict,
        attempt_id,
        candidate_id,
        job_id,
    ) = _setup_production_manual(tag)
    target_id = commission_dict["attempt"]["target_id"]
    for signal in ("http_200", "submit_click"):
        receipt = _receipt_dict(
            origin_id=target_id,
            candidate_id=candidate_id,
            job_id=job_id,
            attempt_id=attempt_id,
            signal=signal,
            # Even with verified transport + matched correlation, the signal
            # alone is insufficient.
            authentication="verified",
            correlation="matched",
        )
        receipt_ref = _retain_receipt(channel, receipt)
        result = orr.record_origin_receipt(
            channel, commission_ref, receipt_ref, 0, f"cmd_{tag}_{signal}"
        )
        assert _is_missing(result), f"signal {signal} must not create a fact"
        assert result["reason"] == "not_observed"
    # No accepted facts means unknown, not noncommitment: no application
    # publication exists.
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt_id,
        "kind": "production",
    }
    published = orv.read_domain(channel, entity, "application")
    assert _is_missing(published)
    # Observations were retained (observation-only recording is not blocked).
    head = ev.journal_head(channel, commission_dict["journal_id"])
    prefix = ev.JournalPrefix(
        journal_id=head.journal_id,
        last_sequence=head.last_sequence,
        head_hash=head.head_hash,
    )
    events = ev.read_prefix(channel, prefix)
    observed = [e for e in events if e.event_kind == "origin.receipt_observed"]
    assert len(observed) == 2
    assert all(e.payload["data"]["accepted"] is False for e in observed)


# ---------------------------------------------------------------------------
# 3. Employer rejection preserves historical application commitment
# ---------------------------------------------------------------------------


def test_employer_rejection_preserves_historical_application_commitment():
    tag = "reject"
    (
        channel,
        _producer,
        _principal,
        commission_ref,
        commission_dict,
        attempt_id,
        candidate_id,
        job_id,
    ) = _setup_production_manual(tag)
    target_id = commission_dict["attempt"]["target_id"]
    committed = _receipt_dict(
        origin_id=target_id,
        candidate_id=candidate_id,
        job_id=job_id,
        attempt_id=attempt_id,
        signal="verified_receipt",
        state="committed",
        coverage="at_boundary",
    )
    committed_ref = _retain_receipt(channel, committed)
    first = orr.record_origin_receipt(
        channel, commission_ref, committed_ref, 0, f"cmd_{tag}_commit"
    )
    assert not _is_missing(first)
    assert len(first.value["facts"]) == 1
    assert first.value["facts"][0]["state"] == "committed"
    first_fact = dict(first.value["facts"][0])

    # A later employer rejection notice is journaled but never erases the
    # historical commitment and is not normalized into not_committed.
    rejection = _receipt_dict(
        origin_id=target_id,
        candidate_id=candidate_id,
        job_id=job_id,
        attempt_id=attempt_id,
        signal="rejection_notice",
        state="not_committed",
        coverage="at_boundary",
        authentication="verified",
        correlation="matched",
    )
    rejection_ref = _retain_receipt(channel, rejection)
    second = orr.record_origin_receipt(
        channel, commission_ref, rejection_ref, 1, f"cmd_{tag}_reject"
    )
    assert _is_missing(second)
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt_id,
        "kind": "production",
    }
    published = orv.read_domain(channel, entity, "application")
    assert not _is_missing(published)
    assert published.revision == 1
    facts = published.record["value"]["facts"]
    assert len(facts) == 1
    assert facts[0] == first_fact
    assert facts[0]["state"] == "committed"
    # The rejection observation is retained in the journal.
    head = ev.journal_head(channel, commission_dict["journal_id"])
    prefix = ev.JournalPrefix(
        journal_id=head.journal_id,
        last_sequence=head.last_sequence,
        head_hash=head.head_hash,
    )
    events = ev.read_prefix(channel, prefix)
    observed = [e for e in events if e.event_kind == "origin.receipt_observed"]
    assert len(observed) == 2
    assert observed[0].payload["data"]["accepted"] is True
    assert observed[1].payload["data"]["accepted"] is False


# ---------------------------------------------------------------------------
# 4. Practice fact cited for production commitment is rejected
# ---------------------------------------------------------------------------


def test_practice_fact_cited_for_production_commitment_is_rejected():
    tag = "practice"
    (
        channel,
        _producer,
        _principal,
        commission_ref,
        commission_dict,
        attempt_id,
        candidate_id,
        job_id,
    ) = _setup_production_manual(tag)
    assert commission_dict["attempt"]["kind"] == "production"
    target_id = commission_dict["attempt"]["target_id"]
    # A practice-scope receipt (or fixture truth) cited for a production
    # attempt must be rejected: lineage never promotes evidence.
    receipt = _receipt_dict(
        origin_id=target_id,
        candidate_id=candidate_id,
        job_id=job_id,
        attempt_id=attempt_id,
        attempt_kind="practice",
        signal="verified_receipt",
        authentication="verified",
        correlation="matched",
    )
    receipt_ref = _retain_receipt(channel, receipt)
    result = orr.record_origin_receipt(
        channel, commission_ref, receipt_ref, 0, f"cmd_{tag}_1"
    )
    assert _is_missing(result)
    assert result["reason"] == "not_observed"
    entity = {
        "entity_type": "application_attempt",
        "attempt_id": attempt_id,
        "kind": "production",
    }
    published = orv.read_domain(channel, entity, "application")
    assert _is_missing(published)
    # Historical / synthetic scopes are likewise rejected as facts.
    for scope in ("historical_unscored", "synthetic"):
        scoped = _receipt_dict(
            origin_id=target_id,
            candidate_id=candidate_id,
            job_id=job_id,
            attempt_id=attempt_id,
            attempt_kind="production",
            evidence_scope=scope,
            signal="verified_receipt",
        )
        scoped_ref = _retain_receipt(channel, scoped)
        scoped_result = orr.record_origin_receipt(
            channel, commission_ref, scoped_ref, 0, f"cmd_{tag}_{scope}"
        )
        assert _is_missing(scoped_result)
    published2 = orv.read_domain(channel, entity, "application")
    assert _is_missing(published2)
