"""Conformance tests for lease_authority (tier 3).

Covers exactly the ``-k`` filter named in the module spec:

- ``lease_expiry_after_possible_submit_preserves_outcome_uncertainty``
- ``stale_lease_completion_has_no_effect_and_failed_generation_counts_once``
- ``authority_restart_fences_old_epoch_without_cross_boot_time_comparison``

Every check exercises the real module against the real evidence journal,
access-policy ingress, and content-addressed artifact store: owner-fenced
claims, journal-derived snapshots, authority-clock expiry, fenced epochs, and
the owner-local atomic commit of state, revision, and evidence.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, rel: Path):
    if name in sys.modules:
        return sys.modules[name]
    try:
        return __import__(name)
    except ModuleNotFoundError:
        pass
    here = Path(__file__).resolve()
    if rel.is_absolute():
        path = rel
    else:
        # tests/ -> module dir -> modules/ -> sibling src
        path = (
            here.parents[1] / rel
            if name == "lease_authority"
            else here.parents[2] / rel
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
ap = _load("access_policy", Path("access_policy/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
la = _load("lease_authority", Path("src/__init__.py"))


OWNER = "job.downstream"
CHANNEL = "ch_lease_authority_0001"
PRODUCER = "prod_lease_authority"
PRINCIPAL = "principal_lease_authority"
JOURNAL = "journal_lease_authority_0001"
RUN = "run_lease_authority_0001"
POLICY_ID = "policy_product_lease"
POLICY_VERSION = "1"
LEASE_DURATION_MS = 300000
MAX_RETRIES = 2
FAILURE_CODE = "generation_failed"
ELIGIBLE_STATE = "claimable"

TASK = la.ResourceReference(
    owner_domain=OWNER,
    entity_type="application_attempt",
    entity_id="attempt_lease_0001",
)
OTHER = la.ResourceReference(
    owner_domain=OWNER,
    entity_type="application_attempt",
    entity_id="attempt_lease_0002",
)


@pytest.fixture(autouse=True)
def _fresh_state():
    la.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    la.reset_for_tests()


def _declare_event_kinds(owner_domain: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for kind, version in la.EVENT_KINDS.items():
        ap.register_event_kind(
            kind,
            version,
            role="lifecycle_observation",
            assertion_kind="authoritative_effect",
            owner_domain=owner_domain,
            writer_roles=("kernel",),
        )
        entries.append(
            {
                "event_kind": kind,
                "event_schema_version": version,
                "role": "lifecycle_observation",
                "assertion_kind": "authoritative_effect",
                "owner_domain": owner_domain,
                "writer_roles": ["kernel"],
            }
        )
    return entries


def _retain(name: str, payload: dict) -> store.ArtifactReference:
    return store.retain_artifact(
        CHANNEL,
        OWNER,
        "application/json",
        json.dumps(payload, sort_keys=True).encode("utf-8"),
        "restricted",
    )


def _manifest(
    task: store.ArtifactReference, config: store.ArtifactReference
) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_lease_authority_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_lease_authority",
        activity="kernel_conformance",
        attempt=ev.NOT_APPLICABLE,
        execution={
            "mode": "service",
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
        },
        task=task,
        task_semantic_hash="sha256:" + "a" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=_declare_event_kinds(OWNER),
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": list(la.EVENT_KINDS),
            }
        ],
        clocks=[
            {
                "clock_id": "clock_lease_journal",
                "boot_id": "boot_lease_journal",
                "origin": "engine_measured",
                "source_id": "src_lease_journal",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _policy() -> la.VersionPin:
    return la.register_policy(
        CHANNEL,
        OWNER,
        POLICY_ID,
        POLICY_VERSION,
        {
            "lease_duration_ms": LEASE_DURATION_MS,
            "max_retries": MAX_RETRIES,
            "failure_code": FAILURE_CODE,
            "eligible_state": ELIGIBLE_STATE,
            "renewal_allowed": True,
        },
    )


def _setup() -> la.VersionPin:
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=tuple(la.EVENT_KINDS),
    )
    task = _retain("task", {"task": "lease-conformance"})
    config = _retain("config", {"config": "lease-conformance"})
    ev.admit_manifest(CHANNEL, _manifest(task, config))
    # The pinned owner policy lives in the resource's owner domain, so the
    # same authenticated channel that leases the resource resolves it.
    return _policy()


def _head() -> ev.JournalPrefix:
    return ev.journal_head(CHANNEL, JOURNAL)


def _claim(resource: la.ResourceReference, policy: la.VersionPin) -> la.LeaseRecord:
    return la.transition_lease(
        CHANNEL, resource, "claim", la.load_lease(CHANNEL, resource), policy
    )


# ---------------------------------------------------------------------------
# Assertion 1: expiry preserves outcome uncertainty
# ---------------------------------------------------------------------------


def test_lease_expiry_after_possible_submit_preserves_outcome_uncertainty():
    policy = _setup()

    # A fresh resource has no lease record; the authority assigns the fencing
    # token and owner epoch, and claiming does not change resource state.
    assert cc.is_missing_envelope(la.load_lease(CHANNEL, TASK))
    lease = _claim(TASK, policy)
    assert lease.lease_state == "held"
    assert lease.lease_owner == PRODUCER  # server-assigned, never caller-supplied
    assert lease.resource_state == lease.eligible_state == ELIGIBLE_STATE
    assert lease.retry_count == 0
    assert lease.last_failure_reason == la.make_missing("not_applicable")
    assert lease.lease_expires_at.monotonic_offset_ms > (
        lease.leased_at.monotonic_offset_ms
    )
    assert lease.journal_prefix.last_sequence >= 2  # admission + clock_registered
    registered = ev.read_prefix(CHANNEL, lease.journal_prefix)
    assert len(registered) >= 2
    clock_events = [
        event for event in registered if event.event_kind == "clock_registered"
    ]
    assert clock_events, "the lease-authority clock must be journal-registered"
    clock_data = clock_events[-1].payload["data"]
    assert clock_data["clock_id"] == lease.leased_at.clock_id
    assert clock_data["boot_id"] == lease.leased_at.boot_id
    assert clock_data["origin"] == lease.leased_at.origin
    assert clock_data["unit"] == "ms"
    assert lease.lease_expires_at.clock_id == lease.leased_at.clock_id
    assert lease.lease_expires_at.boot_id == lease.leased_at.boot_id

    claimed_head = _head()

    # The worker may already have submitted native work; the authority cannot
    # observe that.  Once the authority-clock deadline passes, local commit
    # authority is revoked, but nothing about the employer is asserted.
    la.advance_authority_clock_for_tests(LEASE_DURATION_MS + 1000)
    with pytest.raises(la.LeaseExpiredError):
        la.transition_lease(CHANNEL, TASK, "complete", lease, policy)
    assert _head() == claimed_head  # the stale completion had no effect

    expired = la.transition_lease(CHANNEL, TASK, "expire", lease, policy)
    assert expired.lease_state == "unleased"
    assert expired.generation_id == lease.generation_id
    assert expired.retry_count == 0  # expiry is not a failed generation
    assert expired.last_failure_reason == la.make_missing("not_observed")

    head = _head()
    events = ev.read_prefix(CHANNEL, head)
    assert events[-1].event_kind == "lease_expired"
    data = events[-1].payload["data"]
    assert data["commit_authority"] == "revoked"
    assert data["native_outcome"] == la.make_missing("not_observed")
    assert data["elapsed_downtime"] == la.make_missing("not_observed")
    assert data["employer_noncommitment"] == la.make_missing("not_observed")
    assert data["prior_lease_id"] == lease.lease_id
    assert data["lease"]["lease_state"] == "unleased"
    assert data["lease"]["last_failure_reason"] == la.make_missing("not_observed")
    assert data["lease"]["retry_count"] == 0
    rendered = json.dumps(data, sort_keys=True)
    for forbidden in (
        "not_committed",
        "did_not_commit",
        "cancelled",
        "employer_stopped",
        "native_stopped",
    ):
        assert forbidden not in rendered

    # The expired token never regains local commit authority.
    with pytest.raises((la.LeaseExpiredError, la.LeaseStaleError)):
        la.transition_lease(CHANNEL, TASK, "complete", lease, policy)
    assert _head() == head

    # A new generation proceeds without asserting anything about the old one.
    next_lease = la.transition_lease(CHANNEL, TASK, "claim", expired, policy)
    assert next_lease.lease_state == "held"
    assert next_lease.lease_id != lease.lease_id
    assert next_lease.generation_id != lease.generation_id
    assert next_lease.retry_count == lease.retry_count
    completed = la.transition_lease(CHANNEL, TASK, "complete", next_lease, policy)
    assert completed.lease_state == "unleased"
    assert completed.retry_count == 0
    assert completed.last_failure_reason == la.make_missing("not_applicable")


# ---------------------------------------------------------------------------
# Assertion 2: stale completion has no effect; failures count once
# ---------------------------------------------------------------------------


def test_stale_lease_completion_has_no_effect_and_failed_generation_counts_once():
    policy = _setup()
    lease = _claim(TASK, policy)
    renewed = la.transition_lease(CHANNEL, TASK, "renew", lease, policy)
    assert renewed.lease_id == lease.lease_id
    assert renewed.owner_epoch == lease.owner_epoch
    assert renewed.lease_expires_at.monotonic_offset_ms > (
        lease.lease_expires_at.monotonic_offset_ms
    )

    # A claim must not displace an unexpired lease; claiming still does not
    # change resource state.
    busy_head = _head()
    with pytest.raises(la.LeaseBusyError):
        la.transition_lease(CHANNEL, TASK, "claim", renewed, policy)
    assert _head() == busy_head
    assert la.load_lease(CHANNEL, TASK) == renewed

    head = _head()
    stale = dataclasses.replace(renewed, lease_id="lease_forged_stale")
    forged_epoch = dataclasses.replace(
        renewed, owner_epoch="lease_owner_epoch_forged"
    )
    forged_deadline = dataclasses.replace(
        renewed,
        lease_expires_at=la.TimePoint(
            clock_id=renewed.lease_expires_at.clock_id,
            boot_id=renewed.lease_expires_at.boot_id,
            origin=renewed.lease_expires_at.origin,
            monotonic_offset_ms=renewed.lease_expires_at.monotonic_offset_ms
            + 10_000_000,
        ),
    )
    with pytest.raises(la.LeaseStaleError):
        la.transition_lease(CHANNEL, TASK, "complete", stale, policy)
    with pytest.raises(la.LeaseStaleError):
        la.transition_lease(CHANNEL, TASK, "complete", forged_epoch, policy)
    with pytest.raises(la.LeaseStaleError):
        la.transition_lease(CHANNEL, TASK, "complete", forged_deadline, policy)
    assert _head() == head
    assert la.load_lease(CHANNEL, TASK) == renewed

    # The fenced completion gate refuses a non-current token, owner epoch, or
    # revision.
    now = la.authority_now()
    with pytest.raises(la.LeaseStaleError):
        la.validate_completion(
            stale, renewed, now, renewed.entity_revision, renewed.input_revision
        )
    with pytest.raises(la.LeaseStaleError):
        la.validate_completion(
            forged_epoch,
            renewed,
            now,
            renewed.entity_revision,
            renewed.input_revision,
        )
    with pytest.raises(la.LeaseStaleError):
        la.validate_completion(
            forged_deadline,
            renewed,
            now,
            renewed.entity_revision,
            renewed.input_revision,
        )
    with pytest.raises(la.LeaseRevisionConflictError):
        la.validate_completion(
            renewed, renewed, now, renewed.entity_revision + 1, renewed.input_revision
        )
    with pytest.raises(la.LeaseRevisionConflictError):
        la.validate_completion(
            renewed, renewed, now, renewed.entity_revision, renewed.input_revision + 1
        )
    la.validate_completion(
        renewed, renewed, now, renewed.entity_revision, renewed.input_revision
    )

    # A failed generation increments retries exactly once.
    failed = la.transition_lease(CHANNEL, TASK, "fail_generation", renewed, policy)
    assert failed.lease_state == "unleased"
    assert failed.retry_count == 1
    assert failed.last_failure_reason == FAILURE_CODE
    assert failed.generation_id == renewed.generation_id
    failed_head = _head()

    with pytest.raises(la.LeaseStaleError):
        la.transition_lease(CHANNEL, TASK, "fail_generation", renewed, policy)
    assert _head() == failed_head
    assert la.load_lease(CHANNEL, TASK) == failed

    # Even a caller caught up to the failed snapshot cannot count it twice.
    with pytest.raises(la.LeaseFailureAlreadyCountedError):
        la.transition_lease(CHANNEL, TASK, "fail_generation", failed, policy)
    assert _head() == failed_head
    assert la.load_lease(CHANNEL, TASK).retry_count == 1

    # The next generation counts its own failure once and carries the total.
    second = la.transition_lease(CHANNEL, TASK, "claim", failed, policy)
    assert second.retry_count == 1
    assert second.generation_id != failed.generation_id
    second_failed = la.transition_lease(CHANNEL, TASK, "fail_generation", second, policy)
    assert second_failed.retry_count == 2
    assert second_failed.max_retries_effective == MAX_RETRIES  # pinned, not default

    # Retries are bounded by the pinned owner policy.
    exhausted_head = _head()
    with pytest.raises(la.LeaseRetriesExhaustedError):
        la.transition_lease(CHANNEL, TASK, "claim", second_failed, policy)
    assert _head() == exhausted_head

    # A completion after the authority deadline is refused, not inferred away.
    other = _claim(OTHER, policy)
    la.advance_authority_clock_for_tests(LEASE_DURATION_MS + 1)
    with pytest.raises(la.LeaseExpiredError):
        la.validate_completion(
            other,
            other,
            la.authority_now(),
            other.entity_revision,
            other.input_revision,
        )


# ---------------------------------------------------------------------------
# Assertion 3: restart fences the old epoch, no cross-boot comparison
# ---------------------------------------------------------------------------


def test_authority_restart_fences_old_epoch_without_cross_boot_time_comparison():
    policy = _setup()
    lease_a = _claim(TASK, policy)
    old_epoch = lease_a.authority_epoch
    old_clock_id = lease_a.leased_at.clock_id
    old_boot_id = lease_a.leased_at.boot_id
    assert lease_a.lease_expires_at.monotonic_offset_ms > (
        lease_a.leased_at.monotonic_offset_ms
    )
    claim_a_head = _head()

    # The old deadline is far in the old boot's future coordinates.
    la.advance_authority_clock_for_tests(1000)
    fence = la.restart_authority(CHANNEL, OWNER)
    assert fence.event_kind == "authority_epoch_fenced"
    fence_data = fence.payload["data"]
    assert fence_data["fenced_authority_epoch"] == old_epoch
    assert fence_data["fenced_clock_id"] == old_clock_id
    assert fence_data["fenced_boot_id"] == old_boot_id
    new_epoch = la.authority_epoch()
    now = la.authority_now()
    assert new_epoch != old_epoch
    assert fence_data["new_authority_epoch"] == new_epoch
    assert fence_data["new_clock_id"] == now.clock_id
    assert fence_data["new_boot_id"] == now.boot_id
    assert fence_data["downtime"] == la.make_missing("not_observed")
    assert fence_data["native_outcome"] == la.make_missing("not_observed")
    assert fence_data["commit_authority"] == "revoked"

    # New-boot offsets restart near zero, so a naive numeric comparison would
    # call the old lease unexpired.  The epoch fence forbids that comparison.
    assert (now.clock_id, now.boot_id) != (old_clock_id, old_boot_id)
    assert now.monotonic_offset_ms < lease_a.lease_expires_at.monotonic_offset_ms

    head_after_fence = _head()
    assert head_after_fence.last_sequence == claim_a_head.last_sequence + 2
    fenced_events = ev.read_prefix(CHANNEL, head_after_fence)
    assert [event.event_kind for event in fenced_events][-2:] == [
        "clock_registered",
        "authority_epoch_fenced",
    ]

    # The old epoch is fenced: the old lease cannot complete and nothing moves.
    with pytest.raises(la.LeaseFencedError):
        la.transition_lease(CHANNEL, TASK, "complete", lease_a, policy)
    assert _head() == head_after_fence

    # Even an authority time built on the old clock cannot resurrect the lease;
    # a new-boot time is refused before any offsets are subtracted.
    old_boot_now = la.TimePoint(
        clock_id=old_clock_id,
        boot_id=old_boot_id,
        origin="engine_measured",
        monotonic_offset_ms=float(lease_a.leased_at.monotonic_offset_ms) + 2.0,
    )
    with pytest.raises(la.LeaseFencedError):
        la.validate_completion(
            lease_a,
            lease_a,
            old_boot_now,
            lease_a.entity_revision,
            lease_a.input_revision,
        )
    with pytest.raises(la.LeaseClockMismatchError):
        la.validate_completion(
            lease_a,
            lease_a,
            la.authority_now(),
            lease_a.entity_revision,
            lease_a.input_revision,
        )

    # Reclaiming under the new epoch succeeds despite the numerically
    # "unexpired" old deadline: no cross-boot comparison happened.
    lease_b = la.transition_lease(CHANNEL, TASK, "claim", lease_a, policy)
    assert lease_b.lease_id != lease_a.lease_id
    assert lease_b.owner_epoch != lease_a.owner_epoch
    assert lease_b.generation_id != lease_a.generation_id
    assert lease_b.authority_epoch == new_epoch
    assert (lease_b.leased_at.clock_id, lease_b.leased_at.boot_id) == (
        now.clock_id,
        now.boot_id,
    )
    assert lease_b.lease_expires_at.monotonic_offset_ms > (
        lease_b.leased_at.monotonic_offset_ms
    )

    # The durable fence precedes the reclaim in the hash chain.
    head_b = _head()
    events_b = ev.read_prefix(CHANNEL, head_b)
    fence_sequence = next(
        event.journal_sequence
        for event in events_b
        if event.event_id == fence.event_id
    )
    claim_b_sequence = next(
        event.journal_sequence
        for event in events_b
        if event.event_kind == "lease_claimed"
        and event.payload["data"]["lease"]["lease_id"] == lease_b.lease_id
    )
    assert fence_sequence < claim_b_sequence

    # The old snapshot keeps its old clock coordinates; nothing is rewritten.
    old_event = next(
        event
        for event in events_b
        if event.event_kind == "lease_claimed"
        and event.payload["data"]["lease"]["lease_id"] == lease_a.lease_id
    )
    old_snapshot = old_event.payload["data"]["lease"]
    assert old_snapshot["leased_at"]["clock_id"] == old_clock_id
    assert old_snapshot["leased_at"]["boot_id"] == old_boot_id
    assert old_snapshot["lease_expires_at"] == lease_a.lease_expires_at.to_dict()
    assert la.load_lease(CHANNEL, TASK) == lease_b
