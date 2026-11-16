"""Conformance tests for owner_revisions (tier 4).

Covers exactly the ``-k`` filter named in the module spec:

- ``downstream_revision_race_rejects_stale_update_without_lost_fields``
- ``peer_writer_blocked_other_owner_still_acknowledges_independently``
- ``dispatch_and_observation_allow_only_declared_transitions``
- ``cumulative_claim_and_fact_histories_never_drop_or_rewrite_prior_entries``
- ``report_input_pins_never_regress_between_publications``

Every check exercises the real module: immutable authenticated registration,
complete owner revisions, stale revision rejection, declared lifecycle
transitions, cumulative claim/fact preservation, report pin monotonicity, and
independent owner acknowledgements.
"""

from __future__ import annotations

import copy
import importlib.util
import sys
import threading
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "owner_revisions":
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
la = _load("lease_authority")
orv = _load("owner_revisions")


D0 = "sha256:" + "0" * 64
D1 = "sha256:" + "1" * 64
D2 = "sha256:" + "2" * 64
D3 = "sha256:" + "3" * 64
POLICY = {"id": "policy_test", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_owner_test"
BOOT_ID = "boot_owner_test"


@pytest.fixture(autouse=True)
def _fresh_state():
    orv.reset_for_tests()
    ev.reset_for_tests()
    la.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    la.reset_for_tests()
    ev.reset_for_tests()
    orv.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _timepoint(offset: float) -> dict[str, Any]:
    return {
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing("not_observed"),
    }


def _evidence_ref(tag: str, sequence: int = 1) -> dict[str, Any]:
    return {
        "journal_id": f"journal_{tag}",
        "sequence": sequence,
        "event_id": f"event_{tag}",
        "event_hash": D1,
        "pointer": "",
    }


def _artifact_dict(
    digest: str = D1,
    owner_domain: str = "job.downstream",
    access: str = "public",
) -> dict[str, Any]:
    return {
        "digest": digest,
        "size_bytes": 1,
        "media_type": "application/json",
        "owner_domain": owner_domain,
        "access": access,
    }


def _register(
    actor: str,
    channel_id: str,
    axis: str,
    producer_id: str,
    principal_id: str,
    *,
    binding: str | None = None,
    kinds: tuple[str, ...] | None = None,
) -> Any:
    kwargs: dict[str, Any] = {
        "actor": actor,
        "channel_id": channel_id,
        "axis": axis,
        "producer_id": producer_id,
        "principal_id": principal_id,
        "sequence_required": False,
        "allowed_event_kinds": kinds or (f"{axis}.published",),
    }
    if binding is not None:
        kwargs["binding"] = binding
    return ap.register_channel(**kwargs)


# -- job downstream journal fixture (real admitted evidence journal) ---------


def _product_journal() -> tuple[str, str, dict[str, Any], dict[str, Any]]:
    channel = "ch_owner_product_0001"
    producer = "prod_owner_product_0001"
    principal = "principal_owner_product_0001"
    kind = "product.published"
    _register(
        "product_writer",
        channel,
        "job.downstream",
        producer,
        principal,
        kinds=(kind,),
    )
    ap.register_event_kind(
        kind,
        "1",
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain="job.downstream",
        writer_roles=("kernel",),
    )
    task = store.retain_artifact(
        channel,
        "job.downstream",
        "application/json",
        b'{"task":"owner-revision-task"}',
        "restricted",
    )
    config = store.retain_artifact(
        channel,
        "job.downstream",
        "application/json",
        b'{"config":"owner-revision-config"}',
        "restricted",
    )
    manifest = ev.Manifest(
        manifest_id="manifest_owner_product_0001",
        run_id="run_owner_product_0001",
        journal_id="journal_owner_product_0001",
        owner_domain="job.downstream",
        commissioner_id="commissioner_owner_product",
        activity="discovery",
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
        task_semantic_hash=D0,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=[
            {
                "event_kind": kind,
                "event_schema_version": "1",
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": producer,
                "principal_id": principal,
                "owner_domain": "job.downstream",
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": [kind],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_owner_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    admission = ev.admit_manifest(channel, manifest)
    prefix = {
        "journal_id": admission.journal_id,
        "last_sequence": 1,
        "head_hash": admission.event_hash,
    }
    first_ref = {
        "journal_id": admission.journal_id,
        "sequence": 1,
        "event_id": admission.event_id,
        "event_hash": admission.event_hash,
        "pointer": "",
    }
    return channel, producer, prefix, first_ref


def _job_registration(
    producer: str, prefix: dict[str, Any], first_ref: dict[str, Any]
) -> Any:
    return orv.EntityRegistration(
        registration_id="reg_owner_job_0001",
        entity={"entity_type": "job", "target": "target_owner", "job_id": "job_owner"},
        identity={
            "portfolio_job_id": "portfolio_owner_1",
            "first_discovery_ref": first_ref,
        },
        owners={
            "crawler": {
                "role": "crawler",
                "source_id": "src_owner_crawler",
                "writer_id": "prod_owner_crawler",
                "owner_domain": "job.crawler",
                "publication_policy": POLICY,
            },
            "downstream": {
                "role": "product",
                "source_id": "src_owner_product",
                "writer_id": producer,
                "owner_domain": "job.downstream",
                "publication_policy": POLICY,
            },
        },
        evidence_prefix=prefix,
        evidence_refs=[first_ref],
    )


def _material(material_id: str, digest: str = D2) -> dict[str, Any]:
    return {
        "artifact_id": material_id,
        "role": "resume",
        "content": _artifact_dict(digest=digest, owner_domain="job.downstream"),
        "evidence_refs": [_evidence_ref(material_id)],
    }


def _downstream_value(
    *,
    track: str,
    priority: Any,
    materials: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "track": track,
        "priority_hint": priority,
        "selection": _missing("not_observed"),
        "ownership": {
            "state": "unclaimed",
            "claimant": _missing("not_applicable"),
            "lease": _missing("not_applicable"),
            "evidence_refs": [_evidence_ref("ownership")],
        },
        "evaluations": [],
        "materials": materials,
        "application_attempts": [],
    }


def _downstream_revision(
    *,
    registration_digest: str,
    writer_id: str,
    revision: int,
    prefix: dict[str, Any],
    value: dict[str, Any],
) -> Any:
    return orv.DataDomainRevision(
        entity={
            "entity_type": "job",
            "target": "target_owner",
            "job_id": "job_owner",
        },
        registration_digest=registration_digest,
        domain="downstream",
        owner_domain="job.downstream",
        writer_id=writer_id,
        revision=revision,
        previous_revision=revision - 1,
        evidence_prefix=prefix,
        evidence_refs=[_evidence_ref(f"downstream_{revision}", revision + 1)],
        value=value,
    )


# -- attempt fixture ---------------------------------------------------------


class AttemptFixture:
    def __init__(self) -> None:
        self.channels = {
            "dispatch": "ch_owner_dispatch_0001",
            "observation": "ch_owner_observation_0001",
            "execution": "ch_owner_execution_0001",
            "application": "ch_owner_application_0001",
            "report": "ch_owner_report_0001",
        }
        self.writers = {
            "dispatch": "prod_owner_dispatch_0001",
            "observation": "prod_owner_observation_0001",
            "execution": "prod_owner_execution_0001",
            "application": "prod_owner_application_0001",
            "report": "prod_owner_report_0001",
        }
        self.owner_domains = {
            "dispatch": "attempt.dispatch",
            "observation": "attempt.observation",
            "execution": "attempt.execution",
            "application": "attempt.application",
            "report": "attempt.report",
        }
        self.entity = {
            "entity_type": "application_attempt",
            "attempt_id": "attempt_owner_1",
            "kind": "production",
        }
        self.prefix = {
            "journal_id": "journal_owner_attempt_evidence",
            "last_sequence": 1,
            "head_hash": D1,
        }
        self.registration: Any = None
        self.registration_ref: Any = None
        self.commission: Any = None

    def register_channels(self) -> None:
        _register(
            "connector",
            self.channels["dispatch"],
            self.owner_domains["dispatch"],
            self.writers["dispatch"],
            "principal_owner_dispatch",
            binding="bind_owner_dispatch",
        )
        _register(
            "connector",
            self.channels["observation"],
            self.owner_domains["observation"],
            self.writers["observation"],
            "principal_owner_observation",
            binding="bind_owner_observation",
        )
        _register(
            "subject_adapter",
            self.channels["execution"],
            self.owner_domains["execution"],
            self.writers["execution"],
            "principal_owner_execution",
        )
        _register(
            "origin_fact_recorder",
            self.channels["application"],
            self.owner_domains["application"],
            self.writers["application"],
            "principal_owner_application",
            binding="bind_owner_application",
        )
        _register(
            "reconciler",
            self.channels["report"],
            self.owner_domains["report"],
            self.writers["report"],
            "principal_owner_report",
        )

    def setup(self) -> "AttemptFixture":
        self.register_channels()
        self.commission = store.retain_artifact(
            self.channels["dispatch"],
            self.owner_domains["dispatch"],
            "application/json",
            b'{"commission":"owner-attempt-1"}',
            "public",
        )
        self.registration = orv.EntityRegistration(
            registration_id="reg_owner_attempt_0001",
            entity=self.entity,
            identity={
                "commission": self.commission.to_dict(),
                "attempt": {
                    "attempt_id": "attempt_owner_1",
                    "kind": "production",
                    "target_class": "employer_origin",
                    "target_id": "target_owner",
                    "evaluation_partition": "held_out",
                    "rehearsal_of": [],
                    "performance_of": [],
                    "derived_from": [],
                },
                "execution": {
                    "mode": "subject",
                    "subject": {"subject_id": "subject_owner_1"},
                    "connector_version": "1",
                    "binding_version": "1",
                    "assistance": {
                        "planning_owner": "none",
                        "assistance_track": "no_assistance",
                        "planner_identity": _missing(),
                        "plan": _missing(),
                        "online_replanning": False,
                        "description": "No assistance is declared.",
                    },
                },
            },
            owners={
                "dispatch": {
                    "role": "connector",
                    "source_id": "src_owner_connector",
                    "writer_id": self.writers["dispatch"],
                    "owner_domain": self.owner_domains["dispatch"],
                    "publication_policy": POLICY,
                },
                "observation": {
                    "role": "connector",
                    "source_id": "src_owner_connector",
                    "writer_id": self.writers["observation"],
                    "owner_domain": self.owner_domains["observation"],
                    "publication_policy": POLICY,
                },
                "execution": {
                    "role": "subject",
                    "source_id": "subject_owner_1",
                    "writer_id": self.writers["execution"],
                    "owner_domain": self.owner_domains["execution"],
                    "publication_policy": POLICY,
                },
                "application": {
                    "role": "origin",
                    "source_id": "target_owner",
                    "writer_id": self.writers["application"],
                    "owner_domain": self.owner_domains["application"],
                    "publication_policy": POLICY,
                },
                "report": {
                    "role": "reconciler",
                    "source_id": "src_owner_reconciler",
                    "writer_id": self.writers["report"],
                    "owner_domain": self.owner_domains["report"],
                    "publication_policy": POLICY,
                },
            },
            evidence_prefix=self.prefix,
            evidence_refs=[_evidence_ref("attempt_registration")],
        )
        self.registration_ref = orv.register_entity(
            self.channels["dispatch"], self.registration
        )
        return self

    def axis_revision(
        self,
        axis: str,
        revision: int,
        value: dict[str, Any],
        *,
        writer: str | None = None,
    ) -> Any:
        return orv.AxisRevision(
            attempt={
                "attempt_id": self.entity["attempt_id"],
                "kind": self.entity["kind"],
            },
            commission_digest=self.commission.digest,
            axis=axis,
            owner_domain=self.owner_domains[axis],
            writer_id=writer or self.writers[axis],
            revision=revision,
            previous_revision=revision - 1,
            evidence_prefix=self.prefix,
            evidence_refs=[_evidence_ref(f"{axis}_{revision}", revision + 1)],
            value=value,
        )

    def commit(
        self, axis: str, revision: int, value: dict[str, Any], command: str
    ) -> Any:
        return orv.commit_domain(
            self.channels[axis],
            self.registration,
            self.axis_revision(axis, revision, value),
            command,
            _missing(),
        )


def _dispatch_value(
    state: str,
    *,
    handle: Any = None,
    request_digest: Any = None,
    delivery: list[dict[str, Any]] | None = None,
    acceptance: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "state": state,
        "local_handle": handle if handle is not None else _missing(),
        "native_run_id": _missing("not_observed"),
        "request_digest": request_digest if request_digest is not None else _missing(),
        "delivery_refs": list(delivery or []),
        "acceptance_refs": list(acceptance or []),
        "recovery_authorization_refs": [],
        "reason": _missing(),
    }


def _close_snapshot() -> dict[str, Any]:
    return {
        "closure_id": "closure_owner_1",
        "boundary_ref": _evidence_ref("close_boundary", sequence=2),
        "known_versions": {
            "dispatch": {"revision": 0, "record_digest": _missing("not_observed")},
            "execution": {"revision": 0, "record_digest": _missing("not_observed")},
            "application": {
                "revision": 0,
                "record_digest": _missing("not_observed"),
            },
            "report": {"revision": 0, "record_digest": _missing("not_observed")},
        },
        "execution_knowledge": "unknown",
        "execution_evidence_refs": [],
        "application_knowledge": "unknown",
        "application_evidence_refs": [],
        "limitations": ["No close-time facts are available."],
    }


def _observation_value(
    state: str,
    *,
    drain: bool = False,
    measurements: list[dict[str, Any]] | None = None,
    closed_at: Any = None,
    close_reason: Any = None,
    at_close: Any = None,
) -> dict[str, Any]:
    opened = state in ("open", "draining", "closed")
    return {
        "state": state,
        "window_id": "window_owner_1",
        "opened_at": _timepoint(100.0) if opened else _missing(),
        "active_deadline": _timepoint(200.0) if opened else _missing(),
        "drain_started_at": _timepoint(150.0)
        if drain
        else _missing(),
        "drain_deadline": _timepoint(250.0) if drain else _missing(),
        "closed_at": closed_at if closed_at is not None else _missing(),
        "close_reason": close_reason if close_reason is not None else _missing(),
        "at_close": at_close if at_close is not None else _missing(),
        "control_observations": [],
        "late_evidence_refs": [],
        "measurements": list(measurements or []),
    }


def _claim(claim_id: str, state: Any, scope: str = "primitive") -> dict[str, Any]:
    return {
        "claim_id": claim_id,
        "scope": scope,
        "state": state,
        "evidence_refs": [_evidence_ref(claim_id)],
    }


def _fact(fact_id: str, state: str, coverage: str) -> dict[str, Any]:
    return {
        "fact_id": fact_id,
        "origin_id": "origin_owner_1",
        "candidate_id": "candidate_owner_1",
        "job_id": "job_owner",
        "state": state,
        "coverage": coverage,
        "evidence_refs": [_evidence_ref(fact_id)],
    }


def _pins(**revisions: tuple[int, Any]) -> dict[str, Any]:
    pins: dict[str, Any] = {}
    for axis, (revision, digest) in revisions.items():
        pins[axis] = {
            "revision": revision,
            "record_digest": digest if revision else _missing("not_observed"),
        }
    return pins


def _report_value(
    pins: dict[str, Any],
    *,
    comparisons: list[dict[str, Any]] | None = None,
    state: Any = "reconciled",
    coverage: str = "complete",
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "state": state,
        "coverage": coverage,
        "inputs": pins,
        "evaluator": POLICY,
        "comparisons": list(comparisons or []),
        "issues": [],
        "limitations": list(limitations or []),
        "diagnostic": _missing("not_observed"),
    }


# ---------------------------------------------------------------------------
# 1. Downstream revision race
# ---------------------------------------------------------------------------


def test_downstream_revision_race_rejects_stale_update_without_lost_fields():
    channel, producer, prefix, first_ref = _product_journal()
    registration = _job_registration(producer, prefix, first_ref)
    registration_ref = orv.register_entity(channel, registration)
    entity = registration.entity

    material = _material("material_owner_1")
    base_value = _downstream_value(
        track="review", priority=0.5, materials=[material]
    )
    base_revision = _downstream_revision(
        registration_digest=registration_ref.digest,
        writer_id=producer,
        revision=1,
        prefix=prefix,
        value=base_value,
    )
    base_ref = orv.commit_domain(
        channel, registration, base_revision, "cmd_owner_base", _missing()
    )
    assert orv.domain_head(channel, entity, "downstream") == 1
    assert (
        ev.entity_state(
            channel, "job.downstream", "job.target_owner.job_owner"
        ).revision
        == 1
    )

    winner_value = _downstream_value(
        track="go",
        priority=0.9,
        materials=[_material("material_owner_winner", D2)],
    )
    loser_value = _downstream_value(
        track="no_go",
        priority=0.1,
        materials=[_material("material_owner_loser", D3)],
    )
    barrier = threading.Barrier(2)
    results: list[tuple[str, str, Any]] = []
    lock = threading.Lock()

    def race(tag: str, value: dict[str, Any]) -> None:
        revision = _downstream_revision(
            registration_digest=registration_ref.digest,
            writer_id=producer,
            revision=2,
            prefix=prefix,
            value=value,
        )
        barrier.wait()
        try:
            reference = orv.commit_domain(
                channel, registration, revision, f"cmd_owner_{tag}", _missing()
            )
            outcome: tuple[str, str, Any] = ("ok", tag, reference)
        except Exception as exc:  # noqa: BLE001 - asserted below
            outcome = ("error", tag, exc)
        with lock:
            results.append(outcome)

    threads = [
        threading.Thread(target=race, args=("winner", winner_value)),
        threading.Thread(target=race, args=("loser", loser_value)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert all(not thread.is_alive() for thread in threads)

    successes = [item for item in results if item[0] == "ok"]
    failures = [item for item in results if item[0] == "error"]
    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(
        failures[0][2], (orv.StaleRevisionError, orv.RevisionIntegrityError)
    )
    winning_tag = successes[0][1]
    expected_value = winner_value if winning_tag == "winner" else loser_value

    head = orv.read_domain(channel, entity, "downstream")
    assert not isinstance(head, dict)
    assert head.revision == 2
    assert head.previous_revision == 1
    journal_row = ev.entity_state(channel, "job.downstream", "job.target_owner.job_owner")
    assert journal_row.revision == 2
    assert journal_row.state.digest == head.content_digest
    # The rejected stale write contributed nothing: the committed snapshot is
    # byte-for-byte the winning proposal, never a field merge.
    assert head.value == expected_value
    assert set(head.value) == {
        "track",
        "priority_hint",
        "selection",
        "ownership",
        "evaluations",
        "materials",
        "application_attempts",
    }
    losing_tag = "loser" if winning_tag == "winner" else "winner"
    losing_value = loser_value if losing_tag == "loser" else winner_value
    if losing_value["track"] != expected_value["track"]:
        assert head.value["track"] != losing_value["track"]

    # A later writer can base a new complete snapshot on the surviving head
    # without any field having been lost by the rejected race.
    next_value = copy.deepcopy(head.value)
    next_value["track"] = "review"
    next_value["priority_hint"] = 0.75
    next_revision = _downstream_revision(
        registration_digest=registration_ref.digest,
        writer_id=producer,
        revision=3,
        prefix=prefix,
        value=next_value,
    )
    next_ref = orv.commit_domain(
        channel, registration, next_revision, "cmd_owner_next", _missing()
    )
    final_head = orv.read_domain(channel, entity, "downstream")
    assert not isinstance(final_head, dict)
    assert final_head.revision == 3
    assert final_head.value["materials"] == expected_value["materials"]
    assert final_head.value["evaluations"] == expected_value["evaluations"]
    assert final_head.value["ownership"] == expected_value["ownership"]
    assert final_head.value["application_attempts"] == []
    assert set(final_head.record) == {
        "record_type",
        "schema_version",
        "entity",
        "registration_digest",
        "domain",
        "owner_domain",
        "writer_id",
        "revision",
        "previous_revision",
        "evidence_prefix",
        "evidence_refs",
        "value",
    }
    final_journal = ev.entity_state(
        channel, "job.downstream", "job.target_owner.job_owner"
    )
    assert final_journal.revision == 3
    assert final_journal.state.digest == final_head.content_digest

    # A stale proposal at the current key with different bytes is an integrity
    # conflict; an identical retry is idempotent.
    stale_again = _downstream_revision(
        registration_digest=registration_ref.digest,
        writer_id=producer,
        revision=2,
        prefix=prefix,
        value=losing_value,
    )
    with pytest.raises(
        (orv.StaleRevisionError, orv.RevisionIntegrityError)
    ):
        orv.commit_domain(
            channel, registration, stale_again, "cmd_owner_stale_again", _missing()
        )
    replay = orv.commit_domain(
        channel, registration, next_revision, "cmd_owner_replay", _missing()
    )
    assert replay.digest == next_ref.digest
    assert orv.domain_head(channel, entity, "downstream") == 3
    assert base_ref.digest != next_ref.digest


# ---------------------------------------------------------------------------
# 2. Peer writer independence
# ---------------------------------------------------------------------------


def test_peer_writer_blocked_other_owner_still_acknowledges_independently(
    monkeypatch,
):
    fixture = AttemptFixture().setup()
    entity = fixture.entity

    original_retain = store.retain_artifact
    entered = threading.Event()
    release = threading.Event()
    block_enabled = threading.Event()
    block_enabled.set()

    def blocking_retain(
        channel_id: str,
        owner_domain: str,
        media_type: str,
        content: bytes,
        access: str,
    ):
        if (
            block_enabled.is_set()
            and owner_domain == fixture.owner_domains["application"]
        ):
            entered.set()
            if not release.wait(10):
                raise AssertionError("peer block was never released")
        return original_retain(channel_id, owner_domain, media_type, content, access)

    monkeypatch.setattr(store, "retain_artifact", blocking_retain)

    application_revision = fixture.axis_revision(
        "application",
        1,
        {"facts": [_fact("fact_peer_1", "committed", "at_boundary")]},
    )
    outcome: dict[str, Any] = {}

    def blocked_peer_commit() -> None:
        try:
            outcome["reference"] = orv.commit_domain(
                fixture.channels["application"],
                fixture.registration,
                application_revision,
                "cmd_peer_application",
                _missing(),
            )
        except Exception as exc:  # noqa: BLE001 - asserted below
            outcome["error"] = exc

    peer = threading.Thread(target=blocked_peer_commit)
    peer.start()
    assert entered.wait(5), "the peer writer never reached its payload commit"

    # The peer owner is blocked inside its own commit.  A different owner must
    # still acknowledge independently; no global or peer lock may be held.
    report_revision = fixture.axis_revision(
        "report",
        1,
        _report_value(
            _pins(
                dispatch=(0, None),
                observation=(0, None),
                execution=(0, None),
                application=(0, None),
            ),
            state=_missing("not_observed"),
            coverage="incomplete",
            comparisons=[],
            limitations=["The peer application publication is still in flight."],
        ),
    )
    assert not release.is_set()
    report_outcome: dict[str, Any] = {}
    report_done = threading.Event()

    def independent_report_commit() -> None:
        try:
            report_outcome["reference"] = orv.commit_domain(
                fixture.channels["report"],
                fixture.registration,
                report_revision,
                "cmd_peer_report",
                _missing(),
            )
        except Exception as exc:  # noqa: BLE001 - asserted below
            report_outcome["error"] = exc
        finally:
            report_done.set()

    report_thread = threading.Thread(target=independent_report_commit)
    report_thread.start()
    independent = report_done.wait(5)
    # Never leave the blocked peer holding the test forever on a regression.
    blocked_still = not release.is_set()
    if not independent:
        release.set()
    report_thread.join(timeout=10)
    assert independent, "another owner waited for the blocked peer"
    assert blocked_still, "the independent owner returned only after release"
    assert "error" not in report_outcome, report_outcome.get("error")
    report_ref = report_outcome["reference"]
    assert orv.domain_head(fixture.channels["report"], entity, "report") == 1
    assert "error" not in outcome

    release.set()
    peer.join(timeout=10)
    assert not peer.is_alive()
    assert not report_thread.is_alive()
    assert "error" not in outcome, outcome.get("error")
    assert outcome["reference"].digest
    assert (
        orv.domain_head(fixture.channels["application"], entity, "application") == 1
    )
    assert report_ref.digest


# ---------------------------------------------------------------------------
# 3. Declared dispatch / observation transitions
# ---------------------------------------------------------------------------


def test_dispatch_and_observation_allow_only_declared_transitions():
    fixture = AttemptFixture().setup()
    entity = fixture.entity

    prepared = _dispatch_value("prepared", request_digest=D1)
    fixture.commit("dispatch", 1, prepared, "cmd_dispatch_prepared")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 1

    with pytest.raises(orv.TransitionRejectedError):
        fixture.commit("dispatch", 2, prepared, "cmd_dispatch_prepared_again")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 1

    accepted = _dispatch_value(
        "accepted",
        handle="handle_owner_1",
        request_digest=D1,
        delivery=[_evidence_ref("dispatch_delivery", 2)],
        acceptance=[_evidence_ref("dispatch_acceptance", 3)],
    )
    with pytest.raises(orv.TransitionRejectedError):
        fixture.commit("dispatch", 2, accepted, "cmd_dispatch_skip_to_accepted")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 1

    dispatching = _dispatch_value(
        "dispatching",
        handle="handle_owner_1",
        request_digest=D1,
        delivery=[_evidence_ref("dispatch_delivery", 2)],
    )
    fixture.commit("dispatch", 2, dispatching, "cmd_dispatch_dispatching")
    fixture.commit("dispatch", 3, accepted, "cmd_dispatch_accepted")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 3

    with pytest.raises(orv.TransitionRejectedError):
        fixture.commit("dispatch", 4, prepared, "cmd_dispatch_reopen")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 3

    accepted_again = copy.deepcopy(accepted)
    accepted_again["acceptance_refs"] = [
        _evidence_ref("dispatch_acceptance_second", 4)
    ]
    fixture.commit("dispatch", 4, accepted_again, "cmd_dispatch_accepted_evidence")
    assert orv.domain_head(fixture.channels["dispatch"], entity, "dispatch") == 4

    open_value = _observation_value("open")
    fixture.commit("observation", 1, open_value, "cmd_observation_open")
    draining = _observation_value(
        "draining", drain=True, close_reason="operator_stop"
    )
    fixture.commit("observation", 2, draining, "cmd_observation_draining")
    closed = _observation_value(
        "closed",
        drain=True,
        close_reason="normal_completion",
        closed_at=_timepoint(300.0),
        at_close=_close_snapshot(),
    )
    fixture.commit("observation", 3, closed, "cmd_observation_closed")
    assert orv.domain_head(fixture.channels["observation"], entity, "observation") == 3

    with pytest.raises(orv.TransitionRejectedError):
        fixture.commit(
            "observation", 4, _observation_value("open"), "cmd_observation_reopen"
        )
    assert orv.domain_head(fixture.channels["observation"], entity, "observation") == 3

    changed_close = copy.deepcopy(closed)
    changed_close["closed_at"] = _timepoint(999.0)
    with pytest.raises(orv.TransitionRejectedError):
        fixture.commit(
            "observation", 4, changed_close, "cmd_observation_rewrite_closure"
        )
    assert orv.domain_head(fixture.channels["observation"], entity, "observation") == 3

    appended = copy.deepcopy(closed)
    appended["measurements"] = [
        {"measurement_id": "measurement_owner_1", "estimate": 1.0}
    ]
    fixture.commit("observation", 4, appended, "cmd_observation_late_evidence")
    assert orv.domain_head(fixture.channels["observation"], entity, "observation") == 4
    observation_head = orv.read_domain(
        fixture.channels["observation"], entity, "observation"
    )
    assert not isinstance(observation_head, dict)
    assert observation_head.value["closed_at"] == closed["closed_at"]
    assert observation_head.value["close_reason"] == "normal_completion"
    assert observation_head.value["measurements"] == appended["measurements"]
    assert set(observation_head.record) == {
        "record_type",
        "schema_version",
        "attempt",
        "commission_digest",
        "axis",
        "owner_domain",
        "writer_id",
        "revision",
        "previous_revision",
        "evidence_prefix",
        "evidence_refs",
        "value",
    }


# ---------------------------------------------------------------------------
# 4. Cumulative claim and fact histories
# ---------------------------------------------------------------------------


def test_cumulative_claim_and_fact_histories_never_drop_or_rewrite_prior_entries():
    fixture = AttemptFixture().setup()
    entity = fixture.entity

    claim_1 = _claim("claim_owner_1", _missing())
    claim_2 = _claim("claim_owner_2", "completed", "execution_lifecycle")
    claim_3 = _claim("claim_owner_3", "failed", "application_postcondition")

    fixture.commit("execution", 1, {"claims": [claim_1]}, "cmd_exec_1")
    fixture.commit("execution", 2, {"claims": [claim_1, claim_2]}, "cmd_exec_2")
    assert orv.domain_head(fixture.channels["execution"], entity, "execution") == 2

    with pytest.raises(orv.CumulativeHistoryError):
        fixture.commit("execution", 3, {"claims": [claim_2]}, "cmd_exec_drop")
    assert orv.domain_head(fixture.channels["execution"], entity, "execution") == 2

    rewritten = copy.deepcopy(claim_1)
    rewritten["state"] = "completed"
    with pytest.raises(orv.CumulativeHistoryError):
        fixture.commit(
            "execution", 3, {"claims": [rewritten, claim_2]}, "cmd_exec_rewrite"
        )
    assert orv.domain_head(fixture.channels["execution"], entity, "execution") == 2

    fixture.commit(
        "execution", 3, {"claims": [claim_1, claim_2, claim_3]}, "cmd_exec_append"
    )
    execution_head = orv.read_domain(
        fixture.channels["execution"], entity, "execution"
    )
    assert not isinstance(execution_head, dict)
    assert [entry["claim_id"] for entry in execution_head.value["claims"]] == [
        "claim_owner_1",
        "claim_owner_2",
        "claim_owner_3",
    ]
    assert execution_head.value["claims"][0] == claim_1
    assert execution_head.value["claims"][1] == claim_2

    fact_1 = _fact("fact_owner_1", "committed", "at_boundary")
    fact_2 = _fact("fact_owner_2", "not_committed", "final_for_attempt")
    fact_3 = _fact("fact_owner_3", "committed", "at_boundary")

    fixture.commit("application", 1, {"facts": [fact_1]}, "cmd_app_1")
    fixture.commit("application", 2, {"facts": [fact_1, fact_2]}, "cmd_app_2")
    assert (
        orv.domain_head(fixture.channels["application"], entity, "application")
        == 2
    )

    with pytest.raises(orv.CumulativeHistoryError):
        fixture.commit("application", 3, {"facts": [fact_1]}, "cmd_app_drop")
    assert (
        orv.domain_head(fixture.channels["application"], entity, "application")
        == 2
    )

    fact_rewritten = copy.deepcopy(fact_1)
    fact_rewritten["state"] = "not_committed"
    with pytest.raises(orv.CumulativeHistoryError):
        fixture.commit(
            "application",
            3,
            {"facts": [fact_rewritten, fact_2]},
            "cmd_app_rewrite",
        )
    assert (
        orv.domain_head(fixture.channels["application"], entity, "application")
        == 2
    )

    fixture.commit(
        "application",
        3,
        {"facts": [fact_1, fact_2, fact_3]},
        "cmd_app_append",
    )
    application_head = orv.read_domain(
        fixture.channels["application"], entity, "application"
    )
    assert not isinstance(application_head, dict)
    assert [entry["fact_id"] for entry in application_head.value["facts"]] == [
        "fact_owner_1",
        "fact_owner_2",
        "fact_owner_3",
    ]
    assert application_head.value["facts"][0] == fact_1
    assert application_head.value["facts"][1] == fact_2


# ---------------------------------------------------------------------------
# 5. Report input pins
# ---------------------------------------------------------------------------


def test_report_input_pins_never_regress_between_publications():
    fixture = AttemptFixture().setup()
    entity = fixture.entity

    prepared = _dispatch_value("prepared", request_digest=D1)
    dispatch_1 = fixture.commit("dispatch", 1, prepared, "cmd_pins_dispatch_1")
    open_value = _observation_value("open")
    observation_1 = fixture.commit(
        "observation", 1, open_value, "cmd_pins_observation_1"
    )
    claim_1 = _claim("claim_pins_1", _missing())
    execution_1 = fixture.commit(
        "execution", 1, {"claims": [claim_1]}, "cmd_pins_execution_1"
    )
    fact_1 = _fact("fact_pins_1", "committed", "at_boundary")
    application_1 = fixture.commit(
        "application", 1, {"facts": [fact_1]}, "cmd_pins_application_1"
    )

    pins_1 = _pins(
        dispatch=(1, dispatch_1.digest),
        observation=(1, observation_1.digest),
        execution=(1, execution_1.digest),
        application=(1, application_1.digest),
    )
    report_1 = fixture.commit(
        "report",
        1,
        _report_value(
            pins_1,
            comparisons=[{"claim_id": "claim_pins_1", "result": "consistent"}],
        ),
        "cmd_pins_report_1",
    )

    dispatching = _dispatch_value(
        "dispatching",
        handle="handle_pins_1",
        request_digest=D1,
        delivery=[_evidence_ref("pins_delivery", 2)],
    )
    dispatch_2 = fixture.commit("dispatch", 2, dispatching, "cmd_pins_dispatch_2")
    draining = _observation_value(
        "draining", drain=True, close_reason="operator_stop"
    )
    observation_2 = fixture.commit(
        "observation", 2, draining, "cmd_pins_observation_2"
    )
    claim_2 = _claim("claim_pins_2", "completed", "execution_lifecycle")
    execution_2 = fixture.commit(
        "execution", 2, {"claims": [claim_1, claim_2]}, "cmd_pins_execution_2"
    )
    fact_2 = _fact("fact_pins_2", "not_committed", "final_for_attempt")
    application_2 = fixture.commit(
        "application", 2, {"facts": [fact_1, fact_2]}, "cmd_pins_application_2"
    )

    pins_2 = _pins(
        dispatch=(2, dispatch_2.digest),
        observation=(2, observation_2.digest),
        execution=(2, execution_2.digest),
        application=(2, application_2.digest),
    )
    fixture.commit(
        "report",
        2,
        _report_value(
            pins_2,
            comparisons=[
                {"claim_id": "claim_pins_1", "result": "consistent"},
                {"claim_id": "claim_pins_2", "result": "consistent"},
            ],
        ),
        "cmd_pins_report_2",
    )
    assert orv.domain_head(fixture.channels["report"], entity, "report") == 2

    regressed = _pins(
        dispatch=(2, dispatch_2.digest),
        observation=(1, observation_1.digest),
        execution=(2, execution_2.digest),
        application=(2, application_2.digest),
    )
    with pytest.raises(orv.PinRegressionError):
        fixture.commit(
            "report",
            3,
            _report_value(
                regressed,
                comparisons=[
                    {"claim_id": "claim_pins_1", "result": "consistent"}
                ],
            ),
            "cmd_pins_report_regressed",
        )
    assert orv.domain_head(fixture.channels["report"], entity, "report") == 2

    same_revision_new_digest = _pins(
        dispatch=(2, dispatch_2.digest),
        observation=(2, observation_2.digest),
        execution=(2, execution_1.digest),
        application=(2, application_2.digest),
    )
    with pytest.raises(orv.PinRegressionError):
        fixture.commit(
            "report",
            3,
            _report_value(
                same_revision_new_digest,
                comparisons=[
                    {"claim_id": "claim_pins_1", "result": "consistent"}
                ],
            ),
            "cmd_pins_report_swapped_digest",
        )
    assert orv.domain_head(fixture.channels["report"], entity, "report") == 2

    unpublished_pin = _pins(
        dispatch=(2, dispatch_2.digest),
        observation=(2, observation_2.digest),
        execution=(3, D3),
        application=(2, application_2.digest),
    )
    with pytest.raises(orv.PinResolutionError):
        fixture.commit(
            "report",
            3,
            _report_value(
                unpublished_pin,
                comparisons=[
                    {"claim_id": "claim_pins_1", "result": "consistent"}
                ],
            ),
            "cmd_pins_report_future",
        )
    assert orv.domain_head(fixture.channels["report"], entity, "report") == 2

    # Equal pins are allowed between publications; only regression is refused.
    fixture.commit(
        "report",
        3,
        _report_value(
            pins_2,
            comparisons=[
                {"claim_id": "claim_pins_1", "result": "consistent"},
                {"claim_id": "claim_pins_2", "result": "consistent"},
            ],
            limitations=["The report was reissued with unchanged input pins."],
        ),
        "cmd_pins_report_3",
    )
    report_head = orv.read_domain(fixture.channels["report"], entity, "report")
    assert not isinstance(report_head, dict)
    assert report_head.revision == 3
    assert report_head.value["inputs"] == pins_2
    assert report_head.value["limitations"] == [
        "The report was reissued with unchanged input pins."
    ]
    assert report_1.digest != report_head.content_digest
