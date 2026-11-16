"""Conformance tests for usage_accounting (tier 3).

Covers exactly the ``-k`` filter named in the module spec:

- ``missing_provider_usage_does_not_default_to_zero_cost``
- ``cost_reservations_reported_usage_and_invoiced_charges_remain_distinct``

Every check exercises the real module against the real evidence journal,
access-policy ingress, and content-addressed artifact store: pinned policy and
price artifacts, provider-reported measurements, owner-local atomic commits,
journaled evidence citations, and idempotent replay of committed accounting.
"""

from __future__ import annotations

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
            if name == "usage_accounting"
            else here.parents[2] / rel
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
ap = _load("access_policy", Path("access_policy/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
ua = _load("usage_accounting", Path("src/__init__.py"))


OWNER = "job.downstream"
CHANNEL = "ch_usage_accounting_0001"
PRODUCER = "prod_usage_accounting"
PRINCIPAL = "principal_usage_accounting"
JOURNAL = "journal_usage_accounting_0001"
RUN = "run_usage_accounting_0001"
REPORT_CLOCK = "clock_usage_report"
REPORT_BOOT = "boot_usage_report"
AUTHORITY_EVENT = "provider_call_observed"
AUTHORITY_EVENT_VERSION = "1"


@pytest.fixture(autouse=True)
def _fresh_state():
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixture composition: pinned artifacts, ingress registry, admitted journal
# ---------------------------------------------------------------------------


def _retain(payload: dict) -> store.ArtifactReference:
    content = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return store.retain_artifact(CHANNEL, OWNER, "application/json", content, "restricted")


def _pin(payload: dict, pin_id: str, version: str) -> tuple[ua.VersionPin, store.ArtifactReference]:
    reference = _retain(payload)
    return (
        ua.VersionPin(id=pin_id, version=version, artifact_digest=reference.digest),
        reference,
    )


def _declare_event_kinds() -> list[dict]:
    entries: list[dict] = list(ua.event_kind_declarations(OWNER))
    for entry in entries:
        ap.register_event_kind(
            entry["event_kind"],
            entry["event_schema_version"],
            role=entry["role"],
            assertion_kind=entry["assertion_kind"],
            owner_domain=OWNER,
            writer_roles=entry["writer_roles"],
        )
    ap.register_event_kind(
        AUTHORITY_EVENT,
        AUTHORITY_EVENT_VERSION,
        role="external_input",
        assertion_kind="observation",
        owner_domain=OWNER,
        writer_roles=("kernel",),
    )
    entries.append(
        {
            "event_kind": AUTHORITY_EVENT,
            "event_schema_version": AUTHORITY_EVENT_VERSION,
            "role": "external_input",
            "assertion_kind": "observation",
            "owner_domain": OWNER,
            "writer_roles": ["kernel"],
        }
    )
    return entries


def _manifest(task: store.ArtifactReference, config: store.ArtifactReference) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_usage_accounting_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_usage_accounting",
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
        task_semantic_hash="sha256:" + "b" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=_declare_event_kinds(),
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": list(ua.EVENT_KINDS) + [AUTHORITY_EVENT],
            }
        ],
        clocks=[
            {
                "clock_id": "clock_usage_journal",
                "boot_id": "boot_usage_journal",
                "origin": "engine_measured",
                "source_id": "src_usage_journal",
                "basis": "monotonic_offset",
                "unit": "ms",
            },
            {
                "clock_id": REPORT_CLOCK,
                "boot_id": REPORT_BOOT,
                "origin": "subject_reported",
                "source_id": "src_usage_report",
                "basis": "opaque_report",
                "unit": "ms",
            },
        ],
    )


def _setup() -> tuple[ua.VersionPin, ua.VersionPin]:
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=tuple(ua.EVENT_KINDS) + (AUTHORITY_EVENT,),
    )
    task = _retain({"task": "usage-accounting-conformance"})
    config = _retain({"configuration": "usage-accounting-conformance"})
    ev.admit_manifest(CHANNEL, _manifest(task, config))
    policy_pin, _policy_ref = _pin(
        {
            "currency": "USD",
            "reserved_cost_usd": 0.02,
            "frozen_cost_limit_usd": 0.5,
        },
        "policy_cost",
        "1",
    )
    pricing_pin, _pricing_ref = _pin(
        {
            "currency": "USD",
            "model_id": "model_usage_conformance",
            "model_version": "2026-05-01",
            "input_usd_per_token": 0.000002,
            "output_usd_per_token": 0.000004,
        },
        "pricing_model_usage_conformance",
        "1",
    )
    return policy_pin, pricing_pin


def _record(reference: store.ArtifactReference) -> dict:
    return json.loads(store.resolve_artifact(CHANNEL, reference))


# ---------------------------------------------------------------------------
# Measurements (provider-reported token evidence)
# ---------------------------------------------------------------------------


def _measurement(
    dimension: str,
    measurement_id: str,
    estimate: dict,
    *,
    method: str,
    censoring: str,
) -> cc.Measurement:
    return cc.Measurement(
        measurement_id=measurement_id,
        name=dimension,
        scope={"kind": "connector_call", "id": "provider_call_usage"},
        quantity="scalar",
        unit="tokens",
        origin="subject_reported",
        clock_id=REPORT_CLOCK,
        boot_id=REPORT_BOOT,
        method=method,
        start=cc.make_missing("not_applicable"),
        end=cc.make_missing("not_applicable"),
        estimate=estimate,
        resolution=cc.make_missing("not_applicable"),
        comparability_group=cc.make_missing("not_applicable"),
        censoring=censoring,
    )


def _exact_measurement(dimension: str, tokens: int, measurement_id: str) -> cc.Measurement:
    return _measurement(
        dimension,
        measurement_id,
        {"kind": "exact", "value": tokens},
        method="source_value",
        censoring="none",
    )


def _unavailable_measurement(dimension: str, measurement_id: str) -> cc.Measurement:
    return _measurement(
        dimension,
        measurement_id,
        {
            "kind": "unavailable",
            "value": cc.make_missing(
                "not_observed", f"provider omitted {dimension} for this call"
            ),
        },
        method="unavailable",
        censoring="unavailable",
    )


def _provider_call_event(call_id: str):
    return ev.append_event(
        CHANNEL,
        OWNER,
        ev.EventSubmission(
            producer_sequence=ev.NOT_APPLICABLE,
            event_kind=AUTHORITY_EVENT,
            event_schema_version=AUTHORITY_EVENT_VERSION,
            occurred_at=ev.NOT_OBSERVED,
            payload=ev.EvidencePayload(
                data={"call_id": call_id, "observation": "provider_call"},
                measurements=(),
                evidence_refs=(),
                artifact_refs=(),
            ),
        ),
    )


def _evidence_ref(envelope) -> ev.EvidenceRef:
    return ev.EvidenceRef(
        journal_id=envelope.journal_id,
        sequence=envelope.journal_sequence,
        event_id=envelope.event_id,
        event_hash=envelope.event_hash,
        pointer="",
    )


# ---------------------------------------------------------------------------
# Assertion 1: missing usage is never zero usage or zero cost
# ---------------------------------------------------------------------------


def test_missing_provider_usage_does_not_default_to_zero_cost() -> None:
    policy, pricing = _setup()

    missing_call = "call_missing_usage_0001"
    reservation_ref = ua.reserve_cost(CHANNEL, missing_call, policy)
    measured = (
        _unavailable_measurement(ua.INPUT_TOKENS, "m_input_missing"),
        _exact_measurement(ua.OUTPUT_TOKENS, 250, "m_output_reported"),
    )
    record_ref = ua.record_model_cost(CHANNEL, missing_call, measured, pricing, ())
    record = _record(record_ref)

    # The absent input-token dimension stays a typed Missing envelope.
    input_usage = record["reported_usage"][ua.INPUT_TOKENS]
    assert input_usage["estimate_kind"] == "unavailable"
    assert input_usage["method"] == "unavailable"
    assert input_usage["value"]["value"] is None
    assert input_usage["value"]["reason"] == "not_observed"
    assert input_usage["origin"] == "subject_reported"
    # The reported output-token count is retained as evidence, not altered.
    assert record["reported_usage"][ua.OUTPUT_TOKENS]["value"] == 250

    # Missing input usage blocks derivation: no zero-dollar "cost" appears.
    derivation = record["cost_derivation"]
    assert derivation["value"] is None
    assert derivation["reason"] == "not_observed"
    assert "amount_usd" not in derivation

    # A reservation remains a distinct declaration on the cost record.
    assert record["reservation"]["artifact"]["digest"] == reservation_ref.digest
    assert record["reservation"]["reserved_cost"]["amount"] == 0.02
    assert record["invoiced_charge"]["value"] is None

    # The journal event carries the same unavailable measurement; missingness
    # is never rewritten to zero between the caller and the journal.
    head = ev.journal_head(CHANNEL, JOURNAL)
    events = ev.read_prefix(CHANNEL, head)
    cost_events = [e for e in events if e.event_kind == ua.MODEL_COST_EVENT_KIND]
    assert len(cost_events) == 1
    journaled = cost_events[0].payload
    assert journaled["data"]["cost_record"]["call_id"] == missing_call
    journal_measurements = {
        item["name"]: item for item in journaled["measurements"]
    }
    assert journal_measurements[ua.INPUT_TOKENS]["estimate"] == {
        "kind": "unavailable",
        "value": {
            "value": None,
            "reason": "not_observed",
            "detail": "provider omitted input_tokens for this call",
        },
    }
    assert journaled["data"]["cost_record"]["cost_derivation"]["value"] is None

    # An established empty usage collection declares no token dimensions at
    # all; both remain Missing and the cost remains underived.
    empty_ref = ua.record_model_cost(
        CHANNEL, "call_missing_usage_0002", (), pricing, ()
    )
    empty = _record(empty_ref)
    for dimension in ua.TOKEN_DIMENSIONS:
        dimension_usage = empty["reported_usage"][dimension]
        assert dimension_usage["estimate_kind"] == "unavailable"
        assert dimension_usage["value"]["value"] is None
        assert dimension_usage["method"] == "unavailable"
    assert empty["cost_derivation"]["value"] is None
    assert empty["cost_derivation"]["reason"] == "not_observed"

    # Missing pricing is also never a fabricated zero-dollar derivation, even
    # when usage is an explicitly reported zero.
    missing_pricing_ref = ua.record_model_cost(
        CHANNEL,
        "call_missing_price_0001",
        (
            _exact_measurement(ua.INPUT_TOKENS, 0, "m_input_zero_no_price"),
            _exact_measurement(ua.OUTPUT_TOKENS, 0, "m_output_zero_no_price"),
        ),
        cc.make_missing("not_observed", "provider price schedule was not supplied"),
        (),
    )
    missing_pricing = _record(missing_pricing_ref)
    assert missing_pricing["reported_usage"][ua.INPUT_TOKENS]["value"] == 0
    assert missing_pricing["pricing"]["value"] is None
    assert missing_pricing["cost_derivation"]["value"] is None
    assert "amount_usd" not in missing_pricing["cost_derivation"]

    # An explicitly reported zero is real evidence: known prices price it as
    # exact zero, which is distinct from the missing cases above.
    zero_ref = ua.record_model_cost(
        CHANNEL,
        "call_explicit_zero_0001",
        (
            _exact_measurement(ua.INPUT_TOKENS, 0, "m_input_zero_reported"),
            _exact_measurement(ua.OUTPUT_TOKENS, 0, "m_output_zero_reported"),
        ),
        pricing,
        (),
    )
    zero = _record(zero_ref)
    assert zero["reported_usage"][ua.INPUT_TOKENS]["value"] == 0
    assert zero["reported_usage"][ua.OUTPUT_TOKENS]["value"] == 0
    assert zero["cost_derivation"]["amount_usd"] == 0.0
    assert zero["cost_derivation"]["exact_amount"] == "0"
    assert zero["cost_derivation"]["is_invoice_fact"] is False
    assert zero["cost_derivation"] != missing_pricing["cost_derivation"]


# ---------------------------------------------------------------------------
# Assertion 2: reservation, reported usage, and invoice stay distinct
# ---------------------------------------------------------------------------


def test_cost_reservations_reported_usage_and_invoiced_charges_remain_distinct() -> None:
    policy, pricing = _setup()
    call_id = "call_distinct_0001"
    provider_evidence = _provider_call_event(call_id)
    source_ref = _evidence_ref(provider_evidence)

    reservation_ref = ua.reserve_cost(CHANNEL, call_id, policy)
    reservation_bytes = store.resolve_artifact(CHANNEL, reservation_ref)
    reservation = json.loads(reservation_bytes)
    assert reservation["record_type"] == "cost_reservation"
    assert reservation["state"] == "reserved"
    assert reservation["kind"] == "reservation"
    assert reservation["reserved_cost"]["amount"] == 0.02
    assert reservation["reserved_cost"]["basis"] == "policy_declaration"
    assert reservation["frozen_cost_limit"]["amount"] == 0.5
    # A reservation is a declaration about budget, never observed usage and
    # never an invoice fact.
    assert reservation["reported_usage"]["value"] is None
    assert reservation["reported_usage"]["reason"] == "not_applicable"
    assert reservation["cost_derivation"]["value"] is None
    assert reservation["invoiced_charge"]["value"] is None
    assert reservation["is_observed_usage"] is False
    assert reservation["is_invoice_fact"] is False

    head_after_reservation = ev.journal_head(CHANNEL, JOURNAL)
    # Repeating the identical reservation is idempotent: same artifact, no
    # second declaration event.
    assert ua.reserve_cost(CHANNEL, call_id, policy) == reservation_ref
    assert ev.journal_head(CHANNEL, JOURNAL) == head_after_reservation
    # A changed policy under the same call identity cannot silently replace a
    # frozen limit; it is a conflict and the original reservation survives.
    changed_pin, _changed_ref = _pin(
        {
            "currency": "USD",
            "reserved_cost_usd": 0.99,
            "frozen_cost_limit_usd": 99.0,
        },
        "policy_cost",
        "2",
    )
    with pytest.raises(ua.CostConflictError):
        ua.reserve_cost(CHANNEL, call_id, changed_pin)
    assert ev.journal_head(CHANNEL, JOURNAL) == head_after_reservation
    assert store.resolve_artifact(CHANNEL, reservation_ref) == reservation_bytes

    usage = (
        _exact_measurement(ua.INPUT_TOKENS, 1200, "m_input_tokens"),
        _exact_measurement(ua.OUTPUT_TOKENS, 300, "m_output_tokens"),
    )
    cost_ref = ua.record_model_cost(CHANNEL, call_id, usage, pricing, (source_ref,))
    record = _record(cost_ref)
    assert record["record_type"] == "model_cost_record"

    # The reservation is cited as its own unmodified artifact.
    assert record["reservation"]["artifact"]["digest"] == reservation_ref.digest
    assert record["reservation"]["reserved_cost"]["amount"] == 0.02
    assert record["reservation"]["frozen_cost_limit"]["amount"] == 0.5
    assert store.resolve_artifact(CHANNEL, reservation_ref) == reservation_bytes

    # Reported usage is evidence with provenance, not the reservation amount.
    assert record["reported_usage"][ua.INPUT_TOKENS]["value"] == 1200
    assert record["reported_usage"][ua.OUTPUT_TOKENS]["value"] == 300
    assert record["reported_usage"][ua.INPUT_TOKENS]["origin"] == "subject_reported"
    assert record["reported_usage"][ua.INPUT_TOKENS]["estimate_kind"] == "exact"

    # The computed cost is an exact derivation over declared prices, but it is
    # explicitly not an invoice fact, and it is not the reservation.
    derivation = record["cost_derivation"]
    expected = 1200 * 0.000002 + 300 * 0.000004
    assert derivation["basis"] == "declared_price_schedule"
    assert derivation["amount_usd"] == pytest.approx(expected)
    assert derivation["exact_amount"] == "0.0036"
    assert derivation["exactness"] == "exact_under_declared_prices"
    assert derivation["is_invoice_fact"] is False
    assert derivation["amount_usd"] != record["reservation"]["reserved_cost"]["amount"]
    assert record["invoiced_charge"]["value"] is None
    assert record["invoiced_charge"]["reason"] == "not_observed"

    head_after_cost = ev.journal_head(CHANNEL, JOURNAL)
    events = ev.read_prefix(CHANNEL, head_after_cost)
    cost_events = [e for e in events if e.event_kind == ua.MODEL_COST_EVENT_KIND]
    assert len(cost_events) == 1
    cost_payload = cost_events[0].payload
    assert cost_payload["data"]["cost_record"]["call_id"] == call_id
    assert cost_payload["evidence_refs"] == [source_ref.to_dict()]
    artifact_digests = {
        reference["digest"] for reference in cost_payload["artifact_refs"]
    }
    assert reservation_ref.digest in artifact_digests
    assert record["invoiced_charge"] == cost_payload["data"]["cost_record"][
        "invoiced_charge"
    ]

    # Identical retry is idempotent: same artifact, no second charge event.
    assert (
        ua.record_model_cost(CHANNEL, call_id, usage, pricing, (source_ref,))
        == cost_ref
    )
    assert ev.journal_head(CHANNEL, JOURNAL) == head_after_cost

    # Different usage under the same call identity is a conflict, not a
    # second charge.
    with pytest.raises(ua.CostConflictError):
        ua.record_model_cost(
            CHANNEL,
            call_id,
            (
                _exact_measurement(ua.INPUT_TOKENS, 9999, "m_input_tokens"),
                _exact_measurement(ua.OUTPUT_TOKENS, 300, "m_output_tokens"),
            ),
            pricing,
            (source_ref,),
        )
    assert ev.journal_head(CHANNEL, JOURNAL) == head_after_cost

    # The same provider-call evidence cannot be priced again under another
    # call identity.
    with pytest.raises(ua.CostDuplicateEvidenceError):
        ua.record_model_cost(
            CHANNEL, "call_distinct_0002", usage, pricing, (source_ref,)
        )
    assert ev.journal_head(CHANNEL, JOURNAL) == head_after_cost
    cost_events_after = [
        e
        for e in ev.read_prefix(CHANNEL, head_after_cost)
        if e.event_kind == ua.MODEL_COST_EVENT_KIND
    ]
    assert len(cost_events_after) == 1
