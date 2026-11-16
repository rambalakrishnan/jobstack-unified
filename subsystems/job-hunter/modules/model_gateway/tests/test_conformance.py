"""Conformance tests for model_gateway (tier 4).

Covers exactly the ``-k`` filter named in the module spec:

- ``model_responses_retain_raw_bytes_and_explicit_schema_validation_outcomes``
- ``model_disclosure_and_cost_policy_are_checked_before_provider_dispatch``

Every check exercises the real module against the real strict codec,
access-policy ingress, content-addressed artifact store, evidence journal,
and usage accounting: pinned cost/pricing policy artifacts, provider-reported
measurements, owner-local atomic commits, journaled call evidence, and
provider dispatch gated on disclosure grants and frozen cost reservations.
"""

from __future__ import annotations

import asyncio
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
            if name == "model_gateway"
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
ua = _load("usage_accounting", Path("usage_accounting/src/__init__.py"))
mg = _load("model_gateway", Path("src/__init__.py"))

OWNER = "job.downstream"
CHANNEL = "ch_model_gateway_0001"
PRODUCER = "prod_model_gateway"
PRINCIPAL = "principal_model_gateway"
JOURNAL = "journal_model_gateway_0001"
RUN = "run_model_gateway_0001"
JOURNAL_CLOCK = "clock_model_journal"
JOURNAL_BOOT = "boot_model_journal"
REPORT_CLOCK = "clock_model_report"
REPORT_BOOT = "boot_model_report"

PROVIDER = "opencode-go/muse-spark"


@pytest.fixture(autouse=True)
def _fresh_state():
    mg.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    mg.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixture composition: pinned artifacts, ingress registry, admitted journal
# ---------------------------------------------------------------------------


def _retain(payload: dict, access: str = "restricted"):
    content = json.dumps(payload, sort_keys=True).encode("utf-8")
    return store.retain_artifact(CHANNEL, OWNER, "application/json", content, access)


def _pin(payload: dict, pin_id: str, version: str, access: str = "restricted"):
    reference = _retain(payload, access)
    return (
        mg.VersionPin(id=pin_id, version=version, artifact_digest=reference.digest),
        reference,
    )


def _declare_event_kinds() -> list[dict]:
    entries: list[dict] = []
    for entry in list(ua.event_kind_declarations(OWNER)) + list(
        mg.event_kind_declarations(OWNER)
    ):
        ap.register_event_kind(
            entry["event_kind"],
            entry["event_schema_version"],
            role=entry["role"],
            assertion_kind=entry["assertion_kind"],
            owner_domain=OWNER,
            writer_roles=tuple(entry["writer_roles"]),
        )
        entries.append(entry)
    return entries


def _manifest(task, config) -> ev.Manifest:
    kinds = list(ua.EVENT_KINDS) + list(mg.EVENT_KINDS)
    return ev.Manifest(
        manifest_id="manifest_model_gateway_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_model_gateway",
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
        task_semantic_hash="sha256:" + "c" * 64,
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
                "allowed_event_kinds": kinds,
            }
        ],
        clocks=[
            {
                "clock_id": JOURNAL_CLOCK,
                "boot_id": JOURNAL_BOOT,
                "origin": "engine_measured",
                "source_id": "src_model_journal",
                "basis": "monotonic_offset",
                "unit": "ms",
            },
            {
                "clock_id": REPORT_CLOCK,
                "boot_id": REPORT_BOOT,
                "origin": "subject_reported",
                "source_id": "src_model_report",
                "basis": "opaque_report",
                "unit": "ms",
            },
        ],
    )


def _setup():
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=tuple(ua.EVENT_KINDS) + tuple(mg.EVENT_KINDS),
    )
    task = _retain({"task": "model-gateway-conformance"})
    config = _retain({"configuration": "model-gateway-conformance"})
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    assert admission.journal_sequence == 1
    policy_pin, _ = _pin(
        {
            "currency": "USD",
            "reserved_cost_usd": 0.02,
            "frozen_cost_limit_usd": 0.5,
        },
        PROVIDER,
        "2026-01-15",
    )
    pricing_pin, _ = _pin(
        {
            "currency": "USD",
            "model_id": PROVIDER,
            "model_version": "spark-2026-01-15",
            "input_usd_per_token": 0.000002,
            "output_usd_per_token": 0.000004,
        },
        f"pricing_{PROVIDER}",
        "1",
    )
    schema_pin, _ = _pin(
        {
            "schema_id": "record/v1",
            "mapping": "completion.object",
            "description": "Pinned structured-output mapping for completions.",
        },
        "record/v1",
        "1",
    )
    prompt = _retain({"prompt": "evaluate candidate fit", "job": "job-001"})
    job_input = _retain({"profile": "candidate summary for job-001"})
    return policy_pin, pricing_pin, schema_pin, prompt, job_input


def _record(reference) -> dict:
    return json.loads(store.resolve_artifact(CHANNEL, reference))


def _resolve_raw(record: dict) -> bytes:
    reference = store.ArtifactReference(
        digest=record["raw_response_digest"],
        size_bytes=record["raw_response_size"],
        media_type=record["raw_response_media_type"],
        owner_domain=OWNER,
        access="restricted",
    )
    return store.resolve_artifact(CHANNEL, reference)


def _call_events(call_id: str) -> list:
    prefix = ev.journal_head(CHANNEL, JOURNAL)
    return [
        envelope
        for envelope in ev.read_prefix(CHANNEL, prefix)
        if envelope.event_kind == "model_call_recorded"
        and envelope.payload["data"]["call_id"] == call_id
    ]


def _grant(call_id: str, **overrides) -> None:
    kwargs: dict = {
        "providers": [PROVIDER],
        "purpose": "candidate_evaluation",
        "allowed_access": ["public", "restricted"],
    }
    kwargs.update(overrides)
    mg.authorize_disclosure_for_tests(call_id, **kwargs)


# ---------------------------------------------------------------------------
# Assertion 1: raw bytes retained + explicit validation outcomes
# ---------------------------------------------------------------------------


def test_model_responses_retain_raw_bytes_and_explicit_schema_validation_outcomes() -> None:
    policy_pin, pricing_pin, schema_pin, prompt, job_input = _setup()
    inputs = (job_input,)

    # -- Case A: valid structured output retains every call element. ---------
    call_valid = "call_model_valid_0001"
    _grant(call_valid)
    raw_valid = json.dumps(
        {"id": "completion-1", "tokens": {"recommendation": "advance"}},
        sort_keys=True,
    ).encode("utf-8")
    mg.stage_model_response_for_tests(
        call_valid,
        raw_valid,
        input_tokens=120,
        output_tokens=45,
        pricing=pricing_pin,
        provider=PROVIDER,
        model_version="spark-2026-01-15",
    )
    record_ref = asyncio.run(
        mg.invoke_model(CHANNEL, call_valid, policy_pin, prompt, inputs, schema_pin)
    )
    record = _record(record_ref)
    assert record["record_type"] == "model_call_record"
    assert record["call_id"] == call_valid
    assert record["provider"] == PROVIDER
    assert record["provider_version_evidence"] == "spark-2026-01-15"
    assert record["policy_pin"] == policy_pin.to_dict()
    assert record["prompt_digest"] == prompt.digest
    assert record["input_digests"] == [job_input.digest]
    assert record["output_schema_pin"] == schema_pin.to_dict()
    assert _resolve_raw(record) == raw_valid
    assert record["validation"]["valid"] is True
    assert record["validation"]["schema_id"] == "record/v1"
    assert record["validation"]["error"] == {
        "value": None,
        "reason": "not_applicable",
        "detail": "structured output validated",
    }
    assert record["usage_summary"] == {"input_tokens": 120, "output_tokens": 45}
    assert record["pricing"] == pricing_pin.to_dict()
    assert record["cost_derivation"]["basis"] == "declared_price_schedule"
    assert record["cost_derivation"]["is_invoice_fact"] is False
    assert record["cost_derivation"]["input_tokens"] == 120
    assert record["cost_derivation"]["output_tokens"] == 45
    assert record["authorization"]["producer_id"] == PRODUCER
    assert record["authorization"]["owner_domain"] == OWNER
    assert record["disclosure"]["purpose"] == "candidate_evaluation"
    assert record["disclosure"]["providers"] == [PROVIDER]
    assert record["journal"]["journal_id"] == JOURNAL
    assert record["journal"]["sequence"] >= 2
    events = _call_events(call_valid)
    assert len(events) == 1
    assert events[0].payload["data"]["raw_response_digest"] == record["raw_response_digest"]
    assert events[0].payload["data"]["validation"]["valid"] is True
    assert mg.dispatch_attempts_for_tests() == 1

    # -- Case B: undeclared properties fail validation; raw bytes survive. ---
    call_invalid = "call_model_invalid_0001"
    _grant(call_invalid)
    raw_invalid = b'{"id": "completion-2", "undeclared_property": 1}'
    mg.stage_model_response_for_tests(
        call_invalid,
        raw_invalid,
        input_tokens=10,
        output_tokens=5,
        pricing=pricing_pin,
        provider=PROVIDER,
        model_version="spark-2026-01-15",
    )
    invalid_ref = asyncio.run(
        mg.invoke_model(CHANNEL, call_invalid, policy_pin, prompt, inputs, schema_pin)
    )
    invalid = _record(invalid_ref)
    assert invalid["validation"]["valid"] is False
    assert invalid["validation"]["schema_id"] == "record/v1"
    assert invalid["validation"]["error"]["value"] is None
    assert invalid["validation"]["error"]["reason"] == "not_observed"
    assert "validation failed" in invalid["validation"]["error"]["detail"]
    assert invalid["validation"]["canonical_digest"]["reason"] == "not_observed"
    # The original bytes are preserved byte-for-byte; nothing was repaired.
    assert _resolve_raw(invalid) == raw_invalid
    assert invalid_ref.digest != record_ref.digest
    assert mg.dispatch_attempts_for_tests() == 2

    # -- Case C: malformed bytes fail validation; raw bytes survive. ---------
    call_malformed = "call_model_malformed_0001"
    _grant(call_malformed)
    raw_malformed = b"not-json{{{"
    mg.stage_model_response_for_tests(
        call_malformed,
        raw_malformed,
        input_tokens=3,
        output_tokens=1,
        pricing=pricing_pin,
        provider=PROVIDER,
        model_version="spark-2026-01-15",
    )
    malformed_ref = asyncio.run(
        mg.invoke_model(CHANNEL, call_malformed, policy_pin, prompt, inputs, schema_pin)
    )
    malformed = _record(malformed_ref)
    assert malformed["validation"]["valid"] is False
    assert malformed["validation"]["error"]["reason"] == "not_observed"
    assert _resolve_raw(malformed) == raw_malformed
    assert mg.dispatch_attempts_for_tests() == 3

    # -- Case D: missing usage/pricing stay missing, never zero. --------------
    call_missing = "call_model_missing_0001"
    _grant(call_missing)
    raw_missing = json.dumps({"id": "completion-4", "tokens": {}}, sort_keys=True).encode(
        "utf-8"
    )
    mg.stage_model_response_for_tests(
        call_missing,
        raw_missing,
        input_tokens=None,
        output_tokens=None,
        pricing=None,
        provider=PROVIDER,
        model_version=None,
    )
    missing_ref = asyncio.run(
        mg.invoke_model(CHANNEL, call_missing, policy_pin, prompt, inputs, schema_pin)
    )
    missing = _record(missing_ref)
    assert missing["validation"]["valid"] is True
    assert _resolve_raw(missing) == raw_missing
    assert missing["usage_summary"]["input_tokens"]["reason"] == "not_observed"
    assert missing["usage_summary"]["output_tokens"]["reason"] == "not_observed"
    assert missing["pricing"]["reason"] == "not_observed"
    assert missing["provider_version_evidence"]["reason"] == "not_observed"
    assert missing["cost_derivation"]["value"] is None
    assert missing["cost_derivation"]["reason"] == "not_observed"
    assert mg.dispatch_attempts_for_tests() == 4

    # -- Case E: stable identity replays without re-dispatch. -----------------
    replayed = asyncio.run(
        mg.invoke_model(CHANNEL, call_valid, policy_pin, prompt, inputs, schema_pin)
    )
    assert replayed.digest == record_ref.digest
    assert mg.dispatch_attempts_for_tests() == 4
    assert len(_call_events(call_valid)) == 1

    other_prompt = _retain({"prompt": "different prompt"})
    with pytest.raises(mg.ModelConflictError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_valid, policy_pin, other_prompt, inputs, schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 4


# ---------------------------------------------------------------------------
# Assertion 2: disclosure + cost policy gate provider dispatch
# ---------------------------------------------------------------------------


def test_model_disclosure_and_cost_policy_are_checked_before_provider_dispatch() -> None:
    policy_pin, pricing_pin, schema_pin, prompt, job_input = _setup()
    inputs = (job_input,)

    def _stage(call_id: str) -> None:
        raw = json.dumps({"id": call_id, "tokens": {}}, sort_keys=True).encode("utf-8")
        mg.stage_model_response_for_tests(
            call_id,
            raw,
            input_tokens=8,
            output_tokens=2,
            pricing=pricing_pin,
            provider=PROVIDER,
            model_version="spark-2026-01-15",
        )

    # -- Case A: no disclosure grant reaches no provider. --------------------
    call_no_grant = "call_nogrant_0001"
    _stage(call_no_grant)
    with pytest.raises(mg.DisclosureDeniedError):
        asyncio.run(
            mg.invoke_model(CHANNEL, call_no_grant, policy_pin, prompt, inputs, schema_pin)
        )
    assert mg.dispatch_attempts_for_tests() == 0
    assert _call_events(call_no_grant) == []

    # -- Case B: restricted data outside a public-only grant is denied. -------
    call_public_only = "call_public_only_0001"
    _grant(call_public_only, allowed_access=["public"])
    _stage(call_public_only)
    with pytest.raises(mg.DisclosureDeniedError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_public_only, policy_pin, prompt, inputs, schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0

    # -- Case C: a grant for another provider does not authorize dispatch. ---
    call_provider_mismatch = "call_provider_mismatch_0001"
    _grant(call_provider_mismatch, providers=["other-provider/other-model"])
    _stage(call_provider_mismatch)
    with pytest.raises(mg.DisclosureDeniedError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_provider_mismatch, policy_pin, prompt, inputs, schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0

    # -- Case D: secret material is never disclosed to models. ----------------
    secret_input = _retain({"notes": "handoff password: s3cr3t-value-here"})
    call_secret = "call_secret_0001"
    _grant(call_secret)
    _stage(call_secret)
    with pytest.raises(mg.DisclosureDeniedError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_secret, policy_pin, prompt, (secret_input,), schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0

    # -- Case E: malformed cost policy blocks dispatch after disclosure. ------
    bad_policy_pin, _ = _pin(
        {"currency": "USD", "undeclared_field": 1}, PROVIDER, "bad"
    )
    call_bad_cost = "call_bad_cost_0001"
    _grant(call_bad_cost)
    _stage(call_bad_cost)
    with pytest.raises(mg.CostPolicyDeniedError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_bad_cost, bad_policy_pin, prompt, inputs, schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0
    assert _call_events(call_bad_cost) == []

    # -- Case F: unknown output schema blocks dispatch. -----------------------
    bad_schema_pin, _ = _pin({"schema_id": "unknown-schema/v9"}, "unknown-schema/v9", "9")
    call_bad_schema = "call_bad_schema_0001"
    _grant(call_bad_schema)
    _stage(call_bad_schema)
    with pytest.raises(mg.ModelPolicyError):
        asyncio.run(
            mg.invoke_model(
                CHANNEL, call_bad_schema, policy_pin, prompt, inputs, bad_schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0

    # -- Case G: unauthenticated callers never reach the provider. ------------
    call_noauth = "call_noauth_0001"
    _grant(call_noauth)
    _stage(call_noauth)
    with pytest.raises(PermissionError):
        asyncio.run(
            mg.invoke_model(
                "ch_unknown_no_session", call_noauth, policy_pin, prompt, inputs, schema_pin
            )
        )
    assert mg.dispatch_attempts_for_tests() == 0

    # -- Case H: authorized + funded calls dispatch exactly once. -------------
    call_ok = "call_ok_0001"
    _grant(call_ok)
    _stage(call_ok)
    record_ref = asyncio.run(
        mg.invoke_model(CHANNEL, call_ok, policy_pin, prompt, inputs, schema_pin)
    )
    assert mg.dispatch_attempts_for_tests() == 1
    record = _record(record_ref)
    assert record["call_id"] == call_ok
    assert record["provider"] == PROVIDER
    assert record["disclosure"]["purpose"] == "candidate_evaluation"
    assert record["validation"]["valid"] is True
    assert len(_call_events(call_ok)) == 1
