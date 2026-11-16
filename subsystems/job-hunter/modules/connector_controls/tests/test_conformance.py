"""Conformance tests for connector_controls (tier 6).

Covers exactly the ``-k`` filter named in the module spec, plus the authority
and bounded-target checks those assertions depend on:

- ``cancel_acknowledgement_does_not_imply_no_commit_fact``
- ``process_containment_does_not_certify_native_cancellation``
- ``connection_close_and_end_observation_remain_separate_from_native_cancel``

Every check runs the real module against the real sibling modules: an
authenticated connector channel is registered, the connector carrier is
exercised through ``Prepare``/``Start`` to obtain a genuine handle, and the
control verbs are issued through ``control_task``.  Nothing is monkeypatched.
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    here = Path(__file__).resolve()
    if name == "connector_controls":
        path = here.parents[1] / "src" / "__init__.py"
    else:
        path = here.parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("contract_codec")
ap = _load("access_policy")
store = _load("artifact_store")
ev = _load("evidence_journal")
ct = _load("connector_transport")
ac = _load("attempt_commissioning")
cc = _load("connector_controls")

CHANNEL = "ch_controls_connector"
APP_CHANNEL = "ch_controls_application"
CONNECTOR = "connector_controls_local"
PRINCIPAL = "principal_controls_connector"


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    store.reset_for_tests()
    ev.reset_for_tests()
    ct.reset_for_tests()
    ac.reset_for_tests()
    yield
    ac.reset_for_tests()
    ct.reset_for_tests()
    ev.reset_for_tests()
    store.reset_for_tests()
    ap.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _missing(reason: str = "not_applicable") -> dict[str, Any]:
    return {"value": None, "reason": reason}


def _ref(sequence: int, journal: str = "journal_controls") -> dict[str, Any]:
    return {
        "journal_id": journal,
        "sequence": sequence,
        "event_id": f"evt_controls_{sequence}",
        "event_hash": "sha256:" + f"{sequence:064x}"[:64],
        "pointer": "",
    }


def _timepoint(offset: float = 1.0) -> dict[str, Any]:
    return {
        "clock_id": "clk_controls_monotonic",
        "boot_id": "boot_controls_monotonic",
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing("not_observed"),
    }


def _verified_checks(response_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "authentication": "verified",
        "correlation": "matched",
        "trace_correlation": "not_observed",
        "verification_policy": {"id": "policy_response_verification", "version": "1"},
        "matched_by": ["handle", "request_id"],
        "evidence_refs": [response_ref],
    }


def _unverified_checks(response_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "authentication": "failed",
        "correlation": "mismatched",
        "trace_correlation": "mismatched",
        "verification_policy": {"id": "policy_response_verification", "version": "1"},
        "matched_by": [],
        "evidence_refs": [response_ref],
    }


def _register_connector(
    channel: str = CHANNEL,
    producer: str = "prod_controls_connector",
    principal: str = PRINCIPAL,
    axis: str = "attempt.dispatch",
) -> None:
    ap.register_channel(
        actor="connector",
        channel_id=channel,
        axis=axis,
        producer_id=producer,
        principal_id=principal,
        sequence_required=False,
        allowed_event_kinds=("connector.control_observed",),
        binding="bind_controls_runtime",
    )


def _request(
    operation: str,
    payload: dict[str, Any],
    request_id: str,
    *,
    connector_id: str = CONNECTOR,
    call_limit_ms: float = 1000.0,
) -> Any:
    return ct.ConnectorRequest(
        request_id=request_id,
        connector_id=connector_id,
        operation=operation,
        call_limit={"kind": "exact", "unit": "ms", "value": call_limit_ms},
        payload=payload,
    )


async def _prepare_and_start(
    channel: str = CHANNEL,
    connector_id: str = CONNECTOR,
    tag: str = "primary",
) -> dict[str, Any]:
    preparation = await ct.call_connector(
        channel,
        _request(
            "Prepare",
            {
                "scope": {
                    "activity": "application_attempt",
                    "run_id": "run_controls",
                    "journal_id": "journal_controls",
                    "attempt": _missing("not_observed"),
                    "commission": _missing("not_observed"),
                },
                "configuration": {
                    "connector_id": connector_id,
                    "connector_version": "controls/0.1.0",
                    "binding": _missing("not_applicable"),
                    "subject": _missing("not_observed"),
                },
                "task": {"task_type": "apply", "task_id": f"task_controls_{tag}"},
            },
            f"req_prepare_{tag}",
            connector_id=connector_id,
        ),
    )
    assert not preparation.is_error, preparation.result
    preparation_id = preparation.result["preparation"]["preparation_id"]
    started = await ct.call_connector(
        channel,
        _request(
            "Start",
            {
                "preparation": {"preparation_id": preparation_id},
                "idempotency_key": f"idem_controls_{tag}",
                "accepted_concern_ids": [],
                "recovery": _missing("not_applicable"),
            },
            f"req_start_{tag}",
            connector_id=connector_id,
        ),
    )
    assert not started.is_error, started.result
    return started.result["handle"]


def _handle() -> dict[str, Any]:
    _register_connector()
    return asyncio.run(_prepare_and_start())


def _policy_artifact() -> dict[str, Any]:
    reference = store.retain_artifact(
        CHANNEL,
        "attempt.dispatch",
        "application/json",
        b'{"policy_id":"contain_local_process","reviewed":true}',
        "restricted",
    )
    return reference.to_dict()


def _reviewed_policy(**overrides: Any) -> dict[str, Any]:
    policy: dict[str, Any] = {
        "policy_id": "contain_local_process",
        "version": "1",
        "artifact": _policy_artifact(),
        "review_refs": [_ref(41, "journal_controls_review")],
    }
    policy.update(overrides)
    return policy


def _contain_payload(
    handle: dict[str, Any],
    *,
    kind: str = "local_process",
    resource_id: str = "local_process_ref_0001",
    target: dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
    authorization_refs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "handle": handle,
        "target": (
            {"kind": kind, "resource_id": resource_id} if target is None else target
        ),
        "policy": _reviewed_policy() if policy is None else policy,
        "reason": "bounded_local_cleanup",
        "authorization_refs": (
            [_ref(42, "journal_controls_authorization")]
            if authorization_refs is None
            else authorization_refs
        ),
    }


def _cancel_payload(handle: dict[str, Any], reason: str = "operator_stop") -> dict[str, Any]:
    return {
        "handle": handle,
        "reason": reason,
        "authorization_refs": [_ref(43, "journal_controls_cancel")],
    }


def _error_code(result: Any) -> str:
    assert isinstance(result, ct.ConnectorError), result
    return result.code


# ---------------------------------------------------------------------------
# EXT-CLOSE / EXT-CONTROLS: cancel acknowledgement never implies no commit
# ---------------------------------------------------------------------------


def test_cancel_acknowledgement_does_not_imply_no_commit_fact() -> None:
    handle = _handle()
    receipt = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "RequestNativeCancel",
                _cancel_payload(handle),
                "req_cancel_ack",
            ),
        )
    )
    assert isinstance(receipt, cc.ControlReceipt), receipt

    # A request is recorded as a request; it is not an acknowledgement.
    assert receipt.operation == "RequestNativeCancel"
    assert receipt.target_scope == "native_execution"
    assert receipt.disposition == "requested"
    assert receipt.acknowledged is False
    assert receipt.effect_observed is False
    assert receipt.observation.native_claim_refs == ()
    assert receipt.observation.effect_refs == ()
    assert receipt.certifies_native_cancellation is False
    assert receipt.implies_cancellation is False

    # A control observation can never establish commit absence.
    assert receipt.has_no_commit_fact is False
    assert receipt.no_commit_fact == {"value": None, "reason": "not_observed"}
    assert receipt.commit_absence_state == "unknown"
    assert receipt.observation.commit_absence_state == "unknown"
    assert receipt.observation.has_no_commit_fact is False

    # The carrier receipt is schema-shaped and preserved immutably.
    document = receipt.to_dict()
    assert document["kind"] == "control_receipt"
    assert document["handle"] == handle
    assert document["observation"]["operation"] == "RequestNativeCancel"
    assert document["observation"]["disposition"] == "requested"
    assert set(document["observation"]) == {
        "control_event_id",
        "operation_id",
        "operation",
        "target_scope",
        "disposition",
        "at",
        "authorization_ref",
        "capability_ref",
        "opportunity",
        "request_ref",
        "response_ref",
        "response_checks",
        "native_claim_refs",
        "effect_refs",
        "affected_attempts",
        "measurements",
        "limitations",
    }

    # Authorization is derived from the authenticated registration, not from
    # the cited references.
    assert receipt.authorization.role == "connector"
    assert receipt.authorization.principal_id == PRINCIPAL
    assert receipt.authorization.grant == "attempt.dispatch.write"
    assert receipt.authorization.resource.startswith("control_scope_")

    # The owner-local journal append is attempted; an unavailable audit is
    # disclosed rather than invented as a registration.
    if receipt.audit.appended:
        assert receipt.registration_verified is True
        assert set(receipt.registration_ref) == {
            "journal_id",
            "sequence",
            "event_id",
            "event_hash",
            "pointer",
        }
    else:
        assert receipt.registration_verified is False
        assert any("not journaled" in note for note in receipt.all_limitations)
    assert any(
        "authorization citation" in note for note in receipt.all_limitations
    )

    # A verified acknowledgement is a separate, append-only observation.
    response_ref = _ref(51, "journal_controls_response")
    acknowledged = receipt.with_acknowledgement(
        at=_timepoint(2.0),
        response_ref=response_ref,
        source_checks=_verified_checks(response_ref),
    )
    assert acknowledged.disposition == "acknowledged"
    assert acknowledged.acknowledged is True
    assert acknowledged.operation_id == receipt.operation_id
    assert acknowledged.control_event_id != receipt.control_event_id
    assert len(acknowledged.observations) == 2
    assert acknowledged.observations[0].control_event_id == receipt.control_event_id
    assert acknowledged.observation.response_ref == response_ref
    assert acknowledged.effect_observed is False
    assert acknowledged.certifies_native_cancellation is False
    assert acknowledged.implies_cancellation is False
    assert any(
        "not an observed effect" in note for note in acknowledged.all_limitations
    )

    # An acknowledgement still never implies a no-commit fact.
    assert acknowledged.has_no_commit_fact is False
    assert acknowledged.no_commit_fact == {"value": None, "reason": "not_observed"}
    assert acknowledged.commit_absence_state == "unknown"

    # Unverified response evidence never upgrades the disposition.
    withheld = receipt.with_acknowledgement(
        at=_timepoint(3.0),
        response_ref=_ref(52, "journal_controls_response"),
        source_checks=_unverified_checks(_ref(52, "journal_controls_response")),
    )
    assert withheld.acknowledged is False
    assert withheld.disposition == "unknown"
    assert any(
        "acknowledgement withheld" in note for note in withheld.all_limitations
    )
    assert withheld.has_no_commit_fact is False

    # A subject's confirmed-stop report remains a claim, not a fact.
    claimed = acknowledged.with_subject_stop_claim(
        _ref(53, "journal_controls_native_report")
    )
    assert len(claimed.stop_claims) == 1
    assert claimed.stop_claims[0].state == "claimed"
    assert claimed.stop_claims[0].source == "subject"
    assert claimed.stop_claims[0].kind == "stop"
    assert claimed.stop_claims[0].to_dict()["refs"] == [
        _ref(53, "journal_controls_native_report")
    ]
    assert claimed.disposition == "acknowledged"
    assert claimed.has_no_commit_fact is False
    assert claimed.commit_absence_state == "unknown"
    assert claimed.certifies_native_cancellation is False

    # The observation type itself refuses an unbacked acknowledgement.
    unbacked = receipt.observation.to_dict()
    unbacked["disposition"] = "acknowledged"
    with pytest.raises(ValueError, match="acknowledgement"):
        cc.ControlObservation(**unbacked)

    # Claim states are closed: a stop report is never upgraded to a fact.
    with pytest.raises(ValueError, match="claim"):
        cc.RetainedClaim(
            claim_id="clm_controls_bad",
            kind="stop",
            source="subject",
            state="confirmed",
            refs=(_ref(54),),
        )

    # Only controls are accepted, and only connector authority may issue them.
    unsupported = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request("Prepare", {"scope": {}, "configuration": {}, "task": {}}, "req_not_control"),
        )
    )
    assert _error_code(unsupported) == "INVALID_REQUEST"

    unknown_handle = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "RequestNativeCancel",
                _cancel_payload({"connector_id": CONNECTOR, "local_handle": "hdl_unknown"}),
                "req_unknown_handle",
            ),
        )
    )
    assert _error_code(unknown_handle) == "UNKNOWN_HANDLE"

    unmapped = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "RequestNativeCancel",
                _cancel_payload(handle, reason="unsupported_mapping_test"),
                "req_cancel_unmapped",
            ),
        )
    )
    assert _error_code(unmapped) == "UNSUPPORTED_MAPPING"
    assert unmapped.kind == "connector_error"

    # Application credentials never grant connector control access.
    ap.register_channel(
        actor="origin_fact_recorder",
        channel_id=APP_CHANNEL,
        axis="attempt.application",
        producer_id="prod_controls_application",
        principal_id="principal_controls_application",
        sequence_required=False,
        allowed_event_kinds=("attempt.commissioned",),
        binding="bind_controls_application",
    )
    denied = asyncio.run(
        cc.control_task(
            APP_CHANNEL,
            _request(
                "RequestNativeCancel",
                _cancel_payload(handle),
                "req_cancel_application",
            ),
        )
    )
    assert _error_code(denied) == "FORBIDDEN"

    unauthenticated = asyncio.run(
        cc.control_task(
            "ch_controls_unknown",
            _request(
                "RequestNativeCancel",
                _cancel_payload(handle),
                "req_cancel_unknown_channel",
            ),
        )
    )
    assert _error_code(unauthenticated) == "UNAUTHENTICATED"


# ---------------------------------------------------------------------------
# EXT-CONTROLS: containment never certifies native cancellation
# ---------------------------------------------------------------------------


def test_process_containment_does_not_certify_native_cancellation() -> None:
    handle = _handle()
    containment = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request("Contain", _contain_payload(handle), "req_contain_local"),
        )
    )
    assert isinstance(containment, cc.ControlReceipt), containment
    assert containment.operation == "Contain"
    assert containment.target_scope == "local_process"
    assert containment.disposition == "requested"
    assert containment.acknowledged is False
    assert containment.effect_observed is False
    assert containment.certifies_native_cancellation is False
    assert containment.implies_cancellation is False
    assert containment.observation.native_claim_refs == ()
    assert containment.has_no_commit_fact is False
    assert containment.commit_absence_state == "unknown"

    # Even an *observed* containment effect is not a native-cancellation
    # certification: the remote execution was never addressed by this call.
    observed = containment.with_effect_evidence(
        at=_timepoint(4.0),
        effect_refs=[_ref(61, "journal_controls_containment_effect")],
    )
    assert observed.disposition == "effect_observed"
    assert observed.effect_observed is True
    assert observed.observation.effect_refs == (
        _ref(61, "journal_controls_containment_effect"),
    )
    assert observed.certifies_native_cancellation is False
    assert observed.implies_cancellation is False
    assert observed.operation == "Contain"
    assert observed.target_scope == "local_process"
    assert observed.has_no_commit_fact is False
    assert observed.no_commit_fact == {"value": None, "reason": "not_observed"}
    assert observed.commit_absence_state == "unknown"

    # Containment targets are bounded: no shell text, guessed PIDs, paths, or
    # unbounded shared-resource cleanup.
    for target in (
        {"kind": "local_process", "resource_id": "rm -rf / && curl http://evil"},
        {"kind": "local_process", "resource_id": "12345"},
        {"kind": "local_process", "resource_id": "pid:4242"},
        {"kind": "local_process", "resource_id": "shared_resources/host_1"},
        {"kind": "shared_host", "resource_id": "host_1"},
        {"kind": "local_process", "resource_id": "local_process_ref_0001", "pid": 42},
    ):
        rejected = asyncio.run(
            cc.control_task(
                CHANNEL,
                _request(
                    "Contain",
                    _contain_payload(handle, target=target),
                    "req_contain_bad_target",
                ),
            )
        )
        assert _error_code(rejected) == "INVALID_REQUEST", target

    # Fixture mutation authority requires a commissioned laboratory fixture;
    # an employer origin's mutation authority is never sealed by containment.
    fixture_target = {
        "kind": "fixture_mutation_authority",
        "resource_id": "fixture_origin_authority_1",
    }
    without_commission = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                {
                    "handle": handle,
                    "target": fixture_target,
                    "policy": _reviewed_policy(),
                    "reason": "fixture_seal",
                    "authorization_refs": [_ref(42, "journal_controls_authorization")],
                },
                "req_contain_fixture_no_commission",
            ),
        )
    )
    assert _error_code(without_commission) == "PREREQUISITE_UNAVAILABLE"

    unresolvable_commission = {
        "digest": "sha256:" + "7" * 64,
        "size_bytes": 32,
        "media_type": "application/json",
        "owner_domain": "attempt.dispatch",
        "access": "restricted",
    }
    missing_commission = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                {
                    "handle": handle,
                    "target": fixture_target,
                    "policy": _reviewed_policy(commission=unresolvable_commission),
                    "reason": "fixture_seal",
                    "authorization_refs": [_ref(42, "journal_controls_authorization")],
                },
                "req_contain_fixture_bad_commission",
            ),
        )
    )
    assert _error_code(missing_commission) == "PREREQUISITE_UNAVAILABLE"

    # A unreviewed or unbounded policy is not executable.
    no_review = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                {
                    "handle": handle,
                    "target": {"kind": "local_process", "resource_id": "local_process_ref_0002"},
                    "policy": {"policy_id": "contain_local_process", "version": "1"},
                    "reason": "bounded_local_cleanup",
                    "authorization_refs": [_ref(42)],
                },
                "req_contain_no_review",
            ),
        )
    )
    assert _error_code(no_review) == "INVALID_REQUEST"

    unavailable_policy = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                _contain_payload(
                    handle,
                    policy=_reviewed_policy(
                        artifact={
                            "digest": "sha256:" + "6" * 64,
                            "size_bytes": 8,
                            "media_type": "application/json",
                            "owner_domain": "attempt.dispatch",
                            "access": "restricted",
                        }
                    ),
                ),
                "req_contain_unavailable_policy",
            ),
        )
    )
    assert _error_code(unavailable_policy) == "PREREQUISITE_UNAVAILABLE"

    # Containment is separately authorized and never stands in for release,
    # close, or cancellation: it requires its own explicit authorization and
    # cannot carry another verb's payload field.
    no_authorization = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                _contain_payload(handle, authorization_refs=[]),
                "req_contain_no_authorization",
            ),
        )
    )
    assert _error_code(no_authorization) == "INVALID_REQUEST"

    merged_verbs = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "Contain",
                {
                    **_contain_payload(handle),
                    "end_observation": True,
                    "context_ref": "ctx_controls_1",
                },
                "req_contain_merged_verbs",
            ),
        )
    )
    assert _error_code(merged_verbs) == "INVALID_REQUEST"

    cancellation = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request("RequestNativeCancel", _cancel_payload(handle), "req_cancel_vs_contain"),
        )
    )
    assert isinstance(cancellation, cc.ControlReceipt)
    assert cancellation.operation == "RequestNativeCancel"
    assert cancellation.target_scope == "native_execution"
    assert cancellation.certifies_native_cancellation is False
    assert cancellation.operation_id != containment.operation_id
    assert containment.target_scope != cancellation.target_scope
    assert containment.operation != cancellation.operation

    # The contract's containment scope vocabulary is exactly the bounded set.
    assert cc.CONTAINMENT_TARGET_KINDS == frozenset(
        {
            "fixture_mutation_authority",
            "local_process",
            "deployment_slot",
            "harness_resources",
        }
    )


# ---------------------------------------------------------------------------
# EXT-CLOSE / LIFE-CLOSE: close and end_observation stay separate from cancel
# ---------------------------------------------------------------------------


def test_connection_close_and_end_observation_remain_separate_from_native_cancel() -> None:
    handle = _handle()
    transport_only = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "CloseObservationConnection",
                {
                    "handle": handle,
                    "reason": "operator_stop",
                    "end_observation": False,
                    "authorization_refs": [_ref(71, "journal_controls_close")],
                },
                "req_close_transport_only",
            ),
        )
    )
    assert isinstance(transport_only, cc.ControlReceipt), transport_only
    assert transport_only.operation == "CloseObservationConnection"
    assert transport_only.target_scope == "observation_connection"
    assert transport_only.disposition == "requested"
    assert transport_only.closes_transport is True
    assert transport_only.ends_observation is False
    assert transport_only.stops_new_commands is False
    assert transport_only.begins_finalization is False
    assert transport_only.observation.native_claim_refs == ()
    assert transport_only.observation.effect_refs == ()
    assert transport_only.certifies_native_cancellation is False
    assert transport_only.implies_cancellation is False
    assert transport_only.durable_observation_closed == {
        "value": None,
        "reason": "not_observed",
    }
    assert transport_only.has_no_commit_fact is False
    assert transport_only.commit_absence_state == "unknown"

    end_observation = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "CloseObservationConnection",
                {
                    "handle": handle,
                    "reason": "local_deadline",
                    "end_observation": True,
                    "authorization_refs": [_ref(72, "journal_controls_close")],
                },
                "req_close_end_observation",
            ),
        )
    )
    assert isinstance(end_observation, cc.ControlReceipt), end_observation
    assert end_observation.operation == "CloseObservationConnection"
    assert end_observation.closes_transport is True
    assert end_observation.ends_observation is True
    assert end_observation.stops_new_commands is True
    assert end_observation.begins_finalization is True
    # Ending observation still requests no cancellation and closes no durable
    # Observe; the receipt never publishes connector-owned closure state.
    assert end_observation.certifies_native_cancellation is False
    assert end_observation.implies_cancellation is False
    assert end_observation.durable_observation_closed == {
        "value": None,
        "reason": "not_observed",
    }
    assert end_observation.observation.native_claim_refs == ()
    assert end_observation.observation.effect_refs == ()
    assert end_observation.disposition == "requested"

    released = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "ReleaseNativeContext",
                {
                    "handle": handle,
                    "context_ref": "ctx_controls_1",
                    "authorization_refs": [_ref(73, "journal_controls_release")],
                },
                "req_release_context",
            ),
        )
    )
    assert isinstance(released, cc.ControlReceipt), released
    assert released.operation == "ReleaseNativeContext"
    assert released.target_scope == "native_context"
    assert released.disposition == "requested"
    assert released.ends_observation is False
    assert released.certifies_native_cancellation is False
    assert released.durable_observation_closed == {
        "value": None,
        "reason": "not_observed",
    }

    # A release without a named context uses the typed Missing envelope; a bare
    # null is rejected outright.
    anonymous_release = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "ReleaseNativeContext",
                {
                    "handle": handle,
                    "context_ref": _missing("not_applicable"),
                    "authorization_refs": [_ref(74, "journal_controls_release")],
                },
                "req_release_context_missing",
            ),
        )
    )
    assert isinstance(anonymous_release, cc.ControlReceipt), anonymous_release
    assert anonymous_release.operation == "ReleaseNativeContext"
    assert anonymous_release.target_scope == "native_context"
    null_release = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "ReleaseNativeContext",
                {
                    "handle": handle,
                    "context_ref": None,
                    "authorization_refs": [],
                },
                "req_release_context_null",
            ),
        )
    )
    assert _error_code(null_release) == "INVALID_REQUEST"

    cancellation = asyncio.run(
        cc.control_task(
            CHANNEL,
            _request(
                "RequestNativeCancel",
                _cancel_payload(handle, reason="normal_completion"),
                "req_cancel_after_close",
            ),
        )
    )
    assert isinstance(cancellation, cc.ControlReceipt), cancellation
    assert cancellation.operation == "RequestNativeCancel"
    assert cancellation.target_scope == "native_execution"
    assert cancellation.disposition == "requested"
    assert cancellation.certifies_native_cancellation is False

    # Every control is its own operation: distinct operation ids, distinct
    # control events, distinct target scopes.  Closing did not record a
    # cancellation, and cancelling did not record a close.
    receipts = (transport_only, end_observation, released, cancellation)
    assert len({receipt.operation_id for receipt in receipts}) == len(receipts)
    assert len({receipt.control_event_id for receipt in receipts}) == len(receipts)
    assert {receipt.target_scope for receipt in receipts} == {
        "observation_connection",
        "native_context",
        "native_execution",
    }
    for close_receipt in (transport_only, end_observation):
        assert close_receipt.observation.operation == "CloseObservationConnection"
        assert close_receipt.observation.operation != cancellation.observation.operation
        assert close_receipt.observation.target_scope == "observation_connection"
        assert close_receipt.observation.native_claim_refs == ()
        assert close_receipt.observation.effect_refs == ()
        assert close_receipt.acknowledged is False

    # Observation histories are append-only per operation; a cancellation
    # observation can never be appended to a close receipt.
    with pytest.raises(ValueError, match="operation"):
        transport_only.append_observation(cancellation.observation)

    # end_observation must be an explicit boolean; missing, bare-null, and
    # numeric stand-ins are rejected, as are merged or unbounded close payloads.
    for payload in (
        {"handle": handle, "reason": "operator_stop", "authorization_refs": []},
        {
            "handle": handle,
            "reason": "operator_stop",
            "end_observation": None,
            "authorization_refs": [],
        },
        {
            "handle": handle,
            "reason": "operator_stop",
            "end_observation": 1,
            "authorization_refs": [],
        },
        {
            "handle": handle,
            "reason": "operator_stop",
            "end_observation": "true",
            "authorization_refs": [],
        },
        {
            "handle": handle,
            "reason": "operator_stop",
            "end_observation": True,
            "authorization_refs": [],
            "context_ref": "ctx_controls_1",
        },
        {
            "handle": handle,
            "reason": "shutdown_now",
            "end_observation": True,
            "authorization_refs": [],
        },
    ):
        rejected = asyncio.run(
            cc.control_task(
                CHANNEL,
                _request(
                    "CloseObservationConnection",
                    payload,
                    "req_close_invalid",
                ),
            )
        )
        assert _error_code(rejected) == "INVALID_REQUEST", payload
