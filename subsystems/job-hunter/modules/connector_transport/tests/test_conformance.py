"""Conformance tests for connector_transport (tier 3)."""
from __future__ import annotations

import asyncio
import copy
import importlib.util
import sys
from pathlib import Path

import pytest


def _load(name: str, rel: Path):
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_sibling(name: str):
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"cannot load {name}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


_load_sibling("contract_codec")
_load_sibling("access_policy")
_load_sibling("artifact_store")
_load_sibling("evidence_journal")
ap = sys.modules["access_policy"]
store = sys.modules["artifact_store"]
ev = sys.modules["evidence_journal"]
ct = _load("connector_transport", Path("src/__init__.py"))

CHANNEL = "ch_transport_product_0001"
PRODUCER = "prod_transport_product"
PRINCIPAL = "principal_transport_product"
OWNER = "job.downstream"
CONNECTOR = "conn_transport_test"
KIND = "product.published"

FABRICATED_PHRASES = [
    "task failed",
    "task succeeded",
    "task completed",
    "task success",
    "application committed",
    "application success",
    "origin success",
    "task outcome",
    "task status",
]
FABRICATED_KEYS = {
    "task_status",
    "application_success",
    "origin_success",
    "task_outcome",
    "qualification",
    "application_committed",
}


@pytest.fixture(autouse=True)
def _fresh_state():
    for mod in (ap, store, ev, ct):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()
    yield
    for mod in (ap, store, ev, ct):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()


def _register():
    return ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=True,
        allowed_event_kinds=(KIND,),
    )


def _call_limit(value: float = 5000.0):
    return {"kind": "exact", "unit": "ms", "value": value}


def _missing(reason: str = "not_applicable"):
    return {"value": None, "reason": reason}


def _prepare_payload(task_id: str = "task_conflict_001"):
    return {
        "scope": {"activity": "application_attempt", "run_id": "run_transport_001"},
        "configuration": {"connector_id": CONNECTOR, "connector_version": "transport/0.1.0"},
        "task": {
            "task_id": task_id,
            "task_type": "extract",
            "entry": {"logical_id": "entry_001"},
            "goal": "extract bounded fixture fields",
        },
        "assistance": {"planning_owner": "none"},
        "planning_evidence_refs": [],
        "preparation_measurements": [],
        "runtime_access": _missing("not_applicable"),
    }


def _req(request_id: str, operation: str, payload: dict, call_limit=None):
    return ct.ConnectorRequest(
        request_id=request_id,
        connector_id=CONNECTOR,
        operation=operation,
        call_limit=copy.deepcopy(call_limit) if call_limit is not None else _call_limit(),
        payload=copy.deepcopy(payload),
    )


def _run(req):
    return asyncio.run(ct.call_connector(CHANNEL, req))


def _assert_error_shape(result: dict, operation: str):
    assert isinstance(result, dict), f"{operation}: result must be a dict"
    assert result.get("kind") == "connector_error", f"{operation}: expected connector_error"
    required = {
        "kind",
        "code",
        "fault_domain",
        "detail",
        "operation_delivery",
        "retry_guidance",
        "retry_after",
        "handle",
        "evidence_refs",
    }
    assert set(result.keys()) == required, f"{operation}: error keys {sorted(result.keys())}"
    assert result["code"] in ct.ERROR_CODES, f"unknown code {result['code']!r}"
    assert result["fault_domain"] in ct.FAULT_DOMAINS
    assert result["operation_delivery"] in ct.DELIVERY_VALUES
    assert result["retry_guidance"] in ct.RETRY_VALUES
    assert isinstance(result["detail"], str) and result["detail"], "detail must be nonempty"
    lowered = result["detail"].lower()
    for phrase in FABRICATED_PHRASES:
        assert phrase not in lowered, f"error detail fabricates task outcome: {phrase!r}"
    for key in FABRICATED_KEYS:
        assert key not in result, f"error result fabricates outcome field {key!r}"
    # retry_after is a DurationLimit or typed Missing
    ra = result["retry_after"]
    assert isinstance(ra, dict), "retry_after must be an object"
    if ra.get("value") is None and "reason" in ra:
        assert ra["reason"] in (
            "not_enabled",
            "not_applicable",
            "not_observed",
            "observation_lost",
            "unsupported_by_subject",
            "manual_override",
        )
    else:
        assert ra.get("kind") == "exact" and ra.get("unit") == "ms"
    # handle is a HandleReference or typed Missing
    h = result["handle"]
    assert isinstance(h, dict), "handle must be an object"
    if h.get("value") is None and "reason" in h:
        assert "reason" in h
    else:
        assert "connector_id" in h and "local_handle" in h
    assert isinstance(result["evidence_refs"], list)
    # DELIVERY_UNCERTAIN constraint
    if result["code"] == "DELIVERY_UNCERTAIN":
        assert result["operation_delivery"] == "may_have_dispatched"
        assert result["retry_guidance"] in (
            "same_command_only",
            "operator_review",
            "do_not_retry",
        )
    if result["retry_guidance"] == "new_command_if_not_dispatched":
        assert result["operation_delivery"] in ("not_dispatched", "not_applicable")


def test_changed_request_under_same_command_identity_is_rejected_as_conflict():
    _register()
    request_id = "req_conflict_001"
    payload = _prepare_payload("task_conflict_001")
    first = _run(_req(request_id, "Prepare", payload))
    assert first.operation == "Prepare"
    assert first.request_id == request_id
    assert first.connector_id == CONNECTOR
    assert first.result.get("kind") == "prepared", f"expected prepared, got {first.result}"
    prep_id = first.result["preparation"]["preparation_id"]
    assert isinstance(prep_id, str) and prep_id

    # Identical retry returns the retained receipt without another effect.
    identical = _run(_req(request_id, "Prepare", copy.deepcopy(payload)))
    assert identical.result.get("kind") == "prepared"
    assert identical.result["preparation"]["preparation_id"] == prep_id
    assert identical.to_dict()["result"] == first.to_dict()["result"]

    # Changed payload under the same command identity is rejected.
    changed_payload = _prepare_payload("task_conflict_CHANGED")
    conflict = _run(_req(request_id, "Prepare", changed_payload))
    assert conflict.result.get("kind") == "connector_error"
    _assert_error_shape(conflict.result, "Prepare")
    assert conflict.result["code"] == "IDEMPOTENCY_CONFLICT"

    # Changed call_limit under the same command identity is also a conflict:
    # retries must preserve the original command.
    changed_limit = _run(
        _req(request_id, "Prepare", copy.deepcopy(payload), call_limit=_call_limit(999.0))
    )
    assert changed_limit.result.get("kind") == "connector_error"
    assert changed_limit.result["code"] == "IDEMPOTENCY_CONFLICT"

    # The retained receipt still replays for the original identical command.
    replay = _run(_req(request_id, "Prepare", copy.deepcopy(payload)))
    assert replay.result.get("kind") == "prepared"
    assert replay.result["preparation"]["preparation_id"] == prep_id

    # A new command identity with the changed content is accepted (no cross-key leak).
    fresh = _run(_req("req_conflict_002", "Prepare", changed_payload))
    assert fresh.result.get("kind") == "prepared"
    assert fresh.result["preparation"]["preparation_id"] != prep_id

    # Changed operation under the same request_id is also a conflict, not a second command.
    wrong_op = _run(_req(request_id, "Contain", {"handle": {"connector_id": CONNECTOR, "local_handle": "hdl_x"}, "target": {"kind": "local_process", "resource_id": "r1"}, "policy": {"id": "p", "version": "1"}, "reason": "test"}))
    assert wrong_op.result.get("kind") == "connector_error"
    assert wrong_op.result["code"] == "IDEMPOTENCY_CONFLICT"


def test_connector_errors_describe_operations_without_fabricating_task_outcomes():
    _register()
    # 1) UNKNOWN_HANDLE via Observe describes the operation.
    bad_handle = {"connector_id": CONNECTOR, "local_handle": "hdl_missing_001"}
    after = {
        "handle": bad_handle,
        "journal_id": "journal_missing",
        "sequence": 0,
        "event_hash": _missing("not_applicable"),
    }
    obs_bad = _run(
        _req(
            "req_err_observe_001",
            "Observe",
            {
                "handle": bad_handle,
                "after": after,
                "through": _missing("not_applicable"),
                "max_items": 10,
                "wait_limit": _call_limit(100.0),
            },
        )
    )
    assert obs_bad.result.get("kind") == "connector_error"
    _assert_error_shape(obs_bad.result, "Observe")
    assert obs_bad.result["code"] == "UNKNOWN_HANDLE"
    assert "observe" in obs_bad.result["detail"].lower()

    # 2) INVALID_REQUEST via Prepare with a missing task object.
    bad_prepare = _run(_req("req_err_prepare_001", "Prepare", {"scope": {}, "configuration": {}}))
    assert bad_prepare.result.get("kind") == "connector_error"
    _assert_error_shape(bad_prepare.result, "Prepare")
    assert bad_prepare.result["code"] == "INVALID_REQUEST"

    # 3) PREREQUISITE_UNAVAILABLE is a local prerequisite failure, not a subject failure.
    needy = _prepare_payload("task_prereq_001")
    needy["require_runtime"] = True
    needy["runtime_access"] = _missing("not_applicable")
    prereq = _run(_req("req_err_prepare_002", "Prepare", needy))
    assert prereq.result.get("kind") == "connector_error"
    _assert_error_shape(prereq.result, "Prepare")
    assert prereq.result["code"] == "PREREQUISITE_UNAVAILABLE"
    assert "subject" not in prereq.result["detail"].lower() or "subject-facing" not in prereq.result["detail"].lower()
    lowered = prereq.result["detail"].lower()
    assert "failed" not in lowered or "prerequisite" in lowered or "runtime" in lowered
    assert "subject failed" not in lowered
    assert "task failed" not in lowered

    # 4) UNSUPPORTED_MAPPING for an unmapped task type is a translation failure.
    unmapped = _prepare_payload("task_unmapped_001")
    unmapped["task"]["task_type"] = "teleport"
    mapping_err = _run(_req("req_err_prepare_003", "Prepare", unmapped))
    assert mapping_err.result.get("kind") == "connector_error"
    _assert_error_shape(mapping_err.result, "Prepare")
    assert mapping_err.result["code"] == "UNSUPPORTED_MAPPING"
    assert "subject failed" not in mapping_err.result["detail"].lower()

    # 5) IDEMPOTENCY_CONFLICT also carries the full error shape.
    payload = _prepare_payload("task_err_conflict_001")
    ok = _run(_req("req_err_conflict_001", "Prepare", payload))
    assert ok.result.get("kind") == "prepared"
    conflict = _run(_req("req_err_conflict_001", "Prepare", _prepare_payload("task_err_conflict_CHANGED")))
    assert conflict.result.get("kind") == "connector_error"
    _assert_error_shape(conflict.result, "Prepare")
    assert conflict.result["code"] == "IDEMPOTENCY_CONFLICT"

    # 6) Native failed/completed/stopped claims are ordinary Observe evidence, not errors.
    prep = _run(_req("req_obs_prep_001", "Prepare", _prepare_payload("task_observe_001")))
    assert prep.result.get("kind") == "prepared"
    prep_id = prep.result["preparation"]["preparation_id"]
    start = _run(
        _req(
            "req_obs_start_001",
            "Start",
            {
                "preparation": {"preparation_id": prep_id},
                "idempotency_key": "logical_obs_001",
                "accepted_concern_ids": [],
                "authorization_refs": [],
                "recovery": _missing("not_applicable"),
            },
        )
    )
    assert start.result.get("kind") == "started", f"start failed: {start.result}"
    handle = start.result["handle"]
    for status in ("failed", "completed", "stopped"):
        staged = ct.stage_native_report_for_tests(handle, status)
        assert staged["payload"]["normalized_claims"][0]["status"] == status
        page_req = _req(
            f"req_obs_read_{status}",
            "Observe",
            {
                "handle": handle,
                "after": {
                    "handle": handle,
                    "journal_id": f"journal_{handle['local_handle']}",
                    "sequence": 0,
                    "event_hash": _missing("not_applicable"),
                },
                "through": _missing("not_applicable"),
                "max_items": 10,
                "wait_limit": _call_limit(100.0),
            },
        )
        page = _run(page_req)
        assert page.result.get("kind") == "observation_page", (
            f"native {status} claim must be normal Observe evidence, got {page.result}"
        )
        assert page.result["kind"] == "observation_page"
        assert isinstance(page.result["items"], list) and page.result["items"]
        found = [
            item
            for item in page.result["items"]
            if item.get("payload", {}).get("kind") == "native_report"
            and any(
                str(c.get("status", "")).lower() == status
                for c in item["payload"].get("normalized_claims", [])
            )
        ]
        assert found, f"native {status} claim missing from Observe page"
        # The page itself carries no composite task outcome.
        for key in FABRICATED_KEYS:
            assert key not in page.result
        assert page.result.get("kind") != "connector_error"

    # 7) Control errors also describe only the operation (unknown handle, not task failure).
    cancel = _run(
        _req(
            "req_err_cancel_001",
            "RequestNativeCancel",
            {"handle": bad_handle, "reason": "operator request", "authorization_refs": []},
        )
    )
    assert cancel.result.get("kind") == "connector_error"
    _assert_error_shape(cancel.result, "RequestNativeCancel")
    assert cancel.result["code"] == "UNKNOWN_HANDLE"
