"""Conformance tests for connector_dispatch (tier 6)."""
from __future__ import annotations

import asyncio
import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


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


def _load_self():
    name = "connector_dispatch"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "src" / "__init__.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


codec = _load_sibling("contract_codec")
ap = _load_sibling("access_policy")
store = _load_sibling("artifact_store")
ev = _load_sibling("evidence_journal")
ct = _load_sibling("connector_transport")
ac = _load_sibling("attempt_commissioning")
dispatch = _load_self()

CHANNEL = "ch_dispatch_product_0001"
PRODUCER = "prod_dispatch_product"
PRINCIPAL = "principal_dispatch_product"
OWNER = "job.downstream"
CONNECTOR = "conn_dispatch_test"
CONNECTOR_B = "conn_dispatch_exec_b"
SUBJECT = "subject_dispatch_test"
TARGET = "employer_origin_test"
KIND = "dispatch.decision"

D0 = "sha256:" + "0" * 64
POLICY = {"id": "policy_dispatch_test", "version": "1", "artifact_digest": D0}
CLOCK_ID = "clock_dispatch_test"
BOOT_ID = "boot_dispatch_test"

CONFIG_A = {
    "connector_id": CONNECTOR,
    "connector_version": "dispatch/0.1.0",
    "profile": "alpha",
}
CONFIG_B = {
    "connector_id": CONNECTOR,
    "connector_version": "dispatch/0.1.0",
    "profile": "bravo",
}
CONFIG_EXEC_A = {
    "connector_id": CONNECTOR,
    "connector_version": "dispatch/0.1.0",
    "executor": "a",
}
CONFIG_EXEC_B = {
    "connector_id": CONNECTOR_B,
    "connector_version": "dispatch/0.1.0",
    "executor": "b",
}

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
    for mod in (ap, store, ev, ct, ac, dispatch):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()
    yield
    for mod in (ap, store, ev, ct, ac, dispatch):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _register():
    return ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=(KIND,),
    )


def _missing(reason: str = "not_applicable"):
    return {"value": None, "reason": reason}


def _call_limit(value: float = 5000.0):
    return {"kind": "exact", "unit": "ms", "value": value}


def _duration_limit(value: float = 5000.0):
    return {"kind": "exact", "unit": "ms", "value": value}


def _evidence_ref(journal_id: str, event_id: str, sequence: int = 1):
    return {
        "journal_id": journal_id,
        "sequence": sequence,
        "event_id": event_id,
        "event_hash": D0,
        "pointer": "",
    }


def _timepoint(offset: float = 1.0):
    return {
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset,
        "utc_annotation": _missing("not_observed"),
    }


def _budgets(value: float = 5000.0):
    return {
        "active_limit": _duration_limit(value),
        "action_limit": _duration_limit(value),
        "observation_byte_limit": _duration_limit(value),
        "recovery_limit": _duration_limit(value),
        "model_token_limit": _duration_limit(value),
    }


def _context_policy(
    browser_mode: str = "fresh",
    browser_req: str = "required",
    learning_mode: str = "fresh",
    learning_req: str = "required",
):
    return {
        "browser_state": {
            "mode": browser_mode,
            "requirement": browser_req,
            "resource_ref": _missing(),
            "baseline": _missing(),
        },
        "learning_state": {
            "mode": learning_mode,
            "requirement": learning_req,
            "resource_ref": _missing(),
            "baseline": _missing(),
        },
    }


def _task(
    task_id: str,
    task_type: str = "extract",
    *,
    context_policy=None,
    budgets=None,
    extra: dict | None = None,
):
    effect = "read_only" if task_type in ("extract", "discover_jobs") else "commissioned_application"
    interfaces = ["read_only_acquisition"] if effect == "read_only" else ["ordinary_browser"]
    task = {
        "task_id": task_id,
        "task_type": task_type,
        "entry": {"logical_id": "entry_001", "url": "https://example.invalid/apply"},
        "goal": f"bounded fixture goal for {task_id}",
        "success_criteria": [{"criterion_id": "c1", "description": "fields extracted"}],
        "inputs": [],
        "permitted_origins": [{"logical_id": "entry_001", "origin": "https://example.invalid"}],
        "permitted_interfaces": interfaces,
        "effect_policy": effect,
        "budgets": copy.deepcopy(budgets) if budgets is not None else _budgets(),
        "context_policy": copy.deepcopy(context_policy)
        if context_policy is not None
        else _context_policy(),
        "output_schema": {"id": "schema_extract", "version": "1", "artifact_digest": D0},
    }
    if extra:
        task.update(copy.deepcopy(extra))
    return task


def _scope_discovery(run_id: str = "run_dispatch_discovery"):
    return {
        "activity": "discovery",
        "run_id": run_id,
        "journal_id": f"journal_{run_id}",
        "manifest_hash": D0,
        "admission_ref": _evidence_ref(f"journal_{run_id}", f"evt_admit_{run_id}"),
        "attempt": _missing(),
        "commission": _missing(),
        "commission_ref": _missing(),
        "authorization_refs": [_evidence_ref(f"journal_{run_id}", f"evt_auth_{run_id}")],
        "observation_policy": {
            "active_limit": _duration_limit(),
            "drain_limit": _duration_limit(),
            "native_cancel_wait_limit": _duration_limit(),
            "cleanup_wait_limit": _duration_limit(),
            "fixture_close_action": "seal_after_drain",
        },
    }


def _scope_application(commission_id: str, run_id: str, journal_id: str, commission_ref: dict):
    return {
        "activity": "application_attempt",
        "run_id": run_id,
        "journal_id": journal_id,
        "manifest_hash": D0,
        "admission_ref": _evidence_ref(journal_id, f"evt_admit_{run_id}"),
        "attempt": {"attempt_id": f"attempt_{commission_id}", "kind": "production"},
        "commission": {"commission_id": commission_id},
        "commission_ref": copy.deepcopy(commission_ref),
        "authorization_refs": [_evidence_ref(journal_id, f"evt_auth_{run_id}")],
        "observation_policy": {
            "active_limit": _duration_limit(),
            "drain_limit": _duration_limit(),
            "native_cancel_wait_limit": _duration_limit(),
            "cleanup_wait_limit": _duration_limit(),
            "fixture_close_action": "not_applicable",
        },
    }


def _prepare_payload(
    scope: dict,
    configuration: dict,
    task: dict,
    *,
    runtime_access=None,
    assistance=None,
):
    return {
        "scope": copy.deepcopy(scope),
        "configuration": copy.deepcopy(configuration),
        "task": copy.deepcopy(task),
        "assistance": copy.deepcopy(assistance)
        if assistance is not None
        else {"planning_owner": "none"},
        "planning_evidence_refs": [],
        "preparation_measurements": [],
        "runtime_access": copy.deepcopy(runtime_access)
        if runtime_access is not None
        else _missing(),
    }


def _start_payload(preparation_id: str, key: str, accepted=None, recovery=None):
    return {
        "preparation": {"preparation_id": preparation_id},
        "idempotency_key": key,
        "accepted_concern_ids": list(accepted) if accepted is not None else [],
        "authorization_refs": [_evidence_ref("journal_dispatch_test", f"evt_start_{key}")],
        "recovery": copy.deepcopy(recovery) if recovery is not None else _missing(),
    }


def _req(request_id: str, connector_id: str, operation: str, payload: dict):
    return ct.ConnectorRequest(
        request_id=request_id,
        connector_id=connector_id,
        operation=operation,
        call_limit=_call_limit(),
        payload=copy.deepcopy(payload),
    )


def _register_subject(connector_id: str, version: str, configuration: dict):
    return dispatch.register_subject_for_tests(
        connector_id, SUBJECT, version, configuration=copy.deepcopy(configuration)
    )


def _commission_record(
    commission_id: str,
    run_id: str,
    journal_id: str,
    subject_version: str = "v1",
) -> dict[str, Any]:
    task_bytes = json.dumps({"task": commission_id}, sort_keys=True).encode("utf-8")
    task_ref = store.retain_artifact(CHANNEL, OWNER, "application/json", task_bytes, "public")
    snapshot_bytes = json.dumps({"snapshot": commission_id}, sort_keys=True).encode("utf-8")
    snapshot_ref = store.retain_artifact(CHANNEL, OWNER, "application/json", snapshot_bytes, "public")
    return {
        "record_type": "attempt_commission",
        "schema_version": "application-attempt-lifecycle/0.1.0",
        "kernel_version": "evidence-kernel/0.1.0",
        "commission_id": commission_id,
        "run_id": run_id,
        "journal_id": journal_id,
        "manifest_hash": D0,
        "admission_ref": _evidence_ref(journal_id, f"evt_admit_{commission_id}"),
        "commissioned_by": PRINCIPAL,
        "commissioned_at": _timepoint(),
        "attempt": {
            "attempt_id": f"attempt_{commission_id}",
            "kind": "production",
            "target_class": "employer_origin",
            "target_id": TARGET,
            "evaluation_partition": "held_out",
            "rehearsal_of": [],
            "performance_of": [],
            "derived_from": [],
        },
        "candidate_id": "candidate_dispatch_001",
        "candidate_profile": _missing("not_observed"),
        "job": {
            "job_id": "portfolio_job_dispatch_001",
            "source_target": "source_target_dispatch",
            "source_job_id": "source_job_dispatch_001",
            "snapshot": snapshot_ref.to_dict(),
        },
        "selection_evidence": _missing("not_observed"),
        "task": task_ref.to_dict(),
        "task_semantic_hash": D0,
        "initial_materials": [],
        "execution": {
            "mode": "subject",
            "subject": {
                "subject_id": SUBJECT,
                "subject_version": subject_version,
                "revision_basis": "native_revision",
                "native_revision": "rev_1",
                "configured_mode": "subject_apply",
                "interface_surface": "browser_task",
                "configuration_digest": D0,
                "stack": [],
            },
            "connector_version": "conn_v1",
            "binding_version": "bind_v1",
            "assistance": {
                "planning_owner": "none",
                "assistance_track": "no_assistance",
                "planner_identity": _missing(),
                "plan": _missing(),
                "online_replanning": False,
                "description": "No assistance is declared.",
            },
        },
        "owners": {
            "dispatch": {
                "role": "connector",
                "source_id": CONNECTOR,
                "writer_id": "writer_dispatch",
                "owner_domain": "attempt.dispatch",
                "publication_policy": dict(POLICY),
            },
            "observation": {
                "role": "connector",
                "source_id": "src_dispatch_obs",
                "writer_id": "writer_obs",
                "owner_domain": "attempt.observation",
                "publication_policy": dict(POLICY),
            },
            "execution": {
                "role": "subject",
                "source_id": SUBJECT,
                "writer_id": "writer_exec",
                "owner_domain": "attempt.execution",
                "publication_policy": dict(POLICY),
            },
            "application": {
                "role": "origin",
                "source_id": TARGET,
                "writer_id": "writer_app",
                "owner_domain": "attempt.application",
                "publication_policy": dict(POLICY),
            },
            "report": {
                "role": "reconciler",
                "source_id": "src_dispatch_rec",
                "writer_id": "writer_rep",
                "owner_domain": "attempt.report",
                "publication_policy": dict(POLICY),
            },
        },
        "idempotency_key": f"commission_key_{commission_id}",
        "authorization_refs": [_evidence_ref(journal_id, f"evt_commauth_{commission_id}")],
        "recovery_review_refs": [],
        "observation_policy": {
            "active_limit": _duration_limit(0),
            "drain_limit": _duration_limit(0),
            "native_cancel_wait_limit": _duration_limit(0),
            "cleanup_wait_limit": _duration_limit(0),
            "fixture_close_action": "not_applicable",
        },
        "origin_policy": dict(POLICY),
    }


def _retain_commission(record: dict) -> dict:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ref = store.retain_artifact(CHANNEL, OWNER, "application/json", payload, "public")
    return ref.to_dict()


def _assert_error_shape(result: dict, operation: str):
    assert result.get("kind") == "connector_error", f"{operation}: expected connector_error"
    required = {
        "kind", "code", "fault_domain", "detail", "operation_delivery",
        "retry_guidance", "retry_after", "handle", "evidence_refs",
    }
    assert set(result.keys()) == required, f"{operation}: keys {sorted(result.keys())}"
    assert result["code"] in ct.ERROR_CODES
    assert result["fault_domain"] in ct.FAULT_DOMAINS
    assert result["operation_delivery"] in ct.DELIVERY_VALUES
    assert result["retry_guidance"] in ct.RETRY_VALUES
    assert isinstance(result["detail"], str) and result["detail"]
    for key in FABRICATED_KEYS:
        assert key not in result


# ---------------------------------------------------------------------------
# Conformance assertions
# ---------------------------------------------------------------------------


def test_prepare_browsing_or_invoking_planning_fails_connector_conformance():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    base_scope = _scope_discovery("run_prepare_conf")
    base_task = _task("task_prepare_conf_001")


    def _payload_with(mutate):
        payload = _prepare_payload(base_scope, CONFIG_A, base_task)
        mutate(payload)
        return payload

    cases = [
        ("top-level browse_target", lambda p: p.update({"browse_target": {"url": "https://example.invalid"}})),
        ("nested probe_subject", lambda p: p["task"].update({"probe_subject": {"capability": "native_dom_access"}})),
        ("top-level invoke_planning", lambda p: p.update({"invoke_planning": True})),
        ("nested planning_request", lambda p: p["assistance"].update({"planning_request": {"goal": "plan it"}})),
        ("top-level test_login", lambda p: p.update({"test_login": {"account": "candidate"}})),
        ("nested reset_context", lambda p: p["task"].update({"reset_context": True})),
        ("nested improve_plan", lambda p: p["task"].update({"improve_plan": True})),
        ("nested execute_actions", lambda p: p["scope"].update({"execute_actions": ["click"]})),
        ("forbidden recovery", lambda p: p.update({"recovery": _missing()})),
    ]
    for index, (label, mutate) in enumerate(cases):
        payload = _payload_with(mutate)
        response = asyncio.run(
            dispatch.prepare_task(CHANNEL, _req(f"req_browse_{index:02d}", CONNECTOR, "Prepare", payload))
        )
        assert response.result.get("kind") == "connector_error", label
        _assert_error_shape(response.result, "Prepare")
        assert response.result["code"] == "INVALID_REQUEST", label
        lowered = response.result["detail"].lower()
        assert ("non-executing" in lowered) or ("recovery" in lowered), label

    # Positive control: the identical shape without execution keys prepares.
    clean = asyncio.run(
        dispatch.prepare_task(
            CHANNEL, _req("req_browse_clean", CONNECTOR, "Prepare", _payload_with(lambda p: None))
        )
    )
    assert clean.result.get("kind") == "prepared", f"clean prepare failed: {clean.result}"
    assert clean.result["preparation"]["preparation_id"]
    assert isinstance(clean.result["record"]["concerns"], list)

    # Operation mismatch is never reinterpreted.
    describe_as_prepare = asyncio.run(
        dispatch.prepare_task(CHANNEL, _req("req_op_mm_001", CONNECTOR, "Describe", {}))
    )
    assert describe_as_prepare.result["code"] == "INVALID_REQUEST"
    prepare_as_describe = asyncio.run(
        dispatch.describe_subject(
            CHANNEL, _req("req_op_mm_002", CONNECTOR, "Prepare", _payload_with(lambda p: None))
        )
    )
    assert prepare_as_describe.result["code"] == "INVALID_REQUEST"
    prepare_as_start = asyncio.run(
        dispatch.start_task(CHANNEL, _req("req_op_mm_003", CONNECTOR, "Prepare", _payload_with(lambda p: None)))
    )
    assert prepare_as_start.result["code"] == "INVALID_REQUEST"


def test_start_before_commission_registration_is_rejected():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    commission_id = "commission_unregistered_001"
    run_id = "run_unregistered_001"
    journal_id = "journal_unregistered_001"
    record = _commission_record(commission_id, run_id, journal_id)
    # NOTE: commission bytes are deliberately NOT retained yet.
    dead_ref = {
        "digest": "sha256:" + "d" * 64,
        "size_bytes": 8,
        "media_type": "application/json",
        "owner_domain": OWNER,
        "access": "public",
    }
    scope = _scope_application(commission_id, run_id, journal_id, dead_ref)
    task = _task("task_apply_unregistered_001", "apply")
    prepared = asyncio.run(
        dispatch.prepare_task(
            CHANNEL, _req("req_unreg_prepare", CONNECTOR, "Prepare", _prepare_payload(scope, CONFIG_A, task))
        )
    )
    assert prepared.result.get("kind") == "prepared", f"prepare failed: {prepared.result}"
    prep_id = prepared.result["preparation"]["preparation_id"]

    rejected = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_unreg_start", CONNECTOR, "Start", _start_payload(prep_id, "logical_unreg_001"))
        )
    )
    assert rejected.result.get("kind") == "connector_error"
    _assert_error_shape(rejected.result, "Start")
    assert rejected.result["code"] == "NOT_ADMITTED"
    assert "commission" in rejected.result["detail"].lower()
    # The rejection claimed no logical execution.
    assert dispatch.get_commission_execution_for_tests(commission_id) is None
    assert dispatch.get_preparation_for_tests(prep_id) is not None

    # After registration the same logical key starts exactly once.
    live_ref = _retain_commission(record)
    assert ac.load_commission(CHANNEL, live_ref).commission_id == commission_id
    scope_live = _scope_application(commission_id, run_id, journal_id, live_ref)
    prepared_live = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req("req_unreg_prepare2", CONNECTOR, "Prepare", _prepare_payload(scope_live, CONFIG_A, task)),
        )
    )
    assert prepared_live.result.get("kind") == "prepared"
    prep_live = prepared_live.result["preparation"]["preparation_id"]
    started = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_unreg_start2", CONNECTOR, "Start", _start_payload(prep_live, "logical_unreg_001"))
        )
    )
    assert started.result.get("kind") == "started", f"start failed: {started.result}"
    execution = dispatch.get_commission_execution_for_tests(commission_id)
    assert execution is not None
    assert execution["local_handle"] == started.result["handle"]["local_handle"]
    assert execution["connector_id"] == CONNECTOR


def test_unaccepted_required_preparation_concern_rejects_start():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    scope = _scope_discovery("run_concern_001")
    runtime_access = {
        "purpose": "account_session",
        "access_ref": "sess_ref_concern_001",
        "authorization_refs": [_evidence_ref("journal_concern_001", "evt_sess_auth")],
    }
    prepared = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req(
                "req_concern_prepare",
                CONNECTOR,
                "Prepare",
                _prepare_payload(scope, CONFIG_A, _task("task_concern_001"), runtime_access=runtime_access),
            ),
        )
    )
    assert prepared.result.get("kind") == "prepared", f"prepare failed: {prepared.result}"
    concerns = prepared.result["record"]["concerns"]
    assert {c["concern_id"] for c in concerns} == {"session_use_requires_acceptance"}
    concern = concerns[0]
    assert concern["disposition"] == "requires_acceptance"
    assert concern["category"] == "state_policy_unverified"
    assert concern["detail"]
    assert concern["evidence_refs"]
    prep_id = prepared.result["preparation"]["preparation_id"]

    # Starting without accepting the required concern is rejected.
    refused = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_concern_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_concern_001"))
        )
    )
    assert refused.result.get("kind") == "connector_error"
    _assert_error_shape(refused.result, "Start")
    assert refused.result["code"] == "FORBIDDEN"
    assert "session_use_requires_acceptance" in refused.result["detail"]

    # Unknown concern IDs are rejected rather than silently accepted.
    unknown = asyncio.run(
        dispatch.start_task(
            CHANNEL,
            _req(
                "req_concern_start2", CONNECTOR, "Start",
                _start_payload(prep_id, "logical_concern_001", accepted=["concern_nope_unknown"]),
            ),
        )
    )
    assert unknown.result["code"] == "INVALID_REQUEST"

    # Accepting the evidenced concern under a new command starts.
    accepted_start = asyncio.run(
        dispatch.start_task(
            CHANNEL,
            _req(
                "req_concern_start3", CONNECTOR, "Start",
                _start_payload(prep_id, "logical_concern_001", accepted=["session_use_requires_acceptance"]),
            ),
        )
    )
    assert accepted_start.result.get("kind") == "started", f"start failed: {accepted_start.result}"
    assert accepted_start.result["disposition"] == "accepted_locally"


def test_stale_configuration_or_preparation_is_rejected():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    described = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_stale_desc1", CONNECTOR, "Describe", {})))
    assert described.result.get("record_type") == "connector_descriptor"

    scope = _scope_discovery("run_stale_001")
    prepared = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req("req_stale_prepare1", CONNECTOR, "Prepare", _prepare_payload(scope, CONFIG_A, _task("task_stale_001"))),
        )
    )
    assert prepared.result.get("kind") == "prepared"
    prep_id = prepared.result["preparation"]["preparation_id"]

    # Rotating the live configuration stale-marks the preparation: no silent reprepare.
    dispatch.rotate_configuration_for_tests(CONNECTOR, CONFIG_B)
    stale = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_stale_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_stale_001"))
        )
    )
    assert stale.result.get("kind") == "connector_error"
    _assert_error_shape(stale.result, "Start")
    assert stale.result["code"] == "STALE_PREPARATION"

    # A fresh preparation under the live configuration starts.
    prepared_fresh = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req("req_stale_prepare2", CONNECTOR, "Prepare", _prepare_payload(scope, CONFIG_B, _task("task_stale_001"))),
        )
    )
    assert prepared_fresh.result.get("kind") == "prepared"
    prep_fresh = prepared_fresh.result["preparation"]["preparation_id"]
    started = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_stale_start2", CONNECTOR, "Start", _start_payload(prep_fresh, "logical_stale_001"))
        )
    )
    assert started.result.get("kind") == "started", f"fresh start failed: {started.result}"

    # A superseded descriptor stale-marks preparations pinned to it.
    dispatch.register_subject_for_tests(CONNECTOR, SUBJECT, "v2", configuration=dict(CONFIG_B))
    described_v2 = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_stale_desc2", CONNECTOR, "Describe", {})))
    assert described_v2.result["subject"]["subject_version"] == "v2"
    stale_desc = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_stale_start3", CONNECTOR, "Start", _start_payload(prep_id, "logical_stale_002"))
        )
    )
    assert stale_desc.result["code"] == "STALE_PREPARATION"
    # And a preparation under the new descriptor starts on a fresh key.
    prepared_v2 = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req("req_stale_prepare3", CONNECTOR, "Prepare", _prepare_payload(scope, CONFIG_B, _task("task_stale_002"))),
        )
    )
    assert prepared_v2.result.get("kind") == "prepared"
    started_v2 = asyncio.run(
        dispatch.start_task(
            CHANNEL,
            _req(
                "req_stale_start4", CONNECTOR, "Start",
                _start_payload(prepared_v2.result["preparation"]["preparation_id"], "logical_stale_003"),
            ),
        )
    )
    assert started_v2.result.get("kind") == "started"


def test_repeated_start_new_request_id_same_logical_key_returns_same_handle():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    prepared = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req(
                "req_repeat_prepare", CONNECTOR, "Prepare",
                _prepare_payload(_scope_discovery("run_repeat_001"), CONFIG_A, _task("task_repeat_001")),
            ),
        )
    )
    assert prepared.result.get("kind") == "prepared"
    prep_id = prepared.result["preparation"]["preparation_id"]

    first = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_repeat_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_repeat_001"))
        )
    )
    assert first.result.get("kind") == "started", f"first start failed: {first.result}"
    assert first.result["disposition"] == "accepted_locally"
    handle = first.result["handle"]
    assert handle["connector_id"] == CONNECTOR
    assert handle["local_handle"]

    # New command identity, same logical key: the same handle, no second execution.
    second = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_repeat_start2", CONNECTOR, "Start", _start_payload(prep_id, "logical_repeat_001"))
        )
    )
    assert second.result.get("kind") == "started"
    assert second.result["disposition"] == "existing_handle"
    assert second.result["handle"] == handle
    assert second.result["handle_artifact"] == first.result["handle_artifact"]

    # Identical retry of the first command replays its retained receipt.
    replay = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_repeat_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_repeat_001"))
        )
    )
    assert replay.to_dict()["result"] == first.to_dict()["result"]

    # Changed content under the same command identity is a conflict.
    conflict = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_repeat_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_repeat_CHANGED"))
        )
    )
    assert conflict.result["code"] == "IDEMPOTENCY_CONFLICT"


def test_changed_executor_after_uncertain_delivery_never_automatically_reexecutes():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_EXEC_A)
    _register_subject(CONNECTOR_B, "v1", CONFIG_EXEC_B)
    commission_id = "commission_exec_fence_001"
    run_id = "run_exec_fence_001"
    journal_id = "journal_exec_fence_001"
    live_ref = _retain_commission(_commission_record(commission_id, run_id, journal_id))
    scope = _scope_application(commission_id, run_id, journal_id, live_ref)
    task = _task("task_apply_exec_001", "apply")

    prepared_a = asyncio.run(
        dispatch.prepare_task(
            CHANNEL, _req("req_exec_prepare_a", CONNECTOR, "Prepare", _prepare_payload(scope, CONFIG_EXEC_A, task))
        )
    )
    assert prepared_a.result.get("kind") == "prepared"
    started_a = asyncio.run(
        dispatch.start_task(
            CHANNEL,
            _req(
                "req_exec_start_a", CONNECTOR, "Start",
                _start_payload(prepared_a.result["preparation"]["preparation_id"], "logical_exec_001"),
            ),
        )
    )
    assert started_a.result.get("kind") == "started", f"start A failed: {started_a.result}"
    handle_a = started_a.result["handle"]["local_handle"]

    # Delivery may have occurred: uncertainty is preserved on the same handle.
    marked = dispatch.mark_delivery_uncertain_for_tests(handle_a)
    assert marked["delivery"] == "may_have_dispatched"
    assert marked["commission_id"] == commission_id

    # Preparing through the replacement executor is non-executing, hence allowed;
    # starting through it must never launch a second execution.
    prepared_b = asyncio.run(
        dispatch.prepare_task(
            CHANNEL, _req("req_exec_prepare_b", CONNECTOR_B, "Prepare", _prepare_payload(scope, CONFIG_EXEC_B, task))
        )
    )
    assert prepared_b.result.get("kind") == "prepared"
    prep_b = prepared_b.result["preparation"]["preparation_id"]

    switched_same_key = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_exec_start_b1", CONNECTOR_B, "Start", _start_payload(prep_b, "logical_exec_001"))
        )
    )
    assert switched_same_key.result.get("kind") == "connector_error"
    _assert_error_shape(switched_same_key.result, "Start")
    assert switched_same_key.result["code"] == "IDEMPOTENCY_CONFLICT"
    assert "executor" in switched_same_key.result["detail"].lower()
    assert switched_same_key.result["retry_guidance"] != "new_command_if_not_dispatched"

    switched_new_key = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_exec_start_b2", CONNECTOR_B, "Start", _start_payload(prep_b, "logical_exec_002"))
        )
    )
    assert switched_new_key.result["code"] == "IDEMPOTENCY_CONFLICT"

    # The commissioned execution is untouched: same connector, same handle.
    execution = dispatch.get_commission_execution_for_tests(commission_id)
    assert execution is not None
    assert execution["connector_id"] == CONNECTOR
    assert execution["local_handle"] == handle_a
    assert execution["delivery"] == "may_have_dispatched"

    # The original logical key still discloses its handle; the fence is stable.
    again = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_exec_start_b3", CONNECTOR_B, "Start", _start_payload(prep_b, "logical_exec_001"))
        )
    )
    assert again.result["code"] == "IDEMPOTENCY_CONFLICT"
    original = asyncio.run(
        dispatch.start_task(
            CHANNEL,
            _req(
                "req_exec_start_a2", CONNECTOR, "Start",
                _start_payload(prepared_a.result["preparation"]["preparation_id"], "logical_exec_001"),
            ),
        )
    )
    assert original.result.get("kind") == "started"
    assert original.result["handle"]["local_handle"] == handle_a


def test_resume_after_draining_or_closure_is_rejected():
    _register()
    _register_subject(CONNECTOR, "v1", CONFIG_A)
    prepared = asyncio.run(
        dispatch.prepare_task(
            CHANNEL,
            _req(
                "req_resume_prepare", CONNECTOR, "Prepare",
                _prepare_payload(_scope_discovery("run_resume_001"), CONFIG_A, _task("task_resume_001")),
            ),
        )
    )
    assert prepared.result.get("kind") == "prepared"
    prep_id = prepared.result["preparation"]["preparation_id"]
    started = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_resume_start1", CONNECTOR, "Start", _start_payload(prep_id, "logical_resume_001"))
        )
    )
    assert started.result.get("kind") == "started", f"start failed: {started.result}"
    handle = copy.deepcopy(started.result["handle"])
    assert dispatch.get_observation_state_for_tests(handle["local_handle"]) == "open"

    checkpoint_bytes = json.dumps({"checkpoint": "native_step_3"}).encode("utf-8")
    checkpoint_ref = store.retain_artifact(CHANNEL, OWNER, "application/json", checkpoint_bytes, "public").to_dict()

    def _recovery():
        return {
            "handle": copy.deepcopy(handle),
            "checkpoint": copy.deepcopy(checkpoint_ref),
            "native_resume_contract": {"contract_id": "nrc_resume_001", "max_steps": 5},
            "authorization_refs": [_evidence_ref("journal_resume_001", "evt_resume_auth")],
            "evidence_refs": [_evidence_ref("journal_resume_001", "evt_resume_evidence")],
        }

    # A malformed resume authorization is rejected while the window is open.
    malformed = _recovery()
    del malformed["evidence_refs"]
    bad_shape = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_resume_bad", CONNECTOR, "Start", _start_payload(prep_id, "logical_resume_001", recovery=malformed))
        )
    )
    assert bad_shape.result["code"] == "INVALID_REQUEST"

    # Resume with a new command identity preserves the same logical dispatch.
    resumed = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_resume_start2", CONNECTOR, "Start", _start_payload(prep_id, "logical_resume_001", recovery=_recovery()))
        )
    )
    assert resumed.result.get("kind") == "started", f"resume failed: {resumed.result}"
    assert resumed.result["handle"] == handle

    # Once draining, resume is rejected.
    dispatch.set_observation_state_for_tests(handle["local_handle"], "draining")
    draining = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_resume_start3", CONNECTOR, "Start", _start_payload(prep_id, "logical_resume_001", recovery=_recovery()))
        )
    )
    assert draining.result.get("kind") == "connector_error"
    _assert_error_shape(draining.result, "Start")
    assert draining.result["code"] == "OBSERVATION_CLOSED"
    assert "draining" in draining.result["detail"]

    # After closure, resume is rejected.
    dispatch.set_observation_state_for_tests(handle["local_handle"], "closed")
    closed = asyncio.run(
        dispatch.start_task(
            CHANNEL, _req("req_resume_start4", CONNECTOR, "Start", _start_payload(prep_id, "logical_resume_001", recovery=_recovery()))
        )
    )
    assert closed.result["code"] == "OBSERVATION_CLOSED"
    assert "closed" in closed.result["detail"]


def test_new_subject_version_starts_unknown_until_own_evidence():
    _register()
    expected_catalog = [
        "native_goal_task",
        "native_plan_execution",
        "native_cancel",
        "native_context_release",
        "native_artifact_retrieval",
        "native_revision",
        "native_dom_access",
        "browser_state_isolation",
        "browser_state_persistence",
        "learning_state_control",
    ]

    dispatch.register_subject_for_tests(CONNECTOR, SUBJECT, "v1", configuration=dict(CONFIG_A))
    first = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_version_desc1", CONNECTOR, "Describe", {})))
    assert first.result.get("record_type") == "connector_descriptor"
    descriptor = first.result
    assert descriptor["connector_id"] == CONNECTOR
    assert descriptor["subject"]["subject_id"] == SUBJECT
    assert descriptor["subject"]["subject_version"] == "v1"
    assert descriptor["subject"]["configured_mode"] == "subject_apply"
    assert descriptor["subject"]["interface_surface"] == "browser_task"
    assert descriptor["capabilities"]["subject"] == descriptor["subject"]
    capabilities = descriptor["capabilities"]["capabilities"]
    assert [c["capability_id"] for c in capabilities] == expected_catalog
    assert len({c["capability_id"] for c in capabilities}) == len(capabilities)
    for entry in capabilities:
        assert entry["availability"] == "unknown", entry["capability_id"]
        assert entry["evidence"] == []
    assert len(descriptor["operations"]) == 9
    assert sorted(op["operation"] for op in descriptor["operations"]) == sorted(ct.OPERATIONS)
    assert descriptor["action_grounding"] == "unknown"
    assert descriptor["execution_substrate"] == "unknown"
    text = json.dumps(descriptor)
    for key in FABRICATED_KEYS:
        assert f'"{key}"' not in text
    assert "application_success" not in text

    # Version-scoped evidence establishes one capability for v1 only.
    dispatch.record_capability_evidence_for_tests(SUBJECT, "v1", "native_goal_task", "present")
    evidenced = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_version_desc2", CONNECTOR, "Describe", {})))
    by_id = {c["capability_id"]: c for c in evidenced.result["capabilities"]["capabilities"]}
    assert by_id["native_goal_task"]["availability"] == "present"
    assert by_id["native_goal_task"]["claim_origin"] == "native"
    assert len(by_id["native_goal_task"]["evidence"]) == 1
    assert by_id["native_goal_task"]["evidence"][0]["basis"] == "executed_observation"
    assert by_id["native_goal_task"]["evidence"][0]["ref"]["event_hash"] == D0
    for capability_id, entry in by_id.items():
        if capability_id != "native_goal_task":
            assert entry["availability"] == "unknown", capability_id
    assert evidenced.result["capabilities"]["descriptor_revision"] == 2

    # A new subject version starts unknown on every capability: neither
    # presence nor absence inherits from its predecessor.
    dispatch.register_subject_for_tests(CONNECTOR, SUBJECT, "v2", configuration=dict(CONFIG_A))
    fresh = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_version_desc3", CONNECTOR, "Describe", {})))
    assert fresh.result["subject"]["subject_version"] == "v2"
    for entry in fresh.result["capabilities"]["capabilities"]:
        assert entry["availability"] == "unknown", entry["capability_id"]
        assert entry["evidence"] == []
    assert fresh.result["capabilities"]["descriptor_revision"] == 1

    # Evidence recorded for v2 stays on v2; v1 keeps its own finding.
    dispatch.record_capability_evidence_for_tests(SUBJECT, "v2", "native_cancel", "absent")
    v2_evidenced = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_version_desc4", CONNECTOR, "Describe", {})))
    v2_by_id = {c["capability_id"]: c for c in v2_evidenced.result["capabilities"]["capabilities"]}
    assert v2_by_id["native_cancel"]["availability"] == "absent"
    assert v2_by_id["native_goal_task"]["availability"] == "unknown"
    dispatch.register_subject_for_tests(CONNECTOR, SUBJECT, "v1", configuration=dict(CONFIG_A))
    v1_again = asyncio.run(dispatch.describe_subject(CHANNEL, _req("req_version_desc5", CONNECTOR, "Describe", {})))
    v1_by_id = {c["capability_id"]: c for c in v1_again.result["capabilities"]["capabilities"]}
    assert v1_by_id["native_goal_task"]["availability"] == "present"
    assert v1_by_id["native_cancel"]["availability"] == "unknown"
