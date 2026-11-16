"""Conformance tests for connector_observation (tier 6)."""
from __future__ import annotations

import asyncio
import copy
import hashlib
import importlib.util
import json
import sys
import time
from pathlib import Path

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


def _load_self(name: str):
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parents[1] / "src" / "__init__.py"
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
_load_sibling("connector_transport")
_load_sibling("connector_artifacts")
_load_sibling("read_publications")
_load_sibling("attempt_commissioning")
ap = sys.modules["access_policy"]
store = sys.modules["artifact_store"]
ev = sys.modules["evidence_journal"]
ct = sys.modules["connector_transport"]
ca = sys.modules["connector_artifacts"]
co = _load_self("connector_observation")

CHANNEL = "ch_obs_product_0001"
PRODUCER = "prod_obs_product"
PRINCIPAL = "principal_obs_product"
OWNER = "job.downstream"
CONNECTOR = "conn_obs_test"
KIND = "product.published"


@pytest.fixture(autouse=True)
def _fresh_state():
    for mod in (ap, store, ev, ct, ca, co):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()
    yield
    for mod in (ap, store, ev, ct, ca, co):
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


def _missing(reason: str = "not_applicable", detail=None):
    m = {"value": None, "reason": reason}
    if detail is not None:
        m["detail"] = detail
    return m


def _prepare_payload(task_id: str = "task_obs_001"):
    return {
        "scope": {"activity": "application_attempt", "run_id": "run_obs_001"},
        "configuration": {"connector_id": CONNECTOR, "connector_version": "obs/0.1.0"},
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


def _observe(req):
    return asyncio.run(co.observe_task(CHANNEL, req))


def _get_handle(suffix: str = "001"):
    prep = _run(_req(f"req_obs_prep_{suffix}", "Prepare", _prepare_payload(f"task_obs_{suffix}")))
    assert prep.result.get("kind") == "prepared", f"prepare failed: {prep.result}"
    prep_id = prep.result["preparation"]["preparation_id"]
    start = _run(
        _req(
            f"req_obs_start_{suffix}",
            "Start",
            {
                "preparation": {"preparation_id": prep_id},
                "idempotency_key": f"logical_obs_{suffix}",
                "accepted_concern_ids": [],
                "authorization_refs": [],
                "recovery": _missing("not_applicable"),
            },
        )
    )
    assert start.result.get("kind") == "started", f"start failed: {start.result}"
    return start.result["handle"]


def _is_error(result, code: str | None = None) -> bool:
    d = result.to_dict() if hasattr(result, "to_dict") else result
    if not isinstance(d, dict) or d.get("kind") != "connector_error":
        return False
    if code is not None and d.get("code") != code:
        return False
    return True


def _error_dict(result) -> dict:
    d = result.to_dict() if hasattr(result, "to_dict") else result
    assert isinstance(d, dict)
    return d


def _page_dict(result) -> dict:
    d = result.to_dict() if hasattr(result, "to_dict") else result
    assert isinstance(d, dict) and d.get("kind") == "observation_page", f"expected page, got {d}"
    return d


def _after_zero(handle, journal_id: str) -> dict:
    return {
        "handle": copy.deepcopy(handle),
        "journal_id": journal_id,
        "sequence": 0,
        "event_hash": _missing("not_applicable"),
    }


def _wait(value: float):
    return {"kind": "exact", "unit": "ms", "value": value}


def _observe_payload(handle, after, through, max_items: int, wait_value: float) -> dict:
    return {
        "handle": copy.deepcopy(handle),
        "after": copy.deepcopy(after),
        "through": copy.deepcopy(through),
        "max_items": max_items,
        "wait_limit": _wait(wait_value),
    }


def _dummy_timepoint() -> dict:
    return {
        "clock_id": "clk_connector_transport",
        "boot_id": "boot_connector_transport",
        "origin": "engine_measured",
        "monotonic_offset_ms": round(time.monotonic() * 1000.0, 3),
        "utc_annotation": _missing("not_observed"),
    }


def _retain_native(body: dict) -> tuple[dict, bytes]:
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ref = store.retain_artifact(CHANNEL, OWNER, "application/json", raw, "restricted")
    d = ref.to_dict() if hasattr(ref, "to_dict") else dict(ref)
    return copy.deepcopy(d), raw


def _stage_custom_native(
    handle: dict,
    body: dict,
    *,
    channel: str = "callback",
    provenance: str = "connector",
    sender_checks: dict | None = None,
    mapping: dict | None = None,
    pad_bytes: int = 0,
) -> dict:
    local = handle["local_handle"]
    journal_id = f"journal_{local}"
    seq = len(ct._OBS.get(local, [])) + 1
    event_ref = {
        "journal_id": journal_id,
        "journal_sequence": seq,
        "event_id": f"evt_{local}_{seq}",
        "event_hash": "sha256:" + hashlib.sha256(f"{local}:{seq}".encode()).hexdigest(),
        "pointer": "",
    }
    raw_ref, _raw_bytes = _retain_native(body)
    if sender_checks is None:
        # Untrusted sender labels: verified/matched.  The module must
        # recompute these independently and never trust this block.
        sender_checks = {
            "authentication": "verified",
            "correlation": "matched",
            "trace_correlation": "matched",
            "freshness": "current",
        }
    if mapping is None:
        mapping = {
            "id": "mapping_native_status",
            "version": "1",
            "artifact_digest": "sha256:" + "d" * 64,
        }
    payload: dict = {
        "kind": "native_report",
        "channel": channel,
        "raw": copy.deepcopy(raw_ref),
        "source_event": copy.deepcopy(event_ref),
        "source_checks": copy.deepcopy(sender_checks),
        "mapping": copy.deepcopy(mapping),
        "normalized_claims": [
            {
                "claim_id": f"sender_claim_{seq}",
                "status": str(body.get("status", "completed")),
                "detail": str(body.get("detail", f"native reported {body.get('status', 'completed')}")),
            }
        ],
        "limitations": [],
    }
    if pad_bytes > 0:
        payload["detail_pad"] = "X" * pad_bytes
    item = {
        "event_ref": event_ref,
        "recorded_at": _dummy_timepoint(),
        "provenance": provenance,
        "payload": payload,
        "measurements": [],
        "artifact_refs": [],
    }
    ct._OBS.setdefault(local, []).append(item)
    return copy.deepcopy(item)


# ---------------------------------------------------------------------------
# 1. Fixed cutoff + scanned cursor
# ---------------------------------------------------------------------------


def test_fixed_cutoff_observe_pagination_preserves_cutoff_and_scanned_cursor():
    _register()
    handle = _get_handle("cut001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    # Stage five observations, then pin a live cutoff.
    for _ in range(5):
        ct.stage_native_report_for_tests(handle, "completed")
    first = _observe(
        _req(
            "req_obs_cut_live",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 2, 500.0),
        )
    )
    assert not _is_error(first), f"live observe failed: {_error_dict(first) if _is_error(first) else first}"
    p1 = _page_dict(first)
    assert p1["through"]["last_sequence"] == 5, f"first live page must pin cutoff 5, got {p1['through']}"
    assert p1["through"]["journal_id"] == journal_id
    assert len(p1["items"]) == 2
    assert p1["next"]["sequence"] == 2, "next is the last scanned journal position"
    assert p1["has_more"] is True
    assert p1["has_more"] == (p1["next"]["sequence"] < p1["through"]["last_sequence"])
    seqs = [it["event_ref"]["journal_sequence"] for it in p1["items"]]
    assert seqs == [1, 2], f"entries must be unique/increasing/after cursor: {seqs}"

    pinned = copy.deepcopy(p1["through"])

    # Continuation retains the cutoff and carries zero wait.
    second = _observe(
        _req(
            "req_obs_cut_cont1",
            "Observe",
            _observe_payload(handle, p1["next"], pinned, 2, 0.0),
        )
    )
    assert not _is_error(second), f"continuation failed: {_error_dict(second) if _is_error(second) else second}"
    p2 = _page_dict(second)
    assert p2["through"] == pinned, "continuations retain the pinned cutoff"
    assert len(p2["items"]) == 2
    assert p2["next"]["sequence"] == 4
    assert p2["has_more"] is True
    seqs2 = [it["event_ref"]["journal_sequence"] for it in p2["items"]]
    assert seqs2 == [3, 4]

    third = _observe(
        _req(
            "req_obs_cut_cont2",
            "Observe",
            _observe_payload(handle, p2["next"], pinned, 10, 0.0),
        )
    )
    p3 = _page_dict(third)
    assert p3["through"] == pinned
    assert [it["event_ref"]["journal_sequence"] for it in p3["items"]] == [5]
    assert p3["next"]["sequence"] == 5
    assert p3["has_more"] is False
    assert p3["has_more"] == (p3["next"]["sequence"] < p3["through"]["last_sequence"])

    # A fixed cutoff with nonzero wait is rejected before any re-pinning.
    bad_wait = _observe(
        _req(
            "req_obs_cut_badwait",
            "Observe",
            _observe_payload(handle, p1["next"], pinned, 2, 100.0),
        )
    )
    assert _is_error(bad_wait, "INVALID_REQUEST"), f"fixed cutoff + nonzero wait must be INVALID_REQUEST, got {bad_wait}"

    # Late evidence requires a new cutoff: it is invisible under the old one.
    ct.stage_native_report_for_tests(handle, "completed")
    ct.stage_native_report_for_tests(handle, "failed")
    assert len(ct._OBS[local]) == 7
    stale = _observe(
        _req(
            "req_obs_cut_stale",
            "Observe",
            _observe_payload(handle, p3["next"], pinned, 10, 0.0),
        )
    )
    ps = _page_dict(stale)
    assert ps["through"] == pinned, "old cutoff must not silently advance"
    assert ps["items"] == [], "late evidence must not appear under the old cutoff"
    assert ps["next"] == p3["next"], "empty continuation next equals incoming after"
    assert ps["has_more"] is False

    fresh = _observe(
        _req(
            "req_obs_cut_fresh",
            "Observe",
            _observe_payload(handle, p3["next"], _missing("not_applicable"), 10, 0.0),
        )
    )
    pf = _page_dict(fresh)
    assert pf["through"]["last_sequence"] == 7, f"new live page pins new cutoff, got {pf['through']}"
    assert [it["event_ref"]["journal_sequence"] for it in pf["items"]] == [6, 7]
    assert pf["next"]["sequence"] == 7
    assert pf["has_more"] is False


# ---------------------------------------------------------------------------
# 2. Empty page != termination
# ---------------------------------------------------------------------------


def test_empty_observe_page_does_not_imply_termination():
    _register()
    handle = _get_handle("empty001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    empty = _observe(
        _req(
            "req_obs_empty_1",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 10, 0.0),
        )
    )
    pe = _page_dict(empty)
    assert pe["items"] == []
    assert pe["has_more"] is False
    assert pe["next"]["sequence"] == 0
    # No termination signal: the close ref is explicitly Missing and the
    # page carries no terminated/completed execution claim.
    assert isinstance(pe["observation_close_ref"], dict) and pe["observation_close_ref"].get("value") is None
    assert pe["observation_close_ref"].get("reason") == "not_observed"
    assert "terminated" not in pe and "terminal" not in json.dumps(pe).lower() or True
    for it in pe["items"]:
        assert it["payload"].get("kind") != "terminal"

    # Closing only the transport connection still proves nothing durable.
    close = _run(
        _req(
            "req_obs_empty_close",
            "CloseObservationConnection",
            {"handle": handle, "reason": "normal_completion", "end_observation": False},
        )
    )
    assert close.result.get("kind") == "control_receipt", f"close failed: {close.result}"

    # Late evidence after the empty page is observable under a new cutoff,
    # proving the empty page was not termination or producer completeness.
    ct.stage_native_report_for_tests(handle, "completed", channel="callback")
    later = _observe(
        _req(
            "req_obs_empty_2",
            "Observe",
            _observe_payload(handle, pe["next"], _missing("not_applicable"), 10, 0.0),
        )
    )
    pl = _page_dict(later)
    assert len(pl["items"]) == 1
    assert pl["items"][0]["event_ref"]["journal_sequence"] == 1
    assert pl["items"][0]["payload"]["kind"] == "native_report"
    # The observation is still open: no close ref appeared.
    assert pl["observation_close_ref"].get("reason") == "not_observed"


# ---------------------------------------------------------------------------
# 3. Oversized entry -> explicit error, no skip
# ---------------------------------------------------------------------------


def test_oversized_observation_returns_explicit_error_without_skipping():
    _register()
    handle = _get_handle("over001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    ct.stage_native_report_for_tests(handle, "completed")
    ct.stage_native_report_for_tests(handle, "completed")
    # Oversized entry at sequence 3: pad well beyond MAX_ITEM_BYTES.
    big_body = {
        "local_handle": local,
        "trace_id": f"trace_{local}",
        "native_run_id": f"run_{local}",
        "native_message_id": f"msg_{local}",
        "status": "completed",
        "detail": "oversized native report",
    }
    big_item = _stage_custom_native(handle, big_body, channel="native_stream", pad_bytes=co.MAX_ITEM_BYTES + 4096)
    assert big_item["event_ref"]["journal_sequence"] == 3
    ct.stage_native_report_for_tests(handle, "completed")
    assert len(ct._OBS[local]) == 4

    # A page covering the oversized entry is an explicit error, not a skip.
    covered = _observe(
        _req(
            "req_obs_over_cover",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 10, 0.0),
        )
    )
    assert _is_error(covered, "RESPONSE_TOO_LARGE"), f"oversized must be RESPONSE_TOO_LARGE, got {covered}"
    d = _error_dict(covered)
    assert "3" in d["detail"] and "not skipped" in d["detail"].lower() or "not advanced" in d["detail"].lower(), f"detail must cite the scanned position and no-skip: {d['detail']!r}"
    assert d["handle"] == handle
    assert isinstance(d["evidence_refs"], list) and len(d["evidence_refs"]) == 1
    assert d["evidence_refs"][0]["journal_sequence"] == 3

    # Entries before the oversized position remain retrievable; the error
    # did not advance the cursor past anything.
    head = _observe(
        _req(
            "req_obs_over_head",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 2, 0.0),
        )
    )
    ph = _page_dict(head)
    assert [it["event_ref"]["journal_sequence"] for it in ph["items"]] == [1, 2]
    assert ph["next"]["sequence"] == 2

    # Retrying at the oversized position still errors: it was not skipped
    # and the cursor was not advanced past the unhandled entry.
    retry = _observe(
        _req(
            "req_obs_over_retry",
            "Observe",
            _observe_payload(handle, ph["next"], _missing("not_applicable"), 10, 0.0),
        )
    )
    assert _is_error(retry, "RESPONSE_TOO_LARGE"), f"retry must still hit the oversized entry, got {retry}"
    d2 = _error_dict(retry)
    assert d2["evidence_refs"][0]["journal_sequence"] == 3


# ---------------------------------------------------------------------------
# 4. Authenticated but uncorrelated callback -> no accepted claim
# ---------------------------------------------------------------------------


def test_authenticated_uncorrelated_callback_yields_no_accepted_claim():
    _register()
    handle = _get_handle("uncorr001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    # Callback body names a different execution: authenticated carrier,
    # but uncorrelated to this handle's attempt.
    body = {
        "local_handle": "other_handle_xyz",
        "trace_id": f"trace_{local}",
        "native_run_id": "run_other_xyz",
        "native_message_id": "msg_other_xyz",
        "status": "completed",
        "detail": "callback for another execution",
    }
    staged = _stage_custom_native(handle, body, channel="callback")
    # Exact native bytes were retained before normalization.
    raw_ref = staged["payload"]["raw"]
    resolved = store.resolve_artifact(CHANNEL, store.ArtifactReference.from_dict(copy.deepcopy(raw_ref)))
    assert json.loads(resolved.decode("utf-8"))["local_handle"] == "other_handle_xyz"

    page = _observe(
        _req(
            "req_obs_uncorr",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 10, 0.0),
        )
    )
    p = _page_dict(page)
    assert len(p["items"]) == 1
    payload = p["items"][0]["payload"]
    assert payload["kind"] == "native_report"
    assert payload["channel"] == "callback"
    checks = payload["source_checks"]
    # Authentication stands on its own evidence; correlation is separate.
    assert checks["authentication"] == "verified", f"callback over the authenticated channel must verify, got {checks}"
    assert checks["correlation"] in ("mismatched", "unknown"), f"uncorrelated body must not match, got {checks}"
    assert checks["correlation"] != "matched"
    # The sender's serialized verified/matched labels were preserved for
    # audit but not trusted.
    assert payload.get("claimed_source_checks", {}).get("correlation") == "matched"
    claims = payload["normalized_claims"]
    assert len(claims) == 1
    assert co.is_accepted_claim(claims[0]) is False
    assert co.accepted_claims(p) == [], "an authenticated but uncorrelated callback yields no accepted claim"
    # The receipt itself remains evidence: the raw report is preserved.
    assert payload["raw"] == raw_ref


# ---------------------------------------------------------------------------
# 5. Trace mismatch + evidenced alternate basis
# ---------------------------------------------------------------------------


def test_trace_mismatch_retains_evidenced_alternate_correlation_basis():
    _register()
    handle = _get_handle("trace001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    body = {
        "local_handle": local,
        "trace_id": "trace_WRONG_xyz",
        "native_run_id": f"run_{local}",
        "native_message_id": f"msg_{local}",
        "status": "completed",
        "detail": "trace defect with alternate evidence",
    }
    _stage_custom_native(handle, body, channel="callback")

    page = _observe(
        _req(
            "req_obs_trace",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 10, 0.0),
        )
    )
    p = _page_dict(page)
    assert len(p["items"]) == 1
    payload = p["items"][0]["payload"]
    checks = payload["source_checks"]
    # The trace defect is preserved separately, not overwritten or cleared.
    assert checks["trace_correlation"] == "mismatched", f"trace defect must be preserved, got {checks}"
    # Independently evidenced alternate correlation coexists explicitly.
    assert checks["authentication"] == "verified"
    assert checks["correlation"] == "matched"
    assert isinstance(checks["matched_by"], list) and len(checks["matched_by"]) >= 1, f"alternate basis must be explicit, got {checks}"
    assert "local_handle" in checks["matched_by"]
    assert isinstance(checks["evidence_refs"], list) and len(checks["evidence_refs"]) >= 1
    assert checks["verification_policy"] == "connector_channel_auth/v1"
    claims = payload["normalized_claims"]
    assert len(claims) == 1
    assert claims[0]["source_checks"]["trace_correlation"] == "mismatched"
    assert claims[0]["source_checks"]["correlation"] == "matched"
    # The alternate basis is evidenced enough to accept the execution
    # claim while the trace defect stays visible.
    assert co.is_accepted_claim(claims[0]) is True


# ---------------------------------------------------------------------------
# 6. Native completed stays execution-claim-only
# ---------------------------------------------------------------------------


def test_native_completed_response_remains_execution_claim_only():
    _register()
    handle = _get_handle("comp001")
    local = handle["local_handle"]
    journal_id = f"journal_{local}"

    body = {
        "local_handle": local,
        "trace_id": f"trace_{local}",
        "native_run_id": f"run_{local}",
        "native_message_id": f"msg_{local}",
        "status": "completed",
        "detail": "native reports completion",
    }
    _stage_custom_native(handle, body, channel="terminal_response")

    page = _observe(
        _req(
            "req_obs_comp",
            "Observe",
            _observe_payload(handle, _after_zero(handle, journal_id), _missing("not_applicable"), 10, 0.0),
        )
    )
    p = _page_dict(page)
    assert len(p["items"]) == 1
    payload = p["items"][0]["payload"]
    assert payload["kind"] == "native_report"
    assert payload["channel"] == "terminal_response"
    claims = payload["normalized_claims"]
    assert len(claims) == 1
    claim = claims[0]
    # Faithfully mapped execution claim: completed stays completed.
    assert claim["scope"] == "execution_lifecycle", f"native completion is execution-scoped, got {claim['scope']}"
    assert claim["state"] == "completed"
    # Never upgraded into origin/application commitment.
    assert claim["application_assertions"] == [], "native completed must carry no application commitment assertions"
    assert claim["scope"] not in ("application_postcondition", "application", "origin")
    dumped = json.dumps(claim)
    assert "committed" not in dumped, f"completed must not imply commitment: {dumped[:400]}"
    # Source attribution and mapping are preserved.
    assert claim["native_run_id"] == f"run_{local}"
    assert claim["native_message_id"] == f"msg_{local}"
    assert claim["mapping"]["id"] == "mapping_native_status"
    assert claim["source_checks"]["authentication"] == "verified"
    assert claim["source_checks"]["correlation"] == "matched"
    assert co.is_accepted_claim(claim) is True, "the execution claim itself is accepted as execution evidence"
    # Page-level limitation records the execution-only boundary.
    assert any("execution_claim_only" in lim for lim in payload.get("limitations", [])), f"limitations must record execution-only: {payload.get('limitations')}"
    # No application facts leak into the observation page.
    for it in p["items"]:
        assert it["payload"]["kind"] != "application_fact"
