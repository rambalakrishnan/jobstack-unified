"""Conformance tests for connector_artifacts (tier 4)."""
from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import importlib.util
import sys
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
ap = sys.modules["access_policy"]
store = sys.modules["artifact_store"]
ev = sys.modules["evidence_journal"]
ct = sys.modules["connector_transport"]
ca = _load_self("connector_artifacts")

CHANNEL = "ch_artifacts_product_0001"
PRODUCER = "prod_artifacts_product"
PRINCIPAL = "principal_artifacts_product"
OWNER = "job.downstream"
CONNECTOR = "conn_artifacts_test"
KIND = "product.published"


@pytest.fixture(autouse=True)
def _fresh_state():
    for mod in (ap, store, ev, ct, ca):
        fn = getattr(mod, "reset_for_tests", None)
        if callable(fn):
            fn()
    yield
    for mod in (ap, store, ev, ct, ca):
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


def _prepare_payload(task_id: str = "task_artifacts_001"):
    return {
        "scope": {"activity": "application_attempt", "run_id": "run_artifacts_001"},
        "configuration": {"connector_id": CONNECTOR, "connector_version": "artifacts/0.1.0"},
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


def _collect(req):
    return asyncio.run(ca.collect_task_artifacts(CHANNEL, req))


def _get_handle(suffix: str = "001"):
    prep = _run(_req(f"req_art_prep_{suffix}", "Prepare", _prepare_payload(f"task_art_{suffix}")))
    assert prep.result.get("kind") == "prepared", f"prepare failed: {prep.result}"
    prep_id = prep.result["preparation"]["preparation_id"]
    start = _run(
        _req(
            f"req_art_start_{suffix}",
            "Start",
            {
                "preparation": {"preparation_id": prep_id},
                "idempotency_key": f"logical_art_{suffix}",
                "accepted_concern_ids": [],
                "authorization_refs": [],
                "recovery": _missing("not_applicable"),
            },
        )
    )
    assert start.result.get("kind") == "started", f"start failed: {start.result}"
    return start.result["handle"]


def _retain(content: bytes, access: str = "public", media: str = "application/octet-stream"):
    return store.retain_artifact(CHANNEL, OWNER, media, content, access)


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


def test_collect_artifacts_arbitrary_path_or_url_is_rejected():
    _register()
    handle = _get_handle("path001")
    content = b"artifact-bytes-for-path-test-001"
    ref = _retain(content)
    digest = ref.digest if hasattr(ref, "digest") else ref["digest"]

    # Control: valid selectors succeed through the real transport + verifier.
    inv = _collect(_req("req_art_ctrl_inv", "CollectArtifacts", {"handle": handle, "selector": {"mode": "inventory"}}))
    assert isinstance(inv, ca.ArtifactInventory), f"valid inventory rejected: {_error_dict(inv) if _is_error(inv) else inv}"
    assert inv.coverage in ("complete", "partial", "unknown")
    named_ok = _collect(_req("req_art_ctrl_named", "CollectArtifacts", {"handle": handle, "selector": {"mode": "named", "names": ["ghost"]}}))
    assert isinstance(named_ok, ca.ArtifactInventory), f"valid named rejected: {_error_dict(named_ok) if _is_error(named_ok) else named_ok}"
    chunk_ok = _collect(_req("req_art_ctrl_bytes", "CollectArtifacts", {"handle": handle, "selector": {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 64}}))
    assert isinstance(chunk_ok, ca.ArtifactChunk), f"valid bytes rejected: {_error_dict(chunk_ok) if _is_error(chunk_ok) else chunk_ok}"
    assert chunk_ok.data_bytes == content

    malicious_selectors = [
        {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 10, "path": "/tmp/evil.bin"},
        {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 10, "url": "https://evil.example/file.bin"},
        {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 10, "uri": "file:///etc/passwd"},
        {"mode": "inventory", "path": "/etc/passwd"},
        {"mode": "inventory", "url": "https://evil.example/inventory"},
        {"mode": "named", "names": ["a"], "url": "https://evil.example/named"},
        {"mode": "named", "names": ["a"], "paths": ["/tmp/a", "/tmp/b"]},
        # Digest slots carrying paths/URLs instead of a registered digest.
        {"mode": "bytes", "digest": "/tmp/evil.bin", "offset": 0, "max_bytes": 10},
        {"mode": "bytes", "digest": "https://evil.example/x.bin", "offset": 0, "max_bytes": 10},
        {"mode": "bytes", "digest": "file:///tmp/x", "offset": 0, "max_bytes": 10},
        # Modes that smuggle path/URL fetching.
        {"mode": "url", "url": "https://evil.example/x"},
        {"mode": "path", "path": "/tmp/x"},
        {"path": "/tmp/x"},
        {"url": "https://evil.example/x"},
    ]
    calls: list[dict] = []
    original = ct.call_connector

    async def spy(channel_id, request):
        calls.append({"channel_id": channel_id})
        return await original(channel_id, request)

    ct.call_connector = spy  # type: ignore[assignment]
    try:
        for i, selector in enumerate(malicious_selectors):
            calls.clear()
            req = _req(f"req_art_bad_{i:03d}", "CollectArtifacts", {"handle": handle, "selector": selector})
            result = asyncio.run(ca.collect_task_artifacts(CHANNEL, req))
            assert _is_error(result, "INVALID_REQUEST"), f"selector {selector} must be INVALID_REQUEST, got {_error_dict(result) if _is_error(result) else result}"
            d = _error_dict(result)
            assert "path" in d["detail"].lower() or "url" in d["detail"].lower() or "uri" in d["detail"].lower() or "digest" in d["detail"].lower(), f"detail must name the violation: {d['detail']!r}"
            assert not calls, f"arbitrary path/URL selector must be rejected before transport: {selector}"

        # Payload-level smuggling is also rejected locally.
        calls.clear()
        payload_bad = {"handle": handle, "selector": {"mode": "inventory"}, "path": "/tmp/x"}
        result = asyncio.run(ca.collect_task_artifacts(CHANNEL, _req("req_art_bad_payload", "CollectArtifacts", payload_bad)))
        assert _is_error(result, "INVALID_REQUEST"), f"payload path smuggling must be rejected, got {_error_dict(result) if _is_error(result) else result}"
        assert not calls

        # Non-CollectArtifacts operations are refused through this interface.
        calls.clear()
        other = _req("req_art_bad_op", "Observe", {"handle": handle, "selector": {"mode": "inventory"}})
        result = asyncio.run(ca.collect_task_artifacts(CHANNEL, other))
        assert _is_error(result, "INVALID_REQUEST"), f"non-CollectArtifacts must be rejected, got {result}"
        assert not calls
    finally:
        ct.call_connector = original  # type: ignore[assignment]


def test_artifact_chunk_corruption_is_rejected():
    _register()
    handle = _get_handle("chunk001")
    content = b"chunk-verification-bytes-0123456789-abcdef"
    ref = _retain(content)
    digest = ref.digest if hasattr(ref, "digest") else ref["digest"]
    size = len(content)

    selector = {"mode": "bytes", "digest": digest, "offset": 0, "max_bytes": 1024}
    good = _collect(_req("req_art_chunk_good", "CollectArtifacts", {"handle": handle, "selector": selector}))
    assert isinstance(good, ca.ArtifactChunk), f"valid chunk rejected: {_error_dict(good) if _is_error(good) else good}"
    good_dict = good.to_dict()
    assert good_dict["digest"] == digest
    assert good_dict["size_bytes"] == size
    assert good_dict["offset"] == 0
    assert good_dict["returned_bytes"] == size
    assert good_dict["end_of_artifact"] is True
    assert base64.b64decode(good_dict["data_base64"], validate=True) == content
    assert good_dict["chunk_digest"] == "sha256:" + hashlib.sha256(content).hexdigest()
    # The verifier accepts the genuine chunk directly too.
    assert ca.verify_artifact_chunk(good_dict, handle, selector) is None

    def corrupt(mutator, label: str) -> dict:
        bad = copy.deepcopy(good_dict)
        mutator(bad)
        return bad

    cases: list[tuple[str, dict, str]] = []

    def _malformed(d):
        d["data_base64"] = "!!!not-base64!!!"

    cases.append(("malformed_base64", corrupt(_malformed, "m"), "INTEGRITY_CONFLICT"))

    def _digest_mismatch(d):
        last = d["chunk_digest"][-1]
        flipped = "0" if last != "0" else "1"
        d["chunk_digest"] = d["chunk_digest"][:-1] + flipped

    cases.append(("chunk_digest_mismatch", corrupt(_digest_mismatch, "c"), "INTEGRITY_CONFLICT"))

    def _returned_mismatch(d):
        d["returned_bytes"] = d["returned_bytes"] + 1

    cases.append(("returned_bytes_mismatch", corrupt(_returned_mismatch, "r"), "INTEGRITY_CONFLICT"))

    def _truncated_data(d):
        raw = base64.b64decode(d["data_base64"], validate=True)[:-1]
        d["data_base64"] = base64.b64encode(raw).decode("ascii")
        # Keep the old chunk_digest/returned_bytes so lengths and hash disagree.

    cases.append(("truncated_data", corrupt(_truncated_data, "t"), "INTEGRITY_CONFLICT"))

    def _size_mismatch(d):
        d["size_bytes"] = d["size_bytes"] + 5

    cases.append(("size_mismatch", corrupt(_size_mismatch, "s"), "INTEGRITY_CONFLICT"))

    def _offset_mismatch(d):
        d["offset"] = d["offset"] + 1

    cases.append(("offset_mismatch", corrupt(_offset_mismatch, "o"), "INTEGRITY_CONFLICT"))

    def _eof_flip(d):
        d["end_of_artifact"] = False

    cases.append(("eof_mismatch", corrupt(_eof_flip, "e"), "INTEGRITY_CONFLICT"))

    def _nonprogress(d):
        d["returned_bytes"] = 0
        d["data_base64"] = base64.b64encode(b"").decode("ascii")
        d["chunk_digest"] = "sha256:" + hashlib.sha256(b"").hexdigest()
        d["end_of_artifact"] = False

    cases.append(("nonprogressing_non_eof", corrupt(_nonprogress, "n"), "INTEGRITY_CONFLICT"))

    def _assembled_mismatch(d):
        # Keep valid chunk framing but name a different artifact digest.
        other = _retain(b"different-artifact-bytes-xyz")
        other_digest = other.digest if hasattr(other, "digest") else other["digest"]
        d["digest"] = other_digest

    cases.append(("assembled_digest_mismatch", corrupt(_assembled_mismatch, "a"), "INTEGRITY_CONFLICT"))

    def _overrun(d):
        d["size_bytes"] = 4  # offset(0)+returned(size) overruns

    cases.append(("bounds_overrun", corrupt(_overrun, "b"), "INTEGRITY_CONFLICT"))

    # Direct verifier checks: every corruption is rejected without transport.
    for label, bad_dict, expected_code in cases:
        err = ca.verify_artifact_chunk(bad_dict, handle, selector)
        assert err is not None, f"verifier accepted {label}"
        assert err.code == expected_code, f"{label}: expected {expected_code}, got {err.code}"

    # End-to-end: corrupted transport payloads surface as errors, never chunks.
    original = ct.call_connector
    for i, (label, bad_dict, expected_code) in enumerate(cases):
        async def fake(channel_id, request, _bad=bad_dict):
            req_d = request.to_dict() if hasattr(request, "to_dict") else dict(request)
            return ct.ConnectorResponse(
                request_id=req_d.get("request_id", f"req_art_corr_{i}"),
                connector_id=req_d.get("connector_id", CONNECTOR),
                operation="CollectArtifacts",
                result=copy.deepcopy(_bad),
            )

        ct.call_connector = fake  # type: ignore[assignment]
        try:
            req = _req(f"req_art_corr_e2e_{i:03d}", "CollectArtifacts", {"handle": handle, "selector": copy.deepcopy(selector)})
            result = asyncio.run(ca.collect_task_artifacts(CHANNEL, req))
            assert _is_error(result, expected_code), f"e2e {label} must be {expected_code}, got {_error_dict(result) if _is_error(result) else result}"
        finally:
            ct.call_connector = original  # type: ignore[assignment]

    # Offsets beyond EOF are rejected (request-side and chunk-side).
    beyond_selector = {"mode": "bytes", "digest": digest, "offset": size + 1, "max_bytes": 8}
    beyond = _collect(_req("req_art_beyond", "CollectArtifacts", {"handle": handle, "selector": beyond_selector}))
    assert _is_error(beyond, "INVALID_REQUEST"), f"beyond-EOF offset must be INVALID_REQUEST, got {_error_dict(beyond) if _is_error(beyond) else beyond}"


def test_named_artifact_inventory_preserves_missing_slots_and_known_digests():
    _register()
    handle = _get_handle("named001")
    local = handle["local_handle"]

    alpha = b"alpha-artifact-bytes-001"
    beta = b"beta-artifact-bytes-002-longer-payload"
    delta = b"delta-will-be-lost-003"
    ref_alpha = _retain(alpha, access="public")
    ref_beta = _retain(beta, access="restricted")
    ref_delta = _retain(delta, access="public")
    digest_alpha = ref_alpha.digest if hasattr(ref_alpha, "digest") else ref_alpha["digest"]
    digest_beta = ref_beta.digest if hasattr(ref_beta, "digest") else ref_beta["digest"]
    digest_delta = ref_delta.digest if hasattr(ref_delta, "digest") else ref_delta["digest"]

    ca.register_named_artifact_for_tests(CONNECTOR, local, "alpha", ref_alpha)
    ca.register_named_artifact_for_tests(CONNECTOR, local, "beta", ref_beta)
    ca.register_named_artifact_for_tests(CONNECTOR, local, "delta", ref_delta)
    # "gamma" is never registered: a genuinely missing slot.

    # Simulate an integrity incident: delta's bytes are lost while its
    # identity stays known.
    store.drop_retained_bytes_for_tests(digest_delta)
    assert digest_delta in store.known_digests()

    names = ["alpha", "beta", "gamma", "delta"]
    result = _collect(_req("req_art_named_mix", "CollectArtifacts", {"handle": handle, "selector": {"mode": "named", "names": names}}))
    assert isinstance(result, ca.ArtifactInventory), f"named inventory failed: {_error_dict(result) if _is_error(result) else result}"
    inv = result.to_dict()
    assert inv["kind"] == "artifact_inventory"
    assert inv["handle"] == handle
    assert inv["coverage"] in ("complete", "partial", "unknown")
    assert isinstance(inv["limitations"], list)
    slots = inv["artifacts"]
    assert len(slots) == len(names), f"must preserve every requested name, got {[s.get('name') for s in slots]}"
    assert [s["name"] for s in slots] == names, "named inventory must preserve requested order and missing slots"
    by_name = {s["name"]: s for s in slots}

    def _is_missing_env(v):
        return isinstance(v, dict) and v.get("value") is None and "reason" in v

    # Available slots carry expected_digest == content.digest.
    for name, digest, raw in (("alpha", digest_alpha, alpha), ("beta", digest_beta, beta)):
        slot = by_name[name]
        assert set(slot.keys()) == {"name", "expected_digest", "content", "evidence_refs"}
        assert slot["expected_digest"] == digest, f"{name} must preserve its known digest"
        content = slot["content"]
        assert isinstance(content, dict) and not _is_missing_env(content), f"{name} content must be available"
        assert content["digest"] == digest
        assert content["size_bytes"] == len(raw)
        assert slot["expected_digest"] == content["digest"]
        assert isinstance(slot["evidence_refs"], list)

    # Restricted access survives transfer without downgrade.
    assert by_name["beta"]["content"]["access"] == "restricted"
    assert by_name["alpha"]["content"]["access"] == "public"

    # Missing slots are preserved, never dropped or fabricated.
    gamma = by_name["gamma"]
    assert _is_missing_env(gamma["expected_digest"]), f"gamma expected_digest must be Missing, got {gamma['expected_digest']}"
    assert _is_missing_env(gamma["content"]), f"gamma content must be Missing, got {gamma['content']}"
    assert gamma["expected_digest"]["reason"] == "not_observed"
    assert gamma["content"]["reason"] == "not_observed"

    # Known identity survives loss: digest preserved, content explicitly lost.
    lost = by_name["delta"]
    assert lost["expected_digest"] == digest_delta, f"lost slot must preserve its known digest, got {lost['expected_digest']}"
    assert _is_missing_env(lost["content"]), f"lost content must be Missing, got {lost['content']}"
    assert lost["content"]["reason"] == "observation_lost"

    # The inventory verifier accepts this exact preservation shape.
    assert ca.verify_artifact_inventory(inv, handle, {"mode": "named", "names": names}) is None

    # Duplicate or empty names are rejected; they never yield a partial inventory.
    dup = _collect(_req("req_art_named_dup", "CollectArtifacts", {"handle": handle, "selector": {"mode": "named", "names": ["alpha", "alpha"]}}))
    assert _is_error(dup, "INVALID_REQUEST"), f"duplicate names must be rejected, got {dup}"
    empty = _collect(_req("req_art_named_empty", "CollectArtifacts", {"handle": handle, "selector": {"mode": "named", "names": []}}))
    assert _is_error(empty, "INVALID_REQUEST"), f"empty names must be rejected, got {empty}"

    # Inventory mode lists the handle-local registered names (missing names
    # stay absent here because they were never declared for the handle).
    full = _collect(_req("req_art_inv_full", "CollectArtifacts", {"handle": handle, "selector": {"mode": "inventory"}}))
    assert isinstance(full, ca.ArtifactInventory), f"inventory failed: {_error_dict(full) if _is_error(full) else full}"
    got_names = sorted(s.name for s in full.artifacts)
    assert got_names == ["alpha", "beta", "delta"], f"inventory must list registered names, got {got_names}"
