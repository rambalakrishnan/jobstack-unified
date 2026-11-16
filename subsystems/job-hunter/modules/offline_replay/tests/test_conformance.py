"""Conformance tests for offline_replay (tier 8).

Covers exactly the ``-k`` filter named in the module spec:

* ``replay_causing_external_write_fails_conformance``
* ``missing_replay_inputs_prevent_matched_receipt_without_mutating_source_diagnostic``

Every check exercises the real module: journals are admitted and appended
through ``evidence_journal``, bundles are retained and resolved through
``artifact_store``, strict JSON and digests are validated through
``contract_codec``, diagnostics are derived through ``attempt_diagnostics``,
and replay runs through ``offline_replay.replay_diagnostic``.
"""

from __future__ import annotations

import copy
import dataclasses
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


def _load(name: str):
    if name in sys.modules:
        return sys.modules[name]
    try:
        return __import__(name)
    except ModuleNotFoundError:
        pass
    here = Path(__file__).resolve()
    if name == "offline_replay":
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
cc = _load("contract_codec")
ad = _load("attempt_diagnostics")
replay = _load("offline_replay")

CHANNEL = "ch_replay_product_0001"
PRODUCER = "prod_replay_product"
PRINCIPAL = "principal_replay_product"
OWNER = "job.downstream"
OBS_KIND = "replay.observation"
REQ_KIND = "analysis_requested"
KIND_VERSION = "1"
CLOCK_ID = "clock_replay_engine"
BOOT_ID = "boot_replay_engine"

SIX_REASONS = frozenset(
    {
        "not_enabled",
        "not_applicable",
        "not_observed",
        "observation_lost",
        "unsupported_by_subject",
        "manual_override",
    }
)


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    store.reset_for_tests()
    ev.reset_for_tests()
    ad.reset_for_tests()
    replay.reset_for_tests()
    yield
    replay.reset_for_tests()
    ad.reset_for_tests()
    ev.reset_for_tests()
    store.reset_for_tests()
    ap.reset_for_tests()


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------


def _register() -> None:
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=True,
        allowed_event_kinds=(OBS_KIND, REQ_KIND),
    )
    for kind in (OBS_KIND, REQ_KIND):
        ap.register_event_kind(
            kind,
            KIND_VERSION,
            role="derived_output",
            assertion_kind="authoritative_effect",
            owner_domain=OWNER,
            writer_roles=("kernel",),
        )


def _retain_json(payload: Any) -> Any:
    return store.retain_artifact(
        CHANNEL,
        OWNER,
        "application/json",
        json.dumps(payload, sort_keys=True).encode("utf-8"),
        "restricted",
    )


def _scope(rid: str) -> dict[str, str]:
    return {"kind": "attempt", "id": f"scope:{rid}"}


def _manifest(
    journal_id: str,
    run_id: str,
    manifest_id: str,
    task: Any,
    config: Any,
) -> Any:
    return ev.Manifest(
        manifest_id=manifest_id,
        run_id=run_id,
        journal_id=journal_id,
        owner_domain=OWNER,
        commissioner_id="commissioner_replay",
        activity="application_attempt",
        attempt={
            "attempt_id": f"attempt_{run_id}",
            "kind": "practice",
            "target_class": "laboratory_fixture",
            "target_id": f"target_{run_id}",
            "evaluation_partition": "held_in",
            "rehearsal_of": [],
            "performance_of": [],
            "derived_from": [],
        },
        execution={
            "mode": "subject",
            "subject": "subject_browser_1",
            "connector_version": "connector_1",
            "binding_version": "binding_1",
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
        event_registry=[
            {
                "event_kind": kind,
                "event_schema_version": KIND_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "owner_domain": OWNER,
                "writer_roles": ["kernel"],
            }
            for kind in (OBS_KIND, REQ_KIND)
        ],
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": True,
                "allowed_event_kinds": [OBS_KIND, REQ_KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_replay_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup_journal(tag: str) -> Any:
    task = _retain_json({"fixture": f"task_{tag}"})
    config = _retain_json({"fixture": f"config_{tag}"})
    manifest = _manifest(
        f"journal_replay_{tag}",
        f"run_replay_{tag}",
        f"manifest_replay_{tag}",
        task,
        config,
    )
    ev.admit_manifest(CHANNEL, manifest)
    return manifest


def _timepoint(offset_ms: float) -> Any:
    return ev.TimePoint(
        clock_id=CLOCK_ID,
        boot_id=BOOT_ID,
        origin="engine_measured",
        monotonic_offset_ms=offset_ms,
    )


def _measurement(mid: str, start_ms: float, end_ms: float) -> dict[str, Any]:
    def _endpoint(offset: float) -> dict[str, Any]:
        return {
            "clock_id": CLOCK_ID,
            "boot_id": BOOT_ID,
            "origin": "engine_measured",
            "monotonic_offset_ms": offset,
            "utc_annotation": {"value": None, "reason": "not_observed"},
        }

    return {
        "measurement_id": mid,
        "name": "navigation_ms",
        "scope": "attempt",
        "quantity": "duration",
        "unit": "ms",
        "origin": "engine_measured",
        "clock_id": CLOCK_ID,
        "boot_id": BOOT_ID,
        "method": "endpoint_difference",
        "start": _endpoint(start_ms),
        "end": _endpoint(end_ms),
        "estimate": {"kind": "exact", "value": end_ms - start_ms},
        "resolution": 1.0,
        "censoring": "none",
        "comparability_group": {"value": None, "reason": "not_applicable"},
    }


def _append_obs(
    producer_sequence: int,
    data: dict[str, Any],
    measurements: list[dict[str, Any]] | None = None,
) -> Any:
    return ev.append_event(
        CHANNEL,
        OWNER,
        ev.EventSubmission(
            producer_sequence=producer_sequence,
            event_kind=OBS_KIND,
            event_schema_version=KIND_VERSION,
            occurred_at=_timepoint(1000.0 + producer_sequence * 100.0),
            payload=ev.EvidencePayload(
                data=data,
                measurements=list(measurements or []),
                evidence_refs=[],
                artifact_refs=[],
            ),
        ),
    )


def _append_request(producer_sequence: int, request: Any) -> Any:
    return ev.append_event(
        CHANNEL,
        OWNER,
        ev.EventSubmission(
            producer_sequence=producer_sequence,
            event_kind=REQ_KIND,
            event_schema_version=KIND_VERSION,
            occurred_at=_timepoint(1000.0 + producer_sequence * 100.0),
            payload=ev.EvidencePayload(
                data=request.to_dict(),
                measurements=[],
                evidence_refs=[],
                artifact_refs=[],
            ),
        ),
    )


def _classifier_rule(rid: str) -> dict[str, Any]:
    return {
        "requirement_id": rid,
        "facet": "f1",
        "contract_version": "1",
        "scope": _scope(rid),
        "defect_locus": "subject",
        "capability_id": f"capability_{rid}",
        "signals": {
            "exposed": f"sig:{rid}:exposed",
            "blocked": f"sig:{rid}:blocked",
            "controls": [f"sig:{rid}:ctl"],
            "controls_invalid": f"sig:{rid}:ctl_bad",
            "satisfied": f"sig:{rid}:sat",
            "violated": f"sig:{rid}:vio",
            "absent": f"sig:{rid}:absent",
            "unsupported": f"sig:{rid}:unsup",
            "descriptor": f"cap:{rid}",
        },
    }


def _classifier_pin(rules: list[dict[str, Any]], label: str) -> Any:
    ref = _retain_json(
        {"bundle": "classifier", "bundle_version": "1", "rules": rules}
    )
    return ad.VersionPin(
        id=f"classifier_{label}", version="1", artifact_digest=ref.digest
    )


def _registry_pin(rids: list[str], label: str) -> Any:
    ref = _retain_json(
        {
            "registry": "requirements",
            "registry_version": "1",
            "requirements": [
                {
                    "requirement_id": rid,
                    "facet": "f1",
                    "contract_version": "1",
                    "scope": _scope(rid),
                    "required": True,
                }
                for rid in rids
            ],
        }
    )
    return ad.VersionPin(
        id=f"registry_{label}", version="1", artifact_digest=ref.digest
    )


def _engine_pin(label: str) -> Any:
    ref = _retain_json(
        {"engine": "offline_replay", "engine_version": "1", "label": label}
    )
    return ad.VersionPin(
        id=f"replay_engine_{label}", version="1", artifact_digest=ref.digest
    )


def _retain_bundle(request: Any, prefix: Any, extra: dict[str, Any] | None = None) -> Any:
    payload: dict[str, Any] = {
        "record_type": "ReplayInputBundle",
        "bundle_version": "1",
        "analysis_request": request.to_dict(),
        "expected_prefix": {
            "journal_id": prefix.journal_id,
            "last_sequence": prefix.last_sequence,
            "head_hash": prefix.head_hash,
        },
    }
    if extra:
        payload.update(extra)
    return _retain_json(payload)


def _assert_no_bare_nulls(node: Any, path: str = "$") -> None:
    if isinstance(node, dict):
        keys = set(node.keys())
        if keys in ({"value", "reason"}, {"value", "reason", "detail"}) and (
            node.get("value") is None
        ):
            assert node["reason"] in SIX_REASONS, f"bad Missing reason at {path}"
            detail = node.get("detail")
            if detail is not None:
                assert isinstance(detail, str) and detail, (
                    f"Missing.detail must be nonempty at {path}"
                )
            return
        for key, value in node.items():
            assert value is not None, f"bare null at {path}.{key}"
            _assert_no_bare_nulls(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            assert value is not None, f"bare null at {path}[{index}]"
            _assert_no_bare_nulls(value, f"{path}[{index}]")


def _assert_source_intact(source: Any, snapshot_bytes: bytes, snapshot_dict: dict) -> None:
    assert ad.to_canonical_bytes(source) == snapshot_bytes
    assert source.to_dict() == snapshot_dict


# ---------------------------------------------------------------------------
# Assertion 1: replay causing an external write fails conformance
# ---------------------------------------------------------------------------


def test_replay_causing_external_write_fails_conformance():
    _register()
    manifest = _setup_journal("ext")
    classifier = _classifier_pin([_classifier_rule("R1")], "ext")
    registry = _registry_pin(["R1"], "ext")
    request = ad.AnalysisRequest(
        diagnostic_id="diag_replay_ext",
        analysis_revision=1,
        classifier=classifier,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_obs(
        1,
        {"sig:R1:exposed": True, "sig:R1:ctl": True, "sig:R1:sat": True},
        [_measurement("m_replay_ext", 100.0, 250.0)],
    )
    _append_request(2, request)
    prefix = ev.journal_head(CHANNEL, manifest.journal_id)
    assert prefix.last_sequence == 3
    source = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)
    source_bytes = ad.to_canonical_bytes(source)
    source_dict = copy.deepcopy(source.to_dict())
    engine = _engine_pin("ext")

    # A clean offline replay matches and performs no external effect.
    bundle_ref = _retain_bundle(request, prefix)
    digests_before = set(store.known_digests())
    head_before = ev.journal_head(CHANNEL, manifest.journal_id)
    receipt = replay.replay_diagnostic(CHANNEL, manifest, source, bundle_ref, engine)
    assert receipt.verdict == "matched"
    assert receipt.replay_kind == "diagnostic_rederivation"
    assert receipt.replay_kind not in ("exact_fixture_replay", "live_reproduction")
    assert receipt.external_write_attempted is False
    assert receipt.rederived_digest == receipt.source_digest
    assert receipt.missing_inputs == ()
    assert set(store.known_digests()) == digests_before
    assert ev.journal_head(CHANNEL, manifest.journal_id) == head_before
    _assert_source_intact(source, source_bytes, source_dict)
    _assert_no_bare_nulls(receipt.to_dict())
    assert replay.to_canonical_bytes(receipt)

    # The implementation never touches execution/effect planes.
    for forbidden in (
        "connector_transport",
        "connector_dispatch",
        "connector_observation",
        "connector_controls",
        "provider_effects",
        "browser_bindings",
        "native_control",
    ):
        assert forbidden not in sys.modules, f"forbidden module loaded: {forbidden}"
    src_text = (Path(__file__).resolve().parents[1] / "src" / "__init__.py").read_text()
    for snippet in (
        "import connector",
        "from connector",
        "import provider_effects",
        "from provider_effects",
        "import browser",
        "from browser",
        "import native_control",
        "from native_control",
    ):
        assert snippet not in src_text, f"forbidden import in module: {snippet}"

    # Every bundle that would cause an external write fails conformance.
    malicious_extras: list[dict[str, Any]] = [
        {"employer_mutation": True},
        {"external_write": True},
        {"external_effects": ["employer_submit"]},
        {"browser_actions": [{"action": "click", "target": "submit"}]},
        {"control_action": "cancel_attempt"},
        {"email_send": {"to": "employer@example.com", "subject": "apply"}},
        {"calendar_write": {"event": "interview", "when": "tomorrow"}},
        {"subject_action": "drive_browser"},
        {"replay_kind": "live_reproduction"},
        {"replay_kind": "exact_fixture_replay"},
    ]
    for index, extra in enumerate(malicious_extras):
        bad_ref = _retain_bundle(request, prefix, extra)
        digests_mid = set(store.known_digests())
        head_mid = ev.journal_head(CHANNEL, manifest.journal_id)
        with pytest.raises(replay.ReplayConformanceError):
            replay.replay_diagnostic(CHANNEL, manifest, source, bad_ref, engine)
        # The refusal performs nothing: no journal growth, no new bytes,
        # and the source diagnostic is untouched.
        assert ev.journal_head(CHANNEL, manifest.journal_id) == head_mid, (
            f"case {index} grew the journal"
        )
        assert set(store.known_digests()) == digests_mid, (
            f"case {index} retained bytes during replay"
        )
        _assert_source_intact(source, source_bytes, source_dict)

    # An explicitly inactive flag declares no effect and still matches.
    quiet_ref = _retain_bundle(request, prefix, {"employer_mutation": False})
    quiet = replay.replay_diagnostic(CHANNEL, manifest, source, quiet_ref, engine)
    assert quiet.verdict == "matched"
    assert quiet.external_write_attempted is False
    _assert_source_intact(source, source_bytes, source_dict)


# ---------------------------------------------------------------------------
# Assertion 2: missing replay inputs prevent a matched receipt
# ---------------------------------------------------------------------------


def test_missing_replay_inputs_prevent_matched_receipt_without_mutating_source_diagnostic():
    _register()
    manifest = _setup_journal("missing")
    classifier = _classifier_pin([_classifier_rule("R1")], "missing")
    registry = _registry_pin(["R1"], "missing")
    request = ad.AnalysisRequest(
        diagnostic_id="diag_replay_missing",
        analysis_revision=1,
        classifier=classifier,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_obs(
        1,
        {"sig:R1:exposed": True, "sig:R1:ctl": True, "sig:R1:sat": True},
        [_measurement("m_replay_missing", 40.0, 90.0)],
    )
    _append_request(2, request)
    prefix = ev.journal_head(CHANNEL, manifest.journal_id)
    source = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)
    source_bytes = ad.to_canonical_bytes(source)
    source_dict = copy.deepcopy(source.to_dict())
    engine = _engine_pin("missing")

    # The harness replays cleanly before inputs go missing.
    good_ref = _retain_bundle(request, prefix)
    good = replay.replay_diagnostic(CHANNEL, manifest, source, good_ref, engine)
    assert good.verdict == "matched"
    _assert_source_intact(source, source_bytes, source_dict)

    def _assert_inputs_missing(rcpt: Any, label: str) -> None:
        assert rcpt.verdict == "inputs_missing", label
        assert rcpt.verdict != "matched", label
        assert rcpt.replay_kind == "diagnostic_rederivation", label
        assert rcpt.external_write_attempted is False, label
        assert rcpt.missing_inputs, label
        assert isinstance(rcpt.rederived_digest, ev.Missing), label
        assert rcpt.rederived_digest.reason in SIX_REASONS, label
        _assert_no_bare_nulls(rcpt.to_dict())
        assert replay.to_canonical_bytes(rcpt)
        _assert_source_intact(source, source_bytes, source_dict)

    # Case A: the bundle omits its recorded analysis request.
    truncated = _retain_json(
        {
            "record_type": "ReplayInputBundle",
            "bundle_version": "1",
            "expected_prefix": {
                "journal_id": prefix.journal_id,
                "last_sequence": prefix.last_sequence,
                "head_hash": prefix.head_hash,
            },
        }
    )
    _assert_inputs_missing(
        replay.replay_diagnostic(CHANNEL, manifest, source, truncated, engine),
        "bundle without analysis_request must not match",
    )

    # Case B: the bundle names a prefix that does not verify.
    tampered_prefix = ev.JournalPrefix(
        journal_id=prefix.journal_id,
        last_sequence=prefix.last_sequence,
        head_hash="sha256:" + "0" * 64,
    )
    tampered_ref = _retain_json(
        {
            "record_type": "ReplayInputBundle",
            "bundle_version": "1",
            "analysis_request": request.to_dict(),
            "expected_prefix": {
                "journal_id": tampered_prefix.journal_id,
                "last_sequence": tampered_prefix.last_sequence,
                "head_hash": tampered_prefix.head_hash,
            },
        }
    )
    _assert_inputs_missing(
        replay.replay_diagnostic(CHANNEL, manifest, source, tampered_ref, engine),
        "unverifiable prefix must not match",
    )

    # Case C: the bundle bytes themselves were never retained.
    fake_digest = "sha256:" + "f" * 64
    assert fake_digest not in set(store.known_digests())
    fake_ref = store.ArtifactReference(
        digest=fake_digest,
        size_bytes=12,
        media_type="application/json",
        owner_domain=OWNER,
        access="restricted",
    )
    _assert_inputs_missing(
        replay.replay_diagnostic(CHANNEL, manifest, source, fake_ref, engine),
        "unavailable bundle bytes must not match",
    )

    # Case D: a grown prefix re-derives to a different diagnostic, so the
    # receipt is mismatched (never matched) while the source is intact.
    # This also proves replay re-derives instead of echoing the source.
    _append_obs(3, {"sig:R1:exposed": True, "sig:R1:ctl": True, "sig:R1:vio": True})
    request2 = ad.AnalysisRequest(
        diagnostic_id="diag_replay_missing",
        analysis_revision=2,
        classifier=classifier,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_request(4, request2)
    prefix2 = ev.journal_head(CHANNEL, manifest.journal_id)
    assert prefix2.last_sequence == 5
    grown_ref = _retain_bundle(request2, prefix2)
    grown = replay.replay_diagnostic(CHANNEL, manifest, source, grown_ref, engine)
    assert grown.verdict == "mismatched"
    assert grown.verdict != "matched"
    assert grown.replay_kind == "diagnostic_rederivation"
    assert grown.external_write_attempted is False
    assert grown.missing_inputs == ()
    assert isinstance(grown.rederived_digest, str)
    assert grown.rederived_digest != grown.source_digest
    _assert_no_bare_nulls(grown.to_dict())
    _assert_source_intact(source, source_bytes, source_dict)

    # The receipt is a separate immutable record, not the source.
    assert grown is not source  # type: ignore[comparison-overlap]
    with pytest.raises(dataclasses.FrozenInstanceError):
        grown.verdict = "matched"  # type: ignore[misc]

    # Case E (last): the pinned classifier bytes are lost, so the recorded
    # bundle can no longer be re-derived. Loss is explicit, not empty input.
    store.drop_retained_bytes_for_tests(classifier.artifact_digest)
    _assert_inputs_missing(
        replay.replay_diagnostic(CHANNEL, manifest, source, good_ref, engine),
        "lost classifier bytes must not match",
    )

    # Replay performs no timing reproduction, no live fetch, and no wall
    # clock reads: the module contains no sleep/network/time hooks.
    src_text = (Path(__file__).resolve().parents[1] / "src" / "__init__.py").read_text()
    for snippet in (
        "time.sleep",
        "sleep(",
        "import socket",
        "import urllib",
        "import requests",
        "from requests",
        "import httpx",
        "import time\n",
        "from time import",
        "datetime.now",
    ):
        assert snippet not in src_text, f"forbidden timing/network hook: {snippet}"
