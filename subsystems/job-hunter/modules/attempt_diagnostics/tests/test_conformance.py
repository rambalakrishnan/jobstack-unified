"""Conformance tests for attempt_diagnostics (tier 7).

Covers exactly the ``-k`` filter named in the module spec:

* ``diagnostic_derivation_uses_only_manifest_prefix_and_pinned_classifier``
* ``capability_opportunity_and_result_remain_independent_in_diagnostics``
* ``disabled_or_unsupported_fix_suggestions_remain_reasoned_missing_values``

Every check exercises the real module: journals are admitted and appended
through ``evidence_journal``, classifier/requirement/fix bundles are
retained and resolved through ``artifact_store``, strict JSON and
measurements are validated through ``contract_codec``, and diagnostics are
derived through ``attempt_diagnostics.derive_diagnostic``.
"""

from __future__ import annotations

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
    if name == "attempt_diagnostics":
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

CHANNEL = "ch_diag_product_0001"
PRODUCER = "prod_diag_product"
PRINCIPAL = "principal_diag_product"
OWNER = "job.downstream"
OBS_KIND = "diag.observation"
REQ_KIND = "analysis_requested"
KIND_VERSION = "1"
CLOCK_ID = "clock_diag_engine"
BOOT_ID = "boot_diag_engine"

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
    yield
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
    *,
    mode: str = "subject",
    target_class: str = "laboratory_fixture",
) -> Any:
    if mode == "manual":
        subject: Any = ev.NOT_APPLICABLE
        connector: Any = ev.NOT_APPLICABLE
        binding: Any = ev.NOT_APPLICABLE
    else:
        subject = "subject_browser_1"
        connector = "connector_1"
        binding = "binding_1"
    return ev.Manifest(
        manifest_id=manifest_id,
        run_id=run_id,
        journal_id=journal_id,
        owner_domain=OWNER,
        commissioner_id="commissioner_diag",
        activity="application_attempt",
        attempt={
            "attempt_id": f"attempt_{run_id}",
            "kind": "practice" if target_class == "laboratory_fixture" else "production",
            "target_class": target_class,
            "target_id": f"target_{run_id}",
            "evaluation_partition": "held_in" if target_class == "laboratory_fixture" else "held_out",
            "rehearsal_of": [],
            "performance_of": [],
            "derived_from": [],
        },
        execution={
            "mode": mode,
            "subject": subject,
            "connector_version": connector,
            "binding_version": binding,
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
                "source_id": "src_diag_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup_journal(
    tag: str, *, mode: str = "subject", target_class: str = "laboratory_fixture"
) -> Any:
    task = _retain_json({"fixture": f"task_{tag}"})
    config = _retain_json({"fixture": f"config_{tag}"})
    manifest = _manifest(
        f"journal_diag_{tag}",
        f"run_diag_{tag}",
        f"manifest_diag_{tag}",
        task,
        config,
        mode=mode,
        target_class=target_class,
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


def _append_request(
    producer_sequence: int, request: Any
) -> Any:
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


def _classifier_rule(
    rid: str, *, facet: str = "f1", locus: str = "subject", capability: bool = True
) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "requirement_id": rid,
        "facet": facet,
        "contract_version": "1",
        "scope": _scope(rid),
        "defect_locus": locus,
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
    if capability:
        rule["capability_id"] = f"capability_{rid}"
    return rule


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


def _fix_pin(rules: list[dict[str, Any]], label: str) -> Any:
    ref = _retain_json(
        {"registry": "fix", "registry_version": "1", "rules": rules}
    )
    return ad.VersionPin(
        id=f"fix_{label}", version="1", artifact_digest=ref.digest
    )


def _fix_rule(
    iid: str,
    rid: str,
    plan_digest: str,
    *,
    approved: bool = True,
    target: str = "subject",
    target_class: str = "laboratory_fixture",
    contra: bool = True,
) -> dict[str, Any]:
    return {
        "rule_instance_id": iid,
        "requirement_id": rid,
        "target": target,
        "target_class": target_class,
        "approved": approved,
        "plan_digest": plan_digest,
        "contraindications_absent": contra,
    }


def _cap_record(rid: str, availability: str = "absent") -> dict[str, Any]:
    return {
        "capability_id": f"capability_{rid}",
        "availability": availability,
        "descriptor_digest": "sha256:" + "ab" * 32,
        "scope": _scope(rid),
    }


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


def _collect_refs(node: Any, out: list[dict[str, Any]]) -> None:
    if isinstance(node, dict):
        if {"journal_id", "sequence", "event_id", "event_hash", "pointer"} <= set(
            node.keys()
        ):
            out.append(node)
        for value in node.values():
            _collect_refs(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_refs(value, out)


def _collect_offsets(node: Any, out: list[float]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "monotonic_offset_ms":
                out.append(value)
            else:
                _collect_offsets(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_offsets(value, out)


# ---------------------------------------------------------------------------
# Assertion 1: derivation uses only manifest, prefix, pinned classifier
# ---------------------------------------------------------------------------



def test_diagnostic_derivation_uses_only_manifest_prefix_and_pinned_classifier():
    _register()
    manifest = _setup_journal("derive")
    classifier = _classifier_pin([_classifier_rule("R1")], "derive")
    registry = _registry_pin(["R1"], "derive")
    request = ad.AnalysisRequest(
        diagnostic_id="diag_derive_1",
        analysis_revision=1,
        classifier=classifier,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    measurement = _measurement("m_nav_1", 100.0, 250.0)
    _append_obs(
        1,
        {"sig:R1:exposed": True, "sig:R1:ctl": True, "sig:R1:sat": True},
        [measurement],
    )
    _append_request(2, request)
    prefix = ev.journal_head(CHANNEL, manifest.journal_id)
    assert prefix.last_sequence == 3

    first = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)
    second = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)

    # Deterministic: repeated derivation is byte-identical (no wall time,
    # no mutable reads, no randomness).
    assert ad.to_canonical_bytes(first) == ad.to_canonical_bytes(second)
    assert first.to_dict() == second.to_dict()

    # The manifest, prefix, and pins are faithfully bound into the output.
    events = ev.read_prefix(CHANNEL, prefix)
    assert first.manifest_hash == events[0].manifest_hash
    assert first.run_id == manifest.run_id
    assert first.input_prefix == prefix
    assert first.classifier == classifier
    assert first.requirement_registry == registry
    assert first.diagnostic_id == "diag_derive_1"
    assert first.analysis_revision == 1
    assert first.analysis_request_ref.sequence == 3

    # Measurements are copied verbatim, never rewritten.
    assert len(first.measurements) == 1
    assert first.measurements[0].measurement == measurement
    assert first.measurements[0].evidence_refs[0].sequence == 2

    # No invented time coordinates: every offset in the diagnostic is one
    # copied from the named prefix.
    offsets: list[float] = []
    _collect_offsets(first.to_dict(), offsets)
    assert sorted(offsets) == [100.0, 250.0]

    # Every citation resolves inside the named prefix.
    refs: list[dict[str, Any]] = []
    _collect_refs(first.to_dict(), refs)
    assert refs
    for ref in refs:
        assert ref["journal_id"] == manifest.journal_id
        assert ref["sequence"] <= prefix.last_sequence

    # Late evidence beyond the prefix is ignored: the same named prefix
    # re-derives identically after the journal grows.
    _append_obs(3, {"sig:R1:vio": True})
    grown_head = ev.journal_head(CHANNEL, manifest.journal_id)
    assert grown_head.last_sequence == 4
    replayed = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)
    assert ad.to_canonical_bytes(replayed) == ad.to_canonical_bytes(first)

    # A prefix that does not end at the analysis request is refused.
    with pytest.raises(ad.DiagnosticDerivationError):
        ad.derive_diagnostic(CHANNEL, manifest, grown_head, request)

    # A substituted manifest is refused: the diagnostic is a function of
    # the admitted manifest, not of whatever object is handed in.
    tampered = dataclasses.replace(manifest, run_id="run_diag_tampered")
    with pytest.raises(ad.DiagnosticDerivationError):
        ad.derive_diagnostic(CHANNEL, tampered, prefix, request)

    # The pinned classifier matters: a different bundle over a new request
    # derives a different diagnostic over the grown journal.
    classifier2 = _classifier_pin([], "derive_empty")
    request2 = ad.AnalysisRequest(
        diagnostic_id="diag_derive_1",
        analysis_revision=2,
        classifier=classifier2,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_request(4, request2)
    prefix2 = ev.journal_head(CHANNEL, manifest.journal_id)
    assert prefix2.last_sequence == 5
    other = ad.derive_diagnostic(CHANNEL, manifest, prefix2, request2)
    assert ad.to_canonical_bytes(other) != ad.to_canonical_bytes(first)
    assert other.requirement_assessments == ()
    assert any("R1" in note for note in other.validity["limitations"])

    _assert_no_bare_nulls(first.to_dict())
    _assert_no_bare_nulls(other.to_dict())


# ---------------------------------------------------------------------------
# Assertion 2: capability, opportunity, and result stay independent
# ---------------------------------------------------------------------------


def test_capability_opportunity_and_result_remain_independent_in_diagnostics():
    _register()
    manifest = _setup_journal("assess")
    rids = [f"R{i}" for i in range(1, 11)]
    classifier = _classifier_pin(
        [_classifier_rule(rid) for rid in rids], "assess"
    )
    registry = _registry_pin(rids, "assess")
    request = ad.AnalysisRequest(
        diagnostic_id="diag_assess_1",
        analysis_revision=1,
        classifier=classifier,
        requirement_registry=registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    data: dict[str, Any] = {
        # R1: exposed + valid controls + satisfaction -> satisfied.
        "sig:R1:exposed": True,
        "sig:R1:ctl": True,
        "sig:R1:sat": True,
        # R2: exposed + valid controls + violation -> violated.
        "sig:R2:exposed": True,
        "sig:R2:ctl": True,
        "sig:R2:vio": True,
        # R3: satisfaction signal without exposure -> not_exercised.
        "sig:R3:sat": True,
        # R4: violation signal without exposure -> not_exercised.
        "sig:R4:vio": True,
        # R5: exposed violation with invalid controls -> indeterminate.
        "sig:R5:exposed": True,
        "sig:R5:ctl": True,
        "sig:R5:ctl_bad": True,
        "sig:R5:vio": True,
        # R6: exposed + valid controls + evidenced absent capability.
        "sig:R6:exposed": True,
        "sig:R6:ctl": True,
        "sig:R6:absent": True,
        "cap:R6": _cap_record("R6", "absent"),
        # R7: absence signal without descriptor evidence -> indeterminate.
        "sig:R7:exposed": True,
        "sig:R7:ctl": True,
        "sig:R7:absent": True,
        # R8: blocked -> not_exercised.
        "sig:R8:blocked": True,
        # R9: capability absent but unexposed -> not_exercised.
        "cap:R9": _cap_record("R9", "absent"),
        # R10: conflicting satisfaction + violation -> indeterminate.
        "sig:R10:exposed": True,
        "sig:R10:ctl": True,
        "sig:R10:sat": True,
        "sig:R10:vio": True,
    }
    _append_obs(1, data, [_measurement("m_assess_1", 10.0, 60.0)])
    _append_request(2, request)
    prefix = ev.journal_head(CHANNEL, manifest.journal_id)

    document = ad.derive_diagnostic(CHANNEL, manifest, prefix, request)
    by_id = {item.requirement_id: item for item in document.requirement_assessments}
    assert set(by_id) == set(rids)

    def _state(rid: str) -> tuple[str, str]:
        item = by_id[rid]
        return (item.opportunity.state, item.result)

    assert _state("R1") == ("exposed", "satisfied")
    assert _state("R2") == ("exposed", "violated")
    assert _state("R3") == ("unexposed", "not_exercised")
    assert _state("R4") == ("unexposed", "not_exercised")
    assert _state("R5") == ("exposed", "indeterminate")
    assert _state("R6") == ("exposed", "native_absence")
    assert _state("R7") == ("exposed", "indeterminate")
    assert _state("R8") == ("blocked", "not_exercised")
    assert _state("R9") == ("unexposed", "not_exercised")
    assert _state("R10") == ("exposed", "indeterminate")

    # satisfied/violated always ride on an exposed opportunity.
    for item in document.requirement_assessments:
        if item.result in ("satisfied", "violated"):
            assert item.opportunity.state == "exposed"
        assert item.evidence_refs, f"{item.requirement_id} lacks support"

    # native_absence carries evidenced capability references in the exact
    # scope; absence without that evidence stays indeterminate.
    assert len(by_id["R6"].capability_refs) == 1
    cap_ref = by_id["R6"].capability_refs[0]
    assert cap_ref.capability_id == "capability_R6"
    assert cap_ref.descriptor_digest == "sha256:" + "ab" * 32
    assert by_id["R7"].capability_refs == ()

    # An absent capability does not promote unexercised work: R9 cites its
    # capability record yet remains not_exercised.
    assert len(by_id["R9"].capability_refs) == 1
    assert by_id["R9"].result == "not_exercised"

    # Findings exist only for violated/native_absence/indeterminate work,
    # and assessments link to them.
    finding_kinds = {item.finding_id: item.kind for item in document.findings}
    assert finding_kinds["F-R2-f1"] == "requirement_violation"
    assert finding_kinds["F-R6-f1"] == "native_capability_absent"
    assert finding_kinds["F-R5-f1"] == "indeterminate"
    assert "F-R1-f1" not in finding_kinds
    assert "F-R3-f1" not in finding_kinds
    assert by_id["R2"].finding_refs == ("F-R2-f1",)
    assert by_id["R1"].finding_refs == ()

    _assert_no_bare_nulls(document.to_dict())

    # Manual execution is assessable but never gains a subject capability
    # descriptor or fabricated capability references.
    manual_manifest = _setup_journal("assess_manual", mode="manual")
    manual_classifier = _classifier_pin([_classifier_rule("RM1")], "manual")
    manual_registry = _registry_pin(["RM1"], "manual")
    manual_request = ad.AnalysisRequest(
        diagnostic_id="diag_assess_manual",
        analysis_revision=1,
        classifier=manual_classifier,
        requirement_registry=manual_registry,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_obs(
        3,
        {"sig:RM1:exposed": True, "sig:RM1:ctl": True, "sig:RM1:sat": True},
        [_measurement("m_manual_1", 5.0, 15.0)],
    )
    _append_request(4, manual_request)
    manual_prefix = ev.journal_head(CHANNEL, manual_manifest.journal_id)
    manual_doc = ad.derive_diagnostic(
        CHANNEL, manual_manifest, manual_prefix, manual_request
    )
    assert manual_doc.capability_descriptors == ()
    assert len(manual_doc.requirement_assessments) == 1
    manual_assessment = manual_doc.requirement_assessments[0]
    assert manual_assessment.opportunity.state == "exposed"
    assert manual_assessment.result == "satisfied"
    assert manual_assessment.capability_refs == ()
    _assert_no_bare_nulls(manual_doc.to_dict())


# ---------------------------------------------------------------------------
# Assertion 3: disabled/unsupported fix suggestions stay reasoned Missing
# ---------------------------------------------------------------------------


def test_disabled_or_unsupported_fix_suggestions_remain_reasoned_missing_values():
    _register()

    # Part A: a disabled fix facility yields reasoned not_enabled
    # suggestions, never bare nulls or fabricated references.
    manifest_a = _setup_journal("fixoff")
    classifier_a = _classifier_pin([_classifier_rule("R1")], "fixoff")
    registry_a = _registry_pin(["R1"], "fixoff")
    request_a = ad.AnalysisRequest(
        diagnostic_id="diag_fixoff",
        analysis_revision=1,
        classifier=classifier_a,
        requirement_registry=registry_a,
        fix_registry=ev.Missing("not_enabled"),
    )
    _append_obs(
        1,
        {"sig:R1:exposed": True, "sig:R1:ctl": True, "sig:R1:vio": True},
        [_measurement("m_fixoff_1", 1.0, 2.0)],
    )
    _append_request(2, request_a)
    prefix_a = ev.journal_head(CHANNEL, manifest_a.journal_id)
    disabled = ad.derive_diagnostic(CHANNEL, manifest_a, prefix_a, request_a)
    assert len(disabled.findings) == 1
    suggestion = disabled.findings[0].suggested_fix
    assert isinstance(suggestion, ev.Missing)
    assert suggestion.reason == "not_enabled"
    assert suggestion.detail
    _assert_no_bare_nulls(disabled.to_dict())

    # Part B: a pinned registry with mixed eligibility.  R1 is blocked by
    # an evidenced subject limitation, R2/R3/R4 lack eligible rules, R5
    # earns a genuine FixReference, and R6 (indeterminate) cannot support
    # a concrete remedy.
    manifest_b = _setup_journal("fixon")
    plan_r1 = _retain_json({"plan": "verify R1"})
    plan_r5 = _retain_json({"plan": "verify R5"})
    plan_r6 = _retain_json({"plan": "verify R6"})
    rids = ["R1", "R2", "R3", "R4", "R5", "R6"]
    classifier_b = _classifier_pin(
        [_classifier_rule(rid) for rid in rids], "fixon"
    )
    registry_b = _registry_pin(rids, "fixon")
    fix_b = _fix_pin(
        [
            _fix_rule("FIX-R1-001", "R1", plan_r1.digest),
            _fix_rule("FIX-R3-001", "R3", plan_r1.digest, approved=False),
            _fix_rule(
                "FIX-R4-001",
                "R4",
                plan_r1.digest,
                target_class="employer_origin",
            ),
            _fix_rule("FIX-R5-001", "R5", plan_r5.digest),
            _fix_rule("FIX-R6-001", "R6", plan_r6.digest),
        ],
        "fixon",
    )
    request_b = ad.AnalysisRequest(
        diagnostic_id="diag_fixon",
        analysis_revision=1,
        classifier=classifier_b,
        requirement_registry=registry_b,
        fix_registry=fix_b,
    )
    _append_obs(
        3,
        {
            "sig:R1:exposed": True,
            "sig:R1:ctl": True,
            "sig:R1:vio": True,
            "sig:R1:unsup": True,
            "sig:R2:exposed": True,
            "sig:R2:ctl": True,
            "sig:R2:vio": True,
            "sig:R3:exposed": True,
            "sig:R3:ctl": True,
            "sig:R3:vio": True,
            "sig:R4:exposed": True,
            "sig:R4:ctl": True,
            "sig:R4:vio": True,
            "sig:R5:exposed": True,
            "sig:R5:ctl": True,
            "sig:R5:vio": True,
            "sig:R6:exposed": True,
            "sig:R6:ctl": True,
        },
        [_measurement("m_fixon_1", 3.0, 9.0)],
    )
    _append_request(4, request_b)
    prefix_b = ev.journal_head(CHANNEL, manifest_b.journal_id)
    mixed = ad.derive_diagnostic(CHANNEL, manifest_b, prefix_b, request_b)

    fixes = {
        item.finding_id: item.suggested_fix for item in mixed.findings
    }
    assert set(fixes) == {f"F-{rid}-f1" for rid in rids}

    unsup = fixes["F-R1-f1"]
    assert isinstance(unsup, ev.Missing)
    assert unsup.reason == "unsupported_by_subject"
    assert unsup.detail

    for rid in ("R2", "R3", "R4"):
        missing = fixes[f"F-{rid}-f1"]
        assert isinstance(missing, ev.Missing), rid
        assert missing.reason == "not_observed", rid
        assert missing.detail, rid

    positive = fixes["F-R5-f1"]
    assert isinstance(positive, ad.FixReference)
    assert positive.registry == fix_b
    assert positive.rule_instance_id == "FIX-R5-001"
    assert positive.verification_plan.digest == plan_r5.digest
    assert (
        store.resolve_artifact(CHANNEL, positive.verification_plan)
        == store.resolve_artifact(CHANNEL, plan_r5)
    )
    assert positive.evidence_refs

    weak = fixes["F-R6-f1"]
    assert isinstance(weak, ev.Missing)
    assert weak.reason == "not_observed"
    assert weak.detail
    _assert_no_bare_nulls(mixed.to_dict())

    # Part C: lost verification-plan bytes degrade to a reasoned
    # observation_lost suggestion for that finding alone.
    store.drop_retained_bytes_for_tests(plan_r5.digest)
    relost = ad.derive_diagnostic(CHANNEL, manifest_b, prefix_b, request_b)
    relost_fixes = {
        item.finding_id: item.suggested_fix for item in relost.findings
    }
    lost = relost_fixes["F-R5-f1"]
    assert isinstance(lost, ev.Missing)
    assert lost.reason == "observation_lost"
    assert lost.detail
    still_unsup = relost_fixes["F-R1-f1"]
    assert isinstance(still_unsup, ev.Missing)
    assert still_unsup.reason == "unsupported_by_subject"
    _assert_no_bare_nulls(relost.to_dict())

    # Part D: a subject-targeted rule for manual work is not_applicable.
    manifest_d = _setup_journal("fixmanual", mode="manual")
    plan_m = _retain_json({"plan": "verify RM1"})
    classifier_d = _classifier_pin([_classifier_rule("RM1")], "fixmanual")
    registry_d = _registry_pin(["RM1"], "fixmanual")
    fix_d = _fix_pin(
        [_fix_rule("FIX-RM1-001", "RM1", plan_m.digest)], "fixmanual"
    )
    request_d = ad.AnalysisRequest(
        diagnostic_id="diag_fixmanual",
        analysis_revision=1,
        classifier=classifier_d,
        requirement_registry=registry_d,
        fix_registry=fix_d,
    )
    _append_obs(
        5,
        {"sig:RM1:exposed": True, "sig:RM1:ctl": True, "sig:RM1:vio": True},
        [_measurement("m_fixmanual_1", 7.0, 11.0)],
    )
    _append_request(6, request_d)
    prefix_d = ev.journal_head(CHANNEL, manifest_d.journal_id)
    manual = ad.derive_diagnostic(CHANNEL, manifest_d, prefix_d, request_d)
    assert len(manual.findings) == 1
    scoped = manual.findings[0].suggested_fix
    assert isinstance(scoped, ev.Missing)
    assert scoped.reason == "not_applicable"
    assert scoped.detail
    _assert_no_bare_nulls(manual.to_dict())
