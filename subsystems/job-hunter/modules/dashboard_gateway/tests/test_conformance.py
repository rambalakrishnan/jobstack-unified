"""Conformance tests for dashboard_gateway (tier 5).

Covers exactly the ``-k`` filter named in the module spec:

- ``new_facts_with_old_report_are_explicitly_marked_stale``
- ``dashboard_scalar_application_status_mutation_is_rejected``
- ``dashboard_displays_close_time_knowledge_separately_from_later_facts``

Every check exercises the real module with real siblings: authenticated
channels, retained artifacts, admitted journals, installed/sealed job rows,
and the HTTP projection gateway.
"""

from __future__ import annotations

import hashlib
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
        path = here.parents[1] / rel if name == "dashboard_gateway" else here.parents[2] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ap = _load("access_policy", Path("access_policy/src/__init__.py"))
cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
rp = _load("read_publications", Path("read_publications/src/__init__.py"))
dg = _load("dashboard_gateway", Path("src/__init__.py"))


@pytest.fixture(autouse=True)
def _fresh_state():
    dg.reset_for_tests()
    rp.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    rp.reset_for_tests()
    dg.reset_for_tests()


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _fake_digest(char: str) -> str:
    assert len(char) == 1 and char in "0123456789abcdef"
    return "sha256:" + char * 64


def _parse_response(raw: bytes) -> dict:
    assert isinstance(raw, bytes)
    obj = json.loads(raw.decode("utf-8"))
    assert isinstance(obj, dict)
    assert "http_status" in obj
    return obj


# ---------------------------------------------------------------------------
# Snapshot builders
# ---------------------------------------------------------------------------


def _dispatch_axis(revision: int = 1, digest_char: str = "a", state: str | dict | None = "dispatched"):
    if revision == 0:
        return {"revision": 0, "record_digest": cc.make_missing("not_observed", "no dispatch publication"), "state": cc.make_missing("not_observed")}
    digest = _fake_digest(digest_char)
    if state is None:
        state = cc.make_missing("not_observed")
    return {"revision": revision, "record_digest": digest, "state": state}


def _close_snapshot(closure_id="closure_0001", known_app=1, exec_knowledge="unknown", app_knowledge="unknown"):
    return {
        "closure_id": closure_id,
        "known_versions": {"dispatch": 1, "observation": 2, "execution": 1, "application": known_app},
        "execution_knowledge": exec_knowledge,
        "application_knowledge": app_knowledge,
        "limitations": ["close-time outcome rests only on boundary evidence"],
    }


def _observation_axis(revision=2, digest_char="b", closed=False, close_snapshot=None):
    if revision == 0:
        return {
            "revision": 0,
            "record_digest": cc.make_missing("not_observed", "no observation publication"),
            "closed": False,
            "close_snapshot": cc.make_missing("not_observed", "observation never opened"),
        }
    digest = _fake_digest(digest_char)
    if closed:
        assert close_snapshot is not None
        return {"revision": revision, "record_digest": digest, "closed": True, "close_snapshot": close_snapshot}
    return {
        "revision": revision,
        "record_digest": digest,
        "closed": False,
        "close_snapshot": cc.make_missing("not_observed", "observation has not closed"),
    }


def _execution_axis(revision=1, digest_char="c", claims=None):
    if revision == 0:
        return {"revision": 0, "record_digest": cc.make_missing("not_applicable", "manual lane has no subject execution"), "claims": []}
    if claims is None:
        claims = [{"claim_id": "claim_0001", "state": "completed"}]
    return {"revision": revision, "record_digest": _fake_digest(digest_char), "claims": claims}


def _fact(fact_id, revision, state="committed", coverage="at_boundary"):
    return {"fact_id": fact_id, "revision": revision, "state": state, "coverage": coverage}


def _application_axis(revision=1, digest_char="d", facts=None):
    if revision == 0:
        return {"revision": 0, "record_digest": cc.make_missing("not_observed", "no application facts yet"), "facts": []}
    if facts is None:
        facts = [_fact("fact_0001", 1)]
    return {"revision": revision, "record_digest": _fake_digest(digest_char), "facts": facts}


def _report_pin(revision, digest_char_or_missing="e"):
    if revision == 0:
        return {"revision": 0, "record_digest": cc.make_missing("not_observed", "no publication at report time")}
    if isinstance(digest_char_or_missing, dict):
        return {"revision": revision, "record_digest": digest_char_or_missing}
    return {"revision": revision, "record_digest": _fake_digest(digest_char_or_missing)}


def _report_axis(revision=1, digest_char="e", state="reconciled", coverage="complete", inputs=None):
    if revision == 0:
        return {
            "revision": 0,
            "record_digest": cc.make_missing("not_observed", "no report published"),
            "state": cc.make_missing("not_observed", "no report state"),
            "coverage": cc.make_missing("not_observed", "no report coverage"),
            "inputs": {
                "dispatch": _report_pin(0),
                "observation": _report_pin(0),
                "execution": _report_pin(0),
                "application": _report_pin(0),
            },
            "issues": [],
            "limitations": [],
        }
    if inputs is None:
        inputs = {
            "dispatch": _report_pin(1, "a"),
            "observation": _report_pin(2, "b"),
            "execution": _report_pin(1, "c"),
            "application": _report_pin(1, "d"),
        }
    return {
        "revision": revision,
        "record_digest": _fake_digest(digest_char),
        "state": state,
        "coverage": coverage,
        "inputs": inputs,
        "issues": [],
        "limitations": [],
    }


def _snapshot(
    attempt_id="attempt_0001",
    kind="production",
    target="employer_origin_acme",
    axes=None,
    seal_name="evidence_updated",
    job_ref=None,
    issues=None,
    limitations=None,
):
    if axes is None:
        axes = {
            "dispatch": _dispatch_axis(),
            "observation": _observation_axis(),
            "execution": _execution_axis(),
            "application": _application_axis(),
            "report": _report_axis(),
        }
    versions = {axis: axes[axis]["revision"] for axis in ("dispatch", "observation", "execution", "application", "report")}
    snap = {
        "record_type": "attempt_snapshot",
        "schema_version": "dashboard-gateway/0.1.0",
        "attempt": {"attempt_id": attempt_id, "kind": kind, "target": target},
        "commission": {"commission_id": "commission_0001", "job_id": "job_0001", "basis": "manual_selection: high_priority_match"},
        "commission_digest": _fake_digest("f"),
        "input_prefix": {"journal_id": "journal_dashboard_0001", "last_sequence": 5, "head_hash": _fake_digest("1")},
        "axes": axes,
        "seal_point": {"seal_id": "seal_0001", "name": seal_name, "versions": versions},
    }
    if job_ref is not None:
        snap["job_ref"] = job_ref
    snap["issues"] = list(issues) if issues else []
    snap["limitations"] = list(limitations) if limitations else []
    return snap


# ---------------------------------------------------------------------------
# Row installation helpers (for job_ref coverage)
# ---------------------------------------------------------------------------

CRAWLER_CHANNEL = "ch_dashboard_crawler_0001"
PRODUCT_CHANNEL = "ch_dashboard_product_0001"
PUBLISHER_CHANNEL = "ch_dashboard_publisher_0001"
VIEW = "view_dashboard_0001"
SOURCE_JOURNAL = "journal_dashboard_source_0001"
ENTITY = {"entity_type": "job", "target": "target_acme", "job_id": "job_0001"}
DISCOVERY = {
    "journal_id": SOURCE_JOURNAL,
    "sequence": 1,
    "event_id": "evt_dashboard_discovery_0001",
    "event_hash": "sha256:" + "a" * 64,
    "pointer": "",
}


def _register_row_channels():
    ap.register_channel(
        actor="crawler_writer",
        channel_id=CRAWLER_CHANNEL,
        axis="job.crawler",
        producer_id="prod_dashboard_crawler",
        principal_id="principal_dashboard_crawler",
        sequence_required=False,
        allowed_event_kinds=("crawler.published",),
    )
    ap.register_channel(
        actor="product_writer",
        channel_id=PRODUCT_CHANNEL,
        axis="job.downstream",
        producer_id="prod_dashboard_product",
        principal_id="principal_dashboard_product",
        sequence_required=False,
        allowed_event_kinds=("product.published",),
    )
    ap.register_channel(
        actor="read_view_publisher",
        channel_id=PUBLISHER_CHANNEL,
        axis=rp.PUBLISHER_AXIS,
        producer_id="prod_dashboard_publisher",
        principal_id="principal_dashboard_publisher",
        sequence_required=False,
        allowed_event_kinds=(rp.INSTALL_EVENT_KIND, rp.SEAL_EVENT_KIND, rp.ROW_EVENT_KIND),
    )


def _registration():
    owners = {
        "crawler": {
            "role": "crawler",
            "source_id": "src_dashboard_crawler",
            "writer_id": "writer_dashboard_crawler",
            "owner_domain": "job.crawler",
            "publication_policy": {"id": "policy_crawler", "version": "1", "artifact_digest": "sha256:" + "1" * 64},
        },
        "downstream": {
            "role": "product",
            "source_id": "src_dashboard_product",
            "writer_id": "writer_dashboard_product",
            "owner_domain": "job.downstream",
            "publication_policy": {"id": "policy_product", "version": "1", "artifact_digest": "sha256:" + "2" * 64},
        },
    }
    return rp.EntityRegistration(
        registration_id="reg_dashboard_0001",
        entity=dict(ENTITY),
        identity={"portfolio_job_id": "portfolio_job_0001", "first_discovery_ref": dict(DISCOVERY)},
        owners=owners,
        evidence_prefix={"journal_id": SOURCE_JOURNAL, "last_sequence": 3, "head_hash": "sha256:" + "b" * 64},
        evidence_refs=(dict(DISCOVERY),),
    )


def _document(domain, revision, registration_digest, value=None):
    if domain == "crawler":
        owner_domain, writer = "job.crawler", "writer_dashboard_crawler"
    else:
        owner_domain, writer = "job.downstream", "writer_dashboard_product"
    return {
        "record_type": "owned_domain_revision",
        "schema_version": rp.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration_digest": registration_digest,
        "domain": domain,
        "owner_domain": owner_domain,
        "writer_id": writer,
        "revision": revision,
        "previous_revision": revision - 1,
        "evidence_prefix": {"journal_id": SOURCE_JOURNAL, "last_sequence": 4 + revision, "head_hash": "sha256:" + "c" * 64},
        "evidence_refs": [dict(DISCOVERY)],
        "value": value if value is not None else {"label": f"{domain} revision {revision}"},
    }


def _install_sealed_row():
    _register_row_channels()
    registration = _registration()
    registration_digest = str(cc.canonical_digest(_canonical(registration.to_dict())))
    crawler_doc = _document("crawler", 1, registration_digest, {"coverage": "full_crawl", "input_revision": 7})
    downstream_doc = _document("downstream", 1, registration_digest, {"selection": "job_0001", "basis": "manual_selection"})
    crawler_ref = store.retain_artifact(CRAWLER_CHANNEL, "job.crawler", "application/json", _canonical(crawler_doc), "public")
    downstream_ref = store.retain_artifact(PRODUCT_CHANNEL, "job.downstream", "application/json", _canonical(downstream_doc), "public")
    rp.install_publication(PUBLISHER_CHANNEL, registration, crawler_ref, VIEW)
    rp.install_publication(PUBLISHER_CHANNEL, registration, downstream_ref, VIEW)
    row = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "published")
    assert row.domains["crawler"].revision == 1
    assert row.domains["downstream"].revision == 1
    return registration


# ---------------------------------------------------------------------------
# Command journal helpers
# ---------------------------------------------------------------------------

CMD_CHANNEL = "ch_dashboard_cmd_0001"
CMD_PRODUCER = "prod_dashboard_cmd"
CMD_OWNER = "job.downstream"
CMD_JOURNAL = "journal_dashboard_cmd_0001"
CMD_RUN = "run_dashboard_cmd_0001"
CMD_KIND = "dashboard.command_requested"
CMD_VERSION = "1"
CMD_CLOCK = "clock_dashboard_engine"
CMD_BOOT = "boot_dashboard_engine"


def _admit_command_journal():
    ap.register_channel(
        actor="product_writer",
        channel_id=CMD_CHANNEL,
        axis=CMD_OWNER,
        producer_id=CMD_PRODUCER,
        principal_id="principal_dashboard_cmd",
        sequence_required=True,
        allowed_event_kinds=(CMD_KIND,),
    )
    ap.register_event_kind(
        CMD_KIND,
        CMD_VERSION,
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain=CMD_OWNER,
        writer_roles=("kernel",),
    )
    task_ref = store.retain_artifact(CMD_CHANNEL, CMD_OWNER, "application/json", b'{"fixture":"dashboard_task"}', "restricted")
    config_ref = store.retain_artifact(CMD_CHANNEL, CMD_OWNER, "application/json", b'{"fixture":"dashboard_config"}', "restricted")
    manifest = ev.Manifest(
        manifest_id="manifest_dashboard_cmd_0001",
        run_id=CMD_RUN,
        journal_id=CMD_JOURNAL,
        owner_domain=CMD_OWNER,
        commissioner_id="commissioner_dashboard",
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
        task=task_ref,
        task_semantic_hash="sha256:" + "a" * 64,
        effective_configuration=config_ref,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[{"id": "build_task", "version": "1", "artifact_digest": task_ref.digest}],
        event_registry=[
            {
                "event_kind": CMD_KIND,
                "event_schema_version": CMD_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "owner_domain": CMD_OWNER,
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": CMD_PRODUCER,
                "principal_id": "principal_dashboard_cmd",
                "owner_domain": CMD_OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": True,
                "allowed_event_kinds": [CMD_KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CMD_CLOCK,
                "boot_id": CMD_BOOT,
                "origin": "engine_measured",
                "source_id": "src_dashboard_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    admission = ev.admit_manifest(CMD_CHANNEL, manifest)
    assert admission.journal_sequence == 1
    return admission


def _occurred_at(offset_ms: float = 1000.0):
    return {
        "clock_id": CMD_CLOCK,
        "boot_id": CMD_BOOT,
        "origin": "engine_measured",
        "monotonic_offset_ms": offset_ms,
        "utc_annotation": cc.make_missing("not_observed"),
    }


def _command_body(command, resource_id, sequence, offset_ms=1000.0, payload_data=None):
    body = {
        "command": command,
        "resource_id": resource_id,
        "producer_sequence": sequence,
        "event_kind": CMD_KIND,
        "event_schema_version": CMD_VERSION,
        "occurred_at": _occurred_at(offset_ms),
    }
    if payload_data is not None:
        body["payload_data"] = payload_data
    return body


# ---------------------------------------------------------------------------
# Assertion 1: new facts with old report are explicitly marked stale
# ---------------------------------------------------------------------------


def test_new_facts_with_old_report_are_explicitly_marked_stale():
    _install_sealed_row()
    job_ref = {"entity": dict(ENTITY), "view_id": VIEW}

    # Current application advanced to revision 3 with three cumulative facts,
    # while the report still pins application revision 1.
    facts = [
        _fact("fact_0001", 1, "committed", "at_boundary"),
        _fact("fact_0002", 2, "committed", "at_boundary"),
        _fact("fact_0003", 3, "committed", "final_for_attempt"),
    ]
    axes = {
        "dispatch": _dispatch_axis(revision=1, digest_char="a"),
        "observation": _observation_axis(revision=2, digest_char="b", closed=False),
        "execution": _execution_axis(revision=1, digest_char="c"),
        "application": _application_axis(revision=3, digest_char="d", facts=facts),
        "report": _report_axis(
            revision=1,
            digest_char="e",
            state="reconciled",
            coverage="complete",
            inputs={
                "dispatch": _report_pin(1, "a"),
                "observation": _report_pin(2, "b"),
                "execution": _report_pin(1, "c"),
                "application": _report_pin(1, "d"),
            },
        ),
    }
    snap = _snapshot(attempt_id="attempt_stale_0001", axes=axes, seal_name="evidence_updated", job_ref=job_ref)

    stored = _parse_response(dg.handle_http(PUBLISHER_CHANNEL, "POST", "/dashboard/snapshots", _canonical(snap)))
    assert stored["http_status"] == 201
    assert stored["stored"] is True
    assert stored["attempt_id"] == "attempt_stale_0001"
    assert stored["report_stale"] is True
    assert stored["stale_axes"] == ["application"]
    assert stored["projection_notes"]["authoritative"] is False

    # The stored projection bytes are durable in the artifact store.
    artifact_dict = stored["artifact"]
    assert artifact_dict["digest"].startswith("sha256:")
    ref = store.ArtifactReference.from_dict(artifact_dict)
    resolved = store.resolve_artifact(PUBLISHER_CHANNEL, ref)
    assert json.loads(resolved.decode("utf-8"))["attempt"]["attempt_id"] == "attempt_stale_0001"

    # Dashboard renders the staleness explicitly alongside the preserved report.
    view = _parse_response(dg.handle_http(PUBLISHER_CHANNEL, "GET", "/dashboard/attempts/attempt_stale_0001", b""))
    assert view["http_status"] == 200
    projection = view["projection"]
    assert projection["attempt"]["attempt_id"] == "attempt_stale_0001"
    assert projection["attempt"]["kind"] == "production"
    assert projection["commission"]["job_id"] == "job_0001"
    assert "manual_selection" in projection["commission"]["basis"]
    # All five axes are present; none are hidden.
    assert set(projection["axes"].keys()) == {"dispatch", "observation", "execution", "application", "report"}
    assert projection["axes"]["application"]["revision"] == 3
    assert len(projection["axes"]["application"]["facts"]) == 3
    # Report coverage and input-pin staleness are explicit.
    report = projection["report"]
    assert report["revision"] == 1
    assert report["state"] == "reconciled"
    assert report["report_present"] is True
    assert report["report_stale"] is True
    assert report["stale_axes"] == ["application"]
    assert report["inputs"]["application"]["revision"] == 1
    assert report["current_versions"]["application"] == 3
    # No success badge hides the staleness.
    assert not any(isinstance(issue, dict) and issue.get("kind") == "success" for issue in projection["issues"])
    assert any(issue.get("kind") == "stale_report" for issue in projection["issues"])
    assert "stale" in json.dumps(projection).lower()
    assert "status" not in projection or projection.get("status") != "success"
    # Job row pins are displayed from the sealed read view.
    job_row = projection["job_row"]
    assert job_row["crawler_revision"] == 1
    assert job_row["downstream_revision"] == 1
    assert job_row["crawler_value"]["coverage"] == "full_crawl"
    assert job_row["downstream_value"]["selection"] == "job_0001"
    # Seal vector matches the slots.
    assert projection["seal_point"]["versions"]["application"] == 3
    # Strict gate: bare nulls are rejected, never stored.
    bad = json.dumps({"attempt": None}).encode("utf-8")
    rejected = _parse_response(dg.handle_http(PUBLISHER_CHANNEL, "POST", "/dashboard/snapshots", bad))
    assert rejected["http_status"] == 400


# ---------------------------------------------------------------------------
# Assertion 2: scalar application-status mutation is rejected
# ---------------------------------------------------------------------------


def test_dashboard_scalar_application_status_mutation_is_rejected():
    _admit_command_journal()
    head_before = ev.journal_head(CMD_CHANNEL, CMD_JOURNAL)
    assert head_before.last_sequence == 1

    # Forbidden generic set-status command via the command endpoint.
    forbidden = _command_body("set_application_status", "attempt_0001", 1, 1000.0, {"status": "hired"})
    resp = _parse_response(dg.handle_http(CMD_CHANNEL, "POST", "/dashboard/commands", _canonical(forbidden)))
    assert resp["http_status"] == 403
    assert "scalar" in resp["message"].lower()
    assert "rejected" in resp["message"].lower()
    assert resp["effect_claim"]["value"] is None

    # Variant spellings are also rejected.
    for variant in ("set_status", "update_application_status", "application_status"):
        body = _command_body(variant, "attempt_0001", 2, 1100.0)
        out = _parse_response(dg.handle_http(CMD_CHANNEL, "POST", "/dashboard/commands", _canonical(body)))
        assert out["http_status"] == 403, variant

    # Whole-row replacement is rejected as well.
    replace = _command_body("replace_row", "attempt_0001", 3, 1200.0)
    out = _parse_response(dg.handle_http(CMD_CHANNEL, "POST", "/dashboard/commands", _canonical(replace)))
    assert out["http_status"] == 403

    # Direct status paths never exist as writes.
    for path, method in (
        ("/dashboard/application-status", "POST"),
        ("/dashboard/status", "POST"),
        ("/application/status", "PUT"),
    ):
        out = _parse_response(dg.handle_http(CMD_CHANNEL, method, path, _canonical({"status": "hired"})))
        assert out["http_status"] == 403, f"{method} {path}"
        assert "rejected" in out["message"].lower()

    # None of the rejections journaled anything.
    head_after_rejections = ev.journal_head(CMD_CHANNEL, CMD_JOURNAL)
    assert head_after_rejections == head_before
    assert head_after_rejections.last_sequence == 1

    # An authorized dashboard command succeeds and journals intent only.
    allowed = _command_body("select_job", "job_0001", 4, 2000.0, {"job_id": "job_0001", "note": "operator selected job_0001"})
    ok = _parse_response(dg.handle_http(CMD_CHANNEL, "POST", "/dashboard/commands", _canonical(allowed)))
    assert ok["http_status"] == 201
    assert ok["accepted"] is True
    assert ok["command"] == "select_job"
    assert ok["journal_envelope"]["event_kind"] == CMD_KIND
    assert ok["journal_envelope"]["journal_sequence"] == 2
    assert ok["external_effect"]["value"] is None
    assert ok["external_effect"]["reason"] == "not_observed"
    head_after_allowed = ev.journal_head(CMD_CHANNEL, CMD_JOURNAL)
    assert head_after_allowed.last_sequence == 2
    assert head_after_allowed.head_hash == ok["journal_envelope"]["event_hash"]
    # The journaled payload records intent and explicitly claims no effect.
    prefix = ev.JournalPrefix(journal_id=CMD_JOURNAL, last_sequence=2, head_hash=head_after_allowed.head_hash)
    events = ev.read_prefix(CMD_CHANNEL, prefix)
    assert events[-1].payload["data"]["command"] == "select_job"
    assert events[-1].payload["data"]["effect_claim"]["reason"] == "not_observed"


# ---------------------------------------------------------------------------
# Assertion 3: close-time knowledge is displayed separately from later facts
# ---------------------------------------------------------------------------


def test_dashboard_displays_close_time_knowledge_separately_from_later_facts():
    ap.register_channel(
        actor="product_writer",
        channel_id="ch_dashboard_close_0001",
        axis="job.downstream",
        producer_id="prod_dashboard_close",
        principal_id="principal_dashboard_close",
        sequence_required=False,
        allowed_event_kinds=("product.published",),
    )
    channel = "ch_dashboard_close_0001"

    # Observation closed when application was at revision 1 with unknown
    # outcome; two later facts arrived after the boundary.
    close = _close_snapshot(closure_id="closure_close_0001", known_app=1, exec_knowledge="terminal", app_knowledge="unknown")
    facts = [
        _fact("fact_close_0001", 1, "not_committed", "at_boundary"),
        _fact("fact_late_0002", 2, "committed", "at_boundary"),
        _fact("fact_late_0003", 3, "committed", "final_for_attempt"),
    ]
    axes = {
        "dispatch": _dispatch_axis(revision=1, digest_char="a"),
        "observation": _observation_axis(revision=3, digest_char="b", closed=True, close_snapshot=close),
        "execution": _execution_axis(revision=1, digest_char="c"),
        "application": _application_axis(revision=3, digest_char="d", facts=facts),
        "report": _report_axis(
            revision=2,
            digest_char="e",
            state="reconciled",
            coverage="complete",
            inputs={
                "dispatch": _report_pin(1, "a"),
                "observation": _report_pin(3, "b"),
                "execution": _report_pin(1, "c"),
                "application": _report_pin(3, "d"),
            },
        ),
    }
    snap = _snapshot(attempt_id="attempt_close_0001", axes=axes, seal_name="observation_closed")

    stored = _parse_response(dg.handle_http(channel, "POST", "/dashboard/snapshots", _canonical(snap)))
    assert stored["http_status"] == 201
    assert stored["close_applicable"] is True

    view = _parse_response(dg.handle_http(channel, "GET", "/dashboard/attempts/attempt_close_0001", b""))
    assert view["http_status"] == 200
    projection = view["projection"]

    # Attempt kind/target and all five axes are displayed.
    assert projection["attempt"]["kind"] == "production"
    assert projection["attempt"]["target"] == "employer_origin_acme"
    assert set(projection["axes"].keys()) == {"dispatch", "observation", "execution", "application", "report"}
    assert projection["axes"]["observation"]["closed"] is True

    # Close-time knowledge is preserved exactly and shown separately.
    close_time = projection["close_time"]
    assert close_time["close_applicable"] is True
    assert close_time["close_preserved"] is True
    knowledge = close_time["close_time_knowledge"]
    assert knowledge["closure_id"] == "closure_close_0001"
    assert knowledge["known_versions"]["application"] == 1
    assert knowledge["execution_knowledge"] == "terminal"
    assert knowledge["application_knowledge"] == "unknown"
    assert knowledge["limitations"] == ["close-time outcome rests only on boundary evidence"]

    # At-close facts and later facts are split by the close boundary.
    at_close = close_time["at_close_facts"]
    later = close_time["later_facts"]
    assert [fact["fact_id"] for fact in at_close] == ["fact_close_0001"]
    assert [fact["fact_id"] for fact in later] == ["fact_late_0002", "fact_late_0003"]
    assert all(fact["revision"] <= 1 for fact in at_close)
    assert all(fact["revision"] > 1 for fact in later)
    # Later commitment does not rewrite the preserved close snapshot.
    assert knowledge["application_knowledge"] == "unknown"
    assert later[0]["state"] == "committed"
    # The full cumulative fact list is still present on the axis.
    assert len(projection["axes"]["application"]["facts"]) == 3
    # Seal proves the closed observation.
    assert projection["seal_point"]["name"] == "observation_closed"
    assert projection["seal_point"]["versions"]["observation"] == 3

