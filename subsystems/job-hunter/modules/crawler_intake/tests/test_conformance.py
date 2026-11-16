"""Conformance tests for crawler_intake (tier 6).

Covers exactly the ``-k`` filter named in the module spec:

- ``crawler_pass_missing_required_extraction_is_rejected_as_incomplete_extraction``
- ``failed_render_presented_as_usable_content_is_rejected``
- ``bypass_presented_as_genuine_classifier_pass_is_rejected``
- ``empty_unproven_coverage_is_not_presented_as_complete``
- ``same_fetch_key_different_response_preserves_acquisition_and_retains_observation``

Every check exercises the real module with real siblings: authenticated
channels, retained artifacts, an installed read view, a hash-chained owner
journal, and complete crawler ``LogicalRow`` documents.
"""

from __future__ import annotations

import copy
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
    path = (Path(__file__).resolve().parents[1] / rel).resolve()
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("access_policy", Path("../access_policy/src/__init__.py"))
cc = _load("contract_codec", Path("../contract_codec/src/__init__.py"))
store = _load("artifact_store", Path("../artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("../evidence_journal/src/__init__.py"))
rp = _load("read_publications", Path("../read_publications/src/__init__.py"))
ci = _load("crawler_intake", Path("src/__init__.py"))

CRAWLER_CHANNEL = "ch_crawler_intake_crawler_0001"
CRAWLER_PRODUCER = "prod_crawler_intake_crawler"
INTAKE_CHANNEL = "ch_crawler_intake_downstream_0001"
INTAKE_PRODUCER = "prod_crawler_intake_downstream"
PUBLISHER_CHANNEL = "ch_crawler_intake_publisher_0001"
PUBLISHER_PRODUCER = "prod_crawler_intake_publisher"

INTAKE_JOURNAL = "journal_crawler_intake_0001"
SOURCE_JOURNAL = "journal_crawler_source_0001"
VIEW = "view_crawler_intake_0001"

ENTITY = {"entity_type": "job", "target": "target_acme", "job_id": "job_0001"}
DISCOVERY_REF = {
    "journal_id": SOURCE_JOURNAL,
    "sequence": 1,
    "event_id": "evt_crawler_discovery_0001",
    "event_hash": "sha256:" + "d" * 64,
    "pointer": "",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest_for(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _missing(reason: str = "not_observed") -> dict:
    return {"value": None, "reason": reason}


def _evidence_ref(suffix: str, sequence: int = 1) -> dict:
    return {
        "journal_id": SOURCE_JOURNAL,
        "sequence": sequence,
        "event_id": f"evt_crawler_intake_{suffix}",
        "event_hash": _digest_for(f"event-{suffix}-{sequence}"),
        "pointer": "",
    }


def _time_point(offset_ms: float = 1500.0) -> dict:
    return {
        "clock_id": "clock_crawler_intake",
        "boot_id": "boot_crawler_intake",
        "origin": "engine_measured",
        "monotonic_offset_ms": float(offset_ms),
        "utc_annotation": _missing("not_observed"),
    }


def _version_pin(pin_id: str, label: str) -> dict:
    return {
        "id": pin_id,
        "version": "1",
        "artifact_digest": _digest_for(label),
    }


def _measurement(label: str) -> dict:
    return {
        "measurement": {
            "measurement_id": f"m_{label}",
            "note": "structural evidence",
        },
        "evidence_refs": [_evidence_ref(f"meas_{label}")],
    }


def _retain_public(label: str, payload: dict) -> dict:
    reference = store.retain_artifact(
        CRAWLER_CHANNEL,
        "job.crawler",
        "application/json",
        _canonical(payload),
        "public",
    )
    return reference.to_dict()


def _render_observation(verdict: str, suffix: str) -> dict:
    return {
        "transport": "HttpClient",
        "operation": f"op_{suffix}",
        "verdict": verdict,
        "basis": f"basis_{suffix}",
        "response_hash": f"response-{suffix}",
        "evidence_refs": [_evidence_ref(f"render_{suffix}")],
        "measurements": [_measurement(f"render_{suffix}")],
    }


CORE_FIELD_TYPES = (
    ("title", "string"),
    ("employer", "text"),
    ("snippet", "text"),
    ("description", "text"),
    ("posted_date", "date"),
    ("location", "text"),
    ("direct_apply_url", "url"),
    ("portal_type", "string"),
    ("closing_date", "text"),
)


def _declarations(extra=()):
    declarations = []
    for name, decl_type in CORE_FIELD_TYPES:
        declarations.append(
            {
                "name": name,
                "type": decl_type,
                "required": True,
                "nullable": False,
                "extraction_binding": _version_pin(f"ext_{name}", f"binding-{name}"),
            }
        )
    for item in extra:
        declarations.append(
            {
                "name": item["name"],
                "type": item["type"],
                "required": bool(item.get("required", False)),
                "nullable": False if item.get("required", False) else True,
                "extraction_binding": _version_pin(
                    f"ext_{item['name']}", f"binding-{item['name']}"
                ),
            }
        )
    return declarations


def _full_content() -> dict:
    return {
        "title": "Senior Systems Engineer",
        "employer": "Acme Corp",
        "snippet": "Systems role snippet",
        "description": "Full description with responsibilities and qualifications.",
        "posted_date": "2026-10-01",
        "location": "Springfield",
        "direct_apply_url": "https://example.com/apply/job_0001",
        "portal_type": "greenhouse",
        "closing_date": "2026-11-30",
        "extended": [],
    }


def _missing_content() -> dict:
    return {
        field: _missing("not_observed") for field, _decl_type in CORE_FIELD_TYPES
    } | {"extended": []}


def _acquisition(
    *,
    verdict: str = "Pass",
    content: dict | None = None,
    fetch_key: str | None = None,
    source_response: object = "artifact",
    declarations=None,
    suffix: str = "pass",
) -> dict:
    body = dict(content) if content is not None else _full_content()
    key = fetch_key or _digest_for("fetch-key-base")
    if source_response == "artifact":
        response_ref = _retain_public(
            f"response-{suffix}", {"html": f"<p>{suffix}</p>"}
        )
    elif source_response == "missing":
        response_ref = _missing("not_observed")
    elif isinstance(source_response, dict):
        response_ref = dict(source_response)
    else:
        raise TypeError(f"unsupported source_response fixture: {source_response!r}")
    source_url = "https://example.com/listings/job_0001"
    return {
        "source_url": source_url,
        "listing_page_url": _missing("not_observed"),
        "fetch_key": key,
        "fetch_key_profile": "crawler-fetch-key/1",
        "fetch_identity": {
            "phase_token": "A_full",
            "listing_source_url": source_url,
        },
        "source_response": response_ref,
        "extractor": _version_pin("extractor_html", f"extractor-{suffix}"),
        "content_declarations": (
            _declarations() if declarations is None else list(declarations)
        ),
        "content": body,
        "render_verdict": verdict,
        "render_basis": f"render_basis_{suffix}",
        "render_history": [_render_observation(verdict, suffix)],
        "rendered_at": _time_point(),
        "evidence_refs": [_evidence_ref(f"acq_{suffix}")],
    }


def _classifier_result(
    result_id: str,
    verdict: str = "PASS",
    applied: str = "PASS",
    suffix: str = "genuine",
) -> dict:
    return {
        "result_id": result_id,
        "stage": "description",
        "model": _version_pin("classifier_model", f"model-{suffix}"),
        "tokenizer_digest": _digest_for(f"tokenizer-{suffix}"),
        "prompt_digest": _digest_for(f"prompt-{suffix}"),
        "canonicalization_version": "canon_v1",
        "input_hash": _digest_for(f"input-{suffix}"),
        "verdict": verdict,
        "verdict_applied": applied,
        "confidence": 0.91,
        "reason": "model output recorded",
        "classified_at": _time_point(),
        "latency": _measurement(f"cls_{suffix}"),
        "application_revision": 1,
        "policy_revision": "policy_v3",
        "evidence_refs": [_evidence_ref(f"cls_{suffix}")],
    }


def _processing(
    *,
    pipeline_state: str = "ready",
    results: list[dict] | None = None,
    final_id: object = "missing-else",
    bypass: object = "missing",
    suffix: str = "pass",
) -> dict:
    if results is None:
        genuine = _classifier_result("res_genuine_0001", "PASS", "PASS", suffix)
        results = [genuine]
    if final_id == "missing-else":
        final_value: object = results[0]["result_id"] if results else _missing(
            "not_applicable"
        )
    elif final_id == "missing":
        final_value = _missing("not_applicable")
    else:
        final_value = final_id
    bypass_value = _missing("not_applicable") if bypass == "missing" else bypass
    return {
        "pipeline_state": pipeline_state,
        "classification_surface": "phase_a_full_description",
        "active_run_id": "run_crawler_0001",
        "input_revision": 1,
        "generation_id": "gen_0001",
        "lease": _missing("not_applicable"),
        "retry_count": 0,
        "max_retries_effective": 3,
        "last_failure_reason": _missing("not_observed"),
        "classifier_results": list(results),
        "final_genuine_result_id": final_value,
        "bypass_reason": bypass_value,
        "semantic_candidate": "SHORTLISTED",
        "semantic_evidence_refs": [_evidence_ref(f"sem_{suffix}")],
    }


def _coverage_ref(status: str, proven: bool, suffix: str) -> dict:
    return {
        "run_id": "run_crawler_0001",
        "partition_id": f"part_{suffix}",
        "partition_definition_hash": _digest_for(f"partition-{suffix}"),
        "status": status,
        "pagination_coverage_proven": proven,
        "ledger": _retain_public(
            f"ledger-{suffix}-{status}",
            {"ledger": suffix, "status": status},
        ),
        "evidence_refs": [_evidence_ref(f"cov_{suffix}_{status}")],
    }


def _discovery(coverage: list[dict] | None = None, suffix: str = "pass") -> dict:
    refs = (
        list(coverage)
        if coverage is not None
        else [_coverage_ref("proven", True, suffix)]
    )
    return {
        "first_seen_run_id": "run_crawler_0001",
        "last_seen_run_id": "run_crawler_0001",
        "first_seen_at": _time_point(900.0),
        "last_seen_at": _time_point(1100.0),
        "coverage": refs,
    }


def _registration(registration_id: str = "reg_crawler_intake_0001"):
    owners = {
        "crawler": {
            "role": "crawler",
            "source_id": "src_crawler_0001",
            "writer_id": "writer_crawler_0001",
            "owner_domain": "job.crawler",
            "publication_policy": _version_pin("policy_crawler", "policy-crawler"),
        },
        "downstream": {
            "role": "product",
            "source_id": "src_product_0001",
            "writer_id": "writer_product_0001",
            "owner_domain": "job.downstream",
            "publication_policy": _version_pin("policy_product", "policy-product"),
        },
    }
    return rp.EntityRegistration(
        registration_id=registration_id,
        entity=dict(ENTITY),
        identity={
            "portfolio_job_id": "portfolio_job_0001",
            "first_discovery_ref": dict(DISCOVERY_REF),
        },
        owners=owners,
        evidence_prefix={
            "journal_id": SOURCE_JOURNAL,
            "last_sequence": 3,
            "head_hash": _digest_for("registration-prefix"),
        },
        evidence_refs=(dict(DISCOVERY_REF),),
    )


def _registration_digest(registration) -> str:
    return str(cc.canonical_digest(_canonical(registration.to_dict())))


def _owned_revision(revision: int, registration_digest: str, value: dict) -> dict:
    return {
        "record_type": "owned_domain_revision",
        "schema_version": rp.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration_digest": registration_digest,
        "domain": "crawler",
        "owner_domain": "job.crawler",
        "writer_id": "writer_crawler_0001",
        "revision": revision,
        "previous_revision": revision - 1,
        "evidence_prefix": {
            "journal_id": SOURCE_JOURNAL,
            "last_sequence": 4 + revision,
            "head_hash": _digest_for(f"doc-prefix-{revision}"),
        },
        "evidence_refs": [_evidence_ref(f"doc_{revision}", sequence=4 + revision)],
        "value": value,
    }


def _row(
    revision: int,
    doc: dict,
    doc_ref: dict,
    registration,
    registration_digest: str,
    seal_id: str | None = None,
) -> dict:
    seal = seal_id or f"seal_crawler_intake_{revision:04d}"
    return {
        "record_type": "logical_row",
        "schema_version": rp.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration_digest": registration_digest,
        "registration": registration.to_dict(),
        "domains": {
            "crawler": {
                "revision": revision,
                "document": dict(doc_ref),
                "publication_ref": _evidence_ref(f"pub_{revision}", sequence=2),
                "snapshot": copy.deepcopy(doc),
            },
            "downstream": {"revision": 0, "value": _missing("not_observed")},
        },
        "seal_point": {
            "seal_id": seal,
            "name": "published",
            "view_id": VIEW,
            "versions": {"crawler": revision, "downstream": 0},
            "sealed_at": _time_point(2000.0),
            "input_prefix": {
                "journal_id": SOURCE_JOURNAL,
                "last_sequence": 5,
                "head_hash": _digest_for("seal-prefix"),
            },
            "evidence_refs": [_evidence_ref(f"seal_{revision}", sequence=2)],
        },
    }


def _setup_pass_row(
    *,
    content: dict | None = None,
    fetch_key: str | None = None,
    declarations=None,
    acquisition_kwargs: dict | None = None,
    processing_kwargs: dict | None = None,
    discovery_kwargs: dict | None = None,
    lineage: object = None,
    seal_id: str | None = None,
    revision: int = 1,
    suffix: str | None = None,
    value: dict | None = None,
):
    suffix = suffix or f"rev{revision}"
    registration = _registration()
    registration_digest = _registration_digest(registration)
    if value is None:
        acquisition = _acquisition(
            content=content,
            fetch_key=fetch_key,
            declarations=declarations,
            suffix=suffix,
            **dict(acquisition_kwargs or {}),
        )
        processing = _processing(suffix=suffix, **dict(processing_kwargs or {}))
        discovery = _discovery(suffix=suffix, **dict(discovery_kwargs or {}))
        value = {
            "acquisition": acquisition,
            "processing": processing,
            "discovery": discovery,
            "replacement_lineage": (
                _missing("not_applicable") if lineage is None else lineage
            ),
        }
    document = _owned_revision(revision, registration_digest, value)
    doc_ref = _retain_public(f"doc-{suffix}", document)
    row = _row(
        revision,
        document,
        doc_ref,
        registration,
        registration_digest,
        seal_id=seal_id,
    )
    return row, document, doc_ref, registration, registration_digest


# ---------------------------------------------------------------------------
# Channel and journal setup
# ---------------------------------------------------------------------------


def _register_channels() -> None:
    ap.register_channel(
        actor="crawler_writer",
        channel_id=CRAWLER_CHANNEL,
        axis="job.crawler",
        producer_id=CRAWLER_PRODUCER,
        principal_id="principal_crawler_intake_crawler",
        sequence_required=False,
        allowed_event_kinds=("crawler.published",),
    )
    ap.register_channel(
        actor="product_writer",
        channel_id=INTAKE_CHANNEL,
        axis="job.downstream",
        producer_id=INTAKE_PRODUCER,
        principal_id="principal_crawler_intake_product",
        sequence_required=False,
        allowed_event_kinds=(ci.INTAKE_EVENT_KIND,),
    )
    ap.register_channel(
        actor="read_view_publisher",
        channel_id=PUBLISHER_CHANNEL,
        axis="publication.derived",
        producer_id=PUBLISHER_PRODUCER,
        principal_id="principal_crawler_intake_publisher",
        sequence_required=False,
        allowed_event_kinds=(
            rp.INSTALL_EVENT_KIND,
            rp.SEAL_EVENT_KIND,
            rp.ROW_EVENT_KIND,
        ),
    )
    ap.register_event_kind(
        ci.INTAKE_EVENT_KIND,
        ci.INTAKE_EVENT_SCHEMA_VERSION,
        role="derived_output",
        assertion_kind="observation",
        owner_domain="job.downstream",
        writer_roles=("kernel",),
    )


def _reset_all() -> None:
    ci.reset_for_tests()
    rp.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    _register_channels()


@pytest.fixture(autouse=True)
def _fresh_state():
    _reset_all()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    rp.reset_for_tests()
    ci.reset_for_tests()


def _admit_intake_journal() -> None:
    """Admit the downstream intake journal so observation events can persist."""
    task = store.retain_artifact(
        INTAKE_CHANNEL,
        "job.downstream",
        "application/json",
        _canonical({"kind": "crawler_intake_task"}),
        "restricted",
    )
    configuration = store.retain_artifact(
        INTAKE_CHANNEL,
        "job.downstream",
        "application/json",
        _canonical(
            {
                "kind": "crawler_intake_configuration",
                "event_kind": ci.INTAKE_EVENT_KIND,
            }
        ),
        "restricted",
    )
    descriptor = ap.channel_projection(INTAKE_CHANNEL)["producer"]
    manifest = ev.Manifest(
        manifest_id="manifest_crawler_intake_0001",
        run_id="run_crawler_intake_0001",
        journal_id=INTAKE_JOURNAL,
        owner_domain="job.downstream",
        commissioner_id="commissioner_crawler_intake",
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
                "description": "crawler intake conformance host",
            },
        },
        task=task,
        task_semantic_hash=task.digest,
        effective_configuration=configuration,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {
                "id": "crawler_intake",
                "version": "1",
                "artifact_digest": task.digest,
            }
        ],
        event_registry=[
            {
                "event_kind": ci.INTAKE_EVENT_KIND,
                "event_schema_version": ci.INTAKE_EVENT_SCHEMA_VERSION,
                "role": "derived_output",
                "assertion_kind": "observation",
                "owner_domain": "job.downstream",
                "writer_roles": ["kernel"],
            }
        ],
        producers=[dict(descriptor)],
        clocks=[
            {
                "clock_id": "clock_crawler_intake",
                "boot_id": "boot_crawler_intake",
                "origin": "engine_measured",
                "source_id": "src_crawler_intake_clock",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    ev.admit_manifest(INTAKE_CHANNEL, manifest)


# ---------------------------------------------------------------------------
# Assertion 1: a Pass missing required extraction is incomplete_extraction
# ---------------------------------------------------------------------------


def test_crawler_pass_missing_required_extraction_is_rejected_as_incomplete_extraction():
    # (a) A declared, required canonical field carrying reasoned Missingness is
    #     incomplete extraction, not a valid job and not a render failure.
    content = _full_content()
    content["description"] = _missing("not_observed")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(content=content, suffix="missing")
    with pytest.raises(ci.IncompleteExtractionError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert excinfo.value.code == "incomplete_extraction"
    assert "incomplete_extraction" in str(excinfo.value).lower()
    assert ci.observations() == ()
    ci.reset_for_tests()

    # (b) A content contract that drops the required declaration is rejected
    #     just as hard: declaring less cannot make a Pass complete.
    reduced = [decl for decl in _declarations() if decl["name"] != "description"]
    content = _full_content()
    content["description"] = _missing("not_observed")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        content=content, declarations=reduced, suffix="undeclared"
    )
    with pytest.raises(ci.IncompleteExtractionError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "omits required" in str(excinfo.value)
    ci.reset_for_tests()

    # (c) A Pass without the observed response bytes cannot be materialized.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        acquisition_kwargs={"source_response": "missing"}, suffix="noresponse"
    )
    with pytest.raises(ci.IncompleteExtractionError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "source_response" in str(excinfo.value)
    ci.reset_for_tests()

    # (d) A required value of the wrong type is incomplete extraction too.
    content = _full_content()
    content["posted_date"] = 42
    row, _doc, _ref, _reg, _digest = _setup_pass_row(content=content, suffix="wrongtype")
    with pytest.raises(ci.IncompleteExtractionError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "posted_date" in str(excinfo.value)
    ci.reset_for_tests()

    # (e) The same complete row admitted through the installed read view is
    #     usable: the module re-verifies the immutable row root and its bytes.
    _reset_all()
    registration = _registration()
    registration_digest = _registration_digest(registration)
    acquisition = _acquisition(suffix="view")
    processing = _processing(suffix="view")
    discovery = _discovery(suffix="view")
    document = _owned_revision(
        1,
        registration_digest,
        {
            "acquisition": acquisition,
            "processing": processing,
            "discovery": discovery,
            "replacement_lineage": _missing("not_applicable"),
        },
    )
    doc_ref = _retain_public("doc-view", document)
    rp.install_publication(
        PUBLISHER_CHANNEL,
        registration,
        store.ArtifactReference.from_dict(doc_ref),
        VIEW,
    )
    sealed = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "published")
    accepted = ci.accept_job_row(PUBLISHER_CHANNEL, sealed)
    assert accepted.render_verdict == "Pass"
    assert accepted.pipeline_state == "ready"
    assert accepted.usable is True
    assert accepted.job_content["description"].startswith("Full description")
    assert accepted.job_content["closing_date"] == "2026-11-30"
    assert accepted.job_content["extended"] == []
    assert accepted.crawler_input["revision"] == 1
    assert accepted.crawler_input["record_digest"] == doc_ref["digest"]
    assert accepted.seal_id == sealed.seal_point.seal_id
    assert (
        accepted.logical_row_ref
        == sealed.domains["crawler"].publication_ref.to_dict()
    )
    assert accepted.coverage_statuses == ("proven",)
    assert accepted.coverage_complete is True
    retained_row = store.resolve_artifact(
        PUBLISHER_CHANNEL,
        store.ArtifactReference.from_dict(accepted.logical_row),
    )
    assert retained_row == _canonical(sealed.to_dict())
    round_trip = ci.EvaluationJobInput.from_dict(accepted.to_dict())
    assert round_trip.to_dict() == accepted.to_dict()

    # (f) A delivered row that disagrees with the installed view is rejected.
    tampered = copy.deepcopy(sealed.to_dict())
    tampered["seal_point"]["seal_id"] = "seal_tampered_0001"
    with pytest.raises(ci.RowAdmissionError):
        ci.accept_job_row(PUBLISHER_CHANNEL, tampered)

    # (g) A snapshot that is not the referenced complete document is rejected.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(suffix="snapshot")
    tampered_row = copy.deepcopy(row)
    tampered_row["domains"]["crawler"]["snapshot"]["value"]["acquisition"][
        "content"
    ]["title"] = "Tampered title"
    with pytest.raises(ci.RowAdmissionError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, tampered_row)
    assert "snapshot" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Assertion 2: a failed render is never presented as usable content
# ---------------------------------------------------------------------------


def test_failed_render_presented_as_usable_content_is_rejected():
    # (a) A non-Pass verdict smuggling extracted content is rejected.
    usable = _missing_content()
    usable["title"] = "Smuggled usable title"
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        content=usable,
        acquisition_kwargs={"verdict": "ThinShell"},
        processing_kwargs={
            "pipeline_state": "render_failed",
            "results": [],
            "final_id": _missing("not_applicable"),
        },
        suffix="usable",
    )
    with pytest.raises(ci.UnusableContentError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert excinfo.value.code == "failed_render_as_usable"
    assert "usable" in str(excinfo.value).lower()
    ci.reset_for_tests()

    # (b) A non-Pass verdict paired with a non-failed pipeline state is not a
    #     render failure: it is unusable content pretending to be ready.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        content=_missing_content(),
        acquisition_kwargs={"verdict": "SensorFail"},
        processing_kwargs={
            "pipeline_state": "ready",
            "results": [],
            "final_id": _missing("not_applicable"),
        },
        suffix="readystate",
    )
    with pytest.raises(ci.UnusableContentError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "requires pipeline_state='render_failed'" in str(excinfo.value)
    ci.reset_for_tests()

    # (c) A failed render carrying a classifier result is rejected: a
    #     non-Pass acquisition has no genuine classifier result.
    genuine = _classifier_result("res_genuine_0001", "PASS", "PASS", "failed-carry")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        content=_missing_content(),
        acquisition_kwargs={"verdict": "ThinShell"},
        processing_kwargs={
            "pipeline_state": "render_failed",
            "results": [genuine],
            "final_id": _missing("not_applicable"),
        },
        suffix="carriedresult",
    )
    with pytest.raises(ci.UnusableContentError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "classifier results" in str(excinfo.value)
    ci.reset_for_tests()

    # (d) A honestly failed render is admitted, but every content value keeps
    #     its reasoned missingness and nothing becomes usable content.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        content=_missing_content(),
        acquisition_kwargs={"verdict": "ThinShell", "source_response": "missing"},
        processing_kwargs={
            "pipeline_state": "render_failed",
            "results": [],
            "final_id": _missing("not_applicable"),
        },
        suffix="honestfail",
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.render_verdict == "ThinShell"
    assert accepted.pipeline_state == "render_failed"
    assert accepted.usable is False
    assert accepted.job_content["title"] == _missing("not_observed")
    assert accepted.job_content["description"] == _missing("not_observed")
    assert accepted.job_content["direct_apply_url"] == _missing("not_observed")
    assert accepted.job_content["extended"] == []
    assert accepted.genuine_result_id == _missing("not_applicable")
    assert accepted.classifier_verdicts == ()


# ---------------------------------------------------------------------------
# Assertion 3: a bypass is never presented as a genuine classifier pass
# ---------------------------------------------------------------------------


def test_bypass_presented_as_genuine_classifier_pass_is_rejected():
    genuine = _classifier_result("res_genuine_0001", "PASS", "PASS", "bypass")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        processing_kwargs={
            "results": [genuine],
            "final_id": "res_genuine_0001",
            "bypass": "operator_bypass_no_model",
        },
        suffix="bypassgenuine",
    )
    with pytest.raises(ci.BypassAsGenuineError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert excinfo.value.code == "bypass_as_genuine"
    assert "bypass produces no classifier result" in str(excinfo.value)
    ci.reset_for_tests()

    # A shadow-mode raw VETO applied as PASS is not a genuine pass.
    shadow = _classifier_result("res_shadow_0001", "VETO", "PASS", "shadow")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        processing_kwargs={
            "results": [shadow],
            "final_id": "res_shadow_0001",
        },
        suffix="shadow",
    )
    with pytest.raises(ci.BypassAsGenuineError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "only PASS/PASS is a genuine pass" in str(excinfo.value)
    ci.reset_for_tests()

    # A genuine result with a missing classifier body is not a genuine pass.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        processing_kwargs={
            "results": [],
            "final_id": "res_missing_0001",
        },
        suffix="dangling",
    )
    with pytest.raises(ci.BypassAsGenuineError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert "resolves to no classifier result" in str(excinfo.value)
    ci.reset_for_tests()

    # (d) A bypassed acquisition is admitted with no genuine result at all.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        processing_kwargs={
            "results": [],
            "final_id": _missing("not_applicable"),
            "bypass": "operator_bypass_no_model",
        },
        suffix="bypassonly",
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.genuine_result_id == _missing("not_applicable")
    assert accepted.bypass_reason == "operator_bypass_no_model"
    assert accepted.classifier_verdicts == ()
    assert accepted.render_verdict == "Pass"
    ci.reset_for_tests()

    # A shadow-mode result that is not named as the genuine pass is admitted
    # with the raw and applied verdicts preserved: the shadow stays visible
    # instead of being collapsed into a genuine pass.
    shadow_open = _classifier_result("res_shadow_0002", "VETO", "PASS", "shadow-open")
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        processing_kwargs={
            "results": [shadow_open],
            "final_id": _missing("not_applicable"),
        },
        suffix="shadowopen",
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.genuine_result_id == _missing("not_applicable")
    assert accepted.classifier_verdicts == (("res_shadow_0002", "VETO", "PASS"),)
    ci.reset_for_tests()

    # (e) A genuine PASS/PASS result stays a genuine classifier pass.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(suffix="genuine")
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.genuine_result_id == "res_genuine_0001"
    assert accepted.bypass_reason == _missing("not_applicable")
    assert accepted.classifier_verdicts == (("res_genuine_0001", "PASS", "PASS"),)


# ---------------------------------------------------------------------------
# Assertion 4: empty unproven coverage is never presented as complete
# ---------------------------------------------------------------------------


def test_empty_unproven_coverage_is_not_presented_as_complete():
    # (a) An empty_unproven coverage reference is admitted only as unproven:
    #     no observations never prove emptiness.
    empty_refs = [_coverage_ref("empty_unproven", False, "empty")]
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        discovery_kwargs={"coverage": empty_refs}, suffix="emptycoverage"
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.coverage_statuses == ("empty_unproven",)
    assert accepted.coverage_complete is False
    assert accepted.coverage_complete is not True
    assert accepted.usable is True
    ci.reset_for_tests()

    # (b) No coverage references at all is an established empty collection,
    #     not proof of complete coverage.
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        discovery_kwargs={"coverage": []}, suffix="nocoverage"
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.coverage_statuses == ()
    assert accepted.coverage_complete is False
    ci.reset_for_tests()

    # (c) Every partition must be proven before completeness is claimed.
    mixed = [
        _coverage_ref("proven", True, "mixed_a"),
        _coverage_ref("empty_unproven", False, "mixed_b"),
    ]
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        discovery_kwargs={"coverage": mixed}, suffix="mixedcoverage"
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.coverage_statuses == ("proven", "empty_unproven")
    assert accepted.coverage_complete is False
    ci.reset_for_tests()

    # (d) Referenced proof for every partition is complete coverage.
    proven_refs = [
        _coverage_ref("proven", True, "proven_a"),
        _coverage_ref("proven", True, "proven_b"),
    ]
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        discovery_kwargs={"coverage": proven_refs}, suffix="provencoverage"
    )
    accepted = ci.accept_job_row(INTAKE_CHANNEL, row)
    assert accepted.coverage_statuses == ("proven", "proven")
    assert accepted.coverage_complete is True
    ci.reset_for_tests()

    # (e) Claiming proof on an empty_unproven status is rejected outright.
    bad_refs = [_coverage_ref("empty_unproven", True, "bad")]
    row, _doc, _ref, _reg, _digest = _setup_pass_row(
        discovery_kwargs={"coverage": bad_refs}, suffix="badcoverage"
    )
    with pytest.raises(ci.CoverageNotProvenError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row)
    assert excinfo.value.code == "coverage_not_proven"
    assert "cannot be presented as proven" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Assertion 5: a same-key response change preserves acquisition, retains the
#              observation, and never installs a replacement
# ---------------------------------------------------------------------------


def test_same_fetch_key_different_response_preserves_acquisition_and_retains_observation():
    _admit_intake_journal()
    fetch_key = _digest_for("fetch-key-stable")

    row1, _doc1, doc_ref1, _reg, _digest = _setup_pass_row(
        fetch_key=fetch_key,
        seal_id="seal_crawler_intake_samekey_0001",
        suffix="samekey1",
    )
    first = ci.accept_job_row(INTAKE_CHANNEL, row1)
    assert first.fetch_key == fetch_key
    assert first.crawler_input["revision"] == 1
    prior_digest = first.acquisition_digest
    assert prior_digest.startswith("sha256:")

    # A newer response under the same fetch key must not win the acquisition.
    newer_content = _full_content()
    newer_content["description"] = "Newer extractor output that must not win."
    row2, _doc2, doc_ref2, _reg, _digest = _setup_pass_row(
        content=newer_content,
        fetch_key=fetch_key,
        revision=2,
        seal_id="seal_crawler_intake_samekey_0002",
        suffix="samekey2",
    )
    with pytest.raises(ci.SameFetchKeyConflictError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row2)
    assert excinfo.value.code == "same_fetch_key_conflict"
    assert excinfo.value.observation_retained is True
    assert "same fetch key" in str(excinfo.value).lower()
    assert "observation" in str(excinfo.value)
    assert prior_digest in str(excinfo.value)

    # The differing response was retained as an observation artifact.
    recorded = ci.observations(INTAKE_CHANNEL)
    assert len(recorded) == 1
    observation = recorded[0]
    assert observation["prior_acquisition_digest"] == prior_digest
    assert observation["fetch_key"] == fetch_key
    assert observation["prior_revision"] == 1
    assert observation["observed_revision"] == 2
    assert observation["observed_record_digest"] == doc_ref2["digest"]
    assert observation["observed_acquisition_digest"] != prior_digest
    observation_ref = store.ArtifactReference.from_dict(
        observation["observation_artifact"]
    )
    observation_bytes = store.resolve_artifact(INTAKE_CHANNEL, observation_ref)
    observation_body = json.loads(observation_bytes)
    assert observation_body["record_type"] == ci.INTAKE_OBSERVATION_RECORD_TYPE
    assert observation_body["prior_acquisition_digest"] == prior_digest
    assert observation_body["observed_acquisition_digest"] == (
        observation["observed_acquisition_digest"]
    )
    assert _canonical(observation_body) == observation_bytes

    # The observation is journaled in the intake owner's hash-chained journal.
    head = ev.journal_head(INTAKE_CHANNEL, INTAKE_JOURNAL)
    events = ev.read_prefix(INTAKE_CHANNEL, head)
    intake_events = [
        event for event in events if event.event_kind == ci.INTAKE_EVENT_KIND
    ]
    assert len(intake_events) == 1
    event = intake_events[0]
    assert event.owner_domain == "job.downstream"
    assert event.payload["data"]["fetch_key"] == fetch_key
    assert event.payload["data"]["prior_acquisition_digest"] == prior_digest
    assert event.payload["data"]["observed_record_digest"] == doc_ref2["digest"]
    assert event.payload["artifact_refs"] == [observation_ref.to_dict()]

    # The prior acquisition is preserved: re-admitting the identical original
    # revision is an acquisition no-op, not a conflict.
    again = ci.accept_job_row(INTAKE_CHANNEL, row1)
    assert again.fetch_key == fetch_key
    assert again.acquisition_digest == prior_digest
    assert again.crawler_input["revision"] == 1
    assert first.acquisition_digest == prior_digest

    # Re-offering the differing response is still an observation, never an
    # installed same-key replacement; each observation is retained.
    with pytest.raises(ci.SameFetchKeyConflictError):
        ci.accept_job_row(INTAKE_CHANNEL, row2)
    assert len(ci.observations(INTAKE_CHANNEL)) == 2
    assert ci.observations(INTAKE_CHANNEL)[0]["prior_acquisition_digest"] == prior_digest

    # A changed fetch key without replacement evidence requires an archive
    # instead of mutating the acquisition in place.
    changed_key = _digest_for("fetch-key-changed")
    row3, _doc3, _ref3, _reg, _digest = _setup_pass_row(
        fetch_key=changed_key,
        revision=3,
        seal_id="seal_crawler_intake_samekey_0003",
        suffix="changedkey",
    )
    with pytest.raises(ci.ReplacementRequiredError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row3)
    assert excinfo.value.code == "replacement_required"
    assert "fetch key changed" in str(excinfo.value)
    assert fetch_key in str(excinfo.value)
    assert changed_key in str(excinfo.value)

    # A named lineage whose archive root is not a complete prior-row archive is
    # rejected through archive_retention: a locator or partial payload is not
    # replacement evidence.
    phantom_root = _retain_public(
        "phantom-archive", {"record_type": "not_an_archive"}
    )
    lineage = {
        "replacement_id": "replacement_missing_0001",
        "prior_crawler_revision": 1,
        "archive_root": phantom_root,
    }
    row4, _doc4, _ref4, _reg, _digest = _setup_pass_row(
        fetch_key=changed_key,
        revision=2,
        lineage=lineage,
        seal_id="seal_crawler_intake_samekey_0004",
        suffix="phantomarchive",
    )
    with pytest.raises(ci.ReplacementRequiredError) as excinfo:
        ci.accept_job_row(INTAKE_CHANNEL, row4)
    assert excinfo.value.code == "replacement_required"
    assert "complete verified prior-row archive" in str(excinfo.value)

    # Independent processing/classification advancement may move the crawler
    # revision while the acquisition itself is preserved exactly: no new
    # acquisition, no observation, no archive.
    first_document_value = json.loads(
        json.dumps(row1["domains"]["crawler"]["snapshot"]["value"])
    )
    advanced_value = {
        "acquisition": first_document_value["acquisition"],
        "processing": _processing(
            pipeline_state="pending_classification",
            results=[],
            final_id=_missing("not_applicable"),
            suffix="advanced",
        ),
        "discovery": _discovery(suffix="advanced"),
        "replacement_lineage": _missing("not_applicable"),
    }
    row5, _doc5, ref5, _reg5, _digest5 = _setup_pass_row(
        value=advanced_value,
        revision=4,
        seal_id="seal_crawler_intake_samekey_0005",
        suffix="advanced",
    )
    advanced = ci.accept_job_row(INTAKE_CHANNEL, row5)
    assert advanced.acquisition_digest == prior_digest
    assert advanced.fetch_key == fetch_key
    assert advanced.crawler_input["revision"] == 4
    assert advanced.crawler_input["record_digest"] == ref5["digest"]
    assert advanced.pipeline_state == "pending_classification"
    assert advanced.genuine_result_id == _missing("not_applicable")
    assert len(ci.observations(INTAKE_CHANNEL)) == 2
