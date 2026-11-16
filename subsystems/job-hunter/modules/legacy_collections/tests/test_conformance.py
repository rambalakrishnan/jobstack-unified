"""Conformance tests for legacy_collections (tier 3).

Covers exactly the ``-k`` filter named in the module spec:

- ``legacy_company_title_collision_never_automatically_merges_identities``
- ``legacy_unknown_status_or_type_preserves_source_and_requires_mapping``
- ``all_twelve_legacy_collection_adapters_remain_private_and_evidenced``

Every check exercises the real module against the real sibling dependencies:
authenticated product-writer authorization, restricted artifact resolution and
retention, the tier-0 strict codec gate, and an admitted evidence journal.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


def _load(name: str, rel: Path):
    """Import a sibling module, falling back to its in-tree source path."""
    if name in sys.modules:
        return sys.modules[name]
    try:
        return __import__(name)
    except ModuleNotFoundError:
        pass
    here = Path(__file__).resolve()
    path = (
        here.parents[1] / rel
        if name == "legacy_collections"
        else here.parents[2] / rel
    )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load("contract_codec", Path("contract_codec/src/__init__.py"))
ap = _load("access_policy", Path("access_policy/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
legacy = _load("legacy_collections", Path("src/__init__.py"))


CHANNEL = "ch_legacy_import_0001"
PRODUCER = "prod_legacy_import"
PRINCIPAL = "principal_legacy_import"
OWNER = "job.downstream"
JOURNAL = "journal_legacy_import_0001"
RUN = "run_legacy_import_0001"
CLOCK_ID = "clock_legacy_engine"
BOOT_ID = "boot_legacy_engine"
CRAWLER_CHANNEL = "ch_legacy_crawler_0001"
CRAWLER_PRODUCER = "prod_legacy_crawler"

PIN = legacy.VersionPin(
    id="legacy.mapping.job-hunter",
    version="legacy-1",
    artifact_digest="sha256:" + "b" * 64,
)

JOBS_BASE = {
    "track": "backend",
    "company": "Acme Corp",
    "title": "Senior Engineer",
    "location": "Remote",
    "sourceUrl": "https://acme.example/jobs/alpha",
    "directApplyUrl": "https://acme.example/apply/alpha",
    "portalType": "greenhouse",
    "rawDescription": "Build the alpha platform.",
    "status": "OPEN",
    "closingDate": "2026-01-31",
}

DOCS = {
    "jobs": dict(JOBS_BASE, jobId="job_legacy_1"),
    "evaluations": {
        "evaluationId": "evaluation_legacy_1",
        "jobId": "job_legacy_1",
        "goNoGo": "GO",
        "suitabilityScore": "82/100",
        "desirabilityRank": "2",
        "scoreBreakdownNotes": "Strong backend fit.",
        "vetoReason": "none",
    },
    "artifacts": {
        "artifactId": "artifact_legacy_1",
        "jobId": "job_legacy_1",
        "functionalTitle": "Backend Engineer Package",
        "resumeJson": {"sections": ["experience", "education"]},
        "coverLetter": "Dear Acme, I build reliable services.",
        "supplementalResponses": [{"question": "Sponsorship?", "answer": "No"}],
        "fabricationLog": [{"issue": "none", "resolution": "not needed"}],
    },
    "trackers": {
        "trackerId": "tracker_legacy_1",
        "jobId": "job_legacy_1",
        "status": "AWAITING_RESPONSE_V2",
        "submissionMode": "assisted_auto",
        "dateApplied": "2026-02-03",
        "targetSalarySubmitted": "$120k + equity",
        "cheatSheetGenerated": False,
    },
    "emails": {
        "emailId": "email_legacy_1",
        "threadId": "thread_legacy_1",
        "category": "application_update",
        "companyName": "Acme Corp",
        "jobTitle": "Senior Engineer",
        "actionRequired": "respond",
        "summary": "Recruiter asked for availability.",
    },
    "schedules": {
        "eventId": "provider_event_legacy_1",
        "jobId": "job_legacy_1",
        "startTime": "2026-03-01 09:00",
        "endTime": "2026-03-01 09:45",
        "calendarId": "primary",
        "cheatSheetUrl": "https://resolver.example/sheet/1",
    },
    "settings": {
        "userId": "user_local_1",
        "references": [{"name": "Ref One", "relationship": "manager"}],
        "costLimits": {"monthlyUsd": 40},
        "notificationPrefs": {"email": True},
        "addressOverrides": {"zone": "America/Los_Angeles", "anchor": "home"},
    },
    "vault": {
        "key": "vault:provider-key-1",
        "ciphertext": "ciphertext-bytes-marker-DO-NOT-COPY",
        "iv": "iv-marker-DO-NOT-COPY",
        "tag": "tag-marker-DO-NOT-COPY",
    },
    "logs": {
        "agent": "legacy.runtime",
        "level": "INFO",
        "message": "worker heartbeat observed",
        "timestamp": "2026-02-01T10:00:00Z",
        "jobId": "job_legacy_1",
    },
    "costs": {
        "callId": "call_legacy_1",
        "model": "model-observed-1",
        "inputTokens": 1200,
        "outputTokens": 300,
        "costUsd": 0.42,
        "timestamp": "2026-02-01",
    },
    "tasks": {
        "taskId": "task_legacy_1",
        "service": "legacy-worker",
        "handler": "process_job",
        "status": "SUCCEEDED_V2",
        "payload": {"jobId": "job_legacy_1"},
        "result": {"accepted": True},
    },
    "noGoList": {
        "jobId": "job_legacy_nogo_1",
        "title": "Staff Engineer",
        "company": "Acme Corp",
        "reason": "on-call load",
        "hashedKey": "legacy-hash-equal",
    },
}

VAULT_MARKERS = (
    b"ciphertext-bytes-marker",
    b"iv-marker",
    b"tag-marker",
)


@pytest.fixture(autouse=True)
def _fresh_state():
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()


# ---------------------------------------------------------------------------
# Fixture plumbing
# ---------------------------------------------------------------------------


def _retain_bytes(payload: bytes) -> store.ArtifactReference:
    return store.retain_artifact(
        CHANNEL, OWNER, "application/json", payload, "restricted"
    )


def _manifest(
    task: store.ArtifactReference,
    config: store.ArtifactReference,
    sequence_required: bool,
) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_legacy_import_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_conformance",
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
        task_semantic_hash="sha256:" + "a" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=[
            {
                "event_kind": legacy.IMPORT_EVENT_KIND,
                "event_schema_version": legacy.IMPORT_EVENT_SCHEMA_VERSION,
                "role": legacy.IMPORT_EVENT_ROLE,
                "assertion_kind": legacy.IMPORT_ASSERTION_KIND,
                "owner_domain": OWNER,
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": sequence_required,
                "allowed_event_kinds": [legacy.IMPORT_EVENT_KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_legacy_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup(sequence_required: bool = True) -> None:
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=sequence_required,
        allowed_event_kinds=(legacy.IMPORT_EVENT_KIND,),
    )
    ap.register_event_kind(
        legacy.IMPORT_EVENT_KIND,
        legacy.IMPORT_EVENT_SCHEMA_VERSION,
        role=legacy.IMPORT_EVENT_ROLE,
        assertion_kind=legacy.IMPORT_ASSERTION_KIND,
        owner_domain=OWNER,
        writer_roles=("kernel",),
    )
    task = _retain_bytes(b'{"fixture":"task"}')
    config = _retain_bytes(b'{"fixture":"config"}')
    ev.admit_manifest(CHANNEL, _manifest(task, config, sequence_required))


def _import_doc(collection: str, document: dict):
    raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
    source = store.retain_artifact(
        CHANNEL, OWNER, "application/json", raw, "restricted"
    )
    reference = legacy.import_legacy_document(CHANNEL, collection, source, PIN)
    return reference, source, raw


def _decode(reference: store.ArtifactReference) -> dict:
    return json.loads(store.resolve_artifact(CHANNEL, reference))


def _projection(reference: store.ArtifactReference) -> dict:
    return _decode(reference)["timing"]


def _events() -> tuple:
    return ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))


def _is_missing(value) -> bool:
    return (
        isinstance(value, dict)
        and "value" in value
        and value["value"] is None
        and "reason" in value
    )


def _codes(projection: dict) -> set:
    return {(issue["code"], issue.get("legacy_field")) for issue in projection["issues"]}


# ---------------------------------------------------------------------------
# Assertion: company/title collision never automatically merges identities
# ---------------------------------------------------------------------------


def test_legacy_company_title_collision_never_automatically_merges_identities():
    _setup()
    alpha = dict(JOBS_BASE, jobId="job_legacy_alpha")
    beta = dict(
        JOBS_BASE,
        jobId="job_legacy_beta",
        sourceUrl="https://acme.example/jobs/beta",
        directApplyUrl="https://acme.example/apply/beta",
    )
    ref_alpha, _source_alpha, _raw_alpha = _import_doc("jobs", alpha)
    ref_beta, _source_beta, _raw_beta = _import_doc("jobs", beta)

    # Identical company/title/location never collapse two legacy identities.
    assert ref_alpha.digest != ref_beta.digest
    record_alpha = _decode(ref_alpha)
    record_beta = _decode(ref_beta)
    assert record_alpha["id"] == "jobs:job_legacy_alpha"
    assert record_beta["id"] == "jobs:job_legacy_beta"
    assert record_alpha["id"] != record_beta["id"]
    projection_alpha = record_alpha["timing"]
    projection_beta = record_beta["timing"]

    assert (
        projection_alpha["fields"]["job.crawler.content.employer"]["value"]
        == "Acme Corp"
        == projection_beta["fields"]["job.crawler.content.employer"]["value"]
    )
    assert (
        projection_alpha["fields"]["job.crawler.content.title"]["value"]
        == "Senior Engineer"
        == projection_beta["fields"]["job.crawler.content.title"]["value"]
    )
    assert (
        projection_alpha["fields"]["job.crawler.content.location"]["value"]
        == "Remote"
        == projection_beta["fields"]["job.crawler.content.location"]["value"]
    )
    assert projection_alpha["legacy_identity"]["value"] == "job_legacy_alpha"
    assert projection_beta["legacy_identity"]["value"] == "job_legacy_beta"

    # The documented legacy formula is recorded as a non-authoritative hint and
    # is never recomputed: its encoding/normalization is not supplied.
    for projection in (projection_alpha, projection_beta):
        hint = projection["collision_hint"]
        assert hint["formula"] == "sha256(companyName|jobTitle|locationRaw)"
        assert hint["authority"] == "duplicate_candidate_hint_only"
        assert hint["may_merge_identities"] is False
        assert hint["recomputed"] is False
        assert hint["inputs_present"] == ["company", "title", "location"]
        assert hint["hashed_key"]["reason"] == "not_observed"
        assert hint["hashed_key"]["value"] is None
        rules = projection["identity_rules"]
        assert rules["derived_from"] == "legacy_identity_field"
        assert rules["automatic_merge"] is False
        assert rules["collision_hint_authority"] == "duplicate_candidate_hint_only"

    # A legacy import never fabricates a crawler source root.
    assert projection_alpha["legacy_identity"]["source_root"]["reason"] == "not_observed"
    assert projection_beta["legacy_identity"]["source_root"]["reason"] == "not_observed"
    assert (
        projection_alpha["fields"]["acquisition.source_url"]["value"]
        == "https://acme.example/jobs/alpha"
    )
    assert (
        projection_beta["fields"]["acquisition.source_url"]["value"]
        == "https://acme.example/jobs/beta"
    )

    # A stored legacy duplicate hash is preserved verbatim and still cannot
    # merge two different portfolio identities.
    nogo_alpha = {
        "jobId": "job_legacy_alpha",
        "title": "Senior Engineer",
        "company": "Acme Corp",
        "reason": "compensation band",
        "hashedKey": "legacy-hash-equal",
    }
    nogo_beta = {
        "jobId": "job_legacy_beta",
        "title": "Senior Engineer",
        "company": "Acme Corp",
        "reason": "commute",
        "hashedKey": "legacy-hash-equal",
    }
    nref_alpha, _n_source_alpha, _n_raw_alpha = _import_doc("noGoList", nogo_alpha)
    nref_beta, _n_source_beta, _n_raw_beta = _import_doc("noGoList", nogo_beta)
    assert nref_alpha.digest != nref_beta.digest
    nogo_record_alpha = _decode(nref_alpha)
    nogo_record_beta = _decode(nref_beta)
    assert nogo_record_alpha["id"] == "noGoList:job_legacy_alpha"
    assert nogo_record_beta["id"] == "noGoList:job_legacy_beta"
    for record, identity in (
        (nogo_record_alpha, "job_legacy_alpha"),
        (nogo_record_beta, "job_legacy_beta"),
    ):
        projection = record["timing"]
        hint = projection["collision_hint"]
        assert projection["legacy_identity"]["value"] == identity
        assert hint["hashed_key"] == "legacy-hash-equal"
        assert hint["formula"] == "companyName|jobTitle"
        assert hint["authority"] == "duplicate_candidate_hint_only"
        assert hint["may_merge_identities"] is False
        assert hint["recomputed"] is False

    # Identical bytes converge on one content address; different documents are
    # never merged into a shared identity.
    ref_alpha_again, _s, _r = _import_doc("jobs", alpha)
    assert ref_alpha_again.digest == ref_alpha.digest
    assert _decode(ref_alpha_again) == record_alpha

    # A document missing its identity field never falls back to company/title
    # similarity: the identity stays Missing(not_observed).
    anonymous = dict(JOBS_BASE, title="Unlisted Role")
    anonymous_ref, _a_source, _a_raw = _import_doc("jobs", anonymous)
    anonymous_record = _decode(anonymous_ref)
    anonymous_projection = anonymous_record["timing"]
    assert anonymous_record["id"].startswith("jobs:unidentified:")
    assert anonymous_projection["legacy_identity"]["value"]["reason"] == "not_observed"
    assert ("missing_legacy_identity", "jobId") in _codes(anonymous_projection)

    # Each import is its own journaled event; no event claims a merged identity
    # and nothing is promoted into a current-run observation.
    import_events = [
        event for event in _events() if event.event_kind == legacy.IMPORT_EVENT_KIND
    ]
    assert len(import_events) == 6
    cited: set[str] = set()
    for event in import_events:
        assert event.payload["data"]["private_projection"] is True
        assert event.payload["data"]["document_scope"] == "historical_legacy_import"
        assert event.payload["data"]["promoted_to_current_run"] is False
        cited.update(entry["digest"] for entry in event.payload["artifact_refs"])
    for reference in (ref_alpha, ref_beta, nref_alpha, nref_beta):
        assert reference.digest in cited

    # No merge surface is exposed at all.
    assert "import_legacy_document" in legacy.__all__
    assert not any("merge" in name.lower() for name in legacy.__all__)
    assert not hasattr(legacy, "merge_identities")
    assert not hasattr(legacy, "merge_documents")


# ---------------------------------------------------------------------------
# Assertion: unknown status/type preserves source and requires a mapping
# ---------------------------------------------------------------------------


def test_legacy_unknown_status_or_type_preserves_source_and_requires_mapping():
    # The declared interface exposes no sequence allocator: a channel registered
    # without a sequence requirement is the honest path for historical imports.
    _setup(sequence_required=False)
    tracker = dict(
        DOCS["trackers"], mysteryField={"nested": [1, None]}
    )
    tracker_ref, tracker_source, tracker_raw = _import_doc("trackers", tracker)
    record = _decode(tracker_ref)
    projection = record["timing"]

    assert record["id"] == "trackers:tracker_legacy_1"
    assert projection["mapping_required"] is True
    codes = _codes(projection)

    # Unknown status vocabulary is preserved verbatim, marked uninterpreted,
    # and never mapped onto an executable state or a life axis.
    status = projection["fields"]["display.legacy_status"]
    assert status["value"] == "AWAITING_RESPONSE_V2"
    assert status["disposition"] == "preserved_legacy_text"
    assert status["mapping_required"] is True
    assert status["published_axis"]["reason"] == "not_applicable"
    assert [target for target in projection["fields"] if target.endswith("status")] == [
        "display.legacy_status"
    ]
    assert not any(
        target.startswith(("attempt.", "life.", "application."))
        for target in projection["fields"]
    )
    assert ("unknown_legacy_enum", "status") in codes

    # Typed semantics without original types stay unresolved legacy values.
    salary = projection["fields"]["legacy.target_salary_submitted"]
    assert salary["value"] == "$120k + equity"
    assert ("unresolved_original_type", "targetSalarySubmitted") in codes
    assert ("evidence_required", "dateApplied") in codes

    # The raw source bytes are untouched and cited.
    assert store.resolve_artifact(CHANNEL, tracker_source) == tracker_raw
    assert projection["source_artifact"]["digest"] == tracker_source.digest
    assert projection["source_artifact"]["access"] == "restricted"

    # false and zero are known values, never missing-value sentinels.
    generated = projection["fields"]["legacy.cheat_sheet_generated"]
    assert generated["value"] is False
    assert not _is_missing(generated["value"])

    # Unmapped legacy fields are preserved (with nulls becoming typed Missing)
    # and require an explicit mapping.
    unmapped = projection["unmapped_fields"]["mysteryField"]
    assert unmapped["nested"][0] == 1
    assert unmapped["nested"][1]["reason"] == "not_observed"
    assert ("unmapped_legacy_field", "mysteryField") in codes

    # An absent semantic field is Missing(not_observed) plus a migration issue,
    # never a default or inferred score.
    evaluation = {
        "evaluationId": "evaluation_legacy_1",
        "jobId": "job_legacy_1",
        "goNoGo": "GO",
        "scoreBreakdownNotes": "Strong backend fit.",
    }
    evaluation_ref, _e_source, _e_raw = _import_doc("evaluations", evaluation)
    evaluation_projection = _projection(evaluation_ref)
    score = evaluation_projection["fields"]["evaluation.score"]
    assert _is_missing(score["value"])
    assert score["value"]["reason"] == "not_observed"
    assert score["mapping_required"] is False
    assert ("missing_legacy_field", "suitabilityScore") in _codes(evaluation_projection)

    # An original type that cannot be recovered is preserved verbatim and
    # flagged, not coerced into a number.
    typed_evaluation = dict(
        evaluation, evaluationId="evaluation_legacy_2", suitabilityScore="82/100"
    )
    typed_ref, _t_source, _t_raw = _import_doc("evaluations", typed_evaluation)
    typed_projection = _projection(typed_ref)
    typed_score = typed_projection["fields"]["evaluation.score"]
    assert typed_score["value"] == "82/100"
    assert typed_score["disposition"] == "preserved_legacy_value"
    assert typed_score["mapping_required"] is True
    assert ("unresolved_original_type", "suitabilityScore") in _codes(typed_projection)

    # A calendar string without stated timezone semantics is never parsed into
    # a typed instant.
    schedule_ref, _s_source, _s_raw = _import_doc("schedules", DOCS["schedules"])
    schedule_projection = _projection(schedule_ref)
    start = schedule_projection["fields"]["calendar.start_time"]
    assert start["value"] == "2026-03-01 09:00"
    assert start["mapping_required"] is True
    assert "typed_start_time" not in schedule_projection["fields"]
    assert ("unresolved_original_type", "startTime") in _codes(schedule_projection)

    # Zero usage is measured content; an explicit source null is a typed
    # Missing with an issue, and the normalized record carries no bare null.
    costs = {
        "callId": "call_legacy_1",
        "model": "model-observed-1",
        "inputTokens": 0,
        "outputTokens": 0,
        "costUsd": None,
        "timestamp": "2026-02-01",
    }
    costs_ref, _c_source, _c_raw = _import_doc("costs", costs)
    costs_projection = _projection(costs_ref)
    assert costs_projection["fields"]["usage.input_tokens"]["value"] == 0
    assert costs_projection["fields"]["usage.output_tokens"]["value"] == 0
    assert not _is_missing(costs_projection["fields"]["usage.input_tokens"]["value"])
    cost = costs_projection["fields"]["usage.cost_usd"]
    assert _is_missing(cost["value"])
    assert cost["value"]["reason"] == "not_observed"
    assert any(
        issue["code"] == "explicit_null_value" and issue.get("path") == "costUsd"
        for issue in costs_projection["issues"]
    )

    # Every projection is already canonical and passes the strict codec gate
    # (bare nulls, duplicate keys, and malformed Missing envelopes rejected).
    for reference in (tracker_ref, evaluation_ref, typed_ref, schedule_ref, costs_ref):
        body = store.resolve_artifact(CHANNEL, reference)
        assert contract_codec.validate_record(body, legacy.RECORD_SCHEMA_ID) == body

    # An unsequenced producer journals typed Missing instead of a fabricated
    # sequence; the import is still evidenced.
    import_events = [
        event for event in _events() if event.event_kind == legacy.IMPORT_EVENT_KIND
    ]
    assert len(import_events) == 5
    for event in import_events:
        sequence = event.to_dict()["producer_sequence"]
        assert sequence["value"] is None
        assert sequence["reason"] == "not_applicable"


# ---------------------------------------------------------------------------
# Assertion: all twelve adapters stay private and evidenced
# ---------------------------------------------------------------------------


def test_all_twelve_legacy_collection_adapters_remain_private_and_evidenced():
    _setup()
    assert len(legacy.LEGACY_COLLECTIONS) == 12
    assert set(legacy.COLLECTION_ADAPTERS) == set(legacy.LEGACY_COLLECTIONS)
    assert set(DOCS) == set(legacy.LEGACY_COLLECTIONS)

    projections: dict[str, store.ArtifactReference] = {}
    sources: dict[str, store.ArtifactReference] = {}
    for collection in legacy.LEGACY_COLLECTIONS:
        adapter = legacy.COLLECTION_ADAPTERS[collection]
        assert adapter.collection == collection
        assert adapter.private is True
        assert adapter.shared_contract is False

        reference, source, _raw = _import_doc(collection, DOCS[collection])
        projections[collection] = reference
        sources[collection] = source

        assert reference.access == "restricted"
        assert reference.owner_domain == legacy.PRIVATE_OWNER_DOMAIN
        assert reference.media_type == "application/json"
        body = store.resolve_artifact(CHANNEL, reference)
        assert contract_codec.validate_record(body, legacy.RECORD_SCHEMA_ID) == body
        record = json.loads(body)
        projection = record["timing"]
        assert record["id"].startswith(collection + ":")
        assert projection["collection"] == collection
        assert projection["private"] is True
        assert projection["rebuildable"] is True
        assert projection["authority"] == "private_projection"
        assert projection["shared_contract"] is False
        assert projection["observation_scope"] == "historical_preserved_source"
        assert projection["promoted_to_current_run"] is False
        assert projection["adapter"] == PIN.to_dict()
        assert projection["source_artifact"]["digest"] == source.digest
        for entry in projection["fields"].values():
            assert entry["published_axis"]["reason"] == "not_applicable"

    # One journaled import event per collection, each citing its artifacts.
    import_events = [
        event for event in _events() if event.event_kind == legacy.IMPORT_EVENT_KIND
    ]
    assert len(import_events) == 12
    cited: set[str] = set()
    seen_collections: set[str] = set()
    for event in import_events:
        assert event.owner_domain == OWNER
        assert event.provenance == "server"
        assert event.role == legacy.IMPORT_EVENT_ROLE
        assert event.assertion_kind == legacy.IMPORT_ASSERTION_KIND
        data = event.payload["data"]
        assert data["collection"] in legacy.LEGACY_COLLECTIONS
        assert data["private_projection"] is True
        assert data["document_scope"] == "historical_legacy_import"
        assert data["promoted_to_current_run"] is False
        assert data["adapter"] == PIN.to_dict()
        assert len(event.payload["artifact_refs"]) >= 2
        for entry in event.payload["artifact_refs"]:
            assert entry["access"] == "restricted"
            assert entry["owner_domain"] == OWNER
        seen_collections.add(data["collection"])
        cited.update(entry["digest"] for entry in event.payload["artifact_refs"])
    assert seen_collections == set(legacy.LEGACY_COLLECTIONS)
    assert {reference.digest for reference in projections.values()} <= cited
    assert {reference.digest for reference in sources.values()} <= cited
    assert len({reference.digest for reference in projections.values()}) == 12
    # The only journaled writes are the manifest admission and the imports: no
    # other owner axis is written by a legacy import.
    assert {event.event_kind for event in _events()} == {
        "manifest_admitted",
        legacy.IMPORT_EVENT_KIND,
    }

    # Vault: secret bytes never reach an ordinary import artifact or any
    # artifact retained by the import itself.
    vault_body = store.resolve_artifact(CHANNEL, projections["vault"])
    for marker in VAULT_MARKERS:
        assert marker not in vault_body
    vault_projection = json.loads(vault_body)["timing"]
    for target in ("secret.ciphertext", "secret.iv", "secret.tag"):
        entry = vault_projection["fields"][target]
        assert entry["value"]["reason"] == "not_applicable"
        assert "retained_artifact" not in entry
    assert vault_projection["legacy_identity"]["value"] == "vault:provider-key-1"
    assert any(
        issue["code"] == "secret_material_redacted"
        for issue in vault_projection["issues"]
    )
    vault_event = next(
        event
        for event in import_events
        if event.payload["data"]["collection"] == "vault"
    )
    vault_source_digest = sources["vault"].digest
    cited_import_digests = set()
    for entry in vault_event.payload["artifact_refs"]:
        if entry["digest"] == vault_source_digest:
            continue
        cited_import_digests.add(entry["digest"])
        resolved = store.resolve_artifact(
            CHANNEL, store.ArtifactReference.from_dict(entry)
        )
        for marker in VAULT_MARKERS:
            assert marker not in resolved
    assert cited_import_digests == {projections["vault"].digest}

    # Unknown collections are rejected rather than guessed; a public artifact
    # is never an importable legacy source; a restricted artifact is readable
    # only inside its owner domain.
    jobs_source = sources["jobs"]
    with pytest.raises(legacy.UnknownLegacyCollectionError):
        legacy.import_legacy_document(CHANNEL, "jobHistory", jobs_source, PIN)
    public_source = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"jobId":"job_public"}', "public"
    )
    with pytest.raises(legacy.LegacySourceError):
        legacy.import_legacy_document(CHANNEL, "jobs", public_source, PIN)
    with pytest.raises(legacy.LegacyMappingError):
        legacy.import_legacy_document(
            CHANNEL, "jobs", jobs_source, {"id": "mapping", "version": "1"}
        )
    broken_source = store.retain_artifact(
        CHANNEL, OWNER, "application/octet-stream", b"not-json", "restricted"
    )
    with pytest.raises(legacy.LegacySourceError):
        legacy.import_legacy_document(CHANNEL, "jobs", broken_source, PIN)
    with pytest.raises(legacy.LegacyAuthorityError):
        legacy.import_legacy_document(
            "ch_unregistered_legacy", "jobs", jobs_source, PIN
        )

    ap.register_channel(
        actor="crawler_writer",
        channel_id=CRAWLER_CHANNEL,
        axis="job.crawler",
        producer_id=CRAWLER_PRODUCER,
        principal_id="principal_legacy_crawler",
        sequence_required=False,
        allowed_event_kinds=("crawler.extracted",),
    )
    foreign_source = store.retain_artifact(
        CRAWLER_CHANNEL,
        "job.crawler",
        "application/json",
        b'{"jobId":"job_foreign"}',
        "restricted",
    )
    with pytest.raises(legacy.LegacySourceError):
        legacy.import_legacy_document(CHANNEL, "jobs", foreign_source, PIN)

    # The module exposes imports only: no publish/merge surface.
    assert "import_legacy_document" in legacy.__all__
    assert not any(
        name.startswith(("publish", "write_", "merge")) for name in legacy.__all__
    )
