"""Conformance tests for material_generation (tier 5).

Covers seam mapping section 9 (Materials and factual integrity):

* unsupported_material_claim_blocks_affected_automatic_submission
* actual_submitted_material_versions_do_not_rewrite_initial_commission_materials
"""

from __future__ import annotations

import asyncio
import dataclasses
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
        path = (
            here.parents[1] / rel
            if name == "material_generation"
            else here.parents[2] / rel
        )
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ap = _load("access_policy", Path("access_policy/src/__init__.py"))
cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
store = _load("artifact_store", Path("artifact_store/src/__init__.py"))
ev = _load("evidence_journal", Path("evidence_journal/src/__init__.py"))
ci = _load("candidate_inputs", Path("candidate_inputs/src/__init__.py"))
mgw = _load("model_gateway", Path("model_gateway/src/__init__.py"))
mg = _load("material_generation", Path("src/__init__.py"))

CHANNEL = "ch_material_generation_0001"
PRODUCER = "prod_material_generation"
PRINCIPAL = "principal_material_generation"
OWNER = "job.downstream"
JOURNAL = "journal_material_generation_0001"
RUN = "run_material_generation_0001"
CLOCK_ID = "clock_material_engine"
BOOT_ID = "boot_material_engine"
SOURCE_KIND = "product.published"
SOURCE_VERSION = "1"


@pytest.fixture(autouse=True)
def _fresh_state():
    for mod in (ap, store, ev, mgw, mg):
        reset = getattr(mod, "reset_for_tests", None)
        if callable(reset):
            reset()
    yield
    for mod in (ap, store, ev, mgw, mg):
        reset = getattr(mod, "reset_for_tests", None)
        if callable(reset):
            reset()


# ---------------------------------------------------------------------------
# Fixture composition: channel, journal, profile inputs
# ---------------------------------------------------------------------------


def _retain_json(obj, media_type="application/json", access="restricted"):
    content = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return store.retain_artifact(CHANNEL, OWNER, media_type, content, access)


def _manifest(task, config) -> ev.Manifest:
    registry = [
        {
            "event_kind": SOURCE_KIND,
            "event_schema_version": SOURCE_VERSION,
            "role": "derived_output",
            "assertion_kind": "authoritative_effect",
            "owner_domain": OWNER,
            "writer_roles": ["kernel"],
        }
    ]
    registry.extend(mg.event_kind_declarations(OWNER))
    return ev.Manifest(
        manifest_id="manifest_material_generation_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_material_generation",
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
        task_semantic_hash="sha256:" + "b" * 64,
        effective_configuration=config,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {"id": "build_task", "version": "1", "artifact_digest": task.digest}
        ],
        event_registry=registry,
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": PRINCIPAL,
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": False,
                "allowed_event_kinds": [
                    SOURCE_KIND,
                    mg.GENERATED_EVENT_KIND,
                    mg.SUBMITTED_EVENT_KIND,
                ],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_material_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup():
    ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id=PRINCIPAL,
        sequence_required=False,
        allowed_event_kinds=(
            SOURCE_KIND,
            mg.GENERATED_EVENT_KIND,
            mg.SUBMITTED_EVENT_KIND,
        ),
    )
    ap.register_event_kind(
        SOURCE_KIND,
        SOURCE_VERSION,
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain=OWNER,
        writer_roles=("kernel",),
    )
    for entry in mg.event_kind_declarations(OWNER):
        ap.register_event_kind(
            entry["event_kind"],
            entry["event_schema_version"],
            role=entry["role"],
            assertion_kind=entry["assertion_kind"],
            owner_domain=OWNER,
            writer_roles=tuple(entry["writer_roles"]),
        )
    task = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"task"}', "restricted"
    )
    config = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"config"}', "restricted"
    )
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    assert admission.journal_sequence == 1
    return admission


def _source_event(note: str) -> ev.EventSubmission:
    return ev.EventSubmission(
        producer_sequence=ev.NOT_APPLICABLE,
        event_kind=SOURCE_KIND,
        event_schema_version=SOURCE_VERSION,
        occurred_at=ev.TimePoint(
            clock_id=CLOCK_ID,
            boot_id=BOOT_ID,
            origin="engine_measured",
            monotonic_offset_ms=1000.0,
        ),
        payload=ev.EvidencePayload(
            data={"note": note},
            measurements=[],
            evidence_refs=[],
            artifact_refs=[],
        ),
    )


def _source_ref():
    first = ev.append_event(CHANNEL, OWNER, _source_event("source observed"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=first.journal_sequence,
        event_id=first.event_id,
        event_hash=first.event_hash,
        pointer="",
    )
    prefix = {
        "journal_id": JOURNAL,
        "last_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }
    return ref, prefix


def _catalog_dict() -> dict:
    specs = [
        ("pb01_structural_deconstruction",
         "Recursive Structural Deconstruction & Isomorphic Mapping",
         ["decompose systems", "identify invariants", "normalize mismatches"],
         ["complex system mismatch"], ["requires system access"]),
        ("pb02_human_asset_optimization",
         "Human Asset Optimization & Reverse-Pyramid Leadership",
         ["train", "coach", "remove obstacles", "delegate", "measure cohorts"],
         ["team performance gap"], ["requires cohort consent"]),
        ("pb03_compliance_automation",
         "Compliance-to-Automation Pipeline",
         ["interpret rules", "author SOPs", "automate checks", "remediate"],
         ["regulatory update"], ["requires legal review"]),
        ("pb04_field_triage",
         "High-Stakes De-escalation & Autonomous Field Triage",
         ["de-escalate", "apply policy", "preserve safety", "document"],
         ["field incident"], ["safety takes precedence"]),
        ("pb05_hardware_software_integration",
         "Cross-Domain Hardware/Software Integration",
         ["integrate hardware", "firmware", "sensors", "actuators", "software"],
         ["cross-domain build"], ["requires hardware access"]),
        ("pb06_cognitive_offloading",
         "Latency-Aware Cognitive Offloading",
         ["route local reasoning", "retrieve context", "preserve responsiveness"],
         ["latency budget exceeded"], ["requires connectivity plan"]),
        ("pb07_public_governance",
         "Public/Community Governance & Parliamentary Procedure",
         ["parliamentary procedure", "reporting", "consensus",
          "public presentation"],
         ["governance session"], ["requires quorum"]),
        ("pb08_campaign_engineering",
         "Data-Driven Campaign Engineering",
         ["BI", "demographic targeting", "conversion", "budget optimization"],
         ["campaign launch"], ["requires budget approval"]),
    ]
    return {
        "record_type": "playbook_catalog",
        "schema_version": "job-hunter-playbooks/0.1.0",
        "entries": [
            {
                "playbook_id": pid,
                "name": name,
                "primitive_actions": actions,
                "trigger_conditions": triggers,
                "limitations": limits,
                "source_refs": [f"inventory:{pid}:source", "corpus:doc-042"],
            }
            for pid, name, actions, triggers, limits in specs
        ],
    }


CLEAN_JOBS = [
    {"employer": "Alpha", "title": "Technician",
     "start": "2021-01", "end": "2021-12"},
    {"employer": "Beta", "title": "Senior Technician",
     "start": "2022-01", "end": "2023-03"},
]


def _profile_ref(history_obj, unresolved_items, ref, prefix, candidate_id="cand_0001"):
    history_ref = _retain_json(history_obj)
    capability_ref = _retain_json(
        {"analysis_kind": "analytical_interpretation",
         "note": "preliminary skills summary"}
    )
    source_doc_ref = _retain_json({"resume": "raw history text"})
    catalog_ref = _retain_json(_catalog_dict())
    disclosure_ref = _retain_json({"policy": "restricted", "version": "1"})
    profile = {
        "record_type": "candidate_profile_artifact",
        "schema_version": "job-hunter-candidate-profile/0.1.0",
        "candidate_id": candidate_id,
        "source_documents": [source_doc_ref.to_dict()],
        "source_evidence_refs": [ref.to_dict()],
        "employment_history": history_ref.to_dict(),
        "capability_profile": capability_ref.to_dict(),
        "playbook_catalog": {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": catalog_ref.digest,
        },
        "constraints": {"value": None, "reason": "not_observed"},
        "disclosure_policy": {
            "id": "disclosure_policy", "version": "1",
            "artifact_digest": disclosure_ref.digest,
        },
        "unresolved_items": unresolved_items,
        "evidence_prefix": prefix,
    }
    return _retain_json(profile)


def _policy_pin():
    policy_ref = _retain_json(
        {"id": "generation_policy", "version": "1", "disclosure": "restricted"}
    )
    return mg.VersionPin(
        id="generation_policy", version="1", artifact_digest=policy_ref.digest
    )


def _job_ref(portfolio_job_id, title, employer):
    return _retain_json(
        {
            "portfolio_job_id": portfolio_job_id,
            "title": title,
            "employer": employer,
            "description": f"Posted role: {title} at {employer}.",
            "location": "Onsite",
        }
    )


# ---------------------------------------------------------------------------
# Assertion 1: unresolved unsupported claims block automatic submission
# ---------------------------------------------------------------------------


def test_unsupported_material_claim_blocks_affected_automatic_submission() -> None:
    _setup()
    ref, prefix = _source_ref()
    history = {
        "jobs": [dict(job) for job in CLEAN_JOBS],
        "note": "candidate mentions PMP certification; "
                "independent verification pending",
    }
    items = [
        {
            "code": "credential_unverified",
            "detail": "Claimed PMP credential is not independently verified; "
                      "it must not appear as a held credential.",
            "affected_fields": ["capability_profile.credentials"],
            "evidence_refs": [ref.to_dict()],
        }
    ]
    profile_ref = _profile_ref(history, items, ref, prefix)
    loaded = ci.load_candidate_profile(CHANNEL, profile_ref)
    assert [item.code for item in loaded.unresolved_items] == [
        "credential_unverified"
    ]

    job_ref = _job_ref("portfolio_job_0001", "Systems Integrator", "Acme Transit")
    policy_pin = _policy_pin()
    package = asyncio.run(
        mg.generate_materials(
            CHANNEL, profile_ref, job_ref,
            {"value": None, "reason": "not_observed"}, policy_pin,
        )
    )

    assert package.record_type == "job_hunter_material_package"
    assert package.schema_version == "job-hunter-material/0.1.0"
    assert package.portfolio_job_id == "portfolio_job_0001"

    # The fabrication log records the integrity issue without resolving it.
    kinds = [(issue.kind, issue.resolution) for issue in package.fabrication_log]
    assert ("unsupported_claim", "unresolved") in kinds

    # The affected automatic submission is blocked; the log is not a license.
    assert mg.automatic_submission_allowed(package) is False
    assert len(mg.submission_blockers(package)) >= 1
    with pytest.raises(mg.MaterialBlockedError):
        mg.assert_automatic_submission_allowed(package)
    # The manual lane may still proceed under operator review.
    assert mg.submission_allowed(package, "manual") is True
    assert mg.submission_allowed(package, "automatic") is False

    # Fabrication log does not authorize fabrication: the unverified
    # credential appears nowhere in the generated bytes.
    resume_bytes = store.resolve_artifact(CHANNEL, package.resume_json)
    cover_bytes = store.resolve_artifact(CHANNEL, package.cover_letter)
    assert b"PMP" not in resume_bytes
    assert b"PMP" not in cover_bytes

    # A functional title never replaces the actual requested title.
    assert mg.is_missing(package.functional_title)
    resume_obj = json.loads(resume_bytes.decode("utf-8"))
    assert resume_obj["job_title"] == "Systems Integrator"
    assert resume_obj["job_employer"] == "Acme Transit"

    # Supported facts flow through with nonempty support and rationale.
    assert b"Alpha" in resume_bytes
    assert len(package.claim_support) >= 1
    for claim in package.claim_support:
        assert len(claim.source_refs) >= 1
        assert claim.transformation_rationale != ""

    # Evidence refs are nonempty and cite the generation event.
    assert len(package.evidence_refs) >= 1
    gen_ref = package.evidence_refs[0]
    events = ev.read_prefix(CHANNEL, ev.journal_head(CHANNEL, JOURNAL))
    cited = [e for e in events if e.event_id == gen_ref.event_id]
    assert len(cited) == 1
    assert cited[0].event_kind == mg.GENERATED_EVENT_KIND

    # A clean profile generates submittable materials on the same job.
    clean_history = {
        "jobs": [dict(job) for job in CLEAN_JOBS],
        "note": "verified employment intervals",
    }
    clean_profile_ref = _profile_ref(clean_history, [], ref, prefix)
    clean_package = asyncio.run(
        mg.generate_materials(
            CHANNEL, clean_profile_ref, job_ref,
            {"value": None, "reason": "not_observed"}, policy_pin,
        )
    )
    assert mg.automatic_submission_allowed(clean_package) is True
    mg.assert_automatic_submission_allowed(clean_package)
    assert clean_package.artifact_id != package.artifact_id


# ---------------------------------------------------------------------------
# Assertion 2: submitted versions never rewrite commission initial materials
# ---------------------------------------------------------------------------


def test_actual_submitted_material_versions_do_not_rewrite_initial_commission_materials() -> None:
    _setup()
    ref, prefix = _source_ref()
    history = {
        "jobs": [dict(job) for job in CLEAN_JOBS],
        "note": "verified employment intervals",
    }
    profile_ref = _profile_ref(history, [], ref, prefix)
    job_a = _job_ref("portfolio_job_A", "Systems Integrator", "Acme Transit")
    job_b = _job_ref("portfolio_job_B", "Field Coordinator", "Beta Mobility")
    policy_pin = _policy_pin()
    evaluation_ref = _retain_json(
        {"evaluation_id": "eval_0001", "recommended_selection": "go"}
    )

    v1 = asyncio.run(
        mg.generate_materials(CHANNEL, profile_ref, job_a, evaluation_ref, policy_pin)
    )
    assert not mg.is_missing(v1.evaluation)
    assert v1.evaluation.digest == evaluation_ref.digest

    # The commission freezes its initial materials: snapshot bytes + digest.
    initial_resume_ref = v1.resume_json
    initial_resume_bytes = store.resolve_artifact(CHANNEL, initial_resume_ref)
    initial_digest = initial_resume_ref.digest
    initial_cover_bytes = store.resolve_artifact(CHANNEL, v1.cover_letter)
    v1_snapshot = v1.to_dict()
    assert mg.MaterialPackage.from_dict(v1_snapshot).to_dict() == v1_snapshot

    # Later materials are new immutable artifacts, never a rewrite of v1.
    v2 = asyncio.run(
        mg.generate_materials(CHANNEL, profile_ref, job_b, evaluation_ref, policy_pin)
    )
    assert v2.artifact_id != v1.artifact_id
    assert v2.portfolio_job_id == "portfolio_job_B"
    assert v2.resume_json.digest != initial_digest
    assert store.resolve_artifact(CHANNEL, initial_resume_ref) == initial_resume_bytes
    assert store.resolve_artifact(CHANNEL, v1.cover_letter) == initial_cover_bytes
    assert v1.to_dict() == v1_snapshot

    # Packages are immutable records.
    with pytest.raises(dataclasses.FrozenInstanceError):
        v1.artifact_id = "mat_tampered"

    # Actual submitted bytes are separately journaled as attempt evidence.
    submission = ev.EventSubmission(
        producer_sequence=ev.NOT_APPLICABLE,
        event_kind=mg.SUBMITTED_EVENT_KIND,
        event_schema_version="1",
        occurred_at=ev.NOT_OBSERVED,
        payload=ev.EvidencePayload(
            data={
                "record": mg.SUBMITTED_EVENT_KIND,
                "artifact_id": v1.artifact_id,
                "submitted_resume_digest": initial_digest,
                "note": "actual submitted bytes; "
                        "commission initial_materials unchanged",
            },
            measurements=(),
            evidence_refs=(),
            artifact_refs=(initial_resume_ref,),
        ),
    )
    sub_envelope = ev.append_event(CHANNEL, OWNER, submission)
    assert sub_envelope.journal_sequence > v1.evidence_refs[0].sequence

    # Initial materials remain intact after submission journaling.
    assert store.resolve_artifact(CHANNEL, initial_resume_ref) == initial_resume_bytes
    assert v1.resume_json.digest == initial_digest
    assert v1.to_dict() == v1_snapshot

    # Generation and submission are distinct journaled events.
    head_now = ev.journal_head(CHANNEL, JOURNAL)
    kinds = [e.event_kind for e in ev.read_prefix(CHANNEL, head_now)]
    assert kinds.count(mg.GENERATED_EVENT_KIND) == 2
    assert kinds.count(mg.SUBMITTED_EVENT_KIND) == 1

    # An idempotent repeat returns the identical package without a new event.
    v1_again = asyncio.run(
        mg.generate_materials(CHANNEL, profile_ref, job_a, evaluation_ref, policy_pin)
    )
    assert v1_again.to_dict() == v1_snapshot
    assert ev.journal_head(CHANNEL, JOURNAL).last_sequence == head_now.last_sequence
