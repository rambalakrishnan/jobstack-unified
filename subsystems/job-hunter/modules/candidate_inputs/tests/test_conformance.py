"""Conformance tests for candidate_inputs (tier 3).

Covers exactly the ``-k`` filter named in the module spec:

- ``ambiguous_candidate_salary_units_remain_unresolved_without_conversion``
- ``all_eight_playbooks_preserve_sources_without_becoming_executor_capabilities``
- ``candidate_credentials_and_disclosure_permissions_are_never_inferred_from_analysis``

Every check exercises the real module with real siblings: authenticated
channels, retained artifacts, admitted journals, and verified prefixes.
"""

from __future__ import annotations

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
        path = here.parents[1] / rel if name == "candidate_inputs" else here.parents[2] / rel
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
ci = _load("candidate_inputs", Path("src/__init__.py"))

CHANNEL = "ch_candidate_inputs_product_0001"
PRODUCER = "prod_candidate_inputs_product"
OWNER = "job.downstream"
JOURNAL = "journal_candidate_inputs_0001"
RUN = "run_candidate_inputs_0001"
KIND = "product.published"
KIND_VERSION = "1"
CLOCK_ID = "clock_candidate_inputs_engine"
BOOT_ID = "boot_candidate_inputs_engine"

EXPECTED_PROFILE_KEYS = frozenset({
    "record_type",
    "schema_version",
    "candidate_id",
    "source_documents",
    "source_evidence_refs",
    "employment_history",
    "capability_profile",
    "playbook_catalog",
    "constraints",
    "disclosure_policy",
    "unresolved_items",
    "evidence_prefix",
})
EXPECTED_ENTRY_KEYS = frozenset({
    "playbook_id",
    "name",
    "primitive_actions",
    "trigger_conditions",
    "limitations",
    "source_refs",
})
EXPECTED_PLAYBOOK_IDS = (
    "pb01_structural_deconstruction",
    "pb02_human_asset_optimization",
    "pb03_compliance_automation",
    "pb04_field_triage",
    "pb05_hardware_software_integration",
    "pb06_cognitive_offloading",
    "pb07_public_governance",
    "pb08_campaign_engineering",
)


@pytest.fixture(autouse=True)
def _fresh_state():
    ci_missing = False
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()


def _register_writer():
    return ap.register_channel(
        actor="product_writer",
        channel_id=CHANNEL,
        axis=OWNER,
        producer_id=PRODUCER,
        principal_id="principal_candidate_inputs_product",
        sequence_required=True,
        allowed_event_kinds=(KIND,),
    )


def _register_event_kind() -> None:
    ap.register_event_kind(
        KIND,
        KIND_VERSION,
        role="derived_output",
        assertion_kind="authoritative_effect",
        owner_domain=OWNER,
        writer_roles=("kernel",),
    )


def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _retain_json(name: str, obj) -> store.ArtifactReference:
    del name
    return store.retain_artifact(
        CHANNEL, OWNER, "application/json", _canonical(obj), "restricted"
    )


def _manifest(task, config) -> ev.Manifest:
    return ev.Manifest(
        manifest_id="manifest_candidate_inputs_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_candidate_inputs",
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
        event_registry=[
            {
                "event_kind": KIND,
                "event_schema_version": KIND_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "owner_domain": OWNER,
                "writer_roles": ["kernel"],
            }
        ],
        producers=[
            {
                "producer_id": PRODUCER,
                "principal_id": "principal_candidate_inputs_product",
                "owner_domain": OWNER,
                "role": "kernel",
                "provenance": "server",
                "sequence_required": True,
                "allowed_event_kinds": [KIND],
            }
        ],
        clocks=[
            {
                "clock_id": CLOCK_ID,
                "boot_id": BOOT_ID,
                "origin": "engine_measured",
                "source_id": "src_candidate_inputs_engine",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )


def _setup():
    _register_writer()
    _register_event_kind()
    task = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"task"}', "restricted"
    )
    config = store.retain_artifact(
        CHANNEL, OWNER, "application/json", b'{"fixture":"config"}', "restricted"
    )
    admission = ev.admit_manifest(CHANNEL, _manifest(task, config))
    return admission


def _submission(producer_sequence, note: str) -> ev.EventSubmission:
    return ev.EventSubmission(
        producer_sequence=producer_sequence,
        event_kind=KIND,
        event_schema_version=KIND_VERSION,
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


def _valid_catalog_dict() -> dict:
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
         ["parliamentary procedure", "reporting", "consensus", "public presentation"],
         ["governance session"], ["requires quorum"]),
        ("pb08_campaign_engineering",
         "Data-Driven Campaign Engineering",
         ["BI", "demographic targeting", "conversion", "budget optimization"],
         ["campaign launch"], ["requires budget approval"]),
    ]
    entries = [
        {
            "playbook_id": pid,
            "name": name,
            "primitive_actions": actions,
            "trigger_conditions": triggers,
            "limitations": limits,
            "source_refs": [f"inventory:{pid}:source", "corpus:doc-042"],
        }
        for pid, name, actions, triggers, limits in specs
    ]
    return {
        "record_type": "playbook_catalog",
        "schema_version": "job-hunter-playbooks/0.1.0",
        "entries": entries,
    }


def _profile_dict(
    *,
    candidate_id="cand_0001",
    source_documents,
    source_evidence_refs,
    employment_history,
    capability_profile,
    playbook_catalog,
    constraints,
    disclosure_policy,
    unresolved_items,
    evidence_prefix,
) -> dict:
    return {
        "record_type": "candidate_profile_artifact",
        "schema_version": "job-hunter-candidate-profile/0.1.0",
        "candidate_id": candidate_id,
        "source_documents": source_documents,
        "source_evidence_refs": source_evidence_refs,
        "employment_history": employment_history,
        "capability_profile": capability_profile,
        "playbook_catalog": playbook_catalog,
        "constraints": constraints,
        "disclosure_policy": disclosure_policy,
        "unresolved_items": unresolved_items,
        "evidence_prefix": evidence_prefix,
    }


# ---------------------------------------------------------------------------
# Assertion 1: salary units and dates remain unresolved without conversion
# ---------------------------------------------------------------------------


def test_ambiguous_candidate_salary_units_remain_unresolved_without_conversion():
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "salary source observed"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=first.journal_sequence,
        event_id=first.event_id,
        event_hash=first.event_hash,
        pointer="",
    )

    history = {
        "monthly_salary": 22,
        "salary_unit": "monthly",
        "jobs": [
            {"employer": "Alpha", "start": "2021-01", "end": "2021-12"},
            {"employer": "Beta", "start": "2021-06", "end": "2022-03"},
        ],
    }
    history_ref = _retain_json("history", history)
    capability_ref = _retain_json(
        "capability",
        {"analysis_kind": "analytical_interpretation",
         "note": "preliminary skills summary"},
    )
    source_doc_ref = _retain_json(
        "resume", {"resume": "raw history text", "classification": "restricted"}
    )
    catalog_ref = _retain_json("catalog", _valid_catalog_dict())
    disclosure_ref = _retain_json(
        "disclosure", {"policy": "restricted", "version": "1"}
    )
    prefix_dict = {
        "journal_id": JOURNAL,
        "last_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }
    items = [
        {
            "code": "salary_unit_ambiguity",
            "detail": "Monthly salary value 22 must not be converted to hourly "
                      "pay without an evidenced unit basis.",
            "affected_fields": ["employment_history.monthly_salary"],
            "evidence_refs": [ref.to_dict()],
        },
        {
            "code": "employment_date_conflict",
            "detail": "Overlapping employment intervals remain unresolved "
                      "until evidenced.",
            "affected_fields": ["employment_history.jobs"],
            "evidence_refs": [ref.to_dict()],
        },
    ]
    profile = _profile_dict(
        source_documents=[source_doc_ref.to_dict()],
        source_evidence_refs=[ref.to_dict()],
        employment_history=history_ref.to_dict(),
        capability_profile=capability_ref.to_dict(),
        playbook_catalog={
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": catalog_ref.digest,
        },
        constraints={"value": None, "reason": "not_observed"},
        disclosure_policy={
            "id": "disclosure_policy", "version": "1",
            "artifact_digest": disclosure_ref.digest,
        },
        unresolved_items=items,
        evidence_prefix=prefix_dict,
    )
    profile_ref = _retain_json("profile", profile)

    loaded = ci.load_candidate_profile(CHANNEL, profile_ref)
    assert loaded.candidate_id == "cand_0001"
    assert [item.code for item in loaded.unresolved_items] == [
        "salary_unit_ambiguity", "employment_date_conflict",
    ]
    assert loaded.unresolved_items[0].affected_fields == (
        "employment_history.monthly_salary",
    )
    assert loaded.unresolved_items[0].detail != ""
    # The employment history reference is preserved exactly, never converted.
    assert loaded.employment_history.digest == history_ref.digest
    assert loaded.employment_history.size_bytes == history_ref.size_bytes

    # The exact retained history bytes are untouched: 22 stays monthly.
    raw_history = store.resolve_artifact(CHANNEL, loaded.employment_history)
    decoded = json.loads(raw_history.decode("utf-8"))
    assert decoded["monthly_salary"] == 22
    assert decoded["salary_unit"] == "monthly"
    assert "hourly_rate" not in decoded
    assert "hourly" not in raw_history.decode("utf-8").lower()
    assert len(decoded["jobs"]) == 2

    # Loading is stable: nothing is silently reconciled on re-read.
    reloaded = ci.load_candidate_profile(CHANNEL, profile_ref)
    assert reloaded.to_dict() == loaded.to_dict()

    # Dropping the salary/date coverage while the ambiguity signals remain
    # is rejected: the loader never resolves by omission.
    bare = dict(profile, unresolved_items=[])
    bare_ref = _retain_json("profile-bare", bare)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, bare_ref)

    only_salary = dict(profile, unresolved_items=items[:1])
    only_salary_ref = _retain_json("profile-only-salary", only_salary)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, only_salary_ref)


# ---------------------------------------------------------------------------
# Assertion 2: eight playbooks preserve sources, never become capabilities
# ---------------------------------------------------------------------------


def test_all_eight_playbooks_preserve_sources_without_becoming_executor_capabilities():
    _register_writer()

    catalog = _valid_catalog_dict()
    catalog_ref = _retain_json("catalog", catalog)
    pin = {
        "id": "playbook_catalog",
        "version": "0.1.0",
        "artifact_digest": catalog_ref.digest,
    }
    loaded = ci.load_playbook_catalog(CHANNEL, pin)
    assert loaded.record_type == "playbook_catalog"
    assert loaded.schema_version == "job-hunter-playbooks/0.1.0"
    assert len(loaded.entries) == 8
    assert tuple(entry.playbook_id for entry in loaded.entries) == EXPECTED_PLAYBOOK_IDS
    assert len({entry.playbook_id for entry in loaded.entries}) == 8
    for entry, raw in zip(loaded.entries, catalog["entries"]):
        assert entry.name == raw["name"]
        assert list(entry.primitive_actions) == raw["primitive_actions"]
        assert list(entry.trigger_conditions) == raw["trigger_conditions"]
        assert list(entry.limitations) == raw["limitations"]
        # Documentary sources are preserved verbatim and never empty.
        assert len(entry.source_refs) >= 1
        assert list(entry.source_refs) == raw["source_refs"]
        assert set(entry.to_dict().keys()) == EXPECTED_ENTRY_KEYS

    # Playbook entries are documentary records, not executor capabilities:
    # they carry no subject binding, mode, interface, or capability catalog.
    for forbidden in (
        "subject_id", "subject_version", "configured_mode", "mode",
        "interface_surface", "capabilities", "catalog", "availability",
    ):
        assert not hasattr(loaded, forbidden)
    for entry in loaded.entries:
        for forbidden in (
            "subject_id", "subject_version", "configured_mode", "mode",
            "interface_surface", "capabilities", "catalog", "availability",
        ):
            assert not hasattr(entry, forbidden)
    assert set(loaded.to_dict().keys()) == {"record_type", "schema_version", "entries"}

    # Seven entries are rejected: the catalog must hold exactly eight.
    short = dict(catalog, entries=catalog["entries"][:7])
    short_ref = _retain_json("catalog-short", short)
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": short_ref.digest,
        })

    # Duplicate identifiers are rejected.
    dup_entries = list(catalog["entries"])
    dup_entries[7] = dict(dup_entries[7], playbook_id=dup_entries[0]["playbook_id"])
    dup = dict(catalog, entries=dup_entries)
    dup_ref = _retain_json("catalog-dup", dup)
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": dup_ref.digest,
        })

    # Unknown identifiers are rejected.
    unknown_entries = list(catalog["entries"])
    unknown_entries[0] = dict(unknown_entries[0], playbook_id="pb09_unknown")
    unknown = dict(catalog, entries=unknown_entries)
    unknown_ref = _retain_json("catalog-unknown", unknown)
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": unknown_ref.digest,
        })

    # Empty documentary sources are rejected.
    empty_src_entries = [dict(entry) for entry in catalog["entries"]]
    empty_src_entries[3] = dict(empty_src_entries[3], source_refs=[])
    empty_src = dict(catalog, entries=empty_src_entries)
    empty_src_ref = _retain_json("catalog-empty-src", empty_src)
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": empty_src_ref.digest,
        })

    # Executor capability fields smuggled into an entry are rejected as
    # undeclared properties, never reinterpreted.
    smuggled_entries = [dict(entry) for entry in catalog["entries"]]
    smuggled_entries[0] = dict(
        smuggled_entries[0], subject_id="subject_1", availability="present"
    )
    smuggled = dict(catalog, entries=smuggled_entries)
    smuggled_ref = _retain_json("catalog-smuggled", smuggled)
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": smuggled_ref.digest,
        })

    # A pin naming bytes that were never retained is an unresolved
    # reference, not a catalog.
    with pytest.raises(ci.InvalidCatalogError):
        ci.load_playbook_catalog(CHANNEL, {
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": "sha256:" + "0" * 64,
        })


# ---------------------------------------------------------------------------
# Assertion 3: credentials and disclosure are never inferred from analysis
# ---------------------------------------------------------------------------


def test_candidate_credentials_and_disclosure_permissions_are_never_inferred_from_analysis():
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "credential source observed"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=first.journal_sequence,
        event_id=first.event_id,
        event_hash=first.event_hash,
        pointer="",
    )

    history = {
        "exclusion_query": "CDL",
        "note": "CDL appears in an exclusion query",
        "jobs": [
            {"employer": "Gamma", "start": "2019-01", "end": "2019-12"},
            {"employer": "Delta", "start": "2020-01", "end": "2020-12"},
        ],
    }
    capability = {
        "inferred_capabilities": ["structural analysis"],
        "analysis_kind": "analytical_interpretation",
        "equivalent_experience_proposed": "candidate proposes equivalent "
                                          "experience for a degree rule",
        "note": "inferred, not verified",
    }
    history_ref = _retain_json("history", history)
    capability_ref = _retain_json("capability", capability)
    source_doc_ref = _retain_json(
        "sensitive",
        {"sensitive_history": "restricted personal details",
         "classification": "restricted"},
    )
    constraints_ref = _retain_json(
        "constraints",
        {"employer_contact": "requires explicit permission", "max_hours": 40},
    )
    catalog_ref = _retain_json("catalog", _valid_catalog_dict())
    disclosure_ref = _retain_json(
        "disclosure", {"policy": "restricted", "version": "1"}
    )
    prefix_dict = {
        "journal_id": JOURNAL,
        "last_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }
    items = [
        {
            "code": "license_unverified",
            "detail": "CDL in an exclusion query does not establish current "
                      "license possession.",
            "affected_fields": ["employment_history.exclusion_query"],
            "evidence_refs": [ref.to_dict()],
        },
        {
            "code": "credential_unverified",
            "detail": "Inferred capabilities are analytical interpretation, "
                      "not verified credentials.",
            "affected_fields": ["capability_profile.inferred_capabilities"],
            "evidence_refs": [ref.to_dict()],
        },
        {
            "code": "disclosure_unapproved",
            "detail": "Sensitive personal history is not automatically "
                      "approved application content.",
            "affected_fields": ["source_documents"],
            "evidence_refs": [ref.to_dict()],
        },
        {
            "code": "degree_requirement_unmet",
            "detail": "Equivalent experience does not automatically satisfy "
                      "a mandatory degree rule.",
            "affected_fields": [
                "capability_profile.equivalent_experience_proposed"
            ],
            "evidence_refs": [ref.to_dict()],
        },
    ]
    profile = _profile_dict(
        candidate_id="cand_0002",
        source_documents=[source_doc_ref.to_dict()],
        source_evidence_refs=[ref.to_dict()],
        employment_history=history_ref.to_dict(),
        capability_profile=capability_ref.to_dict(),
        playbook_catalog={
            "id": "playbook_catalog", "version": "0.1.0",
            "artifact_digest": catalog_ref.digest,
        },
        constraints=constraints_ref.to_dict(),
        disclosure_policy={
            "id": "disclosure_policy", "version": "1",
            "artifact_digest": disclosure_ref.digest,
        },
        unresolved_items=items,
        evidence_prefix=prefix_dict,
    )
    profile_ref = _retain_json("profile", profile)

    loaded = ci.load_candidate_profile(CHANNEL, profile_ref)
    # The closed shape carries no inferred credentials or permissions.
    assert set(loaded.to_dict().keys()) == EXPECTED_PROFILE_KEYS
    for forbidden in (
        "credentials", "verified_credentials", "license_possession",
        "disclosure_approved", "inferred_permissions", "permissions",
    ):
        assert not hasattr(loaded, forbidden)
        assert forbidden not in loaded.to_dict()

    # The capability profile stays an analytical artifact reference; the
    # loader never expands it into credentials.
    assert loaded.capability_profile.digest == capability_ref.digest
    raw_capability = store.resolve_artifact(CHANNEL, loaded.capability_profile)
    decoded_capability = json.loads(raw_capability.decode("utf-8"))
    assert decoded_capability["analysis_kind"] == "analytical_interpretation"
    assert "verified_credentials" not in decoded_capability
    assert "credentials" not in decoded_capability

    # CDL history is preserved verbatim, never promoted to a license.
    raw_history = store.resolve_artifact(CHANNEL, loaded.employment_history)
    decoded_history = json.loads(raw_history.decode("utf-8"))
    assert decoded_history["exclusion_query"] == "CDL"
    assert "license_verified" not in decoded_history
    assert "license_possession" not in decoded_history

    # The pinned disclosure policy is preserved; nothing is auto-approved.
    assert loaded.disclosure_policy.id == "disclosure_policy"
    assert loaded.disclosure_policy.artifact_digest == disclosure_ref.digest
    assert [item.code for item in loaded.unresolved_items] == [
        "license_unverified", "credential_unverified",
        "disclosure_unapproved", "degree_requirement_unmet",
    ]

    # A missing disclosure pin is rejected: permissions are never inferred.
    no_pin = dict(profile, disclosure_policy={"value": None, "reason": "not_observed"})
    no_pin_ref = _retain_json("profile-no-pin", no_pin)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, no_pin_ref)

    # Smuggled inferred credentials are rejected as undeclared properties.
    smuggled = dict(profile, verified_credentials=["welding license"])
    smuggled_ref = _retain_json("profile-smuggled", smuggled)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, smuggled_ref)

    smuggled_permission = dict(profile, disclosure_approved=True)
    smuggled_permission_ref = _retain_json(
        "profile-smuggled-permission", smuggled_permission
    )
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, smuggled_permission_ref)

    # CDL without a license item is rejected: possession stays unresolved.
    no_license_items = [item for item in items if item["code"] != "license_unverified"]
    no_license = dict(profile, unresolved_items=no_license_items)
    no_license_ref = _retain_json("profile-no-license", no_license)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, no_license_ref)

    # Equivalent experience without a degree item is rejected.
    no_degree_items = [
        item for item in items if item["code"] != "degree_requirement_unmet"
    ]
    no_degree = dict(profile, unresolved_items=no_degree_items)
    no_degree_ref = _retain_json("profile-no-degree", no_degree)
    with pytest.raises(ci.InvalidProfileError):
        ci.load_candidate_profile(CHANNEL, no_degree_ref)
