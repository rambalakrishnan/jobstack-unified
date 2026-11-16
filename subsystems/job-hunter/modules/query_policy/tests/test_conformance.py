"""Conformance tests for query_policy (tier 4).

Covers exactly the ``-k`` filter named in the module spec:

- ``bachelors_requirement_is_flagged_not_automatically_excluded``
- ``query_families_preserve_board_syntax_and_explicit_soft_veto_activation``

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
        path = here.parents[1] / rel if name == "query_policy" else here.parents[2] / rel
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
ci = _load("candidate_inputs", Path("candidate_inputs/src/__init__.py"))
qp = _load("query_policy", Path("src/__init__.py"))

CHANNEL = "ch_query_policy_product_0001"
PRODUCER = "prod_query_policy_product"
OWNER = "job.downstream"
JOURNAL = "journal_query_policy_0001"
RUN = "run_query_policy_0001"
KIND = "product.published"
KIND_VERSION = "1"
CLOCK_ID = "clock_query_policy_engine"
BOOT_ID = "boot_query_policy_engine"


@pytest.fixture(autouse=True)
def _fresh_state():
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
        principal_id="principal_query_policy_product",
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
        manifest_id="manifest_query_policy_0001",
        run_id=RUN,
        journal_id=JOURNAL,
        owner_domain=OWNER,
        commissioner_id="commissioner_query_policy",
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
                "principal_id": "principal_query_policy_product",
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
                "source_id": "src_query_policy_engine",
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


def _valid_veto_dict(*, approval_ref: dict, entries: list[dict] | None = None) -> dict:
    if entries is None:
        entries = [
            {
                "term": "CDL required",
                "type": "hard",
                "reason": "license possession not evidenced",
                "action": "exclude",
            },
            {
                "term": "Bachelor's required",
                "type": "soft",
                "reason": "supplied source rule flags degree language",
                "action": "flag",
            },
            {
                "term": "night shift",
                "type": "soft",
                "reason": "candidate shift preference",
                "action": "flag",
            },
        ]
    return {
        "record_type": "negative_veto_policy",
        "schema_version": "job-hunter-veto-policy/0.1.0",
        "entries": entries,
        "approval_refs": [approval_ref],
    }


def _valid_syntax_dict() -> dict:
    return {
        "record_type": "job_search_syntax_mapping",
        "schema_version": "job-hunter-syntax-mapping/0.1.0",
        "mappings": {
            "google": {"query_operator": "phrase_minus", "note": "preserve quotes and minus"},
            "governmentjobs": {"query_operator": "keywords", "category_ui": "separate"},
            "neogov": {"query_operator": "keywords", "category_ui": "separate"},
            "usajobs": {
                "query_operator": "keywords",
                "series": "separate",
                "exclusions": "separate",
            },
            "linkedin": {"query_operator": "pinned_linkedin_v1"},
            "indeed": {"query_operator": "pinned_indeed_v1"},
            "greenhouse": {"query_operator": "site", "site": "site:greenhouse.io"},
            "lever": {"query_operator": "site", "site": "site:lever.co"},
            "county": {"adapter_evidence": "journal:county_adapter:evt_001"},
            "transit": {"adapter_evidence": "journal:transit_adapter:evt_001"},
            "exa": {"search": "neural", "contents": "livecrawl"},
        },
    }


def _build_inputs():
    """Admit journal, retain profile/catalog/veto/syntax, return pins + refs."""
    _setup()
    first = ev.append_event(CHANNEL, OWNER, _submission(1, "query inputs observed"))
    head = ev.journal_head(CHANNEL, JOURNAL)
    ref = ev.EvidenceRef(
        journal_id=JOURNAL,
        sequence=first.journal_sequence,
        event_id=first.event_id,
        event_hash=first.event_hash,
        pointer="",
    )
    capability_ref = _retain_json(
        "capability",
        {"analysis_kind": "analytical_interpretation", "note": "clean skills summary"},
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
    catalog_pin = {
        "id": "playbook_catalog",
        "version": "0.1.0",
        "artifact_digest": catalog_ref.digest,
    }
    profile = _profile_dict(
        source_documents=[source_doc_ref.to_dict()],
        source_evidence_refs=[ref.to_dict()],
        employment_history={"value": None, "reason": "not_observed"},
        capability_profile=capability_ref.to_dict(),
        playbook_catalog=catalog_pin,
        constraints={"value": None, "reason": "not_observed"},
        disclosure_policy={
            "id": "disclosure_policy",
            "version": "1",
            "artifact_digest": disclosure_ref.digest,
        },
        unresolved_items=[],
        evidence_prefix=prefix_dict,
    )
    profile_ref = _retain_json("profile", profile)
    veto_ref = _retain_json("veto", _valid_veto_dict(approval_ref=ref.to_dict()))
    syntax_ref = _retain_json("syntax", _valid_syntax_dict())
    veto_pin = {
        "id": "veto_policy",
        "version": "0.1.0",
        "artifact_digest": veto_ref.digest,
    }
    syntax_pin = {
        "id": "syntax_mapping",
        "version": "0.1.0",
        "artifact_digest": syntax_ref.digest,
    }
    return {
        "ref": ref,
        "head": head,
        "profile_ref": profile_ref,
        "catalog_pin": catalog_pin,
        "veto_pin": veto_pin,
        "syntax_pin": syntax_pin,
        "veto_ref": veto_ref,
        "syntax_ref": syntax_ref,
    }


# ---------------------------------------------------------------------------
# Assertion 1: bachelor's requirement is flagged, not automatically excluded
# ---------------------------------------------------------------------------


def test_bachelors_requirement_is_flagged_not_automatically_excluded():
    inputs = _build_inputs()
    ref = inputs["ref"]

    artifact = qp.build_query(
        CHANNEL,
        "q_bachelors_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "B",
        "google",
    )
    assert artifact.record_type == "job_search_query"
    assert artifact.schema_version == "job-hunter-query/0.1.0"
    assert artifact.family == "B"
    assert artifact.board == "google"
    assert artifact.query_text != ""
    assert len(artifact.evidence_refs) >= 1

    # The pinned veto policy flags bachelor's language; it never excludes.
    policy = qp.load_veto_policy(CHANNEL, inputs["veto_pin"])
    bachelors = [e for e in policy.entries if "bachelor" in e.term.lower()]
    assert len(bachelors) == 1
    assert bachelors[0].action == "flag"
    assert bachelors[0].type == "soft"
    assert bachelors[0].reason != ""
    assert len(policy.approval_refs) >= 1

    # Flagged terms never become automatic exclusions in the artifact.
    lowered_exclusions = [t.lower() for t in artifact.category_exclusions]
    lowered_series = [t.lower() for t in artifact.series_filters]
    assert not any("bachelor" in t for t in lowered_exclusions)
    assert not any("bachelor" in t for t in lowered_series)
    assert qp.veto_decision("Posting notes Bachelor's required", policy) == "flag"
    assert (
        qp.veto_decision(
            "Posting notes Bachelor's required", policy, activate_soft=True
        )
        == "flag"
    )

    # A veto artifact that auto-excludes bachelor's language is rejected.
    bad_entries = [
        {
            "term": "CDL required",
            "type": "hard",
            "reason": "license possession not evidenced",
            "action": "exclude",
        },
        {
            "term": "Bachelor's required",
            "type": "hard",
            "reason": "degree gate",
            "action": "exclude",
        },
    ]
    bad_ref = _retain_json(
        "veto-bad", _valid_veto_dict(approval_ref=ref.to_dict(), entries=bad_entries)
    )
    bad_pin = {
        "id": "veto_policy",
        "version": "0.1.0",
        "artifact_digest": bad_ref.digest,
    }
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_bachelors_0002",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            bad_pin,
            inputs["syntax_pin"],
            "B",
            "google",
        )

    # A global query veto stays distinct: no crawler relevance veto and no
    # product no-go fields leak into the query artifact, and no execution
    # or empty-result claim is made.
    as_dict = artifact.to_dict()
    assert set(as_dict.keys()) == {
        "record_type",
        "schema_version",
        "query_id",
        "family",
        "board",
        "query_text",
        "category_exclusions",
        "series_filters",
        "candidate_profile",
        "playbook_catalog",
        "veto_policy",
        "syntax_mapping",
        "evidence_refs",
    }
    for forbidden in (
        "crawler_veto",
        "relevance_veto",
        "product_selection",
        "selection",
        "no_go",
        "executed",
        "execution",
        "no_opportunities",
        "empty_proves_absence",
    ):
        assert forbidden not in as_dict
    assert as_dict["veto_policy"] == inputs["veto_pin"]


# ---------------------------------------------------------------------------
# Assertion 2: families preserve board syntax; soft vetoes need activation
# ---------------------------------------------------------------------------


def test_query_families_preserve_board_syntax_and_explicit_soft_veto_activation():
    inputs = _build_inputs()
    ref = inputs["ref"]

    # Every family renders a nonempty, closed, evidenced artifact whose
    # exact source text is retained.
    for family in ("A", "B", "C", "D", "E", "broad", "title_expansion"):
        artifact = qp.build_query(
            CHANNEL,
            f"q_{family}_google_0001",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            inputs["syntax_pin"],
            family,
            "google",
        )
        source = qp.SOURCE_QUERY_TEXT[family]
        assert artifact.query_text == source
        assert artifact.family == family
        assert isinstance(artifact.category_exclusions, tuple)
        assert isinstance(artifact.series_filters, tuple)
        assert all(isinstance(t, str) and t for t in artifact.category_exclusions)
        assert all(isinstance(t, str) and t for t in artifact.series_filters)
        assert len(artifact.evidence_refs) >= 1
        as_dict = artifact.to_dict()
        assert as_dict["query_text"] != ""
        assert isinstance(as_dict["category_exclusions"], list)
        assert isinstance(as_dict["series_filters"], list)

    # Google preserves phrase quotes and minus terms inline.
    google = qp.build_query(
        CHANNEL,
        "q_A_google_0002",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "A",
        "google",
    )
    assert '"' in google.query_text
    assert "-" in google.query_text

    # GovernmentJobs/NeoGov: keywords in query_text, UI category
    # exclusions in a separate array.
    neogov = qp.build_query(
        CHANNEL,
        "q_B_neogov_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "B",
        "neogov",
    )
    assert neogov.query_text != ""
    assert "category:" not in neogov.query_text.lower()
    assert "CDL required" in list(neogov.category_exclusions)
    assert neogov.series_filters == ()

    # USAJobs: keywords, series, and exclusions stay in three channels.
    usajobs = qp.build_query(
        CHANNEL,
        "q_B_usajobs_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "B",
        "usajobs",
    )
    assert usajobs.query_text != ""
    assert tuple(usajobs.series_filters) == ("0301", "1102")
    assert "CDL required" in list(usajobs.category_exclusions)

    # LinkedIn/Indeed require their pinned syntax mappings.
    for board in ("linkedin", "indeed"):
        artifact = qp.build_query(
            CHANNEL,
            f"q_A_{board}_0001",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            inputs["syntax_pin"],
            "A",
            board,
        )
        assert artifact.query_text == qp.SOURCE_QUERY_TEXT["A"]
    thin_syntax = {
        "record_type": "job_search_syntax_mapping",
        "schema_version": "job-hunter-syntax-mapping/0.1.0",
        "mappings": {"google": {"query_operator": "phrase_minus"}},
    }
    thin_ref = _retain_json("syntax-thin", thin_syntax)
    thin_pin = {
        "id": "syntax_mapping",
        "version": "0.1.0",
        "artifact_digest": thin_ref.digest,
    }
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_A_linkedin_0002",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            thin_pin,
            "A",
            "linkedin",
        )

    # Greenhouse/Lever retain site restrictions alongside the source.
    greenhouse = qp.build_query(
        CHANNEL,
        "q_A_greenhouse_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "A",
        "greenhouse",
    )
    assert "site:greenhouse.io" in greenhouse.query_text
    assert qp.SOURCE_QUERY_TEXT["A"] in greenhouse.query_text
    lever = qp.build_query(
        CHANNEL,
        "q_A_lever_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "A",
        "lever",
    )
    assert "site:lever.co" in lever.query_text
    assert qp.SOURCE_QUERY_TEXT["A"] in lever.query_text

    # County/transit require independently evidenced adapters.
    county = qp.build_query(
        CHANNEL,
        "q_D_county_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "D",
        "county",
    )
    assert county.query_text == qp.SOURCE_QUERY_TEXT["D"]
    bare_adapter = {
        "record_type": "job_search_syntax_mapping",
        "schema_version": "job-hunter-syntax-mapping/0.1.0",
        "mappings": {"county": {"query_operator": "keywords"}},
    }
    bare_ref = _retain_json("syntax-bare", bare_adapter)
    bare_pin = {
        "id": "syntax_mapping",
        "version": "0.1.0",
        "artifact_digest": bare_ref.digest,
    }
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_D_county_0002",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            bare_pin,
            "D",
            "county",
        )

    # Exa search/contents semantics come from its actual adapter entry.
    exa = qp.build_query(
        CHANNEL,
        "q_E_exa_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "E",
        "exa",
    )
    assert exa.query_text == qp.SOURCE_QUERY_TEXT["E"]

    # Title expansion remains secondary: title-scoped, family-pinned, and
    # never promoted over the capability-driven families.
    titles = qp.build_query(
        CHANNEL,
        "q_title_0001",
        inputs["profile_ref"],
        inputs["catalog_pin"],
        inputs["veto_pin"],
        inputs["syntax_pin"],
        "title_expansion",
        "google",
    )
    assert titles.family == "title_expansion"
    assert "title:" in titles.query_text
    assert titles.query_text != qp.SOURCE_QUERY_TEXT["A"]
    assert "title:" not in qp.SOURCE_QUERY_TEXT["A"]

    # Pinned syntax never establishes credentials, quota, response shape,
    # or acquisition permission.
    syntax_raw = store.resolve_artifact(CHANNEL, inputs["syntax_ref"])
    syntax_text = syntax_raw.decode("utf-8").lower()
    assert "credential" not in syntax_text
    assert "quota" not in syntax_text
    for artifact in (google, usajobs, exa):
        as_dict = artifact.to_dict()
        for forbidden in ("credentials", "quota", "response_shape", "permission"):
            assert forbidden not in as_dict

    # Veto activation: hard exclusions apply by default; soft exclusions
    # require explicit activation and are never silent.
    policy = qp.load_veto_policy(CHANNEL, inputs["veto_pin"])
    assert qp.veto_decision("Role lists CDL required", policy) == "exclude"
    assert qp.veto_decision("Role is night shift", policy) == "flag"
    assert qp.veto_decision("Role is night shift", policy, activate_soft=True) == "flag"

    soft_exclude_entries = [
        {
            "term": "CDL required",
            "type": "hard",
            "reason": "license possession not evidenced",
            "action": "exclude",
        },
        {
            "term": "night shift",
            "type": "soft",
            "reason": "candidate shift preference",
            "action": "exclude",
        },
    ]
    soft_ref = _retain_json(
        "veto-soft", _valid_veto_dict(approval_ref=ref.to_dict(), entries=soft_exclude_entries)
    )
    soft_pin = {
        "id": "veto_policy",
        "version": "0.1.0",
        "artifact_digest": soft_ref.digest,
    }
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_soft_0001",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            soft_pin,
            inputs["syntax_pin"],
            "A",
            "google",
        )

    # Direct decision semantics: a soft exclusion degrades to flag until
    # the caller explicitly activates it.
    direct = qp.VetoPolicy(
        record_type="negative_veto_policy",
        schema_version="job-hunter-veto-policy/0.1.0",
        entries=(
            qp.VetoEntry(
                term="night shift", type="soft", reason="preference", action="exclude"
            ),
        ),
        approval_refs=(ref,),
    )
    assert qp.veto_decision("night shift role", direct) == "flag"
    assert qp.veto_decision("night shift role", direct, activate_soft=True) == "exclude"

    # Unknown family or board is rejected; nothing is invented.
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_Z_0001",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            inputs["syntax_pin"],
            "Z",
            "google",
        )
    with pytest.raises(qp.QueryPolicyError):
        qp.build_query(
            CHANNEL,
            "q_A_unknown_0001",
            inputs["profile_ref"],
            inputs["catalog_pin"],
            inputs["veto_pin"],
            inputs["syntax_pin"],
            "A",
            "unknown-board",
        )
