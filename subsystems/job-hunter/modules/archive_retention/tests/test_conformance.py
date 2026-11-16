"""Conformance tests for archive_retention (tier 5).

Covers exactly the ``-k`` filter named in the module spec:

- ``changed_fetch_key_without_complete_archive_rejects_replacement``
- ``archive_requiring_mutable_peer_lookup_fails_validation``
- ``archive_dependency_reclaimed_while_reachable_fails_retention``

Every check exercises the real module with real siblings: authenticated
channels, retained immutable extents, an admitted owner journal with
hash-chained evidence, verified archive roots, and journaled retention
revisions.  The crawler replacement commit itself is produced by the test as
received evidence; ``verify_replacement`` never performs that write.
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
        path = here.parents[1] / rel if name == "archive_retention" else here.parents[2] / rel
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
ar = _load("archive_retention", Path("src/__init__.py"))

CRAWLER_CHANNEL = "ch_archive_retention_crawler_0001"
CRAWLER_PRODUCER = "prod_archive_retention_crawler"
PRODUCT_CHANNEL = "ch_archive_retention_product_0001"
PRODUCT_PRODUCER = "prod_archive_retention_product"
JOURNAL_ID = "journal_archive_retention_0001"

VIEW = "view_ingest_0001"
ENTITY = {"entity_type": "job", "target": "target_acme", "job_id": "job_0001"}

OLD_KEY = "sha256:" + hashlib.sha256(b"old fetch key").hexdigest()
NEW_KEY = "sha256:" + hashlib.sha256(b"new fetch key").hexdigest()
NEWER_KEY = "sha256:" + hashlib.sha256(b"yet newer fetch key").hexdigest()


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@pytest.fixture(autouse=True)
def _fresh_state():
    ar._OWNER_LOCKS.clear()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    ar._OWNER_LOCKS.clear()


# ---------------------------------------------------------------------------
# Owner journal, channels, and manifest
# ---------------------------------------------------------------------------


def _time_point() -> dict:
    return {
        "clock_id": "clock_archive_retention",
        "boot_id": "boot_archive_retention",
        "origin": "engine_measured",
        "monotonic_offset_ms": 12.5,
        "utc_annotation": {"value": None, "reason": "not_observed"},
    }


def _events():
    return ev.read_prefix(CRAWLER_CHANNEL, ev.journal_head(CRAWLER_CHANNEL, JOURNAL_ID))


def _head():
    return ev.journal_head(CRAWLER_CHANNEL, JOURNAL_ID)


def _prefix_dict() -> dict:
    head = _head()
    return {
        "journal_id": head.journal_id,
        "last_sequence": head.last_sequence,
        "head_hash": head.head_hash,
    }


def _ref(envelope) -> dict:
    return {
        "journal_id": envelope.journal_id,
        "sequence": envelope.journal_sequence,
        "event_id": envelope.event_id,
        "event_hash": envelope.event_hash,
        "pointer": "",
    }


def _admission_ref() -> dict:
    return _ref(_events()[0])


def _append(kind: str, data: dict, evidence_refs=()):
    submission = ev.EventSubmission(
        producer_sequence=ev.NOT_OBSERVED,
        event_kind=kind,
        event_schema_version=ar.EVENT_SCHEMA_VERSION,
        occurred_at=ev.NOT_OBSERVED,
        payload=ev.EvidencePayload(
            data=dict(data),
            measurements=(),
            evidence_refs=list(evidence_refs),
            artifact_refs=(),
        ),
    )
    return ev.append_event(CRAWLER_CHANNEL, "job.crawler", submission)


def _retain(document: dict, *, owner_domain: str = "job.crawler", channel: str = CRAWLER_CHANNEL):
    return store.retain_artifact(
        channel, owner_domain, "application/json", _canonical(document), "restricted"
    )


def _bootstrap():
    ap.register_channel(
        actor="crawler_writer",
        channel_id=CRAWLER_CHANNEL,
        axis="job.crawler",
        producer_id=CRAWLER_PRODUCER,
        principal_id="principal_archive_retention_crawler",
        sequence_required=False,
        allowed_event_kinds=(
            ar.PIN_EVENT_KIND,
            ar.RETIREMENT_EVENT_KIND,
            ar.REPLACEMENT_EVENT_KIND,
        ),
    )
    ap.register_channel(
        actor="product_writer",
        channel_id=PRODUCT_CHANNEL,
        axis="job.downstream",
        producer_id=PRODUCT_PRODUCER,
        principal_id="principal_archive_retention_product",
        sequence_required=False,
        allowed_event_kinds=("product.domain_written",),
    )
    for kind in (
        ar.PIN_EVENT_KIND,
        ar.RETIREMENT_EVENT_KIND,
        ar.REPLACEMENT_EVENT_KIND,
    ):
        ap.register_event_kind(
            kind,
            ar.EVENT_SCHEMA_VERSION,
            role="derived_output",
            assertion_kind="authoritative_effect",
            owner_domain="job.crawler",
            writer_roles=("kernel",),
        )

    task = store.retain_artifact(
        CRAWLER_CHANNEL,
        "job.crawler",
        "application/json",
        _canonical({"kind": "archive_retention_task"}),
        "restricted",
    )
    configuration = store.retain_artifact(
        CRAWLER_CHANNEL,
        "job.crawler",
        "application/json",
        _canonical(
            {
                "kind": "archive_retention_configuration",
                "domains": list(ar.JOB_DOMAINS),
            }
        ),
        "restricted",
    )
    descriptor = ap.channel_projection(CRAWLER_CHANNEL)["producer"]
    manifest = ev.Manifest(
        manifest_id="manifest_archive_retention_0001",
        run_id="run_archive_retention_0001",
        journal_id=JOURNAL_ID,
        owner_domain="job.crawler",
        commissioner_id="commissioner_archive_retention",
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
                "description": "archive retention conformance host",
            },
        },
        task=task,
        task_semantic_hash=task.digest,
        effective_configuration=configuration,
        environment={},
        seed=ev.NOT_OBSERVED,
        build_pins=[
            {
                "id": "archive_retention",
                "version": "1",
                "artifact_digest": task.digest,
            }
        ],
        event_registry=[
            {
                "event_kind": kind,
                "event_schema_version": ar.EVENT_SCHEMA_VERSION,
                "role": "derived_output",
                "assertion_kind": "authoritative_effect",
                "owner_domain": "job.crawler",
                "writer_roles": ["kernel"],
            }
            for kind in (
                ar.PIN_EVENT_KIND,
                ar.RETIREMENT_EVENT_KIND,
                ar.REPLACEMENT_EVENT_KIND,
            )
        ],
        producers=[dict(descriptor)],
        clocks=[
            {
                "clock_id": "clock_archive_retention",
                "boot_id": "boot_archive_retention",
                "origin": "engine_measured",
                "source_id": "src_archive_retention_clock",
                "basis": "monotonic_offset",
                "unit": "ms",
            }
        ],
    )
    ev.admit_manifest(CRAWLER_CHANNEL, manifest)
    return _registration_pair()


def _registration_pair():
    registration = {
        "record_type": ar.REGISTRATION_RECORD_TYPE,
        "schema_version": ar.SCHEMA_VERSION,
        "registration_id": "reg_archive_retention_0001",
        "entity": dict(ENTITY),
        "identity": {
            "portfolio_job_id": "portfolio_0001",
            "first_discovery_ref": _admission_ref(),
        },
        "owners": {
            "crawler": {
                "role": "crawler",
                "source_id": "src_crawler_0001",
                "writer_id": "writer_crawler_0001",
                "owner_domain": "job.crawler",
                "publication_policy": {
                    "id": "policy_crawler",
                    "version": "1",
                    "artifact_digest": "sha256:" + "1" * 64,
                },
            },
            "downstream": {
                "role": "product",
                "source_id": "src_product_0001",
                "writer_id": "writer_product_0001",
                "owner_domain": "job.downstream",
                "publication_policy": {
                    "id": "policy_product",
                    "version": "1",
                    "artifact_digest": "sha256:" + "2" * 64,
                },
            },
        },
        "evidence_prefix": _prefix_dict(),
        "evidence_refs": [_admission_ref()],
    }
    return registration, _retain(registration)


# ---------------------------------------------------------------------------
# Archived row components
# ---------------------------------------------------------------------------


def _owned_document(
    *,
    domain: str,
    revision: int,
    registration_digest: str,
    value: dict,
) -> dict:
    return {
        "record_type": ar.OWNED_REVISION_RECORD_TYPE,
        "schema_version": ar.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration_digest": registration_digest,
        "domain": domain,
        "owner_domain": ar.DOMAIN_OWNERS[domain],
        "writer_id": (
            "writer_crawler_0001" if domain == "crawler" else "writer_product_0001"
        ),
        "revision": revision,
        "previous_revision": revision - 1,
        "evidence_prefix": _prefix_dict(),
        "evidence_refs": [_admission_ref()],
        "value": value,
    }


def _crawler_doc(
    revision: int,
    fetch_key: str,
    registration_digest: str,
    *,
    lineage: dict | None = None,
) -> dict:
    return _owned_document(
        domain="crawler",
        revision=revision,
        registration_digest=registration_digest,
        value={
            "acquisition": {
                "source_url": "https://example.invalid/job/1",
                "fetch_key": fetch_key,
            },
            "processing": {"extractor": "fixture/1"},
            "discovery": {"run_id": "run_archive_retention_0001"},
            "replacement_lineage": (
                lineage
                if lineage is not None
                else {
                    "value": None,
                    "reason": "not_applicable",
                    "detail": "no prior replacement",
                }
            ),
        },
    )


def _downstream_doc(revision: int, value: dict | None = None) -> dict:
    return _owned_document(
        domain="downstream",
        revision=revision,
        registration_digest=_REGISTRATION_DIGEST[0],
        value=value if value is not None else {"track": "shortlist", "priority": 1},
    )


_REGISTRATION_DIGEST: list[str] = [""]


def _lineage(replacement_id: str, prior_revision: int, archive_root) -> dict:
    root = (
        archive_root.to_dict()
        if hasattr(archive_root, "to_dict")
        else dict(archive_root)
    )
    return {
        "replacement_id": replacement_id,
        "prior_crawler_revision": prior_revision,
        "archive_root": root,
    }


def _seal(versions: dict) -> dict:
    return {
        "seal_id": "seal_replacement_0001",
        "name": "fetch_key_replacement",
        "view_id": VIEW,
        "versions": dict(versions),
        "sealed_at": _time_point(),
        "input_prefix": _prefix_dict(),
        "evidence_refs": [_admission_ref()],
    }


def _archive(
    registration: dict,
    registration_ref,
    crawler_doc: dict,
    downstream_doc: dict,
    *,
    crawler_ref=None,
    downstream_ref=None,
    manifest_domains: dict | None = None,
    row_domains: dict | None = None,
    seal: dict | None = None,
):
    crawler_ref = crawler_ref or _retain(crawler_doc)
    downstream_ref = downstream_ref or _retain(downstream_doc)
    versions = {
        "crawler": crawler_doc["revision"],
        "downstream": downstream_doc["revision"],
    }
    if manifest_domains is None:
        manifest_domains = {
            "crawler": {
                "revision": crawler_doc["revision"],
                "document": crawler_ref.to_dict(),
                "publication_ref": _admission_ref(),
            },
            "downstream": {
                "revision": downstream_doc["revision"],
                "document": downstream_ref.to_dict(),
                "publication_ref": _admission_ref(),
            },
        }
    if row_domains is None:
        row_domains = {
            "crawler": {**manifest_domains["crawler"], "snapshot": crawler_doc},
            "downstream": {**manifest_domains["downstream"], "snapshot": downstream_doc},
        }
    seal_point = seal if seal is not None else _seal(versions)
    manifest = {
        "encoding": ar.ARCHIVE_ENCODING,
        "schema_version": ar.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration": registration_ref.to_dict(),
        "domains": manifest_domains,
        "seal_point": seal_point,
    }
    manifest_bytes = _canonical(manifest)
    root = {
        "digest": str(cc.canonical_digest(manifest_bytes)),
        "size_bytes": len(manifest_bytes),
        "media_type": "application/json",
        "owner_domain": "job.crawler",
        "access": "restricted",
    }
    record = {
        "record_type": ar.ARCHIVE_RECORD_TYPE,
        "schema_version": ar.SCHEMA_VERSION,
        "root": root,
        "storage_manifest": manifest,
        "payload_json": {
            "record_type": ar.LOGICAL_ROW_RECORD_TYPE,
            "schema_version": ar.SCHEMA_VERSION,
            "entity": dict(ENTITY),
            "registration_digest": registration_ref.digest,
            "registration": registration,
            "domains": row_domains,
            "seal_point": seal_point,
        },
    }
    return _retain(record), record


# ---------------------------------------------------------------------------
# Retention pins and replacement receipts
# ---------------------------------------------------------------------------


def _pin(
    pin_id: str,
    archive_ref,
    *,
    kind: str = "live_replacement",
    revision: int = 1,
    previous_revision: int = 0,
    state: str = "active",
    release_ref: dict | None = None,
    evidence_refs=None,
) -> dict:
    return {
        "record_type": ar.PIN_RECORD_TYPE,
        "schema_version": ar.SCHEMA_VERSION,
        "pin_id": pin_id,
        "owner_domain": "job.crawler",
        "writer_id": CRAWLER_PRODUCER,
        "revision": revision,
        "previous_revision": previous_revision,
        "dependent": {
            "entity": dict(ENTITY),
            "kind": kind,
            "root_id": pin_id,
        },
        "archive_root": archive_ref.to_dict(),
        "state": state,
        "release_ref": (
            dict(release_ref)
            if release_ref is not None
            else {"value": None, "reason": "not_applicable"}
        ),
        "evidence_prefix": _prefix_dict(),
        "evidence_refs": (
            [_admission_ref()] if evidence_refs is None else list(evidence_refs)
        ),
    }


def _latest_pin_envelope(pin_id: str):
    latest = None
    for envelope in _events():
        if envelope.event_kind != ar.PIN_EVENT_KIND:
            continue
        data = envelope.payload["data"]
        if data.get("record_type") == ar.PIN_RECORD_TYPE and data.get("pin_id") == pin_id:
            latest = envelope
    return latest


def _current_pin(pin_id: str):
    state = ev.entity_state(CRAWLER_CHANNEL, "job.crawler", pin_id)
    if isinstance(state.state, ev.Missing):
        return state.revision, None
    raw = store.resolve_artifact(CRAWLER_CHANNEL, state.state)
    return state.revision, ar.RetentionPinRevision.from_dict(json.loads(raw))


def _retire(pin_id: str, archive_ref) -> dict:
    envelope = _append(
        ar.RETIREMENT_EVENT_KIND,
        {
            "record_type": ar.RETIREMENT_RECORD_TYPE,
            "pin_id": pin_id,
            "archive_root_digest": archive_ref.digest,
        },
    )
    return _ref(envelope)


def _release(
    pin_id: str,
    archive_ref,
    previous_revision: int,
    retirement_ref: dict,
    *support_refs,
    kind: str = "live_replacement",
):
    pin = _pin(
        pin_id,
        archive_ref,
        kind=kind,
        revision=previous_revision + 1,
        previous_revision=previous_revision,
        state="released",
        release_ref=retirement_ref,
        evidence_refs=[retirement_ref, *support_refs],
    )
    return ar.revise_retention(CRAWLER_CHANNEL, pin)


def _receipt(
    archive_ref,
    old_doc: dict,
    old_doc_ref,
    old_fetch_key: str,
    new_doc: dict,
    archived_vector: dict,
    pin_envelope,
    pin_id: str,
    *,
    replacement_id: str = "replacement_0001",
) -> dict:
    return {
        "record_type": ar.REPLACEMENT_RECORD_TYPE,
        "schema_version": ar.SCHEMA_VERSION,
        "replacement_id": replacement_id,
        "entity": dict(ENTITY),
        "registration_digest": _REGISTRATION_DIGEST[0],
        "old_crawler": {
            "revision": old_doc["revision"],
            "record_digest": old_doc_ref.digest,
        },
        "old_fetch_key": old_fetch_key,
        "new_crawler": new_doc,
        "archive_root": archive_ref.to_dict(),
        "archived_vector": dict(archived_vector),
        "retention_pin_id": pin_id,
        "commit_ref": _admission_ref(),
        "evidence_prefix": _prefix_dict(),
        "evidence_refs": (
            [_ref(pin_envelope)] if pin_envelope is not None else [_admission_ref()]
        ),
    }


def _commit_projection(receipt: dict, *, override: dict | None = None) -> dict:
    data = {
        "record_type": ar.REPLACEMENT_RECORD_TYPE,
        "replacement_id": receipt["replacement_id"],
        "entity": dict(receipt["entity"]),
        "registration_digest": receipt["registration_digest"],
        "old_crawler_revision": receipt["old_crawler"]["revision"],
        "old_crawler_record_digest": receipt["old_crawler"]["record_digest"],
        "old_fetch_key": receipt["old_fetch_key"],
        "new_crawler_revision": receipt["new_crawler"]["revision"],
        "new_crawler_previous_revision": receipt["new_crawler"]["previous_revision"],
        "new_fetch_key": receipt["new_crawler"]["value"]["acquisition"]["fetch_key"],
        "archive_root_digest": receipt["archive_root"]["digest"],
        "archived_vector": dict(receipt["archived_vector"]),
        "retention_pin_id": receipt["retention_pin_id"],
    }
    if override:
        data.update(override)
    return data


def _append_commit(receipt: dict, *, override: dict | None = None) -> dict:
    data = _commit_projection(receipt, override=override)
    evidence_refs = [_ref(_latest_pin_envelope(receipt["retention_pin_id"]))] if receipt["evidence_refs"] else []
    envelope = _append(ar.REPLACEMENT_EVENT_KIND, data, evidence_refs=evidence_refs)
    receipt["commit_ref"] = _ref(envelope)
    receipt["evidence_prefix"] = _prefix_dict()
    return receipt


def _setup_valid_replacement():
    """Bootstrap, archive the prior row, pin it, and record a valid replacement."""
    registration, registration_ref = _bootstrap()
    _REGISTRATION_DIGEST[0] = registration_ref.digest
    crawler_doc = _crawler_doc(1, OLD_KEY, registration_ref.digest)
    downstream_doc = _downstream_doc(2)
    crawler_ref = _retain(crawler_doc)
    downstream_ref = _retain(downstream_doc)
    archive_ref, record = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        crawler_ref=crawler_ref,
        downstream_ref=downstream_ref,
    )
    pin = _pin("pin_archive_0001", archive_ref)
    ar.revise_retention(CRAWLER_CHANNEL, pin)
    pin_envelope = _latest_pin_envelope("pin_archive_0001")
    new_doc = _crawler_doc(
        2,
        NEW_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_0001", 1, archive_ref),
    )
    receipt = _receipt(
        archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        new_doc,
        {"crawler": 1, "downstream": 2},
        pin_envelope,
        "pin_archive_0001",
    )
    _append_commit(receipt)
    return {
        "registration": registration,
        "registration_ref": registration_ref,
        "crawler_doc": crawler_doc,
        "downstream_doc": downstream_doc,
        "crawler_ref": crawler_ref,
        "downstream_ref": downstream_ref,
        "archive_ref": archive_ref,
        "record": record,
        "pin_envelope": pin_envelope,
        "new_doc": new_doc,
        "receipt": receipt,
    }


# ---------------------------------------------------------------------------
# Assertion 1: a changed fetch key without a complete archive is rejected
# ---------------------------------------------------------------------------


def test_changed_fetch_key_without_complete_archive_rejects_replacement():
    fixture = _setup_valid_replacement()
    registration = fixture["registration"]
    registration_ref = fixture["registration_ref"]
    crawler_doc = fixture["crawler_doc"]
    downstream_doc = fixture["downstream_doc"]
    crawler_ref = fixture["crawler_ref"]
    archive_ref = fixture["archive_ref"]
    pin_envelope = fixture["pin_envelope"]

    verified = ar.verify_replacement(CRAWLER_CHANNEL, fixture["receipt"])
    assert isinstance(verified, ar.ArchiveRecord)
    # The returned archive is the complete previous logical row.
    assert verified.payload_json["registration"] == registration
    assert verified.payload_json["domains"]["crawler"]["snapshot"] == crawler_doc
    assert verified.payload_json["domains"]["downstream"]["snapshot"] == downstream_doc
    assert verified.payload_json["seal_point"]["versions"] == {
        "crawler": 1,
        "downstream": 2,
    }
    # The root hashes the canonical storage manifest, not the wrapper.
    assert verified.root.digest == str(
        cc.canonical_digest(_canonical(verified.storage_manifest))
    )
    assert verified.root.size_bytes == len(_canonical(verified.storage_manifest))

    # (a) The old crawler pin does not name the archived revision.
    receipt = dict(fixture["receipt"])
    receipt["old_crawler"] = {
        "revision": 2,
        "record_digest": crawler_ref.digest,
    }
    _append_commit(receipt)
    with pytest.raises(ar.ReplacementRejectedError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (b) The archived vector is not the seal vector that was actually cut.
    receipt = _receipt(
        archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        fixture["new_doc"],
        {"crawler": 1, "downstream": 3},
        pin_envelope,
        "pin_archive_0001",
    )
    _append_commit(receipt)
    with pytest.raises(ar.ReplacementRejectedError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (c) A crawler-only archive is not the complete previous row.
    partial_manifest = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
        }
    }
    partial_row = {
        "crawler": {
            **partial_manifest["crawler"],
            "snapshot": crawler_doc,
        }
    }
    partial_archive_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        manifest_domains=partial_manifest,
        row_domains=partial_row,
        seal=_seal({"crawler": 1, "downstream": 0}),
    )
    partial_new = _crawler_doc(
        2,
        NEW_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_partial", 1, partial_archive_ref),
    )
    receipt = _receipt(
        partial_archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        partial_new,
        {"crawler": 1, "downstream": 0},
        pin_envelope,
        "pin_archive_0001",
        replacement_id="replacement_partial",
    )
    _append_commit(receipt)
    with pytest.raises(ar.IncompleteArchiveError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (d) A hash list in place of a complete domain slot is not an archive.
    hashlist_manifest = {
        "crawler": {"revision": 1, "hashes": [crawler_ref.digest]},
        "downstream": {
            "revision": 2,
            "document": fixture["downstream_ref"].to_dict(),
            "publication_ref": _admission_ref(),
        },
    }
    hashlist_row = {
        "crawler": dict(hashlist_manifest["crawler"]),
        "downstream": {
            **hashlist_manifest["downstream"],
            "snapshot": downstream_doc,
        },
    }
    hashlist_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        manifest_domains=hashlist_manifest,
        row_domains=hashlist_row,
    )
    receipt = _receipt(
        hashlist_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_hashlist", 1, hashlist_ref),
        ),
        {"crawler": 1, "downstream": 2},
        pin_envelope,
        "pin_archive_0001",
        replacement_id="replacement_hashlist",
    )
    _append_commit(receipt)
    with pytest.raises(ar.IncompleteArchiveError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (e) A different response under the same fetch key is a no-op, not a
    # replacement, and cannot be committed as one.
    same_key_new = _crawler_doc(
        2,
        OLD_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_same_key", 1, archive_ref),
    )
    receipt = _receipt(
        archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        same_key_new,
        {"crawler": 1, "downstream": 2},
        pin_envelope,
        "pin_archive_0001",
        replacement_id="replacement_same_key",
    )
    _append_commit(receipt)
    with pytest.raises(ar.ReplacementRejectedError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (f) A changed-field diff in payload_json is not the complete row.
    diff_row = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": {"fetch_key": OLD_KEY},
        },
        "downstream": {
            "revision": 2,
            "document": fixture["downstream_ref"].to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": downstream_doc,
        },
    }
    diff_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        row_domains=diff_row,
    )
    receipt = _receipt(
        diff_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_diff", 1, diff_ref),
        ),
        {"crawler": 1, "downstream": 2},
        pin_envelope,
        "pin_archive_0001",
        replacement_id="replacement_diff",
    )
    _append_commit(receipt)
    with pytest.raises(ar.IncompleteArchiveError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (g) The journaled commit event names a different archived cut.
    receipt = _receipt(
        archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_stale", 1, archive_ref),
        ),
        {"crawler": 1, "downstream": 2},
        pin_envelope,
        "pin_archive_0001",
        replacement_id="replacement_stale",
    )
    _append_commit(receipt, override={"archived_vector": {"crawler": 9, "downstream": 9}})
    with pytest.raises(ar.ReplacementRejectedError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (h) A released retention pin no longer protects the root at the cut.
    retirement_ref = _retire("pin_archive_0001", archive_ref)
    _release(
        "pin_archive_0001",
        archive_ref,
        1,
        retirement_ref,
        _ref(pin_envelope),
    )
    released_envelope = _latest_pin_envelope("pin_archive_0001")
    receipt = _receipt(
        archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_released", 1, archive_ref),
        ),
        {"crawler": 1, "downstream": 2},
        released_envelope,
        "pin_archive_0001",
        replacement_id="replacement_released",
    )
    _append_commit(receipt)
    with pytest.raises(ar.ReplacementRejectedError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)


# ---------------------------------------------------------------------------
# Assertion 2: expansion never consults mutable peer state
# ---------------------------------------------------------------------------


def test_archive_requiring_mutable_peer_lookup_fails_validation():
    registration, registration_ref = _bootstrap()
    _REGISTRATION_DIGEST[0] = registration_ref.digest
    crawler_doc = _crawler_doc(1, OLD_KEY, registration_ref.digest)
    downstream_doc = _downstream_doc(2)
    crawler_ref = _retain(crawler_doc)
    downstream_ref = _retain(downstream_doc)
    archive_ref, _record = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        crawler_ref=crawler_ref,
        downstream_ref=downstream_ref,
    )

    # (a) A restricted extent owned by the publishing peer is a locator, not
    # an imported archive component; the archive domain may not read it.
    peer_ref = store.retain_artifact(
        PRODUCT_CHANNEL,
        "job.downstream",
        "application/json",
        _canonical(downstream_doc),
        "restricted",
    )
    peer_manifest = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
        },
        "downstream": {
            "revision": 2,
            "document": peer_ref.to_dict(),
            "publication_ref": _admission_ref(),
        },
    }
    peer_row = {
        "crawler": {**peer_manifest["crawler"], "snapshot": crawler_doc},
        "downstream": {**peer_manifest["downstream"], "snapshot": downstream_doc},
    }
    peer_archive_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        manifest_domains=peer_manifest,
        row_domains=peer_row,
    )
    receipt = _receipt(
        peer_archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_peer", 1, peer_archive_ref),
        ),
        {"crawler": 1, "downstream": 2},
        None,
        "pin_archive_0001",
        replacement_id="replacement_peer",
    )
    with pytest.raises(ar.IncompleteArchiveError) as peer_exc:
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert "import complete local extents" in str(peer_exc.value)

    # (b) A promised digest that was never retained locally fails explicitly;
    # nothing is fetched from a peer and no hashes-only body is accepted.
    ghost_doc = _downstream_doc(4, value={"track": "never-imported"})
    ghost_bytes = _canonical(ghost_doc)
    ghost_ref = {
        "digest": "sha256:" + hashlib.sha256(ghost_bytes).hexdigest(),
        "size_bytes": len(ghost_bytes),
        "media_type": "application/json",
        "owner_domain": "job.crawler",
        "access": "restricted",
    }
    ghost_manifest = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
        },
        "downstream": {
            "revision": 4,
            "document": ghost_ref,
            "publication_ref": _admission_ref(),
        },
    }
    ghost_row = {
        "crawler": {**ghost_manifest["crawler"], "snapshot": crawler_doc},
        "downstream": {**ghost_manifest["downstream"], "snapshot": ghost_doc},
    }
    ghost_archive_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        manifest_domains=ghost_manifest,
        row_domains=ghost_row,
        seal=_seal({"crawler": 1, "downstream": 4}),
    )
    receipt = _receipt(
        ghost_archive_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_ghost", 1, ghost_archive_ref),
        ),
        {"crawler": 1, "downstream": 4},
        None,
        "pin_archive_0001",
        replacement_id="replacement_ghost",
    )
    with pytest.raises(ar.IncompleteArchiveError) as ghost_exc:
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert ghost_exc.value.missing is not None
    assert ghost_exc.value.missing["value"] is None
    assert ghost_exc.value.missing["reason"] == "not_observed"

    # (c) payload_json substituting a peer locator for the snapshot is a diff,
    # not an expansion of the retained manifest.
    locator_row = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": crawler_doc,
        },
        "downstream": {
            "revision": 2,
            "document": downstream_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": {"$ref": "peer://job.downstream/latest"},
        },
    }
    locator_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        row_domains=locator_row,
    )
    receipt = _receipt(
        locator_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_locator", 1, locator_ref),
        ),
        {"crawler": 1, "downstream": 2},
        None,
        "pin_archive_0001",
        replacement_id="replacement_locator",
    )
    with pytest.raises(ar.IncompleteArchiveError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (d) A hash list in place of the snapshot is not the complete old row.
    hash_row = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": crawler_doc,
        },
        "downstream": {
            "revision": 2,
            "document": downstream_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": [downstream_ref.digest],
        },
    }
    hash_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        row_domains=hash_row,
    )
    receipt = _receipt(
        hash_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_hash", 1, hash_ref),
        ),
        {"crawler": 1, "downstream": 2},
        None,
        "pin_archive_0001",
        replacement_id="replacement_hash",
    )
    with pytest.raises(ar.IncompleteArchiveError):
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)

    # (e) A newer downstream record is never silently selected: the archived
    # revision stays exactly the manifested document.
    newer = _downstream_doc(3, value={"track": "applied", "priority": 9})
    newer_row = {
        "crawler": {
            "revision": 1,
            "document": crawler_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": crawler_doc,
        },
        "downstream": {
            "revision": 2,
            "document": downstream_ref.to_dict(),
            "publication_ref": _admission_ref(),
            "snapshot": newer,
        },
    }
    newer_ref, _ = _archive(
        registration,
        registration_ref,
        crawler_doc,
        downstream_doc,
        row_domains=newer_row,
    )
    receipt = _receipt(
        newer_ref,
        crawler_doc,
        crawler_ref,
        OLD_KEY,
        _crawler_doc(
            2,
            NEW_KEY,
            registration_ref.digest,
            lineage=_lineage("replacement_newer", 1, newer_ref),
        ),
        {"crawler": 1, "downstream": 2},
        None,
        "pin_archive_0001",
        replacement_id="replacement_newer",
    )
    with pytest.raises(ar.IncompleteArchiveError) as newer_exc:
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert "expansion differs" in str(newer_exc.value)
    # The manifested extent is untouched; no upgraded revision was installed.
    assert store.resolve_artifact(CRAWLER_CHANNEL, downstream_ref) == _canonical(
        downstream_doc
    )

    # (f) A retained later archive whose backward link names an archive that
    # was never imported cannot be validated or pinned.
    fabricated_root = {
        "digest": "sha256:" + hashlib.sha256(b"never imported archive").hexdigest(),
        "size_bytes": len(b"never imported archive"),
        "media_type": "application/json",
        "owner_domain": "job.crawler",
        "access": "restricted",
    }
    linked_crawler_doc = _crawler_doc(
        2,
        NEW_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_prior", 1, fabricated_root),
    )
    linked_crawler_ref = _retain(linked_crawler_doc)
    linked_archive_ref, _ = _archive(
        registration,
        registration_ref,
        linked_crawler_doc,
        _downstream_doc(3),
        crawler_ref=linked_crawler_ref,
    )
    linked_new = _crawler_doc(
        3,
        NEWER_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_linked", 2, linked_archive_ref),
    )
    receipt = _receipt(
        linked_archive_ref,
        linked_crawler_doc,
        linked_crawler_ref,
        NEW_KEY,
        linked_new,
        {"crawler": 2, "downstream": 3},
        None,
        "pin_archive_0001",
        replacement_id="replacement_linked",
    )
    with pytest.raises(ar.IncompleteArchiveError) as linked_exc:
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert linked_exc.value.missing is not None
    assert linked_exc.value.missing["reason"] == "not_observed"
    with pytest.raises(ar.IncompleteArchiveError):
        ar.revise_retention(
            CRAWLER_CHANNEL,
            _pin("pin_linked_archive", linked_archive_ref, kind="retained_archive"),
        )


# ---------------------------------------------------------------------------
# Assertion 3: a reclaimed dependency never satisfies retention
# ---------------------------------------------------------------------------


def test_archive_dependency_reclaimed_while_reachable_fails_retention():
    fixture = _setup_valid_replacement()
    registration = fixture["registration"]
    registration_ref = fixture["registration_ref"]
    crawler_doc = fixture["crawler_doc"]
    downstream_doc = fixture["downstream_doc"]
    crawler_ref = fixture["crawler_ref"]
    downstream_ref = fixture["downstream_ref"]
    archive_ref = fixture["archive_ref"]
    receipt = fixture["receipt"]
    replacement_record = ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert replacement_record.payload_json["domains"]["downstream"]["snapshot"] == downstream_doc

    # A retained later archive carries the replacement's backward link: it
    # keeps the earlier archive alive, so a newer publication cannot release.
    newer_downstream = _downstream_doc(3, value={"track": "applied", "priority": 4})
    newer_downstream_ref = _retain(newer_downstream)
    later_crawler_doc = _crawler_doc(
        2,
        NEW_KEY,
        registration_ref.digest,
        lineage=_lineage("replacement_0001", 1, archive_ref),
    )
    later_crawler_ref = _retain(later_crawler_doc)
    later_archive_ref, _ = _archive(
        registration,
        registration_ref,
        later_crawler_doc,
        newer_downstream,
        crawler_ref=later_crawler_ref,
        downstream_ref=newer_downstream_ref,
    )
    ar.revise_retention(
        CRAWLER_CHANNEL,
        _pin("pin_later_archive", later_archive_ref, kind="retained_archive"),
    )
    later_pin_envelope = _latest_pin_envelope("pin_later_archive")

    retirement_for_prior = _retire("pin_archive_0001", archive_ref)
    with pytest.raises(ar.RetentionStillReachableError):
        _release(
            "pin_archive_0001",
            archive_ref,
            1,
            retirement_for_prior,
            _ref(fixture["pin_envelope"]),
        )
    assert _current_pin("pin_archive_0001")[0] == 1
    assert _current_pin("pin_archive_0001")[1].state == "active"

    # An unrelated retained archive can still be released with evidence, and
    # released pins remain journaled without mutating archived content.
    standalone_doc = _downstream_doc(2, value={"track": "rejected", "priority": 0})
    standalone_archive_ref, _ = _archive(
        registration,
        registration_ref,
        _crawler_doc(1, OLD_KEY, registration_ref.digest),
        standalone_doc,
    )
    ar.revise_retention(
        CRAWLER_CHANNEL,
        _pin("pin_standalone", standalone_archive_ref, kind="retained_evidence"),
    )
    standalone_pin_envelope = _latest_pin_envelope("pin_standalone")
    standalone_retirement = _retire("pin_standalone", standalone_archive_ref)
    released_ref = _release(
        "pin_standalone",
        standalone_archive_ref,
        1,
        standalone_retirement,
        _ref(standalone_pin_envelope),
        kind="retained_evidence",
    )
    revision, released_pin = _current_pin("pin_standalone")
    assert revision == 2
    assert released_pin.state == "released"
    assert released_pin.release_ref == standalone_retirement
    assert released_ref.digest in store.known_digests()
    # Released retention history does not mutate archived content.
    assert store.resolve_artifact(CRAWLER_CHANNEL, standalone_archive_ref) is not None

    # The reachable dependency is reclaimed underneath the live replacement.
    store.drop_retained_bytes_for_tests(downstream_ref.digest)
    assert downstream_ref.digest in store.known_digests()
    head_before = _head()

    # Re-pinning the reachable archive fails as an integrity incident.
    with pytest.raises(ar.ArchiveIntegrityError) as repin_exc:
        ar.revise_retention(
            CRAWLER_CHANNEL,
            _pin(
                "pin_archive_0001",
                archive_ref,
                revision=2,
                previous_revision=1,
            ),
        )
    assert repin_exc.value.missing is not None
    assert repin_exc.value.missing["reason"] == "observation_lost"
    assert _head() == head_before

    # Releasing it also fails; a newer publication or an explicit release
    # attempt cannot turn loss into successful garbage collection.
    with pytest.raises(ar.ArchiveIntegrityError):
        _release(
            "pin_archive_0001",
            archive_ref,
            1,
            retirement_for_prior,
            _ref(fixture["pin_envelope"]),
        )
    assert _head() == head_before
    revision, live_pin = _current_pin("pin_archive_0001")
    assert revision == 1
    assert live_pin.state == "active"

    # Replacement verification reports the loss instead of reconstructing the
    # row from peer state or the latest downstream record.
    with pytest.raises(ar.ArchiveIntegrityError) as verify_exc:
        ar.verify_replacement(CRAWLER_CHANNEL, receipt)
    assert verify_exc.value.missing is not None
    assert verify_exc.value.missing["reason"] == "observation_lost"

    # The exact bytes return; the live replacement still blocks release.
    _retain(downstream_doc)
    assert store.resolve_artifact(CRAWLER_CHANNEL, downstream_ref) == _canonical(
        downstream_doc
    )
    with pytest.raises(ar.RetentionStillReachableError):
        _release(
            "pin_archive_0001",
            archive_ref,
            1,
            retirement_for_prior,
            _ref(fixture["pin_envelope"]),
        )

    # The later archive is not reached by the earlier one, so it may retire.
    later_retirement = _retire("pin_later_archive", later_archive_ref)
    _release(
        "pin_later_archive",
        later_archive_ref,
        1,
        later_retirement,
        _ref(later_pin_envelope),
        kind="retained_archive",
    )
    assert _current_pin("pin_later_archive")[1].state == "released"

    # With every protector retired, the earlier root may be released; its
    # archived content is still retrievable and the history stays journaled.
    _release(
        "pin_archive_0001",
        archive_ref,
        1,
        retirement_for_prior,
        _ref(fixture["pin_envelope"]),
    )
    revision, final_pin = _current_pin("pin_archive_0001")
    assert revision == 2
    assert final_pin.state == "released"
    assert store.resolve_artifact(CRAWLER_CHANNEL, archive_ref) is not None
    pin_events = [
        envelope
        for envelope in _events()
        if envelope.event_kind == ar.PIN_EVENT_KIND
        and envelope.payload["data"].get("pin_id") == "pin_archive_0001"
    ]
    assert [envelope.payload["data"]["state"] for envelope in pin_events] == [
        "active",
        "released",
    ]

    # A released pin is terminal.
    with pytest.raises(ar.RetentionRejectedError):
        ar.revise_retention(
            CRAWLER_CHANNEL,
            _pin(
                "pin_archive_0001",
                archive_ref,
                revision=3,
                previous_revision=2,
                state="released",
                release_ref=retirement_for_prior,
                evidence_refs=[retirement_for_prior, _ref(fixture["pin_envelope"])],
            ),
        )
