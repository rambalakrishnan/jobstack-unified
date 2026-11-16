"""Conformance tests for read_publications (tier 4).

Covers exactly the ``-k`` filter named in the module spec:

- ``crawler_row_with_partial_publication_is_rejected``
- ``publication_reordering_never_rolls_back_installed_revision``
- ``seal_vectors_pin_complete_local_publications_without_global_synchronization``

Every check exercises the real module with real siblings: authenticated
channels, retained artifacts, an admitted derived journal, hash-chained
installation/seal events, and verified LogicalRow roots.
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
        path = here.parents[1] / rel if name == "read_publications" else here.parents[2] / rel
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
rp = _load("read_publications", Path("src/__init__.py"))

CRAWLER_CHANNEL = "ch_read_publications_crawler_0001"
CRAWLER_PRODUCER = "prod_read_publications_crawler"
PRODUCT_CHANNEL = "ch_read_publications_product_0001"
PRODUCT_PRODUCER = "prod_read_publications_product"
PUBLISHER_CHANNEL = "ch_read_publications_publisher_0001"
PUBLISHER_PRODUCER = "prod_read_publications_publisher"

VIEW = "view_read_publications_0001"
SOURCE_JOURNAL = "journal_crawler_source_0001"

ENTITY = {"entity_type": "job", "target": "target_acme", "job_id": "job_0001"}
DISCOVERY = {
    "journal_id": SOURCE_JOURNAL,
    "sequence": 1,
    "event_id": "evt_crawler_discovery_0001",
    "event_hash": "sha256:" + "a" * 64,
    "pointer": "",
}


def _canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _digest(value) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _registration_digest(registration) -> str:
    # The row names the digest of the complete canonical registration bytes.
    return str(cc.canonical_digest(_canonical(registration.to_dict())))


@pytest.fixture(autouse=True)
def _fresh_state():
    rp.reset_for_tests()
    ev.reset_for_tests()
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()
    ev.reset_for_tests()
    rp.reset_for_tests()


def _register_channels() -> None:
    ap.register_channel(
        actor="crawler_writer",
        channel_id=CRAWLER_CHANNEL,
        axis="job.crawler",
        producer_id=CRAWLER_PRODUCER,
        principal_id="principal_read_publications_crawler",
        sequence_required=False,
        allowed_event_kinds=("crawler.published",),
    )
    ap.register_channel(
        actor="product_writer",
        channel_id=PRODUCT_CHANNEL,
        axis="job.downstream",
        producer_id=PRODUCT_PRODUCER,
        principal_id="principal_read_publications_product",
        sequence_required=False,
        allowed_event_kinds=("product.published",),
    )
    ap.register_channel(
        actor="read_view_publisher",
        channel_id=PUBLISHER_CHANNEL,
        axis=rp.PUBLISHER_AXIS,
        producer_id=PUBLISHER_PRODUCER,
        principal_id="principal_read_publications_publisher",
        sequence_required=False,
        allowed_event_kinds=(
            rp.INSTALL_EVENT_KIND,
            rp.SEAL_EVENT_KIND,
            rp.ROW_EVENT_KIND,
        ),
    )


def _registration(registration_id: str = "reg_read_publications_0001"):
    owners = {
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
    }
    return rp.EntityRegistration(
        registration_id=registration_id,
        entity=ENTITY,
        identity={
            "portfolio_job_id": "portfolio_job_0001",
            "first_discovery_ref": dict(DISCOVERY),
        },
        owners=owners,
        evidence_prefix={
            "journal_id": SOURCE_JOURNAL,
            "last_sequence": 3,
            "head_hash": "sha256:" + "b" * 64,
        },
        evidence_refs=(dict(DISCOVERY),),
    )


def _document(
    domain: str,
    revision: int,
    registration_digest: str,
    *,
    value=None,
    writer_id: str | None = None,
) -> dict:
    if domain == "crawler":
        owner_domain, default_writer = "job.crawler", "writer_crawler_0001"
    else:
        owner_domain, default_writer = "job.downstream", "writer_product_0001"
    return {
        "record_type": "owned_domain_revision",
        "schema_version": rp.SCHEMA_VERSION,
        "entity": dict(ENTITY),
        "registration_digest": registration_digest,
        "domain": domain,
        "owner_domain": owner_domain,
        "writer_id": writer_id or default_writer,
        "revision": revision,
        "previous_revision": revision - 1,
        "evidence_prefix": {
            "journal_id": SOURCE_JOURNAL,
            "last_sequence": 4 + revision,
            "head_hash": "sha256:" + "c" * 64,
        },
        "evidence_refs": [dict(DISCOVERY)],
        "value": value if value is not None else {"label": f"{domain} revision {revision}"},
    }


def _retain(domain: str, document: dict):
    channel = CRAWLER_CHANNEL if domain == "crawler" else PRODUCT_CHANNEL
    owner_domain = "job.crawler" if domain == "crawler" else "job.downstream"
    return store.retain_artifact(
        channel,
        owner_domain,
        "application/json",
        _canonical(document),
        "public",
    )


def _publish(domain: str, revision: int, registration, **kwargs):
    document = _document(
        domain, revision, _registration_digest(registration), **kwargs
    )
    return _retain(domain, document), document


def _journal_head():
    return ev.journal_head(PUBLISHER_CHANNEL, rp.publisher_journal_id(PUBLISHER_CHANNEL))


def _all_events():
    return ev.read_prefix(PUBLISHER_CHANNEL, _journal_head())


def _setup():
    _register_channels()
    registration = _registration()
    return registration, _registration_digest(registration)


# ---------------------------------------------------------------------------
# Assertion 1: a crawler row over a partial publication is rejected
# ---------------------------------------------------------------------------


def test_crawler_row_with_partial_publication_is_rejected():
    registration, registration_digest = _setup()

    first_ref, first_document = _publish("crawler", 1, registration)
    first_receipt = rp.install_publication(
        PUBLISHER_CHANNEL, registration, first_ref, VIEW
    )
    assert first_receipt.revision == 1
    assert first_receipt.document.digest == first_ref.digest
    head_before = _journal_head()

    # (a) A delivery whose complete bytes were only partially transferred is
    # rejected: the fabricated reference names the full document digest while
    # only a prefix of those bytes ever reached the store.
    partial_document = _document(
        "crawler", 2, registration_digest, value={"label": "partial transfer"}
    )
    partial_bytes = _canonical(partial_document)
    store.retain_artifact(
        CRAWLER_CHANNEL,
        "job.crawler",
        "application/json",
        partial_bytes[: len(partial_bytes) // 2],
        "public",
    )
    partial_ref = store.ArtifactReference(
        digest="sha256:" + hashlib.sha256(partial_bytes).hexdigest(),
        size_bytes=len(partial_bytes),
        media_type="application/json",
        owner_domain="job.crawler",
        access="public",
    )
    with pytest.raises(rp.PublicationRejectedError) as partial_exc:
        rp.install_publication(PUBLISHER_CHANNEL, registration, partial_ref, VIEW)
    assert partial_exc.value.missing is not None
    assert partial_exc.value.missing["value"] is None
    assert partial_exc.value.missing["reason"] == "not_observed"
    assert _journal_head() == head_before

    # (b) Complete bytes that are not a complete publication are rejected too.
    incomplete = _document("crawler", 2, registration_digest)
    del incomplete["value"]
    incomplete_ref = _retain("crawler", incomplete)
    with pytest.raises(rp.PublicationRejectedError):
        rp.install_publication(PUBLISHER_CHANNEL, registration, incomplete_ref, VIEW)
    assert _journal_head() == head_before

    # (c) The prior complete revision stays visible; a failed delivery never
    # exposes a partially transferred body and never advances the pointer.
    row = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "published")
    assert dict(row.seal_point.versions) == {"crawler": 1, "downstream": 0}
    assert row.domains["crawler"].revision == 1
    assert row.domains["crawler"].document.digest == first_ref.digest
    assert row.domains["crawler"].snapshot == first_document

    # (d) A crawler-backed row cannot be sealed from a view with no crawler
    # publication at all: the crawler slot is nonzero for a reason.
    with pytest.raises(rp.RowAdmissionError):
        rp.seal_row(PUBLISHER_CHANNEL, registration, "view_empty_0001", "published")

    # (e) Lost published bytes are an explicit rejection, never revision zero.
    store.drop_retained_bytes_for_tests(first_ref.digest)
    with pytest.raises(rp.PublicationRejectedError):
        rp.load_row(PUBLISHER_CHANNEL, ENTITY, VIEW)
    assert row.domains["crawler"].revision == 1


# ---------------------------------------------------------------------------
# Assertion 2: reordering never rolls back the installed revision
# ---------------------------------------------------------------------------


def test_publication_reordering_never_rolls_back_installed_revision():
    registration, _registration_digest_value = _setup()

    first_ref, _first_document = _publish("crawler", 1, registration)
    first_receipt = rp.install_publication(
        PUBLISHER_CHANNEL, registration, first_ref, VIEW
    )
    second_ref, second_document = _publish("crawler", 2, registration)
    second_receipt = rp.install_publication(
        PUBLISHER_CHANNEL, registration, second_ref, VIEW
    )

    assert second_receipt.supersedes["revision"] == 1
    assert second_receipt.supersedes["record_digest"] == first_ref.digest
    delay = second_receipt.publication_delay["measurement"]
    assert delay["method"] == "unavailable"
    assert delay["estimate"]["kind"] == "unavailable"
    assert second_receipt.publication_ref.sequence > first_receipt.publication_ref.sequence
    head_after_install = _journal_head()

    # An identical retry returns the existing receipt with no new effect.
    retry = rp.install_publication(PUBLISHER_CHANNEL, registration, second_ref, VIEW)
    assert retry.receipt_id == second_receipt.receipt_id
    assert retry.publication_ref.to_dict() == second_receipt.publication_ref.to_dict()
    assert _journal_head() == head_after_install

    # A reordered older delivery is rejected and moves nothing.
    with pytest.raises(rp.StalePublicationError):
        rp.install_publication(PUBLISHER_CHANNEL, registration, first_ref, VIEW)
    assert _journal_head() == head_after_install

    # A different body offered under the installed revision identity is an
    # integrity conflict, not a rollback and not last-write-wins.
    conflicting_ref, _conflicting_document = _publish(
        "crawler", 2, registration, value={"label": "conflicting revision 2"}
    )
    with pytest.raises(rp.RevisionIdentityConflictError):
        rp.install_publication(
            PUBLISHER_CHANNEL, registration, conflicting_ref, VIEW
        )
    assert _journal_head() == head_after_install

    # The installed revision remains exactly what the seal pins and loads.
    row = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "published")
    assert row.domains["crawler"].revision == 2
    assert row.domains["crawler"].document.digest == second_ref.digest
    assert row.domains["crawler"].snapshot == second_document
    assert (
        row.domains["crawler"].publication_ref.to_dict()
        == second_receipt.publication_ref.to_dict()
    )
    loaded = rp.load_row(PUBLISHER_CHANNEL, ENTITY, VIEW)
    assert loaded.to_dict() == row.to_dict()
    assert loaded.sealed_versions() == {"crawler": 2, "downstream": 0}


# ---------------------------------------------------------------------------
# Assertion 3: seal vectors pin complete local publications (no global sync)
# ---------------------------------------------------------------------------


def test_seal_vectors_pin_complete_local_publications_without_global_synchronization():
    registration, _registration_digest_value = _setup()

    first_ref, _first_document = _publish("crawler", 1, registration)
    rp.install_publication(PUBLISHER_CHANNEL, registration, first_ref, VIEW)
    second_ref, second_document = _publish("crawler", 2, registration)
    second_receipt = rp.install_publication(
        PUBLISHER_CHANNEL, registration, second_ref, VIEW
    )

    # No owner journal exists in this process: the seal and its vector have to
    # come from locally installed complete publications alone.
    with pytest.raises(ev.JournalNotAdmittedError):
        ev.journal_head(CRAWLER_CHANNEL, SOURCE_JOURNAL)
    with pytest.raises(ev.JournalNotAdmittedError):
        ev.journal_head(PUBLISHER_CHANNEL, SOURCE_JOURNAL)

    row = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "published")

    # Every declared domain slot is present and the vector equals the slots.
    assert set(row.domains) == set(rp.JOB_DOMAINS)
    assert dict(row.seal_point.versions) == {
        domain: row.domains[domain].revision for domain in rp.JOB_DOMAINS
    }
    assert dict(row.seal_point.versions) == {"crawler": 2, "downstream": 0}

    crawler_slot = row.domains["crawler"]
    assert crawler_slot.revision == 2
    assert crawler_slot.snapshot == second_document
    assert crawler_slot.snapshot["revision"] == crawler_slot.revision
    assert crawler_slot.document.digest == second_ref.digest
    assert crawler_slot.publication_ref.to_dict() == second_receipt.publication_ref.to_dict()

    downstream_slot = row.domains["downstream"]
    assert downstream_slot.revision == 0
    assert downstream_slot.missing["value"] is None
    assert downstream_slot.missing["reason"] == "not_observed"

    # The seal-selection event is inside the row's input prefix and pins the
    # complete local document digests and publication receipts.
    prefix = ev.read_prefix(
        PUBLISHER_CHANNEL,
        ev.JournalPrefix(
            journal_id=row.seal_point.input_prefix["journal_id"],
            last_sequence=row.seal_point.input_prefix["last_sequence"],
            head_hash=row.seal_point.input_prefix["head_hash"],
        ),
    )
    selection = prefix[-1]
    assert selection.event_kind == rp.SEAL_EVENT_KIND
    assert selection.journal_sequence == row.seal_point.input_prefix["last_sequence"]
    assert selection.event_hash == row.seal_point.input_prefix["head_hash"]
    selected = selection.payload["data"]["selected"]
    crawler_entry = next(entry for entry in selected if entry["domain"] == "crawler")
    assert crawler_entry["revision"] == 2
    assert crawler_entry["document"]["digest"] == second_ref.digest
    assert (
        crawler_entry["publication_ref"]
        == second_receipt.publication_ref.to_dict()
    )
    downstream_entry = next(
        entry for entry in selected if entry["domain"] == "downstream"
    )
    assert downstream_entry["revision"] == 0
    assert downstream_entry["value"]["reason"] == "not_observed"
    assert all(event.owner_domain == rp.PUBLISHER_AXIS for event in prefix)
    assert second_receipt.publication_ref.to_dict() in [
        dict(ref) for ref in row.seal_point.evidence_refs
    ]

    # The row's own registration event is deliberately outside its prefix.
    head = _journal_head()
    all_events = ev.read_prefix(PUBLISHER_CHANNEL, head)
    registrations = [
        event for event in all_events if event.event_kind == rp.ROW_EVENT_KIND
    ]
    registration_event = registrations[-1]
    assert registration_event.journal_sequence == (
        row.seal_point.input_prefix["last_sequence"] + 1
    )
    row_digest = _digest(row.to_dict())
    assert registration_event.payload["data"]["row_digest"] == row_digest
    assert (
        registration_event.payload["data"]["input_prefix"]
        == row.seal_point.input_prefix
    )
    registered_bytes = store.resolve_artifact(
        PUBLISHER_CHANNEL,
        store.ArtifactReference.from_dict(
            registration_event.payload["data"]["row"]
        ),
    )
    assert json.loads(registered_bytes) == row.to_dict()
    assert rp.load_row(PUBLISHER_CHANNEL, ENTITY, VIEW).to_dict() == row.to_dict()

    # New publications do not freeze or rewrite the old seal.
    third_ref, _third_document = _publish("crawler", 3, registration)
    rp.install_publication(PUBLISHER_CHANNEL, registration, third_ref, VIEW)
    newer = rp.seal_row(PUBLISHER_CHANNEL, registration, VIEW, "evidence_updated")
    assert dict(newer.seal_point.versions) == {"crawler": 3, "downstream": 0}
    assert newer.seal_point.seal_id != row.seal_point.seal_id
    assert row.sealed_versions() == {"crawler": 2, "downstream": 0}
    preserved = store.resolve_artifact(
        PUBLISHER_CHANNEL,
        store.ArtifactReference.from_dict(
            registration_event.payload["data"]["row"]
        ),
    )
    assert json.loads(preserved) == row.to_dict()
    assert rp.load_row(PUBLISHER_CHANNEL, ENTITY, VIEW).to_dict() == newer.to_dict()
