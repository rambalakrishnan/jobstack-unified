"""Conformance tests for artifact_store (tier 1).

Covers exactly the ``-k`` filter named in the module spec:

- ``missing_artifact_bytes_report_explicit_loss_or_unavailability``
- ``redacted_artifacts_receive_new_identity_without_replacing_original_bytes``

Every check exercises the real module: authenticated retention, digest
verification, explicit Missing-enveloped loss reporting, and redaction
with derivation evidence and preserved originals.
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
        path = here.parents[1] / rel if name == "artifact_store" else here.parents[2] / rel
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ap = _load("access_policy", Path("access_policy/src/__init__.py"))
cc = _load("contract_codec", Path("contract_codec/src/__init__.py"))
store = _load("artifact_store", Path("src/__init__.py"))


@pytest.fixture(autouse=True)
def _fresh_state():
    ap.reset_for_tests()
    store.reset_for_tests()
    yield
    store.reset_for_tests()
    ap.reset_for_tests()


def _register_crawler(channel_id="ch_artifact_crawler_0001", producer="prod_artifact_crawler"):
    return ap.register_channel(
        actor="crawler_writer",
        channel_id=channel_id,
        axis="job.crawler",
        producer_id=producer,
        principal_id="principal_artifact_crawler",
        sequence_required=True,
        allowed_event_kinds=("discovery.source_observed",),
    )


def _register_product(channel_id="ch_artifact_product_0001", producer="prod_artifact_product"):
    return ap.register_channel(
        actor="product_writer",
        channel_id=channel_id,
        axis="job.downstream",
        producer_id=producer,
        principal_id="principal_artifact_product",
        sequence_required=True,
        allowed_event_kinds=("product.published",),
    )


# ---------------------------------------------------------------------------
# Assertion 1: missing bytes report explicit loss or unavailability
# ---------------------------------------------------------------------------


def test_missing_artifact_bytes_report_explicit_loss_or_unavailability():
    crawler = "ch_artifact_crawler_0001"
    _register_crawler()
    _register_product()

    content = b"raw vendor body with exact bytes \x00\x01"
    ref = store.retain_artifact(crawler, "job.crawler", "application/octet-stream", content, "public")
    assert ref.digest == "sha256:" + hashlib.sha256(content).hexdigest()
    assert ref.size_bytes == len(content)
    assert store.resolve_artifact(crawler, ref) == content

    # Case A: digest never retained -> explicit unavailability, digest preserved.
    ghost_digest = "sha256:" + hashlib.sha256(b"never-retained-bytes").hexdigest()
    ghost = store.ArtifactReference(
        digest=ghost_digest,
        size_bytes=20,
        media_type="application/octet-stream",
        owner_domain="job.crawler",
        access="public",
    )
    assert ghost_digest not in store.known_digests()
    with pytest.raises(store.ArtifactUnavailableError) as excinfo:
        store.resolve_artifact(crawler, ghost)
    err = excinfo.value
    assert err.digest == ghost_digest
    assert err.missing["value"] is None
    assert err.missing["reason"] == "not_observed"
    assert isinstance(err.missing["detail"], str) and err.missing["detail"]
    assert ghost_digest in str(err) or ghost_digest in err.missing["detail"]
    assert cc.is_missing_envelope(err.missing)
    # A failed retrieval never erases identity tracking.
    assert ref.digest in store.known_digests()

    # Case B: retained bytes subsequently lost -> explicit loss incident.
    store.drop_retained_bytes_for_tests(ref.digest)
    assert ref.digest in store.known_digests()
    with pytest.raises(store.ArtifactLostError) as lostinfo:
        store.resolve_artifact(crawler, ref)
    lost = lostinfo.value
    assert lost.digest == ref.digest
    assert lost.missing["value"] is None
    assert lost.missing["reason"] == "observation_lost"
    assert "integrity incident" in lost.missing["detail"]
    assert cc.is_missing_envelope(lost.missing)
    # Loss is not successful garbage collection: still lost on retry.
    with pytest.raises(store.ArtifactLostError):
        store.resolve_artifact(crawler, ref)

    # Size tampering is also an integrity incident, never silent bytes.
    ref2 = store.retain_artifact(crawler, "job.crawler", "text/plain", b"hello", "public")
    tampered = store.ArtifactReference(
        digest=ref2.digest,
        size_bytes=ref2.size_bytes + 1,
        media_type=ref2.media_type,
        owner_domain=ref2.owner_domain,
        access=ref2.access,
    )
    with pytest.raises(store.ArtifactLostError) as tamperinfo:
        store.resolve_artifact(crawler, tampered)
    assert tamperinfo.value.missing["reason"] == "observation_lost"

    # Hash possession alone grants nothing: unknown channel cannot resolve.
    with pytest.raises(Exception):
        store.resolve_artifact("ch_unknown_no_session", ref2)
    try:
        store.resolve_artifact("ch_unknown_no_session", ref2)
    except Exception as e:  # noqa: BLE001
        assert isinstance(e, ap.AuthorizationError)

    # Restricted bytes resolve only within their owner domain.
    restricted = store.retain_artifact(
        crawler, "job.crawler", "application/octet-stream", b"secret-bytes", "restricted"
    )
    assert store.resolve_artifact(crawler, restricted) == b"secret-bytes"
    with pytest.raises(store.ArtifactAccessDeniedError):
        store.resolve_artifact("ch_artifact_product_0001", restricted)

    # Structured retention still rejects bare nulls via contract_codec.
    bad = json.dumps({"id": "r1", "salary": None}).encode()
    with pytest.raises(ValueError):
        store.retain_validated_record(
            crawler, "job.crawler", "application/json", bad, "public", "record/v1"
        )
    good = json.dumps({"id": "r1", "salary": cc.make_missing("not_observed")}).encode()
    validated = store.retain_validated_record(
        crawler, "job.crawler", "application/json", good, "public", "record/v1"
    )
    assert store.resolve_artifact(crawler, validated) == good


# ---------------------------------------------------------------------------
# Assertion 2: redaction mints a new identity; original bytes preserved
# ---------------------------------------------------------------------------


def test_redacted_artifacts_receive_new_identity_without_replacing_original_bytes():
    crawler = "ch_artifact_crawler_0001"
    _register_crawler()

    original = b"candidate Alice, ssn 123-45-6789, email alice@example.com"
    src = store.retain_artifact(
        crawler, "job.crawler", "text/plain", original, "restricted"
    )
    assert src.digest == "sha256:" + hashlib.sha256(original).hexdigest()
    assert src.access == "restricted"

    redacted_bytes = b"candidate Alice, ssn [redacted], email [redacted]"
    assert redacted_bytes != original
    redacted = store.redact_artifact(crawler, src, redacted_bytes)

    # New identity: different digest, correct size, exact-byte addressing.
    assert redacted.digest != src.digest
    assert redacted.digest == "sha256:" + hashlib.sha256(redacted_bytes).hexdigest()
    assert redacted.size_bytes == len(redacted_bytes)
    assert redacted.owner_domain == src.owner_domain

    # Original bytes are preserved verbatim under the original digest.
    assert store.resolve_artifact(crawler, src) == original
    assert store.resolve_artifact(crawler, redacted) == redacted_bytes
    assert store.resolve_artifact(crawler, src) != redacted_bytes

    # Derivation evidence links the redacted export to its source.
    derivation = store.redaction_derivation(redacted.digest)
    assert derivation["record_type"] == "redaction_derivation"
    assert derivation["source_digest"] == src.digest
    assert derivation["redacted_digest"] == redacted.digest
    assert derivation["source_size_bytes"] == len(original)
    assert derivation["redacted_size_bytes"] == len(redacted_bytes)
    assert len(store.derivations()) == 1

    # Idempotent retention: same bytes keep the same digest; nothing mutates.
    again = store.retain_artifact(crawler, "job.crawler", "text/plain", original, "restricted")
    assert again.digest == src.digest
    assert store.resolve_artifact(crawler, src) == original

    # A "redaction" identical to the source is rejected: no new identity.
    with pytest.raises(ValueError):
        store.redact_artifact(crawler, src, original)
    # Original still intact after the rejected redaction.
    assert store.resolve_artifact(crawler, src) == original
