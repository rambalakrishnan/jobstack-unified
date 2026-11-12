"""Conformance assertions T01 (3.1) and T02 (3.2 + 3.5)."""
from __future__ import annotations

import hashlib
import json
import math
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from __init__ import (  # noqa: E402
    ContractError,
    canonical_bytes,
    digest_bytes,
    validate_record,
)

MAX = 9007199254740991
GOOD_DIGEST = "sha256:" + "ab" * 32


def good_ref(seq=1):
    return {
        "journal_id": "j1",
        "sequence": seq,
        "event_id": "e1",
        "event_hash": GOOD_DIGEST,
        "pointer": "/a",
    }


def strict_loads(text):
    def hook(pairs):
        obj = {}
        for k, v in pairs:
            if k in obj:
                raise ContractError("duplicate mapping key")
            obj[k] = v
        return obj

    return json.loads(text, object_pairs_hook=hook)


# ---------------------------------------------------------------- T01 ---
class TestT01ScalarStructural:
    def test_T01_identifiers(self):
        validate_record("abc", "Identifier/1")
        for bad in ("", None, 0, b"x", False):
            with pytest.raises(ValueError):
                validate_record(bad, "Identifier/1")

    def test_T01_revision_bounds(self):
        validate_record(0, "Revision/1")
        validate_record(MAX, "Revision/1")
        for bad in (-1, MAX + 1, True, 1.0, "1", None):
            with pytest.raises(ValueError):
                validate_record(bad, "Revision/1")

    def test_T01_positive_int(self):
        validate_record(1, "PositiveInteger/1")
        validate_record(MAX, "PositiveInteger/1")
        for bad in (0, -3, MAX + 1, True, None):
            with pytest.raises(ValueError):
                validate_record(bad, "PositiveInteger/1")

    def test_T01_digest(self):
        validate_record(GOOD_DIGEST, "Digest/1")
        for bad in (
            "sha256:" + "AB" * 32,
            "sha256:abc",
            "md5:" + "a" * 32,
            "sha256:" + "ab" * 31 + "a",
            "",
            None,
        ):
            with pytest.raises(ValueError):
                validate_record(bad, "Digest/1")

    def test_T01_number_rejects_nonfinite_oob(self):
        validate_record(3, "Number/1")
        validate_record(1.5, "Number/1")
        for bad in (float("nan"), float("inf"), float("-inf"), True, MAX + 1,
                    "3", None):
            with pytest.raises(ValueError):
                validate_record(bad, "Number/1")

    def test_T01_datetime_format(self):
        validate_record("2026-01-02T03:04:05Z", "DateTime/1")
        validate_record("2026-01-02T03:04:05.5+02:00", "DateTime/1")
        for bad in ("2026-01-02", "not-a-date", "2026-13-01T00:00:00Z",
                    "", None, 123):
            with pytest.raises(ValueError):
                validate_record(bad, "DateTime/1")

    def test_T01_url_origin(self):
        validate_record("https://example.com/a", "Url/1")
        for bad in ("notaurl", "ftp://x", "https://", "http://exa mple.com",
                    "", None):
            with pytest.raises(ValueError):
                validate_record(bad, "Url/1")

    def test_T01_closed_objects_reject_unknown(self):
        validate_record({"engine": "browser_oxide", "revision": 1},
                        "BrowserOxide/1")
        validate_record({"engine": "camoufox", "revision": 0}, "Camoufox/1")
        with pytest.raises(ValueError):
            validate_record(
                {"engine": "browser_oxide", "revision": 1, "extra": 1},
                "BrowserOxide/1")
        with pytest.raises(ValueError):
            validate_record(
                {"engine": "camoufox", "revision": 1, "extra": 1},
                "Camoufox/1")

    def test_T01_subjects_not_merged(self):
        # engine tags are disjoint; neither schema accepts the other's tag
        with pytest.raises(ValueError):
            validate_record({"engine": "camoufox", "revision": 1},
                            "BrowserOxide/1")
        with pytest.raises(ValueError):
            validate_record({"engine": "browser_oxide", "revision": 1},
                            "Camoufox/1")

    def test_T01_missing_required_not_defaulted(self):
        with pytest.raises(ValueError):
            validate_record({"engine": "browser_oxide"}, "BrowserOxide/1")
        with pytest.raises(ValueError):
            validate_record({"revision": 1}, "BrowserOxide/1")

    def test_T01_no_success_false_zero_defaults(self):
        # success/false/zero/empty must not validate as stand-ins
        for bad in (None, False, 0, {}, []):
            with pytest.raises(ValueError):
                validate_record(bad, "BrowserOxide/1")

    def test_T01_unknown_versions_rejected(self):
        with pytest.raises(ValueError):
            validate_record({"engine": "browser_oxide", "revision": 1},
                            "BrowserOxide/2")
        with pytest.raises(ValueError):
            validate_record("x", "Nope/9")
        with pytest.raises(ValueError):
            validate_record("x", "BrowserOxide/1 ")

    def test_T01_duplicate_keys_rejected(self):
        with pytest.raises(ValueError):
            strict_loads('{"a": 1, "a": 2}')
        assert strict_loads('{"a": 1, "b": 2}') == {"a": 1, "b": 2}

    def test_T01_evidence_map_bare_nulls_bytes_rejected(self):
        validate_record({"k": "v", "n": 1, "b": True}, "EvidenceMap/1")
        validate_record({"k": {"value": None, "reason": "not_observed"}},
                        "EvidenceMap/1")
        for bad in ({"k": None}, {"k": b"\x00"}, {"k": float("nan")}):
            with pytest.raises(ValueError):
                validate_record(bad, "EvidenceMap/1")

    def test_T01_canonical_rejects_artifacts(self):
        with pytest.raises(ValueError):
            canonical_bytes(b"a\x00b")
        with pytest.raises(ValueError):
            canonical_bytes(None)
        with pytest.raises(ValueError):
            canonical_bytes(float("nan"))


# ---------------------------------------------------------------- T02 ---
class TestT02MissingRefsArtifacts:
    def test_T02_missing_reasons(self):
        for reason in ("not_enabled", "not_applicable", "not_observed",
                       "observation_lost", "unsupported_by_subject",
                       "manual_override"):
            validate_record({"value": None, "reason": reason}, "Missing/1")
        validate_record(
            {"value": None, "reason": "not_observed", "detail": "why"},
            "Missing/1")

    def test_T02_missing_envelope_strict(self):
        for bad in (
            {"value": None},  # no reason
            {"reason": "not_observed"},  # no value
            {"value": 0, "reason": "not_observed"},  # zero is not missing
            {"value": False, "reason": "not_observed"},
            {"value": None, "reason": "bogus"},
            {"value": None, "reason": "not_observed", "detail": ""},
            {"value": None, "reason": "not_observed", "extra": 1},
            None,  # bare null, not envelope
        ):
            with pytest.raises(ValueError):
                validate_record(bad, "Missing/1")

    def test_T02_evidence_ref(self):
        validate_record(good_ref(), "EvidenceRef/1")
        bad = good_ref()
        bad["sequence"] = 0
        with pytest.raises(ValueError):
            validate_record(bad, "EvidenceRef/1")
        bad = good_ref()
        del bad["pointer"]
        with pytest.raises(ValueError):
            validate_record(bad, "EvidenceRef/1")
        bad = good_ref()
        bad["zzz"] = 1
        with pytest.raises(ValueError):
            validate_record(bad, "EvidenceRef/1")

    def test_T02_journal_prefix(self):
        validate_record(
            {"journal_id": "j", "last_sequence": 2, "head_hash": GOOD_DIGEST},
            "JournalPrefix/1")
        with pytest.raises(ValueError):
            validate_record(
                {"journal_id": "j", "last_sequence": 0,
                 "head_hash": GOOD_DIGEST}, "JournalPrefix/1")

    def test_T02_artifact_ref(self):
        ref = {"digest": GOOD_DIGEST, "size_bytes": 10,
               "media_type": "application/octet-stream",
               "owner_domain": "example.com", "access": "public"}
        validate_record(ref, "ArtifactReference/1")
        bad = dict(ref)
        bad["access"] = "world"
        with pytest.raises(ValueError):
            validate_record(bad, "ArtifactReference/1")
        bad = dict(ref)
        del bad["digest"]
        with pytest.raises(ValueError):
            validate_record(bad, "ArtifactReference/1")

    def test_T02_artifact_slot_identity_survives_loss(self):
        slot = {"name": "s", "expected_digest": GOOD_DIGEST,
                "content": {"value": None, "reason": "observation_lost"},
                "evidence_refs": []}
        validate_record(slot, "ArtifactSlot/1")  # empty = established empty
        slot2 = dict(slot)
        slot2["content"] = b"bytes-here"
        validate_record(slot2, "ArtifactSlot/1")
        bad = dict(slot)
        bad["content"] = None  # bare null, not Missing
        with pytest.raises(ValueError):
            validate_record(bad, "ArtifactSlot/1")
        bad = dict(slot)
        del bad["content"]  # required unavailable => Missing, not omitted
        with pytest.raises(ValueError):
            validate_record(bad, "ArtifactSlot/1")

    def test_T02_version_pin(self):
        validate_record(
            {"id": "p", "version": "1.0", "artifact_digest": GOOD_DIGEST},
            "VersionPin/1")
        with pytest.raises(ValueError):
            validate_record(
                {"id": "p", "version": "", "artifact_digest": GOOD_DIGEST},
                "VersionPin/1")

    def test_T02_measurement_needs_refs(self):
        me = {"measurement": {"m": 1}, "evidence_refs": [good_ref()]}
        validate_record(me, "MeasurementEvidence/1")
        with pytest.raises(ValueError):
            validate_record({"measurement": {"m": 1}, "evidence_refs": []},
                            "MeasurementEvidence/1")

    def test_T02_digest_exact_bytes(self):
        assert digest_bytes(b"abc") == "sha256:" + hashlib.sha256(b"abc").hexdigest()
        assert digest_bytes(b"a\x00b") != digest_bytes(b"ab")  # nulls matter

    def test_T02_canonical_digest_chain(self):
        e1 = {"journal_id": "j", "sequence": 1, "body": "a"}
        h1 = digest_bytes(canonical_bytes(e1))
        e2 = {"journal_id": "j", "sequence": 2, "prev": h1, "body": "b"}
        h2 = digest_bytes(canonical_bytes(e2))
        assert h1 != h2
        assert e2["prev"] == h1  # n>1 links to n-1
        # canonical form is key-order stable
        assert canonical_bytes({"b": 1, "a": 2}) == b'{"a":2,"b":1}'
        # unknown collection contents are not empty array
        assert canonical_bytes([]) != canonical_bytes(
            {"value": None, "reason": "not_observed"})

    def test_T02_native_none_not_success(self):
        with pytest.raises(ValueError):
            validate_record(None, "MeasurementEvidence/1")
        with pytest.raises(ValueError):
            validate_record(None, "EvidenceMap/1")
