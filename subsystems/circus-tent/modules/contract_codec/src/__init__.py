"""contract_codec: scalar/structural validation, canonical JSON, digests.

Seam mapping sections 3.1, 3.2, 3.5.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from urllib.parse import urlparse

MAX_SAFE_INT = 9007199254740991

NULL_REASONS = frozenset({
    "not_enabled",
    "not_applicable",
    "not_observed",
    "observation_lost",
    "unsupported_by_subject",
    "manual_override",
})

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATETIME_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

# Distinct closed schemas for the two native subjects. Deliberately NOT merged
# into a shared primitive schema (see FORBIDDEN boundary constraint).
_BROWSER_OXIDE_FIELDS = frozenset({"engine", "revision"})
_CAMOUFOX_FIELDS = frozenset({"engine", "revision"})

_EVIDENCE_REF_FIELDS = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
)
_JOURNAL_PREFIX_FIELDS = frozenset({"journal_id", "last_sequence", "head_hash"})
_ARTIFACT_REF_FIELDS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
_ARTIFACT_SLOT_FIELDS = frozenset(
    {"name", "expected_digest", "content", "evidence_refs"}
)
_VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_MEASUREMENT_FIELDS = frozenset({"measurement", "evidence_refs"})
_MISSING_FIELDS = frozenset({"value", "reason", "detail"})


class ContractError(ValueError):
    """Raised for any contract validation failure."""


def digest_bytes(content: bytes) -> str:
    """Return ``sha256:<hex>`` digest of exact stored bytes."""
    if not isinstance(content, (bytes, bytearray)):
        raise ContractError("digest_bytes requires bytes")
    return "sha256:" + hashlib.sha256(bytes(content)).hexdigest()


def canonical_bytes(value: object) -> bytes:
    """RFC 8785-style canonical JSON bytes.

    Rejects bare nulls (``None``), non-finite numbers, ``bytes``
    (artifacts, possibly containing literal nulls), and non-str keys.
    """
    _check_canonicalizable(value)
    text = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return text.encode("utf-8")


def _is_missing_envelope(value: object) -> bool:
    return (
        isinstance(value, dict)
        and "value" in value
        and value.get("value") is None
        and "reason" in value
    )


def _check_missing_envelope(value: dict) -> None:
    unknown = set(value.keys()) - {"value", "reason", "detail"}
    if unknown:
        raise ContractError(f"bad Missing envelope keys: {sorted(unknown)}")
    if value["reason"] not in NULL_REASONS:
        raise ContractError("bad Missing reason")
    if "detail" in value:
        detail = value["detail"]
        if not isinstance(detail, str) or not detail:
            raise ContractError("bad Missing detail")


def _check_canonicalizable(value: object) -> None:
    if value is None:
        raise ContractError("bare null rejected; use Missing envelope")
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        # allow_nan=False in dumps also guards, but fail fast with ValueError
        if value != value or value in (float("inf"), float("-inf")):
            raise ContractError("non-finite number rejected")
        return
    if isinstance(value, str):
        return
    if isinstance(value, (bytes, bytearray)):
        raise ContractError("native bytes are artifacts; not inline JSON")
    if isinstance(value, (list, tuple)):
        for item in value:
            _check_canonicalizable(item)
        return
    if isinstance(value, dict):
        if _is_missing_envelope(value):
            _check_missing_envelope(value)
            return
        for key, item in value.items():
            if not isinstance(key, str):
                raise ContractError("non-string mapping key rejected")
            _check_canonicalizable(item)
        return
    raise ContractError(f"non-JSON-compatible type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# scalar helpers
# ---------------------------------------------------------------------------

def _require_identifier(value: object, field: str) -> None:
    if not isinstance(value, str) or not value:
        raise ContractError(f"{field}: Identifier must be nonempty string")


def _require_revision(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{field}: Revision must be integer")
    if not 0 <= value <= MAX_SAFE_INT:
        raise ContractError(f"{field}: Revision out of bounds")


def _require_positive_int(value: object, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{field}: PositiveInteger must be integer")
    if not 1 <= value <= MAX_SAFE_INT:
        raise ContractError(f"{field}: PositiveInteger out of bounds")


def _require_digest(value: object, field: str) -> None:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ContractError(f"{field}: Digest must match sha256:<64 hex>")


def _require_datetime(value: object, field: str) -> None:
    if not isinstance(value, str) or not _DATETIME_RE.match(value):
        raise ContractError(f"{field}: Date-time format invalid")
    probe = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        datetime.fromisoformat(probe)
    except ValueError:
        raise ContractError(f"{field}: Date-time calendar invalid")


def _require_url(value: object, field: str) -> None:
    if not isinstance(value, str) or not value or any(
        ch.isspace() for ch in value
    ):
        raise ContractError(f"{field}: URL invalid")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ContractError(f"{field}: URL/origin not authorized form")


def _require_number(value: object, field: str) -> None:
    if isinstance(value, bool):
        raise ContractError(f"{field}: boolean is not numeric")
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise ContractError(f"{field}: numeric out of bounds")
        return
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ContractError(f"{field}: non-finite number rejected")
        if abs(value) > float(MAX_SAFE_INT):
            raise ContractError(f"{field}: numeric out of bounds")
        return
    raise ContractError(f"{field}: not numeric")


def _reject_unknown(value: dict, allowed: frozenset, schema: str) -> None:
    unknown = set(value.keys()) - set(allowed)
    if unknown:
        raise ContractError(f"{schema}: unknown properties {sorted(unknown)}")


def _require_missing(value: object, field: str = "missing") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: Missing must be an object")
    _reject_unknown(value, _MISSING_FIELDS, "Missing")
    if "value" not in value or "reason" not in value:
        raise ContractError(f"{field}: Missing requires value+reason")
    if value["value"] is not None:
        raise ContractError(f"{field}: Missing value must be null")
    if value["reason"] not in NULL_REASONS:
        raise ContractError(f"{field}: unknown NullReason")
    if "detail" in value:
        detail = value["detail"]
        if not isinstance(detail, str) or not detail:
            raise ContractError(f"{field}: detail must be nonempty string")


def _require_evidence_value(value: object, field: str) -> None:
    if value is None:
        raise ContractError(f"{field}: bare null; use Missing")
    if isinstance(value, bool):
        return
    if isinstance(value, (int, float)):
        _require_number(value, field)
        return
    if isinstance(value, str):
        return
    if isinstance(value, (bytes, bytearray)):
        raise ContractError(f"{field}: bytes are artifacts")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _require_evidence_value(item, f"{field}[{i}]")
        return
    if isinstance(value, dict):
        if set(value.keys()) == {"value", "reason"} or (
            set(value.keys()) <= {"value", "reason", "detail"}
            and "reason" in value
            and value.get("value") is None
        ):
            _require_missing(value, field)
            return
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ContractError(f"{field}: bad evidence key")
            _require_evidence_value(item, f"{field}.{key}")
        return
    raise ContractError(f"{field}: non-evidence type")


def _require_evidence_map(value: object, field: str = "evidence") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: EvidenceMap must be object")
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ContractError(f"{field}: bad evidence key")
        _require_evidence_value(item, f"{field}.{key}")


def _require_evidence_ref(value: object, field: str = "evidence_ref") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: EvidenceRef must be object")
    _reject_unknown(value, _EVIDENCE_REF_FIELDS, "EvidenceRef")
    for key in ("journal_id", "sequence", "event_id", "event_hash", "pointer"):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_identifier(value["journal_id"], f"{field}.journal_id")
    _require_positive_int(value["sequence"], f"{field}.sequence")
    _require_identifier(value["event_id"], f"{field}.event_id")
    _require_digest(value["event_hash"], f"{field}.event_hash")
    pointer = value["pointer"]
    if not isinstance(pointer, str) or not (
        pointer == "" or pointer.startswith("/")
    ):
        raise ContractError(f"{field}.pointer: bad JSON pointer")


def _require_journal_prefix(value: object, field: str = "prefix") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: JournalPrefix must be object")
    _reject_unknown(value, _JOURNAL_PREFIX_FIELDS, "JournalPrefix")
    for key in ("journal_id", "last_sequence", "head_hash"):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_identifier(value["journal_id"], f"{field}.journal_id")
    _require_positive_int(value["last_sequence"], f"{field}.last_sequence")
    _require_digest(value["head_hash"], f"{field}.head_hash")


def _require_artifact_ref(value: object, field: str = "artifact") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: ArtifactReference must be object")
    _reject_unknown(value, _ARTIFACT_REF_FIELDS, "ArtifactReference")
    for key in (
        "digest",
        "size_bytes",
        "media_type",
        "owner_domain",
        "access",
    ):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_digest(value["digest"], f"{field}.digest")
    size = value["size_bytes"]
    if isinstance(size, bool) or not isinstance(size, int):
        raise ContractError(f"{field}.size_bytes: must be integer")
    if not 0 <= size <= MAX_SAFE_INT:
        raise ContractError(f"{field}.size_bytes: out of bounds")
    if not isinstance(value["media_type"], str) or "/" not in value["media_type"]:
        raise ContractError(f"{field}.media_type: invalid")
    _require_identifier(value["owner_domain"], f"{field}.owner_domain")
    if value["access"] not in ("public", "restricted"):
        raise ContractError(f"{field}.access: must be public|restricted")


def _require_artifact_slot(value: object, field: str = "slot") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: ArtifactSlot must be object")
    _reject_unknown(value, _ARTIFACT_SLOT_FIELDS, "ArtifactSlot")
    for key in ("name", "expected_digest", "content", "evidence_refs"):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_identifier(value["name"], f"{field}.name")
    _require_digest(value["expected_digest"], f"{field}.expected_digest")
    content = value["content"]
    if isinstance(content, dict) and content.get("value") is None:
        _require_missing(content, f"{field}.content")
    elif not isinstance(content, (bytes, bytearray)):
        raise ContractError(f"{field}.content: bytes or Missing required")
    refs = value["evidence_refs"]
    if not isinstance(refs, list):
        raise ContractError(f"{field}.evidence_refs: must be array")
    for i, ref in enumerate(refs):
        _require_evidence_ref(ref, f"{field}.evidence_refs[{i}]")


def _require_version_pin(value: object, field: str = "pin") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: VersionPin must be object")
    _reject_unknown(value, _VERSION_PIN_FIELDS, "VersionPin")
    for key in ("id", "version", "artifact_digest"):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_identifier(value["id"], f"{field}.id")
    if not isinstance(value["version"], str) or not value["version"]:
        raise ContractError(f"{field}.version: nonempty string required")
    _require_digest(value["artifact_digest"], f"{field}.artifact_digest")


def _require_measurement(value: object, field: str = "measurement_ev") -> None:
    if not isinstance(value, dict):
        raise ContractError(f"{field}: MeasurementEvidence must be object")
    _reject_unknown(value, _MEASUREMENT_FIELDS, "MeasurementEvidence")
    for key in ("measurement", "evidence_refs"):
        if key not in value:
            raise ContractError(f"{field}: missing required {key}")
    _require_evidence_map(value["measurement"], f"{field}.measurement")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not refs:
        raise ContractError(f"{field}.evidence_refs: nonempty array required")
    for i, ref in enumerate(refs):
        _require_evidence_ref(ref, f"{field}.evidence_refs[{i}]")


# ---------------------------------------------------------------------------
# public dispatch
# ---------------------------------------------------------------------------

_VALIDATORS = {
    "Missing/1": _require_missing,
    "EvidenceMap/1": _require_evidence_map,
    "EvidenceRef/1": _require_evidence_ref,
    "JournalPrefix/1": _require_journal_prefix,
    "ArtifactReference/1": _require_artifact_ref,
    "ArtifactSlot/1": _require_artifact_slot,
    "VersionPin/1": _require_version_pin,
    "MeasurementEvidence/1": _require_measurement,
    "Identifier/1": lambda v, f="value": _require_identifier(v, f),
    "Revision/1": lambda v, f="value": _require_revision(v, f),
    "PositiveInteger/1": lambda v, f="value": _require_positive_int(v, f),
    "Digest/1": lambda v, f="value": _require_digest(v, f),
    "DateTime/1": lambda v, f="value": _require_datetime(v, f),
    "Url/1": lambda v, f="value": _require_url(v, f),
    "Number/1": lambda v, f="value": _require_number(v, f),
}


def _validate_browser_oxide(value: object) -> None:
    if not isinstance(value, dict):
        raise ContractError("BrowserOxide: must be object")
    _reject_unknown(value, _BROWSER_OXIDE_FIELDS, "BrowserOxide")
    if "engine" not in value or "revision" not in value:
        raise ContractError("BrowserOxide: engine+revision required")
    if value["engine"] != "browser_oxide":
        raise ContractError("BrowserOxide: engine tag mismatch")
    _require_revision(value["revision"], "BrowserOxide.revision")


def _validate_camoufox(value: object) -> None:
    if not isinstance(value, dict):
        raise ContractError("Camoufox: must be object")
    _reject_unknown(value, _CAMOUFOX_FIELDS, "Camoufox")
    if "engine" not in value or "revision" not in value:
        raise ContractError("Camoufox: engine+revision required")
    if value["engine"] != "camoufox":
        raise ContractError("Camoufox: engine tag mismatch")
    _require_revision(value["revision"], "Camoufox.revision")


_VALIDATORS["BrowserOxide/1"] = lambda v, f="value": _validate_browser_oxide(v)
_VALIDATORS["Camoufox/1"] = lambda v, f="value": _validate_camoufox(v)


def validate_record(value: object, schema_id: str) -> None:
    """Validate ``value`` against versioned ``schema_id``.

    Raises :class:`ContractError` (a ``ValueError``) on any violation,
    including unknown schema versions. Never fills defaults.
    """
    try:
        validator = _VALIDATORS[schema_id]
    except (KeyError, TypeError):
        raise ContractError(f"unknown schema version: {schema_id!r}")
    validator(value)


__all__ = [
    "ContractError",
    "MAX_SAFE_INT",
    "NULL_REASONS",
    "canonical_bytes",
    "digest_bytes",
    "validate_record",
]
