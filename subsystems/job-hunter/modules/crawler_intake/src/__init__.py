"""crawler_intake: read-only admission of crawler LogicalRows to evaluation input.

Implements the Job Hunter obligations for consuming a crawler-backed
``W.LogicalRow`` (seam mapping 5.1) and transforming it into a pinned,
read-only evaluation input (seam mapping 5.3 / 5.4 / 5.5).

The module never writes a crawler acquisition, processing, classification,
discovery, lease, or replacement field, and it never publishes a downstream
product decision.  It verifies the row and its complete crawler document, then
produces :class:`EvaluationJobInput` pinning:

* the exact crawler revision and published document digest,
* the retained logical-row artifact and its crawler publication evidence,
* the canonical ``JobContent`` fields with typed missingness preserved,
* the crawler render verdict / pipeline state,
* the genuine classifier result (or the bypass reason), and
* every coverage reference status plus an explicit completeness answer.

Explicit rejection codes (``code`` on each error):

``incomplete_extraction``
    A render ``Pass`` acquisition whose declared required content is absent,
    mistyped, or undeclared.  It is never materialized as a valid job.
``failed_render_as_usable``
    A non-Pass acquisition presented as usable content: ``pipeline_state`` is
    not ``render_failed``, a content value is not reasoned ``Missing``, or the
    acquisition carries a classifier result.
``bypass_as_genuine``
    A bypassed classification presented as a genuine classifier pass, or a
    result other than raw ``PASS`` applied ``PASS`` named as the genuine result
    (shadow-mode ``VETO`` applied ``PASS`` stays distinguishable).
``coverage_not_proven``
    Coverage presented as proven/complete although its status is not
    ``proven`` -- ``empty_unproven`` never proves emptiness.
``same_fetch_key_conflict``
    A same-fetch-key acquisition change.  The prior acquisition is preserved
    and the differing response is retained as an observation, never installed
    as a replacement.
``replacement_required``
    A changed fetch key without a complete verified prior-row archive.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import json
import math
import re
import sys
import threading
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _load_sibling(name: str):
    """Import a sibling module, falling back to its in-tree source path."""
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = (
        Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
    )
    spec = importlib.util.spec_from_file_location(name, sibling_path)
    if spec is None or spec.loader is None:  # pragma: no cover - import plumbing
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")
read_publications = _load_sibling("read_publications")
archive_retention = _load_sibling("archive_retention")


def _load_optional_sibling(name: str):
    try:
        return _load_sibling(name)
    except Exception:  # pragma: no cover - optional read-only introspection
        return None


access_policy = _load_optional_sibling("access_policy")

__all__ = [
    "SCHEMA_VERSION",
    "INTAKE_EVENT_KIND",
    "INTAKE_EVENT_SCHEMA_VERSION",
    "INTAKE_OWNER_FALLBACK",
    "INTAKE_OBSERVATION_RECORD_TYPE",
    "CORE_CONTENT_FIELDS",
    "DECLARATION_TYPES",
    "RENDER_VERDICTS",
    "PIPELINE_STATES",
    "COVERAGE_STATUSES",
    "PASS",
    "RENDER_FAILED",
    "CrawlerIntakeError",
    "RowAdmissionError",
    "IncompleteExtractionError",
    "UnusableContentError",
    "BypassAsGenuineError",
    "CoverageNotProvenError",
    "SameFetchKeyConflictError",
    "ReplacementRequiredError",
    "EvaluationJobInput",
    "accept_job_row",
    "observations",
    "reset_for_tests",
]

SCHEMA_VERSION = read_publications.SCHEMA_VERSION

INTAKE_EVENT_KIND = "crawler_intake.observation_recorded"
INTAKE_EVENT_SCHEMA_VERSION = "1"
INTAKE_OBSERVATION_RECORD_TYPE = "crawler_intake_observation"
INTAKE_OWNER_FALLBACK = "job.downstream"

PASS = "Pass"
RENDER_FAILED = "render_failed"

CORE_CONTENT_FIELDS: tuple[str, ...] = (
    "title",
    "employer",
    "snippet",
    "description",
    "posted_date",
    "location",
    "direct_apply_url",
    "portal_type",
    "closing_date",
)

DECLARATION_TYPES = frozenset(
    {
        "string",
        "text",
        "date",
        "url",
        "number",
        "boolean",
        "salary",
        "requirements",
    }
)

RENDER_VERDICTS = frozenset(
    {
        PASS,
        "ThinShell",
        "RenderIncomplete",
        "EdgeBlock",
        "SensorFail",
        "ChallengeIncomplete",
    }
)

PIPELINE_STATES = frozenset(
    {"pending_classification", "ready", "vetoed", RENDER_FAILED, "failed"}
)

COVERAGE_STATUSES = frozenset(
    {"open", "bisected", "proven", "incomplete", "empty_unproven"}
)

SEMANTIC_STATES = frozenset({"DISCOVERED", "SHORTLISTED", "CLOSED"})

CLASSIFIER_VERDICTS = frozenset({"PASS", "VETO"})

_ORIGINS = frozenset(
    {"engine_measured", "browser_measured", "subject_reported", "manual_reference"}
)

_MISSING_REASONS = frozenset(getattr(contract_codec, "VALID_MISSING_REASONS", ()))

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_POINTER_RE = re.compile(r"^(?:/(?:[^~/]|~[01])*)*$")

_MAX_REVISION = 9007199254740991

_DOCUMENT_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "entity",
        "registration_digest",
        "domain",
        "owner_domain",
        "writer_id",
        "revision",
        "previous_revision",
        "evidence_prefix",
        "evidence_refs",
        "value",
    }
)
_ROW_FIELDS = frozenset(
    {
        "record_type",
        "schema_version",
        "entity",
        "registration_digest",
        "registration",
        "domains",
        "seal_point",
    }
)
_VALUE_FIELDS = frozenset(
    {"acquisition", "processing", "discovery", "replacement_lineage"}
)
_ACQUISITION_FIELDS = frozenset(
    {
        "source_url",
        "listing_page_url",
        "fetch_key",
        "fetch_key_profile",
        "fetch_identity",
        "source_response",
        "extractor",
        "content_declarations",
        "content",
        "render_verdict",
        "render_basis",
        "render_history",
        "rendered_at",
        "evidence_refs",
    }
)
_PROCESSING_FIELDS = frozenset(
    {
        "pipeline_state",
        "classification_surface",
        "active_run_id",
        "input_revision",
        "generation_id",
        "lease",
        "retry_count",
        "max_retries_effective",
        "last_failure_reason",
        "classifier_results",
        "final_genuine_result_id",
        "bypass_reason",
        "semantic_candidate",
        "semantic_evidence_refs",
    }
)
_DISCOVERY_FIELDS = frozenset(
    {
        "first_seen_run_id",
        "last_seen_run_id",
        "first_seen_at",
        "last_seen_at",
        "coverage",
    }
)
_COVERAGE_FIELDS = frozenset(
    {
        "run_id",
        "partition_id",
        "partition_definition_hash",
        "status",
        "pagination_coverage_proven",
        "ledger",
        "evidence_refs",
    }
)
_DECLARATION_FIELDS = frozenset(
    {"name", "type", "required", "nullable", "extraction_binding"}
)
_EXTENDED_FIELDS = frozenset({"name", "type", "value"})
_RENDER_OBSERVATION_FIELDS = frozenset(
    {"transport", "operation", "verdict", "basis", "response_hash", "evidence_refs", "measurements"}
)
_CLASSIFIER_FIELDS = frozenset(
    {
        "result_id",
        "stage",
        "model",
        "tokenizer_digest",
        "prompt_digest",
        "canonicalization_version",
        "input_hash",
        "verdict",
        "verdict_applied",
        "confidence",
        "reason",
        "classified_at",
        "latency",
        "application_revision",
        "policy_revision",
        "evidence_refs",
    }
)
_LINEAGE_FIELDS = frozenset(
    {"replacement_id", "prior_crawler_revision", "archive_root"}
)
_TIME_POINT_FIELDS = frozenset(
    {"clock_id", "boot_id", "origin", "monotonic_offset_ms", "utc_annotation"}
)
_PREFIX_FIELDS = frozenset({"journal_id", "last_sequence", "head_hash"})
_EVIDENCE_REF_FIELDS = frozenset(
    {"journal_id", "sequence", "event_id", "event_hash", "pointer"}
)
_VERSION_PIN_FIELDS = frozenset({"id", "version", "artifact_digest"})
_ARTIFACT_FIELDS = frozenset(
    {"digest", "size_bytes", "media_type", "owner_domain", "access"}
)
_FETCH_IDENTITY_FIELDS = frozenset(
    {
        "phase_token",
        "listing_source_url",
        "canonical_url",
        "method",
        "request_body_digest",
        "representation_headers",
    }
)
_MEASUREMENT_FIELDS = frozenset({"measurement", "evidence_refs"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CrawlerIntakeError(Exception):
    """Base class for crawler-intake contract violations."""

    code = "crawler_intake_error"

    def __init__(self, message: str) -> None:
        self.message = str(message)
        super().__init__(f"{self.code}: {self.message}")


class RowAdmissionError(CrawlerIntakeError, ValueError):
    """The row, its registration, or its crawler document is not admissible."""

    code = "row_admission"


class IncompleteExtractionError(CrawlerIntakeError, ValueError):
    """A render Pass lacks required, correctly typed declared content."""

    code = "incomplete_extraction"


class UnusableContentError(CrawlerIntakeError, ValueError):
    """A failed render was presented as usable content."""

    code = "failed_render_as_usable"


class BypassAsGenuineError(CrawlerIntakeError, ValueError):
    """A bypassed or shadow classification was presented as a genuine pass."""

    code = "bypass_as_genuine"


class CoverageNotProvenError(CrawlerIntakeError, ValueError):
    """Unproven coverage was presented as proven or complete."""

    code = "coverage_not_proven"


class SameFetchKeyConflictError(CrawlerIntakeError):
    """A same-fetch-key acquisition change; the prior acquisition is preserved.

    ``observation_retained`` records whether the differing response was
    durably retained as an observation before this rejection.
    """

    code = "same_fetch_key_conflict"

    def __init__(self, message: str, *, observation_retained: bool) -> None:
        self.observation_retained = bool(observation_retained)
        super().__init__(message)


class ReplacementRequiredError(CrawlerIntakeError):
    """A changed fetch key without a complete verified prior-row archive."""

    code = "replacement_required"


# ---------------------------------------------------------------------------
# Module-local admission state (one process, no shared database writes)
# ---------------------------------------------------------------------------

_LOCK = threading.RLock()

# entity_key -> {"fetch_key", "acquisition_digest", "revision", "record_digest"}
_SEEN: dict[tuple[str, str], dict[str, Any]] = {}
# entity_key -> {crawler_revision: document_digest}
_SEEN_REVISIONS: dict[tuple[str, str], dict[int, str]] = {}
# Retained same-fetch-key observations, newest last.
_OBSERVATIONS: list[dict[str, Any]] = []


def reset_for_tests() -> None:
    """Drop process-local admission state (test isolation only)."""
    with _LOCK:
        _SEEN.clear()
        _SEEN_REVISIONS.clear()
        _OBSERVATIONS.clear()


def observations(channel_id: str | None = None) -> tuple[dict[str, Any], ...]:
    """Return retained same-fetch-key observations (fresh copies)."""
    with _LOCK:
        entries = [
            _copy_json(entry)
            for entry in _OBSERVATIONS
            if channel_id is None or entry.get("channel_id") == channel_id
        ]
    return tuple(entries)


# ---------------------------------------------------------------------------
# Canonical JSON, digests, and strict gate
# ---------------------------------------------------------------------------


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _byte_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _digest(value: Any) -> str:
    return _byte_digest(_canonical_bytes(value))


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, item in pairs:
        if key in obj:
            raise ValueError(f"duplicate mapping key: {key!r}")
        obj[key] = item
    return obj


def _reject_nonfinite(token: str) -> Any:
    raise ValueError(f"non-finite number rejected: {token!r}")


def _is_missing(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and "value" in value
        and "reason" in value
        and value.get("value") is None
    )


def _validate_missing(value: Any, where: str) -> dict[str, Any]:
    data = _require_mapping(value, where)
    extra = set(data.keys()) - {"value", "reason", "detail"}
    if extra:
        raise RowAdmissionError(
            f"{where}: undeclared Missing properties {sorted(extra)}"
        )
    if data.get("value") is not None:
        raise RowAdmissionError(f"{where}: Missing.value must be null")
    reason = data.get("reason")
    if reason not in _MISSING_REASONS:
        raise RowAdmissionError(f"{where}: unknown Missing reason {reason!r}")
    if "detail" in data:
        detail = data["detail"]
        if not isinstance(detail, str) or not detail:
            raise RowAdmissionError(
                f"{where}: Missing.detail must be a nonempty string"
            )
    return dict(data)


def _check_no_bare_null(node: Any, path: str) -> None:
    if isinstance(node, Mapping):
        if _is_missing(node):
            _validate_missing(node, path)
            return
        for key, item in node.items():
            if item is None:
                raise RowAdmissionError(
                    f"bare null rejected at {path}.{key}; use a typed Missing envelope"
                )
            _check_no_bare_null(item, f"{path}.{key}")
    elif isinstance(node, list):
        for index, item in enumerate(node):
            if item is None:
                raise RowAdmissionError(
                    f"bare null rejected at {path}[{index}]; use a typed Missing envelope"
                )
            _check_no_bare_null(item, f"{path}[{index}]")


def _strict_gate(raw: bytes, context: str) -> Any:
    """Parse canonical JSON bytes, rejecting duplicates, nonfinite and nulls."""
    if not isinstance(raw, bytes):
        raise RowAdmissionError(f"{context} must be exact bytes")
    try:
        parsed = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise RowAdmissionError(f"{context} is not strict JSON: {exc}") from exc
    _check_no_bare_null(parsed, context)
    if _canonical_bytes(parsed) != raw:
        raise RowAdmissionError(
            f"{context} is not a canonical complete document; "
            "the published bytes must be exactly the canonical encoding"
        )
    return parsed


# ---------------------------------------------------------------------------
# Primitive validators
# ---------------------------------------------------------------------------


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise RowAdmissionError(
            f"{where} must be a JSON object, not {type(value).__name__}"
        )
    return dict(value)


def _closed(value: Any, allowed: frozenset[str], where: str) -> dict[str, Any]:
    data = _require_mapping(value, where)
    if set(data.keys()) != set(allowed):
        raise RowAdmissionError(
            f"{where} must contain exactly {sorted(allowed)}; "
            f"got {sorted(data.keys())}"
        )
    return data


def _require_identifier(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise RowAdmissionError(
            f"{where} must be a string identifier, not {type(value).__name__}"
        )
    if not value or value != value.strip():
        raise RowAdmissionError(f"{where} must be a nonempty unpadded identifier")
    if len(value) > 256:
        raise RowAdmissionError(f"{where} must be at most 256 characters")
    if "\x00" in value or any(ord(char) < 0x20 for char in value):
        raise RowAdmissionError(f"{where} must not contain control characters")
    return value


def _require_digest(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise RowAdmissionError(
            f"{where} must be a sha256:<64 lowercase hex> digest"
        )
    return value


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_number(value: Any, where: str) -> float | int:
    if not _is_number(value):
        raise RowAdmissionError(f"{where} must be a finite number")
    if isinstance(value, float) and not math.isfinite(value):
        raise RowAdmissionError(f"{where} must be a finite number")
    return value


def _require_revision(
    value: Any, where: str, *, positive: bool = False
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise RowAdmissionError(f"{where} must be an integer revision")
    minimum = 1 if positive else 0
    if value < minimum or value > _MAX_REVISION:
        raise RowAdmissionError(
            f"{where} must be between {minimum} and {_MAX_REVISION}"
        )
    return value


def _require_bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise RowAdmissionError(f"{where} must be a boolean")
    return value


_URL_SAFE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)


def _require_url(value: Any, where: str) -> str:
    text = _require_identifier(value, where)
    if not _URL_SAFE.match(text):
        raise RowAdmissionError(f"{where} must be an absolute http(s) URL")
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise RowAdmissionError(f"{where} must be an absolute http(s) URL")
    return text


def _validate_evidence_ref(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _EVIDENCE_REF_FIELDS, where)
    _require_identifier(data["journal_id"], f"{where}.journal_id")
    _require_revision(data["sequence"], f"{where}.sequence", positive=True)
    _require_identifier(data["event_id"], f"{where}.event_id")
    _require_digest(data["event_hash"], f"{where}.event_hash")
    pointer = data["pointer"]
    if not isinstance(pointer, str) or not _POINTER_RE.match(pointer):
        raise RowAdmissionError(f"{where}.pointer must be a JSON pointer")
    return data


def _validate_support_refs(
    value: Any, where: str, *, minimum: int = 1
) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise RowAdmissionError(f"{where} must be an array of EvidenceRef")
    refs = tuple(
        _validate_evidence_ref(item, f"{where}[{index}]")
        for index, item in enumerate(value)
    )
    if len(refs) < minimum:
        raise RowAdmissionError(
            f"{where} requires at least {minimum} EvidenceRef"
        )
    if len({_canonical_bytes(ref) for ref in refs}) != len(refs):
        raise RowAdmissionError(f"{where} must not repeat an EvidenceRef")
    return refs


def _validate_artifact_ref(value: Any, where: str) -> dict[str, Any]:
    try:
        return artifact_store.ArtifactReference.from_dict(
            _closed(value, _ARTIFACT_FIELDS, where)
        ).to_dict()
    except RowAdmissionError:
        raise
    except (TypeError, ValueError) as exc:
        raise RowAdmissionError(f"{where} is not an ArtifactReference: {exc}") from exc


def _validate_version_pin(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _VERSION_PIN_FIELDS, where)
    _require_identifier(data["id"], f"{where}.id")
    _require_identifier(data["version"], f"{where}.version")
    _require_digest(data["artifact_digest"], f"{where}.artifact_digest")
    return data


def _validate_time_point(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _TIME_POINT_FIELDS, where)
    _require_identifier(data["clock_id"], f"{where}.clock_id")
    _require_identifier(data["boot_id"], f"{where}.boot_id")
    origin = data["origin"]
    if origin not in _ORIGINS:
        raise RowAdmissionError(
            f"{where}.origin must be one of {sorted(_ORIGINS)}; got {origin!r}"
        )
    _require_number(data["monotonic_offset_ms"], f"{where}.monotonic_offset_ms")
    annotation = data["utc_annotation"]
    if _is_missing(annotation):
        _validate_missing(annotation, f"{where}.utc_annotation")
    else:
        _require_identifier(annotation, f"{where}.utc_annotation")
    return data


def _validate_prefix(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _PREFIX_FIELDS, where)
    _require_identifier(data["journal_id"], f"{where}.journal_id")
    _require_revision(data["last_sequence"], f"{where}.last_sequence", positive=True)
    _require_digest(data["head_hash"], f"{where}.head_hash")
    return data


def _validate_measurement_evidence(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _MEASUREMENT_FIELDS, where)
    measurement = _require_mapping(data["measurement"], f"{where}.measurement")
    if not measurement:
        raise RowAdmissionError(f"{where}.measurement must not be empty")
    _check_no_bare_null(measurement, f"{where}.measurement")
    _require_identifier(
        measurement.get("measurement_id"), f"{where}.measurement.measurement_id"
    )
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    return data


def _validate_render_observation(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _RENDER_OBSERVATION_FIELDS, where)
    _require_identifier(data["transport"], f"{where}.transport")
    _require_identifier(data["operation"], f"{where}.operation")
    verdict = data["verdict"]
    if verdict not in RENDER_VERDICTS:
        raise RowAdmissionError(f"{where}.verdict is not a render observation verdict")
    _require_identifier(data["basis"], f"{where}.basis")
    _require_identifier(data["response_hash"], f"{where}.response_hash")
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    measurements = data["measurements"]
    if isinstance(measurements, (str, bytes)) or not isinstance(measurements, Sequence):
        raise RowAdmissionError(f"{where}.measurements must be an array")
    for index, item in enumerate(measurements):
        _validate_measurement_evidence(item, f"{where}.measurements[{index}]")
    return data


def _validate_fetch_identity(value: Any, where: str, source_url: str) -> dict[str, Any]:
    data = _require_mapping(value, where)
    if not data:
        raise RowAdmissionError(f"{where} must retain the fetch identity basis")
    extra = set(data.keys()) - _FETCH_IDENTITY_FIELDS
    if extra:
        raise RowAdmissionError(f"{where}: undeclared properties {sorted(extra)}")
    for key, item in data.items():
        if key in {"listing_source_url", "canonical_url"}:
            _require_url(item, f"{where}.{key}")
        elif key == "method":
            _require_identifier(item, f"{where}.method")
            if item != item.upper():
                raise RowAdmissionError(f"{where}.method must be uppercase")
        elif key == "request_body_digest":
            _require_digest(item, f"{where}.request_body_digest")
        elif key == "representation_headers":
            headers = _require_mapping(item, f"{where}.representation_headers")
            if not headers:
                raise RowAdmissionError(
                    f"{where}.representation_headers must retain representation headers"
                )
            for header, header_value in headers.items():
                _require_identifier(header, f"{where}.representation_headers key")
                if isinstance(header_value, (list, tuple)):
                    values = list(header_value)
                    if not values:
                        raise RowAdmissionError(
                            f"{where}.representation_headers[{header!r}] must not be empty"
                        )
                    for inner in values:
                        _require_identifier(inner, f"{where}.representation_headers[{header!r}]")
                else:
                    _require_identifier(
                        header_value, f"{where}.representation_headers[{header!r}]"
                    )
        else:
            _require_identifier(item, f"{where}.{key}")
    listing = data.get("listing_source_url")
    if isinstance(listing, str) and listing != source_url:
        raise RowAdmissionError(
            f"{where}.listing_source_url disagrees with acquisition.source_url"
        )
    return data


# ---------------------------------------------------------------------------
# Content contract
# ---------------------------------------------------------------------------


def _validate_declarations(value: Any, where: str) -> tuple[dict[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence) or not value:
        raise RowAdmissionError(f"{where} requires at least one declaration")
    declarations: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        site = f"{where}[{index}]"
        data = _closed(item, _DECLARATION_FIELDS, site)
        _require_identifier(data["name"], f"{site}.name")
        if data["type"] not in DECLARATION_TYPES:
            raise RowAdmissionError(
                f"{site}.type must be one of {sorted(DECLARATION_TYPES)}"
            )
        required = _require_bool(data["required"], f"{site}.required")
        nullable = _require_bool(data["nullable"], f"{site}.nullable")
        if required and nullable:
            raise RowAdmissionError(
                f"{site}: required content cannot be declared nullable"
            )
        _validate_version_pin(data["extraction_binding"], f"{site}.extraction_binding")
        declarations.append(data)
    names = [item["name"] for item in declarations]
    if len(set(names)) != len(names):
        raise RowAdmissionError(f"{where} must not repeat a declared name")
    return tuple(declarations)


def _check_typed_value(value: Any, decl_type: str, where: str) -> Any:
    if decl_type in {"string", "text", "date"}:
        if not isinstance(value, str):
            raise RowAdmissionError(f"{where} must be a string for type {decl_type!r}")
        return value
    if decl_type == "url":
        return _require_url(value, where)
    if decl_type == "number":
        return _require_number(value, where)
    if decl_type == "boolean":
        return _require_bool(value, where)
    if decl_type == "salary":
        salary = _require_mapping(value, where)
        allowed = {"amount", "currency", "period", "text"}
        extra = set(salary.keys()) - allowed
        if extra:
            raise RowAdmissionError(f"{where}: undeclared salary properties {sorted(extra)}")
        if not salary:
            raise RowAdmissionError(f"{where}: a salary extraction requires a value")
        for key, item in salary.items():
            if key == "amount":
                if isinstance(item, bool) or not isinstance(item, (int, float, str)):
                    raise RowAdmissionError(f"{where}.amount must be a number or text")
            else:
                _require_identifier(item, f"{where}.{key}")
        return salary
    if decl_type == "requirements":
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise RowAdmissionError(f"{where} must be an array of requirement strings")
        listed = list(value)
        if not listed:
            raise RowAdmissionError(f"{where} must not be an empty requirements array")
        for index, item in enumerate(listed):
            _require_identifier(item, f"{where}[{index}]")
        return listed
    raise RowAdmissionError(f"{where}: unsupported declaration type {decl_type!r}")


def _validate_content(
    value: Any,
    declarations: tuple[dict[str, Any], ...],
    where: str,
) -> dict[str, Any]:
    data = _require_mapping(value, where)
    expected = set(CORE_CONTENT_FIELDS) | {"extended"}
    if set(data.keys()) != expected:
        raise RowAdmissionError(
            f"{where} must contain exactly the canonical JobContent fields "
            f"{sorted(expected)}; got {sorted(data.keys())}"
        )
    typed: dict[str, tuple[str, Any]] = {
        decl["name"]: (decl["type"], decl["required"]) for decl in declarations
    }
    out: dict[str, Any] = {}
    for field in CORE_CONTENT_FIELDS:
        item = data[field]
        if _is_missing(item):
            out[field] = _validate_missing(item, f"{where}.{field}")
        else:
            # Typing of present values is an extraction-quality question and is
            # decided by _interpret_render_content (Pass vs failed render).
            out[field] = item
    extended = data["extended"]
    if isinstance(extended, (str, bytes)) or not isinstance(extended, Sequence):
        raise RowAdmissionError(f"{where}.extended must be an array")
    items: list[dict[str, Any]] = []
    for index, item in enumerate(extended):
        site = f"{where}.extended[{index}]"
        record = _closed(item, _EXTENDED_FIELDS, site)
        name = _require_identifier(record["name"], f"{site}.name")
        if name in CORE_CONTENT_FIELDS:
            raise RowAdmissionError(
                f"{site}: {name!r} is a canonical field, not an extended extraction"
            )
        declared = typed.get(name)
        if declared is not None and declared[0] != record["type"]:
            raise RowAdmissionError(
                f"{site}.type disagrees with the declared extraction binding"
            )
        if record["type"] not in DECLARATION_TYPES:
            raise RowAdmissionError(
                f"{site}.type must be one of {sorted(DECLARATION_TYPES)}"
            )
        if _is_missing(record["value"]):
            normalized_value = _validate_missing(record["value"], f"{site}.value")
        else:
            normalized_value = record["value"]
        items.append(
            {"name": name, "type": record["type"], "value": normalized_value}
        )
    extended_names = [item["name"] for item in items]
    if len(set(extended_names)) != len(extended_names):
        raise RowAdmissionError(f"{where}.extended must not repeat a name")
    extra_declared = {
        decl["name"] for decl in declarations if decl["name"] not in CORE_CONTENT_FIELDS
    }
    if extra_declared != set(extended_names):
        raise RowAdmissionError(
            f"{where}.extended must exactly represent the declared extended "
            f"fields {sorted(extra_declared)}"
        )
    out["extended"] = items
    return out


def _check_required_value(value: Any, decl_type: str, where: str) -> Any:
    if _is_missing(value):
        raise IncompleteExtractionError(
            f"{where} is required by the declared content contract but is Missing"
        )
    try:
        return _check_typed_value(value, decl_type, where)
    except RowAdmissionError as exc:
        raise IncompleteExtractionError(
            f"{where} is required and must carry correctly typed content: {exc.message}"
        ) from exc


# ---------------------------------------------------------------------------
# Crawler document validation
# ---------------------------------------------------------------------------


def _validate_acquisition(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _ACQUISITION_FIELDS, where)
    source_url = _require_url(data["source_url"], f"{where}.source_url")
    listing = data["listing_page_url"]
    if _is_missing(listing):
        _validate_missing(listing, f"{where}.listing_page_url")
    else:
        _require_url(listing, f"{where}.listing_page_url")
    _require_digest(data["fetch_key"], f"{where}.fetch_key")
    _require_identifier(data["fetch_key_profile"], f"{where}.fetch_key_profile")
    _validate_fetch_identity(data["fetch_identity"], f"{where}.fetch_identity", source_url)
    source_response = data["source_response"]
    if _is_missing(source_response):
        _validate_missing(source_response, f"{where}.source_response")
    else:
        _validate_artifact_ref(source_response, f"{where}.source_response")
    _validate_version_pin(data["extractor"], f"{where}.extractor")
    declarations = _validate_declarations(
        data["content_declarations"], f"{where}.content_declarations"
    )
    content = _validate_content(data["content"], declarations, f"{where}.content")
    verdict = data["render_verdict"]
    if verdict not in RENDER_VERDICTS:
        raise RowAdmissionError(
            f"{where}.render_verdict must be one of {sorted(RENDER_VERDICTS)}"
        )
    _require_identifier(data["render_basis"], f"{where}.render_basis")
    history = data["render_history"]
    if isinstance(history, (str, bytes)) or not isinstance(history, Sequence) or not history:
        raise RowAdmissionError(f"{where}.render_history requires an observation")
    observations_seen = [
        _validate_render_observation(item, f"{where}.render_history[{index}]")
        for index, item in enumerate(history)
    ]
    if observations_seen[-1]["verdict"] != verdict:
        raise RowAdmissionError(
            f"{where}.render_history must end with the observation that "
            f"established render_verdict {verdict!r}"
        )
    _validate_time_point(data["rendered_at"], f"{where}.rendered_at")
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    data = dict(data)
    data["content_declarations"] = list(declarations)
    data["content"] = content
    return data


def _validate_classifier_result(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _CLASSIFIER_FIELDS, where)
    _require_identifier(data["result_id"], f"{where}.result_id")
    _require_identifier(data["stage"], f"{where}.stage")
    _validate_version_pin(data["model"], f"{where}.model")
    _require_digest(data["tokenizer_digest"], f"{where}.tokenizer_digest")
    _require_digest(data["prompt_digest"], f"{where}.prompt_digest")
    _require_identifier(data["canonicalization_version"], f"{where}.canonicalization_version")
    _require_digest(data["input_hash"], f"{where}.input_hash")
    if data["verdict"] not in CLASSIFIER_VERDICTS:
        raise RowAdmissionError(
            f"{where}.verdict must be one of {sorted(CLASSIFIER_VERDICTS)}"
        )
    if data["verdict_applied"] not in CLASSIFIER_VERDICTS:
        raise RowAdmissionError(
            f"{where}.verdict_applied must be one of {sorted(CLASSIFIER_VERDICTS)}"
        )
    confidence = _require_number(data["confidence"], f"{where}.confidence")
    if confidence < 0 or confidence > 1:
        raise RowAdmissionError(f"{where}.confidence must be within [0, 1]")
    _require_identifier(data["reason"], f"{where}.reason")
    _validate_time_point(data["classified_at"], f"{where}.classified_at")
    _validate_measurement_evidence(data["latency"], f"{where}.latency")
    _require_revision(data["application_revision"], f"{where}.application_revision")
    _require_identifier(data["policy_revision"], f"{where}.policy_revision")
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    return data


def _validate_processing(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _PROCESSING_FIELDS, where)
    if data["pipeline_state"] not in PIPELINE_STATES:
        raise RowAdmissionError(
            f"{where}.pipeline_state must be one of {sorted(PIPELINE_STATES)}"
        )
    _require_identifier(data["classification_surface"], f"{where}.classification_surface")
    _require_identifier(data["active_run_id"], f"{where}.active_run_id")
    _require_revision(data["input_revision"], f"{where}.input_revision")
    _require_identifier(data["generation_id"], f"{where}.generation_id")
    lease = data["lease"]
    if _is_missing(lease):
        _validate_missing(lease, f"{where}.lease")
    else:
        lease_value = _require_mapping(lease, f"{where}.lease")
        if not lease_value:
            raise RowAdmissionError(f"{where}.lease must not be an empty object")
        _check_no_bare_null(lease_value, f"{where}.lease")
    retry_count = _require_revision(data["retry_count"], f"{where}.retry_count")
    max_retries = _require_revision(
        data["max_retries_effective"], f"{where}.max_retries_effective"
    )
    if retry_count > max_retries:
        raise RowAdmissionError(
            f"{where}: retry_count cannot exceed max_retries_effective"
        )
    failure = data["last_failure_reason"]
    if _is_missing(failure):
        _validate_missing(failure, f"{where}.last_failure_reason")
    else:
        _require_identifier(failure, f"{where}.last_failure_reason")
    results = data["classifier_results"]
    if isinstance(results, (str, bytes)) or not isinstance(results, Sequence):
        raise RowAdmissionError(f"{where}.classifier_results must be an array")
    normalized_results = [
        _validate_classifier_result(item, f"{where}.classifier_results[{index}]")
        for index, item in enumerate(results)
    ]
    result_ids = [item["result_id"] for item in normalized_results]
    if len(set(result_ids)) != len(result_ids):
        raise RowAdmissionError(
            f"{where}.classifier_results must not repeat a result_id"
        )
    final_id = data["final_genuine_result_id"]
    if _is_missing(final_id):
        _validate_missing(final_id, f"{where}.final_genuine_result_id")
    else:
        _require_identifier(final_id, f"{where}.final_genuine_result_id")
    bypass = data["bypass_reason"]
    if _is_missing(bypass):
        _validate_missing(bypass, f"{where}.bypass_reason")
    else:
        _require_identifier(bypass, f"{where}.bypass_reason")
    semantic = data["semantic_candidate"]
    if _is_missing(semantic):
        _validate_missing(semantic, f"{where}.semantic_candidate")
    elif semantic not in SEMANTIC_STATES:
        raise RowAdmissionError(
            f"{where}.semantic_candidate must be one of {sorted(SEMANTIC_STATES)}"
        )
    semantic_refs = data["semantic_evidence_refs"]
    if isinstance(semantic_refs, (str, bytes)) or not isinstance(semantic_refs, Sequence):
        raise RowAdmissionError(f"{where}.semantic_evidence_refs must be an array")
    normalized_semantic_refs = tuple(
        _validate_evidence_ref(item, f"{where}.semantic_evidence_refs[{index}]")
        for index, item in enumerate(semantic_refs)
    )
    if semantic == "CLOSED" and not normalized_semantic_refs:
        raise RowAdmissionError(
            f"{where}: a CLOSED candidate requires closure evidence; "
            "absence from one crawl never proves closure"
        )
    data = dict(data)
    data["classifier_results"] = normalized_results
    data["semantic_evidence_refs"] = list(normalized_semantic_refs)
    return data


def _validate_coverage_ref(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _COVERAGE_FIELDS, where)
    _require_identifier(data["run_id"], f"{where}.run_id")
    _require_identifier(data["partition_id"], f"{where}.partition_id")
    _require_digest(
        data["partition_definition_hash"], f"{where}.partition_definition_hash"
    )
    status = data["status"]
    if status not in COVERAGE_STATUSES:
        raise RowAdmissionError(
            f"{where}.status must be one of {sorted(COVERAGE_STATUSES)}"
        )
    proven = _require_bool(
        data["pagination_coverage_proven"], f"{where}.pagination_coverage_proven"
    )
    if proven and status != "proven":
        raise CoverageNotProvenError(
            f"{where}: coverage status {status!r} cannot be presented as proven; "
            "only a proven status with referenced proof establishes pagination coverage"
        )
    if status == "proven" and not proven:
        raise CoverageNotProvenError(
            f"{where}: a proven status must carry pagination_coverage_proven=true"
        )
    _validate_artifact_ref(data["ledger"], f"{where}.ledger")
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    return data


def _validate_discovery(value: Any, where: str) -> dict[str, Any]:
    data = _closed(value, _DISCOVERY_FIELDS, where)
    _require_identifier(data["first_seen_run_id"], f"{where}.first_seen_run_id")
    _require_identifier(data["last_seen_run_id"], f"{where}.last_seen_run_id")
    _validate_time_point(data["first_seen_at"], f"{where}.first_seen_at")
    _validate_time_point(data["last_seen_at"], f"{where}.last_seen_at")
    coverage = data["coverage"]
    if isinstance(coverage, (str, bytes)) or not isinstance(coverage, Sequence):
        raise RowAdmissionError(f"{where}.coverage must be an array")
    normalized = [
        _validate_coverage_ref(item, f"{where}.coverage[{index}]")
        for index, item in enumerate(coverage)
    ]
    partitions = [(item["run_id"], item["partition_id"]) for item in normalized]
    if len(set(partitions)) != len(partitions):
        raise RowAdmissionError(
            f"{where}.coverage must not repeat a (run_id, partition_id) reference"
        )
    data = dict(data)
    data["coverage"] = normalized
    return data


def _validate_replacement_lineage(value: Any, where: str) -> Any:
    if _is_missing(value):
        return _validate_missing(value, where)
    data = _closed(value, _LINEAGE_FIELDS, where)
    _require_identifier(data["replacement_id"], f"{where}.replacement_id")
    _require_revision(
        data["prior_crawler_revision"], f"{where}.prior_crawler_revision", positive=True
    )
    _validate_artifact_ref(data["archive_root"], f"{where}.archive_root")
    return data


def _validate_job_entity(value: Any, where: str) -> dict[str, Any]:
    data = _require_mapping(value, where)
    if set(data.keys()) != {"entity_type", "target", "job_id"}:
        raise RowAdmissionError(
            f"{where} must be a JobEntityKey with exactly "
            "['entity_type', 'job_id', 'target']"
        )
    if data["entity_type"] != "job":
        raise RowAdmissionError(f"{where}.entity_type must be 'job'")
    _require_identifier(data["target"], f"{where}.target")
    _require_identifier(data["job_id"], f"{where}.job_id")
    return data


def _validate_owned_revision(doc: Any, row: Mapping[str, Any]) -> dict[str, Any]:
    where = "crawler revision"
    data = _closed(doc, _DOCUMENT_FIELDS, where)
    if data["record_type"] != "owned_domain_revision":
        raise RowAdmissionError(
            f"{where}.record_type must be 'owned_domain_revision'"
        )
    if data["schema_version"] != SCHEMA_VERSION:
        raise RowAdmissionError(
            f"{where}.schema_version must be {SCHEMA_VERSION!r}"
        )
    entity = _validate_job_entity(data["entity"], f"{where}.entity")
    if entity != dict(row["entity"]):
        raise RowAdmissionError(
            f"{where}.entity disagrees with the row entity"
        )
    if data["registration_digest"] != row["registration_digest"]:
        raise RowAdmissionError(
            f"{where}.registration_digest disagrees with the row registration"
        )
    if data["domain"] != "crawler":
        raise RowAdmissionError(f"{where}.domain must be 'crawler'")
    if data["owner_domain"] != "job.crawler":
        raise RowAdmissionError(
            f"{where}.owner_domain must be 'job.crawler'; crawler acquisition "
            "fields belong exclusively to the crawler owner"
        )
    owners = row["registration"]["owners"]
    if data["writer_id"] != owners["crawler"]["writer_id"]:
        raise RowAdmissionError(
            f"{where}.writer_id disagrees with the registered crawler writer"
        )
    revision = _require_revision(data["revision"], f"{where}.revision", positive=True)
    slot_revision = int(row["domains"]["crawler"]["revision"])
    if revision != slot_revision:
        raise RowAdmissionError(
            f"{where}.revision {revision} disagrees with the row crawler slot "
            f"revision {slot_revision}"
        )
    if data["previous_revision"] != revision - 1:
        raise RowAdmissionError(
            f"{where}.previous_revision must be {revision - 1}; "
            "a published revision is a complete contiguous snapshot"
        )
    _validate_prefix(data["evidence_prefix"], f"{where}.evidence_prefix")
    _validate_support_refs(data["evidence_refs"], f"{where}.evidence_refs")
    value = _closed(data["value"], _VALUE_FIELDS, f"{where}.value")
    if not value:
        raise RowAdmissionError(f"{where}.value must not be empty")
    normalized_value = {
        "acquisition": _validate_acquisition(
            value["acquisition"], f"{where}.value.acquisition"
        ),
        "processing": _validate_processing(
            value["processing"], f"{where}.value.processing"
        ),
        "discovery": _validate_discovery(
            value["discovery"], f"{where}.value.discovery"
        ),
        "replacement_lineage": _validate_replacement_lineage(
            value["replacement_lineage"], f"{where}.value.replacement_lineage"
        ),
    }
    normalized = dict(data)
    normalized["value"] = normalized_value
    return normalized


# ---------------------------------------------------------------------------
# Row admission
# ---------------------------------------------------------------------------


def _row_to_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, Mapping):
        return dict(row)
    to_dict = getattr(row, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        if isinstance(data, Mapping):
            return dict(data)
    raise RowAdmissionError(
        f"row must be a LogicalRow mapping, not {type(row).__name__}"
    )


def _admit_row(row: Any) -> tuple[dict[str, Any], Any]:
    """Structurally admit one complete LogicalRow root (seam mapping 5.1)."""
    row_dict = _row_to_dict(row)
    if set(row_dict.keys()) != set(_ROW_FIELDS):
        raise RowAdmissionError(
            f"row must contain exactly {sorted(_ROW_FIELDS)}; "
            f"got {sorted(row_dict.keys())}"
        )
    if row_dict["record_type"] != "logical_row":
        raise RowAdmissionError("row.record_type must be 'logical_row'")
    try:
        logical = read_publications.LogicalRow.from_dict(row_dict)
    except Exception as exc:
        raise RowAdmissionError(f"row is not an admissible LogicalRow: {exc}") from exc
    normalized = logical.to_dict()
    entity = _validate_job_entity(normalized["entity"], "row.entity")
    registration = normalized["registration"]
    if registration["entity"] != entity:
        raise RowAdmissionError("row.entity and registration.entity disagree")
    expected_digest = str(
        contract_codec.canonical_digest(_canonical_bytes(registration))
    )
    if normalized["registration_digest"] != expected_digest:
        raise RowAdmissionError(
            "row.registration_digest does not match the complete registration bytes"
        )
    crawler_slot = normalized["domains"]["crawler"]
    if crawler_slot["revision"] == 0:
        raise RowAdmissionError(
            "crawler slot must be a published revision; a crawler-backed "
            "evaluation cannot consume a row without a crawler publication"
        )
    versions = dict(normalized["seal_point"]["versions"])
    if versions != {
        "crawler": crawler_slot["revision"],
        "downstream": normalized["domains"]["downstream"]["revision"],
    }:
        raise RowAdmissionError("row seal vector disagrees with the domain slots")
    return normalized, logical


def _admit_crawler_document(
    channel_id: str, row: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    slot = row["domains"]["crawler"]
    reference = dict(slot["document"])
    try:
        ref = artifact_store.ArtifactReference.from_dict(reference)
    except Exception as exc:
        raise RowAdmissionError(
            f"crawler document reference is invalid: {exc}"
        ) from exc
    try:
        raw = artifact_store.resolve_artifact(channel_id, ref)
    except Exception as exc:
        raise RowAdmissionError(
            f"crawler document bytes are unavailable: {exc}"
        ) from exc
    if _byte_digest(raw) != ref.digest:
        raise RowAdmissionError(
            "crawler document bytes do not match the referenced digest"
        )
    document = _strict_gate(raw, "crawler document")
    if not isinstance(document, Mapping):
        raise RowAdmissionError("crawler document must be a JSON object")
    if dict(slot["snapshot"]) != dict(document):
        raise RowAdmissionError(
            "crawler slot snapshot does not equal the referenced published document"
        )
    return dict(document), reference


def _verify_cited_prefix(channel_id: str, row: Mapping[str, Any]) -> None:
    """Re-verify a cited journal prefix when this channel may read it."""
    prefix = row["seal_point"]["input_prefix"]
    try:
        prefix_value = evidence_journal.JournalPrefix(
            journal_id=str(prefix["journal_id"]),
            last_sequence=int(prefix["last_sequence"]),
            head_hash=str(prefix["head_hash"]),
        )
        evidence_journal.read_prefix(channel_id, prefix_value)
    except evidence_journal.JournalNotAdmittedError:
        return
    except Exception as exc:
        if access_policy is not None and isinstance(
            exc, access_policy.AuthorizationError
        ):
            return
        raise RowAdmissionError(
            f"cited seal evidence prefix cannot be verified: {exc}"
        ) from exc


def _verify_read_view(
    channel_id: str, row: Mapping[str, Any], view_id: str
) -> None:
    """Cross-check the row root against its installed read view when available.

    Intake usually holds a downstream intake channel, not read-view publisher
    authority, so an inaccessible view is not fatal: the row's bytes, digests,
    and evidence are verified independently.  A visible view that disagrees
    with the delivered row is always fatal.
    """
    try:
        loaded = read_publications.load_row(
            channel_id, dict(row["entity"]), str(view_id)
        )
    except (
        read_publications.RowAdmissionError,
        read_publications.PublicationRejectedError,
        read_publications.ViewIntegrityError,
    ) as exc:
        raise RowAdmissionError(
            f"the installed read view cannot prove this row: {exc}"
        ) from exc
    except Exception:
        # No read-view publisher authority (or no admitted publisher journal):
        # the row's own bytes, digests and evidence were verified independently.
        return
    if loaded.to_dict() != dict(row):
        raise RowAdmissionError(
            "delivered row disagrees with the complete immutable row root "
            "installed in its named view"
        )


# ---------------------------------------------------------------------------
# Interpretation rules (seam mapping 5.4 / 5.5)
# ---------------------------------------------------------------------------


def _interpret_render_content(
    acquisition: Mapping[str, Any], processing: Mapping[str, Any]
) -> None:
    verdict = acquisition["render_verdict"]
    pipeline = processing["pipeline_state"]
    content = dict(acquisition["content"])
    declarations = list(acquisition["content_declarations"])
    if verdict == PASS:
        if _is_missing(acquisition["source_response"]):
            raise IncompleteExtractionError(
                "a Pass acquisition requires a retained source_response artifact"
            )
        if pipeline in {RENDER_FAILED, "failed"}:
            raise IncompleteExtractionError(
                f"a Pass acquisition cannot carry pipeline_state={pipeline!r}"
            )
        declared_required = {
            decl["name"]: decl for decl in declarations if decl.get("required") is True
        }
        missing_declarations = [
            field for field in CORE_CONTENT_FIELDS if field not in declared_required
        ]
        if missing_declarations:
            raise IncompleteExtractionError(
                "the declared content contract omits required canonical fields "
                f"{missing_declarations}"
            )
        extended_by_name = {
            str(item["name"]): item for item in content.get("extended", ())
        }

        def declared_value(name: str) -> Any:
            if name in CORE_CONTENT_FIELDS:
                return content[name]
            record = extended_by_name.get(name)
            if record is None:
                raise IncompleteExtractionError(
                    f"content.{name} is declared but absent from the extraction"
                )
            return record["value"]

        for declaration in declarations:
            name = str(declaration["name"])
            value = declared_value(name)
            if declaration.get("required") is True:
                _check_required_value(
                    value,
                    str(declaration["type"]),
                    f"content.{name}",
                )
            elif not _is_missing(value):
                try:
                    _check_typed_value(
                        value, str(declaration["type"]), f"content.{name}"
                    )
                except RowAdmissionError as exc:
                    raise IncompleteExtractionError(
                        f"content.{name} is declared and must carry correctly "
                        f"typed content: {exc.message}"
                    ) from exc
        return

    # Non-Pass acquisition: a failed render, never usable content.
    if pipeline != RENDER_FAILED:
        raise UnusableContentError(
            f"non-Pass render verdict {verdict!r} requires "
            f"pipeline_state={RENDER_FAILED!r}; got {pipeline!r} "
            "(failed render presented as usable content)"
        )
    for field in CORE_CONTENT_FIELDS:
        if not _is_missing(content[field]):
            raise UnusableContentError(
                f"failed render ({verdict!r}) presented as usable content: "
                f"content.{field} must be Missing"
            )
        _validate_missing(content[field], f"content.{field}")
    for item in content.get("extended", []):
        if not _is_missing(item.get("value")):
            raise UnusableContentError(
                f"failed render ({verdict!r}) presented as usable content: "
                f"extended {item.get('name')!r} must be Missing"
            )
    if list(processing["classifier_results"]):
        raise UnusableContentError(
            f"failed render ({verdict!r}) must carry no classifier results"
        )
    if not _is_missing(processing["final_genuine_result_id"]):
        raise UnusableContentError(
            f"failed render ({verdict!r}) must carry no genuine classifier result"
        )


def _interpret_classification(processing: Mapping[str, Any]) -> None:
    bypass = processing["bypass_reason"]
    final_id = processing["final_genuine_result_id"]
    results = list(processing["classifier_results"])
    if not _is_missing(bypass):
        if results:
            raise BypassAsGenuineError(
                "bypass_reason is set but classifier_results is nonempty: "
                "a bypass produces no classifier result"
            )
        if not _is_missing(final_id):
            raise BypassAsGenuineError(
                "bypass_reason is set but final_genuine_result_id is present: "
                "a bypass is never a genuine classifier pass"
            )
        return
    if _is_missing(final_id):
        return
    matches = [result for result in results if result["result_id"] == final_id]
    if not matches:
        raise BypassAsGenuineError(
            f"final_genuine_result_id {final_id!r} resolves to no classifier result"
        )
    genuine = matches[0]
    if genuine["verdict"] != "PASS" or genuine["verdict_applied"] != "PASS":
        raise BypassAsGenuineError(
            f"result {final_id!r} is verdict={genuine['verdict']!r} "
            f"applied={genuine['verdict_applied']!r}: only PASS/PASS is a "
            "genuine pass (a shadow VETO applied as PASS stays distinguishable)"
        )


def _coverage_complete(discovery: Mapping[str, Any]) -> tuple[tuple[str, ...], bool]:
    coverage = list(discovery["coverage"])
    statuses = tuple(str(item["status"]) for item in coverage)
    complete = bool(coverage) and all(
        item["status"] == "proven" and item["pagination_coverage_proven"] is True
        for item in coverage
    )
    return statuses, complete


def _transform_content(content: Mapping[str, Any]) -> dict[str, Any]:
    """Map crawler content to canonical JobContent without inventing values."""
    out: dict[str, Any] = {}
    for field in CORE_CONTENT_FIELDS:
        out[field] = _copy_json(content[field])
    extended = []
    for item in content.get("extended", ()):
        record = dict(item)
        extended.append(
            {
                "name": record["name"],
                "type": record["type"],
                "value": _copy_json(record["value"]),
            }
        )
    out["extended"] = extended
    return out


def _copy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True))


# ---------------------------------------------------------------------------
# Same-fetch-key observations and replacement verification
# ---------------------------------------------------------------------------


def _owner_domain_for_channel(channel_id: str, fallback: str) -> str:
    """Return the authenticated channel's owner axis (the retention domain)."""
    if access_policy is None:
        return fallback
    try:
        projection = access_policy.channel_projection(channel_id)
        axis = projection.get("axis") if isinstance(projection, Mapping) else None
        if isinstance(axis, str) and axis:
            return axis
    except Exception:
        pass
    return fallback


def _record_observation_event(
    channel_id: str,
    owner_domain: str,
    observation: Mapping[str, Any],
    artifact: Any,
) -> Any:
    """Journal the retained observation when the owner journal accepts it."""
    if access_policy is None:
        return None
    try:
        projection = access_policy.channel_projection(channel_id)
    except Exception:
        return None
    producer = projection.get("producer") if isinstance(projection, Mapping) else None
    raw_kinds = producer.get("allowed_event_kinds") if isinstance(producer, Mapping) else ()
    if (
        isinstance(raw_kinds, (str, bytes))
        or not isinstance(raw_kinds, Sequence)
    ):
        return None
    kinds = tuple(str(kind) for kind in raw_kinds)
    if INTAKE_EVENT_KIND not in kinds:
        return None
    try:
        submission = evidence_journal.EventSubmission(
            producer_sequence=evidence_journal.NOT_OBSERVED,
            event_kind=INTAKE_EVENT_KIND,
            event_schema_version=INTAKE_EVENT_SCHEMA_VERSION,
            occurred_at=evidence_journal.NOT_OBSERVED,
            payload=evidence_journal.EvidencePayload(
                data=dict(observation),
                measurements=(),
                evidence_refs=(),
                artifact_refs=(artifact.to_dict(),) if artifact is not None else (),
            ),
        )
    except Exception:
        return None
    try:
        return evidence_journal.append_event(channel_id, owner_domain, submission)
    except Exception:
        return None


def _attempt_replacement_verification(
    channel_id: str,
    row: Mapping[str, Any],
    document: Mapping[str, Any],
    seen: Mapping[str, Any],
    lineage: Mapping[str, Any],
) -> None:
    """Verify a changed fetch key through archive_retention (OWD-REPLACE).

    The complete ``FetchKeyReplacement`` receipt is crawler-owned evidence; a
    delivered row carries only its backward lineage and its own evidence
    prefix.  Intake reconstructs the strongest receipt those bytes support and
    lets ``archive_retention`` decide.  Anything short of a complete verified
    prior-row archive is a ``replacement_required`` rejection: intake never
    mutates the acquisition, never synthesizes a commit event, and never
    treats a missing archive as a no-op.
    """
    prior_revision = int(seen["revision"])
    if int(lineage["prior_crawler_revision"]) != prior_revision:
        raise ReplacementRequiredError(
            "replacement lineage names prior crawler revision "
            f"{lineage['prior_crawler_revision']} but intake holds revision "
            f"{prior_revision}"
        )
    commit_ref = dict(document["evidence_refs"][0])
    receipt = {
        "record_type": "fetch_key_replacement",
        "schema_version": archive_retention.SCHEMA_VERSION,
        "replacement_id": str(lineage["replacement_id"]),
        "entity": dict(row["entity"]),
        "registration_digest": str(row["registration_digest"]),
        "old_crawler": {
            "revision": prior_revision,
            "record_digest": str(seen["record_digest"]),
        },
        "old_fetch_key": str(seen["fetch_key"]),
        "new_crawler": dict(document),
        "archive_root": dict(lineage["archive_root"]),
        "archived_vector": {
            "crawler": prior_revision,
            "downstream": int(
                dict(row["seal_point"]["versions"]).get("downstream", 0)
            ),
        },
        "retention_pin_id": str(lineage["replacement_id"]),
        "commit_ref": commit_ref,
        "evidence_prefix": dict(document["evidence_prefix"]),
        "evidence_refs": [commit_ref],
    }
    try:
        archive_retention.verify_replacement(channel_id, receipt)
    except Exception as exc:
        raise ReplacementRequiredError(
            "a changed fetch key requires a complete verified prior-row archive: "
            f"{exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Public evaluation input
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EvaluationJobInput:
    """Pinned, read-only crawler input consumed by one evaluation."""

    portfolio_job_id: str
    source_key: Mapping[str, Any]
    logical_row: Any
    logical_row_ref: Any
    seal_id: str
    crawler_input: Mapping[str, Any]
    job_content: Mapping[str, Any]
    render_verdict: str
    pipeline_state: str
    genuine_result_id: Any
    bypass_reason: Any
    classifier_verdicts: tuple[tuple[str, str, str], ...]
    coverage_statuses: tuple[str, ...]
    coverage_complete: bool
    acquisition_digest: str
    fetch_key: str

    def __post_init__(self) -> None:
        _require_identifier(self.portfolio_job_id, "job_input.portfolio_job_id")
        _validate_job_entity(self.source_key, "job_input.source_key")
        _validate_artifact_ref(self.logical_row, "job_input.logical_row")
        _validate_evidence_ref(self.logical_row_ref, "job_input.logical_row_ref")
        _require_identifier(self.seal_id, "job_input.seal_id")
        pin = _require_mapping(self.crawler_input, "job_input.crawler_input")
        if set(pin.keys()) != {"revision", "record_digest"}:
            raise RowAdmissionError(
                "job_input.crawler_input must pin exactly revision and record_digest"
            )
        _require_revision(pin["revision"], "job_input.crawler_input.revision", positive=True)
        _require_digest(pin["record_digest"], "job_input.crawler_input.record_digest")
        content = _require_mapping(self.job_content, "job_input.job_content")
        if set(content.keys()) != set(CORE_CONTENT_FIELDS) | {"extended"}:
            raise RowAdmissionError(
                "job_input.job_content must contain the canonical JobContent fields"
            )
        if self.render_verdict not in RENDER_VERDICTS:
            raise RowAdmissionError("job_input.render_verdict is not a render verdict")
        if self.pipeline_state not in PIPELINE_STATES:
            raise RowAdmissionError("job_input.pipeline_state is not a pipeline state")
        _require_digest(self.acquisition_digest, "job_input.acquisition_digest")
        _require_digest(self.fetch_key, "job_input.fetch_key")
        for field, value in (
            ("job_input.genuine_result_id", self.genuine_result_id),
            ("job_input.bypass_reason", self.bypass_reason),
        ):
            if _is_missing(value):
                _validate_missing(value, field)
            else:
                _require_identifier(value, field)
        if isinstance(self.classifier_verdicts, (str, bytes)) or not isinstance(
            self.classifier_verdicts, Sequence
        ):
            raise RowAdmissionError(
                "job_input.classifier_verdicts must be an array of (id, verdict, applied)"
            )
        for entry in self.classifier_verdicts:
            if isinstance(entry, (str, bytes)) or not isinstance(entry, Sequence) or len(entry) != 3:
                raise RowAdmissionError(
                    "job_input.classifier_verdicts entries must be "
                    "(result_id, verdict, verdict_applied)"
                )
            result_id, verdict, applied = entry
            _require_identifier(result_id, "job_input.classifier_verdicts.result_id")
            if verdict not in CLASSIFIER_VERDICTS:
                raise RowAdmissionError(
                    "job_input.classifier_verdicts must retain the raw classifier verdict"
                )
            if applied not in CLASSIFIER_VERDICTS:
                raise RowAdmissionError(
                    "job_input.classifier_verdicts must retain the applied verdict"
                )
        if not isinstance(self.coverage_complete, bool):
            raise RowAdmissionError("job_input.coverage_complete must be a boolean")
        for status in self.coverage_statuses:
            if status not in COVERAGE_STATUSES:
                raise RowAdmissionError(
                    "job_input.coverage_statuses must retain crawler coverage statuses"
                )

    @property
    def usable(self) -> bool:
        """True only for a Pass acquisition that is not a failed render."""
        return self.render_verdict == PASS and self.pipeline_state != RENDER_FAILED

    def to_dict(self) -> dict[str, Any]:
        return {
            "portfolio_job_id": self.portfolio_job_id,
            "source_key": dict(self.source_key),
            "logical_row": dict(self.logical_row),
            "logical_row_ref": dict(self.logical_row_ref),
            "seal_id": self.seal_id,
            "crawler_input": dict(self.crawler_input),
            "job_content": _copy_json(dict(self.job_content)),
            "render_verdict": self.render_verdict,
            "pipeline_state": self.pipeline_state,
            "genuine_result_id": _copy_json(self.genuine_result_id)
            if isinstance(self.genuine_result_id, Mapping)
            else self.genuine_result_id,
            "bypass_reason": _copy_json(self.bypass_reason)
            if isinstance(self.bypass_reason, Mapping)
            else self.bypass_reason,
            "classifier_verdicts": [list(item) for item in self.classifier_verdicts],
            "coverage_statuses": list(self.coverage_statuses),
            "coverage_complete": self.coverage_complete,
            "acquisition_digest": self.acquisition_digest,
            "fetch_key": self.fetch_key,
        }

    @classmethod
    def from_dict(cls, data: Any) -> "EvaluationJobInput":
        if isinstance(data, cls):
            return data
        if hasattr(data, "to_dict") and not isinstance(data, dict):
            return cls.from_dict(data.to_dict())
        if not isinstance(data, Mapping):
            raise TypeError("EvaluationJobInput must be decoded from a dict")
        return cls(
            portfolio_job_id=data["portfolio_job_id"],
            source_key=data["source_key"],
            logical_row=data["logical_row"],
            logical_row_ref=data["logical_row_ref"],
            seal_id=data["seal_id"],
            crawler_input=data["crawler_input"],
            job_content=data["job_content"],
            render_verdict=data["render_verdict"],
            pipeline_state=data["pipeline_state"],
            genuine_result_id=data["genuine_result_id"],
            bypass_reason=data["bypass_reason"],
            classifier_verdicts=tuple(
                tuple(item) for item in data["classifier_verdicts"]
            ),
            coverage_statuses=tuple(data["coverage_statuses"]),
            coverage_complete=data["coverage_complete"],
            acquisition_digest=data["acquisition_digest"],
            fetch_key=data["fetch_key"],
        )


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def accept_job_row(channel_id: str, row: Any) -> EvaluationJobInput:
    """Admit one crawler-backed LogicalRow as pinned evaluation input.

    The row and its complete crawler document are verified read-only; no
    crawler, processing, classification, discovery, lease, or replacement
    field is written.  A same-fetch-key acquisition change preserves the prior
    acquisition, retains the differing response as an observation, and is
    rejected with ``same_fetch_key_conflict``.  A changed fetch key requires a
    complete verified prior-row archive.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise RowAdmissionError("channel_id must be a nonempty identifier")

    row_dict, _logical = _admit_row(row)
    entity = dict(row_dict["entity"])
    view_id = str(row_dict["seal_point"]["view_id"])

    _verify_read_view(channel_id, row_dict, view_id)
    _verify_cited_prefix(channel_id, row_dict)

    document, document_ref = _admit_crawler_document(channel_id, row_dict)
    owned = _validate_owned_revision(document, row_dict)
    value = owned["value"]
    acquisition = value["acquisition"]
    processing = value["processing"]
    discovery = value["discovery"]
    lineage = value["replacement_lineage"]

    _interpret_render_content(acquisition, processing)
    _interpret_classification(processing)
    coverage_statuses, coverage_complete = _coverage_complete(discovery)

    fetch_key = str(acquisition["fetch_key"])
    acquisition_digest = _digest(acquisition)
    revision = int(owned["revision"])
    record_digest = str(document_ref["digest"])
    entity_key = (str(entity["target"]), str(entity["job_id"]))

    with _LOCK:
        prior_revision_digest = _SEEN_REVISIONS.get(entity_key, {}).get(revision)
        if prior_revision_digest is not None and prior_revision_digest != record_digest:
            raise RowAdmissionError(
                f"revision identity conflict: crawler revision {revision} "
                "names two different document digests"
            )
        seen = _SEEN.get(entity_key)
        if seen is None:
            _SEEN[entity_key] = {
                "fetch_key": fetch_key,
                "acquisition_digest": acquisition_digest,
                "revision": revision,
                "record_digest": record_digest,
            }
            _SEEN_REVISIONS.setdefault(entity_key, {})[revision] = record_digest
        elif seen["fetch_key"] == fetch_key:
            if seen["acquisition_digest"] == acquisition_digest:
                seen["revision"] = max(int(seen["revision"]), revision)
                _SEEN_REVISIONS.setdefault(entity_key, {})[revision] = record_digest
            else:
                observation = {
                    "record_type": INTAKE_OBSERVATION_RECORD_TYPE,
                    "channel_id": str(channel_id),
                    "entity": entity,
                    "fetch_key": fetch_key,
                    "prior_revision": int(seen["revision"]),
                    "prior_acquisition_digest": str(seen["acquisition_digest"]),
                    "observed_revision": revision,
                    "observed_acquisition_digest": acquisition_digest,
                    "observed_record_digest": record_digest,
                }
                owner_domain = _owner_domain_for_channel(
                    channel_id, INTAKE_OWNER_FALLBACK
                )
                retained = None
                try:
                    retained = artifact_store.retain_artifact(
                        channel_id,
                        owner_domain,
                        "application/json",
                        _canonical_bytes(observation),
                        "restricted",
                    )
                except Exception:
                    retained = None
                envelope = _record_observation_event(
                    channel_id, owner_domain, observation, retained
                )
                entry = dict(observation)
                entry["owner_domain"] = owner_domain
                entry["observation_retained"] = retained is not None
                if retained is not None:
                    entry["observation_artifact"] = retained.to_dict()
                if envelope is not None:
                    entry["journal_event"] = {
                        "journal_id": envelope.journal_id,
                        "sequence": envelope.journal_sequence,
                        "event_id": envelope.event_id,
                        "event_hash": envelope.event_hash,
                        "pointer": "",
                    }
                _OBSERVATIONS.append(entry)
                retained_note = (
                    "is retained as an observation, not installed as a replacement"
                    if retained is not None
                    else "could not be durably retained as an observation"
                )
                raise SameFetchKeyConflictError(
                    f"same fetch key {fetch_key} preserves acquisition "
                    f"{seen['acquisition_digest']}; observed {acquisition_digest} "
                    f"{retained_note}",
                    observation_retained=retained is not None,
                )
        else:
            if _is_missing(lineage):
                raise ReplacementRequiredError(
                    f"fetch key changed from {seen['fetch_key']} to {fetch_key} "
                    "without a complete prior-row archive "
                    "(replacement_lineage is inapplicable)"
                )
            _attempt_replacement_verification(
                channel_id, row_dict, document, seen, dict(lineage)
            )
            _SEEN[entity_key] = {
                "fetch_key": fetch_key,
                "acquisition_digest": acquisition_digest,
                "revision": revision,
                "record_digest": record_digest,
            }
            _SEEN_REVISIONS.setdefault(entity_key, {})[revision] = record_digest

    job_content = _transform_content(acquisition["content"])
    if _is_missing(acquisition["content"]["direct_apply_url"]) and not _is_missing(
        job_content["direct_apply_url"]
    ):
        raise RowAdmissionError("direct_apply_url must never default from source_url")

    owner_domain = _owner_domain_for_channel(channel_id, INTAKE_OWNER_FALLBACK)
    try:
        row_ref = artifact_store.retain_artifact(
            channel_id,
            owner_domain,
            "application/json",
            _canonical_bytes(row_dict),
            "restricted",
        )
    except Exception as exc:
        raise RowAdmissionError(
            f"logical row bytes cannot be retained as the pinned input artifact: {exc}"
        ) from exc

    registration = dict(row_dict["registration"])
    identity = registration.get("identity")
    portfolio_job_id = str(entity["job_id"])
    if (
        isinstance(identity, Mapping)
        and isinstance(identity.get("portfolio_job_id"), str)
        and identity["portfolio_job_id"]
    ):
        portfolio_job_id = str(identity["portfolio_job_id"])
    seal_id = str(row_dict["seal_point"]["seal_id"])

    genuine = processing["final_genuine_result_id"]
    genuine_value: Any = (
        dict(genuine) if _is_missing(genuine) else str(genuine)
    )
    bypass = processing["bypass_reason"]
    bypass_value: Any = dict(bypass) if _is_missing(bypass) else str(bypass)
    classifier_verdicts = tuple(
        (
            str(result["result_id"]),
            str(result["verdict"]),
            str(result["verdict_applied"]),
        )
        for result in processing["classifier_results"]
    )

    return EvaluationJobInput(
        portfolio_job_id=portfolio_job_id,
        source_key=entity,
        logical_row=row_ref.to_dict(),
        logical_row_ref=dict(row_dict["domains"]["crawler"]["publication_ref"]),
        seal_id=seal_id,
        crawler_input={"revision": revision, "record_digest": record_digest},
        job_content=job_content,
        render_verdict=str(acquisition["render_verdict"]),
        pipeline_state=str(processing["pipeline_state"]),
        genuine_result_id=genuine_value,
        bypass_reason=bypass_value,
        classifier_verdicts=classifier_verdicts,
        coverage_statuses=coverage_statuses,
        coverage_complete=coverage_complete,
        acquisition_digest=acquisition_digest,
        fetch_key=fetch_key,
    )
