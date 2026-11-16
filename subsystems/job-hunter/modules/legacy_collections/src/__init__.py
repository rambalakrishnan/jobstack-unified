"""legacy_collections: private localization of the twelve legacy collections (tier 3).

Implements seam mapping 16: the twelve Firestore collection names are private
legacy storage namespaces or projections, never shared wire contracts and
never a required deployment.  A legacy document is only ever *imported* as an
immutable, restricted source artifact plus a private projection that cites it:

* the raw source artifact is resolved through the artifact store and must be
  classified ``restricted``; it is never rewritten;
* absent fields become typed ``Missing`` envelopes (never in-band nulls and
  never guessed defaults), explicit source nulls are preserved as
  ``Missing(not_observed)`` with a migration issue;
* unknown legacy vocabulary (statuses, severities, classification versions)
  stays uninterpreted legacy data and is flagged as requiring a mapping;
* the documented legacy duplicate formulas are recorded as
  ``duplicate_candidate_hint_only``: company/title similarity never merges
  identities, source roots, or attempts;
* the legacy vault boundary is honoured: secret bytes never enter an ordinary
  import artifact, so only the opaque lookup identity survives;
* every import is journaled through :func:`evidence_journal.append_event` with
  the source and projection artifact references, so the projection is
  rebuildable and evidenced rather than a new authority.

The tier-0 codec exposes only fixed demo schemas.  Like ``evidence_journal``,
this module reuses ``record/v1``'s opaque ``timing`` property as the strict
JSON gate container for the private projection, which keeps duplicate keys,
bare nulls, nonfinite numbers, and malformed Missing envelopes rejected by the
shared codec.

Public interface (EXPOSES)::

    import_legacy_document(channel_id, collection, source, mapping)
        -> ArtifactReference
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import math
import re
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any


def _load_sibling(name: str):  # pragma: no cover - import plumbing
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
    if spec is None or spec.loader is None:  # pragma: no cover
        raise ModuleNotFoundError(f"sibling module {name!r} not found")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


contract_codec = _load_sibling("contract_codec")
access_policy = _load_sibling("access_policy")
artifact_store = _load_sibling("artifact_store")
evidence_journal = _load_sibling("evidence_journal")

__all__ = [
    "COLLECTION_ADAPTERS",
    "DEFAULT_ADAPTER_VERSION",
    "IMPORT_ASSERTION_KIND",
    "IMPORT_EVENT_KIND",
    "IMPORT_EVENT_ROLE",
    "IMPORT_EVENT_SCHEMA_VERSION",
    "IMPORT_OPERATION",
    "ISSUE_CODES",
    "LEGACY_COLLECTIONS",
    "LegacyAuthorityError",
    "LegacyCollectionsError",
    "LegacyEvidenceError",
    "LegacyMappingError",
    "LegacyProjectionError",
    "LegacySourceError",
    "CollectionAdapter",
    "FieldMapping",
    "Missing",
    "PRIVATE_OWNER_DOMAIN",
    "PROJECTION_SCHEMA_VERSION",
    "RECORD_SCHEMA_ID",
    "UnknownLegacyCollectionError",
    "VersionPin",
    "import_legacy_document",
]

# ---------------------------------------------------------------------------
# Kernel pins
# ---------------------------------------------------------------------------

PROJECTION_SCHEMA_VERSION = "legacy-collections/0.1.0"
DEFAULT_ADAPTER_VERSION = "1"

#: The tier-0 record schema whose opaque ``timing`` property is the strict gate.
RECORD_SCHEMA_ID = "record/v1"

#: Private projections live under the product writer's private domain.  A
#: legacy import never publishes a crawler, attempt, or application axis.
PRIVATE_OWNER_DOMAIN = "job.downstream"

#: The authenticated product-writer grant an importing channel must hold.
IMPORT_OPERATION = "job.downstream.write"

#: Event kind journaled for each import (pinned by the admitted manifest).
IMPORT_EVENT_KIND = "legacy.document_imported"
IMPORT_EVENT_SCHEMA_VERSION = DEFAULT_ADAPTER_VERSION
IMPORT_EVENT_ROLE = "external_input"
IMPORT_ASSERTION_KIND = "observation"

#: The twelve private legacy storage namespaces of seam mapping 16.
LEGACY_COLLECTIONS = (
    "jobs",
    "evaluations",
    "artifacts",
    "trackers",
    "emails",
    "schedules",
    "settings",
    "vault",
    "logs",
    "costs",
    "tasks",
    "noGoList",
)

DISPOSITION_MAPPED = "mapped_source_value"
DISPOSITION_PRESERVED = "preserved_legacy_value"
DISPOSITION_DISPLAY = "preserved_legacy_text"
DISPOSITION_RESTRICTED = "restricted_artifact_reference"
DISPOSITION_CANDIDATE = "candidate_match_not_identity"
DISPOSITION_SECRET = "secret_redacted"
DISPOSITION_SOURCE = "source_preserved"
DISPOSITION_SNAPSHOT = "historical_display_snapshot"

DISPOSITIONS = frozenset(
    {
        DISPOSITION_MAPPED,
        DISPOSITION_PRESERVED,
        DISPOSITION_DISPLAY,
        DISPOSITION_RESTRICTED,
        DISPOSITION_CANDIDATE,
        DISPOSITION_SECRET,
        DISPOSITION_SOURCE,
        DISPOSITION_SNAPSHOT,
    }
)

ISSUE_MISSING_FIELD = "missing_legacy_field"
ISSUE_EXPLICIT_NULL = "explicit_null_value"
ISSUE_UNKNOWN_ENUM = "unknown_legacy_enum"
ISSUE_UNRESOLVED_TYPE = "unresolved_original_type"
ISSUE_POLICY_PIN = "pinned_policy_required"
ISSUE_CANDIDATE_MATCH = "candidate_match_not_identity"
ISSUE_SECRET_REDACTED = "secret_material_redacted"
ISSUE_SANITIZATION = "sanitization_pin_required"
ISSUE_EVIDENCE_REQUIRED = "evidence_required"
ISSUE_UNMAPPED_FIELD = "unmapped_legacy_field"
ISSUE_IDENTITY_MISSING = "missing_legacy_identity"

ISSUE_CODES = frozenset(
    {
        ISSUE_MISSING_FIELD,
        ISSUE_EXPLICIT_NULL,
        ISSUE_UNKNOWN_ENUM,
        ISSUE_UNRESOLVED_TYPE,
        ISSUE_POLICY_PIN,
        ISSUE_CANDIDATE_MATCH,
        ISSUE_SECRET_REDACTED,
        ISSUE_SANITIZATION,
        ISSUE_EVIDENCE_REQUIRED,
        ISSUE_UNMAPPED_FIELD,
        ISSUE_IDENTITY_MISSING,
    }
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MISSING_SHAPE_KEYS = frozenset({"value", "reason", "detail"})

_SEQUENCE_LOCK = threading.Lock()
_SEQUENCES: dict[tuple[str, str], int] = {}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LegacyCollectionsError(Exception):
    """Base class for legacy-collection import contract violations."""


class UnknownLegacyCollectionError(LegacyCollectionsError, ValueError):
    """The collection name is not one of the twelve private namespaces."""


class LegacyAuthorityError(LegacyCollectionsError):
    """The authenticated channel holds no legacy-import write grant."""


class LegacySourceError(LegacyCollectionsError, ValueError):
    """The source artifact is not a restricted, resolvable legacy document."""


class LegacyMappingError(LegacyCollectionsError, ValueError):
    """The adapter/mapping pin is missing or malformed."""


class LegacyProjectionError(LegacyCollectionsError, ValueError):
    """The private projection could not be built or passed the codec gate."""


class LegacyEvidenceError(LegacyCollectionsError):
    """The import could not be registered in the owning journal."""


# ---------------------------------------------------------------------------
# Kernel vocabulary
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Missing:
    """Typed missingness envelope (``K.Missing``); never an in-band null."""

    reason: str
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.reason not in contract_codec.VALID_MISSING_REASONS:
            raise ValueError(f"unknown Missing reason: {self.reason!r}")
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail
        ):
            raise ValueError("Missing.detail must be a nonempty string when present")

    @property
    def value(self) -> None:
        return None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"value": None, "reason": self.reason}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


@dataclass(frozen=True, slots=True)
class VersionPin:
    """Pinned adapter/mapping revision (``K.VersionPin``).

    Recomputing a legacy hash, parsing a legacy type, or interpreting a legacy
    enum requires a pinned adapter; imports record this pin so a projection is
    reproducible and the mapping is never silently improvised.
    """

    id: str
    version: str
    artifact_digest: str

    def __post_init__(self) -> None:
        _require_identifier(self.id, "mapping.id")
        _require_identifier(self.version, "mapping.version")
        _require_digest(self.artifact_digest, "mapping.artifact_digest")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "artifact_digest": self.artifact_digest,
        }


@dataclass(frozen=True, slots=True)
class FieldMapping:
    """One legacy field's declared canonical/private mapping."""

    legacy_field: str
    target: str
    disposition: str
    note: str = ""
    mapping_required: bool = False
    issue_codes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_identifier(self.legacy_field, "legacy_field")
        _require_identifier(self.target, "target")
        if self.disposition not in DISPOSITIONS:
            raise ValueError(f"unknown field disposition: {self.disposition!r}")
        if not isinstance(self.note, str):
            raise TypeError("note must be a string")
        if type(self.mapping_required) is not bool:
            raise TypeError("mapping_required must be a bool")
        if isinstance(self.issue_codes, (str, bytes)) or not isinstance(
            self.issue_codes, Sequence
        ):
            raise TypeError("issue_codes must be a sequence of issue codes")
        codes = tuple(self.issue_codes)
        for code in codes:
            if code not in ISSUE_CODES:
                raise ValueError(f"unknown issue code: {code!r}")
        if len(set(codes)) != len(codes):
            raise ValueError("issue_codes must be unique")
        object.__setattr__(self, "issue_codes", codes)


@dataclass(frozen=True, slots=True)
class CollectionAdapter:
    """Declarative private adapter for one legacy collection.

    The adapter preserves source values exactly; it never normalizes, maps, or
    infers an enum.  ``private``/``shared_contract`` state the storage rule of
    mapping 16.1 explicitly so no adapter can quietly become a shared contract.
    """

    collection: str
    identity_field: str | None
    identity_kind: str
    fields: tuple[FieldMapping, ...]
    collision_formula: str | None = None
    hint_field: str | None = None
    hint_inputs: tuple[str, ...] = ()
    identity_requires_source_root: bool = False
    withhold_unmapped: bool = False
    notes: tuple[str, ...] = ()
    private: bool = True
    shared_contract: bool = False

    def __post_init__(self) -> None:
        if self.collection not in LEGACY_COLLECTIONS:
            raise ValueError(f"unknown legacy collection: {self.collection!r}")
        _require_identifier(self.identity_kind, "identity_kind")
        if self.identity_field is not None:
            _require_identifier(self.identity_field, "identity_field")
        if isinstance(self.fields, (str, bytes)) or not isinstance(
            self.fields, Sequence
        ):
            raise TypeError("fields must be a sequence of FieldMapping records")
        mappings = tuple(self.fields)
        if not mappings:
            raise ValueError("a collection adapter requires at least one field mapping")
        for mapping in mappings:
            if not isinstance(mapping, FieldMapping):
                raise TypeError("fields entries must be FieldMapping records")
            if mapping.legacy_field == self.identity_field:
                raise ValueError(
                    f"{self.collection}: identity field {mapping.legacy_field!r} "
                    "must not be repeated in fields"
                )
            if mapping.legacy_field == self.hint_field:
                raise ValueError(
                    f"{self.collection}: hint field {mapping.legacy_field!r} "
                    "must not be repeated in fields"
                )
        legacy_names = [mapping.legacy_field for mapping in mappings]
        if len(set(legacy_names)) != len(legacy_names):
            raise ValueError(f"{self.collection}: duplicate legacy field mapping")
        targets = [mapping.target for mapping in mappings]
        if len(set(targets)) != len(targets):
            raise ValueError(f"{self.collection}: duplicate canonical target")
        if self.collision_formula is None and self.hint_field is not None:
            raise ValueError("a hint field requires a documented collision formula")
        if self.collision_formula is not None and not self.hint_inputs:
            raise ValueError("a collision formula requires its legacy input fields")
        if self.private is not True or self.shared_contract is not False:
            raise ValueError(
                f"{self.collection}: legacy adapters remain private projections "
                "and never shared contracts"
            )
        object.__setattr__(self, "fields", mappings)
        object.__setattr__(self, "hint_inputs", tuple(self.hint_inputs))
        object.__setattr__(self, "notes", tuple(self.notes))


def _require_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value:
        raise ValueError(f"{field} must be nonempty")
    if value != value.strip():
        raise ValueError(f"{field} must not be padded with whitespace")
    if len(value) > 256:
        raise ValueError(f"{field} must be at most 256 characters")
    if any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        raise ValueError(f"{field} must be a sha256:<64 lowercase hex> digest")
    return value


# ---------------------------------------------------------------------------
# The twelve private adapters (seam mapping 16.2 - 16.13)
# ---------------------------------------------------------------------------

_JOB_FIELDS = (
    FieldMapping("track", "job.downstream.track", DISPOSITION_MAPPED),
    FieldMapping("company", "job.crawler.content.employer", DISPOSITION_MAPPED),
    FieldMapping("title", "job.crawler.content.title", DISPOSITION_MAPPED),
    FieldMapping("location", "job.crawler.content.location", DISPOSITION_MAPPED),
    FieldMapping("sourceUrl", "acquisition.source_url", DISPOSITION_MAPPED),
    FieldMapping(
        "directApplyUrl",
        "job.crawler.content.direct_apply_url",
        DISPOSITION_MAPPED,
        note="no fallback: the legacy value is preserved exactly and an absent value stays missing",
    ),
    FieldMapping("portalType", "job.crawler.content.portal_type", DISPOSITION_MAPPED),
    FieldMapping(
        "rawDescription",
        "job.crawler.content.description",
        DISPOSITION_RESTRICTED,
        note="description bytes are retained as a restricted source artifact, never inlined",
    ),
    FieldMapping(
        "status",
        "display.legacy_status",
        DISPOSITION_DISPLAY,
        note="preserved legacy text; derived display only, never an acquisition or product state",
        mapping_required=True,
        issue_codes=(ISSUE_UNKNOWN_ENUM,),
    ),
    FieldMapping(
        "closingDate",
        "preserved.closing_date",
        DISPOSITION_SOURCE,
        note="source-preserved text, not a typed instant",
    ),
)

_EVALUATION_FIELDS = (
    FieldMapping("jobId", "portfolio.job_identity", DISPOSITION_MAPPED),
    FieldMapping(
        "goNoGo",
        "product.selection_recommendation",
        DISPOSITION_PRESERVED,
        note="an explicit product selection/recommendation requires a pinned policy",
        mapping_required=True,
        issue_codes=(ISSUE_POLICY_PIN,),
    ),
    FieldMapping(
        "suitabilityScore",
        "evaluation.score",
        DISPOSITION_PRESERVED,
        note="an evaluation score only when a pinned rubric establishes equivalence",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "desirabilityRank",
        "evaluation.ranking_position",
        DISPOSITION_PRESERVED,
        note="a position in a named ranking artifact; the legacy document names none",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "scoreBreakdownNotes",
        "evaluation.rationale",
        DISPOSITION_PRESERVED,
        note="retained rationale; an evidence-backed assessment requires its evidence references",
        mapping_required=True,
        issue_codes=(ISSUE_EVIDENCE_REQUIRED,),
    ),
    FieldMapping(
        "vetoReason",
        "product.rejection_rationale",
        DISPOSITION_MAPPED,
        note="job-specific rejection rationale; never a posting closure",
    ),
)

_ARTIFACT_FIELDS = (
    FieldMapping("jobId", "portfolio.job_identity", DISPOSITION_MAPPED),
    FieldMapping("functionalTitle", "material.functional_title", DISPOSITION_MAPPED),
    FieldMapping(
        "resumeJson",
        "material.resume_artifact",
        DISPOSITION_RESTRICTED,
        note="immutable restricted structured-resume artifact",
    ),
    FieldMapping(
        "coverLetter",
        "material.cover_artifact",
        DISPOSITION_RESTRICTED,
        note="immutable restricted cover artifact",
    ),
    FieldMapping(
        "supplementalResponses",
        "material.supplemental_artifact",
        DISPOSITION_RESTRICTED,
        note="immutable restricted response artifact",
    ),
    FieldMapping(
        "fabricationLog",
        "integrity.fabrication_log",
        DISPOSITION_MAPPED,
        note="preserved integrity issues and resolutions",
    ),
)

_TRACKER_FIELDS = (
    FieldMapping("jobId", "portfolio.job_identity", DISPOSITION_MAPPED),
    FieldMapping(
        "status",
        "display.legacy_status",
        DISPOSITION_DISPLAY,
        note="legacy display value only; the five life axes are authoritative",
        mapping_required=True,
        issue_codes=(ISSUE_UNKNOWN_ENUM,),
    ),
    FieldMapping(
        "submissionMode",
        "legacy.submission_mode",
        DISPOSITION_PRESERVED,
        note="a commissioned mode requires the commission record plus realized assistance evidence",
        mapping_required=True,
        issue_codes=(ISSUE_EVIDENCE_REQUIRED,),
    ),
    FieldMapping(
        "dateApplied",
        "legacy.date_applied",
        DISPOSITION_SOURCE,
        note="source-preserved business value; an APPLIED display requires commitment evidence",
        mapping_required=True,
        issue_codes=(ISSUE_EVIDENCE_REQUIRED,),
    ),
    FieldMapping(
        "targetSalarySubmitted",
        "legacy.target_salary_submitted",
        DISPOSITION_PRESERVED,
        note="the actually submitted value with unit, currency, and evidence is not supplied here",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "cheatSheetGenerated",
        "legacy.cheat_sheet_generated",
        DISPOSITION_MAPPED,
        note="known generation fact; false is not unknown",
    ),
)

_EMAIL_FIELDS = (
    FieldMapping("threadId", "provider.thread_identity", DISPOSITION_MAPPED),
    FieldMapping(
        "category",
        "classification.versioned_category",
        DISPOSITION_PRESERVED,
        note="a versioned classification result; the legacy document carries no classifier version",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "companyName",
        "match.candidate_employer",
        DISPOSITION_CANDIDATE,
        note="an extracted candidate match, never identity authority",
        mapping_required=True,
        issue_codes=(ISSUE_CANDIDATE_MATCH,),
    ),
    FieldMapping(
        "jobTitle",
        "match.candidate_job",
        DISPOSITION_CANDIDATE,
        note="an extracted candidate match, never identity authority",
        mapping_required=True,
        issue_codes=(ISSUE_CANDIDATE_MATCH,),
    ),
    FieldMapping(
        "actionRequired",
        "work.policy_recommendation",
        DISPOSITION_PRESERVED,
        note="a policy-derived work recommendation requires the pinned policy",
        mapping_required=True,
        issue_codes=(ISSUE_POLICY_PIN,),
    ),
    FieldMapping(
        "summary",
        "derived.summary",
        DISPOSITION_PRESERVED,
        note="a derived summary must cite retained message bytes",
        mapping_required=True,
        issue_codes=(ISSUE_EVIDENCE_REQUIRED,),
    ),
)

_SCHEDULE_FIELDS = (
    FieldMapping("jobId", "portfolio.job_identity", DISPOSITION_MAPPED),
    FieldMapping(
        "startTime",
        "calendar.start_time",
        DISPOSITION_PRESERVED,
        note="a typed calendar value with actual timezone semantics is required; no timezone is guessed",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "endTime",
        "calendar.end_time",
        DISPOSITION_PRESERVED,
        note="a typed calendar value with actual timezone semantics is required; no timezone is guessed",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping("calendarId", "calendar.provider_calendar", DISPOSITION_MAPPED),
    FieldMapping(
        "cheatSheetUrl",
        "resolver.private_url",
        DISPOSITION_MAPPED,
        note="private resolver output for an immutable artifact; never evidence identity and never a substitute for retained bytes",
    ),
)

_SETTINGS_FIELDS = (
    FieldMapping(
        "references",
        "candidate.references",
        DISPOSITION_RESTRICTED,
        note="restricted versioned candidate-reference data",
    ),
    FieldMapping(
        "costLimits",
        "config.cost_limits",
        DISPOSITION_MAPPED,
        note="explicit configuration declarations",
    ),
    FieldMapping(
        "notificationPrefs",
        "config.notification_prefs",
        DISPOSITION_PRESERVED,
        note="a versioned notification policy; the legacy document carries no policy version",
        mapping_required=True,
        issue_codes=(ISSUE_POLICY_PIN,),
    ),
    FieldMapping(
        "addressOverrides",
        "config.address_overrides",
        DISPOSITION_PRESERVED,
        note="address anchors and zone rules must come from authorized profile/policy data; no guessed substitution",
        mapping_required=True,
        issue_codes=(ISSUE_POLICY_PIN,),
    ),
)

_VAULT_FIELDS = (
    FieldMapping(
        "ciphertext",
        "secret.ciphertext",
        DISPOSITION_SECRET,
        note="secret-provider-managed bytes; never copied into an ordinary import artifact",
        mapping_required=True,
        issue_codes=(ISSUE_SECRET_REDACTED,),
    ),
    FieldMapping(
        "iv",
        "secret.iv",
        DISPOSITION_SECRET,
        note="provider-defined cryptographic parameter; no algorithm is established by the field name",
        mapping_required=True,
        issue_codes=(ISSUE_SECRET_REDACTED,),
    ),
    FieldMapping(
        "tag",
        "secret.tag",
        DISPOSITION_SECRET,
        note="provider-defined authentication parameter; no scheme is established by the field name",
        mapping_required=True,
        issue_codes=(ISSUE_SECRET_REDACTED,),
    ),
)

_LOG_FIELDS = (
    FieldMapping(
        "agent",
        "producer.registered_component",
        DISPOSITION_MAPPED,
        note="a registered component/producer identity",
    ),
    FieldMapping(
        "level",
        "operations.severity",
        DISPOSITION_PRESERVED,
        note="private operational severity; interpreted only under a pinned mapping",
        mapping_required=True,
        issue_codes=(ISSUE_UNKNOWN_ENUM,),
    ),
    FieldMapping(
        "message",
        "operations.message",
        DISPOSITION_RESTRICTED,
        note="sanitized operational text; no sanitizer is pinned, so raw text stays restricted",
        mapping_required=True,
        issue_codes=(ISSUE_SANITIZATION,),
    ),
    FieldMapping(
        "timestamp",
        "operations.source_timestamp",
        DISPOSITION_SOURCE,
        note="original source annotation; the actual ingestion TimePoint is assigned by the journal",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "jobId",
        "portfolio.job_identity",
        DISPOSITION_MAPPED,
        note="optional association represented honestly; no fabricated job id",
    ),
)

_COST_FIELDS = (
    FieldMapping("model", "usage.observed_model", DISPOSITION_MAPPED),
    FieldMapping(
        "inputTokens",
        "usage.input_tokens",
        DISPOSITION_PRESERVED,
        note="reported/measured scalar usage with provenance is required",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "outputTokens",
        "usage.output_tokens",
        DISPOSITION_PRESERVED,
        note="reported/measured scalar usage with provenance is required",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "costUsd",
        "usage.cost_usd",
        DISPOSITION_PRESERVED,
        note="a priced derivation or provider charge with declared basis is required",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
    FieldMapping(
        "timestamp",
        "usage.receipt_timepoint",
        DISPOSITION_PRESERVED,
        note="actual receipt TimePoint; the source billing date is retained separately",
        mapping_required=True,
        issue_codes=(ISSUE_UNRESOLVED_TYPE,),
    ),
)

_TASK_FIELDS = (
    FieldMapping("service", "workflow.durable_service", DISPOSITION_MAPPED),
    FieldMapping("handler", "workflow.handler", DISPOSITION_MAPPED),
    FieldMapping(
        "status",
        "workflow.local_scheduler_state",
        DISPOSITION_PRESERVED,
        note="local scheduler state only; never native acceptance or employer commitment",
        mapping_required=True,
        issue_codes=(ISSUE_UNKNOWN_ENUM,),
    ),
    FieldMapping(
        "payload",
        "workflow.private_command",
        DISPOSITION_PRESERVED,
        note="a validated private command references immutable inputs",
    ),
    FieldMapping(
        "result",
        "workflow.local_result",
        DISPOSITION_PRESERVED,
        note="durable local result or typed uncertainty; replay never repeats external mutations",
    ),
)

_NOGO_FIELDS = (
    FieldMapping(
        "title",
        "historical.display_title",
        DISPOSITION_SNAPSHOT,
        note="historical display snapshot",
    ),
    FieldMapping(
        "company",
        "historical.display_company",
        DISPOSITION_SNAPSHOT,
        note="historical display snapshot",
    ),
    FieldMapping(
        "reason",
        "product.rejection_rationale",
        DISPOSITION_PRESERVED,
        note="an evidenced product rejection rationale is required",
        mapping_required=True,
        issue_codes=(ISSUE_EVIDENCE_REQUIRED,),
    ),
)

COLLECTION_ADAPTERS: Mapping[str, CollectionAdapter] = MappingProxyType(
    {
        "jobs": CollectionAdapter(
            collection="jobs",
            identity_field="jobId",
            identity_kind="portfolio_job_identity",
            identity_requires_source_root=True,
            fields=_JOB_FIELDS,
            collision_formula="sha256(companyName|jobTitle|locationRaw)",
            hint_inputs=("company", "title", "location"),
            notes=(
                "a private jobs projection may combine domains for reading; it is never a multi-owner write",
            ),
        ),
        "evaluations": CollectionAdapter(
            collection="evaluations",
            identity_field="evaluationId",
            identity_kind="immutable_evaluation_identity",
            fields=_EVALUATION_FIELDS,
            notes=(
                "absent original types or scoring semantics are migration issues, not defaults",
            ),
        ),
        "artifacts": CollectionAdapter(
            collection="artifacts",
            identity_field="artifactId",
            identity_kind="product_artifact_identity",
            fields=_ARTIFACT_FIELDS,
            notes=(
                "legacy collection content is not overwritten when a new version is generated",
            ),
        ),
        "trackers": CollectionAdapter(
            collection="trackers",
            identity_field="trackerId",
            identity_kind="private_projection_identity",
            fields=_TRACKER_FIELDS,
            notes=(
                "the supplied field list contains no executable status enum; unknown values remain uninterpreted legacy data",
                "a tracker links all relevant attempts rather than treating one job row as one immutable application",
            ),
        ),
        "emails": CollectionAdapter(
            collection="emails",
            identity_field="emailId",
            identity_kind="provider_message_identity",
            fields=_EMAIL_FIELDS,
            notes=(
                "classification is not origin verification; company/title similarity never binds an email to an attempt",
            ),
        ),
        "schedules": CollectionAdapter(
            collection="schedules",
            identity_field="eventId",
            identity_kind="provider_event_identity",
            fields=_SCHEDULE_FIELDS,
            notes=(
                "a calendar write acknowledgement proves neither interview attendance nor employer confirmation",
            ),
        ),
        "settings": CollectionAdapter(
            collection="settings",
            identity_field="userId",
            identity_kind="local_principal_association",
            fields=_SETTINGS_FIELDS,
            notes=(
                "settings updates do not retroactively alter commissioned tasks",
            ),
        ),
        "vault": CollectionAdapter(
            collection="vault",
            identity_field="key",
            identity_kind="private_secret_lookup_identity",
            fields=_VAULT_FIELDS,
            withhold_unmapped=True,
            notes=(
                "the field names establish no cipher suite, key-management system, rotation policy, or authentication algorithm",
                "secret bytes never enter ordinary journals, task fields, logs, source control, or dashboard caches",
            ),
        ),
        "logs": CollectionAdapter(
            collection="logs",
            identity_field=None,
            identity_kind="no_identity_field",
            fields=_LOG_FIELDS,
            notes=(
                "operational logs are not citable evidence unless registered in the relevant journal prefix",
            ),
        ),
        "costs": CollectionAdapter(
            collection="costs",
            identity_field="callId",
            identity_kind="provider_call_identity",
            fields=_COST_FIELDS,
            notes=(
                "missing usage or price remains missing; an exact computed cost is not automatically an invoice fact",
            ),
        ),
        "tasks": CollectionAdapter(
            collection="tasks",
            identity_field="taskId",
            identity_kind="private_work_identity",
            fields=_TASK_FIELDS,
            notes=(
                "Restate completion establishes neither native acceptance nor employer commitment",
            ),
        ),
        "noGoList": CollectionAdapter(
            collection="noGoList",
            identity_field="jobId",
            identity_kind="portfolio_job_association",
            fields=_NOGO_FIELDS,
            collision_formula="companyName|jobTitle",
            hint_field="hashedKey",
            hint_inputs=("company", "title"),
            notes=(
                "a no-go entry is not a crawler closure, permanent global exclusion, or proof of a mandatory credential",
                "reconsideration creates a new decision while retaining the old entry's evidence",
            ),
        ),
    }
)


# ---------------------------------------------------------------------------
# Small coercion helpers
# ---------------------------------------------------------------------------


def _is_missing_mapping(value: Any) -> bool:
    return (
        isinstance(value, dict)
        and "value" in value
        and value.get("value") is None
        and "reason" in value
    )


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate mapping key: {key!r}")
        obj[key] = value
    return obj


def _reject_nonfinite(literal: str) -> Any:
    raise ValueError(f"nonfinite number literal rejected: {literal!r}")


def _parse_source_document(payload: bytes) -> dict[str, Any]:
    """Parse a legacy document with duplicate-key/nonfinite rejection."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacySourceError(f"legacy source bytes are not valid utf-8: {exc}") from exc
    try:
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_nonfinite,
        )
    except (ValueError, TypeError) as exc:
        raise LegacySourceError(f"legacy source is not strict JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise LegacySourceError("a legacy collection document must be a JSON object")
    return document


def _normalize_legacy_value(value: Any, path: str, issues: list[dict[str, Any]]) -> Any:
    """Preserve a decoded legacy value; convert nulls into typed Missing.

    Types are never coerced and strings are never trimmed, case-folded, or
    Unicode-normalized.  Explicit nulls become ``Missing(not_observed)`` so the
    normalized record carries no in-band null.
    """
    if value is None:
        issues.append(
            {
                "code": ISSUE_EXPLICIT_NULL,
                "path": path,
                "detail": "the legacy source carried an explicit null; it is preserved as Missing(not_observed) rather than an in-band null",
            }
        )
        return Missing(
            "not_observed", f"explicit null in the legacy source at {path}"
        ).to_dict()
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, str):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise LegacySourceError(
                f"legacy source at {path} carries a nonfinite number"
            )
        return value
    if isinstance(value, list):
        return [
            _normalize_legacy_value(entry, f"{path}[{index}]", issues)
            for index, entry in enumerate(value)
        ]
    if isinstance(value, dict):
        if "reason" in value and value.get("value") is None and set(value) <= _MISSING_SHAPE_KEYS:
            raise LegacySourceError(
                f"legacy source at {path} claims typed Missing semantics; source "
                "documents never author kernel envelopes"
            )
        return {
            key: _normalize_legacy_value(entry, f"{path}.{key}", issues)
            for key, entry in value.items()
        }
    raise LegacySourceError(
        f"legacy source at {path} carries unsupported value type {type(value).__name__}"
    )


def _retain_restricted_field(
    channel_id: str, owner_domain: str, value: Any
) -> Any:
    """Retain one restricted legacy field value as its own content address."""
    if isinstance(value, str):
        payload = value.encode("utf-8")
        media_type = "text/plain"
    else:
        payload = _canonical_bytes(value)
        media_type = "application/json"
    try:
        return artifact_store.retain_artifact(
            channel_id, owner_domain, media_type, payload, "restricted"
        )
    except (artifact_store.ArtifactError, TypeError, ValueError) as exc:
        raise LegacyProjectionError(
            f"restricted field artifact could not be retained: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Projection construction
# ---------------------------------------------------------------------------


def _authorize_import(channel_id: str, collection: str) -> Any:
    try:
        descriptor = access_policy.authorize(channel_id, IMPORT_OPERATION, collection)
    except access_policy.AuthorizationError as exc:
        raise LegacyAuthorityError(
            "legacy import requires an authenticated channel holding the "
            f"{IMPORT_OPERATION!r} grant: {exc}"
        ) from exc
    if descriptor.owner_domain != PRIVATE_OWNER_DOMAIN:
        raise LegacyAuthorityError(
            f"legacy imports remain private to {PRIVATE_OWNER_DOMAIN!r}; "
            f"authenticated domain is {descriptor.owner_domain!r}"
        )
    return descriptor


def _coerce_source(source: Any) -> Any:
    try:
        if isinstance(source, artifact_store.ArtifactReference):
            reference = source
        elif isinstance(source, Mapping):
            reference = artifact_store.ArtifactReference.from_dict(dict(source))
        else:
            raise TypeError(
                "source must be an ArtifactReference, not "
                f"{type(source).__name__}"
            )
    except (TypeError, ValueError) as exc:
        raise LegacySourceError(
            f"source is not a valid ArtifactReference: {exc}"
        ) from exc
    if reference.access != "restricted":
        raise LegacySourceError(
            "legacy documents are imported only as restricted source "
            f"artifacts; {reference.digest} is {reference.access!r}"
        )
    return reference


def _coerce_mapping(mapping: Any) -> VersionPin:
    try:
        if isinstance(mapping, VersionPin):
            return mapping
        if isinstance(mapping, Mapping):
            keys = set(mapping.keys())
            expected = {"id", "version", "artifact_digest"}
            if keys != expected:
                raise ValueError(
                    f"mapping pin must contain exactly {sorted(expected)}; "
                    f"got {sorted(keys)}"
                )
            return VersionPin(
                id=mapping["id"],
                version=mapping["version"],
                artifact_digest=mapping["artifact_digest"],
            )
        raise TypeError(f"mapping must be a VersionPin, not {type(mapping).__name__}")
    except (TypeError, ValueError) as exc:
        raise LegacyMappingError(
            f"mapping is not a valid pinned legacy adapter: {exc}"
        ) from exc


def _identity_entry(
    adapter: CollectionAdapter,
    document: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> tuple[dict[str, Any], str]:
    entry: dict[str, Any] = {
        "kind": adapter.identity_kind,
        "legacy_field": adapter.identity_field or "none",
    }
    identity_text = ""
    if adapter.identity_field is None:
        entry["value"] = Missing(
            "not_applicable",
            f"legacy {adapter.collection} records carry no identity field; the "
            "record is identified by its restricted source artifact",
        ).to_dict()
    elif adapter.identity_field in document:
        normalized = _normalize_legacy_value(
            document[adapter.identity_field], adapter.identity_field, issues
        )
        entry["value"] = normalized
        if isinstance(normalized, str) and normalized:
            identity_text = normalized
        else:
            issues.append(
                {
                    "code": ISSUE_IDENTITY_MISSING,
                    "legacy_field": adapter.identity_field,
                    "detail": "the legacy identity is not a nonempty string; it is preserved verbatim and the record falls back to its source digest",
                }
            )
    else:
        entry["value"] = Missing(
            "not_observed",
            f"the legacy document has no {adapter.identity_field} field; identity remains unknown",
        ).to_dict()
        issues.append(
            {
                "code": ISSUE_IDENTITY_MISSING,
                "legacy_field": adapter.identity_field,
                "detail": "a missing legacy identity is never substituted with company/title similarity",
            }
        )
    if adapter.identity_requires_source_root:
        entry["source_root"] = Missing(
            "not_observed",
            "legacy documents carry no crawler source target or job id; "
            "association requires a separate evidenced relation",
        ).to_dict()
    return entry, identity_text


def _field_entry(
    mapping: FieldMapping, value: Any, retained: Any | None = None
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "legacy_field": mapping.legacy_field,
        "target": mapping.target,
        "disposition": mapping.disposition,
        "value": value,
        "mapping_required": mapping.mapping_required,
        "published_axis": Missing(
            "not_applicable",
            "an import preserves a private projection only; no shared owner axis is published",
        ).to_dict(),
        "note": mapping.note,
    }
    if retained is not None:
        entry["retained_artifact"] = retained.to_dict()
    return entry


def _collision_hint(
    adapter: CollectionAdapter,
    document: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> Any:
    if adapter.collision_formula is None:
        return Missing(
            "not_applicable",
            f"the {adapter.collection} collection defines no legacy duplicate formula",
        ).to_dict()
    if adapter.hint_field is not None and adapter.hint_field in document:
        hashed: Any = _normalize_legacy_value(
            document[adapter.hint_field], adapter.hint_field, issues
        )
        note = (
            "the stored legacy hash is preserved verbatim; its encoding and "
            "normalization are not supplied and it is never recomputed here"
        )
    else:
        hashed = Missing(
            "not_observed",
            "the legacy hash encoding and normalization are not supplied; "
            "recomputation requires a pinned adapter",
        ).to_dict()
        note = (
            "the documented legacy formula is recorded for reference only; no "
            "hash is recomputed without a pinned adapter"
        )
    return {
        "formula": adapter.collision_formula,
        "hashed_key": hashed,
        "inputs_present": [name for name in adapter.hint_inputs if name in document],
        "recomputed": False,
        "authority": "duplicate_candidate_hint_only",
        "may_merge_identities": False,
        "note": note,
    }


def _project_document(
    adapter: CollectionAdapter,
    document: Mapping[str, Any],
    *,
    channel_id: str,
    owner_domain: str,
    source: Any,
    pin: VersionPin,
) -> tuple[dict[str, Any], list[Any], bool]:
    issues: list[dict[str, Any]] = []
    field_entries: dict[str, Any] = {}
    unmapped: dict[str, Any] = {}
    retained_fields: list[Any] = []

    identity, identity_text = _identity_entry(adapter, document, issues)

    for mapping in adapter.fields:
        if mapping.legacy_field not in document:
            entry = _field_entry(
                mapping,
                Missing(
                    "not_observed",
                    f"the legacy document has no {mapping.legacy_field} field",
                ).to_dict(),
            )
            entry["mapping_required"] = False
            field_entries[mapping.target] = entry
            issues.append(
                {
                    "code": ISSUE_MISSING_FIELD,
                    "legacy_field": mapping.legacy_field,
                    "target": mapping.target,
                    "detail": "absence remains Missing(not_observed); no default or inferred value is applied",
                }
            )
            continue
        normalized = _normalize_legacy_value(
            document[mapping.legacy_field], mapping.legacy_field, issues
        )
        retained = None
        if mapping.disposition == DISPOSITION_SECRET:
            normalized = Missing(
                "not_applicable",
                "secret bytes remain behind the scoped secret-provider boundary; "
                "legacy vault content is never copied into an ordinary import artifact",
            ).to_dict()
        elif mapping.disposition == DISPOSITION_RESTRICTED and not _is_missing_mapping(
            normalized
        ):
            retained = _retain_restricted_field(channel_id, owner_domain, normalized)
            retained_fields.append(retained)
            normalized = Missing(
                "not_applicable",
                "the legacy value is retained as its own restricted artifact; it "
                "is not inlined into the private projection",
            ).to_dict()
        field_entries[mapping.target] = _field_entry(mapping, normalized, retained)
        for code in mapping.issue_codes:
            issues.append(
                {
                    "code": code,
                    "legacy_field": mapping.legacy_field,
                    "target": mapping.target,
                    "detail": mapping.note or f"{code} applies to {mapping.legacy_field}",
                }
            )

    declared = {mapping.legacy_field for mapping in adapter.fields}
    for field_name, raw_value in document.items():
        if field_name == adapter.identity_field:
            continue
        if field_name == adapter.hint_field:
            continue
        if field_name in declared:
            continue
        if adapter.withhold_unmapped:
            unmapped[field_name] = Missing(
                "not_applicable",
                "an unmapped vault field is withheld; secret material never "
                "enters ordinary import artifacts",
            ).to_dict()
            detail = "unmapped vault field withheld rather than preserved"
        else:
            unmapped[field_name] = _normalize_legacy_value(
                raw_value, field_name, issues
            )
            detail = "no canonical mapping is declared; the value is preserved verbatim and requires an explicit mapping"
        issues.append(
            {
                "code": ISSUE_UNMAPPED_FIELD,
                "legacy_field": field_name,
                "detail": detail,
            }
        )

    collision = _collision_hint(adapter, document, issues)
    mapping_required = bool(unmapped) or any(
        entry["mapping_required"] for entry in field_entries.values()
    )
    if identity_text:
        record_id = f"{adapter.collection}:{identity_text}"
    else:
        record_id = (
            f"{adapter.collection}:unidentified:"
            f"{source.digest.removeprefix('sha256:')[:16]}"
        )
    projection: dict[str, Any] = {
        "record_type": "legacy_import_projection",
        "schema_version": PROJECTION_SCHEMA_VERSION,
        "collection": adapter.collection,
        "private": True,
        "rebuildable": True,
        "authority": "private_projection",
        "shared_contract": False,
        "observation_scope": "historical_preserved_source",
        "promoted_to_current_run": False,
        "adapter": pin.to_dict(),
        "source_artifact": source.to_dict(),
        "legacy_identity": identity,
        "fields": field_entries,
        "unmapped_fields": unmapped,
        "issues": issues,
        "mapping_required": mapping_required,
        "identity_rules": {
            "derived_from": "legacy_identity_field",
            "collision_hint_authority": (
                "duplicate_candidate_hint_only"
                if adapter.collision_formula is not None
                else "not_applicable"
            ),
            "automatic_merge": False,
        },
        "collision_hint": collision,
        "adapter_notes": list(adapter.notes),
    }
    return {"id": record_id, "timing": projection}, retained_fields, mapping_required


def _validate_projection(body: dict[str, Any]) -> bytes:
    try:
        return contract_codec.validate_record(_canonical_bytes(body), RECORD_SCHEMA_ID)
    except (TypeError, ValueError) as exc:
        raise LegacyProjectionError(
            f"normalized projection failed the strict codec gate: {exc}"
        ) from exc


def _claim_producer_sequence(channel_id: str, descriptor: Any) -> Any:
    """Claim the next producer sequence for this channel's import producer.

    The tier-3 interface exposes no sequence allocator; the producer's own
    counter lives here and only ever advances.  Gaps after a rejected import
    are harmless: evidence-journal requires strictly increasing sequences, not
    contiguous ones.
    """
    if not descriptor.sequence_required:
        return evidence_journal.NOT_APPLICABLE
    key = (channel_id, descriptor.producer_id)
    with _SEQUENCE_LOCK:
        sequence = _SEQUENCES.get(key, 0) + 1
        _SEQUENCES[key] = sequence
    return sequence


def _journal_import(
    channel_id: str,
    descriptor: Any,
    adapter: CollectionAdapter,
    pin: VersionPin,
    source: Any,
    normalized: Any,
    retained_fields: Sequence[Any],
    mapping_required: bool,
    issues: Sequence[Mapping[str, Any]],
) -> Any:
    ordered: list[Any] = []
    seen: set[str] = set()
    for reference in (source, normalized, *retained_fields):
        if reference.digest in seen:
            continue
        seen.add(reference.digest)
        ordered.append(reference)
    submission = evidence_journal.EventSubmission(
        producer_sequence=_claim_producer_sequence(channel_id, descriptor),
        event_kind=IMPORT_EVENT_KIND,
        event_schema_version=IMPORT_EVENT_SCHEMA_VERSION,
        # The import act is now; the legacy document carries no observed
        # occurrence time and this module is given no clock registry, so the
        # occurrence stays an explicit Missing while the journal assigns the
        # authenticated receipt time.
        occurred_at=evidence_journal.NOT_OBSERVED,
        payload=evidence_journal.EvidencePayload(
            data={
                "collection": adapter.collection,
                "adapter": pin.to_dict(),
                "identity_kind": adapter.identity_kind,
                "issue_codes": sorted({issue["code"] for issue in issues}),
                "mapping_required": mapping_required,
                "document_scope": "historical_legacy_import",
                "promoted_to_current_run": False,
                "private_projection": True,
            },
            measurements=[],
            evidence_refs=[],
            artifact_refs=[reference.to_dict() for reference in ordered],
        ),
    )
    try:
        return evidence_journal.append_event(
            channel_id, descriptor.owner_domain, submission
        )
    except (
        evidence_journal.EvidenceJournalError,
        access_policy.AuthorizationError,
    ) as exc:
        raise LegacyEvidenceError(
            "the legacy import was not registered in the owning journal: "
            f"{exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def import_legacy_document(
    channel_id: str,
    collection: str,
    source: artifact_store.ArtifactReference,
    mapping: VersionPin,
) -> artifact_store.ArtifactReference:
    """Import one legacy document as a private, evidenced projection.

    Steps: authorize the authenticated channel's private write grant, resolve
    the restricted source artifact, preserve every source value (unknown
    enums/types stay uninterpreted), retain restricted field content as its own
    artifacts, validate the projection through the strict codec gate, retain
    the projection as ``restricted`` bytes, and journal one
    ``legacy.document_imported`` event citing the source and projection.

    The returned :class:`ArtifactReference` is the private projection.  The raw
    legacy document is never modified and is never promoted into a current-run
    observation.
    """
    _require_identifier(channel_id, "channel_id")
    if not isinstance(collection, str) or collection not in COLLECTION_ADAPTERS:
        raise UnknownLegacyCollectionError(
            f"unknown legacy collection {collection!r}; the twelve private "
            f"namespaces are {list(LEGACY_COLLECTIONS)}"
        )
    adapter = COLLECTION_ADAPTERS[collection]
    descriptor = _authorize_import(channel_id, collection)
    pin = _coerce_mapping(mapping)
    reference = _coerce_source(source)

    try:
        payload = artifact_store.resolve_artifact(channel_id, reference)
    except (artifact_store.ArtifactError, TypeError, ValueError) as exc:
        raise LegacySourceError(
            f"legacy source {reference.digest} could not be resolved under the "
            f"authenticated channel: {exc}"
        ) from exc
    document = _parse_source_document(payload)

    body, retained_fields, mapping_required = _project_document(
        adapter,
        document,
        channel_id=channel_id,
        owner_domain=descriptor.owner_domain,
        source=reference,
        pin=pin,
    )
    canonical = _validate_projection(body)
    try:
        normalized = artifact_store.retain_artifact(
            channel_id,
            descriptor.owner_domain,
            "application/json",
            canonical,
            "restricted",
        )
    except (artifact_store.ArtifactError, TypeError, ValueError) as exc:
        raise LegacyProjectionError(
            f"the private projection could not be retained: {exc}"
        ) from exc

    issues = body["timing"]["issues"]
    _journal_import(
        channel_id,
        descriptor,
        adapter,
        pin,
        reference,
        normalized,
        retained_fields,
        mapping_required,
        issues,
    )
    return normalized
