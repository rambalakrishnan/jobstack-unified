"""access_policy: authenticated ingress authorization + secret quarantine.

Tier-0 authority for the job-hunter subsystem. This module answers two
questions and nothing else:

* Which authenticated ingress channel may perform which authoritative write
  (seam mapping 2.3 write grants; invariants EXT-AUTHORITY, LIFE-AXES,
  OWD-OWNER, EK-PROVENANCE)?
* How do secret bytes stay out of ordinary journals, task fields, logs,
  source control, and dashboard caches (seam mapping 16.9 and section 18)?

Control plane vs data plane
---------------------------
``register_channel`` is the authenticated control plane. It binds an ingress
``channel_id`` to a server-assigned :class:`ProducerDescriptor` and derives the
bounded grant from the registration's *actor* policy. Callers never widen that
grant at request time: ``authorize`` resolves the channel handle and returns
the registered descriptor. Serialized ``writer_id``, producer ids, provenance
labels, role labels, hashes, or digests never influence the decision.

``authorize_event_submission`` is the untrusted-ingress path for an
``EventSubmission`` (evidence kernel). It rejects submitted server-assigned
fields, assigns producer identity, provenance, owner domain, role,
assertion kind, event id, and sequence from the authenticated registration and
the registered event registry, and screens the payload for secret material
before anything could reach an ordinary journal.

Operation vocabulary
--------------------
``authorize(channel_id, operation, resource_id)`` grants exactly one
``<owner-axis>.write`` operation per axis, plus derived-publication pointer and
seal operations. Unknown operation strings (for example a whole-attempt status
update) are denied; no multi-axis command exists here. ``resource_id`` is the
scope the write applies to (an entity, attempt, or job identity). It is never
bearer authority.

Secret policy
-------------
``screen_ordinary_content`` rejects payloads that carry secret bytes or bare
nulls (absent values must use :class:`Missing` envelopes).
``quarantine_ordinary_content`` moves offending content into restricted
in-process storage and returns an opaque ``quarantine:`` reference that is safe
for ordinary records. ``resolve_quarantine`` requires a registered runtime
binding with the ``quarantine.resolve`` scope and a matching credential;
reference or hash possession alone grants nothing. ``sanitize_task_fields`` and
``redact_log_text`` are the task-field and log counterparts.

Error taxonomy
--------------
* :class:`AuthorizationError` (a ``PermissionError``) is the base for runtime
  denials: :class:`UnknownChannelError` (authentication),
  :class:`SpoofDetectedError` (serialized identity claims),
  :class:`GrantDeniedError` (authenticated but not granted),
  :class:`RegistrationConflictError` (control-plane duplication),
  :class:`VaultAccessDenied`, and :class:`SecretDetectedError`.
* :class:`InvalidSubmissionError` and :class:`ContentContractError` are
  ``ValueError`` subclasses for malformed ingress/content shapes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

__all__ = [
    "ACTOR_POLICIES",
    "ASSERTION_KINDS",
    "EVENT_ROLES",
    "MISSING_REASONS",
    "NOT_APPLICABLE",
    "ORDINARY_SINKS",
    "PRODUCER_ROLES",
    "PROVENANCES",
    "AuthorizationError",
    "ContentContractError",
    "EventKindDeclaration",
    "GrantDeniedError",
    "IngestionAssignment",
    "InvalidSubmissionError",
    "Missing",
    "ProducerDescriptor",
    "QuarantineReceipt",
    "RegistrationConflictError",
    "SecretDetectedError",
    "SecretFinding",
    "SpoofDetectedError",
    "TaskFieldSanitization",
    "UnknownChannelError",
    "VaultAccessDenied",
    "authorize",
    "authorize_event_submission",
    "binding_projection",
    "channel_projection",
    "contains_secret_material",
    "grants_for_actor",
    "is_opaque_reference",
    "quarantine_count",
    "quarantine_ordinary_content",
    "redact_log_text",
    "register_channel",
    "register_event_kind",
    "register_runtime_binding",
    "resolve_quarantine",
    "reset_for_tests",
    "revoke_channel",
    "sanitize_task_fields",
    "scan_secret_material",
    "screen_ordinary_content",
]

# ---------------------------------------------------------------------------
# Contract enums and vocabulary
# ---------------------------------------------------------------------------

PRODUCER_ROLES = frozenset(
    {
        "kernel",
        "application_origin",
        "connector",
        "subject",
        "observer",
        "analyzer",
        "lease_authority",
        "importer",
    }
)
PROVENANCES = frozenset(
    {"server", "fixture_client", "connector", "subject", "manual_observer", "importer"}
)
ASSERTION_KINDS = frozenset(
    {"observation", "claim", "authoritative_effect", "derived_assessment"}
)
EVENT_ROLES = frozenset({"external_input", "derived_output", "lifecycle_observation"})
MISSING_REASONS = frozenset(
    {
        "not_enabled",
        "not_applicable",
        "not_observed",
        "observation_lost",
        "unsupported_by_subject",
        "manual_override",
    }
)
ORDINARY_SINKS = frozenset(
    {"journal", "task_fields", "log", "dashboard_cache", "source_control"}
)


# ---------------------------------------------------------------------------
# Missing envelope and identifier validation
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Missing:
    """Typed missingness envelope (evidence kernel ``K.Missing``).

    ``value`` is always ``None``; callers must never put a bare null in a
    record, task field, or journal payload.
    """

    reason: str = "not_applicable"
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.reason not in MISSING_REASONS:
            raise ValueError(f"unknown Missing reason: {self.reason!r}")
        if self.detail is not None and (
            not isinstance(self.detail, str) or not self.detail
        ):
            raise ValueError("Missing.detail must be a nonempty string when present")

    @property
    def value(self) -> None:
        return None

    def to_dict(self) -> dict[str, object]:
        out: dict[str, object] = {"value": None, "reason": self.reason}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


NOT_APPLICABLE = Missing("not_applicable")


def _require_identifier(value: object, field: str) -> str:
    """Validate an opaque contract identifier (no spelling-based authority)."""
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field} must be at most 256 characters")
    if "\x00" in value or any(ord(char) < 0x20 for char in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SecretFinding:
    """A secret-material finding. Never stores the offending value."""

    path: str
    category: str

    def describe(self) -> str:
        return f"{self.category} at {self.path}"


class AuthorizationError(PermissionError):
    """Base class for every runtime authorization denial."""


class UnknownChannelError(AuthorizationError):
    """``channel_id`` resolves to no authenticated ingress session."""


class GrantDeniedError(AuthorizationError):
    """Channel is authenticated but holds no grant for the requested write."""


class RegistrationConflictError(AuthorizationError):
    """Control-plane registration would duplicate or recycle authority."""


class VaultAccessDenied(AuthorizationError):
    """Scoped runtime binding is absent, wrong, or lacks the requested scope."""


class SpoofDetectedError(AuthorizationError):
    """Serialized provenance/writer identity was submitted and is rejected."""

    def __init__(self, fields: Sequence[str], *, context: str = "submission") -> None:
        self.fields = tuple(fields)
        super().__init__(
            f"spoofed provenance/writer identity rejected in {context}: "
            + ", ".join(self.fields)
            + "; authority derives only from authenticated registration"
        )


class SecretDetectedError(AuthorizationError):
    """Secret material was rejected for an ordinary sink (and quarantined)."""

    def __init__(
        self,
        findings: Sequence[SecretFinding],
        *,
        sink: str,
        receipt: QuarantineReceipt | None = None,
    ) -> None:
        self.findings = tuple(findings)
        self.sink = sink
        self.receipt = receipt
        detail = ", ".join(finding.describe() for finding in self.findings)
        message = f"secret material rejected for ordinary sink {sink!r}: {detail}"
        if receipt is not None:
            message += f"; quarantined as {receipt.reference}"
        super().__init__(message)


class InvalidSubmissionError(ValueError):
    """Submission shape violates the EventSubmission contract."""


class ContentContractError(ValueError):
    """Ordinary content violates missingness or JSON-content constraints."""


# ---------------------------------------------------------------------------
# Secret scanning
# ---------------------------------------------------------------------------

_SECRET_FIELD_NAMES = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth_token",
        "bearer_token",
        "ciphertext",
        "client_secret",
        "cookie",
        "credential",
        "credentials",
        "password",
        "passphrase",
        "passwd",
        "private_key",
        "refresh_token",
        "secret",
        "secret_key",
        "session_token",
        "set_cookie",
        "signing_key",
        "token",
    }
)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")),
    (
        "jwt",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
    ),
    ("bearer_token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("provider_api_key", re.compile(r"\bsk-[A-Za-z0-9]{16,}\b")),
    (
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|passphrase|secret|api[_-]?key|"
            r"access[_-]?token|refresh[_-]?token|client[_-]?secret|"
            r"private[_-]?key)\b\s*[:=]\s*[^\s,;\"']{4,}"
        ),
    ),
)

_PLACEHOLDER_VALUES = frozenset(
    {"", "[redacted]", "<redacted>", "redacted", "***", "none", "null"}
)

_OPAQUE_PREFIXES = (
    "artifact:",
    "binding:",
    "credentialref:",
    "evidence:",
    "quarantine:",
    "secretref:",
    "vaultref:",
)
_OPAQUE_BODY_RE = re.compile(r"[A-Za-z0-9._~-]{8,}")


def is_opaque_reference(value: object) -> bool:
    """True when ``value`` is an opaque scoped reference, not secret bytes."""
    if not isinstance(value, str):
        return False
    for prefix in _OPAQUE_PREFIXES:
        if value.startswith(prefix):
            return _OPAQUE_BODY_RE.fullmatch(value[len(prefix) :]) is not None
    return False


def _normalized_key(key: object) -> str:
    return str(key).strip().lower().replace("-", "_")


def _value_has_secret(value: object) -> bool:
    if isinstance(value, Missing):
        return False
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "ignore")
    if not isinstance(value, str):
        return False
    stripped = value.strip()
    if not stripped:
        return False
    if stripped.lower() in _PLACEHOLDER_VALUES:
        return False
    if is_opaque_reference(stripped):
        return False
    return True


def _scan_text(text: str, path: str) -> list[SecretFinding]:
    stripped = text.strip()
    if not stripped:
        return []
    if is_opaque_reference(stripped) or stripped.lower() in _PLACEHOLDER_VALUES:
        return []
    findings: list[SecretFinding] = []
    for category, pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            findings.append(SecretFinding(path, category))
    return findings


def _is_missing_like(node: object) -> bool:
    if isinstance(node, Missing):
        return True
    if isinstance(node, Mapping):
        keys = set(node.keys())
        return (
            keys in ({"value", "reason"}, {"value", "reason", "detail"})
            and node.get("value") is None
        )
    return False


def _validate_missing_envelope(node: object, path: str) -> None:
    if isinstance(node, Missing):
        return
    if not isinstance(node, Mapping):
        raise ContentContractError(f"malformed Missing envelope at {path}")
    extra = set(node.keys()) - {"value", "reason", "detail"}
    if extra or "value" not in node:
        raise ContentContractError(f"malformed Missing envelope at {path}")
    if node.get("value") is not None:
        raise ContentContractError(f"Missing.value must be null at {path}")
    reason = node.get("reason")
    if reason not in MISSING_REASONS:
        raise ContentContractError(f"unknown Missing reason at {path}: {reason!r}")
    if "detail" in node:
        detail = node["detail"]
        if not isinstance(detail, str) or not detail:
            raise ContentContractError(
                f"Missing.detail must be a nonempty string at {path}"
            )


def _validate_ordinary_structure(node: object, path: str) -> None:
    """Reject bare nulls, NUL bytes, raw bytes, and non-JSON values."""
    if node is None:
        raise ContentContractError(
            f"bare null at {path}; use a typed Missing envelope"
        )
    if isinstance(node, Missing):
        return
    if isinstance(node, Mapping):
        if _is_missing_like(node):
            _validate_missing_envelope(node, path)
            return
        for key, value in node.items():
            if not isinstance(key, str):
                raise ContentContractError(
                    f"non-string mapping key at {path}: {type(key).__name__}"
                )
            if "\x00" in key:
                raise ContentContractError(f"NUL byte in key at {path}")
            _validate_ordinary_structure(value, f"{path}.{key}")
        return
    if isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _validate_ordinary_structure(value, f"{path}[{index}]")
        return
    if isinstance(node, (bytes, bytearray)):
        raise ContentContractError(
            f"raw bytes at {path}; retain as a restricted artifact instead of "
            "ordinary content"
        )
    if isinstance(node, bool) or isinstance(node, int):
        return
    if isinstance(node, float):
        if not math.isfinite(node):
            raise ContentContractError(f"non-finite number at {path}")
        return
    if isinstance(node, str):
        if "\x00" in node:
            raise ContentContractError(f"NUL byte at {path}")
        return
    raise ContentContractError(
        f"value at {path} is not ordinary JSON content ({type(node).__name__})"
    )


def _scan_node(node: object, path: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    if isinstance(node, Missing):
        return findings
    if isinstance(node, Mapping):
        if _is_missing_like(node):
            return findings
        for key, value in node.items():
            child = f"{path}.{key}"
            if _normalized_key(key) in _SECRET_FIELD_NAMES and _value_has_secret(
                value
            ):
                findings.append(SecretFinding(child, "credential_field"))
            findings.extend(_scan_node(value, child))
        return findings
    if isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            findings.extend(_scan_node(value, f"{path}[{index}]"))
        return findings
    if isinstance(node, (bytes, bytearray)):
        findings.extend(_scan_text(bytes(node).decode("utf-8", "ignore"), path))
        return findings
    if isinstance(node, str):
        findings.extend(_scan_text(node, path))
    return findings


def scan_secret_material(content: object) -> tuple[SecretFinding, ...]:
    """Return deduplicated secret-material findings for arbitrary content."""
    seen: set[tuple[str, str]] = set()
    ordered: list[SecretFinding] = []
    for finding in _scan_node(content, "$"):
        marker = (finding.path, finding.category)
        if marker in seen:
            continue
        seen.add(marker)
        ordered.append(finding)
    return tuple(ordered)


def contains_secret_material(content: object) -> bool:
    """True when ``content`` carries secret bytes (opaque refs are clean)."""
    if isinstance(content, str):
        return bool(_scan_text(content, "$"))
    if isinstance(content, (bytes, bytearray)):
        return bool(_scan_text(bytes(content).decode("utf-8", "ignore"), "$"))
    return bool(scan_secret_material(content))


def _require_sink(where: object) -> str:
    if not isinstance(where, str) or where not in ORDINARY_SINKS:
        raise ValueError(
            f"unknown ordinary sink: {where!r}; expected one of {sorted(ORDINARY_SINKS)}"
        )
    return where


# ---------------------------------------------------------------------------
# Quarantine and scoped runtime bindings
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class QuarantineReceipt:
    """Opaque receipt for quarantined content. Carries no secret bytes."""

    reference: str
    where: str
    reason: str
    size_bytes: int

    def public_projection(self) -> dict[str, object]:
        return {
            "reference": self.reference,
            "where": self.where,
            "reason": self.reason,
            "size_bytes": self.size_bytes,
            "vault_access": Missing(
                "not_observed", "requires scoped runtime binding"
            ).to_dict(),
        }


@dataclass(frozen=True, slots=True)
class TaskFieldSanitization:
    """Task-field copy with secret leaves replaced by opaque references."""

    sanitized: Mapping[str, object]
    receipts: tuple[QuarantineReceipt, ...]

    def references(self) -> tuple[str, ...]:
        return tuple(receipt.reference for receipt in self.receipts)


@dataclass(frozen=True, slots=True)
class _QuarantineEntry:
    payload: bytes
    where: str
    reason: str
    created_ns: int


@dataclass(frozen=True, slots=True)
class _RuntimeBinding:
    binding_id: str
    credential_digest: str
    scopes: frozenset[str]
    opaque_reference: str


_LOCK = threading.RLock()
_QUARANTINE: dict[str, _QuarantineEntry] = {}
_RUNTIME_BINDINGS: dict[str, _RuntimeBinding] = {}
_ALLOWED_RUNTIME_SCOPES = frozenset(
    {"quarantine.resolve", "artifact.restricted", "dashboard.projection"}
)


def _json_fallback(value: object) -> object:
    if isinstance(value, Missing):
        return value.to_dict()
    if isinstance(value, (bytes, bytearray)):
        return {"restricted_bytes_base64": base64.b64encode(bytes(value)).decode("ascii")}
    raise TypeError(f"object of type {type(value).__name__} is not quarantinable")


def _restricted_bytes(content: object) -> bytes:
    if isinstance(content, (bytes, bytearray)):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    try:
        encoded = json.dumps(
            content,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
            default=_json_fallback,
        )
    except (TypeError, ValueError) as exc:
        raise ContentContractError(
            f"content cannot be serialized for quarantine: {exc}"
        ) from exc
    return encoded.encode("utf-8")


def register_runtime_binding(
    binding_id: str, credential: str, scopes: Sequence[str]
) -> str:
    """Register a scoped runtime access binding; returns an opaque reference.

    Only a SHA-256 digest of the credential is retained. The credential itself
    is never stored, projected, or logged.
    """
    _require_identifier(binding_id, "binding_id")
    if not isinstance(credential, str) or len(credential) < 12:
        raise ValueError(
            "runtime credential must be a string of at least 12 characters"
        )
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise TypeError("scopes must be a sequence of scope names")
    scope_set = frozenset(scopes)
    if not scope_set:
        raise ValueError("a runtime binding requires at least one scope")
    unknown = scope_set - _ALLOWED_RUNTIME_SCOPES
    if unknown:
        raise ValueError(f"unknown runtime scopes: {sorted(unknown)}")
    for scope in scope_set:
        if not isinstance(scope, str):
            raise TypeError("runtime scopes must be strings")
    digest = hashlib.sha256(credential.encode("utf-8")).hexdigest()
    with _LOCK:
        if binding_id in _RUNTIME_BINDINGS:
            raise RegistrationConflictError(
                f"runtime binding {binding_id!r} is already registered"
            )
        opaque_reference = "vaultref:" + secrets.token_urlsafe(18)
        _RUNTIME_BINDINGS[binding_id] = _RuntimeBinding(
            binding_id=binding_id,
            credential_digest=digest,
            scopes=scope_set,
            opaque_reference=opaque_reference,
        )
    return opaque_reference


def binding_projection(binding_id: str) -> dict[str, object]:
    """Public view of a runtime binding; never includes the credential."""
    _require_identifier(binding_id, "binding_id")
    with _LOCK:
        binding = _RUNTIME_BINDINGS.get(binding_id)
    if binding is None:
        raise KeyError(f"unknown runtime binding: {binding_id!r}")
    return {
        "binding_id": binding.binding_id,
        "scopes": sorted(binding.scopes),
        "credential_reference": binding.opaque_reference,
    }


def quarantine_ordinary_content(
    content: object, *, where: str, reason: str = "operator_review"
) -> QuarantineReceipt:
    """Move sensitive content into restricted storage; return an opaque receipt."""
    _require_sink(where)
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("reason must be a nonempty string")
    payload = _restricted_bytes(content)
    reference = "quarantine:" + secrets.token_urlsafe(18)
    receipt = QuarantineReceipt(
        reference=reference,
        where=where,
        reason=reason.strip(),
        size_bytes=len(payload),
    )
    with _LOCK:
        _QUARANTINE[reference] = _QuarantineEntry(
            payload=payload,
            where=where,
            reason=reason.strip(),
            created_ns=time.time_ns(),
        )
    return receipt


def resolve_quarantine(
    binding_id: str, credential: str, reference: str
) -> bytes:
    """Resolve quarantined bytes through a privileged runtime binding.

    Reference possession alone grants nothing: the binding must exist, the
    credential must match, and the binding must carry ``quarantine.resolve``.
    """
    _require_identifier(binding_id, "binding_id")
    _require_identifier(reference, "reference")
    if not isinstance(credential, str):
        raise VaultAccessDenied("a runtime credential is required")
    with _LOCK:
        binding = _RUNTIME_BINDINGS.get(binding_id)
        if binding is None:
            raise VaultAccessDenied("no such runtime binding")
        digest = hashlib.sha256(credential.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(digest, binding.credential_digest):
            raise VaultAccessDenied("runtime credential does not match the binding")
        if "quarantine.resolve" not in binding.scopes:
            raise VaultAccessDenied("binding lacks the quarantine.resolve scope")
        entry = _QUARANTINE.get(reference)
    if entry is None:
        raise KeyError(f"unknown quarantine reference: {reference!r}")
    return entry.payload


def quarantine_count() -> int:
    """Number of entries currently held in restricted quarantine storage."""
    with _LOCK:
        return len(_QUARANTINE)


def screen_ordinary_content(content: object, *, where: str) -> None:
    """Reject content bound for an ordinary sink.

    Raises :class:`SecretDetectedError` on secret material and
    :class:`ContentContractError` on bare nulls, NUL bytes, raw bytes, or
    non-JSON values.
    """
    _require_sink(where)
    _validate_ordinary_structure(content, "$")
    findings = scan_secret_material(content)
    if findings:
        raise SecretDetectedError(findings, sink=where)


def _sanitize_node(
    node: object, path: str, receipts: list[QuarantineReceipt]
) -> object:
    if isinstance(node, Missing):
        return node.to_dict()
    if isinstance(node, Mapping):
        if _is_missing_like(node):
            return dict(node)
        sanitized: dict[str, object] = {}
        for key, value in node.items():
            child = f"{path}.{key}"
            if _normalized_key(key) in _SECRET_FIELD_NAMES and _value_has_secret(
                value
            ):
                receipt = quarantine_ordinary_content(
                    value, where="task_fields", reason="secret_task_field"
                )
                receipts.append(receipt)
                sanitized[key] = receipt.reference
                continue
            sanitized[key] = _sanitize_node(value, child, receipts)
        return sanitized
    if isinstance(node, (list, tuple)):
        return [
            _sanitize_node(value, f"{path}[{index}]", receipts)
            for index, value in enumerate(node)
        ]
    if isinstance(node, str):
        if _scan_text(node, path):
            receipt = quarantine_ordinary_content(
                node, where="task_fields", reason="secret_task_field"
            )
            receipts.append(receipt)
            return receipt.reference
        return node
    return node


def sanitize_task_fields(fields: Mapping[str, object]) -> TaskFieldSanitization:
    """Return a task-field copy whose secret leaves are opaque references."""
    if not isinstance(fields, Mapping):
        raise TypeError("task fields must be a mapping")
    _validate_ordinary_structure(fields, "$")
    receipts: list[QuarantineReceipt] = []
    sanitized = _sanitize_node(fields, "$", receipts)
    if not isinstance(sanitized, Mapping):
        raise ContentContractError("task fields must remain a mapping")
    return TaskFieldSanitization(sanitized=sanitized, receipts=tuple(receipts))


def redact_log_text(text: str, *, where: str = "log") -> str:
    """Redact secret spans from operational log text."""
    _require_sink(where)
    if not isinstance(text, str):
        raise TypeError("log text must be a string")
    if "\x00" in text:
        raise ContentContractError("NUL byte in log text")
    if is_opaque_reference(text.strip()):
        return text
    spans: list[tuple[int, int]] = []
    for _category, pattern in _SECRET_PATTERNS:
        spans.extend((match.start(), match.end()) for match in pattern.finditer(text))
    if not spans:
        return text
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        pieces.append("[redacted:secret]")
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


# ---------------------------------------------------------------------------
# Producer descriptors and actor write grants (seam mapping 2.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProducerDescriptor:
    """Server-assigned producer identity (evidence-kernel/0.1.0).

    Registration conveys a bounded write grant, never a control credential.
    """

    producer_id: str
    principal_id: str
    owner_domain: str
    role: str
    provenance: str
    sequence_required: bool
    allowed_event_kinds: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.producer_id, "producer_id")
        _require_identifier(self.principal_id, "principal_id")
        _require_identifier(self.owner_domain, "owner_domain")
        if self.role not in PRODUCER_ROLES:
            raise ValueError(f"unknown producer role: {self.role!r}")
        if self.provenance not in PROVENANCES:
            raise ValueError(f"unknown provenance: {self.provenance!r}")
        if type(self.sequence_required) is not bool:
            raise TypeError("sequence_required must be a bool")
        kinds = self.allowed_event_kinds
        if isinstance(kinds, (str, bytes)) or not isinstance(kinds, Sequence):
            raise TypeError("allowed_event_kinds must be a sequence of identifiers")
        normalized = tuple(kinds)
        if not normalized:
            raise ValueError("allowed_event_kinds requires at least one event kind")
        for kind in normalized:
            _require_identifier(kind, "allowed_event_kinds")
        if len(set(normalized)) != len(normalized):
            raise ValueError("allowed_event_kinds must be unique")
        object.__setattr__(self, "allowed_event_kinds", normalized)

    def to_dict(self) -> dict[str, object]:
        return {
            "producer_id": self.producer_id,
            "principal_id": self.principal_id,
            "owner_domain": self.owner_domain,
            "role": self.role,
            "provenance": self.provenance,
            "sequence_required": self.sequence_required,
            "allowed_event_kinds": list(self.allowed_event_kinds),
        }


@dataclass(frozen=True, slots=True)
class ActorPolicy:
    """Authenticated actor registration policy (never caller-overridable)."""

    role: str
    provenance: str
    axes: Mapping[str, tuple[str, ...]]
    binding_required: bool = False


ACTOR_POLICIES: Mapping[str, ActorPolicy] = MappingProxyType(
    {
        "crawler_writer": ActorPolicy(
            role="kernel",
            provenance="server",
            axes={"job.crawler": ("job.crawler.write",)},
        ),
        "product_writer": ActorPolicy(
            role="kernel",
            provenance="server",
            axes={"job.downstream": ("job.downstream.write",)},
        ),
        "connector": ActorPolicy(
            role="connector",
            provenance="connector",
            axes={
                "attempt.dispatch": ("attempt.dispatch.write",),
                "attempt.observation": ("attempt.observation.write",),
            },
            binding_required=True,
        ),
        "subject_adapter": ActorPolicy(
            role="subject",
            provenance="subject",
            axes={"attempt.execution": ("attempt.execution.write",)},
        ),
        "manual_recorder": ActorPolicy(
            role="observer",
            provenance="manual_observer",
            axes={"attempt.observation": ("attempt.observation.write",)},
        ),
        "origin_fact_recorder": ActorPolicy(
            role="application_origin",
            provenance="server",
            axes={"attempt.application": ("attempt.application.write",)},
            binding_required=True,
        ),
        "reconciler": ActorPolicy(
            role="analyzer",
            provenance="server",
            axes={"attempt.report": ("attempt.report.write",)},
        ),
        "read_view_publisher": ActorPolicy(
            role="kernel",
            provenance="server",
            axes={
                "publication.derived": (
                    "publication.pointer.write",
                    "publication.seal.write",
                )
            },
        ),
        "dashboard": ActorPolicy(
            role="kernel",
            provenance="server",
            axes={"presentation.dashboard": ()},
        ),
    }
)

_KNOWN_AXES = frozenset(
    axis for policy in ACTOR_POLICIES.values() for axis in policy.axes
)


def grants_for_actor(
    actor: str, axis: str | Missing = NOT_APPLICABLE
) -> frozenset[str]:
    """Return the write-operation preset for an actor (all axes or one)."""
    if not isinstance(actor, str) or actor not in ACTOR_POLICIES:
        raise ValueError(f"unknown actor: {actor!r}")
    policy = ACTOR_POLICIES[actor]
    if isinstance(axis, Missing):
        return frozenset(
            operation for operations in policy.axes.values() for operation in operations
        )
    if not isinstance(axis, str):
        raise TypeError("axis must be a string or a Missing envelope")
    if axis not in policy.axes:
        return frozenset()
    return frozenset(policy.axes[axis])


# ---------------------------------------------------------------------------
# Channel registry (authenticated ingress)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ChannelBinding:
    channel_id: str
    actor: str
    descriptor: ProducerDescriptor
    grants: frozenset[str]
    axis: str
    binding: str | Missing
    registered_ns: int


_CHANNELS: dict[str, _ChannelBinding] = {}
_PRODUCER_IDENTITIES: dict[str, tuple[str, str]] = {}
_RETIRED_PRODUCERS: set[str] = set()
_AXIS_OWNERS: dict[tuple[str, str], str] = {}
_SEQUENCES: dict[str, int] = {}
_EVENT_KINDS: dict[tuple[str, str], "EventKindDeclaration"] = {}


def _require_channel(channel_id: object) -> _ChannelBinding:
    if not isinstance(channel_id, str) or not channel_id:
        raise UnknownChannelError(
            "channel_id resolves to no authenticated ingress session"
        )
    with _LOCK:
        binding = _CHANNELS.get(channel_id)
    if binding is None:
        raise UnknownChannelError(
            "channel_id resolves to no authenticated ingress session"
        )
    return binding


def register_channel(
    *,
    actor: str,
    channel_id: str,
    axis: str,
    producer_id: str,
    principal_id: str,
    sequence_required: bool,
    allowed_event_kinds: Sequence[str],
    binding: str | Missing = NOT_APPLICABLE,
) -> ProducerDescriptor:
    """Bind an authenticated ingress channel to a producer + bounded grant.

    This is the authenticated control plane. The descriptor is assigned from
    the actor policy; the caller cannot choose a role, provenance, or a grant
    outside the actor's fixed axes. A producer id that already belongs to
    another principal/actor, a retired producer id, or a second writer for the
    same axis is rejected.
    """
    if not isinstance(actor, str) or actor not in ACTOR_POLICIES:
        raise ValueError(f"unknown actor: {actor!r}")
    policy = ACTOR_POLICIES[actor]
    if not isinstance(axis, str) or axis not in policy.axes:
        raise GrantDeniedError(
            f"{actor!r} holds no write authority for axis {axis!r}"
        )
    _require_identifier(channel_id, "channel_id")
    if isinstance(binding, Missing):
        if policy.binding_required:
            raise GrantDeniedError(
                f"{actor!r} writes only through an authenticated bound registration"
            )
        binding_value: str | Missing = binding
    else:
        _require_identifier(binding, "binding")
        if not policy.binding_required:
            raise ValueError(f"{actor!r} does not accept a runtime binding")
        binding_value = binding
    if type(sequence_required) is not bool:
        raise TypeError("sequence_required must be a bool")

    operations = policy.axes[axis]
    descriptor = ProducerDescriptor(
        producer_id=producer_id,
        principal_id=principal_id,
        owner_domain=axis,
        role=policy.role,
        provenance=policy.provenance,
        sequence_required=sequence_required,
        allowed_event_kinds=tuple(allowed_event_kinds),
    )

    with _LOCK:
        if channel_id in _CHANNELS:
            raise RegistrationConflictError(
                f"channel {channel_id!r} is already registered; revoke it first"
            )
        if producer_id in _RETIRED_PRODUCERS:
            raise RegistrationConflictError(
                "producer ids are never recycled after revocation"
            )
        identity = (principal_id, actor)
        previous = _PRODUCER_IDENTITIES.get(producer_id)
        if previous is not None and previous != identity:
            raise RegistrationConflictError(
                "producer id already belongs to another principal/actor; "
                "writer identity cannot be spoofed"
            )
        axis_key = (axis, policy.provenance)
        owner = _AXIS_OWNERS.get(axis_key)
        if owner is not None and owner != producer_id:
            raise RegistrationConflictError(
                f"axis {axis!r} already has its single bound publication writer"
            )
        _PRODUCER_IDENTITIES[producer_id] = identity
        _AXIS_OWNERS[axis_key] = producer_id
        _CHANNELS[channel_id] = _ChannelBinding(
            channel_id=channel_id,
            actor=actor,
            descriptor=descriptor,
            grants=frozenset(operations),
            axis=axis,
            binding=binding_value,
            registered_ns=time.time_ns(),
        )
    return descriptor


def revoke_channel(channel_id: str) -> None:
    """Revoke an ingress session; its producer id is retired, not recycled."""
    _require_identifier(channel_id, "channel_id")
    with _LOCK:
        binding = _CHANNELS.pop(channel_id, None)
        if binding is None:
            raise UnknownChannelError(
                "channel_id resolves to no authenticated ingress session"
            )
        producer_id = binding.descriptor.producer_id
        remaining = [
            other
            for other in _CHANNELS.values()
            if other.descriptor.producer_id == producer_id
        ]
        if not remaining:
            _RETIRED_PRODUCERS.add(producer_id)
            _PRODUCER_IDENTITIES.pop(producer_id, None)
            _SEQUENCES.pop(producer_id, None)
        for axis_key, owner in list(_AXIS_OWNERS.items()):
            if owner != producer_id:
                continue
            still_bound = any(
                other.descriptor.producer_id == producer_id
                and other.axis == axis_key[0]
                and ACTOR_POLICIES[other.actor].provenance == axis_key[1]
                for other in _CHANNELS.values()
            )
            if not still_bound:
                del _AXIS_OWNERS[axis_key]


def channel_projection(channel_id: str) -> dict[str, object]:
    """Public view of a channel registration; carries no secret material."""
    binding = _require_channel(channel_id)
    return {
        "channel_id": binding.channel_id,
        "actor": binding.actor,
        "axis": binding.axis,
        "grants": sorted(binding.grants),
        "producer": binding.descriptor.to_dict(),
        "binding": (
            binding.binding.to_dict()
            if isinstance(binding.binding, Missing)
            else binding.binding
        ),
    }


# ---------------------------------------------------------------------------
# Authorization (data plane)
# ---------------------------------------------------------------------------

_IDENTITY_CLAIM_RE = re.compile(
    r"(?i)(?:writer_id|producer_id|principal_id|provenance|owner_domain|role|"
    r"assertion_kind|event_hash|manifest_hash|authority|grants?)\s*[:=]"
)


def _reject_serialized_identity(value: str, label: str) -> None:
    if _IDENTITY_CLAIM_RE.search(value):
        raise SpoofDetectedError(
            [f"{label}:serialized_identity_claim"],
            context="operation/resource identifiers",
        )


def authorize(channel_id: str, operation: str, resource_id: str) -> ProducerDescriptor:
    """Authorize one authoritative write for an authenticated channel.

    Resolves ``channel_id`` to its registered ingress session, rejects
    serialized identity claims and secret material in the operation strings,
    checks the bounded grant, and returns the *registered*
    :class:`ProducerDescriptor`. Caller-supplied strings never influence the
    returned identity.
    """
    binding = _require_channel(channel_id)
    op = _require_identifier(operation, "operation")
    resource = _require_identifier(resource_id, "resource_id")
    _reject_serialized_identity(op, "operation")
    _reject_serialized_identity(resource, "resource_id")
    findings = scan_secret_material(op) + scan_secret_material(resource)
    if findings:
        raise SecretDetectedError(findings, sink="authorize_identifiers")
    if op not in binding.grants:
        raise GrantDeniedError(
            f"authenticated channel holds no {op!r} write grant"
        )
    policy = ACTOR_POLICIES[binding.actor]
    if policy.binding_required and isinstance(binding.binding, Missing):
        raise GrantDeniedError(
            "write grant requires an active authenticated binding"
        )
    return binding.descriptor


# ---------------------------------------------------------------------------
# Event registry and EventSubmission ingress (EK-PROVENANCE)
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventKindDeclaration:
    """Manifest-pinned registry entry for one event kind + schema version."""

    event_kind: str
    event_schema_version: str
    role: str
    assertion_kind: str
    owner_domain: str
    writer_roles: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_identifier(self.event_kind, "event_kind")
        _require_identifier(self.event_schema_version, "event_schema_version")
        if self.role not in EVENT_ROLES:
            raise ValueError(f"unknown event role: {self.role!r}")
        if self.assertion_kind not in ASSERTION_KINDS:
            raise ValueError(
                f"unknown assertion kind: {self.assertion_kind!r}"
            )
        _require_identifier(self.owner_domain, "owner_domain")
        if self.owner_domain not in _KNOWN_AXES:
            raise ValueError(f"unknown owner domain: {self.owner_domain!r}")
        roles = self.writer_roles
        if isinstance(roles, (str, bytes)) or not isinstance(roles, Sequence):
            raise TypeError("writer_roles must be a sequence of producer roles")
        normalized = tuple(roles)
        if not normalized:
            raise ValueError("writer_roles requires at least one producer role")
        for role in normalized:
            if role not in PRODUCER_ROLES:
                raise ValueError(f"unknown producer role in writer_roles: {role!r}")
        if len(set(normalized)) != len(normalized):
            raise ValueError("writer_roles must be unique")
        if (
            self.assertion_kind == "authoritative_effect"
            and self.owner_domain == "attempt.application"
            and set(normalized) != {"application_origin"}
        ):
            raise ValueError(
                "application authoritative_effect entries admit "
                "application_origin only"
            )
        object.__setattr__(self, "writer_roles", normalized)

    def to_dict(self) -> dict[str, object]:
        return {
            "event_kind": self.event_kind,
            "event_schema_version": self.event_schema_version,
            "role": self.role,
            "assertion_kind": self.assertion_kind,
            "owner_domain": self.owner_domain,
            "writer_roles": list(self.writer_roles),
        }


def register_event_kind(
    event_kind: str,
    event_schema_version: str,
    *,
    role: str,
    assertion_kind: str,
    owner_domain: str,
    writer_roles: Sequence[str],
) -> EventKindDeclaration:
    """Register a manifest-pinned event kind; kind+version is unique."""
    declaration = EventKindDeclaration(
        event_kind=event_kind,
        event_schema_version=event_schema_version,
        role=role,
        assertion_kind=assertion_kind,
        owner_domain=owner_domain,
        writer_roles=writer_roles,  # type: ignore[arg-type]
    )
    with _LOCK:
        key = (declaration.event_kind, declaration.event_schema_version)
        if key in _EVENT_KINDS:
            raise RegistrationConflictError(
                "event kind/version is already registered"
            )
        _EVENT_KINDS[key] = declaration
    return declaration


_SUBMISSION_FIELDS = frozenset(
    {"producer_sequence", "event_kind", "event_schema_version", "occurred_at", "payload"}
)
_SERVER_ASSIGNED_FIELDS = frozenset(
    {
        "assertion_kind",
        "authority",
        "causal_refs",
        "digest",
        "event_hash",
        "event_id",
        "evidence_scope",
        "grants",
        "hashes",
        "journal_id",
        "journal_sequence",
        "manifest_hash",
        "owner_domain",
        "payload_hash",
        "previous_event_hash",
        "principal_id",
        "producer_id",
        "provenance",
        "received_at",
        "record_type",
        "recorded_at",
        "role",
        "run_id",
        "schema_version",
        "sequence",
        "writer_id",
        "writer_role",
    }
)
_PAYLOAD_FIELDS = frozenset(
    {"data", "measurements", "evidence_refs", "artifact_refs"}
)


def _validate_submission(submission: object) -> Mapping[str, object]:
    if not isinstance(submission, Mapping):
        raise InvalidSubmissionError("EventSubmission must be a mapping")
    keys = set(submission.keys())
    spoofed = sorted(str(key) for key in keys & _SERVER_ASSIGNED_FIELDS)
    if spoofed:
        raise SpoofDetectedError(spoofed, context="EventSubmission")
    unknown = sorted(str(key) for key in keys - _SUBMISSION_FIELDS)
    if unknown:
        raise InvalidSubmissionError(
            f"unknown EventSubmission fields: {unknown}"
        )
    missing = sorted(_SUBMISSION_FIELDS - keys)
    if missing:
        raise InvalidSubmissionError(
            f"EventSubmission is missing required fields: {missing}"
        )
    _validate_ordinary_structure(submission, "$")

    _require_identifier(submission["event_kind"], "event_kind")
    _require_identifier(submission["event_schema_version"], "event_schema_version")
    occurred_at = submission["occurred_at"]
    if not isinstance(occurred_at, (Missing, Mapping)):
        raise InvalidSubmissionError(
            "occurred_at must be a TimePoint mapping or a typed Missing envelope"
        )

    sequence = submission["producer_sequence"]
    if _is_missing_like(sequence):
        _validate_missing_envelope(sequence, "$.producer_sequence")
    elif isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
        raise InvalidSubmissionError(
            "producer_sequence must be a positive integer or a typed Missing "
            "envelope; bare nulls are not accepted"
        )

    payload = submission["payload"]
    if not isinstance(payload, Mapping):
        raise InvalidSubmissionError("payload must be an EvidencePayload mapping")
    payload_keys = set(payload.keys())
    if payload_keys != _PAYLOAD_FIELDS:
        raise InvalidSubmissionError(
            "payload must contain exactly "
            f"{sorted(_PAYLOAD_FIELDS)}; got {sorted(map(str, payload_keys))}"
        )
    if not isinstance(payload["data"], Mapping):
        raise InvalidSubmissionError("payload.data must be an EvidenceMap mapping")
    for field in ("measurements", "evidence_refs", "artifact_refs"):
        value = payload[field]
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise InvalidSubmissionError(f"payload.{field} must be a sequence")
    return submission


@dataclass(frozen=True, slots=True)
class IngestionAssignment:
    """Server-assigned identity/authority fields for one accepted submission."""

    event_id: str
    event_kind: str
    event_schema_version: str
    occurred_at: object
    producer_id: str
    principal_id: str
    owner_domain: str
    role: str
    provenance: str
    assertion_kind: str
    producer_sequence: object
    received_at_ns: int
    payload: Mapping[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "event_kind": self.event_kind,
            "event_schema_version": self.event_schema_version,
            "occurred_at": (
                self.occurred_at.to_dict()
                if isinstance(self.occurred_at, Missing)
                else self.occurred_at
            ),
            "producer_id": self.producer_id,
            "principal_id": self.principal_id,
            "owner_domain": self.owner_domain,
            "role": self.role,
            "provenance": self.provenance,
            "assertion_kind": self.assertion_kind,
            "producer_sequence": (
                self.producer_sequence.to_dict()
                if isinstance(self.producer_sequence, Missing)
                else self.producer_sequence
            ),
            "received_at_ns": self.received_at_ns,
            "payload": self.payload,
        }


def authorize_event_submission(
    channel_id: str, submission: Mapping[str, object]
) -> IngestionAssignment:
    """Validate an untrusted EventSubmission and assign server identity.

    Submitted server-assigned fields (producer id, provenance, owner domain,
    role, assertion kind, event id, sequence, hashes, writer labels) are
    rejected outright; they are assigned here from the authenticated
    registration and the registered event registry. Secret material in the
    submission is quarantined and rejected for the journal sink.
    """
    binding = _require_channel(channel_id)
    validated = _validate_submission(submission)
    event_kind = validated["event_kind"]
    event_schema_version = validated["event_schema_version"]
    with _LOCK:
        declaration = _EVENT_KINDS.get((event_kind, event_schema_version))
    if declaration is None:
        raise InvalidSubmissionError(
            "event kind/version is not registered in the manifest event registry"
        )
    descriptor = binding.descriptor
    if event_kind not in descriptor.allowed_event_kinds:
        raise GrantDeniedError(
            "event kind is outside the producer's registered write grant"
        )
    if declaration.owner_domain != descriptor.owner_domain:
        raise GrantDeniedError(
            "event kind belongs to a different owner domain than this channel"
        )
    if descriptor.role not in declaration.writer_roles:
        raise GrantDeniedError(
            "registered producer role is not admitted for this event kind"
        )
    if not grants_for_actor(binding.actor, descriptor.owner_domain):
        raise GrantDeniedError(
            "authenticated channel holds no authoritative write for this "
            "owner domain"
        )

    findings = scan_secret_material(validated)
    if findings:
        receipt = quarantine_ordinary_content(
            validated,
            where="journal",
            reason="secret_material_in_event_submission",
        )
        raise SecretDetectedError(findings, sink="journal", receipt=receipt)

    sequence = validated["producer_sequence"]
    if _is_missing_like(sequence):
        if descriptor.sequence_required:
            raise InvalidSubmissionError(
                "registered producer requires a positive producer_sequence"
            )
    else:
        assert isinstance(sequence, int)
        with _LOCK:
            last = _SEQUENCES.get(descriptor.producer_id, 0)
            if sequence <= last:
                raise InvalidSubmissionError(
                    "producer_sequence must strictly increase per producer"
                )
            _SEQUENCES[descriptor.producer_id] = sequence

    payload = validated["payload"]
    return IngestionAssignment(
        event_id="evt_" + secrets.token_hex(12),
        event_kind=event_kind,
        event_schema_version=event_schema_version,
        occurred_at=validated["occurred_at"],
        producer_id=descriptor.producer_id,
        principal_id=descriptor.principal_id,
        owner_domain=descriptor.owner_domain,
        role=descriptor.role,
        provenance=descriptor.provenance,
        assertion_kind=declaration.assertion_kind,
        producer_sequence=sequence,
        received_at_ns=time.time_ns(),
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Test isolation
# ---------------------------------------------------------------------------


def reset_for_tests() -> None:
    """Clear every registry and quarantine store (test harness only)."""
    with _LOCK:
        _CHANNELS.clear()
        _PRODUCER_IDENTITIES.clear()
        _RETIRED_PRODUCERS.clear()
        _AXIS_OWNERS.clear()
        _SEQUENCES.clear()
        _EVENT_KINDS.clear()
        _QUARANTINE.clear()
        _RUNTIME_BINDINGS.clear()
