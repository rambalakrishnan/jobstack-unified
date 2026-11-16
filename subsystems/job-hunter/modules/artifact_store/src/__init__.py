"""artifact_store: immutable content-addressed artifact retention (tier 1).

Citable artifacts are immutable, content-addressed, access-classified, and
resolved only through an authenticated channel. Digests name exact bytes
(``sha256:<64 lowercase hex>`` of the stored bytes). References grant no
read authority: hash possession alone resolves nothing.

Loss is an integrity incident, not garbage collection: resolving a digest
whose bytes were retained but are no longer available raises
:class:`ArtifactLostError` with an ``observation_lost`` Missing envelope,
while a digest that was never retained raises
:class:`ArtifactUnavailableError` with a ``not_observed`` envelope. The
known digest is never erased by a failed retrieval.

Redaction produces a new artifact with derivation evidence; the original
bytes keep their digest and remain resolvable.
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


def _load_sibling(name: str):  # pragma: no cover - import plumbing
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

__all__ = [
    "ArtifactReference",
    "ArtifactError",
    "ArtifactUnavailableError",
    "ArtifactLostError",
    "ArtifactAccessDeniedError",
    "retain_artifact",
    "resolve_artifact",
    "redact_artifact",
    "retain_validated_record",
    "redaction_derivation",
    "derivations",
    "known_digests",
    "reset_for_tests",
    "drop_retained_bytes_for_tests",
]

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ACCESS_CLASSES = frozenset({"public", "restricted"})

_LOCK = threading.Lock()
_BYTES: dict[str, bytes] = {}
_KNOWN: set[str] = set()
_META: dict[str, "ArtifactReference"] = {}
_DERIVATIONS: list[dict[str, Any]] = []
_DERIVATION_BY_DIGEST: dict[str, dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ArtifactError(Exception):
    """Base class for artifact retention/resolution failures."""


class ArtifactUnavailableError(ArtifactError):
    """No bytes were ever retained for the requested digest.

    Carries a ``not_observed`` Missing envelope. The requested digest is
    preserved on :attr:`digest` and never erased by the failed retrieval.
    """

    def __init__(self, digest: str, missing: dict[str, Any], message: str) -> None:
        self.digest = digest
        self.missing = missing
        super().__init__(message)


class ArtifactLostError(ArtifactError):
    """Retained bytes are no longer available: an integrity incident.

    Carries an ``observation_lost`` Missing envelope. This is never
    successful garbage collection.
    """

    def __init__(self, digest: str, missing: dict[str, Any], message: str) -> None:
        self.digest = digest
        self.missing = missing
        super().__init__(message)


class ArtifactAccessDeniedError(ArtifactError, PermissionError):
    """An authenticated channel may not resolve a restricted artifact."""


# ---------------------------------------------------------------------------
# Value type
# ---------------------------------------------------------------------------


def _require_identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field} must be a str, not {type(value).__name__}")
    if not value or value != value.strip():
        raise ValueError(f"{field} must be a nonempty identifier without padding")
    if len(value) > 256:
        raise ValueError(f"{field} must be at most 256 characters")
    if "\x00" in value or any(ord(c) < 0x20 for c in value):
        raise ValueError(f"{field} must not contain control characters")
    return value


def _require_media_type(value: object) -> str:
    # Media types (e.g. "application/json") allow "/" but never NUL/controls.
    return _require_identifier(value, "media_type")


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """Immutable byte identity (``K.ArtifactReference``).

    Fields: ``digest``, ``size_bytes``, ``media_type``, ``owner_domain``,
    ``access``. Possession grants no read authority.
    """

    digest: str
    size_bytes: int
    media_type: str
    owner_domain: str
    access: str

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not _DIGEST_RE.match(self.digest):
            raise ValueError(f"invalid artifact digest: {self.digest!r}")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise TypeError("size_bytes must be an int")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be nonnegative")
        _require_media_type(self.media_type)
        _require_identifier(self.owner_domain, "owner_domain")
        if self.access not in _ACCESS_CLASSES:
            raise ValueError(
                f"access must be one of {sorted(_ACCESS_CLASSES)}, "
                f"got {self.access!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
            "owner_domain": self.owner_domain,
            "access": self.access,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ArtifactReference":
        if not isinstance(data, dict):
            raise TypeError("ArtifactReference must be decoded from a dict")
        allowed = {"digest", "size_bytes", "media_type", "owner_domain", "access"}
        extra = set(data.keys()) - allowed
        if extra:
            raise ValueError(f"undeclared ArtifactReference properties: {sorted(extra)}")
        missing = allowed - set(data.keys())
        if missing:
            raise ValueError(f"missing ArtifactReference properties: {sorted(missing)}")
        for key in allowed:
            if data[key] is None:
                raise ValueError(
                    f"ArtifactReference.{key} must not be a bare null; "
                    "all fields are required"
                )
        return cls(
            digest=data["digest"],
            size_bytes=data["size_bytes"],
            media_type=data["media_type"],
            owner_domain=data["owner_domain"],
            access=data["access"],
        )


def _coerce_reference(ref: Any) -> ArtifactReference:
    if isinstance(ref, ArtifactReference):
        return ref
    if isinstance(ref, dict):
        return ArtifactReference.from_dict(ref)
    raise TypeError(
        "reference must be an ArtifactReference or dict, "
        f"not {type(ref).__name__}"
    )


def _exact_digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _authorize_retain(channel_id: str, owner_domain: str) -> Any:
    """Authorize an owner-local retain through the registered channel."""
    projection = access_policy.channel_projection(channel_id)
    axis = projection["axis"]
    if axis != owner_domain:
        raise access_policy.GrantDeniedError(
            f"owner-local write required: channel axis {axis!r} cannot "
            f"retain for owner_domain {owner_domain!r}"
        )
    grants = list(projection["grants"])
    if not grants:
        raise access_policy.GrantDeniedError(
            f"authenticated channel holds no write grant for {owner_domain!r}"
        )
    # Exercise the data-plane grant; the descriptor is server-assigned.
    return access_policy.authorize(channel_id, grants[0], owner_domain)


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def retain_artifact(
    channel_id: str,
    owner_domain: str,
    media_type: str,
    content: bytes,
    access: str,
) -> ArtifactReference:
    """Retain exact immutable bytes and return their content address.

    Bytes and access metadata are durable before this function returns.
    Re-retaining identical bytes is idempotent and yields the same digest.
    """
    _require_identifier(channel_id, "channel_id")
    _require_identifier(owner_domain, "owner_domain")
    _require_media_type(media_type)
    if isinstance(content, bytearray):
        content = bytes(content)
    if not isinstance(content, bytes):
        raise TypeError(f"content must be bytes, not {type(content).__name__}")
    if access not in _ACCESS_CLASSES:
        raise ValueError(
            f"access must be one of {sorted(_ACCESS_CLASSES)}, got {access!r}"
        )
    _authorize_retain(channel_id, owner_domain)
    digest = _exact_digest(content)
    ref = ArtifactReference(
        digest=digest,
        size_bytes=len(content),
        media_type=media_type,
        owner_domain=owner_domain,
        access=access,
    )
    with _LOCK:
        existing = _BYTES.get(digest)
        if existing is not None and existing != content:
            missing = contract_codec.make_missing(
                "observation_lost",
                f"stored bytes for {digest} no longer match their digest; "
                "integrity incident",
            )
            raise ArtifactLostError(digest, missing, missing["detail"])
        # Durable install before acknowledgement (owner-local effect).
        _BYTES[digest] = bytes(content)
        _KNOWN.add(digest)
        _META.setdefault(digest, ref)
    return ref


def resolve_artifact(channel_id: str, reference: ArtifactReference) -> bytes:
    """Resolve the exact retained bytes for a reference.

    Requires an authenticated channel; digest possession alone grants
    nothing. Restricted artifacts resolve only within their owner domain.
    Missing bytes raise explicit loss/unavailability errors; hashes alone
    or reconstructed bytes are never substituted.
    """
    _require_identifier(channel_id, "channel_id")
    ref = _coerce_reference(reference)
    projection = access_policy.channel_projection(channel_id)
    if ref.access == "restricted" and projection["axis"] != ref.owner_domain:
        raise ArtifactAccessDeniedError(
            f"restricted artifact {ref.digest} in {ref.owner_domain!r} "
            f"is not readable from channel axis {projection['axis']!r}; "
            "reference possession grants no read authority"
        )
    with _LOCK:
        payload = _BYTES.get(ref.digest)
        known = ref.digest in _KNOWN
    if payload is None:
        if known:
            missing = contract_codec.make_missing(
                "observation_lost",
                f"retained bytes for {ref.digest} are unavailable; "
                "loss is an integrity incident, not garbage collection",
            )
            raise ArtifactLostError(ref.digest, missing, missing["detail"])
        missing = contract_codec.make_missing(
            "not_observed",
            f"no retained bytes for {ref.digest}",
        )
        raise ArtifactUnavailableError(ref.digest, missing, missing["detail"])
    if len(payload) != ref.size_bytes:
        missing = contract_codec.make_missing(
            "observation_lost",
            f"size mismatch for {ref.digest}: reference names "
            f"{ref.size_bytes} bytes but {len(payload)} are stored; "
            "integrity incident",
        )
        raise ArtifactLostError(ref.digest, missing, missing["detail"])
    if _exact_digest(payload) != ref.digest:
        missing = contract_codec.make_missing(
            "observation_lost",
            f"digest mismatch for {ref.digest}: stored bytes changed; "
            "integrity incident",
        )
        raise ArtifactLostError(ref.digest, missing, missing["detail"])
    return payload


# ---------------------------------------------------------------------------
# Redaction (new identity + derivation evidence, original preserved)
# ---------------------------------------------------------------------------


def redact_artifact(
    channel_id: str,
    source: ArtifactReference,
    redacted_content: bytes,
    *,
    media_type: str | None = None,
    access: str | None = None,
) -> ArtifactReference:
    """Retain a redacted export as a new artifact; preserve the original.

    The redacted bytes receive a new digest. A derivation record linking
    the source digest to the redacted digest is stored as evidence. The
    original bytes are never replaced or mutated.
    """
    _require_identifier(channel_id, "channel_id")
    src = _coerce_reference(source)
    if isinstance(redacted_content, bytearray):
        redacted_content = bytes(redacted_content)
    if not isinstance(redacted_content, bytes):
        raise TypeError(
            f"redacted_content must be bytes, not {type(redacted_content).__name__}"
        )
    # The derivation must come from available original bytes.
    original = resolve_artifact(channel_id, src)
    if redacted_content == original:
        raise ValueError(
            "redaction must produce different bytes; identical bytes would "
            "share the original digest instead of receiving a new identity"
        )
    new_media = src.media_type if media_type is None else media_type
    new_access = src.access if access is None else access
    redacted = retain_artifact(
        channel_id, src.owner_domain, new_media, redacted_content, new_access
    )
    if redacted.digest == src.digest:  # pragma: no cover - unreachable
        raise ArtifactLostError(
            src.digest,
            contract_codec.make_missing(
                "observation_lost", "redaction digest collision; integrity incident"
            ),
            "redaction digest collision",
        )
    derivation: dict[str, Any] = {
        "record_type": "redaction_derivation",
        "source_digest": src.digest,
        "source_size_bytes": src.size_bytes,
        "redacted_digest": redacted.digest,
        "redacted_size_bytes": redacted.size_bytes,
        "owner_domain": src.owner_domain,
        "media_type": redacted.media_type,
        "access": redacted.access,
    }
    with _LOCK:
        # Original bytes must still be exactly what they were.
        current = _BYTES.get(src.digest)
        if current is None or current != original:
            missing = contract_codec.make_missing(
                "observation_lost",
                f"original bytes for {src.digest} changed during redaction; "
                "integrity incident",
            )
            raise ArtifactLostError(src.digest, missing, missing["detail"])
        _DERIVATIONS.append(dict(derivation))
        _DERIVATION_BY_DIGEST[redacted.digest] = dict(derivation)
    return redacted


def retain_validated_record(
    channel_id: str,
    owner_domain: str,
    media_type: str,
    content: bytes,
    access: str,
    schema_id: str,
) -> ArtifactReference:
    """Validate structured bytes via contract_codec, then retain them.

    Raw artifacts may carry arbitrary bytes, but normalized records must
    pass :func:`contract_codec.validate_record` (no bare nulls, no
    duplicate keys, declared properties only) before retention.
    """
    contract_codec.validate_record(content, schema_id)
    return retain_artifact(channel_id, owner_domain, media_type, content, access)


def redaction_derivation(redacted_digest: str) -> dict[str, Any]:
    """Return the derivation evidence for a redacted artifact digest."""
    _require_identifier(redacted_digest, "redacted_digest")
    with _LOCK:
        derivation = _DERIVATION_BY_DIGEST.get(redacted_digest)
        if derivation is None:
            raise KeyError(f"no redaction derivation for {redacted_digest!r}")
        return dict(derivation)


def derivations() -> tuple[dict[str, Any], ...]:
    """All recorded redaction derivations (oldest first)."""
    with _LOCK:
        return tuple(dict(d) for d in _DERIVATIONS)


def known_digests() -> frozenset[str]:
    """Digests ever retained (failed retrieval never erases them)."""
    with _LOCK:
        return frozenset(_KNOWN)


def reset_for_tests() -> None:
    """Clear retained bytes, identities, and derivations (tests only)."""
    with _LOCK:
        _BYTES.clear()
        _KNOWN.clear()
        _META.clear()
        _DERIVATIONS.clear()
        _DERIVATION_BY_DIGEST.clear()


def drop_retained_bytes_for_tests(digest: str) -> None:
    """Simulate an integrity incident: bytes lost while identity is known.

    Test harness only. The digest stays in the known set so that a later
    :func:`resolve_artifact` reports explicit ``observation_lost`` loss
    rather than successful collection.
    """
    _require_identifier(digest, "digest")
    with _LOCK:
        if digest not in _KNOWN:
            raise KeyError(f"digest was never retained: {digest!r}")
        _BYTES.pop(digest, None)
