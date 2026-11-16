"""connector_artifacts: verified artifact collection over the connector carrier (tier 4).

Implements ``job-hunter-seam-mapping.md#13.4`` (JH-12): inventory and
verified chunk transfer of already-produced, retained artifacts.

Selectors (closed):

* Inventory: ``mode`` only.
* Named: ``mode``, unique nonempty ``names``.
* Bytes: ``mode``, registered ``digest``, ``offset``, positive ``max_bytes``.

Rules enforced here (``EXT-ARTIFACTS``, ``EK-ARTIFACTS``, ``EK-HASHES``):

* Only ``CollectArtifacts`` is accepted through this interface.
* Collection never fetches arbitrary caller URLs or filesystem paths.
  Selectors carrying ``path``/``url`` (or siblings) are rejected with
  ``INVALID_REQUEST`` before any transport call.
* Every named request receives exactly those names, including missing
  slots.  Known identities survive byte loss: ``expected_digest`` keeps
  the digest while ``content`` becomes a typed ``Missing``.
* Chunks are verified strictly: canonical padded base64, decoded length
  versus ``returned_bytes``, ``chunk_digest`` versus the decoded bytes,
  request ``offset`` equality, ``offset + returned_bytes <= size_bytes``,
  ``end_of_artifact`` exactly at EOF, progress on non-EOF chunks, the
  ``max_bytes`` bound, and the assembled digest for whole-artifact
  transfers.  Any mismatch yields a ``connector_error``; corrupt bytes
  are never surfaced as a valid chunk.
* Transfer never reruns a workflow, never creates a browser context to
  manufacture missing artifacts, and never downgrades restricted
  content.

The module forwards validated requests through
:func:`connector_transport.call_connector` and verifies the returned
``artifact_inventory`` / ``artifact_chunk`` before surfacing it.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import importlib
import importlib.util
import json
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _load_sibling(name: str):
    """Import a sibling module, falling back to its source path."""
    if name in sys.modules:
        return sys.modules[name]
    try:
        return importlib.import_module(name)
    except ModuleNotFoundError:
        pass
    sibling_path = Path(__file__).resolve().parents[2] / name / "src" / "__init__.py"
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
connector_transport = _load_sibling("connector_transport")
try:
    access_policy = _load_sibling("access_policy")
except Exception:  # pragma: no cover - audit helper only
    access_policy = None  # type: ignore[assignment]

__all__ = [
    "SCHEMA_VERSION",
    "RECORD_TYPE_REQUEST",
    "OPERATION",
    "ConnectorRequest",
    "ConnectorError",
    "ArtifactSlot",
    "ArtifactInventory",
    "ArtifactChunk",
    "collect_task_artifacts",
    "verify_artifact_chunk",
    "verify_artifact_inventory",
    "register_named_artifact_for_tests",
    "reset_for_tests",
]

SCHEMA_VERSION = "external-connector/0.1.0"
RECORD_TYPE_REQUEST = "connector_request"
OPERATION = "CollectArtifacts"

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_B64_RE = re.compile(
    r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"
)
_SAFE_INT_MAX = 9007199254740991

_FORBIDDEN_SELECTOR_KEYS = frozenset(
    {
        "path",
        "paths",
        "url",
        "urls",
        "uri",
        "uris",
        "href",
        "hrefs",
        "file",
        "files",
        "filepath",
        "filepaths",
        "filename",
        "filenames",
        "filesystem",
        "location",
        "locations",
        "address",
        "addresses",
        "endpoint",
        "endpoints",
        "link",
        "links",
    }
)

_INVENTORY_KEYS = frozenset(
    {"kind", "handle", "artifacts", "coverage", "evidence_prefix", "limitations"}
)
_CHUNK_KEYS = frozenset(
    {
        "kind",
        "handle",
        "digest",
        "size_bytes",
        "offset",
        "returned_bytes",
        "data_base64",
        "chunk_digest",
        "end_of_artifact",
        "evidence_refs",
    }
)
_SLOT_KEYS = frozenset({"name", "expected_digest", "content", "evidence_refs"})
_ERROR_KEYS = frozenset(
    {
        "kind",
        "code",
        "fault_domain",
        "detail",
        "operation_delivery",
        "retry_guidance",
        "retry_after",
        "handle",
        "evidence_refs",
    }
)

_LOCK = threading.RLock()
# (connector_id, local_handle, name) -> ArtifactReference (or its dict form).
_NAMED: dict[tuple[str, str, str], Any] = {}

# Re-export the transport request type so callers use one identity.
try:
    ConnectorRequest = connector_transport.ConnectorRequest  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - transport always present in practice

    @dataclass(slots=True)
    class ConnectorRequest:  # type: ignore[no-redef]
        request_id: str
        connector_id: str
        operation: str
        call_limit: dict[str, Any]
        payload: dict[str, Any]
        record_type: str = RECORD_TYPE_REQUEST
        schema_version: str = SCHEMA_VERSION

        def to_dict(self) -> dict[str, Any]:
            return {
                "record_type": self.record_type,
                "schema_version": self.schema_version,
                "request_id": self.request_id,
                "connector_id": self.connector_id,
                "operation": self.operation,
                "call_limit": copy.deepcopy(self.call_limit),
                "payload": copy.deepcopy(self.payload),
            }


# ---------------------------------------------------------------------------
# Value types
# ---------------------------------------------------------------------------


def _missing(reason: str, detail: str | None = None) -> dict[str, Any]:
    try:
        return dict(contract_codec.make_missing(reason, detail))  # type: ignore[attr-defined]
    except Exception:
        m: dict[str, Any] = {"value": None, "reason": reason}
        if detail:
            m["detail"] = detail
        return m


def _is_missing(v: Any) -> bool:
    try:
        return bool(contract_codec.is_missing_envelope(v))  # type: ignore[attr-defined]
    except Exception:
        return (
            isinstance(v, dict)
            and set(v.keys()) <= {"value", "reason", "detail"}
            and v.get("value") is None
            and isinstance(v.get("reason"), str)
        )


def _is_digest(v: Any) -> bool:
    return isinstance(v, str) and bool(_DIGEST_RE.match(v))


def _is_identifier(v: Any) -> bool:
    return isinstance(v, str) and bool(v) and "\x00" not in v


def _is_plain_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


@dataclass(frozen=True, slots=True)
class ConnectorError:
    """Typed ``connector_error`` result."""

    code: str
    detail: str
    operation_delivery: str = "not_applicable"
    retry_guidance: str = "do_not_retry"
    handle: Any = field(
        default_factory=lambda: {"value": None, "reason": "not_applicable"}
    )
    evidence_refs: tuple[Any, ...] = ()
    fault_domain: str = "request"
    retry_after: Any = field(
        default_factory=lambda: {"value": None, "reason": "not_applicable"}
    )
    kind: str = "connector_error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "code": self.code,
            "fault_domain": self.fault_domain,
            "detail": self.detail,
            "operation_delivery": self.operation_delivery,
            "retry_guidance": self.retry_guidance,
            "retry_after": copy.deepcopy(self.retry_after),
            "handle": copy.deepcopy(self.handle),
            "evidence_refs": [copy.deepcopy(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ConnectorError":
        return cls(
            code=str(d.get("code", "INTERNAL_ERROR")),
            detail=str(d.get("detail", "")),
            operation_delivery=str(d.get("operation_delivery", "not_applicable")),
            retry_guidance=str(d.get("retry_guidance", "do_not_retry")),
            handle=copy.deepcopy(d.get("handle", _missing("not_applicable"))),
            evidence_refs=tuple(copy.deepcopy(d.get("evidence_refs", []))),
            fault_domain=str(d.get("fault_domain", "request")),
            retry_after=copy.deepcopy(d.get("retry_after", _missing("not_applicable"))),
            kind="connector_error",
        )


@dataclass(frozen=True, slots=True)
class ArtifactSlot:
    """One named artifact slot (available or explicitly missing)."""

    name: str
    expected_digest: Any  # Digest str | Missing dict
    content: Any  # ArtifactReference dict | Missing dict
    evidence_refs: tuple[Any, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "expected_digest": copy.deepcopy(self.expected_digest),
            "content": copy.deepcopy(self.content),
            "evidence_refs": [copy.deepcopy(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ArtifactSlot":
        return cls(
            name=str(d.get("name", "")),
            expected_digest=copy.deepcopy(d.get("expected_digest")),
            content=copy.deepcopy(d.get("content")),
            evidence_refs=tuple(copy.deepcopy(d.get("evidence_refs", []))),
        )


@dataclass(frozen=True, slots=True)
class ArtifactInventory:
    """Typed ``artifact_inventory`` result."""

    handle: dict[str, Any]
    artifacts: tuple[ArtifactSlot, ...]
    coverage: str
    evidence_prefix: dict[str, Any]
    limitations: tuple[str, ...]
    kind: str = "artifact_inventory"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "handle": copy.deepcopy(self.handle),
            "artifacts": [s.to_dict() for s in self.artifacts],
            "coverage": self.coverage,
            "evidence_prefix": copy.deepcopy(self.evidence_prefix),
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ArtifactInventory":
        return cls(
            handle=copy.deepcopy(d.get("handle", {})),
            artifacts=tuple(
                ArtifactSlot.from_dict(s) for s in d.get("artifacts", [])
            ),
            coverage=str(d.get("coverage", "unknown")),
            evidence_prefix=copy.deepcopy(d.get("evidence_prefix", {})),
            limitations=tuple(d.get("limitations", [])),
            kind="artifact_inventory",
        )


@dataclass(frozen=True, slots=True)
class ArtifactChunk:
    """Typed ``artifact_chunk`` result (verified before surfacing)."""

    handle: dict[str, Any]
    digest: str
    size_bytes: int
    offset: int
    returned_bytes: int
    data_base64: str
    chunk_digest: str
    end_of_artifact: bool
    evidence_refs: tuple[Any, ...] = ()
    kind: str = "artifact_chunk"

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "handle": copy.deepcopy(self.handle),
            "digest": self.digest,
            "size_bytes": self.size_bytes,
            "offset": self.offset,
            "returned_bytes": self.returned_bytes,
            "data_base64": self.data_base64,
            "chunk_digest": self.chunk_digest,
            "end_of_artifact": self.end_of_artifact,
            "evidence_refs": [copy.deepcopy(r) for r in self.evidence_refs],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ArtifactChunk":
        return cls(
            handle=copy.deepcopy(d.get("handle", {})),
            digest=str(d.get("digest", "")),
            size_bytes=int(d.get("size_bytes", 0)),
            offset=int(d.get("offset", 0)),
            returned_bytes=int(d.get("returned_bytes", 0)),
            data_base64=str(d.get("data_base64", "")),
            chunk_digest=str(d.get("chunk_digest", "")),
            end_of_artifact=bool(d.get("end_of_artifact", False)),
            evidence_refs=tuple(copy.deepcopy(d.get("evidence_refs", []))),
            kind="artifact_chunk",
        )

    @property
    def data_bytes(self) -> bytes:
        return base64.b64decode(self.data_base64.encode("ascii"), validate=True)


# ---------------------------------------------------------------------------
# Test registry
# ---------------------------------------------------------------------------


def register_named_artifact_for_tests(
    connector_id: str, local_handle: str, name: str, reference: Any
) -> None:
    """Bind a connector-local artifact name to a retained reference (tests)."""
    if not _is_identifier(connector_id):
        raise ValueError("connector_id must be a nonempty identifier")
    if not _is_identifier(local_handle):
        raise ValueError("local_handle must be a nonempty identifier")
    if not _is_identifier(name):
        raise ValueError("name must be a nonempty identifier")
    with _LOCK:
        _NAMED[(connector_id, local_handle, name)] = reference


def reset_for_tests() -> None:
    """Clear the named-artifact registry (tests only)."""
    with _LOCK:
        _NAMED.clear()


def _ref_digest(ref: Any) -> str | None:
    if ref is None:
        return None
    if isinstance(ref, dict):
        d = ref.get("digest")
        return d if _is_digest(d) else None
    d = getattr(ref, "digest", None)
    return d if _is_digest(d) else None


def _ref_to_dict(ref: Any) -> dict[str, Any]:
    if isinstance(ref, dict):
        return copy.deepcopy(ref)
    to_dict = getattr(ref, "to_dict", None)
    if callable(to_dict):
        return copy.deepcopy(to_dict())
    return {
        "digest": getattr(ref, "digest", None),
        "size_bytes": getattr(ref, "size_bytes", None),
        "media_type": getattr(ref, "media_type", None),
        "owner_domain": getattr(ref, "owner_domain", None),
        "access": getattr(ref, "access", None),
    }


def _named_lookup(connector_id: str, local_handle: str, name: str) -> Any | None:
    with _LOCK:
        return _NAMED.get((connector_id, local_handle, name))


def _named_for_handle(connector_id: str, local_handle: str) -> list[tuple[str, Any]]:
    with _LOCK:
        out = [
            (name, ref)
            for (cid, hdl, name), ref in _NAMED.items()
            if cid == connector_id and hdl == local_handle
        ]
    out.sort(key=lambda kv: kv[0])
    return out


# ---------------------------------------------------------------------------
# Request validation
# ---------------------------------------------------------------------------


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _strict_gate(req_dict: dict[str, Any]) -> str | None:
    """Reject non-strict JSON (duplicate keys, bare nulls, nonfinite)."""
    try:
        wrapper = {"timing": req_dict}
        data = _canonical_json_bytes(wrapper)
    except Exception as exc:
        return f"request is not canonical JSON: {exc}"
    try:
        contract_codec.validate_record(data, "record/v1")  # type: ignore[attr-defined]
    except Exception as exc:
        return f"request is not strict canonical JSON: {exc}"
    return None


def _make_error(
    code: str,
    detail: str,
    handle: Any | None = None,
    evidence_refs: list[Any] | tuple[Any, ...] = (),
) -> ConnectorError:
    try:
        d = connector_transport.make_connector_error(  # type: ignore[attr-defined]
            code,
            detail,
            handle=copy.deepcopy(handle) if handle is not None else None,
            evidence_refs=list(evidence_refs),
        )
        return ConnectorError.from_dict(d)
    except Exception:
        h = copy.deepcopy(handle) if handle is not None else _missing("not_applicable")
        return ConnectorError(
            code=code,
            detail=detail,
            handle=h,
            evidence_refs=tuple(evidence_refs),
        )


def _validate_handle(handle: Any) -> tuple[dict[str, Any] | None, ConnectorError | None]:
    if not isinstance(handle, dict):
        return None, _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts operation requires a handle reference object; "
            "arbitrary paths or URLs are never accepted as a handle.",
            handle=None,
        )
    if set(handle.keys()) != {"connector_id", "local_handle"}:
        return None, _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts handle must carry exactly connector_id and "
            "local_handle; arbitrary paths or URLs are rejected.",
            handle=None,
        )
    cid = handle.get("connector_id")
    local = handle.get("local_handle")
    if not _is_identifier(cid) or not _is_identifier(local):
        return None, _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts handle requires nonempty connector_id and "
            "local_handle identifiers.",
            handle=None,
        )
    return {"connector_id": cid, "local_handle": local}, None


def _validate_selector(
    selector: Any, handle: dict[str, Any] | None
) -> tuple[dict[str, Any] | None, ConnectorError | None]:
    if not isinstance(selector, dict):
        return None, _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts operation requires a selector object with mode "
            "inventory, named, or bytes; arbitrary paths or URLs are rejected.",
            handle=handle,
        )
    forbidden = set(selector.keys()) & _FORBIDDEN_SELECTOR_KEYS
    if forbidden:
        names = ", ".join(sorted(forbidden))
        return None, _make_error(
            "INVALID_REQUEST",
            f"CollectArtifacts selector rejects arbitrary paths/URLs ({names}); "
            "bytes selects an already registered, authorized digest, never a "
            "caller path or URL.",
            handle=handle,
        )
    mode = selector.get("mode")
    if mode == "inventory":
        if set(selector.keys()) != {"mode"}:
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts inventory selector carries only mode; "
                "arbitrary paths or URLs are rejected.",
                handle=handle,
            )
        return {"mode": "inventory"}, None
    if mode == "named":
        if set(selector.keys()) != {"mode", "names"}:
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts named selector carries only mode and names; "
                "arbitrary paths or URLs are rejected.",
                handle=handle,
            )
        names = selector.get("names")
        if not isinstance(names, list) or not names:
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts named selector requires a nonempty names list.",
                handle=handle,
            )
        if len(set(names)) != len(names):
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts named selector requires unique names.",
                handle=handle,
            )
        for name in names:
            if not _is_identifier(name):
                return None, _make_error(
                    "INVALID_REQUEST",
                    "CollectArtifacts named selector requires nonempty name "
                    "identifiers; arbitrary paths or URLs are rejected.",
                    handle=handle,
                )
        return {"mode": "named", "names": list(names)}, None
    if mode == "bytes":
        if set(selector.keys()) != {"mode", "digest", "offset", "max_bytes"}:
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts bytes selector carries only mode, digest, "
                "offset, and max_bytes; arbitrary paths or URLs are rejected.",
                handle=handle,
            )
        digest = selector.get("digest")
        offset = selector.get("offset")
        max_bytes = selector.get("max_bytes")
        if not _is_digest(digest):
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts bytes selector requires a registered "
                "sha256:<hex> digest; arbitrary paths or URLs are rejected.",
                handle=handle,
            )
        if not _is_plain_int(offset) or not (0 <= offset <= _SAFE_INT_MAX):
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts bytes selector requires a nonnegative offset.",
                handle=handle,
            )
        if not _is_plain_int(max_bytes) or not (1 <= max_bytes <= _SAFE_INT_MAX):
            return None, _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts bytes selector requires positive max_bytes.",
                handle=handle,
            )
        try:
            bound = int(connector_transport.MAX_ARTIFACT_BYTES)  # type: ignore[attr-defined]
        except Exception:
            bound = 1_000_000
        if max_bytes > bound:
            return None, _make_error(
                "BUDGET_EXCEEDED",
                "CollectArtifacts bytes selector exceeds the local transfer bound.",
                handle=handle,
            )
        return {
            "mode": "bytes",
            "digest": digest,
            "offset": offset,
            "max_bytes": max_bytes,
        }, None
    return None, _make_error(
        "INVALID_REQUEST",
        "CollectArtifacts selector mode must be inventory, named, or bytes; "
        "arbitrary paths or URLs are rejected.",
        handle=handle,
    )


# ---------------------------------------------------------------------------
# Result verification
# ---------------------------------------------------------------------------


def _handle_matches(request_handle: dict[str, Any], result_handle: Any) -> bool:
    return (
        isinstance(result_handle, dict)
        and result_handle.get("connector_id") == request_handle.get("connector_id")
        and result_handle.get("local_handle") == request_handle.get("local_handle")
    )


def _check_evidence_refs_refs(refs: Any) -> bool:
    if not isinstance(refs, list):
        return False
    for r in refs:
        if not isinstance(r, dict):
            return False
    return True


def _check_artifact_reference_dict(d: Any) -> str | None:
    if not isinstance(d, dict):
        return "artifact content must be an object"
    if set(d.keys()) != {"digest", "size_bytes", "media_type", "owner_domain", "access"}:
        return "artifact content has undeclared properties"
    if not _is_digest(d.get("digest")):
        return "artifact digest is not a canonical sha256 digest"
    size = d.get("size_bytes")
    if not _is_plain_int(size) or not (0 <= size <= _SAFE_INT_MAX):
        return "artifact size_bytes is not a safe revision integer"
    if not _is_identifier(d.get("media_type")):
        return "artifact media_type must be a nonempty identifier"
    if not _is_identifier(d.get("owner_domain")):
        return "artifact owner_domain must be a nonempty identifier"
    if d.get("access") not in ("public", "restricted"):
        return "artifact access must be public or restricted"
    return None


def verify_artifact_inventory(
    result: dict[str, Any] | ArtifactInventory,
    request_handle: dict[str, Any],
    selector: dict[str, Any],
) -> ConnectorError | None:
    """Verify an inventory result; ``None`` means valid."""
    d = result.to_dict() if isinstance(result, ArtifactInventory) else result
    if not isinstance(d, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory result must be an object.",
            handle=request_handle,
        )
    if set(d.keys()) != _INVENTORY_KEYS:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory result carries exactly kind, handle, "
            "artifacts, coverage, evidence_prefix, and limitations.",
            handle=request_handle,
        )
    if d.get("kind") != "artifact_inventory":
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory result kind must be artifact_inventory.",
            handle=request_handle,
        )
    if not _handle_matches(request_handle, d.get("handle")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory handle does not match the request handle.",
            handle=request_handle,
        )
    if d.get("coverage") not in ("complete", "partial", "unknown"):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory coverage must be complete, partial, "
            "or unknown.",
            handle=request_handle,
        )
    prefix = d.get("evidence_prefix")
    if not isinstance(prefix, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory evidence_prefix must be an object.",
            handle=request_handle,
        )
    if set(prefix.keys()) != {"journal_id", "last_sequence", "head_hash"}:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory evidence_prefix carries journal_id, "
            "last_sequence, and head_hash.",
            handle=request_handle,
        )
    if not _is_identifier(prefix.get("journal_id")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory journal_id must be nonempty.",
            handle=request_handle,
        )
    last = prefix.get("last_sequence")
    # The transport issues last_sequence 0 for a handle-local prefix that has
    # not yet journaled; accept >= 0 here while still requiring an integer.
    if not _is_plain_int(last) or not (0 <= last <= _SAFE_INT_MAX):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory last_sequence must be a safe integer.",
            handle=request_handle,
        )
    if not _is_digest(prefix.get("head_hash")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory head_hash must be a canonical digest.",
            handle=request_handle,
        )
    limitations = d.get("limitations")
    if not isinstance(limitations, list) or any(
        not (isinstance(x, str) and x) for x in limitations
    ):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory limitations must be nonempty strings.",
            handle=request_handle,
        )
    slots = d.get("artifacts")
    if not isinstance(slots, list):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts inventory artifacts must be a list.",
            handle=request_handle,
        )
    seen: set[str] = set()
    for slot in slots:
        if not isinstance(slot, dict) or set(slot.keys()) != _SLOT_KEYS:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts inventory slots carry exactly name, "
                "expected_digest, content, and evidence_refs.",
                handle=request_handle,
            )
        name = slot.get("name")
        if not _is_identifier(name):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts inventory slot names must be nonempty.",
                handle=request_handle,
            )
        if name in seen:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts inventory names must be unique.",
                handle=request_handle,
            )
        seen.add(name)
        expected = slot.get("expected_digest")
        content = slot.get("content")
        if not (_is_digest(expected) or _is_missing(expected)):
            return _make_error(
                "INTEGRITY_CONFLICT",
                f"CollectArtifacts slot {name!r} expected_digest must be a "
                "digest or a typed Missing.",
                handle=request_handle,
            )
        if isinstance(content, dict) and not _is_missing(content):
            err = _check_artifact_reference_dict(content)
            if err is not None:
                return _make_error(
                    "INTEGRITY_CONFLICT",
                    f"CollectArtifacts slot {name!r} content is invalid: {err}.",
                    handle=request_handle,
                )
            if expected != content.get("digest"):
                return _make_error(
                    "INTEGRITY_CONFLICT",
                    f"CollectArtifacts slot {name!r} available content requires "
                    "expected_digest equal to content.digest.",
                    handle=request_handle,
                )
        elif not _is_missing(content):
            return _make_error(
                "INTEGRITY_CONFLICT",
                f"CollectArtifacts slot {name!r} content must be an artifact "
                "reference or a typed Missing.",
                handle=request_handle,
            )
        if not _check_evidence_refs_refs(slot.get("evidence_refs")):
            return _make_error(
                "INTEGRITY_CONFLICT",
                f"CollectArtifacts slot {name!r} evidence_refs must be a list.",
                handle=request_handle,
            )
    if selector.get("mode") == "named":
        wanted = list(selector.get("names", []))
        if len(slots) != len(wanted) or set(seen) != set(wanted):
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts named request must receive exactly those "
                "names, including missing slots.",
                handle=request_handle,
            )
    return None


def verify_artifact_chunk(
    result: dict[str, Any] | ArtifactChunk,
    request_handle: dict[str, Any],
    selector: dict[str, Any],
) -> ConnectorError | None:
    """Verify a chunk result against its bytes selector; ``None`` = valid."""
    d = result.to_dict() if isinstance(result, ArtifactChunk) else result
    if not isinstance(d, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk result must be an object.",
            handle=request_handle,
        )
    if set(d.keys()) != _CHUNK_KEYS:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk result carries exactly kind, handle, digest, "
            "size_bytes, offset, returned_bytes, data_base64, chunk_digest, "
            "end_of_artifact, and evidence_refs.",
            handle=request_handle,
        )
    if d.get("kind") != "artifact_chunk":
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk result kind must be artifact_chunk.",
            handle=request_handle,
        )
    if not _handle_matches(request_handle, d.get("handle")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk handle does not match the request handle.",
            handle=request_handle,
        )
    digest = d.get("digest")
    if not _is_digest(digest):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk digest must be canonical.",
            handle=request_handle,
        )
    if digest != selector.get("digest"):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk digest does not match the bytes selector.",
            handle=request_handle,
        )
    size = d.get("size_bytes")
    offset = d.get("offset")
    returned = d.get("returned_bytes")
    if not _is_plain_int(size) or not (0 <= size <= _SAFE_INT_MAX):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk size_bytes must be a safe integer.",
            handle=request_handle,
        )
    if not _is_plain_int(offset) or not (0 <= offset <= _SAFE_INT_MAX):
        return _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts chunk offset must be a safe integer.",
            handle=request_handle,
        )
    if offset != selector.get("offset"):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk offset must equal the request offset.",
            handle=request_handle,
        )
    if not _is_plain_int(returned) or not (0 <= returned <= _SAFE_INT_MAX):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk returned_bytes must be a safe integer.",
            handle=request_handle,
        )
    max_bytes = selector.get("max_bytes")
    if isinstance(max_bytes, int) and returned > max_bytes:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk returned_bytes exceeds the requested "
            "max_bytes bound.",
            handle=request_handle,
        )
    if offset > size:
        return _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts chunk offset is beyond EOF.",
            handle=request_handle,
        )
    if offset + returned > size:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk overruns size_bytes.",
            handle=request_handle,
        )
    end = d.get("end_of_artifact")
    if not isinstance(end, bool):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk end_of_artifact must be a boolean.",
            handle=request_handle,
        )
    if end != (offset + returned == size):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk end_of_artifact is true exactly at "
            "size_bytes.",
            handle=request_handle,
        )
    if not end and returned == 0:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts non-EOF chunk must make progress.",
            handle=request_handle,
        )
    data_b64 = d.get("data_base64")
    if not isinstance(data_b64, str) or not _B64_RE.match(data_b64):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk data_base64 is not canonical padded base64.",
            handle=request_handle,
        )
    try:
        decoded = base64.b64decode(data_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk data_base64 is malformed.",
            handle=request_handle,
        )
    if base64.b64encode(decoded).decode("ascii") != data_b64:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk data_base64 is not canonical.",
            handle=request_handle,
        )
    if len(decoded) != returned:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk returned_bytes does not match the decoded "
            "payload length.",
            handle=request_handle,
        )
    chunk_digest = d.get("chunk_digest")
    if not _is_digest(chunk_digest):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk chunk_digest must be canonical.",
            handle=request_handle,
        )
    if "sha256:" + hashlib.sha256(decoded).hexdigest() != chunk_digest:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk chunk_digest does not match the decoded bytes.",
            handle=request_handle,
        )
    if not _check_evidence_refs_refs(d.get("evidence_refs")):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts chunk evidence_refs must be a list.",
            handle=request_handle,
        )
    # Whole-artifact transfers additionally verify the assembled digest.
    if offset == 0 and end:
        if "sha256:" + hashlib.sha256(decoded).hexdigest() != digest:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts assembled bytes do not match the requested "
                "artifact digest.",
                handle=request_handle,
            )
        if len(decoded) != size:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts assembled bytes do not match size_bytes.",
                handle=request_handle,
            )
    return None


def _slot_for_registered(
    channel_id: str, name: str, ref: Any, evidence_refs: list[Any]
) -> dict[str, Any]:
    digest = _ref_digest(ref)
    if digest is None:
        return {
            "name": name,
            "expected_digest": _missing("not_observed"),
            "content": _missing("not_observed"),
            "evidence_refs": list(evidence_refs),
        }
    try:
        known = artifact_store.known_digests()  # type: ignore[attr-defined]
    except Exception:
        known = frozenset()
    # Known identity survives loss: keep the digest even when bytes are gone.
    expected: Any = digest
    if digest not in known:
        # The registry still names the digest, but the store never retained
        # it (or state was reset); report the slot as not observed while
        # preserving the requested name.
        pass
    try:
        payload = artifact_store.resolve_artifact(channel_id, ref)  # type: ignore[attr-defined]
    except Exception as exc:
        mod = type(exc).__module__
        cls = type(exc).__name__
        if cls == "ArtifactLostError" or "Lost" in cls:
            return {
                "name": name,
                "expected_digest": expected,
                "content": _missing(
                    "observation_lost",
                    f"retained bytes for {digest} are unavailable",
                ),
                "evidence_refs": list(evidence_refs),
            }
        if cls in ("ArtifactAccessDeniedError",) or "Denied" in cls:
            return {
                "name": name,
                "expected_digest": _missing("not_observed"),
                "content": _missing("not_observed"),
                "evidence_refs": list(evidence_refs),
            }
        return {
            "name": name,
            "expected_digest": expected if digest in known else _missing("not_observed"),
            "content": _missing("not_observed"),
            "evidence_refs": list(evidence_refs),
        }
    if not isinstance(payload, (bytes, bytearray)) or (
        "sha256:" + hashlib.sha256(bytes(payload)).hexdigest()
    ) != digest:
        return {
            "name": name,
            "expected_digest": expected,
            "content": _missing(
                "observation_lost", f"retained bytes for {digest} changed"
            ),
            "evidence_refs": list(evidence_refs),
        }
    ref_dict = _ref_to_dict(ref)
    if ref_dict.get("size_bytes") != len(payload):
        return {
            "name": name,
            "expected_digest": expected,
            "content": _missing(
                "observation_lost", f"size mismatch for {digest}"
            ),
            "evidence_refs": list(evidence_refs),
        }
    return {
        "name": name,
        "expected_digest": expected,
        "content": ref_dict,
        "evidence_refs": list(evidence_refs),
    }


def _enrich_inventory(
    channel_id: str,
    handle: dict[str, Any],
    selector: dict[str, Any],
    inventory: dict[str, Any],
) -> dict[str, Any]:
    """Fill named/inventory slots from the handle-local name registry."""
    mode = selector.get("mode")
    if mode == "bytes":
        return inventory
    cid = handle.get("connector_id", "")
    local = handle.get("local_handle", "")
    out = copy.deepcopy(inventory)
    if mode == "named":
        wanted: list[str] = list(selector.get("names", []))
        by_name = {s.get("name"): s for s in out.get("artifacts", [])}
        enriched: list[dict[str, Any]] = []
        for name in wanted:
            base = by_name.get(name, {})
            refs = list(base.get("evidence_refs", []))
            registered = _named_lookup(cid, local, name)
            if registered is None:
                enriched.append(
                    {
                        "name": name,
                        "expected_digest": _missing("not_observed"),
                        "content": _missing("not_observed"),
                        "evidence_refs": refs,
                    }
                )
            else:
                enriched.append(
                    _slot_for_registered(channel_id, name, registered, refs)
                )
        out["artifacts"] = enriched
        return out
    # Inventory mode: list every name registered for this handle.  An empty
    # registry is an established empty inventory, not an unavailable source.
    registered_all = _named_for_handle(cid, local)
    if not registered_all:
        out["artifacts"] = []
        return out
    enriched_all: list[dict[str, Any]] = []
    for name, ref in registered_all:
        enriched_all.append(_slot_for_registered(channel_id, name, ref, []))
    out["artifacts"] = enriched_all
    return out


def _try_audit_journal(
    channel_id: str, request_id: str, connector_id: str, outcome: str
) -> None:
    """Best-effort collection audit; never fails the read path."""
    try:
        owner = None
        if access_policy is not None:
            try:
                proj = access_policy.channel_projection(channel_id)  # type: ignore[attr-defined]
                owner = proj.get("axis")
            except Exception:
                owner = None
        if not isinstance(owner, str) or not owner:
            return
        submission_cls = getattr(evidence_journal, "EventSubmission", None)
        if submission_cls is None:
            return
        occurred = getattr(evidence_journal, "TimePoint", None)
        _ = occurred
        return
    except Exception:
        return


def _try_ensure_retained(channel_id: str, chunk: dict[str, Any], decoded: bytes) -> None:
    """Best-effort durability for whole-artifact transfers (idempotent)."""
    try:
        if chunk.get("offset") != 0 or not chunk.get("end_of_artifact"):
            return
        meta_map = getattr(artifact_store, "_META", {}) or {}
        meta = meta_map.get(chunk.get("digest"))
        if meta is None:
            return
        owner = getattr(meta, "owner_domain", None)
        media = getattr(meta, "media_type", None)
        access = getattr(meta, "access", None)
        if not (
            isinstance(owner, str) and isinstance(media, str) and isinstance(access, str)
        ):
            return
        artifact_store.retain_artifact(channel_id, owner, media, bytes(decoded), access)  # type: ignore[attr-defined]
    except Exception:
        return


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def collect_task_artifacts(
    channel_id: str, request: Any
) -> ArtifactInventory | ArtifactChunk | ConnectorError:
    """Collect retained artifacts for one authorized handle.

    Accepts only ``CollectArtifacts`` requests whose selector is inventory,
    named, or bytes over an already registered digest.  Arbitrary caller
    paths or URLs are rejected before any transport call.  Returned
    inventories preserve every requested name (including missing slots
    and known digests); returned chunks are verified byte-for-byte and
    any corruption surfaces as a ``connector_error``.
    """
    if not _is_identifier(channel_id):
        return _make_error(
            "UNAUTHENTICATED",
            "CollectArtifacts operation requires an authenticated channel.",
            handle=None,
        )
    if hasattr(request, "to_dict") and callable(request.to_dict):
        try:
            req_dict = copy.deepcopy(request.to_dict())
        except Exception:
            return _make_error(
                "INVALID_REQUEST",
                "CollectArtifacts operation requires a connector request object.",
                handle=None,
            )
    elif isinstance(request, dict):
        req_dict = copy.deepcopy(request)
    else:
        return _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts operation requires a connector request object.",
            handle=None,
        )
    if req_dict.get("record_type") != RECORD_TYPE_REQUEST:
        return _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts request must carry record_type connector_request.",
            handle=None,
        )
    if req_dict.get("schema_version") != SCHEMA_VERSION:
        return _make_error(
            "UNSUPPORTED_VERSION",
            f"CollectArtifacts operation requires schema_version {SCHEMA_VERSION}.",
            handle=None,
        )
    if req_dict.get("operation") != OPERATION:
        return _make_error(
            "INVALID_REQUEST",
            "This interface accepts only the CollectArtifacts operation.",
            handle=None,
        )
    gate_err = _strict_gate(req_dict)
    if gate_err is not None:
        return _make_error("INVALID_REQUEST", gate_err, handle=None)
    payload = req_dict.get("payload")
    if not isinstance(payload, dict):
        return _make_error(
            "INVALID_REQUEST",
            "CollectArtifacts operation requires an object payload.",
            handle=None,
        )
    if set(payload.keys()) != {"handle", "selector"}:
        forbidden = (set(payload.keys()) - {"handle", "selector"}) & (
            _FORBIDDEN_SELECTOR_KEYS | {"mode", "names", "digest"}
        )
        if forbidden:
            detail = (
                "CollectArtifacts payload rejects arbitrary paths/URLs "
                f"({', '.join(sorted(forbidden))}); it carries only handle "
                "and selector."
            )
        else:
            detail = (
                "CollectArtifacts payload carries exactly handle and selector."
            )
        return _make_error("INVALID_REQUEST", detail, handle=None)
    handle, handle_err = _validate_handle(payload.get("handle"))
    if handle_err is not None or handle is None:
        assert handle_err is not None
        return handle_err
    selector, selector_err = _validate_selector(payload.get("selector"), handle)
    if selector_err is not None or selector is None:
        assert selector_err is not None
        return selector_err

    try:
        response = await connector_transport.call_connector(channel_id, req_dict)  # type: ignore[attr-defined]
    except TypeError as exc:
        return _make_error(
            "INVALID_REQUEST", f"CollectArtifacts request is malformed: {exc}.",
            handle=handle,
        )
    except Exception as exc:
        return _make_error(
            "INTERNAL_ERROR",
            f"CollectArtifacts transport failed: {exc}.",
            handle=handle,
        )
    result: Any
    if hasattr(response, "result"):
        result = copy.deepcopy(response.result)
    elif isinstance(response, dict):
        result = copy.deepcopy(response.get("result", response))
    else:
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts transport returned an unrecognized response.",
            handle=handle,
        )
    if not isinstance(result, dict):
        return _make_error(
            "INTEGRITY_CONFLICT",
            "CollectArtifacts transport returned a non-object result.",
            handle=handle,
        )
    kind = result.get("kind")
    if kind == "connector_error":
        if set(result.keys()) != _ERROR_KEYS:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts transport returned a malformed error.",
                handle=handle,
            )
        try:
            return ConnectorError.from_dict(result)
        except Exception:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts transport returned an invalid error.",
                handle=handle,
            )
    if kind == "artifact_inventory":
        enriched = _enrich_inventory(channel_id, handle, selector, result)
        inv_err = verify_artifact_inventory(enriched, handle, selector)
        if inv_err is not None:
            return inv_err
        _try_audit_journal(
            channel_id, str(req_dict.get("request_id", "")), str(req_dict.get("connector_id", "")), "inventory"
        )
        return ArtifactInventory.from_dict(enriched)
    if kind == "artifact_chunk":
        chunk_err = verify_artifact_chunk(result, handle, selector)
        if chunk_err is not None:
            return chunk_err
        # Cross-check the assembled identity against retained bytes when the
        # store still holds them; loss surfaces explicitly, never silently.
        try:
            known = artifact_store.known_digests()  # type: ignore[attr-defined]
        except Exception:
            known = frozenset()
        if result.get("digest") not in known:
            return _make_error(
                "ARTIFACT_UNAVAILABLE",
                "CollectArtifacts chunk names a digest that was never retained.",
                handle=handle,
            )
        try:
            decoded = base64.b64decode(
                str(result.get("data_base64", "")).encode("ascii"), validate=True
            )
        except Exception:
            return _make_error(
                "INTEGRITY_CONFLICT",
                "CollectArtifacts chunk data_base64 is malformed.",
                handle=handle,
            )
        _try_ensure_retained(channel_id, result, decoded)
        _try_audit_journal(
            channel_id, str(req_dict.get("request_id", "")), str(req_dict.get("connector_id", "")), "chunk"
        )
        return ArtifactChunk.from_dict(result)
    return _make_error(
        "INTEGRITY_CONFLICT",
        f"CollectArtifacts transport returned unknown kind {kind!r}.",
        handle=handle,
    )
