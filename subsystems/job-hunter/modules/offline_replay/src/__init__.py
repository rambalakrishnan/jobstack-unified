"""offline_replay: offline diagnostic re-derivation and comparison (tier 8)."""
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


def _load_sibling(name: str):
    """Import a required sibling module, falling back to its source path."""
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
attempt_diagnostics = _load_sibling("attempt_diagnostics")

__all__ = [
    "SCHEMA_VERSION",
    "RECORD_TYPE",
    "REPLAY_KIND",
    "Missing",
    "Manifest",
    "JournalPrefix",
    "JournalEnvelope",
    "ArtifactReference",
    "DiagnosticDocument",
    "VersionPin",
    "AnalysisRequest",
    "ReplayReceipt",
    "ReplayError",
    "ReplayConformanceError",
    "replay_diagnostic",
    "to_canonical_bytes",
    "reset_for_tests",
]

SCHEMA_VERSION = "offline-replay/1"
RECORD_TYPE = "ReplayReceipt"
REPLAY_KIND = "diagnostic_rederivation"

# Shared kernel types are aliased, never redefined, so manifests, prefixes,
# envelopes, references, and diagnostics stay interchangeable with the sibling
# modules that own them.
Missing = evidence_journal.Missing
Manifest = evidence_journal.Manifest
JournalPrefix = evidence_journal.JournalPrefix
JournalEnvelope = evidence_journal.JournalEnvelope
ArtifactReference = artifact_store.ArtifactReference
DiagnosticDocument = attempt_diagnostics.DiagnosticDocument
VersionPin = attempt_diagnostics.VersionPin
AnalysisRequest = attempt_diagnostics.AnalysisRequest

_CODEC_GATE_SCHEMA = "record/v1"

_VERDICTS = frozenset({"matched", "mismatched", "inputs_missing"})

# Any recorded bundle that activates one of these effects would require a
# browser, subject, control action, email send, calendar write, or employer
# mutation. Offline replay performs none of those; such a bundle fails
# conformance instead of executing.
_EXTERNAL_WRITE_KEYS = frozenset({
    "external_write",
    "external_writes",
    "external_effect",
    "external_effects",
    "employer_mutation",
    "employer_mutations",
    "mutate_employer",
    "employer_write",
    "employer_submit",
    "browser",
    "browser_action",
    "browser_actions",
    "invoke_browser",
    "browse",
    "subject_action",
    "subject_actions",
    "invoke_subject",
    "subject_control",
    "control_action",
    "control_actions",
    "native_control",
    "control_client",
    "email_send",
    "email_sends",
    "send_email",
    "outbound_send",
    "calendar_write",
    "calendar_writes",
    "calendar_event_write",
    "provider_effect",
    "provider_effects",
    "live_effect",
    "live_effects",
    "live_reproduction",
    "live_reproduce",
    "perform_live_reproduction",
    "exact_fixture_replay",
    "fixture_replay_live",
    "production_dispatch",
    "submit_application",
    "dispatch",
})

_FORBIDDEN_REPLAY_KINDS = frozenset({"exact_fixture_replay", "live_reproduction"})


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReplayError(Exception):
    """Base class for offline-replay failures."""


class ReplayConformanceError(ReplayError, ValueError):
    """The requested replay would violate offline conformance.

    Raised when the input bundle declares an external write (browser,
    subject, control action, email send, calendar write, or employer
    mutation) or mislabels diagnostic re-derivation as exact fixture
    replay or live reproduction. The replay is refused before any
    re-derivation; no external effect is performed.
    """


# ---------------------------------------------------------------------------
# Value type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ReplayReceipt:
    """Immutable comparison receipt (``K.ReplayReceipt``).

    A receipt is a separate immutable record; the compared source
    diagnostic is never modified. ``replay_kind`` is always
    ``diagnostic_rederivation``: production re-derivation offline is
    not live reproduction and not exact fixture replay.
    """

    record_type: str
    schema_version: str
    replay_kind: str
    replay_engine: Any
    source_diagnostic_id: str
    analysis_revision: int
    input_prefix: Any
    source_digest: str
    rederived_digest: Any  # str | Missing
    verdict: str
    missing_inputs: tuple
    external_write_attempted: bool
    detail: str

    def __post_init__(self) -> None:
        if self.record_type != RECORD_TYPE:
            raise ReplayError(f"record_type must be {RECORD_TYPE!r}")
        if self.schema_version != SCHEMA_VERSION:
            raise ReplayError(f"schema_version must be {SCHEMA_VERSION!r}")
        if self.replay_kind != REPLAY_KIND:
            raise ReplayError(f"replay_kind must be {REPLAY_KIND!r}")
        if not isinstance(self.replay_engine, VersionPin):
            raise ReplayError("replay_engine must be a VersionPin")
        if not isinstance(self.source_diagnostic_id, str) or not self.source_diagnostic_id:
            raise ReplayError("source_diagnostic_id must be a nonempty string")
        if (
            isinstance(self.analysis_revision, bool)
            or not isinstance(self.analysis_revision, int)
            or self.analysis_revision < 1
        ):
            raise ReplayError("analysis_revision must be a positive integer")
        if not isinstance(self.input_prefix, JournalPrefix):
            raise ReplayError("input_prefix must be a JournalPrefix")
        _require_digest(self.source_digest, "source_digest")
        if isinstance(self.rederived_digest, str):
            _require_digest(self.rederived_digest, "rederived_digest")
        elif _as_missing(self.rederived_digest) is None:
            raise ReplayError(
                "rederived_digest must be a digest string or a Missing envelope"
            )
        if self.verdict not in _VERDICTS:
            raise ReplayError(f"verdict must be one of {sorted(_VERDICTS)}")
        if not isinstance(self.missing_inputs, tuple):
            raise ReplayError("missing_inputs must be a tuple")
        for name in self.missing_inputs:
            if not isinstance(name, str) or not name:
                raise ReplayError("missing_inputs entries must be nonempty strings")
        if self.verdict == "inputs_missing" and not self.missing_inputs:
            raise ReplayError("inputs_missing verdict requires named missing inputs")
        if self.verdict in ("matched", "mismatched") and self.missing_inputs:
            raise ReplayError(f"{self.verdict} verdict names no missing inputs")
        if self.verdict == "matched" and isinstance(self.rederived_digest, str):
            if self.rederived_digest != self.source_digest:
                raise ReplayError("matched verdict requires equal digests")
        if self.external_write_attempted is not False:
            raise ReplayError("a returned receipt never attempted an external write")
        if not isinstance(self.detail, str) or not self.detail:
            raise ReplayError("detail must be a nonempty string")

    def to_dict(self) -> dict[str, Any]:
        rederived = self.rederived_digest
        return {
            "record_type": self.record_type,
            "schema_version": self.schema_version,
            "replay_kind": self.replay_kind,
            "replay_engine": self.replay_engine.to_dict(),
            "source_diagnostic_id": self.source_diagnostic_id,
            "analysis_revision": self.analysis_revision,
            "input_prefix": {
                "journal_id": self.input_prefix.journal_id,
                "last_sequence": self.input_prefix.last_sequence,
                "head_hash": self.input_prefix.head_hash,
            },
            "source_digest": self.source_digest,
            "rederived_digest": (
                rederived
                if isinstance(rederived, str)
                else _as_missing(rederived).to_dict()  # type: ignore[union-attr]
            ),
            "verdict": self.verdict,
            "missing_inputs": list(self.missing_inputs),
            "external_write_attempted": self.external_write_attempted,
            "detail": self.detail,
        }


def to_canonical_bytes(receipt: ReplayReceipt) -> bytes:
    """Render a receipt as canonical JSON bytes (deterministic)."""
    if not isinstance(receipt, ReplayReceipt):
        raise TypeError("to_canonical_bytes requires a ReplayReceipt")
    return _canonical_bytes(receipt.to_dict())


def reset_for_tests() -> None:
    """No global state; defined for harness symmetry."""
    return None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_digest(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ReplayError(f"{field} must be a str, not {type(value).__name__}")
    body = value.split("sha256:", 1)
    if len(body) != 2 or body[0] != "" or len(body[1]) != 64:
        raise ReplayError(f"{field} must be sha256:<64 hex>, got {value!r}")
    if any(c not in "0123456789abcdef" for c in body[1]):
        raise ReplayError(f"{field} must be lowercase hex, got {value!r}")
    return value


def _as_missing(value: Any) -> Any | None:
    if isinstance(value, Missing):
        return value
    if isinstance(value, Mapping):
        keys = set(value.keys())
        if keys in ({"value", "reason"}, {"value", "reason", "detail"}):
            if value.get("value") is None and isinstance(value.get("reason"), str):
                try:
                    return Missing(
                        reason=value["reason"], detail=value.get("detail")
                    )
                except (TypeError, ValueError):
                    return None
    return None


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, val in pairs:
        if key in obj:
            raise ReplayError(f"duplicate mapping key: {key!r}")
        obj[key] = val
    return obj


def _strict_gate(raw: bytes, context: str) -> Any:
    """Parse strict JSON bytes through the tier-0 kernel gate.

    The payload rides inside ``record/v1.timing`` so duplicate keys, bare
    nulls, nonfinite numbers, and malformed Missing envelopes are rejected
    by ``contract_codec`` before this module applies its closed shapes.
    """
    if not isinstance(raw, bytes):
        raise ReplayError(f"{context} must decode from bytes")
    wrapper = b'{"id":"offline_replay_gate","timing":' + raw + b"}"
    try:
        contract_codec.validate_record(wrapper, _CODEC_GATE_SCHEMA)
    except (TypeError, ValueError) as exc:
        raise ReplayError(
            f"{context}: strict JSON gate rejected record: {exc}"
        ) from exc
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReplayError(
            f"{context}: record bytes are not valid utf-8: {exc}"
        ) from exc
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_object)
    except json.JSONDecodeError as exc:
        raise ReplayError(
            f"{context}: record bytes are not valid JSON: {exc}"
        ) from exc


def _is_active(value: Any) -> bool:
    """Whether a declared effect field requests a real external effect."""
    if value is None or value is False:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip() != ""
    if isinstance(value, (list, tuple, dict, set, frozenset)):
        return len(value) > 0
    missing = _as_missing(value)
    if missing is not None:
        return False
    return True


def _scan_for_external_write(node: Any, path: str) -> None:
    """Refuse any bundle that would cause an external write."""
    if isinstance(node, Mapping):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and key in _EXTERNAL_WRITE_KEYS and _is_active(value):
                raise ReplayConformanceError(
                    f"replay declares external write at {here}: "
                    f"{key!r} is active; diagnostic replay invokes no "
                    "browser, subject, control action, email send, "
                    "calendar write, or employer mutation"
                )
            _scan_for_external_write(value, here)
    elif isinstance(node, (list, tuple)):
        for index, value in enumerate(node):
            _scan_for_external_write(value, f"{path}[{index}]")


def _coerce_prefix(value: Any) -> Any:
    if isinstance(value, JournalPrefix):
        return value
    if isinstance(value, Mapping) and set(value.keys()) == {
        "journal_id",
        "last_sequence",
        "head_hash",
    }:
        try:
            return JournalPrefix(
                journal_id=value["journal_id"],
                last_sequence=value["last_sequence"],
                head_hash=value["head_hash"],
            )
        except (TypeError, ValueError) as exc:
            raise ReplayError(f"invalid expected_prefix: {exc}") from exc
    raise ReplayError(
        "expected_prefix must be a JournalPrefix mapping, "
        f"not {type(value).__name__}"
    )


def _coerce_request(value: Any) -> Any:
    if isinstance(value, AnalysisRequest):
        return value
    if isinstance(value, Mapping):
        try:
            return AnalysisRequest.from_dict(value)
        except Exception as exc:
            raise ReplayError(f"invalid analysis_request: {exc}") from exc
    raise ReplayError(
        "analysis_request must be an AnalysisRequest mapping, "
        f"not {type(value).__name__}"
    )


def _inputs_missing_receipt(
    *,
    replay_engine: Any,
    source: Any,
    prefix: Any,
    source_digest: str,
    missing_inputs: tuple[str, ...],
    reason: str,
    detail: str,
) -> ReplayReceipt:
    if reason not in contract_codec.VALID_MISSING_REASONS:
        reason = "not_observed"
    trimmed = detail.strip() or "required replay inputs are missing"
    if len(trimmed) > 500:
        trimmed = trimmed[:497] + "..."
    return ReplayReceipt(
        record_type=RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        replay_kind=REPLAY_KIND,
        replay_engine=replay_engine,
        source_diagnostic_id=source.diagnostic_id,
        analysis_revision=source.analysis_revision,
        input_prefix=prefix,
        source_digest=source_digest,
        rederived_digest=Missing(reason=reason, detail=trimmed),
        verdict="inputs_missing",
        missing_inputs=tuple(missing_inputs),
        external_write_attempted=False,
        detail=trimmed,
    )


def _describe_mismatch(source: Any, rederived: Any) -> str:
    try:
        left = source.to_dict()
        right = rederived.to_dict()
    except Exception:
        return "re-derived diagnostic differs from source"
    if not isinstance(left, dict) or not isinstance(right, dict):
        return "re-derived diagnostic differs from source"
    differing: list[str] = []
    for key in sorted(set(left.keys()) | set(right.keys())):
        try:
            if _canonical_bytes(left.get(key)) != _canonical_bytes(right.get(key)):
                differing.append(str(key))
        except (TypeError, ValueError):
            differing.append(str(key))
    if not differing:
        return "re-derived bytes differ from source bytes"
    shown = ", ".join(differing[:8])
    suffix = "" if len(differing) <= 8 else f" (+{len(differing) - 8} more)"
    text = f"re-derived diagnostic differs in fields: {shown}{suffix}"
    if len(text) > 500:
        text = text[:497] + "..."
    return text


# ---------------------------------------------------------------------------
# Public interface (EXPOSES)
# ---------------------------------------------------------------------------


def replay_diagnostic(
    channel_id: str,
    manifest: Manifest,
    source: DiagnosticDocument,
    input_bundle: ArtifactReference,
    replay_engine: VersionPin,
) -> ReplayReceipt:
    """Re-derive a production diagnostic offline and compare it to source.

    The re-derivation consumes only the immutable ``manifest``, the named
    journal prefix, and the pinned classifier bundle named by the replay
    input bundle. Recorded derived outputs are never fed back as
    authoritative inputs. The comparison covers the re-derived diagnostic
    bytes; the source document is never modified. The result is a
    separate immutable receipt for later registration.

    A bundle that declares any external write (browser, subject, control
    action, email send, calendar write, or employer mutation) fails
    conformance: this function raises :class:`ReplayConformanceError`
    before any re-derivation and performs no external effect. Missing
    replay inputs prevent a matched receipt: they yield an
    ``inputs_missing`` receipt, never ``matched``.
    """
    if not isinstance(channel_id, str) or not channel_id:
        raise ReplayError("channel_id must be a nonempty string")
    if not isinstance(manifest, Manifest):
        raise ReplayError(
            "manifest must be an evidence_journal.Manifest instance, "
            f"not {type(manifest).__name__}"
        )
    if not isinstance(source, DiagnosticDocument):
        raise ReplayError(
            "source must be an attempt_diagnostics.DiagnosticDocument instance, "
            f"not {type(source).__name__}"
        )
    if isinstance(input_bundle, ArtifactReference):
        bundle_ref = input_bundle
    elif isinstance(input_bundle, Mapping):
        try:
            bundle_ref = ArtifactReference.from_dict(dict(input_bundle))
        except (TypeError, ValueError) as exc:
            raise ReplayError(f"invalid input_bundle reference: {exc}") from exc
    else:
        raise ReplayError(
            "input_bundle must be an ArtifactReference, "
            f"not {type(input_bundle).__name__}"
        )
    if isinstance(replay_engine, VersionPin):
        engine = replay_engine
    elif isinstance(replay_engine, Mapping):
        try:
            engine = VersionPin.from_dict(replay_engine)
        except Exception as exc:
            raise ReplayError(f"invalid replay_engine pin: {exc}") from exc
    else:
        raise ReplayError(
            "replay_engine must be a VersionPin, "
            f"not {type(replay_engine).__name__}"
        )

    # Snapshot the source before touching any other input. The frozen
    # document cannot be mutated; the digest pins what we compare against.
    try:
        source_bytes = attempt_diagnostics.to_canonical_bytes(source)
    except Exception as exc:
        raise ReplayError(f"source diagnostic does not serialize: {exc}") from exc
    try:
        source_digest = str(contract_codec.canonical_digest(source_bytes))
    except (TypeError, ValueError) as exc:
        raise ReplayError(
            f"source diagnostic is not a strict record: {exc}"
        ) from exc
    source_prefix = source.input_prefix

    # Resolve the recorded input bundle. Absent bytes are explicit
    # missing inputs, never a reason to consult a live service.
    try:
        bundle_bytes = artifact_store.resolve_artifact(channel_id, bundle_ref)
    except artifact_store.ArtifactLostError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("input_bundle_bytes",),
            reason="observation_lost",
            detail=f"input bundle bytes are lost: {exc}",
        )
    except artifact_store.ArtifactUnavailableError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("input_bundle_bytes",),
            reason="not_observed",
            detail=f"input bundle bytes are unavailable: {exc}",
        )
    except artifact_store.ArtifactAccessDeniedError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("input_bundle_bytes",),
            reason="not_observed",
            detail=f"input bundle bytes are not readable from this channel: {exc}",
        )

    try:
        bundle = _strict_gate(bundle_bytes, "replay input bundle")
    except ReplayError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("input_bundle_parse",),
            reason="not_observed",
            detail=str(exc),
        )
    if not isinstance(bundle, dict):
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("input_bundle_shape",),
            reason="not_observed",
            detail="replay input bundle must be a JSON object",
        )

    # Fail fast on external effects, before reading the journal or
    # re-deriving anything. No browser, subject, control action, email
    # send, calendar write, or employer mutation is ever invoked.
    _scan_for_external_write(bundle, "$")
    declared_kind = bundle.get("replay_kind")
    if declared_kind is not None and declared_kind != REPLAY_KIND:
        if declared_kind in _FORBIDDEN_REPLAY_KINDS:
            raise ReplayConformanceError(
                f"bundle mislabels offline re-derivation as {declared_kind!r}; "
                "production diagnostic re-derivation is not exact fixture "
                "replay or live reproduction"
            )
        raise ReplayConformanceError(
            f"bundle declares unsupported replay_kind {declared_kind!r}; "
            f"offline replay is only {REPLAY_KIND!r}"
        )

    absent = tuple(
        key for key in ("expected_prefix", "analysis_request") if key not in bundle
    )
    if absent:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=absent,
            reason="not_observed",
            detail=f"replay input bundle omits required inputs: {', '.join(absent)}",
        )

    try:
        prefix = _coerce_prefix(bundle["expected_prefix"])
    except ReplayError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=source_prefix,
            source_digest=source_digest,
            missing_inputs=("expected_prefix",),
            reason="not_observed",
            detail=str(exc),
        )
    try:
        request = _coerce_request(bundle["analysis_request"])
    except ReplayError as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("analysis_request",),
            reason="not_observed",
            detail=str(exc),
        )

    # Re-verify the named prefix chain before re-derivation. A prefix
    # that is not readable or not intact is missing input, not a cue
    # to fetch from a live service.
    try:
        events = evidence_journal.read_prefix(channel_id, prefix)
    except Exception as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("journal_prefix",),
            reason="not_observed",
            detail=f"named prefix is not readable or not intact: {exc}",
        )
    if not events:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("journal_prefix",),
            reason="not_observed",
            detail="named prefix contains no events",
        )

    # Re-derive from manifest, prefix, and pinned classifier only. The
    # recorded source diagnostic contributes nothing but the comparison
    # target; its derived outputs are never authoritative inputs here.
    try:
        rederived = attempt_diagnostics.derive_diagnostic(
            channel_id, manifest, prefix, request
        )
    except Exception as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("rederivation_inputs",),
            reason="not_observed",
            detail=f"re-derivation refused: {exc}",
        )

    try:
        rederived_bytes = attempt_diagnostics.to_canonical_bytes(rederived)
    except Exception as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("rederived_serialization",),
            reason="observation_lost",
            detail=f"re-derived diagnostic does not serialize: {exc}",
        )
    try:
        rederived_digest = str(contract_codec.canonical_digest(rederived_bytes))
    except (TypeError, ValueError) as exc:
        return _inputs_missing_receipt(
            replay_engine=engine,
            source=source,
            prefix=prefix,
            source_digest=source_digest,
            missing_inputs=("rederived_digest",),
            reason="observation_lost",
            detail=f"re-derived diagnostic is not a strict record: {exc}",
        )

    if rederived_bytes == source_bytes:
        return ReplayReceipt(
            record_type=RECORD_TYPE,
            schema_version=SCHEMA_VERSION,
            replay_kind=REPLAY_KIND,
            replay_engine=engine,
            source_diagnostic_id=source.diagnostic_id,
            analysis_revision=source.analysis_revision,
            input_prefix=prefix,
            source_digest=source_digest,
            rederived_digest=rederived_digest,
            verdict="matched",
            missing_inputs=(),
            external_write_attempted=False,
            detail="re-derived diagnostic is byte-identical to source",
        )
    return ReplayReceipt(
        record_type=RECORD_TYPE,
        schema_version=SCHEMA_VERSION,
        replay_kind=REPLAY_KIND,
        replay_engine=engine,
        source_diagnostic_id=source.diagnostic_id,
        analysis_revision=source.analysis_revision,
        input_prefix=prefix,
        source_digest=source_digest,
        rederived_digest=rederived_digest,
        verdict="mismatched",
        missing_inputs=(),
        external_write_attempted=False,
        detail=_describe_mismatch(source, rederived),
    )
