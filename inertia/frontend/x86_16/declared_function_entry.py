"""Explicit conditional function-entry declarations bound to exact MZ source.

Layer: Frontend.
Responsibility: admit a caller-declared function-entry premise only when it
binds the exact serialized MZ source, the exact relocated load module, an
exact native range and entry coordinate inside that module, an exact declared
environment digest, an explicit register constraint set, and an explicit
return frame whose bytes are present in declared memory. The admitted
premise is a seed for a locally scoped proof — it never claims the runtime,
the CRT prologue, or any execution path actually reaches this state, and it
infers no register, memory or return behavior beyond the declared fields.
Forbidden: reachability claims, ABI or name-derived defaults, text-based
evidence, or treating overlay bytes as observed truth.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from itertools import pairwise

from inertia.frontend.x86_16.mz_invocation_source import mz_invocation_source_8616

__all__ = [
    "DeclaredEntryFailure8616",
    "DeclaredEntryMemory8616",
    "DeclaredEntryReturn8616",
    "DeclaredEntryReturnKind8616",
    "DeclaredFunctionEntryAdmission8616",
    "DeclaredFunctionEntryAssumption8616",
    "DeclaredFunctionEntryRefusal8616",
    "DeclaredFunctionEntrySpec8616",
    "admit_declared_function_entry_8616",
    "revalidate_declared_function_entry_8616",
]

_SPEC_VERSION_8616: int = 1
_WORD_MAX_8616: int = 0xFFFF
_REAL_MODE_LIMIT_8616: int = 0x100000
_DIGEST_HEX_8616: int = 64
_MANDATORY_REGISTERS_8616: frozenset[str] = frozenset({"ss", "sp"})
_OPTIONAL_REGISTERS_8616: frozenset[str] = frozenset(
    {"ax", "bx", "cx", "dx", "bp", "si", "di", "ds", "es", "fs", "gs", "flags"}
)
_ENTRY_REGISTERS_8616: frozenset[str] = frozenset({"cs", "ip"})


class DeclaredEntryReturnKind8616(StrEnum):
    """Which architectural return shape the declared boundary asserts."""

    NEAR = "near"
    FAR = "far"


class DeclaredFunctionEntryAssumption8616(StrEnum):
    """Authority granted by admission: an explicit conditional entry premise."""

    DECLARED_FUNCTION_ENTRY = "declared_function_entry"


class DeclaredEntryFailure8616(StrEnum):
    """Stable typed reasons a function-entry declaration cannot be admitted."""

    SPEC_MALFORMED = "spec_malformed"
    VERSION_UNSUPPORTED = "version_unsupported"
    DIGEST_MALFORMED = "digest_malformed"
    SOURCE_MISMATCH = "source_mismatch"
    MODULE_MISMATCH = "module_mismatch"
    ENVIRONMENT_MISMATCH = "environment_mismatch"
    RANGE_INVALID = "range_invalid"
    NATIVE_DIGEST_MISMATCH = "native_digest_mismatch"
    ENTRY_INVALID = "entry_invalid"
    REGISTER_INVALID = "register_invalid"
    MEMORY_INVALID = "memory_invalid"
    MEMORY_ALTERS_NATIVE = "memory_alters_native"
    RETURN_INVALID = "return_invalid"
    FRAME_INVALID = "frame_invalid"
    FRAME_UNDECLARED = "frame_undeclared"


_Failure8616 = DeclaredEntryFailure8616


@dataclass(frozen=True, slots=True)
class DeclaredEntryMemory8616:
    """One declared overlay span: immutable bytes at a real-mode address."""

    address: int
    data: bytes


@dataclass(frozen=True, slots=True)
class DeclaredEntryReturn8616:
    """The declared return-target boundary shape for the conditional entry."""

    kind: DeclaredEntryReturnKind8616
    segment: int
    offset: int


@dataclass(frozen=True, slots=True)
class DeclaredFunctionEntrySpec8616:
    """One parsed declaration before it binds to the exact current source.

    ``range_start``/``range_end`` are absolute linear addresses delimiting the
    function's native bytes inside the relocated module. ``registers`` carries
    fixed 16-bit constraints only — mandatory ``ss``/``sp`` plus optional
    canonical words; ``cs``/``ip`` belong to the entry fields and are refused
    here. ``use_environment_memory`` states whether the caller's declared
    baseline environment memory is part of the conditional premise; ``False``
    leaves every unspecified data byte unknown, including module/code bytes.
    Source bytes authenticate instruction decoding separately.
    """

    version: int
    source_sha256: str
    relocated_sha256: str
    load_segment: int
    entry_segment: int
    entry_offset: int
    range_start: int
    range_end: int
    native_sha256: str
    environment_sha256: str
    use_environment_memory: bool
    registers: tuple[tuple[str, int], ...]
    memory: tuple[DeclaredEntryMemory8616, ...]
    return_boundary: DeclaredEntryReturn8616

    def to_dict(self) -> dict[str, object]:
        """Serialize the complete conditional premise deterministically."""
        return _declaration_document_8616(self)


@dataclass(frozen=True, slots=True)
class DeclaredFunctionEntryRefusal8616:
    """Typed refusal result: an enumerated reason plus human detail."""

    reason: DeclaredEntryFailure8616
    detail: str


@dataclass(frozen=True, slots=True)
class DeclaredFunctionEntryAdmission8616:
    """A declaration bound to the exact source, module, and environment.

    ``complete`` checks retained-input consistency only, never live project
    freshness. Consumers must authenticate current mapped bytes and call the
    explicit revalidator with current source/module/environment identity.
    ``declaration_sha256`` is the deterministic digest
    of every spec field, binding the whole conditional premise — including
    ``use_environment_memory`` and every declared constraint — by identity.
    """

    spec: DeclaredFunctionEntrySpec8616
    source: bytes
    loaded_module: bytes
    environment_sha256: str
    declaration_sha256: str

    @property
    def complete(self) -> bool:
        """Require exact agreement with a fresh admission of the inputs."""
        if type(self) is not DeclaredFunctionEntryAdmission8616:
            return False
        result = admit_declared_function_entry_8616(
            self.spec,
            source=self.source,
            loaded_module=self.loaded_module,
            environment_sha256=self.environment_sha256,
        )
        return result == self

    @property
    def entry_linear(self) -> int:
        """Return the declared entry's physical address."""
        return self.spec.entry_segment * 16 + self.spec.entry_offset

    def to_dict(self) -> dict[str, object]:
        """Expose declaration identity and premises without embedding MZ blobs."""
        return {
            "assumption": DeclaredFunctionEntryAssumption8616.DECLARED_FUNCTION_ENTRY.value,
            "declaration_sha256": self.declaration_sha256,
            "spec": self.spec.to_dict(),
        }


def _refuse_8616(
    reason: DeclaredEntryFailure8616, detail: str
) -> DeclaredFunctionEntryRefusal8616:
    """Return the typed refusal without weakening the contract."""
    return DeclaredFunctionEntryRefusal8616(reason, detail)


def _word_8616(value: object) -> bool:
    """Return whether ``value`` is a strict 16-bit word, bool excluded."""
    return type(value) is int and 0 <= value <= _WORD_MAX_8616


def _digest_8616(value: object) -> bool:
    """Return whether ``value`` is a lowercase SHA-256 hex digest string."""
    return (
        isinstance(value, str)
        and len(value) == _DIGEST_HEX_8616
        and value == value.lower()
        and all(char in "0123456789abcdef" for char in value)
    )


def _register_map_8616(
    spec: DeclaredFunctionEntrySpec8616,
) -> dict[str, int] | DeclaredFunctionEntryRefusal8616:
    """Validate the fixed-register constraint set into a lookup map."""
    registers: dict[str, int] = {}
    for item in spec.registers:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or item[0] != item[0].lower()
        ):
            return _refuse_8616(
                _Failure8616.REGISTER_INVALID, "register constraints must be lowercase name/value pairs"
            )
        name, value = item
        if name in _ENTRY_REGISTERS_8616 or name not in (
            _MANDATORY_REGISTERS_8616 | _OPTIONAL_REGISTERS_8616
        ):
            return _refuse_8616(
                _Failure8616.REGISTER_INVALID, f"register {name!r} is not an admissible fixed constraint"
            )
        if name in registers or not _word_8616(value):
            return _refuse_8616(
                _Failure8616.REGISTER_INVALID, f"register {name!r} is duplicated or out of word bounds"
            )
        registers[name] = value
    if any(name not in registers for name in _MANDATORY_REGISTERS_8616):
        return _refuse_8616(
            _Failure8616.REGISTER_INVALID, "ss/sp constraints are mandatory for the declared return frame"
        )
    return registers


def _memory_check_8616(
    spec: DeclaredFunctionEntrySpec8616, native: bytes
) -> DeclaredFunctionEntryRefusal8616 | None:
    """Validate overlay spans: bounded, nonempty, disjoint, non-altering."""
    spans: list[tuple[int, int]] = []
    for span in spec.memory:
        well_formed = (
            type(span) is DeclaredEntryMemory8616
            and type(span.address) is int
            and isinstance(span.data, bytes)
        )
        if not well_formed:
            return _refuse_8616(
                _Failure8616.MEMORY_INVALID, "declared memory spans require typed address and bytes"
            )
        if (
            span.address < 0
            or len(span.data) == 0
            or span.address + len(span.data) > _REAL_MODE_LIMIT_8616
        ):
            return _refuse_8616(
                _Failure8616.MEMORY_INVALID, "declared memory spans require bounded nonempty immutable bytes"
            )
        spans.append((span.address, span.address + len(span.data)))
        overlap_start = max(span.address, spec.range_start)
        overlap_end = min(span.address + len(span.data), spec.range_end)
        if overlap_start < overlap_end:
            native_offset = overlap_start - spec.range_start
            if span.data[overlap_start - span.address : overlap_end - span.address] != native[
                native_offset : native_offset + overlap_end - overlap_start
            ]:
                return _refuse_8616(
                    _Failure8616.MEMORY_ALTERS_NATIVE, "an overlay span would alter declared native function bytes"
                )
    spans.sort()
    if any(earlier[1] > later[0] for earlier, later in pairwise(spans)):
        return _refuse_8616(_Failure8616.MEMORY_INVALID, "declared memory spans must not overlap")
    return None


def _declared_byte_8616(spec: DeclaredFunctionEntrySpec8616, address: int) -> int | None:
    """Return the declared byte at ``address`` or ``None`` when unspecified."""
    for span in spec.memory:
        if span.address <= address < span.address + len(span.data):
            return span.data[address - span.address]
    return None


def _frame_check_8616(
    spec: DeclaredFunctionEntrySpec8616, registers: dict[str, int]
) -> DeclaredFunctionEntryRefusal8616 | None:
    """Bind the declared return frame at SS:SP against declared memory."""
    boundary = spec.return_boundary
    size = 2 if boundary.kind is DeclaredEntryReturnKind8616.NEAR else 4
    sp = registers["sp"]
    frame_linear = registers["ss"] * 16 + sp
    if (
        sp + size > 0x10000
        or frame_linear + size > _REAL_MODE_LIMIT_8616
        or (frame_linear < spec.range_end
            and spec.range_start < frame_linear + size)
    ):
        return _refuse_8616(
            _Failure8616.FRAME_INVALID, "return frame wraps the stack, leaves real-mode memory, or aliases code"
        )
    expected = boundary.offset.to_bytes(2, "little")
    if boundary.kind is DeclaredEntryReturnKind8616.FAR:
        expected += boundary.segment.to_bytes(2, "little")
    if any(
        _declared_byte_8616(spec, frame_linear + index) != expected[index]
        for index in range(size)
    ):
        return _refuse_8616(
            _Failure8616.FRAME_UNDECLARED, "return frame bytes are not explicitly present in declared memory"
        )
    return None


def _declaration_document_8616(spec: DeclaredFunctionEntrySpec8616) -> dict[str, object]:
    """Project every declared field into the one canonical digest document."""
    return {
        "version": spec.version,
        "source_sha256": spec.source_sha256,
        "relocated_sha256": spec.relocated_sha256,
        "load_segment": spec.load_segment,
        "entry_segment": spec.entry_segment,
        "entry_offset": spec.entry_offset,
        "range_start": spec.range_start,
        "range_end": spec.range_end,
        "native_sha256": spec.native_sha256,
        "environment_sha256": spec.environment_sha256,
        "use_environment_memory": spec.use_environment_memory,
        "registers": [list(item) for item in spec.registers],
        "memory": [
            {"address": span.address, "data": span.data.hex()}
            for span in spec.memory
        ],
        "return_boundary": {
            "kind": spec.return_boundary.kind.value,
            "segment": spec.return_boundary.segment,
            "offset": spec.return_boundary.offset,
        },
    }


def _declaration_digest_8616(spec: DeclaredFunctionEntrySpec8616) -> str:
    """Digest the same complete document exposed to receipt consumers."""
    return hashlib.sha256(
        json.dumps(spec.to_dict(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _preflight_8616(
    spec: DeclaredFunctionEntrySpec8616,
    source: bytes,
    loaded_module: bytes,
    environment_sha256: str,
) -> DeclaredFunctionEntryRefusal8616 | None:
    """Bind schema, digests, environment identity, and raw input shapes."""
    if type(spec.version) is not int or spec.version != _SPEC_VERSION_8616:
        return _refuse_8616(_Failure8616.VERSION_UNSUPPORTED, "only version 1 is admitted")
    if not all(
        _digest_8616(value)
        for value in (
            spec.source_sha256,
            spec.relocated_sha256,
            spec.native_sha256,
            spec.environment_sha256,
            environment_sha256,
        )
    ):
        return _refuse_8616(
            _Failure8616.DIGEST_MALFORMED, "digest fields must be lowercase sha256 hex"
        )
    if environment_sha256 != spec.environment_sha256:
        return _refuse_8616(
            _Failure8616.ENVIRONMENT_MISMATCH, "caller environment digest does not match the declaration"
        )
    if (
        type(spec.use_environment_memory) is not bool
        or not _word_8616(spec.load_segment)
        or type(spec.registers) is not tuple
        or type(spec.memory) is not tuple
    ):
        return _refuse_8616(
            _Failure8616.SPEC_MALFORMED, "baseline flag, load paragraph and immutable constraint tuples required"
        )
    if (
        type(source) is not bytes
        or type(loaded_module) is not bytes
        or hashlib.sha256(source).hexdigest() != spec.source_sha256
    ):
        return _refuse_8616(
            _Failure8616.SOURCE_MISMATCH, "source bytes do not match the declared digest"
        )
    return None


def _native_bytes_8616(
    spec: DeclaredFunctionEntrySpec8616, source: bytes, loaded_module: bytes
) -> bytes | DeclaredFunctionEntryRefusal8616:
    """Recompute the relocated module and slice the digest-bound range."""
    try:
        projection = mz_invocation_source_8616(source, spec.load_segment)
    except (TypeError, ValueError) as error:
        return _refuse_8616(_Failure8616.SOURCE_MISMATCH, f"MZ source refused: {error}")
    if (
        hashlib.sha256(projection.module).hexdigest() != spec.relocated_sha256
        or loaded_module != projection.module
    ):
        return _refuse_8616(
            _Failure8616.MODULE_MISMATCH, "loaded module does not equal the declared relocated module"
        )
    base = spec.load_segment * 16
    if (
        type(spec.range_start) is not int
        or type(spec.range_end) is not int
        or not base <= spec.range_start < spec.range_end <= base + len(projection.module)
    ):
        return _refuse_8616(
            _Failure8616.RANGE_INVALID, "native range must lie inside the relocated module"
        )
    native: bytes = projection.module[spec.range_start - base : spec.range_end - base]
    if hashlib.sha256(native).hexdigest() != spec.native_sha256:
        return _refuse_8616(
            _Failure8616.NATIVE_DIGEST_MISMATCH, "declared range bytes differ from the native digest"
        )
    return native


def _entry_check_8616(spec: DeclaredFunctionEntrySpec8616) -> bool:
    """Return whether entry coordinates are words inside the native range."""
    if not _word_8616(spec.entry_segment) or not _word_8616(spec.entry_offset):
        return False
    window = spec.entry_segment * 16
    return (
        window <= spec.range_start <= window + spec.entry_offset < spec.range_end
        and spec.range_end <= window + 0x10000
    )


def _return_boundary_valid_8616(spec: DeclaredFunctionEntrySpec8616) -> bool:
    """Return whether the declared boundary is typed, word-bounded, same-CS."""
    boundary = spec.return_boundary
    well_formed = (
        type(boundary) is DeclaredEntryReturn8616
        and type(boundary.kind) is DeclaredEntryReturnKind8616
        and _word_8616(boundary.segment)
        and _word_8616(boundary.offset)
    )
    return well_formed and boundary.segment * 16 + boundary.offset < _REAL_MODE_LIMIT_8616 and (
        boundary.kind is not DeclaredEntryReturnKind8616.NEAR
        or boundary.segment == spec.entry_segment
    )


def _state_check_8616(
    spec: DeclaredFunctionEntrySpec8616, native: bytes
) -> DeclaredFunctionEntryRefusal8616 | None:
    """Bind entry, registers, overlay spans, return boundary, and frame."""
    if not _entry_check_8616(spec):
        return _refuse_8616(
            _Failure8616.ENTRY_INVALID, "entry coordinates must be words inside the declared native range"
        )
    registers = _register_map_8616(spec)
    if isinstance(registers, DeclaredFunctionEntryRefusal8616):
        return registers
    memory_failure = _memory_check_8616(spec, native)
    if memory_failure is not None:
        return memory_failure
    if not _return_boundary_valid_8616(spec):
        return _refuse_8616(
            _Failure8616.RETURN_INVALID, "return boundary needs typed kind, word coordinates, same-CS near"
        )
    return _frame_check_8616(spec, registers)


def admit_declared_function_entry_8616(
    spec: DeclaredFunctionEntrySpec8616,
    *,
    source: bytes,
    loaded_module: bytes,
    environment_sha256: str,
) -> DeclaredFunctionEntryAdmission8616 | DeclaredFunctionEntryRefusal8616:
    """Admit one explicit conditional function-entry declaration.

    Binds the exact serialized MZ source, the recomputed relocated module
    (both digest and byte equality), the declared environment digest, the
    native range and entry inside it, the fixed register set, the declared
    overlay spans, and the declared return frame. An admission asserts only
    the declared premise — no reachability, ABI, or handler-body proof.
    """
    if type(spec) is not DeclaredFunctionEntrySpec8616:
        return _refuse_8616(_Failure8616.SPEC_MALFORMED, "spec must be the owned dataclass")
    failure = _preflight_8616(spec, source, loaded_module, environment_sha256)
    if failure is not None:
        return failure
    native = _native_bytes_8616(spec, source, loaded_module)
    if isinstance(native, DeclaredFunctionEntryRefusal8616):
        return native
    failure = _state_check_8616(spec, native)
    if failure is not None:
        return failure
    return DeclaredFunctionEntryAdmission8616(
        spec=spec,
        source=source,
        loaded_module=loaded_module,
        environment_sha256=environment_sha256,
        declaration_sha256=_declaration_digest_8616(spec),
    )


def revalidate_declared_function_entry_8616(
    admission: DeclaredFunctionEntryAdmission8616,
    *,
    source: bytes,
    loaded_module: bytes,
    environment_sha256: str,
) -> bool:
    """Rebind retained premise to current consumer-authenticated input bytes.

    This function reads no project and proves no execution path. Its caller
    must authenticate the supplied live module against the actual loader.
    """
    if type(admission) is not DeclaredFunctionEntryAdmission8616:
        return False
    result = admit_declared_function_entry_8616(
        admission.spec, source=source, loaded_module=loaded_module,
        environment_sha256=environment_sha256,
    )
    return type(result) is DeclaredFunctionEntryAdmission8616 and result == admission
