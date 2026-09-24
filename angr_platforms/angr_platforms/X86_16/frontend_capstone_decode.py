"""Decode exact or bounded x86-16 bytes without constructing VEX.

Layer: Frontend.
Responsibility: publish typed contiguous Capstone block evidence from loaded bytes while refusing uncertain bounds.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, cast

from capstone import CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET

from .frontend_capstone_block import DirectCapstoneBlock8616, DirectCapstoneInstruction8616

_BLOCK_MAX_BYTES_8616 = 400
_CONTROL_GROUPS_8616 = frozenset({CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET})
_CONTROL_MNEMONICS_8616 = frozenset({
    "call", "callf", "lcall", "jmp", "jmpf", "ljmp",
    "ret", "retf", "retw", "iret", "iretw", "int", "int1", "int3", "into",
    "loop", "loope", "loopne", "loopnz", "loopz",
})
_REPEAT_PREFIXES_8616 = frozenset({"rep", "repe", "repne", "repnz", "repz"})
_REFUSED_TERMINATORS_8616 = frozenset({"hlt", "syscall", "sysenter", "sysexit", "ud2"})


class _InstructionBoundary8616(Protocol):
    """Capstone fields required for contiguous block ownership."""

    address: int
    size: int
    mnemonic: str
    op_str: str
    groups: Sequence[int]


class _CapstoneDecoderBoundary8616(Protocol):
    """Architecture-configured Capstone decoder boundary."""

    def disasm(self, code: bytes, address: int) -> Iterable[object]:
        """Decode bytes at their loaded address."""
        ...


class _ArchitectureBoundary8616(Protocol):
    """Project architecture fields required by direct decoding."""

    capstone: _CapstoneDecoderBoundary8616


class _LoaderMemoryBoundary8616(Protocol):
    """Loaded-memory byte reader used by bounded decoding."""

    def load(self, address: int, size: int) -> object:
        """Read one loaded address range."""
        ...


class _LoaderBoundary8616(Protocol):
    """Project loader fields required by bounded decoding."""

    memory: _LoaderMemoryBoundary8616


class _ProjectBoundary8616(Protocol):
    """Dynamic project fields required at the Frontend boundary."""

    arch: _ArchitectureBoundary8616
    loader: _LoaderBoundary8616


class CapstoneBlockDecodeStatus8616(Enum):
    """Typed outcome of one direct Capstone block request."""

    COMPLETE = "complete"
    REFUSED = "refused"


class CapstoneBlockDecodeFailureReason8616(Enum):
    """Stable reason direct block decoding could not close."""

    INVALID_BOUNDS = "invalid_bounds"
    BYTE_READ_FAILED = "byte_read_failed"
    DECODER_UNAVAILABLE = "decoder_unavailable"
    DECODE_INCOMPLETE = "decode_incomplete"
    TERMINATOR_UNSUPPORTED = "terminator_unsupported"


@dataclass(frozen=True, slots=True)
class CapstoneBlockDecodeFailure8616:
    """One typed direct-decode refusal."""

    reason: CapstoneBlockDecodeFailureReason8616
    detail: str = ""


@dataclass(frozen=True, slots=True)
class CapstoneBlockDecodeArtifact8616:
    """Closed direct-decode result for one requested block."""

    status: CapstoneBlockDecodeStatus8616
    block: DirectCapstoneBlock8616 | None
    failure: CapstoneBlockDecodeFailure8616 | None
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether the request materialized one contiguous block."""
        return (
            self.status is CapstoneBlockDecodeStatus8616.COMPLETE
            and self.block is not None
            and self.failure is None
            and self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


def _refused_8616(
    reason: CapstoneBlockDecodeFailureReason8616,
    detail: str = "",
) -> CapstoneBlockDecodeArtifact8616:
    """Return one closed typed refusal."""
    return CapstoneBlockDecodeArtifact8616(
        CapstoneBlockDecodeStatus8616.REFUSED,
        None,
        CapstoneBlockDecodeFailure8616(reason, detail),
        1,
        1,
        1,
        0,
        1,
    )


def _instruction_view_8616(instruction: object) -> DirectCapstoneInstruction8616:
    """Wrap one raw Capstone instruction in the legacy consumer shape."""
    boundary = cast(_InstructionBoundary8616, instruction)
    return DirectCapstoneInstruction8616(
        boundary.address,
        boundary.size,
        boundary.mnemonic,
        boundary.op_str,
        instruction,
    )


def _complete_8616(
    address: int,
    code: bytes,
    instructions: tuple[object, ...],
    consumed: int,
) -> CapstoneBlockDecodeArtifact8616:
    """Return one complete direct block projection."""
    wrapped = tuple(_instruction_view_8616(instruction) for instruction in instructions)
    return CapstoneBlockDecodeArtifact8616(
        CapstoneBlockDecodeStatus8616.COMPLETE,
        DirectCapstoneBlock8616(address, consumed, code[:consumed], wrapped),
        None,
        1,
        1,
        1,
        1,
        0,
    )


def _instruction_terminates_block_8616(instruction: object) -> tuple[bool, bool, bool]:
    """Return ``(terminates, supported, repeats)`` for one instruction."""
    boundary = cast(_InstructionBoundary8616, instruction)
    try:
        mnemonic = boundary.mnemonic.lower()
    except (AttributeError, TypeError):
        return False, False, False
    if mnemonic in _REFUSED_TERMINATORS_8616:
        return True, False, False
    repeats = mnemonic.partition(" ")[0] in _REPEAT_PREFIXES_8616
    try:
        groups = frozenset(int(group) for group in boundary.groups)
    except (AttributeError, TypeError, ValueError):
        groups = frozenset()
    terminates = repeats or bool(groups & _CONTROL_GROUPS_8616)
    terminates = terminates or mnemonic in _CONTROL_MNEMONICS_8616 or mnemonic.startswith("j")
    return terminates, True, repeats


def _scan_decoded_instructions_8616(
    decoder: object,
    address: int,
    code: bytes,
    *,
    require_full_extent: bool,
) -> CapstoneBlockDecodeArtifact8616 | tuple[tuple[object, ...], int, bool]:
    """Decode until a proven terminator or return a typed decode refusal."""
    instructions: list[object] = []
    expected = address
    terminated = False
    for instruction in decoder.disasm(code, address):
        instruction_boundary = cast(_InstructionBoundary8616, instruction)
        instruction_address = int(instruction_boundary.address)
        instruction_size = int(instruction_boundary.size)
        if instruction_address != expected or instruction_size <= 0:
            return _refused_8616(
                CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
                "Capstone instruction ownership is not contiguous",
            )
        terminates = False
        if not require_full_extent:
            terminates, supported, repeats = _instruction_terminates_block_8616(instruction)
            if not supported:
                return _refused_8616(
                    CapstoneBlockDecodeFailureReason8616.TERMINATOR_UNSUPPORTED,
                    str(instruction_boundary.mnemonic),
                )
            if repeats and instructions:
                terminated = True
                break
        expected += instruction_size
        if expected > address + len(code):
            return _refused_8616(
                CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
                "Capstone instruction exceeds the requested byte extent",
            )
        instructions.append(instruction)
        if require_full_extent:
            continue
        terminated = terminates
        if terminated:
            break
    return tuple(instructions), expected - address, terminated


def _decode_8616(
    project: object,
    address: int,
    code: bytes,
    *,
    require_full_extent: bool,
) -> CapstoneBlockDecodeArtifact8616:
    """Decode contiguous bytes, stopping only at a proven block terminator."""
    if address < 0 or not code:
        return _refused_8616(CapstoneBlockDecodeFailureReason8616.INVALID_BOUNDS)
    boundary = cast(_ProjectBoundary8616, project)
    try:
        decoder = boundary.arch.capstone
    except (AttributeError, TypeError) as error:
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.DECODER_UNAVAILABLE,
            f"{type(error).__name__}: {error}",
        )
    try:
        scan = _scan_decoded_instructions_8616(
            decoder,
            address,
            code,
            require_full_extent=require_full_extent,
        )
    except Exception as error:
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
            f"{type(error).__name__}: {error}",
        )
    if isinstance(scan, CapstoneBlockDecodeArtifact8616):
        return scan
    instructions, consumed, terminated = scan
    if not instructions or consumed <= 0:
        return _refused_8616(CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE)
    if require_full_extent and consumed != len(code):
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
            f"expected={len(code)} consumed={consumed}",
        )
    if not require_full_extent and not terminated and consumed != len(code):
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.DECODE_INCOMPLETE,
            "Capstone stopped before the bounded byte extent",
        )
    return _complete_8616(address, code, tuple(instructions), consumed)


def decode_exact_capstone_block_8616(
    project: object,
    address: int,
    code: bytes,
) -> CapstoneBlockDecodeArtifact8616:
    """Decode every byte in one exact caller-owned block extent."""
    return _decode_8616(project, address, code, require_full_extent=True)


def decode_bounded_capstone_block_8616(
    project: object,
    address: int,
    region_end: int,
) -> CapstoneBlockDecodeArtifact8616:
    """Decode one basic block within a proven loaded upper bound."""
    read_size = min(_BLOCK_MAX_BYTES_8616, region_end - address)
    if address < 0 or read_size <= 0:
        return _refused_8616(CapstoneBlockDecodeFailureReason8616.INVALID_BOUNDS)
    boundary = cast(_ProjectBoundary8616, project)
    try:
        code = bytes(cast(Any, boundary.loader.memory.load(address, read_size)))
    except Exception as error:
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.BYTE_READ_FAILED,
            f"{type(error).__name__}: {error}",
        )
    if len(code) != read_size:
        return _refused_8616(
            CapstoneBlockDecodeFailureReason8616.BYTE_READ_FAILED,
            f"expected={read_size} actual={len(code)}",
        )
    return _decode_8616(project, address, code, require_full_extent=False)


__all__ = [
    "CapstoneBlockDecodeArtifact8616",
    "CapstoneBlockDecodeFailure8616",
    "CapstoneBlockDecodeFailureReason8616",
    "CapstoneBlockDecodeStatus8616",
    "DirectCapstoneBlock8616",
    "DirectCapstoneInstruction8616",
    "decode_bounded_capstone_block_8616",
    "decode_exact_capstone_block_8616",
]
