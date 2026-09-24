"""Layer: Optional evidence/reporting.

Responsibility: find fast candidate entry points from direct 16-bit trace evidence.
Forbidden: treating trace candidates as proven function boundaries without later validation.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class FastTraceResult:
    """Optional trace-derived entry candidates that still require validation."""

    entries: tuple[int, ...]
    call_targets: tuple[int, ...]
    jump_targets: tuple[int, ...]
    returns: tuple[int, ...]
    scores: dict[int, int]


class _DecodedInsn8616(Protocol):
    """Capstone instruction fields consumed at the dynamic arch boundary."""

    size: int
    address: int
    mnemonic: str


class _CapstoneDisasm8616(Protocol):
    """Capstone disassembler reached through the dynamic angr arch object."""

    def disasm(self, code: bytes, addr: int, count: int) -> Iterator[_DecodedInsn8616]:
        """Yield up to ``count`` decoded instructions starting at ``addr``."""
        ...


def _looks_like_16bit_function_prologue(code: bytes, offset: int) -> bool:
    window = code[offset : offset + 4]
    return window.startswith(b"\x55\x8b\xec")


def _looks_like_16bit_entry_byte(code: bytes, offset: int) -> bool:
    if offset < 0 or offset >= len(code):
        return False
    byte = code[offset]
    return byte not in {0x00, 0x90, 0xCC}


def _resolve_16bit_function_start(code: bytes, offset: int, *, max_padding: int = 0x10) -> int | None:
    if offset < 0 or offset >= len(code):
        return None
    if _looks_like_16bit_function_prologue(code, offset):
        return offset
    padded = offset
    limit = min(len(code), offset + max_padding)
    while padded < limit and code[padded] in {0x00, 0x90, 0xCC}:
        padded += 1
    if padded < len(code) and _looks_like_16bit_function_prologue(code, padded):
        return padded
    return None


def _resolve_16bit_call_target(code: bytes, offset: int) -> int | None:
    canonical = _resolve_16bit_function_start(code, offset)
    if canonical is not None:
        return canonical
    if _looks_like_16bit_entry_byte(code, offset):
        return offset
    return None


def _branch_target_event_8616(
    code: bytes,
    offset: int,
    insn_addr: int,
    linked_base: int,
) -> tuple[int, int, str] | None:
    """Return one scored call/jump event for a direct branch instruction."""
    opcode = code[offset]
    if opcode == 0xE8 and offset + 2 < len(code):
        rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
        canonical = _resolve_16bit_call_target(code, insn_addr + 3 + rel - linked_base)
        return (linked_base + canonical, 10, "call") if canonical is not None else None
    if opcode == 0x9A and offset + 4 < len(code):
        off = int.from_bytes(code[offset + 1 : offset + 3], "little")
        seg = int.from_bytes(code[offset + 3 : offset + 5], "little")
        canonical = _resolve_16bit_call_target(code, (seg << 4) + off)
        return (linked_base + canonical, 12, "call") if canonical is not None else None
    if opcode == 0xE9 and offset + 2 < len(code):
        rel = int.from_bytes(code[offset + 1 : offset + 3], "little", signed=True)
        canonical = _resolve_16bit_function_start(code, insn_addr + 3 + rel - linked_base)
        return (linked_base + canonical, 2, "jump") if canonical is not None else None
    if (opcode == 0xEB and offset + 1 < len(code)) or (0x70 <= opcode <= 0x7F and offset + 1 < len(code)):
        rel = int.from_bytes(code[offset + 1 : offset + 2], "little", signed=True)
        canonical = _resolve_16bit_function_start(code, insn_addr + 2 + rel - linked_base)
        return (linked_base + canonical, 2, "jump") if canonical is not None else None
    return None


def _trace_window_8616(
    code: bytes,
    window_start: int,
    window_end: int,
    linked_base: int,
    disasm: _CapstoneDisasm8616,
) -> tuple[list[tuple[int, int, str]], set[int]]:
    """Return scored candidate events and return sites for one trace window."""
    events: list[tuple[int, int, str]] = []
    returns: set[int] = set()
    align_bytes = {0x00, 0x90, 0xCC}
    offset = max(0, window_start - linked_base)
    stop = min(len(code), window_end - linked_base)
    while offset < stop:
        insn = next(disasm.disasm(code[offset : offset + 16], linked_base + offset, 1), None)
        if insn is None or insn.size <= 0:
            break
        addr = insn.address
        event = _branch_target_event_8616(code, offset, addr, linked_base)
        if event is not None:
            events.append(event)
        if code[offset : offset + 3] == b"\x55\x8b\xec":
            events.append((addr, 3, "jump"))

        offset += insn.size
        if insn.mnemonic.lower() in {"ret", "retf", "iret"}:
            returns.add(addr)
            next_offset = offset
            while next_offset < stop and code[next_offset] in align_bytes:
                next_offset += 1
            if next_offset < stop and _looks_like_16bit_function_prologue(code, next_offset):
                events.append((linked_base + next_offset, 1, "jump"))
    return events, returns


def trace_16bit_seed_candidates(
    project: object,
    code: bytes,
    *,
    linked_base: int,
    windows: list[tuple[int, int]],
) -> FastTraceResult:
    """Find optional 16-bit entry candidates from direct trace evidence.

    Dynamic attribute boundary: project/arch/capstone are third-party angr
    objects. Results are candidates only and must not be treated as proven
    function boundaries without later validation.
    """
    image_end = linked_base + len(code)
    call_targets: set[int] = set()
    jump_targets: set[int] = set()
    returns: set[int] = set()
    scores: dict[int, int] = {}

    def _in_windows(addr: int) -> bool:
        return any(start <= addr < end for start, end in windows)

    def _add(addr: int, weight: int, bucket: set[int]) -> None:
        if not (linked_base <= addr < image_end):
            return
        if not _in_windows(addr):
            return
        bucket.add(addr)
        scores[addr] = scores.get(addr, 0) + weight

    try:
        disasm = getattr(getattr(project, "arch", None), "capstone", None)
    except (AttributeError, TypeError):
        disasm = None
    if disasm is None:
        return FastTraceResult(entries=(), call_targets=(), jump_targets=(), returns=(), scores={})

    for window_start, window_end in windows:
        if window_start >= window_end:
            continue
        events, window_returns = _trace_window_8616(
            code, window_start, window_end, linked_base, disasm,
        )
        for addr, weight, bucket_name in events:
            _add(addr, weight, call_targets if bucket_name == "call" else jump_targets)
        returns.update(window_returns)

    entries = tuple(sorted(scores, key=lambda seed: (-scores[seed], seed)))
    return FastTraceResult(
        entries=entries,
        call_targets=tuple(sorted(call_targets)),
        jump_targets=tuple(sorted(jump_targets)),
        returns=tuple(sorted(returns)),
        scores=scores,
    )
