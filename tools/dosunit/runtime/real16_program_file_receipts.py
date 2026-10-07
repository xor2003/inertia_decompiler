"""Declared file-cursor evidence for initialized DOS program execution.

Layer: dosunit concrete execution contracts.
Responsibility: retain checked successful read/seek transitions and require
complete final cursor accounting separately from output stream chunking.
Receipts establish execution evidence only, never symbolic equivalence.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit.runtime.real16_program_input import INPUT_HANDLE_MAX, INPUT_HANDLE_MIN, MAX_INPUT_FILES, U32_MAX


class FileOperation(StrEnum):
    """Successful operation on one explicitly declared regular-file handle."""

    READ = "read"
    SEEK = "seek"


def _integer(value: int, minimum: int, maximum: int) -> bool:
    """Check a bounded exact integer without accepting bool or float aliases."""
    return type(value) is int and minimum <= value <= maximum


@dataclass(frozen=True, slots=True)
class FileReceipt:
    """One executed successful cursor transition with actual returned bytes."""

    operation: FileOperation
    handle: int
    before: int
    after: int
    payload: bytes = b""

    def __post_init__(self) -> None:
        """Bind successful read lengths and seek payload absence to the state."""
        if not isinstance(self.operation, FileOperation):
            raise ValueError("file receipt requires a typed operation")
        if not _integer(self.handle, INPUT_HANDLE_MIN, INPUT_HANDLE_MAX):
            raise ValueError("file receipt requires a declared regular-file handle")
        if not _integer(self.before, 0, U32_MAX) or not _integer(self.after, 0, U32_MAX):
            raise ValueError("file cursor must be an exact unsigned 32-bit integer")
        if not isinstance(self.payload, bytes):
            raise ValueError("file receipt payload must be immutable bytes")
        if self.operation is FileOperation.READ:
            if len(self.payload) > 0xFFFF or self.after != self.before + len(self.payload):
                raise ValueError("read cursor transition must match returned byte count")
        elif self.payload:
            raise ValueError("seek receipt cannot contain returned file bytes")


type FilePositions = tuple[tuple[int, int], ...]


def _positions_valid(positions: FilePositions) -> bool:
    """Require a bounded deterministic unique handle/cursor denominator."""
    if not isinstance(positions, tuple) or len(positions) > MAX_INPUT_FILES:
        return False
    previous = INPUT_HANDLE_MIN - 1
    for pair in positions:
        if not isinstance(pair, tuple) or len(pair) != 2:
            return False
        handle, cursor = pair
        if not _integer(handle, INPUT_HANDLE_MIN, INPUT_HANDLE_MAX) or handle <= previous:
            return False
        if not _integer(cursor, 0, U32_MAX):
            return False
        previous = handle
    return True


def file_state_complete(
    initial: FilePositions, final: FilePositions, receipts: tuple[FileReceipt, ...],
) -> bool:
    """Verify every declared handle's complete chronological cursor projection.

    No read-call chunk boundary is itself observable. Final cursors remain
    observable under this explicit file environment; missing, duplicated,
    foreign or discontinuous transitions cannot yield execution agreement.
    """
    if not _positions_valid(initial) or not _positions_valid(final):
        return False
    if tuple(handle for handle, _ in initial) != tuple(handle for handle, _ in final):
        return False
    if not isinstance(receipts, tuple):
        return False
    positions = dict(initial)
    for receipt in receipts:
        if not isinstance(receipt, FileReceipt):
            return False
        if receipt.handle not in positions or positions[receipt.handle] != receipt.before:
            return False
        positions[receipt.handle] = receipt.after
    return tuple(sorted(positions.items())) == final
