"""Carry immutable byte witnesses for caller boundary reconstruction.

Layer: Frontend.
Responsibility: capture executable block extents and validate them against a
fresh evidence project before rebuilding closed reachability. Function.size
from angr is a sum, never a bound. No project, CFG or SSA object is transported.
Unknown boundaries remain unavailable; malformed or mismatched proofs fail
before downstream consumers can treat them as caller context.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, cast

from .frontend_function_boundary import ExactFunctionRangeBoundary8616
from .frontend_function_boundary_index import exact_function_range_inventory_8616


class _BlockSurface(Protocol):
    """Executable coordinates exposed by a third-party block."""

    addr: int
    size: int


class _FunctionSurface(Protocol):
    """Third-party caller inventory; aggregate size is intentionally absent."""

    addr: int
    blocks: Iterable[_BlockSurface]


class _MemorySurface(Protocol):
    """Loader bytes used to bind a witness to its evidence owner."""

    def load(self, addr: int, size: int) -> bytes:
        """Read exactly the requested mapped bytes."""
        ...


class _ImageSurface(Protocol):
    """Inclusive loaded-image address limits."""

    min_addr: int
    max_addr: int


class _LoaderSurface(Protocol):
    """Required third-party loader surfaces for evidence verification."""

    memory: _MemorySurface
    main_object: _ImageSurface


class _ProjectSurface(Protocol):
    """Fresh project holding the executable image."""

    loader: _LoaderSurface


@dataclass(frozen=True, slots=True, order=True)
class BoundaryBlockWitness8616:
    """One block extent bound to its loaded executable bytes."""

    addr: int
    size: int
    digest: str


@dataclass(frozen=True, slots=True)
class FunctionBoundaryWitness8616:
    """Canonical caller entry and block witnesses, independent of a project."""

    entry: int
    blocks: tuple[BoundaryBlockWitness8616, ...]

    @property
    def end(self) -> int:
        """Return the enclosing bound from extents, never summed block sizes."""
        return max(block.addr + block.size for block in self.blocks)

    def validate(self) -> None:
        """Reject malformed identities before reading loader bytes."""
        if type(self.entry) is not int or self.entry < 0 or not self.blocks:
            raise ValueError("caller boundary needs a nonnegative entry and blocks")
        if self.blocks != tuple(sorted(set(self.blocks))):
            raise ValueError("caller boundary blocks must be canonical and unique")
        if self.entry != self.blocks[0].addr:
            raise ValueError("caller boundary entry must begin its first extent")
        for block in self.blocks:
            if type(block.addr) is not int or type(block.size) is not int or block.size <= 0:
                raise ValueError("caller boundary extent must have integer coordinates and positive size")
            if block.addr < self.entry:
                raise ValueError("caller boundary contains an extent before entry")
            if len(block.digest) != 64 or any(char not in "0123456789abcdef" for char in block.digest):
                raise ValueError("caller boundary has an invalid byte digest")


def _digest(project: object, addr: int, size: int) -> str:
    """Require mapped owner bytes, including full instruction tails."""
    loader = cast(_ProjectSurface, project).loader
    image = loader.main_object
    if not image.min_addr <= addr < addr + size <= image.max_addr + 1:
        raise ValueError(f"caller boundary extent is unmapped: {addr:#x}+{size:#x}")
    raw = loader.memory.load(addr, size)
    if len(raw) != size:
        raise ValueError(f"caller boundary extent is truncated: {addr:#x}")
    return sha256(raw).hexdigest()


def _covered(start: int, end: int, blocks: tuple[BoundaryBlockWitness8616, ...]) -> bool:
    """Allow decoder block splitting, but never admit bytes in inventory gaps."""
    cursor = start
    for block in blocks:
        if block.addr > cursor:
            break
        cursor = max(cursor, block.addr + block.size)
        if cursor >= end:
            return True
    return False


def restore_function_boundary_8616(
    project: object, witness: FunctionBoundaryWitness8616,
) -> ExactFunctionRangeBoundary8616 | None:
    """Rebuild closed caller reachability only from matching executable bytes.

    Hash verification precedes the existing immutable-project reachability
    cache. Byte identity is local to witnessed code; unreachable gaps are not
    evidence and must never become reachable through reconstruction.
    """
    witness.validate()
    for block in witness.blocks:
        if _digest(project, block.addr, block.size) != block.digest:
            raise ValueError(f"caller boundary bytes disagree at {block.addr:#x}")
    inventory = exact_function_range_inventory_8616(project, ((witness.entry, witness.end),))
    if len(inventory.boundaries) != 1:
        return None
    boundary = inventory.boundaries[0]
    for raw_block in boundary.blocks:
        decoded = cast(_BlockSurface, raw_block)
        if not _covered(decoded.addr, decoded.addr + decoded.size, witness.blocks):
            return None
    return boundary


def capture_function_boundary_8616(
    project: object, function: object,
) -> FunctionBoundaryWitness8616 | None:
    """Capture and validate existing caller blocks without guessing absent bounds."""
    surface = cast(_FunctionSurface, function)
    try:
        entry = surface.addr
        extents = tuple((block.addr, block.size) for block in surface.blocks)
    except AttributeError:
        return None
    if not extents or type(entry) is not int:
        return None
    if any(type(addr) is not int or type(size) is not int or size <= 0 for addr, size in extents):
        return None
    try:
        witness = FunctionBoundaryWitness8616(entry, tuple(sorted({
            BoundaryBlockWitness8616(addr, size, _digest(project, addr, size))
            for addr, size in extents
        })))
        restored = restore_function_boundary_8616(project, witness)
    except (AttributeError, KeyError, ValueError):
        return None
    return witness if restored is not None else None


def function_boundary_record_8616(
    project: object, function: object, *,
    required_entry: int | None = None, required_instruction: int | None = None,
) -> dict[str, object] | None:
    """Encode a proven caller boundary, preserving unknown as an absent witness."""
    witness = capture_function_boundary_8616(project, function)
    if witness is None:
        return None
    if required_entry is not None and witness.entry != required_entry:
        return None
    if required_instruction is not None:
        boundary = restore_function_boundary_8616(project, witness)
        if boundary is None or required_instruction not in boundary.reachable_instruction_addrs:
            return None
    return {"entry": witness.entry, "blocks": [
        {"addr": block.addr, "size": block.size, "digest": block.digest}
        for block in witness.blocks
    ]}


def _block_from_record(value: object) -> BoundaryBlockWitness8616:
    """Validate JSON primitives before constructing a typed block witness."""
    if not isinstance(value, dict) or set(value) != {"addr", "size", "digest"}:
        raise ValueError("caller boundary block has incompatible fields")
    addr, size, digest = value["addr"], value["size"], value["digest"]
    if type(addr) is not int or type(size) is not int or not isinstance(digest, str):
        raise ValueError("caller boundary block has invalid field types")
    return BoundaryBlockWitness8616(addr, size, digest)


def function_boundary_from_record_8616(
    project: object, value: object,
) -> ExactFunctionRangeBoundary8616 | None:
    """Rebind a serialized witness only after byte and reachability verification."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"entry", "blocks"}:
        raise ValueError("caller boundary has incompatible fields")
    entry, blocks = value["entry"], value["blocks"]
    if type(entry) is not int or not isinstance(blocks, list):
        raise ValueError("caller boundary has invalid field types")
    witness = FunctionBoundaryWitness8616(entry, tuple(_block_from_record(block) for block in blocks))
    boundary = restore_function_boundary_8616(project, witness)
    if boundary is None:
        raise ValueError(f"caller boundary reachability is incomplete: {entry:#x}")
    return boundary
