# cython: language_level=3, infer_types=True
"""Carry immutable byte witnesses for caller boundary reconstruction.

Layer: Frontend.
Responsibility: capture executable block extents and validate them against a
fresh evidence project before rebuilding closed reachability. Function.size
from angr is a sum, never a bound. No project, CFG or SSA object is transported.
Unknown boundaries remain unavailable; malformed or mismatched proofs fail
before downstream consumers can treat them as caller context.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, cast

from .frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    bounded_entry_function_boundary_8616,
)
from .frontend_function_boundary_index import exact_function_range_inventory_8616
import dataclasses
import operator


class _BlockSurface(Protocol):
    """Executable coordinates exposed by a third-party block."""

    addr: cython.longlong
    size: cython.longlong


class _FunctionSurface(Protocol):
    """Third-party caller inventory; aggregate size is intentionally absent."""

    addr: cython.longlong
    blocks: Iterable[_BlockSurface]


class _MemorySurface(Protocol):
    """Loader bytes used to bind a witness to its evidence owner."""

    def load(self, addr: cython.longlong, size: cython.longlong) -> object:
        """Read exactly the requested mapped bytes."""
        ...


class _ImageSurface(Protocol):
    """Inclusive loaded-image address limits."""

    min_addr: cython.longlong
    max_addr: cython.longlong


class _LoaderSurface(Protocol):
    """Required third-party loader surfaces for evidence verification."""

    memory: _MemorySurface
    main_object: _ImageSurface


class _ProjectSurface(Protocol):
    """Fresh project holding the executable image."""

    loader: _LoaderSurface


@dataclasses.dataclass(frozen=True, order=True)
class BoundaryBlockWitness8616:
    """One block extent bound to its loaded executable bytes."""

    addr: cython.longlong
    size: cython.longlong
    digest: object


@dataclasses.dataclass(frozen=True, )
class FunctionBoundaryWitness8616:
    """Canonical caller entry and block witnesses, independent of a project."""

    entry: cython.longlong
    blocks: object

    @property
    def start(self) -> cython.longlong:
        """Return the decoding floor independently of the callable entry."""
        return min(block.addr for block in iter(self.blocks))

    @property
    def end(self) -> cython.longlong:
        """Return the enclosing bound from extents, never summed block sizes."""
        return max(block.addr + block.size for block in iter(self.blocks))

    def validate(self) -> None:
        """Reject malformed identities before reading loader bytes."""
        block: object
        if type(self.entry) is not int or self.entry < 0 or not self.blocks:
            raise ValueError("caller boundary needs a nonnegative entry and blocks")
        if operator.ne(self.blocks, tuple(sorted(tuple(set(self.blocks))))):
            raise ValueError("caller boundary blocks must be canonical and unique")
        if self.entry not in {block.addr for block in iter(self.blocks)}:
            raise ValueError("caller boundary entry must begin a witnessed extent")
        for block in self.blocks:
            if type(block.addr) is not int or type(block.size) is not int or block.size <= 0:
                raise ValueError("caller boundary extent must have integer coordinates and positive size")
            if block.addr < 0:
                raise ValueError("caller boundary contains a negative extent")
            if len(block.digest) != 64 or any(char not in "0123456789abcdef" for char in iter(block.digest)):
                raise ValueError("caller boundary has an invalid byte digest")


@cython.ccall
def _digest(project: object, addr: cython.longlong, size: cython.longlong) -> object:
    """Require mapped owner bytes, including full instruction tails."""
    loader = cast(_ProjectSurface, project).loader
    image = loader.main_object
    if not image.min_addr <= addr < addr + size <= image.max_addr + 1:
        raise ValueError(f"caller boundary extent is unmapped: {addr:#x}+{size:#x}")
    raw = loader.memory.load(addr, size)
    if operator.ne(len(raw), size):
        raise ValueError(f"caller boundary extent is truncated: {addr:#x}")
    return sha256(raw).hexdigest()


@cython.ccall
def _covered(start: cython.longlong, end: cython.longlong, blocks: object) -> cython.bint:
    """Allow decoder block splitting, but never admit bytes in inventory gaps."""
    block: object
    cursor = start
    for block in blocks:
        if block.addr > cursor:
            break
        cursor = max(cursor, block.addr + block.size)
        if cursor >= end:
            return True
    return False


@cython.ccall
def restore_function_boundary_8616(
    project: object, witness: FunctionBoundaryWitness8616,
) -> ExactFunctionRangeBoundary8616 | None:
    """Rebuild closed caller reachability only from matching executable bytes.

    Hash verification precedes the existing immutable-project reachability
    cache. Byte identity is local to witnessed code; unreachable gaps are not
    evidence and must never become reachable through reconstruction.
    """
    boundary: object
    block: object
    raw_block: object
    witness.validate()
    for block in witness.blocks:
        if operator.ne(_digest(project, block.addr, block.size), block.digest):
            raise ValueError(f"caller boundary bytes disagree at {block.addr:#x}")
    if operator.eq(witness.start, witness.entry):
        # Preserve the established immutable-project boundary identity after
        # every byte witness has been revalidated above.
        inventory = exact_function_range_inventory_8616(project, ((witness.entry, witness.end),))
        boundary = inventory.boundaries[0] if len(inventory.boundaries) == 1 else None
    else:
        boundary = bounded_entry_function_boundary_8616(
            project, witness.entry, witness.start, witness.end
        )
    if boundary is None:
        return None
    for raw_block in boundary.blocks:
        decoded = cast(_BlockSurface, raw_block)
        if not _covered(decoded.addr, decoded.addr + decoded.size, witness.blocks):
            return None
    return boundary


def capture_function_boundary_8616(
    project: object, function: object,
) -> FunctionBoundaryWitness8616 | None:
    """Capture and validate existing caller blocks without guessing absent bounds."""
    restored: object
    surface = cast(_FunctionSurface, function)
    try:
        entry = surface.addr
        extents = tuple((block.addr, block.size) for block in iter(surface.blocks))
    except AttributeError:
        return None
    if not extents or type(entry) is not int:
        return None
    if any(type(addr) is not int or type(size) is not int or size <= 0 for addr, size in iter(extents)):
        return None
    try:
        witness = FunctionBoundaryWitness8616(entry, tuple(sorted({
            BoundaryBlockWitness8616(addr, size, _digest(project, addr, size))
            for addr, size in iter(extents)
        })))
        restored = restore_function_boundary_8616(project, witness)
    except (AttributeError, KeyError, ValueError):
        return None
    return witness if restored is not None else None


@cython.ccall
def function_boundary_record_8616(
    project: object, function: object, *,
    required_entry: int | None = None, required_instruction: int | None = None,
) -> object:
    """Encode a proven caller boundary, preserving unknown as an absent witness."""
    boundary: object
    witness: object
    witness = capture_function_boundary_8616(project, function)
    if witness is None:
        return None
    if required_entry is not None and operator.ne(witness.entry, required_entry):
        return None
    if required_instruction is not None:
        boundary = restore_function_boundary_8616(project, witness)
        if boundary is None or required_instruction not in boundary.reachable_instruction_addrs:
            return None
    return {"entry": witness.entry, "blocks": [
        {"addr": block.addr, "size": block.size, "digest": block.digest}
        for block in iter(witness.blocks)
    ]}


@cython.ccall
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
    boundary: object
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"entry", "blocks"}:
        raise ValueError("caller boundary has incompatible fields")
    entry, blocks = value["entry"], value["blocks"]
    if type(entry) is not int or not isinstance(blocks, list):
        raise ValueError("caller boundary has invalid field types")
    witness = FunctionBoundaryWitness8616(entry, tuple(_block_from_record(block) for block in iter(blocks)))
    boundary = restore_function_boundary_8616(project, witness)
    if boundary is None:
        raise ValueError(f"caller boundary reachability is incomplete: {entry:#x}")
    return boundary
