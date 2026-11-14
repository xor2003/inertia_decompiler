# cython: language_level=3, infer_types=True
"""Build exact function boundaries from bounded binary reachability.

Layer: Frontend.
Responsibility: turn a proven executable range and entry into one immutable
function boundary whose blocks and instructions come from the closed Frontend
reachability census. This module does not infer signatures, types, aliases, or
structured control flow.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
from typing import Protocol, cast

from .frontend_capstone_block import DirectCapstoneBlock8616
from .frontend_instruction_reachability import (
    ConditionalIndirectEdge8616,
    collect_instruction_reachability_8616,
)
from .frontend_near_return_continuation import (
    NearCallFramePremise8616,
    NearReturnContinuationArtifact8616,
    prove_near_return_continuations_8616,
)
import dataclasses
import operator

__all__ = [
    "ExactFunctionRangeBoundary8616",
    "bounded_entry_function_boundary_8616",
    "exact_function_range_boundary_8616",
    "mapped_entry_function_boundary_8616",
]


@dataclasses.dataclass(frozen=True, )
class ExactFunctionRangeBoundary8616:
    """One binary-framed inventory; conditional edges retain IR proof obligations.

    ``conditional_edges`` authorizes decoding only. Raw IR must retain their
    pending markers until an invocation-bound semantic owner discharges them.
    """

    project: object = field(compare=False, repr=False)
    addr: cython.longlong
    size: cython.longlong
    block_addrs_set: object
    reachable_instruction_addrs: object
    successor_edges: object
    blocks: object = field(default=(), compare=False, repr=False)
    info: object = field(default_factory=dict, compare=False, repr=False)
    near_return_continuations: NearReturnContinuationArtifact8616 | None = field(
        default=None, compare=False, repr=False
    )

    decode_lower_bound: int | None = None
    conditional_edges: tuple[ConditionalIndirectEdge8616, ...] = ()

    @property
    def decode_start(self) -> cython.longlong:
        """Return the independently supplied lower decoding bound."""
        return self.addr if self.decode_lower_bound is None else self.decode_lower_bound

    @property
    def decode_end(self) -> cython.longlong:
        """Return the exclusive upper decoding bound, independent of entry."""
        return self.addr + self.size

    @property
    def predecessors_by_block(self) -> dict[cython.longlong, frozenset[cython.longlong]]:
        """Project the closed Frontend edge census as predecessor identities."""
        return {
            block_addr: frozenset(
                source for source, target in iter(self.successor_edges) if target == block_addr
            )
            for block_addr in iter(self.block_addrs_set)
        }


@cython.ccall
def exact_function_range_boundary_8616(
    project: object,
    start: cython.longlong,
    end: cython.longlong,
    *,
    premise: NearCallFramePremise8616 | None = None,
) -> ExactFunctionRangeBoundary8616 | None:
    """Materialize a range only when every reachable block is classified.

    ``premise`` is the independently supplied source-bound entry-frame
    premise: a proven near-CALL row binds ``SS:[SP]`` to its return word
    for this exact head, so an indirect terminal that demonstrably
    transfers to that word is a closed return edge. The proof runs over
    the already-decoded census — never bytes, names, or helpers — and
    only a fully proven candidate discharges its unresolved terminal;
    every unproven terminal keeps reachability incomplete. The
    premise-derived artifact rides the returned boundary so IR import
    and the scoped continuation view can re-authenticate the identical
    provenance without re-deriving it.
    """
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        return None
    return _bounded_entry_function_boundary_8616(project, start, start, end, premise)


@cython.ccall
def bounded_entry_function_boundary_8616(
    project: object,
    entry: cython.longlong,
    decode_start: cython.longlong,
    decode_end: cython.longlong,
) -> ExactFunctionRangeBoundary8616 | None:
    """Close an independent entry inside supplied executable decoding bounds.

    A caller supplies authority for the entry and bounds, such as verified
    block-byte witnesses. Only complete native reachability becomes a boundary;
    this route carries no invocation premise or conditional return authority.
    Consumers remain responsible for checking that decoded extents belong to
    their supplied witness rather than merely its enclosing interval.
    """
    if (
        type(entry) is not int
        or type(decode_start) is not int
        or type(decode_end) is not int
        or not 0 <= decode_start <= entry < decode_end
    ):
        return None
    return _bounded_entry_function_boundary_8616(
        project, entry, decode_start, decode_end, None
    )


@cython.ccall
def _bounded_entry_function_boundary_8616(
    project: object,
    entry: cython.longlong,
    lower: cython.longlong,
    end: cython.longlong,
    premise: NearCallFramePremise8616 | None,
    conditional_edges: object = (),
) -> ExactFunctionRangeBoundary8616 | None:
    """Close the entry census within independently supplied decoding bounds.

    Entry identity remains distinct from the mapped image's decoding floor.
    Exact-range callers supply their start for both coordinates; mapped callers
    permit backward direct edges while retaining every unresolved obligation.
    """
    reachability = collect_instruction_reachability_8616(
        project,
        entry=entry,
        region_start=lower,
        region_end=end,
        conditional_edges=conditional_edges,
    )
    continuations: NearReturnContinuationArtifact8616 | None = None
    if not reachability.inventory_complete and reachability.blocks:
        continuations = prove_near_return_continuations_8616(
            reachability.blocks,
            reachability.successor_edges,
            entry=entry,
            premise=premise,
        )
        if continuations.proven_block_addrs:
            reachability = collect_instruction_reachability_8616(
                project,
                entry=entry,
                region_start=lower,
                region_end=end,
                proven_return_block_addrs=continuations.proven_block_addrs,
                conditional_edges=conditional_edges,
            )
    if not reachability.inventory_complete or not reachability.reachable_block_addrs:
        return None
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=entry,
        size=end - entry,
        block_addrs_set=frozenset(reachability.reachable_block_addrs),
        reachable_instruction_addrs=frozenset(reachability.reachable_instruction_addrs),
        successor_edges=reachability.successor_edges,
        blocks=reachability.blocks,
        near_return_continuations=continuations,
        decode_lower_bound=lower,
        conditional_edges=conditional_edges,
    )


class _MappedImage8616(Protocol):
    """Third-party loaded-object bounds, inclusive at the upper endpoint."""

    min_addr: cython.longlong
    max_addr: cython.longlong


class _MappedMemory8616(Protocol):
    """Live loader bytes required to authenticate a native boundary census."""

    def load(self, address: cython.longlong, size: cython.longlong) -> object:
        """Read the requested mapped span or raise KeyError for a missing span."""
        ...


class _MappedLoader8616(Protocol):
    """Third-party object lookup for an independently proved entry address."""

    memory: _MappedMemory8616

    def find_object_containing(self, address: cython.longlong) -> object | None:
        """Return the loaded image owning this coordinate."""
        ...


class _MappedProject8616(Protocol):
    """Minimal loader boundary; reachability stays with its existing owner."""

    loader: _MappedLoader8616


@cython.ccall
def _mapped_native_bytes_current_8616(
    project: object, blocks: object,
) -> cython.bint:
    """Reject stale decoded-block inventory entries using current loader bytes."""
    block: object
    memory = cast(_MappedProject8616, project).loader.memory
    for block in blocks:
        try:
            current = bytes(memory.load(block.addr, block.size))
        except KeyError:
            return False
        if operator.ne(len(current), block.size) or operator.ne(current, block.code):
            return False
    return True


@cython.ccall
def _mapped_native_blocks_8616(
    boundary: ExactFunctionRangeBoundary8616,
) -> object:
    """Select exact owned native blocks; foreign backend surfaces keep their range."""
    block: object
    blocks: list[DirectCapstoneBlock8616] = []
    for block in boundary.blocks:
        if type(block) is not DirectCapstoneBlock8616:
            return None
        blocks.append(block)
    return tuple(blocks) if blocks else None


def _tight_mapped_boundary_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616, lower: cython.longlong,
    premise: NearCallFramePremise8616 | None,
    conditional_edges: object,
) -> ExactFunctionRangeBoundary8616 | None:
    """Reprove closure at the discovered instruction extent, retaining backward reach.

    Image padding only bounds discovery. A second native census must establish
    the tighter boundary independently; the first census is not trimmed or
    republished. Changed bytes, open paths and failed conditional premises may
    therefore refuse instead of inheriting the discovery's completeness.
    """
    blocks: object
    current_blocks: object
    refined: object
    blocks = _mapped_native_blocks_8616(boundary)
    if blocks is None:
        return boundary
    end = max(block.addr + block.size for block in iter(blocks))
    if not boundary.addr < end <= boundary.addr + boundary.size:
        return None
    refined = boundary
    if operator.ne(end, boundary.addr + boundary.size):
        refined = _bounded_entry_function_boundary_8616(
            project, boundary.addr, lower, end, premise, conditional_edges,
        )
    if refined is None:
        return None
    current_blocks = _mapped_native_blocks_8616(refined)
    if current_blocks is None or not _mapped_native_bytes_current_8616(project, current_blocks):
        return None
    return refined


@cython.ccall
def mapped_entry_function_boundary_8616(
    project: object,
    entry: cython.longlong,
    *,
    premise: NearCallFramePremise8616 | None = None,
    conditional_edges: object = (),
) -> ExactFunctionRangeBoundary8616 | None:
    """Close reachable binary instructions without optional function catalogs.

    The caller must independently prove this entry, for example from a mapped
    direct CALL. The image's inclusive upper bound limits decoding; it does not
    declare the whole image to be the function. Only closed entry reachability
    becomes the boundary. Backward targets inside the mapped image are decoded;
    open paths and targets outside that image still refuse.
    ``premise`` is the caller's independently proven source-bound
    entry-frame premise; it is forwarded verbatim and never invented here.
    ``conditional_edges`` supplies decoding assumptions, never unconditional
    control evidence. They remain on the boundary for pending raw IR import.
    When discovery leaves an unused image suffix, independently reprove the
    boundary at the decoded block extent while retaining the image lower bound.
    """
    discovered: object
    image: object
    if type(entry) is not int or entry < 0:
        return None
    try:
        image = cast(_MappedProject8616, project).loader.find_object_containing(entry)
        if image is None:
            return None
        mapped = cast(_MappedImage8616, image)
        lower, upper = mapped.min_addr, mapped.max_addr
    except (AttributeError, KeyError):
        return None
    if type(lower) is not int or type(upper) is not int or not lower <= entry <= upper:
        return None
    discovered = _bounded_entry_function_boundary_8616(
        project, entry, lower, upper + 1, premise, conditional_edges
    )
    if discovered is None:
        return None
    return _tight_mapped_boundary_8616(project, discovered, lower, premise, conditional_edges)
