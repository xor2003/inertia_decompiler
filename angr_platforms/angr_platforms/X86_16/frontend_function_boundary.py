"""Build exact function boundaries from bounded binary reachability.

Layer: Frontend.
Responsibility: turn a proven executable range and entry into one immutable
function boundary whose blocks and instructions come from the closed Frontend
reachability census. This module does not infer signatures, types, aliases, or
structured control flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, cast

from .frontend_instruction_reachability import collect_instruction_reachability_8616

__all__ = [
    "ExactFunctionRangeBoundary8616",
    "exact_function_range_boundary_8616",
    "mapped_entry_function_boundary_8616",
]


@dataclass(frozen=True, slots=True)
class ExactFunctionRangeBoundary8616:
    """One closed binary-framed function boundary for IR import."""

    project: object = field(compare=False, repr=False)
    addr: int
    size: int
    block_addrs_set: frozenset[int]
    reachable_instruction_addrs: frozenset[int]
    successor_edges: tuple[tuple[int, int], ...]
    blocks: tuple[object, ...] = field(default=(), compare=False, repr=False)
    info: dict[str, object] = field(default_factory=dict, compare=False, repr=False)

    @property
    def predecessors_by_block(self) -> dict[int, frozenset[int]]:
        """Project the closed Frontend edge census as predecessor identities."""
        return {
            block_addr: frozenset(
                source for source, target in self.successor_edges if target == block_addr
            )
            for block_addr in self.block_addrs_set
        }


def exact_function_range_boundary_8616(
    project: object,
    start: int,
    end: int,
) -> ExactFunctionRangeBoundary8616 | None:
    """Materialize a range only when every reachable block is classified."""
    if not isinstance(start, int) or not isinstance(end, int) or end <= start:
        return None
    reachability = collect_instruction_reachability_8616(
        project,
        entry=start,
        region_start=start,
        region_end=end,
    )
    if not reachability.complete or not reachability.reachable_block_addrs:
        return None
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=start,
        size=end - start,
        block_addrs_set=frozenset(reachability.reachable_block_addrs),
        reachable_instruction_addrs=frozenset(reachability.reachable_instruction_addrs),
        successor_edges=reachability.successor_edges,
        blocks=reachability.blocks,
    )


class _MappedImage8616(Protocol):
    """Third-party loaded-object bounds, inclusive at the upper endpoint."""

    min_addr: int
    max_addr: int


class _MappedLoader8616(Protocol):
    """Third-party object lookup for an independently proved entry address."""

    def find_object_containing(self, address: int) -> object | None:
        """Return the loaded image owning this coordinate."""
        ...


class _MappedProject8616(Protocol):
    """Minimal loader boundary; reachability stays with its existing owner."""

    loader: _MappedLoader8616


def mapped_entry_function_boundary_8616(project: object, entry: int) -> ExactFunctionRangeBoundary8616 | None:
    """Close reachable binary instructions without optional function catalogs.

    The caller must independently prove this entry, for example from a mapped
    direct CALL. The image's inclusive upper bound limits decoding; it does not
    declare the whole image to be the function. Only closed entry reachability
    becomes the boundary. Open paths and targets before entry still refuse.
    """
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
    return exact_function_range_boundary_8616(project, entry, upper + 1)
