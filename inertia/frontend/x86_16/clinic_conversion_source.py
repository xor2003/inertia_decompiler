"""Authenticate the native context consumed by one Clinic conversion.

Layer: Frontend/runtime.
Responsibility: retain exact block partitions, control edges and execution
VEX snapshots, then check their mapped bytes and identity before consuming
a function-entry proof. No target is inferred or changed here.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from .clinic_scoped_control import ClinicScopedPartition8616

import pyvex
from angr import ailment


class _Node(Protocol):
    """Native graph node coordinates at the angr boundary."""

    addr: int
    size: int


class _Graph(Protocol):
    """Control graph surface used by the native importer and Clinic."""

    def nodes(self) -> Iterable[object]:
        """Enumerate graph nodes."""
        ...

    def edges(self) -> Iterable[tuple[object, object]]:
        """Enumerate directed control edges."""
        ...


class _Function(Protocol):
    """Recovered native function identity and graph."""

    graph: _Graph


class _Memory(Protocol):
    """Mapped executable bytes, independently of cached block objects."""

    def load(self, addr: int, size: int) -> bytes:
        """Read the exact mapped byte extent."""
        ...


class _Loader(Protocol):
    """CLE loader memory boundary."""

    memory: _Memory


class _Project(Protocol):
    """Native project source authority."""

    loader: _Loader


class _Clinic(Protocol):
    """Third-party Clinic state consumed before SSA."""

    project: _Project
    function: _Function
    _func_graph: _Graph
    _blocks_by_addr_and_size: Mapping[tuple[int, int], object]


@dataclass(frozen=True, slots=True)
class ClinicControlSurface8616:
    """Immutable partition and successor coordinates for one control graph."""

    nodes: tuple[tuple[int, int], ...]
    edges: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class ClinicConversionContext8616:
    """The exact native function and graph being converted this time."""

    project: object = field(compare=False)
    function: object = field(compare=False)
    graph: ClinicControlSurface8616


@dataclass(frozen=True, slots=True)
class ClinicVexSnapshot8616:
    """Private deep execution snapshot with explicit temporary widths."""

    vex: pyvex.IRSB = field(compare=False)
    types: tuple[str, ...]

    def matches(self, vex: object) -> bool:
        """Reject replacement, mutation or a changed temporary type domain."""
        return (
            isinstance(vex, pyvex.IRSB)
            and self.vex == vex
            and self.types == tuple(vex.tyenv.types)
        )


def _semantic_ail_statements(block: ailment.Block, ip_offset: int) -> tuple[ailment.Stmt.Statement, ...]:
    """Exclude only the constant-PC assignments Clinic itself removes."""
    return tuple(
        stmt for stmt in block.statements
        if not (
            isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.dst, ailment.Expr.Register)
            and stmt.dst.reg_offset == ip_offset
            and isinstance(stmt.src, ailment.Expr.Const)
        )
    )


@dataclass(frozen=True, slots=True)
class ClinicAilSnapshot8616:
    """Frozen converted effects used to bind the native function theorem."""

    statements: tuple[ailment.Stmt.Statement, ...] = field(compare=False)
    indices: tuple[int | None, ...]
    ip_offset: int

    def matches(self, block: object) -> bool:
        """Reject in-place changes to earlier converted register effects."""
        if not isinstance(block, ailment.Block):
            return False
        current = _semantic_ail_statements(block, self.ip_offset)
        if len(current) != len(self.statements):
            return False
        # Rust AIL equality compares allocations; likes compares typed effects.
        # Instruction coordinates are additionally bound, independent of likes.
        return all(
            saved.likes(actual)
            and index == actual.idx
            and saved.tags.get("ins_addr") == actual.tags.get("ins_addr")
            for saved, index, actual in zip(self.statements, self.indices, current, strict=True)
        )


def snapshot_clinic_ail_8616(block: ailment.Block, ip_offset: int) -> ClinicAilSnapshot8616:
    """Freeze converted effects while retaining Clinic's known PC cleanup."""
    statements = _semantic_ail_statements(block, ip_offset)
    # Rust AIL deepcopy allocates fresh statement indices. Bind the original
    # coordinates separately from the copied semantic effects.
    return ClinicAilSnapshot8616(deepcopy(statements), tuple(stmt.idx for stmt in statements), ip_offset)


def snapshot_clinic_vex_8616(vex: pyvex.IRSB) -> ClinicVexSnapshot8616:
    """Freeze execution fields without rendered text or target inference."""
    return ClinicVexSnapshot8616(deepcopy(vex), tuple(vex.tyenv.types))


def _graph_surface(graph: _Graph) -> ClinicControlSurface8616:
    """Capture only coordinates consumed by the native control proof."""
    nodes = tuple(sorted((cast(_Node, n).addr, cast(_Node, n).size) for n in graph.nodes()))
    edges = tuple(sorted((cast(_Node, a).addr, cast(_Node, b).addr) for a, b in graph.edges()))
    return ClinicControlSurface8616(nodes, edges)


def snapshot_clinic_context_8616(clinic: object) -> ClinicConversionContext8616:
    """Bind one conversion to its recovered function and Clinic graph."""
    boundary = cast(_Clinic, clinic)
    return ClinicConversionContext8616(boundary.project, boundary.function, _graph_surface(boundary._func_graph))


def clinic_context_is_current_8616(
    clinic: object, context: ClinicConversionContext8616,
    *, scoped_partition: ClinicScopedPartition8616 | None = None,
) -> bool:
    """Require identical context and native/converted successor relations."""
    boundary = cast(_Clinic, clinic)
    if scoped_partition is not None:
        from .clinic_scoped_control import ClinicScopedPartition8616
        if type(scoped_partition) is not ClinicScopedPartition8616:
            return False
        return scoped_partition.authenticates(clinic, context)
    return (
        boundary.project is context.project
        and boundary.function is context.function
        and _graph_surface(boundary._func_graph) == context.graph
        and _graph_surface(boundary.function.graph) == context.graph
    )


def clinic_source_bytes_8616(clinic: object, addr: int, size: int) -> bytes:
    """Read live mapped bytes, bypassing cached block byte projections."""
    return bytes(cast(_Clinic, clinic).project.loader.memory.load(addr, size))


def clinic_converted_object_8616(clinic: object, addr: int, size: int) -> object | None:
    """Find the exact converted object that subsequent SSA will consume."""
    return cast(_Clinic, clinic)._blocks_by_addr_and_size.get((addr, size))
