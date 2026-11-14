# cython: language_level=3, infer_types=True
"""Authenticate the native context consumed by one Clinic conversion.

Layer: Frontend/runtime.
Responsibility: retain exact block partitions, control edges and execution
VEX snapshots, then check their mapped bytes and identity before consuming
a function-entry proof. No target is inferred or changed here.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Mapping
from copy import deepcopy
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, cast
import dataclasses
import operator
import builtins
ClinicScopedPartition8616 = typing.TypeVar("ClinicScopedPartition8616")

if TYPE_CHECKING:
    from .clinic_scoped_control import ClinicScopedPartition8616

import pyvex
from angr import ailment


class _Node(Protocol):
    """Native graph node coordinates at the angr boundary."""

    addr: cython.longlong
    size: cython.longlong


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

    def load(self, addr: cython.longlong, size: cython.longlong) -> object:
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
    _blocks_by_addr_and_size: Mapping[tuple[cython.longlong, cython.longlong], object]


@dataclasses.dataclass(frozen=True, )
class ClinicControlSurface8616:
    """Immutable partition and successor coordinates for one control graph."""

    nodes: object
    edges: object


@dataclasses.dataclass(frozen=True, )
class ClinicConversionContext8616:
    """The exact native function and graph being converted this time."""

    project: object = field(compare=False)
    function: object = field(compare=False)
    graph: ClinicControlSurface8616


@dataclasses.dataclass(frozen=True, )
class ClinicVexSnapshot8616:
    """Private deep execution snapshot with explicit temporary widths."""

    vex: pyvex.IRSB = field(compare=False)
    types: object

    def matches(self, vex: object) -> cython.bint:
        """Reject replacement, mutation or a changed temporary type domain."""
        return (
            isinstance(vex, pyvex.IRSB)
            and operator.eq(self.vex, vex)
            and operator.eq(self.types, tuple(vex.tyenv.types))
        )


def _semantic_ail_statements(block: ailment.Block, ip_offset: cython.longlong) -> tuple[ailment.Stmt.Statement, ...]:
    """Exclude only the constant-PC assignments Clinic itself removes."""
    return tuple(
        stmt for stmt in iter(block.statements)
        if not (
            isinstance(stmt, ailment.Stmt.Assignment)
            and isinstance(stmt.dst, ailment.Expr.Register)
            and operator.eq(stmt.dst.reg_offset, ip_offset)
            and isinstance(stmt.src, ailment.Expr.Const)
        )
    )


@dataclasses.dataclass(frozen=True, )
class ClinicAilSnapshot8616:
    """Frozen converted effects used to bind the native function theorem."""

    statements: object = field(compare=False)
    indices: object
    ip_offset: cython.longlong

    def matches(self, block: object) -> cython.bint:
        """Reject in-place changes to earlier converted register effects."""
        if not isinstance(block, ailment.Block):
            return False
        current = _semantic_ail_statements(block, self.ip_offset)
        if operator.ne(len(current), len(self.statements)):
            return False
        # Rust AIL equality compares allocations; likes compares typed effects.
        # Instruction coordinates are additionally bound, independent of likes.
        return all(
            saved.likes(actual)
            and operator.eq(index, actual.idx)
            and operator.eq(saved.tags.get("ins_addr"), actual.tags.get("ins_addr"))
            for saved, index, actual in builtins.iter(zip(self.statements, self.indices, current, strict=True))
        )


def snapshot_clinic_ail_8616(block: ailment.Block, ip_offset: cython.longlong) -> ClinicAilSnapshot8616:
    """Freeze converted effects while retaining Clinic's known PC cleanup."""
    statements = _semantic_ail_statements(block, ip_offset)
    # Rust AIL deepcopy allocates fresh statement indices. Bind the original
    # coordinates separately from the copied semantic effects.
    return ClinicAilSnapshot8616(deepcopy(statements), tuple(stmt.idx for stmt in iter(statements)), ip_offset)


@cython.ccall
def snapshot_clinic_vex_8616(vex: pyvex.IRSB) -> ClinicVexSnapshot8616:
    """Freeze execution fields without rendered text or target inference."""
    return ClinicVexSnapshot8616(deepcopy(vex), tuple(vex.tyenv.types))


def _graph_surface(graph: _Graph) -> ClinicControlSurface8616:
    """Capture only coordinates consumed by the native control proof."""
    nodes = tuple(sorted((cast(_Node, n).addr, cast(_Node, n).size) for n in builtins.iter(graph.nodes())))
    edges = tuple(sorted((cast(_Node, a).addr, cast(_Node, b).addr) for a, b in builtins.iter(graph.edges())))
    return ClinicControlSurface8616(nodes, edges)


@cython.ccall
def snapshot_clinic_context_8616(clinic: object) -> ClinicConversionContext8616:
    """Bind one conversion to its recovered function and Clinic graph."""
    boundary = cast(_Clinic, clinic)
    return ClinicConversionContext8616(boundary.project, boundary.function, _graph_surface(boundary._func_graph))


@cython.ccall
def clinic_context_is_current_8616(
    clinic: object, context: ClinicConversionContext8616,
    *, scoped_partition: ClinicScopedPartition8616 | None = None,
) -> cython.bint:
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
        and operator.eq(_graph_surface(boundary._func_graph), context.graph)
        and operator.eq(_graph_surface(boundary.function.graph), context.graph)
    )


@cython.ccall
def clinic_source_bytes_8616(clinic: object, addr: cython.longlong, size: cython.longlong) -> bytes:
    """Read live mapped bytes, bypassing cached block byte projections."""
    return bytes(cast(_Clinic, clinic).project.loader.memory.load(addr, size))


@cython.ccall
def clinic_converted_object_8616(clinic: object, addr: cython.longlong, size: cython.longlong) -> object | None:
    """Find the exact converted object that subsequent SSA will consume."""
    return cast(_Clinic, clinic)._blocks_by_addr_and_size.get((addr, size))
