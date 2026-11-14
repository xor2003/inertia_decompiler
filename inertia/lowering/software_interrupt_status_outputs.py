# cython: language_level=3, infer_types=True
"""Materialize status-register outputs of DOS software interrupts.

Layer: Types/Lowering.
Responsibility: project an exact DOS interrupt call followed by a physical
FLAGS-carrier read into an explicit runtime status-output assignment.
Consumes typed call identity and structured register storage. It does not
infer branch meaning from rendered C or assembly text.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from inertia.frontend.x86_16.interrupt_contract import interrupt_core_addr_8616
from inertia.lowering.c_ast_utils import (
    _clone_c_ast_tree_8616,
    _iter_c_nodes_deep_8616,
    _replace_c_children_8616,
)
from inertia.pipeline.errors import PipelineHardError
import dataclasses
import operator
import builtins

__all__ = [
    "SoftwareInterruptStatusOutputStats8616",
    "materialize_software_interrupt_status_outputs_8616",
]


@dataclasses.dataclass(frozen=True, )
class SoftwareInterruptStatusOutputStats8616:
    """Closed evidence counters for interrupt status-output Lowering."""

    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0
    failure_count: cython.longlong = 0


class _CodegenSurface8616(Protocol):
    """Owned fields needed from the dynamic structured-codegen boundary."""

    cfunc: _CFunctionSurface8616
    project: _ProjectRegisterSurface8616
    _inertia_software_interrupt_status_output_stats_8616: SoftwareInterruptStatusOutputStats8616


class _CFunctionSurface8616(Protocol):
    """Structured function root consumed by status-output Lowering."""

    statements: object


class _ArchRegisterSurface8616(Protocol):
    """Third-party architecture register map consumed at the typed boundary."""

    registers: Mapping[str, tuple[cython.longlong, cython.longlong]]


class _ProjectRegisterSurface8616(Protocol):
    """Project architecture surface consumed by status-output Lowering."""

    arch: _ArchRegisterSurface8616


class _TaggedNode8616(Protocol):
    """Third-party structured node tag boundary."""

    tags: object


class _CalleeIdentity8616(Protocol):
    """Third-party callee identity boundary."""

    name: object
    addr: object


@cython.ccall
def _instruction_address_8616(node: object) -> int | None:
    """Return one exact instruction tag from a structured node."""
    address: object
    try:
        tags = cast(_TaggedNode8616, node).tags
    except AttributeError:
        return None
    if not isinstance(tags, dict):
        return None
    address = tags.get("ins_addr")
    return address if isinstance(address, int) else None


@cython.ccall
def _is_dos_int21_call_8616(node: object) -> cython.bint:
    """Recognize the frontend-owned DOS interrupt helper identity."""
    callee: object
    if not isinstance(node, structured_c.CFunctionCall):
        return False
    target_addr = interrupt_core_addr_8616(0x21)
    if isinstance(node.callee_target, structured_c.CConstant):
        value = node.callee_target.value
        return isinstance(value, int) and value == target_addr
    if isinstance(node.callee_target, (str, int)) and node.callee_target in {
        "dos_int21",
        "interrupt_int21",
        target_addr,
    }:
        return True
    callee = node.callee_func
    if callee is None:
        return False
    boundary = cast(_CalleeIdentity8616, callee)
    try:
        name = boundary.name
    except AttributeError:
        name = None
    try:
        address = boundary.addr
    except AttributeError:
        address = None
    return name in {"dos_int21", "interrupt_int21"} or address == target_addr


@cython.ccall
def _interrupt_call_identity_8616(call: structured_c.CFunctionCall) -> int | None:
    """Return exact callsite tag or stable synthetic interrupt target identity."""
    address: object
    address = _instruction_address_8616(call)
    if address is not None:
        return address
    target = call.callee_target
    if isinstance(target, structured_c.CConstant) and isinstance(target.value, int):
        return target.value
    if isinstance(target, int):
        return target
    return None


def _interrupt_callsite_address_8616(
    statement: object,
    call: structured_c.CFunctionCall,
) -> int | None:
    """Return the nearest tagged owner of one exact interrupt call occurrence."""
    candidate: object
    owners: list[tuple[cython.longlong, cython.longlong]] = []
    for candidate in _iter_c_nodes_deep_8616(statement):
        address = _instruction_address_8616(candidate)
        if not isinstance(address, int):
            continue
        descendants = tuple(_iter_c_nodes_deep_8616(candidate))
        if any(descendant is call for descendant in iter(descendants)):
            owners.append((len(descendants), address))
    if owners:
        return min(owners)[1]
    return _interrupt_call_identity_8616(call)


@cython.ccall
def _is_status_accessor_call_8616(node: object) -> cython.bint:
    """Return whether a node is the owned status-output accessor."""
    return isinstance(node, structured_c.CFunctionCall) and node.callee_target == "dos_int21_flags"


@cython.ccall
def _physical_register_offset_8616(node: object) -> int | None:
    """Return exact physical register offset from either angr carrier form."""
    candidate: object
    if isinstance(node, structured_c.CVariable):
        for candidate in (node.unified_variable, node.variable):
            if isinstance(candidate, SimRegisterVariable) and isinstance(candidate.reg, int):
                return candidate.reg
        return None
    if isinstance(node, structured_c.CDirtyExpression):
        try:
            # Dynamic angr boundary: a dirty payload may be any AIL expression,
            # not only a VirtualVariable carrying physical register identity.
            offset = node.dirty.oident
        except AttributeError:
            return None
        return offset if isinstance(offset, int) else None
    return None


def _statement_value_roots_8616(statement: object) -> tuple[object, ...]:
    """Return value-evaluated roots without descending into branch bodies."""
    if isinstance(statement, structured_c.CIfElse):
        return tuple(condition for condition, _body in iter(statement.condition_and_nodes))
    return (statement,)


@cython.ccall
def _transparent_statement_leaf_8616(statement: object) -> object:
    """Unwrap transparent one-statement containers before expression rewrites."""
    current = statement
    visited: set[cython.longlong] = set()
    while isinstance(current, structured_c.CStatements) and id(current) not in visited:
        visited.add(id(current))
        children = tuple(current.statements or ())
        if len(children) != 1:
            break
        current = children[0]
    return current


@cython.ccall
def _flags_carriers_8616(statement: object, flags_offset: cython.longlong) -> tuple[structured_c.CExpression, ...]:
    """Collect one representative per physical FLAGS storage identity.

    Structured condition trees may clone the same register read into several
    boolean subexpressions.  Those nodes are distinct C-AST objects but consume
    one post-interrupt FLAGS definition, so object identity must not turn them
    into competing status outputs.
    """
    node: object
    root: object
    carriers: list[structured_c.CExpression] = []
    seen_registers: set[cython.longlong] = set()
    for root in _statement_value_roots_8616(statement):
        assignment_lhs_ids = {
            id(node.lhs)
            for node in builtins.iter(_iter_c_nodes_deep_8616(root))
            if isinstance(node, structured_c.CAssignment)
        }
        for node in _iter_c_nodes_deep_8616(root):
            register_offset = _physical_register_offset_8616(node)
            if (
                register_offset != flags_offset
                or id(node) in assignment_lhs_ids
                or register_offset in seen_registers
            ):
                continue
            seen_registers.add(register_offset)
            carriers.append(cast(structured_c.CExpression, node))
    return tuple(carriers)


@cython.ccall
def _writes_flags_8616(statement: object, flags_offset: cython.longlong) -> cython.bint:
    """Return whether a statement explicitly overwrites physical FLAGS."""
    node: object
    root: object
    for root in _statement_value_roots_8616(statement):
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, structured_c.CAssignment):
                continue
            if operator.eq(_physical_register_offset_8616(node.lhs), flags_offset):
                return True
    return False


def _calls_in_statement_8616(statement: object) -> tuple[structured_c.CFunctionCall, ...]:
    """Return every call expression owned by one statement."""
    return tuple(
        node
        for root in builtins.iter(_statement_value_roots_8616(statement))
        for node in builtins.iter(_iter_c_nodes_deep_8616(root))
        if isinstance(node, structured_c.CFunctionCall)
    )


@cython.ccall
def _status_assignment_8616(
    carrier: structured_c.CExpression,
    callsite_addr: cython.longlong,
    codegen: object,
) -> structured_c.CAssignment:
    """Build one explicit post-interrupt FLAGS output definition."""
    tags = {"ins_addr": callsite_addr, "inertia_software_interrupt_status_output_8616": True}
    accessor = structured_c.CFunctionCall(
        "dos_int21_flags",
        None,
        [],
        tags=tags,
        codegen=codegen,
    )
    return structured_c.CAssignment(
        cast(structured_c.CExpression, _clone_c_ast_tree_8616(carrier)),
        accessor,
        tags=tags,
        codegen=codegen,
    )


@cython.ccall
def _canonical_flags_carrier_8616(
    carrier: structured_c.CExpression,
    flags_offset: cython.longlong,
    flags_size: cython.longlong,
    codegen: object,
) -> structured_c.CExpression:
    """Return a renderable typed carrier for one proven physical FLAGS read."""
    if not isinstance(carrier, structured_c.CDirtyExpression):
        return carrier
    return structured_c.CVariable(
        SimRegisterVariable(flags_offset, flags_size, name="flags"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _replace_dirty_flags_carriers_8616(
    statement: object,
    canonical: structured_c.CExpression,
    flags_offset: cython.longlong,
) -> cython.bint:
    """Replace dirty reads after their enclosing statement ownership is stable."""

    def replace(node: object) -> object:
        if (
            isinstance(node, structured_c.CDirtyExpression)
            and operator.eq(_physical_register_offset_8616(node), flags_offset)
        ):
            replacement = cast(
                structured_c.CExpression,
                _clone_c_ast_tree_8616(canonical),
            )
            tags = cast(_TaggedNode8616, node).tags
            if isinstance(tags, dict):
                replacement.tags = dict(tags)
            return replacement
        return node

    return bool(_replace_c_children_8616(statement, replace))


def _replace_stale_flags_projection_8616(
    statement: object,
    canonical: structured_c.CExpression,
    flags_offset: cython.longlong,
    callsite_addr: cython.longlong,
) -> cython.bint:
    """Invalidate maximal pre-interrupt FLAGS expressions in one later consumer."""
    address: object
    node: object
    root: object
    candidates: list[object] = []
    for root in _statement_value_roots_8616(statement):
        for node in _iter_c_nodes_deep_8616(root):
            address = _instruction_address_8616(node)
            if address is None or address >= callsite_addr:
                continue
            if any(
                operator.eq(_physical_register_offset_8616(descendant), flags_offset)
                for descendant in builtins.iter(_iter_c_nodes_deep_8616(node))
            ):
                candidates.append(node)
    candidate_ids = {id(candidate) for candidate in iter(candidates)}
    maximal_ids = {
        id(candidate)
        for candidate in iter(candidates)
        if not any(
            operator.ne(id(candidate), id(owner))
            and any(operator.eq(id(descendant), id(candidate)) for descendant in builtins.iter(_iter_c_nodes_deep_8616(owner)))
            for owner in iter(candidates)
        )
    }
    if not maximal_ids:
        return False

    def replace(node: object) -> object:
        if id(node) not in maximal_ids or id(node) not in candidate_ids:
            return node
        replacement = cast(
            structured_c.CExpression,
            _clone_c_ast_tree_8616(canonical),
        )
        tags = cast(_TaggedNode8616, node).tags
        if isinstance(tags, dict):
            replacement.tags = dict(tags)
        return replacement

    return bool(_replace_c_children_8616(statement, replace))


def materialize_software_interrupt_status_outputs_8616(codegen: object) -> cython.bint:
    """Materialize every proven DOS interrupt FLAGS result consumed by C."""
    flags_info: object
    root: object
    container: object
    index: object
    statement: object
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    root = cfunc.statements
    flags_info = surface.project.arch.registers.get("flags")
    if root is None or not isinstance(flags_info, tuple):
        stats = SoftwareInterruptStatusOutputStats8616()
        surface._inertia_software_interrupt_status_output_stats_8616 = stats
        return False
    flags_offset = int(flags_info[0])
    flags_size = int(flags_info[1])
    raw = normalized = classified = materialized = failures = 0
    changed = False
    containers = tuple(
        node
        for node in builtins.iter(_iter_c_nodes_deep_8616(root))
        if isinstance(node, structured_c.CStatements)
    )
    for container in containers:
        statements = list(container.statements or ())
        scan = _StatusOutputScan8616(codegen, flags_offset, flags_size)
        for index, statement in enumerate(statements):
            scan.scan_statement(index, statement, statements)
        changed = scan.apply(container, statements) or changed
        raw += scan.raw
        normalized += scan.normalized
        classified += scan.classified
        materialized += scan.materialized
        failures += scan.failures
    stats = SoftwareInterruptStatusOutputStats8616(
        raw,
        normalized,
        classified,
        materialized,
        failures,
    )
    surface._inertia_software_interrupt_status_output_stats_8616 = stats
    if failures or classified != materialized:
        raise PipelineHardError(
            "classified software interrupt status output was not materialized",
            layer="lowering",
        )
    return changed


@cython.dataclasses.dataclass()
class _StatusOutputScan8616:
    """Mutable per-container DOS-interrupt FLAGS consumer scan state."""

    codegen: object
    flags_offset: cython.longlong
    flags_size: cython.longlong
    pending: object = None
    insertions: object = field(default_factory=dict)
    carrier_rewrites: object = field(
        default_factory=list
    )
    raw: cython.longlong = 0
    normalized: cython.longlong = 0
    classified: cython.longlong = 0
    materialized: cython.longlong = 0
    failures: cython.longlong = 0

    def scan_statement(
        self,
        index: cython.longlong,
        statement: object,
        statements: object,
    ) -> None:
        """Advance the pending-interrupt state machine over one statement."""
        calls = _calls_in_statement_8616(statement)
        interrupt_calls = tuple(call for call in iter(calls) if _is_dos_int21_call_8616(call))
        if interrupt_calls:
            self._track_interrupt(index, statement, interrupt_calls)
            return
        carriers = _flags_carriers_8616(statement, self.flags_offset)
        if carriers and self.pending is not None:
            self._consume_carriers(statement, statements, carriers)
            return
        if self.pending is not None and (
            _writes_flags_8616(statement, self.flags_offset)
            or any(not _is_status_accessor_call_8616(call) for call in iter(calls))
        ):
            self.pending = None

    @cython.ccall
    def _track_interrupt(
        self,
        index: cython.longlong,
        statement: object,
        interrupt_calls: object,
    ) -> None:
        """Latch a single exact DOS interrupt callsite as pending."""
        if len(interrupt_calls) != 1:
            self.pending = None
            return
        callsite_addr = _interrupt_callsite_address_8616(statement, interrupt_calls[0])
        self.pending = (index, callsite_addr) if isinstance(callsite_addr, int) else None

    def _consume_carriers(
        self,
        statement: object,
        statements: object,
        carriers: object,
    ) -> None:
        """Record insertion and carrier rewrites for the pending FLAGS read."""
        self.raw += 1
        assert self.pending is not None
        call_index, callsite_addr = self.pending
        read_addr = _instruction_address_8616(statement)
        if len(carriers) != 1 or (
            isinstance(read_addr, int)
            and operator.ne(callsite_addr, interrupt_core_addr_8616(0x21))
            and read_addr <= callsite_addr
        ):
            self.failures += 1
            self.pending = None
            return
        self.normalized += 1
        self.classified += 1
        carrier = _canonical_flags_carrier_8616(
            carriers[0],
            self.flags_offset,
            self.flags_size,
            self.codegen,
        )
        self.carrier_rewrites.append(
            (
                _transparent_statement_leaf_8616(statement),
                carrier,
                callsite_addr,
            )
        )
        if call_index + 1 < len(statements):
            existing_calls = _calls_in_statement_8616(statements[call_index + 1])
            if any(_is_status_accessor_call_8616(call) for call in iter(existing_calls)):
                self.materialized += 1
                self.pending = None
                return
        self.insertions[call_index] = _status_assignment_8616(
            carrier,
            callsite_addr,
            self.codegen,
        )
        self.materialized += 1
        self.pending = None

    @cython.ccall
    def apply(
        self,
        container: structured_c.CStatements,
        statements: object,
    ) -> cython.bint:
        """Apply recorded insertions and carrier rewrites to the container."""
        insertion: object
        callsite_addr: object
        carrier: object
        index: object
        statement: object
        changed = False
        if self.insertions:
            rewritten: list[structured_c.CStatement] = []
            for index, statement in enumerate(statements):
                rewritten.append(statement)
                insertion = self.insertions.get(index)
                if insertion is not None:
                    rewritten.append(insertion)
            container.statements = rewritten
            changed = True
        for statement, carrier, callsite_addr in self.carrier_rewrites:
            changed = (
                _replace_stale_flags_projection_8616(
                    statement,
                    carrier,
                    self.flags_offset,
                    callsite_addr,
                )
                or changed
            )
            changed = (
                _replace_dirty_flags_carriers_8616(
                    statement,
                    carrier,
                    self.flags_offset,
                )
                or changed
            )
        return changed
