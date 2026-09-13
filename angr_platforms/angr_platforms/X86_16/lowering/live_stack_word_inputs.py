"""Project proven incoming stack words still read by the structured body.

Layer: Types/Lowering.
Responsibility: consume current Alias entry versions and exact typed read bytes
before positive-BP argument planning. No grouping into far pointers is inferred.
Unknown versions, writes, calls, and incomplete storage evidence refuse recovery.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CAssignment, CUnaryOp, CVariable
from angr.project import Project
from angr.sim_type import SimType
from angr.sim_variable import SimStackVariable

from ..alias.stack_memory_ssa_contracts import StackMemoryAliasFactKind8616, StackMemorySSAAliasArtifact8616
from ..c_ast_utils import _replace_c_children_8616
from ..ir.core import AddressStatus, MemSpace
from ..ir.logical_memory_contracts import IRMemoryAccessKind8616
from ..ir.ssa_function import SSAFunctionArtifact
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

_WORD_BYTES = 2
_BITS_PER_BYTE = 8
_FIRST_ARGUMENT = 4


class _CodegenBoundary(Protocol):
    """Owned evidence attached to the third-party codegen object."""

    _inertia_stack_memory_ssa_alias_artifact: StackMemorySSAAliasArtifact8616
    _inertia_vex_ir_function_ssa: SSAFunctionArtifact
    project: Project


@dataclass(frozen=True, slots=True)
class LiveStackWordInputs8616:
    """Incoming evidence accounting; materialization counts projected offsets only.

    The consuming positive-BP planner separately accounts for C parameters.
    """

    offsets: frozenset[int] = frozenset()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


def _read_bytes(codegen: object, node: object) -> frozenset[int]:
    """Resolve only exact typed stack-value bytes through the coordinate owner."""
    if not isinstance(node, CVariable) or not isinstance(node.variable, SimStackVariable):
        return frozenset()
    variable = node.variable
    if variable.base != "bp" or not isinstance(node.variable_type, SimType):
        return frozenset()
    offset = machine_bp_offset_for_stack_variable_8616(codegen, variable)
    try:
        # Lowering can publish an unbound type between argument-planning passes.
        # Resolve its value width in the actual target, never from slot padding.
        bits = node.variable_type.with_arch(cast(_CodegenBoundary, codegen).project.arch).size
    except (AttributeError, TypeError, ValueError):
        return frozenset()
    if not isinstance(offset, int) or not isinstance(bits, int) or bits <= 0 or bits % _BITS_PER_BYTE:
        return frozenset()
    width = min(variable.size, bits // _BITS_PER_BYTE)
    return frozenset(range(offset, offset + width))


def _entry_word_evidence(alias: StackMemorySSAAliasArtifact8616) -> tuple[set[int], set[int], set[int]]:
    """Require a logical word owner as well as exact incoming raw bytes."""
    incoming: set[int] = set()
    written: set[int] = set()
    for fact in alias.facts:
        address = fact.address
        exact = address.space is MemSpace.SS and address.base == ("bp",) and address.status is AddressStatus.STABLE
        if not exact or address.offset < _FIRST_ARGUMENT:
            continue
        byte_range = range(address.offset, address.offset + address.size)
        if fact.kind is StackMemoryAliasFactKind8616.STORE:
            written.update(byte_range)
        elif fact.kind is StackMemoryAliasFactKind8616.LOAD and address.version == 0:
            incoming.update(byte_range)
    candidates = {
        access.address.offset
        for access in alias.logical_accesses
        if access.source.kind is IRMemoryAccessKind8616.READ
        and access.address.space is MemSpace.SS
        and access.address.base == ("bp",)
        and access.address.status is AddressStatus.STABLE
        and access.address.size == _WORD_BYTES
        and access.address.offset >= _FIRST_ARGUMENT
        and all(item.raw_slice.address.version == 0 for item in access.slices)
    }
    return candidates, incoming, written


def collect_live_stack_word_inputs_8616(codegen: object, root: object) -> LiveStackWordInputs8616:
    """Retain full incoming words only when both bytes survive as value reads."""
    boundary = cast(_CodegenBoundary, codegen)
    try:
        alias = boundary._inertia_stack_memory_ssa_alias_artifact
        source = boundary._inertia_vex_ir_function_ssa
    except AttributeError:
        return LiveStackWordInputs8616()
    if not alias.complete or alias.source_ssa is not source or alias.call_effects:
        return LiveStackWordInputs8616()
    candidates, incoming, written = _entry_word_evidence(alias)
    reads: set[int] = set()

    def collect(node: object) -> object:
        """Collect reads and conservatively exclude any structured write target."""
        if isinstance(node, CAssignment):
            written.update(_read_bytes(codegen, node.lhs))
        reads.update(_read_bytes(codegen, node))
        return node

    def is_read(parent: object, attr: str) -> bool:
        """Exclude assignment storage and address-taking from value demand."""
        if isinstance(parent, CAssignment) and attr == "lhs":
            return False
        if isinstance(parent, CUnaryOp) and parent.op == "Reference":
            return False
        return attr != "variable"

    _replace_c_children_8616(root, collect, should_process_child=is_read)
    defined = {offset for offset in candidates if {offset, offset + 1} <= incoming - written}
    live = frozenset(offset for offset in defined if {offset, offset + 1} <= reads)
    return LiveStackWordInputs8616(live, len(candidates), len(defined), len(live), len(live), len(candidates) - len(live))
