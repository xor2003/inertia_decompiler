"""Project DOS interrupt aggregate arguments and scalar field accesses.

Layer: Types/Lowering.
Responsibility: materialize already-classified REGS/SREGS global bases,
references, and unique ABI field paths in the structured C AST.

Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimStruct, SimType, TypeRef
from angr.sim_variable import SimMemoryVariable
from angr.utils.types import unpack_typeref

from .cod_global_identity import CodGlobalIdentityFact8616
from .dos_interrupt_abi import DosInterruptAbiArgumentKind8616, DosInterruptAggregateTypes8616
from .dos_interrupt_aggregate_evidence import (
    DosInterruptAggregateCallFact8616,
    DosInterruptAggregateObjectFact8616,
)
from .indexed_global_evidence import IndexedSegmentedGlobalEvidence8616

__all__ = [
    "materialize_dos_interrupt_call_arguments_8616",
    "project_dos_interrupt_global_access_8616",
]


@dataclass(frozen=True, slots=True)
class _GlobalAccessSurface8616:
    """One structured global scalar access before aggregate projection."""

    offset: int
    width: int
    name: str | None


class _CFunctionSurface8616(Protocol):
    """Third-party C function identity used for global variable regions."""

    addr: int


class _CodegenSurface8616(Protocol):
    """Third-party codegen fields used to build C expressions."""

    cfunc: _CFunctionSurface8616


def _aggregate_size_8616(kind: DosInterruptAbiArgumentKind8616) -> int:
    """Return the ABI byte extent for one aggregate kind."""
    return 14 if kind is DosInterruptAbiArgumentKind8616.REGS else 8


def _aggregate_base_8616(
    codegen: object,
    fact: DosInterruptAggregateObjectFact8616,
    types: DosInterruptAggregateTypes8616,
) -> structured_c.CVariable:
    """Build one typed global base expression from exact storage identity."""
    aggregate_type: SimType = (
        types.regs if fact.kind is DosInterruptAbiArgumentKind8616.REGS else types.sregs
    )
    type_name = "REGS" if fact.kind is DosInterruptAbiArgumentKind8616.REGS else "SREGS"
    surface = cast(_CodegenSurface8616, codegen)
    variable = SimMemoryVariable(
        fact.base_offset,
        _aggregate_size_8616(fact.kind),
        name=fact.display_name,
        region=surface.cfunc.addr,
    )
    return structured_c.CVariable(
        variable,
        variable_type=TypeRef(type_name, aggregate_type),
        codegen=codegen,
    )


def _reference_matches_object_8616(
    node: object,
    fact: DosInterruptAggregateObjectFact8616,
) -> bool:
    """Return whether an argument references the exact typed global base."""
    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Reference":
        return False
    operand = node.operand
    if not isinstance(operand, structured_c.CVariable):
        return False
    variable = operand.variable
    return (
        isinstance(variable, SimMemoryVariable)
        and variable.addr == fact.base_offset
        and variable.name == fact.display_name
    )


def materialize_dos_interrupt_call_arguments_8616(
    codegen: object,
    fact: DosInterruptAggregateCallFact8616,
    types: DosInterruptAggregateTypes8616,
) -> tuple[bool, bool]:
    """Materialize all aggregate arguments atomically and report success/change."""
    args = tuple(cast(Sequence[object], fact.call.args or ()))
    if len(args) != len(fact.contract.argument_kinds):
        return False, False
    rewritten = list(args)
    changed = False
    for obj in fact.objects:
        current = rewritten[obj.argument_index]
        if not _reference_matches_object_8616(current, obj):
            base = _aggregate_base_8616(codegen, obj, types)
            rewritten[obj.argument_index] = structured_c.CUnaryOp("Reference", base, codegen=codegen)
            changed = True
    if changed:
        fact.call.args = rewritten
    materialized = all(
        _reference_matches_object_8616(fact.call.args[obj.argument_index], obj)
        for obj in fact.objects
    )
    return materialized, changed


def _simtype_width_8616(type_: object) -> int | None:
    """Return a C expression type width in bytes at the third-party boundary."""
    if not isinstance(type_, SimType):
        return None
    try:
        bits = unpack_typeref(type_).size
    except (AttributeError, ValueError):
        return None
    return bits // 8 if isinstance(bits, int) and bits > 0 and bits % 8 == 0 else None


def _access_surface_8616(node: object) -> _GlobalAccessSurface8616 | None:
    """Return exact address, width, and name for supported scalar global nodes."""
    if isinstance(node, structured_c.CVariable):
        variable = node.variable
        if isinstance(variable, SimMemoryVariable) and isinstance(variable.addr, int):
            return _GlobalAccessSurface8616(variable.addr & 0xFFFF, int(variable.size), variable.name)
        return None
    if not isinstance(node, structured_c.CIndexedVariable):
        return None
    base = node.variable
    index = node.index
    if not isinstance(base, structured_c.CVariable) or not isinstance(index, structured_c.CConstant):
        return None
    variable = base.variable
    width = _simtype_width_8616(node.type)
    if width is None and isinstance(variable, SimMemoryVariable) and variable.size in {1, 2, 4}:
        width = int(variable.size)
    if (
        not isinstance(variable, SimMemoryVariable)
        or not isinstance(variable.addr, int)
        or not isinstance(index.value, int)
        or width is None
    ):
        return None
    return _GlobalAccessSurface8616(
        (variable.addr + index.value * width) & 0xFFFF,
        width,
        variable.name,
    )


def _name_matches_object_8616(
    name: str | None,
    fact: DosInterruptAggregateObjectFact8616,
) -> bool:
    """Match optional display identity without using it as type proof."""
    return isinstance(name, str) and name in {fact.display_name, *fact.canonical_names}


def _evidence_matches_object_8616(
    surface: _GlobalAccessSurface8616,
    fact: DosInterruptAggregateObjectFact8616,
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
) -> bool:
    """Return whether exact storage evidence associates an access with an object."""
    if _name_matches_object_8616(surface.name, fact):
        return True
    if any(
        item.base_offset == surface.offset
        and item.width == surface.width
        and item.name in fact.canonical_names
        for item in evidence
    ):
        return True
    return any(
        item.offset == surface.offset
        and item.width == surface.width
        and item.source_alias == fact.display_name
        for item in identities
    )


def _projection_path_8616(
    fact: DosInterruptAggregateObjectFact8616,
    access_offset: int,
    width: int,
    types: DosInterruptAggregateTypes8616,
) -> tuple[tuple[SimStruct, int, str], ...] | None:
    """Return the unique ABI field path for one exact offset and width."""
    relative = (access_offset - fact.base_offset) & 0xFFFF
    if fact.kind is DosInterruptAbiArgumentKind8616.SREGS:
        sreg_names = ("es", "cs", "ss", "ds")
        if width == 2 and relative % 2 == 0 and relative // 2 < len(sreg_names):
            return ((types.sregs, relative, sreg_names[relative // 2]),)
        return None
    if width == 1 and relative < 8:
        byte_names = ("al", "ah", "bl", "bh", "cl", "ch", "dl", "dh")
        return (
            (cast(SimStruct, types.regs), 0, "h"),
            (types.regs_bytes, relative, byte_names[relative]),
        )
    if width == 2 and relative % 2 == 0 and relative <= 12:
        word_names = ("ax", "bx", "cx", "dx", "si", "di", "cflag")
        return (
            (cast(SimStruct, types.regs), 0, "x"),
            (types.regs_words, relative, word_names[relative // 2]),
        )
    return None


def _access_candidates_8616(
    node: object,
    surface: _GlobalAccessSurface8616,
    objects: tuple[DosInterruptAggregateObjectFact8616, ...],
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
    types: DosInterruptAggregateTypes8616,
    *,
    alternate_evidence_widths: bool,
) -> tuple[
    tuple[DosInterruptAggregateObjectFact8616, tuple[tuple[SimStruct, int, str], ...]], ...
]:
    """Collect unique projections for exact or fallback width evidence."""
    candidates: list[
        tuple[DosInterruptAggregateObjectFact8616, tuple[tuple[SimStruct, int, str], ...]]
    ] = []
    for fact in objects:
        widths = {surface.width}
        if alternate_evidence_widths:
            widths = set()
            if isinstance(node, structured_c.CVariable) and _name_matches_object_8616(
                surface.name, fact
            ):
                widths.update(
                    item.width
                    for item in evidence
                    if item.base_offset == surface.offset and item.name in fact.canonical_names
                )
                widths.update(
                    item.width
                    for item in identities
                    if item.offset == surface.offset and item.source_alias == fact.display_name
                )
            widths.discard(surface.width)
        for width in widths:
            candidate = _GlobalAccessSurface8616(surface.offset, width, surface.name)
            if not _evidence_matches_object_8616(candidate, fact, evidence, identities):
                continue
            path = _projection_path_8616(fact, surface.offset, width, types)
            if path is not None:
                candidates.append((fact, path))
    return tuple(dict.fromkeys(candidates))


def project_dos_interrupt_global_access_8616(
    codegen: object,
    node: object,
    objects: tuple[DosInterruptAggregateObjectFact8616, ...],
    evidence: tuple[IndexedSegmentedGlobalEvidence8616, ...],
    identities: tuple[CodGlobalIdentityFact8616, ...],
    types: DosInterruptAggregateTypes8616,
) -> structured_c.CExpression | None:
    """Project one scalar global node only when exactly one ABI field matches."""
    surface = _access_surface_8616(node)
    if surface is None:
        return None

    exact = _access_candidates_8616(
        node,
        surface,
        objects,
        evidence,
        identities,
        types,
        alternate_evidence_widths=False,
    )
    if len(exact) > 1:
        return None
    candidates = exact or _access_candidates_8616(
        node,
        surface,
        objects,
        evidence,
        identities,
        types,
        alternate_evidence_widths=True,
    )
    if len(candidates) != 1:
        return None
    fact, path = candidates[0]
    result: structured_c.CExpression = _aggregate_base_8616(codegen, fact, types)
    for container, offset, field_name in path:
        result = structured_c.CVariableField(
            result,
            structured_c.CStructField(container, offset, field_name, codegen=codegen),
            codegen=codegen,
        )
    return result
