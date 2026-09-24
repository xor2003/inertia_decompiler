"""Validate binary-proven segmented writes against the final structured C AST.

Layer: Tail validation.
Responsibility: report final-AST loss of typed direct segmented-memory stores.
Consumes alias, widening, lowering, and typed binary facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
Forbidden: semantic recovery, source/COD/assembly/rendered-C inspection.

This guard never mutates C. It matches exact segment spaces, runtime segment
sources, byte ranges, and write multiplicity. One word assignment or two byte
assignments may cover one binary word store, while one final write cannot cover
repeated binary writes.

Dynamic boundary: angr C nodes and codegen containers expose version-dependent
child and tag attributes. Dynamic access is restricted to those third-party
surfaces.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable
from archinfo import Arch

from .ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .lowering.runtime_segment_access import runtime_segment_access_space_8616
from .lowering.segmented_global_loads import DirectSegmentedGlobalStoreEvidence8616
from .validation_aggregate_storage import aggregate_field_storage_8616
from .widening.segmented_load_identity import segmented_load_identity_8616

_CHILD_ATTRIBUTES_8616 = (
    "statements",
    "lhs",
    "rhs",
    "expr",
    "operand",
    "args",
    "condition",
    "condition_and_nodes",
    "true_node",
    "false_node",
    "else_node",
    "body",
    "init",
    "initializer",
    "iteration",
    "iterator",
    "retval",
    "switch",
    "cases",
    "default",
)


class RequiredMemoryEffectIssueKind8616(Enum):
    """Typed reasons why one final required-memory-effect guard failed."""

    MALFORMED_EVIDENCE = "malformed_evidence"
    MISSING_WRITE = "missing_write"


@dataclass(frozen=True, slots=True)
class RequiredMemoryEffectIssue8616:
    """One malformed obligation or binary-proven write missing from final C."""

    kind: RequiredMemoryEffectIssueKind8616
    effect: DirectSegmentedGlobalStoreEvidence8616 | None = None
    source_index: int | None = None

    def token(self) -> str:
        """Return a stable diagnostic token for snapshots and tests."""
        if self.effect is None:
            return f"malformed-required-memory-effect:index={self.source_index}"
        effect = self.effect
        return (
            f"missing-required-memory-write:{effect.space.value}:"
            f"0x{effect.offset & 0xFFFF:04x}:width={effect.width}:"
            f"ins=0x{effect.ins_addr:x}"
        )


@dataclass(frozen=True, slots=True)
class RequiredMemoryEffectValidationReport8616:
    """Closed evidence result for binary-proven final memory writes."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    issues: tuple[RequiredMemoryEffectIssue8616, ...] = ()

    @property
    def passed(self) -> bool:
        """Return whether every well-formed obligation has final AST coverage."""
        return self.failure_count == 0 and not self.issues

    def issue_tokens(self) -> tuple[str, ...]:
        """Return stable tokens for canonical validation snapshots."""
        return tuple(issue.token() for issue in self.issues)


@dataclass(frozen=True, slots=True)
class _FinalSegmentedWrite8616:
    """One final structured-C write classified by typed storage location."""

    space: MemSpace
    offset: int | None
    width: int
    segment_source: IRAddress | int | None = None
    affine_base: int | None = None
    ins_addr: int | None = None


class _ProjectArchBoundary8616(Protocol):
    """Typed project surface needed for final lvalue width resolution."""

    arch: Arch


def _boundary_tuple_8616(value: object) -> tuple[object, ...]:
    """Convert one dynamic third-party collection to a stable tuple."""
    return tuple(cast(Iterable[object], value))


def _strip_casts_8616(node: object) -> object:
    """Remove structured-C casts from one expression."""
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _iter_ast_nodes_8616(root: object) -> Iterable[object]:
    """Walk every structured-C occurrence without following object cycles."""
    pending: list[tuple[object, frozenset[int]]] = [(root, frozenset())]
    while pending:
        node, ancestors = pending.pop()
        if node is None or id(node) in ancestors:
            continue
        child_ancestors = ancestors | {id(node)}
        if isinstance(node, dict):
            pending.extend((child, child_ancestors) for child in reversed(tuple(node.values())))
            continue
        if isinstance(node, (list, tuple)):
            pending.extend((child, child_ancestors) for child in reversed(node))
            continue
        yield node
        for attribute in _CHILD_ATTRIBUTES_8616:
            child = getattr(node, attribute, None)
            if isinstance(child, (list, tuple)):
                pending.extend((item, child_ancestors) for item in reversed(child))
            elif child is not None:
                pending.append((child, child_ancestors))


def _constant_int_8616(node: object) -> int | None:
    """Return one exact structured-C integer constant."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CConstant):
        return None
    value = node.value
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _dynamic_affine_base_8616(node: object) -> int | None:
    """Return the constant base of one additive expression with a dynamic term."""
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp) or node.op != "Add":
        return None
    lhs_constant = _constant_int_8616(node.lhs)
    rhs_constant = _constant_int_8616(node.rhs)
    if lhs_constant is not None and rhs_constant is None:
        return lhs_constant & 0xFFFF
    if rhs_constant is not None and lhs_constant is None:
        return rhs_constant & 0xFFFF
    return None


def _instruction_address_8616(node: object) -> int | None:
    """Return exact instruction provenance from one third-party C node."""
    tags = getattr(node, "tags", None)
    if not isinstance(tags, dict):
        return None
    value = tags.get("ins_addr")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _helper_width_8616(call: structured_c.CFunctionCall) -> int | None:
    """Return the byte width of one supported segmented runtime helper."""
    target = call.callee_target
    if not isinstance(target, str):
        callee = call.callee_func
        target = callee.name if callee is not None else None
    return {"SEG_U8": 1, "SEG_U16": 2, "SEG_U32": 4}.get(
        target.upper() if isinstance(target, str) else ""
    )


def _segment_source_identity_8616(node: object) -> IRAddress | int | None:
    """Return an exact nested segment value used by a runtime helper."""
    constant = _constant_int_8616(node)
    if constant is not None:
        return constant & 0xFFFF
    identity = segmented_load_identity_8616(_strip_casts_8616(node))
    if identity is None:
        return None
    return IRAddress(
        space=identity.space,
        offset=identity.offset & 0xFFFF,
        size=identity.width,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )


_LvalueLocation8616 = tuple[MemSpace, int | None, int, IRAddress | int | None, int | None]


def _call_lvalue_location_8616(
    project: object,
    codegen: object,
    node: structured_c.CFunctionCall,
) -> _LvalueLocation8616 | None:
    """Classify one segmented helper call lvalue from typed call evidence."""
    width = _helper_width_8616(node)
    args = _boundary_tuple_8616(node.args or ())
    offset = _constant_int_8616(args[1]) if len(args) == 2 else None
    affine_base = _dynamic_affine_base_8616(args[1]) if len(args) == 2 else None
    space = runtime_segment_access_space_8616(project, codegen, node)
    if width is not None and (offset is not None or affine_base is not None) and space is not None:
        source = _segment_source_identity_8616(args[0]) if len(args) == 2 else None
        return space, offset & 0xFFFF if offset is not None else None, width, source, affine_base
    return None


def _memory_variable_location_8616(
    project: object,
    node: structured_c.CVariable,
) -> _LvalueLocation8616 | None:
    """Classify one direct global variable lvalue in the DS space."""
    variable = node.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    width = int(variable.size)
    variable_type = node.variable_type
    if variable_type is not None:
        try:
            arch = cast(_ProjectArchBoundary8616, project).arch
            size_bits = variable_type.with_arch(arch).size
            byte_width = arch.byte_width
        except (AttributeError, TypeError, ValueError):
            pass
        else:
            if (
                isinstance(size_bits, int)
                and isinstance(byte_width, int)
                and byte_width > 0
                and size_bits > 0
                and size_bits % byte_width == 0
            ):
                width = max(width, size_bits // byte_width)
    return MemSpace.DS, int(variable.addr) & 0xFFFF, width, None, None


def _indexed_lvalue_location_8616(
    node: structured_c.CIndexedVariable,
) -> _LvalueLocation8616 | None:
    """Classify one constant-indexed global array lvalue in the DS space."""
    base = _strip_casts_8616(node.variable)
    index = _constant_int_8616(node.index)
    if not isinstance(base, structured_c.CVariable) or index is None:
        return None
    variable = base.variable
    if not isinstance(variable, SimMemoryVariable):
        return None
    width = int(variable.size)
    return MemSpace.DS, (int(variable.addr) + index * width) & 0xFFFF, width, None, None


def _segmented_lvalue_location_8616(
    project: object,
    codegen: object,
    lvalue: object,
) -> _LvalueLocation8616 | None:
    """Classify one final assignment lvalue without parsing rendered text."""
    node = _strip_casts_8616(lvalue)
    aggregate_storage = aggregate_field_storage_8616(node)
    if aggregate_storage is not None:
        return aggregate_storage.space, aggregate_storage.offset, aggregate_storage.width, None, None
    identity = segmented_load_identity_8616(node)
    if identity is not None:
        args = _boundary_tuple_8616(node.args or ()) if isinstance(node, structured_c.CFunctionCall) else ()
        source = _segment_source_identity_8616(args[0]) if len(args) == 2 else None
        return identity.space, identity.offset, identity.width, source, None
    if isinstance(node, structured_c.CFunctionCall):
        return _call_lvalue_location_8616(project, codegen, node)
    if isinstance(node, structured_c.CVariable):
        return _memory_variable_location_8616(project, node)
    if not isinstance(node, structured_c.CIndexedVariable):
        return None
    return _indexed_lvalue_location_8616(node)


def _final_segmented_writes_8616(
    project: object,
    codegen: object,
    root: object,
) -> tuple[_FinalSegmentedWrite8616, ...]:
    """Collect exact segmented write locations from final structured C."""
    writes: list[_FinalSegmentedWrite8616] = []
    for node in _iter_ast_nodes_8616(root):
        if not isinstance(node, structured_c.CAssignment):
            continue
        location = _segmented_lvalue_location_8616(project, codegen, node.lhs)
        if location is None:
            continue
        space, offset, width, segment_source, affine_base = location
        if width <= 0:
            continue
        writes.append(
            _FinalSegmentedWrite8616(
                space=space,
                offset=offset,
                width=width,
                segment_source=segment_source,
                affine_base=affine_base,
                ins_addr=_instruction_address_8616(node),
            )
        )
    return tuple(writes)


def _effect_is_well_formed_8616(effect: DirectSegmentedGlobalStoreEvidence8616) -> bool:
    """Return whether one dynamic obligation satisfies the owned contract."""
    return bool(
        effect.space in {MemSpace.DS, MemSpace.ES, MemSpace.SS}
        and 0 <= effect.offset <= 0xFFFF
        and effect.width in {1, 2, 4}
        and isinstance(effect.ins_addr, int)
        and not isinstance(effect.ins_addr, bool)
    )


def validate_required_memory_effects_8616(
    project: object,
    codegen: object,
    root: object,
) -> RequiredMemoryEffectValidationReport8616:
    """Verify final C covers every typed binary-proven direct segmented store."""
    raw_values = _boundary_tuple_8616(
        getattr(
            codegen,
            "_inertia_required_direct_segmented_global_stores_8616",
            (),
        )
        or ()
    )
    malformed = tuple(
        RequiredMemoryEffectIssue8616(
            RequiredMemoryEffectIssueKind8616.MALFORMED_EVIDENCE,
            source_index=index,
        )
        for index, value in enumerate(raw_values)
        if not isinstance(value, DirectSegmentedGlobalStoreEvidence8616)
        or not _effect_is_well_formed_8616(value)
    )
    normalized = tuple(
        dict.fromkeys(
            value
            for value in raw_values
            if isinstance(value, DirectSegmentedGlobalStoreEvidence8616)
            and _effect_is_well_formed_8616(value)
        )
    )
    writes = _final_segmented_writes_8616(project, codegen, root)
    available_bytes: Counter[tuple[MemSpace, int, IRAddress | int | None]] = Counter()
    available_affine: Counter[
        tuple[MemSpace, int, int, IRAddress | int | None, int]
    ] = Counter()
    for write in writes:
        if write.offset is not None:
            available_bytes.update(
                (write.space, (write.offset + index) & 0xFFFF, write.segment_source)
                for index in range(write.width)
            )
        elif write.affine_base is not None and write.ins_addr is not None:
            available_affine[
                (write.space, write.affine_base, write.width, write.segment_source, write.ins_addr)
            ] += 1
    missing_items: list[RequiredMemoryEffectIssue8616] = []
    for effect in normalized:
        required_source: IRAddress | int | None = effect.segment_source or effect.segment_value
        selected: list[tuple[MemSpace, int, IRAddress | int | None]] = []
        for index in range(effect.width):
            address = (effect.offset + index) & 0xFFFF
            matching = next(
                (
                    key
                    for key, count in available_bytes.items()
                    if count > 0
                    and key[0] is effect.space
                    and key[1] == address
                    and (required_source is None or key[2] == required_source)
                ),
                None,
            )
            if matching is None:
                break
            selected.append(matching)
        if len(selected) == effect.width:
            available_bytes.subtract(selected)
            continue
        affine_key = (
            effect.space,
            effect.offset,
            effect.width,
            required_source,
            effect.ins_addr,
        )
        if available_affine[affine_key] > 0:
            available_affine[affine_key] -= 1
            continue
        missing_items.append(
            RequiredMemoryEffectIssue8616(
                RequiredMemoryEffectIssueKind8616.MISSING_WRITE,
                effect=effect,
            )
        )
    missing = tuple(missing_items)
    issues = (*malformed, *missing)
    materialized_count = len(normalized) - len(missing)
    return RequiredMemoryEffectValidationReport8616(
        raw_fact_count=len(raw_values),
        normalized_fact_count=len(normalized),
        classified_fact_count=len(normalized),
        materialized_count=materialized_count,
        failure_count=len(issues),
        issues=issues,
    )
