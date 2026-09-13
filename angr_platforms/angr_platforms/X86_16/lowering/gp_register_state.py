"""Lower proven GP architectural live-ins to explicit C runtime state.

Layer: Types/Lowering.
Responsibility: project typed SSA-proven 16/32-bit GP-register live-ins into
coherent 32-bit runtime lanes instead of uninitialized automatic C locals.
Consumes alias, widening, and typed facts, including IR/SSA facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from typing import Protocol, cast

from angr.ailment.expression import VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeLong
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616
from ..ir.function_ssa_registry import (
    FunctionSSAArtifactVerdict8616,
    registered_function_ssa_artifact_8616,
)
from ..ir.register_live_in import register_live_in_names_8616
from ..ir.ssa_function import SSAFunctionArtifact
from .global_declarations import (
    GlobalDeclarationCType8616,
    record_global_declaration_spec_8616,
)
from .stack_value_projection import project_pointer_storage_value_8616

__all__ = [
    "GPRegisterStateLoweringStats8616",
    "RuntimeGPExpressionView8616",
    "gp_live_in_names_from_c_ast_8616",
    "gp_live_in_names_from_ssa_8616",
    "lower_architectural_gp_register_state_8616",
    "runtime_gp_expression_view_8616",
    "runtime_gp_live_in_name_8616",
    "runtime_gp_name_for_variable_8616",
    "runtime_gp_state_assignment_8616",
    "runtime_gp_state_expr_8616",
    "runtime_gp_state_names_8616",
    "runtime_gp_state_symbols_8616",
]

_RUNTIME_GP_STATE_SYMBOLS_8616 = {
    "eax": "inertia_eax",
    "ebp": "inertia_ebp",
    "ebx": "inertia_ebx",
    "ecx": "inertia_ecx",
    "edx": "inertia_edx",
    "edi": "inertia_edi",
    "esi": "inertia_esi",
    "esp": "inertia_esp",
}
_RUNTIME_GP_STATE_ADDRESSES_8616 = {
    "eax": 0x1_0000,
    "ebx": 0x1_0004,
    "ecx": 0x1_0008,
    "edx": 0x1_000C,
    "esi": 0x1_0010,
    "edi": 0x1_0014,
    "esp": 0x1_0018,
    "ebp": 0x1_001C,
}


def runtime_gp_state_symbols_8616() -> tuple[str, ...]:
    """Expose the emitted GP storage ABI to target runtime providers."""
    return tuple(sorted(_RUNTIME_GP_STATE_SYMBOLS_8616.values()))


_GP_REGISTER_VIEWS_8616 = {
    "eax": ("eax", 0, 4),
    "ax": ("eax", 0, 2),
    "al": ("eax", 0, 1),
    "ah": ("eax", 8, 1),
    "ebx": ("ebx", 0, 4),
    "bx": ("ebx", 0, 2),
    "bl": ("ebx", 0, 1),
    "bh": ("ebx", 8, 1),
    "ecx": ("ecx", 0, 4),
    "cx": ("ecx", 0, 2),
    "cl": ("ecx", 0, 1),
    "ch": ("ecx", 8, 1),
    "edx": ("edx", 0, 4),
    "dx": ("edx", 0, 2),
    "dl": ("edx", 0, 1),
    "dh": ("edx", 8, 1),
    "esi": ("esi", 0, 4),
    "si": ("esi", 0, 2),
    "edi": ("edi", 0, 4),
    "di": ("edi", 0, 2),
    "esp": ("esp", 0, 4),
    "sp": ("esp", 0, 2),
    "ebp": ("ebp", 0, 4),
    "bp": ("ebp", 0, 2),
}

_POINTER_WORD_BYTES_8616 = 2


@dataclass(frozen=True, slots=True)
class RuntimeGPExpressionView8616:
    """One structured-C projection of an owned architectural GP lane."""

    register_name: str
    parent_name: str
    bit_shift: int
    width: int


def runtime_gp_name_for_variable_8616(variable: object) -> str | None:
    """Return the architectural GP name owned by one runtime-state variable."""
    if not isinstance(variable, SimMemoryVariable):
        return None
    if variable.category != "inertia_gp_register_state":
        return None
    name = variable.name
    if not isinstance(name, str):
        return None
    return next(
        (
            register_name
            for register_name, symbol_name in _RUNTIME_GP_STATE_SYMBOLS_8616.items()
            if symbol_name == name
        ),
        None,
    )


def runtime_gp_expression_view_8616(
    expression: object,
) -> RuntimeGPExpressionView8616 | None:
    """Classify the exact structured projection emitted by this owner."""
    while isinstance(expression, structured_c.CTypeCast):
        expression = expression.expr
    mask: int | None = None
    if isinstance(expression, structured_c.CBinaryOp) and expression.op == "And":
        if not isinstance(expression.rhs, structured_c.CConstant) or not isinstance(
            expression.rhs.value,
            int,
        ):
            return None
        mask = expression.rhs.value
        expression = expression.lhs
    bit_shift = 0
    if isinstance(expression, structured_c.CBinaryOp) and expression.op == "Shr":
        if not isinstance(expression.rhs, structured_c.CConstant) or not isinstance(
            expression.rhs.value,
            int,
        ):
            return None
        bit_shift = expression.rhs.value
        expression = expression.lhs
    if not isinstance(expression, structured_c.CVariable):
        return None
    parent_name = runtime_gp_name_for_variable_8616(expression.variable)
    if parent_name is None:
        return None
    width = 4 if mask is None else {0xFF: 1, 0xFFFF: 2, 0xFFFF_FFFF: 4}.get(mask)
    if width is None:
        return None
    register_name = next(
        (
            name
            for name, view in _GP_REGISTER_VIEWS_8616.items()
            if view == (parent_name, bit_shift, width)
        ),
        None,
    )
    if register_name is None:
        return None
    return RuntimeGPExpressionView8616(
        register_name=register_name,
        parent_name=parent_name,
        bit_shift=bit_shift,
        width=width,
    )


def runtime_gp_live_in_name_8616(register_name: str) -> str | None:
    """Return the canonical runtime lane for one supported GP register view."""
    view = _GP_REGISTER_VIEWS_8616.get(register_name.strip().lower())
    return view[0] if view is not None else None


def runtime_gp_state_expr_8616(
    register_name: str,
    *,
    codegen: object,
    function_addr: int,
) -> structured_c.CExpression | None:
    """Materialize one supported GP view from explicit architectural runtime state."""
    view = _GP_REGISTER_VIEWS_8616.get(register_name.strip().lower())
    if view is None:
        return None
    parent_name, bit_shift, view_width = view
    parent = structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[parent_name],
            4,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[parent_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=_runtime_gp_lane_type_8616(codegen),
        codegen=codegen,
    )
    if view_width == 4:
        return parent
    projected: structured_c.CExpression = parent
    if bit_shift:
        projected = structured_c.CBinaryOp(
            "Shr",
            projected,
            structured_c.CConstant(bit_shift, _runtime_gp_lane_type_8616(codegen), codegen=codegen),
            codegen=codegen,
        )
    return structured_c.CBinaryOp(
        "And",
        projected,
        structured_c.CConstant(
            (1 << (view_width * 8)) - 1,
            _runtime_gp_lane_type_8616(codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def runtime_gp_state_assignment_8616(
    register_name: str,
    value: structured_c.CExpression,
    *,
    codegen: object,
    function_addr: int,
) -> structured_c.CAssignment | None:
    """Materialize one proven architectural GP write into coherent runtime state."""
    view = _GP_REGISTER_VIEWS_8616.get(register_name.strip().lower())
    if view is None:
        return None
    parent_name, bit_shift, view_width = view
    record_global_declaration_spec_8616(
        codegen,
        ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
        name=_RUNTIME_GP_STATE_SYMBOLS_8616[parent_name],
        array_len=None,
    )
    source = structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[parent_name],
            4,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[parent_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=_runtime_gp_lane_type_8616(codegen),
        codegen=codegen,
    )
    if view_width == 4:
        projected = project_pointer_storage_value_8616(codegen, value, view_width)
        return None if projected is None else structured_c.CAssignment(source, projected, codegen=codegen)
    return _runtime_gp_subview_write_8616(
        parent_name,
        bit_shift,
        view_width,
        source,
        value,
        function_addr,
    )


class _ProjectGPRegisters8616(Protocol):
    """Project boundary consumed by GP-state lowering."""

    arch: Arch


class _CFunctionGPRegisters8616(Protocol):
    """Structured function boundary mutated by GP-state lowering."""

    addr: int
    statements: object
    unified_local_vars: MutableMapping[object, object]


class _CodegenGPRegisters8616(Protocol):
    """Dynamic codegen boundary consumed by GP-state lowering."""

    cfunc: _CFunctionGPRegisters8616 | None
    project: _ProjectGPRegisters8616 | None
    _inertia_gp_register_state_lowering_stats_8616: GPRegisterStateLoweringStats8616


def _runtime_gp_lane_type_8616(codegen: object) -> SimTypeLong:
    """Return the architecture-bound 32-bit type for one coherent GP lane."""
    project = cast(_CodegenGPRegisters8616, codegen).project
    lane_type = SimTypeLong(False)
    return cast(SimTypeLong, lane_type.with_arch(project.arch)) if project is not None else lane_type


def _bind_gp_write_value_type_8616(
    codegen: object,
    value: structured_c.CExpression,
) -> None:
    """Bind an angr variable's existing value type before width comparison."""
    project = cast(_CodegenGPRegisters8616, codegen).project
    if project is None or not isinstance(value, structured_c.CVariable):
        return
    value_type = value.variable_type
    if value_type is not None:
        value.variable_type = value_type.with_arch(project.arch)


@dataclass(frozen=True, slots=True)
class GPRegisterStateLoweringStats8616:
    """Closed evidence counters for architectural GP-state lowering."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def gp_live_in_names_from_ssa_8616(artifact: SSAFunctionArtifact) -> frozenset[str]:
    """Return GP parents with upward-exposed bits using the owned view inventory."""
    return register_live_in_names_8616(artifact, _GP_REGISTER_VIEWS_8616)


def _c_register_identity_8616(
    node: object,
    project: _ProjectGPRegisters8616,
) -> tuple[tuple[int, int, str | None, int | None], str] | None:
    """Return one exact structured-C register identity and its GP parent."""
    if not isinstance(node, structured_c.CVariable) or not isinstance(
        node.variable,
        SimRegisterVariable,
    ):
        return None
    variable = node.variable
    if variable.ident is None:
        return None
    projection = _register_projection_for_shape_8616(project, variable.reg, variable.size)
    if projection is None:
        return None
    register_name, _bit_shift, _view_width = projection
    return (
        (variable.reg, variable.size, variable.ident, variable.region),
        register_name,
    )


def gp_live_in_names_from_c_ast_8616(
    root: object,
    project: _ProjectGPRegisters8616,
) -> frozenset[str]:
    """Return GP parents with an SSA C carrier read but never defined in the AST."""
    observed: dict[tuple[int, int, str | None, int | None], str] = {}
    defined: set[tuple[int, int, str | None, int | None]] = set()
    for node in _iter_c_nodes_deep_8616(root):
        identity = _c_register_identity_8616(node, project)
        if identity is not None:
            key, register_name = identity
            observed[key] = register_name
        if isinstance(node, structured_c.CAssignment):
            lhs_identity = _c_register_identity_8616(node.lhs, project)
            if lhs_identity is not None:
                defined.add(lhs_identity[0])
    return frozenset(
        register_name
        for key, register_name in observed.items()
        if key not in defined
    )


def _register_projection_for_shape_8616(
    project: _ProjectGPRegisters8616,
    offset: int,
    size: int,
) -> tuple[str, int, int] | None:
    """Resolve one exact GP view into its coherent 32-bit runtime lane."""
    names = {
        name.lower(): _GP_REGISTER_VIEWS_8616[name.lower()]
        for name, shape in project.arch.registers.items()
        if name.lower() in _GP_REGISTER_VIEWS_8616
        and len(shape) >= 2
        and shape[0] == offset
        and shape[1] == size
    }
    projections = frozenset(names.values())
    return next(iter(projections)) if len(projections) == 1 else None


def _runtime_gp_cvar_8616(
    register_name: str,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CVariable:
    """Build one explicit runtime-state C variable at its canonical width."""
    return structured_c.CVariable(
        SimMemoryVariable(
            _RUNTIME_GP_STATE_ADDRESSES_8616[register_name],
            4,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
            region=function_addr,
            category="inertia_gp_register_state",
        ),
        variable_type=_runtime_gp_lane_type_8616(source.codegen),
        codegen=source.codegen,
    )


def _runtime_gp_expr_8616(
    register_name: str,
    bit_shift: int,
    view_width: int,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    function_addr: int,
) -> structured_c.CExpression:
    """Build one coherent full-register state expression or narrow view."""
    parent = _runtime_gp_cvar_8616(register_name, source, function_addr)
    if view_width == 4:
        return parent
    projected: structured_c.CExpression = parent
    if bit_shift:
        projected = structured_c.CBinaryOp(
            "Shr",
            projected,
            structured_c.CConstant(
                bit_shift,
                _runtime_gp_lane_type_8616(source.codegen),
                codegen=source.codegen,
            ),
            codegen=source.codegen,
        )
    mask = (1 << (view_width * 8)) - 1
    return structured_c.CBinaryOp(
        "And",
        projected,
        structured_c.CConstant(
            mask,
            _runtime_gp_lane_type_8616(source.codegen),
            codegen=source.codegen,
        ),
        codegen=source.codegen,
    )


def _runtime_gp_parent_mask_8616(
    expression: structured_c.CExpression,
    parent_name: str,
    codegen: object,
) -> int | None:
    """Return the constant mask on one unshifted runtime GP parent."""
    mask = 0xFFFF_FFFF
    while isinstance(expression, structured_c.CTypeCast):
        expression = expression.expr
    while (
        isinstance(expression, structured_c.CBinaryOp)
        and expression.op == "And"
        and isinstance(expression.rhs, structured_c.CConstant)
        and isinstance(expression.rhs.value, int)
    ):
        mask &= expression.rhs.value
        expression = expression.lhs
        while isinstance(expression, structured_c.CTypeCast):
            expression = expression.expr
    if (
        isinstance(expression, structured_c.CVariable)
        and runtime_gp_name_for_variable_8616(expression.variable) == parent_name
    ):
        return mask
    if isinstance(expression, structured_c.CVariable) and isinstance(
        expression.variable,
        SimRegisterVariable,
    ):
        project = cast(_CodegenGPRegisters8616, codegen).project
        if project is None:
            return None
        projection = _register_projection_for_shape_8616(
            project,
            expression.variable.reg,
            expression.variable.size,
        )
        if projection is not None:
            projected_parent, projected_shift, projected_width = projection
            if projected_parent == parent_name and projected_shift == 0:
                return mask & ((1 << (projected_width * 8)) - 1)
    return None


def _runtime_gp_subview_write_8616(
    register_name: str,
    bit_shift: int,
    view_width: int,
    source: structured_c.CVariable | structured_c.CDirtyExpression,
    value: structured_c.CExpression,
    function_addr: int,
    *,
    tags: Mapping[str, object] | None = None,
) -> structured_c.CAssignment:
    """Project one narrow-register write while preserving its origin tags."""
    codegen = source.codegen
    _bind_gp_write_value_type_8616(codegen, value)
    # Byte-register writes consume the low byte of the pointer's offset word.
    projected = project_pointer_storage_value_8616(codegen, value, max(view_width, _POINTER_WORD_BYTES_8616))
    assert projected is not None
    value = projected
    lane_type = _runtime_gp_lane_type_8616(codegen)
    parent_lhs = _runtime_gp_cvar_8616(register_name, source, function_addr)
    parent_read = _runtime_gp_cvar_8616(register_name, source, function_addr)
    value_mask = (1 << (view_width * 8)) - 1
    preserve_mask = 0xFFFF_FFFF ^ (value_mask << bit_shift)
    self_mask = (
        _runtime_gp_parent_mask_8616(value, register_name, codegen)
        if bit_shift == 0
        else None
    )
    if self_mask is not None:
        combined_mask = preserve_mask | (self_mask & value_mask)
        return structured_c.CAssignment(
            parent_lhs,
            structured_c.CBinaryOp(
                "And",
                parent_read,
                structured_c.CConstant(combined_mask, lane_type, codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
            tags=tags,
        )
    preserved = structured_c.CBinaryOp(
        "And",
        parent_read,
        structured_c.CConstant(preserve_mask, lane_type, codegen=codegen),
        codegen=codegen,
    )
    inserted: structured_c.CExpression = structured_c.CBinaryOp(
        "And",
        value,
        structured_c.CConstant(value_mask, lane_type, codegen=codegen),
        codegen=codegen,
    )
    if bit_shift:
        inserted = structured_c.CBinaryOp(
            "Shl",
            inserted,
            structured_c.CConstant(bit_shift, lane_type, codegen=codegen),
            codegen=codegen,
        )
    return structured_c.CAssignment(
        parent_lhs,
        structured_c.CBinaryOp("Or", preserved, inserted, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )


def _addressed_gp_high_byte_view_8616(
    node: object,
    project: _ProjectGPRegisters8616,
) -> tuple[str, structured_c.CVariable] | None:
    """Recognize angr's ``*((byte *)&word_register + 1)`` high-byte view."""
    def strip_casts(candidate: object) -> object:
        """Remove representational casts from an angr address expression."""
        while isinstance(candidate, structured_c.CTypeCast):
            candidate = candidate.expr
        return candidate

    if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
        return None
    address = strip_casts(node.operand)
    if not isinstance(address, structured_c.CBinaryOp) or address.op != "Add":
        return None
    reference: structured_c.CUnaryOp | None = None
    displacement: structured_c.CConstant | None = None
    for candidate_reference, candidate_displacement in (
        (address.lhs, address.rhs),
        (address.rhs, address.lhs),
    ):
        candidate_reference = strip_casts(candidate_reference)
        candidate_displacement = strip_casts(candidate_displacement)
        if (
            isinstance(candidate_reference, structured_c.CUnaryOp)
            and candidate_reference.op in {"Reference", "AddressOf"}
            and isinstance(candidate_displacement, structured_c.CConstant)
            and candidate_displacement.value == 1
        ):
            reference = candidate_reference
            displacement = candidate_displacement
            break
    if reference is None or displacement is None:
        return None
    carrier = strip_casts(reference.operand)
    source: structured_c.CVariable | None = None
    if isinstance(carrier, structured_c.CVariable) and isinstance(
        carrier.variable,
        SimRegisterVariable,
    ):
        projection = _register_projection_for_shape_8616(
            project,
            carrier.variable.reg,
            carrier.variable.size,
        )
        if projection is None:
            return None
        register_name, bit_shift, view_width = projection
        source = carrier
    else:
        runtime_view = runtime_gp_expression_view_8616(carrier)
        if runtime_view is None:
            return None
        register_name = runtime_view.parent_name
        bit_shift = runtime_view.bit_shift
        view_width = runtime_view.width
        source = next(
            (
                candidate
                for candidate in (carrier, *_iter_c_nodes_deep_8616(carrier))
                if isinstance(candidate, structured_c.CVariable)
                and runtime_gp_name_for_variable_8616(candidate.variable) == register_name
            ),
            None,
        )
    if bit_shift != 0 or view_width not in {2, 4}:
        return None
    if source is None:
        return None
    return register_name, source


def runtime_gp_state_names_8616(codegen: object) -> frozenset[str]:
    """Return authoritative runtime lanes for both lowering and effect retention."""
    boundary = cast(_CodegenGPRegisters8616, codegen)
    cfunc = boundary.cfunc
    project = boundary.project
    if cfunc is None or project is None:
        return frozenset()
    resolution = registered_function_ssa_artifact_8616(project, cfunc.addr)
    live_ins: set[str] = set()
    if resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN and resolution.artifact is not None:
        live_ins.update(gp_live_in_names_from_ssa_8616(resolution.artifact))
    else:
        # Missing C assignments cannot contradict an authoritative SSA definition.
        live_ins.update(gp_live_in_names_from_c_ast_8616(cfunc.statements, project))
    state_owned_names = set(live_ins)
    state_owned_names.update(
        register_name
        for node in _iter_c_nodes_deep_8616(cfunc.statements)
        if isinstance(node, structured_c.CVariable)
        for register_name in (runtime_gp_name_for_variable_8616(node.variable),)
        if register_name is not None
    )
    return frozenset(state_owned_names)


def lower_architectural_gp_register_state_8616(codegen: object) -> bool:
    """Materialize SSA-proven GP live-ins as explicit runtime globals."""
    boundary = cast(_CodegenGPRegisters8616, codegen)
    cfunc = boundary.cfunc
    project = boundary.project
    if cfunc is None or project is None:
        boundary._inertia_gp_register_state_lowering_stats_8616 = GPRegisterStateLoweringStats8616(0, 0, 0, 0, 0)
        return False
    state_owned_names = runtime_gp_state_names_8616(codegen)
    raw_ids: set[int] = set()
    materialized_ids: set[int] = set()

    def transform(node: object) -> object:
        """Replace one exact live-in register carrier."""
        high_byte_view = _addressed_gp_high_byte_view_8616(node, project)
        if high_byte_view is not None:
            register_name, carrier = high_byte_view
            raw_ids.add(id(node))
            if register_name not in state_owned_names:
                return node
            materialized_ids.add(id(node))
            record_global_declaration_spec_8616(
                codegen,
                ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
                name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
                array_len=None,
            )
            return _runtime_gp_expr_8616(
                register_name,
                8,
                1,
                carrier,
                cfunc.addr,
            )
        if isinstance(node, structured_c.CAssignment):
            lhs = node.lhs
            lhs_projection: tuple[str, int, int] | None = None
            if isinstance(lhs, structured_c.CDirtyExpression):
                dirty = lhs.dirty
                if (
                    # Dynamic angr boundary: opaque dirty expressions may omit category.
                    getattr(dirty, "category", None) is VirtualVariableCategory.REGISTER
                    and isinstance(dirty.oident, int)
                    # Dynamic angr AIL boundary: compatibility nodes may omit size.
                    and isinstance(getattr(dirty, "size", None), int)
                ):
                    lhs_projection = _register_projection_for_shape_8616(
                        project,
                        dirty.oident,
                        cast(int, dirty.size),
                    )
            elif isinstance(lhs, structured_c.CVariable) and isinstance(
                lhs.variable,
                SimRegisterVariable,
            ):
                lhs_projection = _register_projection_for_shape_8616(
                    project,
                    lhs.variable.reg,
                    lhs.variable.size,
                )
            if lhs_projection is not None:
                register_name, bit_shift, view_width = lhs_projection
                if register_name in state_owned_names and view_width < 4:
                    raw_ids.add(id(lhs))
                    materialized_ids.add(id(lhs))
                    record_global_declaration_spec_8616(
                        codegen,
                        ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
                        name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
                        array_len=None,
                    )
                    return _runtime_gp_subview_write_8616(
                        register_name,
                        bit_shift,
                        view_width,
                        lhs,
                        node.rhs,
                        cfunc.addr,
                        tags=node.tags,
                    )
        projection: tuple[str, int, int] | None = None
        if isinstance(node, structured_c.CDirtyExpression):
            dirty = node.dirty
            # Dynamic angr boundary: opaque dirty expressions may omit category.
            if getattr(dirty, "category", None) is VirtualVariableCategory.REGISTER:
                offset = dirty.oident
                # Dynamic angr AIL boundary: compatibility nodes may omit size.
                size = getattr(dirty, "size", None)
                if isinstance(offset, int) and isinstance(size, int):
                    projection = _register_projection_for_shape_8616(project, offset, size)
        elif isinstance(node, structured_c.CVariable):
            variable = node.variable
            if isinstance(variable, SimRegisterVariable):
                projection = _register_projection_for_shape_8616(project, variable.reg, variable.size)
        if projection is None:
            return node
        register_name, bit_shift, view_width = projection
        raw_ids.add(id(node))
        if register_name not in state_owned_names:
            return node
        materialized_ids.add(id(node))
        record_global_declaration_spec_8616(
            codegen,
            ctype=GlobalDeclarationCType8616.UNSIGNED_LONG,
            name=_RUNTIME_GP_STATE_SYMBOLS_8616[register_name],
            array_len=None,
        )
        return _runtime_gp_expr_8616(
            register_name,
            bit_shift,
            view_width,
            cast(structured_c.CVariable | structured_c.CDirtyExpression, node),
            cfunc.addr,
        )

    root = cfunc.statements
    new_root = transform(root)
    changed = new_root is not root
    if changed:
        cfunc.statements = new_root
    if _replace_c_children_8616(cfunc.statements, transform):
        changed = True
    # Dynamic angr/codegen boundary adapters may omit the unified-local mapping.
    unified_local_vars = getattr(cfunc, "unified_local_vars", None)
    if isinstance(unified_local_vars, MutableMapping):
        for variable in tuple(unified_local_vars):
            if isinstance(variable, SimRegisterVariable):
                projection = _register_projection_for_shape_8616(project, variable.reg, variable.size)
                if projection is not None and projection[0] in state_owned_names:
                    del unified_local_vars[variable]
                    changed = True
    classified = len(materialized_ids)
    boundary._inertia_gp_register_state_lowering_stats_8616 = GPRegisterStateLoweringStats8616(
        raw_fact_count=len(raw_ids),
        normalized_fact_count=len(raw_ids),
        classified_fact_count=classified,
        materialized_count=classified,
        failure_count=0,
    )
    return changed
