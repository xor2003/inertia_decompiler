"""Layer: Frontend/runtime.

Responsibility: install runtime compatibility patches needed before x86-16 decompilation.
Forbidden: recovering alias, type, or validation semantics through compatibility hooks.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any, Protocol, cast

from angr import ailment
from angr.analyses.decompiler.clinic import Clinic
from angr.knowledge_plugins.functions.function import Function, PrototypeSource

from .ail_displacement_compat import apply_register_displacement_compatibility_8616
from .call_frame_compat import apply_call_frame_compatibility_8616
from .codegen_parentheses import apply_codegen_parentheses_8616
from .patch_dirty import apply_patch as _apply_dirty_patch
from .stack_anchor_compat import apply_native_stack_anchor_compatibility_8616
from .stack_compat import apply_x86_16_stack_compatibility as _apply_stack_compatibility
from .typehoon_compat import apply_x86_16_typehoon_compatibility as _apply_typehoon_compatibility

__all__ = ["apply_x86_16_compatibility"]


class _AilBlockStatements8616(Protocol):
    """Mutable statement sequence shared by Python and Rust AIL blocks."""

    statements: list[object]


class _AilConstantValue8616(Protocol):
    """Constant payload read only after the backend's Const class check."""

    value: object


class _AilDirtyExpression8616(Protocol):
    """Decoded dirty-helper fields needed to preserve an OUT side effect."""

    callee: str
    operands: Sequence[object]
    idx: int | None
    tags: Mapping[str, object]


class _AilDirtyStatement8616(Protocol):
    """Dirty-statement fields shared by the supported AIL backends."""

    dirty: _AilDirtyExpression8616
    idx: int | None
    tags: Mapping[str, object]


class _ClinicArchBoundary8616(Protocol):
    """Third-party architecture identity required by the Clinic guard."""

    name: str


class _ClinicProjectBoundary8616(Protocol):
    """Third-party project surface required by the Clinic guard."""

    arch: _ClinicArchBoundary8616


class _ClinicBoundary8616(Protocol):
    """Third-party Clinic surface required by the custom-lifter guard."""

    project: _ClinicProjectBoundary8616


def _normalize_x86_16_io_dirty_statements(
    block: object,
) -> tuple[object, int, int, int, int]:
    """Convert typed OUT Dirty statements into ordinary AIL side-effect calls."""
    if not isinstance(block, ailment.Block):
        return block, 0, 0, 0, 0
    ail_block = cast(_AilBlockStatements8616, block)
    raw_fact_count = 0
    normalized_fact_count = 0
    materialized_count = 0
    failure_count = 0
    statements: list[object] = []
    helper_by_width = {
        8: "inertia_io_out8",
        16: "inertia_io_out16",
        32: "inertia_io_out32",
    }
    for statement in ail_block.statements:
        if not isinstance(statement, ailment.Stmt.DirtyStatement):
            statements.append(statement)
            continue
        dirty_statement = cast(_AilDirtyStatement8616, statement)
        dirty = dirty_statement.dirty
        if dirty.callee != "x86g_dirtyhelper_OUT":
            statements.append(statement)
            continue
        raw_fact_count += 1
        operands = tuple(dirty.operands)
        width_value = (
            cast(_AilConstantValue8616, operands[-1]).value
            if len(operands) == 3 and isinstance(operands[-1], ailment.Expr.Const) else None
        )
        width = width_value if isinstance(width_value, int) else None
        helper = helper_by_width.get(width) if width is not None else None
        if helper is None:
            failure_count += 1
            statements.append(statement)
            continue
        normalized_fact_count += 1
        call = ailment.Expr.Call(
            dirty.idx,
            helper,
            args=operands[:2],
            bits=0,
            **dict(dirty.tags),
        )
        statements.append(
            ailment.Stmt.SideEffectStatement(
                dirty_statement.idx,
                call,
                **dict(dirty_statement.tags),
            )
        )
        materialized_count += 1
    ail_block.statements = statements
    return block, raw_fact_count, normalized_fact_count, materialized_count, failure_count


def _apply_function_prototype_source_compatibility() -> None:
    """Restore the writable guessed-prototype view over angr's source enum."""
    guessed_property = Function.is_prototype_guessed
    if guessed_property.fset is not None:
        return

    def _set_is_prototype_guessed(function: Function, guessed: bool) -> None:
        """Translate the legacy boolean assignment into typed prototype provenance."""
        if guessed:
            function.prototype_source = PrototypeSource.GUESSED
        elif function.prototype_source in {
            PrototypeSource.NONE,
            PrototypeSource.GUESSED,
            PrototypeSource.CCA_LOW,
        }:
            function.prototype_source = PrototypeSource.USER

    function_type = cast(Any, Function)
    function_type.is_prototype_guessed = property(
        guessed_property.fget,
        _set_is_prototype_guessed,
        guessed_property.fdel,
        guessed_property.__doc__,
    )


def _apply_clinic_custom_lifter_compatibility() -> None:
    """Keep Clinic's native fast relift from bypassing the x86-16 lifter.

    Dynamic boundary: marker attributes belong to third-party angr methods
    whose compatibility wrappers must remain idempotent across imports.
    """
    current = cast(Callable[[_ClinicBoundary8616, object], object | None], Clinic._convert_vex_fast)
    if getattr(current, "_inertia_x86_16_custom_lifter_guard", False):
        return

    def _convert_vex_fast_with_custom_lifter_guard(
        clinic: _ClinicBoundary8616,
        block: object,
    ) -> object | None:
        """Use cached custom VEX for x86-16 and retain angr's fast path otherwise."""
        if clinic.project.arch.name == "86_16":
            return None
        return current(clinic, block)

    guarded = cast(Any, _convert_vex_fast_with_custom_lifter_guard)
    guarded._inertia_x86_16_custom_lifter_guard = True
    Clinic._convert_vex_fast = guarded

    current_convert = cast(Callable[[_ClinicBoundary8616, object], object], Clinic._convert_vex)
    if getattr(current_convert, "_inertia_x86_16_io_dirty_normalizer", False):
        return

    def _convert_vex_with_io_normalization(
        clinic: _ClinicBoundary8616,
        block: object,
    ) -> object:
        """Materialize x86-16 port writes immediately after VEX-to-AIL conversion."""
        converted = current_convert(clinic, block)
        if clinic.project.arch.name != "86_16":
            return converted
        converted, raw, _normalized, materialized, failures = _normalize_x86_16_io_dirty_statements(converted)
        if raw > 0 and materialized == 0:
            msg = f"x86-16 I/O effects were not materialized: raw={raw} failures={failures}"
            raise TypeError(msg)
        return converted

    convert_guarded = cast(Any, _convert_vex_with_io_normalization)
    convert_guarded._inertia_x86_16_io_dirty_normalizer = True
    Clinic._convert_vex = convert_guarded


def apply_x86_16_compatibility() -> None:
    """Install all frontend/runtime compatibility patches for x86-16 support."""
    _apply_function_prototype_source_compatibility()
    _apply_clinic_custom_lifter_compatibility()
    apply_call_frame_compatibility_8616()
    apply_register_displacement_compatibility_8616()
    apply_codegen_parentheses_8616()
    _apply_stack_compatibility()
    apply_native_stack_anchor_compatibility_8616()
    _apply_typehoon_compatibility()
    _apply_dirty_patch()
