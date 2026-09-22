"""Recover stack parameters used as indirect near-call targets.

Layer: Types/Lowering.
Responsibility: consume typed binary callsite summaries and persist exact
positive-BP function-pointer parameter types across structured-C regeneration.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import replace
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import (
    SimType,
    SimTypeChar,
    SimTypeFunction,
    SimTypeLong,
    SimTypeShort,
)
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from ..callsite_summary import CallsiteSummary8616
from ..pipeline.errors import PipelineHardError
from .argument_frame_base import proven_first_argument_machine_bp_offset_8616
from .callee_global_object_type_surface import cfunc_roots_8616
from .function_pointer_parameter_evidence import (
    FunctionPointerParameterEvidence8616,
    FunctionPointerParameterFact8616,
    FunctionPointerParameterFailure8616,
    collect_function_pointer_parameter_evidence_8616,
)
from .near_pointer_type import SimTypeNearPointer16_8616, near_pointer_type_8616
from .stack_prototype_layout import (
    stack_prototype_argument_layout_8616,
    stack_prototype_cvar_for_machine_bp_range_8616,
)
from .stack_storage_evidence import proven_bp_entry_sp_delta_8616

log: logging.Logger = logging.getLogger(__name__)


class _VariableManager8616(Protocol):
    """angr variable-manager type surface at the third-party boundary."""

    def set_variable_type(
        self,
        variable: object,
        type_: SimType,
        *,
        name: str | None = None,
        override_bot: bool = True,
        all_unified: bool = False,
    ) -> None:
        """Persist one exact variable type across codegen regeneration."""


class _CFunction8616(Protocol):
    """angr CFunction fields consumed by parameter type materialization."""

    addr: int
    arg_list: Sequence[object]
    functy: SimTypeFunction
    variable_manager: _VariableManager8616


class _Function8616(Protocol):
    """angr function prototype retained across regeneration."""

    prototype: object
    is_prototype_guessed: bool


class _FunctionManager8616(Protocol):
    """angr function lookup surface."""

    def function(self, *, addr: int, create: bool = False) -> _Function8616 | None:
        """Return one existing function without guessing a contract."""


class _KnowledgeBase8616(Protocol):
    """angr knowledge-base surface required by this lowering."""

    functions: _FunctionManager8616


class _Project8616(Protocol):
    """Project fields required by function-pointer parameter lowering."""

    arch: Arch
    kb: _KnowledgeBase8616


class _Codegen8616(Protocol):
    """Owned evidence state attached to the dynamic angr codegen boundary."""

    cfunc: _CFunction8616 | None
    project: _Project8616
    _inertia_callsite_summaries: object
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_function_pointer_parameter_evidence_8616: FunctionPointerParameterEvidence8616


def _integer_type_8616(width: int, arch: Arch) -> SimType:
    """Build one unsigned scalar type from an exact binary width."""
    if width == 1:
        type_: SimType = SimTypeChar(signed=False)
    elif width == 2:
        type_ = SimTypeShort(signed=False)
    else:
        type_ = SimTypeLong(signed=False)
    return cast(SimType, type_.with_arch(arch))


def _function_pointer_type_8616(
    fact: FunctionPointerParameterFact8616,
    arch: Arch,
) -> SimTypeNearPointer16_8616:
    """Build a near function-pointer type from one classified binary fact."""
    prototype = SimTypeFunction(
        [_integer_type_8616(width, arch) for width in fact.argument_widths],
        _integer_type_8616(fact.return_width, arch),
        variadic=False,
    ).with_arch(arch)
    return near_pointer_type_8616(cast(SimType, prototype), arch)


def _typed_summary_values_8616(codegen: _Codegen8616) -> tuple[CallsiteSummary8616, ...]:
    """Read typed summaries across the dynamic angr codegen boundary."""
    summary_map = codegen._inertia_callsite_summaries
    if not isinstance(summary_map, Mapping):
        return ()
    return tuple(
        summary
        for key, summary in summary_map.items()
        if isinstance(key, int) and isinstance(summary, CallsiteSummary8616)
    )


def _debug_parameter_surface_8616(
    codegen: _Codegen8616,
    cfunc: _CFunction8616,
    evidence: FunctionPointerParameterEvidence8616,
) -> None:
    """Report the typed ABI surface only when explicit diagnostics are enabled."""
    if not os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_PARAMETERS"):
        return
    layout: list[tuple[int, int | None, int | None, str | None]] = []
    for index, argument in enumerate(cfunc.arg_list):
        if isinstance(argument, CVariable) and isinstance(argument.variable, SimStackVariable):
            layout.append(
                (
                    index,
                    argument.variable.offset,
                    argument.variable.size,
                    argument.variable.base,
                )
            )
        else:
            layout.append((index, None, None, None))
    prototype_count = (
        len(tuple(cfunc.functy.args or ()))
        if isinstance(cfunc.functy, SimTypeFunction)
        else None
    )
    log.warning(
        "[function-pointer-parameters] function=%#x facts=%r prototype_count=%r bp_delta=%r arg_layout=%r",
        cfunc.addr,
        tuple(fact.stack_offset for fact in evidence.facts),
        prototype_count,
        proven_bp_entry_sp_delta_8616(codegen),
        tuple(layout),
    )


def _stack_argument_at_offset_8616(
    codegen: _Codegen8616,
    cfunc: _CFunction8616,
    offset: int,
    storage_width: int,
) -> tuple[int, CVariable] | None:
    """Resolve one machine-BP slot through the authoritative frame layout."""
    layout = stack_prototype_argument_layout_8616(
        cfunc.functy,
        codegen.project.arch,
        first_argument_bp_offset=proven_first_argument_machine_bp_offset_8616(codegen),
    )
    slots = tuple(
        (index, slot)
        for index, slot in enumerate(layout)
        if slot.offset == offset and slot.storage_width == storage_width
    )
    if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_PARAMETERS"):
        log.warning(
            "[function-pointer-parameters] resolve offset=%d width=%d layout=%r slot_count=%d",
            offset,
            storage_width,
            tuple((slot.offset, slot.storage_width) for slot in layout),
            len(slots),
        )
    if len(slots) != 1:
        return None
    argument = stack_prototype_cvar_for_machine_bp_range_8616(
        codegen,
        offset,
        storage_width,
    )
    if os.environ.get("INERTIA_DEBUG_FUNCTION_POINTER_PARAMETERS"):
        log.warning("[function-pointer-parameters] resolve cvar=%s", argument is not None)
    if argument is None:
        return None
    return slots[0][0], argument


def _replace_prototype_argument_8616(
    prototype: SimTypeFunction,
    index: int,
    argument_type: SimType,
    arch: Arch,
) -> SimTypeFunction:
    """Return a prototype with one exact argument type replaced."""
    args = list(prototype.args or ())
    if index >= len(args):
        return prototype
    args[index] = argument_type
    return cast(
        SimTypeFunction,
        SimTypeFunction(
            args,
            prototype.returnty,
            arg_names=tuple(prototype.arg_names or ()),
            variadic=prototype.variadic,
        ).with_arch(arch),
    )


def _materialize_fact_8616(
    project: _Project8616,
    codegen: _Codegen8616,
    cfunc: _CFunction8616,
    fact: FunctionPointerParameterFact8616,
) -> tuple[bool, FunctionPointerParameterFailure8616 | None]:
    """Persist one classified fact to the argument, AST, manager, and prototypes."""
    if not isinstance(cfunc.functy, SimTypeFunction):
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    prototype_args = tuple(cfunc.functy.args or ())
    pointer_type = _function_pointer_type_8616(fact, project.arch)
    try:
        pointer_bits = pointer_type.size
    except ValueError:
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    byte_width = project.arch.byte_width
    if (
        not isinstance(pointer_bits, int)
        or not isinstance(byte_width, int)
        or byte_width <= 0
        or pointer_bits <= 0
        or pointer_bits % byte_width != 0
    ):
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    pointer_storage_width = max(2, ((pointer_bits // byte_width) + 1) & ~1)
    matched = _stack_argument_at_offset_8616(
        codegen,
        cfunc,
        fact.stack_offset,
        pointer_storage_width,
    )
    if matched is None:
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    index, argument = matched
    if index >= len(prototype_args):
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    if not isinstance(argument.variable, SimStackVariable):
        return False, FunctionPointerParameterFailure8616.PARAMETER_SLOT_MISSING
    argument_offset = argument.variable.offset
    try:
        cfunc.variable_manager.set_variable_type(
            argument.variable,
            pointer_type,
            override_bot=True,
            all_unified=True,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False, FunctionPointerParameterFailure8616.VARIABLE_MANAGER_REJECTED
    changed = argument.variable_type != pointer_type
    argument.variable_type = pointer_type

    new_cfunc_type = _replace_prototype_argument_8616(cfunc.functy, index, pointer_type, project.arch)
    if new_cfunc_type != cfunc.functy:
        cfunc.functy = new_cfunc_type
        changed = True
    for root in cfunc_roots_8616(cfunc):
        for node in _iter_c_nodes_deep_8616(root):
            if (
                isinstance(node, CVariable)
                and isinstance(node.variable, SimStackVariable)
                and node.variable.offset == argument_offset
                and node.variable.base == "bp"
                and node.variable_type != pointer_type
            ):
                node.variable_type = pointer_type
                changed = True

    function = project.kb.functions.function(addr=cfunc.addr, create=False)
    if function is not None and isinstance(function.prototype, SimTypeFunction):
        new_function_type = _replace_prototype_argument_8616(
            function.prototype,
            index,
            pointer_type,
            project.arch,
        )
        if new_function_type != function.prototype:
            function.prototype = new_function_type
            changed = True
        function.is_prototype_guessed = False
    return changed, None


def materialize_function_pointer_parameters_8616(project_raw: object, codegen_raw: object) -> bool:
    """Persist all consistent BP-indirect call target parameter types."""
    project = cast(_Project8616, project_raw)
    codegen = cast(_Codegen8616, codegen_raw)
    try:
        cfunc = codegen.cfunc
        summaries = _typed_summary_values_8616(codegen)
    except AttributeError:
        return False
    evidence = collect_function_pointer_parameter_evidence_8616(summaries)
    if cfunc is None or not evidence.facts:
        codegen._inertia_function_pointer_parameter_evidence_8616 = evidence
        return False
    _debug_parameter_surface_8616(codegen, cfunc, evidence)

    changed = False
    materialized_count = 0
    failures = list(evidence.failures)
    for fact in evidence.facts:
        fact_changed, failure = _materialize_fact_8616(project, codegen, cfunc, fact)
        if failure is not None:
            failures.append(failure)
            continue
        materialized_count += 1
        changed = fact_changed or changed
    evidence = replace(
        evidence,
        materialized_count=materialized_count,
        failure_count=len(failures),
        failures=tuple(failures),
    )
    codegen._inertia_function_pointer_parameter_evidence_8616 = evidence
    if evidence.classified_fact_count > 0 and evidence.materialized_count == 0:
        raise PipelineHardError(
            "function-pointer parameter facts were classified but not materialized "
            f"at {cfunc.addr:#x}; failures={tuple(failure.value for failure in evidence.failures)!r}"
        )
    if changed:
        codegen._inertia_codegen_decl_refresh_required_8616 = True
    return changed


__all__ = [
    "FunctionPointerParameterEvidence8616",
    "FunctionPointerParameterFact8616",
    "FunctionPointerParameterFailure8616",
    "collect_function_pointer_parameter_evidence_8616",
    "materialize_function_pointer_parameters_8616",
]
