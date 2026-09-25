"""Materialize stack-argument signedness from proven condition evidence.

Layer: Types/lowering.
Responsibility: join typed ConditionIR operands with widened stack arguments and
materialize their scalar signedness on angr C-AST and prototype surfaces.

Structuring may record a CFG-proven wide ``ConditionIR`` here, but it must not
mutate types. This module consumes those typed facts. It never infers from
rendered C, function names, sidecars, or compiler-specific sample identities.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CIndexedVariable, CVariable
from angr.sim_type import SimType, SimTypeChar, SimTypeFunction, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from archinfo import Arch

from ..c_ast_utils import _iter_c_nodes_deep_8616
from .authoritative_function_prototypes import publish_codegen_function_prototype_8616
from .condition_argument_type_facts import (
    StackArgumentSignedness8616,
    StackArgumentTypeFact8616,
    collect_condition_argument_type_facts_8616,
    record_wide_condition_argument_type_evidence_8616,
)
from .semantic_cast import CSemanticCast8616
from .stack_variable_coordinates import machine_bp_offset_for_stack_variable_8616

__all__ = [
    "ConditionArgumentTypeResult8616",
    "ConditionArgumentTypeStats8616",
    "StackArgumentSignedness8616",
    "apply_condition_argument_types_8616",
    "record_wide_condition_argument_type_evidence_8616",
]


class _ProjectSurface8616(Protocol):
    """Third-party project fields used at the type materialization boundary."""

    arch: Arch
    kb: object


class _CodegenSurface8616(Protocol):
    """Dynamic codegen fields consumed and produced by this Lowering owner."""

    cfunc: object
    _inertia_condition_argument_type_result_8616: ConditionArgumentTypeResult8616


class _CFunctionSurface8616(Protocol):
    """angr CFunction fields updated by stack-argument type materialization."""

    addr: int
    arg_list: tuple[object, ...] | list[object]
    body: object
    statements: object
    functy: object
    variables_in_use: object
    unified_local_vars: object


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base function manager boundary."""

    functions: _FunctionManagerSurface8616


class _FunctionManagerSurface8616(Protocol):
    """Third-party function lookup used to synchronize prototypes."""

    def function(self, *, addr: int, create: bool) -> _FunctionSurface8616 | None:
        """Return one existing function without creating it."""


class _FunctionSurface8616(Protocol):
    """Third-party function prototype synchronized after materialization."""

    prototype: object


@dataclass(frozen=True, slots=True)
class ConditionArgumentTypeStats8616:
    """Evidence accounting for condition-derived argument type materialization."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class ConditionArgumentTypeResult8616:
    """Result of one condition-derived argument type pass."""

    changed: bool
    changed_offsets: tuple[int, ...]
    stats: ConditionArgumentTypeStats8616


def _scalar_width_8616(type_: object) -> int:
    """Return the byte width of one scalar angr type, or zero when unsupported."""
    if isinstance(type_, SimTypeChar):
        return 1
    if isinstance(type_, SimTypeShort):
        return 2
    if isinstance(type_, SimTypeLong):
        return 4
    return 0


def _scalar_type_8616(
    arch: Arch,
    width: int,
    signedness: StackArgumentSignedness8616,
) -> SimType | None:
    """Build the width-preserving scalar type represented by one proof."""
    signed = signedness is StackArgumentSignedness8616.SIGNED
    type_: SimType
    if width == 1:
        type_ = SimTypeChar(signed=signed)
    elif width == 2:
        type_ = SimTypeShort(signed=signed)
    elif width == 4:
        type_ = SimTypeLong(signed=signed)
    else:
        return None
    return type_.with_arch(arch)


def _argument_cvars_8616(
    codegen: object,
    cfunc: _CFunctionSurface8616,
) -> tuple[CVariable, ...]:
    """Return canonical positive-BP argument variables in emitted order."""
    try:
        args = tuple(cfunc.arg_list or ())
    except AttributeError:
        return ()
    arguments: list[CVariable] = []
    for arg in args:
        if not isinstance(arg, CVariable) or not isinstance(arg.variable, SimStackVariable):
            continue
        bp_offset = machine_bp_offset_for_stack_variable_8616(codegen, arg.variable)
        if arg.variable.base == "bp" and isinstance(bp_offset, int) and bp_offset >= 4:
            arguments.append(arg)
    return tuple(arguments)


def _preserve_argument_index_views_8616(
    codegen: object, roots: list[object], offset: int, width: int, type_: SimType,
) -> None:
    """Keep existing integer index semantics before changing shared declarations."""
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if not isinstance(node, CIndexedVariable) or not isinstance(node.index, CVariable):
                continue
            index = node.index
            variable = index.variable
            previous = index.variable_type
            if not isinstance(variable, SimStackVariable) or variable.base != "bp":
                continue
            matching_storage = (
                variable.size == width
                and machine_bp_offset_for_stack_variable_8616(codegen, variable) == offset
                and _scalar_width_8616(previous) == width
            )
            if matching_storage and previous != type_:
                node.index = CSemanticCast8616(type_, previous, index, codegen=index.codegen)


def _set_argument_surface_type_8616(
    codegen: object,
    cfunc: _CFunctionSurface8616,
    offset: int,
    width: int,
    type_: SimType,
) -> int:
    """Apply one type to matching CVariable and unified-local surfaces."""
    changed = 0
    roots: list[object] = [cfunc]
    with contextlib.suppress(AttributeError):
        roots.append(cfunc.statements)
    with contextlib.suppress(AttributeError):
        roots.append(cfunc.body)
    _preserve_argument_index_views_8616(codegen, roots, offset, width, type_)
    seen: set[int] = set()
    for root in roots:
        for node in _iter_c_nodes_deep_8616(root):
            if id(node) in seen or not isinstance(node, CVariable):
                continue
            seen.add(id(node))
            variable = node.variable
            if not isinstance(variable, SimStackVariable) or variable.base != "bp":
                continue
            if (
                machine_bp_offset_for_stack_variable_8616(codegen, variable) != offset
                or _scalar_width_8616(node.variable_type) != width
            ):
                continue
            if node.variable_type != type_:
                node.variable_type = type_
                changed += 1
    return changed


def _desired_argument_signedness_8616(
    codegen: object,
    arguments: tuple[CVariable, ...],
    facts: tuple[StackArgumentTypeFact8616, ...],
) -> tuple[dict[int, tuple[int, StackArgumentSignedness8616]], int]:
    """Census one unambiguous signedness proof per BP argument offset."""
    desired: dict[int, tuple[int, StackArgumentSignedness8616]] = {}
    failures = 0
    for argument in arguments:
        variable = cast(SimStackVariable, argument.variable)
        base = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if not isinstance(base, int):
            failures += 1
            continue
        width = _scalar_width_8616(argument.variable_type)
        matches = {
            fact.signedness
            for fact in facts
            if width > 0
            and base <= fact.offset
            and fact.offset + fact.size <= base + width
        }
        if len(matches) == 1:
            desired[base] = (width, matches.pop())
        elif len(matches) > 1:
            failures += 1
    return desired, failures


def _apply_desired_types_8616(
    codegen: object,
    cfunc: _CFunctionSurface8616,
    arch: object,
    arguments: tuple[CVariable, ...],
    desired: dict[int, tuple[int, StackArgumentSignedness8616]],
    new_args: list[SimType],
) -> tuple[list[int], int, int]:
    """Apply each desired signedness to the surface and prototype args."""
    changed_offsets: list[int] = []
    materialized = 0
    failures = 0
    for index, argument in enumerate(arguments):
        variable = cast(SimStackVariable, argument.variable)
        base = machine_bp_offset_for_stack_variable_8616(codegen, variable)
        if not isinstance(base, int):
            failures += 1
            continue
        requested = desired.get(base)
        if requested is None or index >= len(new_args):
            continue
        width, signedness = requested
        type_ = _scalar_type_8616(arch, width, signedness)
        if type_ is None:
            failures += 1
            continue
        _set_argument_surface_type_8616(codegen, cfunc, base, width, type_)
        argument.variable_type = type_
        new_args[index] = type_
        changed_offsets.append(base)
        materialized += 1
    return changed_offsets, materialized, failures


def apply_condition_argument_types_8616(
    project: object,
    codegen: object,
) -> ConditionArgumentTypeResult8616:
    """Materialize condition-proven signedness on logical stack arguments."""
    project_surface = cast(_ProjectSurface8616, project)
    codegen_surface = cast(_CodegenSurface8616, codegen)
    try:
        cfunc = cast(_CFunctionSurface8616, codegen_surface.cfunc)
        arch = project_surface.arch
    except AttributeError:
        result = ConditionArgumentTypeResult8616(False, (), ConditionArgumentTypeStats8616(failure_count=1))
        codegen_surface._inertia_condition_argument_type_result_8616 = result
        return result
    fact_result = collect_condition_argument_type_facts_8616(codegen)
    facts = fact_result.facts
    raw_count = fact_result.raw_fact_count
    failures = fact_result.failure_count
    arguments = _argument_cvars_8616(codegen, cfunc)
    desired, census_failures = _desired_argument_signedness_8616(
        codegen, arguments, facts
    )
    failures += census_failures
    function: _FunctionSurface8616 | None = None
    try:
        knowledge_base = cast(_KnowledgeBaseSurface8616, project_surface.kb)
        function = knowledge_base.functions.function(addr=cfunc.addr, create=False)
    except AttributeError:
        pass
    prototype = cfunc.functy
    if not isinstance(prototype, SimTypeFunction) and function is not None:
        prototype = function.prototype
    if not isinstance(prototype, SimTypeFunction):
        result = ConditionArgumentTypeResult8616(
            False,
            (),
            ConditionArgumentTypeStats8616(raw_count, len(facts), len(desired), 0, failures + bool(desired)),
        )
        codegen_surface._inertia_condition_argument_type_result_8616 = result
        return result
    new_args = list(prototype.args)
    changed_offsets, materialized, apply_failures = _apply_desired_types_8616(
        codegen,
        cfunc,
        arch,
        arguments,
        desired,
        new_args,
    )
    failures += apply_failures
    changed = new_args != list(prototype.args)
    if changed:
        rebuilt = SimTypeFunction(
            new_args,
            prototype.returnty,
            arg_names=prototype.arg_names,
            variadic=prototype.variadic,
        ).with_arch(arch)
        cfunc.functy = rebuilt
        if function is not None:
            function.prototype = rebuilt
        publish_codegen_function_prototype_8616(project, codegen)
    result = ConditionArgumentTypeResult8616(
        changed,
        tuple(sorted(changed_offsets)),
        ConditionArgumentTypeStats8616(raw_count, len(facts), len(desired), materialized, failures),
    )
    codegen_surface._inertia_condition_argument_type_result_8616 = result
    return result
