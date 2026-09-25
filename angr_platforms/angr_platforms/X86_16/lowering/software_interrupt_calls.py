"""Materialize typed software-interrupt inputs in structured C calls.

Layer: Types/Lowering.
Responsibility: consume Semantics-owned interrupt input facts and map exact
constants, stack variables, and value operations to C arguments. No register
recovery, disassembly parsing, source metadata, or rendered-C matching belongs
here.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from ..c_ast_utils import _clone_c_ast_tree_8616, _iter_c_nodes_deep_8616
from ..codegen_metadata import get_codegen_side_metadata
from ..interrupt_contract import (
    DOS_SERVICE_BASE_ADDR,
    INTERRUPT_SERVICE_BASE_ADDR,
    interrupt_vector_from_core_addr_8616,
    software_interrupt_service_fact_8616,
    software_interrupt_service_target_8616,
)
from ..ir.core import IRBinaryValue, IRFunctionArtifact, IRValue, MemSpace
from ..pipeline.errors import PipelineHardError
from ..semantics.software_interrupt_inputs import (
    IRScalarValue8616,
    SoftwareInterruptInputArtifact8616,
    SoftwareInterruptInputFact8616,
    build_software_interrupt_input_artifact_8616,
    software_interrupt_value_fingerprint_8616,
)
from ..structured_tags import copy_structured_tags_8616
from .gp_register_state import runtime_gp_expression_view_8616

__all__ = [
    "SoftwareInterruptMaterializationStats8616",
    "SoftwareInterruptTargetMaterializationStats8616",
    "materialize_software_interrupt_calls_8616",
    "materialize_software_interrupt_service_targets_8616",
    "select_software_interrupt_call_8616",
]


@dataclass(slots=True)
class SoftwareInterruptMaterializationStats8616:
    """Closed evidence counters for interrupt call argument lowering."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(slots=True)
class SoftwareInterruptTargetMaterializationStats8616:
    """Closed evidence counters for exact interrupt service targets."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


class _CFunctionSurface8616(Protocol):
    """Third-party C function fields consumed by interrupt lowering."""

    addr: int
    statements: object
    arg_list: object


class _ArchSurface8616(Protocol):
    """Architecture fields needed to lower exact register inputs."""

    registers: dict[str, tuple[int, int]]


class _ProjectSurface8616(Protocol):
    """Project fields needed to lower exact register inputs."""

    arch: _ArchSurface8616
    kb: _KnowledgeBaseSurface8616


class _FunctionCallTargetSurface8616(Protocol):
    """Third-party function callsite mapping consumed by Lowering."""

    def get_call_target(self, callsite_addr: int) -> int | None:
        """Return the target assigned to one exact machine callsite."""


class _FunctionManagerSurface8616(Protocol):
    """Third-party function manager lookup consumed by Lowering."""

    def function(self, *, addr: int) -> _FunctionCallTargetSurface8616 | None:
        """Return the function at one exact address."""


class _KnowledgeBaseSurface8616(Protocol):
    """Third-party knowledge-base function surface consumed by Lowering."""

    functions: _FunctionManagerSurface8616


class _CodegenSurface8616(Protocol):
    """Codegen fields carrying typed IR and interrupt facts."""

    cfunc: _CFunctionSurface8616
    project: _ProjectSurface8616
    _inertia_vex_ir_artifact: IRFunctionArtifact
    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616


class _TaggedCallSurface8616(Protocol):
    """Third-party structured call fields used at the Lowering boundary."""

    tags: object
    args: object
    callee_target: object


class _CVariableSurface8616(Protocol):
    """Third-party C variable storage field."""

    variable: object


def _callsite_addr_8616(call: structured_c.CFunctionCall) -> int | None:
    """Return the exact instruction address tagged on a structured call."""
    try:
        tags = cast(_TaggedCallSurface8616, call).tags
    except AttributeError:
        return None
    owned_tags = copy_structured_tags_8616(tags)
    if owned_tags is None:
        return None
    value = owned_tags.get("ins_addr")
    return value if isinstance(value, int) else None


def _raw_interrupt_vector_8616(call: structured_c.CFunctionCall) -> int | None:
    """Decode the raw lifted interrupt vector from one structured call."""
    target = cast(_TaggedCallSurface8616, call).callee_target
    if isinstance(target, structured_c.CConstant):
        target = target.value
    return interrupt_vector_from_core_addr_8616(target) if isinstance(target, int) else None


def _service_target_matches_vector_8616(target_addr: int, vector: int) -> bool:
    """Validate a service target against its raw interrupt vector."""
    if vector == 0x21:
        selector = target_addr - int(DOS_SERVICE_BASE_ADDR)
        return bool(0 <= selector <= 0xFF)
    return bool(target_addr == int(INTERRUPT_SERVICE_BASE_ADDR) + vector)


def _interrupt_context_8616(
    surface: _CodegenSurface8616,
) -> tuple[object, int, _FunctionCallTargetSurface8616] | None:
    """Resolve the root and owning function's callsite target surface."""
    try:
        root = surface.cfunc.statements
        function_addr = surface.cfunc.addr
        function_manager = surface.project.kb.functions
        function = function_manager.function(addr=function_addr)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    if function is None:
        return None
    return root, function_addr, function


def _proven_service_target_8616(
    surface: _CodegenSurface8616,
    function: _FunctionCallTargetSurface8616,
    *,
    function_addr: int,
    callsite_addr: int,
    vector: int,
) -> int | None:
    """Resolve an exact service target from callsite or project evidence."""
    try:
        target_addr = function.get_call_target(callsite_addr)
    except (AttributeError, KeyError, TypeError, ValueError):
        target_addr = None
    if not isinstance(target_addr, int) or not _service_target_matches_vector_8616(
        target_addr,
        vector,
    ):
        target_addr = software_interrupt_service_target_8616(
            surface.project,
            function_addr=function_addr,
            callsite_addr=callsite_addr,
            vector=vector,
        )
    if not isinstance(target_addr, int) or not _service_target_matches_vector_8616(
        target_addr,
        vector,
    ):
        return None
    return target_addr


def _materialize_service_target_8616(
    surface: _CodegenSurface8616,
    node: object,
    *,
    function: _FunctionCallTargetSurface8616,
    function_addr: int,
    stats: SoftwareInterruptTargetMaterializationStats8616,
) -> bool:
    """Rewrite one interrupt call to its proven service target."""
    if not isinstance(node, structured_c.CFunctionCall):
        return False
    vector = _raw_interrupt_vector_8616(node)
    if vector is None:
        return False
    stats.raw_fact_count += 1
    callsite_addr = _callsite_addr_8616(node)
    if callsite_addr is None:
        return False
    stats.normalized_fact_count += 1
    target_addr = _proven_service_target_8616(
        surface,
        function,
        function_addr=function_addr,
        callsite_addr=callsite_addr,
        vector=vector,
    )
    if target_addr is None:
        return False
    stats.classified_fact_count += 1
    service_fact = software_interrupt_service_fact_8616(
        surface.project,
        function_addr=function_addr,
        callsite_addr=callsite_addr,
        vector=vector,
    )
    cast(_TaggedCallSurface8616, node).callee_target = (
        service_fact.helper_name
        if service_fact is not None and service_fact.target_addr == target_addr
        else target_addr
    )
    stats.materialized_count += 1
    return True


def materialize_software_interrupt_service_targets_8616(
    codegen: object,
) -> bool:
    """Project exact frontend callsite service identities into structured C."""
    surface = cast(_CodegenSurface8616, codegen)
    stats = SoftwareInterruptTargetMaterializationStats8616()
    context = _interrupt_context_8616(surface)
    if context is None:
        get_codegen_side_metadata(codegen)["software_interrupt_target_materialization_8616"] = stats
        return False
    root, function_addr, function = context
    changed = False
    for node in _iter_c_nodes_deep_8616(root):
        if _materialize_service_target_8616(
            surface,
            node,
            function=function,
            function_addr=function_addr,
            stats=stats,
        ):
            changed = True
    get_codegen_side_metadata(codegen)["software_interrupt_target_materialization_8616"] = stats
    if stats.classified_fact_count != stats.materialized_count:
        stats.failure_count = stats.classified_fact_count - stats.materialized_count
        raise PipelineHardError(
            "classified software interrupt service targets were not materialized",
            layer="lowering",
        )
    return changed


def _stack_variable_8616(node: object) -> SimStackVariable | None:
    """Return exact stack storage from one C variable expression."""
    if not isinstance(node, structured_c.CVariable):
        return None
    try:
        variable = cast(_CVariableSurface8616, node).variable
    except AttributeError:
        return None
    return variable if isinstance(variable, SimStackVariable) else None


def _candidate_stack_cvars_8616(
    codegen: _CodegenSurface8616,
    root: object,
) -> tuple[structured_c.CVariable, ...]:
    """Collect deterministic C variable candidates from arguments and body."""
    candidates: list[structured_c.CVariable] = []
    seen: set[int] = set()
    arg_list = codegen.cfunc.arg_list
    sources: list[object] = []
    if isinstance(arg_list, Sequence) and not isinstance(arg_list, (str, bytes)):
        sources.extend(arg_list)
    sources.extend(_iter_c_nodes_deep_8616(root))
    for node in sources:
        if not isinstance(node, structured_c.CVariable) or id(node) in seen:
            continue
        seen.add(id(node))
        candidates.append(node)
    return tuple(candidates)


def _stack_cvar_for_value_8616(
    value: IRValue,
    candidates: tuple[structured_c.CVariable, ...],
    codegen: object,
) -> structured_c.CVariable | None:
    """Resolve or rematerialize an exact Semantics-proven SS stack value."""
    if value.space is not MemSpace.SS or value.name not in {"bp", "sp"}:
        return None
    for candidate in candidates:
        variable = _stack_variable_8616(candidate)
        if variable is None:
            continue
        if variable.offset == value.offset and variable.size == value.size:
            return cast(structured_c.CVariable, _clone_c_ast_tree_8616(candidate))
    surface = cast(_CodegenSurface8616, codegen)
    try:
        region = surface.cfunc.addr
    except AttributeError:
        region = None
    is_argument = value.name == "bp" and value.offset >= 4
    name = f"arg_{value.offset:x}" if is_argument else f"local_{abs(value.offset):x}"
    variable = SimStackVariable(
        value.offset,
        value.size,
        base=value.name,
        name=name,
        region=region,
    )
    return structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _lower_value_8616(
    value: IRScalarValue8616,
    codegen: object,
    candidates: tuple[structured_c.CVariable, ...],
) -> structured_c.CExpression | None:
    """Lower one typed interrupt argument without rediscovering semantics."""
    if isinstance(value, IRBinaryValue):
        lhs = _lower_value_8616(value.lhs, codegen, candidates)
        rhs = _lower_value_8616(value.rhs, codegen, candidates)
        if lhs is None or rhs is None:
            return None
        return structured_c.CBinaryOp(value.op, lhs, rhs, codegen=codegen)
    if value.space is MemSpace.CONST and value.const is not None:
        value_type = {
            1: SimTypeChar(False),
            2: SimTypeShort(False),
        }.get(value.size)
        if value_type is None:
            return None
        return structured_c.CConstant(value.const, value_type, codegen=codegen)
    if value.space is MemSpace.REG and value.name is not None and value.size in {1, 2}:
        arch = cast(_CodegenSurface8616, codegen).project.arch
        register = arch.registers.get(value.name.lower())
        if not isinstance(register, tuple) or not register or not isinstance(register[0], int):
            return None
        value_type = SimTypeChar(False) if value.size == 1 else SimTypeShort(False)
        variable = SimRegisterVariable(register[0], value.size, name=value.name.lower())
        return structured_c.CVariable(variable, variable_type=value_type, codegen=codegen)
    return _stack_cvar_for_value_8616(value, candidates, codegen)


def _actual_value_fingerprint_8616(node: object) -> str | None:
    """Fingerprint the final C subset emitted from interrupt input facts."""
    gp_view = runtime_gp_expression_view_8616(node)
    if gp_view is not None:
        return f"reg:{gp_view.register_name}:size{gp_view.width}"
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        if isinstance(node.type, SimTypeChar):
            size = 1
        elif isinstance(node.type, SimTypeShort):
            size = 2
        else:
            return None
        return f"const:{node.value:#x}:size{size}"
    if isinstance(node, structured_c.CVariable):
        variable = _stack_variable_8616(node)
        if variable is not None:
            return f"stack:SS:BP{variable.offset:+#x}:size{variable.size}"
        raw_variable = cast(_CVariableSurface8616, node).variable
        if isinstance(raw_variable, SimRegisterVariable) and isinstance(raw_variable.name, str):
            return f"reg:{raw_variable.name.lower()}:size{raw_variable.size}"
        return None
    if isinstance(node, structured_c.CBinaryOp):
        lhs = _actual_value_fingerprint_8616(node.lhs)
        rhs = _actual_value_fingerprint_8616(node.rhs)
        if lhs is None or rhs is None:
            return None
        size = 2
        return f"{node.op}({lhs},{rhs}):size{size}"
    return None


def _call_has_expected_arguments_8616(
    call: structured_c.CFunctionCall,
    fact: SoftwareInterruptInputFact8616,
) -> bool:
    """Return whether final call arguments match all proven input values."""
    args = cast(_TaggedCallSurface8616, call).args
    if not isinstance(args, Sequence) or isinstance(args, (str, bytes)):
        return False
    actual = tuple(_actual_value_fingerprint_8616(arg) for arg in args)
    expected = tuple(
        software_interrupt_value_fingerprint_8616(value)
        for value in fact.argument_values
    )
    return actual == expected


def _call_targets_fact_8616(
    call: structured_c.CFunctionCall,
    fact: SoftwareInterruptInputFact8616,
) -> bool:
    """Return whether a call retains the exact typed interrupt core target."""
    target = cast(_TaggedCallSurface8616, call).callee_target
    if isinstance(target, int):
        return bool(target == fact.target_addr)
    return (
        isinstance(target, structured_c.CConstant)
        and isinstance(target.value, int)
        and target.value == fact.target_addr
    )


def select_software_interrupt_call_8616(
    calls: tuple[structured_c.CFunctionCall, ...],
    fact: SoftwareInterruptInputFact8616,
) -> structured_c.CFunctionCall | None:
    """Select one service call without confusing same-address status helpers."""
    callsite_calls = tuple(
        call for call in calls if _callsite_addr_8616(call) == fact.callsite_addr
    )
    materialized = tuple(
        call for call in callsite_calls if _call_has_expected_arguments_8616(call, fact)
    )
    if len(materialized) == 1:
        return materialized[0]
    targeted = tuple(
        call for call in callsite_calls if _call_targets_fact_8616(call, fact)
    )
    if len(targeted) == 1:
        return targeted[0]
    return callsite_calls[0] if len(callsite_calls) == 1 else None


def _materialize_fact_8616(
    codegen: _CodegenSurface8616,
    root: object,
    fact: SoftwareInterruptInputFact8616,
    candidates: tuple[structured_c.CVariable, ...],
) -> tuple[bool, bool]:
    """Materialize one exact fact and report success plus AST change."""
    calls = tuple(
        node
        for node in _iter_c_nodes_deep_8616(root)
        if isinstance(node, structured_c.CFunctionCall)
    )
    call = select_software_interrupt_call_8616(calls, fact)
    if call is None:
        return False, False
    if _call_has_expected_arguments_8616(call, fact):
        return True, False
    arguments = tuple(
        _lower_value_8616(value, codegen, candidates)
        for value in fact.argument_values
    )
    if any(argument is None for argument in arguments):
        return False, False
    cast(_TaggedCallSurface8616, call).args = [
        cast(structured_c.CExpression, argument) for argument in arguments
    ]
    return _call_has_expected_arguments_8616(call, fact), True


def materialize_software_interrupt_calls_8616(codegen: object) -> bool:
    """Attach Semantics facts and materialize every classified interrupt call."""
    surface = cast(_CodegenSurface8616, codegen)
    try:
        ir_artifact = surface._inertia_vex_ir_artifact
        root = surface.cfunc.statements
    except AttributeError:
        return False
    target_changed = materialize_software_interrupt_service_targets_8616(codegen)
    artifact = build_software_interrupt_input_artifact_8616(ir_artifact)
    surface._inertia_software_interrupt_input_artifact_8616 = artifact
    stats = SoftwareInterruptMaterializationStats8616(
        raw_fact_count=artifact.stats.raw_fact_count,
        normalized_fact_count=artifact.stats.normalized_fact_count,
        classified_fact_count=artifact.stats.classified_fact_count,
        failure_count=artifact.stats.failure_count,
    )
    candidates = _candidate_stack_cvars_8616(surface, root)
    changed = False
    for fact in artifact.facts:
        materialized, fact_changed = _materialize_fact_8616(surface, root, fact, candidates)
        if materialized:
            stats.materialized_count += 1
        else:
            stats.failure_count += 1
        changed = fact_changed or changed
    get_codegen_side_metadata(codegen)["software_interrupt_materialization_8616"] = stats
    if stats.failure_count > 0 or stats.classified_fact_count != stats.materialized_count:
        raise PipelineHardError(
            "classified software interrupt inputs were not materialized",
            layer="lowering",
        )
    return changed or target_changed
