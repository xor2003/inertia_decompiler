"""Materialize only binary-proven far callback Values at direct DOS callsites.

Layer: Types/Lowering.
Responsibility: consume exact IR Value, callee ABI, target-code, and typed CFG
proofs before changing a C call's argument or prototype. Separate BP word
stores are never claimed to be one four-byte Alias object or deleted here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import CExpression, CFunctionCall, CVariable
from angr.sim_type import SimTypeFunction, SimTypeShort
from angr.sim_variable import SimMemoryVariable

from ..analysis_helpers import CallTargetKind8616
from ..c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from ..callsite_summary import (
    CallsiteArgumentClass8616,
    CallsiteSummary8616,
    callsite_summary_inventory_8616,
    structured_callsite_addr_8616,
)
from ..codegen_metadata import append_codegen_sequence_attr
from ..ir.logical_memory_write_value import LogicalWordWriteValueArtifact8616, trace_logical_word_write_values_8616
from ..ir.ssa_function import SSAFunctionArtifact
from ..pipeline.errors import PipelineHardError
from ..structuring.call_argument_path_conditions import (
    CallArgumentPathConditionStatus8616,
    materialize_call_argument_typed_path_expression_8616,
)
from .binary_callback_targets import binary_function_pointer_parameter_evidence_8616
from .binary_far_callback_targets import BinaryFarCallbackTargetResult8616, prove_binary_far_callback_target_8616
from .callsite_prototype_seeding import physical_callsite_prototype_seed_8616
from .far_callback_call_value import FarCallbackPathValue8616, prove_far_callback_call_path_values_8616
from .far_pointer_type import SimTypeFarPointer16_8616
from .function_pointer_parameter_evidence import FunctionPointerParameterFact8616
from .function_pointer_parameters import _function_pointer_type_8616


class _CFunction8616(Protocol):
    """Structured function root carried by the third-party code generator."""

    addr: int
    statements: object


class _Codegen8616(Protocol):
    """Owned callsite projections and IR evidence consumed by this pass."""

    cfunc: _CFunction8616
    _inertia_raw_vex_ir_function_ssa_8616: SSAFunctionArtifact
    _inertia_callsite_summaries: dict[int, CallsiteSummary8616]
    _inertia_callsite_summary_inventory_8616: dict[int, CallsiteSummary8616]
    _inertia_callsite_prototype_decls: tuple[str, ...]
    _inertia_codegen_decl_refresh_required_8616: bool
    _inertia_far_callback_call_materialization_result_8616: FarCallbackCallMaterializationResult8616


class _MutableCallee8616(Protocol):
    """Writable guessed-prototype state on the third-party angr Function."""

    is_prototype_guessed: bool


class FarCallbackCallMaterializationDecision8616(StrEnum):
    """Typed outcome for one physically eligible direct far call."""

    MATERIALIZED = "materialized"
    ALREADY_MATERIALIZED = "already-materialized"
    VALUE_NOT_PROVEN = "value-not-proven"
    TARGET_NOT_PROVEN = "target-not-proven"
    CALL_NOT_UNIQUE = "call-not-unique"
    PROTOTYPE_CONFLICT = "prototype-conflict"
    CONDITION_NOT_PROVEN = "condition-not-proven"


@dataclass(frozen=True, slots=True)
class FarCallbackCallMaterializationResult8616:
    """Closed five-counter census of attempted far callback C calls."""

    decisions: tuple[FarCallbackCallMaterializationDecision8616, ...] = ()
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0
    changed: bool = False

    @property
    def closed(self) -> bool:
        """Reject unaccounted facts or classified-but-unmaterialized effects."""
        return bool(
            len(self.decisions) == self.raw_fact_count
            and self.raw_fact_count == self.materialized_count + self.failure_count
            and self.raw_fact_count >= self.normalized_fact_count >= self.classified_fact_count
            and self.classified_fact_count == self.materialized_count
            and self.changed == (FarCallbackCallMaterializationDecision8616.MATERIALIZED in self.decisions)
        )


@dataclass(frozen=True, slots=True)
class _PreparedCall8616:
    """All mutations staged only after the complete binary and CFG proof."""

    call: CFunctionCall
    summary: CallsiteSummary8616
    callback: CExpression
    scalar: CExpression
    prototype: SimTypeFunction
    target_declarations: tuple[str, ...]


def _candidate_8616(summary: CallsiteSummary8616) -> bool:
    """Count only the exact physical layout potentially carrying a far callback."""
    return bool(
        summary.kind is CallTargetKind8616.DIRECT_FAR_CALL
        and summary.target_addr is not None
        and summary.arg_widths == (2, 2, 2)
        and summary.stack_cleanup == 6
    )


def _unique_call_8616(codegen: _Codegen8616, summary: CallsiteSummary8616) -> CFunctionCall | None:
    """Select a unique typed AST call by exact instruction identity, never by name."""
    calls = tuple(
        node for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements)
        if isinstance(node, CFunctionCall)
        and structured_callsite_addr_8616(node) == summary.callsite_addr
    )
    if len(calls) != 1:
        return None
    call = calls[0]
    callee = call.callee_func
    arguments = call.args
    if callee is None or callee.addr != summary.target_addr:
        return None
    if arguments is None or len(arguments) not in (2, 3):
        return None
    return call if all(isinstance(argument, CExpression) for argument in arguments) else None


def _compatible_prototype_8616(
    project: object, call: CFunctionCall, summary: CallsiteSummary8616,
    pointer_type: SimTypeFarPointer16_8616,
) -> SimTypeFunction | None:
    """Replace only a guessed physical signature or preserve an exact logical one."""
    callee = call.callee_func
    if callee is None:
        return None
    current = callee.prototype
    if not isinstance(current, SimTypeFunction) or current.variadic:
        return None
    returnty = current.returnty
    if returnty is None or returnty.size != 16:
        return None
    args = tuple(current.args or ())
    if len(args) == 2:
        if args[0].size != 32 or args[1].size != 16:
            return None
        # Width alone does not prove the callback's pointee argument/return ABI.
        return current if type(args[0]) is type(pointer_type) and args[0] == pointer_type else None
    seed = physical_callsite_prototype_seed_8616(callee)
    if (
        len(args) != 3
        or any(arg.size != 16 for arg in args)
        or not (callee.is_prototype_guessed or (seed is not None and seed.matches(summary, current)))
    ):
        return None
    arch = cast(Any, project).arch
    logical_prototype = SimTypeFunction(
        [pointer_type, SimTypeShort(False).with_arch(arch)], returnty, variadic=False,
    )
    return cast(SimTypeFunction, logical_prototype.with_arch(arch))


def _compatible_far_interface_8616(
    project: object, call: CFunctionCall, summary: CallsiteSummary8616,
    callee_fact: FunctionPointerParameterFact8616,
) -> tuple[SimTypeFarPointer16_8616, SimTypeFunction] | None:
    """Require both the proven far pointer type and a compatible callee ABI."""
    pointer_type = _function_pointer_type_8616(callee_fact, cast(Any, project).arch)
    if not isinstance(pointer_type, SimTypeFarPointer16_8616):
        return None
    prototype = _compatible_prototype_8616(project, call, summary, pointer_type)
    if prototype is None:
        return None
    return pointer_type, prototype


def _prove_targets_8616(
    project: object,
    paths: tuple[FarCallbackPathValue8616, ...],
    callee_fact: FunctionPointerParameterFact8616,
) -> tuple[BinaryFarCallbackTargetResult8616, ...] | None:
    """Require closed code-entry evidence for every proven callback Value."""
    targets = tuple(
        prove_binary_far_callback_target_8616(
            project, segment=path.segment, offset=path.offset, parameter_fact=callee_fact,
        )
        for path in paths
    )
    return targets if all(target.complete and target.proof is not None for target in targets) else None


def _target_leaves_8616(
    codegen: _Codegen8616,
    paths: tuple[FarCallbackPathValue8616, ...],
    targets: tuple[BinaryFarCallbackTargetResult8616, ...],
    pointer_type: SimTypeFarPointer16_8616,
) -> tuple[dict[int, CExpression], tuple[str, ...]] | None:
    """Create typed function-symbol leaves only for distinct proven paths."""
    leaves: dict[int, CExpression] = {}
    names: set[str] = set()
    for path, target in zip(paths, targets, strict=True):
        target_proof = target.proof
        assert target_proof is not None
        if path.source_block_addr is None or path.source_block_addr in leaves:
            return None
        leaves[path.source_block_addr] = CVariable(
            SimMemoryVariable(
                target_proof.addr, 4, name=target_proof.name,
                region=codegen.cfunc.addr,
            ),
            variable_type=pointer_type, codegen=codegen,
        )
        names.add(target_proof.name)
    return leaves, tuple(sorted(names))


def _callback_expression_8616(
    project: object, codegen: _Codegen8616, summary: CallsiteSummary8616,
    leaves: dict[int, CExpression],
) -> CExpression | None:
    """Select one proven Value on every call-executing predecessor path."""
    if len(leaves) == 1:
        callback = next(iter(leaves.values()))
    else:
        condition = materialize_call_argument_typed_path_expression_8616(
            project, codegen, summary, leaves,
        )
        if condition.status is not CallArgumentPathConditionStatus8616.MATERIALIZED or len(condition.expressions) != 1:
            return None
        callback = condition.expressions[0]
    return callback if callback.type is not None and callback.type.size == 32 else None


def _target_function_declaration_8616(prototype: SimTypeFunction, name: str) -> str:
    """Render a direct forward declaration from the proven pointee type."""
    if prototype.returnty is None or prototype.variadic:
        raise PipelineHardError("far callback target declaration lacks a fixed return ABI")
    arguments = ", ".join(arg.c_repr() for arg in prototype.args or ()) or "void"
    return f"{prototype.returnty.c_repr()} {name}({arguments});"


def _prepared_decision_8616(
    codegen: _Codegen8616, call: CFunctionCall, summary: CallsiteSummary8616,
    callback: CExpression, declarations: tuple[str, ...],
) -> FarCallbackCallMaterializationDecision8616:
    """Identify an exact prior publication without weakening current proofs."""
    already = bool(
        len(call.args) == 2
        and _same_c_expression_8616(call.args[0], callback)
        and summary.logical_arg_widths == (4, 2)
        and all(decl in codegen._inertia_callsite_prototype_decls for decl in declarations)
    )
    if already:
        return FarCallbackCallMaterializationDecision8616.ALREADY_MATERIALIZED
    return FarCallbackCallMaterializationDecision8616.MATERIALIZED


def _prepare_call_8616(
    project: object, codegen: _Codegen8616, summary: CallsiteSummary8616,
    writes: LogicalWordWriteValueArtifact8616,
) -> tuple[_PreparedCall8616 | None, FarCallbackCallMaterializationDecision8616, int]:
    """Stage one call without mutating it until every independent proof closes."""
    callee_addr = summary.target_addr
    assert callee_addr is not None
    classified = binary_function_pointer_parameter_evidence_8616(project, callee_addr)
    if classified is None:
        return None, FarCallbackCallMaterializationDecision8616.VALUE_NOT_PROVEN, 0
    callee_fact, indirect_calls = classified
    value = prove_far_callback_call_path_values_8616(
        codegen._inertia_raw_vex_ir_function_ssa_8616, writes, summary,
        callee_fact=callee_fact, callee_indirect_calls=indirect_calls,
    )
    if not value.closed or value.proof is None:
        return None, FarCallbackCallMaterializationDecision8616.VALUE_NOT_PROVEN, 1
    paths = value.proof.paths
    target_proofs = _prove_targets_8616(project, paths, callee_fact)
    if target_proofs is None:
        return None, FarCallbackCallMaterializationDecision8616.TARGET_NOT_PROVEN, 1
    call = _unique_call_8616(codegen, summary)
    if call is None:
        return None, FarCallbackCallMaterializationDecision8616.CALL_NOT_UNIQUE, 1
    compatible = _compatible_far_interface_8616(project, call, summary, callee_fact)
    if compatible is None:
        return None, FarCallbackCallMaterializationDecision8616.PROTOTYPE_CONFLICT, 1
    pointer_type, prototype = compatible
    target_leaves = _target_leaves_8616(codegen, paths, target_proofs, pointer_type)
    if target_leaves is None:
        return None, FarCallbackCallMaterializationDecision8616.CONDITION_NOT_PROVEN, 1
    path_leaves, target_names = target_leaves
    callback = _callback_expression_8616(project, codegen, summary, path_leaves)
    if callback is None:
        return None, FarCallbackCallMaterializationDecision8616.CONDITION_NOT_PROVEN, 1
    scalar = call.args[-1]
    if scalar.type is None or scalar.type.size != 16:
        return None, FarCallbackCallMaterializationDecision8616.VALUE_NOT_PROVEN, 1
    pointee = pointer_type.pts_to
    if not isinstance(pointee, SimTypeFunction):
        raise PipelineHardError("far callback pointer has no function prototype")
    declarations = tuple(
        _target_function_declaration_8616(pointee, name) for name in target_names
    )
    decision = _prepared_decision_8616(codegen, call, summary, callback, declarations)
    return _PreparedCall8616(call, summary, callback, scalar, prototype, declarations), decision, 1


def _publish_prepared_call_8616(codegen: _Codegen8616, prepared: _PreparedCall8616) -> None:
    """Commit all coherent C and typed-callsite projections after proof closure."""
    summary = prepared.summary
    updated = replace(
        summary, logical_arg_widths=(4, 2),
        logical_arg_classes=(CallsiteArgumentClass8616.POINTER, CallsiteArgumentClass8616.VALUE),
    )
    if summary.logical_arg_widths not in ((), summary.arg_widths, updated.logical_arg_widths):
        raise PipelineHardError("far callback logical call shape conflicts with existing evidence")
    callee = prepared.call.callee_func
    if callee is None:
        raise PipelineHardError("far callback call lost its proven callee before publication")
    prepared.call.args = [prepared.callback, prepared.scalar]
    callee.prototype = prepared.prototype
    cast(_MutableCallee8616, callee).is_prototype_guessed = False
    codegen._inertia_callsite_summary_inventory_8616[summary.callsite_addr] = updated
    for node_id, current in tuple(codegen._inertia_callsite_summaries.items()):
        if current.callsite_addr == summary.callsite_addr:
            codegen._inertia_callsite_summaries[node_id] = updated
    append_codegen_sequence_attr(
        codegen, codegen.cfunc, "_inertia_callsite_prototype_decls",
        prepared.target_declarations,
    )
    codegen._inertia_codegen_decl_refresh_required_8616 = True


def materialize_binary_far_callback_calls_8616(
    project: object, codegen_raw: object,
) -> FarCallbackCallMaterializationResult8616:
    """Group proven offset and segment Values into typed C callback arguments.

    This pass preserves each original word store; any eventual dead-store
    removal must independently prove that no live read or validation effect is
    lost. Refused candidates leave arguments, prototypes, and summaries intact.
    """
    codegen = cast(_Codegen8616, codegen_raw)
    inventory = callsite_summary_inventory_8616(codegen)
    try:
        artifact = codegen._inertia_raw_vex_ir_function_ssa_8616
    except AttributeError:
        result = FarCallbackCallMaterializationResult8616()
        codegen._inertia_far_callback_call_materialization_result_8616 = result
        return result
    if not isinstance(artifact, SSAFunctionArtifact):
        raise TypeError("far callback materialization requires typed caller SSA")
    candidates = tuple(summary for summary in inventory.values() if _candidate_8616(summary))
    if not candidates:
        result = FarCallbackCallMaterializationResult8616()
        codegen._inertia_far_callback_call_materialization_result_8616 = result
        return result
    writes = trace_logical_word_write_values_8616(artifact)
    decisions: list[FarCallbackCallMaterializationDecision8616] = []
    normalized = 0
    materialized = 0
    for summary in candidates:
        prepared, decision, normalized_delta = _prepare_call_8616(project, codegen, summary, writes)
        decisions.append(decision)
        normalized += normalized_delta
        if prepared is None:
            continue
        if decision is FarCallbackCallMaterializationDecision8616.MATERIALIZED:
            _publish_prepared_call_8616(codegen, prepared)
        materialized += 1
    result = FarCallbackCallMaterializationResult8616(
        decisions=tuple(decisions), raw_fact_count=len(candidates),
        normalized_fact_count=normalized, classified_fact_count=materialized,
        materialized_count=materialized, failure_count=len(candidates) - materialized,
        changed=FarCallbackCallMaterializationDecision8616.MATERIALIZED in decisions,
    )
    if not result.closed:
        raise PipelineHardError("far callback materialization evidence census did not close")
    codegen._inertia_far_callback_call_materialization_result_8616 = result
    return result


__all__ = [
    "FarCallbackCallMaterializationDecision8616",
    "FarCallbackCallMaterializationResult8616",
    "materialize_binary_far_callback_calls_8616",
]
