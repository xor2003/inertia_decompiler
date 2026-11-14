# cython: language_level=3, infer_types=True
"""Lower typed unobserved call-result carriers to standalone calls.

Layer: Types/Lowering.
Responsibility: consume exact callsite return-use evidence and remove only the
register assignment that stores a proven-clobbered call result while retaining
the call and all of its observable effects.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.

This owner does not infer liveness from rendered C, helper names, source/COD
metadata, or variable names. Unknown or used return classifications are kept.
Stack-probe helpers remain owned by ``fixed_stack_probe_frames`` because their
call itself may become redundant after fixed-frame recovery.
"""

from __future__ import annotations
import typing
import cython

from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CStatements,
    CUnaryOp,
)
from angr.sim_type import SimType, SimTypeBottom

from inertia.lowering.analysis_helpers import (
    InterruptServiceResultKind8616,
    collect_interrupt_service_calls,
    interrupt_service_addr,
    interrupt_service_result_kind_at_addr_8616,
)
from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.pipeline.errors import PipelineHardError
from inertia.semantics.caller_return_use_contracts import CallsiteReturnUseKind8616
from inertia.semantics.callsite_summary import CallsiteSummary8616, structured_callsite_addr_8616
from inertia.semantics.software_interrupt_inputs import SoftwareInterruptInputArtifact8616

from .callsite_prototype_declarations import (
    CallsiteCResultContract8616,
    CallsiteCResultKind8616,
)
from .gp_register_state import runtime_gp_expression_view_8616
from .physical_registers import physical_register_view_8616
from .structured_intrinsics import (
    is_structured_insert_intrinsic_8616,
    lower_structured_insert_call_8616,
)
import dataclasses
import operator
import builtins

__all__ = (
    "UnobservedCallResultLoweringStats8616",
    "lower_unobserved_call_result_assignments_8616",
)


class _UnobservedResultCFunction8616(Protocol):
    """Minimal third-party generated C function surface."""

    statements: object


class _UnobservedResultCodegen8616(Protocol):
    """Dynamic angr codegen fields consumed by this lowering owner."""

    cfunc: _UnobservedResultCFunction8616
    project: object
    _inertia_callsite_summaries: object
    _inertia_callsite_c_result_contracts_8616: object
    _inertia_software_interrupt_input_artifact_8616: SoftwareInterruptInputArtifact8616
    _inertia_unobserved_call_result_lowering_stats_8616: UnobservedCallResultLoweringStats8616


@dataclasses.dataclass(frozen=True, )
class UnobservedCallResultLoweringStats8616:
    """Closed evidence census for unobserved call-result lowering."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong

    @property
    def changed(self) -> cython.bint:
        """Return whether at least one dead result assignment was lowered."""
        return self.materialized_count > 0

    @property
    def closed(self) -> cython.bint:
        """Return whether every classified result was materialized or failed."""
        return bool(
            0 <= self.classified_fact_count <= self.normalized_fact_count <= self.raw_fact_count
            and operator.eq(self.classified_fact_count, self.materialized_count + self.failure_count)
        )


@cython.ccall
def _typed_summary_map_8616(codegen: _UnobservedResultCodegen8616) -> dict[cython.longlong, CallsiteSummary8616]:
    """Narrow dynamic codegen metadata to owned typed callsite summaries."""
    raw = codegen._inertia_callsite_summaries
    if not isinstance(raw, dict):
        return {}
    return {
        node_id: summary
        for node_id, summary in builtins.iter(raw.items())
        if isinstance(node_id, int) and isinstance(summary, CallsiteSummary8616)
    }


@cython.ccall
def _typed_c_result_contract_map_8616(
    codegen: _UnobservedResultCodegen8616,
) -> dict[cython.longlong, CallsiteCResultContract8616]:
    """Narrow final declaration contracts to their owned typed mapping."""
    try:
        raw = codegen._inertia_callsite_c_result_contracts_8616
    except AttributeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {
        callsite_addr: contract
        for callsite_addr, contract in builtins.iter(raw.items())
        if isinstance(callsite_addr, int) and isinstance(contract, CallsiteCResultContract8616)
    }


@cython.ccall
def _c_result_contract_for_call_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
    contracts: object,
) -> CallsiteCResultContract8616 | None:
    """Resolve a final C result contract by stable active or original callsite identity."""
    callsite_addr: object
    contract: object
    callsite_addr = structured_callsite_addr_8616(call)
    if callsite_addr is None:
        return None
    contract = contracts.get(callsite_addr)
    if contract is not None:
        return contract
    try:
        original_delta = cast(Any, codegen.project)._inertia_original_linear_delta
    except AttributeError:
        return None
    if not isinstance(original_delta, int):
        return None
    return contracts.get(callsite_addr + original_delta)


@cython.ccall
def _is_proven_unobserved_ax_result_8616(
    assignment: CAssignment,
    summary: CallsiteSummary8616,
) -> cython.bint:
    """Classify an exact AX-family result assignment from typed binary facts."""
    view: object
    if summary.stack_probe_helper:
        return False
    if summary.return_used is not False or summary.return_use_kind not in {
        None,
        CallsiteReturnUseKind8616.CLOBBERED,
    }:
        return False
    if summary.return_register not in {None, "ax", "eax"}:
        return False
    view = physical_register_view_8616(assignment.lhs)
    return view is not None and view.reg_offset == 0 and view.width in {2, 4}


@dataclasses.dataclass(frozen=True, )
class _ProjectedCallResult8616:
    """One call effect and any independent value retained by its projection."""

    call: CFunctionCall
    residual: object | None = None


def _insert_projection_without_call_result_8616(
    node: CFunctionCall,
) -> _ProjectedCallResult8616 | None:
    """Split an Insert whose base call result is proven disposable later."""
    residual: object
    if not is_structured_insert_intrinsic_8616(node):
        return None
    raw_args = node.args
    if not isinstance(raw_args, (list, tuple)) or len(raw_args) != 3:
        return None
    base, offset, value = raw_args
    if not isinstance(base, CFunctionCall):
        return None
    if any(
        isinstance(candidate, CFunctionCall)
        for operand in iter((offset, value))
        for candidate in iter((operand, ) + tuple(_iter_c_nodes_deep_8616(operand)))
    ):
        return None
    base_type = base.type
    if not isinstance(base_type, SimType):
        return None
    zero_base = CConstant(0, base_type, codegen=node.codegen)
    residual_insert = CFunctionCall(
        node.callee_target,
        node.callee_func,
        [zero_base, offset, value],
        tags=node.tags,
        codegen=node.codegen,
    )
    residual = lower_structured_insert_call_8616(residual_insert)
    if residual is None:
        return None
    return _ProjectedCallResult8616(base, residual)


@cython.ccall
def _projected_call_result_8616(node: object) -> _ProjectedCallResult8616 | None:
    """Return the sole call in an exact generated result projection."""
    if isinstance(node, CFunctionCall):
        if is_structured_insert_intrinsic_8616(node):
            return _insert_projection_without_call_result_8616(node)
        return _ProjectedCallResult8616(node)
    if isinstance(node, CUnaryOp) and node.op in {"Dereference", "Reference"}:
        return _projected_call_result_8616(node.operand)
    if isinstance(node, CBinaryOp) and node.op in {"Add", "Sub"}:
        if isinstance(node.rhs, CConstant) and node.rhs.value == 1:
            return _projected_call_result_8616(node.lhs)
        if node.op == "Add" and isinstance(node.lhs, CConstant) and node.lhs.value == 1:
            return _projected_call_result_8616(node.rhs)
    return None


@cython.ccall
def _masked_subregister_call_result_8616(
    assignment: CAssignment,
) -> _ProjectedCallResult8616 | None:
    """Recognize an exact preserved-carrier OR masked-call projection."""
    projection: object
    preserved: object
    projected: object
    rhs = assignment.rhs
    if not isinstance(rhs, CBinaryOp) or rhs.op != "Or":
        return None
    for preserved, projected in ((rhs.lhs, rhs.rhs), (rhs.rhs, rhs.lhs)):
        projection = _masked_orientation_8616(assignment, preserved, projected)
        if projection is not None:
            return projection
    return None


@cython.ccall
def _masked_orientation_8616(
    assignment: CAssignment,
    preserved: object,
    projected: object,
) -> _ProjectedCallResult8616 | None:
    """Prove one preserved/projected operand orientation of an Or-mask."""
    destination_view: object
    projection: object
    runtime_destination_view: object
    if not isinstance(preserved, CBinaryOp) or preserved.op != "And":
        return None
    if not isinstance(projected, CBinaryOp) or projected.op != "And":
        return None
    preserved_parts = (
        (preserved.lhs, preserved.rhs)
        if isinstance(preserved.rhs, CConstant)
        else (preserved.rhs, preserved.lhs)
    )
    projected_parts = (
        (projected.lhs, projected.rhs)
        if isinstance(projected.rhs, CConstant)
        else (projected.rhs, projected.lhs)
    )
    preserved_value, preserved_mask = preserved_parts
    projected_value, projected_mask = projected_parts
    if not isinstance(preserved_mask, CConstant) or not isinstance(projected_mask, CConstant):
        return None
    projection = _projected_call_result_8616(projected_value)
    if projection is None or projection.residual is not None:
        return None
    destination_view = physical_register_view_8616(assignment.lhs)
    preserved_view = physical_register_view_8616(preserved_value)
    runtime_destination_view = runtime_gp_expression_view_8616(assignment.lhs)
    runtime_preserved_view = runtime_gp_expression_view_8616(preserved_value)
    if not (
        (destination_view is not None and operator.eq(preserved_view, destination_view))
        or (
            runtime_destination_view is not None
            and operator.eq(runtime_preserved_view, runtime_destination_view)
        )
    ):
        return None
    if destination_view is not None:
        destination_width = destination_view.width
    elif runtime_destination_view is not None:
        destination_width = runtime_destination_view.width
    else:
        return None
    full_mask = (1 << (destination_width * 8)) - 1
    preserved_bits = int(preserved_mask.value) & full_mask
    projected_bits = int(projected_mask.value) & full_mask
    if preserved_bits & projected_bits:
        return None
    if operator.ne(preserved_bits | projected_bits, full_mask):
        return None
    return projection


@cython.ccall
def _is_proven_unobserved_projected_result_8616(summary: CallsiteSummary8616) -> cython.bint:
    """Classify a generated call projection from closed caller-use evidence."""
    return bool(
        not summary.stack_probe_helper
        and summary.return_used is False
        and summary.return_use_kind in {None, CallsiteReturnUseKind8616.CLOBBERED}
        and summary.return_register in {None, "ax", "eax"}
    )


@cython.ccall
def _is_typed_void_call_8616(call: CFunctionCall) -> cython.bint:
    """Return whether the structured call carries an explicit void contract."""
    try:
        return_type = call.prototype_returnty
    except (AttributeError, TypeError):
        return False
    return isinstance(return_type, SimTypeBottom) and return_type.label == "void"


def _has_proven_void_interrupt_result_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
) -> cython.bint:
    """Return whether Semantics proves this exact interrupt has no register result."""
    callsite_addr: object
    callsite_addr = structured_callsite_addr_8616(call)
    if callsite_addr is None:
        return False
    try:
        artifact = codegen._inertia_software_interrupt_input_artifact_8616
    except AttributeError:
        return False
    if not isinstance(artifact, SoftwareInterruptInputArtifact8616):
        return False
    matches = tuple(fact for fact in iter(artifact.facts) if operator.eq(fact.callsite_addr, callsite_addr))
    return len(matches) == 1 and matches[0].result_register is None


def _has_typed_void_interrupt_target_8616(
    codegen: _UnobservedResultCodegen8616,
    call: CFunctionCall,
) -> cython.bint:
    """Return whether exact synthetic interrupt identity has a typed void result."""
    cfg_kind: object
    direct_kind: object
    callee = call.callee_func
    try:
        target_addr = cast(Any, callee).addr
    except AttributeError:
        target_addr = None
    if isinstance(target_addr, int):
        direct_kind = interrupt_service_result_kind_at_addr_8616(target_addr)
        if direct_kind is not None:
            return direct_kind is InterruptServiceResultKind8616.VOID
    callsite_addr = structured_callsite_addr_8616(call)
    try:
        function_addr = cast(Any, codegen.cfunc).addr
        functions = cast(Any, codegen.project).kb.functions
        function = functions.function(addr=function_addr, create=False)
        target_addr = function.get_call_target(callsite_addr)
    except (AttributeError, KeyError, TypeError):
        return False
    if isinstance(target_addr, int):
        cfg_kind = interrupt_service_result_kind_at_addr_8616(target_addr)
        if cfg_kind is not None:
            return cfg_kind is InterruptServiceResultKind8616.VOID
    matches = tuple(
        recovered
        for recovered in builtins.iter(collect_interrupt_service_calls(function))
        if operator.eq(recovered.insn_addr, callsite_addr)
    )
    return len(matches) == 1 and (
        interrupt_service_result_kind_at_addr_8616(interrupt_service_addr(matches[0]))
        is InterruptServiceResultKind8616.VOID
    )


@cython.dataclasses.dataclass()
class _UnobservedLowerScan8616:
    """Mutable per-statement scan state for unobserved call-result lowering."""

    boundary: _UnobservedResultCodegen8616
    summaries: object
    c_result_contracts: object
    seen_assignments: object = field(default_factory=set)
    raw_fact_count: cython.longlong = 0
    normalized_fact_count: cython.longlong = 0
    classified_fact_count: cython.longlong = 0
    materialized_count: cython.longlong = 0

    @cython.ccall
    def process_container(self, container: CStatements) -> None:
        """Rewrite proven assignments inside one statement container."""
        replacement: object
        index: object
        statement: object
        statements: list[object] = list(container.statements or ())
        changed = False
        for index, statement in enumerate(statements):
            replacement = self._replacement_8616(statement)
            if replacement is None:
                continue
            statements[index : index + 1] = replacement
            self.materialized_count += 1
            changed = True
        if changed:
            cast(Any, container).statements = statements

    @cython.ccall
    def _replacement_8616(self, statement: object) -> object:
        """Return the proven replacement statement(s) or None."""
        c_result_contract: object
        call: object
        direct_call: object
        projected_call: object
        projection: object
        summary: object
        if not isinstance(statement, CAssignment):
            return None
        direct_call = (
            statement.rhs
            if isinstance(statement.rhs, CFunctionCall)
            and not is_structured_insert_intrinsic_8616(statement.rhs)
            else None
        )
        projection = (
            None
            if direct_call is not None
            else _projected_call_result_8616(statement.rhs)
        )
        if direct_call is None and projection is None:
            projection = _masked_subregister_call_result_8616(statement)
        projected_call = projection.call if projection is not None else None
        call = direct_call or projected_call
        if call is None:
            return None
        assignment_id = id(statement)
        if assignment_id in self.seen_assignments:
            return None
        self.seen_assignments.add(assignment_id)
        self.raw_fact_count += 1
        summary = self.summaries.get(id(call))
        c_result_contract = _c_result_contract_for_call_8616(
            self.boundary,
            call,
            self.c_result_contracts,
        )
        typed_void_projection = projected_call is not None and (
            _is_typed_void_call_8616(call)
            or _has_proven_void_interrupt_result_8616(self.boundary, call)
            or _has_typed_void_interrupt_target_8616(self.boundary, call)
            or (
                c_result_contract is not None
                and c_result_contract.kind is CallsiteCResultKind8616.VOID
            )
        )
        if summary is None and not typed_void_projection:
            return None
        self.normalized_fact_count += 1
        direct_is_proven = summary is not None and direct_call is not None and _is_proven_unobserved_ax_result_8616(
            statement,
            summary,
        )
        projected_is_proven = (
            projected_call is not None
            and (
                typed_void_projection
                or (
                    summary is not None
                    and _is_proven_unobserved_projected_result_8616(summary)
                )
            )
        )
        if not direct_is_proven and not projected_is_proven:
            return None
        self.classified_fact_count += 1
        call_statement = CExpressionStatement(call, codegen=statement.codegen)
        if projection is not None and projection.residual is not None:
            residual_assignment = CAssignment(
                statement.lhs,
                projection.residual,
                tags=statement.tags,
                codegen=statement.codegen,
            )
            return [call_statement, residual_assignment]
        return [call_statement]


def lower_unobserved_call_result_assignments_8616(codegen: object) -> cython.bint:
    """Replace only typed-clobbered AX call assignments with standalone calls."""
    container: object
    boundary = cast(_UnobservedResultCodegen8616, codegen)
    try:
        root = boundary.cfunc.statements
        summaries = _typed_summary_map_8616(boundary)
        c_result_contracts = _typed_c_result_contract_map_8616(boundary)
    except AttributeError:
        return False

    scan = _UnobservedLowerScan8616(
        boundary=boundary,
        summaries=summaries,
        c_result_contracts=c_result_contracts,
    )
    for container in tuple(
        node for node in builtins.iter(_iter_c_nodes_deep_8616(root)) if isinstance(node, CStatements)
    ):
        scan.process_container(container)

    stats = UnobservedCallResultLoweringStats8616(
        raw_fact_count=scan.raw_fact_count,
        normalized_fact_count=scan.normalized_fact_count,
        classified_fact_count=scan.classified_fact_count,
        materialized_count=scan.materialized_count,
        failure_count=scan.classified_fact_count - scan.materialized_count,
    )
    if not stats.closed:
        raise PipelineHardError("unobserved call-result lowering evidence accounting is not closed")
    boundary._inertia_unobserved_call_result_lowering_stats_8616 = stats
    return stats.changed
