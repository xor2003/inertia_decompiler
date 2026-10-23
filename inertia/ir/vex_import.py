"""Import VEX block data into typed x86-16 IR artifacts.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, MutableMapping
from copy import deepcopy
from dataclasses import dataclass, field, replace
from enum import StrEnum
from functools import partial
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Protocol, cast

from inertia.frontend.x86_16.frontend_boundary_transport import (
    capture_function_boundary_8616,
    restore_function_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.frontend.x86_16.function_knowledge_base import function_knowledge_base_8616
from inertia.ir.analysis.alias import storage_of
from inertia.ir.analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact
from inertia.pipeline.errors import PipelineHardError

from .block_ownership import (
    IRBlockOwnershipArtifact8616,
    canonicalize_ir_block_ownership_8616,
)
from .condition_cache_relift import ConditionReliftBlock8616
from .condition_lift_capture import (
    ConditionLiftCaptureSession8616,
    isolated_condition_lift_session_8616,
)
from .core import (
    AddressStatus,
    IRActiveUnary8616,
    IRAddress,
    IRAtom,
    IRBinaryValue,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .dead_temporary_surface_normalization import (
    DeadTemporarySurfaceNormalizationResult8616,
    dead_temporary_surface_producers_8616,
    normalize_dead_temporary_surface_8616,
)
from .direct_evidence_deadline import direct_evidence_deadline_expired_8616
from .entry_domain_call_preservation import (
    EntryDomainCallPreservation8616,
    collect_entry_domain_call_preservations_8616,
    entry_domain_caller_boundary_8616,
    entry_domain_invocation_premise_8616,
)
from .entry_jump_domain import (
    EntryJumpDomainApplication8616,
    EntryJumpDomainApplicationStatus8616,
    EntryJumpDomainProof8616,
    apply_entry_jump_domain_8616,
    collect_pending_terminal_jumps_8616,
    prove_entry_jump_domains_8616,
)
from .function_condition_artifact import build_ir_function_condition_artifact_8616
from .function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from .function_readiness_contracts import (
    FunctionSourceRevision8616,
    function_artifact_body_digest_8616,
    observed_function_source_revision_8616,
    record_function_build_attestation_8616,
)
from .instruction_origin import vex_instruction_origin_8616
from .logical_memory_capture import (
    IRLogicalMemoryCaptureRecord8616,
    collect_accesses_for_block,
    collect_accesses_for_function,
)
from .logical_memory_resolution import resolve_logical_memory_accesses_8616
from .native_copy_memo import native_copy_memo_producers_8616, seed_native_copy_memo_8616, seed_native_decisions_8616
from .native_import_capture import native_capture_copyable_8616
from .native_import_surface_cache import (
    NativeFactRebind8616,
    NativeFactRebindState8616,
    native_import_request_8616,
    request_native_fact_rebind_8616,
    request_native_surface_8616,
)
from .near_call_jump_scope import NearCallJumpScope8616
from .near_return_continuation_view import (
    NEAR_RETURN_CONTINUATION_PENDING_KIND_8616,
)
from .no_effect_instructions import (
    LiftedNoEffectMark8616,
    lifted_no_effect_instr_8616,
    terminal_no_effect_instr_8616,
)
from .regs import register_name_from_offset
from .ssa import _block_local_ssa_binding_count_8616
from .ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from .vex_addressing import SegmentHintMap, block_segment_hints, expr_to_address
from .vex_condition_demand import (
    VexConditionDemand8616,
    collect_vex_condition_demand_8616,
)
from .vex_condition_lifting import (
    _expr_cond,
    _expr_iffalse,
    _expr_iftrue,
    build_condition_from_binop,
    expr_to_condition,
)
from .vex_condition_transport import (
    VexConditionTransportNormalizer8616,
    VexConditionTransportStats8616,
    aggregate_vex_condition_transport_stats_8616,
    build_vex_condition_transport_layout_8616,
)
from .vex_control_flow import terminal_control_flow_instr_8616
from .vex_integer_displacement import canonical_vex_integer_displacement_8616
from .vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpRefusalReason8616,
    terminal_direct_jump_evidence_8616,
)
from .vex_types import vex_expr_size_bytes

if TYPE_CHECKING:
    from .declared_entry_pipeline import DeclaredEntryInput8616
    from .near_call_entry_pipeline import NativeNearCallPipeline8616
    from .near_return_continuation_view import (
        ScopedNearReturnContinuationView8616,
    )
    from .real16_invocation_domain import Real16InvocationDomain8616
    from .scoped_function_ir_view import ScopedFunctionIRView8616
    from .source_graph_binding import ImmutableSourceGraphFacts8616

__all__ = (
    "RawIRFunctionImportBundle8616",
    "apply_x86_16_vex_ir_artifact",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
    "codegen_function_8616",
    "native_census_import_active_8616",
    "prove_scoped_control_obligations_view_8616",
    "prove_scoped_x86_16_ir_function_view_8616",
    "raw_x86_16_function_bundle_8616",
    "raw_x86_16_import_bundle_for_artifact_8616",
)

_TmpValues = Mapping[int, IRValue]
_TmpConditions = Mapping[int, IRCondition]
_MutableTmpValues = dict[int, IRValue]
_MutableTmpConditions = dict[int, IRCondition]
_TmpExprs = dict[int, object]
_DIRECT_INTEGER_CONSTANT_TAGS_8616: frozenset[str] = frozenset(
    {"Ico_U1", "Ico_U8", "Ico_U16", "Ico_U32", "Ico_U64", "Ico_U128"}
)


class IRImportRefusalReason8616(StrEnum):
    """Typed reason an IR import cannot finish its optional evidence work."""

    DIRECT_EVIDENCE_DEADLINE_EXPIRED = "ir_import_direct_evidence_deadline_expired"
    INDIRECT_TERMINAL_PENDING = "indirect_terminal_pending"


class _VexConstBoundary(Protocol):
    """Minimal pyvex constant surface consumed by IR import."""

    value: object


class _VexExprBoundary(Protocol):
    """Minimal pyvex expression surface consumed by IR import."""

    tag: object
    tmp: object
    offset: object
    op: object
    args: object
    con: _VexConstBoundary | None
    addr: object
    result_size: object


class _VexStmtBoundary(Protocol):
    """Minimal pyvex statement surface consumed by IR import."""

    tag: object
    tmp: object
    data: object
    offset: object
    addr: object
    delta: object
    guard: object
    dst: object
    len: object


class _VexBlockBoundary(Protocol):
    """Minimal pyvex block payload consumed by IR import."""

    statements: object
    next: object
    tyenv: object
    jumpkind: object


class _BlockBoundary(Protocol):
    """Minimal angr block surface consumed by IR import."""

    addr: object
    size: object
    vex: _VexBlockBoundary | None


class _FunctionBoundary(Protocol):
    """Minimal angr function surface consumed by IR import."""

    addr: object
    block_addrs_set: object
    graph: object
    info: object


class _FunctionGraphBoundary(Protocol):
    """Minimal graph edge surface exposed by an angr function."""

    edges: object


class _FunctionGraphNodeBoundary(Protocol):
    """Minimal address surface exposed by an angr function-graph node."""

    addr: object


class _FactoryBoundary(Protocol):
    """Minimal angr factory surface consumed by IR import."""

    block: Callable[..., object]


class _FunctionManagerBoundary(Protocol):
    """Minimal angr function manager surface consumed by IR import."""

    function: Callable[..., object | None]


class _KbBoundary(Protocol):
    """Minimal angr knowledge-base surface consumed by IR import."""

    functions: _FunctionManagerBoundary


class _ProjectBoundary(Protocol):
    """Minimal angr project surface consumed by IR import."""

    factory: _FactoryBoundary
    kb: _KbBoundary


class _CFuncBoundary(Protocol):
    """Minimal codegen C function surface consumed by IR import."""

    addr: object


class _CodegenBoundary(Protocol):
    """Codegen boundary fields where IR artifacts are attached."""

    cfunc: _CFuncBoundary | None
    _func: object
    _inertia_vex_ir_source_function_8616: object
    _inertia_raw_vex_ir_artifact_8616: IRFunctionArtifact
    _inertia_raw_vex_ir_frame_8616: object
    _inertia_raw_vex_ir_function_ssa_8616: SSAFunctionArtifact
    _inertia_vex_ir_artifact: IRFunctionArtifact
    _inertia_vex_ir_summary: dict[str, object]
    _inertia_vex_ir_frame: object
    _inertia_vex_ir_function_ssa: object


def _external_int(value: object) -> int:
    """Coerce external pyvex/angr integer-like values without owning their type."""
    return int(cast(Any, value))


def _expr_tag(expr: object | None) -> str:
    """Return a VEX expression tag from the pyvex boundary."""
    if expr is None:
        return ""
    try:
        return str(cast(_VexExprBoundary, expr).tag)
    except AttributeError:
        return ""


def _expr_tmp(expr: object) -> int:
    """Return a VEX temporary id from the pyvex boundary."""
    return _external_int(cast(_VexExprBoundary, expr).tmp)


def _expr_offset(expr: object, default: int = -1) -> int:
    """Return a VEX register offset from the pyvex boundary."""
    try:
        return _external_int(cast(_VexExprBoundary, expr).offset)
    except AttributeError:
        return default


def _expr_op(expr: object | None, default: str = "") -> str:
    """Return a VEX expression op from the pyvex boundary."""
    if expr is None:
        return default
    try:
        return str(cast(_VexExprBoundary, expr).op)
    except AttributeError:
        return default


def _expr_args(expr: object | None) -> tuple[object, ...]:
    """Return VEX expression args from the pyvex boundary."""
    if expr is None:
        return ()
    try:
        args = cast(_VexExprBoundary, expr).args
    except AttributeError:
        return ()
    if args is None:
        return ()
    return tuple(cast(Iterable[object], args))


def _expr_addr(expr: object | None) -> object | None:
    """Return a VEX load address expression from the pyvex boundary."""
    if expr is None:
        return None
    try:
        return cast(_VexExprBoundary, expr).addr
    except AttributeError:
        return None


def _expr_const(expr: object | None) -> _VexConstBoundary | None:
    """Return a VEX constant wrapper from the pyvex boundary."""
    if expr is None:
        return None
    try:
        return cast(_VexExprBoundary, expr).con
    except AttributeError:
        return None


def _stmt_tag(stmt: object | None) -> str:
    """Return a VEX statement tag from the pyvex boundary."""
    if stmt is None:
        return ""
    try:
        return str(cast(_VexStmtBoundary, stmt).tag)
    except AttributeError:
        return ""


def _stmt_tmp(stmt: object) -> int:
    """Return a VEX statement temporary id from the pyvex boundary."""
    return _external_int(cast(_VexStmtBoundary, stmt).tmp)


def _stmt_data(stmt: object | None) -> object | None:
    """Return a VEX statement data expression from the pyvex boundary."""
    if stmt is None:
        return None
    try:
        return cast(_VexStmtBoundary, stmt).data
    except AttributeError:
        return None


def _stmt_offset(stmt: object) -> int:
    """Return a VEX Put statement register offset."""
    return _external_int(cast(_VexStmtBoundary, stmt).offset)


def _stmt_addr(stmt: object | None) -> object | None:
    """Return a VEX Store statement address expression."""
    if stmt is None:
        return None
    try:
        return cast(_VexStmtBoundary, stmt).addr
    except AttributeError:
        return None


def _stmt_instruction_addr(stmt: object) -> int | None:
    """Return the effective guest address carried by a VEX instruction mark."""
    boundary = cast(_VexStmtBoundary, stmt)
    try:
        return _external_int(boundary.addr) + _external_int(boundary.delta)
    except (AttributeError, TypeError, ValueError):
        return None


def _stmt_instruction_size(stmt: object) -> int | None:
    """Return the decoded byte length carried by a VEX instruction mark."""
    try:
        size = _external_int(cast(_VexStmtBoundary, stmt).len)
    except (AttributeError, TypeError, ValueError):
        return None
    return size if size >= 0 else None


def _stmt_guard(stmt: object | None) -> object | None:
    """Return a VEX Exit guard expression."""
    if stmt is None:
        return None
    try:
        return cast(_VexStmtBoundary, stmt).guard
    except AttributeError:
        return None


def _stmt_dst(stmt: object | None) -> object | None:
    """Return a VEX Exit destination expression."""
    if stmt is None:
        return None
    try:
        return cast(_VexStmtBoundary, stmt).dst
    except AttributeError:
        return None


def _block_vex(block: object) -> _VexBlockBoundary | None:
    """Return the VEX payload from an angr block boundary."""
    try:
        return cast(_BlockBoundary, block).vex
    except AttributeError:
        return None


def _block_addr(block: object) -> int:
    """Return the address from an angr block boundary."""
    try:
        return _external_int(cast(_BlockBoundary, block).addr)
    except AttributeError:
        return 0


def _vex_statements(vex: _VexBlockBoundary | None) -> tuple[object, ...]:
    """Return VEX statements as a stable tuple."""
    if vex is None:
        return ()
    try:
        statements = vex.statements
    except AttributeError:
        return ()
    if statements is None:
        return ()
    return tuple(cast(Iterable[object], statements))


def _vex_next(vex: _VexBlockBoundary | None) -> object | None:
    """Return the VEX default successor expression."""
    if vex is None:
        return None
    try:
        return vex.next
    except AttributeError:
        return None


def _vex_type_environment(vex: _VexBlockBoundary | None) -> object | None:
    """Return the external IRSB type environment used by VEX width methods."""
    if vex is None:
        return None
    try:
        return vex.tyenv
    except AttributeError:
        return None


def _vex_jumpkind(vex: _VexBlockBoundary | None) -> str:
    """Return the VEX block jumpkind from the pyvex boundary."""
    if vex is None:
        return ""
    try:
        return str(vex.jumpkind)
    except AttributeError:
        return ""


def _function_addr(function: object) -> int:
    """Return an angr function address from the boundary object."""
    try:
        return _external_int(cast(_FunctionBoundary, function).addr)
    except AttributeError:
        return 0


def _function_block_addrs(function: object) -> tuple[object, ...]:
    """Return a deterministic tuple of function block addresses."""
    try:
        block_addrs = cast(_FunctionBoundary, function).block_addrs_set
    except AttributeError:
        return ()
    if block_addrs is None:
        return ()
    return tuple(sorted(_external_int(block_addr) for block_addr in cast(Iterable[object], block_addrs)))


def _graph_edge_addresses_8616(edge: object) -> tuple[int, int] | None:
    """Resolve one raw graph edge to its two node addresses."""
    if not isinstance(edge, (tuple, list)) or len(edge) < 2:
        return None
    addresses: list[int] = []
    for node in edge[:2]:
        raw_address = node if isinstance(node, int) else cast(_FunctionGraphNodeBoundary, node).addr
        try:
            addresses.append(_external_int(raw_address))
        except (AttributeError, TypeError, ValueError):
            return None
    if len(addresses) != 2:
        return None
    return addresses[0], addresses[1]


def _function_graph_successors(
    function: object,
    block_addrs: frozenset[int],
) -> dict[int, tuple[int, ...]] | None:
    """Read exact Frontend or recovered angr in-function CFG edges."""
    if isinstance(function, ExactFunctionRangeBoundary8616):
        exact_successors: dict[int, set[int]] = {address: set() for address in block_addrs}
        for source, target in function.successor_edges:
            if source in block_addrs and target in block_addrs:
                exact_successors[source].add(target)
        return {
            address: tuple(sorted(targets))
            for address, targets in sorted(exact_successors.items())
        }
    try:
        graph = cast(_FunctionBoundary, function).graph
        edges = cast(_FunctionGraphBoundary, graph).edges
    except AttributeError:
        return None
    raw_edges = edges() if callable(edges) else edges
    successors: dict[int, set[int]] = {address: set() for address in block_addrs}
    try:
        edge_items = tuple(cast(Iterable[object], raw_edges))
    except TypeError:
        return None
    for edge in edge_items:
        addresses = _graph_edge_addresses_8616(edge)
        if addresses is None:
            continue
        if addresses[0] in block_addrs and addresses[1] in block_addrs:
            successors[addresses[0]].add(addresses[1])
    return {
        address: tuple(sorted(targets))
        for address, targets in sorted(successors.items())
    }


def _function_info(function: object) -> MutableMapping[str, object] | None:
    """Return mutable angr function info metadata when available."""
    try:
        info = cast(_FunctionBoundary, function).info
    except AttributeError:
        return None
    return cast(MutableMapping[str, object], info) if isinstance(info, MutableMapping) else None


def _const(expr: object | None) -> int | None:
    """Return a wrapped expression or direct VEX constant value when present."""
    con = _expr_const(expr)
    if con is not None:
        return _external_int(con.value)
    try:
        return _external_int(cast(_VexConstBoundary, expr).value)
    except (AttributeError, TypeError, ValueError):
        return None


def _int_size(
    expr: object | None,
    default: int = 2,
    *,
    type_environment: object | None = None,
) -> int:
    """Return the byte width advertised by a VEX expression boundary."""
    return int(vex_expr_size_bytes(
        expr, type_environment=type_environment, default=default,
    ))


def _binary_value_from_operands_8616(
    op: str,
    left: IRValue,
    right: IRValue,
) -> IRValue:
    """Build binary IR values with width-canonical integer displacements.

    Displacement folds apply only to unpinned register reads: a pinned
    operand's offset is provenance inside the captured tmp result, so
    folding it into a fresh register view would replay it against the
    wrong register state.
    """
    cond = build_condition_from_binop(op, left, right)
    if cond is not None:
        return IRValue(MemSpace.TMP, name=f"cond:{cond.op}", size=1, expr=(op,))
    if left.active_unary is not None or right.active_unary is not None:
        # Compatibility projections cannot flatten an active computation.
        # WrTmp binop rows retain the full operands for exact evaluation.
        return IRValue(MemSpace.TMP, name=f"expr:{op}", size=max(left.size, right.size), expr=(op,))
    displacement = (
        right.const
        if left.space == MemSpace.REG and left.source_tmp is None
        and right.space == MemSpace.CONST and right.source_tmp is None
        else None
    )
    if "Add" in op and displacement is not None:
        return IRValue(
            left.space,
            name=left.name,
            offset=canonical_vex_integer_displacement_8616(op, left.offset + displacement, left.size),
            size=left.size,
            expr=(op,),
        )
    if "Sub" in op and displacement is not None:
        return IRValue(
            left.space,
            name=left.name,
            offset=canonical_vex_integer_displacement_8616(op, left.offset - displacement, left.size),
            size=left.size,
            expr=(op,),
        )
    if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.REG and left.name and right.name:
        return IRValue(
            MemSpace.TMP,
            name=f"addr:{left.name}+{right.name}",
            size=left.size,
            expr=(op, left.name, right.name),
        )
    if "And" in op:
        return IRValue(
            MemSpace.TMP,
            name=f"mask:{left.name or 'lhs'}",
            size=max(left.size, right.size),
            expr=(op,),
        )
    return IRValue(
        MemSpace.TMP,
        name=f"expr:{op}",
        size=max(left.size, right.size),
        expr=(op,),
    )


def _expr_to_value(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    *,
    type_environment: object | None = None,
) -> IRValue:
    """Convert a VEX expression boundary into a typed IR value."""
    convert = partial(_expr_to_value, type_environment=type_environment)
    return _expr_to_value_impl_8616(expr, tmps, conditions, convert, type_environment)


def _unop_result_bits_8616(
    expr: object, type_environment: object | None, size_bytes: int
) -> int:
    """Return the authoritative bit width of one Unop result.

    Real pyvex expressions expose ``result_size(type_environment)`` in
    bits, which keeps one-bit results (``Iop_Not1``) at one bit. Boundaries
    without a callable result size (synthetic fixtures) fall back to the
    byte storage width already resolved by ``_int_size``.
    """
    if type_environment is not None:
        try:
            result_size = cast(_VexExprBoundary, expr).result_size
        except AttributeError:
            result_size = None
        if callable(result_size):
            try:
                bits = int(cast(int, result_size(type_environment)))
            except (TypeError, ValueError):
                bits = 0
            if bits > 0:
                return bits
    return size_bytes * 8


def _unop_ir_value_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    convert: Callable[[object, _TmpValues, _TmpConditions], IRValue],
    type_environment: object | None,
) -> IRValue:
    """Convert one Unop boundary into a typed IR value.

    The result view keeps ``expr=(op,)`` as the provenance projection and
    additionally carries typed ``active_unary`` evidence: the exact VEX
    op, the converted operand, and the authoritative result bit width.
    The operand's own ``source_tmp`` pin is *not* propagated — this value
    is the operation's result, not the captured operand — so consumers
    never mistake the wrapper for the already-computed tmp.
    """
    args = _expr_args(expr)
    op = _expr_op(expr, "unop")
    if not args:
        return IRValue(MemSpace.UNKNOWN, name=op, expr=("empty_unop",))
    inner = convert(args[0], tmps, conditions)
    size = _int_size(expr, type_environment=type_environment)
    return IRValue(
        inner.space,
        name=inner.name,
        offset=inner.offset,
        const=inner.const,
        size=size,
        expr=(op,),
        active_unary=IRActiveUnary8616(
            op=op,
            operand=inner,
            result_bits=_unop_result_bits_8616(expr, type_environment, size),
        ),
    )


def _binop_ir_value_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    convert: Callable[[object, _TmpValues, _TmpConditions], IRValue],
) -> IRValue:
    """Convert one Binop boundary into a typed IR value."""
    op = _expr_op(expr)
    args = _expr_args(expr)
    if len(args) != 2:
        return IRValue(MemSpace.TMP, name=f"expr:{op}", expr=(op,))
    left = convert(args[0], tmps, conditions)
    right = convert(args[1], tmps, conditions)
    return _binary_value_from_operands_8616(op, left, right)


def _expr_to_value_impl_8616(
    expr: object,
    tmps: _TmpValues,
    conditions: _TmpConditions,
    convert: Callable[[object, _TmpValues, _TmpConditions], IRValue],
    type_environment: object | None,
) -> IRValue:
    tag = _expr_tag(expr)
    if tag == "Iex_RdTmp":
        tmp_id = _expr_tmp(expr)
        if tmp_id in tmps:
            return tmps[tmp_id]
        if tmp_id in conditions:
            return IRValue(MemSpace.TMP, name=f"cond_t{tmp_id}", size=1, expr=("condition_tmp",))
        return IRValue(MemSpace.TMP, name=f"t{tmp_id}")
    if tag == "Iex_Get":
        size = _int_size(expr, type_environment=type_environment)
        name = register_name_from_offset(_expr_offset(expr), size=size)
        return IRValue(
            MemSpace.REG,
            name=name,
            size=size,
        )
    # Exit.dst is an IRConst, unlike wrapped expression constants.
    if tag == "Iex_Const" or tag in _DIRECT_INTEGER_CONSTANT_TAGS_8616:
        return IRValue(
            MemSpace.CONST,
            const=_const(expr),
            size=_int_size(expr, type_environment=type_environment),
        )
    if tag == "Iex_Unop":
        return _unop_ir_value_8616(expr, tmps, conditions, convert, type_environment)
    if tag == "Iex_Binop":
        return _binop_ir_value_8616(expr, tmps, conditions, convert)
    if tag == "Iex_Load":
        addr = expr_to_address(
            _expr_addr(expr),
            tmps,
            conditions,
            expr_to_value=convert,
            size=_int_size(expr, type_environment=type_environment),
        )
        return IRValue(
            MemSpace.TMP,
            name="load",
            size=addr.size or _int_size(expr, type_environment=type_environment),
            expr=("load",),
        )
    return IRValue(MemSpace.UNKNOWN, name=tag or "expr")


@dataclass(frozen=True, slots=True)
class _StmtImportContext8616:
    """Shared statement-import context for per-tag conversion helpers."""

    convert: Callable[[object, _TmpValues, _TmpConditions], IRValue]
    instruction_addr: int | None
    segment_hints: SegmentHintMap
    tmp_exprs: _TmpExprs
    type_environment: object | None
    condition_demand: VexConditionDemand8616


def _wrtmp_load_instr_8616(
    data: object,
    tmp_id: int,
    dst: IRValue,
    data_size: int,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr:
    """Import a ``tN = Load(addr)`` write into a LOAD instruction."""
    addr = expr_to_address(
        _expr_addr(data),
        tmps,
        conditions,
        expr_to_value=ctx.convert,
        size=data_size,
        segment_hints=ctx.segment_hints,
        tmp_exprs=ctx.tmp_exprs,
    )
    tmps[tmp_id] = IRValue(
        MemSpace.TMP,
        name=f"load_t{tmp_id}",
        size=data_size,
        expr=("load",),
        source_tmp=tmp_id,
    )
    return IRInstr(
        op="LOAD",
        dst=dst,
        args=(addr,),
        size=data_size,
        addr=ctx.instruction_addr,
    )


def _wrtmp_binop_instr_8616(
    data: object,
    tmp_id: int,
    dst: IRValue,
    data_size: int,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr | None:
    """Import a binary result using its authoritative VEX result width.

    ``data_size`` already sizes ``dst`` from the expression/type environment;
    the instruction and retained temporary consume that same result width.
    Operand widths remain independent: comparison predicates occupy one byte,
    and shift counts need not share the data operand's width.
    """
    op = _expr_op(data, "BINOP")
    args = _expr_args(data)
    if len(args) != 2:
        return None
    left = ctx.convert(args[0], tmps, conditions)
    right = ctx.convert(args[1], tmps, conditions)
    if "Cmp" in op or (
        ctx.condition_demand.requires_eager_condition(tmp_id)
        and any(token in op for token in ("And", "Or"))
    ):
        conditions[tmp_id] = expr_to_condition(
            data,
            tmps,
            conditions,
            expr_to_value=ctx.convert,
            tmp_exprs=ctx.tmp_exprs,
        )
    else:
        cond = build_condition_from_binop(op, left, right)
        if cond is not None:
            conditions[tmp_id] = cond
    value = _binary_value_from_operands_8616(op, left, right)
    tmps[tmp_id] = IRValue(
        value.space,
        name=value.name,
        offset=value.offset,
        const=value.const,
        size=data_size,
        version=value.version,
        expr=value.expr,
        memory_access_insn=value.memory_access_insn,
        source_tmp=tmp_id,
    )
    return IRInstr(
        op=op,
        dst=dst,
        args=(left, right),
        size=data_size,
        addr=ctx.instruction_addr,
    )


def _wrtmp_ite_condition_8616(
    data: object,
    tmp_id: int,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> None:
    """Record an eager ITE condition unless it collapsed to an unknown tmp."""
    if not ctx.condition_demand.requires_eager_condition(tmp_id):
        return
    cond = expr_to_condition(data, tmps, conditions, expr_to_value=ctx.convert, tmp_exprs=ctx.tmp_exprs)
    if not (
        cond.op == "nonzero"
        and len(cond.args) == 1
        and isinstance(cond.args[0], IRValue)
        and cond.args[0].space == MemSpace.UNKNOWN
        and cond.args[0].name == "Iex_ITE"
    ):
        conditions[tmp_id] = cond


def _bound_select_atom_8616(
    expr: object, tmps: _TmpValues, conditions: _TmpConditions,
    ctx: _StmtImportContext8616,
) -> IRValue | None:
    """Convert an atomic select input without hiding nested computations."""
    tag = _expr_tag(expr)
    if tag == "Iex_RdTmp":
        value = tmps.get(_expr_tmp(expr))
    elif tag in {"Iex_Const", "Iex_Get"}:
        value = ctx.convert(expr, tmps, conditions)
    else:
        return None
    if value is None or value.space is MemSpace.UNKNOWN or value.size <= 0:
        return None
    return value


def _wrtmp_select_instr_8616(
    data: object, tmp_id: int, dst: IRValue,
    tmps: _MutableTmpValues, conditions: _TmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr | None:
    """Retain a typed atomic VEX ITE as a three-input temporary selection.

    Guard width must be proven as I1, never inferred from byte storage or
    a literal value. Unbound inputs and nested expressions keep the existing
    explicit UNKNOWN import until their complete semantics can be represented.
    """
    if ctx.type_environment is None:
        return None
    guard_expr, true_expr, false_expr = _expr_cond(data), _expr_iftrue(data), _expr_iffalse(data)
    if guard_expr is None or true_expr is None or false_expr is None:
        return None
    bits = _unop_result_bits_8616(data, ctx.type_environment, 0)
    widths = tuple(_unop_result_bits_8616(expr, ctx.type_environment, 0)
                   for expr in (guard_expr, true_expr, false_expr))
    if bits not in {1, 8, 16, 32, 64} or widths != (1, bits, bits):
        return None
    args = tuple(_bound_select_atom_8616(expr, tmps, conditions, ctx)
                 for expr in (guard_expr, true_expr, false_expr))
    if any(value is None for value in args):
        return None
    operands = cast(tuple[IRValue, IRValue, IRValue], args)
    if tuple(value.size for value in operands) != (1, dst.size, dst.size):
        return None
    tmps[tmp_id] = dst
    return IRInstr(op=f"SELECT{bits}", dst=dst, args=operands, size=dst.size,
                   addr=ctx.instruction_addr)


def _wrtmp_instr_8616(
    stmt: object,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr | None:
    """Import one temporary write with a coherent typed result width.

    Destination, instruction and retained result share the VEX expression's
    authoritative width. The converted operand retains its own value view;
    unsupported semantics remain UNKNOWN without discarding result-type
    facts. The stored view deliberately drops ``active_unary``: the tmp
    already names the computed result, so re-carrying the operation on the
    captured reference would apply it twice.
    """
    data = _stmt_data(stmt)
    tmp_id = _stmt_tmp(stmt)
    data_tag = _expr_tag(data)
    data_size = _int_size(data, type_environment=ctx.type_environment)
    ctx.tmp_exprs[tmp_id] = data
    dst = IRValue(
        MemSpace.TMP,
        name=f"t{tmp_id}",
        size=data_size,
        source_tmp=tmp_id,
    )
    if data_tag == "Iex_Load":
        return _wrtmp_load_instr_8616(data, tmp_id, dst, data_size, tmps, conditions, ctx)
    if data_tag == "Iex_Binop":
        instr = _wrtmp_binop_instr_8616(
            data, tmp_id, dst, data_size, tmps, conditions, ctx,
        )
        if instr is not None:
            return instr
    if data_tag == "Iex_ITE":
        _wrtmp_ite_condition_8616(data, tmp_id, tmps, conditions, ctx)
        selection = _wrtmp_select_instr_8616(data, tmp_id, dst, tmps, conditions, ctx)
        if selection is not None:
            return selection
    value = ctx.convert(data, tmps, conditions)
    tmps[tmp_id] = IRValue(
        value.space,
        name=value.name,
        offset=value.offset,
        const=value.const,
        size=data_size,
        version=value.version,
        expr=value.expr,
        memory_access_insn=value.memory_access_insn,
        source_tmp=tmp_id,
    )
    return IRInstr(op="MOV", dst=dst, args=(value,), size=data_size, addr=ctx.instruction_addr)


def _put_instr_8616(
    stmt: object,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr:
    """Import one ``Ist_Put`` register write into a MOV instruction."""
    offset = _stmt_offset(stmt)
    src = ctx.convert(_stmt_data(stmt), tmps, conditions)
    # Preserve the exact register view. Alias owns parent/slice storage
    # identity; typed IR must retain whether a byte write targets AL or
    # AH so selector semantics can consume the correct lane.
    dst_size = src.size if src.size in {1, 2, 4} else 2
    dst = IRValue(MemSpace.REG, name=register_name_from_offset(offset, size=dst_size), size=dst_size)
    return IRInstr(op="MOV", dst=dst, args=(src,), size=src.size or dst.size, addr=ctx.instruction_addr)


def _store_instr_8616(
    stmt: object,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr:
    """Import one ``Ist_Store`` memory write into a STORE instruction."""
    data_expr = _stmt_data(stmt)
    data = ctx.convert(data_expr, tmps, conditions)
    addr = expr_to_address(
        _stmt_addr(stmt),
        tmps,
        conditions,
        expr_to_value=ctx.convert,
        size=data.size,
        segment_hints=ctx.segment_hints,
        tmp_exprs=ctx.tmp_exprs,
    )
    return IRInstr(op="STORE", dst=None, args=(addr, data), size=data.size, addr=ctx.instruction_addr)


def _exit_instr_8616(
    stmt: object,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    ctx: _StmtImportContext8616,
) -> IRInstr:
    """Import one ``Ist_Exit`` conditional branch into a CJMP instruction."""
    cond = expr_to_condition(
        _stmt_guard(stmt), tmps, conditions, expr_to_value=ctx.convert, tmp_exprs=ctx.tmp_exprs
    )
    target = ctx.convert(_stmt_dst(stmt), tmps, conditions)
    return IRInstr(op="CJMP", dst=None, args=(cond, target), size=0, addr=ctx.instruction_addr)


def _stmt_to_instr(
    stmt: object,
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    *,
    instruction_addr: int | None,
    segment_hints: SegmentHintMap,
    tmp_exprs: _TmpExprs,
    type_environment: object | None,
    condition_demand: VexConditionDemand8616,
) -> IRInstr | None:
    """Convert one VEX statement boundary into a typed IR instruction."""
    ctx = _StmtImportContext8616(
        convert=partial(_expr_to_value, type_environment=type_environment),
        instruction_addr=instruction_addr,
        segment_hints=segment_hints,
        tmp_exprs=tmp_exprs,
        type_environment=type_environment,
        condition_demand=condition_demand,
    )
    tag = _stmt_tag(stmt)
    if tag == "Ist_WrTmp":
        return _wrtmp_instr_8616(stmt, tmps, conditions, ctx)
    if tag == "Ist_Put":
        return _put_instr_8616(stmt, tmps, conditions, ctx)
    if tag == "Ist_Store":
        return _store_instr_8616(stmt, tmps, conditions, ctx)
    if tag == "Ist_Exit":
        return _exit_instr_8616(stmt, tmps, conditions, ctx)
    return None


def _observe_imark_8616(
    block: object,
    pending_mark: tuple[int, int, int] | None,
    statement_index: int,
    stmt: object,
) -> tuple[IRInstr | None, tuple[int, int, int] | None, int | None, int | None]:
    """Close the prior empty span, then open the new instruction mark.

    A pending mark whose span ends here produced zero statements; only
    ``lifted_no_effect_instr_8616`` may decide — by binding the marked
    extent's exact native bytes — whether it earns a no-effect instruction.
    A mark missing integer head or width facts cannot start a span.
    """
    mark_addr = _stmt_instruction_addr(stmt)
    mark_size = _stmt_instruction_size(stmt)
    no_effect = None
    if pending_mark is not None:
        no_effect = lifted_no_effect_instr_8616(
            block,
            LiftedNoEffectMark8616(
                statement_index=pending_mark[0],
                addr=pending_mark[1],
                size=pending_mark[2],
                next_addr=mark_addr if type(mark_addr) is int else None,
            ),
        )
    new_pending: tuple[int, int, int] | None = None
    if (
        type(mark_addr) is int
        and mark_addr >= 0
        and type(mark_size) is int
        and mark_size > 0
    ):
        new_pending = (statement_index, mark_addr, mark_size)
    return no_effect, new_pending, mark_addr, mark_size


def _block_statement_instrs_8616(
    statements: Iterable[object],
    tmps: _MutableTmpValues,
    conditions: _MutableTmpConditions,
    tmp_exprs: _TmpExprs,
    segment_hints: SegmentHintMap,
    condition_demand: VexConditionDemand8616,
    type_environment: object | None,
    transport: VexConditionTransportNormalizer8616,
    block: object,
    addr: int,
) -> tuple[
    list[IRInstr],
    list[IRRefusal],
    int | None,
    int | None,
    LiftedNoEffectMark8616 | None,
]:
    """Import every VEX statement, tracking the latest instruction mark.

    An ``Ist_IMark`` whose span up to the next mark held zero statements is a
    candidate source-bound no-effect instruction; it is emitted only when the
    exact decoded bytes at the marked extent prove the canonical NOP encoding.
    Any statement in the span — imported or refused — disqualifies the mark.
    The trailing mark, if any, is returned so the caller can bind it to the
    block's terminal fallthrough instead of a following mark.
    """
    instrs: list[IRInstr] = []
    refusals: list[IRRefusal] = []
    instruction_addr: int | None = None
    instruction_size: int | None = None
    pending_mark: tuple[int, int, int] | None = None
    for statement_index, stmt in enumerate(statements):
        tag = _stmt_tag(stmt)
        if tag == "Ist_IMark":
            no_effect, pending_mark, instruction_addr, instruction_size = (
                _observe_imark_8616(block, pending_mark, statement_index, stmt)
            )
            if no_effect is not None:
                instrs.append(no_effect)
            continue
        pending_mark = None
        instr = _stmt_to_instr(
            stmt,
            tmps,
            conditions,
            instruction_addr=instruction_addr,
            segment_hints=segment_hints,
            tmp_exprs=tmp_exprs,
            type_environment=type_environment,
            condition_demand=condition_demand,
        )
        if instr is None:
            if tag:
                refusals.append(IRRefusal("unsupported_stmt", f"unsupported VEX statement {tag}", addr))
            continue
        instr = replace(instr, origin=vex_instruction_origin_8616(
            stmt, block_addr=addr, statement_index=statement_index,
        ))
        if instr.op == "LOAD" and tag == "Ist_WrTmp":
            tmp_id = _stmt_tmp(stmt)
            loaded_value = tmps.get(tmp_id)
            if loaded_value is not None:
                replacement = transport.observe_load(instr, loaded_value, tmp_id)
                if replacement is not None:
                    tmps[tmp_id] = replacement
                    continue
        instrs.append(instr)
    trailing_mark = (
        None
        if pending_mark is None
        else LiftedNoEffectMark8616(
            statement_index=pending_mark[0],
            addr=pending_mark[1],
            size=pending_mark[2],
        )
    )
    return instrs, refusals, instruction_addr, instruction_size, trailing_mark


def _block_successor_addrs_8616(
    vex: _VexBlockBoundary | None,
    statements: Iterable[object],
    terminal_target: int | None = None,
) -> tuple[int, ...]:
    """Collect constant exit targets plus the block's fallthrough next.

    ``terminal_target`` is a loader-linear destination already proven by the
    terminal-jump evidence for a symbolic ``next``; it takes the place the
    literal ``next`` constant held before faithful lifting made the near-jump
    composition explicit. Unproven symbolic destinations add nothing.
    """
    successor_addrs: list[int] = []
    for stmt in statements:
        if _stmt_tag(stmt) == "Ist_Exit":
            dst = _stmt_dst(stmt)
            const_dst = _const(dst)
            if const_dst is not None:
                successor_addrs.append(int(const_dst))
    next_const = _const(_vex_next(vex))
    if next_const is not None:
        successor_addrs.append(int(next_const))
    if terminal_target is not None:
        successor_addrs.append(int(terminal_target))
    return tuple(sorted(dict.fromkeys(successor_addrs)))


def _block_to_ir(
    block: object,
    *,
    return_terminal: bool = False,
    indirect_terminal_pending: bool = False,
) -> tuple[IRBlock, VexConditionTransportStats8616, TerminalJumpEvidence8616 | None]:
    """Import one angr block boundary into a typed IR block.

    ``indirect_terminal_pending`` retains a discovery-only target expression.
    It grants neither a successor nor a return claim; the explicit refusal
    prevents this partial surface from becoming universal evidence.

    ``return_terminal`` asserts the Frontend census independently proved
    this block's indirect terminal is the incoming near-CALL
    continuation. The raw ``JMP`` transfer stays on the block verbatim
    and the block carries the typed ``near_return_continuation_pending``
    refusal, so the universal registry, universal coverage, and every
    context-free consumer keep refusing the body — only an authenticated
    scoped view may expose the discharged RET surface. When the VEX exit
    cannot lift the expected Boring transfer the claim refuses rather
    than silently dropping the exit.
    """
    vex = _block_vex(block)
    addr = _block_addr(block)
    if vex is None:
        return (
            IRBlock(
                addr=addr,
                refusals=(IRRefusal("missing_vex", "block has no vex IR", addr),),
            ),
            VexConditionTransportStats8616(),
            None,
        )
    tmps: _MutableTmpValues = {}
    conditions: _MutableTmpConditions = {}
    tmp_exprs: _TmpExprs = {}
    segment_hints = block_segment_hints(block)
    statements = _vex_statements(vex)
    condition_demand = collect_vex_condition_demand_8616(statements)
    transport = VexConditionTransportNormalizer8616(
        build_vex_condition_transport_layout_8616(statements)
    )
    type_environment = _vex_type_environment(vex)
    instrs, refusals, instruction_addr, instruction_size, trailing_mark = (
        _block_statement_instrs_8616(
            statements,
            tmps,
            conditions,
            tmp_exprs,
            segment_hints,
            condition_demand,
            type_environment,
            transport,
            block,
            addr,
        )
    )
    terminal_jump = terminal_direct_jump_evidence_8616(
        block,
        vex,
        instruction_addr=instruction_addr,
        instruction_size=instruction_size,
        tmp_exprs=tmp_exprs,
        type_environment=type_environment,
    )
    refusals.extend(terminal_jump.refusals)
    terminal = terminal_control_flow_instr_8616(
        vex, instruction_addr,
        retain_boring_transfer=terminal_jump.retain or return_terminal or indirect_terminal_pending,
        proven_target=terminal_jump.proven_target,
        resolve_target=partial(
            _expr_to_value, tmps=tmps, conditions=conditions,
            type_environment=type_environment,
        ),
        block_addr=addr,
        statement_count=len(statements),
    )
    if terminal is not None:
        instrs.append(terminal)
    if indirect_terminal_pending:
        refusals.append(IRRefusal(
            IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING,
            "discovery-only indirect terminal requires authenticated invocation target evidence",
            addr,
        ))
    if return_terminal:
        if terminal is None or terminal.op != "JMP":
            refusals.append(IRRefusal(
                "continuation_terminal_unresolved",
                "proven near-return continuation has no liftable Boring exit",
                addr,
            ))
        else:
            refusals.append(IRRefusal(
                NEAR_RETURN_CONTINUATION_PENDING_KIND_8616,
                "proven near-return continuation discharges only under "
                "its bound invocation frame",
                addr,
            ))
    elif terminal is None and trailing_mark is not None:
        no_effect = terminal_no_effect_instr_8616(
            block,
            trailing_mark,
            jumpkind=_vex_jumpkind(vex),
            next_const=_const(_vex_next(vex)),
        )
        if no_effect is not None:
            instrs.append(no_effect)
    return (
        IRBlock(
            addr=addr,
            instrs=tuple(instrs),
            refusals=tuple(refusals),
            successor_addrs=_block_successor_addrs_8616(
                vex, statements, terminal_target=terminal_jump.proven_target,
            ),
        ),
        transport.stats(),
        terminal_jump,
    )


class _NativeCensusGuardSurface8616(Protocol):
    """Project-owned depth marker set by the invocation census.

    While nonzero this import is a census re-derivation, not a pipeline
    import: collection must be suppressed so the re-derived artifact
    carries the identical pre-discharge pending refusals the consumed
    artifact still has, and so census byte-binding cannot recurse back
    into premise construction.
    """

    _inertia_real16_native_census_8616: int


def _native_census_import_active_8616(project: object) -> bool:
    """Return whether this import is a bound invocation-census re-derivation."""
    try:
        depth = cast(
            _NativeCensusGuardSurface8616, project
        )._inertia_real16_native_census_8616
    except AttributeError:
        return False
    if type(depth) is not int or depth < 0:
        raise TypeError("native census import marker must be an int")
    return depth > 0


def _entry_domain_call_preservations_8616(
    project: object,
    function: object,
    function_addr: int,
    domain_artifact: IRFunctionArtifact,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Collect bound callsite CS-preservation evidence for the entry proof.

    Only the in-flight domain artifact's own block and instruction objects
    may carry evidence; a caller whose exact frontend boundary cannot be
    resolved contributes no records, so every reachable CALL keeps its
    default refusal. The decoded target resolver is the existing analysis
    owner, imported lazily to keep this module outside its dependency fan-in.
    """
    if _native_census_import_active_8616(project):
        return ()
    if not any(
        instruction.op == "CALL"
        for block in domain_artifact.blocks
        for instruction in block.instrs
    ):
        return ()
    boundary = entry_domain_caller_boundary_8616(project, function, function_addr)
    if boundary is None:
        return ()
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616

    return tuple(collect_entry_domain_call_preservations_8616(
        project,
        domain_artifact,
        boundary,
        direct_target_resolver=partial(
            resolve_direct_call_target_from_instruction_8616, project,
        ),
    ))


@dataclass(frozen=True, slots=True)
class _X86_16ImportedSurface8616:
    """Lifted pre-discharge function surface plus normalization inputs.

    Internal transport between the shared import core and the two
    artifact-finishing routes. ``condition_capture`` retains the isolated
    lift session so late normalization can ask it for the complete
    captured condition artifact exactly once, over whichever block
    surface the route finalized.
    """

    function_addr: int
    blocks: tuple[IRBlock, ...]
    refusals: tuple[IRRefusal, ...]
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616]
    transport_reports: tuple[VexConditionTransportStats8616, ...]
    condition_blocks: tuple[ConditionReliftBlock8616, ...]
    captured_accesses: tuple[IRLogicalMemoryCaptureRecord8616, ...]
    ownership: IRBlockOwnershipArtifact8616
    condition_capture: ConditionLiftCaptureSession8616
    dead_temporary_normalization: DeadTemporarySurfaceNormalizationResult8616 | None = None


@dataclass(frozen=True, slots=True)
class RawIRFunctionImportBundle8616:
    """Pre-discharge typed import product for one function surface.

    ``artifact`` is the identical fully normalized raw artifact — pending
    terminal-jump refusals retained, logical-memory and condition
    normalization applied — never an earlier pre-normalization body. It
    is the object a consuming in-flight invocation owns, so scoped
    construction binds this identity and never substitutes a relifted
    look-alike. ``terminal_evidence`` retains the per-block decoded
    terminal-jump evidence the same import produced; it is the only
    evidence surface the entry-domain proof may consume for this
    artifact. A bundle is transport evidence for exactly one surface:
    nothing here registers, publishes, or attaches the artifact. The exception
    is a typed deadline-refused bundle: it retains partial, unnormalized facts
    and terminal evidence only for diagnostics, never as a proof surface.
    """

    artifact: IRFunctionArtifact
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616]

    def __post_init__(self) -> None:
        """Freeze the retained evidence map into the bundle's own view."""
        object.__setattr__(
            self,
            "terminal_evidence",
            MappingProxyType(dict(self.terminal_evidence)),
        )


def _import_x86_16_function_surface_8616(
    project: object, function: object,
) -> _X86_16ImportedSurface8616:
    """Reuse isolated native facts while retaining fresh proof and finishing work."""
    function = _native_import_boundary_8616(project, function)
    return request_native_surface_8616(
        project, function, _lift_x86_16_function_surface_8616,
        producers=_native_import_producers_8616(),
        admit=_native_surface_copyable_8616,
        clone=_copy_native_surface_8616,
    )


def _native_import_boundary_8616(project: object, function: object) -> object:
    """Recover native block splits only within authenticated supplied extents.

    A recovered graph may merge a jump-only block into its predecessor while
    another native branch still targets that interior instruction. Its blocks
    remain byte witnesses, but their heads are not a complete native census.
    The frontend reconstructs those heads without admitting bytes in gaps.
    An unavailable witness leaves the existing import/refusal path unchanged;
    it never authorizes a larger function or overrides an exact boundary.
    """
    if isinstance(function, ExactFunctionRangeBoundary8616) or direct_evidence_deadline_expired_8616(project):
        return function
    witness = capture_function_boundary_8616(project, function)
    if witness is None or direct_evidence_deadline_expired_8616(project):
        return function
    boundary = restore_function_boundary_8616(project, witness)
    return function if boundary is None else boundary


def _native_import_producers_8616() -> tuple[object, ...]:
    """Name the authoritative producers for raw lifting and cached projections."""
    return (
        _block_to_ir, canonicalize_ir_block_ownership_8616,
        isolated_condition_lift_session_8616, collect_accesses_for_function,
        collect_accesses_for_block, _lift_x86_16_function_surface_8616,
        _import_x86_16_function_surface_8616, _native_surface_copyable_8616,
        _native_import_boundary_8616, capture_function_boundary_8616,
        restore_function_boundary_8616,
        _copy_native_surface_8616,
        seed_native_copy_memo_8616, native_copy_memo_producers_8616,
        *native_copy_memo_producers_8616(),
        _wrtmp_instr_8616, _wrtmp_select_instr_8616, _bound_select_atom_8616,
        _expr_cond, _expr_iftrue, _expr_iffalse, _unop_result_bits_8616,
        _normalize_native_temporaries_8616,
        *dead_temporary_surface_producers_8616(),
    )


def _copy_native_surface_8616(surface: _X86_16ImportedSurface8616) -> _X86_16ImportedSurface8616:
    """Detach the complete native graph while preserving its internal sharing.

    Frozen dataclasses are not an isolation boundary: a changed consumer node
    must never also change its cached native oracle. One deepcopy memo keeps
    cross-field DAG relationships intact without sharing nodes with callers.
    Exact owned nodes use typed detached constructors in that same memo;
    other objects retain standard deepcopy behavior. Admission already
    rejects opaque condition operands.
    """
    memo = seed_native_copy_memo_8616(surface.blocks)
    if surface.dead_temporary_normalization is not None:
        for result in surface.dead_temporary_normalization.results:
            seed_native_decisions_8616(result.decisions, memo)
    return deepcopy(surface, memo)


def _native_surface_copyable_8616(
    surface: _X86_16ImportedSurface8616, boundary: ExactFunctionRangeBoundary8616,
) -> bool:
    """Retain complete lift inventories, never transient decode failures."""
    return (
        surface.condition_capture._successful_blocks == boundary.block_addrs_set
        and sum(len(block.instrs) for block in surface.blocks) <= 16384
        and native_capture_copyable_8616(surface.condition_capture)
    )


def _native_surface_facts_8616(
    surface: _X86_16ImportedSurface8616,
) -> ImmutableSourceGraphFacts8616 | None:
    """Canonicalize the retained native surface once per session record.

    The frozen facts replay the exact surface ``source_graphs_equal_8616``
    validates — function root, block census, instruction fields and
    refusals — plus the sealed function/block refusal evidence compared
    explicitly by callers. A foreign surface type yields ``None`` so the
    rebind refuses rather than guessing; malformed owned graphs propagate
    the canonical owner's typed serialization refusal.
    """
    if type(surface) is not _X86_16ImportedSurface8616:
        return None
    from .source_graph_binding import capture_immutable_source_graph_facts_8616

    return capture_immutable_source_graph_facts_8616(
        surface.function_addr, surface.blocks, surface.refusals)


def _detached_terminal_evidence_8616(
    surface: _X86_16ImportedSurface8616,
) -> Mapping[int, TerminalJumpEvidence8616]:
    """Detach terminal evidence for one authenticated raw rebinding.

    The retained record's surface stays private; every authenticated rebind
    receives its own deep copy so a mutated evidence value can never reach
    the retained native oracle or a later consumer.
    """
    return deepcopy(surface.terminal_evidence)


def _normalize_native_temporaries_8616(
    project: object, blocks: tuple[IRBlock, ...],
    condition_capture: ConditionLiftCaptureSession8616,
    captured_accesses: tuple[IRLogicalMemoryCaptureRecord8616, ...],
    terminal_evidence: Mapping[int, TerminalJumpEvidence8616],
) -> DeadTemporarySurfaceNormalizationResult8616 | None:
    """Retain partial deadline diagnostics without starting normalization."""
    if direct_evidence_deadline_expired_8616(project):
        return None
    return normalize_dead_temporary_surface_8616(
        blocks, condition_capture, captured_accesses, terminal_evidence,
    )


def _lift_x86_16_function_surface_8616(
    project: object, function: object,
) -> _X86_16ImportedSurface8616:
    """Lift the whole surface; retain pending evidence and captures.

    Shared import core for the universal builder and the raw bundle
    operation. The returned record keeps the pre-discharge block census,
    the flat refusal surface, the retained terminal-jump evidence, and
    every late-normalization input; no entry-jump proof or discharge
    runs here. Expiry stops further block lifts while retaining collected facts;
    each finishing route must mark this partial surface as deadline-refused.
    """
    from .status_flag_lift_context import status_flag_native_source_scope_8616

    function_addr = _function_addr(function)
    blocks: list[IRBlock] = []
    refusals: list[IRRefusal] = []
    terminal_evidence_by_block: dict[int, TerminalJumpEvidence8616] = {}
    transport_reports: list[VexConditionTransportStats8616] = []
    condition_blocks: list[ConditionReliftBlock8616] = []
    exact_block_sizes: dict[int, int] | None = None
    proven_return_block_addrs: frozenset[int] = frozenset()
    pending_indirect_blocks: frozenset[int] = frozenset()
    if isinstance(function, ExactFunctionRangeBoundary8616):
        pending_indirect_blocks = frozenset(edge.block_addr for edge in function.conditional_edges)
        exact_block_sizes = {
            _block_addr(block): _external_int(cast(_BlockBoundary, block).size)
            for block in function.blocks
        }
        if function.near_return_continuations is not None:
            proven_return_block_addrs = (
                function.near_return_continuations.proven_block_addrs
            )
    project_boundary = cast(_ProjectBoundary, project)
    with (
        status_flag_native_source_scope_8616(project, function_addr),
        isolated_condition_lift_session_8616() as condition_capture,
        collect_accesses_for_function(function_addr) as captured,
    ):
        for block_addr in _function_block_addrs(function):
            if direct_evidence_deadline_expired_8616(project):
                break
            block_addr_int = _external_int(block_addr)
            capture_start = len(captured.accesses)
            if exact_block_sizes is not None and block_addr_int not in exact_block_sizes:
                refusals.append(IRRefusal(
                    "exact_block_extent_missing", "Frontend boundary lacks the decoded block extent", block_addr_int,
                ))
                continue
            try:
                with collect_accesses_for_block(block_addr_int):
                    if exact_block_sizes is None:
                        block = project_boundary.factory.block(block_addr, opt_level=0, collect_data_refs=True)
                    else:
                        block = project_boundary.factory.block(
                            block_addr, size=exact_block_sizes[block_addr_int],
                            opt_level=0, collect_data_refs=True,
                        )
            except Exception as ex:
                del captured.accesses[capture_start:]
                refusals.append(IRRefusal("block_decode_failed", str(ex), block_addr_int))
                continue
            ir_block, transport_report, terminal_evidence = _block_to_ir(
                block,
                return_terminal=block_addr_int in proven_return_block_addrs,
                indirect_terminal_pending=block_addr_int in pending_indirect_blocks,
            )
            if terminal_evidence is not None:
                terminal_evidence_by_block[block_addr_int] = terminal_evidence
            condition_capture.record_successful_block(block_addr_int)
            blocks.append(ir_block)
            condition_blocks.append(
                ConditionReliftBlock8616(
                    block_addr_int,
                    _external_int(cast(_BlockBoundary, block).size),
                )
            )
            transport_reports.append(transport_report)
            refusals.extend(ir_block.refusals)
    graph_successors = _function_graph_successors(
        function,
        frozenset(block.addr for block in blocks),
    )
    if graph_successors is not None:
        blocks = [
            IRBlock(
                addr=block.addr,
                instrs=block.instrs,
                refusals=block.refusals,
                successor_addrs=graph_successors[block.addr],
            )
            for block in blocks
        ]
    dead_temporary_normalization = _normalize_native_temporaries_8616(
        project, tuple(blocks), condition_capture, tuple(captured.accesses), terminal_evidence_by_block,
    )
    normalized_blocks = tuple(blocks) if dead_temporary_normalization is None else dead_temporary_normalization.blocks
    ownership = canonicalize_ir_block_ownership_8616(normalized_blocks)
    return _X86_16ImportedSurface8616(
        function_addr=function_addr,
        blocks=tuple(ownership.blocks),
        refusals=tuple(refusals),
        terminal_evidence=terminal_evidence_by_block,
        transport_reports=tuple(transport_reports),
        condition_blocks=tuple(condition_blocks),
        captured_accesses=tuple(captured.accesses),
        ownership=ownership,
        condition_capture=condition_capture,
        dead_temporary_normalization=dead_temporary_normalization,
    )


def _finalize_x86_16_ir_artifact_8616(
    project: object,
    surface: _X86_16ImportedSurface8616,
    blocks: tuple[IRBlock, ...],
    refusals: tuple[IRRefusal, ...],
    *,
    entry_jump_domain: EntryJumpDomainProof8616 | None = None,
    entry_jump_application: EntryJumpDomainApplication8616 | None = None,
) -> IRFunctionArtifact:
    """Late-normalize one block surface into the final typed artifact.

    Shared tail of both artifact routes: logical-memory resolution and
    condition transport run over exactly the supplied block/refusal
    surface — pending blocks for a raw import, discharged blocks for the
    universal builder — so the artifact a scope owns is always the final
    normalized body, never an earlier pre-normalization view.
    """
    captured_accesses = surface.captured_accesses
    removed_capture_sites = frozenset(
        (removal.source_block_addr, removal.instr_addr)
        for removal in surface.ownership.removals
    )
    owned_captures = tuple(
        capture
        for capture in captured_accesses
        if (capture.block_addr, capture.insn_addr) not in removed_capture_sites
    )
    logical_memory = resolve_logical_memory_accesses_8616(
        surface.function_addr,
        blocks,
        owned_captures,
    )
    expected_condition_blocks = frozenset(
        block.addr for block in blocks if len(block.successor_addrs) > 1
    )
    captured_condition_source = surface.condition_capture.complete_artifact(
        frozenset(block.addr for block in blocks),
        expected_condition_blocks,
    )
    condition_evidence = build_ir_function_condition_artifact_8616(
        project,
        surface.function_addr,
        surface.condition_blocks,
        blocks,
        captured_condition_source,
    )
    transport_stats = aggregate_vex_condition_transport_stats_8616(
        surface.transport_reports
    )
    artifact = IRFunctionArtifact(
        function_addr=surface.function_addr,
        blocks=blocks,
        refusals=refusals,
        logical_memory=logical_memory,
        condition_evidence=condition_evidence,
    )
    return IRFunctionArtifact(
        function_addr=artifact.function_addr,
        blocks=artifact.blocks,
        refusals=artifact.refusals,
        summary={
            **build_x86_16_ir_function_artifact_summary(artifact),
            **surface.ownership.stats.to_summary(),
            **surface.ownership.successor_stats.to_summary(),
            **transport_stats.to_summary(),
            **(
                {} if surface.dead_temporary_normalization is None
                else surface.dead_temporary_normalization.to_summary()
            ),
            **(
                {}
                if condition_evidence is None
                else condition_evidence.to_summary()
            ),
            **{
                f"logical_memory_{name}": count
                for name, count in logical_memory.stats.to_dict().items()
            },
            **(
                {}
                if entry_jump_domain is None or entry_jump_application is None
                else {
                    "entry_jump_domain": entry_jump_domain.to_dict(),
                    "entry_jump_domain_application": (
                        entry_jump_application.to_dict()
                    ),
                }
            ),
            "logical_memory_closed": logical_memory.closed,
            "logical_memory_capture_raw_fact_count": len(captured_accesses),
            "logical_memory_capture_owned_fact_count": len(owned_captures),
            "logical_memory_capture_ownership_discarded_count": len(captured_accesses)
            - len(owned_captures),
        },
        logical_memory=logical_memory,
        condition_evidence=condition_evidence,
    )


def _import_raw_x86_16_function_bundle_8616(
    project: object, function: object,
) -> RawIRFunctionImportBundle8616:
    """Import the raw pre-discharge bundle for one function surface.

    Internal operation: the identical product the universal builder
    produces when its entry-jump discharge runs zero transformations —
    a census re-derivation imports the same raw surface — plus the
    terminal evidence the import retained. The pending body is never
    registered, published, or attached here. Expired partial imports retain
    their collected terminal evidence but refuse without late normalization.
    """
    surface = _import_x86_16_function_surface_8616(project, function)
    if direct_evidence_deadline_expired_8616(project):
        return RawIRFunctionImportBundle8616(
            artifact=_deadline_refused_ir_import_8616(surface),
            terminal_evidence=surface.terminal_evidence,
        )
    return RawIRFunctionImportBundle8616(
        artifact=_finalize_x86_16_ir_artifact_8616(
            project, surface, surface.blocks, surface.refusals,
        ),
        terminal_evidence=surface.terminal_evidence,
    )


def raw_x86_16_import_bundle_for_artifact_8616(
    project: object,
    function: object,
    artifact: IRFunctionArtifact,
) -> RawIRFunctionImportBundle8616 | None:
    """Bind fresh import evidence to a caller-held raw artifact.

    A consuming in-flight invocation owns the identical artifact object
    its retained chain records; relifting must never substitute a new
    identity and expect the entry to follow. This operation natively
    rederives the same import and authenticates the supplied artifact
    against the rederived proof surface — function root, block census,
    instruction fields, block refusals, and successor edges under the
    domain owner's canonical form — then returns a bundle anchored on
    the supplied object itself. A ``None`` result means the held
    artifact no longer recomputes the native source surface and no
    evidence may be trusted for it; the rederived object is never
    substituted.

    Compare the normalized native surface before artifact finalization:
    finalization retains these exact blocks/refusals and derives only memory,
    condition and summary products that this operation neither compares nor
    returns. Ordinary raw imports still produce all of those products.

    Inside a live request with a validated retained native record, the same
    comparison runs over the record's PRIVATE canonical facts instead of a
    freshly cloned-and-encoded surface: the caller artifact is canonicalized
    once per call and replayed against frozen native facts — graph nodes,
    function refusals and block refusals — before detached terminal evidence
    is returned. Any missing or stale authority falls back to the ordinary
    fresh re-derivation below unchanged.
    """
    if type(artifact) is not IRFunctionArtifact or direct_evidence_deadline_expired_8616(project):
        return None
    from .source_graph_binding import (
        capture_immutable_source_graph_facts_8616,
        source_graphs_equal_8616,
    )

    resolved = _native_import_boundary_8616(project, function)
    rebound = request_native_fact_rebind_8616(
        project, resolved, _lift_x86_16_function_surface_8616,
        producers=_native_import_producers_8616(),
        admit=_native_surface_copyable_8616,
        clone=_copy_native_surface_8616,
        native_facts=_native_surface_facts_8616,
        caller_facts=lambda: capture_immutable_source_graph_facts_8616(
            artifact.function_addr, artifact.blocks, artifact.refusals),
        detached_evidence=_detached_terminal_evidence_8616,
    )
    if rebound.state is NativeFactRebindState8616.REFUSED:
        return None
    if rebound.state is NativeFactRebindState8616.AUTHENTICATED:
        if direct_evidence_deadline_expired_8616(project):
            return None
        return RawIRFunctionImportBundle8616(
            artifact=artifact,
            terminal_evidence=cast(
                Mapping[int, TerminalJumpEvidence8616], rebound.evidence),
        )
    rederived = _import_x86_16_function_surface_8616(project, resolved)
    if direct_evidence_deadline_expired_8616(project):
        return None
    if artifact.function_addr != rederived.function_addr:
        return None
    if not source_graphs_equal_8616(
        artifact.function_addr, artifact.blocks,
        rederived.function_addr, rederived.blocks,
    ):
        return None
    if artifact.refusals != rederived.refusals or direct_evidence_deadline_expired_8616(project):
        return None
    return RawIRFunctionImportBundle8616(
        artifact=artifact,
        terminal_evidence=rederived.terminal_evidence,
    )


def native_census_facts_rebind_8616(
    project: object,
    boundary: ExactFunctionRangeBoundary8616,
    caller_facts: Callable[[], ImmutableSourceGraphFacts8616 | None],
) -> NativeFactRebind8616:
    """Rebind fresh caller facts to the request-local native fact record.

    The scoped native census seals only immutable graph facts: inside a live
    import request the retained record's private canonical facts replay the
    exact comparison a fresh guarded census import would produce, so the
    caller's freshly captured snapshot authenticates the whole re-derivation
    without cloning or finalizing a second native surface. This route is
    admitted only while the canonical census importer and every census
    finishing producer keep their pinned identities — a replaced producer
    reports UNRESOLVED so the caller's ordinary guarded import still invokes
    it. All other UNRESOLVED cases (no live request, missing or stale
    record, expired budget before authentication) likewise fall back to the
    ordinary route unchanged; REFUSED already proves the caller foreign or
    the deadline spent and must never bind.
    """
    from .real16_invocation_domain import (
        _CANONICAL_NATIVE_CENSUS_IMPORT_8616,
        real16_native_census_import_8616,
    )

    finishing = _census_finishing_producers_8616()
    canonical = _CANONICAL_CENSUS_FINISHING_PRODUCERS_8616
    if (
        real16_native_census_import_8616 is not _CANONICAL_NATIVE_CENSUS_IMPORT_8616
        or len(finishing) != len(canonical)
        or any(
            offered is not required
            for offered, required in zip(finishing, canonical, strict=True)
        )
    ):
        return NativeFactRebind8616(NativeFactRebindState8616.UNRESOLVED)
    resolved = _native_import_boundary_8616(project, boundary)
    return request_native_fact_rebind_8616(
        project, resolved, _lift_x86_16_function_surface_8616,
        producers=_native_import_producers_8616(),
        admit=_native_surface_copyable_8616,
        clone=_copy_native_surface_8616,
        native_facts=_native_surface_facts_8616,
        caller_facts=caller_facts,
        detached_evidence=_detached_terminal_evidence_8616,
    )


def raw_x86_16_function_bundle_8616(
    project: object, function: object,
) -> RawIRFunctionImportBundle8616:
    """Import the raw pre-discharge bundle for a transport-time proof.

    Public seam to the internal raw-bundle operation for owners that must
    run the entry-domain proof on a fresh in-flight surface at a
    conversion boundary. The returned bundle is anchored on the identical
    import product: nothing registers, publishes, or attaches it.
    """
    return _import_raw_x86_16_function_bundle_8616(project, function)


def native_census_import_active_8616(project: object) -> bool:
    """Expose the census re-derivation marker for transport-time gates."""
    return _native_census_import_active_8616(project)


_UNIVERSAL_CENSUS_PROOF_PRODUCERS_8616 = (
    prove_entry_jump_domains_8616, apply_entry_jump_domain_8616,
)


def _universal_census_producers_current_8616() -> bool:
    """Keep independent normalization tied to its canonical proof producers."""
    from . import entry_jump_domain as owner

    expected_prove, expected_apply = _UNIVERSAL_CENSUS_PROOF_PRODUCERS_8616
    return (prove_entry_jump_domains_8616 is expected_prove
            and apply_entry_jump_domain_8616 is expected_apply
            and owner.prove_entry_jump_domains_8616 is expected_prove
            and owner.apply_entry_jump_domain_8616 is expected_apply)


def universally_normalized_census_blocks_8616(
    project: object, boundary: ExactFunctionRangeBoundary8616,
) -> tuple[tuple[IRBlock, ...], tuple[IRBlock, ...]] | None:
    """Reprove a leaf's universal jump normalization without caller premises.

    Return fresh raw and normalized rows for the census to bind independently.
    No source is registered or modified. A conditional proof, residual refusal,
    replaced proof producer, or CALL prevents this narrow normalization route.
    """
    if (not _universal_census_producers_current_8616()
            or boundary.project is not project
            or direct_evidence_deadline_expired_8616(project)):
        return None
    bundle = raw_x86_16_function_bundle_8616(project, boundary)
    artifact = bundle.artifact
    if any(row.op == "CALL" for block in artifact.blocks for row in block.instrs):
        return None
    proof = prove_entry_jump_domains_8616(artifact, bundle.terminal_evidence, project=project)
    application = apply_entry_jump_domain_8616(artifact, proof)
    if proof.invocation_scope is not None or proof.near_call_scope is not None:
        return None
    if (application.status is not EntryJumpDomainApplicationStatus8616.APPLIED
            or application.refusals or any(block.refusals for block in application.blocks)):
        return None
    if (direct_evidence_deadline_expired_8616(project)
            or not _universal_census_producers_current_8616()):
        return None
    return artifact.blocks, application.blocks


def _scoped_call_preservations_8616(
    project: object,
    artifact: IRFunctionArtifact,
    boundary: ExactFunctionRangeBoundary8616,
) -> tuple[EntryDomainCallPreservation8616, ...]:
    """Collect bound callsite records for one owned raw surface.

    Mirrors the universal import's collection rule on an already
    resolved ``(artifact, boundary)`` pair: a census re-derivation
    surface and a call-free surface contribute no records; everything
    else binds the artifact's own block and instruction objects through
    the shared collector and the same decoded direct-target resolver.
    """
    if _native_census_import_active_8616(project):
        return ()
    if not any(
        instruction.op == "CALL"
        for block in artifact.blocks
        for instruction in block.instrs
    ):
        return ()
    from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616

    return tuple(collect_entry_domain_call_preservations_8616(
        project,
        artifact,
        boundary,
        direct_target_resolver=partial(
            resolve_direct_call_target_from_instruction_8616, project,
        ),
    ))


def prove_scoped_x86_16_ir_function_view_8616(
    project: object,
    bundle: RawIRFunctionImportBundle8616,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    near_call_scope: NearCallJumpScope8616 | None = None,
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] | None = None,
) -> ScopedFunctionIRView8616:
    """Construct the scoped CFG view for one authenticated consuming entry.

    ``near_call_scope`` offers a distinct conditional selector-entry premise
    with its complete CALL census. It is retained by the private view and never
    converted to a full invocation domain or published as universal evidence.

    ``bundle`` must be the typed raw import product for the identical
    surface the consuming entry owns: its ``artifact`` is the
    ``source_artifact`` the view retains — including every original raw
    instruction and CALL identity — and its ``terminal_evidence`` is the
    only jump evidence the entry-domain proof may consume for it.
    ``boundary`` is the exact frontend boundary the entry authenticated.
    ``invocation_scope`` is the independently supplied consuming entry —
    never inferred from the proof's own recorded scope. Supplying
    ``call_preservations`` reuses caller records retained from the
    original import; ``None`` collects them under the same rules the
    universal import applies. Records bound to foreign instruction
    objects fail the proof's own revalidation downstream.

    Surface identity is checked before any premise work: when the
    boundary cannot name this artifact's root under this project, or no
    consuming entry was offered, the proof still runs without caller
    records or an invocation resolver and the view returns its own
    typed refusal. This function never relifts to a new identity, never
    registers or publishes the pending or transformed body, and never
    attaches ``_inertia_vex_ir_artifact``.

    Nested premise revalidation shares the existing bounded native-facts
    request cache. Every proof still runs; records expire on request exit.
    """
    with native_import_request_8616():
        return _prove_scoped_x86_16_ir_function_view_8616(
            project, bundle, boundary, invocation_scope=invocation_scope,
            call_preservations=call_preservations,
            near_call_scope=near_call_scope,
        )


def _prove_scoped_x86_16_ir_function_view_8616(
    project: object,
    bundle: RawIRFunctionImportBundle8616,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    invocation_scope: Real16InvocationDomain8616 | None = None,
    near_call_scope: NearCallJumpScope8616 | None = None,
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] | None = None,
) -> ScopedFunctionIRView8616:
    """Revalidate scoped proofs while sharing only request-local native facts."""
    if type(bundle) is not RawIRFunctionImportBundle8616:
        raise TypeError("scoped construction requires the typed raw import bundle")
    if type(bundle.artifact) is not IRFunctionArtifact:
        raise TypeError("scoped construction requires a typed IRFunctionArtifact source")
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise TypeError("scoped construction requires the exact frontend boundary")
    artifact = bundle.artifact
    records: tuple[EntryDomainCallPreservation8616, ...] = ()
    invocation_resolver: Callable[
        [int], Real16InvocationDomain8616 | None
    ] | None = None
    if (
        invocation_scope is not None
        and boundary.project is project
        and boundary.addr == artifact.function_addr
    ):
        records = (
            _scoped_call_preservations_8616(project, artifact, boundary)
            if call_preservations is None
            else call_preservations
        )
        # The consuming premise must anchor the identical raw artifact
        # object the offered entry owns; deriving it over any rebuilt
        # surface would produce a scope no supplied entry can match.
        invocation_resolver = partial(
            entry_domain_invocation_premise_8616,
            project,
            artifact,
            boundary,
            entry_call_preservations=records,
        )
    if near_call_scope is not None and invocation_scope is None:
        from .scoped_function_ir_view import _staged_scoped_function_ir_view_8616

        return _staged_scoped_function_ir_view_8616(
            artifact,
            boundary,
            bundle.terminal_evidence,
            project=project,
            near_call_scope=near_call_scope,
        )
    proof = prove_entry_jump_domains_8616(
        artifact,
        bundle.terminal_evidence,
        project=project,
        call_preservations=records,
        invocation_resolver=invocation_resolver,
        near_call_scope=near_call_scope,
        offered_invocation_scope=(invocation_scope if any(
            record.selector_projection is not None for record in records) else None),
    )
    from .scoped_function_ir_view import prove_scoped_function_ir_view_8616

    return prove_scoped_function_ir_view_8616(
        artifact, boundary, proof, invocation_scope=invocation_scope,
        near_call_scope=near_call_scope,
    )


def prove_scoped_control_obligations_view_8616(
    project: object,
    bundle: RawIRFunctionImportBundle8616,
    boundary: ExactFunctionRangeBoundary8616,
    *,
    invocation_scope: Real16InvocationDomain8616 | None,
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] | None = None,
) -> ScopedNearReturnContinuationView8616:
    """Compose both conditional discharges for a premise-derived surface.

    ``bundle`` must be the typed raw import product for the identical
    pending surface the consuming entry owns — its ``artifact`` retains
    every original block/instruction identity and its
    ``terminal_evidence`` is the only selector evidence the composition
    may consume; ``boundary`` retains the source-bound frame premise and
    proven continuation census. The scoped-control-obligations owner
    discharges the continuation evidence first, then proves the
    selector-window obligations over the continuation-effective surface
    under the same native bytes, the same boundary, and the
    independently supplied ``invocation_scope``. ``call_preservations``
    and the invocation resolver bind the identical raw artifact objects,
    exactly like the single-class scoped view owner. Nothing here
    relifts, registers, or publishes the pending body.
    """
    if type(bundle) is not RawIRFunctionImportBundle8616:
        raise TypeError("scoped construction requires the typed raw import bundle")
    if type(bundle.artifact) is not IRFunctionArtifact:
        raise TypeError("scoped construction requires a typed IRFunctionArtifact source")
    if not isinstance(boundary, ExactFunctionRangeBoundary8616):
        raise TypeError("scoped construction requires the exact frontend boundary")
    artifact = bundle.artifact
    records: tuple[EntryDomainCallPreservation8616, ...] = ()
    invocation_resolver: Callable[
        [int], Real16InvocationDomain8616 | None
    ] | None = None
    if (
        invocation_scope is not None
        and boundary.project is project
        and boundary.addr == artifact.function_addr
    ):
        records = (
            _scoped_call_preservations_8616(project, artifact, boundary)
            if call_preservations is None
            else call_preservations
        )
        # The consuming premise must anchor the identical raw artifact
        # object the offered entry owns; deriving it over any rebuilt
        # surface would produce a scope no supplied entry can match.
        invocation_resolver = partial(
            entry_domain_invocation_premise_8616,
            project,
            artifact,
            boundary,
            entry_call_preservations=records,
        )
    from .scoped_control_obligations import (
        prove_scoped_control_obligations_8616,
    )

    return prove_scoped_control_obligations_8616(
        artifact,
        boundary,
        bundle.terminal_evidence,
        project=project,
        call_preservations=records,
        invocation_resolver=invocation_resolver,
        invocation_scope=invocation_scope,
    )


def _deadline_refused_ir_import_8616(surface: _X86_16ImportedSurface8616) -> IRFunctionArtifact:
    """Retain the unnormalized raw import and refuse publication after expiry."""
    return IRFunctionArtifact(
        function_addr=surface.function_addr,
        blocks=surface.blocks,
        refusals=(*surface.refusals, IRRefusal(
            IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value,
            "direct-evidence deadline elapsed before IR normalization completed",
            surface.function_addr,
        )),
    )


def build_x86_16_ir_function_artifact(project: object, function: object) -> IRFunctionArtifact:
    """Retain the native owner before decoding, then build from fresh facts."""
    from .function_readiness_contracts import bind_function_source_owner_8616

    # The native Function holds a weak manager proxy. Keep its actual owner
    # alive before block decoding can release a temporary analysis context.
    bind_function_source_owner_8616(project, function)
    with native_import_request_8616():
        return _build_x86_16_ir_function_artifact_8616(project, function)


def _census_raw_native_blocks_8616(project: object, function: object) -> tuple[IRBlock, ...] | None:
    """Expose unchanged raw blocks only under the canonical census producers.

    Census imports skip entry discharge. Their finalizer adds annotations and
    summaries without changing blocks, so those products are not native-effect
    inputs. Replaced finishing/import producers retain the ordinary importer
    route and its callbacks rather than being silently skipped.
    """
    current = _census_finishing_producers_8616()
    canonical = _CANONICAL_CENSUS_FINISHING_PRODUCERS_8616
    if len(current) != len(canonical) or any(
        offered is not required for offered, required in zip(current, canonical, strict=True)
    ):
        return None
    return _import_x86_16_function_surface_8616(project, function).blocks


def _census_finishing_producers_8616() -> tuple[object, ...]:
    """Name every direct producer skipped by the raw census projection."""
    return (
        build_x86_16_ir_function_artifact, _build_x86_16_ir_function_artifact_8616,
        _finalize_x86_16_ir_artifact_8616, resolve_logical_memory_accesses_8616,
        build_ir_function_condition_artifact_8616,
        aggregate_vex_condition_transport_stats_8616,
        build_x86_16_ir_function_artifact_summary,
        ConditionLiftCaptureSession8616.complete_artifact,
    )


def _import_source_revision_8616(
    project: object,
    function: object,
) -> FunctionSourceRevision8616 | None:
    """Observe the canonical source generation for the supplied boundary.

    Bind the boundary this producer actually consumes. An explicit range is
    a distinct source scope even when a function-manager entry shares its head;
    registries reconstruct that scope when checking the recorded attestation.
    """
    try:
        addr = cast(_FunctionBoundary, function).addr
    except AttributeError:
        return None
    if not isinstance(addr, int) or addr < 0:
        return None
    return observed_function_source_revision_8616(
        project,
        addr,
        boundary=function,
    )


def _bind_import_source_revision_8616(
    project: object,
    function: object,
    artifact: IRFunctionArtifact,
    before: FunctionSourceRevision8616 | None,
) -> IRFunctionArtifact:
    """Attest one finalized artifact to the exact generation it consumed.

    The generation is observed both before and after the actual import —
    request-local surface reuse included — so a stamp is attached only when
    both ends prove the same unchanged generation. A mid-import change keeps
    the artifact but marks it refused; an unobservable generation leaves it
    unattested, so publication records only an observed binding.
    """
    after = _import_source_revision_8616(project, function)
    if before is None or after is None:
        return artifact
    if before != after:
        return replace(
            artifact,
            refusals=(
                *artifact.refusals,
                IRRefusal(
                    "source_revision_changed",
                    "function source generation changed during IR import",
                ),
            ),
        )
    stamped = replace(artifact, source_revision=after)
    body_digest = function_artifact_body_digest_8616(stamped)
    if body_digest is not None:
        record_function_build_attestation_8616(
            project,
            stamped.function_addr,
            body_digest,
            after,
            "x86_16_vex_ir",
            boundary=function,
        )
    return stamped


def _build_x86_16_ir_function_artifact_8616(project: object, function: object) -> IRFunctionArtifact:
    """Import a recovered function or the exact Frontend block partition.

    Owned exact boundaries supply byte-proven decode extents. Lifting those
    extents keeps instruction effects and logical-memory captures in their
    canonical owner instead of rediscovering an overlapping unbounded tail.
    A missing owned extent refuses; it is not an invitation to guess a size.
    Failed optional entry-jump discharge preserves the raw import refusals.
    Its separate application summary retains the diagnostic without changing
    the native surface that scoped consumers must independently authenticate.
    """
    before_revision = _import_source_revision_8616(project, function)
    surface = _import_x86_16_function_surface_8616(project, function)
    if direct_evidence_deadline_expired_8616(project):
        return _deadline_refused_ir_import_8616(surface)
    function_addr = surface.function_addr
    blocks = list(surface.blocks)
    refusals = list(surface.refusals)
    entry_jump_domain: EntryJumpDomainProof8616 | None = None
    entry_jump_application: EntryJumpDomainApplication8616 | None = None
    # A census re-derivation must reproduce the pre-discharge artifact the
    # consumed surface carries: no callsite collection and no entry-jump
    # discharge, so the imported blocks byte-match the artifact under proof.
    census_import = _native_census_import_active_8616(project)
    if collect_pending_terminal_jumps_8616(
        surface.terminal_evidence
    ) and not census_import:
        domain_artifact = IRFunctionArtifact(
            function_addr=function_addr,
            blocks=tuple(blocks),
        )
        call_preservations = _entry_domain_call_preservations_8616(
            project, function, function_addr, domain_artifact,
        )
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refused_ir_import_8616(surface)
        # The same source-authenticated caller-domain premise that retries
        # a bare selector-window call binding may discharge a pending jump:
        # when the joint fetch-window theorem fails, the resolver is asked
        # for a complete chained premise bound to the exact jump head. No
        # boundary or source means no premise and the refusal stands.
        caller_boundary = entry_domain_caller_boundary_8616(
            project, function, function_addr
        )
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refused_ir_import_8616(surface)
        invocation_resolver = (
            None
            if caller_boundary is None
            else partial(
                entry_domain_invocation_premise_8616,
                project,
                domain_artifact,
                caller_boundary,
                entry_call_preservations=call_preservations,
            )
        )
        entry_jump_domain = prove_entry_jump_domains_8616(
            domain_artifact, surface.terminal_evidence,
            project=project,
            call_preservations=call_preservations,
            invocation_resolver=invocation_resolver,
        )
        if direct_evidence_deadline_expired_8616(project):
            return _deadline_refused_ir_import_8616(surface)
        entry_jump_application = apply_entry_jump_domain_8616(
            domain_artifact, entry_jump_domain,
        )
        if (
            entry_jump_application.status
            is EntryJumpDomainApplicationStatus8616.APPLIED
        ):
            blocks = list(entry_jump_application.blocks)
            discharged_blocks = frozenset(
                jump.block_addr for jump in entry_jump_application.applied
            )
            refusals = [
                refusal for refusal in refusals
                if not (
                    refusal.kind
                    == TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
                    and refusal.block_addr in discharged_blocks
                )
            ]
    if direct_evidence_deadline_expired_8616(project):
        return _deadline_refused_ir_import_8616(surface)
    return _bind_import_source_revision_8616(
        project,
        function,
        _finalize_x86_16_ir_artifact_8616(
            project,
            surface,
            tuple(blocks),
            tuple(refusals),
            entry_jump_domain=entry_jump_domain,
            entry_jump_application=entry_jump_application,
        ),
        before_revision,
    )


@dataclass
class _ArtifactSummaryTally8616:
    """Mutable census state for one IR artifact summary pass."""

    space_counts: dict[str, int] = field(default_factory=lambda: {space.value: 0 for space in MemSpace})
    address_space_counts: dict[str, int] = field(default_factory=lambda: {space.value: 0 for space in MemSpace})
    stable_address_space_counts: dict[str, int] = field(
        default_factory=lambda: {space.value: 0 for space in MemSpace}
    )
    address_status_counts: dict[str, int] = field(
        default_factory=lambda: {status.value: 0 for status in AddressStatus}
    )
    segment_origin_counts: dict[str, int] = field(
        default_factory=lambda: {origin.value: 0 for origin in SegmentOrigin}
    )
    condition_counts: dict[str, int] = field(default_factory=dict)
    ssa_binding_count: int = 0
    aliasable_values: int = 0

    def record_value_atom(self, atom: IRValue | IRBinaryValue | IRAddress) -> None:
        """Count one value atom, descending into binary operands."""
        if isinstance(atom, IRBinaryValue):
            self.record_value_atom(atom.lhs)
            self.record_value_atom(atom.rhs)
            return
        self.space_counts[atom.space.value] = self.space_counts.get(atom.space.value, 0) + 1
        if isinstance(atom, IRAddress):
            self.address_space_counts[atom.space.value] = (
                self.address_space_counts.get(atom.space.value, 0) + 1
            )
            if atom.status == AddressStatus.STABLE:
                self.stable_address_space_counts[atom.space.value] = (
                    self.stable_address_space_counts.get(atom.space.value, 0) + 1
                )
            self.address_status_counts[atom.status.value] = (
                self.address_status_counts.get(atom.status.value, 0) + 1
            )
            self.segment_origin_counts[atom.segment_origin.value] = (
                self.segment_origin_counts.get(atom.segment_origin.value, 0) + 1
            )
        if storage_of(atom) is not None:
            self.aliasable_values += 1

    def record_condition_atom(self, cond: IRCondition) -> None:
        """Count one condition op and every atom in its arguments."""
        self.condition_counts[cond.op] = self.condition_counts.get(cond.op, 0) + 1
        for item in cond.args:
            if isinstance(item, IRCondition):
                self.record_condition_atom(item)
                continue
            self.record_value_atom(item)


def build_x86_16_ir_function_artifact_summary(artifact: IRFunctionArtifact) -> dict[str, object]:
    """Summarize typed IR import facts for diagnostics and downstream gates."""
    tally = _ArtifactSummaryTally8616()
    for block in artifact.blocks:
        tally.ssa_binding_count += _block_local_ssa_binding_count_8616(block)
        for instr in block.instrs:
            atoms: tuple[IRAtom, ...] = instr.args + (() if instr.dst is None else (instr.dst,))
            for atom in atoms:
                if isinstance(atom, IRCondition):
                    tally.record_condition_atom(atom)
                    continue
                tally.record_value_atom(atom)
    frame = build_x86_16_ir_frame_access_artifact(artifact)
    return {
        "block_count": len(artifact.blocks),
        "instruction_count": sum(len(block.instrs) for block in artifact.blocks),
        "refusal_count": len(artifact.refusals),
        "space_counts": dict(sorted(tally.space_counts.items())),
        "address_space_counts": dict(sorted(tally.address_space_counts.items())),
        "stable_address_space_counts": dict(sorted(tally.stable_address_space_counts.items())),
        "address_status_counts": dict(sorted(tally.address_status_counts.items())),
        "segment_origin_counts": dict(sorted(tally.segment_origin_counts.items())),
        "condition_counts": dict(sorted(tally.condition_counts.items())),
        "aliasable_value_count": tally.aliasable_values,
        "ssa_binding_count": tally.ssa_binding_count,
        "frame_slot_count": len(frame.slots),
        "frame_refusal_count": len(frame.refusals),
    }


def _retained_codegen_function_8616(function: object, project: object, func_addr: int) -> object:
    """Validate codegen's exact function owner before importing its instruction facts."""
    boundary = cast(_FunctionBoundary, function)
    if boundary.addr != func_addr:
        raise PipelineHardError("codegen retained function address differs from C function", layer="ir")
    try:
        kb = function_knowledge_base_8616(project, function)
    except ValueError as error:
        raise PipelineHardError(str(error), layer="ir") from error
    if kb.functions.function(addr=func_addr, create=False) is not function:
        raise PipelineHardError("codegen retained function differs from its manager entry", layer="ir")
    return function


def codegen_function_8616(project: object, codegen: object) -> tuple[object, int] | None:
    """Resolve codegen's retained function for coherent IR and semantic consumers.

    Real angr codegen retains the exact function and its analysis owner. Only
    address-only adapters lacking that field use the default project lookup.
    A retained function with a conflicting address or owner is a hard error.
    """
    codegen_boundary = cast(_CodegenBoundary, codegen)
    try:
        cfunc = codegen_boundary.cfunc
    except AttributeError:
        return None
    if cfunc is None:
        return None
    try:
        func_addr = cfunc.addr
    except AttributeError:
        return None
    if not isinstance(func_addr, int):
        return None
    try:
        retained_function = codegen_boundary._func
    except AttributeError:
        # Address-only third-party adapters have no retained function. Real
        # angr codegen always does; its analysis owner must never be replaced
        # by a same-address entry in the unrelated default project KB.
        pass
    else:
        return _retained_codegen_function_8616(retained_function, project, func_addr), func_addr
    project_boundary = cast(_ProjectBoundary, project)
    function = project_boundary.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return None
    return function, func_addr


def _existing_artifacts_current_8616(
    codegen_boundary: _CodegenBoundary,
    function: object,
    func_addr: int,
) -> bool:
    """Reuse matching attachments except imports refused by an expired deadline."""
    try:
        existing_source = codegen_boundary._inertia_vex_ir_source_function_8616
        existing_artifact = codegen_boundary._inertia_raw_vex_ir_artifact_8616
        existing_frame = codegen_boundary._inertia_raw_vex_ir_frame_8616
        existing_ssa = codegen_boundary._inertia_raw_vex_ir_function_ssa_8616
    except AttributeError:
        return False
    return (
        existing_source is function
        and isinstance(existing_artifact, IRFunctionArtifact)
        and existing_artifact.function_addr == func_addr
        and all(
            refusal.kind != IRImportRefusalReason8616.DIRECT_EVIDENCE_DEADLINE_EXPIRED.value
            for refusal in existing_artifact.refusals
        )
        and existing_frame is not None
        and isinstance(existing_ssa, SSAFunctionArtifact)
        and existing_ssa.function_addr == func_addr
    )


def _attach_vex_ir_surface_8616(
    project: object, codegen_boundary: _CodegenBoundary, function: object,
    artifact: IRFunctionArtifact, function_ssa: SSAFunctionArtifact | None,
    declared_entry: DeclaredEntryInput8616 | None,
) -> None:
    """Attach the shared raw/frame/SSA surface to one codegen.

    Only an unscoped artifact may reach the universal registries; a typed
    entry input attaches conditionally to this one consumer and is
    re-retained as the identical object — never published or promoted.
    """
    from .declared_entry_pipeline import retain_declared_entry_pipeline_8616
    from .function_ssa_registry import (
        FunctionSSAArtifactStage8616,
        publish_function_ssa_artifact_8616,
    )

    if function_ssa is None:
        function_ssa = build_x86_16_function_ssa(artifact)
    frame_artifact = build_x86_16_ir_frame_access_artifact(artifact)
    if not artifact.refusals and declared_entry is None:
        publish_function_ir_artifact_8616(project, artifact)
        publish_function_ssa_artifact_8616(
            project,
            function_ssa,
            FunctionSSAArtifactStage8616.IR,
        )
    codegen_boundary._inertia_vex_ir_artifact = artifact
    codegen_boundary._inertia_vex_ir_summary = artifact.summary
    codegen_boundary._inertia_vex_ir_frame = frame_artifact
    codegen_boundary._inertia_vex_ir_function_ssa = function_ssa
    codegen_boundary._inertia_vex_ir_source_function_8616 = function
    codegen_boundary._inertia_raw_vex_ir_artifact_8616 = artifact
    codegen_boundary._inertia_raw_vex_ir_frame_8616 = frame_artifact
    codegen_boundary._inertia_raw_vex_ir_function_ssa_8616 = function_ssa
    if declared_entry is not None:
        retain_declared_entry_pipeline_8616(codegen_boundary, declared_entry)
    info = _function_info(function)
    if info is not None:
        if declared_entry is not None:
            info["x86_16_declared_entry"] = {
                "premise": declared_entry.premise.value,
                "failure": (None if declared_entry.view.failure is None
                            else declared_entry.view.failure.value),
                "detail": declared_entry.view.detail,
            }
        info["x86_16_vex_ir_artifact"] = artifact.to_dict()
        info["x86_16_vex_ir_summary"] = dict(artifact.summary)
        info["x86_16_vex_ir_frame"] = frame_artifact.to_dict()
        info["x86_16_vex_ir_function_ssa"] = function_ssa.to_dict()


def _apply_retained_native_entry_artifact_8616(
    project: object, codegen: object,
) -> NativeNearCallPipeline8616 | None:
    """Attach a retained native entry's raw bundle without claiming proof.

    Only the synchronous structuring prefix calls this private route. The
    declared owner validates deferred source membership and the retained
    entry's exact identities — never the ``authenticates`` replay — and
    the retained raw bundle attaches to this one codegen with no
    universal registry publication; the returned entry is the identical
    pinned object, even when its raw attachments were already present.
    ``None`` means no retained native entry applied and the ordinary
    public attach route owns the request. The canonical full-scope
    consume stays with ``call_stack_effects``.
    """
    from .declared_entry_pipeline import _retained_input_8616, _retained_native_entry_for_8616
    from .near_call_entry_pipeline import NativeNearCallPipeline8616

    if not isinstance(_retained_input_8616(codegen), NativeNearCallPipeline8616):
        return None
    codegen_boundary = cast(_CodegenBoundary, codegen)
    resolved = codegen_function_8616(project, codegen)
    if resolved is None:
        return None
    function, func_addr = resolved
    entry = _retained_native_entry_for_8616(project, codegen, func_addr)
    if entry is None:
        return None
    if not (_existing_artifacts_current_8616(codegen_boundary, function, func_addr)
            and codegen_boundary._inertia_vex_ir_artifact is entry.bundle.artifact):
        _attach_vex_ir_surface_8616(
            project, codegen_boundary, function,
            entry.bundle.artifact, None, entry,
        )
    return entry


def apply_x86_16_vex_ir_artifact(project: object, codegen: object) -> bool:
    """Attach or reuse typed IR for one immutable codegen function snapshot."""
    codegen_boundary = cast(_CodegenBoundary, codegen)
    resolved = codegen_function_8616(project, codegen)
    if resolved is None:
        return False
    function, func_addr = resolved
    from .declared_entry_pipeline import prepare_declared_entry_pipeline_8616

    declared_entry = prepare_declared_entry_pipeline_8616(project, codegen, func_addr)
    if _existing_artifacts_current_8616(codegen_boundary, function, func_addr) and (
        declared_entry is None
        or codegen_boundary._inertia_vex_ir_artifact is declared_entry.bundle.artifact
    ):
        return False
    from .function_ssa_registry import (
        FunctionSSAArtifactStage8616,
        FunctionSSAArtifactVerdict8616,
        registered_function_ssa_artifact_8616,
    )

    raw_resolution = registered_function_ir_artifact_8616(project, func_addr)
    ssa_resolution = registered_function_ssa_artifact_8616(project, func_addr)
    artifact = (
        raw_resolution.artifact
        if raw_resolution.verdict is FunctionIRArtifactVerdict8616.PROVEN
        else None
    )
    function_ssa = (
        ssa_resolution.artifact
        if ssa_resolution.verdict is FunctionSSAArtifactVerdict8616.PROVEN
        and ssa_resolution.stage is FunctionSSAArtifactStage8616.IR
        else None
    )
    if declared_entry is not None:
        artifact = declared_entry.bundle.artifact
        function_ssa = None
    if artifact is None:
        artifact = build_x86_16_ir_function_artifact(project, function)
    _attach_vex_ir_surface_8616(
        project, codegen_boundary, function,
        artifact, function_ssa, declared_entry,
    )
    return False

# Producer identities authenticate a block-preserving canonical finishing path.
_CANONICAL_CENSUS_FINISHING_PRODUCERS_8616 = _census_finishing_producers_8616()
