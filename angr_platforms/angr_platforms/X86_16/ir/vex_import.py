"""Import VEX block data into typed x86-16 IR artifacts.

Layer: IR.
Responsibility: owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from functools import partial
from typing import Any, Protocol, cast

from ..analysis.alias import storage_of
from ..analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact
from ..frontend_function_boundary import ExactFunctionRangeBoundary8616
from .block_ownership import canonicalize_ir_block_ownership_8616
from .condition_cache_relift import ConditionReliftBlock8616
from .condition_lift_capture import isolated_condition_lift_session_8616
from .core import (
    AddressStatus,
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
from .function_condition_artifact import build_ir_function_condition_artifact_8616
from .function_ir_registry import (
    FunctionIRArtifactVerdict8616,
    publish_function_ir_artifact_8616,
    registered_function_ir_artifact_8616,
)
from .logical_memory_capture import (
    collect_accesses_for_block,
    collect_accesses_for_function,
)
from .logical_memory_resolution import resolve_logical_memory_accesses_8616
from .regs import register_name_from_offset
from .ssa import build_x86_16_block_local_ssa
from .ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from .vex_addressing import SegmentHintMap, block_segment_hints, expr_to_address
from .vex_condition_demand import (
    VexConditionDemand8616,
    collect_vex_condition_demand_8616,
)
from .vex_condition_lifting import build_condition_from_binop, expr_to_condition
from .vex_condition_transport import (
    VexConditionTransportNormalizer8616,
    VexConditionTransportStats8616,
    aggregate_vex_condition_transport_stats_8616,
    build_vex_condition_transport_layout_8616,
)
from .vex_control_flow import terminal_control_flow_instr_8616
from .vex_integer_displacement import canonical_vex_integer_displacement_8616
from .vex_types import vex_expr_size_bytes

__all__ = (
    "apply_x86_16_vex_ir_artifact",
    "build_x86_16_ir_function_artifact",
    "build_x86_16_ir_function_artifact_summary",
)

_TmpValues = Mapping[int, IRValue]
_TmpConditions = Mapping[int, IRCondition]
_MutableTmpValues = dict[int, IRValue]
_MutableTmpConditions = dict[int, IRCondition]
_TmpExprs = dict[int, object]


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


class _VexBlockBoundary(Protocol):
    """Minimal pyvex block payload consumed by IR import."""

    statements: object
    next: object
    tyenv: object


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
        if not isinstance(edge, (tuple, list)) or len(edge) < 2:
            continue
        addresses: list[int] = []
        for node in edge[:2]:
            raw_address = node if isinstance(node, int) else cast(_FunctionGraphNodeBoundary, node).addr
            try:
                addresses.append(_external_int(raw_address))
            except (AttributeError, TypeError, ValueError):
                break
        if len(addresses) == 2 and addresses[0] in block_addrs and addresses[1] in block_addrs:
            successors[addresses[0]].add(addresses[1])
    return {
        address: tuple(sorted(targets))
        for address, targets in sorted(successors.items())
    }


def _function_info(function: object) -> dict[object, object] | None:
    """Return mutable angr function info metadata when available."""
    try:
        info = cast(_FunctionBoundary, function).info
    except AttributeError:
        return None
    return info if isinstance(info, dict) else None


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
    return vex_expr_size_bytes(
        expr,
        type_environment=type_environment,
        default=default,
    )


def _binary_value_from_operands_8616(
    op: str,
    left: IRValue,
    right: IRValue,
) -> IRValue:
    """Build binary IR values with width-canonical integer displacements."""
    cond = build_condition_from_binop(op, left, right)
    if cond is not None:
        return IRValue(MemSpace.TMP, name=f"cond:{cond.op}", size=1, expr=(op,))
    if "Add" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
        return IRValue(
            left.space,
            name=left.name,
            offset=canonical_vex_integer_displacement_8616(op, left.offset + int(right.const), left.size),
            size=left.size,
            expr=(op,),
        )
    if "Sub" in op and left.space == MemSpace.REG and right.space == MemSpace.CONST and right.const is not None:
        return IRValue(
            left.space,
            name=left.name,
            offset=canonical_vex_integer_displacement_8616(op, left.offset - int(right.const), left.size),
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

    def _impl() -> IRValue:
        def _unop_value() -> IRValue:
            args = _expr_args(expr)
            op = _expr_op(expr, "unop")
            if not args:
                return IRValue(MemSpace.UNKNOWN, name=op, expr=("empty_unop",))
            inner = convert(args[0], tmps, conditions)
            return IRValue(
                inner.space,
                name=inner.name,
                offset=inner.offset,
                const=inner.const,
                size=_int_size(expr, type_environment=type_environment),
                expr=(op,),
                source_tmp=inner.source_tmp,
            )

        def _binop_value() -> IRValue:
            op = _expr_op(expr)
            args = _expr_args(expr)
            if len(args) != 2:
                return IRValue(MemSpace.TMP, name=f"expr:{op}", expr=(op,))
            left = convert(args[0], tmps, conditions)
            right = convert(args[1], tmps, conditions)
            return _binary_value_from_operands_8616(op, left, right)

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
        if tag == "Iex_Const":
            return IRValue(
                MemSpace.CONST,
                const=_const(expr),
                size=_int_size(expr, type_environment=type_environment),
            )
        if tag == "Iex_Unop":
            return _unop_value()
        if tag == "Iex_Binop":
            return _binop_value()
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

    return _impl()


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
    convert = partial(_expr_to_value, type_environment=type_environment)

    def _impl() -> IRInstr | None:
        tag = _stmt_tag(stmt)
        if tag == "Ist_WrTmp":
            data = _stmt_data(stmt)
            tmp_id = _stmt_tmp(stmt)
            data_tag = _expr_tag(data)
            data_size = _int_size(data, type_environment=type_environment)
            tmp_exprs[tmp_id] = data
            dst = IRValue(
                MemSpace.TMP,
                name=f"t{tmp_id}",
                size=data_size,
                source_tmp=tmp_id,
            )
            if data_tag == "Iex_Load":
                addr = expr_to_address(
                    _expr_addr(data),
                    tmps,
                    conditions,
                    expr_to_value=convert,
                    size=data_size,
                    segment_hints=segment_hints,
                    tmp_exprs=tmp_exprs,
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
                    addr=instruction_addr,
                )
            if data_tag == "Iex_Binop":
                op = _expr_op(data, "BINOP")
                args = _expr_args(data)
                if len(args) == 2:
                    left = convert(args[0], tmps, conditions)
                    right = convert(args[1], tmps, conditions)
                    if "Cmp" in op or (
                        condition_demand.requires_eager_condition(tmp_id)
                        and any(token in op for token in ("And", "Or"))
                    ):
                        conditions[tmp_id] = expr_to_condition(
                            data,
                            tmps,
                            conditions,
                            expr_to_value=convert,
                            tmp_exprs=tmp_exprs,
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
                        size=value.size,
                        version=value.version,
                        expr=value.expr,
                        memory_access_insn=value.memory_access_insn,
                        source_tmp=tmp_id,
                    )
                    return IRInstr(
                        op=op,
                        dst=dst,
                        args=(left, right),
                        size=max(left.size, right.size),
                        addr=instruction_addr,
                    )
            if data_tag == "Iex_ITE" and condition_demand.requires_eager_condition(
                tmp_id
            ):
                cond = expr_to_condition(data, tmps, conditions, expr_to_value=convert, tmp_exprs=tmp_exprs)
                if not (
                    cond.op == "nonzero"
                    and len(cond.args) == 1
                    and isinstance(cond.args[0], IRValue)
                    and cond.args[0].space == MemSpace.UNKNOWN
                    and cond.args[0].name == "Iex_ITE"
                ):
                    conditions[tmp_id] = cond
            value = convert(data, tmps, conditions)
            tmps[tmp_id] = IRValue(
                value.space,
                name=value.name,
                offset=value.offset,
                const=value.const,
                size=value.size,
                version=value.version,
                expr=value.expr,
                memory_access_insn=value.memory_access_insn,
                source_tmp=tmp_id,
            )
            return IRInstr(op="MOV", dst=dst, args=(value,), size=value.size, addr=instruction_addr)
        if tag == "Ist_Put":
            offset = _stmt_offset(stmt)
            src = convert(_stmt_data(stmt), tmps, conditions)
            # Preserve the exact register view. Alias owns parent/slice storage
            # identity; typed IR must retain whether a byte write targets AL or
            # AH so selector semantics can consume the correct lane.
            dst_size = src.size if src.size in {1, 2, 4} else 2
            dst = IRValue(MemSpace.REG, name=register_name_from_offset(offset, size=dst_size), size=dst_size)
            return IRInstr(op="MOV", dst=dst, args=(src,), size=src.size or dst.size, addr=instruction_addr)
        if tag == "Ist_Store":
            data_expr = _stmt_data(stmt)
            data = convert(data_expr, tmps, conditions)
            addr = expr_to_address(
                _stmt_addr(stmt),
                tmps,
                conditions,
                expr_to_value=convert,
                size=data.size,
                segment_hints=segment_hints,
                tmp_exprs=tmp_exprs,
            )
            return IRInstr(op="STORE", dst=None, args=(addr, data), size=data.size, addr=instruction_addr)
        if tag == "Ist_Exit":
            cond = expr_to_condition(
                _stmt_guard(stmt), tmps, conditions, expr_to_value=convert, tmp_exprs=tmp_exprs
            )
            target = convert(_stmt_dst(stmt), tmps, conditions)
            return IRInstr(op="CJMP", dst=None, args=(cond, target), size=0, addr=instruction_addr)
        return None

    return _impl()


def _block_to_ir(
    block: object,
) -> tuple[IRBlock, VexConditionTransportStats8616]:
    """Import one angr block boundary into a typed IR block."""

    def _impl() -> tuple[IRBlock, VexConditionTransportStats8616]:
        vex = _block_vex(block)
        addr = _block_addr(block)
        if vex is None:
            return (
                IRBlock(
                    addr=addr,
                    refusals=(IRRefusal("missing_vex", "block has no vex IR", addr),),
                ),
                VexConditionTransportStats8616(),
            )
        tmps: _MutableTmpValues = {}
        conditions: _MutableTmpConditions = {}
        tmp_exprs: _TmpExprs = {}
        instrs: list[IRInstr] = []
        refusals: list[IRRefusal] = []
        segment_hints = block_segment_hints(block)
        statements = _vex_statements(vex)
        condition_demand = collect_vex_condition_demand_8616(statements)
        transport = VexConditionTransportNormalizer8616(
            build_vex_condition_transport_layout_8616(statements)
        )
        type_environment = _vex_type_environment(vex)
        instruction_addr: int | None = None
        for stmt in statements:
            tag = _stmt_tag(stmt)
            if tag == "Ist_IMark":
                instruction_addr = _stmt_instruction_addr(stmt)
                continue
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
            if instr.op == "LOAD" and tag == "Ist_WrTmp":
                tmp_id = _stmt_tmp(stmt)
                loaded_value = tmps.get(tmp_id)
                if loaded_value is not None:
                    replacement = transport.observe_load(instr, loaded_value, tmp_id)
                    if replacement is not None:
                        tmps[tmp_id] = replacement
                        continue
            instrs.append(instr)
        terminal = terminal_control_flow_instr_8616(vex, instruction_addr)
        if terminal is not None:
            instrs.append(terminal)
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
        return (
            IRBlock(
                addr=addr,
                instrs=tuple(instrs),
                refusals=tuple(refusals),
                successor_addrs=tuple(sorted(dict.fromkeys(successor_addrs))),
            ),
            transport.stats(),
        )

    return _impl()


def build_x86_16_ir_function_artifact(project: object, function: object) -> IRFunctionArtifact:
    """Build a typed IR function artifact from an angr function boundary."""
    function_addr = _function_addr(function)
    blocks: list[IRBlock] = []
    refusals: list[IRRefusal] = []
    transport_reports: list[VexConditionTransportStats8616] = []
    condition_blocks: list[ConditionReliftBlock8616] = []
    project_boundary = cast(_ProjectBoundary, project)
    with (
        isolated_condition_lift_session_8616() as condition_capture,
        collect_accesses_for_function(function_addr) as captured,
    ):
        for block_addr in _function_block_addrs(function):
            block_addr_int = _external_int(block_addr)
            capture_start = len(captured.accesses)
            try:
                with collect_accesses_for_block(block_addr_int):
                    block = project_boundary.factory.block(block_addr, opt_level=0, collect_data_refs=True)
            except Exception as ex:
                del captured.accesses[capture_start:]
                refusals.append(IRRefusal("block_decode_failed", str(ex), block_addr_int))
                continue
            ir_block, transport_report = _block_to_ir(block)
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
    ownership = canonicalize_ir_block_ownership_8616(tuple(blocks))
    blocks = list(ownership.blocks)
    captured_accesses = tuple(captured.accesses)
    removed_capture_sites = frozenset(
        (removal.source_block_addr, removal.instr_addr)
        for removal in ownership.removals
    )
    owned_captures = tuple(
        capture
        for capture in captured_accesses
        if (capture.block_addr, capture.insn_addr) not in removed_capture_sites
    )
    logical_memory = resolve_logical_memory_accesses_8616(
        function_addr,
        tuple(blocks),
        owned_captures,
    )
    expected_condition_blocks = frozenset(
        block.addr for block in blocks if len(block.successor_addrs) > 1
    )
    captured_condition_source = condition_capture.complete_artifact(
        frozenset(block.addr for block in blocks),
        expected_condition_blocks,
    )
    condition_evidence = build_ir_function_condition_artifact_8616(
        project,
        function_addr,
        tuple(condition_blocks),
        tuple(blocks),
        captured_condition_source,
    )
    transport_stats = aggregate_vex_condition_transport_stats_8616(
        tuple(transport_reports)
    )
    artifact = IRFunctionArtifact(
        function_addr=function_addr,
        blocks=tuple(blocks),
        refusals=tuple(refusals),
        logical_memory=logical_memory,
        condition_evidence=condition_evidence,
    )
    return IRFunctionArtifact(
        function_addr=artifact.function_addr,
        blocks=artifact.blocks,
        refusals=artifact.refusals,
        summary={
            **build_x86_16_ir_function_artifact_summary(artifact),
            **ownership.stats.to_summary(),
            **ownership.successor_stats.to_summary(),
            **transport_stats.to_summary(),
            **(
                {}
                if condition_evidence is None
                else condition_evidence.to_summary()
            ),
            **{
                f"logical_memory_{name}": count
                for name, count in logical_memory.stats.to_dict().items()
            },
            "logical_memory_closed": logical_memory.closed,
            "logical_memory_capture_raw_fact_count": len(captured_accesses),
            "logical_memory_capture_owned_fact_count": len(owned_captures),
            "logical_memory_capture_ownership_discarded_count": len(captured_accesses)
            - len(owned_captures),
        },
        logical_memory=logical_memory,
        condition_evidence=condition_evidence,
    )
def build_x86_16_ir_function_artifact_summary(artifact: IRFunctionArtifact) -> dict[str, object]:
    """Summarize typed IR import facts for diagnostics and downstream gates."""

    def _impl() -> dict[str, object]:
        space_counts = {space.value: 0 for space in MemSpace}
        address_space_counts = {space.value: 0 for space in MemSpace}
        stable_address_space_counts = {space.value: 0 for space in MemSpace}
        address_status_counts = {status.value: 0 for status in AddressStatus}
        segment_origin_counts = {origin.value: 0 for origin in SegmentOrigin}
        condition_counts: dict[str, int] = {}
        ssa_binding_count = 0
        aliasable_values = 0

        def _record_value_atom(atom: IRValue | IRBinaryValue | IRAddress) -> None:
            nonlocal aliasable_values
            if isinstance(atom, IRBinaryValue):
                _record_value_atom(atom.lhs)
                _record_value_atom(atom.rhs)
                return
            space_counts[atom.space.value] = space_counts.get(atom.space.value, 0) + 1
            if isinstance(atom, IRAddress):
                address_space_counts[atom.space.value] = address_space_counts.get(atom.space.value, 0) + 1
                if atom.status == AddressStatus.STABLE:
                    stable_address_space_counts[atom.space.value] = (
                        stable_address_space_counts.get(atom.space.value, 0) + 1
                    )
                address_status_counts[atom.status.value] = address_status_counts.get(atom.status.value, 0) + 1
                segment_origin_counts[atom.segment_origin.value] = (
                    segment_origin_counts.get(atom.segment_origin.value, 0) + 1
                )
            if storage_of(atom) is not None:
                aliasable_values += 1

        def _record_condition_atom(cond: IRCondition) -> None:
            condition_counts[cond.op] = condition_counts.get(cond.op, 0) + 1
            for item in cond.args:
                if isinstance(item, IRCondition):
                    _record_condition_atom(item)
                    continue
                _record_value_atom(item)

        for block in artifact.blocks:
            ssa_binding_count += len(build_x86_16_block_local_ssa(block).bindings)
            for instr in block.instrs:
                atoms: tuple[IRAtom, ...] = instr.args + (() if instr.dst is None else (instr.dst,))
                for atom in atoms:
                    if isinstance(atom, IRCondition):
                        _record_condition_atom(atom)
                        continue
                    _record_value_atom(atom)
        frame = build_x86_16_ir_frame_access_artifact(artifact)
        return {
            "block_count": len(artifact.blocks),
            "instruction_count": sum(len(block.instrs) for block in artifact.blocks),
            "refusal_count": len(artifact.refusals),
            "space_counts": dict(sorted(space_counts.items())),
            "address_space_counts": dict(sorted(address_space_counts.items())),
            "stable_address_space_counts": dict(sorted(stable_address_space_counts.items())),
            "address_status_counts": dict(sorted(address_status_counts.items())),
            "segment_origin_counts": dict(sorted(segment_origin_counts.items())),
            "condition_counts": dict(sorted(condition_counts.items())),
            "aliasable_value_count": aliasable_values,
            "ssa_binding_count": ssa_binding_count,
            "frame_slot_count": len(frame.slots),
            "frame_refusal_count": len(frame.refusals),
        }

    return _impl()


def apply_x86_16_vex_ir_artifact(project: object, codegen: object) -> bool:
    """Attach or reuse typed IR for one immutable codegen function snapshot."""
    codegen_boundary = cast(_CodegenBoundary, codegen)
    try:
        cfunc = codegen_boundary.cfunc
    except AttributeError:
        return False
    if cfunc is None:
        return False
    try:
        func_addr = cfunc.addr
    except AttributeError:
        return False
    if not isinstance(func_addr, int):
        return False
    project_boundary = cast(_ProjectBoundary, project)
    function = project_boundary.kb.functions.function(addr=func_addr, create=False)
    if function is None:
        return False
    try:
        existing_source = codegen_boundary._inertia_vex_ir_source_function_8616
        existing_artifact = codegen_boundary._inertia_raw_vex_ir_artifact_8616
        existing_frame = codegen_boundary._inertia_raw_vex_ir_frame_8616
        existing_ssa = codegen_boundary._inertia_raw_vex_ir_function_ssa_8616
    except AttributeError:
        existing_source = None
    else:
        if (
            existing_source is function
            and isinstance(existing_artifact, IRFunctionArtifact)
            and existing_artifact.function_addr == func_addr
            and existing_frame is not None
            and isinstance(existing_ssa, SSAFunctionArtifact)
            and existing_ssa.function_addr == func_addr
        ):
            return False
    from .function_ssa_registry import (
        FunctionSSAArtifactStage8616,
        FunctionSSAArtifactVerdict8616,
        publish_function_ssa_artifact_8616,
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
    if artifact is None:
        artifact = build_x86_16_ir_function_artifact(project, function)
    if function_ssa is None:
        function_ssa = build_x86_16_function_ssa(artifact)
    frame_artifact = build_x86_16_ir_frame_access_artifact(artifact)
    if not artifact.refusals:
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
    info = _function_info(function)
    if info is not None:
        info["x86_16_vex_ir_artifact"] = artifact.to_dict()
        info["x86_16_vex_ir_summary"] = dict(artifact.summary)
        info["x86_16_vex_ir_frame"] = frame_artifact.to_dict()
        info["x86_16_vex_ir_function_ssa"] = function_ssa.to_dict()
    return False
