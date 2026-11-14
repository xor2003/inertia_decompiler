# cython: language_level=3, infer_types=True
"""Rebind exact balanced PUSH/POP transfers across caller-neutral calls.

Layer: Types/Lowering.
Responsibility: consume decoded memory-save instruction identity and rebind a
post-call POP projection to the exact value written by its paired PUSH. Memory
save pairs retain one stack object; immediate/register pairs materialize one
coherent architectural GP write. This pass refuses branching, mismatched
operands, and ambiguous C projections.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.

Dynamic boundary: decoded instructions, Capstone operands, and angr project,
function, and codegen objects expose third-party compatibility attributes.
"""

from __future__ import annotations
import typing
import cython

import copy
import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass
from functools import partial
from typing import Any, Protocol, cast

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.errors import SimEngineError
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_GRP_RET,
    X86_INS_CALL,
    X86_INS_LCALL,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
)

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616, _replace_c_children_8616

from .gp_register_state import (
    runtime_gp_live_in_name_8616,
    runtime_gp_name_for_variable_8616,
    runtime_gp_state_assignment_8616,
    runtime_gp_state_expr_8616,
)
from .segment_access_policy import instruction_addrs_from_node_8616
from .stack_word_recomposition import recognize_stack_word_recomposition_8616
import dataclasses
import operator
import builtins

__all__ = [
    "BalancedImmediateRegisterRestoreStats8616",
    "BalancedMemoryStackRestoreStats8616",
    "materialize_balanced_immediate_register_restores_8616",
    "rebind_balanced_memory_stack_restores_8616",
]

_DynamicValue8616 = typing.TypeAliasType("_DynamicValue8616", Any)
_MemoryOperandKey8616 = typing.TypeAliasType("_MemoryOperandKey8616", tuple[int, int, int, int, int, int])

log: logging.Logger = logging.getLogger(__name__)


class _CFunctionSurface8616(Protocol):
    """Structured function fields consumed by balanced restore lowering."""

    addr: cython.longlong
    statements: object


class _CodegenSurface8616(Protocol):
    """Owned codegen extension used by balanced restore lowering."""

    cfunc: _CFunctionSurface8616 | None
    _inertia_balanced_immediate_register_restore_stats_8616: BalancedImmediateRegisterRestoreStats8616
    _inertia_balanced_memory_stack_restore_stats_8616: BalancedMemoryStackRestoreStats8616


@dataclasses.dataclass(frozen=True, )
class BalancedMemoryStackRestoreStats8616:
    """Closed evidence census for exact memory PUSH/POP stack rebinding."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class BalancedImmediateRegisterRestoreStats8616:
    """Closed evidence census for exact immediate PUSH/register POP transfers."""

    raw_fact_count: cython.longlong
    normalized_fact_count: cython.longlong
    classified_fact_count: cython.longlong
    materialized_count: cython.longlong
    failure_count: cython.longlong


@dataclasses.dataclass(frozen=True, )
class _ImmediateRegisterTransfer8616:
    """One decoded caller-neutral immediate PUSH/register POP transfer."""

    push_addr: cython.longlong
    pop_addr: cython.longlong
    value: cython.longlong
    register_name: object
    width: cython.longlong


def _instruction_stream_8616(function: object) -> tuple[_DynamicValue8616, ...]:
    """Return one deterministic instruction stream, refusing duplicate addresses."""
    address: object
    instruction: object
    prior: object
    block: object
    wrapper: object
    instructions: dict[cython.longlong, _DynamicValue8616] = {}
    try:
        blocks = tuple(cast(_DynamicValue8616, function).blocks or ())
    except (AttributeError, TypeError):
        return ()
    for block in blocks:
        try:
            wrappers = tuple(cast(_DynamicValue8616, block).capstone.insns or ())
        except (AttributeError, TypeError):
            return ()
        for wrapper in wrappers:
            instruction = getattr(wrapper, "insn", wrapper)
            address = getattr(instruction, "address", None)
            if not isinstance(address, int) or isinstance(address, bool):
                return ()
            prior = instructions.get(address)
            if prior is not None:
                if operator.ne(getattr(prior, "id", None), getattr(instruction, "id", None)):
                    return ()
                continue
            instructions[address] = instruction
    return tuple(instructions[address] for address in builtins.iter(sorted(instructions)))


def _memory_operand_key_8616(instruction: object) -> _MemoryOperandKey8616 | None:
    """Return an exact one-operand x86 memory identity and width."""
    memory: object
    size: object
    try:
        operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or operator.ne(getattr(operands[0], "type", None), X86_OP_MEM):
        return None
    operand = operands[0]
    memory = getattr(operand, "mem", None)
    size = getattr(operand, "size", None)
    values = (
        getattr(memory, "segment", None),
        getattr(memory, "base", None),
        getattr(memory, "index", None),
        getattr(memory, "scale", None),
        getattr(memory, "disp", None),
        size,
    )
    if not all(isinstance(value, int) and not isinstance(value, bool) for value in iter(values)):
        return None
    return cast(_MemoryOperandKey8616, values)


@cython.ccall
def _register_operand_width_8616(instruction: object) -> int | None:
    """Return the exact width of one register-only stack operand."""
    width: object
    try:
        operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
    except (AttributeError, TypeError):
        return None
    if len(operands) != 1 or operator.ne(getattr(operands[0], "type", None), X86_OP_REG):
        return None
    width = getattr(operands[0], "size", None)
    return width if isinstance(width, int) and not isinstance(width, bool) and width in {2, 4} else None


@cython.ccall
def _balanced_pairs_8616(
    instructions: Iterable[object],
) -> tuple[tuple[cython.longlong, cython.longlong, int | None], ...]:
    """Pair exact LIFO memory saves and register transfers across calls."""
    address: object
    instruction_id: object
    push_addr: object
    push_key: object
    push_register_width: object
    instruction: object
    stack: list[tuple[cython.longlong, _MemoryOperandKey8616 | None, int | None]] = []
    pairs: list[tuple[cython.longlong, cython.longlong, int | None]] = []
    for instruction in instructions:
        instruction_id = getattr(instruction, "id", None)
        address = getattr(instruction, "address", None)
        if not isinstance(address, int):
            return ()
        if instruction_id in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if operator.eq(instruction_id, X86_INS_PUSH):
            stack.append(
                (
                    address,
                    _memory_operand_key_8616(instruction),
                    _register_operand_width_8616(instruction),
                )
            )
            continue
        if operator.ne(instruction_id, X86_INS_POP):
            groups = frozenset(getattr(instruction, "groups", ()) or ())
            if groups & {X86_GRP_JUMP, X86_GRP_RET}:
                # End only the current straight-line pairing window. Later
                # address-ordered windows may still contain exact local pairs.
                stack.clear()
            continue
        if not stack:
            # No local PUSH belongs to this POP. Closed windows remain valid;
            # an epilogue POP after a branch cannot invalidate their pairs.
            continue
        push_addr, push_key, push_register_width = stack.pop()
        pop_key = _memory_operand_key_8616(instruction)
        if push_key is not None and operator.eq(push_key, pop_key):
            pairs.append((push_addr, address, push_key[-1]))
            continue
        pop_register_width = _register_operand_width_8616(instruction)
        if push_register_width is not None and operator.eq(push_register_width, pop_register_width):
            pairs.append((push_addr, address, push_register_width))
    return tuple(pairs)


@cython.ccall
def _balanced_immediate_register_transfers_8616(
    instructions: Iterable[object],
) -> tuple[_ImmediateRegisterTransfer8616, ...]:
    """Pair exact LIFO immediate/register transfers in straight-line windows."""
    address: object
    instruction_id: object
    transfer: object
    instruction: object
    stack: list[tuple[cython.longlong, int | None, int | None]] = []
    transfers: list[_ImmediateRegisterTransfer8616] = []
    for instruction in instructions:
        instruction_id = getattr(instruction, "id", None)
        address = getattr(instruction, "address", None)
        if not isinstance(address, int):
            return ()
        try:
            operands = tuple(cast(_DynamicValue8616, instruction).operands or ())
        except (AttributeError, TypeError):
            return ()
        if instruction_id in {X86_INS_CALL, X86_INS_LCALL}:
            continue
        if operator.eq(instruction_id, X86_INS_PUSH):
            stack.append(_immediate_push_entry_8616(address, operands))
            continue
        if operator.eq(instruction_id, X86_INS_POP):
            if not stack:
                # Skip only this unpaired POP, preserving independent windows.
                continue
            transfer = _immediate_pop_transfer_8616(instruction, operands, address, stack.pop())
            if transfer is not None:
                transfers.append(transfer)
            continue
        groups = frozenset(getattr(instruction, "groups", ()) or ())
        if groups & {X86_GRP_JUMP, X86_GRP_RET}:
            stack.clear()
    return tuple(transfers)


@cython.ccall
def _immediate_push_entry_8616(
    address: cython.longlong,
    operands: object,
) -> tuple[cython.longlong, int | None, int | None]:
    """Return one decoded immediate-PUSH stack entry."""
    immediate: object
    width: object
    if len(operands) != 1 or operator.ne(getattr(operands[0], "type", None), X86_OP_IMM):
        return (address, None, None)
    immediate = getattr(operands[0], "imm", None)
    width = getattr(operands[0], "size", None)
    return (
        address,
        immediate if isinstance(immediate, int) else None,
        width if isinstance(width, int) and width > 0 else None,
    )


@cython.ccall
def _immediate_pop_operand_shape_8616(
    immediate: object,
    immediate_width: object,
    register_id: object,
    width: object,
) -> object:
    """Return validated (immediate, immediate_width, register_id, width) or None."""
    if immediate is None or immediate_width is None or not isinstance(register_id, int):
        return None
    if not isinstance(width, int) or width not in {2, 4} or immediate_width > width:
        return None
    return (immediate, immediate_width, register_id, width)


@cython.ccall
def _immediate_pop_transfer_8616(
    instruction: object,
    operands: object,
    address: cython.longlong,
    entry: object,
) -> _ImmediateRegisterTransfer8616 | None:
    """Return one proven register-POP transfer for its paired immediate PUSH."""
    register_id: object
    shape: object
    width: object
    push_addr, immediate, immediate_width = entry
    if len(operands) != 1 or operator.ne(getattr(operands[0], "type", None), X86_OP_REG):
        return None
    register_id = getattr(operands[0], "reg", None)
    width = getattr(operands[0], "size", None)
    shape = _immediate_pop_operand_shape_8616(immediate, immediate_width, register_id, width)
    if shape is None:
        return None
    immediate, immediate_width, register_id, width = shape
    try:
        register_name = str(cast(_DynamicValue8616, instruction).reg_name(register_id)).lower()
    except (AttributeError, TypeError, ValueError):
        return None
    if runtime_gp_live_in_name_8616(register_name) is None:
        return None
    immediate_mask = (1 << (immediate_width * 8)) - 1
    normalized = immediate & immediate_mask
    if immediate_width < width and normalized & (1 << (immediate_width * 8 - 1)):
        normalized -= 1 << (immediate_width * 8)
    return _ImmediateRegisterTransfer8616(
        push_addr=push_addr,
        pop_addr=address,
        value=normalized & ((1 << (width * 8)) - 1),
        register_name=register_name,
        width=width,
    )


@cython.ccall
def _register_cvar_matches_8616(
    node: object,
    *,
    register_offset: cython.longlong,
    width: cython.longlong,
) -> cython.bint:
    """Return whether one C variable is the exact decoded register view."""
    return (
        isinstance(node, structured_c.CVariable)
        and isinstance(node.variable, SimRegisterVariable)
        and operator.eq(node.variable.reg, register_offset)
        and operator.eq(node.variable.size, width)
    )


@cython.ccall
def _assignment_writes_stack_pointer_8616(
    statement: object,
    registers: object,
) -> cython.bint:
    """Return whether one assignment owns the decoded POP stack increment."""
    if not isinstance(statement, structured_c.CAssignment):
        return False
    lhs = statement.lhs
    if not isinstance(lhs, structured_c.CVariable):
        return False
    if runtime_gp_name_for_variable_8616(lhs.variable) == "esp":
        return True
    if not isinstance(lhs.variable, SimRegisterVariable):
        return False
    shapes = {
        shape
        for name, shape in builtins.iter(registers.items())
        if name.lower() in {"sp", "esp"} and isinstance(shape, tuple) and len(shape) >= 2
    }
    return (lhs.variable.reg, lhs.variable.size) in shapes


@cython.ccall
def materialize_balanced_immediate_register_restores_8616(
    codegen: object,
    function: object,
    *,
    project: object | None = None,
) -> cython.bint:
    """Materialize exact immediate PUSH/register POP transfers into GP state."""
    arch: object
    cfunc: object
    registers: object
    transfer: object
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    empty = BalancedImmediateRegisterRestoreStats8616(0, 0, 0, 0, 0)
    if cfunc is None or function is None or not isinstance(cfunc.statements, structured_c.CStatements):
        surface._inertia_balanced_immediate_register_restore_stats_8616 = empty
        return False
    if project is None:
        project = getattr(codegen, "project", None)
    arch = getattr(project, "arch", None)
    registers = getattr(arch, "registers", None)
    if not isinstance(registers, dict):
        surface._inertia_balanced_immediate_register_restore_stats_8616 = empty
        return False
    transfers = _balanced_immediate_register_transfers_8616(_instruction_stream_8616(function))
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-register-restore] function=%#x transfers=%s",
            cfunc.addr,
            transfers,
        )
    classified = 0
    materialized = 0
    changed = False
    containers = _statements_containers_8616(cfunc.statements)
    for transfer in transfers:
        classified_delta, materialized_delta, transfer_changed = _materialize_transfer_8616(
            containers=containers,
            transfer=transfer,
            registers=registers,
            codegen=codegen,
            arch=arch,
            function_addr=cfunc.addr,
        )
        classified += classified_delta
        materialized += materialized_delta
        changed = transfer_changed or changed
    raw_count = len(transfers)
    surface._inertia_balanced_immediate_register_restore_stats_8616 = (
        BalancedImmediateRegisterRestoreStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=raw_count,
            classified_fact_count=classified,
            materialized_count=materialized,
            failure_count=max(raw_count - classified, 0) + max(classified - materialized, 0),
        )
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-register-restore] function=%#x raw=%d classified=%d materialized=%d changed=%s",
            cfunc.addr,
            raw_count,
            classified,
            materialized,
            changed,
        )
    return changed


@cython.ccall
def _statements_containers_8616(
    root: structured_c.CStatements,
) -> tuple[structured_c.CStatements, ...]:
    """Return every unique structured statements container in one C tree."""
    return tuple(
        {
            id(node): node
            for node in iter((root, ) + tuple(_iter_c_nodes_deep_8616(root)))
            if isinstance(node, structured_c.CStatements)
        }.values()
    )


@cython.ccall
def _pop_match_containers_8616(
    containers: object,
    transfer: _ImmediateRegisterTransfer8616,
    registers: object,
) -> object:
    """Collect every POP-stack-pointer assignment site matching one transfer."""
    container: object
    index: object
    statement: object
    matches: list[tuple[structured_c.CStatements, cython.longlong]] = []
    for container in containers:
        for index, statement in enumerate(tuple(container.statements)):
            addresses = (
                _statement_instruction_addrs_8616(statement)
                if isinstance(statement, structured_c.CAssignment)
                else instruction_addrs_from_node_8616(statement)
            )
            if transfer.pop_addr in addresses and _assignment_writes_stack_pointer_8616(
                statement,
                registers,
            ):
                matches.append((container, index))
    return matches


@cython.ccall
def _debug_pop_matches_8616(
    transfer: _ImmediateRegisterTransfer8616,
    matches: object,
) -> None:
    """Report an unmatched or ambiguous POP marker site when debugging."""
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-register-restore] pop=%#x matches=%d",
            transfer.pop_addr,
            len(matches),
        )


def _ensure_immediate_assignment_8616(
    container: structured_c.CStatements,
    marker_index: cython.longlong,
    transfer: _ImmediateRegisterTransfer8616,
    codegen: object,
    arch: object,
    function_addr: cython.longlong,
) -> bool | None:
    """Insert the immediate-restore assignment unless already present.

    Returns whether an assignment was inserted; None when the runtime GP state
    assignment cannot be built and the transfer must be abandoned.
    """
    assignment: object
    existing: object
    existing = next(
        (
            statement
            for statement in iter(container.statements)
            if isinstance(statement, structured_c.CAssignment)
            and operator.eq(statement.tags.get("inertia_x86_16_balanced_immediate_pop"), transfer.pop_addr)
        ),
        None,
    )
    if existing is not None:
        return False
    value = structured_c.CConstant(
        transfer.value,
        SimTypeShort(False).with_arch(cast(_DynamicValue8616, arch)),
        codegen=codegen,
    )
    assignment = runtime_gp_state_assignment_8616(
        transfer.register_name,
        value,
        codegen=codegen,
        function_addr=function_addr,
    )
    if assignment is None:
        return None
    assignment.tags.update(
        {
            "ins_addr": transfer.pop_addr,
            "inertia_x86_16_balanced_immediate_pop": transfer.pop_addr,
            "inertia_source_instruction_addrs": (
                transfer.push_addr,
                transfer.pop_addr,
            ),
        }
    )
    container.statements.insert(marker_index, assignment)
    return True


@cython.ccall
def _immediate_read_replacement_8616(
    node: object,
    *,
    register_offset: cython.longlong,
    width: cython.longlong,
    register_name: object,
    codegen: object,
    function_addr: cython.longlong,
) -> object:
    """Project one post-POP register read from coherent runtime state."""
    replacement: object
    if not _register_cvar_matches_8616(
        node,
        register_offset=register_offset,
        width=width,
    ):
        return node
    replacement = runtime_gp_state_expr_8616(
        register_name,
        codegen=codegen,
        function_addr=function_addr,
    )
    return replacement if replacement is not None else node


@cython.ccall
def _replace_register_reads_8616(
    container: structured_c.CStatements,
    marker_index: cython.longlong,
    register_offset: cython.longlong,
    width: cython.longlong,
    register_name: object,
    codegen: object,
    function_addr: cython.longlong,
) -> cython.bint:
    """Rewrite post-POP register reads through coherent runtime state."""
    statement: object
    changed = False
    replace_read = partial(
        _immediate_read_replacement_8616,
        register_offset=register_offset,
        width=width,
        register_name=register_name,
        codegen=codegen,
        function_addr=function_addr,
    )
    for statement in tuple(container.statements[marker_index + 1 :]):
        if isinstance(statement, structured_c.CAssignment) and _register_cvar_matches_8616(
            statement.lhs,
            register_offset=register_offset,
            width=width,
        ):
            break
        if _replace_c_children_8616(statement, replace_read):
            changed = True
    return changed




@cython.ccall
def _materialize_transfer_8616(
    *,
    containers: object,
    transfer: _ImmediateRegisterTransfer8616,
    registers: object,
    codegen: object,
    arch: object,
    function_addr: cython.longlong,
) -> tuple[cython.longlong, cython.longlong, cython.bint]:
    """Materialize one transfer; return (classified, materialized, changed) deltas."""
    inserted: object
    shape: object
    shape = registers.get(transfer.register_name)
    if not isinstance(shape, tuple) or len(shape) < 2 or operator.ne(shape[1], transfer.width):
        return (0, 0, False)
    register_offset = shape[0]
    if not isinstance(register_offset, int):
        return (0, 0, False)
    matches = _pop_match_containers_8616(containers, transfer, registers)
    if len(matches) != 1:
        _debug_pop_matches_8616(transfer, matches)
        return (0, 0, False)
    container, marker_index = matches[0]
    inserted = _ensure_immediate_assignment_8616(
        container,
        marker_index,
        transfer,
        codegen,
        arch,
        function_addr,
    )
    if inserted is None:
        return (1, 0, False)
    changed = False
    if inserted:
        marker_index += 1
        changed = True
    if _replace_register_reads_8616(
        container,
        marker_index,
        register_offset,
        transfer.width,
        transfer.register_name,
        codegen,
        function_addr,
    ):
        changed = True
    return (1, 1, changed)




@cython.ccall
def _decode_instruction_8616(project: object, address: cython.longlong) -> object | None:
    """Decode one exact tagged instruction from immutable project bytes."""
    try:
        wrappers = tuple(
            cast(_DynamicValue8616, project).factory.block(
                address,
                num_inst=1,
                opt_level=0,
            ).capstone.insns
            or ()
        )
    except (AttributeError, KeyError, SimEngineError, TypeError, ValueError):
        return None
    if len(wrappers) != 1:
        return None
    return cast(object, getattr(wrappers[0], "insn", wrappers[0]))


@cython.ccall
def _decode_stack_instruction_8616(
    project: object,
    function: object,
    address: cython.longlong,
) -> object | None:
    """Decode one PUSH/POP across normalized and original linear projections."""
    delta: object
    instruction: object
    inventory: object
    candidate: object
    candidates = [address]
    delta = getattr(project, "_inertia_original_linear_delta", None)
    if isinstance(delta, int) and not isinstance(delta, bool) and delta:
        candidates.extend((address - delta, address + delta))
    inventory = getattr(function, "_inertia_instruction_by_addr_map_8616", None)
    for candidate in dict.fromkeys(candidates):
        if candidate < 0:
            continue
        instruction = inventory.get(candidate) if isinstance(inventory, dict) else None
        if instruction is None:
            instruction = _decode_instruction_8616(project, candidate)
        if (
            getattr(instruction, "id", None) in {X86_INS_PUSH, X86_INS_POP}
            and _memory_operand_key_8616(instruction) is not None
        ):
            return instruction
    return None


def _structured_pairs_8616(
    project: object,
    function: object,
    root: structured_c.CStatements,
) -> tuple[tuple[cython.longlong, cython.longlong], ...]:
    """Pair exact tagged memory saves inside one flat structured sequence."""
    candidates: object
    pairs = _structured_window_pairs_8616(project, function, root)
    candidates_by_key = _ordered_push_pop_candidates_8616(project, function, root)
    for candidates in candidates_by_key.values():
        pushes = tuple(item for item in iter(candidates) if operator.eq(item[2], X86_INS_PUSH))
        pops = tuple(item for item in iter(candidates) if operator.eq(item[2], X86_INS_POP))
        if len(pushes) == len(pops) == 1 and pushes[0][0] < pops[0][0]:
            pairs.add((pushes[0][1], pops[0][1]))
    return tuple(sorted(pairs))


@cython.ccall
def _structured_window_pairs_8616(
    project: object,
    function: object,
    root: structured_c.CStatements,
) -> object:
    """Collect LIFO PUSH/POP pairs inside each straight-line statement window."""
    container: object
    pairs: set[tuple[cython.longlong, cython.longlong]] = set()
    for container in (root, ) + tuple(_iter_c_nodes_deep_8616(root)):
        if isinstance(container, structured_c.CStatements):
            _scan_container_window_pairs_8616(project, function, container, pairs)
    return pairs


@cython.ccall
def _scan_container_window_pairs_8616(
    project: object,
    function: object,
    container: structured_c.CStatements,
    pairs: object,
) -> None:
    """Pair exact PUSH/POP addresses inside one flat statement window."""
    address: object
    instruction_id: object
    push_addr: object
    push_key: object
    statement: object
    stack: list[tuple[cython.longlong, _MemoryOperandKey8616 | None]] = []
    seen_addresses: set[cython.longlong] = set()
    for statement in tuple(container.statements):
        if not isinstance(statement, (structured_c.CAssignment, structured_c.CFunctionCall)):
            stack.clear()
            continue
        if not isinstance(statement, structured_c.CAssignment) or not _stack_variables_8616(statement):
            continue
        addresses = _statement_instruction_addrs_8616(statement)
        if len(addresses) != 1:
            stack.clear()
            continue
        address = next(iter(addresses))
        if address in seen_addresses:
            continue
        seen_addresses.add(address)
        instruction = _decode_stack_instruction_8616(project, function, address)
        instruction_id = getattr(instruction, "id", None)
        if operator.eq(instruction_id, X86_INS_PUSH):
            stack.append((address, _memory_operand_key_8616(instruction)))
            continue
        if operator.ne(instruction_id, X86_INS_POP) or not stack:
            continue
        push_addr, push_key = stack.pop()
        pop_key = _memory_operand_key_8616(instruction)
        if push_key is not None and operator.eq(push_key, pop_key):
            pairs.add((push_addr, address))


@cython.ccall
def _ordered_push_pop_candidates_8616(
    project: object,
    function: object,
    root: structured_c.CStatements,
) -> object:
    """Collect ordered exact PUSH/POP addresses grouped by memory operand key."""
    address: object
    instruction_id: object
    memory_key: object
    statement: object
    candidates_by_key: dict[_MemoryOperandKey8616, list[tuple[cython.longlong, cython.longlong, cython.longlong]]] = {}
    ordered_addresses: list[cython.longlong] = []
    for statement in _iter_c_nodes_deep_8616(root):
        if not isinstance(statement, structured_c.CAssignment) or not _stack_variables_8616(statement):
            continue
        addresses = _statement_instruction_addrs_8616(statement)
        if len(addresses) != 1:
            continue
        address = next(iter(addresses))
        if address in ordered_addresses:
            continue
        instruction = _decode_stack_instruction_8616(project, function, address)
        instruction_id = getattr(instruction, "id", None)
        memory_key = _memory_operand_key_8616(instruction)
        if instruction_id not in {X86_INS_PUSH, X86_INS_POP} or memory_key is None:
            continue
        ordered_addresses.append(address)
        candidates_by_key.setdefault(memory_key, []).append(
            (len(ordered_addresses) - 1, address, cast(int, instruction_id))
        )
    return candidates_by_key


@cython.ccall
def _stack_variables_8616(root: object) -> object:
    """Return unambiguous BP-relative stack variables in one C subtree."""
    node: object
    owner: object
    result: dict[tuple[cython.longlong, cython.longlong], structured_c.CVariable] = {}
    roots = root if isinstance(root, tuple) else (root,)
    for owner in roots:
        for node in _iter_c_nodes_deep_8616(owner):
            if not isinstance(node, structured_c.CVariable) or not isinstance(node.variable, SimStackVariable):
                continue
            variable = node.variable
            if variable.base != "bp" or not isinstance(variable.offset, int) or not isinstance(variable.size, int):
                continue
            result.setdefault((variable.offset, variable.size), node)
    return result


@cython.ccall
def _statement_instruction_addrs_8616(statement: structured_c.CAssignment) -> frozenset[cython.longlong]:
    """Return owner and descendant instruction provenance for one assignment."""
    owner: object
    addresses = set(instruction_addrs_from_node_8616(statement))
    owner = statement.tags.get("ins_addr")
    if isinstance(owner, int) and not isinstance(owner, bool):
        addresses.add(owner)
    return frozenset(addresses)


@cython.ccall
def _remove_statements_8616(root: object, removed: object) -> cython.bint:
    """Remove exact assignment objects from every structured statement owner."""
    node: object
    changed = False
    for node in (root, ) + tuple(_iter_c_nodes_deep_8616(root)):
        if not isinstance(node, structured_c.CStatements):
            continue
        retained = [statement for statement in iter(node.statements) if id(statement) not in removed]
        if operator.ne(len(retained), len(node.statements)):
            node.statements[:] = retained
            changed = True
    return changed


@cython.ccall
def _debug_memory_pair_8616(
    push_addr: cython.longlong,
    pop_addr: cython.longlong,
    push_statements: object,
    pop_statements: object,
    push_variables: object,
    pop_variables: object,
) -> None:
    """Report one decoded pair inventory when debugging."""
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-memory-restore] pair=%#x->%#x push_statements=%d pop_statements=%d push_variables=%s pop_variables=%s",
            push_addr,
            pop_addr,
            len(push_statements),
            len(pop_statements),
            tuple(sorted(push_variables)),
            tuple(sorted(pop_variables)),
        )


def _select_push_exemplar_8616(
    push_variables: object,
    word_pair: cython.bint,
) -> object:
    """Return the unique (or exact word) PUSH exemplar identity, or None."""
    if len(push_variables) == 1:
        (selected,) = push_variables.items()
        return selected
    if (
        word_pair
        and len(push_variables) == 2
        and all(identity[1] == 1 for identity in iter(push_variables))
    ):
        push_identity = min(push_variables, key=lambda identity: identity[0])
        return (push_identity, push_variables[push_identity])
    return None


@cython.ccall
def _balanced_pop_transform_8616(
    node: object,
    *,
    target_identity: object,
    push_exemplar: structured_c.CVariable,
    word_mode: cython.bint,
) -> object:
    """Rewrite one POP-projection node to the paired PUSH exemplar."""
    recomposition: object
    recomposition = recognize_stack_word_recomposition_8616(node) if word_mode else None
    if recomposition is not None:
        recomposed_variables = _stack_variables_8616((recomposition.low, recomposition.high))
        if target_identity in recomposed_variables:
            replacement = copy.copy(push_exemplar)
            replacement.variable_type = SimTypeShort(False).with_arch(
                push_exemplar.codegen.project.arch
            )
            return replacement
    if not isinstance(node, structured_c.CVariable) or not isinstance(node.variable, SimStackVariable):
        return node
    variable = node.variable
    if (variable.offset, variable.size) != target_identity:
        return node
    replacement = copy.copy(push_exemplar)
    replacement.variable_type = (
        SimTypeShort(False).with_arch(push_exemplar.codegen.project.arch)
        if word_mode
        else node.variable_type
    )
    return replacement


@cython.ccall
def _rebind_pop_statements_8616(
    pop_statements: object,
    pop_identity: object,
    exemplar: structured_c.CVariable,
    word_pair: cython.bint,
) -> cython.bint:
    """Rewrite POP reads inside every paired statement; return change flag."""
    statement: object
    transform = partial(
        _balanced_pop_transform_8616,
        target_identity=pop_identity,
        push_exemplar=exemplar,
        word_mode=word_pair,
    )
    changed = False
    for statement in pop_statements:
        if _replace_c_children_8616(statement, transform):
            changed = True
    return changed


def _rewrite_word_pair_push_8616(
    root: structured_c.CStatements,
    push_statements: object,
    push_identity: object,
    exemplar: structured_c.CVariable,
) -> cython.bint:
    """Widen the primary PUSH lhs and drop its redundant twin statements."""
    primary_push: object
    primary_push = next(
        (
            statement
            for statement in iter(push_statements)
            if isinstance(statement.lhs, structured_c.CVariable)
            and isinstance(statement.lhs.variable, SimStackVariable)
            and (statement.lhs.variable.offset, statement.lhs.variable.size)
            in {push_identity, (push_identity[0], 2)}
        ),
        None,
    )
    if primary_push is None:
        return False
    primary_push.lhs = copy.copy(exemplar)
    primary_push.lhs.variable_type = SimTypeShort(False).with_arch(
        exemplar.codegen.project.arch
    )
    redundant = frozenset(
        id(statement)
        for statement in iter(push_statements)
        if statement is not primary_push
    )
    return _remove_statements_8616(root, redundant)


def _rebind_pair_8616(
    *,
    project: object,
    function: object,
    statements: object,
    push_addr: cython.longlong,
    pop_addr: cython.longlong,
    pair_width: int | None,
    root: structured_c.CStatements,
) -> tuple[cython.longlong, cython.longlong]:
    """Rebind one decoded PUSH/POP pair; return (classified, materialized) deltas."""
    push_memory_key: object
    selected: object
    push_statements = tuple(
        statement for statement in iter(statements) if push_addr in _statement_instruction_addrs_8616(statement)
    )
    pop_statements = tuple(
        statement for statement in iter(statements) if pop_addr in _statement_instruction_addrs_8616(statement)
    )
    push_variables = _stack_variables_8616(push_statements)
    pop_variables = _stack_variables_8616(pop_statements)
    _debug_memory_pair_8616(
        push_addr,
        pop_addr,
        push_statements,
        pop_statements,
        push_variables,
        pop_variables,
    )
    push_instruction = (
        _decode_stack_instruction_8616(project, function, push_addr)
        if project is not None
        else None
    )
    push_memory_key = _memory_operand_key_8616(push_instruction)
    word_pair = pair_width == 2 or (push_memory_key is not None and push_memory_key[-1] == 2)
    if len(pop_variables) != 1:
        return (0, 0)
    selected = _select_push_exemplar_8616(push_variables, word_pair)
    if selected is None:
        return (0, 0)
    push_identity, exemplar = selected
    (pop_identity, _pop_exemplar), = pop_variables.items()
    if operator.ne(push_identity[1], pop_identity[1]) and not (
        word_pair and {push_identity[1], pop_identity[1]} <= {1, 2}
    ):
        return (0, 0)
    # Match the original byte identity before widening possibly shared storage.
    # PUSH and POP projections may refer to the same SimStackVariable object.
    changed = _rebind_pop_statements_8616(pop_statements, pop_identity, exemplar, word_pair)
    if word_pair:
        exemplar.variable.size = 2
        exemplar.variable_type = SimTypeShort(False).with_arch(exemplar.codegen.project.arch)
        changed = _rewrite_word_pair_push_8616(root, push_statements, push_identity, exemplar) or changed
    return (1, int(changed))




def rebind_balanced_memory_stack_restores_8616(
    codegen: object,
    function: object,
    *,
    project: object | None = None,
) -> cython.bint:
    """Rebind exact memory POP reads to their paired PUSH stack object."""
    cfunc: object
    pair_width: object
    pop_addr: object
    push_addr: object
    surface = cast(_CodegenSurface8616, codegen)
    cfunc = surface.cfunc
    empty = BalancedMemoryStackRestoreStats8616(0, 0, 0, 0, 0)
    if cfunc is None or function is None or not isinstance(cfunc.statements, structured_c.CStatements):
        surface._inertia_balanced_memory_stack_restore_stats_8616 = empty
        surface._inertia_balanced_immediate_register_restore_stats_8616 = (
            BalancedImmediateRegisterRestoreStats8616(0, 0, 0, 0, 0)
        )
        return False
    if project is None:
        project = getattr(codegen, "project", None)
    register_changed = materialize_balanced_immediate_register_restores_8616(
        codegen,
        function,
        project=project,
    )
    structured_pairs = (
        _structured_pairs_8616(project, function, cfunc.statements)
        if project is not None
        else ()
    )
    pairs = tuple(
        sorted(
            set(_balanced_pairs_8616(_instruction_stream_8616(function)))
            | {(push_addr, pop_addr, None) for push_addr, pop_addr in iter(structured_pairs)}
        )
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-memory-restore] function=%#x pairs=%s",
            cfunc.addr,
            pairs,
        )
    raw_count = len(pairs)
    classified = 0
    materialized = 0
    statements = tuple(
        node
        for node in builtins.iter(_iter_c_nodes_deep_8616(cfunc.statements))
        if isinstance(node, structured_c.CAssignment)
    )
    for push_addr, pop_addr, pair_width in pairs:
        classified_delta, materialized_delta = _rebind_pair_8616(
            project=project,
            function=function,
            statements=statements,
            push_addr=push_addr,
            pop_addr=pop_addr,
            pair_width=pair_width,
            root=cfunc.statements,
        )
        classified += classified_delta
        materialized += materialized_delta
    surface._inertia_balanced_memory_stack_restore_stats_8616 = BalancedMemoryStackRestoreStats8616(
        raw_count,
        raw_count,
        classified,
        materialized,
        max(raw_count - classified, 0) + max(classified - materialized, 0),
    )
    if os.environ.get("INERTIA_DEBUG_BALANCED_REGISTER_RESTORE"):
        log.warning(
            "[balanced-memory-restore] function=%#x raw=%d classified=%d materialized=%d",
            cfunc.addr,
            raw_count,
            classified,
            materialized,
        )
    return materialized > 0 or register_changed
