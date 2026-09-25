"""Prove conservative call return and storage effects from decoded binary code.

Layer: Semantics.
Responsibility: summarize reachable instruction effects for a direct call and
materialize a typed call contract only when every return proves the requested
AX range and every memory write is classified.
Owns instruction effects, flags, branch meaning, and expression interpretation;
this module narrows that ownership to register-value and segmented-memory call
effects.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
Forbidden: function/address/name special cases, rendered assembly or C text,
sidecar dependence, guessed indirect effects, and unknown-write acceptance.

Dynamic boundary: angr blocks and Capstone instruction wrappers are third-party
objects without stable static protocols. Boundary casts are kept in the small
decoder helpers below; owned summaries and contracts use direct typed access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, cast

from capstone import CS_AC_WRITE
from capstone.x86_const import (
    X86_GRP_JUMP,
    X86_GRP_RET,
    X86_INS_AND,
    X86_INS_CALL,
    X86_INS_JMP,
    X86_INS_LCALL,
    X86_INS_MOV,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_DS,
    X86_REG_EAX,
    X86_REG_ES,
    X86_REG_INVALID,
    X86_REG_SP,
    X86_REG_SS,
)

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .call_contracts import (
    CallContractEvidenceKind8616,
    IntegerValueRange8616,
    RuntimeCallReturnContract8616,
)

__all__ = ["binary_call_return_contract_8616"]

type DynamicValue = Any

_MAX_FUNCTION_BLOCKS_8616 = 128
_MAX_RECURSION_DEPTH_8616 = 8


@dataclass(frozen=True, slots=True)
class _BinaryFunctionSummary8616:
    """Conservative effects collected from every decoded function path."""

    all_returns_nonnegative_ax: bool
    return_count: int
    exact_memory_writes: tuple[IRAddress, ...]
    has_unknown_memory_writes: bool


@dataclass(frozen=True, slots=True)
class _InstructionEffects8616:
    """Memory and AX-sign effects of one decoded instruction."""

    ax_sign_clear: bool
    exact_memory_writes: tuple[IRAddress, ...]
    has_unknown_memory_write: bool


def _instruction_from_wrapper_8616(wrapper: DynamicValue) -> DynamicValue:
    """Return the Capstone instruction at the dynamic angr boundary."""
    return cast(Any, wrapper).insn


def _decode_block_8616(project: object, address: int) -> tuple[DynamicValue, ...]:
    """Decode one basic block through the dynamic angr project boundary."""
    project_dynamic = cast(Any, project)
    block = project_dynamic.factory.block(address, opt_level=0)
    return tuple(cast(Any, block).capstone.insns or ())


def _address_is_mapped_8616(project: object, address: int) -> bool:
    """Return whether an instruction address belongs to a loaded object."""
    project_dynamic = cast(Any, project)
    try:
        loader = project_dynamic.loader
    except AttributeError:
        return False
    return loader.find_object_containing(address) is not None


def _direct_target_8616(insn: DynamicValue) -> int | None:
    """Return the exact immediate target of one direct control transfer."""
    operands = tuple(cast(Any, insn).operands or ())
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    target = operands[0].imm
    return target if isinstance(target, int) else None


def _written_registers_8616(insn: DynamicValue) -> frozenset[int]:
    """Return Capstone's explicit and implicit written-register set."""
    try:
        _reads, writes = cast(Any, insn).regs_access()
    except (AttributeError, ValueError):
        return frozenset()
    return frozenset(register for register in writes if isinstance(register, int))


def _immediate_assignment_clears_ax_sign_8616(insn: DynamicValue) -> bool:
    """Prove an immediate MOV establishes a nonnegative 16-bit AX value."""
    if cast(Any, insn).id != X86_INS_MOV:
        return False
    operands = tuple(cast(Any, insn).operands or ())
    if (
        len(operands) != 2
        or operands[0].type != X86_OP_REG
        or operands[1].type != X86_OP_IMM
    ):
        return False
    register = operands[0].reg
    immediate = operands[1].imm
    if not isinstance(immediate, int):
        return False
    if register == X86_REG_AH:
        return immediate & 0x80 == 0
    if register in {X86_REG_AX, X86_REG_EAX}:
        return immediate & 0x8000 == 0
    return False


def _and_clears_ax_sign_8616(insn: DynamicValue) -> bool:
    """Prove an immediate AND clears AX's sign bit."""
    if cast(Any, insn).id != X86_INS_AND:
        return False
    operands = tuple(cast(Any, insn).operands or ())
    if (
        len(operands) != 2
        or operands[0].type != X86_OP_REG
        or operands[1].type != X86_OP_IMM
    ):
        return False
    register = operands[0].reg
    immediate = operands[1].imm
    if not isinstance(immediate, int):
        return False
    if register == X86_REG_AH:
        return immediate & 0x80 == 0
    if register in {X86_REG_AX, X86_REG_EAX}:
        return immediate & 0x8000 == 0
    return False


def _memory_space_8616(mem: DynamicValue) -> MemSpace:
    """Return the architectural memory space selected by one x86 operand."""
    if mem.segment == X86_REG_ES:
        return MemSpace.ES
    if mem.segment == X86_REG_SS or mem.base in {X86_REG_BP, X86_REG_SP}:
        return MemSpace.SS
    if mem.segment in {X86_REG_INVALID, X86_REG_DS}:
        return MemSpace.DS
    return MemSpace.UNKNOWN


def _direct_addressing_8616(mem: object) -> bool:
    """Return whether one capstone mem operand is direct [disp] addressing."""
    return (
        cast(Any, mem).base == X86_REG_INVALID
        and cast(Any, mem).index == X86_REG_INVALID
        and isinstance(cast(Any, mem).disp, int)
    )


def _positive_size_8616(operand: object) -> bool:
    """Return whether one operand has a positive integer byte size."""
    return isinstance(cast(Any, operand).size, int) and cast(Any, operand).size > 0


def _memory_write_8616(operand: DynamicValue) -> tuple[IRAddress | None, bool]:
    """Classify one written memory operand as exact, local-stack, or unknown."""
    mem = cast(Any, operand).mem
    space = _memory_space_8616(mem)
    if space is MemSpace.SS:
        return None, False
    if (
        space not in {MemSpace.DS, MemSpace.ES}
        or not _direct_addressing_8616(mem)
        or not _positive_size_8616(operand)
    ):
        return None, True
    return (
        IRAddress(
            space=space,
            offset=mem.disp & 0xFFFF,
            size=operand.size,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        False,
    )


def _instruction_effects_8616(
    insn: DynamicValue,
    incoming_ax_sign_clear: bool,
) -> _InstructionEffects8616:
    """Apply one non-call instruction to the conservative abstract state."""
    exact_writes: list[IRAddress] = []
    unknown_write = False
    for operand in tuple(cast(Any, insn).operands or ()):
        if operand.type != X86_OP_MEM or not operand.access & CS_AC_WRITE:
            continue
        exact, unknown = _memory_write_8616(operand)
        if exact is not None:
            exact_writes.append(exact)
        unknown_write = unknown_write or unknown

    written_registers = _written_registers_8616(insn)
    ax_sign_clear = incoming_ax_sign_clear
    if written_registers & {X86_REG_AX, X86_REG_AH, X86_REG_EAX}:
        ax_sign_clear = (
            _and_clears_ax_sign_8616(insn)
            or _immediate_assignment_clears_ax_sign_8616(insn)
        )
    elif written_registers == {X86_REG_AL}:
        ax_sign_clear = incoming_ax_sign_clear
    return _InstructionEffects8616(
        ax_sign_clear=ax_sign_clear,
        exact_memory_writes=tuple(exact_writes),
        has_unknown_memory_write=unknown_write,
    )


@dataclass(slots=True)
class _BinaryFunctionScan8616:
    """Mutable worklist state for one binary function summary scan."""

    project: object
    depth: int
    next_active: frozenset[int]
    cache: dict[int, _BinaryFunctionSummary8616]
    worklist: list[tuple[int, bool]]
    visited: set[tuple[int, bool]] = field(default_factory=set)
    exact_writes: set[IRAddress] = field(default_factory=set)
    unknown_write: bool = False
    return_states: list[bool] = field(default_factory=list)

    def apply_call(self, insn: DynamicValue) -> bool:
        """Transfer one direct call through the callee summary."""
        call_target = _direct_target_8616(insn)
        if call_target is None:
            self.unknown_write = True
            return False
        callee = _analyze_binary_function_8616(
            self.project,
            call_target,
            depth=self.depth + 1,
            active_targets=self.next_active,
            cache=self.cache,
        )
        self.exact_writes.update(callee.exact_memory_writes)
        self.unknown_write = (
            self.unknown_write or callee.has_unknown_memory_writes
        )
        return callee.return_count > 0 and callee.all_returns_nonnegative_ax

    def enqueue_jump(
        self,
        insn: DynamicValue,
        next_addr: int,
        ax_sign_clear: bool,
    ) -> None:
        """Enqueue the proven jump target and conditional fallthrough."""
        jump_target = _direct_target_8616(insn)
        if jump_target is None:
            self.unknown_write = True
        elif _address_is_mapped_8616(self.project, jump_target):
            self.worklist.append((jump_target, ax_sign_clear))
        else:
            self.unknown_write = True
        if insn.id != X86_INS_JMP:
            self.worklist.append((next_addr, ax_sign_clear))

    def scan_block(self, block_addr: int, ax_sign_clear: bool) -> None:
        """Decode and transfer one block onto the scan state."""
        try:
            wrappers = _decode_block_8616(self.project, block_addr)
        except (AttributeError, KeyError, ValueError):
            self.unknown_write = True
            return
        if not wrappers:
            self.unknown_write = True
            return

        for wrapper in wrappers:
            insn = _instruction_from_wrapper_8616(wrapper)
            next_addr = insn.address + insn.size
            if insn.id in {X86_INS_CALL, X86_INS_LCALL}:
                ax_sign_clear = self.apply_call(insn)
                continue

            effects = _instruction_effects_8616(insn, ax_sign_clear)
            ax_sign_clear = effects.ax_sign_clear
            self.exact_writes.update(effects.exact_memory_writes)
            self.unknown_write = (
                self.unknown_write or effects.has_unknown_memory_write
            )
            if insn.group(X86_GRP_RET):
                self.return_states.append(ax_sign_clear)
                return
            if insn.group(X86_GRP_JUMP):
                self.enqueue_jump(insn, next_addr, ax_sign_clear)
                return

        last_insn = _instruction_from_wrapper_8616(wrappers[-1])
        fallthrough = last_insn.address + last_insn.size
        if _address_is_mapped_8616(self.project, fallthrough):
            self.worklist.append((fallthrough, ax_sign_clear))
        else:
            self.unknown_write = True

    def summary(self) -> _BinaryFunctionSummary8616:
        """Materialize the converged conservative summary."""
        return _BinaryFunctionSummary8616(
            all_returns_nonnegative_ax=bool(self.return_states)
            and all(self.return_states),
            return_count=len(self.return_states),
            exact_memory_writes=tuple(
                sorted(
                    self.exact_writes,
                    key=lambda address: (
                        address.space.value,
                        address.offset,
                        address.size,
                    ),
                )
            ),
            has_unknown_memory_writes=self.unknown_write,
        )


def _analyze_binary_function_8616(
    project: object,
    target: int,
    *,
    depth: int,
    active_targets: frozenset[int],
    cache: dict[int, _BinaryFunctionSummary8616],
) -> _BinaryFunctionSummary8616:
    """Summarize all decoded paths of one direct binary function."""
    cached = cache.get(target)
    if cached is not None:
        return cached
    if (
        depth > _MAX_RECURSION_DEPTH_8616
        or target in active_targets
        or not _address_is_mapped_8616(project, target)
    ):
        return _BinaryFunctionSummary8616(False, 0, (), True)

    scan = _BinaryFunctionScan8616(
        project=project,
        depth=depth,
        next_active=active_targets | {target},
        cache=cache,
        worklist=[(target, False)],
    )
    while scan.worklist:
        block_addr, ax_sign_clear = scan.worklist.pop()
        state_key = (block_addr, ax_sign_clear)
        if state_key in scan.visited:
            continue
        if len(scan.visited) >= _MAX_FUNCTION_BLOCKS_8616:
            scan.unknown_write = True
            break
        scan.visited.add(state_key)
        scan.scan_block(block_addr, ax_sign_clear)

    summary = scan.summary()
    cache[target] = summary
    return summary


def binary_call_return_contract_8616(
    project: object,
    target: int,
) -> RuntimeCallReturnContract8616 | None:
    """Prove a nonnegative AX return and classified writes for a direct target."""
    summary = _analyze_binary_function_8616(
        project,
        target,
        depth=0,
        active_targets=frozenset(),
        cache={},
    )
    if (
        not summary.all_returns_nonnegative_ax
        or summary.return_count == 0
        or summary.has_unknown_memory_writes
    ):
        return None
    return RuntimeCallReturnContract8616(
        semantic_id=None,
        value_range=IntegerValueRange8616(minimum=0, maximum=0x7FFF),
        preserves_caller_storage=not summary.exact_memory_writes,
        evidence_kind=CallContractEvidenceKind8616.DECODED_BINARY,
        exact_memory_writes=summary.exact_memory_writes,
        has_unknown_memory_writes=False,
    )
