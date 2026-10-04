"""Processor-fault outcome contract for the bounded terminal comparison.

Layer: dosunit symbolic program proof.
Responsibility: own the typed exception vocabulary and the intake decision for
native faults inside the shared symbolic terminal model. The admitted scope is
the CPU divide-error exception (#DE, architectural vector 0) produced by
decoded ``DIV``/``IDIV`` instructions — admitted through the lifter's
``Ijk_SigFPE_IntDiv`` exit evidence — and by a zero ``AAM`` immediate, which
some lifter guests leave unguarded and which is therefore decided directly
from the decoded instruction. Guards are decided against the complete
architectural fault condition (zero divisor or out-of-range quotient), never
only the subset a particular VEX guest happens to emit: the flat32 guest emits
no quotient-overflow exit for ``DIV``/``IDIV``, so the intake decision owns
that condition explicitly. A guard that cannot be proved under the declared
concrete state is a typed refusal, never a silent outcome. A fault is a
nonreturning stop: the environment declares no exception-handler dispatch —
real16 IVT and flat32 IDT delivery are outside the contract, matching the
concrete replays' ``UC_HOOK_INTR`` stop — and the code after the faulting
instruction is never lowered or compared.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import capstone
import pyvex
from capstone import x86_const as decoded_ids

from tools.dosunit import straightline_ssa as S
from tools.dosunit.terminal_memory_effects import (
    MemoryReadAuditor,
    TerminalRefusal,
    TerminalRefusalKind,
    const_eval,
)


class TerminalOutcome(StrEnum):
    """The observed terminal boundary class of a bounded trace.

    ``DECLARED_SERVICE`` is the modeled nonreturning service transfer (DOS
    ``INT 21h/AH=4Ch`` or the declared flat32 exit gateway).
    ``PROCESSOR_FAULT`` is a modeled CPU exception stop — nonreturning under
    the declared environment because no handler dispatch is in scope.
    """

    DECLARED_SERVICE = "declared_service"
    PROCESSOR_FAULT = "processor_fault"


class TerminalFaultKind(StrEnum):
    """The admitted processor-exception classes of this slice."""

    DIVIDE_ERROR = "divide_error"


class DivideFaultReason(StrEnum):
    """The proved architectural reason of a divide-error decision.

    ``PROVED_NO_FAULT`` marks the complete non-faulting verdict of
    ``decide_divide_error``; it never reaches a ``FaultOutcome``.
    """

    ZERO_DIVISOR = "zero_divisor"
    QUOTIENT_OUT_OF_RANGE = "quotient_out_of_range"
    PROVED_NO_FAULT = "proved_no_fault"


DIVIDE_ERROR_VECTOR: int = 0
"""x86 #DE exception vector, matching the concrete replay's fault receipt."""


@dataclass(frozen=True, slots=True)
class FaultOutcome:
    """The typed terminal event of a proved processor fault.

    ``site_address`` and ``encoding`` bind the outcome to the faulting
    instruction inside an admitted block receipt — the absolute address and
    the bytes are retained stale-evidence material. The admitted fault-site
    relation the comparison enforces is the entry-relative instruction-stream
    offset (``site_address - entry``): equivalent programs may load at
    different absolute addresses, but a fault at a different position inside
    the compared stream is a different observable event and must diverge.
    ``reason`` records which architectural condition of the fault kind fired
    (``zero_divisor`` or ``quotient_out_of_range`` for divide errors).
    """

    kind: TerminalFaultKind
    vector: int
    site_address: int
    encoding: bytes
    reason: DivideFaultReason


@dataclass(frozen=True, slots=True)
class DivideGuardDecision:
    """The proved verdict of one divide instruction's fault condition."""

    faulted: bool
    reason: DivideFaultReason


_SIGNAL_FAULT_KINDS: Mapping[str, TerminalFaultKind] = {
    "Ijk_SigFPE_IntDiv": TerminalFaultKind.DIVIDE_ERROR,
}
"""VEX signal jumpkinds admitted as processor-fault evidence."""

_DIVIDE_ERROR_INSTRUCTION_IDS: frozenset[int] = frozenset(
    {decoded_ids.X86_INS_DIV, decoded_ids.X86_INS_IDIV, decoded_ids.X86_INS_AAM}
)
"""Decoded instructions that may legitimately produce #DE evidence."""


def signal_fault_kind(jumpkind: str) -> TerminalFaultKind | None:
    """Map a VEX signal jumpkind to its admitted fault kind, if any."""
    return _SIGNAL_FAULT_KINDS.get(jumpkind)


def _unsigned(value: int, bits: int) -> int:
    """Mask ``value`` into an unsigned ``bits``-wide integer."""
    return value & ((1 << bits) - 1)


def _signed(value: int, bits: int) -> int:
    """Reinterpret ``value`` as a signed ``bits``-wide integer."""
    masked = _unsigned(value, bits)
    return masked - (1 << bits) if masked >= (1 << (bits - 1)) else masked


def _trunc_div(dividend: int, divisor: int) -> int:
    """Integer division truncated toward zero, matching ``idiv`` semantics."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def decide_divide_error(
    *,
    signed: bool,
    operand_bits: int,
    dividend: int,
    divisor: int,
) -> DivideGuardDecision:
    """Decide the complete architectural #DE condition of one divide.

    ``dividend`` is the implicit architectural dividend (``AX``, ``DX:AX`` or
    ``EDX:EAX`` raw bits) and ``divisor`` the instruction operand, both as raw
    machine integers — callers prove them concrete under the declared domain
    or refuse before calling. Zero divisor and out-of-range quotient are the
    fired reasons; anything else is a proved non-faulting divide. Undefined
    division is never totalized: the zero-divisor case returns its own typed
    verdict and no quotient is ever formed from it.
    """
    divisor_value = _signed(divisor, operand_bits) if signed else _unsigned(divisor, operand_bits)
    if divisor_value == 0:
        return DivideGuardDecision(True, DivideFaultReason.ZERO_DIVISOR)
    if signed:
        dividend_value = _signed(dividend, 2 * operand_bits)
        low, high = -(1 << (operand_bits - 1)), (1 << (operand_bits - 1)) - 1
    else:
        dividend_value = _unsigned(dividend, 2 * operand_bits)
        low, high = 0, (1 << operand_bits) - 1
    quotient = _trunc_div(dividend_value, divisor_value)
    if not low <= quotient <= high:
        return DivideGuardDecision(True, DivideFaultReason.QUOTIENT_OUT_OF_RANGE)
    return DivideGuardDecision(False, DivideFaultReason.PROVED_NO_FAULT)


_WIDTH_COERCIONS: frozenset[str] = frozenset({"trunc", "zext", "sext"})
"""Term ops that pass a value through a width change without altering it."""

_MEMORY_TERM_OPS: frozenset[str] = frozenset(
    {"loadle", "loadbe", "storele", "storebe", "mem_input"}
)
"""Memory-shaped term ops a fault-guard resolver must not evaluate generically."""

_RESOLUTION_NODE_LIMIT: int = 256
"""Distinct-term bound for one fault-guard resolution.

Divide operands, dividends and guard expressions are small straight-line
terms; 256 distinct nodes is generous headroom while still refusing
degenerate shared-DAG or deep-chain inputs instead of recursing without
limit. This is an internal evaluation bound, not a resource-cap increase.
"""

_LITERAL_UNWRAP_LIMIT: int = 8
"""Bound on coercion nodes unwrapped while recognizing a literal zero leaf.

Coercion chains in a guard are short; the bound keeps extraction linear and
prevents a degenerate unary chain from being walked without limit.
"""


def _literal_zero(expr: S.SsaExpr) -> bool:
    """Recognize the literal zero constant leaf of a divisor guard.

    The documented VEX shape compares the divisor term against a literal
    ``const`` zero, possibly under the transparent width-coercion chain.
    Only that leaf identifies the divisor operand: extraction never
    evaluates the other operand, so an unknown or shared-DAG divisor term
    is handed to the bounded ``FaultGate._resolve`` untouched rather than
    traversed here. A nonliteral zero expression is not recognized and the
    caller refuses honestly.
    """
    node = expr
    for _ in range(_LITERAL_UNWRAP_LIMIT):
        if node.op == "const":
            return int(node.value or 0) == 0
        if node.op not in _WIDTH_COERCIONS or len(node.args) != 1:
            return False
        node = node.args[0]
    return False


def _guard_divisor(guard: S.SsaExpr) -> S.SsaExpr | None:
    """Extract the divisor term from a lowered ``divisor == 0`` guard.

    VEX lowers the zero-divisor check as ``eq(term, 0)`` wrapped in the
    one-bit coercion chain (``1Uto…``/``…to1``) the signal exit requires;
    the divisor operand term — however it was produced, register or
    memory — is the other side. The zero side is matched as a literal
    constant leaf only, so identifying the divisor never evaluates the
    divisor term itself; a shared-DAG operand stays under the bounded
    resolver's budget. Any other guard shape is not divisor evidence and
    returns ``None`` so the caller refuses instead of guessing the operand.
    """
    expr = guard
    for _ in range(_LITERAL_UNWRAP_LIMIT):
        if expr.op not in _WIDTH_COERCIONS or len(expr.args) != 1:
            break
        expr = expr.args[0]
    if expr.op != "eq" or len(expr.args) != 2:
        return None
    left, right = expr.args
    if _literal_zero(right):
        return left
    if _literal_zero(left):
        return right
    return None


class FaultGate:
    """Admit the fault evidence of one lifted block, in instruction order.

    ``instructions`` maps each lifted instruction address to its decode;
    ``dividend`` supplies the lane's implicit dividend term for a divide
    operand width; ``initial_bytes`` resolves the lane's declared initial
    memory so a divisor loaded from ``mem_input`` can still be proved
    concrete. ``pre_check`` decides fault-capable instructions the lifter
    leaves unguarded (a zero ``AAM`` immediate — decidable from the encoding);
    ``admit_exit`` decides each ``Ist_Exit`` the lifter emits. Every divide
    instruction mark is tracked so ``finish`` can refuse a divide that
    produced no fault evidence at all.
    """

    def __init__(
        self,
        *,
        instructions: Mapping[int, capstone.CsInsn],
        dividend: Callable[[Mapping[str, S.SsaExpr], int], S.SsaExpr | None],
        initial_bytes: Callable[[int, int], bytes | None] | None = None,
    ) -> None:
        """Bind the block's decode map and the lane's fault-input resolvers."""
        self._instructions = instructions
        self._dividend = dividend
        self._initial_bytes = initial_bytes
        self._decisions: dict[int, FaultOutcome | None] = {}
        self._divide_imarks: set[int] = set()

    def pre_check(self, imark: int) -> FaultOutcome | None:
        """Decide an instruction-level fault the lifter does not guard.

        ``AAM`` divides by its immediate byte; a zero immediate is a #DE the
        flat32 guest lifts without any exit. Divide instruction marks are
        recorded so ``finish`` can demand their exit evidence.
        """
        instruction = self._instructions.get(imark)
        if instruction is None:
            return None
        if instruction.id in (decoded_ids.X86_INS_DIV, decoded_ids.X86_INS_IDIV):
            self._divide_imarks.add(imark)
            return None
        if instruction.id != decoded_ids.X86_INS_AAM:
            return None
        if instruction.operands:
            immediate = int(instruction.operands[0].imm)
        elif len(instruction.bytes) >= 2:
            immediate = int(instruction.bytes[1])
        else:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"aam at {hex(imark)} has no decodable immediate",
            )
        if immediate != 0:
            return None
        return FaultOutcome(
            TerminalFaultKind.DIVIDE_ERROR,
            DIVIDE_ERROR_VECTOR,
            imark,
            bytes(instruction.bytes),
            DivideFaultReason.ZERO_DIVISOR,
        )

    def admit_exit(
        self,
        *,
        statement: pyvex.stmt.Exit,
        state: S._IrsbLowerState,
        tyenv: Any,  # noqa: ANN401
        imark: int | None,
        auditor: MemoryReadAuditor | None,
    ) -> FaultOutcome | None:
        """Admit one lowered ``Ist_Exit``; decide the imark's fault once.

        Only the declared signal vocabulary is admitted. The first admitted
        exit of an instruction mark decides the complete fault condition from
        the decoded instruction, the divisor evidence inside the guard and the
        architectural dividend; later exits of the same mark are consistency
        checks — they must be proved false when the instruction was decided
        non-faulting, and a proved-true or unproved guard is a typed refusal.
        """
        jumpkind = str(statement.jk or "")
        kind = signal_fault_kind(jumpkind)
        if kind is None:
            if jumpkind.startswith("Ijk_Sig"):
                raise TerminalRefusal(
                    TerminalRefusalKind.FAULT_BOUNDARY,
                    f"unadmitted trap outcome {jumpkind} at {hex(imark or 0)}",
                )
            raise TerminalRefusal(
                TerminalRefusalKind.CONDITIONAL_CONTROL,
                f"conditional exit {jumpkind} is outside this bounded slice",
            )
        if imark is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                "fault exit precedes any instruction mark",
            )
        guard = self._lower_guard(statement, state, tyenv)
        if auditor is not None:
            auditor.audit_term(guard)
        if imark in self._decisions:
            outcome = self._decisions[imark]
            if outcome is not None:
                return outcome
            proved = self._resolve(guard)
            if proved is None or proved:
                raise TerminalRefusal(
                    TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                    f"fault guard at {hex(imark)} is not consistent with the intake decision",
                )
            return None
        outcome = self._decide(
            instruction=self._instructions.get(imark),
            kind=kind,
            guard=guard,
            imark=imark,
            state=state,
        )
        self._decisions[imark] = outcome
        return outcome

    def finish(self) -> None:
        """Refuse when a divide instruction produced no fault evidence."""
        missing = self._divide_imarks.difference(self._decisions)
        if missing:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"divide instruction at {hex(min(missing))} produced no fault evidence",
            )

    def _resolve(self, term: S.SsaExpr) -> int | None:
        """Prove a term's concrete value under the declared domain.

        Constants evaluate directly; a ``loadle`` straight from the shared
        initial memory resolves through the lane's declared initial bytes —
        the auditor has already admitted the read site, so only the
        declared value is needed here. Any other operation resolves
        recursively when every operand resolves, keeping the same
        ``const_eval`` semantics: a load through a store chain, a symbolic
        address, declared-unconstrained bytes or a symbolic register leaf
        all stay unproved rather than guessed.

        Each call memoizes resolved nodes by identity so a shared DAG is
        visited once per distinct term, never exponentially; a small
        distinct-term bound stops deep or degenerate chains with a typed
        ``FAULT_GUARD_UNPROVED`` refusal instead of unbounded recursion.
        """
        memo: dict[int, int | None] = {}
        remaining = _RESOLUTION_NODE_LIMIT

        def visit(node: S.SsaExpr) -> int | None:
            nonlocal remaining
            key = id(node)
            if key in memo:
                return memo[key]
            remaining -= 1
            if remaining <= 0:
                raise TerminalRefusal(
                    TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                    "fault-guard resolution exceeded the distinct-term bound",
                )
            value = self._resolve_node(node, visit)
            memo[key] = value
            return value

        return visit(term)

    def _resolve_node(
        self, term: S.SsaExpr, visit: Callable[[S.SsaExpr], int | None]
    ) -> int | None:
        """Evaluate one term node once its children are resolved."""
        if term.op == "const":
            return int(term.value or 0) & ((1 << int(term.width)) - 1)
        if (
            term.op == "loadle"
            and len(term.args) == 2
            and term.args[0].op == "mem_input"
            and self._initial_bytes is not None
        ):
            address = visit(term.args[1])
            if address is None:
                return None
            declared = self._initial_bytes(address, term.width // 8)
            if declared is not None and len(declared) == term.width // 8:
                return int.from_bytes(declared, "little")
            return None
        if term.args and term.op not in _MEMORY_TERM_OPS:
            const_args: list[S.SsaExpr] = []
            for arg in term.args:
                resolved = visit(arg)
                if resolved is None:
                    return None
                const_args.append(S.SsaExpr("const", arg.width, value=resolved))
            return const_eval(S.SsaExpr(term.op, term.width, tuple(const_args)))
        return None

    def _lower_guard(
        self, statement: pyvex.stmt.Exit, state: S._IrsbLowerState, tyenv: Any  # noqa: ANN401
    ) -> S.SsaExpr:
        """Lower one exit guard against the current block's temporaries."""
        lowered = S._lower_expr(
            statement.guard,
            temp_defs=state.temp_defs,
            temp_failures=state.temp_failures,
            reg_versions=state.reg_versions,
            tyenv=tyenv,
            memory=state.mem_version,
        )
        if isinstance(lowered, S.LowerFailure):
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                f"fault guard: {lowered.reason}: {lowered.message}",
            )
        return lowered

    def _decide(
        self,
        *,
        instruction: capstone.CsInsn | None,
        kind: TerminalFaultKind,
        guard: S.SsaExpr,
        imark: int,
        state: S._IrsbLowerState,
    ) -> FaultOutcome | None:
        """Decide the complete fault condition for one admitted signal exit."""
        if instruction is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                f"fault exit at {hex(imark)} has no decoded instruction",
            )
        if kind is not TerminalFaultKind.DIVIDE_ERROR:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_BOUNDARY,
                f"unadmitted fault kind {kind.value} at {hex(imark)}",
            )
        if instruction.id not in _DIVIDE_ERROR_INSTRUCTION_IDS or not instruction.operands:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"divide-error evidence at {hex(imark)} on a non-divide instruction",
            )
        divisor_term = _guard_divisor(guard)
        if divisor_term is None:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"guard at {hex(imark)} is not divisor evidence",
            )
        operand_bits = int(instruction.operands[0].size) * 8
        divisor = self._resolve(divisor_term)
        if divisor is None:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"divide divisor at {hex(imark)} is not proved under the declared state",
            )
        signed = instruction.id == decoded_ids.X86_INS_IDIV
        if decide_divide_error(
            signed=signed, operand_bits=operand_bits, dividend=0, divisor=divisor
        ).reason is DivideFaultReason.ZERO_DIVISOR:
            # A proved-zero divisor determines #DE alone: the architectural
            # dividend is irrelevant, so an unconstrained or store-chained
            # dividend term does not turn a decided fault into a refusal.
            return FaultOutcome(
                kind,
                DIVIDE_ERROR_VECTOR,
                imark,
                bytes(instruction.bytes),
                DivideFaultReason.ZERO_DIVISOR,
            )
        dividend_term = self._dividend(state.reg_versions, operand_bits)
        if dividend_term is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                f"no modeled dividend for divide operand width {operand_bits}",
            )
        dividend = self._resolve(dividend_term)
        if dividend is None:
            raise TerminalRefusal(
                TerminalRefusalKind.FAULT_GUARD_UNPROVED,
                f"divide dividend at {hex(imark)} is not proved under the declared state",
            )
        decision = decide_divide_error(
            signed=signed,
            operand_bits=operand_bits,
            dividend=dividend,
            divisor=divisor,
        )
        if not decision.faulted:
            return None
        return FaultOutcome(
            kind,
            DIVIDE_ERROR_VECTOR,
            imark,
            bytes(instruction.bytes),
            decision.reason,
        )
