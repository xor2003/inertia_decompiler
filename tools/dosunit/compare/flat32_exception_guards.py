"""Layer: flat32 validation lowering.

Responsibility: remove only universally unreachable native exceptional exits,
using the same SSA semantics and bounded solver as ordinary equivalence checks.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from typing import Any

import capstone
import pyvex

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import _check_compose_deadline, _ComposeSession, _ret_proof_timeout_ms


@dataclass(frozen=True, slots=True)
class NativeDivision:
    """Native quotient width and signedness authenticated against VEX."""

    width: int
    signed: bool


def _signed_overflow(numerator: S.SsaExpr, divisor: S.SsaExpr, width: int) -> S.SsaExpr:
    """Prove the truncated-toward-zero quotient fits without dividing.

    For magnitude A/B, positive quotients require A < B*2**(N-1),
    negative quotients A < B*(2**(N-1)+1). Both thresholds fit uint64
    for the admitted N<=32 and signed32 divisor. Unsigned absolute value
    also represents abs(INT64_MIN) exactly; no host signed overflow occurs.
    """
    zero = S.SsaExpr("const", 64, value=0)
    divisor = S.SsaExpr("sext", 64, (divisor,))
    negative_n = S.SsaExpr("slt", 1, (numerator, zero))
    negative_d = S.SsaExpr("slt", 1, (divisor, zero))
    absolute_n = S.SsaExpr("ite", 64, (negative_n, S.SsaExpr("sub", 64, (zero, numerator)), numerator))
    absolute_d = S.SsaExpr("ite", 64, (negative_d, S.SsaExpr("sub", 64, (zero, divisor)), divisor))
    negative_q = S.SsaExpr("xor", 1, (negative_n, negative_d))
    bound = S.SsaExpr("add", 64, (
        S.SsaExpr("shl", 64, (absolute_d, S.SsaExpr("const", 64, value=width - 1))),
        S.SsaExpr("ite", 64, (negative_q, absolute_d, zero)),
    ))
    return S.SsaExpr("uge", 1, (absolute_n, bound))


def _guards(state: S._IrsbLowerState, *, irsb: pyvex.IRSB, output_regs: tuple[str, ...],
            max_assignments_per_function: int,
            quotient_widths: Mapping[int, NativeDivision]) -> dict[str, Any] | S.LowerFailure:
    """Materialize original exit predicates without assuming normal completion."""
    names = []
    for index, (guard, _target, kind) in enumerate(state.exits):
        if kind != "Ijk_Boring":
            name = f"exception_guard_{index}"
            names.append(name)
            state.reg_versions[name] = guard
    for statement in irsb.statements:
        if (isinstance(statement, pyvex.stmt.WrTmp)
                and isinstance(statement.data, pyvex.expr.Binop)
                and statement.data.op in {"Iop_DivModU64to32", "Iop_DivModS64to32"}):
            operands = [S._state_expression_lowerer(state)(
                arg, temp_defs=state.temp_defs, temp_failures=state.temp_failures,
                reg_versions=state.reg_versions, tyenv=irsb.tyenv, memory=state.mem_version,
                register_reader=state.architecture.reader if state.architecture else None,
            ) for arg in statement.data.args]
            if any(isinstance(arg, S.LowerFailure) for arg in operands):
                return S.LowerFailure("unsupported_ir", "division operand unavailable")
            numerator, divisor = operands
            assert isinstance(numerator, S.SsaExpr) and isinstance(divisor, S.SsaExpr)
            # VEX may expose division-by-zero without the hardware quotient
            # overflow fault. For an N-bit quotient, dividend >> N < divisor
            # is exact. Keep all numerator bits when checking narrow DIV.
            division = quotient_widths[statement.tmp]
            name = f"division_overflow_{statement.tmp}"
            if division.signed:
                state.reg_versions[name] = _signed_overflow(numerator, divisor, division.width)
            else:
                high = S.SsaExpr("lshr", 64, (numerator, S.SsaExpr("const", 64, value=division.width)))
                state.reg_versions[name] = S.SsaExpr("uge", 1, (high, S._coerce_width(divisor, 64)))
            names.append(name)
    lowered = S._finish_irsb_with_context(
        state, irsb=irsb, output_regs=tuple(names),
        max_assignments_per_function=max_assignments_per_function,
        control_expression=S.SsaExpr("const", 32, value=0),
    )
    if isinstance(lowered, S.LowerFailure):
        return lowered
    # The ordinary finisher also publishes memory effects. They are retained
    # in real block lowering, but this auxiliary query concerns only guards.
    return {**lowered, "outputs": {name: lowered["outputs"][name] for name in names}}


def _division_widths(irsb: pyvex.IRSB, code: bytes) -> dict[int, NativeDivision] | None:
    """Bind each normalized VEX division to its native width and signedness."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    divisions = [ins for ins in decoder.disasm(code, int(irsb.addr))
                 if ins.id in {capstone.x86.X86_INS_DIV, capstone.x86.X86_INS_IDIV}]
    operations = [stmt for stmt in irsb.statements if isinstance(stmt, pyvex.stmt.WrTmp)
                  and isinstance(stmt.data, pyvex.expr.Binop)
                  and stmt.data.op in {"Iop_DivModU64to32", "Iop_DivModS64to32"}]
    if (not divisions or len(divisions) != len(operations)
            or any(ins.operands[0].size not in {1, 2, 4} for ins in divisions)
            or any((ins.id == capstone.x86.X86_INS_IDIV) != (op.data.op == "Iop_DivModS64to32")
                   for ins, op in zip(divisions, operations, strict=True))
            or any(not isinstance(arg, (pyvex.expr.RdTmp, pyvex.expr.Const)) for op in operations for arg in op.data.args)):
        return None
    return {stmt.tmp: NativeDivision(ins.operands[0].size * 8, ins.id == capstone.x86.X86_INS_IDIV)
            for stmt, ins in zip(operations, divisions, strict=True)}


def prune_unreachable_exceptions(
    session: _ComposeSession, irsb: pyvex.IRSB,
) -> tuple[pyvex.IRSB, list[dict[str, Any]]]:
    """Keep all exits unless every exceptional predicate is proved always false.

    No entry-domain or successful-division assumption is supplied. Only Exit
    statements are removed; original arithmetic, memory and register effects
    remain and undergo ordinary lowering and comparison afterward.
    """
    indices = [i for i, statement in enumerate(irsb.statements)
               if isinstance(statement, pyvex.stmt.Exit) and statement.jumpkind != "Ijk_Boring"]
    if not indices:
        return irsb, []
    if any(irsb.statements[i].jumpkind != "Ijk_SigFPE_IntDiv" for i in indices):
        return irsb, []
    code = session.project.loader.memory.load(int(irsb.addr), int(irsb.size))
    quotient_widths = _division_widths(irsb, code)
    if quotient_widths is None:
        return irsb, []
    _check_compose_deadline(session.compose_stats)
    session.compositions += 1
    if session.compositions > session.limits.max_compositions:
        return irsb, []
    guards = S._lower_irsb(
        irsb, output_regs=tuple(session.reg_widths),
        max_assignments_per_function=session.limits.max_assignments_per_block,
        architecture=flat32_register_architecture(), block_finisher=partial(_guards, quotient_widths=quotient_widths),
    )
    if isinstance(guards, S.LowerFailure) or len(guards["outputs"]) != len(indices) + len(quotient_widths):
        return irsb, []
    zero = {"inputs": [], "assignments": [], "outputs": {
        name: {"op": "const", "width": 1, "value": "0x0"} for name in guards["outputs"]}}
    proof = S._compare_functions(guards, zero, timeout_ms=_ret_proof_timeout_ms(session))
    if proof.get("status") != "passed":
        return irsb, []
    result = copy.deepcopy(irsb)
    result.statements = [statement for i, statement in enumerate(result.statements) if i not in indices]
    return result, [{"block": hex(int(irsb.addr)), "exit_statement_indices": indices,
                     "guard_document": guards, "proof": proof}]
