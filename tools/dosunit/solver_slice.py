from __future__ import annotations  # noqa: D100

import time
from dataclasses import dataclass
from typing import Any

from tools.dosunit.ir_edges import BranchTarget, ConditionIR, Operand
from tools.dosunit.model import normalize_hex

REG8_PARENT = {
    "al": ("ax", 0),
    "cl": ("cx", 0),
    "dl": ("dx", 0),
    "bl": ("bx", 0),
    "ah": ("ax", 8),
    "ch": ("cx", 8),
    "dh": ("dx", 8),
    "bh": ("bx", 8),
}
INVERTED_CONDITION = {
    "eq": "ne",
    "ne": "eq",
    "ult": "uge",
    "uge": "ult",
    "ugt": "ule",
    "ule": "ugt",
    "test_zero": "test_nonzero",
    "test_nonzero": "test_zero",
}


@dataclass(frozen=True)
class SolvedEdge:  # noqa: D101
    label: str
    regs: dict[str, int]
    constraints: tuple[str, ...]
    predicate: str
    solver_time_ms: int
    coverage: dict[str, Any]


@dataclass(frozen=True)
class EdgeSolveFailure:  # noqa: D101
    reason: str
    message: str
    label: str


def solve_branch_edge(  # noqa: D103
    target: BranchTarget,
    *,
    label: str,
    timeout_ms: int = 1000,
) -> SolvedEdge | EdgeSolveFailure:
    condition = target.condition if label == "taken" else _invert_condition(target.condition)
    if condition.kind == "unsupported":
        return EdgeSolveFailure("unsupported_ir", "unsupported branch condition", label)
    started = time.monotonic()
    manual = _manual_solution(condition)
    if manual is not None:
        elapsed = int((time.monotonic() - started) * 1000)
        predicate = condition.predicate_text()
        return SolvedEdge(
            label=label,
            regs=manual,
            constraints=(predicate,),
            predicate=predicate,
            solver_time_ms=elapsed,
            coverage=target.coverage(label=label, predicate=predicate),
        )
    try:
        import z3  # type: ignore
    except Exception:
        return EdgeSolveFailure("unsupported_ir", "z3 is unavailable and no manual solution exists", label)

    regs = {name: z3.BitVec(name, 16) for name in _condition_regs(condition)}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.add(_z3_condition(condition, regs, z3))
    status = solver.check()
    elapsed = int((time.monotonic() - started) * 1000)
    if status == z3.unknown:
        return EdgeSolveFailure("timeout", f"z3 returned unknown: {solver.reason_unknown()}", label)
    if status != z3.sat:
        return EdgeSolveFailure("unsupported_ir", "branch predicate is unsatisfiable", label)
    model = solver.model()
    solved_regs = {name: int(model.eval(regs[name], model_completion=True).as_long()) & 0xFFFF for name in sorted(regs)}
    predicate = condition.predicate_text()
    return SolvedEdge(
        label=label,
        regs=solved_regs,
        constraints=(predicate,),
        predicate=predicate,
        solver_time_ms=elapsed,
        coverage=target.coverage(label=label, predicate=predicate),
    )


def _invert_condition(condition: ConditionIR) -> ConditionIR:
    inverted = INVERTED_CONDITION.get(condition.kind)
    if inverted is None:
        return ConditionIR("unsupported", condition.left, condition.right)
    return ConditionIR(inverted, condition.left, condition.right)


def _manual_solution(condition: ConditionIR) -> dict[str, int] | None:
    left = condition.left
    right = condition.right
    if left.kind not in {"reg", "reg8"} or right is None:
        return None
    if condition.kind in {"test_zero", "test_nonzero"}:
        return _manual_test_solution(condition, left, right)
    if right.kind == "imm":
        return _manual_imm_solution(condition, left, right)
    return None


def _manual_test_solution(condition: ConditionIR, left: Operand, right: Operand) -> dict[str, int] | None:
    """Solve test_zero/test_nonzero conditions without the solver."""
    if right.kind in {"reg", "reg8"} and right.value == left.value:
        return _assign_operand_value(left, 0 if condition.kind == "test_zero" else 1)
    if right.kind == "imm":
        mask = int(right.value) & ((1 << right.width) - 1)
        if condition.kind == "test_zero":
            return _assign_operand_value(left, 0)
        if mask == 0:
            return None
        bit = mask & -mask
        return _assign_operand_value(left, bit)
    return None


def _manual_imm_solution(condition: ConditionIR, left: Operand, right: Operand) -> dict[str, int] | None:
    """Solve immediate-comparison conditions without the solver."""
    left_reg = _parent_reg(left)
    imm = int(right.value) & ((1 << right.width) - 1)
    if condition.kind == "eq":
        return _assign_operand_value(left, imm)
    if condition.kind == "ne":
        return _assign_operand_value(left, (imm + 1) & ((1 << right.width) - 1))
    if left.kind == "reg8":
        return None
    if condition.kind == "ult":
        return None if imm == 0 else {left_reg: 0}
    if condition.kind == "uge":
        return {left_reg: imm}
    if condition.kind == "ugt":
        return None if imm == 0xFFFF else {left_reg: (imm + 1) & 0xFFFF}
    if condition.kind == "ule":
        return {left_reg: imm}
    return None


def _assign_operand_value(operand: Operand, value: int) -> dict[str, int]:
    if operand.kind == "reg":
        return {str(operand.value): value & 0xFFFF}
    parent, shift = REG8_PARENT[str(operand.value)]
    return {parent: (value & 0xFF) << shift}


def _parent_reg(operand: Operand) -> str:
    if operand.kind == "reg8":
        return REG8_PARENT[str(operand.value)][0]
    return str(operand.value)


def _condition_regs(condition: ConditionIR) -> set[str]:
    regs: set[str] = set()
    for operand in (condition.left, condition.right):
        if isinstance(operand, Operand) and operand.kind in {"reg", "reg8"}:
            regs.add(_parent_reg(operand))
    return regs


def _z3_operand(operand: Operand, regs: dict[str, Any], z3: Any) -> Any:  # noqa: ANN401
    if operand.kind == "reg":
        return regs[str(operand.value)]
    if operand.kind == "reg8":
        parent, shift = REG8_PARENT[str(operand.value)]
        return z3.Extract(shift + 7, shift, regs[parent])
    return z3.BitVecVal(int(operand.value) & ((1 << operand.width) - 1), operand.width)


def _z3_condition(condition: ConditionIR, regs: dict[str, Any], z3: Any) -> Any:  # noqa: ANN401
    left = _z3_operand(condition.left, regs, z3)
    right = _z3_operand(condition.right, regs, z3) if condition.right is not None else None
    if condition.kind == "eq":
        return left == right
    if condition.kind == "ne":
        return left != right
    if condition.kind == "ult":
        return z3.ULT(left, right)
    if condition.kind == "uge":
        return z3.UGE(left, right)
    if condition.kind == "ugt":
        return z3.UGT(left, right)
    if condition.kind == "ule":
        return z3.ULE(left, right)
    if condition.kind == "test_zero":
        return (left & right) == 0
    if condition.kind == "test_nonzero":
        return (left & right) != 0
    raise ValueError(f"unsupported condition kind: {condition.kind}")


def regs_as_hex(regs: dict[str, int]) -> dict[str, str]:  # noqa: D103
    return {name: normalize_hex(value, width=4) for name, value in sorted(regs.items())}
