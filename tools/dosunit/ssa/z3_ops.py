"""Interpret already-lowered SSA operators through the dynamic Z3 API.

Layer: dosunit SSA solver translation.
Responsibility: preserve arithmetic widths, byte-array effects and exact or
abstract flag summaries. Document normalization and proof policy stay outside.
No solver/backend is imported here; the caller supplies its Z3 API explicitly.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.ssa.x86_lazy_conditions import carry_contract, condition_contract, exact_carry, exact_condition

_Z3_UNSIGNED_BINOPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "add": lambda left, right, _z3: left + right,
    "sub": lambda left, right, _z3: left - right,
    "mul": lambda left, right, _z3: left * right,
    "udiv": lambda left, right, z3: z3.UDiv(left, right),
    "urem": lambda left, right, z3: z3.URem(left, right),
    "and": lambda left, right, _z3: left & right,
    "or": lambda left, right, _z3: left | right,
    "xor": lambda left, right, _z3: left ^ right,
}
_Z3_SIGNED_BINOPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "sdiv": lambda left, right, _z3: left / right,
    "srem": lambda left, right, z3: z3.SRem(left, right),
}
_Z3_UNSIGNED_CMPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "eq": lambda left, right, _z3: left == right,
    "ne": lambda left, right, _z3: left != right,
    "ult": lambda left, right, z3: z3.ULT(left, right),
    "ule": lambda left, right, z3: z3.ULE(left, right),
    "ugt": lambda left, right, z3: z3.UGT(left, right),
    "uge": lambda left, right, z3: z3.UGE(left, right),
}
_Z3_SIGNED_CMPS: dict[str, Callable[[Any, Any, Any], Any]] = {
    "slt": lambda left, right, _z3: left < right,
    "sle": lambda left, right, _z3: left <= right,
    "sgt": lambda left, right, _z3: left > right,
    "sge": lambda left, right, _z3: left >= right,
}


def apply_operator(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Interpret SSA operators at Z3's dynamic API, retaining abstract summaries."""
    if op.startswith("summary_"):
        exact = _z3_exact_x86_flag_summary(op, width, args, z3)
        if exact is not None:
            return exact
        return _z3_uninterpreted_summary(op, width, args, z3)
    if op in _Z3_UNSIGNED_BINOPS:
        return _z3_aligned_binop(_Z3_UNSIGNED_BINOPS[op], width, args, signed=False, z3=z3)
    if op in _Z3_SIGNED_BINOPS:
        return _z3_aligned_binop(_Z3_SIGNED_BINOPS[op], width, args, signed=True, z3=z3)
    if op in {"umull", "smull"}:
        return _z3_mul_wide(args, width, signed=op == "smull", z3=z3)
    if op in _Z3_UNSIGNED_CMPS:
        return _z3_comparison(_Z3_UNSIGNED_CMPS[op], args, signed=False, z3=z3)
    if op in _Z3_SIGNED_CMPS:
        return _z3_comparison(_Z3_SIGNED_CMPS[op], args, signed=True, z3=z3)
    if op in {"loadle", "loadbe", "storele", "storebe"}:
        return _z3_memory_op(op, width, args, z3)
    return _z3_leaf_op(op, width, args, z3)


def _z3_exact_x86_flag_summary(op: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Select admitted flag projections; every other summary remains abstract."""
    if op == "summary_x86g_calculate_condition":
        return _z3_x86_exact_condition(width, args, z3)
    if op == "summary_x86g_calculate_eflags_c":
        return _z3_x86_exact_carry(width, args, z3)
    return None


def _z3_x86_exact_condition(width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Bind the dynamic Z3 adapter to the authoritative exact condition owner."""
    if len(args) != 5 or not all(z3.is_bv(argument) for argument in args):
        return None
    if not z3.is_bv_value(args[0]) or not z3.is_bv_value(args[1]):
        return None
    kind = condition_contract(args[0].as_long(), args[1].as_long())
    if kind is None:
        return None
    return exact_condition(kind, args[2], args[3], args[4], output_width=width)


def _z3_x86_exact_carry(width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Bind exact CF interpretation and refusal to the shared arithmetic owner."""
    if len(args) != 4 or not all(z3.is_bv(argument) for argument in args):
        return None
    if not z3.is_bv_value(args[0]):
        return None
    kind = carry_contract(args[0].as_long())
    if kind is None:
        return None
    return exact_carry(kind, args[1], args[2], args[3], output_width=width)


def _z3_aligned_binop(
    apply: Callable[[Any, Any, Any], Any], width: int, args: list[Any], *, signed: bool, z3: Any  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Apply a z3 binary op over width-aligned operands and resize to `width`."""
    left, right, op_width = _align_z3_pair(args[0], args[1], width, signed=signed, z3=z3)
    return _resize_z3(apply(left, right, z3), op_width, width, signed=signed, z3=z3)


def _z3_mul_wide(args: list[Any], width: int, *, signed: bool, z3: Any) -> Any:  # noqa: ANN401
    """Apply umull/smull by widening each operand to `width` first."""
    return _resize_z3(args[0], args[0].size(), width, signed=signed, z3=z3) * _resize_z3(
        args[1], args[1].size(), width, signed=signed, z3=z3
    )


def _z3_comparison(
    predicate: Callable[[Any, Any, Any], Any], args: list[Any], *, signed: bool, z3: Any  # noqa: ANN401
) -> Any:  # noqa: ANN401
    """Apply a z3 comparison predicate and produce a 1-bit result."""
    left, right, _op_width = _align_z3_pair(
        args[0], args[1], max(args[0].size(), args[1].size()), signed=signed, z3=z3
    )
    return z3.If(predicate(left, right, z3), z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))


def _z3_memory_op(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Apply a z3 load/store op."""
    if op == "loadle":
        return _z3_load(args[0], args[1], width=width, little_endian=True, z3=z3)
    if op == "loadbe":
        return _z3_load(args[0], args[1], width=width, little_endian=False, z3=z3)
    if op == "storele":
        return _z3_store(args[0], args[1], args[2], little_endian=True, z3=z3)
    return _z3_store(args[0], args[1], args[2], little_endian=False, z3=z3)


def _z3_leaf_op(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Apply the remaining z3 leaf ops (not/concat/shift/extend/ite)."""
    if op == "not":
        return ~args[0]
    if op == "concat":
        return z3.Concat(*args)
    if op == "shl":
        return _resize_z3(
            args[0] << _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3),
            args[0].size(),
            width,
            signed=False,
            z3=z3,
        )
    if op == "lshr":
        return z3.LShR(args[0], _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3))
    if op == "ashr":
        return args[0] >> _resize_z3(args[1], args[1].size(), args[0].size(), signed=False, z3=z3)
    if op == "zext":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "sext":
        return _resize_z3(args[0], args[0].size(), width, signed=True, z3=z3)
    if op == "trunc":
        return _resize_z3(args[0], args[0].size(), width, signed=False, z3=z3)
    if op == "ite":
        return z3.If(args[0] != z3.BitVecVal(0, args[0].size()), args[1], args[2])
    raise DosUnitError(f"unsupported SSA op: {op}")


def _z3_uninterpreted_summary(op: str, width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    domain = [arg.sort() for arg in args]
    range_sort = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8)) if width == 0 else z3.BitVecSort(width)
    name = re.sub(r"[^A-Za-z0-9_]", "_", op)
    fn = z3.Function(name, *domain, range_sort)
    return fn(*args)


def _align_z3_pair(left: Any, right: Any, width: int, *, signed: bool, z3: Any) -> tuple[Any, Any, int]:  # noqa: ANN401
    target_width = max(1, int(width), int(left.size()), int(right.size()))
    return (
        _resize_z3(left, left.size(), target_width, signed=signed, z3=z3),
        _resize_z3(right, right.size(), target_width, signed=signed, z3=z3),
        target_width,
    )


def _z3_load(memory: Any, address: Any, *, width: int, little_endian: bool, z3: Any) -> Any:  # noqa: ANN401
    if width % 8 != 0:
        raise DosUnitError(f"memory load width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    bytes_ = [z3.Select(memory, address + z3.BitVecVal(index, 32)) for index in range(width // 8)]
    ordered = list(reversed(bytes_)) if little_endian else bytes_
    if len(ordered) == 1:
        return ordered[0]
    return z3.Concat(*ordered)


def _z3_store(memory: Any, address: Any, value: Any, *, little_endian: bool, z3: Any) -> Any:  # noqa: ANN401
    width = int(value.size())
    if width % 8 != 0:
        raise DosUnitError(f"memory store width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    stored = memory
    byte_count = width // 8
    for index in range(byte_count):
        source_index = index if little_endian else byte_count - index - 1
        byte = z3.Extract(source_index * 8 + 7, source_index * 8, value)
        stored = z3.Store(stored, address + z3.BitVecVal(index, 32), byte)
    return stored


def _resize_z3(value: Any, from_width: int, to_width: int, *, signed: bool, z3: Any) -> Any:  # noqa: ANN401
    if from_width == to_width:
        return value
    if from_width > to_width:
        return z3.Extract(to_width - 1, 0, value)
    extend = z3.SignExt if signed else z3.ZeroExt
    return extend(to_width - from_width, value)


def _align_z3_widths(left: Any, right: Any, z3: Any) -> tuple[Any, Any]:  # noqa: ANN401
    left_width = int(left.size())
    right_width = int(right.size())
    width = max(left_width, right_width)
    return _resize_z3(left, left_width, width, signed=False, z3=z3), _resize_z3(
        right, right_width, width, signed=False, z3=z3
    )


