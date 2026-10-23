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
from tools.dosunit.ssa.x86_lazy_conditions import (
    all_flags_contract,
    carry_contract,
    condition_contract,
    exact_all_flags,
    exact_carry,
    exact_condition,
)

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
    if op.startswith("x87fp_"):
        from tools.dosunit.ssa.z3_x87_fp import apply_x87_op

        result = apply_x87_op(op, width, args, z3)
        if result is not None:
            return result
    if op.startswith("summary_"):
        from tools.dosunit.ssa.z3_repeat_memory import exact_repeat_memory

        memory = exact_repeat_memory(op, width, args, z3)
        if memory is not None:
            return memory
        exact = _z3_exact_x86_flag_summary(op, width, args, z3)
        if exact is not None:
            return exact
        return _z3_uninterpreted_summary(op, width, args, z3)
    numeric = _z3_numeric_op(op, width, args, z3)
    if numeric is not None:
        return numeric
    if op in {"loadle", "loadbe", "storele", "storebe", "memory_preserve", "memory_preserve_slots32", "memory_read_projection"}:
        _z3_memory_op_arity(op, args)
        return _z3_memory_op(op, width, args, z3)
    arity = _LEAF_ARITY.get(op)
    if arity is not None:
        _require_arity(op, args, arity)
    elif op == "concat" and len(args) < 2:
        raise DosUnitError(f"SSA op concat expects at least 2 args, got {len(args)}")
    return _z3_leaf_op(op, width, args, z3)


def _z3_numeric_op(op: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Apply width-aligned binary arithmetic and comparisons, or ``None``."""
    if op in _Z3_UNSIGNED_BINOPS:
        _require_arity(op, args, 2)
        return _z3_aligned_binop(_Z3_UNSIGNED_BINOPS[op], width, args, signed=False, z3=z3)
    if op in _Z3_SIGNED_BINOPS:
        _require_arity(op, args, 2)
        return _z3_aligned_binop(_Z3_SIGNED_BINOPS[op], width, args, signed=True, z3=z3)
    if op in {"umull", "smull"}:
        _require_arity(op, args, 2)
        return _z3_mul_wide(args, width, signed=op == "smull", z3=z3)
    if op in _Z3_UNSIGNED_CMPS:
        _require_arity(op, args, 2)
        return _z3_comparison(_Z3_UNSIGNED_CMPS[op], args, signed=False, z3=z3)
    if op in _Z3_SIGNED_CMPS:
        _require_arity(op, args, 2)
        return _z3_comparison(_Z3_SIGNED_CMPS[op], args, signed=True, z3=z3)
    return None


def _z3_exact_x86_flag_summary(op: str, width: int, args: list[Any], z3: Any) -> Any | None:  # noqa: ANN401
    """Select admitted flag projections; every other summary remains abstract."""
    selectors = 2 if op == "summary_x86g_calculate_condition" else 1
    args = [z3.simplify(arg) if index < selectors and z3.is_bv(arg) else arg
            for index, arg in enumerate(args)]
    selector_index = selectors - 1
    if len(args) > selector_index and z3.is_bv(args[selector_index]):
        selector = args[selector_index]
        if z3.is_app_of(selector, z3.Z3_OP_ITE) and all(z3.is_bv_value(x) for x in selector.children()[1:]):
            results = [_z3_exact_x86_flag_summary(
                op, width, [*args[:selector_index], branch, *args[selector_index + 1:]], z3,
            ) for branch in selector.children()[1:]]
            if all(result is not None for result in results):
                return z3.If(selector.arg(0), *results)
    if op == "summary_x86g_calculate_condition":
        return _z3_x86_exact_condition(width, args, z3)
    if op == "summary_x86g_calculate_eflags_all":
        if len(args) != 4 or not all(z3.is_bv(argument) for argument in args) or not z3.is_bv_value(args[0]):
            return None
        kind = all_flags_contract(args[0].as_long())
        return None if kind is None else exact_all_flags(kind, *args[1:], output_width=width)
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
    """Apply exact byte-array loads, stores or an inclusive unsigned frame."""
    if op == "memory_read_projection":
        return _z3_memory_read_projection(width, args, z3)
    if op == "memory_preserve_slots32":
        return _z3_memory_preserve_slots32(width, args, z3)
    if op == "memory_preserve":
        return _z3_memory_preserve(width, args, z3)
    if op == "loadle":
        return _z3_load(args[0], args[1], width=width, little_endian=True, z3=z3)
    if op == "loadbe":
        return _z3_load(args[0], args[1], width=width, little_endian=False, z3=z3)
    if op == "storele":
        return _z3_store(args[0], args[1], args[2], little_endian=True, z3=z3)
    return _z3_store(args[0], args[1], args[2], little_endian=False, z3=z3)


def _z3_memory_preserve(width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Restore original bytes in [first,last]; retain changed bytes elsewhere.

    Bounds are unsigned, inclusive and nonwrapping. A reversed interval
    preserves nothing. Lambda is an exact pointwise array definition, not an
    uninterpreted summary or a finite sample of the memory relation.
    """
    memory_sort = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8))
    if width != 0 or len(args) != 4:
        raise DosUnitError("memory_preserve requires two arrays and two 32-bit bounds")
    changed, original, first, last = args
    if changed.sort() != memory_sort or original.sort() != memory_sort:
        raise DosUnitError("memory_preserve requires flat32 byte arrays")
    if first.sort() != z3.BitVecSort(32) or last.sort() != z3.BitVecSort(32):
        raise DosUnitError("memory_preserve requires 32-bit bounds")
    address = z3.FreshConst(z3.BitVecSort(32), "preserved_byte")
    inside = z3.And(z3.UGE(address, first), z3.ULE(address, last))
    return z3.Lambda(address, z3.If(inside, z3.Select(original, address), z3.Select(changed, address)))


def _z3_memory_preserve_slots32(width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Frame each relocated DWORD, then merge adjacent canonical byte ranges.

    Slot literals have already passed through document normalization. The
    result preserves precisely their union, including gaps and shuffled slots.
    Symbolic or wrapping slots are refused instead of inventing an interval.
    """
    if width != 0 or not 3 <= len(args) <= 4098:
        raise DosUnitError("memory_preserve_slots32 requires two arrays and 1..4096 slots")
    slots = []
    for term in args[2:]:
        if not z3.is_bv_value(term) or term.size() != 32 or term.as_long() > 0xFFFFFFFC:
            raise DosUnitError("memory_preserve_slots32 requires nonwrapping uint32 literal slots")
        slots.append(term.as_long())
    ranges: list[tuple[int, int]] = []
    for slot in sorted(set(slots)):
        if ranges and slot <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], slot + 3))
        else:
            ranges.append((slot, slot + 3))
    changed, original = args[:2]
    for first, last in ranges:
        changed = _z3_memory_preserve(width, [changed, original,
            z3.BitVecVal(first, 32), z3.BitVecVal(last, 32)], z3)
    return changed


def _require_arity(op: str, args: list[Any], arity: int) -> None:
    """Refuse malformed terms: an argument count mismatch is a defect in
    the term producer, not an unconstrained value or a crash."""
    if len(args) != arity:
        raise DosUnitError(f"SSA op {op} expects {arity} args, got {len(args)}")


def _z3_memory_read_projection(width: int, args: list[Any], z3: Any) -> Any:  # noqa: ANN401
    """Overapproximate unread projection using exact store and choice laws.

    P(Store(M,a,v)) is P(M) inside the unread interval and Store(P(M),a,v)
    outside. The unconstrained base P includes the exact zero-mask projection
    as one interpretation: this can lose proofs but cannot establish a false
    equivalence. No projected array is used as actual program memory. Closed
    pointwise choices distribute projection without capturing bound indices.
    """
    if width != 0 or len(args) != 3 or not z3.is_array(args[0]):
        raise DosUnitError("memory_read_projection requires an array and two bounds")
    if any(not z3.is_bv_value(value) or value.size() != 32 for value in args[1:]):
        raise DosUnitError("memory_read_projection requires literal uint32 bounds")
    first, last = (value.as_long() for value in args[1:])
    if not first <= last or last - first >= 8192:
        raise DosUnitError("memory_read_projection requires 1..8192 bytes")
    from tools.dosunit.ssa.z3_unread_projection import project_unread_array

    return project_unread_array(args[0], first, last, z3)




def _z3_memory_op_arity(op: str, args: list[Any]) -> None:
    """Validate memory-op arity before dispatch."""
    if op in {"loadle", "loadbe"}:
        _require_arity(op, args, 2)
    elif op in {"storele", "storebe"}:
        _require_arity(op, args, 3)
    # memory_preserve keeps its own detailed DosUnitError validation.


_LEAF_ARITY: dict[str, int] = {
    "not": 1, "zext": 1, "sext": 1, "trunc": 1,
    "shl": 2, "lshr": 2, "ashr": 2, "ite": 3,
}


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
    """Preserve unknown semantics while bounding well-shaped flag helper results."""
    if width == 32 and all(z3.is_bv(arg) and arg.size() == 32 for arg in args):
        if op == "summary_x86g_calculate_eflags_c" and len(args) == 4:
            flags = apply_operator("summary_x86g_calculate_eflags_all", 32, args, z3)
            return flags & z3.BitVecVal(1, 32)
        if op == "summary_x86g_calculate_condition" and len(args) == 5 and z3.is_bv_value(args[0]):
            projection = condition_contract(args[0].as_long(), 0)
            if projection is not None:
                flags = apply_operator("summary_x86g_calculate_eflags_all", 32, args[1:], z3)
                zero = z3.BitVecVal(0, 32)
                return exact_condition(projection, flags, zero, zero, output_width=32)
    domain = [arg.sort() for arg in args]
    range_sort = z3.ArraySort(z3.BitVecSort(32), z3.BitVecSort(8)) if width == 0 else z3.BitVecSort(width)
    name = re.sub(r"[^A-Za-z0-9_]", "_", op)
    fn = z3.Function(name, *domain, range_sort)
    result = fn(*args)
    # These pure helpers return flag projections even when the thunk selector
    # is unknown. Keep every possible flag value, but no unrelated high bits.
    flag_ranges = {
        "summary_x86g_calculate_eflags_c": (4, 1),
        "summary_x86g_calculate_condition": (5, 1),
        "summary_x86g_calculate_eflags_all": (4, 0x8d5),
    }
    shape = flag_ranges.get(op)
    if (shape is not None and width == 32 and len(args) == shape[0]
            and all(z3.is_bv(arg) and arg.size() == 32 for arg in args)):
        return result & z3.BitVecVal(shape[1], width)
    return result


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
    """Store every byte exactly, using a modular fill for long repeated constants."""
    width = int(value.size())
    if width % 8 != 0:
        raise DosUnitError(f"memory store width must be byte-addressable: {width}")
    address = _resize_z3(address, address.size(), 32, signed=False, z3=z3)
    stored = memory
    byte_count = width // 8
    # Short stores retain the Store shape used by ordinary load simplifiers.
    # The interval is modular, preserving wrapping writes across address zero.
    if 8 < byte_count < (1 << 32) and z3.is_bv_value(value):
        byte_value = value.as_long() & 255
        repeated = int.from_bytes(bytes([byte_value]) * byte_count, "little")
        if value.as_long() == repeated:
            index = z3.FreshConst(z3.BitVecSort(32), "fill_index")
            within = z3.ULT(index - address, z3.BitVecVal(byte_count, 32))
            return z3.Lambda(index, z3.If(within, z3.BitVecVal(byte_value, 8), z3.Select(memory, index)))
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


