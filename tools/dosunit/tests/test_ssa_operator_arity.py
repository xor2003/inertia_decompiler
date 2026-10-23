"""Malformed scalar/memory terms must never silently discard operands."""

import pytest
import z3

from tools.dosunit.contracts.model import DosUnitError
from tools.dosunit.ssa.z3_ops import apply_operator

pytestmark = pytest.mark.ssa_z3

_BINARY = ("add", "sub", "mul", "udiv", "urem", "sdiv", "srem", "and", "or", "xor",
           "umull", "smull", "eq", "ne", "ult", "ule", "ugt", "uge", "slt", "sle", "sgt", "sge",
           "shl", "lshr", "ashr")


@pytest.mark.parametrize("op", _BINARY)
@pytest.mark.parametrize("count", [0, 1, 3])
def test_binary_arity_is_exact(op: str, count: int) -> None:
    with pytest.raises(DosUnitError, match="expects 2 args"):
        apply_operator(op, 32, [z3.BitVecVal(i, 32) for i in range(count)], z3)


@pytest.mark.parametrize("op,arity", [("not", 1), ("zext", 1), ("sext", 1), ("trunc", 1), ("ite", 3)])
@pytest.mark.parametrize("delta", [-1, 1])
def test_leaf_arity_is_exact(op: str, arity: int, delta: int) -> None:
    with pytest.raises(DosUnitError, match=f"expects {arity} args"):
        apply_operator(op, 32, [z3.BitVecVal(i, 32) for i in range(arity + delta)], z3)


@pytest.mark.parametrize("op,arity", [("loadle", 2), ("loadbe", 2), ("storele", 3), ("storebe", 3)])
@pytest.mark.parametrize("delta", [-1, 1])
def test_memory_arity_is_exact(op: str, arity: int, delta: int) -> None:
    memory = z3.Array("arity_memory", z3.BitVecSort(32), z3.BitVecSort(8))
    args = [memory, *[z3.BitVecVal(i, 32) for i in range(arity + delta - 1)]]
    with pytest.raises(DosUnitError, match=f"expects {arity} args"):
        apply_operator(op, 32 if op.startswith("load") else 0, args, z3)


def test_explicit_binary_or_chain_keeps_every_operand() -> None:
    zero, one = z3.BitVecVal(0, 32), z3.BitVecVal(1, 32)
    result = apply_operator("or", 32, [apply_operator("or", 32, [zero, zero], z3), one], z3)
    assert z3.simplify(result).as_long() == 1


def test_concat_is_nonempty_and_variadic() -> None:
    for args in ([], [z3.BitVecVal(1, 8)]):
        with pytest.raises(DosUnitError, match="concat"):
            apply_operator("concat", 8, args, z3)
    for count in (2, 3):
        args = [z3.BitVecVal(i + 1, 8) for i in range(count)]
        result = z3.simplify(apply_operator("concat", count * 8, args, z3))
        assert result.as_long() == int.from_bytes(bytes(range(1, count + 1)), "big")


def test_malformed_or_cannot_prove_equality_to_zero() -> None:
    """The complete comparison must not accept a dropped nonzero operand."""
    from tools.dosunit.compare.straightline_ssa import _compare_functions

    zero = {"op": "const", "width": 32, "value": "0x0"}
    one = {"op": "const", "width": 32, "value": "0x1"}
    left = {"inputs": [], "assignments": [{"id": "bad", "op": "or", "width": 32,
             "args": [zero, zero, one]}], "outputs": {"eax": {"ref": "bad"}}}
    right = {"inputs": [], "assignments": [], "outputs": {"eax": zero}}
    with pytest.raises(DosUnitError, match="expects 2 args"):
        _compare_functions(left, right, timeout_ms=1000)
