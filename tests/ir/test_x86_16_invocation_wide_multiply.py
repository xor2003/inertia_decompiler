"""Widening products retain exact signedness, widths and native provenance."""
from dataclasses import replace

import pytest
import tests.ir.test_x86_16_declared_resize_boundary as native
import inertia.ir.real16_edge_feasibility8616 as kb
import inertia.ir.real16_invocation_domain as census
from inertia.ir.core import IRInstr, IRValue, MemSpace


def test_native_neg_resize_argument() -> None:
    """Native NEG BX uses the widened product then narrows before AH4A."""
    caller = bytes.fromhex("b80001 8ec0 b8004a bbc0ff f7db 83fb40 7403 b8004b cd21 e80100 c3")
    env = native._environment()
    boot = native._boot(caller, env)
    project, raw, coverage = native._world(boot, len(caller))
    assert any(row.op == "Iop_MullS16" for block in raw.blocks for row in block.instrs)
    relation = native._resize_relation(env, native.MODULE_BASE + 21)
    premise = native._resize_premise(project, coverage, native.MODULE_BASE + 23, boot, (relation,))
    assert premise.complete
    assert (native.MODULE_BASE, native.MODULE_BASE + 18) in premise.infeasible_edges
    assert len(premise.service_consumptions) == 1
    assert premise.service_consumptions[0].answer_bx == 0x40
    product = next(row for block in raw.blocks for row in block.instrs if row.op == "Iop_MullS16")
    operand = product.args[1]
    assert isinstance(operand, IRValue)
    object.__setattr__(product, "args", (product.args[0], replace(operand, size=1)))
    assert not premise.complete


@pytest.mark.parametrize("bits", [8, 16, 32])
@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize("inputs", [(0, 0), (-1, 2), (-1, -1), ("minimum", -1)])
def test_widening_product_consumers(bits: int, signed: bool, inputs: tuple) -> None:
    """Both interpreters agree on the full double-width product bit pattern."""
    left, right = inputs
    if left == "minimum":
        left = 1 << (bits - 1)
    mask = (1 << bits) - 1
    a, b = left & mask, right & mask
    expected_a = a - (1 << bits) if signed and a & (1 << (bits - 1)) else a
    expected_b = b - (1 << bits) if signed and b & (1 << (bits - 1)) else b
    expected = (expected_a * expected_b) & ((1 << (bits * 2)) - 1)
    args = (IRValue(MemSpace.CONST, const=left, size=bits // 8), IRValue(MemSpace.CONST, const=right, size=bits // 8))
    dst = IRValue(MemSpace.TMP, name="t7", source_tmp=7, size=bits // 4)
    row = IRInstr(f"Iop_Mull{'S' if signed else 'U'}{bits}", dst, args)
    exact, known = {}, {}
    census._simulate_tmp_write_8616(row, dst, {}, exact)
    kb._kb_tmp_write_8616(row, dst, {}, known)
    assert exact[7] == expected
    assert known[7] == ((1 << (bits * 2)) - 1, expected)


@pytest.mark.parametrize("defect", ["left_width", "right_width", "result_width", "unsupported128", "spelling", "unknown"])
def test_invalid_widening_product_refuses(defect: str) -> None:
    """Malformed widths and unsupported/unknown operations cannot mint values."""
    left = IRValue(MemSpace.REG, name="ax", size=2)
    right = IRValue(MemSpace.CONST, const=-1, size=2)
    dst = IRValue(MemSpace.TMP, name="t7", source_tmp=7, size=4)
    op = "Iop_MullS16"
    if defect == "left_width":
        left = replace(left, size=1)
    elif defect == "right_width":
        right = replace(right, size=4)
    elif defect == "result_width":
        dst = replace(dst, size=2)
    elif defect == "unsupported128":
        op, left, right, dst = "Iop_MullU64", replace(left, size=8), replace(right, size=8), replace(dst, size=16)
    elif defect == "spelling":
        op = "Iop_MullS016"
    row = IRInstr(op, dst, (left, right))
    exact, known = {7: 123}, {7: (0xFFFFFFFF, 123)}
    registers = {} if defect == "unknown" else {"ax": 2}
    bits = {} if defect == "unknown" else {"ax": (0xFFFF, 2)}
    census._simulate_tmp_write_8616(row, dst, registers, exact)
    kb._kb_tmp_write_8616(row, dst, bits, known)
    assert 7 not in exact
    assert known[7] == (0, 0)
