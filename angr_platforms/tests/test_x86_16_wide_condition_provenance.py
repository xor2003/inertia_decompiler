"""Derived wide predicates must not replay their source word-register binding."""

import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from angr_platforms.X86_16.alias.condition_register_bindings import condition_operand_storage_binding_8616
from angr_platforms.X86_16.ir.condition_ir import ConditionRegisterBindingIR
from angr_platforms.X86_16.structuring.wide_stack_condition_chains import recover_wide_stack_condition_chain_8616
from angr_platforms.X86_16.structuring.wide_stack_predicate_graphs import (
    WidePredicateLeaf8616,
    recover_wide_stack_predicate_graph_8616,
)
from angr_platforms.X86_16.structuring.wide_stack_single_branches import recover_wide_stack_single_body_condition_8616
from test_x86_16_wide_stack_condition_chains import _adjacent, _condition, _word


@pytest.mark.parametrize("mode", ["chain", "graph", "single"])
def test_wide_condition_discards_obsolete_scalar_binding(mode):
    yes, no = 0x1030, 0x1040
    root = replace(
        _condition("slt", 10, 6, 0x1000, yes, 0x1010),
        producer_insn=0x1000,
        producer_semantics=("cmp_mem_reg16", ("bp", 10, 10), "dx"),
        register_bindings=(ConditionRegisterBindingIR("dx", _word(6)),),
    )
    equal = _condition("eq", 10, 6, 0x1010, 0x1020, no)
    low = _condition("ult", 8, 4, 0x1020, yes, no)
    conditions = {item.block_addr: item for item in (root, equal, low)}

    def classify(target):
        return True if target == yes else False if target == no else None

    if mode == "chain":
        result = recover_wide_stack_condition_chain_8616(root, conditions, {}, yes, no, _adjacent)
        condition = result.condition
    elif mode == "single":
        result = recover_wide_stack_single_body_condition_8616(root, conditions, {}, _adjacent, classify)
        condition = result.condition
    else:
        result = recover_wide_stack_predicate_graph_8616(tuple(conditions.values()), {}, _adjacent, classify)
        assert isinstance(result.expression, WidePredicateLeaf8616)
        condition = result.expression.condition
    assert condition is not None
    assert condition.producer_insn == root.producer_insn
    assert condition.producer_semantics is None
    assert condition.register_bindings == ()
    assert condition_operand_storage_binding_8616(condition, condition.lhs) is condition.lhs
    assert condition_operand_storage_binding_8616(condition, condition.rhs) is condition.rhs
    assert root.register_bindings  # Original word evidence remains intact.


_REFERENCE = """
unsigned short _InBoxLng(long x, long z, long xl, long zl, long xh, long zh) {
    if (x < xl || x > xh || z < zl || z > zh) return 0;
    return 1;
}
"""
_HARNESS = """
#include <stdio.h>
static int mismatch(const char *axis, long value, long low, long high,
                    unsigned expected, unsigned actual) {
    fprintf(stderr, "%s: value=%ld low=%ld high=%ld expected=%u actual=%u\\n",
            axis, value, low, high, expected, actual);
    return 1;
}
int main(void) {
    static const long values[] = {
        -2147483647L - 1, -65537, -65536, -32769, -1,
        0, 1, 32767, 32768, 65535, 65536, 65537, 2147483647
    };
    unsigned count = sizeof(values) / sizeof(values[0]);
    for (unsigned i = 0; i < count; ++i)
    for (unsigned j = 0; j < count; ++j)
    for (unsigned k = 0; k < count; ++k) {
        long value = values[i], low = values[j], high = values[k];
        unsigned expected = value >= low && value <= high;
        unsigned actual = _InBoxLng(value, 0, low, -1, high, 1);
        if (actual != expected) return mismatch("x", value, low, high, expected, actual);
        actual = _InBoxLng(0, value, -1, low, 1, high);
        if (actual != expected) return mismatch("z", value, low, high, expected, actual);
        actual = _InBoxLng(value, value, low, low, high, high);
        if (actual != expected) return mismatch("both", value, low, high, expected, actual);
    }
    return 0;
}
"""


def assert_inbox_behavior(generated_c: str, directory: Path) -> None:
    """Execute unchanged C on signed dword boundaries and reversed bounds."""
    source, executable = directory / "inbox.c", directory / "inbox"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=2)
    assert executed.returncode == 0, "InBoxLng behavior mismatch: " + executed.stderr


def test_inbox_oracle_accepts_inclusive_signed_bounds(tmp_path: Path) -> None:
    assert_inbox_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("x < xl", "x <= xl"),
    ("x < xl", "x < (short)(xl >> 16)"),
    ("z > zh", "z > (short)(zh >> 16)"),
    ("return 1", "return 0"),
])
def test_inbox_oracle_rejects_corruption(tmp_path: Path, original: str, replacement: str) -> None:
    with pytest.raises(AssertionError, match="InBoxLng behavior mismatch"):
        assert_inbox_behavior(_REFERENCE.replace(original, replacement), tmp_path)
