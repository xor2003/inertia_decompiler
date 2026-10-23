"""Dead-state analysis handles exact cancellation without dropping live effects."""
from copy import deepcopy

import pytest

from tools.dosunit.compare.flat32_dead_flags import FLAGS, REGISTERS, _flag_inputs


@pytest.mark.parametrize("operation", ["sub", "xor"])
@pytest.mark.parametrize("width", [8, 16, 32])
def test_identical_value_cancels_but_other_operand_stays_live(operation, width):
    value = {"op": "input", "name": "eax", "width": width}
    zero = {"op": operation, "width": width, "args": [value, deepcopy(value)]}
    assert _flag_inputs([zero], frozenset(), FLAGS | REGISTERS) == frozenset()
    changed = deepcopy(zero)
    changed["args"][1]["name"] = "ecx"
    assert _flag_inputs([changed], frozenset(), FLAGS | REGISTERS) == {"eax", "ecx"}
    assert _flag_inputs([zero, value], frozenset(), FLAGS | REGISTERS) == {"eax"}


def test_width_mismatch_and_non_cancelling_arithmetic_remain_live():
    value = {"op": "input", "name": "eax", "width": 32}
    for operation, width in [("sub", 16), ("add", 32), ("or", 32)]:
        term = {"op": operation, "width": width, "args": [value, deepcopy(value)]}
        assert _flag_inputs([term], frozenset(), FLAGS | REGISTERS) == {"eax"}


def test_cancellation_does_not_hide_address_or_separate_flag_dependencies():
    value = {"op": "input", "name": "eax", "width": 32}
    zero = {"op": "sub", "width": 32, "args": [value, deepcopy(value)]}
    memory = {"op": "storele", "width": 0, "args": [
        {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}, value, zero]}
    flag = {"op": "input", "name": "cc_dep1", "width": 32}
    assert _flag_inputs([memory, flag], frozenset(), FLAGS | REGISTERS) == {"eax", "cc_dep1"}
