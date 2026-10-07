"""Focused tests for generated runtime memory-read helper ownership."""

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CConstant, CFunctionCall, CUnaryOp
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    _pure_consumed_push_carrier_expression_8616,
)
from inertia.lowering.runtime_memory_helpers import (
    MemoryPointerHelper8616,
    SegmentedMemoryReadHelper8616,
    memory_pointer_helper_8616,
    segmented_memory_read_helper_8616,
)


class _Codegen:
    """Minimal angr structured-C codegen fixture."""

    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-C node index."""
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def test_classifies_only_generated_memory_read_helpers() -> None:
    """Typed helper identity must not include ordinary source calls."""
    assert memory_pointer_helper_8616(SimpleNamespace(callee_target="MEM_U16")) is MemoryPointerHelper8616.MEM_U16
    assert (
        segmented_memory_read_helper_8616(SimpleNamespace(callee_target="SEG_U16"))
        is SegmentedMemoryReadHelper8616.SEG_U16
    )
    assert memory_pointer_helper_8616(SimpleNamespace(callee_target="sub_10010")) is None
    assert segmented_memory_read_helper_8616(SimpleNamespace(callee_target="sub_10010")) is None


def test_consumed_push_purity_keeps_ordinary_calls() -> None:
    """Only recursively pure generated reads may be removed as PUSH carriers."""
    codegen = _Codegen()
    pointer = CConstant(0x1234, SimTypeShort(False), codegen=codegen)
    memory_read = CFunctionCall("MEM_U16", None, [pointer], codegen=codegen)
    segmented_read = CFunctionCall("SEG_U16", None, [pointer, pointer], codegen=codegen)
    ordinary_call = CFunctionCall("sub_10010", None, [pointer], codegen=codegen)

    assert _pure_consumed_push_carrier_expression_8616(memory_read) is True
    assert _pure_consumed_push_carrier_expression_8616(segmented_read) is True
    assert _pure_consumed_push_carrier_expression_8616(ordinary_call) is False


@pytest.mark.parametrize("tag,nested_call,expected", [
    ("MEM_U16", False, 2),
    (None, False, 0),
    ("MEM_U8", False, 0),
    ("MEM_U16", True, 0),
])
def test_indexed_prefix_survives_only_proven_read_helper(tag, nested_call, expected):
    """A generated read preserves bounds, but its unknown argument call does not."""
    from tests.structuring.test_x86_16_indexed_stack_ranges import (
        _Codegen as RangeCodegen,
    )
    from tests.structuring.test_x86_16_indexed_stack_ranges import (
        _const,
        _signed_remainder_fact,
        _two_loop_fixture,
    )

    from inertia.structuring.indexed_stack_ranges import (
        collect_indexed_stack_read_proofs_8616,
    )

    root, random_read, high_read = _two_loop_fixture()
    codegen = RangeCodegen()
    pointer = (
        CFunctionCall("unknown", None, [], codegen=codegen)
        if nested_call else _const(0, codegen)
    )
    helper = CFunctionCall(
        "MEM_U16", None, [pointer], codegen=codegen,
        tags={"inertia_x86_16_runtime_pointer_helper": tag},
    )
    root.statements[-1].body.statements.insert(1, helper)
    report = collect_indexed_stack_read_proofs_8616(
        root, direct_stack_move_facts=(_signed_remainder_fact(),),
    )
    assert report.materialized_count == expected
    if expected:
        assert {proof.read_node_id for proof in report.proofs} == {id(random_read), id(high_read)}
def test_consumed_push_purity_accepts_value_only_dereference() -> None:
    """An exact consumed PUSH may discard its duplicate pure memory read."""
    codegen = _Codegen()
    pointer = CConstant(0x1234, SimTypeShort(False), codegen=codegen)
    memory_read = CUnaryOp("Dereference", pointer, codegen=codegen)

    assert _pure_consumed_push_carrier_expression_8616(memory_read) is True
