from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace
from typing import Protocol, cast

import pytest
from angr import ailment
from angr.ailment.expression import Convert, StackBaseOffset, VirtualVariable, VirtualVariableCategory
from angr.ailment.manager import Manager
from angr.analyses.s_propagator import SPropagator
from angr.code_location import AILCodeLocation
from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions
from angr_platforms.X86_16.stack_compat import (
    StackPointerPropagationVerdict8616,
    StackValueUse8616,
    apply_x86_16_stack_compatibility,
    classify_stack_value_use_8616,
    normalize_stack_pointer_replacement_8616,
)


@pytest.mark.parametrize("kind", [
    "address", "data", "mixed", "return", "call", "nested_call", "missing",
    "load_address", "load_guard", "load_alt", "store_guard", "definition",
])
def test_stack_value_roles_do_not_turn_numeric_operands_into_addresses(kind):
    value = VirtualVariable(1, 7, 16, VirtualVariableCategory.REGISTER, oident=16)
    constant = ailment.Expr.Const(2, 0x200, 16)
    if kind in {"address", "data", "mixed"}:
        statement = ailment.Stmt.Store(
            3, value if kind != "data" else constant,
            value if kind != "address" else constant, 2, "Iend_LE",
        )
    elif kind == "return":
        statement = ailment.Stmt.Return(3, [value])
    elif kind.startswith("load_"):
        load = ailment.Expr.Load(
            3, value if kind == "load_address" else constant, 2, "Iend_LE",
            guard=value if kind == "load_guard" else None,
            alt=value if kind == "load_alt" else None,
        )
        statement = ailment.Stmt.Return(4, [load])
    elif kind == "store_guard":
        statement = ailment.Stmt.Store(3, value, constant, 2, "Iend_LE", guard=value)
    elif kind == "definition":
        statement = ailment.Stmt.Assignment(3, value, constant)
    elif kind in {"call", "nested_call"}:
        call = ailment.Expr.Call(3, constant, args=(value,), bits=16)
        statement = (
            ailment.Stmt.Return(4, [ailment.Expr.Load(5, call, 2, "Iend_LE")])
            if kind == "nested_call" else ailment.Stmt.SideEffectStatement(4, call)
        )
    else:
        statement = None
    expected = (
        StackValueUse8616.UNKNOWN if kind in {"missing", "definition"} else
        StackValueUse8616.ADDRESS_ONLY if kind in {"address", "load_address"} else StackValueUse8616.VALUE
    )
    assert classify_stack_value_use_8616(statement, 7) is expected


@pytest.mark.parametrize("kind", ["address", "data", "mixed", "missing"])
@pytest.mark.parametrize("graph_mode", [False, True])
@pytest.mark.parametrize("value_bits", [16, 32])
def test_stack_propagator_filters_numeric_address_replacements(monkeypatch, kind, graph_mode, value_bits):
    value = VirtualVariable(1, 7, value_bits, VirtualVariableCategory.REGISTER, oident=16)
    constant = ailment.Expr.Const(2, 0x200, 16)
    statement = ailment.Stmt.Store(
        3, value if kind in {"address", "mixed"} else constant,
        value if kind != "address" else constant, 2, "Iend_LE",
    )
    block = ailment.Block(0x1000, 1, statements=[statement])
    location = AILCodeLocation(0x1000, None, 9 if kind == "missing" else 0)
    replacement = StackBaseOffset(4, 16, -2)
    entries = {location: {value: replacement}}

    def original(receiver):
        receiver.model.replacements = entries

    monkeypatch.setattr(SPropagator, "_analyze", original)
    apply_x86_16_stack_compatibility()
    receiver = SimpleNamespace(
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16", sp_offset=16, bp_offset=20)),
        model=SimpleNamespace(), func_graph=[block] if graph_mode else None,
        block=None if graph_mode else block, _ail_manager=Manager(),
    )
    SPropagator._analyze(receiver)

    accepted = kind == "address" and value_bits == 16
    assert entries[location] == ({value: replacement} if accepted else {})
    stats = receiver.model._inertia_stack_pointer_propagation_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.failure_count == (0 if accepted else 1)


class _StackOffsetToAddr(Protocol):
    __name__: str

    def __call__(self, self_obj: _LiveDefinitionsStub, offset: int) -> int: ...


@dataclass(frozen=True, slots=True)
class _ArchStub:
    bits: int


@dataclass(frozen=True, slots=True)
class _LiveDefinitionsStub:
    arch: _ArchStub


def test_x86_16_stack_compat_patches_16bit_stack_offsets() -> None:
    original = LiveDefinitions.stack_offset_to_stack_addr
    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()

        patched = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
        assert patched.__name__ == "_stack_offset_to_stack_addr_8616"
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=16)), 2) == 0x8000
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=16)), -2) == 0x7FFC
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = original


def test_x86_16_stack_compat_delegates_non_16bit_offsets() -> None:
    previous = LiveDefinitions.stack_offset_to_stack_addr

    def original(self_obj: _LiveDefinitionsStub, offset: int) -> int:
        return 0xABC000 + self_obj.arch.bits + offset

    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()

        patched = cast(_StackOffsetToAddr, LiveDefinitions.stack_offset_to_stack_addr)
        assert patched(_LiveDefinitionsStub(_ArchStub(bits=32)), 5) == 0xABC025
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = previous


def test_x86_16_stack_compat_patch_is_idempotent() -> None:
    original = LiveDefinitions.stack_offset_to_stack_addr
    try:
        LiveDefinitions.stack_offset_to_stack_addr = original

        apply_x86_16_stack_compatibility()
        first = LiveDefinitions.stack_offset_to_stack_addr
        apply_x86_16_stack_compatibility()

        assert LiveDefinitions.stack_offset_to_stack_addr is first
    finally:
        LiveDefinitions.stack_offset_to_stack_addr = original


def test_x86_16_stack_compat_patch_installs_propagator_normalization_once() -> None:
    apply_x86_16_stack_compatibility()
    first = SPropagator._analyze

    apply_x86_16_stack_compatibility()

    assert first.__name__ == "_analyze_8616"
    assert SPropagator._analyze is first


@pytest.mark.parametrize("sp_offset,bp_offset", [(None, 20), (16, None)])
def test_x86_16_stack_compat_refuses_missing_register_offsets(monkeypatch, sp_offset, bp_offset):
    def original(self):
        self.model.replacements = {}

    monkeypatch.setattr(SPropagator, "_analyze", original)
    monkeypatch.setattr(LiveDefinitions, "stack_offset_to_stack_addr", LiveDefinitions.stack_offset_to_stack_addr)
    apply_x86_16_stack_compatibility()
    receiver = SimpleNamespace(
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16", sp_offset=sp_offset, bp_offset=bp_offset)),
        model=SimpleNamespace(),
    )

    with pytest.raises(ValueError, match="requires registered SP and BP offsets"):
        SPropagator._analyze(receiver)


def test_x86_16_stack_pointer_replacement_narrows_loader_address_width() -> None:
    manager = Manager()
    stack_pointer = VirtualVariable(
        manager.next_atom(),
        1,
        16,
        VirtualVariableCategory.REGISTER,
        oident=16,
    )
    stack_address = StackBaseOffset(manager.next_atom(), 32, -14)

    result = normalize_stack_pointer_replacement_8616(
        stack_pointer,
        stack_address,
        stack_register_offsets=frozenset((16, 20)),
        ail_manager=manager,
    )

    assert result.verdict is StackPointerPropagationVerdict8616.MATERIALIZED_NARROWING
    assert isinstance(result.replacement, Convert)
    assert result.replacement.from_bits == 32
    assert result.replacement.to_bits == 16
    assert result.replacement.operand == stack_address
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 1
    assert result.stats.materialized_count == 1
    assert result.stats.failure_count == 0


def test_x86_16_stack_pointer_replacement_refuses_unproven_upper_bits() -> None:
    manager = Manager()
    stack_pointer = VirtualVariable(
        manager.next_atom(),
        1,
        32,
        VirtualVariableCategory.REGISTER,
        oident=16,
    )
    stack_address = StackBaseOffset(manager.next_atom(), 16, 0)

    result = normalize_stack_pointer_replacement_8616(
        stack_pointer,
        stack_address,
        stack_register_offsets=frozenset((16, 20)),
        ail_manager=manager,
    )

    assert result.verdict is StackPointerPropagationVerdict8616.REFUSED_WIDENING
    assert result.replacement is stack_address
    assert result.stats.raw_fact_count == 1
    assert result.stats.normalized_fact_count == 1
    assert result.stats.classified_fact_count == 0
    assert result.stats.materialized_count == 0
    assert result.stats.failure_count == 1
