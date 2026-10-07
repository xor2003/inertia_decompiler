"""Typed direct-global register update regressions."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
import inertia.lowering.direct_global_register_updates as updates
from inertia.pipeline.structured_ast_query_index import StructuredAstQuerySession8616
from capstone.x86_const import X86_INS_MOV, X86_INS_XOR, X86_OP_MEM, X86_OP_REG


class _Codegen:
    """Minimal angr structured-node owner for Lowering tests."""

    def __init__(self) -> None:
        self._next = 0
        self.cstyle_null_cmp = True
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_ident(self, name: str) -> str:
        """Allocate one display identity."""
        self._next += 1
        return f"{name}_{self._next}"

    def next_node_idx(self) -> int:
        """Allocate one node identity."""
        self._next += 1
        return self._next


def _memory(offset: int, width: int = 2) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_MEM, size=width, mem=SimpleNamespace(base=0, index=0, disp=offset))


def _register(register_id: int, width: int = 2) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_REG, size=width, reg=register_id)


def test_collects_adjacent_direct_global_xor(monkeypatch: pytest.MonkeyPatch) -> None:
    instructions = (
        SimpleNamespace(id=X86_INS_MOV, address=0x12D40, operands=(_register(3), _memory(0x39A))),
        SimpleNamespace(id=X86_INS_XOR, address=0x12D43, operands=(_memory(0x39E), _register(3))),
    )
    monkeypatch.setattr(updates, "_direct_global_update_blocks_8616", lambda *_args: (object(),))
    monkeypatch.setattr(updates, "_capstone_insns_for_direct_global_update_8616", lambda *_args: instructions)

    facts = updates.collect_direct_global_register_updates_8616(object(), object())

    assert facts == (
        updates.DirectGlobalRegisterUpdate8616(
            0x39A, 0x39E, 2, 3, updates.DirectGlobalRegisterUpdateOp8616.XOR, 0x12D40, 0x12D43
        ),
    )


def test_materializes_exact_tagged_global_xor(monkeypatch: pytest.MonkeyPatch) -> None:
    codegen = _Codegen()
    assignments = []
    for lane in (0x39E, 0x39F):
        destination = structured_c.CVariable(
            SimMemoryVariable(lane, 1, name=f"g_{lane:04X}", region=0x12D2C), codegen=codegen
        )
        unsupported = structured_c.CDirtyExpression(SimpleNamespace(callee=None), codegen=codegen)
        rhs = structured_c.CBinaryOp("Xor", destination, unsupported, codegen=codegen)
        assignments.append(
            structured_c.CAssignment(destination, rhs, codegen=codegen, tags={"ins_addr": 0x12D43})
        )
    codegen.cfunc = SimpleNamespace(
        addr=0x12D2C, statements=structured_c.CStatements(assignments, codegen=codegen)
    )
    project = SimpleNamespace(kb=SimpleNamespace(functions={0x12D2C: object()}))
    fact = updates.DirectGlobalRegisterUpdate8616(
        0x39A, 0x39E, 2, 3, updates.DirectGlobalRegisterUpdateOp8616.XOR, 0x12D40, 0x12D43
    )
    monkeypatch.setattr(updates, "collect_direct_global_register_updates_8616", lambda *_args: (fact,))
    root = codegen.cfunc.statements
    query_session = StructuredAstQuerySession8616(root)
    original_iter = updates._iter_c_nodes_deep_8616
    root_scan_count = 0

    def count_root_scans(node: object):
        nonlocal root_scan_count
        if node is root:
            root_scan_count += 1
        yield from original_iter(node)

    monkeypatch.setattr(updates, "_iter_c_nodes_deep_8616", count_root_scans)

    changed = updates.materialize_direct_global_register_updates_8616(
        project,
        codegen,
        {0x39A: ("g_039A", 2), 0x39E: ("g_039E", 2)},
        query_session=query_session,
    )

    assert changed is True
    assert root_scan_count == 0
    assert query_session.stats().build_count == 1
    for assignment in assignments:
        assert isinstance(assignment.rhs, structured_c.CBinaryOp)
        assert assignment.rhs.op == "Xor"
        assert isinstance(assignment.rhs.rhs, structured_c.CVariable)
        assert assignment.rhs.rhs.variable.addr == 0x39A
    assert codegen._inertia_direct_global_register_update_stats_8616.complete


def test_refuses_update_without_exact_source_global(monkeypatch: pytest.MonkeyPatch) -> None:
    codegen = _Codegen()
    destination = structured_c.CVariable(SimMemoryVariable(0x39E, 2), codegen=codegen)
    assignment = structured_c.CAssignment(destination, object(), codegen=codegen, tags={"ins_addr": 0x12D43})
    codegen.cfunc = SimpleNamespace(addr=0x12D2C, statements=structured_c.CStatements([assignment], codegen=codegen))
    project = SimpleNamespace(kb=SimpleNamespace(functions={0x12D2C: object()}))
    fact = updates.DirectGlobalRegisterUpdate8616(
        0x39A, 0x39E, 2, 3, updates.DirectGlobalRegisterUpdateOp8616.XOR, 0x12D40, 0x12D43
    )
    monkeypatch.setattr(updates, "collect_direct_global_register_updates_8616", lambda *_args: (fact,))

    assert updates.materialize_direct_global_register_updates_8616(project, codegen, {}) is False
    assert assignment.rhs.__class__ is object
    assert codegen._inertia_direct_global_register_update_stats_8616.failure_count == 1


def test_materializer_reuses_binary_facts_until_function_surface_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x12D2C,
        statements=structured_c.CStatements([], codegen=codegen),
    )
    function = SimpleNamespace(addr=0x12D2C, size=1, blocks=())
    project = SimpleNamespace(kb=SimpleNamespace(functions={0x12D2C: function}))
    collect_count = 0

    def collect(*_args: object) -> tuple[updates.DirectGlobalRegisterUpdate8616, ...]:
        nonlocal collect_count
        collect_count += 1
        return ()

    monkeypatch.setattr(updates, "collect_direct_global_register_updates_8616", collect)

    assert updates.materialize_direct_global_register_updates_8616(project, codegen, {}) is False
    assert updates.materialize_direct_global_register_updates_8616(project, codegen, {}) is False
    assert collect_count == 1

    function.size = 2
    assert updates.materialize_direct_global_register_updates_8616(project, codegen, {}) is False
    assert collect_count == 2
