"""Tests for immutable Frontend function-boundary inventory reuse."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
import pytest
import inertia.frontend.x86_16.frontend_function_boundary_index as index_module
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary_program import (
    build_callsite_summary_inventory_with_program_evidence_8616,
)
from inertia.ir import IRValue, MemSpace
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401

from inertia.frontend.x86_16.frontend_function_boundary import (
    ExactFunctionRangeBoundary8616,
    exact_function_range_boundary_8616,
)
from inertia.frontend.x86_16.frontend_function_boundary_index import (
    exact_function_entry_boundary_8616,
    exact_function_range_inventory_8616,
)
from inertia.semantics.call_stack_effect_pipeline import (
    build_semantic_function_ssa_8616,
)
from inertia.semantics.direct_near_call_target_binding import (
    prove_direct_near_call_target_binding_8616,
)


def _boundary(project: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
    """Build one minimal complete boundary fixture."""
    return ExactFunctionRangeBoundary8616(
        project=project,
        addr=start,
        size=end - start,
        block_addrs_set=frozenset({start}),
        reachable_instruction_addrs=frozenset({start}),
        successor_edges=(),
    )


def test_exact_function_range_inventory_reuses_boundaries(monkeypatch) -> None:
    project = SimpleNamespace()
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)
    ranges = ((0x100, 0x120), (0x200, 0x230))

    first = exact_function_range_inventory_8616(project, ranges)
    second = exact_function_range_inventory_8616(project, ranges)

    assert second is first
    assert calls == list(ranges)
    assert tuple(boundary.addr for boundary in first.boundaries) == (0x100, 0x200)


def test_exact_function_range_inventory_keys_distinct_ranges(monkeypatch) -> None:
    project = SimpleNamespace()
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)

    exact_function_range_inventory_8616(project, ((0x100, 0x120),))
    exact_function_range_inventory_8616(project, ((0x100, 0x130),))

    assert calls == [(0x100, 0x120), (0x100, 0x130)]


def test_exact_function_range_inventory_keeps_failed_ranges_closed(monkeypatch) -> None:
    project = SimpleNamespace()
    monkeypatch.setattr(
        index_module,
        "exact_function_range_boundary_8616",
        lambda _project, _start, _end: None,
    )

    inventory = exact_function_range_inventory_8616(project, ((0x100, 0x120),))

    assert inventory.ranges == ((0x100, 0x120),)
    assert inventory.boundaries == ()


@pytest.mark.parametrize("start,end,accepted", [
    (0x1000, 0x1020, True), (0x1000, 0x1100, True),
    (0xFFF, 0x1020, False), (0x1000, 0x1101, False), (0x1000, 0x1000, False),
])
def test_exact_function_range_inventory_refuses_ranges_outside_rebased_image(monkeypatch, start, end, accepted) -> None:
    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(min_addr=0x1000, max_addr=0x10FF))
    )
    calls: list[tuple[int, int]] = []

    def collect(project_arg: object, start: int, end: int) -> ExactFunctionRangeBoundary8616:
        calls.append((start, end))
        return _boundary(project_arg, start, end)

    monkeypatch.setattr(index_module, "exact_function_range_boundary_8616", collect)

    inventory = exact_function_range_inventory_8616(
        project,
        ((start, end), (0x10000, 0x10020)),
    )

    assert calls == ([(start, end)] if accepted else [])
    assert tuple(boundary.addr for boundary in inventory.boundaries) == ((start,) if accepted else ())


def test_exact_function_entry_boundary_accepts_only_padding_to_prologue(monkeypatch) -> None:
    boundary = _boundary(object(), 0x100, 0x120)
    image = b"\x90" * 7 + b"\x55\x8b\xec" + b"\x90" * 22

    class Memory:
        def load(self, addr: int, size: int) -> bytes:
            offset = addr - 0x100
            return image[offset : offset + size]

    project = SimpleNamespace(loader=SimpleNamespace(memory=Memory()))
    monkeypatch.setattr(
        index_module,
        "exact_function_range_inventory_8616",
        lambda _project, ranges: SimpleNamespace(ranges=ranges, boundaries=(boundary,)),
    )

    assert exact_function_entry_boundary_8616(project, 0x107, ((0x100, 0x120),)) is boundary
    assert exact_function_entry_boundary_8616(project, 0x108, ((0x100, 0x120),)) is None


def test_exact_binary_boundary_closes_pointer_index_call_and_cfg_evidence() -> None:
    """Preserve the closed source-free boundary needed before index-use proof."""
    # Rebasing the select_word machine code keeps the call's relative target
    # and the two BP argument reads; the helper body is deliberately minimal.
    function_bytes = bytes.fromhex(
        "55 8b ec b8 00 00 e8 c2 04 57 56 8b 46 06 d1 e0 "
        "03 46 04 e9 00 00 5e 5f 8b e5 5d c3"
    )
    image = bytearray(0x5BD)
    image[0xF1 : 0xF1 + len(function_bytes)] = function_bytes
    image[0x5BC] = 0xC3
    project = angr.Project(
        io.BytesIO(image),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x10F1,
        },
        auto_load_libs=False,
        simos="DOS",
    )
    boundary = exact_function_range_boundary_8616(project, 0x10F1, 0x110D)
    assert boundary is not None
    assert boundary.successor_edges == ((0x10F1, 0x10FA), (0x10FA, 0x1107))

    _, outputs, ssa = build_semantic_function_ssa_8616(project, boundary)
    assert not outputs.function.refusals
    assert ssa.predecessor_map[0x10FA] == (0x10F1,)
    assert ssa.predecessor_map[0x1107] == (0x10FA,)
    calls = tuple(
        instruction
        for block in outputs.function.blocks
        for instruction in block.instrs
        if instruction.op == "CALL"
    )
    assert len(calls) == 1
    assert calls[0].addr == 0x10F7
    assert len(calls[0].args) == 1
    assert isinstance(calls[0].args[0], IRValue)
    # Keep the native segmented expression; the source-bound theorem supplies
    # its target rather than requiring the importer to replace it with a literal.
    assert calls[0].args[0].const is None
    call_block = next(block for block in outputs.function.blocks if calls[0] in block.instrs)
    summary = build_callsite_summary_inventory_with_program_evidence_8616(
        project, boundary, (calls[0].addr,),
    )[calls[0].addr]
    target_proof = prove_direct_near_call_target_binding_8616(
        project, block=call_block, instruction=calls[0], summary=summary,
    )
    assert target_proof.complete
    assert target_proof.target_addr == 0x15BC
    assert calls[0].call_stack_effect is not None
    assert calls[0].call_stack_effect.complete
    assert outputs.function.logical_memory is not None
    reads = tuple(
        (access.key.insn_addr, access.address.space, access.address.base,
         access.address.offset, access.address.size)
        for access in outputs.function.logical_memory.accesses
        if access.kind == "read" and access.key.insn_addr in (0x10FC, 0x1101)
    )
    assert reads == (
        (0x10FC, MemSpace.SS, ("bp",), 6, 2),
        (0x1101, MemSpace.SS, ("bp",), 4, 2),
    )
