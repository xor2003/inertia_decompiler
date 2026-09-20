"""Tests for typed bounded Frontend instruction inventory reuse."""

from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16 import decompiler_postprocess_stage, frontend_function_instructions
from angr_platforms.X86_16.frontend_function_instructions import (
    BoundedLinearInstructionStatus8616,
    collect_bounded_linear_instruction_inventory_8616,
)


def _instruction(address: int, mnemonic: str = "ret") -> object:
    """Build one immutable decoded-instruction fixture."""
    return SimpleNamespace(address=address, size=1, mnemonic=mnemonic)


def test_bounded_inventory_reuses_exact_request(monkeypatch) -> None:
    """An unchanged function, window, and base surface decode only once."""
    calls: list[int] = []
    terminal = _instruction(0x1000)

    def decode(
        _project: object,
        address: int,
        *,
        num_inst: int | None = None,
        opt_level: int = 0,
    ) -> tuple[object, ...]:
        calls.append(address)
        assert num_inst == 1
        assert opt_level == 0
        return (terminal,)

    monkeypatch.setattr(
        frontend_function_instructions,
        "decoded_block_instructions_8616",
        decode,
    )
    first = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x1000,
        base_instructions=(terminal,),
    )
    second = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x1000,
        base_instructions=(terminal,),
        previous=first,
    )

    assert second is first
    assert first.closed is True
    assert first.status is BoundedLinearInstructionStatus8616.TERMINAL_REACHED
    assert calls == [0x1000]


def test_bounded_inventory_invalidates_changed_consumed_surface(monkeypatch) -> None:
    """Function, window, and base changes must each refuse stale reuse."""
    calls: list[int] = []

    def decode(
        _project: object,
        address: int,
        *,
        num_inst: int | None = None,
        opt_level: int = 0,
    ) -> tuple[object, ...]:
        calls.append(address)
        return (_instruction(address),)

    monkeypatch.setattr(
        frontend_function_instructions,
        "decoded_block_instructions_8616",
        decode,
    )
    first = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x1000,
        base_instructions=(_instruction(0x1000),),
    )
    changed_function = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x2000,
        base_instructions=(_instruction(0x2000),),
        previous=first,
    )
    changed_window = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x2000,
        base_instructions=(_instruction(0x2000),),
        previous=changed_function,
        max_bytes=0x400,
    )
    changed_base = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x2000,
        base_instructions=(_instruction(0x2000, "nop"),),
        previous=changed_window,
        max_bytes=0x400,
    )

    assert changed_function is not first
    assert changed_window is not changed_function
    assert changed_base is not changed_window
    assert calls == [0x1000, 0x2000, 0x2000, 0x2000]


def test_bounded_inventory_decodes_to_exact_region_end(monkeypatch) -> None:
    """An exact sidecar end is decoded even when no terminal opcode is present."""
    instructions = (
        _instruction(0x1000, "nop"),
        _instruction(0x1001, "nop"),
        _instruction(0x1002, "ret"),
    )

    def decode(
        _project: object,
        address: int,
        *,
        num_inst: int | None = None,
        opt_level: int = 0,
    ) -> tuple[object, ...]:
        assert num_inst == 1
        assert opt_level == 0
        return (instructions[address - 0x1000],)

    monkeypatch.setattr(
        frontend_function_instructions,
        "decoded_block_instructions_8616",
        decode,
    )

    inventory = collect_bounded_linear_instruction_inventory_8616(
        object(),
        function_entry=0x1000,
        base_instructions=(),
        exact_end=0x1002,
    )

    assert inventory.status is BoundedLinearInstructionStatus8616.EXACT_END_REACHED
    assert inventory.exact_end == 0x1002
    assert inventory.max_bytes == 2
    assert [instruction.address for instruction in inventory.sequential_instructions] == [
        0x1000,
        0x1001,
    ]
    assert inventory.closed is True


def test_stage_reuses_inventory_without_reloading_instruction_bytes(monkeypatch) -> None:
    """The Rewrite compatibility wrapper must not repeat Frontend byte reads."""
    terminal = _instruction(0x1000)
    loads: list[tuple[int, int]] = []

    monkeypatch.setattr(
        frontend_function_instructions,
        "decoded_block_instructions_8616",
        lambda *_args, **_kwargs: (terminal,),
    )
    monkeypatch.setattr(
        decompiler_postprocess_stage._jcc,
        "_function_insns_for_codegen_8616",
        lambda *_args: (terminal,),
    )
    memory = SimpleNamespace(
        load=lambda address, size: loads.append((address, size)) or b"\xc3",
    )
    project = SimpleNamespace(loader=SimpleNamespace(memory=memory))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    first = decompiler_postprocess_stage._linear_function_insns_for_codegen_8616(
        project,
        codegen,
    )
    second = decompiler_postprocess_stage._linear_function_insns_for_codegen_8616(
        project,
        codegen,
    )

    assert first == second == (terminal,)
    assert loads == [(0x1000, 1)]
    assert codegen._inertia_instruction_bytes_by_addr_8616 == {0x1000: b"\xc3"}
