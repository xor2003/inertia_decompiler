"""Regression tests for typed JCC instruction-inventory consumption."""

from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall
import inertia.postprocess.decompiler_postprocess_jcc as decompiler_postprocess_jcc

from inertia.frontend.x86_16.frontend_function_instructions import (
    FunctionInstructionInventory8616,
    FunctionInstructionInventoryStatus8616,
)


class _Operand:
    """Minimal immediate Capstone operand boundary."""

    type = 2
    imm = 0x2000


class _Instruction:
    """Minimal instruction boundary consumed by call-return recovery."""

    def __init__(self, address: int, mnemonic: str) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.operands = (_Operand(),) if mnemonic == "call" else ()


class _Codegen:
    """Minimal angr codegen identity allocator."""

    def __init__(self) -> None:
        self._idx = 0
        self.cfunc = SimpleNamespace(addr=0x1000)

    def next_idx(self, name: str) -> int:
        """Allocate one C-node identity."""
        del name
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Allocate one C-node index."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return the deterministic display identity used by the fixture."""
        return name


def _inventory(
    *instructions: object,
    complete: bool,
) -> FunctionInstructionInventory8616:
    """Build closed complete or refused frontend instruction evidence."""
    return FunctionInstructionInventory8616(
        function_entry=0x1000,
        block_addrs=(0x1000,),
        instructions=tuple(instructions),
        status=(
            FunctionInstructionInventoryStatus8616.COMPLETE
            if complete
            else FunctionInstructionInventoryStatus8616.DECODE_REFUSED
        ),
        raw_fact_count=1,
        normalized_fact_count=1,
        classified_fact_count=1,
        materialized_count=int(complete),
        failure_count=int(not complete),
    )


def _project() -> SimpleNamespace:
    """Build the narrow project boundary needed for callee naming."""
    callee = SimpleNamespace(name="clock", prototype=SimpleNamespace(args=()))
    return SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda *, addr, create=False: callee if addr == 0x2000 else None
            )
        )
    )


def test_complete_inventory_skips_linear_instruction_rescue(monkeypatch) -> None:
    """A closed frontend inventory must not trigger byte-by-byte re-decoding."""
    call = _Instruction(0x1000, "call")
    guard = _Instruction(0x1002, "cmp")
    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "collect_function_instruction_inventory_8616",
        lambda project, *, function_entry: _inventory(call, guard, complete=True),
    )

    def refuse_linear_rescue(*args: object, **kwargs: object) -> tuple[object, ...]:
        raise AssertionError("complete frontend evidence must bypass linear rescue")

    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "_linear_insns_before_addr_8616",
        refuse_linear_rescue,
    )
    codegen = _Codegen()

    result = decompiler_postprocess_jcc._call_return_expr_before_insn_8616(
        _project(), codegen, 0x1002
    )

    assert isinstance(result, CFunctionCall)


def test_incomplete_inventory_keeps_linear_instruction_rescue(monkeypatch) -> None:
    """Refused frontend evidence must preserve the bounded fallback path."""
    call = _Instruction(0x1000, "call")
    guard = _Instruction(0x1002, "cmp")
    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "collect_function_instruction_inventory_8616",
        lambda project, *, function_entry: _inventory(call, complete=False),
    )
    rescue_calls: list[int] = []

    def linear_rescue(
        project: object,
        codegen: object,
        ins_addr: int,
        *,
        max_bytes: int = 0x800,
    ) -> tuple[object, ...]:
        del project, codegen, max_bytes
        rescue_calls.append(ins_addr)
        return call, guard

    monkeypatch.setattr(
        decompiler_postprocess_jcc,
        "_linear_insns_before_addr_8616",
        linear_rescue,
    )
    codegen = _Codegen()

    result = decompiler_postprocess_jcc._call_return_expr_before_insn_8616(
        _project(), codegen, 0x1002
    )

    assert isinstance(result, CFunctionCall)
    assert rescue_calls == [0x1002]
