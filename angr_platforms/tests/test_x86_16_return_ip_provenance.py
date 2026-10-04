"""Regressions for frontend-owned x86-16 return-address provenance."""

from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import angr
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.control_coordinates import ControlAddressDomain
from angr_platforms.X86_16.stack_helpers import StackEmulator, near_return_ip16
from pyvex.expr import Get


class _ReturnIpEmulator:
    """Minimal emulator boundary that rejects architectural IP reads."""

    def __init__(self, instruction_addr: int) -> None:
        """Bind one exact frontend instruction address."""
        self.lifter_instruction = SimpleNamespace(addr=instruction_addr)
        self.control_address_domain = ControlAddressDomain.ARCHITECTURAL_OFFSET

    def get_sgreg(self, _reg: object) -> int:
        """Supply the unused CS input required by the stack boundary."""
        return 0

    def get_gpreg(self, _reg: object) -> object:
        """Reject unresolved IP carriers in exact return-address recovery."""
        raise AssertionError("return IP must not read the architectural IP carrier")

    def constant(self, value: object, _ty: object) -> object:
        """Return a concrete value for helper-level evidence tests."""
        return value


def _lift_far_call(instruction_addr: int) -> angr.Block:
    """Lift one immediate far call at an explicit architectural address."""
    code = bytes.fromhex("9a78563412")
    project = angr.load_shellcode(
        code,
        arch=Arch86_16(),
        start_offset=instruction_addr,
        load_address=instruction_addr,
        selfmodifying_code=False,
        rebase_granularity=0x1000,
    )
    return project.factory.block(instruction_addr, num_inst=1, insn_bytes=code, opt_level=0)


def test_return_ip_uses_exact_instruction_address_and_wraps_at_ffff() -> None:
    emulator = cast(StackEmulator, _ReturnIpEmulator(0xFFFF))

    assert near_return_ip16(emulator, 5) == 0x0004


def test_far_call_vex_has_no_uninitialized_ip_read() -> None:
    block = _lift_far_call(0x1085)
    ip_offset = block.vex.arch.ip_offset

    ip_reads = [
        expression
        for statement in block.vex.statements
        for expression in statement.expressions
        if isinstance(expression, Get) and expression.offset == ip_offset
    ]

    assert ip_reads == []
