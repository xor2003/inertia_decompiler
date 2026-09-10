"""Frontend/Semantics regressions for x86 ALU effect ordering.

The flag equations consume the instruction's pre-write operands.  These tests
keep that contract visible both at the shared helper boundary and in lifted VEX,
where a destination ``Put`` before the flags ``Put`` changes what later flag
expressions read.
"""

from __future__ import annotations

import io
from collections.abc import Callable

import angr
import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.semantics.alu_semantics import (
    binary_operation,
    binary_operation_with_carry,
    rotate_left_operation,
    shift_left_operation,
    unary_operation,
)
from pyvex.stmt import Put


class _IntegerEmulator:
    def __init__(self, carry: bool = False) -> None:
        self.carry = carry

    def constant(self, value: int, _value_type: object) -> int:
        return value

    def is_carry(self) -> bool:
        return self.carry


def _record(events: list[str], event: str) -> Callable[..., None]:
    def record(*_values: object) -> None:
        events.append(event)

    return record


def _project_from_bytes(code: bytes) -> angr.Project:
    return angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )


def test_binary_alu_helper_emits_flags_before_destination_write() -> None:
    events: list[str] = []

    binary_operation(
        _IntegerEmulator(),
        lambda: 7,
        lambda: 3,
        _record(events, "result"),
        _record(events, "flags"),
        lambda lhs, rhs: lhs - rhs,
    )

    assert events == ["flags", "result"]


def test_carry_alu_helper_emits_flags_before_destination_write() -> None:
    events: list[str] = []

    binary_operation_with_carry(
        _IntegerEmulator(carry=True),
        lambda: 7,
        lambda: 3,
        _record(events, "result"),
        _record(events, "flags"),
        lambda lhs, rhs, carry: lhs - rhs - carry,
        width_bits=16,
    )

    assert events == ["flags", "result"]


@pytest.mark.parametrize(
    "operation",
    (
        lambda events: unary_operation(
            lambda: 7,
            _record(events, "result"),
            _record(events, "flags"),
            lambda value: value + 1,
        ),
        lambda events: shift_left_operation(
            _IntegerEmulator(),
            lambda: 7,
            _record(events, "result"),
            _record(events, "flags"),
            1,
            16,
        ),
        lambda events: rotate_left_operation(
            _IntegerEmulator(),
            lambda: 7,
            _record(events, "result"),
            _record(events, "flags"),
            1,
            16,
        ),
    ),
)
def test_other_alu_helpers_emit_flags_before_destination_write(
    operation: Callable[[list[str]], None],
) -> None:
    events: list[str] = []

    operation(events)

    assert events == ["flags", "result"]


@pytest.mark.parametrize(
    "code,destination_name",
    (
        (bytes.fromhex("2b060420"), "ax"),  # sub ax, [0x2004]
        (bytes.fromhex("1b160620"), "dx"),  # sbb dx, [0x2006]
        (bytes.fromhex("03060420"), "ax"),  # add ax, [0x2004]
        (bytes.fromhex("13160620"), "dx"),  # adc dx, [0x2006]
        (bytes.fromhex("83c404"), "sp"),  # add sp, 4
        (bytes.fromhex("83ec04"), "sp"),  # sub sp, 4
        (bytes.fromhex("40"), "ax"),  # inc ax
        (bytes.fromhex("d1e0"), "ax"),  # shl ax, 1
    ),
)
def test_lifted_flags_use_prewrite_destination(
    code: bytes,
    destination_name: str,
) -> None:
    project = _project_from_bytes(code)
    irsb = project.factory.block(0x1000, num_inst=1, opt_level=0).vex
    flags_offset = project.arch.get_register_offset("flags")
    destination_offset = project.arch.get_register_offset(destination_name)
    flag_puts = [index for index, statement in enumerate(irsb.statements) if isinstance(statement, Put) and statement.offset == flags_offset]
    destination_puts = [
        index
        for index, statement in enumerate(irsb.statements)
        if isinstance(statement, Put) and statement.offset == destination_offset
    ]

    assert flag_puts
    assert destination_puts
    assert max(flag_puts) < min(destination_puts)


def test_full_decompiler_preserves_one_low_subtraction_and_one_high_borrow() -> None:
    code = bytes.fromhex("a100208b1602202b0604201b160620c3")
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)

    decompiler = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert decompiler.codegen is not None
    generated = decompiler.codegen.text
    carry_pipeline = decompiler.codegen._inertia_carry_borrow_widening_pipeline_8616
    carry_lowering = decompiler.codegen._inertia_carry_borrow_bit_lowering_artifact_8616
    postprocess = cfg.functions[0x1000].info["x86_16_decompiler_postprocess"]
    assert carry_pipeline.complete
    assert carry_pipeline.semantics.stats.materialized_count == 1
    assert carry_pipeline.widening.stats.materialized_count == 1
    assert carry_lowering.complete
    assert carry_lowering.stats.materialized_count == 1
    assert carry_lowering.stats.failure_count == 0
    assert "failed" not in postprocess["tail_validation_verdict"]
    assert generated.count("g_2000 - g_2004") == 1
    assert " & 1" not in generated


@pytest.mark.parametrize("code", ["2b060420c3", "1b160620c3", "13160620c3"])
def test_native_clinic_keeps_flag_value_ites_out_of_straight_line_cfg(code: str) -> None:
    """Direct decompilation must not split inside an ALU instruction for FLAGS."""
    project = _project_from_bytes(bytes.fromhex(code))
    cfg = project.analyses.CFGFast(normalize=True)
    function = cfg.functions[0x1000]
    assert len(function.graph) == 1

    decompiler = project.analyses.Decompiler(function, cfg=cfg)

    assert decompiler.codegen is not None
    assert decompiler.clinic is not None
    assert decompiler.clinic.graph is not None
    assert {block.addr for block in decompiler.clinic.graph.nodes()} == {function.addr}


def test_full_decompiler_preserves_one_low_addition_and_one_high_carry() -> None:
    code = bytes.fromhex("a100208b1602200306042013160620c3")
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(normalize=True)

    decompiler = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)

    assert decompiler.codegen is not None
    generated = decompiler.codegen.text
    carry_pipeline = decompiler.codegen._inertia_carry_borrow_widening_pipeline_8616
    carry_lowering = decompiler.codegen._inertia_carry_borrow_bit_lowering_artifact_8616
    postprocess = cfg.functions[0x1000].info["x86_16_decompiler_postprocess"]
    assert carry_pipeline.complete
    assert carry_pipeline.semantics.stats.materialized_count == 1
    assert carry_pipeline.widening.stats.materialized_count == 1
    assert carry_lowering.complete
    assert carry_lowering.stats.materialized_count == 1
    assert carry_lowering.stats.failure_count == 0
    assert "failed" not in postprocess["tail_validation_verdict"]
    assert generated.count("g_2000 + g_2004") == 1
    assert " & 1" not in generated
