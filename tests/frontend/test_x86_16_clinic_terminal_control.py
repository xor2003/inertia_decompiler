"""Transport proven native terminal JMP targets at the Clinic VEX-to-AIL boundary."""

from __future__ import annotations

import io
from types import SimpleNamespace
from typing import cast

import angr
import inertia.frontend.x86_16.public_api  # noqa: F401  # installs the compatibility wrappers
import pyvex
from angr import ailment
from angr.analyses.decompiler.clinic import Clinic
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.vex_terminal_jump import TerminalJumpRefusalReason8616

from inertia.frontend.x86_16.clinic_terminal_control import (
    CLINIC_TERMINAL_TRANSPORT_ATTR_8616,
    ClinicTerminalControlRefusal8616,
    ClinicTerminalTransport8616,
    record_clinic_terminal_transport_8616,
    transport_terminal_direct_jump_8616,
)
from tests.fixtures.x86_16_logical_memory_fixtures import FUNCTION_ADDR


def _x86_16_project(code: bytes) -> angr.Project:
    """Build one blob project under the native architecture."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": FUNCTION_ADDR,
            "entry_point": FUNCTION_ADDR,
        },
        auto_load_libs=False,
    )


def _clinic_stub(project: angr.Project) -> SimpleNamespace:
    """Expose the Clinic surfaces the conversion wrapper requires."""
    return SimpleNamespace(
        project=project,
        _ail_manager=ailment.Manager(arch=project.arch),
        _convert_vex_fast=lambda _block: None,
    )


def _convert(clinic: SimpleNamespace, block: object) -> ailment.Block:
    """Run the patched Clinic conversion boundary for one block."""
    converted = Clinic._convert_vex(cast(Clinic, clinic), block)
    assert isinstance(converted, ailment.Block)
    return converted


def _terminal(converted: ailment.Block) -> ailment.Stmt.Jump:
    """Return the converted block's terminal Jump statement."""
    assert converted.statements
    statement = converted.statements[-1]
    assert isinstance(statement, ailment.Stmt.Jump)
    return cast(ailment.Stmt.Jump, statement)


def _reports(clinic: SimpleNamespace) -> tuple[ClinicTerminalTransport8616, ...]:
    """Return the transport reports recorded on the clinic boundary."""
    return cast(
        "tuple[ClinicTerminalTransport8616, ...]",
        getattr(clinic, CLINIC_TERMINAL_TRANSPORT_ATTR_8616, ()),
    )


def test_converted_boring_terminal_jump_binds_proven_const() -> None:
    """The proven rel16 destination replaces the symbolic ``next`` operand."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    clinic = _clinic_stub(project)

    converted = _convert(clinic, block)

    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Const)
    assert terminal.target.value == FUNCTION_ADDR + 9
    assert terminal.tags.get("ins_addr") == FUNCTION_ADDR + 1
    # Execution VEX is untouched: ``next`` remains the lifter's RdTmp.
    assert isinstance(block.vex.next, pyvex.expr.RdTmp)
    reports = _reports(clinic)
    assert len(reports) == 1
    report = reports[0]
    assert report.applied
    assert report.proven_target == FUNCTION_ADDR + 9
    assert report.refusal is None
    assert report.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 1,
        "failure_count": 0,
    }
    assert report.stats.closed
    assert report.evidence is not None
    assert report.evidence.decoded is not None
    assert report.evidence.decoded.form.value == "jmp_rel16"


def test_raw_conversion_without_transport_keeps_symbolic_terminal() -> None:
    """The pre-transport converter emits the symbolic ``Goto(tmp)`` shape."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)

    converted = ailment.IRSBConverter.convert(block.vex, manager)

    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Tmp)
    assert terminal.target.tmp_idx == cast(pyvex.expr.RdTmp, block.vex.next).tmp


def test_selector_window_unproved_keeps_symbolic_with_typed_refusal() -> None:
    """A target outside every fetch window is refused, never guessed."""
    project = _x86_16_project(bytes.fromhex("eb80"))
    block = project.factory.block(FUNCTION_ADDR)
    clinic = _clinic_stub(project)

    converted = _convert(clinic, block)

    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Tmp)
    (report,) = _reports(clinic)
    assert not report.applied
    assert report.refusal is None
    assert report.evidence is not None
    assert (
        report.evidence.failure
        is TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
    )
    assert report.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
    assert report.stats.closed


def test_stale_terminal_bytes_keep_symbolic() -> None:
    """Bytes that do not decode to the marked terminal jump are not retained."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    stale = SimpleNamespace(
        addr=block.addr, size=block.size,
        bytes=b"\x90" * cast(int, block.size), vex=block.vex,
    )

    report = transport_terminal_direct_jump_8616(
        stale, converted, next_atom=manager.next_atom,
    )

    assert not report.applied
    assert report.refusal is None
    assert report.evidence is not None
    assert not report.evidence.retain
    assert report.stats.closed
    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Tmp)


def test_conflicting_constant_next_is_a_typed_refusal() -> None:
    """A literal ``next`` disagreeing with the decoded edge is not bound."""
    project = _x86_16_project(bytes.fromhex("eb00"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    fake_vex = SimpleNamespace(
        addr=block.vex.addr,
        jumpkind="Ijk_Boring",
        next=SimpleNamespace(con=SimpleNamespace(value=0x9999)),
        statements=block.vex.statements,
        tyenv=block.vex.tyenv,
    )
    fake_block = SimpleNamespace(
        addr=block.addr, size=block.size, bytes=block.bytes, vex=fake_vex,
    )

    report = transport_terminal_direct_jump_8616(
        fake_block, converted, next_atom=manager.next_atom,
    )

    assert not report.applied
    assert report.evidence is not None
    assert report.evidence.failure is TerminalJumpRefusalReason8616.CONSTANT_CONFLICT
    assert report.stats.to_dict() == {
        "raw_fact_count": 1,
        "normalized_fact_count": 1,
        "classified_fact_count": 1,
        "materialized_count": 0,
        "failure_count": 1,
    }
    assert report.stats.closed
    assert isinstance(_terminal(converted).target, ailment.Expr.Tmp)


def test_ail_terminal_with_different_tmp_is_not_rewritten() -> None:
    """A terminal Jump bound to another operand is never repointed."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    jump = _terminal(converted)
    foreign_tmp = cast(pyvex.expr.RdTmp, block.vex.next).tmp + 1000
    statements = list(converted.statements)
    statements[-1] = ailment.Stmt.Jump(
        jump.idx, ailment.Expr.Tmp(None, foreign_tmp, 32), **dict(jump.tags),
    )
    converted.statements = statements

    report = transport_terminal_direct_jump_8616(
        block, converted, next_atom=manager.next_atom,
    )

    assert not report.applied
    assert report.refusal is ClinicTerminalControlRefusal8616.AIL_TARGET_MISMATCH
    assert report.stats.closed
    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Tmp)
    assert terminal.target.tmp_idx == foreign_tmp


def test_unbound_next_operand_kind_keeps_symbolic() -> None:
    """A proven target still refuses when ``next`` has no AIL identity."""
    project = _x86_16_project(bytes.fromhex("eb00"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    fake_vex = SimpleNamespace(
        addr=block.vex.addr,
        jumpkind="Ijk_Boring",
        next=SimpleNamespace(con=SimpleNamespace(value=FUNCTION_ADDR + 2)),
        statements=block.vex.statements,
        tyenv=block.vex.tyenv,
    )
    fake_block = SimpleNamespace(
        addr=block.addr, size=block.size, bytes=block.bytes, vex=fake_vex,
    )

    report = transport_terminal_direct_jump_8616(
        fake_block, converted, next_atom=manager.next_atom,
    )

    assert not report.applied
    assert report.evidence is not None
    assert report.evidence.proven_target == FUNCTION_ADDR + 2
    assert report.refusal is ClinicTerminalControlRefusal8616.NEXT_OPERAND_UNBOUND
    assert report.stats.closed
    assert isinstance(_terminal(converted).target, ailment.Expr.Tmp)


def test_non_boring_terminal_is_not_examined() -> None:
    """Call and return block tails never enter the terminal-jump transport."""
    project = _x86_16_project(bytes.fromhex("c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)

    report = transport_terminal_direct_jump_8616(
        block, converted, next_atom=manager.next_atom,
    )

    assert not report.applied
    assert report.evidence is None
    assert report.stats.to_dict() == {
        "raw_fact_count": 0,
        "normalized_fact_count": 0,
        "classified_fact_count": 0,
        "materialized_count": 0,
        "failure_count": 0,
    }
    assert report.stats.closed


def test_non_86_16_architecture_is_untouched() -> None:
    """The wrapper leaves non-native arches on the unmodified angr path."""
    code = b"\xe9\x00\x00\x00\x00"
    project = angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": "x86", "base_addr": FUNCTION_ADDR},
        auto_load_libs=False,
    )
    block = project.factory.block(FUNCTION_ADDR)
    clinic = _clinic_stub(project)

    converted = Clinic._convert_vex(cast(Clinic, clinic), block)

    assert _reports(clinic) == ()
    assert isinstance(converted, ailment.Block)


def test_report_ledger_appends_each_block_decision() -> None:
    """Every converted block leaves one closed decision on the clinic."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    clinic = _clinic_stub(project)
    _convert(clinic, block)
    _convert(clinic, project.factory.block(FUNCTION_ADDR + 4))

    reports = _reports(clinic)
    assert len(reports) == 2
    assert all(report.stats.closed for report in reports)


def test_record_helper_appends_to_existing_tuple() -> None:
    """The ledger helper preserves earlier reports verbatim."""
    clinic = SimpleNamespace()
    project = _x86_16_project(bytes.fromhex("eb00"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    first = transport_terminal_direct_jump_8616(
        block, converted, next_atom=manager.next_atom,
    )
    record_clinic_terminal_transport_8616(clinic, first)
    record_clinic_terminal_transport_8616(clinic, first)

    assert _reports(clinic) == (first, first)


def test_same_tmp_with_wrong_width_keeps_symbolic() -> None:
    """Temporary index equality never permits truncating loaded control."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    jump = _terminal(converted)
    rows = list(converted.statements)
    rows[-1] = ailment.Stmt.Jump(
        jump.idx, ailment.Expr.Tmp(None, jump.target.tmp_idx, 16), **dict(jump.tags),
    )
    converted.statements = rows
    report = transport_terminal_direct_jump_8616(block, converted, next_atom=manager.next_atom)
    assert not report.applied
    assert report.refusal is ClinicTerminalControlRefusal8616.AIL_TARGET_MISMATCH
    assert report.stats.closed
    assert _terminal(converted).target.bits == 16


def test_foreign_converted_block_keeps_symbolic() -> None:
    """Reused temporary indices from another block carry no binding proof."""
    project = _x86_16_project(bytes.fromhex("90e90500c3"))
    block = project.factory.block(FUNCTION_ADDR)
    manager = ailment.Manager(arch=project.arch)
    converted = ailment.IRSBConverter.convert(block.vex, manager)
    foreign = ailment.Block(FUNCTION_ADDR + 16, block.size, list(converted.statements))
    report = transport_terminal_direct_jump_8616(block, foreign, next_atom=manager.next_atom)
    assert not report.applied
    assert report.refusal is ClinicTerminalControlRefusal8616.AIL_SOURCE_MISMATCH
    assert report.stats.closed
    assert isinstance(_terminal(foreign).target, ailment.Expr.Tmp)
