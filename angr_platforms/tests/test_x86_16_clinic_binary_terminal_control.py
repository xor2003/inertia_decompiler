"""Check native terminal control transport on the actual CMP16 MZ image.

Layer: Tests/default binary lane.
Responsibility: preserve the actual-image transport regression independently
of the always-available synthetic routine ownership controls.
"""
from pathlib import Path

import pytest
from angr import ailment
from test_x86_16_clinic_terminal_control import _clinic_stub, _convert, _reports, _terminal

CMP16_EXE = Path(__file__).resolve().parents[2] / "examples/build_msc6_tiny/CMP16.EXE"
CMP16_JUMP_BLOCK_ADDR = 0x101C3
CMP16_JUMP_TARGET = 0x101CC

@pytest.mark.skipif(not CMP16_EXE.is_file(), reason="CMP16.EXE example binary is not available")
def test_cmp16_real_block_terminal_binds_proven_target() -> None:
    """The real CMP16 block 0x101c3 binds its proven destination 0x101cc."""
    from inertia_decompiler.project_loading import _build_project

    project = _build_project(
        CMP16_EXE, force_blob=False, base_addr=0x1000, entry_point=0,
    )
    block = project.factory.block(CMP16_JUMP_BLOCK_ADDR)
    assert block.bytes == bytes.fromhex("e90600")
    clinic = _clinic_stub(project)

    converted = _convert(clinic, block)

    terminal = _terminal(converted)
    assert isinstance(terminal.target, ailment.Expr.Const)
    assert terminal.target.value == CMP16_JUMP_TARGET
    (report,) = _reports(clinic)
    assert report.applied
    assert report.proven_target == CMP16_JUMP_TARGET
    assert report.stats.closed


