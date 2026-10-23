"""Discovery retains indirect native targets without granting control authority."""

import pytest

from inertia.cli.project_loading import _build_project_from_bytes
from inertia.ir.core import IRValue
from inertia.ir.vex_import import IRImportRefusalReason8616, _block_to_ir

pytestmark = pytest.mark.decompiler


def test_conditional_boundary_keeps_indirect_refusal_in_raw_ir() -> None:
    """Decoding an assumed destination cannot turn its raw transfer into proof."""
    from inertia.frontend.x86_16.frontend_function_boundary import mapped_entry_function_boundary_8616
    from inertia.frontend.x86_16.frontend_instruction_reachability import ConditionalIndirectEdge8616
    from inertia.ir.vex_import import raw_x86_16_function_bundle_8616

    project = _build_project_from_bytes(bytes.fromhex("ffe3c3"), base_addr=0x1000, entry_point=0x1000)
    assert mapped_entry_function_boundary_8616(project, 0x1000) is None
    edge = ConditionalIndirectEdge8616(0x1000, 0x1000, 0x1002)
    boundary = mapped_entry_function_boundary_8616(project, 0x1000, conditional_edges=(edge,))
    assert boundary is not None
    assert boundary.conditional_edges == (edge,)
    raw = raw_x86_16_function_bundle_8616(project, boundary).artifact
    block = next(item for item in raw.blocks if item.addr == 0x1000)
    assert block.instrs[-1].op == "JMP"
    assert block.instrs[-1].args[0].const is None
    assert any(item.kind is IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING for item in block.refusals)


def test_cs_table_terminal_retained_only_as_pending_discovery() -> None:
    """A real CS table JMP keeps its expression but gains no successor proof."""
    project = _build_project_from_bytes(
        bytes.fromhex("d1e32effa73903"), base_addr=0x1D37, entry_point=0x1D37,
    )
    native = project.factory.block(0x1D37, opt_level=0)
    block, _, _ = _block_to_ir(native, indirect_terminal_pending=True)
    assert block.instrs[-1].op == "JMP"
    assert block.instrs[-1].addr == 0x1D39
    assert block.instrs[-1].args
    target = block.instrs[-1].args[0]
    assert isinstance(target, IRValue) and target.const is None
    assert block.instrs[-1].origin is not None
    assert block.successor_addrs == ()
    assert any(item.kind is IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING for item in block.refusals)
    assert not any(item.kind == "near_return_continuation_pending" for item in block.refusals)


@pytest.mark.parametrize("code", ["ffd3", "c3", "90"])
def test_pending_discovery_never_mints_successful_boundary(code: str) -> None:
    """Wrong terminal shapes cannot turn discovery into control authority."""
    project = _build_project_from_bytes(bytes.fromhex(code), base_addr=0x1000, entry_point=0x1000)
    block, _, _ = _block_to_ir(project.factory.block(0x1000, opt_level=0), indirect_terminal_pending=True)
    assert any(item.kind is IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING for item in block.refusals)
