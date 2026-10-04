"""Regress exact BP live-ins without treating a CALL as preservation."""

from dataclasses import replace

import pytest
from angr_platforms.X86_16.ir import IRBlock, IRCallStackEffect8616, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.scalar_affine_contracts import ScalarAffineTrace8616
from angr_platforms.X86_16.ir.scalar_affine_trace import trace_scalar_affine_expression_8616
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa


def _reg(name: str, size: int = 2) -> IRValue:
    return IRValue(MemSpace.REG, name=name, size=size)


def _mov(name: str, source: IRValue, addr: int) -> IRInstr:
    return IRInstr("MOV", _reg(name), (source,), size=2, addr=addr)


def _call(addr: int, preserved: bool = True, complete: bool = True) -> IRInstr:
    return IRInstr("CALL", None, (), addr=addr, call_stack_effect=IRCallStackEffect8616(
        complete=complete, net_stack_delta=0, bp_preserved=preserved,
    ))


def _blocks(
    *, call: IRInstr | None = None, conflicting: bool = False,
    loop: bool = False, same_block: bool = False,
) -> tuple[tuple[IRBlock, ...], int]:
    setup = (_mov("bp", _reg("sp", size=2), 0x1000),)
    use = IRInstr("Iop_Add16", _reg("ax"), (
        _reg("bp"), IRValue(MemSpace.CONST, const=0xFFEC, size=2),
    ), size=2, addr=0x1020)
    middle = () if call is None else (call,)
    if same_block:
        return (IRBlock(0x1000, (*setup, *middle, use)),), 0x1000
    entry = IRBlock(0x1000, setup, successor_addrs=(0x1010, 0x1018) if conflicting else (0x1010,))
    left = IRBlock(0x1010, middle, successor_addrs=(0x1020,))
    right = (IRBlock(0x1018, (_mov("bp", _reg("ax"), 0x1018),), successor_addrs=(0x1020,)),) if conflicting else ()
    tail = IRBlock(0x1020, (use,), successor_addrs=(0x1010,) if loop else ())
    return (entry, left, *right, tail), 0x1020


def _trace(blocks: tuple[IRBlock, ...], block_addr: int, enabled: bool = True) -> ScalarAffineTrace8616:
    artifact = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, blocks))
    block = next(item for item in artifact.blocks if item.addr == block_addr)
    root = block.instrs[-1].dst
    assert root is not None
    return trace_scalar_affine_expression_8616(
        artifact, root, block_addr=block_addr, before_index=len(block.instrs),
        allow_entry_registers=enabled,
    )


@pytest.mark.parametrize("call", [None, _call(0x1010)])
def test_bp_livein_follows_the_same_exact_entry_definition(call: IRInstr | None) -> None:
    """Unique reaching frame values survive only explicit preserving calls."""
    blocks, addr = _blocks(call=call)
    trace = _trace(blocks, addr)
    assert trace.complete
    assert trace.expression is not None
    assert trace.expression.constant == 0xFFEC
    assert [(term.source.register_name, term.coefficient) for term in trace.expression.terms] == [("sp", 1)]
    if call is not None:
        assert any(site.op == "CALL" and site.instr_addr == call.addr for site in trace.expression.definition_path)


@pytest.mark.parametrize("call", [_call(0x1010, preserved=False), _call(0x1010, complete=False), IRInstr("CALL", None, (), addr=0x1010)])
@pytest.mark.parametrize("same_block", [False, True])
def test_unknown_calls_refuse_even_when_ssa_has_no_bp_destination(call: IRInstr, same_block: bool) -> None:
    """Absence of a CALL destination never constitutes preservation."""
    blocks, addr = _blocks(call=call, same_block=same_block)
    trace = _trace(blocks, addr)
    assert not trace.complete
    assert trace.expression is None
    assert trace.stats.materialized_count == 0 and trace.stats.failure_count == 1


def test_conflicting_reaching_definitions_refuse() -> None:
    """A second reaching BP write prevents choosing an arbitrary predecessor."""
    blocks, addr = _blocks(conflicting=True)
    assert not _trace(blocks, addr).complete


def test_preserving_loop_does_not_erase_the_unique_entry_definition() -> None:
    """Unwritten loop back-edges carry the exact proven definition."""
    blocks, addr = _blocks(call=_call(0x1010), loop=True)
    assert _trace(blocks, addr).complete


def test_cross_block_frame_extension_remains_opt_in() -> None:
    """Default scalar tracing does not admit new function-entry roots."""
    blocks, addr = _blocks(call=_call(0x1010))
    assert not _trace(blocks, addr, enabled=False).complete


def test_full_parent_bp_write_cannot_borrow_word_origin() -> None:
    """An EBP write kills a prior word-sized BP value."""
    blocks, addr = _blocks()
    wide = IRInstr("MOV", _reg("ebp", size=4), (IRValue(MemSpace.CONST, const=0, size=4),), size=4, addr=0x1010)
    blocks = (blocks[0], replace(blocks[1], instrs=(wide,)), blocks[2])
    assert not _trace(blocks, addr).complete


def test_unknown_incoming_block_does_not_disappear_from_proof() -> None:
    """A missing predecessor is a refusal, never an absent obligation."""
    blocks, addr = _blocks()
    artifact = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, blocks))
    artifact = replace(artifact, predecessor_map={**artifact.predecessor_map, addr: (0x1010, 0xDEAD)})
    root = artifact.blocks[-1].instrs[-1].dst
    assert root is not None
    assert not trace_scalar_affine_expression_8616(
        artifact, root, block_addr=addr, before_index=1, allow_entry_registers=True,
    ).complete


def test_local_preservation_call_survives_in_definition_provenance() -> None:
    """A same-block proof retains the CALL fact that authorized transport."""
    blocks, addr = _blocks(call=_call(0x1001), same_block=True)
    trace = _trace(blocks, addr)
    assert trace.complete and trace.expression is not None
    assert any(site.op == "CALL" for site in trace.expression.definition_path)


def test_unknown_call_before_frame_setup_cannot_invent_entry_sp() -> None:
    """An unproved CALL invalidates the entry-SP leaf used by later setup."""
    blocks, addr = _blocks(same_block=True)
    block = replace(blocks[0], instrs=(_call(0x1000, complete=False), *blocks[0].instrs))
    assert not _trace((block,), addr).complete


def test_full_parent_sp_write_invalidates_the_entry_leaf() -> None:
    """An ESP write cannot leave a stale word-SP entry origin readable."""
    blocks, addr = _blocks(same_block=True)
    clobber = IRInstr("MOV", _reg("esp", size=4), (IRValue(MemSpace.CONST, const=0x1234, size=4),), size=4, addr=0x1000)
    block = replace(blocks[0], instrs=(clobber, *blocks[0].instrs))
    assert not _trace((block,), addr).complete


def test_frame_producer_width_disagreement_refuses() -> None:
    """A word SP value cannot borrow a differently sized MOV producer."""
    blocks, addr = _blocks(same_block=True)
    bad_width = IRInstr("MOV", _reg("sp"), (_reg("sp"),), size=4, addr=0x1000)
    block = replace(blocks[0], instrs=(bad_width, *blocks[0].instrs))
    assert not _trace((block,), addr).complete


def test_entry_bp_proof_retains_its_preserving_call() -> None:
    """Entry-register source records retain consumed CALL preservation sites."""
    from angr_platforms.X86_16.ir.frame_register_reaching_definition import resolve_bp_reaching_definition_8616

    artifact = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, (
        IRBlock(0x1000, (_call(0x1000),)),
    )))
    root = replace(_reg("bp"), version=0)
    proof = resolve_bp_reaching_definition_8616(artifact, root, block_addr=0x1000, before_index=1)
    assert proof.complete and proof.entry_register is not None
    assert proof.entry_register.function_addr == artifact.function_addr
    assert tuple(site.instr_addr for site in proof.preservation_sites) == (0x1000,)


def test_missing_frame_origin_cannot_close_positive_counters() -> None:
    """Counters alone are insufficient when the typed source is removed."""
    from angr_platforms.X86_16.ir.frame_register_reaching_definition import resolve_bp_reaching_definition_8616

    blocks, addr = _blocks()
    artifact = build_x86_16_function_ssa(IRFunctionArtifact(0x1000, blocks))
    root = replace(_reg("bp"), version=0)
    proof = resolve_bp_reaching_definition_8616(artifact, root, block_addr=addr, before_index=0)
    assert proof.complete and proof.definition is not None
    assert not replace(proof, definition=None).complete


@pytest.mark.parametrize("register", ["sp", "bp"])
def test_scalar_entry_leaf_retains_preserving_call(register: str) -> None:
    """The scalar projection must retain each CALL fact consumed by its leaf."""
    block = IRBlock(0x1000, (_call(0x1000), _mov("ax", _reg(register), 0x1001)))
    trace = _trace((block,), block.addr)
    assert trace.complete and trace.expression is not None
    assert tuple(site.instr_addr for site in trace.expression.definition_path if site.op == "CALL") == (0x1000,)


def test_missing_entry_predecessor_census_refuses() -> None:
    """An absent census entry is not evidence that function entry has no edges."""
    block = IRBlock(0x1000, (_mov("ax", _reg("bp"), 0x1000),))
    artifact = replace(build_x86_16_function_ssa(IRFunctionArtifact(0x1000, (block,))), predecessor_map={})
    root = artifact.blocks[0].instrs[0].dst
    assert root is not None
    assert not trace_scalar_affine_expression_8616(
        artifact, root, block_addr=block.addr, before_index=1, allow_entry_registers=True,
    ).complete


def test_entry_sp_call_without_exact_instruction_site_refuses() -> None:
    """A preservation flag alone cannot supply exact CALL provenance."""
    block = IRBlock(0x1000, (replace(_call(0x1000), addr=None), _mov("ax", _reg("sp"), 0x1001)))
    assert not _trace((block,), block.addr).complete
