"""Native oracle for a word output defined only on a successful input call."""

import struct
from pathlib import Path
from types import SimpleNamespace

import angr
import networkx as nx
import pytest
from angr import options as o
from angr.codenode import BlockNode
from angr_platforms.X86_16.alias.terminal_pointer_outputs import (
    classify_terminal_pointer_output_aliases_8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir import MemSpace
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.semantics.branch_target_return import (
    BranchTargetReturnEffectKind8616,
    TerminalAxReturnEffectKind8616,
    branch_target_return_effect_8616,
    terminal_ax_return_effect_8616,
)
from angr_platforms.X86_16.semantics.terminal_pointer_output_contracts import (
    TerminalPointerOutputDisposition8616,
)
from angr_platforms.X86_16.semantics.terminal_pointer_outputs import (
    collect_terminal_pointer_output_evidence_8616,
)
from angr_platforms.X86_16.widening.terminal_pointer_output_views import (
    widen_terminal_pointer_output_views_8616,
)
from x86_16_logical_memory_fixtures import FUNCTION_ADDR, lift_ir_artifact_with_blocks

CODE_BASE = 0x100
RETURN_ADDRESS = 0x180
STACK_SEGMENT = 0x200
STACK_POINTER = 0x8000
OUTPUT_OFFSET = 0x300
INITIAL_WORD = 0xA55A
KEY_WORD = 0x1E61
WORD_BYTES = 2
ZERO_FLAG = 0x40
NATIVE_BODY = bytes.fromhex("558becb401cd16741132e4cd1632e48b5e048907b80100eb039033c05dc3")


@pytest.mark.parametrize(
    ("encoding", "fixed_stack_slot"),
    [
        ("8b4604", True), ("8b4204", False), ("8b4304", False),
        ("368b4604", True), ("268b4604", False), ("3e8b4604", False),
    ],
    ids=["bp-displacement", "bp-si-displacement", "bp-di-displacement", "explicit-ss", "es-override", "ds-override"],
)
def test_native_return_load_keeps_dynamic_stack_index(encoding, fixed_stack_slot):
    project = angr.load_shellcode(bytes.fromhex(encoding), arch=Arch86_16(), load_address=CODE_BASE)
    instruction = project.factory.block(CODE_BASE, num_inst=1).capstone.insns[0].insn
    branch_effect = branch_target_return_effect_8616(instruction, lambda _instruction: None)
    terminal_effect = terminal_ax_return_effect_8616(instruction)
    assert (branch_effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_STACK) == fixed_stack_slot
    assert (terminal_effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK) == fixed_stack_slot


@pytest.mark.parametrize(
    ("encoding", "data_global"),
    [("a13412", True), ("3ea13412", True), ("26a13412", False), ("36a13412", False)],
)
def test_native_return_load_keeps_global_segment(encoding, data_global):
    project = angr.load_shellcode(bytes.fromhex(encoding), arch=Arch86_16(), load_address=CODE_BASE)
    instruction = project.factory.block(CODE_BASE, num_inst=1).capstone.insns[0].insn
    branch_effect = branch_target_return_effect_8616(instruction, lambda _instruction: None)
    terminal_effect = terminal_ax_return_effect_8616(instruction)
    assert (branch_effect.kind is BranchTargetReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL) == data_global
    assert (terminal_effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_DIRECT_GLOBAL) == data_global


@pytest.mark.parametrize(
    ("encoding", "supported"),
    [("034604", True), ("26034604", False), ("03063412", True), ("2603063412", False)],
)
def test_native_return_arithmetic_keeps_memory_segment(encoding, supported):
    project = angr.load_shellcode(bytes.fromhex(encoding), arch=Arch86_16(), load_address=CODE_BASE)
    instruction = project.factory.block(CODE_BASE, num_inst=1).capstone.insns[0].insn
    effect = terminal_ax_return_effect_8616(instruction)
    assert (effect.kind is TerminalAxReturnEffectKind8616.REG_ALU_VALUE) == supported


@pytest.mark.parametrize(
    ("encoding", "register"),
    [("33c0", "ax"), ("2bc0", "ax"), ("33d2", "dx"), ("32e4", "ah"), ("2ae4", "ah")],
)
def test_native_terminal_return_recognizes_self_clear(encoding, register):
    project = angr.load_shellcode(bytes.fromhex(encoding), arch=Arch86_16(), load_address=CODE_BASE)
    instruction = project.factory.block(CODE_BASE, num_inst=1).capstone.insns[0].insn
    effect = terminal_ax_return_effect_8616(instruction)
    if register == "ah":
        assert effect.kind is TerminalAxReturnEffectKind8616.CLEAR_AH_TO_ZERO
    else:
        assert effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM
        assert effect.dst_reg == register
        assert effect.imm == 0


@pytest.mark.parametrize("encoding", ["33c2", "1bc0", "6633c0"])
def test_native_terminal_return_does_not_guess_self_clear(encoding):
    project = angr.load_shellcode(bytes.fromhex(encoding), arch=Arch86_16(), load_address=CODE_BASE)
    instruction = project.factory.block(CODE_BASE, num_inst=1).capstone.insns[0].insn
    effect = terminal_ax_return_effect_8616(instruction)
    assert effect.kind not in {
        TerminalAxReturnEffectKind8616.MOV_REG_IMM,
        TerminalAxReturnEffectKind8616.CLEAR_AH_TO_ZERO,
    }


def test_native_oracle_matches_life_input_routine():
    image = (Path(__file__).resolve().parents[2] / "examples/LIFE.EXE").read_bytes()
    header_bytes = struct.unpack_from("<H", image, 8)[0] * 16
    file_offset = header_bytes + 0xAC5
    assert image[file_offset:file_offset + len(NATIVE_BODY)] == NATIVE_BODY


@pytest.mark.parametrize(
    ("body", "width"),
    [(NATIVE_BODY, WORD_BYTES), (NATIVE_BODY[:18] + b"\x88" + NATIVE_BODY[19:], 1)],
    ids=["word-output", "byte-output"],
)
def test_native_conditional_output_preserves_logical_and_execution_width(body, width):
    """Keep decoded operand width distinct from independently executed bytes."""
    entry, branch, read, success, failure, epilogue = (
        FUNCTION_ADDR + offset for offset in (0, 7, 9, 13, 26, 28)
    )
    edges = (
        (entry, branch), (branch, read), (branch, failure),
        (read, success), (success, epilogue), (failure, epilogue),
    )
    artifact = lift_ir_artifact_with_blocks(
        body, (entry, branch, read, success, failure, epilogue), edges,
    )
    project = angr.load_shellcode(body, arch=Arch86_16(), load_address=entry)
    evidence = collect_terminal_pointer_output_evidence_8616(
        project, build_x86_16_function_ssa(artifact),
    )
    assert evidence.complete
    assert evidence.must_write_facts == ()
    assert {(fact.relative_offset, fact.width) for fact in evidence.facts} == {
        (offset, 1) for offset in range(width)
    }
    store_address = entry + 18
    for fact in evidence.facts:
        assert fact.segment is MemSpace.DS
        assert fact.disposition is TerminalPointerOutputDisposition8616.CONDITIONAL
        assert fact.terminal_block_addrs == (epilogue,)
        assert fact.definitely_written_terminal_block_addrs == ()
        assert {site.instr_addr for site in fact.store_sites} == {store_address}
    assert artifact.logical_memory is not None
    output_accesses = [
        access for access in artifact.logical_memory.accesses
        if access.key.insn_addr == store_address
    ]
    assert len(output_accesses) == 1
    output = output_accesses[0]
    assert output.address.size == width
    assert output.address.space is MemSpace.DS
    assert len(output.execution_slices) == width
    nodes = {
        address: BlockNode(address, project.factory.block(address).size)
        for address in (entry, branch, read, success, failure, epilogue)
    }
    graph = nx.DiGraph((nodes[source], nodes[target]) for source, target in edges)
    function = SimpleNamespace(
        addr=entry, project=project, graph=graph, block_addrs_set=set(nodes), info={},
    )
    aliases = classify_terminal_pointer_output_aliases_8616(function, evidence)
    assert aliases.complete, aliases
    parameter_offset = 4
    for fact in aliases.facts:
        assert fact.parameter_storage.space is MemSpace.SS
        assert fact.parameter_storage.base == ("bp",)
        assert fact.parameter_storage.offset == parameter_offset
        assert fact.parameter_storage.size == WORD_BYTES
    views = widen_terminal_pointer_output_views_8616(aliases)
    assert views.complete, views
    assert len(views.facts) == 1
    assert views.facts[0].width == width
    assert views.facts[0].disposition is TerminalPointerOutputDisposition8616.CONDITIONAL


@pytest.mark.parametrize("available", [False, True])
@pytest.mark.parametrize("data_segment", [STACK_SEGMENT, STACK_SEGMENT + 0x100])
def test_native_pointer_output_depends_on_return_and_data_segment(available, data_segment):
    _assert_pointer_output_behavior(NATIVE_BODY, available, data_segment)


@pytest.mark.parametrize(
    ("body", "available"),
    [
        pytest.param(NATIVE_BODY[:18] + b"\x88" + NATIVE_BODY[19:], True, id="lost-high-byte"),
        pytest.param(NATIVE_BODY[:7] + b"\x90\x90" + NATIVE_BODY[9:], False, id="write-without-input"),
    ],
)
def test_native_output_oracle_rejects_corrupted_effects(body, available):
    with pytest.raises(AssertionError, match="pointer output word differs"):
        _assert_pointer_output_behavior(body, available, STACK_SEGMENT)


def _assert_pointer_output_behavior(body, available, data_segment):
    """Execute the real routine with controlled BIOS input and guarded memory."""
    project = angr.load_shellcode(body, arch=Arch86_16(), load_address=CODE_BASE)
    interrupt_services = []

    def check_key(state):
        interrupt_services.append(state.solver.eval(state.regs.ah))
        state.regs.flags = 0 if available else ZERO_FLAG

    def read_key(state):
        interrupt_services.append(state.solver.eval(state.regs.ah))
        state.regs.ax = KEY_WORD

    project.hook(CODE_BASE + 5, check_key, length=WORD_BYTES)
    project.hook(CODE_BASE + 11, read_key, length=WORD_BYTES)
    state = project.factory.blank_state(
        addr=CODE_BASE,
        add_options={o.ZERO_FILL_UNCONSTRAINED_MEMORY, o.ZERO_FILL_UNCONSTRAINED_REGISTERS},
    )
    state.regs.ss, state.regs.ds = STACK_SEGMENT, data_segment
    state.regs.sp, state.regs.bp = STACK_POINTER, 0x7777
    stack_linear = (STACK_SEGMENT << 4) + STACK_POINTER
    state.memory.store(stack_linear, RETURN_ADDRESS, size=WORD_BYTES, endness="Iend_LE")
    state.memory.store(stack_linear + WORD_BYTES, OUTPUT_OFFSET, size=WORD_BYTES, endness="Iend_LE")
    output_linear = (data_segment << 4) + OUTPUT_OFFSET
    stack_output_linear = (STACK_SEGMENT << 4) + OUTPUT_OFFSET
    original_bytes = b"\xC3\x5A\xA5\xD4"
    for address in {output_linear, stack_output_linear}:
        state.memory.store(address - 1, original_bytes)
    manager = project.factory.simgr(state)
    for _ in range(32):
        assert not manager.errored
        assert len(manager.active) == 1
        if manager.active[0].addr == RETURN_ADDRESS:
            break
        manager.step(num_inst=1)
    else:
        pytest.fail("native input routine did not return within its bounded instruction count")
    result = manager.active[0]
    expected = KEY_WORD & 0xFF if available else INITIAL_WORD
    actual = result.solver.eval(result.memory.load(output_linear, WORD_BYTES, endness="Iend_LE"))
    assert actual == expected, "pointer output word differs"
    assert result.solver.eval(result.regs.ax) == int(available)
    expected_bytes = b"\xC3" + expected.to_bytes(WORD_BYTES, "little") + b"\xD4"
    assert result.solver.eval(result.memory.load(output_linear - 1, len(expected_bytes)), cast_to=bytes) == expected_bytes
    if data_segment != STACK_SEGMENT:
        assert result.solver.eval(result.memory.load(stack_output_linear - 1, len(original_bytes)), cast_to=bytes) == original_bytes
    assert interrupt_services == ([1, 0] if available else [1])
