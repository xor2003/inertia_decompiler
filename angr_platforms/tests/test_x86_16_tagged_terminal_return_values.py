"""Regression coverage for path-specific terminal return values."""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CReturn,
    CStatements,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.semantics.branch_target_return import (
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
)
from angr_platforms.X86_16.structuring.return_chains import (
    BranchTargetReturnScanCallbacks8616,
    TerminalAxInstructionAction8616,
    TerminalAxScanCallbacks8616,
    linear_terminal_ax_return_scan_8616,
    scan_branch_target_return_block_8616,
)
from angr_platforms.X86_16.structuring.tagged_terminal_return_values import (
    materialize_tagged_terminal_return_values_8616,
)
from capstone import CS_ARCH_X86, CS_MODE_16, Cs
from capstone.x86_const import X86_OP_IMM

_INITIAL_AX_VALUE = 9
_EXPECTED_BRANCH_COUNT = 2


@dataclass(frozen=True, slots=True)
class _Operand:
    """Minimal decoded operand used by terminal-return tests."""

    type: int
    reg: int = 0
    imm: int = 0


class _Insn:
    """Minimal decoded instruction used by terminal-return tests."""

    def __init__(
        self,
        mnemonic: str,
        operands: tuple[_Operand, ...] = (),
        *,
        address: int = 0,
    ) -> None:
        self.mnemonic = mnemonic
        self.operands = operands
        self.address = address

    @staticmethod
    def reg_name(register: int) -> str:
        """Return the single register name needed by this fixture."""
        return {1: "ax"}.get(register, "")


def _block(*instructions: _Insn) -> SimpleNamespace:
    """Build one minimal decoded block."""
    return SimpleNamespace(capstone=SimpleNamespace(insns=instructions))


def _target(instruction: _Insn) -> int | None:
    """Return one direct branch target from the fixture instruction."""
    if len(instruction.operands) != 1 or instruction.operands[0].type != X86_OP_IMM:
        return None
    return instruction.operands[0].imm


def test_linear_terminal_scan_refuses_multiple_value_predecessors() -> None:
    """A linear proof must not select the first of several return paths."""
    blocks = {
        0x1000: _block(
            _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=1))),
            _Insn("jmp", (_Operand(2, imm=0x1100),)),
        ),
        0x1010: _block(
            _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=0))),
            _Insn("jmp", (_Operand(2, imm=0x1100),)),
        ),
        0x1100: _block(_Insn("ret")),
    }
    terminal_value: list[int | None] = [None]

    def process(
        _instruction: object,
        effect: TerminalAxReturnEffect8616,
    ) -> TerminalAxInstructionAction8616:
        """Track the fixture's exact AX immediate effect."""
        if effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_IMM:
            terminal_value[0] = effect.imm
            return TerminalAxInstructionAction8616(classified=True)
        return TerminalAxInstructionAction8616(abort=True)

    result = linear_terminal_ax_return_scan_8616(
        blocks,
        blocks.get,
        _target,
        TerminalAxScanCallbacks8616(
            combined_return_expr=lambda: terminal_value[0],
            process_instruction=process,
        ),
    )

    assert result.expr is None
    assert result.terminal_value_block_count == _EXPECTED_BRANCH_COUNT


def test_tagged_terminal_return_uses_its_own_cfg_predecessor() -> None:
    """Replace a stale AX self-subtract with the tagged path's proven zero."""
    codegen = SimpleNamespace(
        next_idx=lambda _kind: 0,
        next_node_idx=lambda: 0,
        next_ident=lambda name: name,
        cstyle_null_cmp=False,
        project=SimpleNamespace(arch=Arch86_16()),
    )
    short_type = SimTypeShort(False)
    tags = {"ins_addr": 0x1000, "vex_block_addr": 0x1000}
    ax = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=short_type,
        codegen=codegen,
        tags=tags,
    )
    stale = CBinaryOp(
        "Add",
        ax,
        CUnaryOp("Neg", ax, codegen=codegen),
        codegen=codegen,
        tags=tags,
    )
    terminal_return = CReturn(stale, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=CStatements([terminal_return], codegen=codegen)
    )
    blocks = {
        0x1000: _block(
            _Insn(
                "sub",
                (_Operand(1, reg=1), _Operand(1, reg=1)),
                address=0x1000,
            ),
            _Insn("jmp", (_Operand(2, imm=0x1100),), address=0x1002),
        ),
        0x1100: _block(_Insn("ret", address=0x1100)),
    }
    project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda addr, *, opt_level=0: blocks[addr])
    )
    function = SimpleNamespace(block_addrs_set=frozenset(blocks))

    result = materialize_tagged_terminal_return_values_8616(
        project,
        codegen,
        function,
        expressions_equivalent=lambda lhs, rhs: (
            isinstance(lhs, CConstant)
            and isinstance(rhs, CConstant)
            and lhs.value == rhs.value
        ),
    )

    assert result.changed
    assert (
        result.raw_fact_count,
        result.normalized_fact_count,
        result.classified_fact_count,
        result.materialized_count,
        result.failure_count,
        result.replacement_count,
    ) == (1, 1, 1, 1, 0, 1)
    assert isinstance(terminal_return.retval, CConstant)
    assert terminal_return.retval.value == 0


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [
        ("2b4606", None),  # sub ax, [bp+6]
        ("29d8", None),  # sub ax, bx
        ("f7e3", None),  # mul bx: implicit DX:AX writes
        ("58", None),  # pop ax
        ("6658", None),  # pop eax
        ("5a", None),  # pop dx
        ("b401", None),  # mov ah, 1
        ("b201", None),  # mov dl, 1
        ("0f0b", None),  # ud2: no modeled return-preservation proof
        ("b80500", None),  # classified load whose materializer refuses
        ("83c001", None),  # classified ALU operation whose materializer refuses
        ("40", None),  # classified increment whose materializer refuses
        ("90", 9),  # nop
        ("5f", 9),  # pop di
        ("89ec", 9),  # mov sp, bp
        ("c9", 9),  # leave
    ],
)
def test_branch_return_scan_never_keeps_value_across_unconsumed_effect(encoding, expected):
    """Unknown or unmaterialized effects cannot certify the previous AX value."""
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    instructions = tuple(decoder.disasm(bytes.fromhex("b80900" + encoding + "c3"), 0x1000))
    result = scan_branch_target_return_block_8616(
        _block(*instructions),
        BranchTargetReturnScanCallbacks8616(
            branch_target_imm=_target,
            combine_return_expr=lambda ax, _dx: ax,
            materialize_reg_imm=lambda value: value if value == _INITIAL_AX_VALUE else None,
            materialize_stack_load=lambda _offset, _size: None,
            materialize_direct_global_load=lambda _offset, _size: None,
            materialize_ax_alu_imm=lambda *_args: None,
            materialize_ax_incdec=lambda *_args: None,
        ),
    )
    assert result.expr == expected
    assert result.next_target is None


def test_tagged_return_keeps_complete_expression_when_leaf_effect_is_unknown():
    """A tagged native expression cannot be replaced by a partially scanned leaf."""
    codegen = SimpleNamespace(
        next_node_idx=lambda: 0, next_ident=lambda name: name,
        cstyle_null_cmp=False,
        project=SimpleNamespace(arch=Arch86_16()),
    )
    tags = {"ins_addr": 0x1003, "vex_block_addr": 0x1000}
    original = CBinaryOp(
        "Sub", CConstant(9, SimTypeShort(False), codegen=codegen),
        CConstant(4, SimTypeShort(False), codegen=codegen), codegen=codegen, tags=tags,
    )
    terminal_return = CReturn(original, codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([terminal_return], codegen=codegen))
    blocks = {
        0x1000: _block(
            _Insn("mov", (_Operand(1, reg=1), _Operand(2, imm=9)), address=0x1000),
            _Insn("sub", (_Operand(1, reg=1), _Operand(1, reg=2)), address=0x1003),
            _Insn("jmp", (_Operand(2, imm=0x1100),), address=0x1005),
        ),
        0x1100: _block(_Insn("ret", address=0x1100)),
    }
    project = SimpleNamespace(arch=Arch86_16(), factory=SimpleNamespace(block=lambda addr, *, opt_level=0: blocks[addr]))

    result = materialize_tagged_terminal_return_values_8616(
        project, codegen, SimpleNamespace(block_addrs_set=frozenset(blocks)),
        expressions_equivalent=lambda _left, _right: False,
    )

    assert not result.changed
    assert result.failure_count == 1
    assert result.classified_fact_count == 0
    assert terminal_return.retval is original


@pytest.mark.parametrize(
    ("tail", "expected"),
    [
        ("90c3", 9),  # preserving nop/return
        ("5fc3", 9),  # preserving pop di/return
        ("e9fd00", 9),  # second jump to a preserving return
        ("58c3", None),  # pop ax
        ("6658c3", None),  # pop eax
        ("5ac3", None),  # pop dx
        ("b80500c3", None),  # overwritten return value
        ("e9fdff", None),  # jump to self
        ("90", None),  # incomplete tail
        (None, None),  # missing destination
    ],
)
def test_branch_return_value_requires_complete_preserving_jump_path(tail, expected):
    """A computed value is not a return proof until its entire tail is checked."""
    from angr_platforms.X86_16.structuring.branch_return_expressions import (
        recover_branch_target_return_expression_8616,
    )

    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    encodings = {0x1000: "b80900e9fa00", 0x1200: "c3"}
    if tail is not None:
        encodings[0x1100] = tail
    blocks = {address: _block(*decoder.disasm(bytes.fromhex(code), address)) for address, code in encodings.items()}
    project = SimpleNamespace(arch=Arch86_16(), factory=SimpleNamespace(block=lambda addr, *, opt_level=0: blocks[addr]))
    codegen = SimpleNamespace(next_node_idx=lambda: 0, next_ident=lambda name: name, project=project)

    result = recover_branch_target_return_expression_8616(project, codegen, 0x1000)

    if expected is None:
        assert result is None
    else:
        assert isinstance(result, CConstant)
        assert result.value == expected


@pytest.mark.parametrize("encoding", ["b80900", "b80900ffe0"])
def test_branch_scan_refuses_unterminated_or_unresolved_jump_value(encoding):
    """Computing AX alone proves neither a return nor an indirect destination."""
    decoder = Cs(CS_ARCH_X86, CS_MODE_16)
    decoder.detail = True
    result = scan_branch_target_return_block_8616(
        _block(*decoder.disasm(bytes.fromhex(encoding), 0x1000)),
        BranchTargetReturnScanCallbacks8616(
            branch_target_imm=_target,
            combine_return_expr=lambda ax, _dx: ax,
            materialize_reg_imm=lambda value: value,
            materialize_stack_load=lambda *_args: None,
            materialize_direct_global_load=lambda *_args: None,
            materialize_ax_alu_imm=lambda *_args: None,
            materialize_ax_incdec=lambda *_args: None,
        ),
    )
    assert result.expr is None
    assert result.next_target is None
