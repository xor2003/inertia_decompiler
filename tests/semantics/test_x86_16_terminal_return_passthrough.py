from __future__ import annotations

from types import SimpleNamespace

from inertia.semantics.terminal_call_paths import (
    TerminalCallPathStatus8616,
)
from inertia.semantics.terminal_return_passthrough import (
    TerminalReturnPassThroughFailureKind8616,
    collect_terminal_return_passthrough_evidence_8616,
)


class _Operand:
    def __init__(self, type_: int, *, reg: int = 0, imm: int = 0) -> None:
        self.type = type_
        self.reg = reg
        self.imm = imm


class _Insn:
    def __init__(
        self,
        address: int,
        mnemonic: str,
        operands: tuple[_Operand, ...] = (),
    ) -> None:
        self.address = address
        self.mnemonic = mnemonic
        self.operands = operands

    def reg_name(self, register_id: int) -> str:
        return {1: "ax", 2: "bp"}.get(register_id, "")


class _Factory:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks

    def block(self, address: int, *, size: int) -> object:
        del size
        return self.blocks[address]


class _Graph:
    def __init__(self, successors: dict[int, tuple[int, ...]], sizes: dict[int, int]) -> None:
        self.nodes = tuple(SimpleNamespace(addr=address, size=size) for address, size in sizes.items())
        self.nodes_by_addr = {node.addr: node for node in self.nodes}
        self.successors_by_addr = successors

    def successors(self, node: SimpleNamespace) -> tuple[SimpleNamespace, ...]:
        return tuple(self.nodes_by_addr[address] for address in self.successors_by_addr.get(node.addr, ()))


def _function_and_project(
    blocks: dict[int, tuple[_Insn, ...]],
    successors: dict[int, tuple[int, ...]],
) -> tuple[SimpleNamespace, SimpleNamespace]:
    sizes = {
        address: max(1, max(insn.address for insn in instructions) - address + 1)
        for address, instructions in blocks.items()
    }
    graph = _Graph(successors, sizes)
    function = SimpleNamespace(addr=0x1000, graph=graph)
    project = SimpleNamespace(
        factory=_Factory(
            {
                address: SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
                for address, instructions in blocks.items()
            }
        )
    )
    return project, function


def test_recursive_terminal_call_passthrough_retains_exact_target_path_and_return() -> None:
    project, function = _function_and_project(
        {
            0x1000: (_Insn(0x1000, "call", (_Operand(2, imm=0x1000),)), _Insn(0x1002, "jmp", (_Operand(2, imm=0x1010),))),
            0x1010: (_Insn(0x1010, "pop", (_Operand(1, reg=2),)), _Insn(0x1011, "ret")),
        },
        {0x1000: (0x1010,), 0x1010: ()},
    )

    evidence = collect_terminal_return_passthrough_evidence_8616(project, function, (0x1000,))

    assert evidence.complete is True
    assert evidence.raw_fact_count == evidence.normalized_fact_count == 1
    assert evidence.classified_fact_count == evidence.materialized_count == 1
    assert evidence.failure_count == 0
    assert evidence.facts[0].caller_addr == evidence.facts[0].target_addr == 0x1000
    assert evidence.facts[0].path_block_addrs == (0x1000, 0x1010)
    assert evidence.facts[0].return_instruction_addr == 0x1011


def test_terminal_passthrough_refuses_active_post_call_effect() -> None:
    project, function = _function_and_project(
        {
            0x1000: (
                _Insn(0x1000, "call", (_Operand(2, imm=0x1000),)),
                _Insn(0x1002, "mov", (_Operand(1, reg=1), _Operand(2, imm=3))),
                _Insn(0x1003, "ret"),
            )
        },
        {0x1000: ()},
    )

    evidence = collect_terminal_return_passthrough_evidence_8616(project, function, (0x1000,))

    assert evidence.complete is False
    assert evidence.facts == ()
    assert evidence.failures[0].kind is TerminalReturnPassThroughFailureKind8616.PATH_REFUSED
    assert evidence.failures[0].path_status is TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT


def test_terminal_passthrough_refuses_indirect_target_and_ambiguous_cfg() -> None:
    indirect_project, indirect_function = _function_and_project(
        {0x1000: (_Insn(0x1000, "call", (_Operand(1, reg=1),)), _Insn(0x1002, "ret"))},
        {0x1000: ()},
    )
    ambiguous_project, ambiguous_function = _function_and_project(
        {
            0x1000: (_Insn(0x1000, "call", (_Operand(2, imm=0x1000),)),),
            0x1010: (_Insn(0x1010, "ret"),),
            0x1020: (_Insn(0x1020, "ret"),),
        },
        {0x1000: (0x1010, 0x1020), 0x1010: (), 0x1020: ()},
    )

    indirect = collect_terminal_return_passthrough_evidence_8616(
        indirect_project,
        indirect_function,
        (0x1000,),
    )
    ambiguous = collect_terminal_return_passthrough_evidence_8616(
        ambiguous_project,
        ambiguous_function,
        (0x1000,),
    )

    assert indirect.failures[0].kind is TerminalReturnPassThroughFailureKind8616.DIRECT_TARGET_UNKNOWN
    assert ambiguous.failures[0].kind is TerminalReturnPassThroughFailureKind8616.PATH_REFUSED
    assert ambiguous.failures[0].path_status is TerminalCallPathStatus8616.CFG_PATH_AMBIGUOUS


def test_terminal_passthrough_duplicate_candidate_keeps_census_incomplete() -> None:
    project, function = _function_and_project(
        {0x1000: (_Insn(0x1000, "call", (_Operand(2, imm=0x1000),)), _Insn(0x1002, "ret"))},
        {0x1000: ()},
    )

    evidence = collect_terminal_return_passthrough_evidence_8616(
        project,
        function,
        (0x1000, 0x1000),
    )

    assert evidence.complete is False
    assert len(evidence.facts) == 1
    assert evidence.raw_fact_count == 2
    assert evidence.failure_count == 1
    assert evidence.failures[0].kind is TerminalReturnPassThroughFailureKind8616.DUPLICATE_CALLSITE
