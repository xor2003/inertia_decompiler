from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeShort
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
from angr_platforms.X86_16.lowering import terminal_call_return_types
from angr_platforms.X86_16.lowering.authoritative_function_prototypes import (
    authoritative_function_prototype_8616,
    capture_authoritative_function_prototype_8616,
)
from angr_platforms.X86_16.lowering.terminal_call_return_types import (
    CalleeResultContract8616,
    TerminalCallReturnTypeSource8616,
    apply_terminal_call_return_type_evidence_8616,
    callee_result_contract_8616,
)
from angr_platforms.X86_16.semantics.terminal_call_paths import (
    TerminalCallPathStatus8616,
    angr_terminal_call_path_callbacks_8616,
    prove_terminal_call_path_8616,
)
from angr_platforms.X86_16.semantics.terminal_return_storage import TerminalReturnStorage8616


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
        return {1: "ax", 2: "bp", 3: "eax", 4: "edx", 5: "si", 6: "edi"}.get(register_id, "")


class _Block:
    def __init__(self, instructions: tuple[_Insn, ...]) -> None:
        self.capstone = SimpleNamespace(insns=instructions)


class _Factory:
    def __init__(self, blocks: dict[int, _Block]) -> None:
        self._blocks = blocks

    def block(self, address: int, *, size: int) -> _Block:
        return self._blocks[address]


class _Graph:
    def __init__(self, nodes: tuple[SimpleNamespace, ...], successors: dict[int, tuple[int, ...]]) -> None:
        self.nodes = nodes
        self._nodes_by_addr = {node.addr: node for node in nodes}
        self._successors = successors

    def successors(self, node: SimpleNamespace) -> tuple[SimpleNamespace, ...]:
        return tuple(self._nodes_by_addr[address] for address in self._successors.get(node.addr, ()))


class _FunctionManager:
    def __init__(self, functions: dict[int, SimpleNamespace]) -> None:
        self._functions = functions

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self._functions.get(addr)


def _project_and_function(
    *,
    post_call_instructions: tuple[_Insn, ...],
    callee_prototype: SimTypeFunction | None = None,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    arch = Arch86_16()
    call = _Insn(0x1000, "call", (_Operand(2, imm=0x2000),))
    node = SimpleNamespace(addr=0x1000, size=4)
    function = SimpleNamespace(
        addr=0x1000,
        graph=_Graph((node,), {0x1000: ()}),
        prototype=None,
        calling_convention=None,
        info={},
        is_prototype_guessed=True,
        prototype_source=PrototypeSource.NONE,
    )
    functions = {0x1000: function}
    functions[0x2000] = SimpleNamespace(
        addr=0x2000,
        info={},
        is_prototype_guessed=callee_prototype is None,
        prototype=callee_prototype,
        prototype_source=(
            PrototypeSource.CCA_DECOMPILER
            if callee_prototype is not None
            else PrototypeSource.NONE
        ),
    )
    project = SimpleNamespace(
        arch=arch,
        factory=_Factory({0x1000: _Block((call, *post_call_instructions))}),
        kb=SimpleNamespace(functions=_FunctionManager(functions), labels={}),
    )
    return project, function


def _record_used_result(project: object) -> None:
    """Attach one complete proof that a caller consumes the function result."""
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        CallerReturnUseEvidence8616(
            target_addr=0x1000,
            verdict=CallerReturnUseVerdict8616.USED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=1,
            unused_callsite_count=0,
            callsite_addrs=(0x3000,),
        ),
    )


def test_callee_result_contract_refuses_guessed_prototype() -> None:
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(Arch86_16())
    callee = SimpleNamespace(prototype=prototype, is_prototype_guessed=True)

    assert callee_result_contract_8616(callee) is CalleeResultContract8616.UNKNOWN


def test_callee_result_contract_accepts_explicit_value_prototype() -> None:
    prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(Arch86_16())
    callee = SimpleNamespace(prototype=prototype, is_prototype_guessed=False)

    assert callee_result_contract_8616(callee) is CalleeResultContract8616.VALUE


def test_callee_result_contract_accepts_explicit_void_prototype() -> None:
    prototype = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(Arch86_16())
    callee = SimpleNamespace(prototype=prototype, is_prototype_guessed=False)

    assert callee_result_contract_8616(callee) is CalleeResultContract8616.VOID


@pytest.mark.parametrize(
    ("register_id", "expected_status"),
    [
        pytest.param(2, TerminalCallPathStatus8616.PROVEN, id="bp"),
        pytest.param(5, TerminalCallPathStatus8616.PROVEN, id="si"),
        pytest.param(6, TerminalCallPathStatus8616.PROVEN, id="edi"),
        pytest.param(1, TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT, id="ax-clobber"),
        pytest.param(3, TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT, id="eax-clobber"),
        pytest.param(4, TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT, id="edx-clobber"),
        pytest.param(0, TerminalCallPathStatus8616.UNSAFE_POST_CALL_EFFECT, id="unknown-register"),
    ],
)
def test_terminal_call_path_proves_frame_teardown_to_return(register_id, expected_status) -> None:
    project, function = _project_and_function(
        post_call_instructions=(
            _Insn(0x1002, "pop", (_Operand(1, reg=register_id),)),
            _Insn(0x1003, "ret"),
        )
    )

    result = prove_terminal_call_path_8616(
        0x1000,
        angr_terminal_call_path_callbacks_8616(project, function),
    )

    assert result.status is expected_status
    assert result.path_block_addrs == (0x1000,)


def test_terminal_call_return_type_refuses_without_observed_caller_result(monkeypatch) -> None:
    project, function = _project_and_function(post_call_instructions=(_Insn(0x1003, "ret"),))
    monkeypatch.setattr(
        terminal_call_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert not result.changed
    assert result.evidence.raw_fact_count == 1
    assert result.evidence.normalized_fact_count == 1
    assert result.evidence.classified_fact_count == 0
    assert result.evidence.materialized_count == 0
    assert result.evidence.failure_count == 0
    assert function.prototype is None


def test_terminal_call_return_type_uses_proven_callee_ax_word_for_observed_result(monkeypatch) -> None:
    project, function = _project_and_function(post_call_instructions=(_Insn(0x1003, "ret"),))
    _record_used_result(project)
    monkeypatch.setattr(
        terminal_call_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert result.changed
    assert result.evidence.sources == (TerminalCallReturnTypeSource8616.CALLEE_TERMINAL_AX_WORD,)
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.prototype.returnty.signed is False


def test_terminal_call_return_type_replaces_inferred_void_snapshot() -> None:
    arch = Arch86_16()
    callee_prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)
    project, function = _project_and_function(
        post_call_instructions=(_Insn(0x1003, "ret"),),
        callee_prototype=callee_prototype,
    )
    function.prototype = SimTypeFunction(
        [],
        SimTypeBottom(label="void"),
    ).with_arch(arch)
    function.is_prototype_guessed = False
    function.prototype_source = PrototypeSource.CCA_DECOMPILER
    capture_authoritative_function_prototype_8616(project, function)
    _record_used_result(project)

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert result.changed
    assert result.evidence.materialized_count == 1
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.prototype_source is PrototypeSource.CCA_DECOMPILER
    authoritative = authoritative_function_prototype_8616(
        project,
        function,
        argument_count=0,
    )
    assert authoritative is not None
    assert isinstance(authoritative.returnty, SimTypeShort)


def test_terminal_call_return_type_preserves_explicit_void_prototype() -> None:
    arch = Arch86_16()
    callee_prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(arch)
    project, function = _project_and_function(
        post_call_instructions=(_Insn(0x1003, "ret"),),
        callee_prototype=callee_prototype,
    )
    explicit = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    function.prototype = explicit
    function.is_prototype_guessed = False
    function.prototype_source = PrototypeSource.SIGNATURES
    _record_used_result(project)

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert not result.changed
    assert result.evidence.materialized_count == 0
    assert function.prototype is explicit


def test_terminal_call_return_type_refuses_callee_dx_ax_as_word(monkeypatch) -> None:
    project, function = _project_and_function(post_call_instructions=(_Insn(0x1003, "ret"),))
    _record_used_result(project)
    monkeypatch.setattr(
        terminal_call_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.DX_AX,
    )

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert not result.changed
    assert result.evidence.classified_fact_count == 0
    assert function.prototype is None


def test_terminal_call_return_type_preserves_concrete_byte_callee_prototype() -> None:
    arch = Arch86_16()
    callee_prototype = SimTypeFunction([], SimTypeChar(signed=False)).with_arch(arch)
    project, function = _project_and_function(
        post_call_instructions=(_Insn(0x1003, "ret"),),
        callee_prototype=callee_prototype,
    )
    _record_used_result(project)

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert result.evidence.sources == (TerminalCallReturnTypeSource8616.CALLEE_PROTOTYPE,)
    assert isinstance(function.prototype.returnty, SimTypeChar)
    assert function.prototype.returnty.signed is False


def test_terminal_call_return_type_refuses_post_call_ax_clobber() -> None:
    project, function = _project_and_function(
        post_call_instructions=(
            _Insn(0x1002, "mov", (_Operand(1, reg=1), _Operand(2, imm=3))),
            _Insn(0x1003, "ret"),
        )
    )

    result = apply_terminal_call_return_type_evidence_8616(project, function)

    assert not result.changed
    assert result.evidence.raw_fact_count == 1
    assert result.evidence.normalized_fact_count == 0
    assert result.evidence.classified_fact_count == 0
    assert result.evidence.materialized_count == 0
    assert function.prototype is None
