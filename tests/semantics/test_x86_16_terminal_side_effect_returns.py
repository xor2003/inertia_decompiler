from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
import inertia.lowering.type_clinic_return_compat as type_clinic_return_compat
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallerReturnUseVerdict8616
from inertia.lowering.unused_void_return_types import (
    TerminalReturnValueEvidence8616,
)
import inertia.semantics.terminal_register_returns as terminal_register_returns

from inertia.semantics.branch_target_return import (
    TerminalAxReturnEffectKind8616,
)
from inertia.semantics.terminal_register_returns import (
    TerminalAxReturnEvidence8616,
    TerminalReturnStorageState8616,
    collect_terminal_ax_return_evidence_8616,
)
from inertia.semantics.terminal_value_roles import (
    TerminalAxReturnLane8616,
    TerminalAxUse8616,
    TerminalAxUseKind8616,
    terminal_ax_use_8616,
)


class _Factory:
    def __init__(self, blocks: dict[int, object]) -> None:
        self.blocks = blocks

    def block(self, address: int, *, opt_level: int) -> object:
        assert opt_level == 0
        return self.blocks[address]


def _insn(address: int, mnemonic: str) -> object:
    return SimpleNamespace(address=address, size=1, mnemonic=mnemonic, operands=())


def _terminal_evidence(*, consumed: bool) -> TerminalAxReturnEvidence8616:
    consumed_lanes = (
        TerminalAxReturnLane8616.WORD
        if consumed
        else TerminalAxReturnLane8616.NONE
    )
    return TerminalAxReturnEvidence8616(
        frozenset(
            {
                TerminalReturnStorageState8616(
                    TerminalAxReturnLane8616.WORD,
                    False,
                    TerminalAxReturnLane8616.NONE,
                    consumed_lanes,
                )
            }
        ),
        1,
        1,
        1,
        1,
        0,
    )


def test_capstone_classifies_ax_as_explicit_memory_store_value() -> None:
    instruction = next(
        iter(Arch86_16().capstone.disasm(b"\x89\x07", 0x1000))
    )

    use = terminal_ax_use_8616(
        SimpleNamespace(mnemonic=instruction.mnemonic, insn=instruction)
    )

    assert use == TerminalAxUse8616(
        TerminalAxUseKind8616.MEMORY_EFFECT,
        TerminalAxReturnLane8616.WORD,
    )


def test_capstone_refuses_direct_global_ax_store_as_pointer_output() -> None:
    instruction = next(
        iter(Arch86_16().capstone.disasm(b"\x89\x06\x00\x20", 0x1000))
    )

    use = terminal_ax_use_8616(
        SimpleNamespace(mnemonic=instruction.mnemonic, insn=instruction)
    )

    assert use == TerminalAxUse8616(
        TerminalAxUseKind8616.OTHER,
        TerminalAxReturnLane8616.WORD,
    )


def test_terminal_local_stack_pointer_output_carrier_closes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    load_local = _insn(0x1000, "mov")
    store_pointer = _insn(0x1001, "mov")
    terminal = _insn(0x1002, "ret")
    blocks = {
        0x1000: SimpleNamespace(
            capstone=SimpleNamespace(insns=(load_local, store_pointer, terminal))
        )
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))
    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=(
                TerminalAxReturnEffectKind8616.MOV_REG_STACK
                if insn is load_local
                else TerminalAxReturnEffectKind8616.OTHER
            ),
            dst_reg="ax" if insn is load_local else None,
            mem_disp=-2 if insn is load_local else None,
        ),
    )
    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_use_8616",
        lambda insn: (
            TerminalAxUse8616(
                TerminalAxUseKind8616.MEMORY_EFFECT,
                TerminalAxReturnLane8616.WORD,
            )
            if insn is store_pointer
            else TerminalAxUse8616(
                TerminalAxUseKind8616.NONE,
                TerminalAxReturnLane8616.NONE,
            )
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.proves_local_pointer_output_carrier is True


@pytest.mark.parametrize("later_event", ["read", "write"])
def test_terminal_side_effect_carrier_is_invalidated_by_later_ax_event(
    monkeypatch: pytest.MonkeyPatch,
    later_event: str,
) -> None:
    write_ax = _insn(0x1000, "mov")
    store_ax = _insn(0x1001, "mov")
    later = _insn(0x1002, "mov" if later_event == "write" else "cmp")
    terminal = _insn(0x1003, "ret")
    blocks = {
        0x1000: SimpleNamespace(
            capstone=SimpleNamespace(insns=(write_ax, store_ax, later, terminal))
        )
    }
    project = SimpleNamespace(factory=_Factory(blocks))
    function = SimpleNamespace(addr=0x1000, block_addrs_set=set(blocks))

    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_return_effect_8616",
        lambda insn: SimpleNamespace(
            kind=TerminalAxReturnEffectKind8616.OTHER,
            dst_reg=(
                "ax"
                if insn is write_ax or (later_event == "write" and insn is later)
                else None
            ),
        ),
    )
    monkeypatch.setattr(
        terminal_register_returns,
        "terminal_ax_use_8616",
        lambda insn: (
            TerminalAxUse8616(
                TerminalAxUseKind8616.MEMORY_EFFECT,
                TerminalAxReturnLane8616.WORD,
            )
            if insn is store_ax
            else TerminalAxUse8616(
                TerminalAxUseKind8616.OTHER,
                TerminalAxReturnLane8616.WORD,
            )
            if later_event == "read" and insn is later
            else TerminalAxUse8616(
                TerminalAxUseKind8616.NONE,
                TerminalAxReturnLane8616.NONE,
            )
        ),
    )

    evidence = collect_terminal_ax_return_evidence_8616(project, function)

    assert evidence.complete is True
    assert evidence.proves_local_pointer_output_carrier is False


def test_terminal_side_effect_carrier_requires_every_return_path() -> None:
    side_effect_state = next(iter(_terminal_evidence(consumed=True).storage_states))
    value_state = next(iter(_terminal_evidence(consumed=False).storage_states))
    evidence = TerminalAxReturnEvidence8616(
        frozenset({side_effect_state, value_state}),
        2,
        2,
        2,
        2,
        0,
    )

    assert evidence.proves_local_pointer_output_carrier is False


@pytest.mark.parametrize(
    ("consumed", "expected_changed"),
    [(True, True), (False, False)],
)
def test_clinic_void_demotion_consumes_terminal_side_effect_role(
    monkeypatch: pytest.MonkeyPatch,
    consumed: bool,
    expected_changed: bool,
) -> None:
    arch = Arch86_16()
    prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        info={},
        prototype=prototype,
        prototype_source=PrototypeSource.GUESSED,
    )
    project = SimpleNamespace(arch=arch)
    monkeypatch.setattr(
        type_clinic_return_compat,
        "collect_clinic_terminal_return_evidence_8616",
        lambda _graph: TerminalReturnValueEvidence8616(1, 1, 1, 1, 0, 0),
    )
    monkeypatch.setattr(
        type_clinic_return_compat,
        "proven_function_result_observation_8616",
        lambda _project, _addr: CallerReturnUseVerdict8616.UNUSED,
    )
    monkeypatch.setattr(
        type_clinic_return_compat,
        "collect_terminal_ax_return_evidence_8616",
        lambda _project, _function: _terminal_evidence(consumed=consumed),
    )

    result = type_clinic_return_compat.finalize_clinic_return_type_8616(
        project,
        function,
        object(),
        prototype_was_guessed=True,
    )

    assert result.changed is expected_changed
    assert isinstance(function.prototype.returnty, SimTypeBottom) is expected_changed
    if not expected_changed:
        assert function.prototype is prototype
