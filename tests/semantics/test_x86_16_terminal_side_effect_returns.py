from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort

import inertia.lowering.type_clinic_return_compat as type_clinic_return_compat
import inertia.semantics.terminal_register_returns as terminal_register_returns
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.unused_void_return_types import (
    TerminalReturnValueEvidence8616,
)
from inertia.semantics.branch_target_return import (
    TerminalAxReturnEffectKind8616,
)
from inertia.semantics.callsite_summary import CallerReturnUseVerdict8616
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


@pytest.mark.parametrize("native", [False, True])
@pytest.mark.parametrize("callsite", [False, True])
def test_clinic_cca_scope_is_project_specific_nested_and_thread_local(native, callsite):
    """Only native CCA in the exact dynamic Clinic scope inherits its KB."""
    import threading

    import angr

    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap

    apply_x86_16_bootstrap()

    def make_analysis(owner):
        if not callsite:
            return owner.analyses.CompleteCallingConventions(auto_start=False)
        function = owner.kb.functions.function(addr=0x1000, create=True)
        analysis = owner.analyses.CallingConvention(function)
        assert analysis._variable_manager is analysis.kb.variables
        return analysis

    project = angr.load_shellcode(b"\xc3", arch=Arch86_16() if native else "x86", load_address=0x1000)
    other = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    first, nested = angr.KnowledgeBase(project), angr.KnowledgeBase(project)
    context = type_clinic_return_compat._CLINIC_CALLING_CONVENTION_SCOPE_8616
    scope_type = type_clinic_return_compat._ClinicCallingConventionScope8616
    assert context.get() is None
    assert make_analysis(project).kb is project.kb
    token = context.set(scope_type(project, first))
    try:
        assert make_analysis(project).kb is (first if native else project.kb)
        assert make_analysis(other).kb is other.kb
        observed = []
        thread = threading.Thread(target=lambda: observed.append(
            make_analysis(project).kb,
        ))
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert observed == [project.kb]
        inner = context.set(scope_type(project, nested))
        try:
            assert make_analysis(project).kb is (nested if native else project.kb)
        finally:
            context.reset(inner)
        assert context.get().kb is first
    finally:
        context.reset(token)
    assert context.get() is None
    assert make_analysis(project).kb is project.kb


def test_native_clinic_cca_scope_resets_when_original_recovery_raises(monkeypatch):
    """A failing Clinic call cannot leak its KB into a later CCA request."""
    import angr
    from angr.analyses.decompiler.clinic import Clinic

    project = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    kb = angr.KnowledgeBase(project)
    function = SimpleNamespace(prototype=None, prototype_source=PrototypeSource.NONE)
    clinic = SimpleNamespace(project=project, kb=kb, function=function)
    context = type_clinic_return_compat._CLINIC_CALLING_CONVENTION_SCOPE_8616

    def fail(self, func_graph=None):
        assert context.get().kb is kb
        raise RuntimeError("owned test recovery failure")

    monkeypatch.setattr(Clinic, "_recover_calling_conventions", fail)
    type_clinic_return_compat._preserve_strong_prototype_during_cc_recovery_8616()
    with pytest.raises(RuntimeError, match="owned test recovery failure"):
        Clinic._recover_calling_conventions(clinic)
    assert context.get() is None


def _ail_call_block(block_addr: int, callee_addr: int, args: list[object]) -> object:
    """Build a real AIL block whose terminal statement is a call to ``callee_addr``."""
    from angr.ailment import Block, Expr, Stmt

    call = Expr.Call(
        None,
        Expr.Const(None, callee_addr, 16),
        args=args,
        bits=0,
        ins_addr=block_addr + 2,
    )
    statement = Stmt.SideEffectStatement(None, call, ins_addr=block_addr + 2)
    return Block(block_addr, 4, statements=[statement])


def _same_address_callees(project: object, retained: object, cc: object) -> tuple[object, object]:
    """Register a distinct callee prototype at one address in each KB."""
    word = SimTypeShort(signed=False)
    default_callee = project.kb.functions.function(addr=0x2000, create=True)
    default_callee.prototype = SimTypeFunction([], word).with_arch(project.arch)
    default_callee.calling_convention = cc
    retained_callee = retained.functions.function(addr=0x2000, create=True)
    retained_callee.prototype = SimTypeFunction([word], word).with_arch(project.arch)
    retained_callee.calling_convention = cc
    retained_callee.prototype_source = PrototypeSource.USER
    return default_callee, retained_callee


@pytest.mark.parametrize("native", [False, True])
def test_clinic_callsite_maker_scope_owns_callee_prototype(native):
    """Only a native in-scope CallSiteMaker resolves callees through the Clinic KB."""
    import angr
    from angr.ailment import Expr
    from angr.ailment.manager import Manager
    from angr.analyses.decompiler.callsite_maker import CallSiteMaker
    from angr.analyses.decompiler.variable_map import variable_map_of
    from angr.calling_conventions import SimCCCdecl

    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.frontend.x86_16.simos_86_16 import SimCC8616MSCsmall

    apply_x86_16_bootstrap()
    type_clinic_return_compat._bind_clinic_callsite_maker_kb_8616()

    project = angr.load_shellcode(
        b"\xc3", arch=Arch86_16() if native else "x86", load_address=0x1000
    )
    foreign = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    retained = angr.KnowledgeBase(project)
    nested_kb = angr.KnowledgeBase(project)
    cc = SimCC8616MSCsmall(project.arch) if native else SimCCCdecl(project.arch)
    default_callee, retained_callee = _same_address_callees(project, retained, cc)
    arg = Expr.Const(None, 7, 16)

    def make_maker(maker_project: object = project) -> object:
        return CallSiteMaker(
            maker_project,
            _ail_call_block(0x1000, 0x2000, [arg]),
            ail_manager=Manager(),
        )

    context = type_clinic_return_compat._CLINIC_CALLING_CONVENTION_SCOPE_8616
    scope_type = type_clinic_return_compat._ClinicCallingConventionScope8616
    assert context.get() is None
    unscoped = make_maker()
    assert unscoped.kb is project.kb
    token = context.set(scope_type(project, retained))
    try:
        scoped = make_maker()
        foreign_maker = make_maker(foreign)
        inner = context.set(scope_type(project, nested_kb))
        try:
            nested = make_maker()
        finally:
            context.reset(inner)
    finally:
        context.reset(token)
    assert context.get() is None
    assert make_maker().kb is project.kb
    assert foreign_maker.kb is foreign.kb

    expected_scoped_kb = retained if native else project.kb
    assert scoped.kb is expected_scoped_kb
    assert nested.kb is (nested_kb if native else project.kb)

    unscoped_call = unscoped.result_block.statements[-1].expr
    unscoped_map = variable_map_of(unscoped._ail_manager)
    assert unscoped_map.prototype(unscoped_call) is default_callee.prototype
    assert list(unscoped_call.args) == []
    if native:
        scoped_call = scoped.result_block.statements[-1].expr
        scoped_map = variable_map_of(scoped._ail_manager)
        assert scoped_map.prototype(scoped_call) is retained_callee.prototype
        assert len(scoped_call.args) == 1
        assert isinstance(scoped_call.args[0], Expr.Const)
        assert scoped_call.args[0].value == 7
        assert scoped_call.tags["is_prototype_guessed"] is False
        assert unscoped_call.tags["is_prototype_guessed"] is True


def test_native_clinic_make_callsites_scope_binds_real_callsite_maker() -> None:
    """A real Clinic._make_callsites run publishes its KB to the nested maker."""
    import angr
    import networkx
    from angr.ailment import Expr
    from angr.ailment.manager import Manager
    from angr.analyses.decompiler.clinic import Clinic
    from angr.analyses.decompiler.variable_map import variable_map_of

    from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
    from inertia.frontend.x86_16.simos_86_16 import SimCC8616MSCsmall

    apply_x86_16_bootstrap()
    type_clinic_return_compat._bind_clinic_callsite_maker_kb_8616()
    type_clinic_return_compat._preserve_clinic_kb_during_callsite_making_8616()

    project = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    retained = angr.KnowledgeBase(project)
    cc = SimCC8616MSCsmall(project.arch)
    _default_callee, retained_callee = _same_address_callees(project, retained, cc)
    arg = Expr.Const(None, 7, 16)
    manager = Manager()
    clinic = SimpleNamespace(
        project=project,
        kb=retained,
        _ail_manager=manager,
        function=SimpleNamespace(addr=0x1000),
        _inlining_parents=set(),
        _get_peephole_bundle=lambda *a, **k: None,
    )
    context = type_clinic_return_compat._CLINIC_CALLING_CONVENTION_SCOPE_8616

    graph = networkx.DiGraph()
    graph.add_node(_ail_call_block(0x1000, 0x2000, [arg]))
    out_graph, _offsets, _removed = Clinic._make_callsites(clinic, graph)

    assert context.get() is None
    rewritten_call = next(iter(out_graph.nodes)).statements[-1].expr
    assert variable_map_of(manager).prototype(rewritten_call) is retained_callee.prototype
    assert len(rewritten_call.args) == 1
    assert isinstance(rewritten_call.args[0], Expr.Const)
    assert rewritten_call.args[0].value == 7
    assert project.kb.functions.function(addr=0x2000, create=False) is not retained_callee


def test_native_clinic_callsite_scope_resets_when_make_callsites_raises(monkeypatch):
    """A failing Clinic._make_callsites cannot leak its KB into a later maker."""
    import angr
    from angr.analyses.decompiler.clinic import Clinic

    project = angr.load_shellcode(b"\xc3", arch=Arch86_16(), load_address=0x1000)
    kb = angr.KnowledgeBase(project)
    clinic = SimpleNamespace(project=project, kb=kb)
    context = type_clinic_return_compat._CLINIC_CALLING_CONVENTION_SCOPE_8616

    def fail(
        self,
        ail_graph=None,
        func_args=None,
        stack_pointer_tracker=None,
        preserve_vvar_ids=None,
    ):
        assert context.get().kb is kb
        raise RuntimeError("owned test callsite failure")

    monkeypatch.setattr(Clinic, "_make_callsites", fail)
    type_clinic_return_compat._preserve_clinic_kb_during_callsite_making_8616()
    with pytest.raises(RuntimeError, match="owned test callsite failure"):
        Clinic._make_callsites(clinic, object())
    assert context.get() is None
