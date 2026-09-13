"""Calling-convention seeding must track the contracts it consumes."""

from types import SimpleNamespace

from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr_platforms.X86_16 import calling_convention_compat
from angr_platforms.X86_16.analysis_helpers import seed_calling_conventions
from angr_platforms.X86_16.lowering import terminal_call_return_types, terminal_register_return_types
from angr_platforms.X86_16.semantics.terminal_return_storage import TerminalReturnStorage8616
from test_x86_16_terminal_call_return_types import _Insn, _project_and_function, _record_used_result


def _fixture(monkeypatch, *, void_callee=False, observed=True):
    return_type = SimTypeBottom(label="void") if void_callee else SimTypeShort(False)
    project, caller = _project_and_function(
        post_call_instructions=(_Insn(0x1003, "ret"),),
        callee_prototype=SimTypeFunction([], return_type),
    )
    callee = project.kb.functions.function(addr=0x2000, create=False)
    callee.prototype = callee.prototype.with_arch(project.arch)
    caller.block_addrs_set = {0x1000}
    caller.get_block_size = lambda _addr: 4
    caller.get_call_sites = lambda: (0x1000,)
    caller.get_call_target = lambda _addr: 0x2000
    caller._init_prototype_and_calling_convention = lambda: None
    if observed:
        _record_used_result(project)
    monkeypatch.setattr(calling_convention_compat, "apply_x86_16_stack_byte_prototype_evidence", lambda *_args: False)
    monkeypatch.setattr(calling_convention_compat, "apply_x86_16_wide_stack_prototype_evidence", lambda *_args: False)
    monkeypatch.setattr(
        terminal_register_return_types, "terminal_return_storage_8616", lambda *_args: TerminalReturnStorage8616.NONE,
    )
    calls = []
    original = terminal_call_return_types.apply_terminal_call_return_type_evidence_8616

    def record(project, function):
        calls.append(function.addr)
        return original(project, function)

    monkeypatch.setattr(terminal_call_return_types, "apply_terminal_call_return_type_evidence_8616", record)
    return SimpleNamespace(project=project, functions={caller.addr: caller}), caller, callee, calls


def test_seed_revisits_caller_when_callee_return_contract_changes(monkeypatch):
    cfg, caller, callee, calls = _fixture(monkeypatch, void_callee=True)
    seed_calling_conventions(cfg)
    assert caller.prototype is None
    calls.clear()

    callee.prototype = SimTypeFunction([], SimTypeShort(False)).with_arch(cfg.project.arch)
    seed_calling_conventions(cfg)

    assert calls == [caller.addr]
    assert isinstance(caller.prototype.returnty, SimTypeShort)


def test_seed_revisits_caller_when_result_observation_arrives(monkeypatch):
    cfg, caller, _callee, calls = _fixture(monkeypatch, observed=False)
    seed_calling_conventions(cfg)
    assert caller.prototype is None
    calls.clear()

    _record_used_result(cfg.project)
    seed_calling_conventions(cfg)

    assert calls == [caller.addr]
    assert isinstance(caller.prototype.returnty, SimTypeShort)


def test_seed_reuses_unchanged_dependency_contracts(monkeypatch):
    cfg, _caller, _callee, calls = _fixture(monkeypatch)
    seed_calling_conventions(cfg)
    calls.clear()

    seed_calling_conventions(cfg)

    assert not calls


def test_seed_detects_in_place_callee_return_type_mutation(monkeypatch):
    cfg, caller, callee, calls = _fixture(monkeypatch, void_callee=True)
    seed_calling_conventions(cfg)
    assert caller.prototype is None
    calls.clear()

    callee.prototype.returnty = SimTypeShort(False).with_arch(cfg.project.arch)
    seed_calling_conventions(cfg)

    assert calls == [caller.addr]
    assert isinstance(caller.prototype.returnty, SimTypeShort)


def test_seed_ignores_uninspected_callee_changes(monkeypatch):
    cfg, _caller, _callee, calls = _fixture(monkeypatch)
    seed_calling_conventions(cfg)
    calls.clear()

    cfg.project.kb.functions._functions[0x3000] = SimpleNamespace(
        addr=0x3000, prototype=SimTypeFunction([], SimTypeShort(False)),
    )
    seed_calling_conventions(cfg)

    assert not calls
