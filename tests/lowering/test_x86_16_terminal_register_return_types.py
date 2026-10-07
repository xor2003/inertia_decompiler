from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
import inertia.lowering.terminal_register_return_types as terminal_register_return_types
from inertia.lowering.terminal_register_return_types import (
    apply_terminal_register_return_type_evidence_8616,
    materialize_terminal_register_return_type_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616
import inertia.cli.cli_decompilation as cli_decompilation


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self.function_value = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self.function_value if addr == self.function_value.addr else None


def _record_used_result(project: object, function_addr: int = 0x1000) -> None:
    """Attach one complete proof that a caller consumes the function result."""
    record_caller_return_use_evidence_8616(
        project,
        function_addr,
        CallerReturnUseEvidence8616(
            target_addr=function_addr,
            verdict=CallerReturnUseVerdict8616.USED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=1,
            unused_callsite_count=0,
            callsite_addrs=(0x2000,),
        ),
    )


def test_terminal_ax_word_refines_only_generated_byte_header(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={}, prototype=original)
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is True
    assert result.stats.materialized_count == 1
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.signed is False
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert function.prototype is original


def test_terminal_ax_word_reconciles_generated_signed_word_header(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeShort(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={}, prototype=original)
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is True
    assert result.stats == terminal_register_return_types.TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0)
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.signed is False
    assert function.prototype is original


def test_terminal_ax_word_reconciles_unbound_generated_word_header(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeShort(signed=True))
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={}, prototype=original)
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is True
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeShort)
    assert codegen.cfunc.functy.returnty.signed is False


def test_terminal_ax_mixed_width_paths_refuse_header_refinement(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: None,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is False
    assert result.stats.classified_fact_count == 0
    assert codegen.cfunc.functy is original


def test_terminal_dx_ax_storage_refuses_word_header_refinement(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.DX_AX,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is False
    assert result.stats.classified_fact_count == 0
    assert codegen.cfunc.functy is original


def test_terminal_ax_word_seeds_unobserved_guessed_void_prototype(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction(
        [SimTypeShort(signed=True)],
        SimTypeBottom(label="void"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=object(),
        info={},
        is_prototype_guessed=True,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is True
    assert result.stats == terminal_register_return_types.TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0)
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.prototype.returnty.signed is False


def test_terminal_ax_word_preserves_proven_unused_guessed_void_prototype(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=object(),
        info={},
        is_prototype_guessed=True,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    record_caller_return_use_evidence_8616(
        project,
        function.addr,
        CallerReturnUseEvidence8616(
            target_addr=function.addr,
            verdict=CallerReturnUseVerdict8616.UNUSED,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=0,
            unused_callsite_count=1,
            callsite_addrs=(0x2000,),
        ),
    )
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is False
    assert result.stats == terminal_register_return_types.TerminalRegisterReturnTypeStats8616(1, 1, 0, 0, 0)
    assert function.prototype is original


def test_terminal_ax_word_seeds_observed_guessed_void_prototype(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction(
        [SimTypeShort(signed=True)],
        SimTypeBottom(label="void"),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=object(),
        info={},
        is_prototype_guessed=True,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    _record_used_result(project)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is True
    assert result.stats == terminal_register_return_types.TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0)
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.prototype.returnty.signed is False
    assert function.is_prototype_guessed is False


def test_terminal_ax_word_preserves_explicit_void_prototype(monkeypatch) -> None:
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeBottom(label="void")).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=object(),
        info={ANNOTATION_KEY: {"prototype": original}},
        is_prototype_guessed=False,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    _record_used_result(project)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is False
    assert function.prototype is original


def test_terminal_ax_word_seeds_unknown_prototype_without_freezing_arguments(monkeypatch) -> None:
    arch = Arch86_16()
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=None,
        info={},
        is_prototype_guessed=True,
        prototype=None,
    )
    project = SimpleNamespace(arch=arch)
    _record_used_result(project)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is True
    assert isinstance(function.prototype.returnty, SimTypeShort)
    assert function.prototype.args == ()
    assert function.is_prototype_guessed is True


def test_cli_render_finalizer_replays_terminal_register_type_lowering(monkeypatch) -> None:
    calls: list[tuple[object, object]] = []
    codegen = SimpleNamespace(project=object(), cfunc=SimpleNamespace(functy=object()))
    monkeypatch.setattr(cli_decompilation, "reapply_stack_aggregate_object_facts_8616", lambda _codegen: False)
    monkeypatch.setattr(
        cli_decompilation,
        "reconcile_exact_stack_argument_prototype_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "materialize_function_pointer_parameters_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "materialize_callsite_prototype_declarations_8616",
        lambda _project, _codegen: False,
    )
    monkeypatch.setattr(
        cli_decompilation,
        "materialize_terminal_register_return_type_8616",
        lambda project, active_codegen: calls.append((project, active_codegen)) or SimpleNamespace(changed=True),
    )

    changed = cli_decompilation._finalize_typed_call_interfaces_before_render_8616(codegen)

    assert changed is True
    assert calls == [(codegen.project, codegen)]
