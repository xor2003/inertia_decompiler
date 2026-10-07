from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.knowledge_plugins.functions.function import PrototypeSource
from angr.sim_type import SimTypeBottom, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
    record_caller_return_use_evidence_8616,
)
import inertia.lowering.return_type_evidence as return_type_evidence
import inertia.lowering.unused_void_return_types as unused_void_return_types
from inertia.lowering.return_type_evidence import (
    collect_unobserved_callee_void_evidence_8616,
)
from inertia.lowering.unused_void_return_types import (
    TerminalReturnStorageInput8616,
    TerminalReturnValueEvidence8616,
    UnusedVoidReturnTypeStats8616,
    materialize_unused_caller_void_codegen_type_8616,
    materialize_unused_caller_void_return_type_8616,
    record_terminal_return_value_evidence_8616,
)
from inertia.pipeline.errors import PipelineHardError

from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616


class _FunctionManager:
    def __init__(self, function: SimpleNamespace) -> None:
        self.function_value = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        assert create is False
        return self.function_value if addr == self.function_value.addr else None


def _record_caller_result(project: object, verdict: CallerReturnUseVerdict8616) -> None:
    record_caller_return_use_evidence_8616(
        project,
        0x1000,
        CallerReturnUseEvidence8616(
            target_addr=0x1000,
            verdict=verdict,
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
            failure_count=0,
            used_callsite_count=int(verdict is CallerReturnUseVerdict8616.USED),
            unused_callsite_count=int(verdict is CallerReturnUseVerdict8616.UNUSED),
            callsite_addrs=(0x2000,),
        ),
    )


def _function_fixture(*, explicit: bool = False) -> tuple[Arch86_16, SimpleNamespace, SimTypeFunction]:
    arch = Arch86_16()
    prototype = SimTypeFunction([], SimTypeShort(signed=True)).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        calling_convention=object(),
        info={ANNOTATION_KEY: {"prototype": prototype}} if explicit else {},
        is_prototype_guessed=not explicit,
        prototype=prototype,
        prototype_source=PrototypeSource.USER if explicit else PrototypeSource.GUESSED,
    )
    return arch, function, prototype


def _codegen_fixture(
    *, effectful: bool = False, return_constant: int | None = None
) -> tuple[SimpleNamespace, SimpleNamespace, SimpleNamespace]:
    arch, function, prototype = _function_fixture()
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(
        cstyle_null_cmp=False,
        next_idx=lambda _name: 1,
        project=project,
    next_ident = lambda name: f"{name}_0", next_node_idx = lambda : 1)
    if return_constant is not None:
        return_value = structured_c.CConstant(return_constant, prototype.returnty, codegen=codegen)
    elif effectful:
        return_value = structured_c.CFunctionCall(0x1234, None, [], codegen=codegen)
    else:
        return_value = structured_c.CVariable(
            SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000),
            variable_type=prototype.returnty,
            codegen=codegen,
        )
    return_node = structured_c.CReturn(return_value, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        functy=prototype,
        statements=structured_c.CStatements([return_node], codegen=codegen),
    )
    _record_caller_result(project, CallerReturnUseVerdict8616.UNUSED)
    record_terminal_return_value_evidence_8616(
        project,
        0x1000,
        TerminalReturnValueEvidence8616(1, 1, 1, 1, 0, 0),
    )
    return project, codegen, function


@pytest.mark.parametrize(("terminal_value_proven", "expected_changed"), [(False, True), (True, False)])
def test_unused_caller_demotion_requires_no_terminal_value(
    terminal_value_proven: bool,
    expected_changed: bool,
) -> None:
    arch, function, original = _function_fixture()

    result = materialize_unused_caller_void_return_type_8616(
        SimpleNamespace(arch=arch),
        function,
        caller_observation=CallerReturnUseVerdict8616.UNUSED,
        prototype_was_guessed=True,
        terminal_value_proven=terminal_value_proven,
    )

    assert result.changed is expected_changed
    if expected_changed:
        assert result.stats == UnusedVoidReturnTypeStats8616(2, 2, 2, 1, 0)
        assert isinstance(function.prototype.returnty, SimTypeBottom)
    else:
        assert result.stats == UnusedVoidReturnTypeStats8616()
        assert function.prototype is original


def test_void_return_demotion_requires_typed_unused_caller_evidence() -> None:
    arch, function, original = _function_fixture()

    result = materialize_unused_caller_void_return_type_8616(
        SimpleNamespace(arch=arch),
        function,
        caller_observation=CallerReturnUseVerdict8616.USED,
        prototype_was_guessed=True,
        terminal_value_proven=False,
    )

    assert result.changed is False
    assert result.stats == UnusedVoidReturnTypeStats8616()
    assert function.prototype is original


def test_void_return_demotion_preserves_explicit_prototype() -> None:
    arch, function, original = _function_fixture(explicit=True)

    result = materialize_unused_caller_void_return_type_8616(
        SimpleNamespace(arch=arch),
        function,
        caller_observation=CallerReturnUseVerdict8616.UNUSED,
        prototype_was_guessed=False,
        terminal_value_proven=False,
    )

    assert result.changed is False
    assert result.stats == UnusedVoidReturnTypeStats8616()
    assert function.prototype is original


def test_final_codegen_replays_closed_empty_return_evidence() -> None:
    project, codegen, function = _codegen_fixture()
    record_terminal_return_value_evidence_8616(
        project,
        0x1000,
        TerminalReturnValueEvidence8616(1, 1, 1, 0, 1, 0),
    )

    result = materialize_unused_caller_void_codegen_type_8616(project, codegen)

    assert result.changed is True
    assert result.stats == UnusedVoidReturnTypeStats8616(3, 3, 3, 2, 0)
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeBottom)
    assert isinstance(function.prototype.returnty, SimTypeBottom)
    assert function.prototype_source is PrototypeSource.CCA_DECOMPILER
    assert codegen.cfunc.statements.statements[0].retval is None


@pytest.mark.parametrize(
    ("storage", "expected_changed"),
    [
        (TerminalReturnStorage8616.NONE, True),
        (TerminalReturnStorage8616.CALL_OUTPUT, True),
        (TerminalReturnStorage8616.AX, False),
    ],
)
def test_final_codegen_consumes_exact_terminal_storage(
    monkeypatch: pytest.MonkeyPatch,
    storage: TerminalReturnStorage8616,
    expected_changed: bool,
) -> None:
    project, codegen, function = _codegen_fixture()
    original = function.prototype
    monkeypatch.setattr(
        unused_void_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: storage,
    )

    result = materialize_unused_caller_void_codegen_type_8616(project, codegen)

    assert result.changed is expected_changed
    if expected_changed:
        assert result.stats == UnusedVoidReturnTypeStats8616(4, 4, 4, 2, 0)
        assert isinstance(function.prototype.returnty, SimTypeBottom)
        assert codegen.cfunc.statements.statements[0].retval is None
    else:
        assert result.stats == UnusedVoidReturnTypeStats8616()
        assert function.prototype is original
        assert codegen.cfunc.statements.statements[0].retval is not None


def test_final_codegen_reuses_precomputed_terminal_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sibling lowering consumer must not decode terminal storage twice."""
    project, codegen, function = _codegen_fixture()
    original = function.prototype
    monkeypatch.setattr(
        unused_void_return_types,
        "terminal_return_storage_8616",
        lambda *_args: pytest.fail("precomputed terminal storage must be reused"),
    )

    result = materialize_unused_caller_void_codegen_type_8616(
        project,
        codegen,
        terminal_storage_input=TerminalReturnStorageInput8616(TerminalReturnStorage8616.AX),
    )

    assert result.changed is False
    assert function.prototype is original


def test_exact_empty_terminal_storage_overrides_false_caller_result_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A restored AX is preservation even when a caller reads AX after the call."""
    project, codegen, function = _codegen_fixture()
    monkeypatch.setattr(
        unused_void_return_types,
        "proven_function_result_observation_8616",
        lambda _project, _addr: CallerReturnUseVerdict8616.USED,
    )
    monkeypatch.setattr(
        unused_void_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.NONE,
    )

    result = materialize_unused_caller_void_codegen_type_8616(project, codegen)

    assert result.changed is True
    assert isinstance(function.prototype.returnty, SimTypeBottom)
    assert codegen.cfunc.statements.statements[0].retval is None


@pytest.mark.parametrize(("value", "expected_changed"), [(0, True), (1, False)])
def test_unused_zero_return_is_synthetic_despite_terminal_ax(
    monkeypatch: pytest.MonkeyPatch,
    value: int,
    expected_changed: bool,
) -> None:
    project, codegen, function = _codegen_fixture(return_constant=value)
    monkeypatch.setattr(
        unused_void_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AX,
    )

    result = materialize_unused_caller_void_codegen_type_8616(project, codegen)

    assert result.changed is expected_changed
    assert isinstance(function.prototype.returnty, SimTypeBottom) is expected_changed
    assert (codegen.cfunc.statements.statements[0].retval is None) is expected_changed


def test_exact_empty_terminal_storage_refuses_effectful_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project, codegen, _function = _codegen_fixture(effectful=True)
    monkeypatch.setattr(
        unused_void_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.NONE,
    )

    with pytest.raises(PipelineHardError, match="non-synthetic C return values"):
        materialize_unused_caller_void_codegen_type_8616(project, codegen)


@pytest.mark.parametrize(
    ("storage", "expected_void"),
    [
        (TerminalReturnStorage8616.NONE, True),
        (TerminalReturnStorage8616.CALL_OUTPUT, True),
        (TerminalReturnStorage8616.AX, False),
    ],
)
def test_callee_void_evidence_joins_unused_callers_with_terminal_storage(
    monkeypatch: pytest.MonkeyPatch,
    storage: TerminalReturnStorage8616,
    expected_void: bool,
) -> None:
    arch, function, _prototype = _function_fixture()
    project = SimpleNamespace(
        arch=arch,
        kb=SimpleNamespace(functions=_FunctionManager(function)),
    )
    _record_caller_result(project, CallerReturnUseVerdict8616.UNUSED)
    monkeypatch.setattr(
        return_type_evidence,
        "terminal_return_storage_8616",
        lambda _project, _function: storage,
    )

    evidence = collect_unobserved_callee_void_evidence_8616(project, function.addr)

    assert evidence.proves_void is expected_void
    assert evidence.raw_fact_count == evidence.materialized_count == 2
    assert evidence.failure_count == 0
