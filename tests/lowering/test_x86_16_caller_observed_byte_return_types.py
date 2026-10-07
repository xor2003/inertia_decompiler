"""Caller-observed byte return prototype projection tests."""

from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.caller_return_use_contracts import (
    AxValueView8616,
    ByteReturnExtensionKind8616,
    CallerReturnUseFact8616,
    CallerReturnUseVerdict8616,
    CallsiteReturnUseKind8616,
)
import inertia.lowering.caller_observed_byte_return_types as byte_types
import inertia.lowering.terminal_register_return_types as terminal_register_return_types
from inertia.lowering.interprocedural_storage_contracts import (
    StorageIdentity8616,
    StorageIdentityKind8616,
    StorageTrialSignedness8616,
    StorageTrialStats8616,
    StorageTrialValueClass8616,
)
from inertia.lowering.interprocedural_storage_return_type_collection_contracts import (
    FunctionReturnStorageTypeFailure8616,
    FunctionReturnStorageTypeResult8616,
    FunctionReturnStorageTypeVerdict8616,
)
from inertia.lowering.interprocedural_storage_return_types import (
    classify_return_storage_type_8616,
)
from inertia.lowering.terminal_register_return_types import (
    apply_terminal_register_return_type_evidence_8616,
    materialize_terminal_register_return_type_8616,
)

from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.semantics.terminal_return_storage import TerminalReturnStorage8616


class _FunctionManager:
    """Minimal function manager for terminal projection tests."""

    def __init__(self, function: SimpleNamespace) -> None:
        self.function_value = function

    def function(self, *, addr: int, create: bool) -> SimpleNamespace | None:
        """Return the exact retained function without creating one."""
        assert create is False
        return self.function_value if addr == self.function_value.addr else None


def _unsigned_evidence() -> FunctionReturnStorageTypeResult8616:
    """Build one complete unsigned AL aggregate from an extension witness."""
    fact = CallerReturnUseFact8616(
        caller_addr=0x2000,
        callsite_addr=0x2010,
        verdict=CallerReturnUseVerdict8616.USED,
        kind=CallsiteReturnUseKind8616.VALUE,
        witness_instruction_addr=0x2018,
        byte_extension=ByteReturnExtensionKind8616.ZERO_EXTEND_AL_TO_AX,
        byte_extension_instruction_addr=0x2016,
        observed_value_view=AxValueView8616.AX,
    )
    classification = classify_return_storage_type_8616(
        fact,
        (
            StorageIdentity8616(
                kind=StorageIdentityKind8616.REGISTER,
                width=1,
                register="al",
            ),
        ),
        (),
    )
    assert classification.complete
    return FunctionReturnStorageTypeResult8616(
        function_addr=0x1000,
        verdict=FunctionReturnStorageTypeVerdict8616.PROVEN,
        signedness=StorageTrialSignedness8616.UNSIGNED,
        value_class=StorageTrialValueClass8616.VALUE,
        classifications=(classification,),
        neutral_fact_count=0,
        failure=None,
        stats=StorageTrialStats8616(1, 1, 1, 1, 0),
    )


def _refused_evidence() -> FunctionReturnStorageTypeResult8616:
    """Build one typed refusal for an unavailable complete caller census."""
    return FunctionReturnStorageTypeResult8616(
        function_addr=0x1000,
        verdict=FunctionReturnStorageTypeVerdict8616.UNKNOWN_REFUSE,
        signedness=None,
        value_class=None,
        classifications=(),
        neutral_fact_count=0,
        failure=FunctionReturnStorageTypeFailure8616.EVIDENCE_UNAVAILABLE,
        stats=StorageTrialStats8616(0, 0, 0, 0, 1),
    )


def test_terminal_al_projection_updates_both_generated_prototypes(monkeypatch) -> None:
    """Caller proof keeps the Function and CFunction type projections coherent."""
    arch = Arch86_16()
    original = SimTypeFunction(
        [SimTypeShort(signed=True)],
        SimTypeChar(signed=True),
        arg_names=("value",),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={},
        is_prototype_guessed=True,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AL,
    )
    monkeypatch.setattr(
        byte_types,
        "collect_function_return_storage_type_8616",
        lambda _project, _addr, _storages: _unsigned_evidence(),
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is True
    assert result.stats == terminal_register_return_types.TerminalRegisterReturnTypeStats8616(1, 1, 1, 1, 0)
    assert isinstance(codegen.cfunc.functy.returnty, SimTypeChar)
    assert codegen.cfunc.functy.returnty.signed is False
    assert codegen.cfunc.functy.returnty.c_repr(name="").strip() == "unsigned char"
    assert codegen.cfunc.functy.args == original.args
    assert codegen.cfunc.functy.arg_names == original.arg_names
    assert isinstance(function.prototype.returnty, SimTypeChar)
    assert function.prototype.returnty.signed is False
    assert function.prototype.returnty.c_repr(name="").strip() == "unsigned char"
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True


def test_terminal_al_projection_refuses_incomplete_caller_evidence(monkeypatch) -> None:
    """Incomplete caller evidence keeps both generated prototypes unchanged."""
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, is_prototype_guessed=True, prototype=original)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(functy=original),
        _inertia_codegen_decl_refresh_required_8616=False,
        _inertia_force_codegen_regeneration_8616=False,
    )
    project = SimpleNamespace(arch=arch)
    monkeypatch.setattr(
        byte_types,
        "collect_function_return_storage_type_8616",
        lambda _project, _addr, _storages: _refused_evidence(),
    )

    result = byte_types.materialize_caller_observed_byte_return_type_8616(
        project,
        codegen,
        function,
        TerminalReturnStorage8616.AL,
        explicit_prototype=False,
    )

    assert result.verdict is byte_types.CallerObservedByteReturnTypeVerdict8616.UNKNOWN_REFUSE
    assert result.failure is byte_types.CallerObservedByteReturnTypeFailure8616.EVIDENCE_REFUSED
    assert result.evidence == _refused_evidence()
    assert result.changed is False
    assert codegen.cfunc.functy is original
    assert function.prototype is original
    assert codegen._inertia_codegen_decl_refresh_required_8616 is False
    assert codegen._inertia_force_codegen_regeneration_8616 is False


def test_terminal_al_projection_reports_function_prototype_conflict() -> None:
    """An incompatible Function return type cannot be hidden by CFunction projection."""
    arch = Arch86_16()
    function_prototype = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(arch)
    codegen_prototype = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(addr=0x1000, is_prototype_guessed=True, prototype=function_prototype)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(functy=codegen_prototype),
        _inertia_codegen_decl_refresh_required_8616=False,
        _inertia_force_codegen_regeneration_8616=False,
    )

    result = byte_types.materialize_caller_observed_byte_return_type_8616(
        SimpleNamespace(arch=arch),
        codegen,
        function,
        TerminalReturnStorage8616.AL,
        explicit_prototype=False,
    )

    assert result.verdict is byte_types.CallerObservedByteReturnTypeVerdict8616.CONFLICT
    assert result.failure is byte_types.CallerObservedByteReturnTypeFailure8616.FUNCTION_PROTOTYPE_CONFLICT
    assert result.evidence is None
    assert result.changed is False
    assert codegen.cfunc.functy is codegen_prototype
    assert function.prototype is function_prototype
    assert codegen._inertia_codegen_decl_refresh_required_8616 is False
    assert codegen._inertia_force_codegen_regeneration_8616 is False


def test_terminal_al_projection_seeds_guessed_void_return(monkeypatch) -> None:
    """Early return-only evidence does not freeze or discard guessed arguments."""
    arch = Arch86_16()
    original = SimTypeFunction(
        [SimTypeShort(signed=True)],
        SimTypeBottom(label="void"),
        arg_names=("value",),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={},
        is_prototype_guessed=True,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AL,
    )
    monkeypatch.setattr(
        byte_types,
        "collect_function_return_storage_type_8616",
        lambda _project, _addr, _storages: _unsigned_evidence(),
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is True
    assert isinstance(function.prototype.returnty, SimTypeChar)
    assert function.prototype.returnty.signed is False
    assert function.prototype.args == original.args
    assert function.prototype.arg_names == original.arg_names
    assert function.is_prototype_guessed is True


def test_terminal_al_projection_refines_inferred_non_guessed_return(monkeypatch) -> None:
    """The angr guessed flag does not make an unannotated prototype authoritative."""
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={},
        is_prototype_guessed=False,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch)
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AL,
    )
    monkeypatch.setattr(
        byte_types,
        "collect_function_return_storage_type_8616",
        lambda _project, _addr, _storages: _unsigned_evidence(),
    )

    result = apply_terminal_register_return_type_evidence_8616(project, function)

    assert result.changed is True
    assert isinstance(function.prototype.returnty, SimTypeChar)
    assert function.prototype.returnty.signed is False
    assert function.is_prototype_guessed is False


def test_terminal_al_projection_preserves_explicit_prototype(monkeypatch) -> None:
    """Source/debug prototypes remain authoritative over caller inference."""
    arch = Arch86_16()
    original = SimTypeFunction([], SimTypeChar(signed=True)).with_arch(arch)
    function = SimpleNamespace(
        addr=0x1000,
        block_addrs_set={0x1000},
        info={ANNOTATION_KEY: {"prototype": original}},
        is_prototype_guessed=False,
        prototype=original,
    )
    project = SimpleNamespace(arch=arch, kb=SimpleNamespace(functions=_FunctionManager(function)))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, functy=original))
    monkeypatch.setattr(
        terminal_register_return_types,
        "terminal_return_storage_8616",
        lambda _project, _function: TerminalReturnStorage8616.AL,
    )

    result = materialize_terminal_register_return_type_8616(project, codegen)

    assert result.changed is False
    assert codegen.cfunc.functy is original
    assert function.prototype is original
