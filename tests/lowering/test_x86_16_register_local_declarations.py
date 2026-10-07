"""Tests for Types/Lowering-owned register-local declaration publication."""

from __future__ import annotations

from types import SimpleNamespace

from angr.ailment import Expr
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CIfElse,
    CStatements,
    CVariable,
)
from angr.rustylib.ailment import VirtualVariableCategory
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_stage import (
    _repair_missing_cnode_codegen_metadata_8616,
)
from inertia.lowering.register_local_declarations import (
    materialize_typed_register_locals_8616,
    register_typed_register_local_8616,
)


class _VariableManager:
    """Minimal angr variable-manager boundary for unified identity tests."""

    def __init__(self, unified_by_variable: dict[object, object]) -> None:
        self._unified_by_variable = dict(unified_by_variable)

    def unified_variable(self, variable: object) -> object | None:
        """Return the configured exact unified identity."""
        return self._unified_by_variable.get(variable)


class _Codegen:
    """Minimal structured-codegen constructor boundary."""

    def __init__(self) -> None:
        self._idx = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        """Return one stable node index."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return one stable node index through angr's alternate API."""
        return self.next_idx("")

    @staticmethod
    def next_ident(name: str) -> str:
        """Return a deterministic display identity."""
        return name


def _codegen_with_register(
    *,
    variable_type: object | None,
    unified_variable: SimRegisterVariable | None = None,
) -> tuple[_Codegen, CVariable, SimRegisterVariable]:
    """Build one register use inside a structured condition."""
    codegen = _Codegen()
    variable = SimRegisterVariable(0, 2, name="ax")
    manager = _VariableManager({variable: unified_variable} if unified_variable is not None else {})
    declaration = CVariable(variable, variable_type=variable_type, codegen=codegen)
    condition = CBinaryOp(
        "CmpLT",
        declaration,
        CConstant(3, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    root = CStatements(
        [CIfElse([(condition, CStatements([], codegen=codegen))], codegen=codegen)],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
        variable_manager=manager,
    )
    return codegen, declaration, variable


def test_register_typed_local_uses_exact_unified_identity() -> None:
    """The declaration owner must publish angr's exact unified identity."""
    unified = SimRegisterVariable(0, 2, name="v19")
    word_type = SimTypeShort(False)
    codegen, declaration, variable = _codegen_with_register(
        variable_type=word_type,
        unified_variable=unified,
    )

    assert register_typed_register_local_8616(codegen, declaration) is True
    assert declaration.unified_variable is unified
    assert codegen.cfunc.variables_in_use[variable] is declaration
    assert codegen.cfunc.unified_local_vars[unified] == {(declaration, word_type)}


def test_register_typed_local_removes_pre_unification_map_key() -> None:
    """A later exact unified identity must replace the provisional map key."""
    unified = SimRegisterVariable(0, 2, name="v19")
    word_type = SimTypeShort(False)
    codegen, declaration, variable = _codegen_with_register(
        variable_type=word_type,
        unified_variable=unified,
    )
    codegen.cfunc.unified_local_vars[variable] = {(declaration, word_type)}

    assert register_typed_register_local_8616(codegen, declaration) is True
    assert tuple(codegen.cfunc.unified_local_vars) == (unified,)
    assert next(iter(codegen.cfunc.unified_local_vars)) is unified
    assert codegen.cfunc.unified_local_vars[unified] == {(declaration, word_type)}


def test_register_typed_local_preserves_peers_and_replaces_stale_type() -> None:
    """Map repair removes only this declaration and its obsolete type entry."""
    unified = SimRegisterVariable(0, 2, name="v19")
    word_type = SimTypeShort(False)
    stale_type = SimTypeShort(True)
    codegen, declaration, _variable = _codegen_with_register(
        variable_type=word_type,
        unified_variable=unified,
    )
    peer_variable = SimRegisterVariable(2, 2, name="dx")
    peer_declaration = CVariable(peer_variable, variable_type=word_type, codegen=codegen)
    stale_identity = SimRegisterVariable(4, 2, name="stale_ax")
    codegen.cfunc.unified_local_vars[stale_identity] = {
        (declaration, stale_type),
        (peer_declaration, word_type),
    }
    codegen.cfunc.unified_local_vars[unified] = {(declaration, stale_type)}

    assert register_typed_register_local_8616(codegen, declaration) is True
    stale_entries = codegen.cfunc.unified_local_vars[stale_identity]
    assert len(stale_entries) == 1
    stale_peer, stale_peer_type = next(iter(stale_entries))
    assert stale_peer is peer_declaration
    assert stale_peer_type is word_type
    unified_entries = codegen.cfunc.unified_local_vars[unified]
    assert len(unified_entries) == 1
    current_declaration, current_type = next(iter(unified_entries))
    assert current_declaration is declaration
    assert current_type is declaration.variable_type
    assert register_typed_register_local_8616(codegen, declaration) is False


def test_materialize_typed_register_locals_closes_evidence_counters() -> None:
    """One typed register use must be classified and materialized exactly once."""
    codegen, declaration, variable = _codegen_with_register(variable_type=SimTypeShort(False))

    result = materialize_typed_register_locals_8616(codegen)

    assert result.raw_fact_count == 1
    assert result.normalized_fact_count == 1
    assert result.classified_fact_count == 1
    assert result.materialized_count == 1
    assert result.failure_count == 0
    assert result.closed is True
    assert result.changed is True
    assert codegen.cfunc.variables_in_use[variable] is declaration


def test_materialize_typed_register_locals_derives_type_from_exact_register_width() -> None:
    """Types/Lowering materializes scalar type when physical register width proves it."""
    codegen, declaration, variable = _codegen_with_register(variable_type=None)

    result = materialize_typed_register_locals_8616(codegen)

    assert result.failure_count == 0
    assert result.materialized_count == 1
    assert declaration.variable_type is not None
    assert declaration.variable_type.size == variable.size * 8


def test_materialize_typed_register_locals_resolves_untagged_register_shape() -> None:
    """An exact unique physical shape is sufficient when angr omits reg_name."""
    codegen = _Codegen()
    offset, size = codegen.project.arch.registers["di"]
    dirty = CDirtyExpression(
        Expr.VirtualVariable(
            1,
            3,
            size * 8,
            VirtualVariableCategory.REGISTER,
            oident=offset,
        ),
        codegen=codegen,
    )
    root = CStatements([dirty], codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        variables_in_use={},
        unified_local_vars={},
        variable_manager=_VariableManager({}),
    )

    result = materialize_typed_register_locals_8616(codegen)

    assert result.failure_count == 0
    assert result.materialized_count == 1
    replacement = root.statements[0]
    assert isinstance(replacement, CVariable)
    assert replacement.variable.name == "di"


def test_postprocess_metadata_repair_does_not_publish_declarations() -> None:
    """Rewrite may restore codegen pointers but cannot own register declarations."""
    codegen, declaration, _variable = _codegen_with_register(variable_type=SimTypeShort(False))
    declaration.codegen = None

    assert _repair_missing_cnode_codegen_metadata_8616(codegen.cfunc, codegen) > 0
    assert declaration.codegen is codegen
    assert codegen.cfunc.variables_in_use == {}
    assert codegen.cfunc.unified_local_vars == {}
