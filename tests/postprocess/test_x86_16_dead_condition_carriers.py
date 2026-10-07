"""Focused tests for evidence-gated virtual condition-carrier cleanup."""

from types import SimpleNamespace

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CIfElse,
    CReturn,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.postprocess.decompiler_postprocess_stage import finalize_late_ast_cleanup_8616

from inertia.postprocess.optimization.dead_condition_carriers import (
    prune_unread_pure_condition_carriers_8616,
)


class _Codegen:
    """Minimal dynamic angr codegen boundary for carrier tests."""

    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.stmt_comments: dict[int, str] = {}
        self.expr_comments: dict[int, str] = {}
        self._next_idx = 0
        self.cfunc = SimpleNamespace(statements=CStatements([], codegen=self))

    def next_idx(self, _name: str) -> int:
        """Return one deterministic C-AST node index."""
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _vvar(codegen: _Codegen, vvar_id: int) -> CVariable:
    """Build one virtual register carrier without relying on its rendered name."""
    variable = SimRegisterVariable(0, 2, name=f"carrier_{vvar_id}")
    return CVariable(variable, variable_type=SimTypeShort(False), vvar_id=vvar_id, codegen=codegen)


def _comparison(codegen: _Codegen) -> CBinaryOp:
    """Build one pure borrow-shaped comparison expression."""
    return CBinaryOp(
        "CmpLT",
        _vvar(codegen, 10),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )


def _dirty_vvar(codegen: _Codegen, vvar_id: int) -> CDirtyExpression:
    """Build the AIL virtual-variable wrapper emitted by real structured codegen."""
    dirty = VirtualVariable(
        codegen.next_idx("ail_vvar"),
        vvar_id,
        16,
        VirtualVariableCategory.REGISTER,
        oident=0,
    )
    return CDirtyExpression(dirty, codegen=codegen)


def _dirty_comparison(codegen: _Codegen) -> CBinaryOp:
    """Build a comparison whose operands retain their AIL virtual identities."""
    return CBinaryOp(
        "CmpLT",
        _dirty_vvar(codegen, 10),
        CConstant(7, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )


def test_prunes_unique_unread_pure_condition_carrier() -> None:
    """An unread SSA comparison result has no observable C semantics."""
    codegen = _Codegen()
    assignment = CAssignment(_vvar(codegen, 11), _comparison(codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert codegen.cfunc.statements.statements == []
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0


def test_prunes_real_codegen_dirty_virtual_condition_carrier() -> None:
    """A CDirtyExpression wrapping an AIL vvar uses varid as exact identity."""
    codegen = _Codegen()
    assignment = CAssignment(_dirty_vvar(codegen, 11), _dirty_comparison(codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert codegen.cfunc.statements.statements == []
    assert stats.materialized_count == 1


def test_nested_definition_is_not_double_counted_as_a_read() -> None:
    """Parent structured containers do not turn nested definitions into uses."""
    codegen = _Codegen()
    assignment = CAssignment(_dirty_vvar(codegen, 11), _dirty_comparison(codegen), codegen=codegen)
    body = CStatements([assignment], codegen=codegen)
    guarded = CIfElse(
        [(CConstant(1, SimTypeShort(False), codegen=codegen), body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([guarded], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert body.statements == []
    assert stats.materialized_count == 1


def test_late_cleanup_prunes_empty_guard_before_its_condition_carrier() -> None:
    """Late cleanup removes a no-op consumer before recomputing carrier liveness."""
    codegen = _Codegen()
    assignment = CAssignment(_dirty_vvar(codegen, 11), _dirty_comparison(codegen), codegen=codegen)
    empty_guard = CIfElse(
        [(_dirty_vvar(codegen, 11), CStatements([], codegen=codegen))],
        else_node=CStatements([], codegen=codegen),
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([assignment, empty_guard], codegen=codegen)

    result = finalize_late_ast_cleanup_8616(SimpleNamespace(), codegen)

    assert codegen.cfunc.statements.statements == []
    assert result.empty_noop_guard_changed is True
    assert result.dead_condition_carrier_changed is True


def test_keeps_dirty_virtual_condition_carrier_when_exact_varid_is_read() -> None:
    """The AIL varid identity refuses cleanup when the carrier is consumed."""
    codegen = _Codegen()
    assignment = CAssignment(_dirty_vvar(codegen, 11), _dirty_comparison(codegen), codegen=codegen)
    returned = CReturn(_dirty_vvar(codegen, 11), codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment, returned], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert codegen.cfunc.statements.statements == [assignment, returned]
    assert stats.live_refusal_count == 1


def test_keeps_condition_carrier_when_exact_vvar_is_read() -> None:
    """A structured consumer makes the virtual condition result live."""
    codegen = _Codegen()
    assignment = CAssignment(_vvar(codegen, 11), _comparison(codegen), codegen=codegen)
    returned = CReturn(_vvar(codegen, 11), codegen=codegen)
    codegen.cfunc.statements = CStatements([assignment, returned], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert codegen.cfunc.statements.statements == [assignment, returned]
    assert stats.materialized_count == 0
    assert stats.live_refusal_count == 1


def test_keeps_non_condition_virtual_assignment() -> None:
    """The narrow cleanup does not become a general virtual-register DCE pass."""
    codegen = _Codegen()
    assignment = CAssignment(
        _vvar(codegen, 11),
        CConstant(1, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([assignment], codegen=codegen)

    stats = prune_unread_pure_condition_carriers_8616(codegen)

    assert codegen.cfunc.statements.statements == [assignment]
    assert stats.raw_fact_count == 0
