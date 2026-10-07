from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CForLoop,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.postprocess.affine_compound_assignment import (
    restore_affine_compound_assignment_identity_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.const_formats: dict[int, dict[str, bool]] = {}
        self.display_vvar_ids = False
        self.use_compound_assignments = True
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _local(name: str, offset: int, codegen: _Codegen) -> CVariable:
    return CVariable(
        SimStackVariable(offset, 2, base="bp", name=name, region=0x4010),
        codegen=codegen,
    )


def _const(value: int, codegen: _Codegen) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _codegen_with_iterator(*, same_storage: bool) -> tuple[_Codegen, CAssignment]:
    codegen = _Codegen()
    lhs = _local("i", -4, codegen)
    rhs_lhs = _local("i" if same_storage else "j", -4 if same_storage else -6, codegen)
    iterator = CAssignment(
        lhs,
        CBinaryOp("Add", rhs_lhs, _const(1, codegen), codegen=codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        None,
        CBinaryOp("CmpLT", lhs, _const(8, codegen), codegen=codegen),
        iterator,
        CStatements([], codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([loop], codegen=codegen))
    return codegen, iterator


def _render_assignment(assignment: CAssignment) -> str:
    return "".join(text for text, _obj in assignment.c_repr_chunks(asexpr=True))


def test_restores_compound_render_identity_for_exact_affine_iterator() -> None:
    codegen, iterator = _codegen_with_iterator(same_storage=True)

    stats = restore_affine_compound_assignment_identity_8616(codegen)

    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0
    assert _render_assignment(iterator) == "i += 1"


def test_refuses_compound_render_identity_for_different_storage() -> None:
    codegen, iterator = _codegen_with_iterator(same_storage=False)

    stats = restore_affine_compound_assignment_identity_8616(codegen)

    assert stats.raw_fact_count == 1
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 0
    assert _render_assignment(iterator) == "i = j + 1"
