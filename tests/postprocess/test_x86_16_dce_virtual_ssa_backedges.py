"""Regression tests for virtual-SSA liveness across structured loop backedges."""

from types import SimpleNamespace

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.postprocess.optimization.dce import _dead_code_elimination_8616


class _Codegen:
    """Minimal dynamic angr codegen boundary for DCE tests."""

    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self.stmt_comments: dict[int, str] = {}
        self.expr_comments: dict[int, str] = {}
        self._next_idx = 0
        self.cfunc = SimpleNamespace(statements=structured_c.CStatements([], codegen=self))
        self._inertia_dce_allow_storage_free_dirty_8616 = True
        self._inertia_dce_allow_dirty_value_reads_8616 = True

    def next_idx(self, _name: str) -> int:
        """Return one deterministic C-AST node index."""
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        """Return one deterministic C-AST node index for current angr APIs."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Return a deterministic generated identifier."""
        return name


def _dirty_tmp(codegen: _Codegen, varid: int) -> structured_c.CDirtyExpression:
    """Build one storage-free AIL SSA temporary."""
    virtual = VirtualVariable(
        codegen.next_idx("ail_vvar"),
        varid,
        16,
        VirtualVariableCategory.TMP,
    )
    return structured_c.CDirtyExpression(virtual, codegen=codegen)


def _cyclic_carrier_slice(codegen: _Codegen) -> list[structured_c.CAssignment]:
    """Build a pure dead carrier cycle exposed after semantic materialization."""
    return [
        structured_c.CAssignment(
            _dirty_tmp(codegen, 932),
            _dirty_tmp(codegen, 12),
            tags={"ins_addr": 0x103D5},
            codegen=codegen,
        ),
        structured_c.CAssignment(
            _dirty_tmp(codegen, 933),
            _dirty_tmp(codegen, 932),
            tags={"ins_addr": 0x103D5},
            codegen=codegen,
        ),
        structured_c.CAssignment(
            _dirty_tmp(codegen, 12),
            _dirty_tmp(codegen, 933),
            tags={"ins_addr": 0x103D5},
            codegen=codegen,
        ),
    ]


def test_dce_does_not_treat_virtual_ssa_cycle_as_loop_carried_storage() -> None:
    """A dead SSA cycle must not survive solely because it is inside a loop."""
    codegen = _Codegen()
    body = structured_c.CStatements(_cyclic_carrier_slice(codegen), codegen=codegen)
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        body,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert body.statements == []


def test_dce_does_not_merge_virtual_ssa_liveness_across_switch_arms() -> None:
    """Mutually exclusive arms do not create outside uses for virtual SSA."""
    codegen = _Codegen()
    first_body = structured_c.CStatements(_cyclic_carrier_slice(codegen), codegen=codegen)
    second_body = structured_c.CStatements(_cyclic_carrier_slice(codegen), codegen=codegen)
    switch = structured_c.CSwitchCase(
        _dirty_tmp(codegen, 700),
        [(1, first_body), (2, second_body)],
        None,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([switch], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is True
    assert first_body.statements == []
    assert second_body.statements == []


def test_dce_keeps_virtual_ssa_cycle_reaching_observable_sink() -> None:
    """Observable consumption still keeps every required virtual definition."""
    codegen = _Codegen()
    carriers = _cyclic_carrier_slice(codegen)
    sink = structured_c.CVariable(
        SimMemoryVariable(0x44, 2, name="g_sink"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    observable = structured_c.CAssignment(
        sink,
        _dirty_tmp(codegen, 12),
        codegen=codegen,
    )
    body = structured_c.CStatements([*carriers, observable], codegen=codegen)
    loop = structured_c.CWhileLoop(
        structured_c.CConstant(1, SimTypeShort(False), codegen=codegen),
        body,
        codegen=codegen,
    )
    codegen.cfunc.statements = structured_c.CStatements([loop], codegen=codegen)

    changed = _dead_code_elimination_8616(codegen)

    assert changed is False
    assert body.statements == [*carriers, observable]
