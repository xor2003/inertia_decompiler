from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CIndexedVariable,
    CStatements,
    CStructField,
    CVariable,
    CVariableField,
)
from angr.sim_type import SimStruct, SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFact8616,
    DirectStackMoveSourceKind8616,
    materialize_direct_stack_mov_instructions_8616,
)


class _Codegen:
    """Minimal third-party codegen surface for direct-stack materialization."""

    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False
        root = CStatements([], addr=0x4010, codegen=self)
        self.cfunc = SimpleNamespace(
            addr=0x4010,
            statements=root,
            body=root,
            arg_list=[],
            variables_in_use={},
            unified_local_vars={},
        )

    def next_idx(self, _name: str) -> int:
        """Return one deterministic structured-codegen node identifier."""
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        """Return one deterministic structured-codegen node identifier."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep deterministic test identifiers unchanged."""
        return name


def _projected_field(codegen: _Codegen, index: CVariable) -> CVariableField:
    """Build the typed two-byte aggregate projection used after global lowering."""
    aggregate_type = SimStruct(
        {"field_0": SimTypeChar(False), "field_1": SimTypeChar(False)},
        name="g_0B4C_entry",
        pack=True,
    ).with_arch(codegen.project.arch)
    global_base = CVariable(
        SimMemoryVariable(0x0B4C, 2, name="g_0B4C", region=0x4010),
        variable_type=aggregate_type,
        codegen=codegen,
    )
    return CVariableField(
        CIndexedVariable(global_base, index, variable_type=aggregate_type, codegen=codegen),
        CStructField(aggregate_type, 0, "field_0", codegen=codegen),
        codegen=codegen,
    )


def test_only_exact_indexed_projection_stabilizes_segmented_stack_replay() -> None:
    """Reject BP+4 but accept the binary-proven BP+6 global projection."""
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    dst_variable = SimStackVariable(-4, 2, base="bp", name="pivot", region=0x4010)
    low_variable = SimStackVariable(4, 2, base="bp", name="low", region=0x4010)
    high_variable = SimStackVariable(6, 2, base="bp", name="high", region=0x4010)
    dst = CVariable(dst_variable, variable_type=SimTypeShort(False), codegen=codegen)
    low = CVariable(low_variable, variable_type=SimTypeShort(False), codegen=codegen)
    high = CVariable(high_variable, variable_type=SimTypeShort(False), codegen=codegen)
    for variable, cvar in ((dst_variable, dst), (low_variable, low), (high_variable, high)):
        codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.arg_list = [low, high]
    register = CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements.statements.append(
        CAssignment(dst, register, codegen=codegen, tags={"ins_addr": 0x401A})
    )
    fact = DirectStackMoveFact8616(
        dst_offset=-4,
        width=2,
        source_kind=DirectStackMoveSourceKind8616.SEGMENTED_MEMORY,
        ins_addr=0x401A,
        source_segment_name="ds",
        source_displacement=0x0B4C,
        source_index_offset=6,
        source_index_shift=1,
        source_access_width=1,
        source_sign_extend=True,
    )
    function = SimpleNamespace(
        addr=0x4010,
        blocks=(),
        _inertia_direct_stack_move_instruction_facts_8616=(fact,),
    )
    def replay() -> bool:
        """Replay the one binary-proven segmented stack move."""
        return materialize_direct_stack_mov_instructions_8616(
            codegen,
            project=project,
            function=function,
            materialize_reloads=False,
        )

    assert replay()
    assignment = codegen.cfunc.statements.statements[0]
    assignment.rhs = _projected_field(codegen, low)
    assert replay()
    assignment.rhs = _projected_field(codegen, high)
    assert not replay()
    assert assignment.rhs.variable.index is high
    stats = codegen._inertia_direct_stack_move_lowering_8616
    assert stats["already_materialized_count"] == 2
    assert stats["stale_evidence_rematerialized_count"] == 1
