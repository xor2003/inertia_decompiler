"""Focused tests for Alias-proven GP stack restoration lowering."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.alias.segment_stack_restore import (
    StackRegisterRestoreArtifact8616,
    StackRegisterRestoreFact8616,
    StackRegisterRestoreVerdict8616,
)
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.gp_register_state import (
    runtime_gp_expression_view_8616,
)
from angr_platforms.X86_16.lowering.gp_stack_restore import (
    materialize_gp_stack_restores_8616,
)
from angr_platforms.X86_16.lowering.segmented_memory_lowering import (
    replay_final_codegen_projections_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError
from angr_platforms.X86_16.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen boundary for focused lowering tests."""

    cstyle_null_cmp = False
    _index = 0

    def next_node_idx(self) -> int:
        """Return one deterministic node index."""
        self._index += 1
        return self._index

    def next_ident(self, name: str) -> str:
        """Return the requested deterministic identifier."""
        return name


def _assignment(
    codegen: object,
    lhs: structured_c.CExpression,
    instruction_addr: int,
) -> structured_c.CAssignment:
    """Build one tagged assignment with an irrelevant initial RHS."""
    return structured_c.CAssignment(
        lhs,
        structured_c.CConstant(0, SimTypeChar(False), codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": instruction_addr},
    )


def _artifact() -> StackRegisterRestoreArtifact8616:
    """Return one proven AX save/restore fact."""
    return StackRegisterRestoreArtifact8616(
        facts=(
            StackRegisterRestoreFact8616(
                block_addr=0x1000,
                restore_instruction_addr=0x1008,
                restore_register="ax",
                saved_instruction_addr=0x1000,
                saved_register="ax",
                stack_offsets=(-2, -1),
                verdict=StackRegisterRestoreVerdict8616.PROVEN,
            ),
        ),
    )


def test_materializes_exact_ax_push_bytes_and_observes_pop_write() -> None:
    """A wide stack snapshot replaces the exact POP byte recomposition."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    low = _assignment(
        codegen,
        structured_c.CVariable(
            SimStackVariable(-2, 1, base="bp", name="local_2"),
            variable_type=SimTypeChar(False),
            codegen=codegen,
        ),
        0x1000,
    )
    high = _assignment(
        codegen,
        structured_c.CVariable(
            SimStackVariable(-1, 1, base="bp", name="local_1"),
            variable_type=SimTypeChar(False),
            codegen=codegen,
        ),
        0x1000,
    )
    ax_offset, ax_size = codegen.project.arch.registers["ax"]
    restore = structured_c.CAssignment(
        structured_c.CVariable(
            SimRegisterVariable(ax_offset, ax_size, name="ax"),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        ),
        structured_c.CBinaryOp(
            "Or",
            low.lhs,
            structured_c.CBinaryOp(
                "Shl",
                high.lhs,
                structured_c.CConstant(8, SimTypeChar(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1008},
    )
    marker = _assignment(codegen, low.lhs, 0x1001)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([marker, restore], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
    )
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()

    assert materialize_gp_stack_restores_8616(codegen) is True
    snapshot = codegen.cfunc.statements.statements[0]
    assert isinstance(snapshot, structured_c.CAssignment)
    assert runtime_gp_expression_view_8616(snapshot.rhs).register_name == "ax"
    assert isinstance(restore.rhs, structured_c.CVariable)
    assert restore.rhs.variable.size == 2
    assert restore.rhs.tags["inertia_x86_16_gp_stack_restore"] == (0x1000, 0x1008, "ax")
    assert codegen._inertia_gp_stack_restore_snapshots_8616 == (snapshot.lhs,)

    codegen.cfunc.statements.statements.remove(snapshot)
    marker.tags["ins_addr"] = 0x0
    unified_snapshot = SimStackVariable(-2, 2, base="bp", name="local_2")
    restore.rhs.unified_variable = unified_snapshot
    assert replay_final_codegen_projections_8616(codegen) is True
    snapshot = codegen.cfunc.statements.statements[0]
    assert isinstance(snapshot, structured_c.CAssignment)
    assert snapshot.lhs.variable is restore.rhs.variable
    assert snapshot.lhs.unified_variable is unified_snapshot

    _dead_code_elimination_8616(codegen)
    assert snapshot in codegen.cfunc.statements.statements
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.closed
    assert materialize_gp_stack_restores_8616(codegen) is False
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.materialized_count == 1


def test_materializes_restore_nested_in_terminal_return() -> None:
    """A terminal return owner accepts the proven save snapshot before it."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    low = _assignment(
        codegen,
        structured_c.CVariable(
            SimStackVariable(-2, 1, base="bp", name="local_2"),
            variable_type=SimTypeChar(False),
            codegen=codegen,
        ),
        0x1000,
    )
    high = _assignment(
        codegen,
        structured_c.CVariable(
            SimStackVariable(-1, 1, base="bp", name="local_1"),
            variable_type=SimTypeChar(False),
            codegen=codegen,
        ),
        0x1000,
    )
    restore = structured_c.CBinaryOp(
        "Or",
        low.lhs,
        structured_c.CBinaryOp(
            "Shl",
            high.lhs,
            structured_c.CConstant(8, SimTypeChar(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
        tags={"ins_addr": 0x1008},
    )
    terminal = structured_c.CReturn(
        restore,
        codegen=codegen,
        tags={"ins_addr": 0x1009},
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([terminal], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
    )
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()

    assert materialize_gp_stack_restores_8616(codegen) is True
    snapshot, observed_terminal = codegen.cfunc.statements.statements
    assert isinstance(snapshot, structured_c.CAssignment)
    assert runtime_gp_expression_view_8616(snapshot.rhs).register_name == "ax"
    assert observed_terminal is terminal
    assert isinstance(terminal.retval, structured_c.CVariable)
    assert terminal.retval.variable.size == 2
    assert terminal.retval.tags["inertia_x86_16_gp_stack_restore"] == (
        0x1000,
        0x1008,
        "ax",
    )
    assert codegen._inertia_gp_stack_restore_lowering_stats_8616.closed


def test_classified_restore_without_push_carriers_hard_fails() -> None:
    """Closed evidence accounting rejects a fact that cannot reach C."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=codegen),
        unified_local_vars={},
        variables_in_use={},
    )
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()

    with pytest.raises(PipelineHardError, match="classified but none materialized") as failure:
        materialize_gp_stack_restores_8616(codegen)
    assert failure.value.function_addr == codegen.cfunc.addr
    assert failure.value.details["restore_obligations"] == ((0x1008, "ax", (-2, -1)),)


def test_unmatched_restore_does_not_publish_snapshot_declarations() -> None:
    """A valid insertion point alone must not publish an unused stack snapshot."""
    codegen = _Codegen(project=SimpleNamespace(arch=Arch86_16()))
    local = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    restore = _assignment(codegen, local, 0x1008)
    declarations = {local.variable: {(local, local.type)}}
    uses = {local.variable: local}
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([restore], codegen=codegen),
        unified_local_vars=dict(declarations),
        variables_in_use=dict(uses),
    )
    codegen._inertia_stack_register_restore_artifact_8616 = _artifact()

    with pytest.raises(PipelineHardError, match="classified but none materialized"):
        materialize_gp_stack_restores_8616(codegen)

    assert codegen.cfunc.unified_local_vars == declarations
    assert codegen.cfunc.variables_in_use == uses
    assert codegen.cfunc.statements.statements == [restore]
    assert restore.lhs is local
    assert restore.rhs.value == 0
