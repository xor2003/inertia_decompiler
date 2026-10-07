"""Tests for typed register-indirect near-call carriers."""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeFunction, SimTypeLong, SimTypePointer, SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.near_pointer_type import SimTypeNearPointer16_8616
from inertia.lowering.register_indirect_call_targets import (
    materialize_register_indirect_call_target_types_8616,
)


class _Codegen(SimpleNamespace):
    """Minimal structured-codegen boundary used by the focused tests."""

    _next_node_index: int = 0

    def next_ident(self, class_name: str) -> str:
        """Allocate one deterministic structured-node display identity."""
        self._next_node_index += 1
        return f"{class_name}_{self._next_node_index}"

    def next_node_idx(self) -> int:
        """Allocate one deterministic structured-node numeric identity."""
        self._next_node_index += 1
        return self._next_node_index


class _VariableManager:
    """Preserve the exact unified register identity for declarations."""

    def unified_variable(self, variable: SimRegisterVariable) -> SimRegisterVariable:
        """Return the fixture's already unified register variable."""
        return variable


def _fixture() -> tuple[_Codegen, structured_c.CAssignment, structured_c.CFunctionCall]:
    """Build one AX load followed by an exact register-indirect call."""
    arch = Arch86_16()
    project = SimpleNamespace(arch=arch)
    codegen = _Codegen(project=project)
    ax_offset, ax_size = arch.registers["ax"]
    ax = SimRegisterVariable(
        ax_offset,
        ax_size,
        ident="ssa-ax-3",
        region=0x10000,
        name="v18",
    )
    scalar_type = SimTypeShort(False)
    declaration = structured_c.CVariable(
        ax,
        unified_variable=ax,
        variable_type=scalar_type,
        codegen=codegen,
    )
    lhs = structured_c.CVariable(
        ax,
        unified_variable=ax,
        variable_type=scalar_type,
        codegen=codegen,
    )
    load = structured_c.CFunctionCall(
        "SEG_U16",
        None,
        [
            structured_c.CConstant(0x245A, scalar_type, codegen=codegen),
            structured_c.CConstant(0, scalar_type, codegen=codegen),
        ],
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(lhs, load, codegen=codegen, tags={"ins_addr": 0x10052})
    target = structured_c.CVariable(
        ax,
        unified_variable=ax,
        variable_type=SimTypePointer(scalar_type),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        target,
        None,
        [],
        codegen=codegen,
        tags={"ins_addr": 0x10069},
    )
    statements = structured_c.CStatements([assignment, call], addr=0x10000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x10000,
        body=None,
        statements=statements,
        variable_manager=_VariableManager(),
        variables_in_use={ax: declaration},
        unified_local_vars={ax: {(declaration, scalar_type)}},
    )
    codegen._inertia_callsite_summary_inventory_8616 = {
        0x10069: CallsiteSummary8616(
            callsite_addr=0x10069,
            target_addr=None,
            return_addr=0x1006B,
            kind="near-indirect",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
            return_shape="ax",
            target_source=("reg", "ax"),
        )
    }
    return codegen, assignment, call


def test_materializes_register_indirect_near_function_pointer() -> None:
    """An exact call-AX summary types its local and scalar load coherently."""
    codegen, assignment, call = _fixture()

    assert materialize_register_indirect_call_target_types_8616(codegen) is True

    target_type = call.callee_target.variable_type
    assert isinstance(target_type, SimTypeNearPointer16_8616)
    assert target_type.size == 16
    assert isinstance(target_type.pts_to, SimTypeFunction)
    assert target_type.pts_to.args == ()
    assert isinstance(target_type.pts_to.returnty, SimTypeShort)
    assert isinstance(assignment.rhs, structured_c.CTypeCast)
    assert isinstance(assignment.rhs.dst_type, SimTypeNearPointer16_8616)
    assert isinstance(assignment.rhs.expr, structured_c.CTypeCast)
    assert isinstance(assignment.rhs.expr.dst_type, SimTypeLong)
    declaration = next(iter(codegen.cfunc.variables_in_use.values()))
    assert declaration.variable_type == target_type
    assert codegen.cfunc.unified_local_vars[declaration.variable] == {(declaration, target_type)}
    stats = codegen._inertia_register_indirect_call_target_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_register_indirect_target_materialization_is_idempotent() -> None:
    """Replaying the lowering preserves the already typed near-pointer cast."""
    codegen, assignment, _call = _fixture()
    assert materialize_register_indirect_call_target_types_8616(codegen) is True
    first_rhs = assignment.rhs

    assert materialize_register_indirect_call_target_types_8616(codegen) is False
    assert assignment.rhs is first_rhs
    assert codegen._inertia_register_indirect_call_target_stats_8616.materialized_count == 1
