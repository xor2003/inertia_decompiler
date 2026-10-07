from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort
from angr.sim_variable import (
    SimMemoryVariable,
    SimStackVariable,
    SimTemporaryVariable,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.lowering.logical_word_memory_copy_materialization import (
    materialize_logical_word_memory_copies_8616,
)

from inertia.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from inertia.pipeline.structured_ast_query_index import StructuredAstQuerySession8616
from inertia.widening.logical_word_memory_copies import (
    LogicalWordMemoryCopyFailure8616,
    build_logical_word_memory_copy_artifact_8616,
)
from tests.fixtures.x86_16_logical_memory_fixtures import lift_ir_artifact


class _Codegen:
    def __init__(self, source: object) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self._inertia_stack_memory_ssa_alias_artifact = source
        self.cstyle_null_cmp = False
        self.cfunc: object | None = None
        self._idx = 0

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _alias_artifact(code: str):
    ssa = build_x86_16_function_ssa(lift_ir_artifact(bytes.fromhex(code)))
    return build_x86_16_stack_memory_ssa_alias_artifact(ssa)


def _copy_assignment_fixture():
    alias = _alias_artifact("8b4604a3007090c3")
    codegen = _Codegen(alias)
    arch = codegen.project.arch
    source = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="DLC"),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    temporary = structured_c.CVariable(
        SimTemporaryVariable(1, 1),
        variable_type=SimTypeChar(False).with_arch(arch),
        codegen=codegen,
    )
    rhs = structured_c.CBinaryOp(
        "Or",
        source,
        structured_c.CBinaryOp(
            "Shl",
            temporary,
            structured_c.CConstant(
                8,
                SimTypeShort(False).with_arch(arch),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    destination = structured_c.CVariable(
        SimMemoryVariable(0x7000, 2, name="DirectLiftControl"),
        variable_type=SimTypeShort(False).with_arch(arch),
        codegen=codegen,
    )
    assignment = structured_c.CAssignment(
        destination,
        rhs,
        codegen=codegen,
        tags={"ins_addr": 0x1003},
    )
    body = structured_c.CStatements([assignment], codegen=codegen)
    prototype = SimTypeFunction(
        (SimTypeShort(False),),
        SimTypeShort(True),
        arg_names=("DLC",),
    ).with_arch(arch)
    codegen.cfunc = structured_c.CFunction(
        0x1000,
        "SetDLC",
        prototype,
        [source],
        body,
        {},
        SimpleNamespace(),
        codegen=codegen,
    )
    return codegen, assignment, source, temporary


def test_exact_stack_reload_to_direct_ds_spill_closes_copy_fact() -> None:
    artifact = build_logical_word_memory_copy_artifact_8616(
        _alias_artifact("8b4604a3007090c3")
    )

    assert artifact.complete
    assert artifact.stats.raw_fact_count == artifact.stats.materialized_count == 1
    assert artifact.refusals == ()
    fact = artifact.facts[0]
    assert fact.source_transfer.access.address.offset == 4
    assert fact.destination_transfer.access.address.offset == 0x7000
    assert fact.source_transfer.register == fact.destination_transfer.register


def test_register_update_between_reload_and_spill_refuses_copy() -> None:
    artifact = build_logical_word_memory_copy_artifact_8616(
        _alias_artifact("8b460440a30070c3")
    )

    assert artifact.complete
    assert artifact.facts == ()
    assert artifact.stats.raw_fact_count == artifact.stats.failure_count == 1
    assert (
        artifact.refusals[0].failure
        is LogicalWordMemoryCopyFailure8616.SOURCE_TRANSFER_MISSING
    )


def test_lowering_materializes_only_exact_tagged_global_assignment() -> None:
    codegen, assignment, source, _temporary = _copy_assignment_fixture()
    query_session = StructuredAstQuerySession8616(codegen.cfunc.statements)

    result = materialize_logical_word_memory_copies_8616(
        codegen,
        query_session=query_session,
    )

    assert result.changed
    assert result.artifact.complete
    assert result.artifact.stats.raw_fact_count == 1
    assert result.artifact.stats.materialized_count == 1
    assert result.artifact.refusals == ()
    assert assignment.rhs is source
