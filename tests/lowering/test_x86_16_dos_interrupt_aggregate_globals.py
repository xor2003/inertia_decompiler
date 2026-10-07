from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.cod_global_identity import CodGlobalIdentityFact8616
from inertia.lowering.dos_interrupt_abi import (
    dos_interrupt_prototype_declaration_8616,
)
from inertia.lowering.dos_interrupt_aggregate_globals import (
    materialize_dos_interrupt_aggregate_globals_8616,
)
from inertia.lowering.indexed_global_evidence import (
    IndexedSegmentedGlobalEvidence8616,
)
from inertia.lowering.named_type_definitions import (
    named_type_definitions_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc = None
        self._idx = 0
        self.cstyle_null_cmp = False
        self.max_str_len = None
        self._inertia_global_declaration_specs_8616 = ()

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _constant(codegen: _Codegen, value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=codegen)


def _global(
    codegen: _Codegen,
    offset: int,
    width: int,
    name: str,
) -> structured_c.CVariable:
    type_ = SimTypeChar(False) if width == 1 else SimTypeShort(False)
    return structured_c.CVariable(
        SimMemoryVariable(offset, width, name=name),
        variable_type=type_,
        codegen=codegen,
    )


def _field_path(node: object) -> tuple[str, ...]:
    fields: list[str] = []
    while isinstance(node, structured_c.CVariableField):
        fields.append(node.field.field)
        node = node.variable
    return tuple(reversed(fields))


def test_dos_interrupt_aggregate_materialization_projects_exact_overlapping_objects() -> None:
    codegen = _Codegen()
    segment = structured_c.CVariable(
        SimStackVariable(4, 2, base="bp", name="segment"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    rin = _global(codegen, 0x7000, 1, "rin")
    rout = _global(codegen, 0x7004, 2, "rout")
    rout_al = _global(codegen, 0x7004, 1, "rout")
    rin_ah = structured_c.CIndexedVariable(
        rin,
        _constant(codegen, 1),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    sreg = _global(codegen, 0x7002, 8, "sreg")
    rout_cflag = structured_c.CIndexedVariable(
        rout,
        _constant(codegen, 6),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    call = structured_c.CFunctionCall(
        "intdosx",
        None,
        [
            structured_c.CUnaryOp("Reference", rin, codegen=codegen),
            structured_c.CUnaryOp("Reference", rout, codegen=codegen),
            structured_c.CUnaryOp("Reference", segment, codegen=codegen),
        ],
        codegen=codegen,
        tags={"ins_addr": 0x1026},
    )
    ax = structured_c.CVariable(
        SimRegisterVariable(0, 2, name="ax"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    flag_copy = structured_c.CVariable(
        SimStackVariable(-2, 2, base="bp", name="flag"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    statements = [
        structured_c.CAssignment(rin_ah, _constant(codegen, 0x49), codegen=codegen),
        structured_c.CAssignment(sreg, segment, codegen=codegen),
        structured_c.CAssignment(ax, call, codegen=codegen),
        structured_c.CAssignment(flag_copy, rout_cflag, codegen=codegen),
        structured_c.CReturn(rout_al, codegen=codegen),
    ]
    root = structured_c.CStatements(statements, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)
    summary = CallsiteSummary8616(
        callsite_addr=0x1026,
        target_addr=0x4000,
        return_addr=0x1029,
        kind="near",
        arg_count=3,
        arg_widths=(2, 2, 2),
        stack_cleanup=6,
        return_register="ax",
        return_used=True,
        push_arg_sources=(("imm", 0x7002), ("imm", 0x7004), ("imm", 0x7000)),
    )
    codegen._inertia_callsite_summaries = {id(call): summary}
    codegen._inertia_callsite_summary_inventory_8616 = {0x1026: summary}
    codegen._inertia_indexed_global_evidence_8616 = (
        IndexedSegmentedGlobalEvidence8616(0x7000, "_S424_rin", 0, 1),
        IndexedSegmentedGlobalEvidence8616(0x7001, "_S424_rin", 1, 1),
        IndexedSegmentedGlobalEvidence8616(0x7002, "_S426_sreg", 0, 1),
        IndexedSegmentedGlobalEvidence8616(0x7002, "_S426_sreg", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x7004, "_S425_rout", 0, 1),
        IndexedSegmentedGlobalEvidence8616(0x7004, "_S425_rout", 0, 2),
        IndexedSegmentedGlobalEvidence8616(0x7010, "_S425_rout", 12, 2),
    )
    codegen._inertia_cod_global_identity_facts_8616 = (
        CodGlobalIdentityFact8616(0x7001, 1, "_S424_rin", "rin"),
        CodGlobalIdentityFact8616(0x7002, 2, "_S426_sreg", "sreg"),
        CodGlobalIdentityFact8616(0x7010, 2, "_S425_rout", "rout"),
    )

    assert materialize_dos_interrupt_aggregate_globals_8616(codegen) is True

    assert _field_path(statements[0].lhs) == ("h", "ah")
    assert _field_path(statements[1].lhs) == ("es",)
    assert _field_path(statements[3].rhs) == ("x", "cflag")
    assert _field_path(statements[4].retval) == ("h", "al")
    assert [argument.operand.variable.name for argument in call.args] == ["rin", "rout", "sreg"]
    assert {spec[0:2] for spec in codegen._inertia_global_declaration_specs_8616} == {
        ("REGS", "rin"),
        ("REGS", "rout"),
        ("SREGS", "sreg"),
    }
    assert len(named_type_definitions_8616(codegen)) == 2
    stats = codegen._inertia_dos_interrupt_aggregate_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)
    assert stats.argument_count == 3
    assert stats.field_projection_count == 4
    assert materialize_dos_interrupt_aggregate_globals_8616(codegen) is False


def test_dos_interrupt_prototype_uses_standard_aggregate_abi() -> None:
    assert dos_interrupt_prototype_declaration_8616("intdosx") == (
        "int intdosx(union REGS *in, union REGS *out, struct SREGS *sreg);"
    )
