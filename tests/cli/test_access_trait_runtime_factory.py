"""Legacy access-trait wiring must supply a runtime evidence class."""

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimStackVariable

import inertia.cli.cli_c_ast_rewrites as cli_c_ast_rewrites
from inertia.cli.cli_access_profiles import AccessTraitStrideEvidence


def test_access_trait_factory_creates_and_reuses_typed_records() -> None:
    project = SimpleNamespace(arch=archinfo.ArchX86(), _inertia_access_traits={})
    codegen = SimpleNamespace(
        project=project, next_idx=lambda _name: 1, next_node_idx=lambda: 1,
        next_ident=lambda name: f"{name}_0", cstyle_null_cmp=False,
    )
    word = SimTypeShort(False).with_arch(project.arch)
    base = c.CVariable(
        SimStackVariable(-2, 2, base="bp", region=0x1000),
        variable_type=word, codegen=codegen,
    )
    indexed = c.CIndexedVariable(
        base, c.CConstant(0, word, codegen=codegen), variable_type=word, codegen=codegen,
    )
    dereference = c.CUnaryOp(
        "Dereference", c.CUnaryOp("Reference", indexed, codegen=codegen), codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=dereference)

    for expected_count in (1, 2):
        assert cli_c_ast_rewrites._collect_access_traits(project, codegen) is False
        records = project._inertia_access_traits[0x1000]["induction_evidence"]
        assert len(records) == 1
        record = next(iter(records.values()))
        assert isinstance(record, AccessTraitStrideEvidence)
        assert record.count == expected_count
        assert record.width == 2
        assert record.segment == "expr"
        assert record.index_key == ("stack", "bp", -2, 0x1000)
        assert codegen.cfunc.statements is dereference
