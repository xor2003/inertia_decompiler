from __future__ import annotations

from types import SimpleNamespace

import archinfo
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.postprocess.decompiler_postprocess_utils import (
    _iter_c_nodes_deep_8616,
)
from inertia.lowering.semantic_cast import CSemanticCast8616

from inertia.postprocess.optimization.dce import (
    _dead_code_elimination_8616,
)


class _FakeCodegen(SimpleNamespace):
    def __init__(self) -> None:
        super().__init__()
        self._next = 0
        self.project = SimpleNamespace(arch=archinfo.ArchX86())
        self.cstyle_null_cmp = False

    def next_idx(self, _kind: str) -> int:
        self._next += 1
        return self._next

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _constant(codegen: _FakeCodegen, value: int) -> structured_c.CConstant:
    return structured_c.CConstant(
        value,
        SimTypeShort(False),
        codegen=codegen,
    )


def test_postprocess_ast_walker_descends_into_semantic_cast() -> None:
    codegen = _FakeCodegen()
    variable = SimStackVariable(-8, 2, base="bp", name="segment_word")
    local = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    cast = CSemanticCast8616(
        None,
        SimTypeChar(False),
        local,
        codegen=codegen,
    )

    assert local in tuple(_iter_c_nodes_deep_8616(cast))


def test_dce_partial_stack_write_keeps_prior_full_definition() -> None:
    codegen = _FakeCodegen()
    variable = SimStackVariable(-8, 2, base="bp", name="segment_word")
    local = structured_c.CVariable(
        variable,
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    full_definition = structured_c.CAssignment(
        local,
        _constant(codegen, 0x1234),
        codegen=codegen,
    )
    high_byte_view = CSemanticCast8616(
        None,
        SimTypeChar(False),
        structured_c.CBinaryOp(
            "Shr",
            local,
            _constant(codegen, 8),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    partial_definition = structured_c.CAssignment(
        high_byte_view,
        _constant(codegen, 0x56),
        codegen=codegen,
    )
    returned_value = structured_c.CBinaryOp(
        "Or",
        CSemanticCast8616(
            None,
            SimTypeChar(False),
            local,
            codegen=codegen,
        ),
        structured_c.CBinaryOp(
            "Shl",
            CSemanticCast8616(
                None,
                SimTypeChar(False),
                structured_c.CBinaryOp(
                    "Shr",
                    local,
                    _constant(codegen, 8),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _constant(codegen, 8),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    returned = structured_c.CReturn(returned_value, codegen=codegen)
    statements = structured_c.CStatements(
        [full_definition, partial_definition, returned],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        statements=statements,
        arg_list=(),
        variables_in_use={variable: local},
        unified_local_vars={},
    )

    _dead_code_elimination_8616(codegen)

    assert full_definition in codegen.cfunc.statements.statements
