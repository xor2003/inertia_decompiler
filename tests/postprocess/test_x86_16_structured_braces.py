from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CConstant,
    CExpressionStatement,
    CFunctionCall,
    CIfElse,
    CStatements,
)
from angr.sim_type import SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.postprocess.optimization.structured_braces import (
    normalize_multi_statement_braces_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.stmt_comments: dict[object, str] = {}
        self.expr_comments: dict[object, str] = {}
        self.const_formats: dict[int, dict[str, bool]] = {}
        self.braces_on_own_lines = True
        self.indent_delta = 4
        self.display_block_addrs = False
        self.display_vvar_ids = False
        self.cstyle_null_cmp = False
        self.max_str_len = 64

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _call_statement(name: str, codegen: _Codegen) -> CExpressionStatement:
    return CExpressionStatement(
        CFunctionCall(name, None, [], codegen=codegen),
        codegen=codegen,
    )


def _render(node: object) -> str:
    return "".join(chunk for chunk, _owner in node.c_repr_chunks())


def test_nested_multi_statement_if_body_forces_explicit_braces() -> None:
    codegen = _Codegen()
    nested = CStatements(
        [_call_statement("first", codegen), _call_statement("second", codegen)],
        codegen=codegen,
    )
    body = CStatements([nested], codegen=codegen)
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))

    before = _render(branch)
    changed = normalize_multi_statement_braces_8616(codegen)
    after = _render(branch)

    assert changed is True
    assert "if (1)\n    first();\n    second();" in before
    assert "if (1)\n{\n    first();\n    second();\n}" in after
    assert branch.cstyle_ifs is False
    stats = codegen._inertia_structured_brace_normalization_stats_8616
    assert stats.raw_fact_count == 1
    assert stats.normalized_fact_count == 1
    assert stats.classified_fact_count == 1
    assert stats.materialized_count == 1
    assert stats.failure_count == 0

    assert normalize_multi_statement_braces_8616(codegen) is False


def test_direct_multi_statement_if_body_forces_explicit_braces() -> None:
    codegen = _Codegen()
    body = CStatements(
        [_call_statement("first", codegen), _call_statement("second", codegen)],
        codegen=codegen,
    )
    condition = CConstant(1, SimTypeShort(False), codegen=codegen)
    branch = CIfElse(
        [(condition, body)],
        else_node=None,
        cstyle_ifs=True,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(statements=CStatements([branch], codegen=codegen))

    assert "if (1)\n{\n    first();\n    second();\n}" in _render(branch)
    assert normalize_multi_statement_braces_8616(codegen) is True
    assert branch.cstyle_ifs is False
