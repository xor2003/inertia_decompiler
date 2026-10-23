"""Bind an entry register read before the same assignment publishes its update.

Layer: Types/Lowering tests.
Responsibility: preserve C assignment sequencing and conservative refusal boundaries.
"""
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeInt, SimTypeNum

from inertia.lowering.c_ast_utils import _iter_c_nodes_deep_8616
from inertia.lowering.gp_register_state import (
    lower_architectural_gp_register_state_8616,
    runtime_gp_state_assignment_8616,
)
from tests.lowering.test_x86_16_gp_register_state import (
    _entry_dirty,
    _scoped_codegen,
    _scoped_entry_project,
)

pytestmark = pytest.mark.decompiler


def _statement(codegen: object, value: c.CExpression) -> c.CAssignment:
    """Write a word SP view while preserving upper ESP storage."""
    statement = runtime_gp_state_assignment_8616(
        "sp", value, codegen=codegen, function_addr=0x1D43,
    )
    assert statement is not None
    return statement


def _codegen() -> SimpleNamespace:
    """Provide the existing scoped lowering boundary plus normal renderer flags."""
    codegen = _scoped_codegen(_scoped_entry_project(), None)
    codegen.show_casts = False
    codegen.display_vvar_ids = False
    codegen.display_block_addrs = False
    codegen.show_externs = False
    codegen.use_compound_assignments = False
    codegen.stmt_comments = {}
    codegen.expr_comments = {}
    codegen.const_formats = {}
    codegen.max_str_len = 1024
    codegen.default_simtype_from_bits = lambda bits, signed=False: SimTypeNum(bits, signed).with_arch(codegen.project.arch)
    return codegen


@pytest.mark.parametrize("initial_esp", [0, 1, 0x12348000, 0xFFFF0000])
def test_entry_sp_read_precedes_same_statement_store(tmp_path: Path, initial_esp: int) -> None:
    """Execute the word update across wrap and upper-word boundaries."""
    codegen = _codegen()
    word = SimTypeInt(False).with_arch(codegen.project.arch)
    incoming = _entry_dirty(codegen, 0, "sp")
    rhs = c.CBinaryOp("Sub", incoming, c.CConstant(4, word, codegen=codegen), codegen=codegen)
    codegen.cfunc.statements = c.CStatements([_statement(codegen, rhs)], codegen=codegen)
    assert lower_architectural_gp_register_state_8616(codegen)
    root = codegen.cfunc.statements
    assert not any(isinstance(node, c.CDirtyExpression) for node in _iter_c_nodes_deep_8616(root))
    stats = codegen._inertia_gp_register_state_lowering_stats_8616
    assert stats.raw_fact_count == stats.normalized_fact_count
    assert stats.classified_fact_count == stats.materialized_count > 0
    assert stats.failure_count == 0
    compiler = shutil.which("gcc")
    assert compiler is not None
    source = tmp_path / "entry-sp.c"
    binary = tmp_path / "entry-sp"
    source.write_text(
        "#include <stdint.h>\n#include <stdio.h>\n"
        + f"uint32_t inertia_esp = {initial_esp}U;\n"
        + "void update(void) {\n" + root.c_repr() + "\n}\n"
        + 'int main(void) { update(); printf("%u\\n", inertia_esp); return 0; }\n'
    )
    compiled = subprocess.run(
        [compiler, "-std=c11", "-Werror", str(source), "-o", str(binary)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    (tmp_path / "gcc.log").write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(binary)], capture_output=True, text=True, check=False, timeout=10)
    assert executed.returncode == 0, executed.stderr
    expected = (initial_esp & 0xFFFF0000) | (((initial_esp & 0xFFFF) - 4) & 0xFFFF)
    assert int(executed.stdout) == expected


@pytest.mark.parametrize("nested_effect", ["call", "assignment"])
def test_same_statement_entry_read_refuses_unordered_effects(nested_effect: str) -> None:
    """An opaque RHS effect cannot establish that the initial value is still current."""
    codegen = _codegen()
    word = SimTypeInt(False).with_arch(codegen.project.arch)
    incoming = _entry_dirty(codegen, 0, "sp")
    if nested_effect == "call":
        rhs = c.CBinaryOp(
            "Add", incoming, c.CFunctionCall("opaque", None, args=[], codegen=codegen),
            codegen=codegen,
        )
    else:
        rhs = c.CMultiStatementExpression(
            c.CStatements([_statement(codegen, c.CConstant(8, word, codegen=codegen))], codegen=codegen),
            incoming, codegen=codegen,
        )
    codegen.cfunc.statements = c.CStatements([_statement(codegen, rhs)], codegen=codegen)
    for _ in range(2):
        lower_architectural_gp_register_state_8616(codegen)
        assert any(node is incoming for node in _iter_c_nodes_deep_8616(codegen.cfunc.statements))
