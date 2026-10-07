from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CExpressionStatement,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.condition_ir import ConditionIR, ConditionOp
from inertia.ir.core import IRValue, MemSpace
from inertia.lowering.project_global_signedness import (
    ProjectGlobalSignednessContract8616,
    ProjectGlobalSignednessEvidence8616,
)
from inertia.lowering.signed_global_declarations import (
    materialize_signed_global_declarations_8616,
)

from inertia.semantics.direct_global_ordering import DirectGlobalOrdering8616
from tools.dev.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]


class _Codegen:
    def __init__(self, conditions: tuple[ConditionIR, ...]) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._next_index = 0
        self._inertia_typed_conditions = conditions
        self._inertia_global_declaration_specs_8616 = (("unsigned long", "g_0132", None),)
        self.cfunc: object | None = None

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _constant(value: int) -> IRValue:
    return IRValue(MemSpace.CONST, const=value, size=2)


def _condition(op: ConditionOp, offset: int) -> ConditionIR:
    return ConditionIR(
        op,
        IRValue(MemSpace.DS, offset=offset, size=2),
        _constant(0),
        width_bits=16,
        src_insn=offset + 4,
        block_addr=offset,
    )


def _codegen(*conditions: ConditionIR) -> _Codegen:
    codegen = _Codegen(conditions)
    wide = CVariable(
        SimMemoryVariable(0x132, 4, name="g_0132", region=0x4010),
        codegen=codegen,
    )
    statements = []
    for condition in conditions:
        lhs = (
            CBinaryOp(
                "Shr",
                wide,
                CConstant(16, SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            )
            if condition.lhs.offset == 0x134
            else wide
        )
        comparison = CBinaryOp(
            "CmpLE",
            lhs,
            CConstant(0, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
            tags={"ins_addr": condition.src_insn, "vex_block_addr": condition.block_addr},
        )
        statements.append(CExpressionStatement(comparison, codegen=codegen))
    root = CStatements(statements, codegen=codegen)
    codegen.cfunc = root
    return codegen


def test_signed_high_word_condition_materializes_signed_wide_global_declaration() -> None:
    codegen = _codegen(_condition("sle", 0x134))
    codegen._inertia_global_declaration_specs_8616 = (
        ("unsigned short", "g_before", None),
        ("unsigned long", "g_0132", None),
        ("unsigned char", "g_after", None),
    )

    changed = materialize_signed_global_declarations_8616(codegen.project, codegen)

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned short", "g_before", None),
        ("unsigned char", "g_after", None),
        ("long", "g_0132", None),
    )
    assert codegen._inertia_signed_global_declaration_facts_8616[0].base_offset == 0x132
    stats = codegen._inertia_signed_global_declaration_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)

    codegen._inertia_global_declaration_specs_8616 = (
        ("unsigned short", "g_before", None),
        ("long", "g_0132", None),
        ("unsigned char", "g_after", None),
    )
    assert materialize_signed_global_declarations_8616(codegen.project, codegen) is False
    assert codegen._inertia_global_declaration_specs_8616 == (
        ("unsigned short", "g_before", None),
        ("long", "g_0132", None),
        ("unsigned char", "g_after", None),
    )


def test_typed_high_word_condition_joins_scalar_without_ast_projection() -> None:
    condition = _condition("sle", 0x134)
    codegen = _Codegen((condition,))
    wide = CVariable(
        SimMemoryVariable(0x132, 4, name="g_0132", region=0x4010),
        codegen=codegen,
    )
    codegen.cfunc = CStatements(
        [CExpressionStatement(wide, codegen=codegen)],
        codegen=codegen,
    )

    changed = materialize_signed_global_declarations_8616(codegen.project, codegen)

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (("long", "g_0132", None),)
    stats = codegen._inertia_signed_global_declaration_stats_8616
    assert (stats.raw_fact_count, stats.normalized_fact_count) == (1, 1)
    assert (stats.classified_fact_count, stats.materialized_count, stats.failure_count) == (1, 1, 0)


def test_project_signedness_materializes_current_wide_scalar_without_local_condition() -> None:
    codegen = _Codegen(())
    wide = CVariable(
        SimMemoryVariable(0x132, 4, name="g_0132", region=0x4010),
        codegen=codegen,
    )
    codegen.cfunc = CStatements(
        [CExpressionStatement(wide, codegen=codegen)],
        codegen=codegen,
    )
    codegen.project._inertia_project_global_signedness_evidence_8616 = (
        ProjectGlobalSignednessEvidence8616(
            contracts=(
                ProjectGlobalSignednessContract8616(
                    base_offset=0x132,
                    ordering=DirectGlobalOrdering8616.SIGNED,
                    proof_function_addrs=(0x102E0,),
                    proof_compare_addrs=(0x103DE,),
                ),
            ),
            raw_fact_count=1,
            normalized_fact_count=1,
            classified_fact_count=1,
            materialized_count=1,
        )
    )

    changed = materialize_signed_global_declarations_8616(codegen.project, codegen)

    assert changed is True
    assert codegen._inertia_global_declaration_specs_8616 == (("long", "g_0132", None),)
    stats = codegen._inertia_signed_global_declaration_stats_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (1, 1, 1, 1, 0)


def test_signed_global_declaration_refuses_conflicting_high_word_ordering() -> None:
    codegen = _codegen(
        _condition("sge", 0x134),
        _condition("uge", 0x134),
    )

    changed = materialize_signed_global_declarations_8616(codegen.project, codegen)

    assert changed is False
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "g_0132", None),)
    stats = codegen._inertia_signed_global_declaration_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0
    assert stats.failure_count == 1


@pytest.mark.parametrize("offset", [0x132, 0x136])
def test_signed_global_declaration_refuses_non_high_word_evidence(offset: int) -> None:
    codegen = _codegen(_condition("slt", offset))

    changed = materialize_signed_global_declarations_8616(codegen.project, codegen)

    assert changed is False
    assert codegen._inertia_global_declaration_specs_8616 == (("unsigned long", "g_0132", None),)
    stats = codegen._inertia_signed_global_declaration_stats_8616
    assert stats.classified_fact_count == 0
    assert stats.materialized_count == 0


@pytest.mark.requires_kvm
def test_sortd_runmenu_signed_wide_global_is_sidecar_free_and_validated(tmp_path: Path) -> None:
    sortd_exe = tmp_path / "SORTD.EXE"
    sortd_exe.write_bytes(mz_executable_image((REPO_ROOT / "SORTDEMO.EXE").read_bytes()))
    env = dict(os.environ)
    env.update(INERTIA_DISABLE_TIMING="1", INERTIA_ENABLE_TAIL_VALIDATION="1")

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "decompile.py"),
            str(sortd_exe),
            "--addr",
            "0x102e0",
            "--timeout",
            "240",
            "--no-alternate-source-c",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=420,
        check=False,
    )

    combined = f"{result.stderr}{result.stdout}"
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "extern long g_0132;" in result.stdout
    assert "extern unsigned long g_0132;" not in result.stdout
    assert "g_0132 >> 16 >= 0" in result.stdout
