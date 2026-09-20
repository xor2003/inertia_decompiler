from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    IndexedSegmentedGlobalLoadConsumer8616,
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    recover_indexed_segmented_global_load_site_evidence_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_PUSH,
    X86_INS_SHL,
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CS,
    X86_REG_ES,
    X86_REG_INVALID,
)

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTD_EXE = REPO_ROOT / "SORTD.EXE"


def _reg_operand(register: int) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_REG, size=2, reg=register)


def _immediate_operand(value: int) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_IMM, size=1, imm=value)


def _memory_operand(base: int, displacement: int, *, segment: int) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=2,
        mem=SimpleNamespace(
            base=base,
            index=X86_REG_INVALID,
            segment=segment,
            disp=displacement,
        ),
    )


def _direct_indexed_push_function(segment: int) -> SimpleNamespace:
    instructions = (
        SimpleNamespace(
            address=0x100C5,
            id=X86_INS_MOV,
            operands=(_reg_operand(X86_REG_BX), _memory_operand(X86_REG_BP, -2, segment=X86_REG_INVALID)),
        ),
        SimpleNamespace(
            address=0x100C8,
            id=X86_INS_SHL,
            operands=(_reg_operand(X86_REG_BX), _immediate_operand(1)),
        ),
        SimpleNamespace(
            address=0x100CB,
            id=X86_INS_PUSH,
            operands=(_memory_operand(X86_REG_BX, 0x136, segment=segment),),
        ),
    )
    block = SimpleNamespace(addr=0x100C5, capstone=SimpleNamespace(insns=instructions))
    return SimpleNamespace(addr=0x10060, blocks=(block,))


def test_direct_indexed_ds_push_records_exact_load_site() -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))

    evidence = recover_indexed_segmented_global_load_site_evidence_8616(
        project,
        _direct_indexed_push_function(X86_REG_INVALID),
    )

    assert evidence == (
        IndexedSegmentedGlobalLoadSiteEvidence8616(
            base_offset=0x136,
            width=2,
            index_stack_offset=-2,
            index_shift=1,
            ins_addr=0x100CB,
            destination_register=None,
            index_stack_width=2,
            consumer=IndexedSegmentedGlobalLoadConsumer8616.DIRECT_STACK,
        ),
    )


@pytest.mark.parametrize("segment", [X86_REG_ES, X86_REG_CS])
def test_direct_indexed_push_refuses_non_ds_or_unknown_segment(segment: int) -> None:
    project = SimpleNamespace(arch=Arch86_16(), kb=SimpleNamespace(labels={}))

    evidence = recover_indexed_segmented_global_load_site_evidence_8616(
        project,
        _direct_indexed_push_function(segment),
    )

    assert evidence == ()


@pytest.mark.xdist_group("sortd-initmenu")
def test_sortd_initmenu_materializes_indexed_near_pointer_table(tmp_path: Path) -> None:
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTD_EXE.read_bytes()))
    env = dict(os.environ)
    env.update(
        {
            "INERTIA_DISABLE_TIMING": "1",
            "INERTIA_ENABLE_TAIL_VALIDATION": "1",
        }
    )

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x10060",
            "--timeout",
            "300",
            "--ignore-local-sidecar-hints",
            "--no-alternate-source-c",
            "--window",
            "0x200",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=480,
        check=False,
    )

    combined = f"{result.stdout}\n{result.stderr}"
    assert result.returncode == 0, combined
    assert "no helper metadata (.lst/.map/.cod/debug info) found" in combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "gcc portable-flat syntax check failed:" not in combined
    assert "extern char * g_0136[];" in result.stdout
    assert "extern char * g_0136[1];" not in result.stdout
    assert "sub_12756(g_0136[(unsigned short)local_2], inertia_ds);" in result.stdout
    assert "sub_12756(SEG_U16(inertia_ds, 310 + (local_2 << 1)), inertia_ds);" not in result.stdout
    assert "g_0132[0]" not in result.stdout
    assert "g_0132[1]" not in result.stdout
