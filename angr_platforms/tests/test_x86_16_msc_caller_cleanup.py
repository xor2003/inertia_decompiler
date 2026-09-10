"""Regress caller-cleaned Microsoft C call sites through sidecar-free C output."""

from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import angr
import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CVariable
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeInt, SimTypeLongLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616, _same_c_expression_8616
from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa: F401
from angr_platforms.X86_16.lowering.call_argument_stack_sources import (
    PushStoreWidthVerdict8616,
    classify_push_store_width_8616,
)
from angr_platforms.X86_16.semantics.immediate_semantics import sign_extend_u8_to_u16
from angr_platforms.X86_16.simos_86_16 import (
    SimCC8616MSCmedium,
    SimCC8616MSCsmall,
)
from archinfo import ArchX86

from scripts.check_sortd_sidecar_free import mz_executable_image

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = REPO_ROOT / "decompile.py"
SORTDEMO_EXE = REPO_ROOT / "SORTDEMO.EXE"


def _project_from_bytes(code: bytes) -> angr.Project:
    """Build one 16-bit blob project for caller-cleanup regressions."""
    return angr.Project(
        io.BytesIO(code),
        main_opts={"backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000},
    )


def test_msc_c_conventions_leave_argument_cleanup_to_caller() -> None:
    """The near-call return pops itself; C argument words remain caller-owned."""
    assert SimCC8616MSCsmall.CALLEE_CLEANUP is False
    assert SimCC8616MSCmedium.CALLEE_CLEANUP is False


@pytest.mark.parametrize("encoded,expected", [(0x04, 0x0004), (0x80, 0xFF80), (0xFC, 0xFFFC), (0x1FC, 0xFFFC)])
def test_group83_immediate_sign_extension_is_exact(encoded: int, expected: int) -> None:
    """Normalize positive and negative encoded bytes to exact word patterns."""
    assert sign_extend_u8_to_u16(encoded) == expected


def test_stack_cleanup_immediate_lifts_as_typed_word_constant() -> None:
    """Keep ``add sp, imm8`` affine for angr's stack-pointer tracker."""
    project = _project_from_bytes(bytes.fromhex("83c404c3"))

    vex_text = str(project.factory.block(0x1000, num_inst=1, opt_level=0).vex)

    assert "Add16" in vex_text
    assert "0x0004" in vex_text
    assert "8Sto16" not in vex_text


def test_caller_cleanup_loop_preserves_affine_stack_pointer() -> None:
    """A call-cleanup backedge must survive MZ loader-width stack propagation."""
    code = bytes.fromhex("558bec5050e8180083c4044975f58be55dc3") + b"\x90" * 14 + b"\xc3"
    project = _project_from_bytes(code)
    project.arch.bits = 32
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[0x1000, 0x1020])
    function = cfg.functions[0x1000]

    stack_tracker = project.analyses.StackPointerTracker(
        function,
        {project.arch.sp_offset},
        cross_insn_opt=False,
    )
    expected_offset = stack_tracker.offset_after(0x1001, project.arch.sp_offset)

    assert expected_offset is not None
    assert stack_tracker.offset_before(0x1003, project.arch.sp_offset) == expected_offset
    assert stack_tracker.offset_before(0x100E, project.arch.sp_offset) == expected_offset

    decompiler = project.analyses.Decompiler(function, cfg=cfg)

    assert decompiler.codegen is not None
    assert "/* unsupported instruction */" not in decompiler.codegen.text
    assert "sub_1020();" in decompiler.codegen.text


@pytest.mark.parametrize(
    "store_type,expected",
    [
        (SimTypeChar(False), PushStoreWidthVerdict8616.PARTIAL_REFUSE),
        (SimTypeShort(False), PushStoreWidthVerdict8616.COMPLETE_WIDTH),
        (SimTypeInt(False).with_arch(ArchX86()), PushStoreWidthVerdict8616.COMPLETE_WIDTH),
        (SimTypeLongLong(False), PushStoreWidthVerdict8616.PARTIAL_REFUSE),
        (SimTypeBottom(), PushStoreWidthVerdict8616.UNKNOWN_REFUSE),
    ],
)
def test_push_store_width_requires_one_complete_architectural_value(store_type, expected):
    codegen = SimpleNamespace(
        next_node_idx=lambda: 1, next_ident=lambda name: name, project=SimpleNamespace(arch=ArchX86()),
    )
    variable = CVariable(SimStackVariable(-2, 2, base="bp"), variable_type=store_type, codegen=codegen)
    original_type = variable.variable_type
    assert classify_push_store_width_8616(variable) is expected
    assert variable.variable_type is original_type


def test_push_store_width_refuses_missing_typed_lvalue() -> None:
    assert classify_push_store_width_8616(object()) is PushStoreWidthVerdict8616.UNKNOWN_REFUSE


def test_caller_cleanup_does_not_split_one_push_into_two_arguments() -> None:
    """Two identical word PUSHes cannot become the two bytes of one PUSH."""
    code = bytes.fromhex("558bec5050e8180083c4044975f58be55dc3") + b"\x90" * 14 + b"\xc3"
    project = _project_from_bytes(code)
    project.arch.bits = 32
    cfg = project.analyses.CFGFast(normalize=True, function_starts=[0x1000, 0x1020])
    decompiler = project.analyses.Decompiler(cfg.functions[0x1000], cfg=cfg)
    assert decompiler.codegen is not None
    calls = [
        node
        for node in _iter_c_nodes_deep_8616(decompiler.codegen.cfunc.statements)
        if isinstance(node, CFunctionCall)
    ]
    assert len(calls) == 1
    arguments = calls[0].args
    # A bare RET does not establish formal arity. If physical pushes are
    # projected as arguments, both must retain the same captured AX value.
    assert len(arguments) in {0, 2}
    if arguments:
        assert _same_c_expression_8616(arguments[0], arguments[1])


def test_sortd_percolateup_caller_cleanup_has_no_opaque_sp_expression(
    tmp_path: Path,
) -> None:
    """Lower ``call; add sp, 4`` without leaking opaque SP into flag C."""
    isolated_binary = tmp_path / "SORTD.EXE"
    isolated_binary.write_bytes(mz_executable_image(SORTDEMO_EXE.read_bytes()))
    env = dict(os.environ)
    env.setdefault("INERTIA_ENABLE_TAIL_VALIDATION", "1")
    env.setdefault("INERTIA_DISABLE_TIMING", "1")

    result = subprocess.run(
        [
            sys.executable,
            str(CLI_PATH),
            str(isolated_binary),
            "--addr",
            "0x109e8",
            "--timeout",
            "120",
            "--no-alternate-source-c",
            "--window",
            "0x90",
            "--c-target",
            "portable-flat",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        timeout=240,
        check=False,
    )
    combined = f"{result.stderr}{result.stdout}"

    assert result.returncode == 0, combined
    assert "validation=passed" in combined
    assert "whole-tail validation clean across 1 functions" in combined
    assert "/* unsupported instruction */" not in result.stdout
    declaration_and_call_count = 2
    assert result.stdout.count("sub_107b8(") == declaration_and_call_count
    assert result.stdout.count("sub_10768(") == declaration_and_call_count
