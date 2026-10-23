"""Exact-region publication must preserve the function's analysis owner.

Layer: CLI/frontend regression tests.
Responsibility: preserve native CFG ownership through publication and executed C.
"""
import ctypes
import json
import shutil
import subprocess
from pathlib import Path

import angr
import pytest

from inertia.cli.cli_function_discovery import _commit_exact_region_function_to_kb_8616
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.function_knowledge_base import function_knowledge_base_8616
from inertia.validation.tail_validation import (
    extract_x86_16_tail_validation_snapshot,
    x86_16_tail_validation_snapshot_passed,
)
from tests.cli.test_x86_16_cod_samples import _project_from_bytes

pytestmark = pytest.mark.decompiler


def _private_cfg() -> tuple:
    """Recover a real function in an isolated CFG knowledge base."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(bytes.fromhex("b83412c3"))
    cfg = project.analyses.CFGFast(kb=angr.KnowledgeBase(project), normalize=True)
    return project, cfg, cfg.functions[0x1000]


def test_exact_region_publication_keeps_originating_cfg_owner() -> None:
    """Publishing an alias must retain the actual CFG and its function owner."""
    project, cfg, function = _private_cfg()
    original_kb = function_knowledge_base_8616(project, function)
    assert original_kb is cfg.kb
    assert project.kb.cfgs.get_most_accurate() is None
    changed = _commit_exact_region_function_to_kb_8616(project, cfg, function, (0x1000, 0x1004))
    assert changed
    assert project.kb.functions[0x1000] is function
    assert cfg.functions[0x1000] is function
    assert function_knowledge_base_8616(project, function) is original_kb
    assert original_kb.cfgs.get_most_accurate() is cfg.model


@pytest.mark.parametrize("publish", [False, True])
def test_private_cfg_generated_c_survives_region_publication(tmp_path: Path, publish: bool) -> None:
    """Require native equivalence and executed C before and after publication."""
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("GCC is required for executed generated-C evidence")
    project, cfg, function = _private_cfg()
    if publish:
        _commit_exact_region_function_to_kb_8616(project, cfg, function, (0x1000, 0x1004))
    machine = project.factory.blank_state(addr=0x1000)
    machine.regs.eax = 0x56780000
    machine.regs.esp, machine.regs.ss, machine.regs.cs = 0x8000, 0, 0
    machine.memory.store(0x8000, 0x2000, size=2, endness="Iend_LE")
    execution = project.factory.simgr(machine)
    execution.explore(find=0x2000, n=8)
    assert len(execution.found) == 1
    expected = execution.found[0].solver.eval(execution.found[0].regs.ax)
    assert expected == 0x1234
    result = project.analyses.Decompiler(function, cfg=cfg, kb=cfg.kb)
    assert result.codegen is not None
    generated = result.codegen.text
    (tmp_path / "generated.c").write_text(generated)
    validation = extract_x86_16_tail_validation_snapshot(function.info)
    (tmp_path / "tail-validation.json").write_text(json.dumps(validation, indent=2))
    assert x86_16_tail_validation_snapshot_passed(validation), validation
    source = tmp_path / "harness.c"
    library = tmp_path / "generated.so"
    source.write_text("#define _start recovered_entry\n" + generated)
    compiled = subprocess.run(
        [compiler, "-std=c11", "-Werror", "-shared", "-fPIC", str(source), "-o", str(library)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    (tmp_path / "gcc.log").write_text(compiled.stdout + compiled.stderr)
    assert compiled.returncode == 0, compiled.stderr
    loaded = ctypes.CDLL(str(library))
    loaded.recovered_entry.restype = ctypes.c_uint16
    assert loaded.recovered_entry() == expected
