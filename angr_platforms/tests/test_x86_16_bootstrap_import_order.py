"""Compatibility hooks must survive CLI-first imports in fresh processes."""

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "first_module",
    ["inertia_decompiler.cli_access_object_hints", "angr_platforms.X86_16"],
    ids=["cli-first", "frontend-first"],
)
def test_import_order_preserves_native_return_cleanup(first_module):
    script = """
import importlib
import io
import sys

importlib.import_module(sys.argv[1])
import angr
from angr.analyses.calling_convention.fact_collector import FactCollector
from angr_platforms.X86_16.arch_86_16 import Arch86_16

project = angr.Project(
    io.BytesIO(bytes.fromhex("ca 06 00")), auto_load_libs=False,
    main_opts={"backend": "blob", "arch": Arch86_16(),
               "base_addr": 0x1000, "entry_point": 0x1000},
)
cfg = project.analyses.CFGFast(normalize=True)
facts = project.analyses[FactCollector](cfg.functions[0x1000])
assert facts.extra_pop == 6, facts.extra_pop
proof = facts._inertia_return_cleanup_evidence_8616
assert proof.raw_fact_count == proof.normalized_fact_count == 1
assert proof.classified_fact_count == proof.materialized_count == 1
assert proof.failure_count == 0
"""
    result = subprocess.run(
        [sys.executable, "-c", script, first_module],
        capture_output=True, text=True, timeout=60,
        env={**os.environ, "PYTHON_JIT": "1", "PYTHONHASHSEED": "0"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
