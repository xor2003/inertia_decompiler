"""Comparison policies must be explicit, isolated, and normalization-aware."""

import struct
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from tools.dosunit.compare import straightline_ssa as engine


def scalar_document(value: int, width: int) -> dict:
    return {"functions": [{
        "id": "scalar", "function": {"id": "scalar", "name": "scalar"},
        "part": {"kind": "block", "index": 0, "entry_delta": "0x0"},
        "entry": {"linear": "0x1000"}, "function_entry": {"linear": "0x1000"},
        "source": {"jumpkind": "Ijk_Ret"}, "inputs": [], "assignments": [],
        "outputs": {"value": {"op": "const", "value": value, "width": width}},
    }]}


@pytest.mark.parametrize("width", [16, 32])
@pytest.mark.parametrize("skip_binary_equal", [False, True])
def test_explicit_policy_rejects_raw_identity_with_changed_constant(width, skip_binary_equal):
    from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY

    oracle = scalar_document(7, width)
    oracle["functions"][0]["source"].update(
        function_machine_code_sha256="matching-code", function_machine_code_size=1,
    )
    candidate = deepcopy(oracle)
    candidate["functions"][0]["_constant_normalization"] = {7: 8}
    candidate["functions"][0]["_constant_normalization_reasons"] = {7: "global_reloc"}
    compared = engine.compare_ssa_documents(
        oracle=oracle, candidate=candidate, comparison_policy=EXPLICIT_COMPARISON_POLICY,
        enable_region_equality=False, enable_connectivity=False,
        enable_callee_lemmas=False, skip_binary_equal=skip_binary_equal,
    )
    assert compared["summary"]["total"] == 1
    assert compared["results"][0]["status"] == "failed"
    assert compared["comparison_policy"] == EXPLICIT_COMPARISON_POLICY.document()


@pytest.mark.parametrize("width", [16, 32])
def test_explicit_policy_consumes_declared_normalization(width):
    from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY

    oracle = scalar_document(7, width)
    candidate = scalar_document(8, width)
    candidate["functions"][0]["_constant_normalization"] = {8: 7}
    candidate["functions"][0]["_constant_normalization_reasons"] = {8: "global_reloc"}
    compared = engine.compare_ssa_documents(
        oracle=oracle, candidate=candidate, comparison_policy=EXPLICIT_COMPARISON_POLICY,
        enable_region_equality=False, enable_connectivity=False,
        enable_callee_lemmas=False, skip_binary_equal=False,
    )
    assert compared["summary"]["passed"] == 1
    assert compared["results"][0]["layout_normalization"] is None


def test_layout_policy_is_per_invocation_and_keeps_declared_maps():
    from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY

    oracle = scalar_document(7, 16)["functions"][0]
    candidate = scalar_document(8, 16)["functions"][0]
    candidate["_constant_normalization"] = {9: 10}
    declared = deepcopy(candidate)
    for _ in range(2):
        left, right, detail = engine._prepare_layout_normalized_functions(
            oracle, candidate, global_map={8: 7}, comparison_policy=EXPLICIT_COMPARISON_POLICY,
        )
        assert left is oracle and right is candidate and detail is None
        left, right, detail = engine._prepare_layout_normalized_functions(oracle, candidate, global_map={8: 7})
        assert left is oracle and right["_constant_normalization"] == {9: 10, 8: 7}
        assert detail["global_pair_count"] == 1
        assert candidate == declared


def test_literal_identity_and_legacy_alias_are_backend_independent():
    from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY
    from tools.dosunit.ssa.identity import quick_compare, semantic_payload

    assert engine._quick_compare_functions is quick_compare
    assert engine._semantic_ssa_payload is semantic_payload
    body = scalar_document(7, 32)["functions"][0]
    assert quick_compare(body, deepcopy(body), skip_binary_equal=False,
                         comparison_policy=EXPLICIT_COMPARISON_POLICY)["reason"] == "ssa_equal"
    changed = deepcopy(body)
    changed["outputs"]["value"]["value"] = 8
    assert quick_compare(body, changed, skip_binary_equal=False,
                         comparison_policy=EXPLICIT_COMPARISON_POLICY) is None
    body["_constant_normalization"] = {7: 8}
    assert quick_compare(body, deepcopy(body), skip_binary_equal=False,
                         comparison_policy=EXPLICIT_COMPARISON_POLICY) is None
    assert quick_compare(body, deepcopy(body), skip_binary_equal=False)["reason"] == "ssa_equal"


def test_flat32_adapters_do_not_install_comparison_policy():
    script = """
import importlib.util
import sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
import tools.dosunit.compare.straightline_ssa as engine
layout = engine._prepare_layout_normalized_functions
identity = engine._quick_compare_functions
scan_admission = engine._can_add_dynamic_successor_range
for family in ('msc8', 'bc5'):
    path = root / 'artifacts' / (family + '-z3cmp32') / 'flat32_adapter.py'
    spec = importlib.util.spec_from_file_location(family + '_adapter', path)
    adapter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(adapter)
    for region in (False, True):
        with adapter.installed(region=region):
            assert engine._prepare_layout_normalized_functions is layout
            assert engine._quick_compare_functions is identity
            assert engine._can_add_dynamic_successor_range is scan_admission
        assert engine._prepare_layout_normalized_functions is layout
        assert engine._quick_compare_functions is identity
        assert engine._can_add_dynamic_successor_range is scan_admission
"""
    subprocess.run([sys.executable, "-I", "-c", script, str(Path(__file__).resolve().parents[3])],
                   check=True, capture_output=True, text=True, timeout=30)


def test_region_identity_cannot_override_normalized_block_mismatch(tmp_path):
    from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY

    image = bytearray(0x240)
    image[0x200:0x206] = bytes.fromhex("b80700 eb00 c3")
    size = 32 + len(image)
    header = struct.pack("<14H", 0x5A4D, size % 512, (size + 511) // 512,
                         0, 2, 0x1000, 0xFFFF, 0x80, 0xFFFE, 0, 0, 0, 0x1C, 0) + bytes(4)
    binary = tmp_path / "two_blocks.exe"
    binary.write_bytes(header + image)
    catalog = {"schema": "dosunit.functions.v1", "module": "test", "functions": [{
        "id": "test:f", "names": ["f"], "return_kind": "near", "size": 6,
        "entry": {"kind": "module_relative", "offset": "0x200", "segment_para": "0x0"},
    }]}
    oracle = engine.lower_straightline_ssa_document(
        exe_path=binary, functions_catalog=catalog, output_regs=("ax",),
    )
    assert len(oracle["functions"]) == 2
    candidate = deepcopy(oracle)
    for body in candidate["functions"]:
        body["_constant_normalization"] = {7: 8}
        body["_constant_normalization_reasons"] = {7: "global_reloc"}
    compared = engine.compare_ssa_documents(
        oracle=oracle, candidate=candidate, comparison_policy=EXPLICIT_COMPARISON_POLICY,
        skip_binary_equal=False,
    )
    assert compared["summary"]["passed"] < 2
    assert compared["summary"]["failed"] >= 1
    assert compared["region_equality"]["results"][0]["status"] == "refused"
    assert compared["region_equality"]["results"][0]["reason"] == "region_normalization_requires_block_proof"
