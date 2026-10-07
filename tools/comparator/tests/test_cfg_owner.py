"""Canonical native CFG identity and conservative control-target admission."""

import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_legacy_cfg_exports_share_owner_without_installation(driver):
    root = Path(__file__).resolve().parents[3]
    script = """
import sys
import tools.dosunit.compare.straightline_ssa as engine
registers = engine.REG_BY_OFFSET
sys.path.insert(0, sys.argv[1])
import flat32_cfg as legacy
from tools.comparator import cfg
from tools.comparator.abi import DEFAULT_OUTPUT_REGS
assert legacy.OUTPUT_REGS is DEFAULT_OUTPUT_REGS
for name in ('Block', 'CfgRefusal', 'static_next', 'direct_successors', 'discover', 'pair_graphs', 'lower_blocks'):
    assert getattr(legacy, name) is getattr(cfg, name)
assert engine.REG_BY_OFFSET is registers
"""
    subprocess.run([sys.executable, "-c", script, str(root / "artifacts" / f"{driver}-z3cmp32")],
                   cwd=root, check=True)


def test_float_control_target_refuses_instead_of_truncating_or_crashing():
    import archinfo
    import pyvex

    from tools.comparator.cfg import CfgRefusal, direct_successors, static_next

    block = pyvex.IRSB.empty_block(archinfo.ArchX86(), addr=0x12345000)
    block.jumpkind = "Ijk_Boring"
    block.next = pyvex.expr.Const(pyvex.const.F64(float("nan")))
    assert static_next(block) is None
    with pytest.raises(CfgRefusal):
        direct_successors(block)


@pytest.mark.parametrize("driver", ["msc8", "bc5"])
def test_qualified_driver_import_and_historical_identity(driver):
    root = Path(__file__).resolve().parents[3]
    script = """
import importlib
import sys
owner = importlib.import_module('tools.comparator.' + sys.argv[2] + '_cli')
assert not {'flat32_adapter', 'flat32_cfg', 'flat32_region', 'flat32_catalog', 'flat32_scratch'} & sys.modules.keys()
sys.path.insert(0, sys.argv[1])
import z3cmp32
assert z3cmp32 is owner
"""
    subprocess.run([sys.executable, "-c", script, str(root / "artifacts" / f"{driver}-z3cmp32"), driver],
                   cwd=root, check=True)


def test_native_proof_owners_resolve_without_artifact_modules():
    root = Path(__file__).resolve().parents[3]
    script = """
import sys
from tools.comparator.services import proof_owners
assert not {'angr', 'pyvex', 'z3', 'tools.dosunit.compare.straightline_ssa'} & sys.modules.keys()
owners = proof_owners()
from tools.comparator import catalog, cfg, native, verdict
assert owners.model is native and owners.cfg is cfg
assert owners.catalog is catalog and owners.verdict is verdict
assert not {'flat32_adapter', 'flat32_cfg', 'flat32_catalog', 'flat32_verdict'} & sys.modules.keys()
import tools.dosunit.compare.straightline_ssa as engine
assert owners.model.S is engine
import angr
from tools.dosunit.compare.flat32_cfg_regions import compare_reblocked_cfg
oracle_code = bytes.fromhex('85c074034875fdc3')
for candidate_code, expected in ((oracle_code, verdict.Status.PASSED),
                                  (bytes.fromhex('85c074034075fdc3'), verdict.Status.REFUSED)):
    oracle = angr.load_shellcode(oracle_code, arch='x86', load_address=0x12345000)
    candidate = angr.load_shellcode(candidate_code, arch='x86', load_address=0x23456000)
    result = compare_reblocked_cfg((oracle, candidate), (0x12345000, len(oracle_code)),
                                  (0x23456000, len(candidate_code)), native.OUTPUT_REGS, 10000)
    assert result['status'] is expected, result
assert not {'flat32_adapter', 'flat32_cfg', 'flat32_catalog', 'flat32_verdict'} & sys.modules.keys()
"""
    subprocess.run([sys.executable, "-c", script], cwd=root, check=True)
