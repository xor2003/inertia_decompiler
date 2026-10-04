"""Register versions and closed full-width control survive SSA composition."""

from __future__ import annotations

from types import SimpleNamespace

import archinfo
import pytest
import pyvex

from tools.dosunit import straightline_ssa as S
from tools.dosunit.ssa_control_flow import ControlIndexReason, ControlIndexRefusal, closed_block_index


def _flags_block(*, branch: bool):
    """Use real VEX statements to consume FLAGS after a write within a block."""
    tyenv = pyvex.IRTypeEnv(archinfo.ArchX86())
    statements = [pyvex.stmt.Put(pyvex.expr.Const(pyvex.const.U16(1)), 36)]
    if branch:
        guard = pyvex.expr.Unop("Iop_16to1", [pyvex.expr.Get(36, "Ity_I16")])
        statements.append(pyvex.stmt.Exit(guard, pyvex.const.U32(0x200), "Ijk_Boring", 32))
    else:
        temp = tyenv.add("Ity_I16")
        statements.extend([pyvex.stmt.WrTmp(temp, pyvex.expr.Get(36, "Ity_I16")),
                           pyvex.stmt.Put(pyvex.expr.RdTmp(temp), 0)])
    return SimpleNamespace(statements=statements, tyenv=tyenv,
                           next=pyvex.expr.Const(pyvex.const.U32(0x100)))


@pytest.mark.parametrize("source", ["VEX", "AIL"])
def test_latest_flags_version_is_read(source):
    """Both adapters share sequential packed-FLAGS register versions."""
    state = S._initial_reg_versions()
    assert S._read_register(state, 36, 16, source=source).op == "input"
    for value in (0x40, 2):
        written = S.SsaExpr("const", 16, value=value)
        assert S._write_register(state, 36, written) is None
        assert S._read_register(state, 36, 16, source=source) == written


@pytest.mark.parametrize("branch", [False, True], ids=["data", "control"])
def test_internal_flags_use_survives_excluded_output(branch):
    """Omitting FLAGS from outputs cannot erase a write consumed internally."""
    output = "ip" if branch else "ax"
    lowered = S._lower_irsb(_flags_block(branch=branch), output_regs=(output,),
                           max_assignments_per_function=64)
    assert isinstance(lowered, dict), lowered
    expected = {**lowered, "outputs": {output: {"op": "const", "width": 16,
                                              "value": hex(0x200 if branch else 1)}}}
    assert S._compare_functions(lowered, expected, timeout_ms=3000)["status"] == "passed"
    assert all(item["name"] != "flags" for item in lowered["inputs"])


def test_full_control_index_keeps_distinct_high_words():
    """Different physical blocks cannot replace one another through low IP."""
    blocks = [{"entry": {"linear": hex(address), "ip": "0x1200"},
               "outputs": {"control_ip": {"op": "const", "width": 32, "value": hex(address)}}}
              for address in (0x11200, 0x21200)]
    index = closed_block_index(blocks)
    for block in blocks:
        assert S._successor_for_target(block["outputs"]["control_ip"], index) is block
    assert 0x1200 not in index


def test_contradictory_legacy_alias_refuses():
    """A legacy ambiguous IP is missing address evidence, never a chosen block."""
    with pytest.raises(ControlIndexRefusal) as failure:
        closed_block_index([{"entry": {"ip": "0x1200"}}, {"entry": {"ip": "0x1200"}}])
    assert failure.value.reason is ControlIndexReason.AMBIGUOUS


def test_unresolved_nonterminal_control_is_not_a_return():
    """Unknown continuing control cannot establish a function terminal count."""
    block = {"entry": {"linear": "0x1200"},
             "source": {"jumpkind": "Ijk_Boring", "transfer": {"kind": "direct_successors"}},
             "outputs": {"ip": {"op": "input", "name": "ip", "width": 16}}}
    with pytest.raises(S.LowerFailure, match="nonterminal control"):
        S._compose_abi_state(block, {}, abi_function={}, block_by_key={0x1200: block}, path=[])
