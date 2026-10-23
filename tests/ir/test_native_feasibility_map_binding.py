"""Native feasibility maps bind only blocks that can contribute rows."""
import sys
from dataclasses import replace

import pytest

from inertia.ir import real16_invocation_domain as owner
from tests.ir.test_callee_local_feasibility import SHARED, world

pytestmark = pytest.mark.decompiler


class StopObservation(Exception):
    """Stop after the real native map is handed to feasibility."""


@pytest.mark.parametrize("route", ["root", "callee"])
@pytest.mark.parametrize("mutation", ["none", "before", "callback"])
def test_load_maps_skip_empty_blocks_and_rebind_callbacks(tmp_path, monkeypatch, route, mutation):
    ctx, proof = world(tmp_path, SHARED)
    artifact = proof.callee.coverage.artifact
    blocks = artifact.blocks
    terminal = next(block for block in blocks if block.addr in proof.callee.return_block_addrs)
    loads = [row for block in blocks for row in block.instrs if row.op == "LOAD"]
    assert loads
    expected = {block.addr for block in blocks if any(row.op == "LOAD" for row in block.instrs)}
    assert len(expected) < len(blocks)
    if mutation == "before":
        object.__setattr__(loads[0], "size", loads[0].size + 1)
    counted = []
    original = owner._native_block_bound_8616

    def bind(native, block, **kwargs):
        caller = sys._getframe(1).f_code.co_name
        if caller in {"_census_invocation_8616", "_callee_feasible_scope_8616"}:
            counted.append(block.addr)
        return original(native, block, **kwargs)

    def observe(**kwargs):
        row = loads[0]
        if mutation == "callback":
            object.__setattr__(row, "size", row.size + 1)
        value = kwargs["read_load"](row, (0x2000, 2), owner.PathMemory8616())
        assert value == (77 if mutation == "none" else None)
        raise StopObservation

    monkeypatch.setattr(owner, "_native_block_bound_8616", bind)
    monkeypatch.setattr(owner, "path_load_value_8616", lambda *_args: 77)
    monkeypatch.setattr(owner, "invocation_feasible_scope_8616", observe)
    seed = owner._PathState8616({}, owner.PathMemory8616())
    with pytest.raises(StopObservation):
        if route == "callee":
            owner._callee_feasible_scope_8616(ctx, artifact, frozenset(proof.callee.return_block_addrs), seed)
        else:
            owner._census_invocation_8616(ctx, artifact, proof.callee.coverage.boundary,
                                        frozenset(block.addr for block in blocks), terminal,
                                        terminal.instrs[-1].addr, seed)
    assert set(counted) == expected


def test_call_map_ignores_empty_blocks_but_binds_eligible_rows(tmp_path, monkeypatch):
    ctx, proof = world(tmp_path, SHARED)
    artifact = proof.callee.coverage.artifact
    blocks = {block.addr: block for block in artifact.blocks}
    native = ctx.native_blocks[artifact.function_addr]
    calls = []
    original = owner._native_block_bound_8616

    def bind(native_block, block, **kwargs):
        calls.append(block.addr)
        return original(native_block, block, **kwargs)

    monkeypatch.setattr(owner, "_native_block_bound_8616", bind)
    assert owner._feasibility_call_rows_8616(blocks, native, frozenset(blocks), 0) == {}
    assert calls == []
    block = next(iter(blocks.values()))
    changed = replace(block.instrs[0], op="CALL", addr=block.addr)
    blocks[block.addr] = replace(block, instrs=(changed, *block.instrs[1:]))
    assert owner._feasibility_call_rows_8616(blocks, native, frozenset(blocks), 0) == {}
    assert calls == [block.addr]


@pytest.mark.parametrize("corrupt", [False, True])
def test_native_call_candidates_keep_exact_binding(tmp_path, monkeypatch, corrupt):
    """A real eligible CALL is retained only with the complete unchanged block."""
    from copy import deepcopy

    from tests.ir.test_segment_call_binding_regression import _coverage, _project

    project = _project(bytes.fromhex("83f8007403e80800c3") + b"\x90" * 7 + b"\xc3")
    coverage = _coverage(project, 0x1000, 0x1009)
    blocks = {block.addr: block for block in coverage.artifact.blocks}
    native = deepcopy(blocks)
    call = next(row for block in blocks.values() for row in block.instrs if row.op == "CALL")
    if corrupt:
        object.__setattr__(call, "size", call.size + 1)
    bound = owner._feasibility_call_rows_8616(blocks, native, frozenset(blocks), 0)
    assert (id(call) in bound) is not corrupt
    # The current terminal CALL never receives a callee-effect callback.
    assert owner._feasibility_call_rows_8616(blocks, native, frozenset(blocks), call.addr) == {}


@pytest.mark.parametrize("has_call", [False, True])
def test_malformed_call_block_remains_unbound(tmp_path, has_call):
    """Candidate filtering cannot dereference an unowned instruction payload."""
    from copy import deepcopy

    from inertia.ir.real16_edge_feasibility8616 import Real16CallCutRequest8616
    from tests.ir.test_segment_call_binding_regression import _coverage, _project

    project = _project(bytes.fromhex("e80d00c3") + b"\x90" * 12 + b"\xc3")
    coverage = _coverage(project, 0x1000, 0x1004)
    artifact = coverage.artifact
    blocks = {block.addr: block for block in artifact.blocks}
    native = deepcopy(blocks)
    block = next(block for block in blocks.values() if any(row.op == "CALL" for row in block.instrs))
    index = next(index for index, row in enumerate(block.instrs) if row.op == "CALL")
    cut = Real16CallCutRequest8616(artifact, block, index, block.instrs[index])
    rows = (object(), block.instrs[index]) if has_call else (object(),)
    blocks[block.addr] = replace(block, instrs=rows)
    assert owner._feasibility_call_rows_8616(blocks, native, frozenset(blocks), 0, call_cut=cut) == {}
