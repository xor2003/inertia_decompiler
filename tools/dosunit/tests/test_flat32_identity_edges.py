"""A proved all-identity control block contracts; everything else stays."""

import time
from dataclasses import replace
from typing import Any

import pytest

from tools.dosunit.compare import flat32_identity_edges as I
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionLimits,
    _ComposeSession,
    _LiftedBlock,
    _register_widths,
)


def _const(value: int) -> dict[str, Any]:
    return {"op": "const", "width": 32, "value": hex(value)}


def _input(name: str, width: int = 32) -> dict[str, Any]:
    return {"op": "input", "name": name, "width": width}


def _branch(predicate: dict[str, Any], left: int, right: int) -> dict[str, Any]:
    return {"op": "ite", "width": 32, "args": [predicate, _const(left), _const(right)]}


def _eq_eax(value: int) -> dict[str, Any]:
    return {"op": "eq", "width": 1, "args": [_input("eax"), _const(value)]}


def _identity(target: int) -> dict[str, Any]:
    """A real unconditional-jump block: full coverage, control leaves const."""
    outputs = {name: _input(name, w) for name, w in _register_widths().items()
               if name != "eip"}
    outputs["eip"] = _const(target)
    outputs["ip"] = _const(target)
    return {"outputs": outputs, "assignments": []}


def _block(outputs: dict[str, Any], successors: tuple[int, ...],
           jumpkind: str = "Ijk_Boring", **kw: Any) -> tuple[dict[str, Any], tuple[int, ...], str, dict[str, Any]]:
    return {"outputs": outputs, "assignments": []}, successors, jumpkind, kw


def _make(spec: dict[int, tuple[dict[str, Any], tuple[int, ...], str, dict[str, Any]]]) -> dict[int, _LiftedBlock]:
    return {
        a: _LiftedBlock(a, None, part, jk, succ, kw.get("call_target"), kw.get("fallthrough"),
                        kw.get("tail_targets", frozenset()), kw.get("external_slot"))
        for a, (part, succ, jk, kw) in spec.items()
    }


def _real_shape() -> dict[int, _LiftedBlock]:
    """Oracle find_map_entry shape: extra pure jmp 4->3 and loopback jmp 5->7."""
    return _make({
        0: _block({"ip": _const(1), "eip": _const(1)}, (1,)),
        1: _block({"ip": _branch(_eq_eax(0), 3, 2)}, (3, 2)),
        3: _block({"ip": _const(6), "eip": _const(6)}, (6,)),
        2: _block({"ip": _branch(_eq_eax(9), 4, 5)}, (4, 5)),
        4: _block(_identity(3)["outputs"], (3,)),
        5: _block(_identity(7)["outputs"], (7,)),
        7: _block({"ip": _branch(_eq_eax(0), 3, 2)}, (3, 2)),
        6: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })


def _run(blocks: dict[int, _LiftedBlock], entry: int = 0) -> I.IdentityEdgeResult:
    deadline = time.monotonic() + 5
    session = _ComposeSession(project=None, functions={entry: 4}, labels={},
                              limits=CallCompositionLimits(), reg_widths=_register_widths(),
                              compose_stats={"deadline": deadline})
    return I.contract_identity_edges(blocks, entry, session, deadline=deadline)


def test_real_shape_contracts_both_identity_jumps() -> None:
    blocks = _real_shape()
    result = _run(blocks)
    assert set(result.blocks) == {0, 1, 2, 3, 6, 7}
    assert result.attempted == 2
    assert [p.block for p in result.proofs] == [4, 5]
    preds = {p.block: p.predecessors for p in result.proofs}
    assert preds[4] == (2,) and preds[5] == (2,)
    assert sorted(result.proofs[0].identity_outputs) == sorted(
        [n for n in _register_widths() if n != "eip"])
    assert result.blocks[2].successors == (3, 7)
    rewritten = result.blocks[2].part["outputs"]["ip"]
    assert rewritten == _branch(_eq_eax(9), 3, 7)
    assert blocks[2].part["outputs"]["ip"]["args"][1]["value"] == hex(4)


def test_chain_contracts_transitively() -> None:
    blocks = _make({
        0: _block({"ip": _const(1), "eip": _const(1)}, (1,)),
        1: _block(_identity(2)["outputs"], (2,)),
        2: _block(_identity(3)["outputs"], (3,)),
        3: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    result = _run(blocks)
    assert set(result.blocks) == {0, 3}
    assert result.blocks[0].successors == (3,)
    assert result.blocks[0].part["outputs"]["ip"] == _const(3)
    assert [p.block for p in result.proofs] == [1, 2]


@pytest.mark.parametrize("change", [
    "register", "flag", "memory", "x87", "io", "obligation", "trap", "call",
    "indirect", "entry", "nonconst_ip", "missing_flag", "missing_x87",
    "ref_cycle", "self_ref", "mixed_width", "eip_divergent",
])
def test_non_identity_or_boundary_blocks_are_retained(change: str) -> None:  # noqa: C901 — negative mutation matrix.
    blocks = _make({
        0: _block({"ip": _const(1), "eip": _const(1)}, (1,)),
        1: _block(_identity(2)["outputs"], (2,)),
        2: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    entry = 0
    if change == "register":
        blocks[1].part["outputs"]["eax"] = {"op": "add", "width": 32,
                                            "args": [_input("eax"), _const(1)]}
    elif change == "flag":
        blocks[1].part["outputs"]["cc_op"] = _const(0xD)
    elif change == "memory":
        blocks[1].part["outputs"]["memory"] = {
            "op": "storele", "width": 0,
            "args": [{"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8},
                     _const(0x4000), _const(7)],
        }
    elif change == "x87":
        blocks[1].part["outputs"]["x87_st0"] = {"op": "const", "width": 80, "value": "0x0"}
    elif change == "io":
        blocks[1].part["outputs"]["io"] = {"op": "io_input", "name": "io"}
    elif change == "obligation":
        blocks[1].part["obligations"] = [{"kind": "pending_exception"}]
    elif change == "trap":
        blocks[1].part["trap_exits"] = [0x99]
    elif change == "call":
        blocks[0] = replace(blocks[0], jumpkind="Ijk_Call", call_target=99)
    elif change == "indirect":
        blocks[1].part["outputs"]["ip"] = _input("esi")
    elif change == "nonconst_ip":
        blocks[1].part["outputs"]["ip"] = {"op": "add", "width": 32,
                                           "args": [_input("eax"), _const(2)]}
    elif change == "missing_flag":
        del blocks[1].part["outputs"]["cc_op"]
    elif change == "missing_x87":
        del blocks[1].part["outputs"]["x87_st4"]
    elif change == "ref_cycle":
        blocks[1].part["outputs"]["ip"] = {"ref": "v0"}
        blocks[1].part["assignments"] = [{"id": "v0", "ref": "v1"},
                                       {"id": "v1", "ref": "v0"}]
    elif change == "self_ref":
        blocks[1].part["outputs"]["eax"] = {"ref": "v0"}
        blocks[1].part["assignments"] = [{"id": "v0", "ref": "v0"}]
    elif change == "mixed_width":
        blocks[1].part["outputs"]["eax"] = _input("eax", 16)
    elif change == "eip_divergent":
        blocks[0].part["outputs"]["eip"] = _const(1)
        blocks[1].part["outputs"]["eip"] = _const(2)
        blocks = _make({
            0: _block({"ip": _const(1), "eip": _const(1)}, (1,)),
            1: _block({**_identity(2)["outputs"], "eip": _const(3)}, (2,)),
            2: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
        })
    elif change == "entry":
        blocks = _make({
            0: _block(_identity(1)["outputs"], (1,)),
            1: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
        })
    result = _run(blocks, entry)
    assert not result.proofs
    if change == "entry":
        assert set(result.blocks) == {0, 1}
    else:
        assert 1 in result.blocks


def test_eip_target_set_divergence_retains_block() -> None:
    """ip redirects cleanly but eip collapses both arms: the set diverges."""
    blocks = _make({
        0: _block({"ip": _branch(_eq_eax(0), 1, 2), "eip": _const(1)}, (1, 2)),
        1: _block(_identity(2)["outputs"], (2,)),
        2: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    result = _run(blocks)
    assert not result.proofs
    assert 1 in result.blocks
    assert result.blocks[0].successors == (1, 2)


def test_identity_cycle_is_retained() -> None:
    blocks = _make({
        0: _block({"ip": _const(1), "eip": _const(1)}, (1,)),
        1: _block(_identity(2)["outputs"], (2,)),
        2: _block(_identity(1)["outputs"], (1,)),
        3: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    result = _run(blocks)
    assert not result.proofs
    assert set(result.blocks) == {0, 1, 2, 3}
    assert result.retained_cycles == (1, 2)
    assert result.blocks[0].successors == (1,)


def test_shared_ref_ip_rewritten_only_in_target_arms() -> None:
    pred_ip = _branch(_eq_eax(4), 4, 9)
    blocks = _make({
        0: _block({"ip": {"ref": "v0"}, "eip": {"ref": "v0"}}, (4, 9)),
        4: _block(_identity(3)["outputs"], (3,)),
        9: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
        3: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    blocks[0].part["assignments"] = [{"id": "v0", **pred_ip}]
    result = _run(blocks)
    assert result.proofs and result.proofs[0].block == 4
    rewritten = result.blocks[0].part["outputs"]["ip"]
    assert rewritten["args"][0] == _eq_eax(4)
    assert rewritten["args"][1] == _const(3)
    assert rewritten["args"][2] == _const(9)
    assert result.blocks[0].part["outputs"]["eip"] == rewritten


def test_two_target_predecessor_collapses_after_redirect() -> None:
    blocks = _make({
        0: _block({"ip": _branch(_eq_eax(0), 1, 2)}, (1, 2)),
        1: _block(_identity(2)["outputs"], (2,)),
        2: _block({"ip": _input("eax")}, (), "Ijk_Ret"),
    })
    result = _run(blocks)
    assert [p.block for p in result.proofs] == [1]
    assert result.blocks[0].successors == (2,)
    assert result.blocks[0].part["outputs"]["ip"] == _branch(_eq_eax(0), 2, 2)


def test_unclosed_map_keeps_original() -> None:
    blocks = _real_shape()
    blocks[5] = replace(blocks[5], successors=(0x9999,))
    result = _run(blocks)
    assert not result.proofs
    assert set(result.blocks) == set(blocks)


def test_expired_deadline_keeps_original_map() -> None:
    blocks = _real_shape()
    deadline = time.monotonic() - 1
    session = _ComposeSession(project=None, functions={0: 4}, labels={},
                              limits=CallCompositionLimits(), reg_widths=_register_widths(),
                              compose_stats={"deadline": deadline})
    result = I.contract_identity_edges(blocks, 0, session, deadline=deadline)
    assert not result.proofs
    assert result.blocks == blocks
