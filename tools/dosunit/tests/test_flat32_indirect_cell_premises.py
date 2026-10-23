"""Seeded literal-cell controls for deferred indirect calls in flat32 calls.

Layer: tests.
Responsibility: prove that a ``call r/m32`` whose destination is a preserved
literal ``loadle`` of a global pointer cell composes only by retrying under a
disclosed canonical root-entry premise naming the image bytes at that cell —
published as ``discovered_indirect_target_bytes`` — and that every weakening
(corrupted cell, overlapping write, non-entry target, generic callsite scope)
either produces a real behavioral mismatch or keeps the stable typed refusal,
through the MSC8 PE32 driver lane.
"""


# driver modules are dynamically loaded, so Any annotations are inherent.

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import angr
import pytest

pytestmark = [pytest.mark.ssa_z3, pytest.mark.runtime]

REPO_ROOT = Path(__file__).resolve().parents[3]

import tools.dosunit  # noqa: F401  (parent package before staged children)
from tools.dosunit.compare.flat32_call_composition import compare_functions_with_calls
from tools.dosunit.compare.flat32_call_contracts import (
    CallCompositionRefusal,
    IndirectReadProposal,
)
from tools.dosunit.compare.flat32_call_execution import (
    _indirect_cell_obligation,
    _indirect_read_proposal,
    _reduce_seeded_reads,
    _seed_premise_allowed,
)
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain

DRIVER_DIRS: dict[str, Path] = {
    "msc8": REPO_ROOT / "artifacts" / "msc8-z3cmp32",
}

# Top-level module names each driver dir provides; they collide across dirs
# and with anything already imported, so a lane swaps them atomically.
DRIVER_MODULES: tuple[str, ...] = (
    "flat32_adapter",
    "flat32_catalog",
    "flat32_cfg",
    "flat32_fast_pe",
    "flat32_region",
    "flat32_verdict",
    "z3cmp32",
)

# Union of every ``straightline_ssa`` global either adapter's installed()
# monkey-patches; snapshot/restore is a dynamic seam boundary by design.
SEAM_NAMES: tuple[str, ...] = (
    "_load_lifter_project",
    "_lower_function",
    "_vex_live_statement_indices",
    "REG_BY_OFFSET",
    "SSA_REGISTER_WIDTHS",
    "INTERNAL_STATE_REGS",
    "HIGH_HALF_REGS",
    "RAW_OUTPUT_REGS",
    "BYTE_REGISTER_ACCESS",
    "_lower_expr",
    "_read_register",
    "_write_register",
    "_register_write_target",
    "_finish_irsb_lowering",
    "_prepare_layout_normalized_functions",
    "_quick_compare_functions",
    "_can_add_dynamic_successor_range",
)

_MISSING: Any = object()

import tools.dosunit.compare.straightline_ssa as S


@contextmanager
def _driver_lane(name: str) -> Iterator[Any]:
    """Install one driver dir's modules and restore every global it disturbs."""
    import importlib

    directory = DRIVER_DIRS[name]
    saved_path = list(sys.path)
    saved_modules: dict[str, Any] = {mod: sys.modules.get(mod, _MISSING) for mod in DRIVER_MODULES}
    saved_seams: dict[str, Any] = {seam: getattr(S, seam, _MISSING) for seam in SEAM_NAMES}
    for mod in DRIVER_MODULES:
        sys.modules.pop(mod, None)
    sys.path.insert(0, str(directory))
    try:
        imported = {
            mod: importlib.import_module(mod)
            for mod in DRIVER_MODULES
            if (directory / f"{mod}.py").is_file()
        }
        yield {"lane_name": name, **imported}
    finally:
        sys.path[:] = saved_path
        for mod in DRIVER_MODULES:
            sys.modules.pop(mod, None)
        for mod, previous in saved_modules.items():
            if previous is not _MISSING:
                sys.modules[mod] = previous
        for seam, previous in saved_seams.items():
            if previous is _MISSING:
                if hasattr(S, seam):
                    delattr(S, seam)
            else:
                setattr(S, seam, previous)


@pytest.fixture(params=["msc8"], ids=["msc8"])
def lane(request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    """Run each driver test under the staged driver's isolated modules."""
    with _driver_lane(str(request.param)) as imported:
        yield imported


# --------------------------------------------------------------------------
# Fixtures: root -> allocator carrying a guarded global-callback read.
#
#   ROOT:  call ALLOC; ret
#   ALLOC: mov eax,[CELL]; or eax,eax; jz .skip; call eax; .skip: mov eax,2a; ret
#
# ``CELL`` is a four-byte global slot inside the image.  Its initial bytes are
# the seeded premise under test; program stores to it defeat preservation and
# must keep the stable refusal.
# --------------------------------------------------------------------------

BASE = 0x401000
ALLOC = BASE + 0x40
CB_A = BASE + 0x80
CELL = BASE + 0x400
DOMAIN = Flat32ProofDomain(0x7F000, 0x80000)


def _hex(code: str) -> bytes:
    return bytes.fromhex(code.replace(" ", ""))


def _rel32(src_end: int, dst: int) -> str:
    """Encode a relative32 call/jump displacement from the instruction end."""
    return (dst - src_end).to_bytes(4, "little", signed=True).hex()


def _cell_imm() -> str:
    """Little-endian imm32 for an absolute ``[CELL]`` operand."""
    return CELL.to_bytes(4, "little").hex()


F_ROOT = "e8" + _rel32(BASE + 5, ALLOC) + "c3"  # call ALLOC; ret

CB_A_BODY = "83c005 c3"  # add eax,5; ret


def _alloc_body(pre: str = "") -> str:
    """Allocator body reading ``CELL`` under a zero guard before ``call eax``."""
    return (
        pre
        + f"a1{_cell_imm()}"  # mov eax,[CELL]
        + "09c0"  # or eax,eax
        + "7402"  # jz .skip (+2: over the 2-byte call)
        + "ffd0"  # call eax
        + "b82a000000"  # .skip: mov eax,0x2a
        + "c3"  # ret
    )


def _alloc_overwrite_body() -> str:
    """Allocator body that stores a symbolic argument into ``CELL`` first."""
    return _alloc_body(
        pre="8b442404"  # mov eax,[esp+4]
        + f"a3{_cell_imm()}"  # mov [CELL],eax
    )


def _cell_image(alloc: str, cell_value: int, cb_a: str = CB_A_BODY) -> bytes:
    """Lay out root/alloc/callback code plus the global slot inside one image."""
    image = _hex(F_ROOT).ljust(0x40, b"\x90")
    image += _hex(alloc).ljust(0x40, b"\x90")
    image += _hex(cb_a).ljust(0x80, b"\x90")
    image = image.ljust(0x400, b"\x90")
    image += cell_value.to_bytes(4, "little")
    return image.ljust(0x410, b"\x90")


def _functions(alloc: str, cb_a: str = CB_A_BODY) -> dict[int, int]:
    return {
        BASE: len(_hex(F_ROOT)),
        ALLOC: len(_hex(alloc)),
        CB_A: len(_hex(cb_a)),
    }


def _project(image: bytes) -> angr.Project:
    """Load real i386 bytes as a flat shellcode project at the fixture base."""
    return angr.load_shellcode(image, arch="x86", load_address=BASE)


def _compare(
    adapter: Any,
    oracle_image: bytes,
    candidate_image: bytes,
    *,
    functions: dict[int, int],
) -> dict[str, Any]:
    """Compose both sides under this driver's adapter seams and compare."""
    with adapter.installed(region=True):
        return compare_functions_with_calls(
            _project(oracle_image),
            _project(candidate_image),
            oracle_entry=BASE,
            candidate_entry=BASE,
            oracle_functions=functions,
            candidate_functions=functions,
            outputs=("eax", "ebx", "ecx", "edx", "esi", "edi", "esp"),
            timeout_ms=15000,
            entry_domain=DOMAIN,
        )


# --------------------------------------------------------------------------
# Unit-level controls: gate shape, obligation document, seeded reduction.
# --------------------------------------------------------------------------


def _stub_session(**overrides: Any) -> Any:
    """Minimal session surface for the pure helpers under test."""
    defaults = {
        "root_bound_inputs": False,
        "root_entry": BASE,
        "seed_cells": {},
        "cells_used": {},
        "compose_stats": {},
        "entry_domain": None,
    }
    return SimpleNamespace(**{**defaults, **overrides})


def _const(value: int, width: int = 32) -> dict[str, Any]:
    return {"op": "const", "width": width, "value": hex(value)}


def _mem_input() -> dict[str, Any]:
    return {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}


def _storele(memory: dict[str, Any], address: int, value: int, width: int = 32) -> dict[str, Any]:
    return {"op": "storele", "width": 0,
            "args": [memory, _const(address), _const(value, width)]}


def test_retry_restores_evidence_without_refunding_consumed_work() -> None:
    """A discarded attempt removes partial records but still consumes its budget."""
    from tools.dosunit.compare.flat32_call_contracts import CallCompositionLimits, _ComposeSession
    from tools.dosunit.compare.flat32_call_execution import _evidence_snapshot, _restore_evidence

    session = _ComposeSession(
        project=None, functions={}, labels={}, limits=CallCompositionLimits(), reg_widths={},
    )
    session.call_sites.append({"retained": True})
    session.last_obligation_frame = [{"retained": True}]
    snapshot = _evidence_snapshot(session)
    session.call_sites.append({"discarded": True})
    session.external_sites.append({"discarded": True})
    session.return_targets_proved = 3
    session.last_obligation_frame = [{"discarded": True}]
    session.compositions = 7
    session.inlined_calls = 5
    session.tail_transfers = 2
    _restore_evidence(session, snapshot)
    assert session.call_sites == [{"retained": True}]
    assert session.external_sites == []
    assert session.return_targets_proved == 0
    assert session.last_obligation_frame == [{"retained": True}]
    assert (session.compositions, session.inlined_calls, session.tail_transfers) == (7, 5, 2)


def test_seed_premise_gate_anchors_root_entry_only() -> None:
    """Generic callees and prepared summaries may never anchor cell premises."""
    session = _stub_session()
    assert _seed_premise_allowed(session, BASE, 0)
    assert not _seed_premise_allowed(session, ALLOC, 0)
    assert not _seed_premise_allowed(session, ALLOC, 1)
    session.root_bound_inputs = True
    assert _seed_premise_allowed(session, ALLOC, 1)
    # Transition-bound values are not necessarily rooted at function entry.
    # A loop session has no top-level root anchor even when contextual.
    assert not _seed_premise_allowed(
        _stub_session(root_bound_inputs=True, root_entry=None), ALLOC, 1,
    )
    # A different root owner never admits the other entry's top-level frame.
    assert not _seed_premise_allowed(_stub_session(root_entry=ALLOC), BASE, 0)


def test_indirect_cell_obligation_document_shape() -> None:
    """The serialized premise reuses the accepted entry-range contract shape."""
    obligation = _indirect_cell_obligation(ALLOC, CELL, 0)
    assert obligation["kind"] == "flat32_entry_memory_unsigned_range"
    assert obligation["literal_constants"] is True
    assert obligation["address"] == hex(CELL)
    assert obligation["width"] == 32
    assert obligation["min"] == obligation["max"] == 0
    assert obligation["provenance"] == "discovered_indirect_target_bytes"
    assert obligation["site"]["function_entry"] == hex(ALLOC)
    predicate = obligation["predicate"]
    assert predicate["op"] == "and"
    assert {arg["op"] for arg in predicate["args"]} == {"uge", "ule"}
    bound = predicate["args"][0]["args"][0]
    assert bound["op"] == "loadle" and bound["args"][0]["op"] == "mem_input"


def test_seeded_read_reduction_requires_preservation() -> None:
    """Only a read proved disjoint from every intervening store folds."""
    session = _stub_session(seed_cells={CELL: 0})
    read = {"op": "loadle", "width": 32,
            "args": [_storele(_mem_input(), 0x3000, 7), _const(CELL)]}
    reduced = _reduce_seeded_reads(read, session, [], ALLOC, {})
    assert reduced is not read
    seeded_mem = reduced["args"][0]
    assert seeded_mem["op"] == "storele"
    assert seeded_mem["args"][0]["op"] == "mem_input"
    assert int(seeded_mem["args"][1]["value"], 16) == CELL
    assert session.cells_used == {ALLOC: {CELL}}
    # An overlapping store defeats preservation: the read stays symbolic.
    overlap = {"op": "loadle", "width": 32,
               "args": [_storele(_mem_input(), CELL, 7), _const(CELL)]}
    assert _reduce_seeded_reads(overlap, session, [], ALLOC, {}) is overlap
    # An unseeded literal address is never touched.
    unseeded = {"op": "loadle", "width": 32, "args": [_mem_input(), _const(0x3000)]}
    assert _reduce_seeded_reads(unseeded, session, [], ALLOC, {}) is unseeded


def test_indirect_read_proposal_scope_and_shape() -> None:
    """The proposal gate refuses out-of-scope or unpreserved reads cleanly."""
    session = _stub_session(entry_domain=DOMAIN)
    preserved = {"op": "loadle", "width": 32,
                 "args": [_storele(_mem_input(), 0x3000, 7), _const(CELL)]}
    # Outside the canonical root-entry frame: no proposal, no cells.
    assert _indirect_read_proposal(session, ALLOC, 1, preserved) is None
    # A symbolic-addressed table read is never a cell premise.
    table = {"op": "loadle", "width": 32,
             "args": [_mem_input(), {"op": "reg_input", "name": "eax", "width": 32}]}
    assert _indirect_read_proposal(session, BASE, 0, table) is None
    # An overlapping store keeps the leaf unpreserved: no proposal.
    overlap = {"op": "loadle", "width": 32,
               "args": [_storele(_mem_input(), CELL, 7), _const(CELL)]}
    assert _indirect_read_proposal(session, BASE, 0, overlap) is None
    # A non-32-bit read at the same address is not a callback cell.
    narrow = {"op": "loadle", "width": 8,
              "args": [_mem_input(), _const(CELL)]}
    assert _indirect_read_proposal(session, BASE, 0, narrow) is None
    # The typed signal keeps the stable refusal label and binds the cell.
    proposal = IndirectReadProposal({CELL: 0})
    assert str(proposal) == "call_indirect_target_unconstrained"
    assert proposal.cells == {CELL: 0}
    assert isinstance(proposal, CallCompositionRefusal)


# --------------------------------------------------------------------------
# Driver-level controls through compare_functions_with_calls.
# --------------------------------------------------------------------------


def test_zero_callback_cell_proves_conditional(lane: dict[str, Any]) -> None:
    """A zeroed callback cell proves under the disclosed entry premise."""
    alloc = _alloc_body()
    functions = _functions(alloc)
    verdict = _compare(
        lane["flat32_adapter"],
        _cell_image(alloc, 0),
        _cell_image(alloc, 0),
        functions=functions,
    )
    assert verdict["status"] == "conditional", verdict
    assumption = verdict["indirect_cell_assumptions"]
    assert assumption["kind"] == "discovered_indirect_target_bytes"
    bound = {(item["side"], item["address"]) for item in assumption["obligations"]}
    assert bound == {("oracle", hex(CELL)), ("candidate", hex(CELL))}
    assert all(item["min"] == item["max"] == 0 for item in assumption["obligations"])
    assert all(
        item["site"]["function_entry"] == hex(ALLOC)
        for item in assumption["obligations"]
    )
    # The guarded call stays dead under the premise: no indirect callback
    # record survives in either side's published call-site evidence.
    assert not [
        site
        for side in ("oracle", "candidate")
        for site in verdict["call_sites"][side]
        if site.get("indirect")
    ]


def test_live_callback_cell_dispatches_declared_target(lane: dict[str, Any]) -> None:
    """A nonzero cell naming a declared entry composes the guarded callback."""
    alloc = _alloc_body()
    functions = _functions(alloc)
    verdict = _compare(
        lane["flat32_adapter"],
        _cell_image(alloc, CB_A),
        _cell_image(alloc, CB_A),
        functions=functions,
    )
    assert verdict["status"] == "conditional", verdict
    assumption = verdict["indirect_cell_assumptions"]
    assert all(
        item["min"] == item["max"] == CB_A for item in assumption["obligations"]
    )
    sites = [
        site
        for side in ("oracle", "candidate")
        for site in verdict["call_sites"][side]
        if site.get("indirect")
    ]
    assert {site["target"] for site in sites} == {hex(CB_A)}


def test_corrupted_candidate_cell_never_passes(lane: dict[str, Any]) -> None:
    """A candidate cell pointing outside declared functions must not admit."""
    alloc = _alloc_body()
    functions = _functions(alloc)
    verdict = _compare(
        lane["flat32_adapter"],
        _cell_image(alloc, 0),
        _cell_image(alloc, BASE + 0x410),
        functions=functions,
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("call_target_unmapped"), verdict


def test_overwritten_cell_keeps_stable_refusal(lane: dict[str, Any]) -> None:
    """A callee store into the cell defeats preservation and refuses as before."""
    alloc = _alloc_overwrite_body()
    functions = _functions(alloc)
    verdict = _compare(
        lane["flat32_adapter"],
        _cell_image(alloc, 0),
        _cell_image(alloc, 0),
        functions=functions,
    )
    assert verdict["status"] == "refused", verdict
    assert str(verdict["reason"]).startswith("call_indirect_target"), verdict
    assert "indirect_cell_assumptions" not in verdict
