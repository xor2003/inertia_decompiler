"""Symbolic observations of an actual BC31-recompiled generated function.

Layer: tests.
Responsibility: retain the isolated bitfield score witness and its explicit
entry/private-storage premises. This is not full ABI or whole-case acceptance.
The source C is provenance only; both computations come from lifted bytes.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import (
    Real16CallLimits,
    initial_state,
    prove_terms_equal,
    substitute,
)
from tools.dosunit.compare.real16_call_execution import summarize
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe

DATA = Path(__file__).parent / "data" / "bitfield_score"
DS = 0x277
PRIVATE_OFFSETS = (*range(0xFFB8, 0xFFF8), *range(0xA96, 0xA9A),
                   *range(0xAA6, 0xAAA), 0xD44, 0xD45)


def _constant(value: int, width: int = 16) -> dict[str, Any]:
    """One exact bitvector literal in the existing SSA contract."""
    return {"op": "const", "width": width, "value": hex(value)}


def _load(memory: dict[str, Any], offset: int, width: int = 16) -> dict[str, Any]:
    """Read a fixture byte/word from its declared DS coordinate."""
    return {"op": "loadle", "width": width,
            "args": [memory, _constant(DS * 16 + offset, 32)]}


def _store(memory: dict[str, Any], offset: int, value: dict[str, Any]) -> dict[str, Any]:
    """Write an explicit entry binding or private-footprint restoration."""
    return {"op": "storele", "width": 0,
            "args": [memory, _constant(DS * 16 + offset, 32), value]}


def _fixture_code(record: dict[str, Any]) -> bytes:
    """Reject accidental changes to the recorded compiler byte slice."""
    body = bytes.fromhex(record["code_hex"])
    assert len(body) == record["size"]
    assert hashlib.sha256(body).hexdigest() == record["sha256"]
    return body


def _lower(
    tmp_path: Path, fixture: dict[str, Any], side: str,
    mutation: tuple[int, bytes, bytes] | None,
) -> dict[str, Any]:
    """Embed the exact function and helper slices in a small loadable MZ."""
    image = bytearray(0x700)
    records = [fixture[side]] + ([fixture["helper"]] if side == "candidate" else [])
    functions = []
    for index, record in enumerate(records):
        body = _fixture_code(record)
        start = record["entry"]
        image[start:start + len(body)] = body
        name = "score" if index == 0 else "helper"
        functions.append(_edge_function(f"demo.exe:{name}", name, offset=start, size=len(body)))
    if mutation is not None:
        address, before, after = mutation
        assert len(before) == len(after)
        assert image[address:address + len(before)] == before
        image[address:address + len(after)] = after
    exe = tmp_path / f"{side}.exe"
    exe.write_bytes(_mz_exe(bytes(image)))
    catalog = {"schema": "dosunit.functions.v1", "module": "demo.exe",
               "program_kind": "mz_exe", "functions": functions, "diagnostics": []}
    doc = S.lower_straightline_ssa_document(
        exe_path=exe, functions_catalog=catalog, output_regs=S.INTERNAL_STATE_REGS,
        max_insns_per_function=512, max_assignments_per_function=4096,
    )
    assert doc["counters"]["functions_refused"] == 0, doc["refusals"]
    return doc


def _observations(
    tmp_path: Path, mutation: tuple[int, bytes, bytes] | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Compose real calls, then bind the explicitly conditional fixture domain."""
    fixture = json.loads((DATA / "fixture.json").read_text())
    assert hashlib.sha256((DATA / "generated.c").read_bytes()).hexdigest() == fixture["provenance"]["payload"]["sha256"]
    entry = initial_state()
    for name, value in (("cs", 0x100), ("ds", DS), ("ss", DS), ("sp", 0xFFF8)):
        entry[name] = _constant(value)
    memory = _store(entry["memory"], 0xFFF8, _constant(0x15B))
    entry["memory"] = _store(memory, 0xFFFA, _constant(0x400))
    states = []
    for side in ("oracle", "candidate"):
        doc = _lower(tmp_path, fixture, side, mutation if side == "candidate" else None)
        state, session = summarize(doc, "demo.exe:score", limits=Real16CallLimits(), timeout_ms=15000)
        bindings = dict(entry)
        if side == "candidate":
            memory = entry["memory"]
            for offset, register in ((0xA96, "ax"), (0xA98, "eax_hi"),
                                     (0xAA6, "si"), (0xAA8, "esi_hi")):
                memory = _store(memory, offset, entry[register])
            bindings["memory"] = _store(memory, 0xD44, _constant(DS))
            assert session.inlined_calls == session.return_targets_proved == session.cs_preserved_proved == 1
        cache: dict[int, dict[str, Any]] = {}
        states.append({name: substitute(term, bindings, cache) for name, term in state.items()})
    return states[0], states[1], entry


def _frame(memory: dict[str, Any], original: dict[str, Any]) -> dict[str, Any]:
    """Expose every byte outside the declared, fixed private fixture storage."""
    # This footprint is not inferred from differing stores. It is disjoint
    # from the four input bytes at0400 and the return/argument frame atFFF8.
    assert not set(PRIVATE_OFFSETS).intersection((*range(0x400, 0x404), *range(0xFFF8, 0xFFFC)))
    for offset in PRIVATE_OFFSETS:
        memory = _store(memory, offset, _load(original, offset, 8))
    return memory


def test_compiled_generated_score_under_declared_observations(tmp_path: Path) -> None:
    """Symbolic data satisfy scoped effects and the declared near return."""
    oracle, candidate, entry = _observations(tmp_path)
    pairs = [(name, oracle[name], candidate[name]) for name in ("ax", "sp", "bp", "si", "di", "esi_hi")]
    pairs.extend((
        ("runtime_si", entry["si"], _load(candidate["memory"], 0xAA6)),
        ("runtime_esi_hi", entry["esi_hi"], _load(candidate["memory"], 0xAA8)),
        ("framed_memory", _frame(oracle["memory"], entry["memory"]),
         _frame(candidate["memory"], entry["memory"])),
    ))
    for name, left, right in pairs:
        assert prove_terms_equal(left, right, 5000) is ProofStatus.PROVED, name
    for side, state in (("oracle", oracle), ("candidate", candidate)):
        # The composer exposes a physical control coordinate, not an IP offset.
        for name, expected in (("cs", entry["cs"]), ("control_ip", _constant(0x115B, 32))):
            assert prove_terms_equal(state[name], expected, 5000) is ProofStatus.PROVED, (side, name)


@pytest.mark.parametrize(("mutation", "observation"), [
    ((0x39F, bytes.fromhex("26034502"), bytes.fromhex("262b4502")), "ax"),
    ((0x389, bytes.fromhex("250100"), bytes.fromhex("250000")), "ax"),
    ((0x39F, bytes.fromhex("26034502"), bytes.fromhex("26014502")), "memory"),
], ids=["wrong_return", "omitted_bit", "input_store"])
def test_compiled_generated_score_mutations_have_counterexamples(
    tmp_path: Path, mutation: tuple[int, bytes, bytes], observation: str,
) -> None:
    """Real code mutations fail the corresponding scalar or user-memory proof."""
    oracle, candidate, entry = _observations(tmp_path, mutation)
    left, right = oracle[observation], candidate[observation]
    if observation == "memory":
        left, right = _frame(left, entry["memory"]), _frame(right, entry["memory"])
    assert prove_terms_equal(left, right, 5000) is ProofStatus.COUNTEREXAMPLE
