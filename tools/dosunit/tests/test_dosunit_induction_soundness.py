"""Focused real16 cyclic transition-system induction-soundness regressions.

Layer: dosunit semantic comparison tests.
Responsibility: prove the cyclic region lanes never claim equality over
cutpoint state a successor consumes but no predecessor publishes.  Uses real
byte lowering (MZ images lifted through the X86_16 backend) plus Z3, and
hand-built legacy docs for the narrow-output refusal boundary.
"""

from __future__ import annotations

from pathlib import Path

from tools.dosunit.compare.straightline_ssa import (
    INTERNAL_STATE_REGS,
    _region_cutpoint_state_gaps,
    compare_ssa_documents,
    lower_straightline_ssa_document,
)


def _mz_exe(image: bytes, *, minalloc: int = 0x1000) -> bytes:
    reloc_pos = 0x1C
    relocs: tuple[tuple[int, int], ...] = ()
    header_size = max(0x20, ((reloc_pos + len(relocs) * 4 + 15) // 16) * 16)
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x06:0x08] = len(relocs).to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0A:0x0C] = minalloc.to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    return bytes(header) + bytes(image)


def _catalog(*, offset: int, size: int, name: str = "loop") -> dict[str, object]:
    return {
        "schema": "dosunit.functions.v1",
        "id": "functions:test",
        "module": "demo.exe",
        "program_kind": "mz_exe",
        "functions": [
            {
                "id": f"demo.exe:{name}",
                "names": [name],
                "entry": {
                    "kind": "module_relative",
                    "segment": "seg000",
                    "segment_para": "0x0000",
                    "offset": f"0x{offset:04x}",
                },
                "return_kind": "near",
                "sources": ["fixture"],
                "confidence": "medium",
                "size": size,
                "safe_traps": [],
            }
        ],
        "diagnostics": [],
    }


def _write_loop_exe(tmp_path: Path, name: str, code: bytes) -> Path:
    image = bytearray(0x240)
    image[0x200 : 0x200 + len(code)] = code
    exe = tmp_path / name
    exe.write_bytes(_mz_exe(bytes(image)))
    return exe


def _lower(exe: Path, catalog: dict[str, object]) -> dict[str, object]:
    return lower_straightline_ssa_document(exe_path=exe, functions_catalog=catalog)


def _region_result(compared: dict[str, object]) -> dict[str, object]:
    results = compared["region_equality"]["results"]
    assert len(results) == 1
    return results[0]


def _part(document: dict[str, object], entry_delta: str) -> dict[str, object]:
    for function in document.get("functions", []) or []:
        part = function.get("part") if isinstance(function.get("part"), dict) else {}
        if str(part.get("entry_delta") or "") == entry_delta:
            return function
    raise AssertionError(f"no part at entry_delta {entry_delta}")


def test_dosunit_induction_publishes_complete_nonterminal_state(tmp_path: Path):
    """Nonterminal blocks must publish the full modeled register state."""
    code = bytes.fromhex("31c9 8ed9 eb00 8b07 83c302 83fb08 75f6 c3".replace(" ", ""))
    exe = _write_loop_exe(tmp_path, "loop.exe", code)
    document = _lower(exe, _catalog(offset=0x0200, size=len(code)))

    entry = _part(document, "0x0000")
    published = set(entry.get("outputs") or {})
    missing = sorted(set(INTERNAL_STATE_REGS) - published)
    assert not missing, f"nonterminal block omits cutpoint state: {missing}"


def test_dosunit_induction_rejects_changed_loop_carried_segment_state(tmp_path: Path):
    """mov ds,cx vs mov ds,dx feeding a later-block ds: load must never pass.

    The ds write lives in the entry block and the ds: load lives in the loop
    body, so the changed register only escapes via a dropped nonterminal
    output.  Before the fix this produced ``transition_system_equal``.
    """
    oracle_code = bytes.fromhex("31c9 8ed9 eb00 8b07 83c302 83fb08 75f6 c3".replace(" ", ""))
    candidate_code = bytes.fromhex("31c9 8eda eb00 8b07 83c302 83fb08 75f6 c3".replace(" ", ""))
    catalog = _catalog(offset=0x0200, size=len(oracle_code))
    oracle = _lower(_write_loop_exe(tmp_path, "oracle.exe", oracle_code), catalog)
    candidate = _lower(_write_loop_exe(tmp_path, "candidate.exe", candidate_code), catalog)

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)
    result = _region_result(compared)
    assert result["status"] != "passed"
    assert result["reason"] != "transition_system_equal"


def test_dosunit_induction_rejects_changed_loop_carried_flags_state(tmp_path: Path):
    """stc vs clc feeding a later-block conditional jump must never pass.

    The flag write and the ``jb`` that consumes it sit in different blocks;
    the predecessor's dropped flags output would otherwise be assumed
    unchanged by induction.
    """
    # stc; jmp +3 / jb self / ret  (candidate: clc; jmp +3 / jb self / ret)
    oracle_code = bytes.fromhex("f9 eb01 90 72fe c3".replace(" ", ""))
    candidate_code = bytes.fromhex("f8 eb01 90 72fe c3".replace(" ", ""))
    catalog = _catalog(offset=0x0200, size=len(oracle_code))
    oracle = _lower(_write_loop_exe(tmp_path, "oracle.exe", oracle_code), catalog)
    candidate = _lower(_write_loop_exe(tmp_path, "candidate.exe", candidate_code), catalog)

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)
    result = _region_result(compared)
    assert result["status"] != "passed"
    assert result["reason"] != "transition_system_equal"


def test_dosunit_induction_still_proves_identical_cyclic_regions(tmp_path: Path):
    """Full-state cutpoints must not break honest induction on equal loops."""
    code = bytes.fromhex("31c9 8ed9 eb00 8b07 83c302 83fb08 75f6 c3".replace(" ", ""))
    catalog = _catalog(offset=0x0200, size=len(code))
    oracle = _lower(_write_loop_exe(tmp_path, "oracle.exe", code), catalog)
    candidate = _lower(_write_loop_exe(tmp_path, "candidate.exe", code), catalog)

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)
    result = _region_result(compared)
    assert result["status"] == "passed"


def _block_stub(
    *,
    base: int,
    delta: int,
    index: int,
    successors: list[int] | None = None,
    inputs: list[dict[str, object]] | None = None,
    outputs: dict[str, object] | None = None,
) -> dict[str, object]:
    """Minimal block part shaped like a legacy narrow-output SSA doc."""
    linear = base + delta
    source: dict[str, object] = {
        "jumpkind": "Ijk_Boring" if successors else "Ijk_Ret",
        "instruction_count": 1,
        "instructions": [
            {
                "address": {"ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
                "disassembly": "jmp" if successors else "ret",
                "size": 1,
            }
        ],
        "machine_code_size": 1,
        "machine_code_sha256": "0" * 64,
    }
    if successors is not None:
        source["transfer"] = {
            "kind": "direct_successors",
            "jumpkind": "Ijk_Boring",
            "successors": [
                {"linear": f"0x{base + s:04x}", "low16": f"0x{(base + s) & 0xFFFF:04x}"}
                for s in successors
            ],
        }
    return {
        "id": f"ssa-function:demo.exe:loop:part{index}",
        "function": {"id": "demo.exe:loop", "name": "loop"},
        "part": {"kind": "block", "index": index, "entry_delta": f"0x{delta:04x}"},
        "function_entry": {"cs": "0x0000", "ip": f"0x{base & 0xFFFF:04x}", "linear": f"0x{base:04x}"},
        "entry": {"cs": "0x0000", "ip": f"0x{linear & 0xFFFF:04x}", "linear": f"0x{linear:04x}"},
        "source": source,
        "inputs": list(inputs or []),
        "outputs": dict(outputs or {"ax": {"op": "const", "value": "0x0000", "width": 16}}),
        "assignments": [],
    }


def _legacy_gap_blocks(*, consumed: str) -> list[dict[str, object]]:
    """Cyclic stub region whose delta-4 block reads a state name delta-0 hides."""
    entry = _block_stub(base=0x10740, delta=0x0000, index=0, successors=[0x0004])
    head = _block_stub(
        base=0x10740,
        delta=0x0004,
        index=1,
        successors=[0x0004, 0x0008],
        inputs=[{"name": consumed, "width": 16}],
        outputs={
            "ax": {"op": "const", "value": "0x0000", "width": 16},
            "ip": {
                "op": "ite",
                "width": 16,
                "args": [
                    {"op": "input", "name": consumed, "width": 16},
                    {"op": "const", "value": "0x0744", "width": 16},
                    {"op": "const", "value": "0x0748", "width": 16},
                ],
            },
        },
    )
    tail = _block_stub(base=0x10740, delta=0x0008, index=2)
    return [entry, head, tail]


def test_dosunit_induction_reports_cutpoint_state_gaps():
    """The gap audit names the exact unpublished consumed registers."""
    blocks = _legacy_gap_blocks(consumed="cx")
    gaps = _region_cutpoint_state_gaps(blocks)
    # Both the entry edge and the head's self-loop edge are uncovered.
    assert gaps == [
        {
            "kind": "cutpoint_state_gap",
            "from_delta": "0x0000",
            "to_delta": "0x0004",
            "missing_outputs": ["cx"],
        },
        {
            "kind": "cutpoint_state_gap",
            "from_delta": "0x0004",
            "to_delta": "0x0004",
            "missing_outputs": ["cx"],
        },
    ]

    cx_leaf = {"op": "input", "name": "cx", "width": 16}
    published = []
    for block in blocks:
        full = dict(block)
        full["outputs"] = {**(block.get("outputs") or {}), "cx": dict(cx_leaf)}
        published.append(full)
    assert _region_cutpoint_state_gaps(published) == []


def test_dosunit_induction_reports_unpublished_high_half_state():
    """A successor consuming a 386 high half the predecessor hides is a gap."""
    blocks = _legacy_gap_blocks(consumed="eax_hi")
    gaps = _region_cutpoint_state_gaps(blocks)
    assert {gap["from_delta"] for gap in gaps} == {"0x0000", "0x0004"}
    assert all(gap["missing_outputs"] == ["eax_hi"] for gap in gaps)


def test_dosunit_compare_ssa_region_refuses_legacy_narrow_cutpoints():
    """Legacy docs with hidden consumed state refuse rather than pass."""
    oracle = {
        "schema": "dosunit.ssa.v1",
        "exe": "oracle.exe",
        "functions": _legacy_gap_blocks(consumed="cx"),
    }
    candidate = {
        "schema": "dosunit.ssa.v1",
        "exe": "candidate.exe",
        "functions": _legacy_gap_blocks(consumed="cx"),
    }

    compared = compare_ssa_documents(oracle=oracle, candidate=candidate)
    result = _region_result(compared)
    assert result["status"] == "refused"
    assert result["reason"] == "cutpoint_state_incomplete"


def test_constant_control_target_preserves_intermediate_truncation():
    """A narrowed destination must not resolve to the original wider literal."""
    from tools.dosunit.compare.straightline_ssa import _target_key

    literal = {"op": "const", "value": "0x1234", "width": 16}
    narrowed = {"op": "trunc", "width": 8, "args": [literal]}
    assert _target_key({"op": "zext", "width": 16, "args": [narrowed]}) == 0x34
    negative = {"op": "const", "value": "0x80", "width": 8}
    assert _target_key({"op": "sext", "width": 16, "args": [negative]}) == 0xFF80
    assert _target_key({"op": "trunc", "width": 16, "args": [negative]}) is None


def test_induction_rejects_inverted_loop_guard(tmp_path: Path):
    """Identical successor sets cannot prove equal branch choices."""
    original = bytes.fromhex("83c001 83f805 75f8 c3")
    changed = bytes.fromhex("83c001 83f805 74f8 c3")
    catalog = _catalog(offset=0x0200, size=len(original))
    oracle = _lower(_write_loop_exe(tmp_path, "oracle.exe", original), catalog)
    candidate = _lower(_write_loop_exe(tmp_path, "candidate.exe", changed), catalog)
    result = _region_result(compare_ssa_documents(oracle=oracle, candidate=candidate))
    assert result["status"] != "passed"


def test_solver_compares_guarded_control_outputs():
    """Constant destinations do not make a conditional IP a layout-only value."""
    from tools.dosunit.compare.straightline_ssa import _compare_functions

    guard = {"op": "input", "name": "guard", "width": 1}
    first = {"op": "const", "value": "0x0200", "width": 16}
    second = {"op": "const", "value": "0x0208", "width": 16}
    common = {"inputs": [{"name": "guard", "width": 1}], "outputs": {"ip": {"ref": "next", "width": 16}}}
    oracle = {**common, "assignments": [{"id": "next", "op": "ite", "width": 16, "args": [guard, first, second]}]}
    candidate = {**common, "assignments": [{"id": "next", "op": "ite", "width": 16, "args": [guard, second, first]}]}
    assert _compare_functions(oracle, candidate, timeout_ms=1000)["status"] == "failed"
