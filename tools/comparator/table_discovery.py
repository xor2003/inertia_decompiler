"""Layer: comparator evidence discovery.

Responsibility: propose bounded entry-switch catalogs from decoded native
operands. Proposals require all existing table lemmas before any proof credit.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import capstone

from tools.comparator.table_checks import TargetTable, read_pe_bytes, read_target_table
from tools.comparator.table_dispatch_checks import read_table_dispatch


@dataclass(frozen=True)
class EntryTable:
    """A binary-derived proposal, not a certificate of reachable table contents."""

    entry: int
    dispatch: int
    table: TargetTable


def _guarded_table(image: bytes, entry: int, end: int, branch: capstone.CsInsn,
                   comparison: capstone.CsInsn | None) -> EntryTable | None:
    """Recognize CMP r32,N; JA default; JMP [r32*4+table], bounded to 256 slots."""
    if comparison is None or comparison.id != capstone.x86.X86_INS_CMP:
        return None
    operands = comparison.operands
    if len(operands) != 2 or operands[0].type != capstone.x86.X86_OP_REG or operands[1].type != capstone.x86.X86_OP_IMM:
        return None
    count = operands[1].imm + 1
    if operands[0].size != 4 or not 1 <= count <= 256:
        return None
    site = branch.address + branch.size
    # The canonical indexed near jump occupies seven bytes. Do not borrow
    # an instruction from outside the declared function to propose a table.
    if site + 7 > end:
        return None
    dispatch = read_table_dispatch(image, site)
    if dispatch is None or dispatch.transfer != "jump" or dispatch.scale != 4:
        return None
    if dispatch.index_register != comparison.reg_name(operands[0].reg):
        return None
    table = read_target_table(image, dispatch.table_address, count)
    for target in set(table.targets):
        read_pe_bytes(image, target, 1, executable=True)
    return EntryTable(entry, site, table)


def _entry_table(image: bytes, entry: int, size: int) -> EntryTable | None:
    """Stop at the first control transfer; no multi-block reachability is guessed."""
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    decoder.detail = True
    previous: capstone.CsInsn | None = None
    try:
        raw = read_pe_bytes(image, entry, min(size, 128), executable=True)
        for instruction in decoder.disasm(raw, entry):
            if instruction.id == capstone.x86.X86_INS_JA:
                return _guarded_table(image, entry, entry + size, instruction, previous)
            if any(instruction.group(group) for group in (capstone.CS_GRP_JUMP, capstone.CS_GRP_CALL, capstone.CS_GRP_RET)):
                return None
            previous = instruction
    except ValueError:
        # A missing file-backed extent is absent proposal evidence. The normal
        # function proof retains its own typed refusal; this grants no verdict.
        return None
    return None


def _table_pair(original: EntryTable, candidate: EntryTable) -> dict[str, Any] | None:
    """Propose correspondence by index, rejecting inconsistent duplicate targets."""
    if len(original.table.targets) != len(candidate.table.targets):
        return None
    pairs: dict[int, int] = {}
    for left, right in zip(original.table.targets, candidate.table.targets, strict=True):
        if left in pairs and pairs[left] != right:
            return None
        pairs[left] = right
    return {
        "original_entry": hex(original.entry), "candidate_entry": hex(candidate.entry),
        "original_dispatch": hex(original.dispatch), "candidate_dispatch": hex(candidate.dispatch),
        "original_table": hex(original.table.address), "candidate_table": hex(candidate.table.address),
        "original_count": len(original.table.targets), "candidate_count": len(candidate.table.targets),
        "target_pairs": [{"original": hex(left), "candidate": hex(right)} for left, right in sorted(pairs.items())],
        "check_returning_targets": True, "assume_initial_tables": True,
        "check_selected_slots": True,
    }


def discover_entry_tables(
    original_image: bytes, candidate_image: bytes,
    original_ranges: Mapping[str, tuple[int, int]], candidate_ranges: Mapping[str, tuple[int, int]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build untrusted proposals for the existing full table-proof pipeline.

    Slot pairing is a proposal, not a semantic or symbol match. Every proposed
    target and default continuation must still prove equivalent, as must the
    prefix state, index domain and table preservation. Successful whole-root
    proofs remain conditional on published initial-table byte premises.
    """
    functions: dict[str, list[dict[str, Any]]] = {}
    searched = sorted(original_ranges.keys() & candidate_ranges.keys())
    for name in searched:
        left = _entry_table(original_image, *original_ranges[name])
        if left is None:
            continue
        right = _entry_table(candidate_image, *candidate_ranges[name])
        if right is not None:
            item = _table_pair(left, right)
            if item is not None:
                functions[name] = [item]
    return {"schema": "comparator.target_table_catalog.v1", "functions": functions}, {
        "schema": "comparator.entry_table_discovery.v1", "function_equivalence_proved": False,
        "searched_functions": searched, "proposed_functions": sorted(functions),
        "original_sha256": hashlib.sha256(original_image).hexdigest(),
        "candidate_sha256": hashlib.sha256(candidate_image).hexdigest(),
        "method": "decoded CMP r32, immediate; JA default; indexed DWORD JMP",
        "max_prefix_bytes": 128, "max_table_entries": 256,
        "target_correspondence": "slot-index proposals; each target pair still requires behavioral proof",
        "pending_conditions": ["all existing prefix, dispatch, target and default semantic lemmas",
                               "initial table memory remains an explicit conditional premise"],
    }
