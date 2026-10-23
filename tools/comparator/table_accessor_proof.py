"""Layer: validation conditional read-accessor switch composition.

Responsibility: prove exact MOV EAX,moffs32; RET targets under explicit live
byte-equality premises, checking their consistency with initial table bytes.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from tools.comparator.table_checks import read_pe_bytes
from tools.comparator.table_function_proof import initial_table_premise, promote_table_function
from tools.comparator.table_prefix_checks import _prefix


def _accessor(image: bytes, address: int) -> tuple[int, bytes] | None:
    """Recognize exact unprefixed i386 absolute DWORD load and near return.

    MOV changes EAX only. Equal loaded bytes give equal EAX; identical RET
    encodings use equal ESP and shared memory for identical return effects.
    No address constants are rewritten, and no memory or flags are dropped.
    """
    try:
        raw = read_pe_bytes(image, address, 6, executable=True)
        if raw[0] != 0xA1 or raw[5] not in (0xC3, 0xC2):
            return None
        if raw[5] == 0xC2:
            raw = read_pe_bytes(image, address, 8, executable=True)
    except ValueError:
        return None
    location = int.from_bytes(raw[1:5], "little")
    if location + 4 > 0x100000000:
        return None
    return location, raw[5:]


def joint_read_premise(tables: dict[str, Any], reads: list[tuple[int, int]]) -> dict[str, Any]:
    """Decide consistency of byte equalities and fixed table bytes by union-find.

    Equality classes can share at most one fixed byte value. This proves
    satisfiability even when reads overlap each other or a target table.
    """
    parents: dict[int, int] = {}

    def root(address: int) -> int:
        """Find the canonical byte class with iterative path compression."""
        parents.setdefault(address, address)
        while parents[address] != address:
            parents[address] = parents[parents[address]]
            address = parents[address]
        return address

    for left, right in reads:
        if not 0 <= left <= 0xFFFFFFFC or not 0 <= right <= 0xFFFFFFFC:
            raise ValueError("read relation requires non-wrapping DWORD extents")
        for offset in range(4):
            parents[root(left + offset)] = root(right + offset)
    fixed: dict[int, int] = {}
    for table in tables["tables"].values():
        start = int(table["address"], 0)
        for index, target in enumerate(table["targets"]):
            for offset, byte in enumerate(int(target, 0).to_bytes(4, "little")):
                address = root(start + index * 4 + offset)
                if address in fixed and fixed[address] != byte:
                    return {"status": "incomplete", "reason": "read_relation_conflicts_with_table_bytes",
                            "jointly_satisfiable": False}
                fixed[address] = byte
    return {"status": "checked", "kind": "root_live_global_byte_equalities", "proved": False,
            "jointly_satisfiable": True,
            "reads": [{"original": hex(a), "candidate": hex(b), "width": 4} for a, b in sorted(set(reads))],
            "scope": "at root entry each paired four-byte range has equal live contents in shared memory; "
                     "actual runtime initialization and preservation before the root are assumed"}


def _memory_unchanged(image: bytes, facts: dict[str, Any]) -> bool:
    """Require the native prefix to preserve the entire shared byte array."""
    document, _ = _prefix(image, int(facts["entry"], 0), int(facts["dispatch"], 0))
    return document is not None and document["outputs"]["memory"] == {
        "op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}


def _accessor_lemmas(check: dict[str, Any], images: tuple[bytes, bytes]) -> tuple[list[dict[str, Any]], list[tuple[int, int]]] | None:
    """Cover every declared slot with an exact read/return instruction lemma."""
    pairs = sorted({(int(entry["original_target"], 0), int(entry["candidate_target"], 0))
                    for entry in check["entries"]})
    lemmas: list[dict[str, Any]] = []
    reads: list[tuple[int, int]] = []
    for left, right in pairs:
        original, candidate = _accessor(images[0], left), _accessor(images[1], right)
        if original is None or candidate is None or original[1] != candidate[1]:
            return None
        reads.append((original[0], candidate[0]))
        lemmas.append({"original": {"address": hex(left)}, "candidate": {"address": hex(right)},
                       "status": "checked", "method": "exact_mov_eax_moffs32_matching_near_ret"})
    return lemmas, reads


def promote_accessor_switch(row: dict[str, Any], original: bytes, candidate: bytes) -> None:
    """Join read relations with every existing prefix/table/default obligation.

    The strict report remains intact. Only a refused single-switch function can
    gain conditional credit, and only when its prefix writes no memory at all.
    """
    checks = row.get("partial_table_checks", [])
    if row["status"] != "refused" or len(checks) != 1:
        return
    check = checks[0]
    if not check.get("count_matches") or not check["entries"] or any(
            entry["status"] != "checked" for entry in check["entries"]):
        return
    prefix = check.get("prefix_check", {})
    if prefix.get("status") != "checked" or any(
            not _memory_unchanged(image, prefix[side])
            for image, side in ((original, "original"), (candidate, "candidate"))):
        return
    found = _accessor_lemmas(check, (original, candidate))
    if found is None:
        return
    lemmas, reads = found
    tables = initial_table_premise(check)
    if tables["status"] != "checked":
        return
    relation = joint_read_premise(tables, reads)
    check["accessor_read_relation"] = relation
    if relation["status"] != "checked":
        return
    composed = deepcopy(check)
    composed["status"] = "checked"
    composed["target_block_checks"] = {"status": "checked", "pairs": lemmas}
    promote_table_function(row, [composed])
    if row["status"] == "conditional":
        row["assumptions"]["live_global_reads"] = relation
        row["proof_method"] = "single_switch_read_accessors"
        row["reason"] = "initial_tables_and_live_global_read_relations"
        row["table_function_proof"]["accessor_lemmas"] = lemmas
