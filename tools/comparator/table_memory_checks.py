"""Layer: validation table-memory evidence.

Responsibility: prove a prefix preserves its declared DWORD table in symbolic
memory, including aliasing writes, without assuming initial table contents.
"""

from __future__ import annotations

from typing import Any

from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_memory_preservation import prove_region_preserved
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ssa.ssa_output_lemmas import ScalarPreprocessing


def check_table_preservation(
    document: dict[str, Any], address: int, count: int, *, entry_domain: Flat32ProofDomain | None = None,
) -> dict[str, object]:
    """Compare every table slot after the prefix with the same root-entry slot.

    Proving the complete memory array unchanged is the cheap sufficient case.
    If other memory changed, compare only the exact declared table extent with
    read-over-write reasoning. Initial contents and runtime relocation remain
    separate conditions: preservation does not establish initialization.
    """
    if type(count) is not int or not 0 < count <= 4096 or not 0 <= address < address + 4 * count <= 0x100000000:
        raise ValueError("table preservation requires a valid bounded 32-bit extent")
    initial = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    actual = {"inputs": document["inputs"], "assignments": document["assignments"],
              "outputs": {"memory": document["outputs"]["memory"]}}
    expected = {"inputs": document["inputs"], "assignments": [], "outputs": {"memory": initial}}
    constraints = entry_domain.constraints() if entry_domain is not None else None
    result: dict[str, object] = {"scope": "table_memory_preservation", "address": hex(address), "count": count}
    if entry_domain is not None:
        result["entry_domain_assumptions"] = entry_domain.assumption_document()
    region = prove_region_preserved(document["outputs"]["memory"], address, 4 * count, constraints,
                                    assignments=document["assignments"])
    if region is not None:
        return {**result, "status": "checked", "method": "disjoint_write_regions",
                "stores_checked": region.stores_checked, "quantified_slots": count}
    whole = S._compare_functions(actual, expected, timeout_ms=250, input_constraints=constraints)
    if whole["status"] == "passed":
        return {**result, "status": "checked", "method": "unchanged_memory", "solver_result": whole}
    index_name = "table_preservation_slot_index"
    if any(item.get("name") == index_name for item in document["inputs"]):
        raise ValueError("table preservation proof index collides with a program input")
    index_input = {"op": "input", "name": index_name, "width": 32}
    inputs = [*document["inputs"], {"name": index_name, "width": 32}]
    slot_constraints = [*(constraints or []), {"name": index_name, "kind": "unsigned_range", "min": 0, "max": count - 1}]
    documents = []
    for memory in (document["outputs"]["memory"], initial):
        assignments = list(document["assignments"])
        offset_id, address_id, value_id = (f"v{len(assignments) + index}" for index in range(3))
        assignments.extend([
            {"id": offset_id, "op": "shl", "width": 32,
             "args": [index_input, {"op": "const", "width": 32, "value": "0x2"}]},
            {"id": address_id, "op": "add", "width": 32,
             "args": [{"ref": offset_id}, {"op": "const", "width": 32, "value": hex(address)}]},
            {"id": value_id, "op": "loadle", "width": 32, "args": [memory, {"ref": address_id}]},
        ])
        documents.append({"inputs": inputs, "assignments": assignments, "outputs": {"arbitrary_slot": {"ref": value_id}}})
    proof = S._compare_functions(*documents, timeout_ms=1000,
                                 input_constraints=slot_constraints,
                                 scalar_preprocessing=ScalarPreprocessing.READ_OVER_WRITE)
    return {**result, "status": {"passed": "checked", "failed": "mismatch"}.get(proof["status"], "incomplete"),
            "method": "arbitrary_table_slot", "quantified_slots": count, "solver_result": proof}
