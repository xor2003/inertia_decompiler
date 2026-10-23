"""Layer: validation root-context table evidence.

Responsibility: feed exact native root-prefix states into paired continuations
while preserving root-domain provenance and partial proof scope.
"""

from __future__ import annotations

from typing import Any, cast

from tools.comparator.table_checks import TableCheckStatus, TargetTable, check_target_tables
from tools.comparator.table_dispatch_checks import check_dispatch_binding, read_table_dispatch
from tools.comparator.table_prefix_checks import _prefix
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ssa.composition import compose_block_outputs


def check_rooted_targets(
    original_image: bytes, candidate_image: bytes, correspondence: dict[int, int],
    original_entry: int, candidate_entry: int, original_dispatch: int, candidate_dispatch: int,
    *, entry_domain: Flat32ProofDomain | None = None,
) -> dict[str, object]:
    """Prove prefix-plus-target effects without assuming equal intermediate state.

    Restrict observed effects to the exact prefix condition reaching dispatch,
    proving that condition equal on both sides. Individual slot selection is
    still unrestricted, so a counterexample may select another table target. Coverage, default paths and table initialization
    remain separate obligations; this evidence never promotes a function.
    """
    left, original = _prefix(original_image, original_entry, original_dispatch)
    right, candidate = _prefix(candidate_image, candidate_entry, candidate_dispatch)
    facts: dict[str, object] = {
        "status": "incomplete", "scope": "root_composed_target_paths",
        "original_prefix": original, "candidate_prefix": candidate,
        "function_equivalence_proved": False,
        "pending_conditions": ["dispatch guards select these paired targets",
                               "all default and table paths are covered",
                               "table initialization and preservation hold",
                               "declared root entries match selected functions"],
        "path_guards_applied": False, "dispatch_guards_applied": False,
    }
    if left is None or right is None:
        return facts
    states = (compose_block_outputs(left, left["outputs"], {}),
              compose_block_outputs(right, right["outputs"], {}))
    guards = tuple({"op": "eq", "width": 1, "args": [state["ip"],
                    {"op": "const", "width": 32, "value": "0x0"}]} for state in states)
    facts["dispatch_guards_applied"] = True
    proof = check_returning_targets(original_image, candidate_image, correspondence,
                                    incoming_states=states, entry_domain=entry_domain,
                                    observation_guards=(guards[0], guards[1]))
    return {**proof, **facts, "status": proof["status"]}


def _selected_guard(state: dict[str, Any], register: str, indices: list[int]) -> dict[str, Any]:
    """Select all duplicate slots in root coordinates, retaining dispatch reachability."""
    selected: dict[str, Any] = {"op": "const", "width": 1, "value": "0x0"}
    for index in indices:
        equal = {"op": "eq", "width": 1, "args": [
            state[register], {"op": "const", "width": 32, "value": hex(index)}]}
        selected = {"op": "or", "width": 1, "args": [selected, equal]}
    reached = {"op": "eq", "width": 1, "args": [
        state["ip"], {"op": "const", "width": 32, "value": "0x0"}]}
    return {"op": "and", "width": 1, "args": [reached, selected]}


def check_selected_slot_targets(
    original_image: bytes, candidate_image: bytes, correspondence: dict[int, int],
    original_table: TargetTable, candidate_table: TargetTable,
    original_entry: int, candidate_entry: int, original_dispatch: int, candidate_dispatch: int,
    *, entry_domain: Flat32ProofDomain | None = None,
    abi_observation: Flat32AbiObservation | None = None,
) -> dict[str, Any]:
    """Prove each target on precisely its paired slots, including folded targets.

    Both guards use the same checked slot positions but their own composed index.
    Guard equality is an observed output. Calls remain unsupported here because
    their return-address push is absent from the prefix composition.
    """
    facts: dict[str, Any] = {"status": TableCheckStatus.INCOMPLETE, "scope": "selected_slot_root_paths",
                             "pairs": [], "slot_guards_applied": False, "covered_slots": 0}
    tables = check_target_tables(original_table, candidate_table, correspondence)
    dispatch = check_dispatch_binding(original_image, candidate_image, original_table, candidate_table,
                                    original_dispatch, candidate_dispatch)
    facts.update(table_binding=tables, dispatch_binding=dispatch)
    if tables["status"] != TableCheckStatus.CHECKED or dispatch["status"] != TableCheckStatus.CHECKED:
        return facts
    left_dispatch = read_table_dispatch(original_image, original_dispatch)
    right_dispatch = read_table_dispatch(candidate_image, candidate_dispatch)
    if left_dispatch is None or right_dispatch is None:
        return facts
    if left_dispatch.transfer != "jump" or right_dispatch.transfer != "jump":
        return facts
    left, original = _prefix(original_image, original_entry, original_dispatch)
    right, candidate = _prefix(candidate_image, candidate_entry, candidate_dispatch)
    facts.update(original_prefix=original, candidate_prefix=candidate)
    if left is None or right is None:
        return facts
    states = (compose_block_outputs(left, left["outputs"], {}),
              compose_block_outputs(right, right["outputs"], {}))
    groups: dict[tuple[int, int], list[int]] = {}
    for index, pair in enumerate(zip(original_table.targets, candidate_table.targets, strict=True)):
        if 0 in pair:
            return facts
        groups.setdefault(pair, []).append(index)
    pairs: list[dict[str, Any]] = []
    for (original_address, candidate_address), indices in sorted(groups.items()):
        guards = (_selected_guard(states[0], left_dispatch.index_register, indices),
                  _selected_guard(states[1], right_dispatch.index_register, indices))
        checked = check_returning_targets(
            original_image, candidate_image, {original_address: candidate_address},
            incoming_states=states, entry_domain=entry_domain, observation_guards=guards,
            abi_observation=abi_observation)
        row = cast(list[dict[str, Any]], checked["pairs"])[0]
        pairs.append({**row, "slot_indices": indices, "observation_guards": list(guards)})
    statuses = [row["status"] for row in pairs]
    status = (TableCheckStatus.MISMATCH if TableCheckStatus.MISMATCH in statuses else
              TableCheckStatus.INCOMPLETE if TableCheckStatus.INCOMPLETE in statuses else TableCheckStatus.CHECKED)
    facts.update(status=status, pairs=pairs, slot_guards_applied=True,
                 covered_slots=sum(len(indices) for indices in groups.values()))
    if entry_domain is not None:
        facts["entry_domain_assumptions"] = entry_domain.assumption_document()
    return facts
