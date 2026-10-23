"""Layer: validation completed switch paths.

Responsibility: compare selected and default continuations from exact root state
under an explicit final scalar ABI, without requiring equal dispatch scratch state.
"""

from __future__ import annotations

from typing import Any, cast

from tools.comparator.table_checks import TableCheckStatus, TargetTable
from tools.comparator.table_context_checks import check_selected_slot_targets
from tools.comparator.table_prefix_checks import _prefix
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.compare.flat32_abi_observation import Flat32AbiObservation
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ssa.composition import compose_block_outputs


def check_completed_switch(
    original_image: bytes, candidate_image: bytes, correspondence: dict[int, int],
    original_table: TargetTable, candidate_table: TargetTable,
    original_entry: int, candidate_entry: int, original_dispatch: int, candidate_dispatch: int,
    *, abi_observation: Flat32AbiObservation, entry_domain: Flat32ProofDomain | None = None,
) -> dict[str, Any]:
    """Execute every arm before projecting observations; retain exact selection guards."""
    facts: dict[str, Any] = {"status": TableCheckStatus.INCOMPLETE, "scope": "completed_switch_root_paths",
                             "default_pairs": [], "default_guards_applied": False}
    left, original = _prefix(original_image, original_entry, original_dispatch)
    right, candidate = _prefix(candidate_image, candidate_entry, candidate_dispatch)
    facts.update(original_prefix=original, candidate_prefix=candidate)
    if left is None or right is None:
        return facts
    if len(original["default_targets"]) != len(candidate["default_targets"]):
        return facts
    slots = check_selected_slot_targets(
        original_image, candidate_image, correspondence, original_table, candidate_table,
        original_entry, candidate_entry, original_dispatch, candidate_dispatch,
        entry_domain=entry_domain, abi_observation=abi_observation)
    facts["slot_target_checks"] = slots
    states = (compose_block_outputs(left, left["outputs"], {}),
              compose_block_outputs(right, right["outputs"], {}))
    defaults: list[dict[str, Any]] = []
    for index, (a, b) in enumerate(zip(original["default_targets"], candidate["default_targets"], strict=True), 1):
        guards = tuple({"op": "eq", "width": 1, "args": [
            state["ip"], {"op": "const", "width": 32, "value": hex(index)}]} for state in states)
        proof = check_returning_targets(
            original_image, candidate_image, {int(a, 0): int(b, 0)}, incoming_states=states,
            entry_domain=entry_domain, observation_guards=(guards[0], guards[1]), abi_observation=abi_observation)
        pair = cast(list[dict[str, Any]], proof["pairs"])[0]
        defaults.append({**pair, "control_token": index, "observation_guards": list(guards)})
    statuses = [slots["status"], *(pair["status"] for pair in defaults)]
    facts.update(default_pairs=defaults, default_guards_applied=True,
                 status=TableCheckStatus.MISMATCH if TableCheckStatus.MISMATCH in statuses else
                 TableCheckStatus.INCOMPLETE if TableCheckStatus.INCOMPLETE in statuses else TableCheckStatus.CHECKED)
    if facts["status"] == TableCheckStatus.CHECKED:
        pairs = [*slots["pairs"], *defaults]
        offsets = tuple(sorted({offset for pair in pairs for offset in pair["abi_observation"]["excluded_stack_byte_offsets"]}))
        facts["abi_observation"] = abi_observation.premise(offsets)
    return facts
