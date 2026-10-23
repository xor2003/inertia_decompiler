"""Layer: validation switch-proof composition.

Responsibility: join checked prefix, dispatch, table and returning-target lemmas
into a conditional whole-function result with satisfiable initial table premises.
"""

from __future__ import annotations

from typing import Any

from tools.comparator.table_checks import TableCheckStatus


def initial_table_premise(check: dict[str, Any]) -> dict[str, object]:
    """Check consistency of both tables in the comparator's shared memory domain.

    Root state uses one unconstrained byte array on both sides. Requiring two
    different values at the same address would make the domain empty and is
    never admitted as a proof. Disjoint/identical byte constraints are jointly
    satisfiable without restricting any scalar input. These are explicit entry
    assumptions, not an assertion that actual loaded images satisfy equality.
    """
    cells: dict[int, int] = {}
    tables: dict[str, object] = {}
    for side in ("original", "candidate"):
        address = int(check[side]["address"], 0)
        targets = [int(row[f"{side}_target"], 0) for row in check["entries"]]
        if len(targets) != check[side]["count"]:
            return {"status": "incomplete", "reason": "table_extent_not_covered"}
        for index, target in enumerate(targets):
            for byte_index, byte in enumerate(target.to_bytes(4, "little")):
                slot = address + index * 4 + byte_index
                if slot in cells and cells[slot] != byte:
                    return {"status": "incomplete", "reason": "conflicting_shared_memory_table_bytes",
                            "conflict_address": hex(slot)}
                cells[slot] = byte
        tables[side] = {"address": hex(address), "targets": [hex(target) for target in targets]}
    return {"status": "checked", "kind": "initial_shared_memory_table_bytes", "proved": False,
            "jointly_satisfiable": True, "tables": tables,
            "scope": "at root entry, shared input memory contains both listed preferred-address tables; "
                     "actual loaded-image memory equality and runtime relocation are not established"}


def _complete_lemmas(check: dict[str, Any], target_check: str = "target_block_checks") -> bool:
    """Require the closed single-dispatch, all-returning shape with every lemma checked."""
    if not check.get("initial_tables_assumed"):
        return False
    if target_check == "target_block_checks" and check.get("status") != "checked":
        return False
    if target_check == "slot_target_checks" and not _selected_slots_complete(check):
        return False
    required = ("dispatch_check", "prefix_check", target_check, "root_entry_check")
    if any(check.get(name, {}).get("status") != "checked" for name in required):
        return False
    dispatch, prefix = check["dispatch_check"], check["prefix_check"]
    if any(dispatch[side]["transfer"] != "jump" for side in ("original", "candidate")):
        return False  # CALL's return push is not part of these prefix lemmas.
    if prefix.get("pending_conditions") or prefix.get("solver_result", {}).get("status") != "passed":
        return False
    if prefix.get("default_block_checks", {}).get("status") != "checked":
        return False
    for group in ("index_domain_checks", "table_preservation_checks"):
        if any(prefix.get(group, {}).get(side, {}).get("status") != "checked" for side in ("original", "candidate")):
            return False
    # Every selected index must reach one of the actually proved target pairs.
    proved = {(int(pair["original"]["address"], 0), int(pair["candidate"]["address"], 0))
              for pair in check[target_check]["pairs"] if pair["status"] == "checked"}
    return bool(check["entries"]) and all(
        (int(row["original_target"], 0), int(row["candidate_target"], 0)) in proved
        for row in check["entries"])


def _selected_slots_complete(check: dict[str, Any]) -> bool:
    """Require complete structural table evidence and a checked slot partition."""
    targets = check.get("slot_target_checks", {})
    entries = check.get("entries", [])
    if not entries or not check.get("count_matches") or any(row["status"] != "checked" for row in entries):
        return False
    if targets.get("scope") != "selected_slot_root_paths" or not targets.get("slot_guards_applied"):
        return False
    indices = [index for pair in targets.get("pairs", []) for index in pair["slot_indices"]]
    return (targets.get("covered_slots") == len(entries)
            and sorted(indices) == list(range(len(entries)))
            and targets.get("table_binding", {}).get("status") == "checked"
            and targets.get("dispatch_binding", {}).get("status") == "checked")


def promote_table_function(row: dict[str, Any], checks: list[dict[str, Any]]) -> None:
    """Replace only a refusal, preserving its exact evidence and publishing all premises."""
    if row["status"] != "refused" or len(checks) != 1:
        return
    check = checks[0]
    target_check = "target_block_checks"
    if not _complete_lemmas(check):
        target_check = "slot_target_checks"
        if not _complete_lemmas(check, target_check):
            if not complete_root_paths(check):
                return
            target_check = "root_path_checks"
    premise = initial_table_premise(check)
    check["initial_table_premise"] = premise
    if premise["status"] != "checked":
        return
    strict = {key: value for key, value in row.items() if key != "partial_table_checks"}
    assumptions = {"initial_tables": premise}
    entry_domain = check["prefix_check"].get("entry_domain_assumptions")
    if entry_domain is not None:
        assumptions["entry_esp_domain"] = entry_domain
    completed = target_check == "root_path_checks"
    method = ("single_switch_root_returns" if completed else "single_switch_selected_slots"
              if target_check == "slot_target_checks" else "single_switch_returning_blocks")
    targets = check["root_path_checks"]["slot_target_checks"] if completed else check[target_check]
    if completed:
        assumptions["abi_observation"] = check["root_path_checks"]["abi_observation"]
    row.update(status="conditional", reason="initial_table_memory_assumption",
               backend_status="passed", proof_scope="complete_function",
               proof_method=method, strict_function_result=strict,
               assumptions=assumptions,
               table_function_proof={"complete": True, "dispatches": 1,
                                     "table_entries": len(check["entries"]),
                                     "unique_target_pairs": len(targets["pairs"]),
                                     "root_entry_state": "equal modeled registers and shared memory",
                                     "observations": ("declared scalar ABI, memory and return control" if completed
                                                      else "all modeled registers, memory and return control")})


def complete_root_paths(check: dict[str, Any]) -> bool:
    """Admit no root unless table, bounds, preservation, slots and defaults all close."""
    root = check.get("root_path_checks", {})
    prefix = check.get("prefix_check", {})
    if not check.get("initial_tables_assumed") or root.get("status") != TableCheckStatus.CHECKED:
        return False
    if root.get("scope") != "completed_switch_root_paths" or not root.get("default_guards_applied"):
        return False
    if check.get("root_entry_check", {}).get("status") != TableCheckStatus.CHECKED:
        return False
    binding = root.get("slot_target_checks", {}).get("dispatch_binding", {})
    if binding.get("status") != TableCheckStatus.CHECKED:
        return False
    if any(binding[side]["transfer"] != "jump" for side in ("original", "candidate")):
        return False
    for group in ("index_domain_checks", "table_preservation_checks"):
        if any(prefix.get(group, {}).get(side, {}).get("status") != TableCheckStatus.CHECKED
               for side in ("original", "candidate")):
            return False
    return _closed_partition(check, root, prefix)


def _closed_partition(check: dict[str, Any], root: dict[str, Any], prefix: dict[str, Any]) -> bool:
    """Validate the complete slot/default partition against its native prefix binding."""
    slots = root.get("slot_target_checks", {})
    if slots.get("status") != TableCheckStatus.CHECKED or not _selected_slots_complete({**check, "slot_target_checks": slots}):
        return False
    defaults = root["default_pairs"]
    for side in ("original", "candidate"):
        expected = prefix.get(side, {}).get("default_targets")
        if expected is None or expected != root.get(side + "_prefix", {}).get("default_targets"):
            return False
        if expected != [pair[side]["address"] for pair in defaults]:
            return False
        if root[side + "_prefix"]["entry"] != prefix[side]["entry"]:
            return False
        if root[side + "_prefix"]["dispatch"] != prefix[side]["dispatch"]:
            return False
    return (all(pair["status"] == TableCheckStatus.CHECKED for pair in defaults)
            and [pair["control_token"] for pair in defaults] == list(range(1, len(defaults) + 1))
            and isinstance(root.get("abi_observation"), dict))
