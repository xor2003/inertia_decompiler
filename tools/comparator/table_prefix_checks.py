"""Layer: validation table-dispatch prefix evidence.

Responsibility: compare single-block dispatch prefixes over equal root state,
retaining branch decisions as paired control tokens and all modeled data state.
"""

from __future__ import annotations

from typing import Any

import archinfo
import pyvex

from tools.comparator.table_checks import read_pe_bytes
from tools.comparator.table_dispatch_checks import read_table_dispatch
from tools.comparator.table_memory_checks import check_table_preservation
from tools.comparator.table_target_checks import check_returning_targets
from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S
from tools.dosunit.compare.flat32_call_contracts import CallCompositionRefusal
from tools.dosunit.compare.flat32_call_lowering import _check_exits, _static_next
from tools.dosunit.contracts.binary_environment import requires_environment_contract
from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
from tools.dosunit.ssa.composition import _inline_ssa_json_term
from tools.dosunit.ssa.materialization import input_items, materialize_term


def _control_tokens(term: dict[str, Any], targets: dict[int, int]) -> dict[str, Any]:
    """Rename only terminal control addresses; guards and data constants stay literal."""
    if term.get("op") == "const":
        raw = term["value"]
        address = int(raw, 0) if isinstance(raw, str) else int(raw)
        return {"op": "const", "width": 32, "value": hex(targets[address])}
    if term.get("op") != "ite":
        raise ValueError("prefix control must be a finite tree of direct targets")
    guard, taken, otherwise = term["args"]
    return {**term, "args": [guard, _control_tokens(taken, targets), _control_tokens(otherwise, targets)]}


def _prefix(image: bytes, entry: int, dispatch: int) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Lower an exact, effect-safe prefix ending at the declared dispatch site."""
    facts: dict[str, Any] = {"entry": hex(entry), "dispatch": hex(dispatch)}
    if not 0 < dispatch - entry <= 128:
        return None, {**facts, "pending": "prefix requires 1..128 bytes"}
    raw = read_pe_bytes(image, entry, dispatch - entry, executable=True)
    arch = archinfo.ArchX86()
    irsb = pyvex.IRSB(raw, entry, arch, opt_level=0)
    terminal = _static_next(irsb)
    if irsb.size != len(raw) or irsb.jumpkind != "Ijk_Boring" or terminal is None:
        return None, {**facts, "pending": "prefix requires multi-block composition"}
    if requires_environment_contract(irsb):
        return None, {**facts, "pending": "prefix requires an environment contract"}
    try:
        exits = _check_exits(irsb, arch.ip_offset)
    except CallCompositionRefusal as error:
        return None, {**facts, "pending": str(error)}
    targets = [*exits, terminal]
    if dispatch not in targets or len(set(targets)) != len(targets):
        return None, {**facts, "pending": "duplicate control targets need relational pairing"}
    defaults = [address for address in targets if address != dispatch]
    architecture = flat32_register_architecture()
    outputs = (*(name for name, _width in architecture.registers if name != "eip"), "ip")
    lowered = S._lower_irsb(irsb, output_regs=outputs, max_assignments_per_function=4096,
                            architecture=architecture)
    if isinstance(lowered, S.LowerFailure):
        return None, {**facts, "pending": lowered.reason, "detail": lowered.message}
    lowered["outputs"].setdefault("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    assignments = {row["id"]: row for row in lowered["assignments"]}
    control = _inline_ssa_json_term(lowered["outputs"]["ip"], assignments=assignments, cache={})
    tokens = {dispatch: 0, **{address: index + 1 for index, address in enumerate(defaults)}}
    lowered["outputs"]["ip"] = materialize_term(_control_tokens(control, tokens),
                                                assignments=lowered["assignments"], memo={})
    lowered["inputs"] = input_items(lowered["outputs"].values(), lowered["assignments"])
    facts.update(instruction_bytes=raw.hex(), default_targets=[hex(address) for address in defaults],
                 observed_outputs=sorted(lowered["outputs"]))
    return lowered, facts


def check_dispatch_prefix(
    original_image: bytes, candidate_image: bytes, original_entry: int,
    candidate_entry: int, original_dispatch: int, candidate_dispatch: int,
    *, original_count: int | None = None, candidate_count: int | None = None,
    check_defaults: bool = False,
    entry_domain: Flat32ProofDomain | None = None,
) -> dict[str, object]:
    """Prove data-state and branch-token equality, without assuming default behavior."""
    left, original = _prefix(original_image, original_entry, original_dispatch)
    right, candidate = _prefix(candidate_image, candidate_entry, candidate_dispatch)
    result: dict[str, object] = {
        "status": "incomplete", "scope": "dispatch_prefix",
        "original": original, "candidate": candidate,
        "entry_relation": "equal modeled registers and memory at declared entries",
        "pending_conditions": ["default target continuations are equivalent",
                               "dispatch index is within the declared table extent",
                               "table bytes survive prefix execution",
                               "declared entries are the intended root function entries"],
    }
    if entry_domain is not None:
        result["entry_domain_assumptions"] = entry_domain.assumption_document()
    if left is None or right is None:
        return result
    if len(original["default_targets"]) != len(candidate["default_targets"]):
        result["pending"] = "different prefix control shapes need relational pairing"
        return result
    proof = S._compare_functions(left, right, timeout_ms=1000,
                                 input_constraints=entry_domain.constraints() if entry_domain is not None else None)
    result["solver_result"] = proof
    result["status"] = {"passed": "checked", "failed": "mismatch"}.get(proof["status"], "incomplete")
    result["default_target_pairs"] = [
        {"original": a, "candidate": b}
        for a, b in zip(original["default_targets"], candidate["default_targets"], strict=True)
    ]
    if original_count is not None and candidate_count is not None:
        domains = {
            "original": _index_domain(left, original_image, original_dispatch, original_count, entry_domain),
            "candidate": _index_domain(right, candidate_image, candidate_dispatch, candidate_count, entry_domain),
        }
        result["index_domain_checks"] = domains
        _merge_obligation(result, list(domains.values()), "dispatch index is within the declared table extent")
        preservation = {
            "original": _preservation(left, original_image, original_dispatch, original_count, entry_domain),
            "candidate": _preservation(right, candidate_image, candidate_dispatch, candidate_count, entry_domain),
        }
        result["table_preservation_checks"] = preservation
        _merge_obligation(result, list(preservation.values()), "table bytes survive prefix execution")
    if check_defaults:
        pairs = {int(a, 0): int(b, 0) for a, b in zip(original["default_targets"],
                                                     candidate["default_targets"], strict=True)}
        defaults: dict[str, object] = (check_returning_targets(original_image, candidate_image, pairs)
                    if pairs else {"status": "checked", "pairs": [], "scope": "no_default_edges"})
        result["default_block_checks"] = defaults
        _merge_obligation(result, [defaults], "default target continuations are equivalent")
    return result


def _merge_obligation(result: dict[str, object], checks: list[dict[str, object]], pending: str) -> None:
    """Discharge only checked conditions, preserving every inconclusive or changed child."""
    statuses = [check["status"] for check in checks]
    if "mismatch" in statuses:
        result["status"] = "mismatch"
    elif "incomplete" in statuses and result["status"] != "mismatch":
        result["status"] = "incomplete"
    if all(status == "checked" for status in statuses):
        obligations = result["pending_conditions"]
        if isinstance(obligations, list):
            result["pending_conditions"] = [condition for condition in obligations if condition != pending]


def _preservation(
    document: dict[str, Any], image: bytes, site: int, count: int, entry_domain: Flat32ProofDomain | None,
) -> dict[str, object]:
    """Bind memory preservation to the actual native dispatch displacement."""
    dispatch = read_table_dispatch(image, site)
    if dispatch is None or dispatch.scale != 4:
        return {"status": "incomplete", "pending": "preservation requires canonical DWORD table dispatch"}
    return check_table_preservation(document, dispatch.table_address, count, entry_domain=entry_domain)


def _index_domain(
    document: dict[str, Any], image: bytes, site: int, count: int, entry_domain: Flat32ProofDomain | None,
) -> dict[str, object]:
    """Prove dispatch implies an unsigned in-range index, without sampling values."""
    if type(count) is not int or not 0 < count <= 4096:
        raise ValueError("index proof requires 1..4096 table entries")
    dispatch = read_table_dispatch(image, site)
    if dispatch is None or dispatch.scale != 4:
        return {"status": "incomplete", "pending": "index proof requires canonical DWORD table dispatch"}
    assignments = list(document["assignments"])
    guard = {"op": "eq", "width": 1, "args": [document["outputs"]["ip"],
                                                    {"op": "const", "width": 32, "value": "0x0"}]}
    bound = {"op": "ult", "width": 1, "args": [document["outputs"][dispatch.index_register],
                                                    {"op": "const", "width": 32, "value": hex(count)}]}
    # These operands reference the existing SSA assignment list. Append shallow
    # nodes directly; recursive rematerialization would discard ref operands.
    guard_id, bound_id, obligation_id = (f"v{len(assignments) + offset}" for offset in range(3))
    assignments.extend([{"id": guard_id, **guard}, {"id": bound_id, **bound},
                        {"id": obligation_id, "op": "ite", "width": 1,
                         "args": [{"ref": guard_id}, {"ref": bound_id},
                                  {"op": "const", "width": 1, "value": "0x1"}]}])
    obligation = {"inputs": document["inputs"], "assignments": assignments,
                  "outputs": {"in_range": {"ref": obligation_id}}}
    expected = {"inputs": document["inputs"], "assignments": [],
                "outputs": {"in_range": {"op": "const", "width": 1, "value": "0x1"}}}
    proof = S._compare_functions(obligation, expected, timeout_ms=1000,
                                 input_constraints=entry_domain.constraints() if entry_domain is not None else None)
    return {"status": {"passed": "checked", "failed": "mismatch"}.get(proof["status"], "incomplete"),
            "scope": "dispatch_implies_index_in_range", "register": dispatch.index_register,
            "entry_count": count, "solver_result": proof}
