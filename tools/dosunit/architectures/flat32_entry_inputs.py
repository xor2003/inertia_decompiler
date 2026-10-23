"""Layer: native i386 proof input binding.

Responsibility: encode valid architectural direction at a completed root only,
after callee substitution, without constraining generic SSA or assuming DF=0.
"""
from __future__ import annotations

from typing import Any

from tools.dosunit.contracts.ssa import LowerFailure
from tools.dosunit.ssa.composition import _compose_deadline_check, substitute_inputs
from tools.dosunit.ssa.materialization import input_items


def bind_direction_input(
    document: dict[str, Any], *, architecture_name: str, compose_stats: dict[str, Any],
) -> dict[str, Any]:
    """Bind a completed native root's VEX step to both values of a DF bit."""
    if architecture_name != "X86":
        raise LowerFailure("unsupported_architecture", "direction binding requires native i386")
    _compose_deadline_check(compose_stats)
    inputs = input_items(document["outputs"].values(), document["assignments"])
    direction = [item for item in inputs if item.get("name") == "d"]
    if not direction:
        return document
    if direction != [{"name": "d", "width": 32}] or any(item.get("name") == "x86_df" for item in inputs):
        raise LowerFailure("invalid_architectural_input", "direction width or reserved DF input conflicts")
    step = {"op": "ite", "width": 32, "args": [
        {"op": "input", "name": "x86_df", "width": 1},
        {"op": "const", "width": 32, "value": "0xffffffff"},
        {"op": "const", "width": 32, "value": "0x1"},
    ]}
    identifiers = {assignment["id"] for assignment in document["assignments"]}
    identifier = "x86_direction_step"
    while identifier in identifiers:
        identifier += "_"
    replacement = {"ref": identifier}
    cache: dict[int, dict[str, Any]] = {}
    assignments: list[dict[str, Any]] = [{"id": identifier, **step}]
    for assignment in document["assignments"]:
        _compose_deadline_check(compose_stats)
        bound = substitute_inputs(assignment, {"d": replacement}, cache=cache)
        assignments.append({**bound, "id": assignment["id"]})
    outputs: dict[str, dict[str, Any]] = {}
    for name, term in document["outputs"].items():
        _compose_deadline_check(compose_stats)
        outputs[name] = substitute_inputs(term, {"d": replacement}, cache=cache)
    result = {**document, "assignments": assignments, "outputs": outputs,
              "inputs": input_items(outputs.values(), assignments)}
    result["architectural_input_bindings"] = {
        "d": {"input": "x86_df", "width": 1, "zero": "0x1", "one": "0xffffffff",
              "source": "native_i386_vex_direction", "scope": "completed_root_entry"},
    }
    _compose_deadline_check(compose_stats)
    return result
