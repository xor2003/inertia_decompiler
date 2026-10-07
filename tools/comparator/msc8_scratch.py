"""Layer: validation retry adapter.

Responsibility: retry failed flat32 leaf comparisons under a declared
scratch-stack premise.  Different compilers emit different frame/spill
traffic; memory operations at ``entry_esp + delta`` with ``delta < 0`` touch
callee-owned stack slots (pushes, spill cells, frame locals) that callers
never observe.  The retry routes those accesses onto a separate
``mem_scratch`` input array, so caller-observable memory (argument cells,
globals, heap) is compared exactly while frame/spill traffic still folds
against its own stores.  Results proved only under this premise are reported
``conditional`` with the published assumption; they are never promoted to
unconditional passes.
"""
from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from tools.comparator.verdict import Status

SCRATCH_INPUT: str = "mem_scratch"
SCRATCH_MIN_DELTA: int = -0x2000


def _const(expr: dict[str, Any]) -> int | None:
    """Return the integer value of a const node, else None."""
    if isinstance(expr, dict) and expr.get("op") == "const":
        try:
            return int(str(expr.get("value", "")), 0)
        except ValueError:
            return None
    return None


def _esp_delta(expr: dict[str, Any], by_id: dict[str, dict[str, Any]], depth: int = 0) -> int | None:
    """Constant delta of an address expr from ``input esp``, else None."""
    if depth > 24 or not isinstance(expr, dict):
        return None
    if expr.get("op") == "input" and expr.get("name") == "esp":
        return 0
    if "ref" in expr:
        return _esp_delta(by_id.get(expr["ref"], {}), by_id, depth + 1)
    if expr.get("op") in ("add", "sub"):
        args = expr.get("args") or []
        if len(args) != 2:
            return None
        delta_a, delta_b = (_esp_delta(a, by_id, depth + 1) for a in args)
        const_a, const_b = (_const(a) for a in args)
        if delta_a is not None and const_b is not None:
            return delta_a + const_b if expr["op"] == "add" else delta_a - const_b
        if delta_b is not None and const_a is not None and expr["op"] == "add":
            return delta_b + const_a
    return None


def _is_scratch(addr: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> bool:
    """True when an address is an entry-esp-relative callee slot (delta < 0)."""
    delta = _esp_delta(addr, by_id)
    return delta is not None and SCRATCH_MIN_DELTA <= delta < 0


def _split_function_memory(function: dict[str, Any]) -> bool:
    """Route below-esp memory ops onto ``mem_scratch``; return True if used.

    Store chains are rewritten in program order: each ``storele`` appends to
    the observable channel or the scratch channel by address, each ``loadle``
    reads the matching channel at the referenced chain point, and
    ``outputs.memory`` becomes the observable channel tip (dropped entirely
    when it collapses to the bare input).
    """
    assignments = function.get("assignments") or []
    by_id = {a["id"]: a for a in assignments if isinstance(a, dict) and "id" in a}
    mem_in: dict[str, Any] = {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8}
    scratch_in: dict[str, Any] = {
        "op": "mem_input", "name": SCRATCH_INPUT, "addr_width": 32, "value_width": 8}
    roots: tuple[dict[str, Any], dict[str, Any]] = (mem_in, scratch_in)
    after: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    extra: list[dict[str, Any]] = []
    used = False

    def roots_at(term: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        if isinstance(term, dict) and "ref" in term:
            return after.get(str(term["ref"]), roots)
        return (mem_in, scratch_in)

    for item in assignments:
        if not isinstance(item, dict) or "id" not in item:
            continue
        ident = str(item["id"])
        op = item.get("op")
        args = item.get("args") or []
        if op == "storele" and len(args) == 3:
            parent = roots_at(args[0])
            channel = 1 if _is_scratch(args[1], by_id) else 0
            used = used or channel == 1
            new_id = f"{ident}.cs{len(extra)}"
            node = {
                "id": new_id, "op": "storele", "width": item.get("width", 0),
                "args": [parent[channel], args[1], args[2]],
            }
            by_id[new_id] = node
            extra.append(node)
            roots = ({"ref": new_id}, roots[1]) if channel == 0 else (roots[0], {"ref": new_id})
            after[ident] = roots
        else:
            if op == "loadle" and len(args) == 2:
                channel = 1 if _is_scratch(args[1], by_id) else 0
                used = used or channel == 1
                item["args"] = [roots_at(args[0])[channel], args[1]]
            after[ident] = roots
    assignments.extend(extra)
    if not used:
        return False
    _declare_scratch_input(function)
    outputs = function.get("outputs") or {}
    memory = outputs.get("memory")
    if isinstance(memory, dict):
        tip = roots[0]
        if tip.get("op") == "mem_input":
            del outputs["memory"]
        else:
            outputs["memory"] = tip
    return True


def _declare_scratch_input(function: dict[str, Any]) -> None:
    """Declare the scratch memory input exactly once after memory splitting."""
    fn_inputs = function.setdefault("inputs", [])
    if isinstance(fn_inputs, list) and not any(
        isinstance(item, dict) and item.get("name") == SCRATCH_INPUT for item in fn_inputs
    ):
        fn_inputs.append({"name": SCRATCH_INPUT, "kind": "memory", "addr_width": 32, "value_width": 8})


def normalize_scratch_stores(document: dict[str, Any]) -> dict[str, Any]:
    """Copy a lowered SSA document with below-esp traffic on ``mem_scratch``."""
    out = copy.deepcopy(document)
    for function in out.get("functions", ()):
        _split_function_memory(function)
    return out


def _mask_output(function: dict[str, Any], name: str, mask: int | None) -> None:
    """Narrow ``outputs[name]`` to ``mask`` bits, or drop it when ``mask`` is None.

    Used for partial-register returns: an ``__int16`` callee only defines the
    low 16 bits of ``eax``; upper bits are caller-invisible scratch.  Masking
    both sides yields the honest per-return-width contract.
    """
    outputs = function.get("outputs") or {}
    if name not in outputs:
        return
    if mask is None:
        outputs.pop(name, None)
        return
    term = outputs[name]
    nid = f"{term.get('ref', name)}.msk{name}"
    function.setdefault("assignments", []).append(
        {"id": nid, "op": "and", "width": 32,
         "args": [term, {"op": "const", "value": hex(mask), "width": 32}]})
    outputs[name] = {"ref": nid}


def retry_scratch_frame(
    failed: list[dict[str, Any]],
    oracle_ssa: dict[str, Any],
    candidate_ssa: dict[str, Any],
    compare: Callable[..., dict[str, Any]],
    timeout_ms: int,
    drop_outputs: tuple[str, ...] = (),
    eax_masks: dict[str, int | None] | None = None,
    premise: str = "scratch_frame_stores_masked",
) -> dict[str, dict[str, Any]]:
    """Re-prove failed functions with below-esp traffic on ``mem_scratch``.

    ``drop_outputs`` names additional outputs removed from both documents
    before re-proving (e.g. ``edx`` for the caller-saved scratch premise).
    ``eax_masks`` optionally narrows ``eax`` per function to its declared
    return width (``0xff``/``0xffff``; ``None`` drops ``eax`` for ``void``).
    Returns {name: verdict} for functions proved under the premise; every
    converted verdict is ``conditional`` and carries the published assumption.
    """
    if not failed:
        return {}
    wanted = {item["function"]["name"] for item in failed}
    nossa = normalize_scratch_stores(oracle_ssa)
    ncssa = normalize_scratch_stores(candidate_ssa)
    for document in (nossa, ncssa):
        for function in document.get("functions", ()):
            outputs = function.get("outputs") or {}
            for name in drop_outputs:
                outputs.pop(name, None)
    if eax_masks:
        for document in (nossa, ncssa):
            for function in document.get("functions", ()):
                function_name = (function.get("function") or {}).get("name")
                if function_name in eax_masks:
                    _mask_output(function, "eax", eax_masks[function_name])

    def subset(document: dict[str, Any]) -> dict[str, Any]:
        sub = {key: value for key, value in document.items() if key != "functions"}
        sub["functions"] = [
            f for f in document["functions"]
            if (f.get("function") or {}).get("name") in wanted
        ]
        return sub

    raw = compare(
        oracle=subset(nossa),
        candidate=subset(ncssa),
        mapping_document={
            "schema": "dosunit.mapping.v1",
            "oracle_module": "oracle",
            "candidate_module": "candidate",
            "functions": [
                {
                    "oracle_id": f"oracle:{n}", "oracle_name": n,
                    "candidate_id": f"candidate:{n}", "candidate_name": n,
                    "sources": ["name_match"],
                }
                for n in sorted(wanted)
            ],
        },
        timeout_ms=timeout_ms,
        max_solver_assignments=4096,
        max_solver_inputs=64,
        max_solver_memory_stores=256,
        skip_binary_equal=False,
        allow_aliased_call_targets=False,
        enable_callee_lemmas=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )
    return _conditional_retry_results(raw, wanted, drop_outputs, eax_masks, premise)


def _conditional_retry_results(
    raw: dict[str, Any], wanted: set[str], drop_outputs: tuple[str, ...],
    eax_masks: dict[str, int | None] | None, premise: str,
) -> dict[str, dict[str, Any]]:
    """Publish only positive backend results as explicitly conditional retries."""
    by_name: dict[str, dict[str, Any]] = {}
    for item in raw.get("results", ()):
        name = (item.get("function") or {}).get("name")
        if name not in wanted or item.get("status") != "passed":
            continue
        detail = (
            "below-esp memory accesses routed to a fresh scratch array; "
            "caller-observable memory, registers and control flow proved "
            "equal under the disjoint-stack-domain premise"
        )
        if drop_outputs:
            detail += f"; outputs {','.join(drop_outputs)} excluded from comparison"
        if eax_masks and name in eax_masks:
            mask = eax_masks[name]
            detail += "; eax compared modulo %s" % (
                f"return-width mask {mask:#x}" if mask is not None else "void return (eax dropped)")
        by_name[name] = {
            "status": Status.CONDITIONAL,
            "reason": premise,
            "assumptions": {
                "kind": premise,
                "detail": detail,
                "excluded_outputs": list(drop_outputs),
                "eax_mask": eax_masks.get(name) if eax_masks else None,
            },
            "retried_from": "observable_mismatch",
        }
    return by_name
