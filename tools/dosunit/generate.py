from __future__ import annotations  # noqa: D100

from pathlib import Path
from typing import Any

from tools.dosunit.ir_edges import discover_branch_targets
from tools.dosunit.model import DosUnitError, normalize_hex, normalize_vector, stable_id
from tools.dosunit.solver_slice import EdgeSolveFailure, SolvedEdge, solve_branch_edge


def _solve_entry_seed() -> dict[str, str]:
    try:
        import z3  # type: ignore
    except Exception:
        return {
            "sp": "0xff00",
            "flags": "0x0202",
        }

    sp = z3.BitVec("sp", 16)
    flags = z3.BitVec("flags", 16)
    solver = z3.Solver()
    solver.add(sp == 0xFF00)
    solver.add((flags & 0x0002) == 0x0002)
    solver.add((flags & 0x0200) == 0x0200)
    if solver.check() != z3.sat:
        return {
            "sp": "0xff00",
            "flags": "0x0202",
        }
    model = solver.model()
    return {
        "sp": normalize_hex(model.eval(sp).as_long(), width=4),
        "flags": normalize_hex(model.eval(flags).as_long(), width=4),
    }


def generate_vectors(  # noqa: D103
    *,
    functions_catalog: dict[str, Any],
    exe_path: Path | None = None,
    strategy: str = "entry",
    max_vectors_per_function: int = 1,
    max_branches: int | None = None,
    max_blocks: int | None = None,
    max_loop_unroll: int = 0,
    solver_timeout_ms: int = 1000,
) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    counters = {
        "functions_seen": 0,
        "functions_attempted": 0,
        "paths_attempted": 0,
        "paths_solved": 0,
        "vectors_emitted": 0,
        "branches_seen": 0,
        "branches_attempted": 0,
        "edge_sources": {},
        "edge_fallback_diagnostics": 0,
        "lifter_blocks_lifted": 0,
        "refusals_by_reason": {},
        "solver_time_ms": 0,
    }
    module = str(functions_catalog.get("module", "unknown.exe"))
    functions = list(functions_catalog.get("functions", []) or [])
    counters["functions_seen"] = len(functions)

    if strategy == "edge":
        return _generate_edge_vectors(
            functions=functions,
            module=module,
            exe_path=exe_path,
            max_vectors_per_function=max_vectors_per_function,
            max_branches=max_branches,
            max_blocks=max_blocks,
            max_loop_unroll=max_loop_unroll,
            solver_timeout_ms=solver_timeout_ms,
            counters=counters,
        )

    if strategy != "entry":
        for function in functions:
            refusal = {
                "status": "refused",
                "reason": "unsupported_ir",
                "detail": {
                    "function_id": function.get("id"),
                    "strategy": strategy,
                    "message": "VEX path-constraint generation is not implemented in this scaffold",
                },
            }
            refusals.append(refusal)
        counters["refusals_by_reason"] = {"unsupported_ir": len(refusals)}
        return _generation_document(
            exe_path=exe_path,
            strategy=strategy,
            vectors=vectors,
            refusals=refusals,
            counters=counters,
        )

    seed = _solve_entry_seed()
    for function in functions:
        if (
            len([v for v in vectors if v.get("function", {}).get("name") == function.get("names", [""])[0]])
            >= max_vectors_per_function
        ):
            continue
        counters["functions_attempted"] += 1
        counters["paths_attempted"] += 1
        vector = _make_vector(
            module=module,
            function=function,
            seed=seed,
            regs={"ax": "0x0000"},
            source_origin="manual_fixture",
            assumptions=[
                "entry seed only",
                "VEX path constraints not yet materialized",
                "expected output must be recorded from original x86 execution",
            ],
            constraints=["sp == 0xff00", "reserved flag bit set", "interrupt flag set"],
        )
        vectors.append(vector)
        counters["paths_solved"] += 1
        counters["vectors_emitted"] += 1

    return _generation_document(
        exe_path=exe_path,
        strategy=strategy,
        vectors=vectors,
        refusals=refusals,
        counters=counters,
    )


def _make_vector(
    *,
    module: str,
    function: dict[str, Any],
    seed: dict[str, str],
    regs: dict[str, str | int],
    source_origin: str,
    assumptions: list[str],
    constraints: list[str],
    coverage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry = function.get("entry", {})
    names = function.get("names", []) or []
    function_name = names[0] if names else str(function.get("id", "unknown"))
    concrete_regs = {
        "ax": "0x0000",
        "bx": "0x0000",
        "cx": "0x0000",
        "dx": "0x0000",
        "si": "0x0000",
        "di": "0x0000",
        "bp": "0x0000",
        "sp": seed["sp"],
        "flags": seed["flags"],
    }
    for reg, value in regs.items():
        if reg in concrete_regs:
            concrete_regs[reg] = normalize_hex(value, width=4, field=f"pre.regs.{reg}")
    source: dict[str, Any] = {
        "kind": "z3",
        "origin": source_origin,
        "assumptions": assumptions,
        "solver": {
            "name": "z3",
            "constraints": constraints,
        },
    }
    if coverage is not None:
        source["coverage"] = coverage
    return normalize_vector(
        {
            "schema": "dosunit.vector.v1",
            "module": module,
            "function": {
                "id": function.get("id"),
                "name": function_name,
                "entry": {
                    "cs": entry.get("segment_para", "auto"),
                    "ip": entry.get("offset", "0x0000"),
                    "kind": function.get("return_kind", "near"),
                },
                "size": function.get("size"),
                "end_offset": function.get("end_offset"),
            },
            "source": source,
            "pre": {
                "regs": concrete_regs,
                "sregs": {
                    "cs": entry.get("segment_para", "auto"),
                    "ds": "auto",
                    "es": "auto",
                    "ss": "auto",
                },
                "memory": [],
            },
            "observe": {
                "regs": ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"],
                "sregs": ["ds", "es", "ss"],
                "flags_mask": "0x08d5",
                "memory": [],
                "calls": True,
                "return": True,
            },
            "expected": None,
        }
    )


def _generate_edge_vectors(
    *,
    functions: list[dict[str, Any]],
    module: str,
    exe_path: Path | None,
    max_vectors_per_function: int,
    max_branches: int | None,
    max_blocks: int | None,
    max_loop_unroll: int,
    solver_timeout_ms: int,
    counters: dict[str, Any],
) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    refusals: list[dict[str, Any]] = []
    if exe_path is None:
        return _refuse_edge_generation(
            functions, "--exe is required for bounded edge-vector generation", counters, exe_path
        )

    if max_loop_unroll != 0:
        return _refuse_edge_generation(
            functions,
            "--max-loop-unroll is reserved for future bounded path solving and must be 0 for local edge solving",
            counters,
            exe_path,
        )

    try:
        discovered = discover_branch_targets(
            exe_path=exe_path,
            functions=functions,
            max_branches=max_branches,
            scan_limit=0x200 if max_blocks is None else max(1, max_blocks) * 0x40,
        )
    except DosUnitError as ex:
        return _refuse_edge_generation(functions, str(ex), counters, exe_path)

    refusals.extend(discovered.refusals)
    counters["edge_sources"] = discovered.source_counts
    counters["edge_fallback_diagnostics"] = len(discovered.diagnostics)
    counters["lifter_blocks_lifted"] = discovered.lifter_blocks_lifted
    targets_by_function: dict[str, list[Any]] = {}
    for target in discovered.targets:
        targets_by_function.setdefault(target.function_id, []).append(target)
    counters["branches_seen"] = len(discovered.targets)
    seed = _solve_entry_seed()
    for function in functions:
        counters["functions_attempted"] += 1
        function_id = str(function.get("id", ""))
        targets = targets_by_function.get(function_id, [])
        if not targets:
            if not any(_refusal_function_id(item) == function_id for item in refusals):
                refusals.append(
                    {
                        "status": "refused",
                        "reason": "unsupported_ir",
                        "detail": {
                            "function_id": function.get("id"),
                            "strategy": "edge",
                            "message": "no supported direct branch target found",
                        },
                    }
                )
            continue
        _solve_function_targets(
            function=function,
            targets=targets,
            vectors=vectors,
            refusals=refusals,
            counters=counters,
            module=module,
            seed=seed,
            max_vectors_per_function=max_vectors_per_function,
            solver_timeout_ms=solver_timeout_ms,
        )

    counters["refusals_by_reason"] = _refusal_counts(refusals)
    return _generation_document(
        exe_path=exe_path, strategy="edge", vectors=vectors, refusals=refusals, counters=counters
    )


def _refuse_edge_generation(
    functions: list[dict[str, Any]],
    message: str,
    counters: dict[str, Any],
    exe_path: Path | None,
) -> dict[str, Any]:
    """Refuse every function with one reason and return the document."""
    refusals = [
        {
            "status": "refused",
            "reason": "unsupported_ir",
            "detail": {
                "function_id": function.get("id"),
                "strategy": "edge",
                "message": message,
            },
        }
        for function in functions
    ]
    counters["refusals_by_reason"] = {"unsupported_ir": len(refusals)}
    return _generation_document(
        exe_path=exe_path, strategy="edge", vectors=[], refusals=refusals, counters=counters
    )


def _solve_function_targets(
    *,
    function: dict[str, Any],
    targets: list[Any],
    vectors: list[dict[str, Any]],
    refusals: list[dict[str, Any]],
    counters: dict[str, Any],
    module: str,
    seed: dict[str, str],
    max_vectors_per_function: int,
    solver_timeout_ms: int,
) -> None:
    """Solve each branch target's taken/fallthrough edges for one function."""
    emitted_for_function = 0
    for target in targets:
        counters["branches_attempted"] += 1
        for label in ("taken", "fallthrough"):
            if emitted_for_function >= max_vectors_per_function:
                break
            counters["paths_attempted"] += 1
            solved = solve_branch_edge(target, label=label, timeout_ms=solver_timeout_ms)
            if isinstance(solved, EdgeSolveFailure):
                refusals.append(
                    {
                        "status": "refused",
                        "reason": solved.reason,
                        "detail": {
                            "function_id": function.get("id"),
                            "strategy": "edge",
                            "label": label,
                            "message": solved.message,
                        },
                    }
                )
                continue
            vector = _vector_from_solved_edge(
                module=module,
                function=function,
                seed=seed,
                solved=solved,
            )
            vectors.append(vector)
            emitted_for_function += 1
            counters["paths_solved"] += 1
            counters["vectors_emitted"] += 1
            counters["solver_time_ms"] += solved.solver_time_ms
        if emitted_for_function >= max_vectors_per_function:
            break


def _vector_from_solved_edge(
    *,
    module: str,
    function: dict[str, Any],
    seed: dict[str, str],
    solved: SolvedEdge,
) -> dict[str, Any]:
    return _make_vector(
        module=module,
        function=function,
        seed=seed,
        regs=solved.regs,
        source_origin="original_side_branch_solver",
        assumptions=[
            "original-side local branch edge model",
            "lazy flags: only selected branch predicate materialized",
            "rebuilt comparison uses function mapping, not block correspondence",
            "expected output must be recorded from original x86 execution",
        ],
        constraints=[*solved.constraints, f"path_label == {solved.label}"],
        coverage=solved.coverage,
    )


def _refusal_counts(refusals: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in refusals:
        reason = str(item.get("reason", "unknown"))
        counts[reason] = counts.get(reason, 0) + 1
    return dict(sorted(counts.items()))


def _refusal_function_id(refusal: dict[str, Any]) -> str | None:
    detail = refusal.get("detail", {})
    if isinstance(detail, dict) and "function_id" in detail:
        return str(detail["function_id"])
    return None


def _generation_document(
    *,
    exe_path: Path | None,
    strategy: str,
    vectors: list[dict[str, Any]],
    refusals: list[dict[str, Any]],
    counters: dict[str, Any],
) -> dict[str, Any]:
    document_without_id = {
        "schema": "dosunit.generation.v1",
        "exe": None if exe_path is None else str(exe_path),
        "strategy": strategy,
        "vectors": vectors,
        "refusals": refusals,
        "counters": counters,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("generation", document_without_id)
    return document
