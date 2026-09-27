#!/usr/bin/env python3
"""Layer: validation CLI.

Responsibility: compare complete PE32/ELF32 leaf functions through dosunit SSA/Z3.
The `region` mode composes complete acyclic call-free CFGs; `auto` retries its
loop refusals with bounded matched-CFG induction. Paired direct calls are an
explicit opt-in conditional assumption; other calls and partial scans refuse.
No refusal or conditional result is counted as an unconditional proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Final

import angr
from flat32_adapter import OUTPUT_REGS, S, installed, load32
from flat32_catalog import Symbol, catalog, global_map, lst_data_symbols, lst_functions, mapping, nm_symbols
from flat32_region import RegionLimits
from flat32_verdict import REPORT_SCHEMA, Status, checked_results, exit_code, summarize

REGION_DEFAULT_BLOCK_CAP: Final = 128
REGION_MAX_BLOCK_CAP: Final = 256


def region_limits(max_blocks: int = REGION_DEFAULT_BLOCK_CAP) -> RegionLimits:
    """Return composition budgets aligned with the region scanner boundary."""
    return RegionLimits(
        max_blocks=max_blocks,
        max_compositions=256,
        max_term_nodes=16000,
        max_memory_stores=256,
    )


def mapped_call_entries(
    boundaries: dict[str, tuple[int, int]], symbols: dict[str, Symbol], candidate_delta: int
) -> tuple[dict[int, str], dict[int, str]]:
    """Resolve only unique addresses of functions mapped by name on both sides."""
    oracle: dict[int, str] = {}
    candidate: dict[int, str] = {}
    ambiguous_oracle: set[int] = set()
    ambiguous_candidate: set[int] = set()
    for name in sorted(boundaries.keys() & symbols.keys()):
        oracle_address = boundaries[name][0]
        candidate_address = symbols[name].address + candidate_delta
        if oracle_address in oracle and oracle[oracle_address] != name:
            ambiguous_oracle.add(oracle_address)
        if candidate_address in candidate and candidate[candidate_address] != name:
            ambiguous_candidate.add(candidate_address)
        oracle[oracle_address] = name
        candidate[candidate_address] = name
    for address in ambiguous_oracle:
        del oracle[address]
    for address in ambiguous_candidate:
        del candidate[address]
    return oracle, candidate


def preflight(project: angr.Project, address: int, size: int, scan_limit: int) -> str | None:
    """Require a whole near-return block, with no hidden exceptional/branch exits."""
    block = project.factory.block(address, size=min(size or scan_limit, scan_limit), opt_level=0)
    if block.vex.jumpkind == "Ijk_Call":
        return "call_boundary"
    if block.vex.jumpkind != "Ijk_Ret" or any(stmt.tag == "Ist_Exit" for stmt in block.vex.statements):
        return "flat32_cfg_or_exception_requires_region_proof"
    return None


def select_functions(
    args: argparse.Namespace,
    oracle: angr.Project,
    candidate: angr.Project,
    boundaries: dict[str, tuple[int, int]],
    symbols: dict[str, Symbol],
    names: list[str],
) -> tuple[dict[str, tuple[int, int]], dict[str, tuple[int, int]], list[dict[str, Any]]]:
    """Keep a result for every requested name, including absent and unsupported bodies."""
    oracle_functions: dict[str, tuple[int, int]] = {}
    candidate_functions: dict[str, tuple[int, int]] = {}
    results: list[dict[str, Any]] = []
    delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
    for name in names:
        reason: str | None = None
        if name not in boundaries or name not in symbols:
            reason = "mapping_missing"
        else:
            start, last = boundaries[name]
            last_size = oracle.factory.block(last, num_inst=1).vex.size
            size = last - start + last_size
            symbol = symbols[name]
            address = symbol.address + delta
            if args.mode == "leaf":
                reason = preflight(oracle, start, size, args.scan_limit)
                reason = reason or preflight(candidate, address, symbol.size, args.scan_limit)
            if reason is None:
                oracle_functions[name] = start, size
                candidate_functions[name] = address, symbol.size or args.scan_limit
        if reason is not None:
            results.append({"function": {"name": name}, "status": Status.REFUSED, "reason": reason})
    return oracle_functions, candidate_functions, results


def write_json(directory: Path, name: str, document: object) -> None:
    """Persist a reproducible artifact with readable JSON and a final newline."""
    (directory / name).write_text(json.dumps(document, indent=2) + "\n")


def _mismatch_is_relocation(item: dict[str, Any], relocation: dict[int, int]) -> bool:
    """A diff is relocation-only when candidate/oracle values form a mapped pair."""
    if item.get("kind") != "output_expr_changed":
        return False
    try:
        candidate_int = int(str(item.get("candidate_value")), 0)
        oracle_int = int(str(item.get("oracle_value")), 0)
    except (TypeError, ValueError):
        return False
    return relocation.get(candidate_int) == oracle_int


def retry_loop_with_cfg(
    name: str,
    verdict: dict[str, Any],
    context: tuple[angr.Project, angr.Project, dict[str, tuple[int, int]], dict[str, tuple[int, int]]] | None,
    outputs: tuple[str, ...],
    timeout_ms: int,
    normalization: dict[int, int] | None = None,
) -> dict[str, Any]:
    """Retry only a loop refusal with at most eight blocks and 250 ms per block."""
    if verdict.get("reason") != "loop_requires_inductive_proof" or context is None:
        return verdict
    from flat32_cfg import compare_cfg

    oracle, candidate, oracle_ranges, candidate_ranges = context
    cfg = compare_cfg(
        oracle, candidate, name=name,
        oracle_range=oracle_ranges[name], candidate_range=candidate_ranges[name],
        outputs=outputs, timeout_ms=min(timeout_ms, 250), max_blocks=8,
        normalization=normalization,
    )
    if cfg["status"] == Status.REFUSED:
        return verdict
    return {key: value for key, value in cfg.items()
            if key not in {"function", "oracle_ssa", "candidate_ssa", "block_compare"}}


def _group_region_document(
    document: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[dict[str, Any]]]]:
    """Index parts by function name and refusals by function name."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    by_refusal: dict[str, list[dict[str, Any]]] = {}
    for part in document["functions"]:
        function = part.get("function") if isinstance(part.get("function"), dict) else {}
        by_name.setdefault(str(function.get("name") or ""), []).append(part)
    for refusal in document["refusals"]:
        detail = refusal.get("detail") if isinstance(refusal.get("detail"), dict) else {}
        function_id = str(detail.get("function_id") or "")
        by_refusal.setdefault(function_id.rsplit(":", 1)[-1], []).append(refusal)
    return by_name, by_refusal


def compare_region_mode(
    args: argparse.Namespace,
    oracle_ssa: dict[str, Any],
    candidate_ssa: dict[str, Any],
    names: list[str],
    *,
    existing_results: list[dict[str, Any]],
    relocation: dict[int, int],
    loop_context: tuple[angr.Project, angr.Project, dict[str, tuple[int, int]], dict[str, tuple[int, int]]] | None = None,
    call_entries: tuple[dict[int, str], dict[int, str]] | None = None,
) -> dict[str, Any]:
    """Account for each bounded region; optionally retry loops with CFG induction."""
    from flat32_region import compare_region

    grouped: list[dict[str, list[dict[str, Any]]]] = []
    refusals: list[dict[str, list[dict[str, Any]]]] = []
    for document in (oracle_ssa, candidate_ssa):
        by_name, by_refusal = _group_region_document(document)
        grouped.append(by_name)
        refusals.append(by_refusal)

    # BCC32 -O2 bodies are larger than the sibling comparator's MSC8 corpus.
    limits = region_limits(args.region_max_blocks)
    results = list(existing_results)
    selected = {item["function"]["name"] for item in existing_results}
    return_outputs = tuple(dict.fromkeys((*args.output_regs.split(","), *OUTPUT_REGS[3:])))
    for name in names:
        if name in selected:
            continue
        issue = [*refusals[0].get(name, []), *refusals[1].get(name, [])]
        if issue:
            verdict: dict[str, Any] = {
                "status": Status.REFUSED,
                "reason": "region_lowering_incomplete",
                "lowering_refusals": issue,
            }
        else:
            verdict = compare_region(
                grouped[0].get(name, []), grouped[1].get(name, []),
                outputs=return_outputs, timeout_ms=args.timeout_ms, limits=limits,
                normalization=relocation,
                call_resolver_oracle=call_entries[0].get if call_entries else None,
                call_resolver_candidate=call_entries[1].get if call_entries else None,
            )
            if (
                verdict.get("status") == Status.FAILED
                and relocation
                and verdict.get("mismatches")
                and all(
                    isinstance(item, dict) and _mismatch_is_relocation(item, relocation)
                    for item in verdict["mismatches"]
                )
            ):
                assumptions = dict(verdict.get("paired_call_assumptions") or {})
                assumptions.update(
                    constant_relocation_count=len(relocation),
                    constant_relocation_scope="every output diff is a mapped candidate->oracle data relocation",
                )
                verdict = {
                    "status": Status.CONDITIONAL,
                    "reason": "relocation_assumptions",
                    "backend_status": Status.FAILED,
                    "assumptions": assumptions,
                }
            verdict = retry_loop_with_cfg(
                name, verdict, loop_context, return_outputs, args.timeout_ms, normalization=relocation
            )
            if relocation and verdict.get("status") in {Status.PASSED, Status.CONDITIONAL}:
                assumptions = dict(verdict.get("assumptions") or {})
                assumptions.update(
                    constant_relocation_count=len(relocation),
                    constant_relocation_scope="candidate constants normalized to independently labeled oracle globals",
                )
                verdict = {
                    **verdict, "status": Status.CONDITIONAL,
                    "reason": verdict.get("reason") if verdict.get("status") == Status.CONDITIONAL else "relocation_assumptions",
                    "assumptions": assumptions,
                }
        results.append({"function": {"id": f"oracle:{name}", "name": name}, **verdict})
    results.sort(key=lambda item: item["function"]["name"])
    summary = summarize(results)
    if summary["total"] != len(names):
        raise RuntimeError("region proof obligation accounting mismatch")
    return {
        "schema": REPORT_SCHEMA,
        "summary": summary,
        "results": results,
        "evidence": {
            "raw_fact_count": len(names),
            "normalized_fact_count": len(names) - len(existing_results),
            "classified_fact_count": len(names) - len(existing_results),
            "materialized_count": sum(
                bool(grouped[0].get(name)) and bool(grouped[1].get(name)) and not refusals[0].get(name)
                and not refusals[1].get(name)
                for name in names
            ),
            "failure_count": summary["refused"] + summary["failed"] + summary["conditional"],
        },
        "proof_contract": {
            "control_flow": (
                "complete acyclic PE32 region, or closed matched CFG induction for at most eight blocks"
                if loop_context is not None else "complete acyclic PE32 region, full 32-bit successor targets"
            ),
            "calls": (
                "with --assume-paired-calls, paired direct calls to the same mapped name use "
                "an explicit post-call-state equality assumption; equality is CONDITIONAL, "
                "never PASSED; indirect/unmapped targets and unmatched order refuse"
                if call_entries else "refused until a proven flat32 callee summary is available"
            ),
            "loops": (
                "matched CFG fallback: eight blocks and 250 ms per block; unsupported loops refuse"
                if loop_context is not None else "refused; matched-cfg induction remains available"
            ),
            "outputs": return_outputs,
            "memory": "entire unconstrained flat byte array",
            "global_normalization": "conditional value relocation" if relocation else None,
        },
        "inputs": {
            side: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for side, path in [("oracle", args.oracle_exe), ("candidate", args.candidate_exe)]
        },
        "lowering_refusals": {"oracle": oracle_ssa["refusals"], "candidate": candidate_ssa["refusals"]},
    }


def compare(args: argparse.Namespace) -> dict[str, Any]:
    """Lower accepted complete bodies and retain every missing/refused obligation."""
    oracle, candidate = load32(args.oracle_exe), load32(args.candidate_exe)
    boundaries = lst_functions(args.oracle_lst)
    if args.candidate_lst:
        symbols = {
            name: Symbol(start, last - start + candidate.factory.block(last, num_inst=1).vex.size, "T")
            for name, (start, last) in lst_functions(args.candidate_lst).items()
        }
    else:
        symbols = nm_symbols(args.candidate_exe)
    if args.candidate_syms:
        for name, sym in nm_symbols(args.candidate_syms).items():
            symbols.setdefault(name, sym)
    names = (
        sorted({name.strip() for name in args.functions.split(",") if name.strip()})
        if args.functions
        else sorted(name for name in boundaries.keys() & symbols.keys() if name.startswith("sub_"))
    )
    ofuncs, cfuncs, results = select_functions(args, oracle, candidate, boundaries, symbols, names)
    omod, cmod = "oracle", "candidate"
    ocat = catalog(omod, ofuncs, oracle.loader.main_object.linked_base)
    ccat = catalog(cmod, cfuncs, candidate.loader.main_object.linked_base)
    pairs = mapping(omod, cmod, list(ofuncs))
    output_regs = tuple(dict.fromkeys((*args.output_regs.split(","), *OUTPUT_REGS[3:])))
    if args.mode == "matched-cfg":
        from flat32_cfg import compare_cfg

        normalization = (
            global_map(symbols, candidate, oracle, lst_data_symbols(args.oracle_lst))
            if args.normalize_globals
            else {}
        )
        for name in ofuncs:
            result = compare_cfg(
                oracle,
                candidate,
                name=name,
                oracle_range=ofuncs[name],
                candidate_range=cfuncs[name],
                outputs=output_regs,
                timeout_ms=args.timeout_ms,
                normalization=normalization,
            )
            write_json(args.out_dir, f"{name}.cfg.json", result)
            results.append(
                {
                    key: value
                    for key, value in result.items()
                    if key not in {"oracle_ssa", "candidate_ssa", "block_compare"}
                }
            )
        summary = summarize(results)
        report = {
            "schema": REPORT_SCHEMA,
            "summary": summary,
            "results": results,
            "proof_contract": {
                "control_flow": "closed bijective CFG induction over full internal state",
                "outputs": output_regs,
                "memory": "entire byte array",
                "calls": "refused",
                "global_normalization": None,
            },
        }
        write_json(args.out_dir, "compare.json", report)
        return report
    if args.mode in {"region", "auto"}:
        kwargs = {
            "output_regs": (*output_regs, "ip"),
            "scan_limit": max(args.scan_limit, 0x10000),
            "max_blocks_per_function": args.region_max_blocks,
            "max_insns_per_function": 512,
            "max_assignments_per_function": 4096,
            "follow_call_fallthrough": True,
            "max_function_ms": args.timeout_ms,
            "cache_dir": args.cache_dir,
        }
        ossa = S.lower_straightline_ssa_document(
            exe_path=args.oracle_exe, functions_catalog=ocat, **kwargs
        )
        cssa = S.lower_straightline_ssa_document(
            exe_path=args.candidate_exe, functions_catalog=ccat, **kwargs
        )
        normalization = (
            global_map(symbols, candidate, oracle, lst_data_symbols(args.oracle_lst)) if args.normalize_globals else {}
        )
        loop_context = (oracle, candidate, ofuncs, cfuncs) if args.mode == "auto" else None
        delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
        call_entries = mapped_call_entries(boundaries, symbols, delta) if args.assume_paired_calls else None
        report = compare_region_mode(
            args, ossa, cssa, names,
            existing_results=results, relocation=normalization, loop_context=loop_context,
            call_entries=call_entries,
        )
        write_json(args.out_dir, "compare.json", report)
        write_json(args.out_dir, "oracle.ssa.json", ossa)
        write_json(args.out_dir, "candidate.ssa.json", cssa)
        return report
    kwargs = {
        "output_regs": output_regs,
        "scan_limit": args.scan_limit,
        "max_blocks_per_function": 1,
        "max_insns_per_function": 1024,
        "max_assignments_per_function": 4096,
        "follow_call_fallthrough": False,
        "max_function_ms": args.timeout_ms,
    }
    ossa = S.lower_straightline_ssa_document(exe_path=args.oracle_exe, functions_catalog=ocat, **kwargs)
    cssa = S.lower_straightline_ssa_document(exe_path=args.candidate_exe, functions_catalog=ccat, **kwargs)
    normalization = (
        global_map(symbols, candidate, oracle, lst_data_symbols(args.oracle_lst)) if args.normalize_globals else {}
    )
    for function in cssa["functions"]:
        function["_constant_normalization"] = normalization
        function["_constant_normalization_reasons"] = dict.fromkeys(normalization, "global_reloc")
    raw = S.compare_ssa_documents(
        oracle=ossa,
        candidate=cssa,
        mapping_document=pairs,
        timeout_ms=args.timeout_ms,
        max_solver_assignments=4096,
        max_solver_inputs=64,
        max_solver_memory_stores=256,
        skip_binary_equal=False,
        allow_aliased_call_targets=False,
        enable_callee_lemmas=False,
        enable_region_equality=False,
        enable_connectivity=False,
    )
    expected = {name: f"{omod}:{name}" for name in ofuncs}
    results.extend(checked_results(expected, raw, relocation=normalization))
    results.sort(key=lambda item: item["function"]["name"])
    summary = summarize(results)
    if summary["total"] != len(names):
        raise RuntimeError("proof obligation accounting mismatch")
    report = {
        "schema": REPORT_SCHEMA,
        "summary": summary,
        "results": results,
        "evidence": {
            "raw_fact_count": len(names),
            "normalized_fact_count": len(ofuncs),
            "classified_fact_count": len(ofuncs),
            "materialized_count": len(
                {item["function"]["name"] for item in ossa["functions"]}
                & {item["function"]["name"] for item in cssa["functions"]}
            ),
            "failure_count": summary["refused"] + summary["failed"] + summary["conditional"],
        },
        "proof_contract": {
            "output_regs": output_regs,
            "memory": "entire byte array including stack writes",
            "control_flow": "complete single-block near return; 32-bit return target observed",
            "flags": "pure uninterpreted x86g_calculate_condition; SAT can be spurious",
            "global_normalization": "conditional value relocation; not a pointer-alias or data-initialization proof"
            if normalization
            else None,
        },
        "inputs": {
            side: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for side, path in [("oracle", args.oracle_exe), ("candidate", args.candidate_exe)]
        },
        "lowering_refusals": {"oracle": ossa["refusals"], "candidate": cssa["refusals"]},
    }
    for filename, document in [
        ("oracle.functions.json", ocat),
        ("candidate.functions.json", ccat),
        ("mapping.json", pairs),
        ("oracle.ssa.json", ossa),
        ("candidate.ssa.json", cssa),
        ("raw-compare.json", raw),
        ("compare.json", report),
        ("globals.json", {hex(k): hex(v) for k, v in normalization.items()}),
    ]:
        write_json(args.out_dir, filename, document)
    return report


def main() -> int:
    """Run an explicit selection or enumerate all mapped sub_* obligations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--oracle-lst", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--candidate-lst", type=Path, help="candidate IDA boundaries for a PE32/self-hosted rebuild")
    parser.add_argument("--candidate-syms", type=Path, help="auxiliary symbol-table image (nm-readable) supplying candidate data symbols")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--functions")
    group.add_argument("--all-mapped", action="store_true")
    parser.add_argument("--mode", choices=["leaf", "matched-cfg", "region", "auto"], default="leaf")
    parser.add_argument(
        "--region-max-blocks", type=int, default=REGION_DEFAULT_BLOCK_CAP,
        help="region/auto scanner and composition block cap (default 128, maximum 256)",
    )
    parser.add_argument(
        "--assume-paired-calls", action="store_true",
        help="allow matched direct calls under explicit post-call-state equality assumptions (conditional only)",
    )
    parser.add_argument(
        "--normalize-globals", action="store_true", help="conditional value relocation; see proof_contract"
    )
    parser.add_argument(
        "--output-regs", default="eax,edx,esp", help="explicit return contract; preserved GPRs and eip always checked"
    )
    parser.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x2000)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    parser.add_argument(
        "--cache-dir", type=Path, default=Path("/tmp/z3bcc-vexcache"),
        help="shared VEX lift cache; persists across sharded runs",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.region_max_blocks <= REGION_MAX_BLOCK_CAP:
        parser.error("region-max-blocks must be between 1 and 256")
    if args.assume_paired_calls and args.mode not in {"region", "auto"}:
        parser.error("assume-paired-calls requires region or auto mode")
    if args.scan_limit <= 0 or args.timeout_ms <= 0:
        parser.error("scan-limit and timeout-ms must be positive")
    if args.mode == "matched-cfg" and args.normalize_globals:
        parser.error("matched-cfg currently requires literal data addresses")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with installed(region=args.mode in {"region", "auto"}):
        result = compare(args)
    print(json.dumps(result["summary"]))
    for item in result["results"]:
        print(f"{item['function']['name']}: {item['status']} ({item.get('reason')})")
    return exit_code(result["summary"])


if __name__ == "__main__":
    raise SystemExit(main())
