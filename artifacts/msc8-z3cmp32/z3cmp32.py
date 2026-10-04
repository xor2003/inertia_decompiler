#!/usr/bin/env python3
"""Layer: validation CLI.

Responsibility: compare PE32/ELF32 functions through dosunit SSA/Z3.
The opt-in PE32 region mode composes complete acyclic call-free CFGs;
unproved calls, loops and partial regions remain explicit refusals.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

import angr
from flat32_adapter import OUTPUT_REGS, REG_NAMES, S, installed, load32
from flat32_catalog import Symbol, catalog, global_map, lst_data_symbols, lst_functions, mapping, nm_symbols
from flat32_verdict import REPORT_SCHEMA, Status, checked_results, exit_code, summarize

if TYPE_CHECKING:
    from tools.dosunit.flat32_proof_domain import Flat32ProofDomain
    from tools.dosunit.ordered_io_environment import OrderedIoContract


def preflight(project: angr.Project, address: int, size: int, scan_limit: int) -> str | None:
    """Require a whole near-return block, with no hidden exceptional/branch exits."""
    block = project.factory.block(address, size=min(size or scan_limit, scan_limit), opt_level=0)
    from tools.dosunit.binary_environment import requires_environment_contract

    if requires_environment_contract(block.vex):
        return "external_environment_contract_required"
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


def _component_functions(
    args: argparse.Namespace,
    oracle: angr.Project,
    candidate: angr.Project,
    boundaries: dict[str, tuple[int, int]],
    symbols: dict[str, Symbol],
    names: list[str],
) -> tuple[dict[str, tuple[int, int]], dict[str, tuple[int, int]], list[str]]:
    """Resolve selected names into declared ranges independent of mode admission.

    The recursive component has its own same-coordinate admission rules; a
    function refused by mode preflight can still be a declared member. Each
    side contributes only the names it can actually resolve, so one-sided and
    unresolved selections reach the adapter as refused attempts rather than
    disappearing from the accounting.
    """
    delta = candidate.loader.main_object.mapped_base - candidate.loader.main_object.linked_base
    oracle_functions: dict[str, tuple[int, int]] = {}
    candidate_functions: dict[str, tuple[int, int]] = {}
    unresolved: list[str] = []
    for name in names:
        resolved = False
        if name in boundaries:
            start, last = boundaries[name]
            size = last - start + oracle.factory.block(last, num_inst=1).vex.size
            oracle_functions[name] = start, size
            resolved = True
        if name in symbols:
            symbol = symbols[name]
            candidate_functions[name] = symbol.address + delta, symbol.size or args.scan_limit
            resolved = True
        if not resolved:
            unresolved.append(name)
    return oracle_functions, candidate_functions, unresolved


def _recursive_joint_document(
    args: argparse.Namespace,
    oracle: angr.Project,
    candidate: angr.Project,
    boundaries: dict[str, tuple[int, int]],
    symbols: dict[str, Symbol],
    names: list[str],
) -> dict[str, Any] | None:
    """Attempt the declared opt-in component proof; absent request means no field.

    The image-bound PE32 recursive proof lifts its own same-coordinate member
    closure and needs the unmodified block finisher, so it always re-enters
    this driver's seam with ``region=True`` regardless of the enclosing mode.
    Ordinary rows, statuses and dependencies are never touched; the retained
    outcome is a separate initialized-entry result, never member discharge.
    """
    from tools.dosunit.pe32_recursive_compare import (
        prove_pe32_recursive_compare,
        recursive_request_from_args,
    )

    request = recursive_request_from_args(args)
    if request is None:
        return None
    oracle_functions, candidate_functions, unresolved = _component_functions(
        args, oracle, candidate, boundaries, symbols, names)
    with installed(region=True):
        outcome = prove_pe32_recursive_compare(
            oracle_exe=args.oracle_exe,
            candidate_exe=args.candidate_exe,
            oracle_functions=oracle_functions,
            candidate_functions=candidate_functions,
            request=request,
            unresolved_names=unresolved,
        )
    document: dict[str, Any] = outcome.to_document()
    return document


def retry_loop_with_cfg(
    name: str,
    verdict: dict[str, Any],
    context: tuple[angr.Project, angr.Project, dict[str, tuple[int, int]], dict[str, tuple[int, int]]] | None,
    outputs: tuple[str, ...],
    timeout_ms: int,
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
    )
    if cfg["status"] == Status.REFUSED:
        return verdict
    return {key: value for key, value in cfg.items()
            if key not in {"function", "oracle_ssa", "candidate_ssa", "block_compare"}}


def compare_region_mode(
    args: argparse.Namespace,
    oracle_ssa: dict[str, Any],
    candidate_ssa: dict[str, Any],
    names: list[str],
    existing_results: list[dict[str, Any]],
    loop_context: tuple[angr.Project, angr.Project, dict[str, tuple[int, int]], dict[str, tuple[int, int]]] | None = None,
    entry_domain: Flat32ProofDomain | None = None,
    io_model: OrderedIoContract | None = None,
) -> dict[str, Any]:
    """Account for each bounded region; optionally retry loops with CFG induction.

    ``entry_domain`` is the caller-declared top-level entry-esp premise; it is
    forwarded to the checked call-composition retry only. A verdict that needed
    the premise stays conditional with its serialized assumptions.

    ``io_model`` is the declared ordered-I/O environment contract; it is
    forwarded to the composition retry and the checked environment gate, which
    republishes any discharged verdict covering port events as conditional on
    the recorded premise.
    """
    from flat32_region import compare_region

    grouped: list[dict[str, list[dict[str, Any]]]] = []
    refusals: list[dict[str, list[dict[str, Any]]]] = []
    for document in (oracle_ssa, candidate_ssa):
        by_name: dict[str, list[dict[str, Any]]] = {}
        by_refusal: dict[str, list[dict[str, Any]]] = {}
        for part in document["functions"]:
            function = part.get("function") if isinstance(part.get("function"), dict) else {}
            by_name.setdefault(str(function.get("name") or ""), []).append(part)
        for refusal in document["refusals"]:
            detail = refusal.get("detail") if isinstance(refusal.get("detail"), dict) else {}
            function_id = str(detail.get("function_id") or "")
            by_refusal.setdefault(function_id.rsplit(":", 1)[-1], []).append(refusal)
        grouped.append(by_name)
        refusals.append(by_refusal)

    results = list(existing_results)
    selected = {item["function"]["name"] for item in existing_results}
    return_outputs = tuple(dict.fromkeys((*args.output_regs.split(","), *OUTPUT_REGS[2:])))
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
                outputs=return_outputs, timeout_ms=args.timeout_ms,
            )
            verdict = retry_loop_with_cfg(name, verdict, loop_context, return_outputs, args.timeout_ms)
        from tools.dosunit.flat32_proof_retry import checked_environment_verdict, retry_function_proof

        verdict = retry_function_proof(name, verdict, loop_context, return_outputs, args.timeout_ms,
                                       entry_domain=entry_domain, io_model=io_model)
        verdict = checked_environment_verdict(verdict, loop_context,
                                               grouped[0].get(name, []), grouped[1].get(name, []),
                                               io_model=io_model)
        results.append({"function": {"id": f"oracle:{name}", "name": name}, **verdict})
    results.sort(key=lambda item: item["function"]["name"])
    summary = summarize(results)
    if summary["total"] != len(names):
        raise RuntimeError("region proof obligation accounting mismatch")
    report = {
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
            "calls": "bounded complete nonrecursive VEX composition with checked return targets",
            "loops": (
                "matched CFG fallback: eight blocks and 250 ms per block; unsupported loops refuse"
                if loop_context is not None else "refused; matched-cfg induction remains available"
            ),
            "outputs": return_outputs,
            "memory": "entire unconstrained flat byte array",
            "global_normalization": None,
            "entry_esp_premise": (
                entry_domain.assumption_document() if entry_domain is not None else None
            ),
            "ordered_io_premise": (
                io_model.premise_document() if io_model is not None else None
            ),
        },
        "inputs": {
            side: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for side, path in [("oracle", args.oracle_exe), ("candidate", args.candidate_exe)]
        },
        "lowering_refusals": {"oracle": oracle_ssa["refusals"], "candidate": candidate_ssa["refusals"]},
    }
    for filename, document in (
        ("oracle.ssa.json", oracle_ssa),
        ("candidate.ssa.json", candidate_ssa),
        ("compare.json", report),
    ):
        write_json(args.out_dir, filename, document)
    return report


def _compare(args: argparse.Namespace) -> dict[str, Any]:  # noqa: C901
    """Lower accepted complete bodies and retain every missing/refused obligation."""
    from tools.dosunit.flat32_proof_domain_cli import (
        require_supported_entry_domain,
        require_supported_io_domain,
    )

    entry_domain = require_supported_entry_domain(args)
    io_model = require_supported_io_domain(args)
    oracle, candidate = load32(args.oracle_exe), load32(args.candidate_exe)
    from tools.dosunit.flat32_proof_report import loaded_image_identity

    images = {"oracle": loaded_image_identity(oracle), "candidate": loaded_image_identity(candidate)}
    if args.mode in {"region", "auto"}:
        for path in (args.oracle_exe, args.candidate_exe):
            with path.open("rb") as stream:
                if stream.read(2) != b"MZ":
                    raise ValueError("region mode currently requires PE32 on both sides")
    boundaries = lst_functions(args.oracle_lst)
    if args.candidate_lst:
        symbols = {
            name: Symbol(start, last - start + candidate.factory.block(last, num_inst=1).vex.size, "T")
            for name, (start, last) in lst_functions(args.candidate_lst).items()
        }
        # Function boundaries come from the lst, but data symbols (for
        # --normalize-globals) must come from the exe's own symbol table —
        # VC1.1 LINK strips it, graft it back first with
        # rebuild/tools/mapsyms.py. nm fails on stripped images.
        try:
            for n, s in nm_symbols(args.candidate_exe).items():
                if s.kind in "bBdDrRsS":
                    symbols.setdefault(n, s)
        except subprocess.CalledProcessError:
            pass
    else:
        symbols = nm_symbols(args.candidate_exe)
    names = (
        sorted({name.strip() for name in args.functions.split(",") if name.strip()})
        if args.functions
        else sorted(name for name in boundaries if name.startswith("sub_"))
    )
    ofuncs, cfuncs, results = select_functions(args, oracle, candidate, boundaries, symbols, names)
    recursive_joint = _recursive_joint_document(args, oracle, candidate, boundaries, symbols, names)
    from tools.dosunit.flat32_proof_retry import build_proof_context

    proof_context = build_proof_context(args.mode, oracle, candidate, lambda: select_functions(
        args, oracle, candidate, boundaries, symbols, sorted(boundaries.keys() | symbols.keys()),
    ))
    omod, cmod = "oracle", "candidate"
    ocat = catalog(omod, ofuncs, oracle.loader.main_object.linked_base)
    ccat = catalog(cmod, cfuncs, candidate.loader.main_object.linked_base)
    pairs = mapping(omod, cmod, list(ofuncs))
    output_regs = tuple(dict.fromkeys((*args.output_regs.split(","), *OUTPUT_REGS[2:])))
    if args.mode == "matched-cfg":
        from flat32_cfg import compare_cfg

        for name in ofuncs:
            result = compare_cfg(
                oracle,
                candidate,
                name=name,
                oracle_range=ofuncs[name],
                candidate_range=cfuncs[name],
                outputs=output_regs,
                timeout_ms=args.timeout_ms,
            )
            from tools.dosunit.flat32_proof_retry import checked_cfg_environment_verdict, retry_function_proof

            retried = retry_function_proof(name, result, proof_context, output_regs, args.timeout_ms,
                                           entry_domain=entry_domain, io_model=io_model)
            retried = checked_cfg_environment_verdict(retried, result, proof_context, io_model=io_model)
            result = {**retried, "function": {"id": f"oracle:{name}", "name": name}}
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
            "requested_functions": names,
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
        report["loaded_images"] = images
        report["function_ranges"] = {"oracle": ofuncs, "candidate": cfuncs}
        report["recursive_joint"] = recursive_joint
        return report
    kwargs = {
        "output_regs": (*REG_NAMES, "ip") if args.mode in {"region", "auto"} else output_regs,
        "scan_limit": args.scan_limit,
        "max_blocks_per_function": 64 if args.mode in {"region", "auto"} else 1,
        "max_insns_per_function": 128 if args.mode in {"region", "auto"} else 1024,
        "max_assignments_per_function": 2048 if args.mode in {"region", "auto"} else 4096,
        "follow_call_fallthrough": args.mode in {"region", "auto"},
        "max_function_ms": args.timeout_ms,
    }
    ossa = S.lower_straightline_ssa_document(exe_path=args.oracle_exe, functions_catalog=ocat, **kwargs)
    cssa = S.lower_straightline_ssa_document(exe_path=args.candidate_exe, functions_catalog=ccat, **kwargs)
    if args.mode in {"region", "auto"}:
        context = proof_context
        report = compare_region_mode(
            args, ossa, cssa, names, results, context,
            entry_domain=entry_domain, io_model=io_model,
        )
        report["requested_functions"] = names
        report["loaded_images"] = images
        report["function_ranges"] = {"oracle": ofuncs, "candidate": cfuncs}
        report["recursive_joint"] = recursive_joint
        return report
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
        "requested_functions": names,
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
            "flags": "lazy-flag summaries: supported thunks evaluated exactly; unsupported flag-dependent counterexamples refuse",
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
    report["loaded_images"] = images
    report["function_ranges"] = {"oracle": ofuncs, "candidate": cfuncs}
    report["recursive_joint"] = recursive_joint
    return report


def compare(args: argparse.Namespace) -> dict[str, Any]:
    """Bind complete backend evidence to current binaries and proof contracts."""
    from tools.dosunit.flat32_proof_report import run_bound_comparison

    return run_bound_comparison(_compare, args, Path(__file__))


def main() -> int:
    """Run an explicit selection or enumerate all mapped sub_* obligations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--oracle-lst", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--candidate-lst", type=Path, help="candidate IDA boundaries for a PE32/self-hosted rebuild")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--functions")
    group.add_argument("--all-mapped", action="store_true")
    parser.add_argument("--mode", choices=["leaf", "matched-cfg", "region", "auto"], default="leaf")
    parser.add_argument(
        "--normalize-globals", action="store_true", help="conditional value relocation; see proof_contract"
    )
    parser.add_argument(
        "--output-regs", default="eax,edx,esp", help="explicit return contract; preserved GPRs and eip always checked"
    )
    parser.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x2000)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    from tools.dosunit.flat32_proof_domain_cli import (
        add_entry_esp_range_argument,
        add_ordered_io_argument,
        check_entry_domain_mode,
        check_ordered_io_mode,
    )
    from tools.dosunit.pe32_recursive_compare import add_recursive_arguments, check_recursive_request

    add_entry_esp_range_argument(parser)
    add_ordered_io_argument(parser)
    add_recursive_arguments(parser)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    check_entry_domain_mode(parser, args)
    check_ordered_io_mode(parser, args)
    check_recursive_request(parser, args)
    if args.scan_limit <= 0 or args.timeout_ms <= 0:
        parser.error("scan-limit and timeout-ms must be positive")
    if args.mode in {"matched-cfg", "region", "auto"} and args.normalize_globals:
        parser.error(f"{args.mode} currently requires literal data addresses")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    with installed(region=args.mode in {"region", "auto"}):
        result = compare(args)
    print(json.dumps(result["summary"]))
    for item in result["results"]:
        print(f"{item['function']['name']}: {item['status']} ({item.get('reason')})")
    return exit_code(result["summary"])


if __name__ == "__main__":
    raise SystemExit(main())
