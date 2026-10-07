#!/usr/bin/env python3
"""Layer: validation CLI.

Responsibility: compare PE32/ELF32 functions through dosunit SSA/Z3.
`leaf` admits complete single-block near returns; `matched-cfg` runs closed
bijective CFG induction; the opt-in PE32 `region`/`auto` modes compose
complete bounded acyclic regions. Unproved results in the non-leaf modes
retry through checked lanes: call composition over declared callee ranges,
which inlines every direct call and every indirect call whose composed
target selector finitely enumerates only declared entries, with a Z3-proved
return target at each call site; bounded matched/reblocked CFG induction;
and closed call-loop or macro-step induction, so callers whose loops
contain admitted direct calls can prove. Recursive or undeclared call
targets, indirect selectors with unconstrained or over-budget leaves,
partial scans and exhausted budgets refuse; `--recursive` is a separate
opt-in image-bound PE32 component proof over a caller-declared access
domain, never member discharge. Conditional premise options
(`--normalize-globals`, optionally sourcing its relocation evidence from a
bound `--candidate-link-map`, `--entry-esp-range`, `--ordered-io-environment`)
publish serialized assumptions. No refusal or conditional result is counted
as an unconditional proof.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Any

import angr

from tools.comparator.catalog import catalog, mapping
from tools.comparator.msc8_catalog import (
    ListingEndKind,
    Symbol,
    global_map,
    link_map_global_map,
    listing_size,
    lst_data_symbols,
    lst_functions,
    nm_symbols,
)
from tools.comparator.native import OUTPUT_REGS, S
from tools.comparator.profiles import declared_bounds_only
from tools.comparator.verdict import REPORT_SCHEMA, Status, checked_results, exit_code, summarize
from tools.dosunit.architectures.flat32 import _FLAT32_REG_NAMES as REG_NAMES
from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.architectures.flat32_loader import load_flat32_project as load32
from tools.dosunit.contracts.comparison import EXPLICIT_COMPARISON_POLICY
from tools.dosunit.contracts.scanning import FunctionLoweringPolicy

if TYPE_CHECKING:
    from tools.dosunit.catalog.pe32_link_map import Pe32LinkMap
    from tools.dosunit.contracts.flat32_proof_domain import Flat32ProofDomain
    from tools.dosunit.contracts.ordered_io_environment import OrderedIoContract


_RET8 = {"char", "_byte", "__int8", "signed char", "unsigned char", "bool", "byte"}
_RET16 = {"__int16", "short", "short int", "unsigned short", "unsigned short int",
          "_word", "int16_t", "uint16_t", "wchar_t"}


def _return_width_masks(args: argparse.Namespace, names: list[str]) -> dict[str, int | None]:
    """Map function names to an eax mask derived from the declared return type.

    ``char``/``_BYTE`` → ``0xff``; ``__int16``/``short``/``_WORD`` → ``0xffff``;
    ``void`` → ``None`` (eax dropped).  The candidate's generated C is located
    via ``--candidate-src`` or derived from ``--candidate-lst`` (``X_cand.lst``
    sits beside ``X.c``); oracle names ``sub_<VA>`` resolve through
    ``funcnames.map`` when present beside the oracle listing.

    Optional fields cross a dynamic third-party argparse boundary: external
    callers may omit these declaration inputs, retaining the existing defaults.
    """
    src = getattr(args, "candidate_src", None) or ""
    if not src and getattr(args, "candidate_lst", None):
        src = str(args.candidate_lst).replace("_cand.lst", ".c")
    path = Path(src) if src else None
    if not path or not path.is_file() or not names:
        return {}
    decls: dict[str, str] = {}
    import re
    pat = re.compile(
        r"^\s*([A-Za-z_][\w\s\*]*?)\s*(?:__stdcall|__cdecl|__usercall|__thiscall|"
        r"__userpurge|__fastcall)?\s*(\w+)\s*\(")
    for line in path.read_text(errors="replace").splitlines():
        m = pat.match(line)
        if m:
            decls.setdefault(m.group(2), m.group(1).strip())
    # oracle sub_<VA> -> candidate semantic name through funcnames.map
    fmap: dict[str, str] = {}
    mapc = getattr(args, "candidate_map", None) or ""
    if not mapc and getattr(args, "oracle_lst", None):
        cand = Path(str(args.oracle_lst)).parent / "funcnames.map"
        mapc = str(cand) if cand.is_file() else ""
    if mapc and Path(mapc).is_file():
        import re as _re
        mod = Path(str(getattr(args, "oracle_exe", ""))).name.upper()
        for line in Path(mapc).read_text(errors="replace").splitlines():
            row = _re.split(r"\s+", line.strip(), maxsplit=4)
            if len(row) >= 4 and row[0].upper() == mod:
                fmap[row[2]] = row[3]
                fmap["sub_" + row[1].lstrip("0").upper()] = row[3]
                fmap["sub_" + row[1].lstrip("0").lower()] = row[3]
    return _named_return_masks(decls, fmap, names)


def _named_return_masks(
    decls: dict[str, str], fmap: dict[str, str], names: list[str],
) -> dict[str, int | None]:
    """Preserve the existing declared-width masks and explicit void contract."""
    import re

    masks: dict[str, int | None] = {}
    for name in names:
        ret = decls.get(name) or decls.get(fmap.get(name, ""), "")
        low = re.sub(r"\s+", " ", ret.lower()).strip()
        if low in _RET8 or low.endswith(("char", "_byte")):
            masks[name] = 0xFF
        elif low in _RET16 or low.endswith(("__int16", "short")):
            masks[name] = 0xFFFF
        elif low == "void":
            masks[name] = None
    return masks


def preflight(project: angr.Project, address: int, size: int, scan_limit: int) -> str | None:
    """Require a whole near-return block, with no hidden exceptional/branch exits."""
    block = project.factory.block(address, size=min(size or scan_limit, scan_limit), opt_level=0)
    from tools.dosunit.contracts.binary_environment import requires_environment_contract

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
    from tools.dosunit.catalog.flat32_catalog_admission import check_declared_pair

    for name in names:
        reason: str | None = None
        if name not in boundaries or name not in symbols:
            reason = "mapping_missing"
        else:
            start, last = boundaries[name]
            symbol = symbols[name]
            address = symbol.address + delta
            admission = check_declared_pair(
                oracle, candidate, oracle_entry=start, oracle_end_byte=last,
                candidate_entry=address, candidate_size=symbol.size,
            )
            if admission is not None:
                results.append({"function": {"name": name}, "status": Status.REFUSED,
                                "reason": admission.evidence.status.value,
                                "catalog_admission": admission.to_document()})
                continue
            last_size = oracle.factory.block(last, num_inst=1).vex.size
            size = last - start + last_size
            admission = check_declared_pair(
                oracle, candidate, oracle_entry=start, oracle_end_byte=start + size - 1,
                candidate_entry=address, candidate_size=symbol.size,
            )
            if admission is not None:
                results.append({"function": {"name": name}, "status": Status.REFUSED,
                                "reason": admission.evidence.status.value,
                                "catalog_admission": admission.to_document()})
                continue
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


def _normalization_premise(
    normalization: dict[int, int], link_map: Pe32LinkMap | None
) -> object:
    """Serialize the exact relocation premise sealed into the proof contract.

    An empty map means literal addresses and no premise. A verified LINK map
    adds the bound map identity so the sealed obligation cannot be replayed
    against a different link without changing the contract digest.
    """
    if not normalization:
        return None
    premise = "conditional value relocation; not a pointer-alias or data-initialization proof"
    if link_map is None:
        return premise
    return {
        "premise": premise,
        "source": "candidate MSVC LINK map publics bound to the PE timestamp and image base",
        "map": link_map.provenance(),
        "relocation_count": len(normalization),
        "relocations": {hex(mapped): hex(original) for mapped, original in sorted(normalization.items())},
    }


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
    closure with explicit architecture state and native finishing. It does not
    install an inner driver patch context, regardless of the enclosing mode.
    Ordinary rows, statuses and dependencies are never touched; the retained
    outcome is a separate initialized-entry result, never member discharge.
    """
    from tools.dosunit.compare.pe32_recursive_compare import (
        prove_pe32_recursive_compare,
        recursive_request_from_args,
    )

    request = recursive_request_from_args(args)
    if request is None:
        return None
    oracle_functions, candidate_functions, unresolved = _component_functions(
        args, oracle, candidate, boundaries, symbols, names)
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
    from tools.comparator.msc8_cfg import compare_cfg

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
    from tools.comparator.msc8_region import compare_region

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
        from tools.dosunit.compare.flat32_proof_retry import (
            call_block_retry_cap,
            checked_environment_verdict,
            retry_function_proof,
        )

        verdict = retry_function_proof(name, verdict, loop_context, return_outputs, args.timeout_ms,
                                       entry_domain=entry_domain, io_model=io_model,
                                       call_block_retry_cap=call_block_retry_cap(args))
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
                "matched CFG fallback: eight blocks and 250 ms per block, then closed "
                "reblocked-CFG, call-loop and macro-step induction retries; "
                "still-unproved loops refuse"
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
    from tools.dosunit.reporting.flat32_proof_domain_cli import (
        require_supported_entry_domain,
        require_supported_io_domain,
    )

    entry_domain = require_supported_entry_domain(args)
    from tools.dosunit.compare.flat32_proof_retry import call_block_retry_cap

    call_block_retry_cap(args)
    io_model = require_supported_io_domain(args)
    # dynamic third-party argparse boundary: tests and external callers may omit the input
    candidate_link_map = getattr(args, "candidate_link_map", None)
    if candidate_link_map is not None:
        if not args.normalize_globals:
            raise ValueError("--candidate-link-map supplies a relocation premise and requires --normalize-globals")
        if args.mode != "leaf":
            raise ValueError("--candidate-link-map is supported only in leaf mode")
        from tools.dosunit.catalog.pe32_link_map import load_candidate_link_map

        link_map = load_candidate_link_map(candidate_link_map, args.candidate_exe)
    else:
        link_map = None
    oracle, candidate = load32(args.oracle_exe), load32(args.candidate_exe)
    from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity

    images = {"oracle": loaded_image_identity(oracle), "candidate": loaded_image_identity(candidate)}
    if args.mode in {"region", "auto"}:
        with args.oracle_exe.open("rb") as stream:
            if stream.read(2) != b"MZ":
                raise ValueError("region mode currently requires a PE32 oracle")
        with args.candidate_exe.open("rb") as stream:
            magic = stream.read(4)
            if magic[:2] != b"MZ" and magic != b"\x7fELF":
                raise ValueError("region mode requires a PE32 or ELF32 candidate")
    boundaries = lst_functions(args.oracle_lst)
    if args.candidate_lst:
        candidate_end_kind = ListingEndKind(args.candidate_lst_end_kind)
        symbols = {
            name: Symbol(start, listing_size(candidate, start, last, candidate_end_kind), "T")
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
    from tools.dosunit.compare.flat32_proof_retry import build_proof_context

    proof_context = build_proof_context(args.mode, oracle, candidate, lambda: select_functions(
        args, oracle, candidate, boundaries, symbols, sorted(boundaries.keys() | symbols.keys()),
    ))
    omod, cmod = "oracle", "candidate"
    ocat = catalog(omod, ofuncs, oracle.loader.main_object.linked_base)
    ccat = catalog(cmod, cfuncs, candidate.loader.main_object.linked_base)
    pairs = mapping(omod, cmod, list(ofuncs))
    output_regs = tuple(dict.fromkeys((*args.output_regs.split(","), *OUTPUT_REGS[2:])))
    if args.mode == "matched-cfg":
        from tools.comparator.msc8_cfg import compare_cfg

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
            from tools.dosunit.compare.flat32_proof_retry import checked_cfg_environment_verdict, retry_function_proof

            retried = retry_function_proof(name, result, proof_context, output_regs, args.timeout_ms,
                                           entry_domain=entry_domain, io_model=io_model,
                                           call_block_retry_cap=call_block_retry_cap(args))
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
                "calls": (
                    "call boundaries refuse the CFG compare, then retry through checked "
                    "bounded composition over declared ranges: direct targets and finite "
                    "selector-enumerated indirect targets, each with a proved return; "
                    "undeclared, unconstrained, recursive or over-budget targets refuse"
                ),
                "global_normalization": None,
            },
        }
        write_json(args.out_dir, "compare.json", report)
        report["loaded_images"] = images
        report["function_ranges"] = {"oracle": ofuncs, "candidate": cfuncs}
        report["recursive_joint"] = recursive_joint
        return report
    kwargs = {
        "output_regs": (*REG_NAMES, "ip")
        if args.mode in {"region", "auto"} and not args.output_regs
        else output_regs,
        "scan_limit": args.scan_limit,
        "max_blocks_per_function": 64 if args.mode in {"region", "auto"} else 1,
        "max_insns_per_function": 128 if args.mode in {"region", "auto"} else 1024,
        "max_assignments_per_function": 2048 if args.mode in {"region", "auto"} else 4096,
        "follow_call_fallthrough": args.mode in {"region", "auto"},
        "max_function_ms": args.timeout_ms,
        "architecture": flat32_register_architecture(),
        "function_lowering_policy": (FunctionLoweringPolicy.SCAN if args.mode in {"region", "auto"}
                                     else FunctionLoweringPolicy.FLAT32_LEAF),
        "successor_range_admission": declared_bounds_only,
    }
    ossa = S.lower_straightline_ssa_document(exe_path=args.oracle_exe, functions_catalog=ocat, lifter_project=oracle, **kwargs)
    cssa = S.lower_straightline_ssa_document(exe_path=args.candidate_exe, functions_catalog=ccat, lifter_project=candidate, **kwargs)
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
    if link_map is not None:
        oracle_data = lst_data_symbols(args.oracle_lst)
        for mapped, original in link_map_global_map(link_map, candidate, oracle, oracle_data).items():
            if normalization.get(mapped, original) != original:
                raise ValueError(f"conflicting data relocations at {mapped:#x}")
            normalization[mapped] = original
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
        comparison_policy=EXPLICIT_COMPARISON_POLICY,
    )
    expected = {name: f"{omod}:{name}" for name in ofuncs}
    results.extend(checked_results(expected, raw, relocation=normalization))
    from tools.comparator.msc8_scratch import retry_scratch_frame

    explicit_compare = partial(S.compare_ssa_documents, comparison_policy=EXPLICIT_COMPARISON_POLICY)

    # A LINK-map premise authorizes constant relocation only. Preserve every
    # declared register and memory observation instead of adding masking premises.
    failed = [item for item in results if item.get("status") == Status.FAILED] if link_map is None else []
    retried = retry_scratch_frame(
        failed, ossa, cssa, explicit_compare, args.timeout_ms)
    still = [item for item in failed if item["function"]["name"] not in retried]
    retried.update(retry_scratch_frame(
        still, ossa, cssa, explicit_compare, args.timeout_ms,
        drop_outputs=("edx",), premise="scratch_frame_and_edx_masked"))
    still = [item for item in still if item["function"]["name"] not in retried]
    masks = _return_width_masks(args, [i["function"]["name"] for i in still])
    if masks:
        retried.update(retry_scratch_frame(
            still, ossa, cssa, explicit_compare, args.timeout_ms,
            drop_outputs=("edx",), eax_masks=masks,
            premise="scratch_edx_and_eax_return_width_masked"))
    for item in results:
        verdict = retried.get(item["function"]["name"])
        if verdict is not None:
            item.update(verdict)
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
            "global_normalization": _normalization_premise(normalization, link_map),
        },
        "inputs": {
            side: {"path": str(path.resolve()), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for side, path in [("oracle", args.oracle_exe), ("candidate", args.candidate_exe)]
        },
        "lowering_refusals": {"oracle": ossa["refusals"], "candidate": cssa["refusals"]},
    }
    if link_map is not None:
        report["auxiliary_inputs"] = {"candidate_link_map": link_map.provenance()}
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
    from tools.dosunit.reporting.flat32_proof_report import run_bound_comparison

    return run_bound_comparison(_compare, args, Path(__file__))


def main() -> int:
    """Run an explicit selection or enumerate all mapped sub_* obligations."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle-exe", required=True, type=Path)
    parser.add_argument("--oracle-lst", required=True, type=Path)
    parser.add_argument("--candidate-exe", required=True, type=Path)
    parser.add_argument("--candidate-lst", type=Path, help="candidate IDA boundaries for a PE32/self-hosted rebuild")
    parser.add_argument(
        "--candidate-lst-end-kind", choices=list(ListingEndKind), default=ListingEndKind.INSTRUCTION,
        help="endp meaning: use last-byte for map2lst's next-symbol-minus-one scan bounds; "
             "reachable CFG closure remains mandatory",
    )
    parser.add_argument("--candidate-src", type=Path, default=None,
                        help="candidate generated C for return-width masks (default: derive from --candidate-lst)")
    parser.add_argument("--candidate-map", type=Path, default=None,
                        help="funcnames.map for sub_<VA> to semantic-name resolution")
    parser.add_argument(
        "--candidate-link-map", type=Path, default=None,
        help="MSVC LINK /MAP for a symbol-stripped PE32 candidate; its timestamp/base are "
             "verified against --candidate-exe and its publics supply data-alias relocation "
             "evidence (leaf mode only, requires --normalize-globals)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--functions")
    group.add_argument("--all-mapped", action="store_true")
    parser.add_argument("--mode", choices=["leaf", "matched-cfg", "region", "auto"], default="leaf")
    parser.add_argument("--retry-block-limit", type=int, choices=[128], default=None,
                        help="continue a call-lifting worklist only after its 64-block cap; "
                             "128 blocks maximum, same deadline and other budgets")
    parser.add_argument(
        "--normalize-globals", action="store_true", help="conditional value relocation; see proof_contract"
    )
    parser.add_argument(
        "--output-regs", default="eax,edx,esp", help="explicit return contract; preserved GPRs and eip always checked"
    )
    parser.add_argument("--scan-limit", type=lambda value: int(value, 0), default=0x2000)
    parser.add_argument("--timeout-ms", type=int, default=30000)
    from tools.dosunit.reporting.flat32_proof_domain_cli import (
        add_entry_esp_range_argument,
        add_ordered_io_argument,
        check_entry_domain_mode,
        check_ordered_io_mode,
    )
    from tools.dosunit.compare.pe32_recursive_compare import add_recursive_arguments, check_recursive_request

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
    if args.candidate_link_map is not None and not args.normalize_globals:
        parser.error("--candidate-link-map supplies a relocation premise and requires --normalize-globals")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    result = compare(args)
    print(json.dumps(result["summary"]))
    for item in result["results"]:
        print(f"{item['function']['name']}: {item['status']} ({item.get('reason')})")
    status: int = exit_code(result["summary"])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
