from __future__ import annotations  # noqa: D100

import json
from collections import Counter, defaultdict
from typing import Any


def render_failure_report(  # noqa: D103
    document: dict[str, Any],
    *,
    limit: int = 0,
    mismatch_limit: int = 8,
    show_unresolved_call_targets: bool = True,
    failed_only: bool = False,
    group_by_function: bool = False,
) -> str:
    schema = str(document.get("schema", "unknown"))
    if schema == "dosunit.region_compare.v1":
        return _render_region_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.results.v1":
        return _render_vector_results(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.data_compare.v1":
        return _render_data_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.complexity.v1":
        return _render_complexity(document, limit=limit, mismatch_limit=mismatch_limit)
    if schema == "dosunit.ssa_compare.v1":
        if group_by_function:
            return _render_ssa_compare_grouped(
                document,
                limit=limit,
                mismatch_limit=mismatch_limit,
                show_unresolved_call_targets=show_unresolved_call_targets,
                failed_only=failed_only,
            )
        return _render_ssa_compare(
            document,
            limit=limit,
            mismatch_limit=mismatch_limit,
            show_unresolved_call_targets=show_unresolved_call_targets,
            failed_only=failed_only,
        )
    if schema == "dosunit.ssa_batched_compare.v1":
        return _render_ssa_batched_compare(document, limit=limit)
    if schema == "dosunit.ssa_abi_compare.v1":
        return _render_ssa_abi_compare(document, limit=limit, mismatch_limit=mismatch_limit)
    if "refusals" in document:
        return _render_refusals(document, limit=limit)
    return _render_unknown(document)


def _limited(items: list[Any], limit: int) -> list[Any]:
    if limit <= 0:
        return list(items)
    return list(items[:limit])


def _render_region_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        "",
        "## Failed Or Refused Regions",
        "",
    ]
    failing = [
        result
        for result in document.get("results", []) or []
        if isinstance(result, dict) and result.get("status") != "passed"
    ]
    if not failing:
        lines.append("No failed or refused regions.")
        return "\n".join(lines) + "\n"
    shown_failing = _limited(failing, limit)
    for index, result in enumerate(shown_failing, start=1):
        function = result.get("function", {})
        name = function.get("name") if isinstance(function, dict) else None
        ordinal = result.get("region_ordinal")
        lines.append(f"### {index}. `{name}` region {ordinal} `{result.get('status')}`")
        oracle_entry = _format_address(result.get("oracle_entry"))
        candidate_entry = _format_address(result.get("candidate_entry"))
        if oracle_entry:
            lines.append(f"- Oracle region entry: `{oracle_entry}`")
        if candidate_entry:
            lines.append(f"- Candidate region entry: `{candidate_entry}`")
        if result.get("reason"):
            lines.append(f"- Reason: `{result.get('reason')}`")
        mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
        if not mismatches:
            lines.append("- No mismatch detail recorded.")
            lines.append("")
            continue
        for mismatch in mismatches[:mismatch_limit]:
            lines.extend(_format_region_mismatch(mismatch))
        if len(mismatches) > mismatch_limit:
            lines.append(f"- ... {len(mismatches) - mismatch_limit} more mismatches")
        lines.append("")
    if len(failing) > len(shown_failing):
        lines.append(f"... {len(failing) - len(shown_failing)} more failed/refused regions not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_region_mismatch(mismatch: dict[str, Any]) -> list[str]:
    kind = mismatch.get("kind", "unknown")
    lines = [f"- Mismatch: `{kind}`"]
    lines.extend(_region_mismatch_instruction_lines(mismatch))
    if kind == "region_missing":
        lines.append(f"  - Detail: {mismatch.get('detail')}")
        return lines
    if kind == "instruction_count_changed":
        lines.append(f"  - Oracle count: {mismatch.get('oracle')}")
        lines.append(f"  - Candidate count: {mismatch.get('candidate')}")
        return lines
    if "oracle" in mismatch:
        lines.append(f"  - Oracle: `{_compact_json(mismatch.get('oracle'))}`")
    if "candidate" in mismatch:
        lines.append(f"  - Candidate: `{_compact_json(mismatch.get('candidate'))}`")
    if kind in {"call_boundary", "call_target_mismatch", "direct_call"} and mismatch.get("call_compare"):
        lines.extend(_format_ssa_call_compare(mismatch.get("call_compare", {})))
    if kind == "loop_bound_incomplete" and mismatch.get("loop_summary"):
        lines.append(f"  - Loop summary: `{_compact_json(mismatch.get('loop_summary'))}`")
    return lines


def _region_mismatch_instruction_lines(mismatch: dict[str, Any]) -> list[str]:
    """Render the instruction fields shared by every region mismatch kind."""
    lines: list[str] = []
    if "instruction_index" in mismatch:
        lines.append(f"  - Instruction index: {mismatch.get('instruction_index')}")
    if mismatch.get("mnemonic"):
        lines.append(f"  - Mnemonic: `{mismatch.get('mnemonic')}`")
    oracle_instruction = mismatch.get("oracle_instruction")
    candidate_instruction = mismatch.get("candidate_instruction")
    if isinstance(oracle_instruction, dict):
        lines.append(f"  - Oracle instruction: `{_format_instruction(oracle_instruction)}`")
    if isinstance(candidate_instruction, dict):
        lines.append(f"  - Candidate instruction: `{_format_instruction(candidate_instruction)}`")
    return lines


def _render_vector_results(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Backend: `{document.get('backend')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Status counts: `{_compact_json(summary.get('status_counts', {}))}`",
        f"- Changed fields: `{_compact_json(summary.get('changed_fields', {}))}`",
        f"- Refusal reasons: `{_compact_json(summary.get('refusal_reasons', {}))}`",
        "",
        "## Failed Or Refused Vectors",
        "",
    ]
    failing = [
        result
        for result in document.get("results", []) or []
        if isinstance(result, dict) and result.get("status") != "passed"
    ]
    if not failing:
        lines.append("No failed or refused vectors.")
        return "\n".join(lines) + "\n"
    shown_failing = _limited(failing, limit)
    for index, result in enumerate(shown_failing, start=1):
        verdict = _dict_field(result, "verdict")
        lines.append(f"### {index}. `{result.get('function')}` `{result.get('status')}`")
        lines.append(f"- Vector: `{result.get('vector_id')}`")
        lines.append(f"- Verdict: `{verdict.get('kind')}`")
        changed_fields = list(verdict.get("changed_fields", []) or [])
        if changed_fields:
            lines.append(f"- Changed fields: `{', '.join(str(field) for field in changed_fields)}`")
            oracle = _dict_field(result, "oracle")
            candidate = _dict_field(result, "candidate")
            for field in changed_fields[:mismatch_limit]:
                lines.append(f"  - `{field}` oracle: `{_compact_json(oracle.get(field))}`")
                lines.append(f"  - `{field}` candidate: `{_compact_json(candidate.get(field))}`")
        diagnostics = [item for item in result.get("diagnostics", []) or [] if isinstance(item, dict)]
        for diagnostic in diagnostics[:mismatch_limit]:
            lines.append(f"- Diagnostic `{diagnostic.get('reason')}`: {diagnostic.get('message')}")
        lines.append("")
    if len(failing) > len(shown_failing):
        lines.append(f"... {len(failing) - len(shown_failing)} more failed/refused vectors not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _dict_field(mapping: dict[str, Any], key: str) -> dict[str, Any]:
    """Return the dict value stored under ``key``, or an empty dict."""
    value = mapping.get(key)
    return value if isinstance(value, dict) else {}


def _collect_ssa_compare_data(
    document: dict[str, Any], *, show_unresolved_call_targets: bool, failed_only: bool = False
) -> tuple[Any, ...]:
    summary = _dict_field(document, "summary")
    results = [result for result in document.get("results", []) or [] if isinstance(result, dict)]
    failing = [
        result
        for result in results
        if result.get("status") != "passed" and (not failed_only or result.get("status") == "failed")
    ]
    skipped_function_missing = [result for result in failing if _has_mismatch_kind(result, "function_missing")]
    unresolved_call_target_failures = [
        result
        for result in failing
        if not _has_mismatch_kind(result, "function_missing") and _has_unresolved_call_target(result)
    ]
    displayed_failing = [
        result
        for result in failing
        if not _has_mismatch_kind(result, "function_missing")
        and (show_unresolved_call_targets or not _has_unresolved_call_target(result))
    ]
    semantic_failures = [result for result in displayed_failing if result.get("status") == "failed"]
    mapping_gaps = [
        result for result in displayed_failing if result.get("reason") in {"mapping_missing", "candidate_ssa_missing"}
    ]
    other_refusals = [
        result for result in displayed_failing if result.get("status") == "refused" and result not in mapping_gaps
    ]
    status_reasons = Counter(f"{result.get('status')}:{result.get('reason')}" for result in displayed_failing)
    mismatch_kinds = Counter(
        str(mismatch.get("kind", "unknown"))
        for result in displayed_failing
        for mismatch in (result.get("mismatches", []) or [])
        if isinstance(mismatch, dict)
    )
    region_equality = _dict_field(document, "region_equality")
    region_results = [result for result in region_equality.get("results", []) or [] if isinstance(result, dict)]
    connectivity = _dict_field(document, "connectivity")
    external_parts = _dict_field(document, "external_parts")
    external_results = [result for result in external_parts.get("results", []) or [] if isinstance(result, dict)]
    failing_external_parts = [result for result in external_results if result.get("status") != "passed"]
    loop_scc = _dict_field(document, "loop_scc")
    call_scc = _dict_field(document, "call_scc")
    skipped_region_function_missing = [
        result
        for result in region_results
        if result.get("status") != "passed" and _has_mismatch_kind(result, "function_missing")
    ]
    failing_regions = [
        result
        for result in region_results
        if result.get("status") != "passed" and not _has_mismatch_kind(result, "function_missing")
    ]
    return (
        summary,
        failing,
        skipped_function_missing,
        skipped_region_function_missing,
        unresolved_call_target_failures,
        displayed_failing,
        semantic_failures,
        mapping_gaps,
        other_refusals,
        status_reasons,
        mismatch_kinds,
        region_equality,
        region_results,
        connectivity,
        external_parts,
        failing_external_parts,
        loop_scc,
        call_scc,
        failing_regions,
    )


def _render_data_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = document.get("summary", {})
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Status: `{document.get('status')}`",
        f"Oracle EXE: `{document.get('oracle_exe')}`",
        f"Candidate EXE: `{document.get('candidate_exe')}`",
        "",
        "## Summary",
        "",
        f"- Ranges: {summary.get('ranges', 0)}",
        f"- Literal mismatches: {summary.get('literal_mismatches', 0)}",
        f"- Normalization failures: {summary.get('normalization_failures', 0)}",
        f"- Normalized fields: {summary.get('normalized_fields', 0)}",
        "",
        "## Failed Data Ranges",
        "",
    ]
    failed_ranges = [
        item for item in document.get("ranges", []) or [] if isinstance(item, dict) and item.get("status") != "passed"
    ]
    if not failed_ranges:
        lines.append("No failed data ranges.")
    shown_failed_ranges = _limited(failed_ranges, limit)
    for index, item in enumerate(shown_failed_ranges, start=1):
        lines.append(f"### {index}. `{item.get('oracle_segment')}` -> `{item.get('candidate_segment')}`")
        lines.append(f"- Range: `{item.get('start')}..{item.get('end')}`")
        lines.append(f"- Mismatches: {item.get('mismatch_count')}")
        for mismatch in (item.get("mismatches", []) or [])[:mismatch_limit]:
            if isinstance(mismatch, dict):
                lines.append(
                    f"  - Offset `{mismatch.get('offset')}` oracle `{mismatch.get('oracle')}` candidate `{mismatch.get('candidate')}`"
                )
        lines.append("")
    failed_norms = [
        item
        for item in document.get("normalizations", []) or []
        if isinstance(item, dict) and item.get("status") != "passed"
    ]
    if failed_norms:
        lines.append("## Failed Normalizations")
        lines.append("")
        for item in _limited(failed_norms, limit):
            lines.append(
                f"- `{item.get('symbol')}` oracle `{item.get('oracle_value')}` expected `{item.get('oracle_expected')}`; candidate `{item.get('candidate_value')}` expected `{item.get('candidate_expected')}`"
            )
    return "\n".join(lines) + "\n"


def _render_complexity(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    counters = _dict_field(document, "counters")
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"EXE: `{document.get('exe')}`",
        "",
        "## Summary",
        "",
        f"- Functions seen: {counters.get('functions_seen', 0)}",
        f"- Functions analyzed: {counters.get('functions_analyzed', 0)}",
        f"- Simple whole functions: {counters.get('simple_whole_functions', 0)}",
        f"- Complex functions: {counters.get('complex_functions', 0)}",
        f"- Refused functions: {counters.get('refused_functions', 0)}",
        f"- Comparison parts: {counters.get('comparison_parts_emitted', 0)}",
        f"- Refusal reasons: `{_compact_json(counters.get('refusals_by_reason', {}))}`",
        "",
        "## Complex Functions",
        "",
    ]
    complex_functions = [
        item
        for item in document.get("functions", []) or []
        if isinstance(item, dict) and item.get("classification") != "simple_whole_function"
    ]
    if not complex_functions:
        lines.append("No complex functions.")
    shown_complex_functions = _limited(complex_functions, limit)
    for index, item in enumerate(shown_complex_functions, start=1):
        lines.extend(_format_complex_function(item, index=index, mismatch_limit=mismatch_limit))
    if len(complex_functions) > len(shown_complex_functions):
        lines.append(f"... {len(complex_functions) - len(shown_complex_functions)} more complex functions not shown.")
        lines.append("")

    refusals = [item for item in document.get("refusals", []) or [] if isinstance(item, dict)]
    if refusals:
        lines.append("## Refusals")
        lines.append("")
        shown_refusals = _limited(refusals, limit)
        for index, item in enumerate(shown_refusals, start=1):
            lines.extend(_format_refusal_entry(item, index=index))
        if len(refusals) > len(shown_refusals):
            lines.append(f"... {len(refusals) - len(shown_refusals)} more refusals not shown.")
            lines.append("")
    return "\n".join(lines) + "\n"


def _format_complex_function(item: dict[str, Any], *, index: int, mismatch_limit: int) -> list[str]:
    """Render one complex-function entry with risk and metrics detail."""
    function = _dict_field(item, "function")
    entry = _format_address(item.get("entry"))
    risk = _dict_field(item, "risk")
    lines = [f"### {index}. `{function.get('name', function.get('id', '<unknown>'))}`"]
    if entry:
        lines.append(f"- Entry: `{entry}`")
    lines.append(f"- Classification: `{item.get('classification')}`")
    lines.append(f"- Risk score: {risk.get('score', 0)}")
    blockers = [blocker for blocker in item.get("blockers", []) or [] if isinstance(blocker, dict)]
    if blockers:
        lines.append(
            f"- Blockers: `{', '.join(str(blocker.get('kind')) for blocker in blockers[:mismatch_limit])}`"
        )
    metrics = _dict_field(item, "metrics")
    metric_summary = {
        "insns": metrics.get("instruction_count"),
        "conditions": metrics.get("condition_count"),
        "calls": metrics.get("call_count"),
        "indirect": metrics.get("indirect_control_count"),
        "symbolic_memory": metrics.get("explicit_symbolic_memory_count"),
        "backward": metrics.get("backward_branch_count"),
    }
    lines.append(f"- Metrics: `{_compact_json(metric_summary)}`")
    risk_points = [point for point in item.get("risk_points", []) or [] if isinstance(point, dict)]
    for point in risk_points[:mismatch_limit]:
        address = _format_address(point.get("address"))
        location = f"{address}: " if address else ""
        lines.append(
            f"  - `{', '.join(str(kind) for kind in point.get('kinds', []))}` {location}{point.get('disassembly')}"
        )
    lines.append("")
    return lines


def _format_refusal_entry(item: dict[str, Any], *, index: int) -> list[str]:
    """Render one refusal entry's reason and optional detail."""
    detail = _dict_field(item, "detail")
    lines = [f"### {index}. `{item.get('reason')}`"]
    if detail.get("function_id"):
        lines.append(f"- Function: `{detail.get('function_id')}`")
    if detail.get("message"):
        lines.append(f"- Message: {detail.get('message')}")
    lines.append("")
    return lines


def _render_ssa_compare(
    document: dict[str, Any],
    *,
    limit: int,
    mismatch_limit: int,
    show_unresolved_call_targets: bool,
    failed_only: bool,
) -> str:
    (
        summary,
        _failing,
        skipped_function_missing,
        skipped_region_function_missing,
        unresolved_call_target_failures,
        displayed_failing,
        semantic_failures,
        mapping_gaps,
        other_refusals,
        status_reasons,
        mismatch_kinds,
        region_equality,
        region_results,
        connectivity,
        external_parts,
        failing_external_parts,
        loop_scc,
        call_scc,
        failing_regions,
    ) = _collect_ssa_compare_data(
        document,
        show_unresolved_call_targets=show_unresolved_call_targets,
        failed_only=failed_only,
    )
    candidate_only_parts: dict[str, Any] = (
        _dict_field(document, "candidate_only_parts")
    )
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        f"Mapping: `{document.get('mapping')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        f"- Unmapped oracle functions: {summary.get('skipped_unmapped', 0)}",
        f"- External/shared-tail oracle parts: total `{summary.get('external_oracle_parts_total', 0)}` checked `{summary.get('external_oracle_parts_checked', 0)}` passed `{summary.get('external_oracle_parts_passed', 0)}` unproved `{summary.get('skipped_external_oracle_parts', 0)}`",
        f"- Missing-function rows skipped: {len(skipped_function_missing)}",
        f"- Missing-function region rows skipped: {len(skipped_region_function_missing)}",
        f"- Unresolved-call-target rows skipped: {0 if show_unresolved_call_targets else len(unresolved_call_target_failures)}",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        f"- Region equality: `{region_equality.get('status', 'not_applicable')}` passed `{region_equality.get('passed', 0)}` failed `{region_equality.get('failed', 0)}` refused `{region_equality.get('refused', 0)}` covered `{region_equality.get('covered_results', 0)}` connectivity-covered `{region_equality.get('connectivity_covered_regions', 0)}` skipped-passed `{region_equality.get('skipped_passed_functions', 0)}`",
        f"- Connectivity: `{connectivity.get('status', 'not_applicable')}` edges `{connectivity.get('edges_checked', 0)}` state edges `{connectivity.get('state_edges_checked', 0)}` state inputs `{connectivity.get('state_inputs_checked', 0)}` external edges `{connectivity.get('external_successor_edges_skipped', 0)}` external-covered `{connectivity.get('external_successor_edges_covered', 0)}` external-unproved `{connectivity.get('external_successor_edges_unproved', 0)}` failures `{len(connectivity.get('failures', []) or [])}` refusals `{len(connectivity.get('refusals', []) or [])}`",
        f"- External shared-tail proofs: `{external_parts.get('status', 'not_applicable')}` total `{external_parts.get('total', 0)}` passed `{external_parts.get('passed', 0)}` failed `{external_parts.get('failed', 0)}` refused `{external_parts.get('refused', 0)}`",
        f"- Candidate-only SSA parts: `{candidate_only_parts.get('total', summary.get('candidate_only_parts', 0))}` of `{candidate_only_parts.get('candidate_parts_total', summary.get('candidate_parts_total', 0))}` candidate parts, alias-only `{candidate_only_parts.get('alias_total', summary.get('candidate_alias_only_parts', 0))}`, referenced `{candidate_only_parts.get('candidate_parts_referenced', summary.get('candidate_parts_referenced', 0))}`",
        f"- Loop SCCs: `{loop_scc.get('status', 'not_applicable')}` total `{loop_scc.get('total', 0)}` passed `{loop_scc.get('passed', 0)}` failed `{loop_scc.get('failed', 0)}` refused `{loop_scc.get('refused', 0)}`",
        f"- Call SCCs: `{call_scc.get('status', 'not_applicable')}` total `{call_scc.get('total', 0)}` passed `{call_scc.get('passed', 0)}` failed `{call_scc.get('failed', 0)}` refused `{call_scc.get('refused', 0)}`",
        "",
        "## Cause Summary",
        "",
        f"- Failed/refused by reason: `{_compact_json(dict(sorted(status_reasons.items())))}`",
        f"- Mismatch kinds: `{_compact_json(dict(sorted(mismatch_kinds.items())))}`",
        "",
        "## Failed Or Refused SSA Functions",
        "",
    ]
    if not displayed_failing:
        lines.append("No failed or refused SSA functions.")
        lines.append("")

    if displayed_failing:
        lines.extend(
            [
                "### Reading Notes",
                "",
                "- `observable_mismatch` means Z3 found a symbolic entry state where the bounded SSA outputs differ.",
                "- `memory_expr_changed` means modeled memory effects differ; inspect the shown stores/address expressions in the listed blocks.",
                "- `mapping_missing` means no rebuilt function was mapped for this oracle function; fix mapping/catalog before treating it as a decompiler bug.",
                "- `candidate_ssa_missing` means mapping exists, but the candidate function did not lower to SSA.",
                "- `region_equal` means a stronger composed acyclic function proof covered block-layout differences.",
                "- Missing-function mapping rows are omitted from detailed sections by default.",
                "- Unresolved direct-call-target rows are shown by default; pass `--hide-unresolved-call-targets` to skip them.",
                "",
            ]
        )

    if region_results:
        _append_region_equality_section(lines, failing_regions, limit, mismatch_limit)

    lines.append("## Semantic Mismatches")
    lines.append("")
    if not semantic_failures:
        lines.append("No semantic SSA mismatches.")
        lines.append("")
    shown_semantic_failures = _limited(semantic_failures, limit)
    _append_ssa_result_rows(
        lines, shown_semantic_failures, semantic_failures, "semantic mismatches",
        limit, mismatch_limit, show_candidate=True,
    )

    lines.append("## Mapping / Lowering Gaps")
    lines.append("")
    if not mapping_gaps:
        lines.append("No mapping or candidate-lowering gaps.")
        lines.append("")
    shown_mapping_gaps = _limited(mapping_gaps, limit)
    _append_ssa_result_rows(
        lines, shown_mapping_gaps, mapping_gaps, "mapping/lowering gaps",
        limit, mismatch_limit, show_candidate=False,
    )

    if other_refusals:
        lines.append("## Other Refusals")
        lines.append("")
        shown_other_refusals = _limited(other_refusals, limit)
        _append_ssa_result_rows(
            lines, shown_other_refusals, other_refusals, "other refusals",
            limit, mismatch_limit, show_candidate=True,
        )

    _append_connectivity_gap_section(lines, connectivity, limit)
    _append_external_parts_section(lines, failing_external_parts, limit, mismatch_limit)
    _append_candidate_only_sections(lines, candidate_only_parts, limit, with_description=True)
    displayed_count = len(shown_semantic_failures) + len(shown_mapping_gaps) + len(_limited(other_refusals, limit))
    if len(displayed_failing) > displayed_count:
        lines.append(f"Total hidden by per-section limits: {len(displayed_failing) - displayed_count}.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _append_region_equality_section(
    lines: list[str], failing_regions: list[dict[str, Any]], limit: int, mismatch_limit: int
) -> None:
    """Append the function region-equality proofs section."""
    lines.append("## Function Region Equality")
    lines.append("")
    if not failing_regions:
        lines.append("No failed or refused function-region proofs.")
        lines.append("")
        return
    shown_regions = _limited(failing_regions, limit)
    for index, result in enumerate(shown_regions, start=1):
        lines.extend(_format_ssa_region_result(result, index=index, mismatch_limit=mismatch_limit))
    if len(failing_regions) > len(shown_regions):
        lines.append(
            f"... {len(failing_regions) - len(shown_regions)} more failed/refused region proofs not shown."
        )
        lines.append("")


def _append_external_parts_section(
    lines: list[str], failing_external_parts: list[dict[str, Any]], limit: int, mismatch_limit: int
) -> None:
    """Append the external shared-tail proof-gap section."""
    if not failing_external_parts:
        return
    lines.append("## External Shared-Tail Proof Gaps")
    lines.append("")
    lines.append(
        "These are out-of-declared-body SSA parts reached by functions. They are matched and proved separately when a unique candidate block can be found."
    )
    lines.append("")
    for index, result in enumerate(_limited(failing_external_parts, limit), start=1):
        lines.extend(_format_ssa_result(result, index=index, mismatch_limit=mismatch_limit, show_candidate=True))
    if len(failing_external_parts) > limit:
        lines.append(f"... {len(failing_external_parts) - limit} more external shared-tail proof gaps not shown.")
        lines.append("")


def _append_ssa_result_rows(
    lines: list[str],
    shown: list[dict[str, Any]],
    total_items: list[dict[str, Any]],
    overflow_label: str,
    limit: int,
    mismatch_limit: int,
    *,
    show_candidate: bool,
) -> None:
    """Append one limited SSA result section plus its overflow note."""
    for index, result in enumerate(shown, start=1):
        lines.extend(
            _format_ssa_result(result, index=index, mismatch_limit=mismatch_limit, show_candidate=show_candidate)
        )
    if len(total_items) > len(shown):
        lines.append(f"... {len(total_items) - len(shown)} more {overflow_label} not shown.")
        lines.append("")


def _append_connectivity_gap_section(
    lines: list[str], connectivity: dict[str, Any], limit: int
) -> None:
    """Append the connectivity proof-gap section when gaps exist."""
    connectivity_gaps = [
        item
        for item in [
            *(connectivity.get("failures", []) or []),
            *(connectivity.get("refusals", []) or []),
        ]
        if isinstance(item, dict)
    ]
    if not connectivity_gaps:
        return
    lines.append("## Connectivity Proof Gaps")
    lines.append("")
    lines.append(
        "These are block-edge proof gaps, not semantic mismatches. They mean the predecessor block was proved locally, but the successor edge could not be paired or state-checked."
    )
    lines.append("")
    shown_connectivity_gaps = _limited(connectivity_gaps, limit)
    for index, gap in enumerate(shown_connectivity_gaps, start=1):
        lines.extend(_format_connectivity_gap(gap, index=index))
    if len(connectivity_gaps) > len(shown_connectivity_gaps):
        lines.append(f"... {len(connectivity_gaps) - len(shown_connectivity_gaps)} more connectivity proof gaps not shown.")
        lines.append("")


def _append_candidate_only_sections(
    lines: list[str],
    candidate_only_parts: dict[str, Any],
    limit: int,
    *,
    with_description: bool = False,
) -> None:
    """Append the candidate-only and alias-only SSA leftover sections."""
    if candidate_only_parts.get("enabled") and int(candidate_only_parts.get("total", 0) or 0) > 0:
        lines.append("## Candidate-Only SSA Parts")
        lines.append("")
        if with_description:
            lines.append(
                "These rebuilt SSA parts were not paired with any oracle body or external/shared-tail part. They are coverage leftovers, not semantic mismatches by themselves."
            )
            lines.append("")
        for index, part in enumerate(_limited(candidate_only_parts.get("parts", []) or [], limit), start=1):
            lines.extend(_format_candidate_only_part(part, index=index))
        total = int(candidate_only_parts.get("total", 0) or 0)
        if total > limit:
            lines.append(f"... {total - limit} more candidate-only SSA parts not shown.")
            lines.append("")
    if candidate_only_parts.get("enabled") and int(candidate_only_parts.get("alias_total", 0) or 0) > 0:
        lines.append("## Candidate Alias-Only SSA Parts")
        lines.append("")
        if with_description:
            lines.append(
                "These rebuilt SSA parts were not directly paired, but their entry/part/code signature aliases a candidate block that was paired and checked."
            )
            lines.append("")
        for index, part in enumerate(_limited(candidate_only_parts.get("alias_parts", []) or [], limit), start=1):
            lines.extend(_format_candidate_only_part(part, index=index))
        total = int(candidate_only_parts.get("alias_total", 0) or 0)
        if total > limit:
            lines.append(f"... {total - limit} more candidate alias-only SSA parts not shown.")
            lines.append("")


def _render_ssa_compare_grouped(
    document: dict[str, Any],
    *,
    limit: int,
    mismatch_limit: int,
    show_unresolved_call_targets: bool,
    failed_only: bool,
) -> str:
    (
        summary,
        _failing,
        skipped_function_missing,
        skipped_region_function_missing,
        unresolved_call_target_failures,
        displayed_failing,
        _semantic_failures,
        _mapping_gaps,
        _other_refusals,
        status_reasons,
        mismatch_kinds,
        region_equality,
        region_results,
        _connectivity,
        external_parts,
        _failing_external_parts,
        _loop_scc,
        _call_scc,
        _failing_regions,
    ) = _collect_ssa_compare_data(
        document,
        show_unresolved_call_targets=show_unresolved_call_targets,
        failed_only=failed_only,
    )

    by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in displayed_failing:
        function = _dict_field(result, "function")
        name = function.get("name") or function.get("id") or "<unknown>"
        by_function[name].append(result)

    if not by_function:
        return _render_ssa_compare(
            document,
            limit=limit,
            mismatch_limit=mismatch_limit,
            show_unresolved_call_targets=show_unresolved_call_targets,
            failed_only=failed_only,
        )

    region_only_results = [
        result
        for result in region_results
        if result.get("status") != "passed" and not _has_mismatch_kind(result, "function_missing")
    ]
    lines = [
        "# DOS Unit Failure Report",
        "",
        "## Function-Grouped SSA Results",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        f"Mapping: `{document.get('mapping')}`",
        "",
        "## Summary",
        "",
        f"- Total function entries: {len(by_function)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        f"- Unmapped oracle functions: {summary.get('skipped_unmapped', 0)}",
        f"- External/shared-tail oracle parts: total `{summary.get('external_oracle_parts_total', 0)}` checked `{summary.get('external_oracle_parts_checked', 0)}` passed `{summary.get('external_oracle_parts_passed', 0)}` unproved `{summary.get('skipped_external_oracle_parts', 0)}`",
        f"- Missing-function rows skipped: {len(skipped_function_missing)}",
        f"- Missing-function region rows skipped: {len(skipped_region_function_missing)}",
        f"- Unresolved-call-target rows skipped: {0 if show_unresolved_call_targets else len(unresolved_call_target_failures)}",
        f"- Region equality: `{region_equality.get('status', 'not_applicable')}` passed `{region_equality.get('passed', 0)}` failed `{region_equality.get('failed', 0)}` refused `{region_equality.get('refused', 0)}` covered `{region_equality.get('covered_results', 0)}` connectivity-covered `{region_equality.get('connectivity_covered_regions', 0)}` skipped-passed `{region_equality.get('skipped_passed_functions', 0)}`",
        f"- External shared-tail proofs: `{external_parts.get('status', 'not_applicable')}` total `{external_parts.get('total', 0)}` passed `{external_parts.get('passed', 0)}` failed `{external_parts.get('failed', 0)}` refused `{external_parts.get('refused', 0)}`",
        "",
        f"- Failed/refused by reason: `{_compact_json(dict(sorted(status_reasons.items())))}`",
        f"- Mismatch kinds: `{_compact_json(dict(sorted(mismatch_kinds.items())))}`",
        "",
    ]

    for index, (name, entries) in enumerate(sorted(by_function.items()), start=1):
        if limit > 0 and index > limit:
            break
        lines.extend(_format_grouped_function(name, entries, index=index, mismatch_limit=mismatch_limit))

    if len(by_function) > limit > 0:
        lines.append(f"... {len(by_function) - limit} more failed/refused functions not shown.")
        lines.append("")

    if region_only_results:
        lines.append("## Region Results")
        lines.append("")
        for index, result in enumerate(_limited(region_only_results, limit), start=1):
            lines.extend(_format_ssa_region_result(result, index=index, mismatch_limit=mismatch_limit))
        if len(region_only_results) > len(_limited(region_only_results, limit)):
            lines.append(
                f"... {len(region_only_results) - len(_limited(region_only_results, limit))} more region proofs not shown."
            )
            lines.append("")
    return "\n".join(lines) + "\n"


def _format_grouped_function(
    name: str, entries: list[dict[str, Any]], *, index: int, mismatch_limit: int
) -> list[str]:
    """Render one function's grouped SSA entries headed by the representative."""
    lines: list[str] = []
    representative = entries[0]
    function = _dict_field(representative, "function")
    function_id = function.get("id", name)
    status_counts = Counter(f"{entry.get('status')}:{entry.get('reason')}" for entry in entries)
    lines.append(f"### {index}. `{name}`")
    lines.append(f"- Function id: `{function_id}`")
    lines.append(f"- Entries for function: `{len(entries)}`")
    lines.append(f"- Statuses: `{_compact_json(dict(sorted(status_counts.items())))}`")
    lines.append(f"- Oracle SSA: `{representative.get('oracle_function', '<none>')}`")
    lines.append(f"- Candidate SSA: `{representative.get('candidate_function', '<none>')}`")
    oracle_detail = (
        representative.get("oracle_detail") if isinstance(representative.get("oracle_detail"), dict) else None
    )
    candidate_detail = (
        representative.get("candidate_detail") if isinstance(representative.get("candidate_detail"), dict) else None
    )
    if representative.get("mapped_candidate"):
        mapped_candidate = representative["mapped_candidate"]
        lines.append(
            f"- Mapped candidate: `{mapped_candidate.get('name') or mapped_candidate.get('id')} {_format_ssa_entry(mapped_candidate.get('entry'))}`"
        )
    if oracle_detail:
        lines.extend(_format_ssa_side("Oracle", oracle_detail))
    if candidate_detail:
        lines.extend(_format_ssa_side("Candidate", candidate_detail))
    call_compare = (
        representative.get("call_compare") if isinstance(representative.get("call_compare"), dict) else None
    )
    if call_compare:
        lines.extend(_format_ssa_call_compare(call_compare))
    lines.extend(_format_first_entry_mismatches(entries, mismatch_limit))
    if representative.get("layout_normalization", {}):
        lines.extend(_format_grouped_layout_normalization(representative["layout_normalization"]))
    lines.append("")
    return lines


def _format_first_entry_mismatches(entries: list[dict[str, Any]], mismatch_limit: int) -> list[str]:
    """Render the first mismatch recorded per grouped entry."""
    mismatches = []
    for entry in entries:
        for mismatch in entry.get("mismatches", []) or []:
            if not isinstance(mismatch, dict):
                continue
            mismatches.append(_format_ssa_mismatch(mismatch))
            break
    if not mismatches:
        return ["- No mismatch detail recorded."]
    lines = ["- Mismatches:"]
    for mismatch in mismatches[:mismatch_limit]:
        lines.extend(mismatch)
    return lines


def _format_grouped_layout_normalization(layout_normalization: dict[str, Any]) -> list[str]:
    """Render up to four layout-constant normalization pairs."""
    lines = ["- Layout constant normalization:"]
    pairs = [
        pair
        for pair in layout_normalization.get("pairs", []) or []
        if isinstance(pair, dict)
    ]
    for pair in pairs[:4]:
        lines.append(
            f"  - candidate `{pair.get('candidate')}` -> oracle `{pair.get('oracle')}` ({pair.get('reason', 'unknown')})"
        )
    if len(pairs) > 4:
        lines.append(f"  - ... {len(pairs) - 4} more")
    return lines


def _format_ssa_region_result(result: dict[str, Any], *, index: int, mismatch_limit: int) -> list[str]:
    function = _dict_field(result, "function")
    name = function.get("name", function.get("id", "<unknown>"))
    lines = [f"### {index}. `{name}` region `{result.get('status')}`"]
    if function.get("id"):
        lines.append(f"- Function id: `{function.get('id')}`")
    if result.get("reason"):
        lines.append(f"- Reason: `{result.get('reason')}`")
    observables = _dict_field(result, "observables")
    if observables:
        regs = ", ".join(f"`{item}`" for item in observables.get("regs", []) or [])
        memory = "whole memory" if observables.get("whole_memory") else "declared memory only"
        lines.append(f"- Region observables: regs {regs or '`<none>`'}, {memory}")
    for label, key in (("Oracle", "oracle_region_detail"), ("Candidate", "candidate_region_detail")):
        detail = result.get(key) if isinstance(result.get(key), dict) else None
        if detail:
            lines.extend(_format_region_detail_side(label, detail))
    for label, key in (("Oracle summary", "oracle_summary"), ("Candidate summary", "candidate_summary")):
        summary = result.get(key) if isinstance(result.get(key), dict) else None
        if summary:
            lines.extend(_format_summary_side(summary, label, include_refusal=True))
    lines.extend(_format_result_mismatches(result, mismatch_limit))
    lines.append("")
    return lines


def _format_region_detail_side(label: str, detail: dict[str, Any]) -> list[str]:
    """Render one side's region entry and first instructions."""
    lines = [f"- {label} region entry: `{_format_ssa_entry(detail.get('entry'))}`"]
    if detail.get("part_count") is not None:
        lines.append(f"  - Parts: `{detail.get('part_count')}`")
    instructions = [item for item in detail.get("instructions", []) or [] if isinstance(item, dict)]
    if instructions:
        lines.append(f"  - {label} region first instructions:")
        if detail.get("instructions_truncated"):
            total = len(instructions) + int(detail.get("instructions_truncated") or 0)
            lines.append(f"    - Instruction preview: first `{len(instructions)}` of `{total}`")
        for instruction in instructions:
            lines.append(f"    - `{_format_instruction(instruction)}`")
    return lines


def _format_summary_side(
    summary: dict[str, Any], label: str, *, include_unroll: bool = False, include_refusal: bool = False
) -> list[str]:
    """Render one side's composed-region summary counters."""
    unroll = f", unroll `{summary.get('loop_unroll_bound')}`" if include_unroll else ""
    lines = [
        f"- {label}: status `{summary.get('status')}`, parts `{summary.get('part_count')}`, terminals `{summary.get('terminal_count')}`, blocks `{summary.get('blocks_composed')}`, branches `{summary.get('branch_merges')}`, branch prunes `{summary.get('branch_prunes')}`, loop cuts `{summary.get('loop_cuts')}`{unroll}, inputs `{summary.get('input_count')}`, assignments `{summary.get('assignment_count')}`"
    ]
    if summary.get("outputs"):
        lines.append(f"  - Outputs: `{', '.join(str(item) for item in summary.get('outputs', []) or [])}`")
    if include_refusal and summary.get("reason"):
        lines.append(f"  - Refusal: `{summary.get('reason')}`")
    return lines


def _format_result_mismatches(result: dict[str, Any], mismatch_limit: int) -> list[str]:
    """Render the shared mismatches block used by SSA result formats."""
    mismatches = [item for item in result.get("mismatches", []) or [] if isinstance(item, dict)]
    if not mismatches:
        return ["- No mismatch detail recorded."]
    lines = ["- Mismatches:"]
    for mismatch in mismatches[:mismatch_limit]:
        lines.extend(_format_ssa_mismatch(mismatch))
    if len(mismatches) > mismatch_limit:
        lines.append(f"  - ... {len(mismatches) - mismatch_limit} more mismatches")
    return lines


def _has_mismatch_kind(result: dict[str, Any], kind: str) -> bool:
    return any(
        isinstance(mismatch, dict) and mismatch.get("kind") == kind for mismatch in (result.get("mismatches", []) or [])
    )


def _render_ssa_abi_compare(document: dict[str, Any], *, limit: int, mismatch_limit: int) -> str:
    summary = _dict_field(document, "summary")
    results = [result for result in document.get("results", []) or [] if isinstance(result, dict)]
    failing = [result for result in results if result.get("status") != "passed"]
    status_reasons = Counter(f"{result.get('status')}:{result.get('reason')}" for result in failing)
    mismatch_kinds = Counter(
        str(mismatch.get("kind", "unknown"))
        for result in failing
        for mismatch in (result.get("mismatches", []) or [])
        if isinstance(mismatch, dict)
    )
    lines = [
        "# DOS Unit ABI SSA Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle: `{document.get('oracle')}`",
        f"Candidate: `{document.get('candidate')}`",
        f"Mapping: `{document.get('mapping')}`",
        f"Data segment: `{document.get('data_segment_para')}`",
        "",
        "## Summary",
        "",
        f"- Total: {summary.get('total', 0)}",
        f"- Passed: {summary.get('passed', 0)}",
        f"- Failed: {summary.get('failed', 0)}",
        f"- Refused: {summary.get('refused', 0)}",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        "",
        "## Cause Summary",
        "",
        f"- Failed/refused by reason: `{_compact_json(dict(sorted(status_reasons.items())))}`",
        f"- Mismatch kinds: `{_compact_json(dict(sorted(mismatch_kinds.items())))}`",
        "",
        "## Failed Or Refused ABI Functions",
        "",
    ]
    if not failing:
        lines.append("No failed or refused ABI functions.")
        return "\n".join(lines) + "\n"
    lines.extend(
        [
            "### Reading Notes",
            "",
            "- `call_boundary` means the bounded function summary reached a call; static proof needs a callee summary/inlining policy.",
            "- Memory observables are declared ABI/data effects, not whole-memory equality, so temporary stack pushes are ignored.",
            "- `observable_mismatch` means Z3 found a symbolic entry state where a declared ABI register or memory effect differs.",
            "",
        ]
    )
    shown = _limited(failing, limit)
    for index, result in enumerate(shown, start=1):
        lines.extend(_format_ssa_abi_result(result, index=index, mismatch_limit=mismatch_limit))
    if len(failing) > len(shown):
        lines.append(f"... {len(failing) - len(shown)} more failed/refused ABI functions not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _format_ssa_abi_result(result: dict[str, Any], *, index: int, mismatch_limit: int) -> list[str]:
    function = _dict_field(result, "function")
    name = function.get("name", "<unknown>")
    lines = [f"### {index}. `{name}` `{result.get('status')}`"]
    lines.extend(_format_abi_function_meta(function))
    if result.get("reason"):
        lines.append(f"- Reason: `{result.get('reason')}`")
    lines.extend(_format_abi_observables(result))
    constraints = [item for item in result.get("input_constraints", []) or [] if isinstance(item, dict)]
    if constraints:
        lines.append("- Input constraints: `" + _compact_json(constraints) + "`")
    for label, key in (("Oracle summary", "oracle_summary"), ("Candidate summary", "candidate_summary")):
        summary = result.get(key) if isinstance(result.get(key), dict) else None
        if summary:
            lines.extend(_format_summary_side(summary, label, include_unroll=True))
    lines.extend(_format_result_mismatches(result, mismatch_limit))
    lines.append("")
    return lines


def _format_abi_function_meta(function: dict[str, Any]) -> list[str]:
    """Render ABI kind, convention, inputs, stack args, returns, and reg sets."""
    lines: list[str] = []
    if function.get("kind"):
        lines.append(f"- Kind: `{function.get('kind')}`")
    if function.get("calling_convention"):
        lines.append(f"- Calling convention: `{function.get('calling_convention')}`")
    if function.get("inputs"):
        lines.append(
            "- Register inputs: "
            + ", ".join(
                f"`{item.get('location')}:{item.get('name')}`"
                for item in function.get("inputs", [])
                if isinstance(item, dict)
            )
        )
    if function.get("stack_args"):
        lines.append(
            "- Stack args: "
            + ", ".join(
                f"`[bp+{item.get('bp_offset')}]:{item.get('name')}`"
                for item in function.get("stack_args", [])
                if isinstance(item, dict)
            )
        )
    if function.get("returns"):
        lines.append(
            "- Returns: "
            + ", ".join(f"`{item.get('location')}`" for item in function.get("returns", []) if isinstance(item, dict))
        )
    if function.get("preserved"):
        lines.append("- Preserved: " + ", ".join(f"`{item}`" for item in function.get("preserved", []) or []))
    if function.get("clobbers"):
        lines.append("- Clobbers: " + ", ".join(f"`{item}`" for item in function.get("clobbers", []) or []))
    return lines


def _format_abi_observables(result: dict[str, Any]) -> list[str]:
    """Render the compared register and memory-effect observables."""
    observables = _dict_field(result, "observables")
    if not observables:
        return []
    lines = ["- Compared regs: " + ", ".join(f"`{item}`" for item in observables.get("regs", []) or [])]
    effects = [item for item in observables.get("memory", []) or [] if isinstance(item, dict)]
    if effects:
        lines.append(
            "- Compared memory effects: "
            + ", ".join(
                f"`{item.get('space', 'SEG')}:{item.get('offset')} {item.get('name', '')}`".strip()
                for item in effects
            )
        )
    return lines


def _has_unresolved_call_target(result: dict[str, Any]) -> bool:
    call_compare = result.get("call_compare") if isinstance(result.get("call_compare"), dict) else None
    if not call_compare:
        return False
    for side in ("oracle", "candidate"):
        call = call_compare.get(side) if isinstance(call_compare.get(side), dict) else None
        if call and call.get("resolved") is None:
            return True
    return False


def _format_ssa_result(result: dict[str, Any], *, index: int, mismatch_limit: int, show_candidate: bool) -> list[str]:
    function = _dict_field(result, "function")
    name = function.get("name", function.get("id", "<unknown>"))
    lines = [f"### {index}. `{name}` `{result.get('status')}`"]
    lines.extend(_format_ssa_result_header(function, result))

    oracle_detail = result.get("oracle_detail") if isinstance(result.get("oracle_detail"), dict) else None
    candidate_detail = result.get("candidate_detail") if isinstance(result.get("candidate_detail"), dict) else None
    lines.extend(_format_ssa_side("Oracle", oracle_detail))
    if show_candidate:
        lines.extend(_format_ssa_side("Candidate", candidate_detail))
    lines.extend(_format_ssa_result_call_detail(oracle_detail, candidate_detail, result))

    lines.extend(_format_result_mismatches(result, mismatch_limit))
    lines.append("")
    return lines


def _format_ssa_result_header(function: dict[str, Any], result: dict[str, Any]) -> list[str]:
    """Render identity, reason, SSA ids, and mapped-candidate fields."""
    lines: list[str] = []
    if function.get("id"):
        lines.append(f"- Function id: `{function.get('id')}`")
    if result.get("reason"):
        lines.append(f"- Reason: `{result.get('reason')}`")
    if result.get("oracle_function"):
        lines.append(f"- Oracle SSA id: `{result.get('oracle_function')}`")
    if result.get("candidate_function"):
        lines.append(f"- Candidate SSA id: `{result.get('candidate_function')}`")
    mapped_candidate = result.get("mapped_candidate") if isinstance(result.get("mapped_candidate"), dict) else None
    if mapped_candidate:
        lines.append(
            f"- Mapped candidate: `{mapped_candidate.get('name') or mapped_candidate.get('id')}` `{_format_ssa_entry(mapped_candidate.get('entry'))}`"
        )
    return lines


def _format_ssa_result_call_detail(
    oracle_detail: dict[str, Any] | None,
    candidate_detail: dict[str, Any] | None,
    result: dict[str, Any],
) -> list[str]:
    """Render the call-boundary note, call compare, and layout normalization."""
    lines: list[str] = []
    if _ssa_jumpkind(oracle_detail) == "Ijk_Call" or _ssa_jumpkind(candidate_detail) == "Ijk_Call":
        lines.append(
            "- Call-boundary note: this bounded SSA block stops at a call; memory differences may reflect pushed arguments/return state or an unmapped call-target summary."
        )
    call_compare = result.get("call_compare") if isinstance(result.get("call_compare"), dict) else None
    if call_compare:
        lines.extend(_format_ssa_call_compare(call_compare))
    layout_normalization = (
        result.get("layout_normalization") if isinstance(result.get("layout_normalization"), dict) else None
    )
    if layout_normalization:
        lines.extend(_format_layout_normalization(layout_normalization))
    return lines


def _format_layout_normalization(layout_normalization: dict[str, Any]) -> list[str]:
    pairs = [item for item in layout_normalization.get("pairs", []) or [] if isinstance(item, dict)]
    if not pairs:
        return []
    lines = ["- Layout constant normalization:"]
    for pair in pairs[:8]:
        lines.append(
            f"  - candidate `{pair.get('candidate')}` -> oracle `{pair.get('oracle')}` ({pair.get('reason', 'unknown')})"
        )
    if len(pairs) > 8:
        lines.append(f"  - ... {len(pairs) - 8} more layout constants")
    return lines


def _format_ssa_side(label: str, detail: dict[str, Any] | None) -> list[str]:
    if not isinstance(detail, dict):
        return [f"- {label}: no SSA detail recorded"]
    outputs = ", ".join(str(item) for item in detail.get("outputs", []) or [])
    lines = [
        f"- {label} entry: `{_format_ssa_entry(detail.get('entry'))}`",
        f"- {label} block: `{detail.get('instruction_count', 0)} insns`, jumpkind `{detail.get('jumpkind')}`, inputs `{detail.get('input_count', 0)}`, assignments `{detail.get('assignment_count', 0)}`, outputs `{outputs}`",
    ]
    part = detail.get("part") if isinstance(detail.get("part"), dict) else None
    if part:
        lines.append(
            f"- {label} SSA part: `{part.get('kind', 'block')}` #{part.get('index', 0)} delta `{part.get('entry_delta', '0x0000')}`"
        )
    if detail.get("function_machine_code_sha256"):
        lines.append(
            f"- {label} function bytes: size `{detail.get('function_machine_code_size')}`, sha256 `{str(detail.get('function_machine_code_sha256'))[:16]}...`"
        )
    if detail.get("machine_code_sha256"):
        lines.append(
            f"- {label} block bytes: size `{detail.get('machine_code_size')}`, sha256 `{str(detail.get('machine_code_sha256'))[:16]}...`"
        )
    instructions = [item for item in detail.get("instructions", []) or [] if isinstance(item, dict)]
    if instructions:
        lines.append(f"- {label} instructions:")
        for instruction in instructions:
            lines.append(f"  - `{_format_instruction(instruction)}`")
        truncated = int(detail.get("instructions_truncated", 0) or 0)
        if truncated:
            lines.append(
                f"  - WARNING: report input already truncated {truncated} lifted instructions before rendering"
            )
    return lines


def _format_ssa_call_compare(call_compare: dict[str, Any]) -> list[str]:
    equivalent = "yes" if call_compare.get("equivalent") else "no"
    lines = [
        f"- Direct call target equivalent: `{equivalent}`",
        f"  - Reason: {call_compare.get('reason')}",
    ]
    proof_fact = call_compare.get("proof_fact") if isinstance(call_compare.get("proof_fact"), dict) else None
    if proof_fact:
        pf_oracle = _dict_field(proof_fact, "oracle")
        pf_candidate = _dict_field(proof_fact, "candidate")
        lines.append(
            "  - Callee proof: "
            f"`{proof_fact.get('proof')}` "
            f"oracle `{pf_oracle.get('name') or pf_oracle.get('id')}` -> candidate `{pf_candidate.get('name') or pf_candidate.get('id')}`"
        )
    semantic_target = (
        call_compare.get("semantic_target") if isinstance(call_compare.get("semantic_target"), dict) else None
    )
    if semantic_target:
        lines.append(
            f"  - Semantic call target: `{semantic_target.get('value')}` from `{semantic_target.get('source')}`"
        )
    oracle = call_compare.get("oracle") if isinstance(call_compare.get("oracle"), dict) else None
    candidate = call_compare.get("candidate") if isinstance(call_compare.get("candidate"), dict) else None
    lines.extend(_format_ssa_call_side("Oracle call", oracle))
    lines.extend(_format_ssa_call_side("Candidate call", candidate))
    normalizations = [item for item in call_compare.get("normalizations", []) or [] if isinstance(item, dict)]
    if normalizations:
        lines.append("  - Z3 call normalizations:")
        for item in normalizations:
            applied = "yes" if item.get("applied") else "no"
            detail = f"{item.get('side')}: applied={applied}; {item.get('reason')}"
            if item.get("stored") or item.get("fallthrough"):
                detail += f"; stored={item.get('stored')}; fallthrough={item.get('fallthrough')}"
            lines.append(f"    - {detail}")
    return lines


def _format_ssa_call_side(label: str, call: dict[str, Any] | None) -> list[str]:
    if not isinstance(call, dict):
        return [f"  - {label}: no direct call"]
    resolved = call.get("resolved") if isinstance(call.get("resolved"), dict) else None
    target = call.get("raw", "<unknown>")
    low16 = call.get("low16", "<unknown>")
    if resolved:
        entry = _format_ssa_entry(resolved.get("entry"))
        lines = [
            f"  - {label}: target `{target}` low16 `{low16}` -> `{resolved.get('name') or resolved.get('id')}` `{entry}`"
        ]
        instructions = [item for item in resolved.get("instructions", []) or [] if isinstance(item, dict)]
        if instructions:
            lines.append("    - Target first instructions:")
            for instruction in instructions:
                lines.append(f"      - `{_format_instruction(instruction)}`")
        return lines
    reason = call.get("reason", "unresolved")
    return [f"  - {label}: target `{target}` low16 `{low16}` -> unresolved ({reason})"]


def _format_connectivity_gap(gap: dict[str, Any], *, index: int) -> list[str]:
    function = gap.get("function") or "<unknown>"
    reason = gap.get("reason") or gap.get("kind") or "connectivity_gap"
    lines = [f"### {index}. `{function}` connectivity `{reason}`"]
    for key, label in (
        ("from_delta", "From delta"),
        ("successor_delta", "Successor delta"),
        ("oracle_from_delta", "Oracle from delta"),
        ("oracle_successor_delta", "Oracle successor delta"),
        ("candidate_from_delta", "Candidate from delta"),
        ("expected_candidate_successor_delta", "Expected candidate successor delta"),
        ("candidate_successor_delta", "Candidate successor delta"),
        ("mapped_oracle_successor_delta", "Mapped oracle successor delta"),
    ):
        if gap.get(key) is not None:
            lines.append(f"- {label}: `{gap.get(key)}`")
    if gap.get("detail"):
        lines.append(f"- Detail: {gap.get('detail')}")
    if gap.get("result_index") is not None:
        lines.append(f"- Result index: `{gap.get('result_index')}`")
    if gap.get("oracle_successor_deltas"):
        lines.append(
            f"- Oracle successor deltas: `{', '.join(str(item) for item in gap.get('oracle_successor_deltas') or [])}`"
        )
    if gap.get("candidate_successor_deltas"):
        lines.append(
            f"- Candidate successor deltas: `{', '.join(str(item) for item in gap.get('candidate_successor_deltas') or [])}`"
        )
    lines.append("")
    return lines


def _format_ssa_mismatch(mismatch: dict[str, Any]) -> list[str]:
    lines = [f"  - Kind: `{mismatch.get('kind')}`"]
    if mismatch.get("reg"):
        lines.append(f"    - Register: `{mismatch.get('reg')}`")
    if "oracle_value" in mismatch:
        lines.append(f"    - Oracle value: `{mismatch.get('oracle_value')}`")
    if "candidate_value" in mismatch:
        lines.append(f"    - Candidate value: `{mismatch.get('candidate_value')}`")
    if "counterexample" in mismatch:
        lines.append(f"    - Counterexample: `{_compact_json(mismatch.get('counterexample'))}`")
    if mismatch.get("kind") in {
        "connectivity_successor_mismatch",
        "branch_predicate_unobserved",
        "connectivity_state_unobserved",
        "connectivity_state_mismatch",
        "connectivity_state_refused",
    }:
        lines.extend(_format_connectivity_mismatch_detail(mismatch))
    if mismatch.get("kind") == "output_set_changed":
        lines.append(
            f"    - Oracle-only outputs: `{', '.join(str(item) for item in mismatch.get('oracle_only', []) or [])}`"
        )
        lines.append(
            f"    - Candidate-only outputs: `{', '.join(str(item) for item in mismatch.get('candidate_only', []) or [])}`"
        )
    if mismatch.get("kind") == "region_incomplete":
        lines.extend(_format_region_incomplete_detail(mismatch))
    lines.extend(_format_mismatch_detail_notes(mismatch))
    return lines


def _format_mismatch_detail_notes(mismatch: dict[str, Any]) -> list[str]:
    """Render the free-form detail and per-kind investigation notes."""
    lines: list[str] = []
    if "detail" in mismatch:
        lines.append(f"    - Detail: {mismatch.get('detail')}")
    if mismatch.get("kind") == "memory_expr_changed":
        lines.append(
            "    - Investigation: compare modeled stores/pushes and address expressions in the shown blocks; for call blocks, verify the callee mapping/summary."
        )
    if mismatch.get("kind") == "output_expr_changed":
        lines.append(
            "    - Investigation: compare the producer of the listed register in the shown blocks; `ip` differences are often control-flow or layout mapping issues."
        )
    return lines


_CONNECTIVITY_DELTA_FIELDS: tuple[tuple[str, str], ...] = (
    ("oracle_from_delta", "Oracle from delta"),
    ("oracle_successor_delta", "Oracle successor delta"),
    ("candidate_from_delta", "Candidate from delta"),
    ("expected_candidate_successor_delta", "Expected candidate successor delta"),
    ("candidate_successor_delta", "Candidate successor delta"),
    ("mapped_oracle_successor_delta", "Mapped oracle successor delta"),
)

_CONNECTIVITY_INPUT_FIELDS: tuple[tuple[str, str], ...] = (
    ("oracle_missing_inputs", "Oracle missing successor inputs"),
    ("candidate_missing_inputs", "Candidate missing successor inputs"),
    ("oracle_ignored_inputs", "Oracle ignored successor inputs"),
    ("candidate_ignored_inputs", "Candidate ignored successor inputs"),
    ("checked_inputs", "Checked successor inputs"),
)


def _format_connectivity_mismatch_detail(mismatch: dict[str, Any]) -> list[str]:
    """Render deltas, successor-input buckets, and nested edge mismatches."""
    lines: list[str] = []
    for key, label in _CONNECTIVITY_DELTA_FIELDS:
        if mismatch.get(key):
            lines.append(f"    - {label}: `{mismatch.get(key)}`")
    for key, label in (
        ("candidate_successor_deltas", "Candidate successor deltas"),
        ("oracle_successor_deltas", "Oracle successor deltas"),
        *_CONNECTIVITY_INPUT_FIELDS,
    ):
        if mismatch.get(key):
            lines.append(
                f"    - {label}: `{', '.join(str(item) for item in mismatch.get(key) or [])}`"
            )
    edge_mismatches = [item for item in mismatch.get("edge_mismatches", []) or [] if isinstance(item, dict)]
    if edge_mismatches:
        lines.append("    - Edge-state mismatches:")
        for edge_mismatch in edge_mismatches[:3]:
            lines.extend(f"      {line}" for line in _format_ssa_mismatch(edge_mismatch))
    return lines


def _format_missing_successor_item(item: dict[str, Any]) -> list[str]:
    """Render one missing-successor entry with instruction and refusal detail."""
    line = f"      - from `{item.get('from_delta')}` to missing `{item.get('missing_successor_delta')}`"
    instruction = item.get("last_instruction") if isinstance(item.get("last_instruction"), dict) else None
    if instruction and instruction.get("disassembly"):
        line += f" after `{_format_instruction(instruction)}`"
    lines = [line]
    lowering_refusal = item.get("lowering_refusal") if isinstance(item.get("lowering_refusal"), dict) else None
    if lowering_refusal:
        lines.append(
            f"        - Lowering refusal: `{lowering_refusal.get('reason')}` {lowering_refusal.get('message')}"
        )
        metrics = lowering_refusal.get("metrics") if isinstance(lowering_refusal.get("metrics"), dict) else None
        if metrics:
            lines.append(f"        - Metrics: `{_compact_json(metrics)}`")
    return lines


def _format_region_incomplete_detail(mismatch: dict[str, Any]) -> list[str]:
    """Render missing-successor lists for an incomplete-region mismatch."""
    lines = [
        "    - Meaning: SSA lowering stopped before all direct branch successors were present; this is an incomplete artifact, not a proven semantic mismatch."
    ]
    for key, label in (
        ("oracle_missing_successors", "Oracle missing successors"),
        ("candidate_missing_successors", "Candidate missing successors"),
    ):
        items = [item for item in mismatch.get(key, []) or [] if isinstance(item, dict)]
        if not items:
            continue
        lines.append(f"    - {label}:")
        for item in items[:8]:
            lines.extend(_format_missing_successor_item(item))
        if len(items) > 8:
            lines.append(f"      - ... {len(items) - 8} more")
    return lines


def _format_ssa_entry(entry: Any) -> str:  # noqa: ANN401
    if not isinstance(entry, dict):
        return "<unknown>"
    cs = entry.get("cs")
    ip = entry.get("ip")
    linear = entry.get("linear")
    parts = []
    if cs or ip:
        parts.append(f"{cs or '????'}:{ip or '????'}")
    if linear:
        parts.append(str(linear))
    return " / ".join(parts) if parts else "<unknown>"


def _ssa_jumpkind(detail: dict[str, Any] | None) -> str | None:
    if not isinstance(detail, dict):
        return None
    jumpkind = detail.get("jumpkind")
    return str(jumpkind) if jumpkind is not None else None


def _render_refusals(document: dict[str, Any], *, limit: int) -> str:
    counters = _dict_field(document, "counters")
    lines = [
        "# DOS Unit Failure Report",
        "",
        f"Schema: `{document.get('schema', 'unknown')}`",
        "",
        "## Summary",
        "",
        f"- Functions seen: {counters.get('functions_seen', 0)}",
        f"- Functions lowered: {counters.get('functions_lowered', 0)}",
        f"- Functions refused: {counters.get('functions_refused', 0)}",
        f"- SSA parts lowered: {counters.get('ssa_parts_lowered', 0)}",
        f"- SSA parts refused: {counters.get('ssa_parts_refused', 0)}",
        f"- Refusal reasons: `{_compact_json(counters.get('refusals_by_reason', {}))}`",
        "",
        "## Refusals",
        "",
    ]
    refusals = [item for item in document.get("refusals", []) or [] if isinstance(item, dict)]
    if not refusals:
        lines.append("No refusals.")
        return "\n".join(lines) + "\n"
    shown_refusals = _limited(refusals, limit)
    for index, item in enumerate(shown_refusals, start=1):
        detail = _dict_field(item, "detail")
        lines.append(f"### {index}. `{item.get('reason')}`")
        if detail.get("function_id"):
            lines.append(f"- Function: `{detail.get('function_id')}`")
        if detail.get("message"):
            lines.append(f"- Message: {detail.get('message')}")
        lines.append("")
    if len(refusals) > len(shown_refusals):
        lines.append(f"... {len(refusals) - len(shown_refusals)} more refusals not shown.")
        lines.append("")
    return "\n".join(lines) + "\n"


def _render_ssa_batched_compare(document: dict[str, Any], *, limit: int) -> str:
    summary = _dict_field(document, "summary")
    region_equality: dict[str, Any] = (
        _dict_field(document, "region_equality")
    )
    connectivity: dict[str, Any] = (
        _dict_field(document, "connectivity")
    )
    loop_scc: dict[str, Any] = _dict_field(document, "loop_scc")
    call_scc: dict[str, Any] = _dict_field(document, "call_scc")
    batches = [item for item in document.get("batches", []) or [] if isinstance(item, dict)]
    bad_batches = [
        item
        for item in batches
        if int(item.get("returncode", 0) or 0) != 0
        or int(item.get("main_failed", 0) or 0) != 0
        or int(item.get("main_refused", 0) or 0) != 0
        or int(item.get("external_failed", 0) or 0) != 0
        or int(item.get("external_refused", 0) or 0) != 0
    ]
    lines = [
        "# DOS Unit Batched SSA Compare Report",
        "",
        f"Schema: `{document.get('schema')}`",
        f"Oracle SSA: `{document.get('oracle_ssa')}`",
        f"Candidate SSA: `{document.get('candidate_ssa')}`",
        f"Mapping: `{document.get('mapping')}`",
        f"Output directory: `{document.get('out_dir')}`",
        "",
        "## Summary",
        "",
        f"- Batches: {summary.get('batches', 0)}",
        f"- Completed: {summary.get('batches_completed', 0)}",
        f"- Nonzero batches: `{_compact_json(summary.get('rc_nonzero', []))}`",
        f"- Main SSA parts: `{summary.get('main_passed', 0)}/{summary.get('main_total', 0)}` passed, failed `{summary.get('main_failed', 0)}`, refused `{summary.get('main_refused', 0)}`",
        f"- External/shared-tail SSA parts: `{summary.get('external_passed', 0)}/{summary.get('external_total', 0)}` passed, failed `{summary.get('external_failed', 0)}`, refused `{summary.get('external_refused', 0)}`, unproved `{summary.get('external_unproved', 0)}`",
        f"- Candidate-only SSA parts: `{summary.get('candidate_only_parts', 0)}` of `{summary.get('candidate_parts_total', 0)}` candidate parts, alias-only `{summary.get('candidate_alias_only_parts', 0)}`, referenced `{summary.get('candidate_parts_referenced', 0)}`",
        f"- Region equality: `{region_equality.get('status', 'not_applicable')}` total `{region_equality.get('total', 0)}` passed `{region_equality.get('passed', 0)}` failed `{region_equality.get('failed', 0)}` refused `{region_equality.get('refused', 0)}` covered-results `{region_equality.get('covered_results', 0)}` connectivity-covered `{region_equality.get('connectivity_covered_regions', 0)}`",
        f"- Connectivity: `{connectivity.get('status', 'not_applicable')}` edges `{connectivity.get('edges_checked', 0)}` state edges `{connectivity.get('state_edges_checked', 0)}` state inputs `{connectivity.get('state_inputs_checked', 0)}` external-covered `{connectivity.get('external_successor_edges_covered', 0)}` external-unproved `{connectivity.get('external_successor_edges_unproved', 0)}` failures `{connectivity.get('failures', 0)}` refusals `{connectivity.get('refusals', 0)}`",
        f"- Loop SCCs: `{loop_scc.get('status', 'not_applicable')}` total `{loop_scc.get('total', 0)}` passed `{loop_scc.get('passed', 0)}` failed `{loop_scc.get('failed', 0)}` refused `{loop_scc.get('refused', 0)}`",
        f"- Call SCCs: `{call_scc.get('status', 'not_applicable')}` total `{call_scc.get('total', 0)}` passed `{call_scc.get('passed', 0)}` failed `{call_scc.get('failed', 0)}` refused `{call_scc.get('refused', 0)}`",
        f"- Solver time ms: {summary.get('solver_time_ms', 0)}",
        "",
        "## Notes",
        "",
        "- Main SSA parts are declared function-body parts compared by binary equality, compact SSA equality, Z3, region equality, and connectivity gates as applicable.",
        "- External/shared-tail parts are out-of-declared-body SSA blocks reached by functions; they are proved separately when a unique candidate block can be found.",
        "- Candidate-only SSA parts are rebuilt-only coverage leftovers; inspect them when exact rebuilt coverage is expected, but they are not oracle mismatches.",
        "- SSA generation refusals are not included here. Run `report-failures --results <ssa.json>` on each SSA artifact to see functions that did not lower.",
        "",
        "## Failed Or Refused Batches",
        "",
    ]
    if not bad_batches:
        lines.append("No failed or refused batches.")
        lines.append("")
    else:
        for batch in _limited(bad_batches, limit):
            lines.extend(_format_bad_batch(batch))
        if len(bad_batches) > len(_limited(bad_batches, limit)):
            lines.append(f"... {len(bad_batches) - len(_limited(bad_batches, limit))} more failed/refused batches not shown.")
            lines.append("")
    candidate_only_parts: dict[str, Any] = (
        _dict_field(document, "candidate_only_parts")
    )
    _append_candidate_only_sections(lines, candidate_only_parts, limit)
    return "\n".join(lines)


def _format_bad_batch(batch: dict[str, Any]) -> list[str]:
    """Render one failed or refused batch summary."""
    lines = [
        f"### Batch {batch.get('batch')}",
        f"- Return code: `{batch.get('returncode')}`",
        f"- Compare JSON: `{batch.get('compare')}`",
        f"- Main: passed `{batch.get('main_passed', 0)}/{batch.get('main_total', 0)}`, failed `{batch.get('main_failed', 0)}`, refused `{batch.get('main_refused', 0)}`",
        f"- External/shared-tail: passed `{batch.get('external_passed', 0)}/{batch.get('external_total', 0)}`, failed `{batch.get('external_failed', 0)}`, refused `{batch.get('external_refused', 0)}`, unproved `{batch.get('external_unproved', 0)}`",
    ]
    functions = [str(item) for item in batch.get("functions", []) or []]
    if functions:
        preview = ", ".join(functions[:8])
        suffix = "" if len(functions) <= 8 else f", ... {len(functions) - 8} more"
        lines.append(f"- Functions: `{preview}{suffix}`")
    lines.append("")
    return lines


def _render_unknown(document: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# DOS Unit Failure Report",
            "",
            f"Schema: `{document.get('schema', 'unknown')}`",
            "",
            "No specialized failure renderer is available for this document.",
            "",
        ]
    )


def _compact_json(value: Any) -> str:  # noqa: ANN401
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _format_candidate_only_part(part: dict[str, Any], *, index: int) -> list[str]:
    function: dict[str, Any] = (
        _dict_field(part, "function")
    )
    name = function.get("name") or function.get("id") or part.get("id") or "<unknown>"
    detail = part.get("detail") if isinstance(part.get("detail"), dict) else part
    lines = [f"### {index}. `{name}` candidate-only"]
    if part.get("id"):
        lines.append(f"- SSA id: `{part.get('id')}`")
    if function.get("id"):
        lines.append(f"- Function id: `{function.get('id')}`")
    entry = detail.get("entry") if isinstance(detail, dict) else None
    if entry:
        lines.append(f"- Candidate entry: `{_format_ssa_entry(entry)}`")
    part_info = detail.get("part") if isinstance(detail, dict) and isinstance(detail.get("part"), dict) else {}
    if part_info:
        lines.append(f"- Part: `{_compact_json(part_info)}`")
    jumpkind = detail.get("jumpkind") if isinstance(detail, dict) else None
    if jumpkind:
        lines.append(f"- Jumpkind: `{jumpkind}`")
    if isinstance(detail, dict) and detail.get("instruction_count") is not None:
        lines.append(f"- Instructions: `{detail.get('instruction_count')}`")
    instructions = [item for item in (detail.get("instructions", []) if isinstance(detail, dict) else []) if isinstance(item, dict)]
    if instructions:
        lines.append("- First instructions:")
        for instruction in instructions[:4]:
            lines.append(f"  - `{_format_instruction(instruction)}`")
    lines.append("")
    return lines


def _format_instruction(instruction: dict[str, Any]) -> str:
    address = _format_address(instruction.get("address"))
    disassembly = instruction.get("disassembly", "")
    if address:
        return f"{address}: {disassembly}"
    return str(disassembly)


def _format_address(address: Any) -> str | None:  # noqa: ANN401
    if not isinstance(address, dict):
        return None
    ip = address.get("ip")
    linear = address.get("linear")
    if ip and linear:
        return f"{ip} ({linear})"
    if ip:
        return str(ip)
    if linear:
        return str(linear)
    return None
