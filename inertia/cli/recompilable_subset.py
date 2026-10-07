"""Layer: Recompilable output.

Responsibility: orchestrate bounded generated-C syntax checks over the recompilable subset.
Forbidden: semantic recovery, fallback body substitution, or source-backed output repair.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations

from .recompilable_cases import (
    describe_x86_16_recompilable_subset,
    get_x86_16_recompilable_subset_cases,
)
from .recompilable_checks import (
    check_recompilable_c_text_shape,
    compile_recompilable_c_text,
    syntax_check_recompilable_c_text,
)
from .recompilable_cli_bridge import decompile_recompilable_subset_case

__all__ = [
    "describe_x86_16_recompilable_subset",
    "run_x86_16_recompilable_subset_syntax_checks",
]


def run_x86_16_recompilable_subset_syntax_checks() -> tuple[dict[str, object], ...]:
    """Run syntax, compile, and shape checks for every recompilable subset case."""
    results: list[dict[str, object]] = []
    for case in get_x86_16_recompilable_subset_cases():
        c_text, decompile_meta = decompile_recompilable_subset_case(case)
        syntax_proc = syntax_check_recompilable_c_text(c_text)
        compile_proc = compile_recompilable_c_text(c_text)
        shape = check_recompilable_c_text_shape(c_text, case)
        results.append(
            {
                "name": case.name,
                "expected_kind": case.expected_kind,
                **decompile_meta,
                "returncode": syntax_proc.returncode,
                "stderr": syntax_proc.stderr,
                "syntax_ok": syntax_proc.returncode == 0,
                "compile_returncode": compile_proc.returncode,
                "compile_stderr": compile_proc.stderr,
                "compile_ok": compile_proc.returncode == 0,
                **shape,
            }
        )
    return tuple(results)
