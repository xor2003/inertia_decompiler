"""Layer: Recovery metadata.

Responsibility: attach readable interface summaries from recovered function-state facts.
Forbidden: prototype recovery, source-backed signatures, or semantic repair.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Protocol

from inertia.frontend.x86_16.low_memory_regions import format_x86_16_low_memory_access
from inertia.lowering.analysis_helpers import collect_neighbor_call_targets

from .function_state_summary import FunctionStateSummary, summarize_x86_16_function_state

__all__ = ["apply_x86_16_function_interface_surface"]

_PROTOTYPE_RE = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_][\w$?@]*\s*\([^)]*\)\s*;\s*$")
type _RenderText = Callable[[object], object]


class _FunctionInfoSurface(Protocol):
    """Owned function metadata consumed by this reporting-only surface."""

    addr: int
    name: str
    info: Mapping[str, object]


type _FunctionLookup = Callable[..., _FunctionInfoSurface | None]


class _CodegenFunctionSurface(Protocol):
    """Codegen function fields needed to identify the current function."""

    addr: int
    name: str


class _FunctionLookupSurface(Protocol):
    """Project KB function lookup used by interface annotation."""

    function: _FunctionLookup


class _KnowledgeBaseSurface(Protocol):
    """Project knowledge-base fields consumed by this module."""

    functions: _FunctionLookupSurface


class _ProjectSurface(Protocol):
    """Project fields consumed by interface annotation."""

    kb: _KnowledgeBaseSurface


class _CodegenSurface(Protocol):
    """Codegen fields patched at the render boundary."""

    cfunc: _CodegenFunctionSurface
    render_text: _RenderText
    _inertia_function_interface_surface_installed: bool
    _inertia_function_interface_original_render_text: _RenderText


def _bp_disp(offset: int) -> str:
    if offset == 0:
        return "[bp]"
    sign = "+" if offset > 0 else "-"
    return f"[bp{sign}0x{abs(offset):x}]"


def _join(items: tuple[str, ...] | tuple[int, ...], *, ints: bool = False) -> str:
    if not items:
        return "-"
    if ints:
        return ", ".join(_bp_disp(int(item)) for item in items)
    return ", ".join(str(item) for item in items)


def _summary_from_source(source: _FunctionInfoSurface) -> FunctionStateSummary:
    if source.info:
        return summarize_x86_16_function_state(source.info)
    return summarize_x86_16_function_state({})


def _format_memory_summary(items: tuple[str, ...]) -> str:
    if not items:
        return "-"
    return ", ".join(format_x86_16_low_memory_access(str(item)) for item in items)


def _has_surface_data(summary: FunctionStateSummary) -> bool:
    return any(
        (
            summary.gp_register_inputs,
            summary.gp_register_outputs,
            summary.segment_register_inputs,
            summary.segment_register_outputs,
            summary.flag_inputs,
            summary.flag_outputs,
            summary.frame_stack_reads,
            summary.frame_stack_writes,
            summary.memory_reads,
            summary.memory_writes,
            summary.return_kind != "unknown",
        )
    )


def _function_header_lines(name: str, summary: FunctionStateSummary) -> list[str]:
    if not _has_surface_data(summary):
        return []
    inputs = (*summary.gp_register_inputs, *summary.segment_register_inputs, *summary.flag_inputs)
    outputs = (*summary.gp_register_outputs, *summary.segment_register_outputs, *summary.flag_outputs)
    lines = [
        f"// interface {name}",
        f"//   in:  {_join(inputs)}",
        f"//   out: {_join(outputs)}",
        f"//   ret: {summary.return_kind}",
    ]
    if summary.frame_stack_reads:
        lines.append(f"//   stack-in:  {_join(summary.frame_stack_reads, ints=True)}")
    if summary.frame_stack_writes:
        lines.append(f"//   stack-out: {_join(summary.frame_stack_writes, ints=True)}")
    if summary.memory_reads:
        lines.append(f"//   mem-r: {_format_memory_summary(summary.memory_reads)}")
    if summary.memory_writes:
        lines.append(f"//   mem-w: {_format_memory_summary(summary.memory_writes)}")
    return lines


def _call_comment(name: str, summary: FunctionStateSummary) -> str | None:
    if not _has_surface_data(summary):
        return None
    inputs = (*summary.gp_register_inputs, *summary.segment_register_inputs, *summary.flag_inputs)
    outputs = (*summary.gp_register_outputs, *summary.segment_register_outputs, *summary.flag_outputs)
    return f"/* io {name}: in={_join(inputs)}; out={_join(outputs)}; ret={summary.return_kind} */"


def _prepend_header(rendered: str, header_lines: list[str]) -> str:
    if not header_lines:
        return rendered
    header = "\n".join(header_lines)
    if rendered.startswith(header):
        return rendered
    return f"{header}\n{rendered}"


def _annotate_call_lines(rendered: str, call_comments: dict[str, str]) -> str:
    def _impl() -> str:
        if not call_comments:
            return rendered
        lines = rendered.splitlines()
        updated: list[str] = []
        for line in lines:
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith(("//", "/*", "*"))
                or stripped.endswith("{")
                or _PROTOTYPE_RE.match(stripped)
                or "/* io " in stripped
            ):
                updated.append(line)
                continue
            appended = False
            for name, comment in call_comments.items():
                if f"{name}(" not in line or not stripped.endswith(";"):
                    continue
                updated.append(f"{line} {comment}")
                appended = True
                break
            if not appended:
                updated.append(line)
        return "\n".join(updated)

    return _impl()


def _render_with_interface_surface(project: _ProjectSurface, codegen: _CodegenSurface, rendered: str) -> str:
    cfunc = codegen.cfunc
    function = project.kb.functions.function(addr=cfunc.addr, create=False)
    if function is None:
        return rendered
    current_summary = _summary_from_source(function)
    rendered = _prepend_header(rendered, _function_header_lines(cfunc.name, current_summary))

    call_comments: dict[str, str] = {}
    for seed in collect_neighbor_call_targets(function):
        callee = project.kb.functions.function(addr=seed.target_addr, create=False)
        if callee is None:
            continue
        callee_name = callee.name
        if not isinstance(callee_name, str) or not callee_name:
            continue
        comment = _call_comment(callee_name, _summary_from_source(callee))
        if comment is None:
            continue
        call_comments.setdefault(callee_name, comment)
    return _annotate_call_lines(rendered, call_comments)


def apply_x86_16_function_interface_surface(project: _ProjectSurface, codegen: _CodegenSurface) -> bool:
    """Install readable interface annotations from already-recovered state facts."""
    original = codegen.render_text
    if bool(vars(codegen).get("_inertia_function_interface_surface_installed", False)):
        return False

    def _render_text_with_interface(_cfunc: object) -> object:
        # Runtime contract: facts produced must be consumed before C emission.
        from inertia.pipeline.contracts import assert_pipeline_contracts_8616

        assert_pipeline_contracts_8616(codegen)

        rendered = original(_cfunc)
        if not isinstance(rendered, str):
            return rendered
        return _render_with_interface_surface(project, codegen, rendered)

    codegen._inertia_function_interface_surface_installed = True
    codegen._inertia_function_interface_original_render_text = original
    codegen.render_text = _render_text_with_interface
    return True
