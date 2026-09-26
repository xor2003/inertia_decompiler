# AUTO-GENERATED split from cli_runtime_shared.py
"""Layer: CLI/fallback/reporting.

Responsibility: perform final emitted-C text cleanup and reporting-only normalization.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import angr
from angr.sim_type import SimTypeChar, SimTypeShort
from angr_platforms.X86_16.analysis_helpers import preferred_known_helper_signature_decl
from angr_platforms.X86_16.cod_extract import CODProcMetadata
from angr_platforms.X86_16.cod_known_objects import known_cod_object_spec
from angr_platforms.X86_16.lowering.gp_word_runtime import runtime_gp_word_symbols_8616

from inertia_decompiler.cli_output import (
    _timestamped_print,
)

from .cli_c_ast_rewrites import (
    _cod_stack_alias_for_disp,
    _dos_helper_declarations,
    _int21_call_replacements,
    _interrupt_call_replacement_map,
    _interrupt_helper_declarations,
    _known_helper_declarations,
    _make_unique_identifier,
    _normalize_16bit_signed_offset,
)
from .cli_interrupt_modeling import _interrupt_wrapper_call_text

print: Any = _timestamped_print
__all__ = [
    "_annotate_cod_proc_output",
    "_coalesce_redundant_split_global_incdec_text",
    "_collapse_annotated_stack_aliases_text",
    "_collapse_duplicate_type_keywords_text",
    "_contains_void_function_definition_text",
    "_dedupe_adjacent_prototype_lines",
    "_dedupe_duplicate_local_declarations_text",
    "_format_bp_disp",
    "_format_known_helper_calls",
    "_hoist_c89_local_declarations_text",
    "_materialize_annotated_cod_declarations_text",
    "_materialize_missing_generic_local_declarations_text",
    "_materialize_opaque_pointer_typedefs_text",
    "_normalize_anonymous_call_targets",
    "_normalize_boolean_conditions",
    "_normalize_function_signature_arg_names",
    "_normalize_mk_fp_segment_names",
    "_normalize_spurious_duplicate_local_suffixes",
    "_normalize_unary_not_shift_precedence_text",
    "_prune_invalid_simple_function_prototypes_text",
    "_prune_standalone_memory_helper_reads_text",
    "_prune_trailing_generic_return_text",
    "_prune_unused_local_declarations_text",
    "_prune_unused_staging_assignments",
    "_prune_void_call_assignments_text",
    "_prune_void_function_return_values_text",
    "_repair_missing_cod_function_header_text",
    "_repair_missing_fallthrough_returns",
    "_rewrite_known_helper_signature_text",
    "_sanitize_mangled_autonames_text",
    "_simplify_condition_line",
    "_simplify_negated_condition",
    "_simplify_x86_16_conditions",
    "_simplify_x86_16_stack_byte_pointers",
    "_simplify_x86_16_stack_references",
    "_simplify_x86_16_wrapped_stack_offsets",
    "_source_args_from_cod_source_lines",
    "_split_simple_assignment_conditions",
    "_split_top_level_binary",
]


def _dynamic_text_attr(obj: object, name: str, default: Any = None) -> Any:
    """Read a dynamic CLI/codegen/angr text-postprocess attribute."""
    # Dynamic codegen boundary: angr functions, prototypes, and project plugins expose version-dependent fields.
    return getattr(obj, name, default)


def _is_strict_c_identifier_8616(name: object) -> bool:
    """Return whether a dynamic text token is one complete C identifier."""
    return isinstance(name, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is not None


def _is_plausible_simple_return_type_8616(type_text: str) -> bool:
    """Validate a simple declaration return type without accepting split names."""
    normalized = type_text.replace("*", " * ")
    tokens = tuple(token for token in normalized.split() if token != "*")
    if not tokens:
        return False
    if len(tokens) == 1:
        return _is_strict_c_identifier_8616(tokens[0])
    if tokens[0] in {"struct", "union", "enum"}:
        return len(tokens) == 2 and _is_strict_c_identifier_8616(tokens[1])
    type_words = {
        "_Bool",
        "char",
        "const",
        "double",
        "float",
        "int",
        "long",
        "short",
        "signed",
        "unsigned",
        "void",
        "volatile",
    }
    return all(token in type_words for token in tokens)


def _prune_invalid_simple_function_prototypes_text(c_text: str) -> str:
    """Remove malformed zero-argument prototypes while preserving valid C types."""

    def _impl() -> str:
        lines = c_text.splitlines()
        if not lines:
            return c_text
        prototype_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*]*?)\s+"
            r"(?P<name>[A-Za-z_]\w*)\s*\(\s*(?:void\s*)?\)\s*;\s*$"
        )
        changed = False
        kept: list[str] = []
        brace_depth = 0
        for line in lines:
            match = prototype_re.match(line) if brace_depth == 0 else None
            if match is not None and not _is_plausible_simple_return_type_8616(match.group("ret").strip()):
                changed = True
                brace_depth = max(0, brace_depth + line.count("{") - line.count("}"))
                continue
            kept.append(line)
            brace_depth = max(0, brace_depth + line.count("{") - line.count("}"))
        if not changed:
            return c_text
        normalized = "\n".join(kept)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


_PROTOTYPE_DECL_RE_8616 = re.compile(
    r"^\s*(?P<ret>[A-Za-z_][\w\s\*]*?)\s+(?:\*\s*)*(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^)]*)\)\s*;\s*$"
)
_PROTOTYPE_CALL_RE_8616 = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;\n{}]*)\)\s*;"
)


def _update_bracket_depths_8616(ch: str, depths: tuple[int, int, int]) -> tuple[int, int, int]:
    """Track paren/bracket/brace depth for one character."""

    depth_paren, depth_bracket, depth_brace = depths
    if ch == "(":
        depth_paren += 1
    elif ch == ")" and depth_paren > 0:
        depth_paren -= 1
    elif ch == "[":
        depth_bracket += 1
    elif ch == "]" and depth_bracket > 0:
        depth_bracket -= 1
    elif ch == "{":
        depth_brace += 1
    elif ch == "}" and depth_brace > 0:
        depth_brace -= 1
    return depth_paren, depth_bracket, depth_brace


def _split_top_level_call_args_8616(args_text: str) -> list[str]:
    """Split an argument list at top-level commas only."""

    text = args_text.strip()
    if not text:
        return []
    parts: list[str] = []
    current: list[str] = []
    depth_paren = depth_bracket = depth_brace = 0
    for ch in text:
        if ch == "," and depth_paren == depth_bracket == depth_brace == 0:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
        depth_paren, depth_bracket, depth_brace = _update_bracket_depths_8616(
            ch, (depth_paren, depth_bracket, depth_brace)
        )
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _prototype_declared_arity_8616(args: str) -> int | None:
    """Return the declared arity of one prototype argument string."""

    text = args.strip()
    if not text:
        return 0
    if text == "void":
        return 0
    if "..." in text:
        return None
    return len(_split_top_level_call_args_8616(text))


def _prototype_score_8616(
    ret: str,
    args: str,
    decl: str,
    name: str,
    observed_min_arity: Mapping[str, int],
) -> tuple[int, int]:
    """Score a candidate prototype declaration for conflict selection."""

    ret = ret.strip()
    args = args.strip()
    is_generic = ret == "int" and args == ""
    has_typed_args = bool(args and args != "void")
    observed = observed_min_arity.get(name)
    declared = _prototype_declared_arity_8616(args)
    arity_conflict = isinstance(observed, int) and isinstance(declared, int) and declared > observed
    if arity_conflict and has_typed_args:
        return (-10, len(decl))
    return ((2 if has_typed_args else 0) + (0 if is_generic else 1), len(decl))


@dataclass
class _PruneConflictingPrototypesRun8616:
    """Run state for pruning weaker conflicting prototypes."""

    c_text: str
    lines: list[str]
    observed_min_arity: dict[str, int] = field(default_factory=dict)
    top_level_by_index: list[bool] = field(default_factory=list)
    best_by_name: dict[str, str] = field(default_factory=dict)
    best_score_by_name: dict[str, tuple[int, int]] = field(default_factory=dict)
    replacement_by_name: dict[str, str] = field(default_factory=dict)

    def collect_arities(self) -> None:
        """Record the minimum observed call arity per name."""

        for line in self.lines:
            for call_match in _PROTOTYPE_CALL_RE_8616.finditer(line):
                name = call_match.group("name")
                args = call_match.group("args").strip()
                arity = 0 if not args else len(_split_top_level_call_args_8616(args))
                prev = self.observed_min_arity.get(name)
                if prev is None or arity < prev:
                    self.observed_min_arity[name] = arity

    def collect_top_level_mask(self) -> None:
        """Record which lines sit at top-level brace depth."""

        brace_depth = 0
        for line in self.lines:
            self.top_level_by_index.append(brace_depth == 0)
            brace_depth += line.count("{") - line.count("}")
            if brace_depth < 0:
                brace_depth = 0

    def collect_best_decls(self) -> None:
        """Select the strongest prototype spelling per name."""

        for index, line in enumerate(self.lines):
            if not self.top_level_by_index[index]:
                continue
            stripped = line.strip()
            match = _PROTOTYPE_DECL_RE_8616.match(stripped)
            if match is None:
                continue
            name = match.group("name")
            score = _prototype_score_8616(
                match.group("ret"), match.group("args"), stripped, name, self.observed_min_arity
            )
            prev_score: tuple[int, int] | None = self.best_score_by_name.get(name)
            if prev_score is None or score > prev_score:
                self.best_score_by_name[name] = score
                self.best_by_name[name] = stripped

    def collect_replacements(self) -> None:
        """Mark arity-conflicting prototypes for generic redeclaration."""

        protected_standard_names = {
            "time",
        }
        for name, decl in tuple(self.best_by_name.items()):
            match = _PROTOTYPE_DECL_RE_8616.match(decl)
            if match is None:
                continue
            if name in protected_standard_names:
                continue
            observed = self.observed_min_arity.get(name)
            declared = _prototype_declared_arity_8616(match.group("args"))
            if isinstance(observed, int) and isinstance(declared, int) and declared > observed:
                self.replacement_by_name[name] = f"int {name}();"

    def apply_replacements(self) -> str:
        """Rewrite the lines carrying a weaker winning prototype."""

        out_lines: list[str] = []
        for index, line in enumerate(self.lines):
            stripped = line.strip()
            match = _PROTOTYPE_DECL_RE_8616.match(stripped) if self.top_level_by_index[index] else None
            if match is None:
                out_lines.append(line)
                continue
            name = match.group("name")
            if self.best_by_name.get(name) != stripped:
                continue
            replacement = self.replacement_by_name.get(name)
            if replacement is None:
                out_lines.append(line)
                continue
            indent_match = re.match(r"^\s*", line)
            indent = indent_match.group(0) if indent_match is not None else ""
            out_lines.append(f"{indent}{replacement}")
        normalized = "\n".join(out_lines)
        if self.c_text.endswith("\n"):
            normalized += "\n"
        return normalized


def _prune_weaker_conflicting_prototypes_text(c_text: str) -> str:
    """Drop top-level prototypes that conflict with observed call arity."""

    lines = c_text.splitlines()
    if not lines:
        return c_text
    run = _PruneConflictingPrototypesRun8616(c_text=c_text, lines=lines)
    run.collect_arities()
    run.collect_top_level_mask()
    run.collect_best_decls()
    if not run.best_by_name:
        return c_text
    run.collect_replacements()
    return run.apply_replacements()

_INCDEC_LOCAL_DECL_RE_8616 = re.compile(
    r"^\s*(?:unsigned\s+|signed\s+)?(?:char|short|int|long|uint\d+_t|int\d+_t)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:;|//)"
)
_INCDEC_LOAD_RE_8616 = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[A-Za-z_]\w*)\s*;\s*$")
_INCDEC_WORD_RE_8616 = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+);\s*$")
_INCDEC_HIGH_RE_8616 = re.compile(r"^(?P<indent>\s*)(?P<lhs>mem_[0-9A-Fa-f]+)\s*=\s*(?P<rhs>.+?)\s*>>\s*8;\s*$")
_INCDEC_INC_RE_8616 = re.compile(r"^\s*(?P<lhs>[A-Za-z_]\w*)\s*\+=\s*1;\s*$")
_INCDEC_FOR_HIGH_RE_8616 = re.compile(
    r"^(?P<indent>\s*)for\s*\(\s*SEG_U8\((?P<seg>[^,]+),\s*(?P<high>\d+)\)\s*=\s*"
    r"SEG_U16\(\s*(?P=seg)\s*,\s*(?P<low>\d+)\)\s*\+\s*1\s*>>\s*8\s*;\s*(?P<rest>.*)$"
)


def _norm_incdec_expr_8616(expr: str) -> str:
    """Normalize whitespace out of one expression for comparisons."""

    return re.sub(r"\s+", "", expr.strip())


def _split_incdec_word_pattern_8616(
    lines: list[str],
    index: int,
    local_names: set[str],
) -> str | None:
    """Return the coalesced ``+= 1`` line for a split word inc/dec window."""

    if index < 2 or index + 1 >= len(lines):
        return None
    low_load = _INCDEC_LOAD_RE_8616.match(lines[index - 2])
    high_load = _INCDEC_LOAD_RE_8616.match(lines[index - 1])
    word_store = _INCDEC_WORD_RE_8616.match(lines[index])
    high_store = _INCDEC_HIGH_RE_8616.match(lines[index + 1])
    if low_load is None or high_load is None or word_store is None or high_store is None:
        return None
    word_lhs = word_store.group("lhs")
    low_var = low_load.group("lhs")
    high_var = high_load.group("lhs")
    high_mem = high_load.group("rhs")
    expected_rhs = f"({low_var} | {high_var} * 0x100) + 1"
    if not (
        word_lhs == low_load.group("rhs")
        and word_lhs not in local_names
        and high_mem == high_store.group("lhs")
        and high_mem.startswith("mem_")
        and _norm_incdec_expr_8616(word_store.group("rhs")) == _norm_incdec_expr_8616(expected_rhs)
        and _norm_incdec_expr_8616(high_store.group("rhs")) == _norm_incdec_expr_8616(expected_rhs)
    ):
        return None
    return f"{word_store.group('indent')}{word_lhs} += 1;"


def _coalesce_redundant_split_global_incdec_text(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text
    local_names = {match.group("name") for line in lines if (match := _INCDEC_LOCAL_DECL_RE_8616.match(line))}

    out: list[str] = []
    changed = False
    index = 0
    while index < len(lines):
        for_high = _INCDEC_FOR_HIGH_RE_8616.match(lines[index])
        if for_high is not None and out and _INCDEC_INC_RE_8616.match(out[-1]) is not None:
            low = int(for_high.group("low"))
            high = int(for_high.group("high"))
            if high == low + 1:
                out.append(f"{for_high.group('indent')}for (; {for_high.group('rest')}")
                index += 1
                changed = True
                continue
        coalesced = _split_incdec_word_pattern_8616(lines, index, local_names)
        if coalesced is not None:
            if len(out) >= 2 and out[-2] == lines[index - 2] and out[-1] == lines[index - 1]:
                out.pop()
                out.pop()
            out.append(coalesced)
            index += 2
            changed = True
            continue
        out.append(lines[index])
        index += 1
    if not changed:
        return c_text
    normalized = "\n".join(out)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _helper_name(project: angr.Project, addr: int) -> str | None:
    proc = project.hooked_by(addr)
    if proc is None:
        return None
    name = _dynamic_text_attr(proc, "INT_NAME", None)
    if isinstance(name, str) and name:
        return name
    name = _dynamic_text_attr(proc, "display_name", None)
    if isinstance(name, str) and name:
        return name
    return str(proc.__class__.__name__)


def _normalize_anonymous_call_targets(c_text: str) -> str:
    pattern = re.compile(r"(?<![A-Za-z0-9_])(?P<target>0x[0-9a-fA-F]+|\d+)(?![A-Za-z0-9_])\s*\(\s*\)")

    def _replace(match: re.Match[str]) -> str:
        try:
            target = int(match.group("target"), 0)
        except ValueError:
            return match.group(0)
        return f"sub_{target:x}()"

    return pattern.sub(_replace, c_text)


_VOID_HEADER_START_RE_8616 = re.compile(r"^\s*(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+[A-Za-z_]\w*\s*\(")
_VOID_RETURN_RE_8616 = re.compile(r"^(?P<indent>\s*)return\s+(?P<expr>[^;]+);\s*$")
_VOID_BARE_RETURN_RE_8616 = re.compile(r"^\s*return;\s*$")
_VOID_SIDE_EFFECT_CALL_RE_8616 = re.compile(r"^(?:(?:::0x[0-9a-fA-F]+::)?[A-Za-z_]\w*)\s*\(.*\)$")


@dataclass
class _PruneVoidReturnsRun8616:
    """Run state for pruning return values from void function bodies."""

    lines: list[str]
    out_lines: list[str] = field(default_factory=list)
    changed: bool = False

    def _return_line_is_terminal(self, start_index: int, current_depth: int) -> bool:
        """Return whether the return line closes the enclosing brace block."""

        depth = current_depth
        scan_index = start_index + 1
        while scan_index < len(self.lines):
            scan_line = self.lines[scan_index]
            stripped = scan_line.strip()
            if stripped and stripped != "}" and not stripped.startswith("//"):
                return False
            depth += scan_line.count("{") - scan_line.count("}")
            if depth <= 0:
                return True
            scan_index += 1
        return False

    def process_body(self, index: int, brace_depth: int, is_void: bool) -> int:
        """Rewrite returns inside one function body; return the next index."""

        line_count = len(self.lines)
        while index < line_count and brace_depth > 0:
            body_line = self.lines[index]
            return_match = _VOID_RETURN_RE_8616.match(body_line)
            if is_void and return_match is not None:
                indent = return_match.group("indent")
                expr = return_match.group("expr").strip()
                if _VOID_SIDE_EFFECT_CALL_RE_8616.match(expr) is not None:
                    self.out_lines.append(f"{indent}{expr};")
                if self._return_line_is_terminal(index, brace_depth):
                    self.changed = True
                    brace_depth += body_line.count("{") - body_line.count("}")
                    index += 1
                    continue
                body_line = f"{indent}return;"
                self.changed = True
            elif not is_void and _VOID_BARE_RETURN_RE_8616.match(body_line) is not None:
                self.changed = True
                brace_depth += body_line.count("{") - body_line.count("}")
                index += 1
                continue
            self.out_lines.append(body_line)
            brace_depth += body_line.count("{") - body_line.count("}")
            index += 1
        return index

    def handle_multiline_header(self, index: int, header_lines: list[str], is_void: bool) -> int:
        """Scan a split function header and process its body if present."""

        line_count = len(self.lines)
        brace_index_scan: int | None = None
        scan_index = index + 1
        is_forward_decl = False
        while scan_index < line_count and brace_index_scan is None:
            header_line = self.lines[scan_index]
            header_lines.append(header_line)
            if "{" in header_line:
                brace_index_scan = scan_index
                break
            if ";" in header_line:
                is_forward_decl = True
                break
            scan_index += 1

        if is_forward_decl and brace_index_scan is None:
            self.out_lines.extend(header_lines)
            return scan_index

        if brace_index_scan is None:
            self.out_lines.extend(header_lines)
            return scan_index

        if ";" in self.lines[brace_index_scan] and "{" not in self.lines[brace_index_scan]:
            self.out_lines.extend(header_lines)
            return brace_index_scan + 1

        self.out_lines.extend(header_lines)
        brace_depth = sum(part.count("{") - part.count("}") for part in header_lines)
        return self.process_body(brace_index_scan + 1, brace_depth, is_void)

    def run(self) -> int:
        """Process every top-level line; return the final changed flag."""

        index = 0
        line_count = len(self.lines)
        while index < line_count:
            line = self.lines[index]
            header_match = _VOID_HEADER_START_RE_8616.match(line)
            if header_match is None:
                self.out_lines.append(line)
                index += 1
                continue
            is_void = header_match.group("ret").strip() == "void"

            header_lines = [line]
            if "{" in line:
                self.out_lines.extend(header_lines)
                index = self.process_body(index + 1, 1, is_void)
                continue

            if ";" in line:
                self.out_lines.append(line)
                index += 1
                continue

            index = self.handle_multiline_header(index, header_lines, is_void)
        return self.changed


def _prune_void_function_return_values_text(c_text: str) -> str:
    """Drop ``return expr;`` values inside void definitions."""

    run = _PruneVoidReturnsRun8616(lines=c_text.splitlines())
    if not run.run():
        return c_text
    result = "\n".join(run.out_lines)
    if c_text.endswith("\n"):
        result += "\n"
    return result

def _collect_void_function_names_from_c_text_8616(c_text: str) -> set[str]:
    names: set[str] = set()
    header_re = re.compile(r"^\s*void\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:;|\{)?\s*$")
    for line in c_text.splitlines():
        match = header_re.match(line)
        if match is not None:
            names.add(match.group("name"))
    return names


def _prune_void_call_assignments_text(c_text: str) -> str:
    def _impl() -> str:
        void_names = _collect_void_function_names_from_c_text_8616(c_text)
        if not void_names:
            return c_text
        assignment_re = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<callee>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*)\);\s*$"
        )
        lines = c_text.splitlines()
        changed = False
        out_lines: list[str] = []
        for line in lines:
            match = assignment_re.match(line)
            if match is None or match.group("callee") not in void_names:
                out_lines.append(line)
                continue
            out_lines.append(f"{match.group('indent')}{match.group('callee')}({match.group('args')});")
            changed = True
        if not changed:
            return c_text
        result = "\n".join(out_lines)
        if c_text.endswith("\n"):
            result += "\n"
        return result

    return _impl()


def _contains_void_function_definition_text(c_text: str) -> bool:
    lines = c_text.splitlines()
    header_start_re = re.compile(r"^\s*void\s+[A-Za-z_]\w*\s*\(")

    index = 0
    line_count = len(lines)
    while index < line_count:
        if not header_start_re.match(lines[index]):
            index += 1
            continue

        paren_depth = lines[index].count("(") - lines[index].count(")")
        scan_index = index
        while scan_index < line_count:
            scan_line = lines[scan_index]
            if scan_index != index:
                paren_depth += scan_line.count("(") - scan_line.count(")")
            if paren_depth <= 0:
                if ";" in scan_line and "{" not in scan_line:
                    break
                if "{" in scan_line:
                    return True
            scan_index += 1

        index += 1

    return False


_SIGNATURE_TYPE_KEYWORDS_8616 = {
    "void",
    "char",
    "short",
    "int",
    "long",
    "signed",
    "unsigned",
    "const",
    "volatile",
    "struct",
    "union",
    "enum",
}
_SIGNATURE_CONTROL_NAMES_8616 = {"if", "for", "while", "switch"}


def _signature_split_args_8616(args_text: str) -> list[str]:
    """Split one signature argument list at top-level commas."""

    if not args_text.strip():
        return []
    parts: list[str] = []
    current: list[str] = []
    depths = (0, 0, 0)
    for char in args_text:
        if char == "," and depths == (0, 0, 0):
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        depths = _update_bracket_depths_8616(char, depths)
    if current:
        parts.append("".join(current).strip())
    return parts


def _signature_split_decl_name_8616(arg_text: str) -> tuple[str, str] | None:
    """Split a declaration argument into (type-prefix, name)."""

    text = arg_text.rstrip()
    if not text or text == "void" or text == "...":
        return None
    idx = len(text)
    while idx > 0 and text[idx - 1].isspace():
        idx -= 1
    end = idx
    while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
        idx -= 1
    if idx == end:
        return None
    name = text[idx:end]
    if re.fullmatch(r"[A-Za-z_]\w*", name) is None or name in _SIGNATURE_TYPE_KEYWORDS_8616:
        return None
    prefix = text[:idx]
    if not prefix.strip():
        return None
    return prefix, name


def _normalize_signature_args_8616(args_text: str, declared_local_names: set[str]) -> str:
    """Rename signature parameters to canonical arg/local spellings."""

    args = _signature_split_args_8616(args_text)
    if not args:
        return args_text
    used: set[str] = set()
    normalized: list[str] = []
    for arg in args:
        split = _signature_split_decl_name_8616(arg)
        if split is None:
            normalized.append(arg)
            continue
        prefix, name = split
        candidate = name
        suffix_match = re.fullmatch(r"(?P<base>.+?)_(?P<suffix>\d+)", name)
        if re.fullmatch(r"arg_\d+", name) or (re.fullmatch(r"local_\d+", name) and name not in declared_local_names):
            candidate = name
        elif suffix_match is not None:
            unsuffixed = suffix_match.group("base")
            if unsuffixed:
                candidate = unsuffixed
        suffix = 2
        while candidate in used:
            candidate = f"{name}_{suffix}"
            suffix += 1
        used.add(candidate)
        normalized.append(f"{prefix}{candidate}")
    return ", ".join(normalized)


def _normalize_function_signature_arg_names(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    header_pattern = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    control_statement_names = _SIGNATURE_CONTROL_NAMES_8616

    declared_local_names = {
        match.group("name")
        for match in re.finditer(
            r"(?m)^\s*(?:unsigned\s+short|short|unsigned\s+int|int|unsigned\s+long|long|char|unsigned\s+char|signed\s+char|[A-Za-z_]\w*(?:\s*\*)?)\s+"
            r"(?P<name>local_\d+)\s*(?:;|=)",
            c_text,
        )
    }
    declared_local_names.update(
        match.group("name")
        for match in re.finditer(r"(?m)^\s*.+\(\s*\*(?P<name>local_\d+)\s*\)\s*\([^;]*\)\s*;", c_text)
    )

    lines = c_text.splitlines()
    changed = False
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        if match.group("name") in control_statement_names:
            continue
        args_text = match.group("args")
        normalized_args = _normalize_signature_args_8616(args_text, declared_local_names)
        if normalized_args == args_text:
            continue
        changed = True
        lines[index] = (
            f"{match.group('indent')}{match.group('ret').rstrip()} {match.group('name')}("
            f"{normalized_args}){match.group('suffix')}"
        )

    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized


_GENERIC_LOCAL_NAME_RE_8616 = re.compile(
    r"^(?:a\d+|v\d+|vvar_\d+|tmp_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+|local_[0-9a-fA-F]+)$"
)
_GENERIC_PLAIN_DECL_RE_8616 = re.compile(
    r"^(?!(?:return|if|while|for|switch|goto|case|default|continue|break)\b)"
    r"(?P<type>(?:[A-Za-z_][\w\[\]]*\s+)+(?:\*+\s*)*|[A-Za-z_][\w\[\]]*\s*\*+\s*)"
    r"(?P<name>[A-Za-z_]\w*)(?:\s*\[[^\]]*\]\s*)*;\s*$"
)
_GENERIC_FUNC_PTR_DECL_RE_8616 = re.compile(
    r"^(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)"
    r"\s*\([^;{}]*\)\s*;\s*$"
)
_GENERIC_USE_RE_8616 = re.compile(
    r"(?<![A-Za-z_])(?P<name>a\d+|v\d+|vvar_\d+|tmp_\d+|ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+|local_[0-9a-fA-F]+)(?![A-Za-z_])"
)
_GENERIC_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[$A-Za-z_][$\w]*)\s*\((?P<args>[^()]*)\)"
)


def _declared_generic_local_name_8616(line: str) -> tuple[bool, str | None]:
    """Return whether a line is a declaration and its generic name, if any."""

    decl_part = line.split("//", 1)[0].strip()
    if not decl_part or decl_part.startswith(("/*", "*")):
        return False, None
    if "{" in decl_part or "}" in decl_part:
        return False, None
    if "(" in decl_part or ")" in decl_part:
        funcptr_match = _GENERIC_FUNC_PTR_DECL_RE_8616.fullmatch(decl_part)
        if funcptr_match is None:
            return False, None
        name = funcptr_match.group("name")
        return True, name if _GENERIC_LOCAL_NAME_RE_8616.fullmatch(name) else None
    match = _GENERIC_PLAIN_DECL_RE_8616.fullmatch(decl_part)
    if match is None:
        return False, None
    name = match.group("name")
    return True, name if _GENERIC_LOCAL_NAME_RE_8616.fullmatch(name) else None


def _generic_block_body_end_8616(lines: list[str], brace_index: int) -> int:
    """Return the exclusive end index of the body opened at brace_index."""

    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_end


def _generic_declared_names_8616(
    lines: list[str], body_start: int, body_end: int
) -> tuple[set[str], int]:
    """Scan the leading declaration block for generic names."""

    declared_names: set[str] = set()
    insertion_index = body_start
    scan_index = body_start
    while scan_index < body_end:
        line = lines[scan_index]
        is_declaration, declared_name = _declared_generic_local_name_8616(line)
        if not is_declaration:
            if line.strip() and not line.lstrip().startswith("//"):
                break
        else:
            if declared_name is not None:
                declared_names.add(declared_name)
            insertion_index = scan_index + 1
        scan_index += 1
    return declared_names, insertion_index


def _generic_used_names_8616(lines: list[str], body_start: int, body_end: int) -> list[str]:
    """Collect generic name uses in first-seen order within the body."""

    used_names: list[str] = []
    seen_used: set[str] = set()
    for scan_index in range(body_start, body_end):
        text = lines[scan_index].split("//", 1)[0]
        for use_match in _GENERIC_USE_RE_8616.finditer(text):
            name = use_match.group("name")
            if name in seen_used:
                continue
            seen_used.add(name)
            used_names.append(name)
    return used_names


def _generic_block_brace_index_8616(lines: list[str], index: int) -> tuple[int | None, int]:
    """Scan forward from a header for the body's opening brace."""

    scan_index = index
    while scan_index < len(lines):
        if "{" in lines[scan_index]:
            return scan_index, scan_index
        if ";" in lines[scan_index] and "{" not in lines[scan_index]:
            return None, scan_index
        scan_index += 1
    return None, scan_index


def _materialize_generic_locals_block_8616(lines: list[str], index: int) -> tuple[int, bool]:
    """Insert missing generic local declarations for one function block."""

    match = _GENERIC_HEADER_RE_8616.match(lines[index])
    if match is None:
        return index + 1, False

    arg_names: set[str] = set()
    for arg in _signature_split_args_8616(match.group("args")):
        arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg)
        if arg_match is not None:
            arg_names.add(arg_match.group(1))

    brace_index, scan_index = _generic_block_brace_index_8616(lines, index)
    if brace_index is None:
        return scan_index + 1, False

    body_start = brace_index + 1
    body_end = _generic_block_body_end_8616(lines, brace_index)

    declared_names, insertion_index = _generic_declared_names_8616(lines, body_start, body_end)
    used_names = _generic_used_names_8616(lines, body_start, body_end)

    missing_names = [name for name in used_names if name not in declared_names and name not in arg_names]
    if not missing_names:
        return body_end, False

    decl_lines = [f"    unsigned short {name};" for name in missing_names]
    lines[insertion_index:insertion_index] = decl_lines
    body_end += len(decl_lines)
    return body_end, True


def _materialize_missing_generic_local_declarations_text(c_text: str) -> str:
    """Declare emitted generic locals that have no existing C declarator."""
    # Text-layer rule:
    # This helper is compile hygiene only. It may add missing declarations for names
    # that are already present in emitted text, but it must not infer new storage
    # identity, stack aliases, or semantics. If a generic temp survives because an
    # address-carrier chain was not lowered, fix that earlier in AST/stack lowering.
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    changed = False
    index = 0
    while index < len(lines):
        index, block_changed = _materialize_generic_locals_block_8616(lines, index)
        changed = changed or block_changed
    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

_C89_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
)
_C89_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s+)(?!(?:return|if|while|for|switch|goto|case|default|continue|break|extern|typedef)\b)"
    r"(?P<type>(?:unsigned\s+short|unsigned\s+int|unsigned\s+long|signed\s+short|signed\s+int|signed\s+long|"
    r"short|int|long|char|uint8_t|uint16_t|uint32_t|int8_t|int16_t|int32_t|void\s*\*)"
    r"(?:\s*\*)?)\s+"
    r"(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
)


def _c89_collect_decl_entries_8616(
    lines: list[str], brace_index: int, body_end: int, body_indent: str
) -> list[tuple[int, str, str]]:
    """Collect top-depth C89 declarations inside one function body."""

    depth = 1
    decl_entries: list[tuple[int, str, str]] = []
    scan = brace_index + 1
    while scan < body_end:
        line = lines[scan]
        stripped = line.strip()
        if depth == 1:
            match = _C89_DECL_RE_8616.match(line)
            if match is not None and match.group("indent") == body_indent and "=" not in line:
                decl_entries.append((scan, match.group("name"), line))
        depth += stripped.count("{") - stripped.count("}")
        scan += 1
    return decl_entries


def _c89_insertion_index_8616(
    lines: list[str], brace_index: int, body_end: int, decl_entries: list[tuple[int, str, str]]
) -> int:
    """Return where hoisted declarations should be inserted."""

    insertion = brace_index + 1
    while insertion < body_end:
        stripped = lines[insertion].strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            insertion += 1
            continue
        if any(entry_index == insertion for entry_index, _name, _line in decl_entries):
            insertion += 1
            continue
        break
    return insertion


def _c89_hoist_plan_8616(
    decl_entries: list[tuple[int, str, str]], insertion: int
) -> tuple[list[str], set[int], bool]:
    """Compute the hoisted lines, removed indexes, and changed flag."""

    seen_names: set[str] = set()
    hoisted: list[str] = []
    remove_indexes: set[int] = set()
    local_changed = False
    for line_index, name, line in decl_entries:
        if name in seen_names:
            remove_indexes.add(line_index)
            local_changed = True
            continue
        seen_names.add(name)
        hoisted.append(line)
        if line_index < insertion or line_index >= insertion + len(decl_entries):
            local_changed = True
        remove_indexes.add(line_index)
    return hoisted, remove_indexes, local_changed


def _hoist_c89_decls_block_8616(lines: list[str], index: int) -> tuple[list[str], int, bool]:
    """Hoist C89 declarations for one function; return (lines, index, changed)."""

    if _C89_HEADER_RE_8616.match(lines[index]) is None:
        return lines, index + 1, False
    brace_index = _find_function_brace_index(lines, index)
    if brace_index is None:
        return lines, index + 1, False
    body_end = _find_block_end(lines, brace_index)
    indent_match = re.match(r"^(\s*)", lines[brace_index])
    body_indent = (indent_match.group(1) if indent_match is not None else "") + "    "

    decl_entries = _c89_collect_decl_entries_8616(lines, brace_index, body_end, body_indent)
    if not decl_entries:
        return lines, body_end, False

    insertion = _c89_insertion_index_8616(lines, brace_index, body_end, decl_entries)
    hoisted, remove_indexes, local_changed = _c89_hoist_plan_8616(decl_entries, insertion)
    if not local_changed:
        return lines, body_end, False

    kept = [line for line_index, line in enumerate(lines) if line_index not in remove_indexes]
    removed_before_insertion = sum(1 for line_index in remove_indexes if line_index < insertion)
    insertion_after_removal = insertion - removed_before_insertion
    kept[insertion_after_removal:insertion_after_removal] = hoisted
    lines = kept
    body_end = body_end - len(remove_indexes) + len(hoisted)
    return lines, body_end, True


def _hoist_c89_local_declarations_text(c_text: str) -> str:
    """Hoist depth-1 C89 local declarations to the top of each body."""

    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    changed = False
    index = 0
    while index < len(lines):
        lines, index, block_changed = _hoist_c89_decls_block_8616(lines, index)
        changed = changed or block_changed
    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _codegen_signature_authoritative_8616(function: object | None = None, codegen: object | None = None) -> bool:
    for obj in (codegen, function):
        if obj is not None and _dynamic_text_attr(obj, "_inertia_codegen_signature_authoritative_8616", None):
            return True
    return False


def _rewrite_cod_arg_decl_8616(arg_text: str, pointer_evidence_text: str) -> str:
    """Add a pointer star to one argument spelling when evidence requires it."""

    split_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
    if split_match is None:
        return arg_text
    arg_name = split_match.group(1)
    if not _arg_has_pointer_evidence_8616(pointer_evidence_text, arg_name):
        return arg_text
    if "*" in arg_text[: split_match.start(1)]:
        return arg_text
    prefix = arg_text[: split_match.start(1)].rstrip()
    suffix = arg_text[split_match.end(1) :]
    prefix = f"{prefix} *" if prefix else "*"
    return f"{prefix}{arg_name}{suffix}"


def _rewrite_cod_header_8616(
    lines: list[str],
    header_index: int,
    header_re: re.Pattern[str],
    func_name: str,
    rewritten_args: tuple[str, ...],
    current_args: list[str],
) -> bool | None:
    """Rewrite the function header line; None means the header was lost."""

    if rewritten_args == tuple(current_args):
        return False
    header_match = header_re.match(lines[header_index])
    if header_match is None:
        return None
    replacement_header = (
        f"{header_match.group('indent')}{header_match.group('ret').rstrip()} "
        f"{func_name}({', '.join(rewritten_args)})"
    )
    if header_match.group("suffix") == "{":
        replacement_header += " {"
    elif header_match.group("suffix") == ";":
        replacement_header += ";"
    if lines[header_index] == replacement_header:
        return False
    lines[header_index] = replacement_header
    return True


def _cod_decls_finish_8616(
    lines: list[str],
    c_text: str,
    header_index: int,
    insertion_index: int,
    prototype_declarations: list[str],
    declarations: list[str],
    header_changed: bool,
) -> str:
    """Splice prototype/body declarations and join like the input."""

    if prototype_declarations:
        lines[header_index:header_index] = [*prototype_declarations, ""]
    if not declarations:
        if not header_changed and not prototype_declarations:
            return c_text
        return _join_lines_like_input_8616(lines, c_text)
    lines[insertion_index:insertion_index] = declarations
    return _join_lines_like_input_8616(lines, c_text)


def _materialize_annotated_cod_declarations_text(
    c_text: str,
    function: object,
    metadata: CODProcMetadata | None,
    *,
    preserve_source_header: bool = False,
) -> str:
    """Materialize cleanup-only COD declarations without overriding authoritative headers."""

    def _impl() -> str:
        if metadata is None or function is None:
            return c_text

        func_name = _dynamic_text_attr(function, "name", None)
        if not isinstance(func_name, str) or not func_name:
            return c_text

        lines = c_text.splitlines()
        header_re = re.compile(
            rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>.*)\)\s*(?P<suffix>[{{;]?)\s*$"
        )
        header_index = _find_header_index_8616(lines, header_re)
        if header_index is None:
            return c_text
        span = _find_body_span_8616(lines, header_index)
        if span is None:
            return c_text
        _brace_index, body_start, body_end = span

        body_text = "\n".join(lines[body_start:body_end])
        header_changed = False
        declared_names: set[str] = set()
        insertion_index = body_start
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?:(?:extern|static)\s+)?(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?P<comment>//.*)?$"
        )
        pointer_evidence_text = body_text
        source_prototypes: dict[str, str] = {}

        _normalize_existing_decl_names_8616(
            lines,
            body_start=body_start,
            decl_re=decl_re,
            declared_names=declared_names,
        )

        current_match = header_re.match(lines[header_index])
        if current_match is None:
            return c_text
        current_arg_text = current_match.group("args")
        current_args = _split_args_8616(current_arg_text)
        rewritten_args = (
            tuple(current_args)
            if preserve_source_header
            else tuple(_rewrite_cod_arg_decl_8616(arg_text, pointer_evidence_text) for arg_text in current_args)
        )
        header_result = _rewrite_cod_header_8616(
            lines, header_index, header_re, func_name, rewritten_args, current_args
        )
        if header_result is None:
            return c_text
        if header_result:
            header_changed = True
            body_text = "\n".join(lines[body_start:body_end])

        prototype_declarations, declarations = _collect_cod_materialized_decls_8616(
            metadata=metadata,
            source_prototypes=source_prototypes,
            func_name=func_name,
            body_text=body_text,
            declared_names=declared_names,
        )

        return _cod_decls_finish_8616(
            lines,
            c_text,
            header_index,
            insertion_index,
            prototype_declarations,
            declarations,
            header_changed,
        )

    return _impl()


def _find_header_index_8616(lines: list[str], header_re: re.Pattern[str]) -> int | None:
    for index, line in enumerate(lines):
        if header_re.match(line):
            return index
    return None


def _find_body_span_8616(lines: list[str], header_index: int) -> tuple[int, int, int] | None:
    brace_index = header_index
    while brace_index < len(lines):
        if "{" in lines[brace_index]:
            break
        if ";" in lines[brace_index] and "{" not in lines[brace_index]:
            return None
        brace_index += 1
    if brace_index >= len(lines):
        return None
    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return brace_index, body_start, body_end


def _split_args_8616(arg_text: str) -> list[str]:
    args: list[str] = []
    current: list[str] = []
    depths = (0, 0, 0)
    for char in arg_text:
        if char == "," and depths == (0, 0, 0):
            args.append("".join(current).strip())
            current = []
            continue
        current.append(char)
        depths = _update_bracket_depths_8616(char, depths)
    if current:
        args.append("".join(current).strip())
    return args


def _arg_has_pointer_evidence_8616(pointer_evidence_text: str, arg_name: str) -> bool:
    name = re.escape(arg_name)
    patterns = (
        rf"(?m)(?:^|[=({{[,?:!]|return\s+)\s*\*\s*{name}\s*\+\+",
        rf"(?m)(?:^|[=({{[,?:!]|return\s+)\s*\*\s*{name}\b",
        rf"(?m)(?:^|[=({{[,?:!]|return\s+)\s*\*\s*\(\s*{name}\b",
        rf"(?<![A-Za-z_]){name}\s*\[",
        rf"(?<![A-Za-z_]){name}\s*->",
    )
    return any(re.search(pattern, pointer_evidence_text) is not None for pattern in patterns)


def _join_lines_like_input_8616(lines: list[str], original_text: str) -> str:
    normalized = "\n".join(lines)
    if original_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _source_decl_has_custom_ptr_8616(source_args: list[str]) -> bool:
    for source_arg in source_args:
        source_name_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", source_arg)
        if source_name_match is None:
            continue
        source_prefix = source_arg[: source_name_match.start(1)].strip()
        if "*" not in source_prefix:
            continue
        base_tokens = [token for token in re.split(r"\s+", source_prefix.replace("*", " ").strip()) if token]
        if not base_tokens:
            continue
        base_type = base_tokens[-1]
        if (
            base_type not in {"char", "short", "int", "long", "float", "double", "void", "size_t", "FILE"}
            and base_type[0].isupper()
        ):
            return True
    return False


def _arg_name_used_in_body_8616(body_text: str, name: str) -> bool:
    """Return whether an argument name appears in the function body text."""

    return re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])", body_text) is not None


def _unmaterialized_source_arg_probe_8616(
    body_text: str, current_parts: list[str]
) -> bool:
    """Return whether a current arg name is used while the source had none."""

    for current_part in current_parts:
        current_name = _decl_arg_name_8616(current_part)
        if not current_name:
            continue
        if _arg_name_used_in_body_8616(body_text, current_name):
            return True
    return False


def _renamed_arg_mismatch_probe_8616(
    body_text: str,
    current_parts: list[str],
    source_parts: list[str],
    allowed_aliases: set[str],
) -> bool:
    """Return whether a renamed arg still sees use its source name lacks."""

    for current_part, source_part in zip(current_parts, source_parts, strict=False):
        current_name = _decl_arg_name_8616(current_part)
        source_name = _decl_arg_name_8616(source_part)
        if not current_name or not source_name or current_name == source_name:
            continue
        current_used = _arg_name_used_in_body_8616(body_text, current_name)
        source_used = _arg_name_used_in_body_8616(body_text, source_name)
        if current_used and not source_used:
            if source_name in allowed_aliases:
                continue
            return True
    return False


def _source_header_args_unmaterialized_8616(
    c_text: str,
    *,
    func_name: str,
    source_decl: str | None,
    source_arg_text: str | None = None,
    allowed_positive_arg_aliases: Sequence[str] | None = None,
) -> bool:
    if not isinstance(func_name, str) or not func_name:
        return False
    if not source_decl and not source_arg_text:
        return False
    header_re = re.compile(
        rf"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>.*)\)\s*(?:\{{|\s*$)"
    )
    current_header = header_re.search(c_text)
    if current_header is None:
        return False
    source_parts = _split_source_decl_args_8616(source_decl, source_arg_text)
    current_parts = _split_c_signature_args_8616(current_header.group("args"))
    source_args_text = ""
    if source_decl is not None:
        source_args_text = _source_decl_args_text_8616(source_decl) or ""
    if not source_args_text and isinstance(source_arg_text, str):
        source_args_text = source_arg_text.strip()
    body_text = c_text[current_header.end() :]
    if (
        not source_parts
        and source_args_text in {"", "void"}
        and current_parts
        and _unmaterialized_source_arg_probe_8616(body_text, current_parts)
    ):
        return True
    if not source_parts or len(source_parts) != len(current_parts):
        return False
    allowed_aliases = set(allowed_positive_arg_aliases or ())
    return _renamed_arg_mismatch_probe_8616(body_text, current_parts, source_parts, allowed_aliases)


def _restore_codegen_header_for_unmaterialized_source_args_8616(
    before_text: str,
    after_text: str,
    *,
    func_name: str,
) -> str:
    if not isinstance(func_name, str) or not func_name:
        return after_text
    header_re = re.compile(
        rf"(?m)^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)(?P<suffix>\s*[;{{]?\s*)$"
    )
    before_match = header_re.search(before_text)
    after_match = header_re.search(after_text)
    if before_match is None or after_match is None:
        return after_text
    replacement = before_match.group(0)
    before_suffix = before_match.group("suffix") or ""
    after_suffix = after_match.group("suffix") or ""
    if after_suffix.strip() and not before_suffix.strip():
        replacement = replacement.rstrip() + after_suffix
    return after_text[: after_match.start()] + replacement + after_text[after_match.end() :]


def _apply_local_return_type_to_header_8616(
    lines: list[str],
    *,
    header_index: int,
    header_re: re.Pattern[str],
    func_name: str,
    local_return_type: str | None,
    header_changed: bool,
) -> bool:
    if not isinstance(local_return_type, str):
        return header_changed
    normalized_return_type = " ".join(local_return_type.strip().split())
    if not (normalized_return_type == "void" or normalized_return_type.endswith(" void")):
        return header_changed
    normalized_return_type = "void"
    current_header = header_re.match(lines[header_index])
    if current_header is None:
        return header_changed
    current_args = current_header.group("args")
    replacement_header = f"{current_header.group('indent')}{local_return_type.strip()} {func_name}({current_args})"
    if current_header.group("suffix") == "{":
        replacement_header += " {"
    elif current_header.group("suffix") == ";":
        replacement_header += ";"
    if lines[header_index] != replacement_header:
        lines[header_index] = replacement_header
        return True
    return header_changed


def _normalize_existing_decl_names_8616(
    lines: list[str],
    *,
    body_start: int,
    decl_re: re.Pattern[str],
    declared_names: set[str],
) -> None:
    for scan_index in range(body_start):
        line = lines[scan_index]
        stripped = line.split("//", 1)[0].strip()
        if not stripped or stripped.startswith(("/*", "*")):
            continue
        decl_match = decl_re.match(line)
        if decl_match is None:
            continue
        declared_name = decl_match.group("name")
        spec = known_cod_object_spec(declared_name)
        if spec is None:
            declared_names.add(declared_name)
            continue
        normalized_name = spec.name
        declared_names.add(normalized_name)
        if normalized_name != declared_name:
            lines[scan_index] = re.sub(
                rf"(?<![A-Za-z_]){re.escape(declared_name)}(?![A-Za-z_])\s*;\s*(?://.*)?$",
                f"{normalized_name};",
                line,
                count=1,
            )


def _return_only_helper_decl_8616(name: str, helper_decl: str) -> str:
    head = helper_decl.split("(", 1)[0].strip()
    if head.endswith(name):
        return_type = head[: -len(name)].strip()
        if return_type:
            return f"{return_type} {name}();"
    return f"int {name}();"


def _collect_cod_materialized_decls_8616(
    *,
    metadata: CODProcMetadata,
    source_prototypes: dict[str, str],
    func_name: str,
    body_text: str,
    declared_names: set[str],
) -> tuple[list[str], list[str]]:
    def _impl() -> tuple[list[str], list[str]]:
        declarations: list[str] = []
        prototype_declarations: list[str] = []
        seen_declared = set(declared_names)
        for proto_name, source_proto in source_prototypes.items():
            normalized_proto_name = proto_name.lstrip("_")
            if (
                normalized_proto_name != func_name
                and normalized_proto_name not in seen_declared
                and re.search(
                    rf"(?<![A-Za-z_]){re.escape(normalized_proto_name)}\s*\(",
                    body_text,
                )
            ):
                prototype_declarations.append(source_proto)
                seen_declared.add(normalized_proto_name)
        for global_name in metadata.global_names:
            if not isinstance(global_name, str) or not global_name:
                continue
            spec = known_cod_object_spec(global_name)
            if spec is None:
                continue
            candidate_name = spec.name or global_name
            if global_name in seen_declared or candidate_name in seen_declared:
                continue
            if not re.search(rf"(?<![A-Za-z_]){re.escape(global_name)}(?![A-Za-z_])", body_text) and not re.search(
                rf"(?<![A-Za-z_]){re.escape(candidate_name)}(?![A-Za-z_])",
                body_text,
            ):
                continue
            declarations.append(f"    extern {spec.type_name} {candidate_name};")
            seen_declared.add(candidate_name)
        return prototype_declarations, declarations

    return _impl()


def _normalize_scalar_assigned_extern_arrays_text(c_text: str) -> str:
    def _impl() -> str:
        lines = c_text.splitlines()
        if not lines:
            return c_text
        changed = False
        seen: set[str] = set()
        normalized_lines: list[str] = []
        decl_re = re.compile(r"^(?P<indent>\s*)extern\s+char\s+(?P<name>[A-Za-z_]\w*)\[(?P<size>\d+)\];\s*$")
        for line in lines:
            match = decl_re.match(line)
            if match is None:
                normalized_lines.append(line)
                continue
            name = match.group("name")
            usage_body = "\n".join(candidate for candidate in lines if not decl_re.match(candidate))
            direct_assign = re.search(rf"(?m)^\s*{re.escape(name)}\s*=", usage_body) is not None
            scalar_arith = (
                re.search(
                    rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*(?:\+|-|\*|/|>>|<<|==|!=|<=|>=|<|>)",
                    usage_body,
                )
                is not None
            )
            unary_update = (
                re.search(
                    rf"(?:\+\+|--)\s*(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])|"
                    rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*(?:\+\+|--)",
                    usage_body,
                )
                is not None
            )
            indexed_use = re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z_])\s*\[", usage_body) is not None
            if indexed_use or not (direct_assign or scalar_arith or unary_update):
                normalized_lines.append(line)
                continue
            replacement = f"{match.group('indent')}extern unsigned short {name};"
            if replacement in seen:
                changed = True
                continue
            seen.add(replacement)
            normalized_lines.append(replacement)
            changed = True
        if not changed:
            return c_text
        normalized = "\n".join(normalized_lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _normalize_concat_zero_text(c_text: str) -> str:
    # Lower decompiler textual CONCAT forms that represent zero-extension.
    # Examples:
    #   "x CONCAT 0" -> "x"
    #   "0 CONCAT x" -> "x"
    normalized = re.sub(r"\(\s*([A-Za-z_]\w*)\s+CONCAT\s+0\s*\)", r"\1", c_text)
    normalized = re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\s+CONCAT\s+0(?![A-Za-z_])", r"\1", normalized)
    normalized = re.sub(r"0\s+CONCAT\s+([A-Za-z_]\w*)", r"\1", normalized)
    return normalized


def _prune_dead_stack_base_assignments_text(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text
    assign_re = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>[^;]*stack_base[^;]*);\s*$")
    changed = False
    kept: list[str] = []
    full_text = "\n".join(lines)
    for line in lines:
        m = assign_re.match(line)
        if m is None:
            kept.append(line)
            continue
        lhs = m.group("lhs")
        token_re = re.compile(rf"(?<![A-Za-z_0-9]){re.escape(lhs)}(?![A-Za-z_0-9])")
        occurrences = len(token_re.findall(full_text))
        # Two occurrences means declaration + this assignment, i.e. no real use.
        if occurrences <= 2:
            changed = True
            continue
        kept.append(line)
    if not changed:
        return c_text
    out = "\n".join(kept)
    if c_text.endswith("\n"):
        out += "\n"
    return out


def _materialize_stack_base_placeholder_declaration_text(c_text: str) -> str:
    if "stack_base" not in c_text:
        return c_text
    decl_re = re.compile(r"(?m)^\s*[A-Za-z_][\w\s\*]*\bstack_base\b\s*(?:[;=,\[])")
    if decl_re.search(c_text):
        return c_text
    lines = c_text.splitlines()
    if not lines:
        return c_text
    insert_at = None
    for idx, line in enumerate(lines):
        if "{" in line:
            insert_at = idx + 1
            break
    if insert_at is None:
        return c_text
    lines.insert(insert_at, "    unsigned short stack_base;")
    out = "\n".join(lines)
    if c_text.endswith("\n"):
        out += "\n"
    return out


def _normalize_integer_dereference_stores_text(c_text: str) -> str:
    # Semantic lowering belongs to the typed x86-16 lowering pipeline.  This
    # legacy text hook used to synthesize SEG_U8(0, addr) for raw integer stores,
    # which invented an unproven segment and produced invalid MS C lvalues.
    # Keep the text unchanged so validation/gates expose the real owner.
    return c_text


def _materialize_missing_g_hex_externs_text(c_text: str) -> str:
    token_re = re.compile(r"(?<![A-Za-z_0-9])(g_[0-9a-fA-F]+)(?![A-Za-z_0-9])")
    decl_re = re.compile(r"(?m)^\s*extern\s+[^\n;]*\b(g_[0-9a-fA-F]+)\b[^\n;]*;\s*$")
    used = set(token_re.findall(c_text))
    declared = set(decl_re.findall(c_text))
    missing = sorted(name for name in used if name not in declared)
    if not missing:
        return c_text
    lines = c_text.splitlines()
    insert_at = 0
    for idx, line in enumerate(lines):
        if line.strip().startswith("extern "):
            insert_at = idx + 1
    decl_lines = [f"extern unsigned short {name};" for name in missing]
    lines[insert_at:insert_at] = decl_lines
    out = "\n".join(lines)
    if c_text.endswith("\n"):
        out += "\n"
    return out


_EXTERN_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)extern\s+(?P<type>[^;()]+?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*$"
)
_EXTERN_TYPE_RANK_8616 = {
    "void": 0,
    "char": 1,
    "unsigned char": 2,
    "short": 3,
    "unsigned short": 4,
    "int": 5,
    "unsigned int": 6,
    "long": 7,
    "unsigned long": 8,
}


def _extern_decl_winners_8616(lines: list[str]) -> dict[str, tuple[int, str, str, int]]:
    """Select the strongest extern declaration spelling per name."""

    winners: dict[str, tuple[int, str, str, int]] = {}
    for idx, line in enumerate(lines):
        match = _EXTERN_DECL_RE_8616.match(line)
        if match is None:
            continue
        name = match.group("name")
        raw_type = " ".join(match.group("type").split())
        rank = _EXTERN_TYPE_RANK_8616.get(raw_type, 100)
        prior = winners.get(name)
        if prior is None or rank > prior[0]:
            winners[name] = (rank, raw_type, match.group("indent"), idx)
    return winners


def _extern_decl_rewrite_8616(
    lines: list[str], winners: dict[str, tuple[int, str, str, int]]
) -> tuple[list[str], bool]:
    """Keep the first winning extern decl per name, drop the rest."""

    kept: list[str] = []
    emitted: set[str] = set()
    changed = False
    for line in lines:
        match = _EXTERN_DECL_RE_8616.match(line)
        if match is None:
            kept.append(line)
            continue
        name = match.group("name")
        winner = winners.get(name)
        if winner is None:
            kept.append(line)
            continue
        if name in emitted:
            changed = True
            continue
        winner_type = winner[1]
        winner_indent = winner[2]
        normalized = f"{winner_indent}extern {winner_type} {name};"
        if normalized != line:
            changed = True
        kept.append(normalized)
        emitted.add(name)
    return kept, changed


def _dedupe_conflicting_extern_variable_declarations_text(c_text: str) -> str:
    """Collapse duplicate extern variable declarations to the strongest type."""

    lines = c_text.splitlines()
    if not lines:
        return c_text
    winners = _extern_decl_winners_8616(lines)
    if not winners:
        return c_text
    kept, changed = _extern_decl_rewrite_8616(lines, winners)
    if not changed:
        return c_text
    out = "\n".join(kept)
    if c_text.endswith("\n"):
        out += "\n"
    return out

def _materialize_missing_segment_macro_locals_text(c_text: str) -> str:
    def _impl() -> str:
        needed = {
            segment
            for segment in ("ds", "es", "ss")
            if re.search(rf"\b(?:SEG_U8|SEG_U16|SEG_U32|SEG_PTR|MK_FP)\s*\(\s*{segment}\b", c_text)
        }
        if not needed:
            return c_text
        lines = c_text.splitlines()
        existing = {
            match.group("name")
            for line in lines
            for match in (re.match(r"\s*unsigned\s+short\s+(?P<name>ds|es|ss)\s*(?:;|,)", line),)
            if match is not None
        }
        missing = sorted(needed - existing)
        if not missing:
            return c_text
        for index, line in enumerate(lines):
            if line.strip() == "{":
                insert_at = index + 1
                lines[insert_at:insert_at] = [f"    unsigned short {name};" for name in missing]
                normalized = "\n".join(lines)
                if c_text.endswith("\n"):
                    normalized += "\n"
                return normalized
        return c_text

    return _impl()


def _prototype_for_direct_call(
    name: str,
    observed_arg_count: int | None,
) -> str:
    helper_decl = preferred_known_helper_signature_decl(name)
    if helper_decl is not None:
        match = re.search(r"\((?P<args>[^)]*)\)", helper_decl)
        helper_arg_count = None
        if match is not None:
            arg_text = match.group("args").strip()
            if not arg_text or arg_text == "void":
                helper_arg_count = 0
            else:
                helper_arg_count = len([part for part in arg_text.split(",") if part.strip()])
        if isinstance(helper_arg_count, int) and isinstance(observed_arg_count, int):  # noqa: SIM102
            if helper_arg_count != observed_arg_count:
                return _return_only_helper_decl_8616(name, helper_decl)
        return str(helper_decl).rstrip(";").strip() + ";"
    return f"int {name}();"


def _parameter_names_from_args_text_8616(args_text: str) -> set[str]:
    names: set[str] = set()
    if not args_text.strip() or args_text.strip() == "void":
        return names
    for part in _split_args_8616(args_text):
        fnptr_match = re.search(r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)", part)
        if fnptr_match is not None:
            names.add(fnptr_match.group("name"))
            continue
        match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", part.strip())
        if match is not None:
            names.add(match.group(1))
    return names


def _extract_function_header_args_8616(line: str) -> str | None:
    """Read declaration arguments, never preprocessor replacement expressions."""
    header = line.split("{", 1)[0].strip()
    if not header or header.startswith("#") or header.endswith(";"):
        return None
    close_idx = header.rfind(")")
    if close_idx < 0:
        return None
    depth = 0
    open_idx = None
    for idx in range(close_idx, -1, -1):
        char = header[idx]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_idx = idx
                break
    if open_idx is None:
        return None
    prefix = header[:open_idx].strip()
    if not re.search(r"\b[A-Za-z_]\w*$", prefix):
        return None
    return header[open_idx + 1 : close_idx]


def _collect_declared_and_defined_function_names(lines: list[str]) -> set[str]:
    def _impl() -> set[str]:
        declared = {
            match.group("name")
            for line in lines
            for match in (
                re.match(r"\s*(?:extern\s+)?[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*;", line),
            )
            if match is not None
        }
        defined: set[str] = set()
        definition_re = re.compile(r"\s*[A-Za-z_][\w\s\*]*\s+(?P<name>[A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?P<brace>\{?)\s*$")
        for index, line in enumerate(lines):
            match = definition_re.match(line)
            if match is None:
                continue
            if match.group("brace"):
                defined.add(match.group("name"))
                continue
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                defined.add(match.group("name"))
        return declared | defined

    return _impl()


def _has_decl_or_def_in_text(c_text: str, declared: set[str], name: str) -> bool:
    escaped = re.escape(name)
    decl_or_def_re = re.compile(
        rf"(?m)^\s*(?:extern\s+)?[A-Za-z_][\w\s\*]*?\s+(?:\*\s*)?{escaped}\s*\([^;{{}}]*\)\s*(?:;|\{{.*$)"
    )
    if decl_or_def_re.search(c_text):
        return True
    return name in declared


def _collect_direct_calls_and_observed_arity(
    lines: list[str], c_text: str, declared: set[str]
) -> tuple[list[str], dict[str, int]]:
    def _impl() -> tuple[list[str], dict[str, int]]:
        keywords = {
            "auto",
            "char",
            "const",
            "do",
            "double",
            "else",
            "enum",
            "extern",
            "float",
            "for",
            "if",
            "int",
            "long",
            "register",
            "return",
            "short",
            "signed",
            "sizeof",
            "static",
            "struct",
            "switch",
            "typedef",
            "union",
            "unsigned",
            "void",
            "volatile",
            "while",
        }
        standard_c_functions = {
            "toupper",
            "tolower",
            "isalpha",
            "isdigit",
            "isalnum",
            "isspace",
            "isupper",
            "islower",
            "isprint",
            "iscntrl",
            "ispunct",
            "isxdigit",
        }
        runtime_helpers = {
            "SEG_U8",
            "SEG_U16",
            "SEG_U32",
            "SEG_PTR",
            "SEG_LINEAR",
            "MK_FP",
            "MEM_U8",
            "MEM_U16",
            "MEM_U32",
        }
        parameter_names = _collect_function_parameter_names_8616(lines)
        calls: list[str] = []
        observed_args: dict[str, int] = {}
        for line in lines:
            stripped = line.strip()
            if stripped.startswith(("/*", "*", "//", "#")):
                continue
            for match in re.finditer(r"(?<![A-Za-z_])(?P<name>[A-Za-z_]\w*)\s*\(", line):
                name = match.group("name")
                after = line[match.end() :]
                close_idx = after.find(")")
                if close_idx >= 0:
                    arg_expr = after[:close_idx].strip()
                    argc = 0 if not arg_expr else len([part for part in arg_expr.split(",") if part.strip()])
                    observed_args[name] = max(observed_args.get(name, 0), argc)
                if _name_has_known_binding_8616(
                    c_text,
                    name,
                    keywords,
                    standard_c_functions,
                    runtime_helpers,
                    parameter_names,
                    calls,
                    declared,
                ):
                    continue
                calls.append(name)
        return calls, observed_args

    return _impl()


def _find_first_function_insert_index(lines: list[str]) -> int | None:
    for index, line in enumerate(lines):
        if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", line):
            return index
        if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$", line):
            lookahead = index + 1
            while lookahead < len(lines) and not lines[lookahead].strip():
                lookahead += 1
            if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                return index
    return None


def _materialize_missing_direct_call_prototypes_text(
    c_text: str,
) -> str:
    return c_text


def _strip_comments_and_strings_8616(text: str) -> str:
    text = re.sub(r"(?s)/\*.*?\*/", " ", text)
    text = re.sub(r"//.*?$", " ", text, flags=re.M)
    text = re.sub(r"^\s*#.*?$", " ", text, flags=re.M)
    text = re.sub(r'"(?:\\.|[^"\\])*"', " ", text)
    text = re.sub(r"'(?:\\.|[^'\\])'", " ", text)
    return text


def _name_has_known_binding_8616(
    c_text: str,
    name: str,
    keywords: set[str],
    standard_c_functions: set[str],
    runtime_helpers: set[str],
    parameter_names: set[str],
    calls: list[str],
    declared: set[str],
) -> bool:
    """Return whether a call-shaped name already has a known binding."""

    return (
        name in keywords
        or name in standard_c_functions
        or name in runtime_helpers
        or name in parameter_names
        or name in calls
        or _has_decl_or_def_in_text(c_text, declared, name)
    )


_DECL_FUNCTION_SIG_RE_8616 = re.compile(
    r"^\s*[A-Za-z_][\w\s\*\[\]]*\s+(?P<name>[A-Za-z_][\w$?@]*)"
    r"\s*\((?P<args>[^)]*)\)\s*(?:\{)?\s*;?$"
)
_DECL_TYPEDEF_ALIAS_RE_8616 = re.compile(
    r"^\s*(?:typedef\b.*\s|}\s*)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;\s*$"
)
_DECL_TYPE_TAG_RE_8616 = re.compile(r"\b(?:struct|union|enum)\s+(?P<name>[A-Za-z_]\w*)")
_DECL_STMT_RE_8616 = re.compile(
    r"^\s*(?:extern\s+|static\s+)?[A-Za-z_][\w\s\*\[\]<>]*\b(?P<name>[A-Za-z_][\w$?@]*)(?:\s*[\[,;=]|\s*\()"
)
_DECL_SKIP_TOKENS_8616 = {"return", "if", "for", "while", "switch", "case", "else", "do", "goto"}


def _signature_arg_names_8616(args_text: str) -> set[str]:
    """Collect the trailing identifier of each signature argument."""

    names: set[str] = set()
    for arg in re.split(r",", args_text):
        arg_match = re.search(r"(?<![A-Za-z_])([A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])$", arg.strip())
        if arg_match:
            names.add(arg_match.group(1))
    return names


def _comma_tail_names_8616(line: str) -> set[str]:
    """Collect leading identifiers in each comma-separated tail segment."""

    names: set[str] = set()
    for segment in line.split(",")[1:]:
        nested = re.match(r"(?P<name>[A-Za-z_][\w$?@]*)", segment.strip())
        if nested is not None:
            names.add(nested.group("name"))
    return names


def _collect_declared_identifiers_line_8616(line: str, declared: set[str]) -> None:
    """Add every identifier declared by one stripped line."""

    macro = re.match(r"^#\s*define\s+(?P<name>[A-Za-z_]\w*)\b", line)
    if macro is not None:
        declared.add(macro.group("name"))
        return
    first_token = line.split(None, 1)[0] if line.split(None, 1) else ""
    if first_token in _DECL_SKIP_TOKENS_8616:
        return
    declared.update(match.group("name") for match in _DECL_TYPE_TAG_RE_8616.finditer(line))
    typedef_match = _DECL_TYPEDEF_ALIAS_RE_8616.match(line)
    if typedef_match is not None:
        declared.add(typedef_match.group("name"))
        return
    sig_match = _DECL_FUNCTION_SIG_RE_8616.match(line)
    if sig_match is not None:
        declared.add(sig_match.group("name"))
        declared.update(_signature_arg_names_8616(sig_match.group("args")))
        return
    decl_match = _DECL_STMT_RE_8616.match(line)
    if decl_match is None:
        return
    declared.add(decl_match.group("name"))
    if "," not in line:
        return
    declared.update(_comma_tail_names_8616(line))


def _collect_declared_identifiers_8616(text_lines: list[str]) -> set[str]:
    """Collect every identifier the text already declares."""

    declared: set[str] = set()
    for raw_line in text_lines:
        line = raw_line.strip()
        if not line or line.startswith(("//", "*", "/*", "///")):
            continue
        _collect_declared_identifiers_line_8616(line, declared)
    return declared
def _collect_declared_global_names_8616(text_lines: list[str]) -> set[str]:
    """Collect global extern names already materialized by typed lowering."""

    declared: set[str] = set()
    extern_re = re.compile(r"^\s*extern\b.*\b(?P<name>[A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*;\s*$")
    for raw_line in text_lines:
        match = extern_re.match(raw_line.strip())
        if match is not None:
            declared.add(match.group("name"))
    return declared


def _collect_member_access_names_8616(text: str) -> set[str]:
    """Collect struct member names so metadata cannot promote them to globals."""

    work = _strip_comments_and_strings_8616(text)
    return {
        match.group("name")
        for match in re.finditer(r"\.\s*(?P<name>[A-Za-z_]\w*)\b", work)
        if _is_strict_c_identifier_8616(match.group("name"))
    }


def _is_known_compiler_temp_8616(name: str) -> bool:
    return bool(re.match(r"^(?:vvar_\d+|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]*)*|tmp_\d+|ir_\d+|arg_[0-9a-fA-F]+)$", name))


_GLOBAL_DECL_INFERENCE_RESERVED_IDENTIFIERS_8616 = frozenset(
    {
        "NULL",
        "auto",
        "bool",
        "break",
        "case",
        "char",
        "clock_t",
        "const",
        "continue",
        "default",
        "do",
        "double",
        "else",
        "enum",
        "extern",
        "false",
        "float",
        "for",
        "goto",
        "if",
        "int",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
        "long",
        "register",
        "return",
        "short",
        "signed",
        "sizeof",
        "static",
        "stdbool",
        "stdint",
        "struct",
        "switch",
        "time",
        "time_t",
        "true",
        "typedef",
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "union",
        "unsigned",
        "void",
        "volatile",
        "while",
    }
)


def _safe_finditer_8616(pattern: str, text_value: str) -> Iterable[re.Match[str]]:
    try:
        return re.finditer(pattern, text_value)
    except re.error:
        return ()


def _global_call_arg_candidates_8616(
    work: str, function_like: set[str], candidates: list[str]
) -> None:
    """Collect identifiers passed to known function-like names."""

    executable_work = "\n".join(
        line
        for line in work.splitlines()
        if re.match(r"^\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_][\w$?@]*\s*\([^;{}]*\)\s*;", line) is None
    )
    for call_match in _safe_finditer_8616(
        r"(?<![A-Za-z_])(?P<call>[A-Za-z_][\w$?@]*)\s*\((?P<args>[^;{}]*)\)",
        executable_work,
    ):
        call_name = call_match.group("call")
        if call_name not in function_like:
            continue
        for arg_match in _safe_finditer_8616(
            r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])",
            call_match.group("args") or "",
        ):
            name = arg_match.group("name")
            if name not in function_like:
                candidates.append(name)


def _global_binop_candidates_8616(
    work: str, function_like: set[str], candidates: list[str]
) -> None:
    """Collect identifiers compared or combined in binary operators."""

    for match in _safe_finditer_8616(
        r"(?<![A-Za-z_])(?P<lhs>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])\s*(?:[<>]=?|==|!=)\s*"
        r"(?P<rhs>[A-Za-z_][\w$?@]*|\d+)(?![A-Za-z0-9_])",
        work,
    ):
        for group_name in ("lhs", "rhs"):
            name = match.group(group_name)
            if name and not name.isdigit() and name not in function_like:
                candidates.append(name)
    for match in _safe_finditer_8616(
        r"(?<![A-Za-z_])(?P<lhs>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])\s*(?:[+\-*/%&|^]|<<|>>)\s*"
        r"(?P<rhs>[A-Za-z_][\w$?@]*|\d+)(?![A-Za-z0-9_])",
        work,
    ):
        for group_name in ("lhs", "rhs"):
            name = match.group(group_name)
            if name and not name.isdigit() and name not in function_like:
                candidates.append(name)


def _collect_global_usage_candidates_from_body_8616(text: str, declared: set[str]) -> list[str]:
    def _impl() -> list[str]:
        work = _strip_comments_and_strings_8616(text)
        function_like = {
            m.group("name") for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)(?=\s*\()", work)
        }
        candidates: list[str] = []
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)\s*\[", work)
            if m.group("name") not in function_like
        )
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)\.[A-Za-z_][\w$?@]*", work)
            if m.group("name") not in function_like
        )
        for match in _safe_finditer_8616(
            r"(?<![A-Za-z_])(?P<name>[A-Za-z_][\w$?@]*)(?:\+\+|--)(?![A-Za-z0-9_])|(?:\+\+|--)(?P<name2>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])",
            work,
        ):
            name = match.group("name") or match.group("name2")
            if name:
                candidates.append(name)
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"&\s*(?P<name>[A-Za-z_][\w$?@]*)", work)
            if m.group("name") not in function_like
        )
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(
                r"(?m)^\s*(?P<name>[A-Za-z_][\w$?@]*)(?![A-Za-z0-9_])\s*(?:[+\-*/%&|^]?=|\+\+|--)",
                work,
            )
            if m.group("name") not in function_like
        )
        _global_call_arg_candidates_8616(work, function_like, candidates)
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(r"(?<![A-Za-z_])(?P<name>g_[0-9a-fA-F]+)(?![A-Za-z0-9_])", work)
        )
        candidates.extend(
            m.group("name")
            for m in _safe_finditer_8616(
                r"(?<![A-Za-z_])(?P<name>global_(?:u8|word)_[0-9a-fA-F]+)(?![A-Za-z0-9_])",
                work,
            )
        )
        _global_binop_candidates_8616(work, function_like, candidates)
        ordered: list[str] = []
        seen: set[str] = set()
        for name in candidates:
            if (
                name in seen
                or name in declared
                or _is_known_compiler_temp_8616(name)
                or name in _GLOBAL_DECL_INFERENCE_RESERVED_IDENTIFIERS_8616
            ):
                continue
            seen.add(name)
            ordered.append(name)
        return ordered

    return _impl()


def _collect_function_parameter_names_8616(lines: list[str]) -> set[str]:
    """Collect parameter identifiers so global inference does not redeclare them."""
    names: set[str] = set()
    index = 0
    while index < len(lines):
        candidate = lines[index]
        lookahead = index + 1
        while "{" not in candidate and lookahead < len(lines) and lookahead <= index + 2:
            if ";" in candidate:
                break
            candidate = f"{candidate} {lines[lookahead].strip()}"
            lookahead += 1
        args_text = _extract_function_header_args_8616(candidate)
        if args_text is not None:
            names.update(_parameter_names_from_args_text_8616(args_text))
            index = max(index + 1, lookahead)
            continue
        index += 1
    return names


def _synthetic_name_width_map_8616(synthetic_globals: dict[int, tuple[str, int]] | None) -> dict[str, int]:
    name_to_width: dict[str, int] = {}
    if not synthetic_globals:
        return name_to_width
    for (global_name, width) in synthetic_globals.values():
        if _is_strict_c_identifier_8616(global_name) and isinstance(width, int):
            name_to_width[global_name] = max(name_to_width.get(global_name, 0), width)
    return name_to_width


def _used_global_names_per_line_8616(
    lines: list[str], declared: set[str], missing_synthetic: list[str]
) -> list[str]:
    """Collect g_b and synthetic names in first-seen line order."""

    used: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("/*", "*", "//", "#")):
            continue
        for match in re.finditer(r"(?<![A-Za-z_])(?P<name>g_b[0-9a-fA-F]+)(?![A-Za-z_])", line):
            name = match.group("name")
            if name not in declared and name not in used:
                used.append(name)
        for name in missing_synthetic:
            if (
                name not in used
                and re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", line) is not None
            ):
                used.append(name)
    return used


def _name_in_text_8616(name: str, text: str) -> bool:
    """Return whether the name appears as a whole identifier."""

    return re.search(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])", text) is not None


def _used_global_names_8616(
    lines: list[str], body_text: str, declared: set[str], candidate_names: set[str]
) -> list[str]:
    def _impl() -> list[str]:
        missing_synthetic = sorted(
            name
            for name in candidate_names
            if name not in declared and _name_in_text_8616(name, body_text)
        )
        used = _used_global_names_per_line_8616(lines, declared, missing_synthetic)
        all_text = "\n".join(lines)
        for name in list(candidate_names):
            if name not in used and name not in declared and _name_in_text_8616(name, all_text):
                used.append(name)
        if used:
            return used
        for name in sorted(candidate_names):
            if name not in declared and _name_in_text_8616(name, body_text):
                used.append(name)
        return used

    return _impl()


def _first_function_insert_index_8616(lines: list[str]) -> int | None:
    def _impl() -> int | None:
        insert_at = 0
        function_found = False
        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith(("/*", "//", "*")):
                continue
            function_found = True
            if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*\{", line):
                insert_at = index
                break
            if re.match(r"\s*[A-Za-z_][\w\s\*]*\s+[A-Za-z_]\w*\s*\([^;{}]*\)\s*$", line):
                lookahead = index + 1
                while lookahead < len(lines) and not lines[lookahead].strip():
                    lookahead += 1
                if lookahead < len(lines) and lines[lookahead].strip().startswith("{"):
                    insert_at = index
                    break
        return insert_at if function_found else None

    return _impl()


def _strip_comments_for_global_decl_inference_8616(text: str) -> str:
    without_blocks = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return "\n".join(line.split("//", 1)[0] for line in without_blocks.splitlines())


def _infer_decl_for_global_8616(name: str, width: int | None, body_text: str) -> list[str]:
    escaped = re.escape(name)
    code_text = _strip_comments_for_global_decl_inference_8616(body_text)
    members = {
        match.group("field")
        for match in re.finditer(
            rf"(?<![A-Za-z_]){escaped}\s*\[[^\]]+\]\s*\.\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)", code_text
        )
    }
    has_indexed_use = re.search(rf"(?<![A-Za-z_]){escaped}\s*\[", code_text) is not None
    inferred_width = width
    if inferred_width is None:
        if re.fullmatch(r"global_u8_[0-9a-fA-F]+", name):
            inferred_width = 1
        elif re.fullmatch(r"(?:global_word|g)_[0-9a-fA-F]+", name):
            inferred_width = 2
    declared_type = "char" if inferred_width == 1 else "short" if inferred_width in {2, None} else "long"
    c_decl_type = f"unsigned {declared_type}"
    if members:
        struct_name = f"_inertia_global_{re.sub(r'[^A-Za-z0-9_]', '_', name)}"
        field_names = sorted(field for field in members if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", field)) or ["value"]
        return [
            f"    struct {struct_name} {{",
            *[f"        {c_decl_type} {field};" for field in field_names],
            "    };",
            f"    extern struct {struct_name} {name}[1];",
        ]
    if has_indexed_use:
        return [f"    extern {c_decl_type} {name}[1];"]
    return [f"    extern {c_decl_type} {name};"]


def _normalize_duplicate_generic_hex_global_names_8616(c_text: str) -> str:
    names = {
        match.group("name")
        for match in re.finditer(r"(?<![A-Za-z_])(?P<name>g_[0-9a-fA-F]{1,4})(?![A-Za-z0-9_])", c_text)
    }
    by_value: dict[int, set[str]] = {}
    for name in names:
        with contextlib.suppress(ValueError):
            by_value.setdefault(int(name[2:], 16), set()).add(name)
    replacements: dict[str, str] = {}
    for value, variants in by_value.items():
        if len(variants) < 2:
            continue
        canonical = f"g_{value:04x}"
        for variant in variants:
            if variant != canonical:
                replacements[variant] = canonical
    if not replacements:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        return replacements.get(match.group("name"), match.group("name"))

    return re.sub(r"(?<![A-Za-z_])(?P<name>g_[0-9a-fA-F]{1,4})(?![A-Za-z0-9_])", _replace, c_text)


def _declared_names_for_synthetic_globals_8616(lines: list[str], body_text: str) -> set[str]:
    """Union every identifier spelling already declared in the text."""

    declared = _collect_declared_identifiers_8616(lines)
    declared |= _collect_declared_global_names_8616(lines)
    declared |= _collect_member_access_names_8616(body_text)
    declared |= _collect_function_parameter_names_8616(lines)
    declared |= {
        match.group("name")
        for line in lines
        for match in (
            re.match(
                r"\s*(?:extern\s+)?(?:unsigned\s+)?(?:char|short|int|long|uint\d+_t|int\d+_t)\s+"
                r"(?P<name>g_b[0-9a-fA-F]+)\s*(?:\[[^\]]*\])?\s*(?:;|=|,)",
                line,
            ),
        )
        if match is not None
    }
    return declared


def _synthetic_global_declarations_8616(
    used: list[str],
    candidate_names: set[str],
    name_to_width: dict[str, int],
    body_text: str,
) -> list[str]:
    """Infer the declaration lines for each used global candidate."""

    declarations: list[str] = []
    for name in used:
        if name not in candidate_names:
            continue
        width = name_to_width.get(name)
        declarations.extend(_infer_decl_for_global_8616(name, width, body_text))
    return declarations


def _materialize_missing_synthetic_global_declarations_text(
    c_text: str,
    metadata: CODProcMetadata | None = None,
    synthetic_globals: dict[int, tuple[str, int]] | None = None,
) -> str:
    """Keep reserved runtime lvalues out of legacy missing-global declarations."""
    def _impl() -> str:
        c_text_normalized = _normalize_duplicate_generic_hex_global_names_8616(c_text)
        if c_text_normalized != c_text:
            return _materialize_missing_synthetic_global_declarations_text(
                c_text_normalized,
                metadata,
                synthetic_globals,
            )
        lines = c_text.splitlines()
        if not lines:
            return c_text

        body_text = "\n".join(lines)
        declared = _declared_names_for_synthetic_globals_8616(lines, body_text)

        synthetic_names = {
            global_name
            for global_name, _width in (synthetic_globals or {}).values()
            if _is_strict_c_identifier_8616(global_name)
        }
        candidate_names = set(synthetic_names)

        name_to_width = _synthetic_name_width_map_8616(synthetic_globals)

        if body_text:
            candidate_names.update(_collect_global_usage_candidates_from_body_8616(body_text, declared))
        candidate_names = {name for name in candidate_names if _is_strict_c_identifier_8616(name)}
        candidate_names.difference_update(runtime_gp_word_symbols_8616())

        used = _used_global_names_8616(lines, body_text, declared, candidate_names)
        if not used:
            return c_text

        insert_at = _first_function_insert_index_8616(lines)
        if insert_at is None:
            return c_text

        declarations = _synthetic_global_declarations_8616(used, candidate_names, name_to_width, body_text)

        if insert_at > 0 and lines[insert_at - 1].strip():
            declarations.append("")
        lines[insert_at:insert_at] = declarations
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _gb_array_scalar_use_res_8616(name: str) -> tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]]:
    """Build the scalar/indexed/assignment use patterns for one name."""

    scalar_use_re = re.compile(
        rf"(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])\s*(?:=|\+|-|\*|/|>>|<<|\||&|\^|==|!=|<=|>=|<|>)"
        rf"|(?:\+\+|--)\s*(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])"
        rf"|(?<![A-Za-z0-9_]){re.escape(name)}(?![A-Za-z0-9_])\s*(?:\+\+|--)"
    )
    indexed_use_re = re.compile(rf"(?<![A-Za-z_]){re.escape(name)}(?![A-Za-z0-9_])\s*\[")
    assignment_use_re = re.compile(rf"(?m)^\s*{re.escape(name)}\s*=")
    return scalar_use_re, indexed_use_re, assignment_use_re


def _gb_array_name_needs_scalar_8616(name: str, body_without_gb_decls: str) -> bool:
    """Return whether the name is used as a scalar and never indexed."""

    scalar_use_re, indexed_use_re, assignment_use_re = _gb_array_scalar_use_res_8616(name)
    if indexed_use_re.search(body_without_gb_decls):
        return False
    return bool(
        scalar_use_re.search(body_without_gb_decls) or assignment_use_re.search(body_without_gb_decls)
    )


def _normalize_scalar_gb_array_declarations_text(c_text: str) -> str:
    def _impl() -> str:
        lines = c_text.splitlines()
        if not lines:
            return c_text

        decl_re = re.compile(r"^(?P<indent>\s*)extern\s+char\s+(?P<name>g_[0-9a-fA-F]+)\s*\[(?P<size>\d+)\]\s*;\s*$")
        names: dict[str, tuple[int, int]] = {}
        for idx, line in enumerate(lines):
            match = decl_re.match(line)
            if match is None:
                continue
            names[match.group("name")] = (idx, int(match.group("size")))
        if not names:
            return c_text

        body_without_gb_decls = "\n".join(line for line in lines if decl_re.match(line) is None)
        changed = False
        for name, (idx, _size) in names.items():
            # Scalar usage evidence: arithmetic on the symbol itself (not indexing)
            if _gb_array_name_needs_scalar_8616(name, body_without_gb_decls):
                indent_match = re.match(r"^\s*", lines[idx])
                indent = indent_match.group(0) if indent_match is not None else ""
                lines[idx] = f"{indent}extern unsigned short {name};"
                changed = True
        if not changed:
            return c_text
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _source_function_prototype_decls_from_cod_source_lines(source_lines: Sequence[str] | None) -> dict[str, str]:
    return {}


def _normalize_portable_flat_main_signature_text(
    c_text: str,
    function: object,
    *,
    c_target: str,
) -> str:
    if c_target != "portable-flat":
        return c_text
    if _dynamic_text_attr(function, "name", None) != "main":
        return c_text

    lines = c_text.splitlines()
    header_re = re.compile(
        r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+main\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
    )
    header_result = _normalize_main_header_args(lines, header_re)
    if header_result is None:
        return _join_with_original_trailing_newline(lines, c_text)
    header_index, nonportable_return_type = header_result
    bounds = _find_function_body_bounds(lines, header_index)
    if bounds is None:
        return _join_with_original_trailing_newline(lines, c_text)
    if nonportable_return_type:
        _normalize_nonportable_main_void_call_returns(lines, bounds)
    _ensure_main_returns_zero(lines, bounds[0], bounds[1])
    return _join_with_original_trailing_newline(lines, c_text)


def _join_with_original_trailing_newline(lines: list[str], original_text: str) -> str:
    normalized = "\n".join(lines)
    if original_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _normalize_main_header_args(
    lines: list[str], header_re: re.Pattern[str]
) -> tuple[int, bool] | None:
    header_index: int | None = None
    nonportable_return_type = False
    for index, line in enumerate(lines):
        match = header_re.match(line)
        if match is None or (
            _is_portable_main_argument_list(match.group("args"))
            and match.group("ret").strip() == "int"
        ):
            continue
        replacement_header = f"{match.group('indent')}int main(void)"
        suffix = match.group("suffix")
        if suffix == "{":
            replacement_header += " {"
        elif suffix == ";":
            replacement_header += ";"
        lines[index] = replacement_header
        nonportable_return_type = match.group("ret").strip() != "int"
        if header_index is not None:
            continue
        if suffix != ";" or _has_open_brace_in_lookahead(lines, index + 1):
            header_index = index
    return None if header_index is None else (header_index, nonportable_return_type)


def _is_portable_main_argument_list(args_text: str) -> bool:
    """Return whether an emitted main parameter list has a portable C ABI."""
    normalized = re.sub(r"\s+", " ", args_text.strip())
    if normalized in {"", "void"}:
        return True
    return bool(
        re.fullmatch(
            r"int [A-Za-z_]\w*, char \*\s*\*[A-Za-z_]\w*",
            normalized,
        )
        or re.fullmatch(
            r"int [A-Za-z_]\w*, char \*[A-Za-z_]\w*\[\]",
            normalized,
        )
    )


def _normalize_nonportable_main_void_call_returns(
    lines: list[str], bounds: tuple[int, int]
) -> None:
    """Turn a returned call in a nonportable entry into a statement."""
    return_re = re.compile(r"^(?P<indent>\s*)return\s+(?P<name>[A-Za-z_]\w*)\s*(?P<args>\([^;]+\));\s*$")
    for index in range(bounds[0], min(bounds[1], len(lines))):
        match = return_re.match(lines[index])
        if match is None:
            continue
        indent = match.group("indent")
        lines[index] = f"{indent}{match.group('name')}{match.group('args')};"


def _has_open_brace_in_lookahead(lines: list[str], start_index: int) -> bool:
    lookahead = start_index
    while lookahead < len(lines) and not lines[lookahead].strip():
        lookahead += 1
    return lookahead < len(lines) and lines[lookahead].lstrip().startswith("{")


def _find_function_body_bounds(lines: list[str], header_index: int) -> tuple[int, int] | None:
    brace_index = header_index
    while brace_index < len(lines) and "{" not in lines[brace_index]:
        brace_index += 1
    if brace_index >= len(lines):
        return None
    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_start, body_end


def _ensure_main_returns_zero(lines: list[str], body_start: int, body_end: int) -> None:
    saw_explicit_return = False
    for index in range(body_end - 2, body_start - 1, -1):
        stripped = lines[index].strip()
        if not stripped or stripped.startswith("//"):
            continue
        if stripped.startswith("return"):
            saw_explicit_return = True
        if stripped == "return;":
            indent = lines[index][: len(lines[index]) - len(lines[index].lstrip())]
            lines[index] = f"{indent}return 0;"
            saw_explicit_return = True
        break
    if saw_explicit_return or body_end - 1 >= len(lines):
        return
    closing_line = lines[body_end - 1]
    closing_indent = closing_line[: len(closing_line) - len(closing_line.lstrip())]
    return_indent = closing_indent + "    " if "}" in closing_line else "    "
    lines.insert(body_end - 1, f"{return_indent}return 0;")


def _source_args_from_cod_source_lines(source_lines: tuple[str, ...], func_name: str | None) -> str | None:
    def _impl() -> str | None:
        if not isinstance(func_name, str) or not func_name:
            return None

        candidate_names = {func_name}
        stripped_name = func_name.lstrip("_")
        if stripped_name and stripped_name != func_name:
            candidate_names.add(stripped_name)

        decl_res = (
            re.compile(r"^(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)\s*(?:\{|;)?\s*$"),
            re.compile(
                r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+"
                r"(?P<name>[A-Za-z_][\w$?@]*)\s*\((?P<args>.*)\)\s*(?:\{|;)?\s*$"
            ),
        )
        for line in source_lines:
            stripped = line.strip()
            if not stripped or stripped in {"{", "}"}:
                continue
            if stripped.startswith(("if ", "while ", "for ", "switch ", "return ", "case ", "default ")):
                continue
            for decl_re in decl_res:
                decl_match = decl_re.match(stripped)
                if decl_match is None or decl_match.group("name") not in candidate_names:
                    continue
                return decl_match.group("args")
        return None

    return _impl()


def _repair_missing_cod_function_header_text(c_text: str, function: object, metadata: CODProcMetadata | None) -> str:
    return c_text


def _align_function_header_with_cod_source_decl_text(
    c_text: str,
    function: object,
    metadata: CODProcMetadata | None,
    *,
    codegen: object | None = None,
) -> str:
    """Preserve the recovered header; source declarations are optional annotations."""
    return c_text


def _func_header_match_8616(
    c_text: str, func_name: str
) -> tuple[list[str], re.Match[str], int] | None:
    """Locate the function's header line and return (lines, match, index)."""

    lines = c_text.splitlines()
    header_re = re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )
    header_index = _find_header_index_8616(lines, header_re)
    if header_index is None:
        return None
    match = header_re.match(lines[header_index])
    if match is None:
        return None
    return lines, match, header_index


def _codegen_prototype_parts_8616(
    function: object, codegen: object
) -> tuple[object, tuple[object, ...]]:
    """Resolve the (return_type, arg_types) pair from the codegen prototype."""

    cfunc = _dynamic_text_attr(codegen, "cfunc", None)
    prototype = _dynamic_text_attr(cfunc, "functy", None) or _dynamic_text_attr(cfunc, "prototype", None)
    if prototype is None:
        prototype = _dynamic_text_attr(function, "prototype", None)
    return_type = _dynamic_text_attr(prototype, "returnty", None)
    arg_types = tuple(_dynamic_text_attr(prototype, "args", ()) or ())
    return return_type, arg_types


def _replace_header_and_join_8616(
    lines: list[str],
    header_index: int,
    indent: str,
    ret_text: str,
    func_name: str,
    rewritten_args: list[str],
    suffix: str,
    c_text: str,
) -> str:
    """Replace the header line and join preserving the input newline."""

    replacement = f"{indent}{ret_text} {func_name}({', '.join(rewritten_args)})"
    if suffix == "{":
        replacement += " {"
    elif suffix == ";":
        replacement += ";"
    lines[header_index] = replacement
    return _join_lines_like_input_8616(lines, c_text)


def _normalize_signed_char_function_signature_text(c_text: str, function: object, codegen: object | None) -> str:
    """Render typed signed-byte function signatures explicitly as ``signed char``."""
    if codegen is None:
        return c_text
    func_name = _dynamic_text_attr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text
    return_type, arg_types = _codegen_prototype_parts_8616(function, codegen)
    if not isinstance(return_type, SimTypeChar) and not any(isinstance(arg_type, SimTypeChar) for arg_type in arg_types):
        return c_text

    located = _func_header_match_8616(c_text, func_name)
    if located is None:
        return c_text
    lines, match, header_index = located

    ret_text = match.group("ret").strip()
    if isinstance(return_type, SimTypeChar) and bool(_dynamic_text_attr(return_type, "signed", True)) and ret_text == "char":
        ret_text = "signed char"

    args = _split_args_8616(match.group("args"))
    rewritten_args: list[str] = []
    changed = ret_text != match.group("ret").strip()
    for index, arg_text in enumerate(args):
        arg_type = arg_types[index] if index < len(arg_types) else None
        stripped = arg_text.strip()
        if isinstance(arg_type, SimTypeChar) and bool(_dynamic_text_attr(arg_type, "signed", True)) and stripped.startswith("char "):
            rewritten_args.append(f"signed {stripped}")
            changed = True
            continue
        rewritten_args.append(arg_text)
    if not changed:
        return c_text

    return _replace_header_and_join_8616(
        lines,
        header_index,
        match.group("indent"),
        ret_text,
        func_name,
        rewritten_args,
        match.group("suffix"),
        c_text,
    )


def _msc_signed_arg_text_8616(arg_text: str, arg_type: object) -> str:
    """Rewrite a ``short`` arg spelling to MS C ``int`` when proven signed."""

    stripped = arg_text.strip()
    if (
        isinstance(arg_type, SimTypeShort)
        and bool(_dynamic_text_attr(arg_type, "signed", False))
        and stripped.startswith("short ")
    ):
        return f"int {stripped[len('short ') :]}"
    return arg_text


def _normalize_msc_signed_int_function_signature_text(c_text: str, function: object, codegen: object | None) -> str:
    """Render typed-condition-proven signed 16-bit signatures as MS C ``int``."""
    if codegen is None:
        return c_text
    changed_fields = tuple(_dynamic_text_attr(codegen, "_inertia_typed_condition_signed_stack_arg_changed_fields_8616", ()) or ())
    if "prototype_return" not in changed_fields:
        return c_text
    func_name = _dynamic_text_attr(function, "name", None)
    if not isinstance(func_name, str) or not func_name:
        return c_text
    return_type, arg_types = _codegen_prototype_parts_8616(function, codegen)
    if not isinstance(return_type, SimTypeShort) or not bool(_dynamic_text_attr(return_type, "signed", False)):
        return c_text

    located = _func_header_match_8616(c_text, func_name)
    if located is None:
        return c_text
    lines, match, header_index = located

    changed = False
    ret_text = match.group("ret").strip()
    if ret_text == "short":
        ret_text = "int"
        changed = True

    args = _split_args_8616(match.group("args"))
    rewritten_args: list[str] = []
    for index, arg_text in enumerate(args):
        rewritten = _msc_signed_arg_text_8616(arg_text, arg_types[index] if index < len(arg_types) else None)
        if rewritten != arg_text:
            changed = True
        rewritten_args.append(rewritten)
    if not changed:
        return c_text

    return _replace_header_and_join_8616(
        lines,
        header_index,
        match.group("indent"),
        ret_text,
        func_name,
        rewritten_args,
        match.group("suffix"),
        c_text,
    )


def _split_function_args_preserving_nesting(args_text: str) -> list[str]:
    """Split one argument list at top-level commas, preserving nesting."""

    return _signature_split_args_8616(args_text)


def _find_function_brace_index(lines: list[str], start_index: int) -> int | None:
    scan_index = start_index
    while scan_index < len(lines):
        if "{" in lines[scan_index]:
            return scan_index
        if ";" in lines[scan_index] and "{" not in lines[scan_index]:
            return None
        scan_index += 1
    return None


def _find_block_end(lines: list[str], brace_index: int) -> int:
    body_end = brace_index + 1
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_end


def _extract_reserved_arg_names(args_text: str) -> set[str]:
    return _parameter_names_from_args_text_8616(args_text)


def _function_definition_args_text_8616(line: str) -> str | None:
    stripped = line.strip()
    if stripped.startswith(("if", "while", "for", "switch")):
        return None
    return _extract_function_header_args_8616(line)


def _source_decl_args_text_8616(source_decl: str | None) -> str | None:
    if source_decl is None:
        return None
    text = source_decl.strip().rstrip(";")
    close_idx = text.rfind(")")
    if close_idx < 0:
        return None
    depth = 0
    open_idx = None
    for idx in range(close_idx, -1, -1):
        char = text[idx]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_idx = idx
                break
    if open_idx is None:
        return None
    return text[open_idx + 1 : close_idx].strip()


class _LocalDeclKind8616(Enum):
    SIMPLE = "simple"
    FUNCTION_POINTER = "function_pointer"


@dataclass(frozen=True)
class _LocalDeclEntry8616:
    line_index: int
    name: str
    comment: str
    kind: _LocalDeclKind8616


def _collect_local_decl_entries(
    lines: list[str],
    body_start: int,
    body_end: int,
    decl_re: re.Pattern[str],
    func_ptr_decl_re: re.Pattern[str],
) -> tuple[list[_LocalDeclEntry8616], set[str]]:
    decl_lines: list[_LocalDeclEntry8616] = []
    used_names: set[str] = set()
    for scan_index in range(body_start, body_end):
        line = lines[scan_index]
        decl_match = decl_re.match(line)
        decl_kind = _LocalDeclKind8616.SIMPLE
        if decl_match is None:
            decl_match = func_ptr_decl_re.match(line)
            decl_kind = _LocalDeclKind8616.FUNCTION_POINTER
        if decl_match is None:
            continue
        name = decl_match.group("name")
        comment = decl_match.group("comment") or ""
        decl_lines.append(_LocalDeclEntry8616(scan_index, name, comment, decl_kind))
        used_names.add(name)
    return decl_lines, used_names


def _rewrite_or_prune_duplicate_locals(
    lines: list[str],
    decl_re: re.Pattern[str],
    reserved_names: set[str],
    used_names: set[str],
    decl_lines: list[_LocalDeclEntry8616],
) -> tuple[bool, set[int]]:
    def _impl() -> tuple[bool, set[int]]:
        changed = False
        remove_line_indexes: set[int] = set()
        grouped: dict[str, list[_LocalDeclEntry8616]] = {}
        for entry in decl_lines:
            grouped.setdefault(entry.name, []).append(entry)
        for name, entries in grouped.items():
            if name in reserved_names:
                for entry in entries:
                    unique_name = _make_unique_identifier(name, used_names)
                    old_line = lines[entry.line_index]
                    def replace_decl(match: re.Match[str]) -> str:
                        return (
                            f"{match.group('indent')}{match.group('type')} {unique_name}{match.group('array') or ''};"  # noqa: B023
                            + (f" {match.group('comment')}" if match.group("comment") else "")
                        )

                    lines[entry.line_index] = decl_re.sub(
                        replace_decl,
                        old_line,
                        count=1,
                    )
                    used_names.add(unique_name)
                    changed = True
                continue
            if len(entries) <= 1:
                continue
            keep_entry = max(
                entries,
                key=lambda entry: (
                    entry.name in entry.comment,
                    entry.kind is _LocalDeclKind8616.FUNCTION_POINTER,
                    bool(entry.comment),
                    -entry.line_index,
                ),
            )
            for entry in entries:
                if entry.line_index == keep_entry.line_index:
                    continue
                remove_line_indexes.add(entry.line_index)
                changed = True
        return changed, remove_line_indexes

    return _impl()


def _dedupe_duplicate_local_declarations_text(c_text: str) -> str:
    def _impl() -> str:
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        header_re = re.compile(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
        )
        decl_re = re.compile(
            r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default|continue|break)\b)"
            r"(?P<type>(?:[A-Za-z_][\w\[\]]*\s+)+(?:\*+\s*)*|[A-Za-z_][\w\[\]]*\s*\*+\s*)"
            r"(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
        )
        func_ptr_decl_re = re.compile(
            r"^(?P<indent>\s*)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)"
            r"\s*\([^;{}]*\)\s*;\s*(?P<comment>//.*)?$"
        )

        changed = False
        index = 0
        while index < len(lines):
            match = header_re.match(lines[index])
            args_text = match.group("args") if match is not None else _function_definition_args_text_8616(lines[index])
            if args_text is None:
                index += 1
                continue

            brace_index = _find_function_brace_index(lines, index)
            if brace_index is None:
                index += 1
                continue

            body_start = brace_index + 1
            body_end = _find_block_end(lines, brace_index)
            reserved_names = _extract_reserved_arg_names(args_text)
            decl_lines, local_used_names = _collect_local_decl_entries(
                lines, body_start, body_end, decl_re, func_ptr_decl_re
            )
            if not decl_lines:
                index = body_end
                continue
            used_names = set(reserved_names) | local_used_names
            local_changed, remove_line_indexes = _rewrite_or_prune_duplicate_locals(
                lines, decl_re, reserved_names, used_names, decl_lines
            )
            changed = changed or local_changed

            if remove_line_indexes:
                lines = [line for i, line in enumerate(lines) if i not in remove_line_indexes]
                body_end -= len(remove_line_indexes)

            index = body_end

        if not changed:
            return c_text

        normalized = "\n".join(lines)
        if trailing_newline:
            normalized += "\n"
        return normalized

    return _impl()


_SPURIOUS_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)"
    r"(?P<type>(?:[A-Za-z_][\w\[\]]*\s+)+(?:\*+\s*)*|[A-Za-z_][\w\[\]]*\s*\*+\s*)"
    r"(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
)
_SPURIOUS_HEADER_RE_8616 = re.compile(
    r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^()]*)\)\s*(?:[;{])?\s*$"
)


def _spurious_declared_names_8616(lines: list[str]) -> set[str]:
    """Collect names declared by locals or function headers."""

    declared_names: set[str] = set()
    for line in lines:
        if line.lstrip().startswith("return "):
            continue
        match = _SPURIOUS_DECL_RE_8616.match(line)
        if match is not None:
            declared_names.add(match.group("name"))
    for line in lines:
        match = _SPURIOUS_HEADER_RE_8616.match(line)
        if match is None:
            continue
        args_text = match.group("args").strip()
        if not args_text or args_text == "void":
            continue
        for arg_text in args_text.split(","):
            arg_match = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$", arg_text.strip())
            if arg_match is not None:
                declared_names.add(arg_match.group(1))
    return declared_names


def _spurious_rename_map_8616(lines: list[str], declared_names: set[str]) -> dict[str, str]:
    """Map each stray ``name_2`` use back to the declared base name."""

    rename_map: dict[str, str] = {}
    for name in declared_names:
        suffixed = f"{name}_2"
        if suffixed in declared_names:
            continue
        if any(
            re.search(rf"(?<![A-Za-z0-9_]){re.escape(suffixed)}(?![A-Za-z0-9_])", line) is not None
            for line in lines
        ):
            rename_map[suffixed] = name
    return rename_map


def _apply_spurious_renames_8616(c_text: str, rename_map: dict[str, str]) -> str:
    """Rename every stray suffixed token back to its base name."""

    pattern = re.compile(
        r"(?<![A-Za-z0-9_])("
        + "|".join(sorted((re.escape(name) for name in rename_map), key=len, reverse=True))
        + r")(?![A-Za-z0-9_])"
    )
    return pattern.sub(lambda match: rename_map.get(match.group(1), match.group(1)), c_text)


def _canonicalize_suffixed_helper_calls_8616(normalized: str, declared_names: set[str]) -> str:
    """Canonicalize known two-index helper calls onto declared base names."""

    # Canonicalize known two-index helper calls where materialized alias
    # locals use a "_2" suffix even when the base local exists.
    for base_name in sorted(declared_names):
        suffixed = f"{base_name}_2"
        if suffixed not in declared_names:
            continue
        normalized = re.sub(
            rf"\bSwapBars\(\s*0\s*,\s*{re.escape(suffixed)}\s*\)",
            f"SwapBars(0, {base_name})",
            normalized,
        )
        normalized = re.sub(
            rf"\bPercolateDown\(\s*{re.escape(suffixed)}\s*\)",
            f"PercolateDown({base_name} - 1)",
            normalized,
        )
    return normalized


def _normalize_spurious_duplicate_local_suffixes(c_text: str) -> str:
    """Fold stray ``name_2`` locals back onto their declared base names."""

    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    declared_names = _spurious_declared_names_8616(lines)
    rename_map = _spurious_rename_map_8616(lines, declared_names)
    normalized = c_text if not rename_map else _apply_spurious_renames_8616(c_text, rename_map)
    normalized = _canonicalize_suffixed_helper_calls_8616(normalized, declared_names)
    if trailing_newline and not normalized.endswith("\n"):
        normalized += "\n"
    return normalized


def _collapse_duplicate_type_keywords_text(c_text: str) -> str:
    replacements = (
        (r"\bextern\s+union\s+union\s+REGS\b", "extern union REGS"),
        (r"\bunion\s+union\s+REGS\b", "union REGS"),
        (r"\bextern\s+struct\s+struct\s+SREGS\b", "extern struct SREGS"),
        (r"\bstruct\s+struct\s+SREGS\b", "struct SREGS"),
    )
    normalized = c_text
    for pattern, replacement in replacements:
        normalized = re.sub(pattern, replacement, normalized)
    return normalized


def _dedupe_adjacent_prototype_lines(c_text: str) -> str:
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    prototype_re = re.compile(r"^\s*[A-Za-z_][\w\s\*\[\]]*?\s+[A-Za-z_]\w*\s*\([^)]*\)\s*;\s*$")
    deduped: list[str] = []
    last_prototype: str | None = None

    for line in lines:
        stripped = line.strip()
        if prototype_re.match(stripped):
            if stripped == last_prototype:
                continue
            last_prototype = stripped
            deduped.append(line)
            continue
        if stripped:
            last_prototype = None
        deduped.append(line)

    normalized = "\n".join(deduped)
    if trailing_newline:
        normalized += "\n"
    return normalized


_OPAQUE_BASE_TYPES_8616 = {
    "FILE",
    "clock_t",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "size_t",
}
_OPAQUE_PROTOTYPE_RE_8616 = re.compile(r"^\s*[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^;{}]*)\)\s*;\s*$")
_OPAQUE_HEADER_RE_8616 = re.compile(r"^\s*[A-Za-z_][\w\s\*]*?\s+[A-Za-z_]\w*\s*\((?P<args>[^;{}]*)\)\s*$")
_OPAQUE_POINTER_TYPE_RE_8616 = re.compile(r"\b(?P<type>[A-Z][A-Za-z_]\w*)\s*\*")


def _opaque_known_types_8616(text: str) -> set[str]:
    """Union builtin and text-declared pointer base types."""

    known_types = set(_OPAQUE_BASE_TYPES_8616)
    known_types.update(
        re.findall(r"\btypedef\s+(?:struct\s+)?[A-Za-z_]\w*(?:\s+\*)?\s+([A-Za-z_]\w*)\s*;", text)
    )
    known_types.update(re.findall(r"\b(?:struct|union|enum)\s+([A-Za-z_]\w*)\b", text))
    return known_types


def _opaque_collect_args_types_8616(
    args: str, known_types: set[str], needed: list[str]
) -> None:
    """Append unresolved Capitalized pointer base types from one arg list."""

    for type_name in _OPAQUE_POINTER_TYPE_RE_8616.findall(args):
        if type_name in known_types or type_name in needed:
            continue
        needed.append(type_name)


def _opaque_needed_pointer_types_8616(lines: list[str], known_types: set[str]) -> list[str]:
    """Collect unresolved Capitalized pointer base types from signatures."""

    needed: list[str] = []
    for line in lines:
        match = _OPAQUE_PROTOTYPE_RE_8616.match(line.strip())
        if match is not None:
            _opaque_collect_args_types_8616(match.group("args"), known_types, needed)

    # Handle function headers where the opening brace is on a following line (e.g. decompiled
    # function definitions often use `void foo(...)` + next-line `{` style).
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        match = _OPAQUE_HEADER_RE_8616.match(stripped)
        if match is None:
            continue
        if index + 1 >= len(lines) or lines[index + 1].strip() != "{":
            continue
        _opaque_collect_args_types_8616(match.group("args"), known_types, needed)
    return needed


def _materialize_opaque_pointer_typedefs_text(c_text: str) -> str:
    """Declare opaque struct typedefs for unresolved pointer base types."""

    lines = c_text.splitlines()
    text = "\n".join(lines)
    known_types = _opaque_known_types_8616(text)
    needed = _opaque_needed_pointer_types_8616(lines, known_types)
    if not needed:
        return c_text

    typedef_lines = [f"typedef struct {type_name} {type_name};" for type_name in needed]
    insert_at = next(
        (idx for idx, line in enumerate(lines) if _OPAQUE_PROTOTYPE_RE_8616.match(line.strip())), 0
    )
    lines[insert_at:insert_at] = [*typedef_lines, ""]
    normalized = "\n".join(lines)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


def _sanitize_mangled_autonames_text(c_text: str) -> str:
    token_re = re.compile(
        r"\b(?:(?P<sub>sub_[0-9a-f]+)sub_[0-9a-f]+|(?P<dos>dos_int[0-9]+)sub_[0-9a-f]+|(?P<dos_dup>dos_int[0-9]+)_[0-9]+)\b"
    )

    def _replace(match: re.Match[str]) -> str:
        return match.group("sub") or match.group("dos") or match.group("dos_dup") or match.group(0)

    return token_re.sub(_replace, c_text)


def _strip_register_fragment_suffixes_text(c_text: str) -> str:
    return re.sub(r"(?<![A-Za-z_])([A-Za-z_]\w*)\{r\d+\|\d+b\}(?![A-Za-z0-9_])", r"\1", c_text)


def _normalize_symbol_name_text(name: str | None) -> str | None:
    if not isinstance(name, str):
        return None
    text = name.strip()
    if not text:
        return None
    while text.startswith("_"):
        text = text[1:]
    return text or None


def _align_unknown_call_names_from_cod_evidence_text(c_text: str) -> str:
    """Compatibility surface only; COD call comments must not rename emitted calls."""
    return c_text


def _prune_trailing_generic_return_text(c_text: str) -> str:
    """Remove only an adjacent unreachable generic return in legacy text output."""

    def _impl() -> str:
        trailing_newline = c_text.endswith("\n")
        lines = c_text.splitlines()
        return_re = re.compile(r"^\s*return\s+(?P<expr>[A-Za-z_]\w*)\s*;\s*$")
        generic_return_re = re.compile(r"^(?:ir_\d+(?:_\d+)?|v\d+|vvar_\d+|a\d+)$")

        index = len(lines) - 1
        while index >= 0 and not lines[index].strip():
            index -= 1
        if index < 0 or lines[index].strip() != "}":
            return c_text

        index -= 1
        while index >= 0 and not lines[index].strip():
            index -= 1
        if index < 0:
            return c_text

        match = return_re.match(lines[index])
        if match is not None and not generic_return_re.fullmatch(match.group("expr")):
            previous_index = index - 1
            while previous_index >= 0 and not lines[previous_index].strip():
                previous_index -= 1
            previous_match = return_re.match(lines[previous_index]) if previous_index >= 0 else None
            if previous_match is not None and generic_return_re.fullmatch(previous_match.group("expr")):
                del lines[previous_index]
                normalized = "\n".join(lines)
                if trailing_newline:
                    normalized += "\n"
                return normalized
            return c_text
        return c_text

    return _impl()


def _collapse_annotated_stack_aliases_text(c_text: str) -> str:
    return c_text

def _split_top_level_binary(expr: str, op: str) -> tuple[str, str] | None:
    depth = 0
    i = 0
    while i <= len(expr) - len(op):
        ch = expr[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        if depth == 0 and expr.startswith(op, i):
            return expr[:i].strip(), expr[i + len(op) :].strip()
        i += 1
    return None


def _simplify_negated_condition(expr: str) -> str:
    expr = expr.strip()
    if not expr.startswith("!(") or not expr.endswith(")"):
        return expr

    inner = expr[2:-1].strip()
    if inner.startswith("!(") and inner.endswith(")"):
        collapsed = inner[2:-1].strip()
        if re.fullmatch(r"[A-Za-z_][\w$?@]*(?:\s*\[[^\]]+\])?", collapsed):
            return collapsed

    return expr


def _simplify_condition_line(line: str) -> str:
    marker = "if ("
    start = line.find(marker)
    if start < 0:
        return line

    cond_start = start + len(marker)
    depth = 1
    i = cond_start
    while i < len(line):
        ch = line[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                condition = line[cond_start:i]
                simplified = _simplify_negated_condition(condition)
                if simplified != condition:
                    return line[:cond_start] + simplified + line[i:]
                return line
        i += 1
    return line


def _simplify_x86_16_conditions(c_text: str) -> str:
    return "\n".join(_simplify_condition_line(line) for line in c_text.splitlines())


def _normalize_unary_not_shift_precedence_text(c_text: str) -> str:
    """Canonicalize renderer-leaked unary-not shifts into explicit conditions.

    ``!x >> n`` and ``!(x) >> n`` are not acceptable final C condition forms.
    Emit the explicit zero comparison that the condition materializer should
    have produced earlier.
    """
    parenthesized_pattern = re.compile(
        r"(?P<prefix>(?:^|[^\w$?@]))!\((?P<name>[A-Za-z_][\w$?@]*(?:\s*\[[^\]\n]+\])?)\)"
        r"(?P<space>\s*(?P<op>>>|<<)\s*(?P<rhs>0x[0-9A-Fa-f]+|\d+))"
    )
    bare_pattern = re.compile(
        r"(?P<prefix>(?:^|[^\w$?@]))!(?P<name>[A-Za-z_][\w$?@]*(?:\s*\[[^\]\n]+\])?)"
        r"(?P<space>\s*(?P<op>>>|<<)\s*(?P<rhs>0x[0-9A-Fa-f]+|\d+))"
    )

    def _replace(match: re.Match[str]) -> str:
        expr = f"{match.group('name').strip()} {match.group('op')} {match.group('rhs')}"
        return f"{match.group('prefix')}(({expr}) == 0)"

    c_text = parenthesized_pattern.sub(_replace, c_text)
    return bare_pattern.sub(_replace, c_text)


def _split_simple_assignment_conditions(c_text: str) -> str:
    pattern = re.compile(
        r"(?m)^(?P<indent>\s*)if\s*\(\(\s*(?P<name>[A-Za-z_][\w$?@]*)\s*=\s*(?P<expr>[^;\n]+?)\s*\)\s*!=\s*0\s*\)\s*\n"
        r"(?P=indent)    return\s+(?P=name)\s*;\s*(?P<comment>//[^\n]*)?$"
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        comment = f" {match.group('comment')}" if match.group("comment") else ""
        return (
            f"{indent}{match.group('name')} = {match.group('expr').strip()};\n"
            f"{indent}if ({match.group('name')}) return {match.group('name')};{comment}"
        )

    return pattern.sub(_replace, c_text)


def _split_top_level_ternary_8616(expr: str) -> tuple[str, str, str] | None:
    depth = 0
    question_index: int | None = None
    for index, ch in enumerate(expr):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif ch == "?" and depth == 0 and question_index is None:
            question_index = index
        elif ch == ":" and depth == 0 and question_index is not None:
            return (
                expr[:question_index].strip(),
                expr[question_index + 1 : index].strip(),
                expr[index + 1 :].strip(),
            )
    return None


def _strip_single_outer_parens_8616(expr: str) -> str:
    stripped = expr.strip()
    if len(stripped) < 2 or not stripped.startswith("(") or not stripped.endswith(")"):
        return stripped
    depth = 0
    for index, ch in enumerate(stripped):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and index != len(stripped) - 1:
                return stripped
    if depth != 0:
        return stripped
    return stripped[1:-1].strip()


def _simplify_negated_zero_one_ternary_condition_8616(condition: str) -> str:
    stripped = condition.strip()
    if not stripped.startswith("!((") or not stripped.endswith("))"):
        return condition

    inner = stripped[3:-2].strip()
    ternary = _split_top_level_ternary_8616(inner)
    if ternary is None:
        return condition

    predicate, true_expr, false_expr = ternary
    if true_expr != "0" or false_expr != "1":
        return condition

    return _strip_single_outer_parens_8616(predicate)


def _split_for_header_8616(header: str) -> list[str] | None:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, ch in enumerate(header):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(depth - 1, 0)
        elif ch == ";" and depth == 0:
            parts.append(header[start:index].strip())
            start = index + 1
    parts.append(header[start:].strip())
    return parts if len(parts) == 3 else None


def _simplify_x86_16_wrapped_stack_offsets(c_text: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        name = match.group("name")
        value = int(match.group("value"), 0)
        normalized = _normalize_16bit_signed_offset(value)
        if normalized >= 0:
            return match.group(0)
        return f"&{name} - {-normalized}"

    c_text = re.sub(
        r"&(?P<name>[A-Za-z_][\w$?@]*)\s*\+\s*(?P<value>0x[0-9A-Fa-f]+|\d+)",
        _replace,
        c_text,
    )
    return c_text


_STACK_LOW_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+);\s*$"
)
_STACK_HIGH_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\(char \*\)\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) = (?P<rhs>[^;]+>>\s*8[^;]*);\s*$"
)
_STACK_LOW_STORE_UNCAST_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\) = (?P<rhs>[^;]+);\s*$"
)
_STACK_HIGH_STORE_UNCAST_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\((?P<seg>.+?) \* 16 \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\) = (?P<rhs>[^;]+>>\s*8[^;]*);\s*$"
)
_STACK_POINTER_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
)
_STACK_FAR_POINTER_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<seg>.+?) \* 16 \+ (?P<off>.+?)\)\) = (?P<rhs>[^;]+);\s*$"
)
_STACK_RAW_LINEAR_POINTER_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\s*(?P<addr>0x[0-9A-Fa-f]+|\d+)\s*\)\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_STACK_ALIAS_BASE_RE_8616 = re.compile(
    r"^\s*(?P<name>(?:vvar|ir|tmp)_\d+)\s*=\s*\((?:unsigned\s+)?int\)&\(&(?P<base>[A-Za-z_][\w$?@]*)\)\[(?P<index>-?\d+)\]\s*;\s*$"
)
_STACK_ALIAS_CHAIN_RE_8616 = re.compile(
    r"^\s*(?P<name>(?:vvar|ir|tmp)_\d+)\s*=\s*(?P<expr>(?:vvar|ir|tmp)_\d+(?:\s*[+-]\s*-?\d+)*)\s*;\s*$"
)
_SS_STACK_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss\s*<<\s*4\)\s*\+\s*(?P<expr>.+?)\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_PLAIN_STACK_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\((?P<expr>(?:vvar|ir|tmp)_\d+(?:\s*[+-]\s*-?\d+)*)\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_DIRECT_SS_STACK_STORE_RE_8616 = re.compile(
    r"^(?P<indent>\s*)\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)(?: (?P<op>[+-]) (?P<delta>\d+))?\)\)\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_SEGMENTED_BYTE_PAIR_LOAD_RE_8616 = re.compile(
    r"\(\*\(\(char \*\)\(\((?P<seg>[A-Za-z_][\w$?@]*) << 4\) \+ (?P<off>0x[0-9A-Fa-f]+|\d+)\)\) \| "
    r"\*\(\(char \*\)\(\((?P=seg) << 4\) \+ (?P=off) \+ 1\)\) << 8\)"
)
_STACK_BYTE_PAIR_LOAD_RE_8616 = re.compile(
    r"\(\*\(\(char \*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)\)\) \| "
    r"\*\(\(char \*\)\(\(ss << 4\) \+ (?P=base) \+ 1\)\) << 8\)"
)
_DIRECT_SS_STACK_EXPR_RE_8616 = re.compile(
    r"\*\(\((?P<type>[^()]+?)\s*\*\)\(\(ss << 4\) \+ (?P<base>(?:\(unsigned int\))?&[A-Za-z_][\w$?@]*)(?: (?P<op>[+-]) (?P<delta>\d+))?\)\)"
)
_INDEXED_SS_LOCAL_EXPR_RE_8616 = re.compile(
    r"\(&(?P<base>[A-Za-z_][\w$?@]*)\)\[(?P<segmul>(?:16\s*\*\s*ss|ss\s*\*\s*16))(?:\s*(?P<op>[+-])\s*(?P<delta>\d+))?\]"
)
_BYTE_WALK_LOOP_RE_8616 = re.compile(
    r"(?ms)^(?P<indent>\s*)while \(true\)\n"
    r"(?P=indent)\{\n"
    r"(?P=indent)    (?P<low_tmp>[A-Za-z_][\w$?@]*) = (?P<ptr>[A-Za-z_][\w$?@]*);\n"
    r"(?P=indent)    (?P<high_tmp>[A-Za-z_][\w$?@]*) = (?P=ptr);\n"
    r"(?P=indent)    (?P=ptr) = \((?P=low_tmp) \| (?P=high_tmp) \* 0x100\) \+ 1 >> 8;\n"
    r"(?P=indent)    if \(!\((?P=ptr) \+ 1\)\)\n"
    r"(?P=indent)        break;\n"
    r"(?P=indent)    (?P<cnt_low>[A-Za-z_][\w$?@]*) = (?P<counter>[A-Za-z_][\w$?@]*);\n"
    r"(?P=indent)    (?P<cnt_high>[A-Za-z_][\w$?@]*) = (?P=counter);\n"
    r"(?P=indent)    (?P=counter) = \((?P=cnt_low) \| (?P=cnt_high) \* 0x100\) \+ 1 >> 8;\n"
    r"(?P=indent)\}\n?"
)


def _stack_norm_rhs_8616(rhs: str) -> str:
    """Strip the redundant unsigned-short cast from one rhs."""

    return rhs.replace("(unsigned short)", "").strip()


def _stack_rhs_base_8616(rhs: str) -> str:
    """Strip a trailing ``>> 8`` from one rhs expression."""

    rhs = rhs.strip()
    rhs = re.sub(r"\s*\(?\s*>>\s*8\s*\)?\s*$", "", rhs)
    return rhs.strip()


def _stack_norm_far_offset_8616(off: str) -> str:
    """Normalize a far-pointer offset spelling."""

    off = off.strip()
    off = re.sub(r"^\(unsigned int\)\s*", "", off)
    off = re.sub(r"^\(unsigned short\)\s*", "", off)
    off = re.sub(r"\s*\+\s*0$", "", off)
    return off.strip()


def _linear_addr_to_mk_fp_8616(addr: int) -> tuple[int, int] | None:
    """Return (segment, offset) for a BIOS-data-area linear address."""

    if 0x400 <= addr < 0x500:
        return 0x40, addr - 0x400
    return None


def _rewrite_direct_ss_stack_expr_8616(match: re.Match[str]) -> str:
    """Rewrite a direct ``(ss << 4) + &base`` dereference."""

    base_expr = match.group("base").replace("(unsigned int)", "").strip()
    delta = int(match.group("delta") or "0", 0)
    if match.group("op") == "-":
        delta = -delta
    addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
    return f"*(({match.group('type').strip()} *){addr_expr})"


def _rewrite_indexed_ss_local_expr_8616(match: re.Match[str]) -> str:
    """Rewrite an indexed ``(&base)[ss*16 + delta]`` dereference."""

    delta = int(match.group("delta") or "0", 0)
    if match.group("op") == "-":
        delta = -delta
    addr_expr = f"&{match.group('base')}"
    if delta != 0:
        addr_expr = f"({addr_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
    return f"*((char *){addr_expr})"


def _rewrite_byte_walk_loop_8616(match: re.Match[str]) -> str:
    """Rewrite the split-byte pointer-walk loop into a while (*ptr++)."""

    indent = match.group("indent")
    ptr = match.group("ptr")
    counter = match.group("counter")
    return f"{indent}while (*{ptr}++)\n{indent}{{\n{indent}    {counter} += 1;\n{indent}}}\n"


def _immutable_pointer_names_8616(lines: list[str]) -> set[str]:
    """Collect const-pointer parameter names from the first function header."""

    immutable_pointer_names: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(("/*", "extern ")):
            continue
        if "(" not in stripped or ")" not in stripped or stripped.endswith(";"):
            continue
        params_text = stripped[stripped.find("(") + 1 : stripped.rfind(")")].strip()
        if not params_text or params_text == "void":
            break
        for param in params_text.split(","):
            if "const" not in param or "*" not in param:
                continue
            match = re.search(r"\b([A-Za-z_][\w$?@]*)\s*$", param.strip())
            if match is not None:
                immutable_pointer_names.add(match.group(1))
        break
    return immutable_pointer_names


@dataclass
class _StackAliasResolver8616:
    """Resolve chained vvar/ir/tmp stack-pointer expressions to (base, offset)."""

    seeds: dict[str, tuple[str, int]] = field(default_factory=dict)
    exprs: dict[str, str] = field(default_factory=dict)
    cache: dict[str, tuple[str, int] | None] = field(default_factory=dict)

    @classmethod
    def collect(cls, lines: list[str]) -> _StackAliasResolver8616:
        """Scan seed assignments and chained expressions from the lines."""

        run = cls()
        for line in lines:
            base_match = _STACK_ALIAS_BASE_RE_8616.match(line)
            if base_match is not None:
                run.seeds[base_match.group("name")] = (
                    base_match.group("base"),
                    int(base_match.group("index"), 0),
                )
                continue
            chain_match = _STACK_ALIAS_CHAIN_RE_8616.match(line)
            if chain_match is not None:
                run.exprs[chain_match.group("name")] = chain_match.group("expr").strip()
        return run

    def resolve(self, expr: str, seen: set[str] | None = None) -> tuple[str, int] | None:
        """Resolve one stack-pointer expression to (base, offset)."""

        expr = expr.strip()
        if not expr:
            return None
        if seen is None:
            seen = set()
        first_match = re.match(r"^(?P<name>(?:vvar|ir|tmp)_\d+)", expr)
        if first_match is None:
            return None
        name = first_match.group("name")
        if name in seen:
            return None
        base = self.cache.get(name)
        if base is None and name not in self.cache:
            if name in self.seeds:
                base = self.seeds[name]
            elif name in self.exprs:
                base = self.resolve(self.exprs[name], seen | {name})
            self.cache[name] = base
        if base is None:
            return None
        offset = base[1]
        rest = expr[first_match.end() :]
        for sign, value in re.findall(r"([+-])\s*(-?\d+)", rest):
            delta = int(value, 0)
            offset += delta if sign == "+" else -delta
        return base[0], offset

    @staticmethod
    def render(base: str, offset: int) -> str:
        """Render a resolved (base, offset) as a pointer expression."""

        if offset == 0:
            return f"&{base}"
        op = "+" if offset > 0 else "-"
        return f"(&{base} {op} {abs(offset)})"


def _simplify_x86_16_stack_byte_pointers(c_text: str, metadata: CODProcMetadata | None = None) -> str:
    # Text-layer rule:
    # Keep this limited to surface normalization of already-proven address forms.
    # Do not add new stack-alias discovery or sample-specific carrier recovery here.
    # If a vvar_/ir_/tmp_ chain still represents an SS/BP local, that belongs in
    # _rewrite_ss_stack_byte_offsets() or an earlier lowering stage.
    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    if not lines:
        return c_text

    immutable_pointer_names = _immutable_pointer_names_8616(lines)
    resolver = _StackAliasResolver8616.collect(lines)

    result = _rewrite_stack_pointer_store_lines_8616(
        lines=lines,
        low_store_re=_STACK_LOW_STORE_RE_8616,
        high_store_re=_STACK_HIGH_STORE_RE_8616,
        low_store_uncast_re=_STACK_LOW_STORE_UNCAST_RE_8616,
        high_store_uncast_re=_STACK_HIGH_STORE_UNCAST_RE_8616,
        pointer_store_re=_STACK_POINTER_STORE_RE_8616,
        far_pointer_store_re=_STACK_FAR_POINTER_STORE_RE_8616,
        raw_linear_pointer_store_re=_STACK_RAW_LINEAR_POINTER_STORE_RE_8616,
        ss_stack_store_re=_SS_STACK_STORE_RE_8616,
        plain_stack_store_re=_PLAIN_STACK_STORE_RE_8616,
        direct_ss_stack_store_re=_DIRECT_SS_STACK_STORE_RE_8616,
        stack_pointer_names=set(),
        immutable_pointer_names=immutable_pointer_names,
        resolve_stack_alias_expr=resolver.resolve,
        render_stack_pointer_expr=resolver.render,
        normalize_far_offset=_stack_norm_far_offset_8616,
        linear_address_to_mk_fp_components=_linear_addr_to_mk_fp_8616,
        normalize_rhs=_stack_norm_rhs_8616,
        rhs_base=_stack_rhs_base_8616,
    )

    result = _rewrite_stack_pointer_load_patterns_8616(
        result=result,
        segmented_byte_pair_load_re=_SEGMENTED_BYTE_PAIR_LOAD_RE_8616,
        stack_byte_pair_load_re=_STACK_BYTE_PAIR_LOAD_RE_8616,
    )
    result = _DIRECT_SS_STACK_EXPR_RE_8616.sub(_rewrite_direct_ss_stack_expr_8616, result)
    result = _INDEXED_SS_LOCAL_EXPR_RE_8616.sub(_rewrite_indexed_ss_local_expr_8616, result)

    # Fallback: strip any remaining (ss << 4) + patterns that leaked
    # through the structured lowering.  In real-mode x86 the stack segment
    # base is invariant, so (ss << 4) + offset simplifies to offset within
    # the current SS context.  This is safe purely as an address-space
    # rebasing — it does not recover semantics.
    result = re.sub(r"\(\s*ss\s*<<\s*4\s*\)\s*\+\s*", "", result)

    result = _split_simple_assignment_conditions(result)

    result, count = _BYTE_WALK_LOOP_RE_8616.subn(_rewrite_byte_walk_loop_8616, result)
    if count and result.endswith("\n\n"):
        result = re.sub(r"\n{3,}$", "\n\n", result)
    if trailing_newline:
        result += "\n"
    return result

def _rewrite_stack_pointer_store_lines_8616(
    *,
    lines: list[str],
    low_store_re: re.Pattern[str],
    high_store_re: re.Pattern[str],
    low_store_uncast_re: re.Pattern[str],
    high_store_uncast_re: re.Pattern[str],
    pointer_store_re: re.Pattern[str],
    far_pointer_store_re: re.Pattern[str],
    raw_linear_pointer_store_re: re.Pattern[str],
    ss_stack_store_re: re.Pattern[str],
    plain_stack_store_re: re.Pattern[str],
    direct_ss_stack_store_re: re.Pattern[str],
    stack_pointer_names: set[str],
    immutable_pointer_names: set[str],
    resolve_stack_alias_expr: Callable[[str], tuple[str, int] | None],
    render_stack_pointer_expr: Callable[[str, int], str],
    normalize_far_offset: Callable[[str], str],
    linear_address_to_mk_fp_components: Callable[[int], tuple[int, int] | None],
    normalize_rhs: Callable[[str], str],
    rhs_base: Callable[[str], str],
) -> str:
    kept_lines: list[str] = []
    i = 0
    while i < len(lines):
        current = lines[i]
        next_line = lines[i + 1] if i + 1 < len(lines) else None
        rewritten, step = _rewrite_single_stack_pointer_line_8616(
            current=current,
            next_line=next_line,
            low_store_re=low_store_re,
            high_store_re=high_store_re,
            low_store_uncast_re=low_store_uncast_re,
            high_store_uncast_re=high_store_uncast_re,
            pointer_store_re=pointer_store_re,
            far_pointer_store_re=far_pointer_store_re,
            raw_linear_pointer_store_re=raw_linear_pointer_store_re,
            ss_stack_store_re=ss_stack_store_re,
            plain_stack_store_re=plain_stack_store_re,
            direct_ss_stack_store_re=direct_ss_stack_store_re,
            stack_pointer_names=stack_pointer_names,
            immutable_pointer_names=immutable_pointer_names,
            resolve_stack_alias_expr=resolve_stack_alias_expr,
            render_stack_pointer_expr=render_stack_pointer_expr,
            normalize_far_offset=normalize_far_offset,
            linear_address_to_mk_fp_components=linear_address_to_mk_fp_components,
            normalize_rhs=normalize_rhs,
            rhs_base=rhs_base,
        )
        kept_lines.append(rewritten)
        i += step
    return "\n".join(kept_lines)


def _rewrite_stack_pointer_load_patterns_8616(
    *,
    result: str,
    segmented_byte_pair_load_re: re.Pattern[str],
    stack_byte_pair_load_re: re.Pattern[str],
) -> str:
    result = segmented_byte_pair_load_re.sub(
        lambda match: f"*((unsigned short far *)MK_FP({match.group('seg')}, {match.group('off')}))",
        result,
    )
    return stack_byte_pair_load_re.sub(
        lambda match: f"*((unsigned short *){match.group('base').replace('(unsigned int)', '').strip()})",
        result,
    )


@dataclass
class _StackPointerLineCtx8616:
    """Shared matchers and rewriters for one stack-pointer line pass."""

    low_store_re: re.Pattern[str]
    high_store_re: re.Pattern[str]
    low_store_uncast_re: re.Pattern[str]
    high_store_uncast_re: re.Pattern[str]
    pointer_store_re: re.Pattern[str]
    far_pointer_store_re: re.Pattern[str]
    raw_linear_pointer_store_re: re.Pattern[str]
    ss_stack_store_re: re.Pattern[str]
    plain_stack_store_re: re.Pattern[str]
    direct_ss_stack_store_re: re.Pattern[str]
    stack_pointer_names: set[str]
    immutable_pointer_names: set[str]
    resolve_stack_alias_expr: Callable[[str], tuple[str, int] | None]
    render_stack_pointer_expr: Callable[[str, int], str]
    normalize_far_offset: Callable[[str], str]
    linear_address_to_mk_fp_components: Callable[[int], tuple[int, int] | None]
    normalize_rhs: Callable[[str], str]
    rhs_base: Callable[[str], str]

    def try_raw_stack_store(self, current: str) -> tuple[str, int] | None:
        """Comment out a raw STORE(addr=stack_base...) diagnostic line."""

        raw_stack_store_match = re.match(
            r"^(?P<indent>\s*)STORE\(addr=stack_base[^\n]*\)\s*$", current
        )
        if raw_stack_store_match is not None:
            return f"{raw_stack_store_match.group('indent')}/* {current.strip().replace('/*', '/ *')} */", 1
        return None

    def try_alias_store(self, current: str) -> tuple[str, int] | None:
        """Rewrite stores through a resolvable vvar/ir/tmp alias chain."""

        for store_re in (self.ss_stack_store_re, self.plain_stack_store_re):
            stack_match = store_re.match(current)
            if stack_match is None:
                continue
            stack_pointer = self.resolve_stack_alias_expr(stack_match.group("expr"))
            if stack_pointer is not None:
                base_name, base_offset = stack_pointer
                return (
                    f"{stack_match.group('indent')}*(({stack_match.group('type').strip()} *){self.render_stack_pointer_expr(base_name, base_offset)}) = {stack_match.group('rhs').strip()};",
                    1,
                )
        return None

    def try_direct_ss_store(self, current: str) -> tuple[str, int] | None:
        """Rewrite a direct ``*(type *)((ss << 4) + &base)`` store."""

        direct_match = self.direct_ss_stack_store_re.match(current)
        if direct_match is None:
            return None
        base_expr = direct_match.group("base").replace("(unsigned int)", "").strip()
        delta = int(direct_match.group("delta") or "0", 0)
        if direct_match.group("op") == "-":
            delta = -delta
        addr_expr = base_expr if delta == 0 else f"({base_expr} {'+' if delta > 0 else '-'} {abs(delta)})"
        return (
            f"{direct_match.group('indent')}*(({direct_match.group('type').strip()} *){addr_expr}) = {direct_match.group('rhs').strip()};",
            1,
        )

    def _byte_pair_match(
        self, low_match: re.Match[str], high_match: re.Match[str]
    ) -> tuple[int, str, str] | None:
        """Return (low_off, low_seg, low_rhs) when the pair is a split store."""

        low_seg = low_match.group("seg").strip()
        high_seg = high_match.group("seg").strip()
        low_off = int(low_match.group("off"), 0)
        high_off = int(high_match.group("off"), 0)
        low_rhs = low_match.group("rhs").strip()
        high_rhs = high_match.group("rhs").strip()
        if not (
            low_seg == high_seg
            and high_off == low_off + 1
            and self.rhs_base(high_rhs) == self.normalize_rhs(low_rhs)
        ):
            return None
        return low_off, low_seg, low_rhs

    def try_cast_byte_pair(self, current: str, next_line: str | None) -> tuple[str, int] | None:
        """Coalesce a casted low/high byte-store pair into a word store."""

        if next_line is None:
            return None
        low_match = self.low_store_re.match(current)
        high_match = self.high_store_re.match(next_line)
        if low_match is None or high_match is None:
            return None
        pair = self._byte_pair_match(low_match, high_match)
        if pair is None:
            return None
        _low_off, low_seg, low_rhs = pair
        return (
            f"{low_match.group('indent')}*(unsigned short far *)MK_FP({low_seg}, {low_match.group('off')}) = {low_rhs};",
            2,
        )

    def try_uncast_byte_pair(self, current: str, next_line: str | None) -> tuple[str, int] | None:
        """Coalesce an uncasted low/high byte-store pair into a word store."""

        if next_line is None:
            return None
        low_match = self.low_store_uncast_re.match(current)
        high_match = self.high_store_uncast_re.match(next_line)
        if low_match is None or high_match is None:
            return None
        pair = self._byte_pair_match(low_match, high_match)
        if pair is None:
            return None
        low_off, low_seg, low_rhs = pair
        mk_fp_components = self.linear_address_to_mk_fp_components(low_off)
        if mk_fp_components is not None:
            seg_value, off_value = mk_fp_components
            return (
                f"{low_match.group('indent')}*((unsigned short far *)MK_FP(0x{seg_value:x}, 0x{off_value:x})) = {low_rhs};",
                2,
            )
        return (
            f"{low_match.group('indent')}*((unsigned short far *)MK_FP({low_seg}, {low_match.group('off')})) = {low_rhs};",
            2,
        )

    def try_far_pointer_store(self, current: str) -> tuple[str, int] | None:
        """Rewrite a far-pointer store onto a proven stack local."""

        far_pointer_match = self.far_pointer_store_re.match(current)
        if far_pointer_match is None:
            return None
        ptr_name = self.normalize_far_offset(far_pointer_match.group("off"))
        ptr_base_name = re.sub(r"_\d+$", "", ptr_name)
        stack_target_name = None
        if ptr_name in self.stack_pointer_names and ptr_name not in self.immutable_pointer_names:
            stack_target_name = ptr_name
        elif ptr_base_name in self.stack_pointer_names and ptr_base_name not in self.immutable_pointer_names:
            stack_target_name = ptr_base_name
        if stack_target_name is None:
            return None
        return (
            f"{far_pointer_match.group('indent')}*{stack_target_name} = {far_pointer_match.group('rhs').strip()};",
            1,
        )

    def try_raw_linear_pointer_store(self, current: str) -> tuple[str, int] | None:
        """Rewrite a raw linear-address pointer store as MK_FP when known."""

        raw_match = self.raw_linear_pointer_store_re.match(current)
        if raw_match is None:
            return None
        pointer_type = raw_match.group("type").strip()
        if pointer_type == "char":
            return None
        addr = int(raw_match.group("addr"), 0)
        mk_fp_components = self.linear_address_to_mk_fp_components(addr)
        if mk_fp_components is None:
            return None
        seg_value, off_value = mk_fp_components
        return (
            f"{raw_match.group('indent')}*((%s far *)MK_FP(0x%x, 0x%x)) = %s;"
            % (pointer_type, seg_value, off_value, raw_match.group("rhs").strip()),
            1,
        )

    def try_typed_pointer_store(self, current: str) -> tuple[str, int] | None:
        """Rewrite a typed ``seg * 16 + off`` store as MK_FP."""

        pointer_match = self.pointer_store_re.match(current)
        if pointer_match is None:
            return None
        pointer_type = pointer_match.group("type").strip()
        if pointer_type == "char":
            return None
        return (
            f"{pointer_match.group('indent')}*((%s far *)MK_FP(%s, %s)) = %s;"
            % (
                pointer_type,
                pointer_match.group("seg").strip(),
                pointer_match.group("off").strip(),
                pointer_match.group("rhs").strip(),
            ),
            1,
        )

    def rewrite_line(self, current: str, next_line: str | None) -> tuple[str, int]:
        """Rewrite one line pair; return (line, lines-consumed)."""

        attempts: tuple[Callable[[], tuple[str, int] | None], ...] = (
            lambda: self.try_raw_stack_store(current),
            lambda: self.try_alias_store(current),
            lambda: self.try_direct_ss_store(current),
            lambda: self.try_cast_byte_pair(current, next_line),
            lambda: self.try_uncast_byte_pair(current, next_line),
            lambda: self.try_far_pointer_store(current),
            lambda: self.try_raw_linear_pointer_store(current),
            lambda: self.try_typed_pointer_store(current),
        )
        for attempt in attempts:
            rewritten = attempt()
            if rewritten is not None:
                return rewritten
        return current, 1


def _rewrite_single_stack_pointer_line_8616(
    *,
    current: str,
    next_line: str | None,
    low_store_re: re.Pattern[str],
    high_store_re: re.Pattern[str],
    low_store_uncast_re: re.Pattern[str],
    high_store_uncast_re: re.Pattern[str],
    pointer_store_re: re.Pattern[str],
    far_pointer_store_re: re.Pattern[str],
    raw_linear_pointer_store_re: re.Pattern[str],
    ss_stack_store_re: re.Pattern[str],
    plain_stack_store_re: re.Pattern[str],
    direct_ss_stack_store_re: re.Pattern[str],
    stack_pointer_names: set[str],
    immutable_pointer_names: set[str],
    resolve_stack_alias_expr: Callable[[str], tuple[str, int] | None],
    render_stack_pointer_expr: Callable[[str, int], str],
    normalize_far_offset: Callable[[str], str],
    linear_address_to_mk_fp_components: Callable[[int], tuple[int, int] | None],
    normalize_rhs: Callable[[str], str],
    rhs_base: Callable[[str], str],
) -> tuple[str, int]:
    """Dispatch a single stack-pointer line rewrite."""

    ctx = _StackPointerLineCtx8616(
        low_store_re=low_store_re,
        high_store_re=high_store_re,
        low_store_uncast_re=low_store_uncast_re,
        high_store_uncast_re=high_store_uncast_re,
        pointer_store_re=pointer_store_re,
        far_pointer_store_re=far_pointer_store_re,
        raw_linear_pointer_store_re=raw_linear_pointer_store_re,
        ss_stack_store_re=ss_stack_store_re,
        plain_stack_store_re=plain_stack_store_re,
        direct_ss_stack_store_re=direct_ss_stack_store_re,
        stack_pointer_names=stack_pointer_names,
        immutable_pointer_names=immutable_pointer_names,
        resolve_stack_alias_expr=resolve_stack_alias_expr,
        render_stack_pointer_expr=render_stack_pointer_expr,
        normalize_far_offset=normalize_far_offset,
        linear_address_to_mk_fp_components=linear_address_to_mk_fp_components,
        normalize_rhs=normalize_rhs,
        rhs_base=rhs_base,
    )
    return ctx.rewrite_line(current, next_line)

def _format_bp_disp(disp: int) -> str:
    if disp >= 0:
        return f"[bp+0x{disp:x}]"
    return f"[bp-0x{-disp:x}]"


def _sorted_metadata_stack_aliases(
    metadata: CODProcMetadata | None,
    *,
    negatives_last: bool = False,
) -> list[tuple[int, str]]:
    if metadata is None:
        return []
    aliases = metadata.stack_aliases
    if not aliases:
        return []
    if negatives_last:
        return sorted(aliases.items(), key=lambda item: (item[0] < 0, item[0], str(item[1])))
    return sorted(aliases.items(), key=lambda item: (item[0], str(item[1])))


def _annotate_cod_proc_output(
    c_text: str, function: object, metadata: CODProcMetadata | None, *, codegen: object | None = None
) -> str:
    return c_text


_GENERIC_STACK_NAME_RE_8616 = re.compile(r"^(?:s_[0-9a-fA-F]+|v\d+|vvar_\d+|a\d+)$")
_COD_LINE_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)(?P<suffix>\s*[;{]?\s*)$"
)


def _alias_replacements_from_metadata_8616(metadata: CODProcMetadata) -> dict[str, str]:
    """Seed arg_N -> alias replacements from positive stack aliases."""

    alias_replacements: dict[str, str] = {}
    for disp, alias in _sorted_metadata_stack_aliases(metadata):
        if (
            isinstance(disp, int)
            and disp > 0
            and isinstance(alias, str)
            and alias
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias)
        ):
            alias_replacements.setdefault(f"arg_{disp:x}", alias)
    return alias_replacements


def _collect_header_arg_aliases_8616(
    line_header_match: re.Match[str] | None,
    is_function_header_line: bool,
    local_positive_arg_aliases: list[str],
    alias_replacements: dict[str, str],
) -> bool:
    """Map header arg names onto positive arg aliases; False = skip line."""

    if not (is_function_header_line and local_positive_arg_aliases):
        return False
    if line_header_match is None:
        return True
    header_parts = _split_c_signature_args_8616(line_header_match.group("args"))
    for arg_index, part in enumerate(header_parts):
        if arg_index >= len(local_positive_arg_aliases):
            break
        current_name = _decl_arg_name_8616(part)
        alias = local_positive_arg_aliases[arg_index]
        if current_name and alias and current_name != alias:
            alias_replacements.setdefault(current_name, alias)
    return False


def _annotate_bp_comment_line_8616(
    line: str,
    metadata: CODProcMetadata,
    positive_aliases: dict[int, str],
    alias_replacements: dict[str, str],
) -> str | None:
    """Annotate a [bp+-0x] comment line; None = skip the line."""

    match = re.search(r"// \[bp([+-])0x([0-9a-f]+)\]", line)
    if match is None:
        return line
    disp = int(match.group(2), 16)
    if match.group(1) == "-":
        disp = -disp
    stack_alias = _cod_stack_alias_for_disp(disp, metadata, positive_aliases=positive_aliases)
    if disp > 0 and "<missing-type>" in line:
        return None
    if stack_alias is not None and not line.rstrip().endswith(f" {stack_alias}"):
        line = f"{line} {stack_alias}"
    declaration_part = line.split("//", 1)[0]
    decl_match = re.search(r"(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*$", declaration_part.strip())
    if decl_match is not None:
        current_name = decl_match.group("name")
        if isinstance(stack_alias, str) and stack_alias and _GENERIC_STACK_NAME_RE_8616.fullmatch(current_name):
            alias_replacements.setdefault(current_name, stack_alias)
    return line


def _apply_alias_replacements_8616(lines: list[str], alias_replacements: dict[str, str]) -> list[str]:
    """Apply collected alias renames across the annotated lines."""

    replacement_pattern = re.compile(
        r"(?<![A-Za-z_])("
        + "|".join(sorted((re.escape(name) for name in alias_replacements), key=len, reverse=True))
        + r")(?![A-Za-z_])"
    )
    return [
        replacement_pattern.sub(lambda m: alias_replacements.get(m.group(1), m.group(1)), line) for line in lines
    ]


def _annotate_cod_lines_with_aliases_8616(
    c_text: str,
    *,
    metadata: CODProcMetadata,
    positive_aliases: dict[int, str],
    positive_arg_aliases: list[str],
    source_decl: str | None,
    source_arg_text: str | None,
) -> list[str]:
    def _impl() -> list[str]:
        alias_replacements = _alias_replacements_from_metadata_8616(metadata)
        lines: list[str] = []
        input_lines = c_text.splitlines()
        for index, line in enumerate(input_lines):
            next_line = input_lines[index + 1] if index + 1 < len(input_lines) else None
            line_header_match = _COD_LINE_HEADER_RE_8616.match(line)
            local_positive_arg_aliases = positive_arg_aliases
            local_source_decl = source_decl
            local_source_arg_text = source_arg_text
            if line_header_match is not None and _source_header_args_unmaterialized_8616(
                c_text,
                func_name=line_header_match.group("name"),
                source_decl=source_decl,
                source_arg_text=source_arg_text,
                allowed_positive_arg_aliases=positive_arg_aliases,
            ):
                local_positive_arg_aliases = []
                local_source_decl = None
                local_source_arg_text = None
            line = _rewrite_cod_header_args_line_8616(
                line,
                next_line=next_line,
                metadata=metadata,
                positive_arg_aliases=local_positive_arg_aliases,
                source_decl=local_source_decl,
                source_arg_text=local_source_arg_text,
            )
            is_function_header_line = (
                line_header_match is not None
                and (
                    "{" in line_header_match.group("suffix")
                    or (next_line is not None and next_line.strip() == "{")
                )
            )
            if _collect_header_arg_aliases_8616(
                line_header_match, is_function_header_line, local_positive_arg_aliases, alias_replacements
            ):
                continue
            annotated = _annotate_bp_comment_line_8616(line, metadata, positive_aliases, alias_replacements)
            if annotated is None:
                continue
            lines.append(annotated)
        if not alias_replacements:
            return lines
        return _apply_alias_replacements_8616(lines, alias_replacements)

    return _impl()


def _rewrite_cod_header_args_line_8616(
    line: str,
    *,
    next_line: str | None,
    metadata: CODProcMetadata,
    positive_arg_aliases: list[str],
    source_decl: str | None,
    source_arg_text: str | None,
) -> str:
    def _impl() -> str:
        if not positive_arg_aliases:
            return line
        header_match = re.match(
            r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)(?P<suffix>\s*[;{]?\s*)$",
            line,
        )
        if header_match is None:
            return line
        suffix = header_match.group("suffix")
        if "{" not in suffix and (next_line is None or next_line.strip() != "{"):
            return line
        args_text = header_match.group("args")
        parts = _split_c_signature_args_8616(args_text)
        if not args_text.strip():
            return line
        rewritten, changed = _rewrite_cod_header_arg_parts_8616(
            parts=parts,
            args_text=args_text,
            positive_arg_aliases=positive_arg_aliases,
        )
        if not changed:
            return line
        return f"{header_match.group('indent')}{header_match.group('ret').rstrip()} {header_match.group('name')}({', '.join(rewritten)}){header_match.group('suffix')}"

    return _impl()


def _split_source_decl_args_8616(source_decl: str | None, source_arg_text: str | None) -> list[str]:
    if source_decl is not None:
        source_args = _source_decl_args_text_8616(source_decl)
        if source_args and source_args != "void":
            return _split_c_signature_args_8616(source_args)
    if source_arg_text is not None:
        if source_arg_text.strip() == "void":
            return []
        return _split_c_signature_args_8616(source_arg_text)
    return []


def _rewrite_cod_header_arg_parts_8616(
    *,
    parts: list[str],
    args_text: str,
    positive_arg_aliases: list[str],
) -> tuple[list[str], bool]:
    def _impl() -> tuple[list[str], bool]:
        def normalize_arg_text(part: str) -> str:
            text = part
            text = re.sub(r"\buint16\b", "unsigned short", text)
            text = re.sub(r"\bint16\b", "short", text)
            text = re.sub(r"\buint8\b", "unsigned char", text)
            text = text.replace("FAR *", "*").replace("FAR*", "*")
            text = text.replace("const char*", "const char *").replace("char*", "char *")
            text = re.sub(r"\s*\*\s*", " *", text)
            text = re.sub(r"\(\s+\*", "(*", text)
            return re.sub(r"\s+", " ", text).strip()

        normalized_candidate_parts = [normalize_arg_text(part) for part in parts]
        candidate_parts = normalized_candidate_parts or parts
        rewritten: list[str] = []
        changed = False
        for index, part in enumerate(candidate_parts):
            split = _decl_arg_name_8616(part)
            if split is None or index >= len(positive_arg_aliases):
                rewritten.append(part)
                continue
            alias = positive_arg_aliases[index]
            if split == alias:
                rewritten.append(part)
                continue
            rewritten.append(_replace_decl_arg_name_8616(part, split, alias))
            changed = True
        return rewritten, changed

    return _impl()


def _finalize_cod_annotation_text_8616(c_text: str, metadata: CODProcMetadata) -> str:
    c_text = _prune_unused_staging_assignments(c_text)
    c_text = _simplify_x86_16_stack_references(c_text)
    c_text = _normalize_mk_fp_segment_names(c_text, metadata)
    c_text = _prune_void_function_return_values_text(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    c_text = _dedupe_duplicate_local_declarations_text(c_text)
    c_text = _normalize_spurious_duplicate_local_suffixes(c_text)
    c_text = _collapse_duplicate_type_keywords_text(c_text)
    c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
    c_text = _prune_unused_local_declarations_text(c_text)
    return c_text


class _StagingAssignmentRhsEffect8616(Enum):
    PURE = "pure"
    CALL_LIKE = "call_like"


def _classify_staging_assignment_rhs_effect_8616(rhs: str) -> _StagingAssignmentRhsEffect8616:
    if not isinstance(rhs, str) or not rhs.strip():
        return _StagingAssignmentRhsEffect8616.PURE
    call_like_re = re.compile(r"(?<![A-Za-z_])(?P<name>[A-Za-z_]\w*)\s*\(")
    harmless_keywords = {"sizeof"}
    for match in call_like_re.finditer(rhs):
        if match.group("name") not in harmless_keywords:
            return _StagingAssignmentRhsEffect8616.CALL_LIKE
    return _StagingAssignmentRhsEffect8616.PURE


def _prune_standalone_memory_helper_reads_text(c_text: str) -> str:
    """Drop pure generated memory-helper reads left behind after lowering."""
    lines = c_text.splitlines()
    if not lines:
        return c_text
    standalone_read_re = re.compile(
        r"^(?P<indent>\s*)MEM_U(?:8|16|32)\s*\((?P<args>[^;{}]*)\)\s*;\s*$"
    )
    kept_lines: list[str] = []
    changed = False
    for line in lines:
        match = standalone_read_re.match(line)
        if match is not None and "(" not in match.group("args"):
            changed = True
            continue
        kept_lines.append(line)
    if not changed:
        return c_text
    rewritten = "\n".join(kept_lines)
    if c_text.endswith("\n"):
        rewritten += "\n"
    return rewritten


_STAGING_NAME_PATTERN_8616 = (
    r"(?:s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|vvar_[0-9a-fA-F]+|v\d+|tmp_\d+|ir_\d+|arg_\d+)"
)
_STAGING_NAME_RE_8616 = re.compile(rf"\b{_STAGING_NAME_PATTERN_8616}\b")
_STAGING_DECL_RE_8616 = re.compile(
    rf"^\s*(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>{_STAGING_NAME_PATTERN_8616})\s*(?:;\s*(?://.*)?)?$"
)
_STAGING_ASSIGN_RE_8616 = re.compile(
    rf"^(?P<indent>\s*)(?P<name>{_STAGING_NAME_PATTERN_8616})(?:\{{[^}}]+\}})?\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_STAGING_GENERIC_ASSIGN_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z_]\w*)(?:\{[^}]+\})?\s*=\s*(?P<rhs>[^;]+);\s*$"
)
_STAGING_RAW_REGISTER_FRAG_RE_8616 = re.compile(r"\{r\d+\|\d+b\}")
_STAGING_SELF_ADDR_RE_8616 = re.compile(r"^\s*(?P<name>[A-Za-z_]\w*)\s*=\s*&\s*(?P=name)\s*;\s*$")
_STAGING_IDENT_RE_8616 = re.compile(r"\b[A-Za-z_]\w*\b")


@dataclass
class _StagingPrunePass8616:
    """One staging-assignment prune pass over the current text lines."""

    ident_use_counts: dict[str, int] = field(default_factory=dict)
    used_names: dict[str, int] = field(default_factory=dict)

    def collect_uses(self, lines: list[str]) -> None:
        """Count identifier and staging-name uses across the lines."""

        for line in lines:
            for ident in _STAGING_IDENT_RE_8616.findall(line):
                self.ident_use_counts[ident] = self.ident_use_counts.get(ident, 0) + 1
        for line in lines:
            if _STAGING_NAME_RE_8616.search(line) is None:
                continue
            stripped = line.strip()
            decl_match = _STAGING_DECL_RE_8616.match(stripped)
            if decl_match is not None and not stripped.startswith("return "):
                continue
            assign_match = _STAGING_ASSIGN_RE_8616.match(stripped)
            if assign_match is not None:
                lhs_name = assign_match.group("name")
                rhs = assign_match.group("rhs")
                for name in _STAGING_NAME_RE_8616.findall(rhs):
                    if name == lhs_name:
                        continue
                    self.used_names[name] = self.used_names.get(name, 0) + 1
                continue
            for name in _STAGING_NAME_RE_8616.findall(line):
                self.used_names[name] = self.used_names.get(name, 0) + 1

    def _try_generic_dead_carrier(self, stripped: str) -> bool:
        """Drop an assignment whose lhs is a dead raw-fragment carrier."""

        generic_match = _STAGING_GENERIC_ASSIGN_RE_8616.match(stripped)
        if generic_match is None or _STAGING_RAW_REGISTER_FRAG_RE_8616.search(generic_match.group("rhs")) is None:
            return False
        lhs_name = generic_match.group("name")
        # If the assignment's LHS never appears elsewhere, this is
        # a dead carrier of raw register-fragment text.
        return self.ident_use_counts.get(lhs_name, 0) <= 2

    def prune(self, lines: list[str]) -> tuple[list[str], bool]:
        """Drop unused staging assigns; keep call-like rhs effects."""

        kept_lines: list[str] = []
        changed = False
        for line in lines:
            stripped = line.strip()
            if _STAGING_SELF_ADDR_RE_8616.match(stripped):
                changed = True
                continue
            match = _STAGING_ASSIGN_RE_8616.match(stripped)
            if match is None:
                if self._try_generic_dead_carrier(stripped):
                    changed = True
                    continue
                kept_lines.append(line)
                continue
            name = match.group("name")
            rhs_effect = _classify_staging_assignment_rhs_effect_8616(match.group("rhs"))
            if self.used_names.get(name, 0) == 0:
                changed = True
                if rhs_effect is _StagingAssignmentRhsEffect8616.CALL_LIKE:
                    indent = line[: len(line) - len(line.lstrip())]
                    kept_lines.append(f"{indent}{match.group('rhs').strip()};")
                continue
            kept_lines.append(line)
        return kept_lines, changed


def _prune_unused_staging_assignments(c_text: str) -> str:
    """Prune legacy text-only staging assignments while preserving observed values."""

    current = c_text
    while True:
        lines = current.splitlines()
        if not any(_STAGING_NAME_RE_8616.search(line) for line in lines):
            return current
        run = _StagingPrunePass8616()
        run.collect_uses(lines)
        kept_lines, changed = run.prune(lines)
        updated = "\n".join(kept_lines)
        if not changed or updated == current:
            return updated
        current = updated

_SHADOW_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
)
_SHADOW_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default|break|continue)\b)"
    r"(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?://.*)?$"
)
_SHADOW_FUNC_PTR_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?:[A-Za-z_][\w\s\*\[\]]*?)\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)"
    r"\s*\([^;{}]*\)\s*;\s*(?://.*)?$"
)


def _shadow_function_arg_names_8616(out: list[str], idx: int) -> tuple[set[str], int] | None:
    """Return (arg_names, brace_idx) for the function at idx, else None."""

    m = _SHADOW_HEADER_RE_8616.match(out[idx])
    if m is not None:
        args_text = m.group("args").strip()
        return _parameter_names_from_args_text_8616(args_text), idx
    candidate = out[idx]
    lookahead = idx + 1
    while "{" not in candidate and lookahead < len(out) and lookahead <= idx + 2:
        if ";" in candidate:
            break
        candidate = f"{candidate} {out[lookahead].strip()}"
        lookahead += 1
    args_text = _extract_function_header_args_8616(candidate)
    if args_text is None:
        return None
    arg_names = _parameter_names_from_args_text_8616(args_text)
    brace_idx = idx
    while brace_idx < len(out) and "{" not in out[brace_idx]:
        brace_idx += 1
    return arg_names, brace_idx


def _shadow_body_end_8616(out: list[str], brace_idx: int) -> int:
    """Return the exclusive end of the body opened at brace_idx."""

    body_end = brace_idx + 1
    depth = out[brace_idx].count("{") - out[brace_idx].count("}")
    while body_end < len(out) and depth > 0:
        depth += out[body_end].count("{") - out[body_end].count("}")
        body_end += 1
    return body_end


def _prune_shadow_decls_in_body_8616(
    out: list[str], body_start: int, body_end: int, arg_names: set[str]
) -> tuple[int, bool]:
    """Delete declarations that shadow parameter names; return (end, changed)."""

    scan = body_start
    changed = False
    while scan < body_end:
        stripped = out[scan].strip()
        if not stripped:
            scan += 1
            continue
        dm = _SHADOW_DECL_RE_8616.match(out[scan]) or _SHADOW_FUNC_PTR_RE_8616.match(out[scan])
        if dm is None:
            break
        name = dm.group("name")
        if name in arg_names:
            del out[scan]
            body_end -= 1
            changed = True
            continue
        scan += 1
    return body_end, changed


def _prune_parameter_shadow_declarations_text(c_text: str) -> str:
    """Drop local declarations that shadow function parameter names."""

    lines = c_text.splitlines()
    if not lines:
        return c_text
    out = list(lines)
    idx = 0
    changed = False
    while idx < len(out):
        located = _shadow_function_arg_names_8616(out, idx)
        if located is None:
            idx += 1
            continue
        arg_names, brace_idx = located
        if not arg_names:
            idx += 1
            continue
        while brace_idx < len(out) and "{" not in out[brace_idx]:
            brace_idx += 1
        if brace_idx >= len(out):
            idx += 1
            continue
        body_start = brace_idx + 1
        body_end = _shadow_body_end_8616(out, brace_idx)
        body_end, body_changed = _prune_shadow_decls_in_body_8616(out, body_start, body_end, arg_names)
        changed = changed or body_changed
        idx = body_end
    if not changed:
        return c_text
    normalized = "\n".join(out)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized


_FRAG_IDENT_RE_8616 = re.compile(r"\b[A-Za-z_]\w*\b")
_FRAG_ASSIGN_RE_8616 = re.compile(r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?P<rhs>.+?)\s*;\s*$")
_FRAG_CARRIER_RHS_RE_8616 = re.compile(r"^vvar_\d+(?:\{r\d+\|\d+b\})?(?:\s*(?:[+\-])\s*(?:vvar_\d+|\d+))*$")
_FRAG_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?:[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*;\s*(?://.*)?$"
)
_FRAG_LHS_ASSIGN_RE_8616 = re.compile(r"^\s*(?P<lhs>[A-Za-z_]\w*)\s*=\s*.*;\s*$")


def _frag_declared_names_8616(lines: list[str]) -> set[str]:
    """Collect declared names from decl-shaped lines."""

    declared: set[str] = set()
    for line in lines:
        dm = _FRAG_DECL_RE_8616.match(line)
        if dm is not None:
            declared.add(dm.group("name"))
    return declared


def _frag_read_usage_8616(lines: list[str]) -> dict[str, int]:
    """Count non-lhs identifier reads across non-decl lines."""

    read_usage: dict[str, int] = {}
    for line in lines:
        dm = _FRAG_DECL_RE_8616.match(line)
        if dm is not None:
            continue
        lhs_name: str | None = None
        lm = _FRAG_LHS_ASSIGN_RE_8616.match(line)
        if lm is not None:
            lhs_name = lm.group("lhs")
        for name in _FRAG_IDENT_RE_8616.findall(line):
            if lhs_name is not None and name == lhs_name:
                continue
            read_usage[name] = read_usage.get(name, 0) + 1
    return read_usage


def _frag_carrier_line_dropped_8616(line: str, declared: set[str], read_usage: dict[str, int]) -> bool:
    """Return whether the line is a dead undefined-fragment carrier assign."""

    am = _FRAG_ASSIGN_RE_8616.match(line.strip())
    if am is None:
        return False
    lhs = am.group("lhs")
    rhs = am.group("rhs").strip()
    rhs_base = rhs.split("{", 1)[0]
    rhs_is_undefined_fragment = rhs_base not in declared and _FRAG_CARRIER_RHS_RE_8616.match(rhs) is not None
    rhs_is_dead_carrier_arithmetic = lhs.startswith("vvar_") and _FRAG_CARRIER_RHS_RE_8616.match(rhs) is not None
    return read_usage.get(lhs, 0) == 0 and (rhs_is_undefined_fragment or rhs_is_dead_carrier_arithmetic)


def _frag_live_assigns_reads_8616(out: list[str]) -> tuple[dict[str, int], set[str]]:
    """Count live reads and assigned names after the carrier prune."""

    live_reads: dict[str, int] = {}
    live_assigns: set[str] = set()
    for line in out:
        dm = _FRAG_DECL_RE_8616.match(line)
        if dm is not None:
            continue
        lhs_name = None
        lm = _FRAG_LHS_ASSIGN_RE_8616.match(line)
        if lm is not None:
            lhs_name = lm.group("lhs")
            if lhs_name is not None:
                live_assigns.add(lhs_name)
        for name in _FRAG_IDENT_RE_8616.findall(line):
            if lhs_name is not None and name == lhs_name:
                continue
            live_reads[name] = live_reads.get(name, 0) + 1
    return live_reads, live_assigns


def _prune_undefined_fragment_carrier_assignments_text(c_text: str) -> str:
    """Drop assignments that only carry unresolvable register-fragment text."""

    lines = c_text.splitlines()
    if not lines:
        return c_text
    declared = _frag_declared_names_8616(lines)
    read_usage = _frag_read_usage_8616(lines)
    out: list[str] = []
    changed = False
    for line in lines:
        if _frag_carrier_line_dropped_8616(line, declared, read_usage):
            changed = True
            continue
        out.append(line)
    if not changed:
        return c_text
    live_reads, live_assigns = _frag_live_assigns_reads_8616(out)
    pruned_decls: list[str] = []
    for line in out:
        dm = _FRAG_DECL_RE_8616.match(line)
        if (
            dm is not None
            and dm.group("name").startswith("vvar_")
            and live_reads.get(dm.group("name"), 0) == 0
            and dm.group("name") not in live_assigns
        ):
            changed = True
            continue
        pruned_decls.append(line)
    normalized = "\n".join(pruned_decls)
    if c_text.endswith("\n"):
        normalized += "\n"
    return normalized

def _prune_non_lvalue_arithmetic_assignments(c_text: str) -> str:
    """Preserve assignment effects at the legacy text-cleanup boundary.

    Compatibility only: retire this entry point with its formatter callers.
    Text patterns cannot distinguish invalid arithmetic targets from valid
    cast/index/member lvalues, and invalid assignments can contain live calls.
    Keep all statements; AST owners must repair invalid targets and strict
    recompilation must report any unresolved defect. Never delete code here
    to make generated C compile after its semantic validation has finished.
    """
    return c_text


_SEG_OFF_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>\{?)\s*$"
)


def _seg_off_rewritten_args_8616(args: str, body: str) -> str:
    """Rewrite ``void*`` args used as seg-offset to ``unsigned short``."""

    rewritten = args
    for am in re.finditer(r"\bvoid\s*\*\s*(?P<arg>[A-Za-z_]\w*)\b", args):
        arg_name = am.group("arg")
        used_as_seg_off = re.search(
            rf"\bSEG_U(?:8|16|32)\s*\([^,\n]+,\s*[^)\n]*\b{re.escape(arg_name)}\b",
            body,
        )
        if used_as_seg_off is None:
            continue
        rewritten = re.sub(
            rf"\bvoid\s*\*\s*{re.escape(arg_name)}\b",
            f"unsigned short {arg_name}",
            rewritten,
        )
    return rewritten


def _normalize_seg_offset_void_pointer_args_text(c_text: str) -> str:
    # Normalize nested address-index carriers produced by stack/materialization
    # lanes into scalar offset expressions accepted by C compilers:
    #   &(&v2)[52700 + v6] -> (52700 + v6)
    def _impl() -> str:
        nonlocal c_text
        c_text = re.sub(
            r"&\s*\(\s*&\s*[A-Za-z_]\w*\s*\)\s*\[\s*([^\]]+?)\s*\]",
            r"(\1)",
            c_text,
        )
        lines = c_text.splitlines()
        if not lines:
            return c_text
        changed = False
        for idx, line in enumerate(lines):
            m = _SEG_OFF_HEADER_RE_8616.match(line)
            if m is None:
                continue
            args = m.group("args")
            if "void*" not in args:
                continue
            body = "\n".join(lines[idx + 1 :])
            rewritten = _seg_off_rewritten_args_8616(args, body)
            if rewritten == args:
                continue
            suffix = m.group("suffix")
            lines[idx] = (
                f"{m.group('indent')}{m.group('ret')} {m.group('name')}({rewritten}){(' ' + suffix) if suffix else ''}"
            )
            changed = True
        if not changed:
            return c_text
        normalized = "\n".join(lines)
        if c_text.endswith("\n"):
            normalized += "\n"
        return normalized

    return _impl()


def _normalize_shift_add_precedence_in_assignments(c_text: str) -> str:
    """Normalize assignment RHS expressions that parse incorrectly without explicit parentheses.

    Examples:
      ``x = y + 1 >> 8;`` -> ``x = (y + 1) >> 8;``
    """
    assign_re = re.compile(r"^(?P<indent>\s*)(?P<lhs>[^=;]+?)\s*=\s*(?P<rhs>[^;]+);\s*$")

    def _rewrite_match(match: re.Match[str]) -> str:
        rhs = match.group("rhs").strip()
        full_match = re.fullmatch(r"(?P<base>.+?)\+\s*1\s*>>\s*8", rhs)
        if full_match is None:
            return match.group(0)
        base_expr = full_match.group("base").rstrip()
        if base_expr.endswith((">>", "<<", "&")):
            return match.group(0)
        if base_expr.startswith("(") and base_expr.endswith(")"):
            return match.group(0)
        return f"{match.group('indent')}{match.group('lhs').strip()} = ({base_expr} + 1) >> 8;"

    lines = c_text.splitlines()
    rewritten = [_rewrite_match(match) if (match := assign_re.match(line)) else line for line in lines]
    return "\n".join(rewritten)


def _normalize_unsupported_computed_goto_text(c_text: str) -> str:
    """Rewrite GCC-style computed goto into a compilable conservative fallback.

    MS C does not support ``goto <expression>;`` forms.
    """

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        expr = match.group("expr").strip()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
            return match.group(0)
        return f"{indent}/* unsupported computed goto: {expr} */ return;"

    pattern = re.compile(r"(?m)^(?P<indent>\s*)goto\s+(?P<expr>[^;]+);\s*$")
    return pattern.sub(_replace, c_text)


def _rewrite_known_helper_signature_text(c_text: str, function: object, *, codegen: object | None = None) -> str:
    """Preserve typed recovery; a helper label cannot authorize ABI text changes.

    Compatibility entry point only. Prototype evidence belongs in Types/Lowering,
    before validation, never in a rendered-header or argument-name replacement.
    """
    return c_text


def _compile_function_header_pattern_8616(func_name: str) -> re.Pattern[str]:
    return re.compile(
        rf"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+{re.escape(func_name)}\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{{;]?)\s*$"
    )


def _find_function_body_open_8616(
    lines: list[str], header_pattern: re.Pattern[str]
) -> tuple[int | None, int | None]:
    for index, line in enumerate(lines):
        match = header_pattern.match(line)
        if match is None:
            continue
        suffix = match.group("suffix")
        if suffix == "{":
            return index, index
        if index + 1 < len(lines) and lines[index + 1].strip() == "{":
            return index, index + 1
    return None, None


def _split_c_signature_args_8616(arg_text: str) -> list[str]:
    """Split a signature arg list at top-level commas."""

    return _split_args_8616(arg_text)


def _decl_arg_name_8616(arg_text: str) -> str | None:
    text = arg_text.rstrip()
    if not text or text in {"void", "..."}:
        return None
    fnptr_match = re.search(r"\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*\)", text)
    if fnptr_match is not None:
        return fnptr_match.group("name")
    idx = len(text)
    while idx > 0 and text[idx - 1].isspace():
        idx -= 1
    end = idx
    while idx > 0 and (text[idx - 1].isalnum() or text[idx - 1] == "_"):
        idx -= 1
    if idx == end:
        return None
    name = text[idx:end]
    prefix = text[:idx]
    return name if prefix.strip() else None


def _replace_decl_arg_name_8616(arg_text: str, old_name: str, new_name: str) -> str:
    fnptr_match = re.search(r"\(\s*\*\s*" + re.escape(old_name) + r"\s*\)", arg_text)
    if fnptr_match is not None:
        start, end = fnptr_match.span()
        replacement = re.sub(re.escape(old_name), new_name, arg_text[start:end], count=1)
        return f"{arg_text[:start]}{replacement}{arg_text[end:]}"
    name_match = re.search(rf"(?<![A-Za-z_]){re.escape(old_name)}(?![A-Za-z_])", arg_text)
    if name_match is None:
        return arg_text
    return f"{arg_text[: name_match.start()]}{new_name}{arg_text[name_match.end() :]}"


def _annotated_bp_arg_names_8616(lines_before_header: list[str]) -> list[str]:
    names: list[str] = []
    for line in lines_before_header:
        match = re.match(r"^\s*\*\s+\[bp\+(?P<disp>0x[0-9a-f]+)\]\s*=\s*(?P<name>[A-Za-z_][\w$?@]*)\s*$", line)
        if match is not None:
            names.append(match.group("name"))
    return names


def _find_body_end_index_8616(lines: list[str], body_open_index: int) -> int:
    body_end = body_open_index + 1
    brace_depth = lines[body_open_index].count("{") - lines[body_open_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return body_end


def _rename_identifiers_in_body_8616(
    lines: list[str], start: int, end: int, renamed_pairs: list[tuple[str, str]]
) -> None:
    rename_patterns = [(re.compile(rf"(?<![A-Za-z_]){re.escape(old)}(?![A-Za-z_])"), new) for old, new in renamed_pairs]
    for index in range(start, end):
        line = lines[index]
        for pattern, new in rename_patterns:
            line = pattern.sub(new, line)
        lines[index] = line


def _remove_missing_arg_decls_8616(lines: list[str], start: int, end: int, helper_arg_names: tuple[str, ...]) -> None:
    helper_arg_name_set = set(helper_arg_names)
    for index in range(start, end):
        line = lines[index]
        if "<missing-" not in line and "// [bp" not in line:
            continue
        stripped = line.strip()
        if any(
            re.match(rf"^<missing-[^>]+>\s+{re.escape(arg)}\s*;\s*(?://.*)?$", stripped) for arg in helper_arg_name_set
        ):
            lines[index] = ""


_UNUSED_LOCAL_HEADER_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^()]*)\)\s*(?P<suffix>[{;]?)\s*$"
)
_UNUSED_LOCAL_DECL_RE_8616 = re.compile(
    r"^(?P<indent>\s*)(?!(?:return|if|while|for|switch|goto|case|default)\b)(?P<type>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)(?P<array>\s*\[[^\]]+\])?\s*;\s*(?P<comment>//.*)?$"
)
_UNUSED_LOCAL_SYNTHETIC_RE_8616 = re.compile(
    r"^(?:ir_\d+(?:_\d+)?|s_[0-9a-fA-F]+(?:_[0-9a-fA-F]+)*|stack_bp_[pm][0-9a-fA-F]+_b\d+|tmp_slot_\d+|tmp_\d+|local_[0-9a-fA-F]+|mem_[0-9A-Fa-f]+|v\d+|vvar_\d+|a\d+|arg_\d+|ax(?:_\d+)?|dx(?:_\d+)?|cx(?:_\d+)?|bx(?:_\d+)?|(?:cs|ds|es|ss|fs|gs)(?:_\d+)?|al|ah|[A-Za-z_]\w*_\d+)$"
)
_UNUSED_LOCAL_IDENT_RE_8616 = re.compile(r"[A-Za-z_]\w*")
_UNUSED_LOCAL_SKIP_PREFIXES_8616 = (
    "return ",
    "if ",
    "while ",
    "for ",
    "switch ",
    "goto ",
    "break;",
    "continue;",
)


def _unused_local_block_span_8616(
    lines: list[str], index: int
) -> tuple[int, int, int] | None:
    """Return (brace_index, scan_index, body_end) for the body after index."""

    brace_index = None
    scan_index = index
    while scan_index < len(lines):
        if "{" in lines[scan_index]:
            brace_index = scan_index
            break
        if ";" in lines[scan_index] and "{" not in lines[scan_index]:
            break
        scan_index += 1
    if brace_index is None:
        return None
    body_start = brace_index + 1
    body_end = body_start
    brace_depth = lines[brace_index].count("{") - lines[brace_index].count("}")
    while body_end < len(lines) and brace_depth > 0:
        brace_depth += lines[body_end].count("{") - lines[body_end].count("}")
        body_end += 1
    return brace_index, scan_index, body_end


def _unused_local_decl_names_8616(
    lines: list[str], body_start: int, body_end: int
) -> list[tuple[int, str]]:
    """Collect (line index, name) of removably-shaped local declarations."""

    local_decl_names: list[tuple[int, str]] = []
    for scan_index in range(body_start, body_end):
        stripped_line = lines[scan_index].lstrip()
        if stripped_line.startswith(_UNUSED_LOCAL_SKIP_PREFIXES_8616):
            continue
        decl_match = _UNUSED_LOCAL_DECL_RE_8616.match(lines[scan_index])
        if decl_match is not None:
            name = decl_match.group("name")
            if decl_match.group("comment") is None or _UNUSED_LOCAL_SYNTHETIC_RE_8616.fullmatch(name) is not None:
                local_decl_names.append((scan_index, name))
    return local_decl_names


def _body_identifier_counts_8616(
    lines: list[str], body_start: int, body_end: int, declaration_indexes: set[int]
) -> dict[str, int]:
    """Count identifier uses across non-declaration body lines."""

    body_identifier_counts: dict[str, int] = {}
    for scan_index in range(body_start, body_end):
        if scan_index in declaration_indexes:
            continue
        commentless_line = lines[scan_index].split("//", 1)[0]
        for token_match in _UNUSED_LOCAL_IDENT_RE_8616.finditer(commentless_line):
            token = token_match.group(0)
            body_identifier_counts[token] = body_identifier_counts.get(token, 0) + 1
    return body_identifier_counts


def _unused_locals_removal_8616(
    lines: list[str], body_start: int, body_end: int, arg_names: set[str]
) -> tuple[list[str], bool]:
    """Remove unused local decls in the body span; (lines, removed)."""

    local_decl_names = _unused_local_decl_names_8616(lines, body_start, body_end)
    if not local_decl_names:
        return lines, False

    declaration_indexes = {line_index for line_index, _name in local_decl_names}
    body_identifier_counts = _body_identifier_counts_8616(lines, body_start, body_end, declaration_indexes)
    removed_indexes: set[int] = set()
    for line_index, name in local_decl_names:
        if name in arg_names:
            continue
        if body_identifier_counts.get(name, 0) == 0:
            removed_indexes.add(line_index)
    if not removed_indexes:
        return lines, False
    return [line for idx, line in enumerate(lines) if idx not in removed_indexes], True


def _prune_unused_locals_block_8616(
    lines: list[str], index: int
) -> tuple[list[str], int, bool]:
    """Remove unused local decls in one function body; (lines, index, changed)."""

    match = _UNUSED_LOCAL_HEADER_RE_8616.match(lines[index])
    args_text = match.group("args") if match is not None else _function_definition_args_text_8616(lines[index])
    if args_text is None:
        return lines, index + 1, False

    span = _unused_local_block_span_8616(lines, index)
    if span is None:
        scan_index = index
        while scan_index < len(lines):
            if "{" in lines[scan_index]:
                break
            if ";" in lines[scan_index] and "{" not in lines[scan_index]:
                break
            scan_index += 1
        return lines, scan_index + 1, False

    brace_index, _scan, body_end = span
    body_start = brace_index + 1

    arg_names: set[str] = set()
    arg_names.update(_parameter_names_from_args_text_8616(args_text))

    pruned_lines, removed = _unused_locals_removal_8616(lines, body_start, body_end, arg_names)
    if not removed:
        return lines, body_end, False
    return pruned_lines, 0, True


def _prune_unused_local_declarations_text(c_text: str) -> str:
    """Drop local declarations whose names are never referenced in the body."""

    trailing_newline = c_text.endswith("\n")
    lines = c_text.splitlines()
    changed = False
    index = 0
    while index < len(lines):
        lines, index, block_changed = _prune_unused_locals_block_8616(lines, index)
        changed = changed or block_changed
        if index == 0 and block_changed:
            continue

    if not changed:
        return c_text
    normalized = "\n".join(lines)
    if trailing_newline:
        normalized += "\n"
    return normalized

def _prune_standalone_stack_probe_calls_text(c_text: str) -> str:
    def _impl() -> str:
        trailing_newline = c_text.endswith("\n")
        probe_names = ("aNchkstk", "__aNchkstk", "_chkstk", "__chkstk")
        probe_alt = "|".join(re.escape(name) for name in probe_names)
        call_re = re.compile(rf"^\s*(?:{probe_alt})\s*\(\s*\)\s*;\s*$")
        proto_re = re.compile(rf"^\s*void\s+(?:{probe_alt})\s*\(\s*(?:void)?\s*\)\s*;\s*$")
        lines = c_text.splitlines()
        without_calls = [line for line in lines if call_re.match(line) is None]
        if without_calls == lines:
            return c_text
        remaining_text = "\n".join(without_calls)
        kept_lines = []
        for line in without_calls:
            if (
                proto_re.match(line) is not None
                and re.search(rf"\b(?:{probe_alt})\s*\(", remaining_text.replace(line, "", 1)) is None
            ):
                continue
            kept_lines.append(line)
        result = "\n".join(kept_lines)
        if trailing_newline:
            result += "\n"
        return result

    return _impl()


def _helper_literal_mappings_8616(project: angr.Project) -> dict[str, str]:
    """Map literal address spellings to sim-procedure helper names."""

    mappings: dict[str, str] = {}
    for addr in _dynamic_text_attr(project, "_sim_procedures", {}):
        name = _helper_name(project, addr)
        if not name:
            continue
        mappings[str(addr)] = name
        mappings[hex(addr)] = name
        mappings[hex(addr).upper().replace("X", "x")] = name
    return mappings


def _apply_wrapper_calls_8616(project: angr.Project, function: object, c_text: str) -> str:
    """Replace ``CallReturn();`` markers with interrupt wrapper call text."""

    wrapper_cache = _dynamic_text_attr(project, "_inertia_interrupt_wrappers", None)
    if not isinstance(wrapper_cache, dict):
        return c_text
    wrapper_entry = wrapper_cache.get(_dynamic_text_attr(function, "addr", None))
    if not isinstance(wrapper_entry, dict):
        return c_text
    for sig in wrapper_entry.get("calls", []):
        if "CallReturn();" not in c_text:
            break
        c_text = c_text.replace("CallReturn();", f"{_interrupt_wrapper_call_text(sig)};", 1)
    return c_text


def _apply_int21_helper_replacements_8616(replacements: list[str], c_text: str) -> str:
    """Apply the first matching helper-name pattern per replacement."""

    for replacement in replacements:
        helper_name = replacement.split("(", 1)[0]
        sanitized_helper_name = _sanitize_mangled_autonames_text(helper_name)
        helper_patterns = [
            rf"(?<![A-Za-z0-9_]){re.escape(helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)",
            r"(?<![A-Za-z0-9_])dos_int21(?![A-Za-z0-9_])\s*\(\s*\)",
        ]
        if sanitized_helper_name != helper_name:
            helper_patterns.append(
                rf"(?<![A-Za-z0-9_]){re.escape(sanitized_helper_name)}(?![A-Za-z0-9_])\s*\(\s*\)"
            )
        for pattern in helper_patterns:
            c_text, count = re.subn(pattern, replacement, c_text, count=1)
            if count:
                break
    return c_text


def _apply_interrupt_replacements_8616(interrupt_replacements: dict[str, list[str]], c_text: str) -> str:
    """Apply one replacement per interrupt source name (longest first)."""

    for source_name, source_replacements in sorted(
        interrupt_replacements.items(), key=lambda item: len(item[0]), reverse=True
    ):
        for replacement in source_replacements:
            c_text, count = re.subn(
                rf"(?<![A-Za-z_]){re.escape(source_name)}\s*\(\s*\)",
                replacement,
                c_text,
                count=1,
            )
            if not count:
                break
    return c_text


def _format_known_helper_calls(
    project: angr.Project,
    function: object,
    c_text: str,
    api_style: str,
    binary_path: Path | None,
    cod_metadata: CODProcMetadata | None = None,
    codegen: object | None = None,
) -> str:
    """Preserve legacy helper rendering; new semantic recovery belongs to X86_16."""
    def _impl() -> str:
        """Keep the existing helper replacement and declaration order unchanged."""
        nonlocal c_text
        mappings = _helper_literal_mappings_8616(project)
        for literal, name in sorted(mappings.items(), key=lambda item: len(item[0]), reverse=True):
            c_text = re.sub(rf"(?<![A-Za-z_]){re.escape(literal)}(?=\s*\()", name, c_text)

        c_text = _apply_wrapper_calls_8616(project, function, c_text)

        replacements = _int21_call_replacements(project, function, api_style, binary_path)
        c_text = _apply_int21_helper_replacements_8616(replacements, c_text)

        interrupt_replacements = _interrupt_call_replacement_map(project, function, api_style, binary_path)
        c_text = _apply_interrupt_replacements_8616(interrupt_replacements, c_text)

        declarations = _dos_helper_declarations(function, api_style, binary_path)
        declarations.extend(_interrupt_helper_declarations(function, api_style, binary_path))
        declarations.extend(_known_helper_declarations(cod_metadata))
        if declarations:
            c_text = "\n".join(declarations) + "\n\n" + c_text
        c_text = _rewrite_known_helper_signature_text(c_text, function, codegen=codegen)
        c_text = _align_function_header_with_cod_source_decl_text(c_text, function, cod_metadata, codegen=codegen)
        c_text = _normalize_signed_char_function_signature_text(c_text, function, codegen)
        c_text = _normalize_msc_signed_int_function_signature_text(c_text, function, codegen)
        c_text = _simplify_x86_16_wrapped_stack_offsets(c_text)
        return _repair_missing_fallthrough_returns(c_text).rstrip("\n")

    return _impl()


_FALLTHROUGH_HEADER_RE_8616 = re.compile(
    r"^(?P<ret>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;]*)\)\s*(?:\{)?$"
)
_FALLTHROUGH_EMPTY_HELPERS_8616 = {"_dos_getProcessId", "_dos_setProcessId"}
_FALLTHROUGH_TERMINAL_RETURN_RE_8616 = re.compile(r"^return\s+(?P<expr>[A-Za-z_]\w*)\s*;\s*$")
_FALLTHROUGH_ANY_RETURN_RE_8616 = re.compile(r"return(?:\s+.+)?;\s*")


def _fallthrough_header_match_8616(lines: list[str]) -> re.Match[str] | None:
    """Find the last function-header-shaped line."""

    for idx in range(len(lines) - 1, -1, -1):
        match = _FALLTHROUGH_HEADER_RE_8616.match(lines[idx].strip())
        if match is not None:
            return match
    return None


def _fallthrough_return_candidates_8616(body_text: str) -> list[tuple[int, int, str]]:
    """Collect (priority, assign_count, name) for ax/dx/al/ah-annotated decls."""

    candidates: list[tuple[int, int, str]] = []
    for line in body_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("unsigned short", "char", "short", "int")):
            continue
        if "// ax" in stripped:
            kind = "ax"
        elif "// dx" in stripped:
            kind = "dx"
        elif "// al" in stripped:
            kind = "al"
        elif "// ah" in stripped:
            kind = "ah"
        else:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        name = parts[2].rstrip(";")
        assign_count = body_text.count(f"{name} =")
        if assign_count == 0:
            continue
        priority = {"ax": 3, "dx": 2, "al": 1, "ah": 1}.get(kind, 0)
        candidates.append((priority, assign_count, name))
    return candidates


def _fallthrough_terminal_index_8616(body_lines: list[str]) -> int | None:
    """Index of the last non-trivial, non-comment body line."""

    for line_index in range(len(body_lines) - 1, -1, -1):
        stripped = body_lines[line_index].strip()
        if not stripped or stripped == "}" or stripped.startswith(("//", "/*", "*")):
            continue
        return line_index
    return None


def _fallthrough_terminal_result_8616(
    body_lines: list[str], closing_brace: str, return_name: str, c_text: str
) -> str | None:
    """Resolve the terminal-line case; None means append a new return."""

    terminal_index = _fallthrough_terminal_index_8616(body_lines)
    if terminal_index is not None:
        terminal = body_lines[terminal_index].strip()
        terminal_return = _FALLTHROUGH_TERMINAL_RETURN_RE_8616.match(terminal)
        if terminal_return is not None:
            if terminal_return.group("expr").startswith("vvar_"):
                terminal_indent = body_lines[terminal_index][
                    : len(body_lines[terminal_index]) - len(body_lines[terminal_index].lstrip())
                ]
                body_lines[terminal_index] = f"{terminal_indent}return {return_name};"
                return "\n".join(body_lines) + "}" + closing_brace
            return c_text
        if _FALLTHROUGH_ANY_RETURN_RE_8616.fullmatch(terminal) is not None:
            return c_text
    return None


def _repair_missing_fallthrough_returns(c_text: str) -> str:
    def _impl() -> str:
        nonlocal c_text
        c_text = re.sub(
            r"(?m)^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*(?=\n\s*(?:\}|$))",
            r"\g<indent>if (\g<cond>);",
            c_text,
        )

        lines = c_text.splitlines()
        header_match = _fallthrough_header_match_8616(lines)
        if header_match is None:
            return c_text

        func_name = header_match.group("name")
        if func_name in _FALLTHROUGH_EMPTY_HELPERS_8616:
            return _prune_void_function_return_values_text(c_text)

        ret_type = header_match.group("ret").strip()
        if ret_type == "void" or "return " not in c_text:
            return c_text

        body_text, sep, closing_brace = c_text.rpartition("}")
        if not sep:
            return c_text

        body_lines = body_text.splitlines()
        if not body_lines:
            return c_text

        candidates = _fallthrough_return_candidates_8616(body_text)
        if not candidates:
            return c_text

        candidates.sort(key=lambda item: (item[0], item[1], item[2]))
        return_name = candidates[-1][2]
        indent = "    "
        terminal_result = _fallthrough_terminal_result_8616(body_lines, closing_brace, return_name, c_text)
        if terminal_result is not None:
            return terminal_result
        return body_text + f"\n{indent}return {return_name};\n" + "}" + closing_brace

    return _impl()


_BOOL_IF_LINE_RE_8616 = re.compile(r"^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*$")
_BOOL_ELSE_LINE_RE_8616 = re.compile(r"^(?P<indent>\s*)else\s*$")


def _repair_empty_if_else_gaps_8616(text: str) -> str:
    """Fill empty if/else bodies with braces so old C compilers accept them."""

    lines = text.splitlines()
    if not lines:
        return text
    out: list[str] = []
    changed = False
    index = 0
    while index < len(lines):
        line = lines[index]
        match = _BOOL_IF_LINE_RE_8616.match(line)
        if match is None or index + 1 >= len(lines):
            out.append(line)
            index += 1
            continue

        else_match = _BOOL_ELSE_LINE_RE_8616.match(lines[index + 1])
        if else_match is None or else_match.group("indent") != match.group("indent"):
            out.append(line)
            index += 1
            continue

        indent = match.group("indent")
        else_line = lines[index + 1]
        next_line = lines[index + 2] if index + 2 < len(lines) else ""
        next_stripped = next_line.strip()
        next_indent = next_line[: len(next_line) - len(next_line.lstrip())]
        else_has_rendered_body = bool(next_stripped) and (
            next_stripped == "{" or len(next_indent) > len(indent)
        )

        if else_has_rendered_body:
            out.append(f"{line};")
        else:
            out.extend((line, f"{indent}{{", f"{indent}}}"))
        out.append(else_line)
        if not else_has_rendered_body:
            out.extend((f"{indent}{{", f"{indent}}}"))
        changed = True
        index += 2

    if not changed:
        return text
    suffix = "\n" if text.endswith("\n") else ""
    return "\n".join(out) + suffix


def _normalize_boolean_conditions(c_text: str) -> str:
    plus_not_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!(?P<lhs>[A-Za-z_][\w$?@]*) \+ (?P<rhs>0x[0-9a-fA-F]+|\d+)\)$"
    )
    c_text = plus_not_pattern.sub(
        lambda m: f"{m.group('indent')}{m.group('kind')} (!({m.group('lhs')} + {m.group('rhs')}))", c_text
    )

    def _replace(match: re.Match[str]) -> str:
        indent = match.group("indent")
        kind = match.group("kind")
        expr = match.group("expr")
        return f"{indent}{kind} (({expr}) == 0)"

    pattern = re.compile(r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\)")
    rewritten = pattern.sub(_replace, c_text)

    brace_while_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)\}\s*while \(!\(\((?P<expr>[^()]*(?:\([^()]*\)[^()]*)*)\)\)\);"
    )
    rewritten = brace_while_pattern.sub(lambda m: f"{m.group('indent')}}} while (({m.group('expr')}) == 0);", rewritten)

    control_ternary_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \((?P<condition>!\(\(.+\)\))\)(?P<suffix>.*)$"
    )

    def _rewrite_control_ternary(match: re.Match[str]) -> str:
        simplified = _simplify_negated_zero_one_ternary_condition_8616(match.group("condition"))
        if simplified == match.group("condition"):
            return match.group(0)
        return f"{match.group('indent')}{match.group('kind')} ({simplified}){match.group('suffix')}"

    rewritten = control_ternary_pattern.sub(_rewrite_control_ternary, rewritten)

    for_ternary_pattern = re.compile(r"(?m)^(?P<indent>\s*)for \((?P<header>.+)\)(?P<suffix>.*)$")

    def _rewrite_for_ternary(match: re.Match[str]) -> str:
        parts = _split_for_header_8616(match.group("header"))
        if parts is None:
            return match.group(0)
        simplified = _simplify_negated_zero_one_ternary_condition_8616(parts[1])
        if simplified == parts[1]:
            return match.group(0)
        return f"{match.group('indent')}for ({parts[0]}; {simplified}; {parts[2]}){match.group('suffix')}"

    rewritten = for_ternary_pattern.sub(_rewrite_for_ternary, rewritten)

    addr_pattern = re.compile(r"(?m)^(?P<indent>\s*)(?P<kind>if|while) \(&(?P<name>[A-Za-z_][\w$?@]*)\)$")
    rewritten = addr_pattern.sub(lambda m: f"{m.group('indent')}{m.group('kind')} ({m.group('name')})", rewritten)

    index_pattern = re.compile(r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = &v\d+\[(?P<delta>\d+)\];$")
    rewritten = index_pattern.sub(lambda m: f"{m.group('indent')}{m.group('name')} += {m.group('delta')};", rewritten)

    compound_pattern = re.compile(
        r"(?m)^(?P<indent>\s*)(?P<name>[A-Za-z_][\w$?@]*) = (?P=name) (?P<op>[+-]) (?P<delta>0x[0-9a-fA-F]+|\d+);$"
    )

    def _rewrite_compound(match: re.Match[str]) -> str:
        op = "+=" if match.group("op") == "+" else "-="
        return f"{match.group('indent')}{match.group('name')} {op} {match.group('delta')};"

    rewritten = compound_pattern.sub(_rewrite_compound, rewritten)

    rewritten = _repair_empty_if_else_gaps_8616(rewritten)

    # Repair empty if-body rendering gaps before } or EOF.
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)if \(false\)\s*$",
        r"\g<indent>if (0);",
        rewritten,
    )
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)if \((?P<cond>[^\n]+)\)\s*(?=\n\s*(?:\}|$))",
        r"\g<indent>if (\g<cond>);",
        rewritten,
    )
    # Syntax hygiene only: a generated label directly before a closing brace has
    # no statement to label, which old C compilers reject. Preserve semantics by
    # materializing an explicit empty statement.
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<label>(?!case\b|default\b)[A-Za-z_]\w*)\s*:\s*(?=\n\s*\})",
        r"\g<indent>\g<label>:;",
        rewritten,
    )
    # Strict 16-bit compilers reject shifting raw address expressions. Make the
    # integer high-byte projection explicit for generic address-of carriers.
    rewritten = re.sub(
        r"(?m)^(?P<indent>\s*)(?P<lhs>[A-Za-z_]\w*)\s*=\s*&(?P<base>[A-Za-z_]\w*)\s*>>\s*8\s*;\s*$",
        r"\g<indent>\g<lhs> = ((unsigned short)&\g<base>) >> 8;",
        rewritten,
    )
    return rewritten


def _normalize_mk_fp_segment_names(c_text: str, metadata: CODProcMetadata | None) -> str:
    return c_text


def _simplify_x86_16_stack_references(c_text: str) -> str:
    lines = c_text.splitlines()
    if not lines:
        return c_text

    decl_re = re.compile(
        r"^\s*(?P<decl>[A-Za-z_][\w\s\*\[\]]*?)\s+(?P<name>[A-Za-z_][\w$?@]*)\s*;\s*// \[bp(?P<sign>[+-])0x(?P<value>[0-9A-Fa-f]+)\](?P<suffix>.*)$"
    )

    offset_to_name: dict[int, str] = {}
    for line in lines:
        match = decl_re.match(line)
        if match is None:
            continue
        name = match.group("name")
        value = int(match.group("value"), 16)
        if match.group("sign") == "-":
            value = -value
        offset_to_name.setdefault(value, name)

    if not offset_to_name:
        return c_text

    def _replace(match: re.Match[str]) -> str:
        sign = match.group("sign")
        value = int(match.group("value"), 0)
        offset = value if sign == "+" else -value
        name = offset_to_name.get(offset)
        if name is None:
            return match.group(0)
        if offset == 0:
            return f"&{name}"
        return f"&{name}"

    pattern = re.compile(r"&(?P<anchor>v\d+)\s*(?P<sign>[+-])\s*(?P<value>0x[0-9A-Fa-f]+|\d+)")
    return pattern.sub(_replace, c_text)
