# cython: language_level=3, infer_types=True
"""Layer: Optional evidence/reporting.

Responsibility: parse LST/debug evidence into optional labels and diagnostics.
Forbidden: requiring listing text for arguments, types, control flow, or validation success.

Package ownership contract (canonical inertia/cli package):
Layer: CLI/fallback/reporting.
Owns command entrypoints, fallback orchestration, diagnostics, and reporting of recovered evidence.
Do not perform frontend, IR, semantic, alias, widening, lowering, structuring, rewrite,
postprocess, or validation work here.
"""

from __future__ import annotations
import typing
import cython

import re
from dataclasses import dataclass, field
from pathlib import Path
import dataclasses


@dataclasses.dataclass(frozen=True)
class DebugTypeMemberEvidence:
    """Optional debug evidence for one member of a recovered type."""

    name: object
    offset: int | None = None
    owner_type_index: int | None = None
    type_index: int | None = None
    leaf_index: int | None = None
    attributes: int | None = None
    source: str = ""


@dataclasses.dataclass(frozen=True)
class DebugTypeReferenceEvidence:
    """Optional debug evidence linking a symbol name to a type index."""

    name: object
    type_index: cython.longlong
    symbol_class: str = ""
    source: str = ""


@dataclasses.dataclass(frozen=True)
class DebugSymbolEvidence:
    """Optional debug evidence for one named data or code symbol."""

    name: object
    symbol_class: str = ""
    storage: str = ""
    offset: int | None = None
    signed_offset: int | None = None
    segment: int | None = None
    linear_addr: int | None = None
    length: int | None = None
    type_index: int | None = None
    owner_name: str = ""
    attributes: tuple[tuple[str, str], ...] = ()
    source: str = ""


@dataclasses.dataclass(frozen=True)
class DebugTypeDescriptorEvidence:
    """Optional debug evidence describing a type record from listing metadata."""

    type_index: cython.longlong
    kind: object
    name: str = ""
    size: int | None = None
    base_type_index: int | None = None
    target_type_index: int | None = None
    return_type_index: int | None = None
    call_kind: int | None = None
    attributes: int | None = None
    lower_bound: int | None = None
    upper_bound: int | None = None
    source: str = ""


@dataclasses.dataclass(frozen=True)
class DebugEnumMemberEvidence:
    """Optional debug evidence for one enum member value."""

    name: object
    value: cython.longlong
    owner_type_index: int | None = None
    attributes: int | None = None
    source: str = ""


@dataclasses.dataclass(frozen=True)
class LSTMetadata:
    """Optional listing metadata consumed as labels and diagnostics only."""

    data_labels: object
    code_labels: object
    code_ranges: object = field(default_factory=dict)
    function_entry_addrs: object = field(default_factory=frozenset)
    signature_code_addrs: object = field(default_factory=frozenset)
    absolute_addrs: cython.bint = False
    source_format: str = "generic_lst"
    struct_names: tuple[str, ...] = ()
    debug_source_files: tuple[str, ...] = ()
    debug_type_names: tuple[str, ...] = ()
    debug_type_descriptors: tuple[DebugTypeDescriptorEvidence, ...] = ()
    debug_type_references: tuple[DebugTypeReferenceEvidence, ...] = ()
    debug_symbols: tuple[DebugSymbolEvidence, ...] = ()
    debug_type_members: tuple[DebugTypeMemberEvidence, ...] = ()
    debug_enum_members: tuple[DebugEnumMemberEvidence, ...] = ()
    debug_identifiers: tuple[str, ...] = ()
    debug_line_map: object = field(default_factory=dict)
    cod_path: object = None
    cod_proc_kinds: object = field(default_factory=dict)
    # Binary-pattern extents only; never synthesized from labels or debug bounds.
    signature_code_ranges: object = field(default_factory=dict)


_DATA_LABEL_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+(?:(?:[0-9A-Fa-f]{2,}(?:\s+[0-9A-Fa-f]{2,})*\s+)?)"
    r"([A-Za-z_$?@][\w$?@]*)\s+(db|dw|dd|dq|dt)\b",
    re.IGNORECASE,
)
_PROC_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s+proc(?:\s+\w+)?\b",
    re.IGNORECASE,
)
_ENDP_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s+endp\b",
    re.IGNORECASE,
)
_CODE_LABEL_RE = re.compile(
    r"^(?:[A-Za-z_][\w$?@]*:)?([0-9A-Fa-f]{4,8})\s+([A-Za-z_$?@][\w$?@]*)\s*:\s*$",
    re.IGNORECASE,
)
_SEGMENT_RE = re.compile(r"^(?:[0-9A-Fa-f]{4,8}\s+)?([A-Za-z_$?@][\w$?@]*)\s+segment\b", re.IGNORECASE)
_ENDS_RE = re.compile(r"^(?:[0-9A-Fa-f]{4,8}\s+)?([A-Za-z_$?@][\w$?@]*)\s+ends\b", re.IGNORECASE)
_DOT_SEGMENT_RE = re.compile(r"^\.(code|data)\b", re.IGNORECASE)
_END_RE = re.compile(r"^end\s+([A-Za-z_$?@][\w$?@]*)\b", re.IGNORECASE)
_PROCEDURES_HEADER_RE = re.compile(r"^Procedures,\s+parameters and locals:", re.IGNORECASE)
_SYMBOLS_HEADER_RE = re.compile(r"^Symbols:", re.IGNORECASE)
_SECTION_HEADER_RE = re.compile(r"^[A-Za-z].*:$")
_MASM_PROCEDURE_ROW_RE = re.compile(
    r"^([A-Za-z_$?@][\w$?@]*)\b.*\bP\s+\w+\s+([0-9A-Fa-f]{4,8})\b.*Length=\s*([0-9A-Fa-f]{4,8})",
    re.IGNORECASE,
)
_MASM_SYMBOL_ROW_RE = re.compile(
    r"^([A-Za-z_$?@][\w$?@]*)\b.*\b(Byte|Word|DWord|QWord|TByte)\s+([0-9A-Fa-f]{4,8})\b",
    re.IGNORECASE,
)


@cython.ccall
def _update_summary_section_8616(stripped: object, current_summary_section: object) -> object:
    if _PROCEDURES_HEADER_RE.match(stripped):
        return "procedures"
    if _SYMBOLS_HEADER_RE.match(stripped):
        return "symbols"
    if current_summary_section is not None and _SECTION_HEADER_RE.match(stripped):
        return None
    return current_summary_section


@cython.ccall
def _consume_summary_row_8616(
    stripped: object,
    current_summary_section: object,
    code_labels: object,
    code_ranges: object,
    data_labels: object,
) -> cython.bint:
    procedure_row: object
    symbol_row: object
    if current_summary_section == "procedures":
        procedure_row = _MASM_PROCEDURE_ROW_RE.match(stripped)
        if procedure_row is not None:
            name = procedure_row.group(1)
            start_offset = int(procedure_row.group(2), 16)
            length = int(procedure_row.group(3), 16)
            code_labels.setdefault(start_offset, name)
            if length > 0:
                code_ranges.setdefault(start_offset, (start_offset, start_offset + length))
        return True
    if current_summary_section == "symbols":
        symbol_row = _MASM_SYMBOL_ROW_RE.match(stripped)
        if symbol_row is not None:
            data_labels.setdefault(int(symbol_row.group(3), 16), symbol_row.group(1))
        return True
    return False


@cython.ccall
def _segment_directive_target_8616(
    stripped: object, current_segment: object
) -> object:
    """Resolve one ``SEGMENT`` directive to its space or keep the current one."""
    segment_match: object
    segment_match = _SEGMENT_RE.match(stripped)
    if segment_match is None:
        return None
    segment_name = segment_match.group(1).lower()
    if "code" in segment_name or segment_name in {"text", "_text"}:
        return "CODE", True
    if "data" in segment_name or segment_name in {"_data", "dseg"}:
        return "DATA", True
    return current_segment, True


@cython.ccall
def _ends_directive_target_8616(
    stripped: object, current_segment: object
) -> object:
    """Resolve one ``ENDS`` directive closing the matching space."""
    ends_match: object
    ends_match = _ENDS_RE.match(stripped)
    if ends_match is None:
        return None
    segment_name = ends_match.group(1).lower()
    if current_segment == "CODE" and ("code" in segment_name or segment_name in {"text", "_text"}):
        return None, True
    if current_segment == "DATA" and ("data" in segment_name or segment_name in {"_data", "dseg"}):
        return None, True
    return current_segment, True


@cython.ccall
def _maybe_update_current_segment_8616(
    stripped: object, upper: object, current_segment: object
) -> object:
    """Track the listing's current segment space from its directives."""
    dot_segment_match: object
    target: object
    target = _segment_directive_target_8616(stripped, current_segment)
    if target is not None:
        return target
    target = _ends_directive_target_8616(stripped, current_segment)
    if target is not None:
        return target
    dot_segment_match = _DOT_SEGMENT_RE.match(stripped)
    if dot_segment_match is not None:
        return dot_segment_match.group(1).upper(), True
    if "SEGMENT" in upper and "USE16" in upper:
        if "CODE" in upper:
            return "CODE", True
        if "DATA" in upper:
            return "DATA", True
        return current_segment, True
    return current_segment, False


@cython.ccall
def _consume_code_segment_line_8616(
    stripped: object,
    code_labels: object,
    code_ranges: object,
    colon_code_labels: object,
    open_proc_starts: object,
) -> None:
    endp_match: object
    label_match: object
    proc_match: object
    start_offset: object
    proc_match = _PROC_RE.match(stripped)
    if proc_match is not None:
        offset = int(proc_match.group(1), 16)
        name = proc_match.group(2)
        code_labels.setdefault(offset, name)
        open_proc_starts[name] = offset
        return
    endp_match = _ENDP_RE.match(stripped)
    if endp_match is not None:
        end_offset = int(endp_match.group(1), 16)
        name = endp_match.group(2)
        start_offset = open_proc_starts.pop(name, None)
        if start_offset is not None and end_offset > start_offset:
            code_ranges[start_offset] = (start_offset, end_offset)
        return
    label_match = _CODE_LABEL_RE.match(stripped)
    if label_match is not None:
        colon_code_labels.setdefault(label_match.group(2), int(label_match.group(1), 16))


def _infer_lst_source_format_8616(lines: object) -> str:
    if lines and lines[0].startswith("UASM "):
        return "uasm_lst"
    if lines and lines[0].startswith("Microsoft (R) Macro Assembler"):
        return "masm_lst"
    if any(line.startswith("seg") and "; |" not in line for line in iter(lines[:32])):
        return "ida_lst"
    return "generic_lst"


@cython.ccall
def extract_lst_metadata(lst_path: Path) -> LSTMetadata:
    """Parse optional LST labels without making listing text semantic proof."""
    end_match: object
    entry_label_name: object
    entry_offset: object
    match: object
    line: object
    lines = lst_path.read_text(errors="ignore").splitlines()
    data_labels: dict[cython.longlong, str] = {}
    code_labels: dict[cython.longlong, str] = {}
    code_ranges: dict[cython.longlong, tuple[cython.longlong, cython.longlong]] = {}
    colon_code_labels: dict[str, cython.longlong] = {}

    current_segment: object = None
    current_summary_section: object = None
    open_proc_starts: dict[str, cython.longlong] = {}
    entry_label_name = None

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue

        upper = stripped.upper()
        current_summary_section = _update_summary_section_8616(stripped, current_summary_section)
        if _consume_summary_row_8616(stripped, current_summary_section, code_labels, code_ranges, data_labels):
            continue

        end_match = _END_RE.match(stripped)
        if end_match is not None:
            entry_label_name = end_match.group(1)
            continue

        current_segment, consumed_segment = _maybe_update_current_segment_8616(stripped, upper, current_segment)
        if consumed_segment:
            continue

        match = _DATA_LABEL_RE.match(stripped)
        if match is not None:
            offset = int(match.group(1), 16)
            data_labels.setdefault(offset, match.group(2))
            continue

        if current_segment == "CODE":
            _consume_code_segment_line_8616(stripped, code_labels, code_ranges, colon_code_labels, open_proc_starts)

    if entry_label_name is not None:
        entry_offset = colon_code_labels.get(entry_label_name)
        if entry_offset is not None:
            code_labels.setdefault(entry_offset, entry_label_name)

    source_format = _infer_lst_source_format_8616(lines)
    return LSTMetadata(
        data_labels=data_labels, code_labels=code_labels, code_ranges=code_ranges, source_format=source_format
    )
