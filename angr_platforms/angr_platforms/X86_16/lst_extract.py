"""Layer: Optional evidence/reporting.

Responsibility: parse LST/debug evidence into optional labels and diagnostics.
Forbidden: requiring listing text for arguments, types, control flow, or validation success.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DebugTypeMemberEvidence:
    """Optional debug evidence for one member of a recovered type."""

    name: str
    offset: int | None = None
    owner_type_index: int | None = None
    type_index: int | None = None
    leaf_index: int | None = None
    attributes: int | None = None
    source: str = ""


@dataclass(frozen=True)
class DebugTypeReferenceEvidence:
    """Optional debug evidence linking a symbol name to a type index."""

    name: str
    type_index: int
    symbol_class: str = ""
    source: str = ""


@dataclass(frozen=True)
class DebugSymbolEvidence:
    """Optional debug evidence for one named data or code symbol."""

    name: str
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


@dataclass(frozen=True)
class DebugTypeDescriptorEvidence:
    """Optional debug evidence describing a type record from listing metadata."""

    type_index: int
    kind: str
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


@dataclass(frozen=True)
class DebugEnumMemberEvidence:
    """Optional debug evidence for one enum member value."""

    name: str
    value: int
    owner_type_index: int | None = None
    attributes: int | None = None
    source: str = ""


@dataclass(frozen=True)
class LSTMetadata:
    """Optional listing metadata consumed as labels and diagnostics only."""

    data_labels: dict[int, str]
    code_labels: dict[int, str]
    code_ranges: dict[int, tuple[int, int]] = field(default_factory=dict)
    function_entry_addrs: frozenset[int] = field(default_factory=frozenset)
    signature_code_addrs: frozenset[int] = field(default_factory=frozenset)
    absolute_addrs: bool = False
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
    debug_line_map: dict[int, tuple[int, int]] = field(default_factory=dict)
    cod_path: str | None = None
    cod_proc_kinds: dict[int, str] = field(default_factory=dict)


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


def _update_summary_section_8616(stripped: str, current_summary_section: str | None) -> str | None:
    if _PROCEDURES_HEADER_RE.match(stripped):
        return "procedures"
    if _SYMBOLS_HEADER_RE.match(stripped):
        return "symbols"
    if current_summary_section is not None and _SECTION_HEADER_RE.match(stripped):
        return None
    return current_summary_section


def _consume_summary_row_8616(
    stripped: str,
    current_summary_section: str | None,
    code_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    data_labels: dict[int, str],
) -> bool:
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


def _segment_directive_target_8616(
    stripped: str, current_segment: str | None
) -> tuple[str | None, bool] | None:
    """Resolve one ``SEGMENT`` directive to its space or keep the current one."""
    segment_match = _SEGMENT_RE.match(stripped)
    if segment_match is None:
        return None
    segment_name = segment_match.group(1).lower()
    if "code" in segment_name or segment_name in {"text", "_text"}:
        return "CODE", True
    if "data" in segment_name or segment_name in {"_data", "dseg"}:
        return "DATA", True
    return current_segment, True


def _ends_directive_target_8616(
    stripped: str, current_segment: str | None
) -> tuple[str | None, bool] | None:
    """Resolve one ``ENDS`` directive closing the matching space."""
    ends_match = _ENDS_RE.match(stripped)
    if ends_match is None:
        return None
    segment_name = ends_match.group(1).lower()
    if current_segment == "CODE" and ("code" in segment_name or segment_name in {"text", "_text"}):
        return None, True
    if current_segment == "DATA" and ("data" in segment_name or segment_name in {"_data", "dseg"}):
        return None, True
    return current_segment, True


def _maybe_update_current_segment_8616(
    stripped: str, upper: str, current_segment: str | None
) -> tuple[str | None, bool]:
    """Track the listing's current segment space from its directives."""
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


def _consume_code_segment_line_8616(
    stripped: str,
    code_labels: dict[int, str],
    code_ranges: dict[int, tuple[int, int]],
    colon_code_labels: dict[str, int],
    open_proc_starts: dict[str, int],
) -> None:
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


def _infer_lst_source_format_8616(lines: list[str]) -> str:
    if lines and lines[0].startswith("UASM "):
        return "uasm_lst"
    if lines and lines[0].startswith("Microsoft (R) Macro Assembler"):
        return "masm_lst"
    if any(line.startswith("seg") and "; |" not in line for line in lines[:32]):
        return "ida_lst"
    return "generic_lst"


def extract_lst_metadata(lst_path: Path) -> LSTMetadata:
    """Parse optional LST labels without making listing text semantic proof."""
    lines = lst_path.read_text(errors="ignore").splitlines()
    data_labels: dict[int, str] = {}
    code_labels: dict[int, str] = {}
    code_ranges: dict[int, tuple[int, int]] = {}
    colon_code_labels: dict[str, int] = {}

    current_segment: str | None = None
    current_summary_section: str | None = None
    open_proc_starts: dict[str, int] = {}
    entry_label_name: str | None = None

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
