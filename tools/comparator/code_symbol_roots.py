"""Layer: comparator public-symbol correspondence intake.

Responsibility: recover missing root proposals from unique image-validated
LINK publics. Public names select obligations, never establish equivalence.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from enum import StrEnum
from typing import TYPE_CHECKING

from tools.comparator.msc8_catalog import Symbol
from tools.comparator.msc8_dependencies import _code_extent

if TYPE_CHECKING:
    import angr

    from tools.dosunit.catalog.pe32_link_map import Pe32LinkMap


class CodeSymbolMatchStatus(StrEnum):
    """A selected or ambiguous public declaration, not a proof verdict."""

    ADDED = "added"
    AMBIGUOUS = "ambiguous"


def public_root_name(name: str) -> str:
    """Remove one i386 C underscore and an optional decimal stdcall suffix.

    This is only name correspondence. The suffix does not declare an ABI,
    argument count or function effect to the proof engine.
    """
    return re.sub(r"@[0-9]+$", "", name.removeprefix("_"))


def match_code_symbol_roots(
    candidate: angr.Project, symbols: dict[str, Symbol], names: list[str], code_map: Pe32LinkMap,
) -> tuple[dict[str, Symbol], list[dict[str, object]]]:
    """Propose missing roots while retaining declared mappings and unique entries.

    Public and static coordinates bound scan envelopes, but only publics can
    establish a root proposal. Aliases at one address are deduplicated; two
    distinct addresses with the same canonical name remain ambiguous. Native
    CFG closure and complete effect proofs remain mandatory after admission.
    """
    declarations: dict[int, int] = {}
    matching: dict[str, set[int]] = {}
    for public in (*code_map.publics, *code_map.statics):
        extent = _code_extent(candidate, code_map, public)
        if extent is None:
            continue
        entry, end = extent
        declarations[entry] = min(end, declarations.get(entry, end))
    for public in code_map.publics:
        delta = int(candidate.loader.main_object.mapped_base) - int(candidate.loader.main_object.linked_base)
        entry = public.address + delta
        if entry in declarations and _code_extent(candidate, code_map, public) is not None:
            matching.setdefault(public_root_name(public.name), set()).add(entry)
    delta = int(candidate.loader.main_object.mapped_base) - int(candidate.loader.main_object.linked_base)
    entries = sorted(declarations.keys() | {
        symbol.address + delta for symbol in symbols.values() if symbol.kind in {"T", "t", "W", "w"}
    })
    result = dict(symbols)
    evidence: list[dict[str, object]] = []
    for name in sorted(set(names) - symbols.keys()):
        targets = sorted(matching.get(name, ()))
        if not targets:
            continue
        status = CodeSymbolMatchStatus.AMBIGUOUS
        if len(targets) == 1:
            entry = targets[0]
            index = bisect_right(entries, entry)
            end = min(declarations[entry], entries[index] if index < len(entries) else declarations[entry])
            result[name] = Symbol(entry - delta, end - entry, "T")
            status = CodeSymbolMatchStatus.ADDED
        evidence.append({"function": name, "status": status.value,
                         "candidate_entries": [hex(entry) for entry in targets],
                         "function_equivalence_proved": False,
                         "correspondence": "unique_decorated_public_name"})
    return result, evidence
