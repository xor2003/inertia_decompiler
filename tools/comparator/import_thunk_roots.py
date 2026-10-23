"""Layer: comparator binary-bound correspondence intake.

Responsibility: propose missing roots only from unique executable JMP-IAT
thunks to the same loaded DLL/import identity. This establishes no ABI or proof.
"""

from __future__ import annotations

from enum import StrEnum
from typing import TYPE_CHECKING

import pefile

from tools.comparator.msc8_catalog import Symbol
from tools.comparator.msc8_dependencies import _code_extent
from tools.dosunit.architectures.flat32_pe_loader import InclusivePE
from tools.dosunit.catalog.pe32_link_map import Pe32LinkMap
from tools.dosunit.runtime.pe32_import_service import parse_pe32_imports

if TYPE_CHECKING:
    import angr


class ThunkMatchStatus(StrEnum):
    """Correspondence evidence only; none of these statuses means equivalence."""

    ADDED = "added"
    UNMATCHED = "unmatched"
    AMBIGUOUS = "ambiguous"


def _import_slots(project: angr.Project) -> dict[int, tuple[str, str]]:
    """Read import identities from the exact PE snapshot already loaded by CLE."""
    main = project.loader.main_object
    if not isinstance(main, InclusivePE):
        raise ValueError("import-thunk root matching requires loaded PE images")
    parsed = pefile.PE(data=main.source_pe_bytes)
    try:
        bias = int(main.mapped_base) - int(parsed.OPTIONAL_HEADER.ImageBase)
        return {symbol.slot + bias: (symbol.dll, symbol.name) for symbol in parse_pe32_imports(parsed)}
    finally:
        parsed.close()


def _thunk_slot(project: angr.Project, entry: int) -> int | None:
    """Admit one six-byte absolute JMP wholly within mapped executable memory."""
    section = project.loader.find_section_containing(entry)
    if section is None or not section.is_executable or entry + 5 > section.max_addr:
        return None
    raw = project.loader.memory.load(entry, 6)
    if len(raw) != 6 or raw[:2] != b"\xff\x25":
        return None
    return int.from_bytes(raw[2:], "little")


def _direct_jump_target(project: angr.Project, entry: int) -> int | None:
    """Decode an effect-free rel8/rel32 JMP wholly inside executable memory."""
    section = project.loader.find_section_containing(entry)
    if section is None or not section.is_executable:
        return None
    opcode = project.loader.memory.load(entry, 1)
    size = {b"\xeb": 2, b"\xe9": 5}.get(opcode)
    if size is None or entry + size - 1 > section.max_addr:
        return None
    raw = project.loader.memory.load(entry, size)
    if len(raw) != size:
        return None
    return (entry + size + int.from_bytes(raw[1:], "little", signed=True)) & 0xFFFFFFFF


def _original_import_route(project: angr.Project, entry: int) -> tuple[int, tuple[int, ...]] | None:
    """Follow at most sixteen effect-free JMPs to one native JMP-IAT root.

    This only proposes correspondence. The normal comparator must still
    compose the declared original functions, prove the live target, and
    preserve all external-call premises. Cycles and effectful veneers cannot
    establish an import route here.
    """
    route: list[int] = []
    for _ in range(16):
        if entry in route:
            return None
        route.append(entry)
        slot = _thunk_slot(project, entry)
        if slot is not None:
            return slot, tuple(route)
        target = _direct_jump_target(project, entry)
        if target is None:
            return None
        entry = target
    return None


def match_import_thunk_roots(
    oracle: angr.Project, candidate: angr.Project, boundaries: dict[str, tuple[int, int]],
    symbols: dict[str, Symbol], names: list[str], code_map: Pe32LinkMap,
) -> tuple[dict[str, Symbol], list[dict[str, object]]]:
    """Fill missing root declarations only when native import routes match uniquely.

    Public LINK coordinates are validated against the candidate image. Public
    spelling is irrelevant to matching; aliases at one address are deduplicated
    and distinct candidate addresses for an import remain ambiguous. Existing
    caller-supplied mappings always retain priority. The normal native proof
    pipeline still checks every admitted root and any external premises.
    """
    original_imports, candidate_imports = _import_slots(oracle), _import_slots(candidate)
    targets: dict[tuple[str, str], set[int]] = {}
    for public in code_map.publics:
        extent = _code_extent(candidate, code_map, public)
        if extent is None or extent[1] - extent[0] < 6:
            continue
        slot = _thunk_slot(candidate, extent[0])
        if slot is not None and slot in candidate_imports:
            targets.setdefault(candidate_imports[slot], set()).add(extent[0])
    result = dict(symbols)
    evidence: list[dict[str, object]] = []
    bias = int(candidate.loader.main_object.mapped_base) - int(candidate.loader.main_object.linked_base)
    for name in sorted(set(names) & boundaries.keys() - symbols.keys()):
        original_entry = boundaries[name][0]
        route = _original_import_route(oracle, original_entry)
        if route is None or route[0] not in original_imports:
            continue
        slot, addresses = route
        identity = original_imports[slot]
        entries = sorted(targets.get(identity, ()))
        status = ThunkMatchStatus.AMBIGUOUS if len(entries) > 1 else ThunkMatchStatus.UNMATCHED
        if len(entries) == 1:
            result[name] = Symbol(entries[0] - bias, 6, "T")
            status = ThunkMatchStatus.ADDED
        evidence.append({"function": name, "status": status.value, "original_entry": hex(original_entry),
                         "original_slot": hex(slot), "original_route": [hex(address) for address in addresses],
                         "dll": identity[0], "import": identity[1],
                         "candidate_entries": [hex(entry) for entry in entries],
                         "function_equivalence_proved": False})
    return result, evidence
