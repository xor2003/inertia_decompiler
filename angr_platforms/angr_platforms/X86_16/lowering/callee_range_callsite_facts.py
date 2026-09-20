"""Collect direct-caller facts from independently framed binary ranges.

Layer: Types/Lowering.
Responsibility: decode each supplied caller range once, retain exact direct-call
coordinates, and bind existing recovery summaries to canonical callee targets.
This module does not derive argument interfaces or mutate generated C.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM

from ..analysis_helpers import canonicalize_x86_16_padding_call_target_8616
from ..callsite_summary import summarize_x86_16_callsite
from ..frontend_caller_entry_identity import prove_caller_entry_identity_8616
from ..frontend_function_boundary_index import exact_function_range_inventory_8616
from .callee_callsite_contracts import CalleeCallsiteFact8616

__all__ = [
    "collect_range_callsite_facts_8616",
    "collect_range_callsite_facts_for_target_8616",
]


class _InstructionOperand8616(Protocol):
    """Capstone operand fields consumed at the disassembly boundary."""

    type: int
    imm: int


class _Instruction8616(Protocol):
    """Capstone instruction fields consumed for direct-call discovery."""

    address: int
    mnemonic: str
    operands: Sequence[_InstructionOperand8616]


class _Disassembler8616(Protocol):
    """Capstone engine surface used to decode proven caller ranges."""

    detail: bool

    def disasm(self, code: bytes, address: int) -> Iterable[_Instruction8616]:
        """Decode one bounded caller range."""
        ...


class _Memory8616(Protocol):
    """angr loader-memory surface used by the range decoder."""

    def load(self, address: int, size: int) -> bytes:
        """Read bytes from mapped binary memory."""
        ...


class _ArchSurface8616(Protocol):
    """angr architecture fields used by the range decoder."""

    capstone: _Disassembler8616


class _LoaderSurface8616(Protocol):
    """angr loader fields used by the range decoder."""

    memory: _Memory8616


class _RangeProjectSurface8616(Protocol):
    """angr project fields needed to summarize raw caller ranges."""

    arch: _ArchSurface8616
    loader: _LoaderSurface8616
    _inertia_range_direct_call_ranges_8616: tuple[tuple[int, int], ...]
    _inertia_range_direct_calls_by_target_8616: dict[
        int,
        tuple[tuple[tuple[int, int], _Instruction8616], ...],
    ]


def _direct_call_target_8616(instruction: _Instruction8616) -> int | None:
    """Return one immediate near/far-call target."""
    if instruction.mnemonic.lower() not in {"call", "lcall"}:
        return None
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operands[0].type != X86_OP_IMM:
        return None
    return operands[0].imm


def _range_direct_calls_by_target_8616(
    project: object,
    function_ranges: tuple[tuple[int, int], ...],
) -> dict[int, tuple[tuple[tuple[int, int], _Instruction8616], ...]]:
    """Index canonical direct calls after decoding an exact range set once."""
    surface = cast(_RangeProjectSurface8616, project)
    try:
        cached_ranges = surface._inertia_range_direct_call_ranges_8616
        cached_calls = surface._inertia_range_direct_calls_by_target_8616
    except AttributeError:
        cached_ranges = ()
        cached_calls = {}
    if cached_ranges == function_ranges:
        return cached_calls

    try:
        disassembler = surface.arch.capstone
        memory = surface.loader.memory
    except AttributeError:
        return {}
    disassembler.detail = True
    calls: dict[int, list[tuple[tuple[int, int], _Instruction8616]]] = {}
    for start, end in function_ranges:
        try:
            data = bytes(memory.load(start, end - start))
            identity = prove_caller_entry_identity_8616(start, end, data)
            if identity is None:
                continue
            instructions = tuple(disassembler.disasm(data, start))
        except (KeyError, TypeError, ValueError):
            continue
        caller_range = (identity.entry_addr, end)
        for instruction in instructions:
            direct_target = _direct_call_target_8616(instruction)
            if direct_target is None:
                continue
            target_addr = canonicalize_x86_16_padding_call_target_8616(
                project,
                direct_target,
            )
            if target_addr is None:
                continue
            calls.setdefault(target_addr, []).append((caller_range, instruction))
    indexed = {target: tuple(items) for target, items in calls.items()}
    surface._inertia_range_direct_call_ranges_8616 = function_ranges
    surface._inertia_range_direct_calls_by_target_8616 = indexed
    return indexed


def collect_range_callsite_facts_8616(
    project: object,
    function_ranges: tuple[tuple[int, int], ...],
    *,
    excluded_fact_keys: frozenset[tuple[int, int]] = frozenset(),
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Summarize all direct calls while decoding every exact range once."""
    indexed = _range_direct_calls_by_target_8616(project, function_ranges)
    caller_ranges = tuple(sorted({item[0] for calls in indexed.values() for item in calls}))
    inventory = exact_function_range_inventory_8616(project, caller_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in inventory.boundaries
    }
    facts: list[CalleeCallsiteFact8616] = []
    for target_addr, calls in sorted(indexed.items()):
        for caller_range, instruction in calls:
            caller = boundaries.get(caller_range)
            if (target_addr, instruction.address) in excluded_fact_keys:
                continue
            summary = (
                None
                if caller is None
                else summarize_x86_16_callsite(caller, instruction.address)
            )
            if summary is None or summary.stack_probe_helper:
                continue
            facts.append(
                CalleeCallsiteFact8616(
                    evidence_project=project,
                    caller_function=caller,
                    evidence_target_addr=target_addr,
                    caller_addr=caller_range[0],
                    callsite_addr=instruction.address,
                    summary=summary,
                )
            )
    return tuple(facts)


def collect_range_callsite_facts_for_target_8616(
    project: object,
    target_addr: int,
    function_ranges: tuple[tuple[int, int], ...],
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Build exact caller facts after a bounded direct-target prefilter."""
    matching_calls = _range_direct_calls_by_target_8616(
        project,
        function_ranges,
    ).get(target_addr, ())
    if not matching_calls:
        return ()

    matching_ranges = tuple(dict.fromkeys(item[0] for item in matching_calls))
    inventory = exact_function_range_inventory_8616(project, matching_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in inventory.boundaries
    }
    facts: list[CalleeCallsiteFact8616] = []
    for caller_range, instruction in matching_calls:
        caller = boundaries.get(caller_range)
        summary = (
            None
            if caller is None
            else summarize_x86_16_callsite(caller, instruction.address)
        )
        if summary is None or summary.stack_probe_helper:
            continue
        facts.append(
            CalleeCallsiteFact8616(
                evidence_project=project,
                caller_function=caller,
                evidence_target_addr=target_addr,
                caller_addr=caller_range[0],
                callsite_addr=instruction.address,
                summary=summary,
            )
        )
    return tuple(facts)
