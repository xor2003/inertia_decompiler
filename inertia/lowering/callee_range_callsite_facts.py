# cython: language_level=3, infer_types=True
"""Collect direct-caller facts from independently framed binary ranges.

Layer: Types/Lowering.
Responsibility: decode each supplied caller range once, retain exact direct-call
coordinates, and bind existing recovery summaries to canonical callee targets.
This module does not derive argument interfaces or mutate generated C.

Consumes alias, widening, and typed facts. Do not recover semantics from COD,
source, assembly, or rendered C text.
"""

from __future__ import annotations
import typing
import cython

from collections.abc import Iterable, Sequence
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM

from inertia.frontend.x86_16.frontend_caller_entry_identity import prove_caller_entry_identity_8616
from inertia.frontend.x86_16.frontend_function_boundary_index import exact_function_range_inventory_8616
from inertia.lowering.analysis_helpers import canonicalize_x86_16_padding_call_target_8616
from inertia.semantics.callsite_summary import summarize_x86_16_callsite

from .callee_callsite_contracts import CalleeCallsiteFact8616
import operator
import builtins

__all__ = [
    "collect_range_callsite_facts_8616",
    "collect_range_callsite_facts_for_target_8616",
]


class _InstructionOperand8616(Protocol):
    """Capstone operand fields consumed at the disassembly boundary."""

    type: cython.longlong
    imm: cython.longlong


class _Instruction8616(Protocol):
    """Capstone instruction fields consumed for direct-call discovery."""

    address: cython.longlong
    mnemonic: object
    operands: Sequence[_InstructionOperand8616]


class _Disassembler8616(Protocol):
    """Capstone engine surface used to decode proven caller ranges."""

    detail: cython.bint

    def disasm(self, code: object, address: cython.longlong) -> Iterable[_Instruction8616]:
        """Decode one bounded caller range."""
        ...


class _Memory8616(Protocol):
    """angr loader-memory surface used by the range decoder."""

    def load(self, address: cython.longlong, size: cython.longlong) -> object:
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
    _inertia_range_direct_call_ranges_8616: object
    _inertia_range_direct_calls_by_target_8616: object


@cython.ccall
def _direct_call_target_8616(instruction: _Instruction8616) -> int | None:
    """Return one immediate near/far-call target."""
    if instruction.mnemonic.lower() not in {"call", "lcall"}:
        return None
    operands = tuple(instruction.operands)
    if len(operands) != 1 or operator.ne(operands[0].type, X86_OP_IMM):
        return None
    return operands[0].imm


@cython.ccall
def _range_direct_calls_by_target_8616(
    project: object,
    function_ranges: object,
) -> object:
    """Index canonical direct calls after decoding an exact range set once."""
    direct_target: object
    identity: object
    target_addr: object
    end: object
    instruction: object
    start: object
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
    calls: dict[cython.longlong, list[tuple[tuple[cython.longlong, cython.longlong], _Instruction8616]]] = {}
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
    indexed = {target: tuple(items) for target, items in builtins.iter(calls.items())}
    surface._inertia_range_direct_call_ranges_8616 = function_ranges
    surface._inertia_range_direct_calls_by_target_8616 = indexed
    return indexed


@cython.ccall
def collect_range_callsite_facts_8616(
    project: object,
    function_ranges: object,
    *,
    excluded_fact_keys: object = frozenset(),
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Summarize all direct calls while decoding every exact range once."""
    caller: object
    summary: object
    caller_range: object
    calls: object
    instruction: object
    target_addr: object
    indexed = _range_direct_calls_by_target_8616(project, function_ranges)
    caller_ranges = tuple(sorted({item[0] for calls in builtins.iter(indexed.values()) for item in iter(calls)}))
    inventory = exact_function_range_inventory_8616(project, caller_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in iter(inventory.boundaries)
    }
    facts: list[CalleeCallsiteFact8616] = []
    for target_addr, calls in sorted(tuple(indexed.items())):
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
    target_addr: cython.longlong,
    function_ranges: object,
) -> tuple[CalleeCallsiteFact8616, ...]:
    """Build exact caller facts after a bounded direct-target prefilter."""
    caller: object
    matching_calls: object
    summary: object
    caller_range: object
    instruction: object
    matching_calls = _range_direct_calls_by_target_8616(
        project,
        function_ranges,
    ).get(target_addr, ())
    if not matching_calls:
        return ()

    matching_ranges = tuple(dict.fromkeys(item[0] for item in iter(matching_calls)))
    inventory = exact_function_range_inventory_8616(project, matching_ranges)
    boundaries = {
        (item.addr, item.addr + item.size): item for item in iter(inventory.boundaries)
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
