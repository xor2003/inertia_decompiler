# cython: language_level=3, infer_types=True
"""Layer: CLI/fallback/reporting.

Responsibility: select an explicit declared root's bounded native call closure.
This scope is conditional and never claims discovery of every program function.
"""
from __future__ import annotations
import cython

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from capstone.x86_const import X86_INS_CALL, X86_INS_LCALL

from inertia.cli.mz_static_intake import MzStaticIntakeRequest8616, MzStaticIntakeStatus8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsiteIndex8616
from inertia.ir.entry_domain_call_preservation import Real16InvocationSource8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
import dataclasses
import builtins


class DeclaredDiscoveryStatus8616(StrEnum):
    """Completeness of only the explicitly requested native call closure."""

    CLOSED = "closed"
    INCOMPLETE = "incomplete"
    REFUSED = "refused"


@dataclasses.dataclass(frozen=True)
class DeclaredFunctionDiscovery8616:
    """Selected heads and visible unresolved obligations, with scheduling hints."""

    status: DeclaredDiscoveryStatus8616
    roots: object
    heads: object
    pending_heads: object
    unresolved_callsites: object
    caller_targets: object


class _DecodedInstruction8616(Protocol):
    """Native Capstone instruction fields used for CALL classification."""

    insn: object
    address: cython.longlong


class _CapstoneOpcode8616(Protocol):
    """Typed opcode classification of the retained native decoder result."""

    id: cython.longlong


def declared_discovery_from_index_8616(
    project: object,
    roots: object,
    index: DecodedDirectCallsiteIndex8616,
    pending: object,
) -> DeclaredFunctionDiscovery8616:
    """Project native inventory into selection without asserting call effects."""
    target: object
    census: object
    instruction: object
    closed = {census.entry_addr for census in iter(index.caller_censuses)}
    targets: dict[cython.longlong, set[cython.longlong]] = {}
    unresolved: set[tuple[cython.longlong, cython.longlong]] = set()
    for census in index.caller_censuses:
        for instruction in census.instructions:
            native = cast(_DecodedInstruction8616, instruction)
            if cast(_CapstoneOpcode8616, native.insn).id not in (X86_INS_CALL, X86_INS_LCALL):
                continue
            target = resolve_direct_call_target_from_instruction_8616(project, instruction)
            if target is None:
                unresolved.add((census.entry_addr, native.address))
            else:
                targets.setdefault(census.entry_addr, set()).add(target)
    pending_heads = tuple(sorted(set(pending) | (set(roots) - closed)))
    status = (DeclaredDiscoveryStatus8616.INCOMPLETE
              if pending_heads or unresolved or index.stats.failure_count
              else DeclaredDiscoveryStatus8616.CLOSED)
    return DeclaredFunctionDiscovery8616(
        status, roots, tuple(sorted(closed | set(pending_heads) | set(roots))),
        pending_heads, tuple(sorted(unresolved)),
        tuple((caller, tuple(sorted(callees))) for caller, callees in builtins.iter(sorted(tuple(targets.items())))),
    )


def discover_declared_function_closure_8616(project: object) -> DeclaredFunctionDiscovery8616 | None:
    """Demand existing bounded intake only when explicit function entries exist.

    None preserves ordinary discovery for environment-only declarations. A
    refusal must remain visible, rather than silently selecting a hybrid scope.
    """
    request: object
    source: object
    # Dynamic third-party project boundary: the loader owns this optional slot.
    request = getattr(project, "_inertia_mz_static_invocation_request_8616", None)
    if not isinstance(request, MzStaticIntakeRequest8616) or not request.function_entries:
        return None
    roots = tuple(sorted((entry.spec.entry_segment << 4) + entry.spec.entry_offset
                         for entry in iter(request.function_entries)))
    receipt = request.install(project)
    if receipt.status is not MzStaticIntakeStatus8616.DECLARED_ENTRIES_INSTALLED:
        return DeclaredFunctionDiscovery8616(DeclaredDiscoveryStatus8616.REFUSED, roots, roots, roots, (), ())
    # Dynamic third-party project boundary: successful intake installs the owner.
    source = getattr(project, "_inertia_real16_invocation_source_8616", None)
    if not isinstance(source, Real16InvocationSource8616):
        raise TypeError("declared intake succeeded without a typed invocation source")
    return declared_discovery_from_index_8616(project, roots, source.callsite_index, source.pending_targets)
