"""Layer: Recovery metadata.

Responsibility: collect immutable CFG-derived call targets once per summary request.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from inertia.lowering.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
    collect_neighbor_call_targets,
    resolve_direct_call_target_from_block,
)

__all__ = ["CallsiteTargetInventory8616"]


class _InstructionSurface8616(Protocol):
    """Decoded instruction fields used at the third-party Capstone boundary."""

    address: int
    mnemonic: str
    size: int


class _CapstoneSurface8616(Protocol):
    """Decoded instruction collection exposed by one angr block."""

    insns: Iterable[_InstructionSurface8616]


class _BlockSurface8616(Protocol):
    """Minimal angr block surface needed for direct-call classification."""

    capstone: _CapstoneSurface8616


class _FactorySurface8616(Protocol):
    """Dynamic angr factory boundary used for exact instruction decoding."""

    def block(self, addr: int, *, opt_level: int = 0) -> _BlockSurface8616:
        """Decode one block beginning at an exact machine address."""
        ...


class _ProjectSurface8616(Protocol):
    """Minimal project surface required by direct-call recovery."""

    factory: _FactorySurface8616


class _FunctionSurface8616(Protocol):
    """Recovered function carrying its third-party analysis project."""

    project: _ProjectSurface8616


def _decoded_direct_call_seed_8616(
    function: object,
    callsite_addr: int,
) -> CallTargetSeed | None:
    """Recover one binary-proven direct target absent from CFG target edges."""
    try:
        project = cast(_FunctionSurface8616, function).project
        target_addr = resolve_direct_call_target_from_block(project, callsite_addr)
        instructions = tuple(project.factory.block(callsite_addr, opt_level=0).capstone.insns)
    except (AttributeError, KeyError, TypeError, ValueError):
        return None
    matches = tuple(instruction for instruction in instructions if instruction.address == callsite_addr)
    if len(matches) != 1 or not isinstance(target_addr, int):
        return None
    instruction = matches[0]
    mnemonic = instruction.mnemonic.strip().lower()
    if mnemonic not in {"call", "lcall"}:
        return None
    return_addr = (
        callsite_addr + instruction.size
        if isinstance(instruction.size, int) and instruction.size > 0
        else None
    )
    kind = (
        CallTargetKind8616.DIRECT_FAR_CALL
        if mnemonic == "lcall"
        else CallTargetKind8616.DIRECT_NEAR_CALL
    )
    return CallTargetSeed(callsite_addr, target_addr, return_addr, kind)


@dataclass(frozen=True, slots=True)
class CallsiteTargetInventory8616:
    """Immutable direct-call and tail-jump targets for one recovered function."""

    seeds: tuple[CallTargetSeed, ...]

    @classmethod
    def collect(
        cls,
        function: object,
        callsite_addrs: Iterable[int] = (),
    ) -> CallsiteTargetInventory8616:
        """Collect CFG targets plus exact decoded direct calls missing CFG edges."""
        seeds = list(collect_neighbor_call_targets(function))
        retained_callsites = {seed.callsite_addr for seed in seeds}
        for callsite_addr in sorted(set(callsite_addrs)):
            if callsite_addr in retained_callsites:
                continue
            seed = _decoded_direct_call_seed_8616(function, callsite_addr)
            if seed is not None:
                seeds.append(seed)
                retained_callsites.add(callsite_addr)
        return cls(tuple(seeds))

    def seed_for_callsite(self, callsite_addr: int) -> CallTargetSeed | None:
        """Return the first recovered target fact for an exact callsite."""
        return next((seed for seed in self.seeds if seed.callsite_addr == callsite_addr), None)
