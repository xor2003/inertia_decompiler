"""Seed pre-decompilation callee prototypes from exact callsite stack facts.

Layer: Types/lowering.
Responsibility: expose proven physical call arguments to angr before SSA and
dead-code elimination decide whether branch-carried argument values are live.
The seed is a machine-call interface, not a recovered source-level signature;
later typed lowering may group physical words into wider logical arguments.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping
from dataclasses import dataclass
from enum import StrEnum
from types import SimpleNamespace
from typing import Protocol, cast

from angr.sim_type import SimType, SimTypeBottom, SimTypeFunction, SimTypeLong, SimTypeShort
from archinfo import Arch

from ..callsite_summary import CallsiteSummary8616, summarize_x86_16_callsite
from .argument_frame_base import msc_calling_convention_for_function_8616

__all__ = [
    "CallsitePrototypeSeedDecision8616",
    "CallsitePrototypeSeedResult8616",
    "PhysicalCallsitePrototypeSeed8616",
    "materialize_physical_callsite_prototype_8616",
    "physical_callsite_prototype_seed_8616",
    "seed_physical_callsite_prototype_8616",
]

_SEED_INFO_KEY_8616 = "_inertia_physical_callsite_prototype_seed_8616"


class CallsitePrototypeSeedDecision8616(StrEnum):
    """Typed outcome for one pre-decompilation prototype seed."""

    NO_SUMMARY = "no-summary"
    EXPLICIT_PROTOTYPE = "explicit-prototype"
    INCOMPLETE_PHYSICAL_SHAPE = "incomplete-physical-shape"
    UNSUPPORTED_PHYSICAL_WIDTH = "unsupported-physical-width"
    SEEDED = "seeded"


@dataclass(frozen=True, slots=True)
class CallsitePrototypeSeedResult8616:
    """Closed evidence loop for one pre-decompilation prototype seed."""

    decision: CallsitePrototypeSeedDecision8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


@dataclass(frozen=True, slots=True)
class PhysicalCallsitePrototypeSeed8616:
    """Exact machine-argument prototype owned by an earlier callsite seed."""

    callsite_addr: int
    target_addr: int | None
    physical_widths: tuple[int, ...]
    return_width_bits: int

    def matches(self, summary: CallsiteSummary8616, current: object) -> bool:
        """Authorize replacing only this unchanged physical projection."""
        return bool(
            self.callsite_addr == summary.callsite_addr
            and self.target_addr == summary.target_addr
            and self.physical_widths == summary.arg_widths
            and isinstance(current, SimTypeFunction)
            and not current.variadic
            and tuple(arg.size for arg in current.args or ())
            == tuple(width * 8 for width in reversed(self.physical_widths))
            and current.returnty is not None
            and current.returnty.size == self.return_width_bits
        )

    def as_record(self) -> dict[str, object]:
        """Store the typed seed using angr FunctionInfo's JSON-safe contract."""
        return {
            "schema": 1,
            "callsite_addr": self.callsite_addr,
            "target_addr": self.target_addr,
            "physical_widths": list(self.physical_widths),
            "return_width_bits": self.return_width_bits,
        }


class _ProjectSurface8616(Protocol):
    """Third-party project fields required to bind an angr prototype."""

    arch: Arch


class _CalleeSurface8616(Protocol):
    """Third-party angr Function fields mutated by prototype seeding."""

    prototype: object | None
    calling_convention: object | None
    is_prototype_guessed: bool
    info: MutableMapping[str, object]


def physical_callsite_prototype_seed_8616(callee: object) -> PhysicalCallsitePrototypeSeed8616 | None:
    """Read a seed's typed ownership marker from a third-party function."""
    try:
        info = cast(_CalleeSurface8616, callee).info
    except AttributeError:
        return None
    if not isinstance(info, Mapping):
        return None
    record = info.get(_SEED_INFO_KEY_8616)
    if not isinstance(record, dict) or set(record) != {
        "schema", "callsite_addr", "target_addr", "physical_widths", "return_width_bits",
    }:
        return None
    widths = record["physical_widths"]
    target = record["target_addr"]
    if not (
        record["schema"] == 1
        and type(record["callsite_addr"]) is int
        and (target is None or type(target) is int)
        and isinstance(widths, list)
        and widths
        and all(type(width) is int and width > 0 for width in widths)
        and type(record["return_width_bits"]) is int
    ):
        return None
    return PhysicalCallsitePrototypeSeed8616(
        record["callsite_addr"], target,
        tuple(cast(list[int], widths)), record["return_width_bits"],
    )


def _physical_stack_type_8616(project: _ProjectSurface8616, width: int) -> SimType | None:
    """Return an ABI scalar type for one proven physical stack-slot width."""
    if width == 2:
        return SimTypeShort(signed=False).with_arch(project.arch)
    if width == 4:
        return SimTypeLong(signed=False).with_arch(project.arch)
    return None


def _physical_return_type_8616(project: _ProjectSurface8616, summary: CallsiteSummary8616) -> SimType:
    """Return the caller-observed machine return type for a seeded callee."""
    if summary.return_used is not True:
        return SimTypeBottom(label="void").with_arch(project.arch)
    if summary.return_shape == "dx_ax":
        return SimTypeLong(signed=False).with_arch(project.arch)
    return SimTypeShort(signed=False).with_arch(project.arch)


def materialize_physical_callsite_prototype_8616(
    project: object,
    callee: object,
    summary: CallsiteSummary8616,
) -> CallsitePrototypeSeedResult8616:
    """Materialize a physical call interface without guessing logical types."""
    typed_project = cast(_ProjectSurface8616, project)
    typed_callee = cast(_CalleeSurface8616, callee)
    existing = typed_callee.prototype
    if isinstance(existing, SimTypeFunction) and (existing.args or not typed_callee.is_prototype_guessed):
        return CallsitePrototypeSeedResult8616(
            CallsitePrototypeSeedDecision8616.EXPLICIT_PROTOTYPE,
            1,
            1,
            0,
            0,
            0,
        )

    widths = summary.arg_widths
    if not widths or summary.arg_count != len(widths):
        return CallsitePrototypeSeedResult8616(
            CallsitePrototypeSeedDecision8616.INCOMPLETE_PHYSICAL_SHAPE,
            1,
            0,
            0,
            0,
            1,
        )
    argument_types = tuple(
        _physical_stack_type_8616(typed_project, width)
        for width in reversed(widths)
    )
    if any(argument_type is None for argument_type in argument_types):
        return CallsitePrototypeSeedResult8616(
            CallsitePrototypeSeedDecision8616.UNSUPPORTED_PHYSICAL_WIDTH,
            1,
            1,
            0,
            0,
            1,
        )

    return_type = _physical_return_type_8616(typed_project, summary)
    return_width_bits = return_type.size
    if return_width_bits is None:
        raise TypeError("physical callsite seed requires a sized machine return type")
    prototype = SimTypeFunction(
        [cast(SimType, argument_type) for argument_type in argument_types],
        return_type,
        arg_names=[f"a{index}" for index in range(len(argument_types))],
        variadic=False,
    ).with_arch(typed_project.arch)
    typed_callee.prototype = prototype
    typed_callee.calling_convention = msc_calling_convention_for_function_8616(project, callee)
    typed_callee.is_prototype_guessed = False
    typed_callee.info[_SEED_INFO_KEY_8616] = PhysicalCallsitePrototypeSeed8616(
        summary.callsite_addr, summary.target_addr, summary.arg_widths,
        return_width_bits,
    ).as_record()
    return CallsitePrototypeSeedResult8616(
        CallsitePrototypeSeedDecision8616.SEEDED,
        1,
        1,
        1,
        1,
        0,
    )


def seed_physical_callsite_prototype_8616(
    project: object,
    caller: object,
    callee: object,
    callsite_addr: int,
) -> CallsitePrototypeSeedResult8616:
    """Summarize one callsite and seed its callee before C structuring runs."""
    summary = summarize_x86_16_callsite(cast(SimpleNamespace, caller), callsite_addr)
    if summary is None:
        return CallsitePrototypeSeedResult8616(
            CallsitePrototypeSeedDecision8616.NO_SUMMARY,
            0,
            0,
            0,
            0,
            0,
        )
    return materialize_physical_callsite_prototype_8616(project, callee, summary)
