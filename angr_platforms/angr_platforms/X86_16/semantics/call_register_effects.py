"""Classify register preservation across analysis-only CALL targets.

Layer: Semantics.
Responsibility: combine exact Frontend synthetic-stub identity with the
registered x86-16 Microsoft C calling convention to classify one CALL's
effect on a general register.
Forbidden: source/COD/name/rendered-C inference, reaching-definition joins,
or call-argument materialization.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

Synthetic stub bytes are placeholders and therefore cannot prove callee
behavior.  They may be consumed only together with the project's registered
calling convention.  Real callee bodies remain subject to binary inspection;
this contract never overrides an observed implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast

from angr.calling_conventions import default_cc

from ..simos_86_16 import SimCC8616MSCmedium, SimCC8616MSCsmall
from ..synthetic_call_stub_evidence import is_synthetic_call_stub_8616

__all__ = (
    "MSC16_CALLEE_SAVED_GENERAL_REGISTERS_8616",
    "MSC16_CALLER_SAVED_GENERAL_REGISTERS_8616",
    "SyntheticCallRegisterEffect8616",
    "SyntheticCallRegisterEffectVerdict8616",
    "classify_synthetic_call_register_effect_8616",
)

# Microsoft C 6.0 Advanced Programming Techniques, sections 12.8.3-12.8.5:
# BP/SI/DI survive calls; BX is scratch. This proves only the 16-bit views.
MSC16_CALLEE_SAVED_GENERAL_REGISTERS_8616: frozenset[str] = frozenset({"bp", "di", "si"})
MSC16_CALLER_SAVED_GENERAL_REGISTERS_8616: frozenset[str] = frozenset({"ax", "bx", "cx", "dx"})


class SyntheticCallRegisterEffectVerdict8616(StrEnum):
    """Typed register effect of one exact analysis-only CALL target."""

    PRESERVED = "preserved"
    CLOBBERED = "clobbered"
    UNKNOWN_REFUSE = "unknown_refuse"


@dataclass(frozen=True, slots=True)
class SyntheticCallRegisterEffect8616:
    """One CALL/register verdict with a closed semantic evidence census."""

    callsite_addr: int
    target_addr: int | None
    register: str
    verdict: SyntheticCallRegisterEffectVerdict8616
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closes_evidence(self) -> bool:
        """Return whether the exact input produced one materialized verdict."""
        return (
            self.raw_fact_count
            == self.normalized_fact_count
            == self.classified_fact_count
            == self.materialized_count
            == 1
            and self.failure_count == 0
        )


class _ArchSurface8616(Protocol):
    """Architecture name exposed at the dynamic angr boundary."""

    name: str


class _SimOsSurface8616(Protocol):
    """Platform name exposed at the dynamic angr boundary."""

    name: str


class _ProjectSurface8616(Protocol):
    """Project fields required to select its registered calling convention."""

    arch: _ArchSurface8616
    simos: _SimOsSurface8616


def _unknown_effect_8616(
    callsite_addr: int,
    target_addr: int | None,
    register: str,
    *,
    normalized: bool,
) -> SyntheticCallRegisterEffect8616:
    """Build one explicit refusal for incomplete or unsupported evidence."""
    return SyntheticCallRegisterEffect8616(
        callsite_addr,
        target_addr,
        register,
        SyntheticCallRegisterEffectVerdict8616.UNKNOWN_REFUSE,
        1,
        int(normalized),
        0,
        0,
        1,
    )


def classify_synthetic_call_register_effect_8616(
    project: object,
    *,
    callsite_addr: int,
    target_addr: int | None,
    register: str,
) -> SyntheticCallRegisterEffect8616:
    """Classify one exact synthetic CALL through the registered MS C ABI."""
    normalized_register = register.lower()
    if (
        not isinstance(callsite_addr, int)
        or isinstance(callsite_addr, bool)
        or not isinstance(target_addr, int)
        or isinstance(target_addr, bool)
        or not normalized_register
    ):
        return _unknown_effect_8616(
            callsite_addr,
            target_addr,
            normalized_register,
            normalized=False,
        )
    if not is_synthetic_call_stub_8616(project, target_addr):
        return _unknown_effect_8616(
            callsite_addr,
            target_addr,
            normalized_register,
            normalized=True,
        )

    boundary = cast(_ProjectSurface8616, project)
    try:
        convention = default_cc(boundary.arch.name, boundary.simos.name)
    except (AttributeError, KeyError, TypeError):
        convention = None
    if convention not in {SimCC8616MSCsmall, SimCC8616MSCmedium}:
        return _unknown_effect_8616(
            callsite_addr,
            target_addr,
            normalized_register,
            normalized=True,
        )

    if normalized_register in MSC16_CALLEE_SAVED_GENERAL_REGISTERS_8616:
        verdict = SyntheticCallRegisterEffectVerdict8616.PRESERVED
    elif normalized_register in MSC16_CALLER_SAVED_GENERAL_REGISTERS_8616:
        verdict = SyntheticCallRegisterEffectVerdict8616.CLOBBERED
    else:
        return _unknown_effect_8616(
            callsite_addr,
            target_addr,
            normalized_register,
            normalized=True,
        )
    return SyntheticCallRegisterEffect8616(
        callsite_addr,
        target_addr,
        normalized_register,
        verdict,
        1,
        1,
        1,
        1,
        0,
    )
