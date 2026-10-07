from __future__ import annotations

from collections import UserDict
from types import SimpleNamespace

from angr.sim_type import SimTypeFunction, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.callsite_prototype_seeding import (
    CallsitePrototypeSeedDecision8616,
    materialize_physical_callsite_prototype_8616,
    physical_callsite_prototype_seed_8616,
)


def _summary(*, widths: tuple[int, ...] = (2, 2)) -> CallsiteSummary8616:
    return CallsiteSummary8616(
        callsite_addr=0x102C,
        target_addr=0x1034,
        return_addr=0x102F,
        kind="direct_near",
        arg_count=len(widths),
        arg_widths=widths,
        stack_cleanup=0,
        return_register="ax",
        return_used=True,
    )


def test_physical_callsite_prototype_is_seeded_before_structuring() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    callee = SimpleNamespace(prototype=None, calling_convention=None, is_prototype_guessed=True, info=UserDict())

    result = materialize_physical_callsite_prototype_8616(project, callee, _summary())

    assert result.decision is CallsitePrototypeSeedDecision8616.SEEDED
    assert result.classified_fact_count == result.materialized_count == 1
    assert isinstance(callee.prototype, SimTypeFunction)
    assert tuple(argument.size for argument in callee.prototype.args) == (16, 16)
    assert callee.prototype.returnty.size == 16
    assert callee.calling_convention is not None
    assert callee.is_prototype_guessed is False
    seed = physical_callsite_prototype_seed_8616(callee)
    assert seed is not None and seed.matches(_summary(), callee.prototype)
    assert all(isinstance(value, (str, int, float, bool, list, dict, type(None)))
               for value in callee.info.values())


def test_physical_callsite_prototype_preserves_explicit_interface() -> None:
    project = SimpleNamespace(arch=Arch86_16())
    explicit = SimTypeFunction([], SimTypeShort(signed=False)).with_arch(project.arch)
    callee = SimpleNamespace(
        prototype=explicit,
        calling_convention=None,
        is_prototype_guessed=False,
        info={},
    )

    result = materialize_physical_callsite_prototype_8616(project, callee, _summary())

    assert result.decision is CallsitePrototypeSeedDecision8616.EXPLICIT_PROTOTYPE
    assert callee.prototype is explicit
    assert physical_callsite_prototype_seed_8616(callee) is None
