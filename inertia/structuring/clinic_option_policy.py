"""Protect X86-16 CFG shape from non-control flag expressions.

Layer: Structuring.
Responsibility: configure third-party Clinic so lifter-emitted flag-value ITEs
remain data expressions and cannot be rewritten as synthetic CFG branches.
Owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
Owns only architecture-specific structuring options. It does not recover
conditions, alter instruction semantics, or clean rendered C.

The X86-16 lifter uses ITE expressions to select individual arithmetic flag
bits. angr's generic ``rewrite_ites_to_diamonds`` option treats every ITE as
source-level control flow. For instructions such as ``sub ax, [bp+6]`` this can
split the AIL graph at byte addresses inside the instruction, duplicate the
epilogue, and apply the arithmetic operation twice. A function with no CFG
split has proof that none of its ITEs represents machine control flow, so the
generic rewrite is disabled there. Branch-bearing or unknown CFGs retain
angr's default until ITE provenance can be selected individually.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol, cast

from angr.analyses.decompiler.clinic import Clinic

type ClinicOption8616 = tuple[str, object]

_ITE_DIAMOND_OPTION = "rewrite_ites_to_diamonds"


class _ClinicGraphBoundary8616(Protocol):
    """Typed view of the dynamic third-party angr function graph boundary."""

    @property
    def nodes(self) -> Iterable[object]:
        """Return graph nodes in the order exposed by angr/networkx."""
        ...

    def out_degree(self, node: object) -> int:
        """Return the number of outgoing CFG edges for one graph node."""
        ...


class _ClinicFunctionBoundary8616(Protocol):
    """Typed view of the dynamic third-party angr Function boundary."""

    @property
    def graph(self) -> _ClinicGraphBoundary8616:
        """Return the function CFG supplied by angr."""
        ...


def enforce_x86_16_clinic_options_8616(
    options: Iterable[ClinicOption8616] | None,
    *,
    function: object,
) -> list[ClinicOption8616]:
    """Inspect the dynamic angr CFG and disable ITE diamonds only when straight-line."""
    try:
        graph = cast(_ClinicFunctionBoundary8616, function).graph
        nodes = graph.nodes
    except AttributeError:
        return list(options or ())
    try:
        if any(graph.out_degree(node) > 1 for node in nodes):
            return list(options or ())
    except (AttributeError, TypeError, ValueError):
        return list(options or ())

    protected: list[ClinicOption8616] = []
    found = False
    for name, value in options or ():
        if name == _ITE_DIAMOND_OPTION:
            if not found:
                protected.append((_ITE_DIAMOND_OPTION, False))
                found = True
            continue
        protected.append((name, value))
    if not found:
        protected.append((_ITE_DIAMOND_OPTION, False))
    return protected


def apply_x86_16_clinic_option_policy_8616() -> None:
    """Enforce the shared policy for native and CLI callers before AIL splitting."""
    original = cast(Callable[[Clinic], None], Clinic._analyze_for_decompiling)
    if original.__name__ == "_analyze_with_x86_16_clinic_policy":
        return

    def _analyze_with_x86_16_clinic_policy(self: Clinic) -> None:
        """Set architecture-owned options before native graph transformations."""
        if self.project.arch.name == "86_16":
            options = enforce_x86_16_clinic_options_8616(
                [(_ITE_DIAMOND_OPTION, self._rewrite_ites_to_diamonds)],
                function=self.function,
            )
            self._rewrite_ites_to_diamonds = bool(dict(options)[_ITE_DIAMOND_OPTION])
        original(self)

    Clinic._analyze_for_decompiling = _analyze_with_x86_16_clinic_policy


__all__ = [
    "ClinicOption8616",
    "apply_x86_16_clinic_option_policy_8616",
    "enforce_x86_16_clinic_options_8616",
]
