"""Bind proven terminal register storage before native SSA can discard it.

Layer: Types/Lowering, native AIL compatibility boundary.
Responsibility: project the existing terminal-storage proof into return operands
when native calling-convention recovery cannot supply them. A return carrier
does not prove argument locations or a whole ABI. Never synthesize either here.
Unknown, split-pair and call-only storage remain unsupported by this adapter.
Consumes alias, widening, and typed facts through the terminal-storage owner.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol, cast

from angr.ailment import Block
from angr.ailment.expression import Register
from angr.ailment.statement import Return
from angr.analyses.decompiler.ailgraph_walker import AILGraphWalker
from angr.analyses.decompiler.clinic import Clinic
from angr.knowledge_plugins.functions.function import Function
from angr.project import Project
from angr.sim_type import SimTypeBottom, SimTypeFunction
from archinfo import Arch

from ..semantics.terminal_return_storage import TerminalReturnStorage8616, terminal_return_storage_8616

_REGISTER_CARRIERS = frozenset({
    TerminalReturnStorage8616.AL, TerminalReturnStorage8616.AH, TerminalReturnStorage8616.AX,
})


@dataclass(frozen=True, slots=True)
class NativeTerminalReturnBindingReport8616:
    """Closed census of empty return sites and consumed storage proofs."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int


def bind_terminal_return_register_8616(
    block: Block,
    arch: Arch,
    storage: TerminalReturnStorage8616 | None,
    next_atom: Callable[[], int],
) -> Block:
    """Copy one empty return with an exact independently proven register read."""
    if storage not in _REGISTER_CARRIERS or not block.statements:
        return block
    terminal = block.statements[-1]
    if not isinstance(terminal, Return) or terminal.ret_exprs:
        return block
    assert storage is not None
    name = storage.value
    offset, size = arch.registers[name]
    value = Register(next_atom(), offset, size * arch.byte_width, reg_name=name,
                     ins_addr=terminal.tags.get("ins_addr"))
    replacement = terminal.copy()
    replacement.ret_exprs = [value]
    return block.copy(statements=[*block.statements[:-1], replacement])


class _AtomManager8616(Protocol):
    """Native allocator used to preserve expression identity ownership."""

    def next_atom(self) -> int:
        """Allocate a fresh native expression index."""
        ...


class _ClinicBoundary8616(Protocol):
    """Native Clinic fields consumed without inferring calling conventions."""

    project: Project
    function: Function
    _ail_manager: _AtomManager8616
    _inertia_terminal_return_binding_report_8616: NativeTerminalReturnBindingReport8616


def apply_native_terminal_return_values_8616() -> None:
    """Bind proven return operands at native return construction, before SSA."""
    original = Clinic._make_returns
    if original.__name__ == "_make_returns_with_terminal_storage_8616":
        return

    def _make_returns_with_terminal_storage_8616(self: object, graph: object) -> object:
        """Leave native ABI recovery intact; consume independent storage proof."""
        clinic = cast(_ClinicBoundary8616, self)
        result = cast(Any, original)(self, graph)
        function = clinic.function
        if clinic.project.arch.name != "86_16" or function.calling_convention is not None:
            return result
        prototype = function.prototype
        if isinstance(prototype, SimTypeFunction) and isinstance(prototype.returnty, SimTypeBottom):
            return result
        storage = terminal_return_storage_8616(clinic.project, function)
        empty_returns = sum(
            bool(block.statements)
            and isinstance(block.statements[-1], Return)
            and not block.statements[-1].ret_exprs
            for block in cast(Iterable[Block], result)
        )
        classified = empty_returns if storage in _REGISTER_CARRIERS else 0
        materialized = 0
        clinic._inertia_terminal_return_binding_report_8616 = NativeTerminalReturnBindingReport8616(
            empty_returns, empty_returns, classified, 0, 0,
        )
        if storage not in _REGISTER_CARRIERS:
            return result

        def bind(block: Block) -> Block | None:
            """Replace a graph node only when a return operand was materialized."""
            nonlocal materialized
            replacement = bind_terminal_return_register_8616(
                block, clinic.project.arch, storage, clinic._ail_manager.next_atom,
            )
            if replacement is block:
                return None
            materialized += 1
            return replacement

        AILGraphWalker(result, bind, replace_nodes=True).walk()
        failures = classified - materialized
        clinic._inertia_terminal_return_binding_report_8616 = NativeTerminalReturnBindingReport8616(
            empty_returns, empty_returns, classified, materialized, failures,
        )
        if failures:
            raise RuntimeError("Proven terminal register values were not bound before SSA")
        return result

    cast(Any, Clinic)._make_returns = _make_returns_with_terminal_storage_8616
