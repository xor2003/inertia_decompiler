"""Apply typed return-contract lowering after angr Clinic prototype inference.

Layer: Types/lowering compatibility boundary.
Responsibility: present complete AIL terminal-return evidence to the owned
return-type lowerer after angr has synthesized its generated prototype.
Forbidden: instruction, source, COD, name, or rendered-C based recovery.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from typing import Any, Protocol, cast

from angr import ailment
from angr.analyses.decompiler.clinic import Clinic
from angr.analyses.decompiler.decompiler import Decompiler
from angr.knowledge_plugins.functions.function import PrototypeSource

from .callsite_summary import CallerReturnUseVerdict8616
from .lowering.authoritative_function_prototypes import (
    capture_authoritative_function_prototype_8616,
)
from .lowering.native_terminal_return_values import apply_native_terminal_return_values_8616
from .lowering.return_type_evidence import proven_function_result_observation_8616
from .lowering.unused_void_return_types import (
    TerminalReturnValueEvidence8616,
    UnusedVoidReturnTypeResult8616,
    materialize_unused_caller_void_return_type_8616,
    record_terminal_return_value_evidence_8616,
)
from .semantics.terminal_register_returns import collect_terminal_ax_return_evidence_8616

__all__ = [
    "apply_x86_16_clinic_return_type_compatibility",
    "collect_clinic_terminal_return_evidence_8616",
    "finalize_clinic_return_type_8616",
]


class _GraphSurface8616(Protocol):
    """Third-party AIL graph fields consumed by the compatibility adapter."""

    def nodes(self) -> Iterable[object]:
        """Return graph blocks."""
        ...


class _BlockSurface8616(Protocol):
    """Third-party AIL block fields consumed by the compatibility adapter."""

    statements: Iterable[object]


class _FunctionSurface8616(Protocol):
    """Third-party angr function fields consumed at the Clinic boundary."""

    addr: int
    is_prototype_guessed: bool
    prototype: object | None
    prototype_source: PrototypeSource


class _ClinicSurface8616(Protocol):
    """Third-party angr Clinic fields consumed by the compatibility adapter."""

    _ail_graph: _GraphSurface8616
    function: _FunctionSurface8616
    project: object


class _DecompilerSurface8616(Protocol):
    """Third-party decompiler field available before its constructor runs."""

    project: object


_DECOMPILER_INIT_PATCHED_8616 = False


def _capture_strong_prototype_at_decompiler_entry_8616() -> None:
    """Capture the caller-provided prototype before decompiler setup mutates it."""
    global _DECOMPILER_INIT_PATCHED_8616
    if _DECOMPILER_INIT_PATCHED_8616:
        return
    original = Decompiler.__init__

    def _init_8616(
        self: object,
        function: object,
        *args: object,
        **kwargs: object,
    ) -> None:
        """Publish the strong interface, then enter third-party Decompiler."""
        decompiler = cast(_DecompilerSurface8616, self)
        if not isinstance(function, (int, str)):
            capture_authoritative_function_prototype_8616(
                decompiler.project,
                function,
            )
        cast(Any, original)(self, function, *args, **kwargs)

    cast(Any, Decompiler).__init__ = _init_8616
    _DECOMPILER_INIT_PATCHED_8616 = True


def _preserve_strong_prototype_during_cc_recovery_8616() -> None:
    """Keep authoritative prototypes while Clinic fills a missing calling convention."""
    original = Clinic._recover_calling_conventions
    if original.__name__ == "_recover_calling_conventions_8616":
        return

    def _recover_calling_conventions_8616(self: object, func_graph: object | None = None) -> None:
        """Adapt angr 9.3 Clinic without replacing evidence-backed prototype types."""
        clinic = cast(_ClinicSurface8616, self)
        function = clinic.function
        preserved_prototype = function.prototype
        preserved_source = function.prototype_source
        cast(Any, original)(self, func_graph=func_graph)
        if preserved_prototype is not None and preserved_source >= PrototypeSource.CCA_DECOMPILER:
            function.prototype = preserved_prototype
            function.prototype_source = preserved_source

    cast(Any, Clinic)._recover_calling_conventions = _recover_calling_conventions_8616



def collect_clinic_terminal_return_evidence_8616(graph: object) -> TerminalReturnValueEvidence8616:
    """Classify all AIL Return statements without interpreting their expressions."""
    graph_surface = cast(_GraphSurface8616, graph)
    try:
        blocks = tuple(graph_surface.nodes())
    except (AttributeError, TypeError):
        return TerminalReturnValueEvidence8616(0, 0, 0, 0, 0, 1)
    returns: list[ailment.Stmt.Return] = []
    failure_count = 0
    for block in blocks:
        try:
            statements = tuple(cast(_BlockSurface8616, block).statements)
        except (AttributeError, TypeError):
            failure_count += 1
            continue
        returns.extend(statement for statement in statements if isinstance(statement, ailment.Stmt.Return))
    value_count = sum(bool(statement.ret_exprs) for statement in returns)
    return TerminalReturnValueEvidence8616(
        len(returns),
        len(returns),
        len(returns),
        value_count,
        len(returns) - value_count,
        failure_count,
    )


def finalize_clinic_return_type_8616(
    project: object,
    function: object,
    graph: object,
    *,
    prototype_was_guessed: bool,
) -> UnusedVoidReturnTypeResult8616:
    """Materialize an unobservable empty return contract from closed typed facts."""
    function_surface = cast(_FunctionSurface8616, function)
    evidence = collect_clinic_terminal_return_evidence_8616(graph)
    record_terminal_return_value_evidence_8616(project, function_surface.addr, evidence)
    observation = proven_function_result_observation_8616(project, function_surface.addr)
    terminal_ax_evidence = collect_terminal_ax_return_evidence_8616(project, function)
    terminal_value_proven = (
        not evidence.proves_no_terminal_value
        and not terminal_ax_evidence.proves_missing_value_path
        and not terminal_ax_evidence.proves_local_pointer_output_carrier
    )
    result = materialize_unused_caller_void_return_type_8616(
        project,
        function,
        caller_observation=(observation if observation is not None else CallerReturnUseVerdict8616.UNKNOWN),
        prototype_was_guessed=prototype_was_guessed,
        terminal_value_proven=terminal_value_proven,
    )
    if os.environ.get("INERTIA_DEBUG_TERMINAL_RETURN_TYPES") == "1":
        logging.getLogger(__name__).warning(
            "Clinic return evidence: addr=%#x guessed=%s ail_terminal=%r ax_terminal=%r caller=%s result=%r",
            function_surface.addr,
            prototype_was_guessed,
            evidence,
            terminal_ax_evidence,
            observation,
            result,
        )
    return result


def apply_x86_16_clinic_return_type_compatibility() -> None:
    """Install the post-prototype Clinic lowering adapter once."""
    _capture_strong_prototype_at_decompiler_entry_8616()
    _preserve_strong_prototype_during_cc_recovery_8616()
    apply_native_terminal_return_values_8616()
    original = Clinic._make_function_prototype
    if original.__name__ == "_make_function_prototype_8616":
        return

    def _make_function_prototype_8616(
        self: object,
        arg_list: list[object],
        variable_kb: object | None = None,
    ) -> None:
        """Run Clinic synthesis without replacing an authoritative prototype."""
        clinic = cast(_ClinicSurface8616, self)
        function = clinic.function
        prototype_was_guessed = function.is_prototype_guessed
        authoritative = capture_authoritative_function_prototype_8616(
            clinic.project,
            function,
        )
        if variable_kb is None:
            cast(Any, original)(self, arg_list)
        else:
            cast(Any, original)(self, arg_list, variable_kb)
        finalize_clinic_return_type_8616(
            clinic.project,
            function,
            clinic._ail_graph,
            prototype_was_guessed=prototype_was_guessed,
        )
        if authoritative is not None:
            function.prototype = authoritative.prototype.copy()
            function.prototype_source = authoritative.source

    cast(Any, Clinic)._make_function_prototype = _make_function_prototype_8616
