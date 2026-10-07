"""Layer: CLI/fallback/reporting.

Responsibility: format known helper call/declaration text from explicit helper evidence.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Protocol, runtime_checkable


@runtime_checkable
class _CallTargetLookup(Protocol):
    """Function-like object that can resolve call-site targets."""

    def get_call_target(self, addr: int) -> int | None:
        """Return the target for a call-site instruction address."""


@runtime_checkable
class _InstructionAddressCall(Protocol):
    """Call-like object that exposes its instruction address."""

    insn_addr: int


def _int21_call_replacements(
    project: object,
    function: object,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_dos_int21_calls: Callable[[object, Path | None], Sequence[object]],
    render_dos_int21_call: Callable[[object, str], str],
) -> list[str]:
    return [render_dos_int21_call(call, api_style) for call in collect_dos_int21_calls(function, binary_path)]


def _interrupt_call_replacement_map(
    project: object,
    function: object,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_interrupt_service_calls: Callable[[object, Path | None], Sequence[object]],
    render_interrupt_call: Callable[[object, str], str],
    helper_name: Callable[[object, int], str | None],
    interrupt_service_addr: Callable[[object], int],
    interrupt_service_name: Callable[[object, str], str],
) -> dict[str, tuple[str, ...]]:
    pending_replacements: dict[str, list[str]] = {}

    def append_replacement(source_name: str, replacement: str) -> None:
        pending_replacements.setdefault(source_name, []).append(replacement)

    for call in collect_interrupt_service_calls(function, binary_path):
        replacement = render_interrupt_call(call, api_style)
        if isinstance(call, _InstructionAddressCall) and isinstance(function, _CallTargetLookup):
            target_addr = function.get_call_target(call.insn_addr)
        else:
            target_addr = None
        if isinstance(target_addr, int):
            append_replacement(str(target_addr), replacement)
            append_replacement(hex(target_addr), replacement)
            append_replacement(hex(target_addr).upper().replace("X", "x"), replacement)

        semantic_name = interrupt_service_name(call, "pseudo")
        known_helper_name = helper_name(project, interrupt_service_addr(call))
        if known_helper_name and known_helper_name != semantic_name:
            append_replacement(known_helper_name, replacement)
            unprefixed_helper_name = known_helper_name.lstrip("_")
            if unprefixed_helper_name != known_helper_name:
                append_replacement(unprefixed_helper_name, replacement)

        if semantic_name:
            append_replacement(semantic_name, replacement)
    return {source_name: tuple(values) for source_name, values in pending_replacements.items()}


def _dos_helper_declarations(
    function: object,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_dos_int21_calls: Callable[[object, Path | None], Sequence[object]],
    dos_helper_declarations: Callable[[Sequence[object], str], list[str]],
) -> list[str]:
    return dos_helper_declarations(collect_dos_int21_calls(function, binary_path), api_style)


def _interrupt_helper_declarations(
    function: object,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_interrupt_service_calls: Callable[[object, Path | None], Sequence[object]],
    interrupt_service_declarations: Callable[[Sequence[object], str], list[str]],
) -> list[str]:
    return interrupt_service_declarations(collect_interrupt_service_calls(function, binary_path), api_style)


def _known_helper_declarations(
    cod_metadata: object,
    *,
    preferred_known_helper_signature_decl: Callable[[str], str | None],
) -> list[str]:
    return []
