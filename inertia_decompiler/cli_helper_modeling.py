from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


def _int21_call_replacements(
    project: Any,
    function: Any,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_dos_int21_calls: Callable[[Any, Path | None], list[Any]],
    render_dos_int21_call: Callable[[Any, str], str],
) -> list[str]:
    return [
        render_dos_int21_call(call, api_style)
        for call in collect_dos_int21_calls(function, binary_path)
    ]


def _interrupt_call_replacement_map(
    project: Any,
    function: Any,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_interrupt_service_calls: Callable[[Any, Path | None], list[Any]],
    render_interrupt_call: Callable[[Any, str], str],
    helper_name: Callable[[Any, int], str | None],
    interrupt_service_addr: Callable[[Any], int],
) -> dict[str, str]:
    replacements: dict[str, str] = {}
    for call in collect_interrupt_service_calls(function, binary_path):
        replacement = render_interrupt_call(call, api_style)
        target_addr = getattr(function, "get_call_target", lambda _addr: None)(call.insn_addr)
        if isinstance(target_addr, int):
            replacements[str(target_addr)] = replacement
            replacements[hex(target_addr)] = replacement
            replacements[hex(target_addr).upper().replace("X", "x")] = replacement

        known_helper_name = helper_name(project, interrupt_service_addr(call))
        if known_helper_name:
            replacements[known_helper_name] = replacement
            replacements[known_helper_name.lstrip("_")] = replacement
    return replacements


def _dos_helper_declarations(
    function: Any,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_dos_int21_calls: Callable[[Any, Path | None], list[Any]],
    dos_helper_declarations: Callable[[list[Any], str], list[str]],
) -> list[str]:
    return dos_helper_declarations(collect_dos_int21_calls(function, binary_path), api_style)


def _interrupt_helper_declarations(
    function: Any,
    api_style: str,
    binary_path: Path | None,
    *,
    collect_interrupt_service_calls: Callable[[Any, Path | None], list[Any]],
    interrupt_service_declarations: Callable[[list[Any], str], list[str]],
) -> list[str]:
    return interrupt_service_declarations(collect_interrupt_service_calls(function, binary_path), api_style)


def _known_helper_declarations(
    cod_metadata: Any,
    *,
    preferred_known_helper_signature_decl: Callable[[str], str | None],
) -> list[str]:
    if cod_metadata is None:
        return []

    declarations: list[str] = []
    seen: set[str] = set()
    for call_name in cod_metadata.call_names:
        decl = preferred_known_helper_signature_decl(call_name)
        if decl is None or decl in seen:
            continue
        seen.add(decl)
        declarations.append(decl)
    return declarations
