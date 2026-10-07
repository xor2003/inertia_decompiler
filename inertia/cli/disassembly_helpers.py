"""Format disassembly diagnostics without recovering decompiler semantics.

Layer: CLI/fallback/reporting.
Responsibility: format disassembly diagnostics without recovering or changing semantics.
"""

from __future__ import annotations

from typing import Protocol, cast

import angr

from inertia.cli.project_loading import _describe_exception


class _CapstoneInstructionLike(Protocol):
    address: int
    mnemonic: str
    op_str: str
    size: int


class _LoaderMainObjectLike(Protocol):
    linked_base: int | None
    max_addr: int | None


class _ProjectLoaderLike(Protocol):
    main_object: _LoaderMainObjectLike | None


def _format_first_block_asm(project: angr.Project, addr: int) -> str:
    try:
        block = project.factory.block(addr, opt_level=0)
    except Exception as ex:
        return f"<assembly unavailable: {ex}>"
    insns = cast(list[_CapstoneInstructionLike], block.capstone.insns[:16])
    lines = [f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip() for insn in insns]
    return "\n".join(lines) if lines else "<no instructions>"


def _linear_disassembly(project: angr.Project, start: int, end: int) -> list[_CapstoneInstructionLike]:
    if end <= start:
        return []
    code = bytes(project.loader.memory.load(start, end - start))
    return cast(list[_CapstoneInstructionLike], list(project.arch.capstone.disasm(code, start)))


def _format_asm_range(project: angr.Project, start: int, end: int, *, max_instructions: int = 128) -> str:
    if end <= start:
        return "<no instructions>"
    try:
        insns = _linear_disassembly(project, start, end)
    except Exception as ex:
        return f"<assembly unavailable: {ex}>"
    if not insns:
        return "<no instructions>"
    lines = [f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip() for insn in insns[:max_instructions]]
    if len(insns) > max_instructions:
        lines.append(f"... <truncated after {max_instructions} instructions>")
    return "\n".join(lines)


def _infer_linear_disassembly_window(
    project: angr.Project,
    addr: int,
    *,
    max_window: int = 0x180,
) -> tuple[int, int]:
    try:
        main_object = cast(_ProjectLoaderLike, project.loader).main_object
    except AttributeError:
        main_object = None
    if main_object is None:
        return addr, addr + max_window
    linked_base = main_object.linked_base
    max_addr = main_object.max_addr
    if not isinstance(linked_base, int) or not isinstance(max_addr, int):
        return addr, addr + max_window
    end = min(addr + max_window, max_addr + 1)
    try:
        insns = _linear_disassembly(project, addr, end)
    except Exception:
        return addr, end
    if not insns:
        return addr, end
    for insn in insns:
        mnemonic = insn.mnemonic.lower()
        if mnemonic.startswith("ret") or mnemonic in {"iret", "jmp"}:
            return addr, min(end, insn.address + insn.size)
    return addr, min(end, insns[-1].address + insns[-1].size)


def _probe_lift_break(project: angr.Project, addr: int, *, max_window: int = 0x80) -> str:
    start, end = _infer_linear_disassembly_window(project, addr, max_window=max_window)
    try:
        insns = _linear_disassembly(project, start, end)
    except Exception as ex:
        return f"<lift probe unavailable: {ex}>"
    if not insns:
        return "<lift probe unavailable: no instructions>"
    for index, insn in enumerate(insns):
        try:
            project.factory.block(insn.address, size=max(1, insn.size), opt_level=0)
        except Exception as ex:
            window = insns[max(0, index - 3) : min(len(insns), index + 5)]
            lines = [f"{cur.address:#06x}: {cur.mnemonic} {cur.op_str}".rstrip() for cur in window]
            return f"first lift failure at {insn.address:#x}: {_describe_exception(ex)}\n" + "\n".join(lines)
    return "no per-instruction lift failure detected in linear probe window"
