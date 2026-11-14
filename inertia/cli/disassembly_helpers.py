# cython: language_level=3, infer_types=True
"""Format disassembly diagnostics without recovering decompiler semantics.

Layer: CLI/fallback/reporting.
Responsibility: format disassembly diagnostics without recovering or changing semantics.
"""

from __future__ import annotations
import typing
import cython

from typing import Protocol, cast

import angr

from inertia.cli.project_loading import _describe_exception


class _CapstoneInstructionLike(Protocol):
    address: cython.longlong
    mnemonic: object
    op_str: object
    size: cython.longlong


class _LoaderMainObjectLike(Protocol):
    linked_base: int | None
    max_addr: int | None


class _ProjectLoaderLike(Protocol):
    main_object: _LoaderMainObjectLike | None


@cython.ccall
def _format_first_block_asm(project: angr.Project, addr: cython.longlong) -> object:
    try:
        block = project.factory.block(addr, opt_level=0)
    except Exception as ex:
        return f"<assembly unavailable: {ex}>"
    insns = cast(list[_CapstoneInstructionLike], block.capstone.insns[:16])
    lines = [f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip() for insn in iter(insns)]
    return "\n".join(lines) if lines else "<no instructions>"


@cython.ccall
def _linear_disassembly(project: angr.Project, start: cython.longlong, end: cython.longlong) -> object:
    if end <= start:
        return []
    code = bytes(project.loader.memory.load(start, end - start))
    return cast(list[_CapstoneInstructionLike], list(project.arch.capstone.disasm(code, start)))


@cython.ccall
def _format_asm_range(project: angr.Project, start: cython.longlong, end: cython.longlong, *, max_instructions: cython.longlong = 128) -> str:
    if end <= start:
        return "<no instructions>"
    try:
        insns = _linear_disassembly(project, start, end)
    except Exception as ex:
        return f"<assembly unavailable: {ex}>"
    if not insns:
        return "<no instructions>"
    lines = [f"{insn.address:#06x}: {insn.mnemonic} {insn.op_str}".rstrip() for insn in iter(insns[:max_instructions])]
    if len(insns) > max_instructions:
        lines.append(f"... <truncated after {max_instructions} instructions>")
    return "\n".join(lines)


@cython.ccall
def _infer_linear_disassembly_window(
    project: angr.Project,
    addr: cython.longlong,
    *,
    max_window: cython.longlong = 0x180,
) -> tuple[cython.longlong, cython.longlong]:
    main_object: object
    insn: object
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


@cython.ccall
def _probe_lift_break(project: angr.Project, addr: cython.longlong, *, max_window: cython.longlong = 0x80) -> object:
    index: object
    insn: object
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
            lines = [f"{cur.address:#06x}: {cur.mnemonic} {cur.op_str}".rstrip() for cur in iter(window)]
            return f"first lift failure at {insn.address:#x}: {_describe_exception(ex)}\n" + "\n".join(lines)
    return "no per-instruction lift failure detected in linear probe window"
