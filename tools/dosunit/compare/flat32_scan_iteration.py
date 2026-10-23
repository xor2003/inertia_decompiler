"""Layer: dosunit native SSA lowering.

Responsibility: lower one admitted default-width SCAS iteration and construct
its exact REP continuation, without claiming loop completion or equivalence.
"""

from __future__ import annotations

from typing import Any, cast

import archinfo
import pyvex

from tools.dosunit.architectures.flat32 import flat32_register_architecture
from tools.dosunit.compare import straightline_ssa as S


def lower_scan_body(raw: bytes, address: int) -> dict[str, Any]:
    """Reuse native scalar SCAS flag/index semantics for a two-byte REP form."""
    if raw not in (b"\xf2\xae", b"\xf3\xae", b"\xf2\xaf", b"\xf3\xaf"):
        raise ValueError("scan iteration requires admitted default REP SCAS bytes")
    arch = flat32_register_architecture()
    irsb = pyvex.IRSB(raw[1:], address + 1, cast(Any, archinfo.ArchX86()), opt_level=0, max_inst=1)
    if irsb.size != 1 or irsb.jumpkind != "Ijk_Boring":
        raise S.LowerFailure("scan_iteration_lowering", "scalar SCAS must fall through")
    outputs = (*(name for name, _ in arch.registers if name != "eip"), "ip")
    lowered = S._lower_irsb(irsb, output_regs=outputs, max_assignments_per_function=4096, architecture=arch)
    if isinstance(lowered, S.LowerFailure):
        raise lowered
    lowered["outputs"].setdefault("memory", {"op": "mem_input", "name": "mem", "addr_width": 32, "value_width": 8})
    return cast(dict[str, Any], lowered)


def scan_repeat_guard(
    raw: bytes, before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Decrement ECX once and decide continuation from this iteration's equality.

    The caller must guard this body with incoming ECX != 0. Initial ZF does not
    control the first iteration. VEX owns final flags and DF-scaled EDI update.
    """
    width = 8 if raw[1] == 0xAE else 32
    accumulator = before["eax"] if width == 32 else {"op": "trunc", "width": 8, "args": [before["eax"]]}
    operand = {"op": "loadle", "width": width, "args": [before["memory"], before["edi"]]}
    equal = {"op": "eq", "width": 1, "args": [accumulator, operand]}
    after["ecx"] = {"op": "sub", "width": 32, "args": [before["ecx"], {"op": "const", "width": 32, "value": "0x1"}]}
    nonzero = {"op": "ne", "width": 1, "args": [after["ecx"], {"op": "const", "width": 32, "value": "0x0"}]}
    condition = equal if raw[0] == 0xF3 else {"op": "not", "width": 1, "args": [equal]}
    return {"op": "and", "width": 1, "args": [nonzero, condition]}
