# cython: language_level=3, infer_types=True
"""Initialize shared binary call summaries before Lowering consumes them.

Layer: Types/Lowering.
Responsibility: publish the existing callsite-summary owner's evidence on the
native code generator without depending on a later cleanup pass.
Consumes alias, widening, and typed facts.
Do not recover semantics from COD, source, assembly, or rendered C text.
No call, value, argument, signature or storage recovery belongs here.
"""

from __future__ import annotations
import cython

from collections.abc import Iterable
from typing import Protocol, cast

from angr import Project

from inertia.semantics.callsite_summary import (
    CallsiteSummary8616,
    build_callsite_summary_inventory_8616,
    callsite_summary_inventory_8616,
)


class _FunctionAddress8616(Protocol):
    """Native structured-function identity required for existing KB lookup."""

    addr: cython.longlong


class _Codegen8616(Protocol):
    """Native codegen surface carrying the authoritative typed inventory."""

    project: Project
    cfunc: _FunctionAddress8616
    _inertia_callsite_summary_inventory_8616: object


def ensure_callsite_summary_inventory_8616(codegen: object) -> object:
    """Reuse published evidence or ask its binary owner before consuming it.

    Keep the existing empty-inventory retry behavior: function discovery may
    populate callsites later. A missing native KB/function remains unknown;
    malformed published inventories still fail the owner's contract checks.
    """
    function: object
    inventory = callsite_summary_inventory_8616(codegen)
    if inventory:
        return inventory
    boundary = cast(_Codegen8616, codegen)
    try:
        function = boundary.project.kb.functions.function(addr=boundary.cfunc.addr, create=False)
        if function is None:
            return {}
        raw_callsites = function.get_call_sites()
    except AttributeError:
        return {}
    if not isinstance(raw_callsites, Iterable):
        return {}
    callsite_addrs = tuple(item for item in iter(raw_callsites) if isinstance(item, int))
    inventory = build_callsite_summary_inventory_8616(function, callsite_addrs)
    boundary._inertia_callsite_summary_inventory_8616 = inventory
    return inventory
