from __future__ import annotations

from dataclasses import dataclass
from typing import Any


SAFE_X86_16_SLICE_BASE = 0x1000
_ORIGINAL_ADDR_BY_FUNCTION_ID: dict[int, int] = {}


@dataclass(frozen=True)
class X86ExactSlicePlan:
    original_start: int
    original_end: int
    slice_base: int

    @property
    def needs_rebased_slice(self) -> bool:
        return self.slice_base != self.original_start

    @property
    def slice_start(self) -> int:
        return self.slice_base

    @property
    def slice_end(self) -> int:
        return self.slice_base + max(0, self.original_end - self.original_start)


def plan_x86_16_exact_slice(original_start: int, original_end: int) -> X86ExactSlicePlan:
    slice_base = SAFE_X86_16_SLICE_BASE if original_start >= 0x10000 else original_start
    return X86ExactSlicePlan(
        original_start=original_start,
        original_end=original_end,
        slice_base=slice_base,
    )


def function_original_addr(function: Any) -> int:
    original_addr = _ORIGINAL_ADDR_BY_FUNCTION_ID.get(id(function))
    if isinstance(original_addr, int):
        return original_addr
    info = getattr(function, "info", None)
    if isinstance(info, dict):
        original_addr = info.get("inertia_original_addr")
        if isinstance(original_addr, int):
            return original_addr
    addr = getattr(function, "addr", 0)
    return addr if isinstance(addr, int) else 0


def mark_function_original_addr(function: Any, original_addr: int) -> None:
    _ORIGINAL_ADDR_BY_FUNCTION_ID[id(function)] = original_addr
    info = getattr(function, "info", None)
    if not isinstance(info, dict):
        return
    info["inertia_original_addr"] = original_addr
