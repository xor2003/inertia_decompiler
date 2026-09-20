"""Provide coherent C89 full-register and word-register runtime storage.

Layer: Types/Lowering.
Responsibility: define the shared storage ABI for typed GP subregister views.
Word writes preserve the upper word by construction, not by duplicated shadow
state or aliasing an unsigned-long pointer as an unsigned-short pointer.
Production GP lowering selects coherent views for each fresh codegen. Runtime
providers consume the same default; explicit scalar selection supports legacy
artifacts. Never mix definitions from the two storage ABIs.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, cast


class GPRegisterRuntimeABI8616(StrEnum):
    """Explicit storage selection shared by declarations and runtime providers."""

    SCALAR = "scalar"
    COHERENT_WORD_VIEWS = "coherent_word_views"


DEFAULT_GP_RUNTIME_ABI_8616: GPRegisterRuntimeABI8616 = GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS


class _CodegenABI8616(Protocol):
    """Owned ABI selection carried by the dynamic angr codegen boundary."""

    _inertia_gp_runtime_abi_8616: GPRegisterRuntimeABI8616


def gp_runtime_abi_8616(codegen: object) -> GPRegisterRuntimeABI8616:
    """Read an explicit ABI selection; old codegen objects retain scalar ABI."""
    try:
        selected = cast(_CodegenABI8616, codegen)._inertia_gp_runtime_abi_8616
    except AttributeError:
        return GPRegisterRuntimeABI8616.SCALAR
    if not isinstance(selected, GPRegisterRuntimeABI8616):
        raise ValueError(f"invalid GP runtime ABI on codegen: {selected!r}")
    return selected


def select_gp_runtime_abi_8616(codegen: object, abi: GPRegisterRuntimeABI8616) -> None:
    """Publish the typed storage contract before lowering or rendering views."""
    if not isinstance(abi, GPRegisterRuntimeABI8616):
        raise ValueError(f"expected GPRegisterRuntimeABI8616, got {abi!r}")
    cast(_CodegenABI8616, codegen)._inertia_gp_runtime_abi_8616 = abi


def initialize_gp_runtime_abi_8616(codegen: object) -> None:
    """Initialize fresh/rebuilt codegen while preserving explicit ABI selection."""
    try:
        selected = cast(_CodegenABI8616, codegen)._inertia_gp_runtime_abi_8616
    except AttributeError:
        selected = DEFAULT_GP_RUNTIME_ABI_8616
    # Existing selections must satisfy the same contract, never silently reset.
    select_gp_runtime_abi_8616(codegen, selected)


@dataclass(frozen=True, slots=True)
class GPWordRuntimeLane8616:
    """C symbols naming two views of one shared architectural register lane."""

    full_register: str
    word_register: str

    @property
    def storage_symbol(self) -> str:
        """Return the one externally linked storage object for both views."""
        return f"inertia_gp_{self.full_register}"

    @property
    def full_symbol(self) -> str:
        """Return the public full-register expression name."""
        return f"inertia_{self.full_register}"

    @property
    def word_symbol(self) -> str:
        """Return the public low-word lvalue name."""
        return f"inertia_{self.word_register}"


GP_WORD_RUNTIME_LANES_8616: tuple[GPWordRuntimeLane8616, ...] = tuple(
    GPWordRuntimeLane8616(full, word) for full, word in (
        ("eax", "ax"), ("ebx", "bx"), ("ecx", "cx"), ("edx", "dx"),
        ("esi", "si"), ("edi", "di"), ("esp", "sp"), ("ebp", "bp"),
    )
)

_TYPE_DECLARATIONS = """#include <limits.h>
#if CHAR_BIT != 8
#error Inertia GP runtime requires 8-bit bytes
#endif
#if USHRT_MAX != 0xffffU
#error Inertia GP runtime requires a 16-bit unsigned short
#endif
#if UINT_MAX == 0xffffffffUL
typedef unsigned int inertia_gp_dword;
#elif ULONG_MAX == 0xffffffffUL
typedef unsigned long inertia_gp_dword;
#else
#error Inertia GP runtime requires a 32-bit unsigned integer type
#endif
typedef union inertia_gp_lane {
    inertia_gp_dword full;
    struct {
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        unsigned short high, low;
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || defined(_M_I86) || defined(M_I86)
        unsigned short low, high;
#else
#error Inertia GP runtime needs a known target byte order
#endif
    } word;
} inertia_gp_lane;
typedef char inertia_gp_lane_must_be_four_bytes[(sizeof(inertia_gp_lane) == 4) ? 1 : -1];
"""


def runtime_gp_word_symbols_8616() -> frozenset[str]:
    """Return reserved lvalue macros, which must never become synthetic globals."""
    return frozenset(lane.word_symbol for lane in GP_WORD_RUNTIME_LANES_8616)


def gp_runtime_replaced_declaration_names_8616(codegen: object) -> frozenset[str]:
    """Name scalar declarations superseded by the selected shared-storage ABI."""
    if gp_runtime_abi_8616(codegen) is not GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS:
        return frozenset()
    return frozenset(
        symbol for lane in GP_WORD_RUNTIME_LANES_8616
        for symbol in (lane.full_symbol, lane.word_symbol)
    )


def coherent_gp_runtime_header_8616() -> str:
    """Render declarations and lvalue views without allocating duplicate state.

    Union access remains syntactically through the union object, as required
    for GCC's union type-punning rule under strict aliasing. No subview pointer
    is exported. Taking a word address for use as a full-register pointer is
    not part of this ABI.
    """
    declarations = ["#ifndef INERTIA_COHERENT_GP_RUNTIME_H", "#define INERTIA_COHERENT_GP_RUNTIME_H", _TYPE_DECLARATIONS]
    for lane in GP_WORD_RUNTIME_LANES_8616:
        declarations.extend((
            f"extern inertia_gp_lane {lane.storage_symbol};",
            f"#define {lane.full_symbol} ({lane.storage_symbol}.full)",
            f"#define {lane.word_symbol} ({lane.storage_symbol}.word.low)",
        ))
    return "\n".join((*declarations, "#endif", ""))


def coherent_gp_runtime_definitions_8616() -> str:
    """Render the single runtime translation unit after including its header."""
    return "\n".join(f"inertia_gp_lane {lane.storage_symbol} = {{0}};" for lane in GP_WORD_RUNTIME_LANES_8616) + "\n"


def project_gp_runtime_declarations_8616(
    codegen: object, specs: tuple[object, ...],
) -> tuple[tuple[object, ...], tuple[str, ...]]:
    """Replace owned scalar declarations with the selected shared-storage ABI.

    This consumes typed declaration metadata, never rendered assignments. The
    original inventory is retained on codegen for semantic consumers. Other
    globals remain untouched and use the ordinary declaration renderer.
    """
    if gp_runtime_abi_8616(codegen) is not GPRegisterRuntimeABI8616.COHERENT_WORD_VIEWS:
        return specs, ()
    full_symbols = {lane.full_symbol for lane in GP_WORD_RUNTIME_LANES_8616}
    retained = tuple(
        spec for spec in specs if not (
            isinstance(spec, (tuple, list)) and len(spec) == 3
            and isinstance(spec[1], str) and spec[1] in full_symbols
        )
    )
    return retained, (coherent_gp_runtime_header_8616(),)
