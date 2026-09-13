"""Render C runtime helper declarations required by lowered output.

Layer: Types/Lowering.
Responsibility: owns C runtime helper declarations for lowered output.
Consumes alias, widening, and typed facts by emitting only the helper surface
needed for already-materialized segmented memory and runtime abstractions.
Do not recover semantics from COD, source, assembly, or rendered C text.
"""

from __future__ import annotations

from collections.abc import Sequence

from ..analysis_helpers import (
    InterruptCall,
    interrupt_service_declarations,
    interrupt_service_spec,
)
from ..simos_86_16 import get_interrupt_handler_class

LOWERED_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    "clock": "clock_t clock(void);",
    "rand": "int rand(void);",
    "srand": "void srand(unsigned int seed);",
    "time": "time_t time(time_t *out);",
    "strcpy": "char *strcpy(char *dst, const char *src);",
    "dos_int21_flags": "unsigned short dos_int21_flags(void);",
    "inertia_io_out8": "void inertia_io_out8(uint16_t port, uint8_t value);",
    "inertia_io_out16": "void inertia_io_out16(uint16_t port, uint16_t value);",
    "inertia_io_out32": "void inertia_io_out32(uint16_t port, uint32_t value);",
}

KNOWN_EXTERNAL_DECLARATIONS_8616: dict[str, str] = {
    "memset": "void * memset(void *dst, int value, unsigned short count);",
    "outtext": "void outtext(char *a0);",
    "sprintf": "int sprintf(char *buf, const char *fmt, ...);",
}

LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, str] = {
    name: LOWERED_RUNTIME_HELPER_DECLARATIONS_8616[name]
    for name in ("clock", "rand")
}

LOWERED_RUNTIME_MACROS_8616: frozenset[str] = frozenset(
    {
        "MEM_U8",
        "MEM_U16",
        "MEM_U32",
        "MK_FP",
        "PTR_U16",
        "PTR_U32",
        "SEG_LINEAR",
        "SEG_PTR",
        "SEG_U8",
        "SEG_U16",
        "SEG_U32",
    }
)

# Exact external return ABIs override caller-use inference. An unused result
# proves only that the caller discards it; it does not change the callee ABI.
KNOWN_EXTERNAL_RETURN_TYPES_8616: dict[str, str] = {
    "getvideoconfig": "unsigned short",
    "memset": "void *",
    "outtext": "void",
    "intdos": "int",
    "intdosx": "int",
}

_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "long aNldiv(long dividend, long divisor);",
)

_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: tuple[str, ...] = (
    "int32_t aNldiv(int32_t dividend, int32_t divisor);",
)

_TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616: dict[str, dict[str, str]] = {
    "msc-dos": {
        "aNldiv": _MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "long setbkcolor(long color);",
    },
    "portable-flat": {
        "aNldiv": _PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616[0],
        "setbkcolor": "int32_t setbkcolor(int32_t color);",
    },
}

_RUNTIME_SEGMENT_STATE_DECLARATIONS_8616: tuple[str, ...] = (
    "extern uint16_t inertia_cs;",
    "extern uint16_t inertia_ds;",
    "extern uint16_t inertia_es;",
    "extern uint16_t inertia_ss;",
)


def runtime_helper_declaration_8616(name: str, target: str | None) -> str | None:
    """Return an exact external declaration owned by the selected C ABI."""
    normalized_target = str(target or "").strip().lower()
    target_declarations = _TARGET_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616.get(normalized_target, {})
    declaration = target_declarations.get(name)
    if declaration is not None:
        return declaration
    declaration = KNOWN_EXTERNAL_DECLARATIONS_8616.get(name)
    if declaration is not None:
        return declaration
    return LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.get(name)


def interrupt_helper_declarations_8616(
    calls: Sequence[InterruptCall],
    api_style: str,
) -> list[str]:
    """Lower typed interrupt calls to declarations for their emitted helpers."""
    service_calls = [
        call
        for call in calls
        if call.vector == 0x21 or interrupt_service_spec(call) is not None
    ]
    declarations: list[str] = list(interrupt_service_declarations(service_calls, api_style))
    seen = set(declarations)
    for call in calls:
        handler = get_interrupt_handler_class(call.vector)
        return_type = "void" if handler.NO_RET else "unsigned short"
        if call.vector == 0x33 and call.ax == 0x0004:
            declaration = (
                f"{return_type} {handler.INT_NAME}(unsigned short ax, "
                "unsigned short cx, unsigned short dx);"
            )
        elif call.vector == 0x21:
            declaration = f"{return_type} {handler.INT_NAME}();"
        else:
            declaration = f"{return_type} {handler.INT_NAME}(void);"
        if declaration not in seen:
            seen.add(declaration)
            declarations.append(declaration)
    return declarations


def is_lowered_runtime_macro_8616(name: str) -> bool:
    """Return whether lowering owns ``name`` as a C macro rather than a callable."""
    return name in LOWERED_RUNTIME_MACROS_8616


def render_pointer_storage_macros_8616(target: str) -> str:
    """Render target pointer-to-storage casts for headers and rebuild harnesses."""
    if target not in {"msc-dos", "portable-flat"}:
        raise ValueError(f"Unsupported pointer-storage target: {target!r}")
    intermediate_cast = "(uintptr_t)" if target == "portable-flat" else ""
    return (
        f"#define PTR_U16(ptr)       ((uint16_t){intermediate_cast}(ptr))\n"
        f"#define PTR_U32(ptr)       ((uint32_t){intermediate_cast}(ptr))\n"
    )


def render_c_runtime_header_8616(target: str | None) -> str:
    """Return the C helper header for the requested generated-C target."""
    normalized = str(target or "").strip().lower()
    runtime_helper_declarations = "\n".join(LOWERED_RUNTIME_HELPER_DECLARATIONS_8616.values())
    runtime_segment_state_declarations = "\n".join(_RUNTIME_SEGMENT_STATE_DECLARATIONS_8616)
    if normalized == "msc-dos":
        compiler_helper_declarations = "\n".join(_MSC_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return (
            "#include <DOS.H>\n"
            "\n"
            "typedef signed char    int8_t;\n"
            "typedef signed short   int16_t;\n"
            "typedef signed long    int32_t;\n"
            "typedef unsigned char  uint8_t;\n"
            "typedef unsigned short uint16_t;\n"
            "typedef unsigned long  uint32_t;\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            f"{runtime_segment_state_declarations}\n"
            "\n"
            "#ifndef MK_FP\n"
            "#define MK_FP(seg, off) ((uint8_t far *)((((unsigned long)(unsigned short)(seg)) << 16) | (unsigned short)(off)))\n"
            "#endif\n"
            "\n"
            "#define SEG_PTR(seg, off)  MK_FP((seg), (off))\n"
            "#define SEG_U8(seg, off)   (*(uint8_t  far *)MK_FP((seg), (off)))\n"
            "#define SEG_U16(seg, off)  (*(uint16_t far *)MK_FP((seg), (off)))\n"
            "#define SEG_U32(seg, off)  (*(uint32_t far *)MK_FP((seg), (off)))\n"
            "#define MEM_U8(ptr)        (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)       (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)       (*(uint32_t *)(ptr))\n"
            f"{render_pointer_storage_macros_8616(normalized)}"
        )
    if normalized == "portable-flat":
        compiler_helper_declarations = "\n".join(_PORTABLE_COMPILER_RUNTIME_HELPER_DECLARATIONS_8616)
        return (
            "#include <stdbool.h>\n"
            "#include <stddef.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "typedef long clock_t;\n"
            "typedef long time_t;\n"
            "\n"
            f"{runtime_helper_declarations}\n"
            f"{compiler_helper_declarations}\n"
            "\n"
            "extern uint8_t inertia_memory[];\n"
            f"{runtime_segment_state_declarations}\n"
            "\n"
            "#ifndef far\n"
            "#define far\n"
            "#endif\n"
            "\n"
            "#define SEG_LINEAR(seg, off) ((((uint32_t)(uintptr_t)(seg)) << 4) + ((uint16_t)(uintptr_t)(off)))\n"
            "#define MK_FP(seg, off)      (&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_PTR(seg, off)    ((char *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U8(seg, off)     (*(uint8_t  *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U16(seg, off)    (*(uint16_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define SEG_U32(seg, off)    (*(uint32_t *)&inertia_memory[SEG_LINEAR((seg), (off))])\n"
            "#define MEM_U8(ptr)          (*(uint8_t  *)(ptr))\n"
            "#define MEM_U16(ptr)         (*(uint16_t *)(ptr))\n"
            "#define MEM_U32(ptr)         (*(uint32_t *)(ptr))\n"
            f"{render_pointer_storage_macros_8616(normalized)}"
        )
    return ""


__all__ = [
    "KNOWN_EXTERNAL_DECLARATIONS_8616",
    "KNOWN_EXTERNAL_RETURN_TYPES_8616",
    "LOWERED_RUNTIME_HELPER_DECLARATIONS_8616",
    "LOWERED_RUNTIME_MACROS_8616",
    "LOWERED_ZERO_ARG_RUNTIME_HELPER_DECLARATIONS_8616",
    "interrupt_helper_declarations_8616",
    "is_lowered_runtime_macro_8616",
    "render_c_runtime_header_8616",
    "render_pointer_storage_macros_8616",
    "runtime_helper_declaration_8616",
]
