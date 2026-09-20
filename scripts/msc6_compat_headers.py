"""Layer: Tooling/gates.

Responsibility: provide shared fixed-width and Boolean headers for MS C probes.
Compiler-owned size_t and ptrdiff_t come from the target's standard headers.
"""

from __future__ import annotations

from pathlib import Path

_STDBOOL: str = """#ifndef _STDBOOL_H
#define _STDBOOL_H
#define bool unsigned char
#define true 1
#define false 0
#endif
"""

_STDINT: str = """#ifndef _STDINT_H
#define _STDINT_H
#include <stddef.h>

typedef unsigned char uint8_t;
typedef signed char int8_t;
typedef unsigned short uint16_t;
typedef signed short int16_t;
typedef unsigned long uint32_t;
typedef signed long int32_t;
typedef unsigned int uintptr_t;

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef int16_t int_fast16_t;
typedef uint16_t uint_fast16_t;
typedef int32_t int_least32_t;
typedef uint32_t uint_least32_t;
typedef int16_t int_least16_t;
typedef uint16_t uint_least16_t;
#endif
"""


def write_msc6_compat_headers(out_dir: Path) -> None:
    """Emit headers for the existing MS C small-model test harness."""
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "STDBOOL.H").write_text(_STDBOOL, encoding="ascii")
    (out_dir / "STDINT.H").write_text(_STDINT, encoding="ascii")
