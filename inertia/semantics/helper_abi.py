"""Layer: Recovery metadata.

Responsibility: own typed declarations and ABI shape metadata for known helpers.
Forbidden: using helper names as call-identity proof, substituting helper bodies,
or overriding binary callsite evidence.

Package ownership contract (canonical inertia/semantics package):
Layer: Semantics.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite,
postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from angr.sim_type import SimTypeFunction
from angr.utils.library import convert_cproto_to_py
from archinfo import Arch

__all__ = (
    "KNOWN_HELPER_ABIS_8616",
    "KnownHelperAbi8616",
    "known_helper_abi_8616",
    "known_helper_is_variadic_8616",
    "known_helper_logical_argument_widths_8616",
    "known_helper_prototype_8616",
    "known_helper_signature_declarations_8616",
    "preferred_known_helper_abi_8616",
)


@dataclass(frozen=True, slots=True)
class KnownHelperAbi8616:
    """Typed, optional ABI facts for one externally known helper label."""

    declaration: str | None = None
    variadic: bool = False
    logical_argument_widths: tuple[int, ...] | None = None


KNOWN_HELPER_ABIS_8616: Mapping[str, KnownHelperAbi8616] = MappingProxyType(
    {
        "aNchkstk": KnownHelperAbi8616(declaration="void aNchkstk(void);"),
        "__aNchkstk": KnownHelperAbi8616(declaration="void __aNchkstk(void);"),
        "_abort": KnownHelperAbi8616(declaration="void _abort(void);"),
        "_DEBUG": KnownHelperAbi8616(
            declaration="int _DEBUG(const char *fmt, ...);",
            variadic=True,
        ),
        "_ERROR": KnownHelperAbi8616(
            declaration="int _ERROR(const char *fmt, ...);",
            variadic=True,
        ),
        "_INFO": KnownHelperAbi8616(
            declaration="int _INFO(const char *fmt, ...);",
            variadic=True,
        ),
        "aNldiv": KnownHelperAbi8616(
            declaration="long aNldiv(long dividend, long divisor);",
            logical_argument_widths=(4, 4),
        ),
        "anldiv": KnownHelperAbi8616(logical_argument_widths=(4, 4)),
        "_fflush": KnownHelperAbi8616(declaration="int _fflush(FILE *f);"),
        "_fprintf": KnownHelperAbi8616(
            declaration="int _fprintf(FILE *f, const char *fmt, ...);",
            variadic=True,
        ),
        "_intdos": KnownHelperAbi8616(
            declaration="int _intdos(union REGS *in, union REGS *out);"
        ),
        "_intdosx": KnownHelperAbi8616(
            declaration="int _intdosx(union REGS *in, union REGS *out, struct SREGS *sreg);"
        ),
        "_dos_getProcessId": KnownHelperAbi8616(
            declaration="unsigned short _dos_getProcessId(void);"
        ),
        "_dos_setProcessId": KnownHelperAbi8616(
            declaration="int _dos_setProcessId(const unsigned short pid);"
        ),
        "intdos": KnownHelperAbi8616(
            declaration="int intdos(union REGS *in, union REGS *out);"
        ),
        "intdosx": KnownHelperAbi8616(
            declaration="int intdosx(union REGS *in, union REGS *out, struct SREGS *sreg);"
        ),
        "clearRect": KnownHelperAbi8616(
            declaration=(
                "void clearRect(void *dst, unsigned short left, unsigned short top, "
                "unsigned short right, unsigned short bottom);"
            )
        ),
        "clock": KnownHelperAbi8616(declaration="clock_t clock(void);"),
        "settextrows": KnownHelperAbi8616(declaration="int settextrows(int rows);"),
        "clearscreen": KnownHelperAbi8616(declaration="void clearscreen(int mode);"),
        "displaycursor": KnownHelperAbi8616(declaration="void displaycursor(int mode);"),
        "getvideoconfig": KnownHelperAbi8616(
            declaration="int getvideoconfig(void *config);",
            logical_argument_widths=(4,),
        ),
        "setvideomode": KnownHelperAbi8616(declaration="void setvideomode(int mode);"),
        "_setbkcolor": KnownHelperAbi8616(
            declaration="long _setbkcolor(long color);",
            logical_argument_widths=(4,),
        ),
        "setbkcolor": KnownHelperAbi8616(
            declaration="long setbkcolor(long color);",
            logical_argument_widths=(4,),
        ),
        "settextcolor": KnownHelperAbi8616(declaration="int settextcolor(int color);"),
        "settextposition": KnownHelperAbi8616(
            declaration="void settextposition(int row, int col);"
        ),
        "outtext": KnownHelperAbi8616(
            declaration="int outtext(const char *text);",
            logical_argument_widths=(4,),
        ),
        "outtextxy": KnownHelperAbi8616(logical_argument_widths=(2, 2, 4)),
        "sprintf": KnownHelperAbi8616(
            declaration="int sprintf(char *buf, const char *fmt, ...);",
            variadic=True,
        ),
        "_sprintf": KnownHelperAbi8616(
            declaration="int _sprintf(char *buf, const char *fmt, ...);",
            variadic=True,
        ),
        "strcpy": KnownHelperAbi8616(
            declaration="char *strcpy(char *dst, const char *src);"
        ),
        "exit": KnownHelperAbi8616(declaration="void exit(int status);"),
        "memset": KnownHelperAbi8616(
            declaration="void *memset(void *dst, int ch, unsigned long count);"
        ),
        "inp": KnownHelperAbi8616(
            declaration="unsigned char inp(unsigned short port);"
        ),
        "openFile": KnownHelperAbi8616(
            declaration="int openFile(const char *path, unsigned short mode);"
        ),
        "_openFile": KnownHelperAbi8616(
            declaration="int _openFile(const char *path, unsigned short mode);"
        ),
        "readchar": KnownHelperAbi8616(declaration="unsigned char readchar(void);"),
        "readcharat": KnownHelperAbi8616(
            declaration="unsigned char readcharat(unsigned short rowcol);"
        ),
        "setcursorpos": KnownHelperAbi8616(
            declaration="void setcursorpos(unsigned short rowcol);"
        ),
        "writecharat": KnownHelperAbi8616(
            declaration="void writecharat(unsigned short rowcol, unsigned char ch);"
        ),
        "writestringat": KnownHelperAbi8616(
            declaration="void writestringat(unsigned short rowcol, const char *s);"
        ),
        "dispdigit": KnownHelperAbi8616(
            declaration="void dispdigit(unsigned char digit);"
        ),
        "dispnum": KnownHelperAbi8616(
            declaration="void dispnum(unsigned short value);"
        ),
    }
)


def known_helper_abi_8616(name: str | None) -> KnownHelperAbi8616 | None:
    """Return ABI metadata only for an exact helper label."""
    if not isinstance(name, str) or not name:
        return None
    return KNOWN_HELPER_ABIS_8616.get(name)


def preferred_known_helper_abi_8616(name: str | None) -> KnownHelperAbi8616 | None:
    """Resolve a helper label while preserving canonical underscore preference."""
    if not isinstance(name, str) or not name:
        return None
    stripped = name.lstrip("_")
    underscored = f"_{stripped}" if stripped else name
    candidates = (underscored, name, stripped)
    for candidate in candidates:
        abi = KNOWN_HELPER_ABIS_8616.get(candidate)
        if abi is not None:
            return abi
    folded = stripped.casefold()
    for candidate, abi in KNOWN_HELPER_ABIS_8616.items():
        if candidate.lstrip("_").casefold() == folded:
            return abi
    return None


def known_helper_logical_argument_widths_8616(
    name: str | None,
) -> tuple[int, ...] | None:
    """Return helper ABI widths without treating them as callsite evidence."""
    abi = preferred_known_helper_abi_8616(name)
    return None if abi is None else abi.logical_argument_widths


def known_helper_is_variadic_8616(name: str | None) -> bool:
    """Return whether the helper declaration permits trailing arguments."""
    abi = preferred_known_helper_abi_8616(name)
    return abi is not None and abi.variadic


def known_helper_prototype_8616(
    name: str | None,
    arch: Arch,
) -> SimTypeFunction | None:
    """Project one owned helper declaration into an architecture-bound type."""
    abi = preferred_known_helper_abi_8616(name)
    if abi is None or abi.declaration is None:
        return None
    try:
        _parsed_name, prototype, _rendered = convert_cproto_to_py(abi.declaration)
    except Exception:
        # Dynamic boundary: angr's C parser rejects declarations whose external
        # typedefs are unavailable. Such helpers retain declaration-only metadata.
        return None
    if not isinstance(prototype, SimTypeFunction):
        return None
    bound_prototype = prototype.with_arch(arch)
    return bound_prototype if isinstance(bound_prototype, SimTypeFunction) else None


def known_helper_signature_declarations_8616() -> dict[str, str]:
    """Project the typed ABI catalog into the legacy declaration mapping."""
    return {
        name: abi.declaration
        for name, abi in KNOWN_HELPER_ABIS_8616.items()
        if abi.declaration is not None
    }
