"""Prove the generated-C oracle accepts word results and rejects call corruption."""

from pathlib import Path

import pytest
from x86_16_dosfunc_behavior import assert_dos_free_behavior

_DECLARATIONS = """
#include <stdint.h>
typedef union REGS {
    struct { unsigned short ax, bx, cx, dx, si, di, cflag; } x;
    struct { unsigned char al, ah; } h;
} REGS;
typedef struct SREGS { unsigned short es, cs, ss, ds; } SREGS;
extern REGS rin, rout;
extern SREGS sreg;
extern unsigned long inertia_eax;
int intdosx(REGS *, REGS *, SREGS *);
int ERROR(const char *, ...);
"""


def _wrapper(
    expression: str, *, setup: str = "rin.h.ah = 73; sreg.es = segment;",
    extra_call: str = "", result: str = "err", error_call: bool = True,
) -> str:
    error = 'ERROR("dos_free: error freeing segment 0x%x: error 0x%x", segment, err);' if error_call else ""
    return _DECLARATIONS + f"""
unsigned short _dos_free(unsigned short segment) {{
    {setup}
    {extra_call}
    unsigned short err = {expression};
    if (rout.x.cflag) {{ {error} return {result}; }}
    return 0;
}}
"""


@pytest.mark.parametrize("expression", [
    "intdosx(&rin, &rout, &sreg)",
    "(inertia_eax & 0xffff0000) | (intdosx(&rin, &rout, &sreg) & 0xffff)",
], ids=["word-result", "preserved-upper-eax"])
def test_oracle_accepts_equivalent_word_results(tmp_path: Path, expression: str) -> None:
    assert_dos_free_behavior(_wrapper(expression), tmp_path)


@pytest.mark.parametrize("source", [
    _wrapper("0"),
    _wrapper("intdosx(&rin, &rout, &sreg)", extra_call="intdosx(&rin, &rout, &sreg);"),
    _wrapper("intdosx(&rout, &rout, &sreg)"),
    _wrapper("intdosx(&rin, &rout, &sreg)", result="0"),
    _wrapper("intdosx(&rin, &rout, &sreg)", setup="rin.h.ah = 72; sreg.es = segment;"),
    _wrapper("intdosx(&rin, &rout, &sreg)", setup="rin.h.ah = 73; sreg.es = 0;"),
    _wrapper("intdosx(&rin, &rout, &sreg)", error_call=False),
], ids=["missing-call", "duplicate-call", "wrong-input-pointer", "lost-error-result",
        "wrong-service", "wrong-segment", "missing-error-report"])
def test_oracle_rejects_corrupted_behavior(tmp_path: Path, source: str) -> None:
    with pytest.raises(AssertionError, match="violated the call/result oracle"):
        assert_dos_free_behavior(source, tmp_path)


@pytest.mark.parametrize("original,replacement", [
    ("dos_free: error freeing segment", "wrong operation on segment"),
    (", segment, err);", ", 0, err);"),
    (", segment, err);", ", segment, 0);"),
])
def test_oracle_rejects_corrupted_error_report(tmp_path: Path, original: str, replacement: str) -> None:
    source = _wrapper("intdosx(&rin, &rout, &sreg)").replace(original, replacement)
    with pytest.raises(AssertionError, match="violated the call/result oracle"):
        assert_dos_free_behavior(source, tmp_path)
