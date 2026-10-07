"""Prove the load-program oracle distinguishes behavior under each declared ABI.

The oracle requires an explicit ``LoadProgramAbi`` declaration; each mode has
positive acceptance controls, behavior-mutation rejection controls, and
cross-mode compile-rejection controls proving the declaration discriminates.
"""

from pathlib import Path

import pytest
from tests.fixtures.x86_16_loadprogram_behavior import LoadProgramAbi, assert_loadprogram_behavior

_CORRECT_SOURCE = r'''
extern unsigned short exeLoadParams[11];
unsigned short loadprog(unsigned short, unsigned short, unsigned short, unsigned short, unsigned short);
unsigned short _dos_loadProgram(unsigned short file, unsigned long command, unsigned short *cs, unsigned short *ss)
{
    unsigned short err = loadprog(file, 0, 1, command, command >> 16);
    if (err) return err;
    cs[0] = exeLoadParams[10];
    ss[0] = exeLoadParams[8];
    return 0;
}
'''

# Same observable contract in the emitted binary ABI: the source-level
# `unsigned long command` arrives as its two machine words (arg_6 low,
# arg_8 high) between `file` (arg_4) and the cs/ss pointers (arg_a/arg_c).
_CORRECT_BINARY = r'''
extern unsigned short exeLoadParams[11];
unsigned short loadprog(unsigned short, unsigned short, unsigned short, unsigned short, unsigned short);
unsigned short _dos_loadProgram(unsigned short arg_4, unsigned short arg_6, unsigned short arg_8, unsigned short *arg_a, unsigned short *arg_c)
{
    unsigned short ax;
    unsigned short err;
    err = loadprog((unsigned short)arg_4, 0, 1, (unsigned short)arg_6, (unsigned short)arg_8);
    ax = err;
    if (err)
    {
        return ax;
    }
    arg_a[0] = exeLoadParams[10];
    arg_c[0] = exeLoadParams[8];
    return 0;
}
'''


@pytest.mark.parametrize("copy", [False, True])
def test_loadprogram_oracle_accepts_source_abi_direct_or_copied_return(tmp_path: Path, copy: bool) -> None:
    """Accept equivalent return expressions in the declared source ABI."""
    text = _CORRECT_SOURCE.replace("if (err) return err;", "unsigned short ax = err; if (err) return ax;") if copy else _CORRECT_SOURCE
    assert_loadprogram_behavior(text, tmp_path, abi=LoadProgramAbi.SOURCE)


def test_loadprogram_oracle_accepts_binary_abi_form(tmp_path: Path) -> None:
    """Accept word-split command arguments without rewriting generated C."""
    assert_loadprogram_behavior(_CORRECT_BINARY, tmp_path, abi=LoadProgramAbi.BINARY)


@pytest.mark.parametrize("old,new", [
    ("return err;", "return err + 1;"),
    ("if (err)", "if (!err)"),
    ("cs[0]", "cs[1]"),
    ("exeLoadParams[8]", "exeLoadParams[9]"),
    ("loadprog(file, 0, 1,", "loadprog(file, 0, 2,"),
    ("return 0;", "return loadprog(file, 0, 1, command, command >> 16);"),
])
def test_loadprogram_oracle_rejects_source_abi_corruptions(tmp_path: Path, old: str, new: str) -> None:
    """Reject changed observations even when source-ABI C still compiles."""
    with pytest.raises(AssertionError, match="behavior mismatch"):
        assert_loadprogram_behavior(_CORRECT_SOURCE.replace(old, new), tmp_path, abi=LoadProgramAbi.SOURCE)


@pytest.mark.parametrize("old,new", [
    ("return ax;", "return ax + 1;"),
    ("if (err)", "if (!err)"),
    ("arg_a[0]", "arg_a[1]"),
    ("exeLoadParams[8]", "exeLoadParams[9]"),
    ("arg_4, 0, 1,", "arg_4, 0, 2,"),
    ("(unsigned short)arg_6, (unsigned short)arg_8", "(unsigned short)arg_8, (unsigned short)arg_6"),
    ("return 0;", "return loadprog((unsigned short)arg_4, 0, 1, (unsigned short)arg_6, (unsigned short)arg_8);"),
])
def test_loadprogram_oracle_rejects_binary_abi_corruptions(tmp_path: Path, old: str, new: str) -> None:
    """Reject word-order, call, error and output mutations in the binary ABI."""
    with pytest.raises(AssertionError, match="behavior mismatch"):
        assert_loadprogram_behavior(_CORRECT_BINARY.replace(old, new), tmp_path, abi=LoadProgramAbi.BINARY)


@pytest.mark.parametrize("text,abi", [
    (_CORRECT_SOURCE, LoadProgramAbi.BINARY),
    (_CORRECT_BINARY, LoadProgramAbi.SOURCE),
])
def test_loadprogram_oracle_rejects_wrong_declared_abi(tmp_path: Path, text: str, abi: LoadProgramAbi) -> None:
    """Declaring the wrong ABI must fail at compile time, proving the declared
    mode actually discriminates instead of accepting either shape."""
    with pytest.raises(AssertionError, match="compile failed"):
        assert_loadprogram_behavior(text, tmp_path, abi=abi)
