"""Prove the load-program oracle distinguishes behavior from variable spelling."""

import pytest
from x86_16_loadprogram_behavior import assert_loadprogram_behavior

_CORRECT = r'''
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


@pytest.mark.parametrize("copy", [False, True])
def test_loadprogram_oracle_accepts_direct_or_copied_return(tmp_path, copy) -> None:
    text = _CORRECT.replace("if (err) return err;", "unsigned short ax = err; if (err) return ax;") if copy else _CORRECT
    assert_loadprogram_behavior(text, tmp_path)


@pytest.mark.parametrize("old,new", [
    ("return err;", "return err + 1;"),
    ("if (err)", "if (!err)"),
    ("cs[0]", "cs[1]"),
    ("exeLoadParams[8]", "exeLoadParams[9]"),
    ("loadprog(file, 0, 1,", "loadprog(file, 0, 2,"),
    ("return 0;", "return loadprog(file, 0, 1, command, command >> 16);"),
])
def test_loadprogram_oracle_rejects_compilable_corruptions(tmp_path, old, new) -> None:
    with pytest.raises(AssertionError, match="behavior mismatch"):
        assert_loadprogram_behavior(_CORRECT.replace(old, new), tmp_path)
