"""Execute the ChangeWeather COD fixture's word writes and state transitions.

Layer: Tests.
Responsibility: check compiled output against NHORZ.COD source and instructions.
This tests a normalized object fixture, not a linked NHORZ program.
"""

import subprocess
from pathlib import Path

import pytest

_HARNESS = r"""
unsigned short CLOUDHEIGHT, CLOUDTHICK, BadWeather;
int main(void) {
    for (unsigned state = 0; state <= 65535; ++state) {
        BadWeather = (unsigned short)state;
        for (unsigned repeat = 0; repeat < 3; ++repeat) {
            unsigned expected_bad = BadWeather == 0;
            unsigned expected_height = expected_bad ? 125 : 8150;
            unsigned expected_thick = expected_bad ? 1000 : 500;
            CLOUDHEIGHT = 0xaaaa;
            CLOUDTHICK = 0x5555;
            _ChangeWeather();
            if (BadWeather != expected_bad) return 1;
            if (CLOUDHEIGHT != expected_height) return 2;
            if (CLOUDTHICK != expected_thick) return 3;
        }
    }
    return 0;
}
"""

_REFERENCE = r"""
extern unsigned short CLOUDHEIGHT, CLOUDTHICK, BadWeather;
void _ChangeWeather(void) {
    if (BadWeather) {
        CLOUDHEIGHT = 8150;
        CLOUDTHICK = 500;
        BadWeather = 0;
    } else {
        CLOUDHEIGHT = 125;
        CLOUDTHICK = 1000;
        BadWeather = 1;
    }
}
"""


def assert_changeweather_behavior(generated_c: str, directory: Path) -> None:
    """Check every word state and repeated transitions using unchanged C."""
    source = directory / "changeweather.c"
    executable = directory / "changeweather"
    source.write_text(generated_c + _HARNESS, encoding="ascii")
    compiled = subprocess.run(
        ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
         "-fsanitize=undefined", "-fno-sanitize-recover=undefined",
         str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert compiled.returncode == 0, compiled.stderr
    executed = subprocess.run([str(executable)], capture_output=True, text=True, check=False, timeout=3)
    assert executed.returncode == 0, f"ChangeWeather behavior mismatch: exit={executed.returncode} {executed.stderr}"


def test_changeweather_oracle_accepts_source_behavior(tmp_path: Path) -> None:
    assert_changeweather_behavior(_REFERENCE, tmp_path)


@pytest.mark.parametrize(("original", "replacement"), [
    ("if (BadWeather)", "if (BadWeather == 1)"),
    ("if (BadWeather)", "if (BadWeather & 0xff)"),
    ("CLOUDHEIGHT = 8150;", "CLOUDHEIGHT = 125;"),
    ("CLOUDTHICK = 1000;", "CLOUDTHICK = 500;"),
    ("BadWeather = 0;", ""),
    ("BadWeather = 1;", ""),
])
def test_changeweather_oracle_rejects_corruption(tmp_path: Path, original: str, replacement: str) -> None:
    with pytest.raises(AssertionError, match="ChangeWeather behavior mismatch"):
        assert_changeweather_behavior(_REFERENCE.replace(original, replacement), tmp_path)
