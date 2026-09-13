"""The real MS C rebuild harness must reject byte-store re-evaluation."""

import shutil
import subprocess

import pytest

from scripts.build_msc6_examples import STORAGE_CLASSES_HARNESS_MAIN, STORAGE_CLASSES_PREFIX


@pytest.mark.parametrize("corrupted,expected", [(False, 255), (True, 4)])
def test_storage_harness_rejects_split_store_re_evaluation(tmp_path, corrupted, expected):
    compiler = shutil.which("gcc")
    assert compiler is not None, "GCC is required for the mandatory generated-C runtime oracle"
    update = ("((unsigned char *)&total)[0] = total + g_table[i];\n"
              "((unsigned char *)&total)[1] = (total + g_table[i]) >> 8;"
              if corrupted else "total += g_table[i];")
    functions = """
unsigned short _sum_globals(void) {
    int i;
    unsigned short total = g_counter;
    for (i = 0; i < 4; ++i) {
        UPDATE
    }
    return total;
}
unsigned short bump_static(void) { seen += 2; return seen; }
""".replace("UPDATE", update)
    source = tmp_path / "oracle.c"
    executable = tmp_path / "oracle"
    source.write_text(STORAGE_CLASSES_PREFIX + functions + STORAGE_CLASSES_HARNESS_MAIN)
    compilation = subprocess.run(
        [compiler, "-std=c89", "-Wall", "-Wextra", "-Werror", "-O2", str(source), "-o", str(executable)],
        capture_output=True, text=True, check=False,
    )
    assert compilation.returncode == 0, compilation.stderr
    result = subprocess.run([str(executable)], capture_output=True, text=True, check=False)
    assert result.returncode == expected
