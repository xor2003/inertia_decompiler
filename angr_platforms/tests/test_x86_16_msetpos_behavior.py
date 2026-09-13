"""Source-independent blob recovery must preserve both signed input values."""

import subprocess

from test_x86_16_cod_samples import _F14_COD_DIR, _decompile_blob, _extract_cod_function, _join_entries


def test_msetpos_generated_c_compiles_and_preserves_signed_arguments(tmp_path):
    entries = _extract_cod_function("MONOPRIN.COD", "_mset_pos", cod_dir=_F14_COD_DIR)
    recovered = _decompile_blob(_join_entries(entries))
    source = """
#include <stdint.h>
uint32_t inertia_eax;
uint16_t inertia_ds;
uint16_t memory[4];
#define SEG_U16(segment, offset) memory[(offset) / 2]
#define _start recovered_msetpos
""" + recovered + """
#undef _start
int main(void) {
    uint32_t bits;
    if (recovered_msetpos((uint16_t)-81, (uint16_t)-26) != 0) return 1;
    if (memory[1] != (uint16_t)-1 || memory[2] != (uint16_t)-1) return 2;
    if (recovered_msetpos(161, 52) != 0) return 3;
    if (memory[1] != 1 || memory[2] != 2) return 4;
    for (bits = 0; bits <= UINT16_MAX; ++bits) {
        int32_t signed_value = bits < 32768 ? (int32_t)bits : (int32_t)bits - 65536;
        if (recovered_msetpos((uint16_t)bits, (uint16_t)bits) != 0) return 5;
        if (memory[1] != (uint16_t)(signed_value % 80)) return 6;
        if (memory[2] != (uint16_t)(signed_value % 25)) return 7;
    }
    return 0;
}
"""
    executable = tmp_path / "msetpos"
    compiled = subprocess.run(
        ["gcc", "-x", "c", "-std=c11", "-pedantic-errors", "-o", str(executable), "-"],
        input=source, capture_output=True, text=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + "\n" + recovered
    assert subprocess.run([str(executable)], check=False).returncode == 0
