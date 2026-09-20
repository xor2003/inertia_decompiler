"""Check generated environment-size reads against controlled guest memory.

The COD listing has an unresolved _psp relocation at DS:0. This harness binds
that slot explicitly; it does not claim execution equivalence to a linked DOS
environment or replace any generated function body.
"""

import shutil
import subprocess

from test_x86_16_cod_regressions import COD_DIR, _run_cod_proc

_HARNESS = r"""
uint8_t inertia_memory[0x100000];
uint16_t inertia_cs, inertia_ds, inertia_es, inertia_ss;
#ifdef INERTIA_COHERENT_GP_RUNTIME_H
inertia_gp_lane inertia_gp_eax, inertia_gp_ebx, inertia_gp_ecx, inertia_gp_edx;
inertia_gp_lane inertia_gp_esi, inertia_gp_edi, inertia_gp_esp, inertia_gp_ebp;
#endif
static void store_word(uint16_t segment, uint16_t offset, uint16_t value)
{
    inertia_memory[((uint32_t)segment << 4) + offset] = (uint8_t)value;
    inertia_memory[((uint32_t)segment << 4) + (uint16_t)(offset + 1)] = (uint8_t)(value >> 8);
}
int main(void)
{
    const uint16_t cases[][2] = {{0, 0x1234}, {1, 0xabcd}, {0x2345, 0}, {0xffff, 0xffff}};
    unsigned i;
    inertia_ds = 0x300;
    store_word(inertia_ds, 0, 0x500);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint16_t environment = cases[i][0];
        uint16_t mcb = (uint16_t)(environment - 1);
        uint16_t expected = cases[i][1];
        store_word(0x500, 0x2c, environment);
        store_word(environment, 3, (uint16_t)(expected ^ 0x5a5a));
        store_word(mcb, 3, expected);
        inertia_es = 0xeeee;
        if (_dos_envSize() != expected) return 1 + i;
        if (inertia_es != mcb) return 20 + i;
    }
    return 0;
}
"""


def test_cod_envsize_reads_environment_mcb_and_preserves_selector(tmp_path):
    compiler = shutil.which("gcc")
    assert compiler is not None, "generated-C behavioral gate requires gcc"
    result = _run_cod_proc(COD_DIR / "DOSFUNC.COD", "_dos_envSize", timeout=30)
    assert result.returncode == 0, result.stderr[-6000:]
    assert "validation=passed" in result.stderr
    assert "whole-tail validation clean" in result.stderr
    lost_load = "#include <stdint.h>\nunsigned short _dos_envSize(void) { return 44; }\n"
    for name, code, expected in (("generated", result.stdout, 0), ("lost_load", lost_load, 1)):
        source = tmp_path / f"{name}.c"
        binary = tmp_path / name
        source.write_text(code + _HARNESS, encoding="utf-8")
        compiled = subprocess.run([compiler, "-std=c11", "-O0", "-Wall", "-Wextra",
                                   "-Werror=implicit-function-declaration", "-Werror=return-type",
                                   "-Werror=int-conversion", str(source), "-o", str(binary)],
                                  capture_output=True, text=True, check=False, timeout=30)
        assert compiled.returncode == 0, compiled.stderr
        execution = subprocess.run([str(binary)], capture_output=True, text=True, check=False, timeout=10)
        assert execution.returncode == expected, execution.stderr
