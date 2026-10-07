"""Execute the native near-pointer offset representation in the default DOS lane.

Layer: Tests.
Responsibility: check modular offset/null behavior using MS C 6 and KVM without
adding a native DOS execution dependency to the fast unit lane.
"""

import pytest
from inertia.lowering.c_runtime_header import render_c_runtime_header_8616

import tools.compiler_toolchain.build_msc6_examples as build


@pytest.mark.requires_kvm
@pytest.mark.skipif(
    not build.DEFAULT_KVIKDOS.is_file() or not build.DEFAULT_MSC6_ROOT.is_dir(),
    reason="external DOS runtime gate requires kvikdos and MS C 6",
)
def test_msc6_near_byte_runtime_preserves_encoded_offsets(tmp_path):
    """Check the native 16-bit representation, including wrap and null, in DOS."""
    source = tmp_path / "NEARBYTE.C"
    source.write_text(render_c_runtime_header_8616("msc-dos") + r"""
static unsigned int evaluations;
static uint32_t input_offset;
static uint32_t next_offset(void) { ++evaluations; return input_offset; }
int main(void) {
    static const uint16_t cases[][2] = {
        {17, 6}, {0xfffe, 2}, {0xffff, 3}, {0x1234, 0xfffe}, {0, 0}, {0, 7}
    };
    unsigned int i;
    struct SREGS segments;
    segread(&segments);
    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        uint16_t original = cases[i][0], delta = cases[i][1];
        uint16_t expected = (uint16_t)(original + delta);
        void near *base = (void near *)original;
        void near *result = NEAR_BYTE_ADD(segments.ds, segments.ds, base, delta);
        if (NEAR_OFFSET(segments.ds, result) != expected) return 1;
        if (!expected && result != (void near *)0) return 2;
    }
    for (i = 0; i < 3; ++i) {
        void near *result;
        input_offset = i == 0 ? 0UL : (i == 1 ? 2UL : 65536UL);
        evaluations = 0;
        result = NEAR_ARG_PTR(segments.ds, next_offset());
        if (evaluations != 1) return 3;
        if (NEAR_OFFSET(segments.ds, result) != (uint16_t)input_offset) return 4;
        if (!(uint16_t)input_offset && result != (void near *)0) return 5;
    }
    return 0;
}
""")
    built, *diagnostics = build._compile_and_link(
        source, tmp_path, kvikdos=build.DEFAULT_KVIKDOS, msc6_root=build.DEFAULT_MSC6_ROOT,
        obj_name="NEARBYTE.OBJ", exe_name="NEARBYTE.EXE", map_name="NEARBYTE.MAP",
    )
    assert built, "\n".join(diagnostics)
    passed, exit_code, stdout, stderr = build._run_example(
        tmp_path / "NEARBYTE.EXE", tmp_path, kvikdos=build.DEFAULT_KVIKDOS,
    )
    assert passed and exit_code == 0, (exit_code, stdout, stderr)
