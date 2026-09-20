"""Keep compiler-owned size types intact in both compatibility-header users."""

import subprocess

import pytest

from scripts import build_msc6_examples, compare_msc6_ssa_examples


@pytest.mark.parametrize("owner", [build_msc6_examples, compare_msc6_ssa_examples])
@pytest.mark.parametrize("standard_first", [False, True])
def test_headers_preserve_target_size_types(owner, standard_first, tmp_path):
    owner._ensure_msvc6_compat_headers(tmp_path)
    # Model the target's 16-bit types, not the host's 64-bit stddef types.
    (tmp_path / "stddef.h").write_text(
        "#ifndef TARGET_STDDEF_H\n#define TARGET_STDDEF_H\n"
        "typedef unsigned short size_t;\ntypedef short ptrdiff_t;\n#endif\n"
    )
    headers = ['#include <stddef.h>', '#include "STDINT.H"']
    if not standard_first:
        headers.reverse()
    source = "\n".join(headers) + "\nchar size_check[sizeof(size_t) == 2 ? 1 : -1];\n"
    source += "char diff_check[sizeof(ptrdiff_t) == 2 ? 1 : -1];\n"
    result = subprocess.run(
        ["gcc", "-std=c89", "-pedantic-errors", "-fsyntax-only", "-I", str(tmp_path), "-x", "c", "-"],
        input=source, capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, result.stderr
