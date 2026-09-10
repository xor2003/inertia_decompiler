"""Execute rendered carry predicates with cosmetic casts disabled."""

import shutil
import subprocess
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.c_ast_utils import _iter_c_nodes_deep_8616
from angr_platforms.X86_16.lowering.carry_borrow_bit_predicate import (
    _canonical_addition_carry_predicate_8616,
)


def test_rendered_word_carry_preserves_overflow_with_hidden_casts(tmp_path):
    """C integer promotion must not erase the machine's low-word truncation."""
    compiler = shutil.which("gcc")
    assert compiler is not None, "gcc is required for generated-C execution"
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=Arch86_16()),
        next_idx=lambda _name: 1,
        next_node_idx=lambda: 1,
        next_ident=lambda name: name,
        show_casts=False,
        display_vvar_ids=False,
        cstyle_null_cmp=False,
        const_formats={},
    )
    operands = [
        c.CVariable(
            SimRegisterVariable(offset, 2, name=name),
            variable_type=SimTypeShort(False),
            codegen=codegen,
        )
        for offset, name in ((0, "lhs"), (2, "rhs"))
    ]
    addition = c.CBinaryOp("Add", *operands, codegen=codegen)
    predicate = _canonical_addition_carry_predicate_8616(addition, ())
    assert not any(isinstance(node, c.CBinaryOp) and node.op == "Add" for node in _iter_c_nodes_deep_8616(predicate))
    rendered = "".join(text for text, _node in predicate.c_repr_chunks())
    program = f"""int main(void) {{
    const unsigned short values[] = {{0, 1, 2, 32767, 32768, 65534, 65535}};
    for (unsigned int i = 0; i < 65536; ++i) {{
        for (unsigned int j = 0; j < sizeof(values)/sizeof(values[0]); ++j) {{
            unsigned short lhs = (unsigned short)i, rhs = values[j];
            unsigned int expected = ((unsigned int)lhs + rhs) > 65535;
            if ((unsigned int)({rendered}) != expected) return 1;
        }}
    }}
    return 0;
}}
"""
    executable = tmp_path / "word-carry"
    compiled = subprocess.run(
        [compiler, "-std=c99", "-Wall", "-Werror", "-O2", "-x", "c", "-", "-o", str(executable)],
        input=program, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr + program
    assert subprocess.run([str(executable)], check=False).returncode == 0, program
