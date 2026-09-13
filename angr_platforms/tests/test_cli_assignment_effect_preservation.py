"""Text formatting cannot delete stores, even to hide invalid generated C."""

import pytest

from inertia_decompiler.cli_c_text_postprocess import _prune_non_lvalue_arithmetic_assignments


@pytest.mark.parametrize("statement", [
    "((unsigned char *)&total)[0] = total + ax;",
    "((unsigned char *)&total)[1] = (total + ax) >> 8;",
    "(*(words + offset)) = value;",
    "(records + offset)->field = value;",
    "a + b = function_with_effects();",
    "array[index] = value;",
    "total += value;",
])
def test_cli_preserves_assignment_effects_without_semantic_proof(statement):
    source = "void f(void)\n{\n    " + statement + "\n}\n"

    assert _prune_non_lvalue_arithmetic_assignments(source).splitlines() == source.splitlines()
