"""Keep the recovered signed-wide bounds function in the non-skipping lane."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pycparser import c_ast, c_parser
from test_x86_16_cli import REPO_ROOT, _run_decompile_proc
from test_x86_16_wide_condition_provenance import assert_inbox_behavior

# Operand spellings that stay signed and at least 32 bits wide on both the GCC
# host oracle and the MS C DOS target. Narrower or unsigned casts would change
# the boundary comparisons, so the structure check refuses them explicitly.
_SIGNED_WIDE_TYPE_NAMES_8616 = frozenset(
    {
        ("int32_t",),
        ("int64_t",),
        ("long",),
        ("signed", "long"),
        ("long", "int"),
        ("signed", "long", "int"),
        ("long", "long"),
        ("signed", "long", "long"),
    }
)

# The emitted slice has no #include context; give pycparser typedefs for the
# spelled names so casts parse while the original spellings stay inspectable.
_PARSE_PRELUDE_8616 = (
    "typedef long int32_t; typedef unsigned long uint32_t;"
    "typedef short int16_t; typedef unsigned short uint16_t;"
    "typedef signed char int8_t; typedef unsigned char uint8_t;"
    "typedef long int64_t; typedef unsigned long uint64_t;"
    "typedef unsigned long size_t; typedef unsigned long uintptr_t;"
    "typedef long intptr_t; typedef long ptrdiff_t;"
)


def _emitted_function_8616(output: str, name: str) -> str:
    """Slice one emitted function definition out of the CLI's C section."""
    emitted = output.split("/* == c == */", 1)[-1]
    match = re.search(rf"(?m)^[^\n;(){{}}]*\b{re.escape(name)}\s*\([^;\n]*\)\s*\{{", emitted)
    assert match is not None, output
    end = emitted.find("\n}", match.end())
    assert end >= 0, output
    return emitted[match.start() : end + 2]


def _type_name_tuple_8616(node: c_ast.Node) -> tuple[str, ...]:
    """Project one declarator or typename node to its flat type-name tuple."""
    while isinstance(node, c_ast.TypeDecl):
        node = node.type
    return tuple(node.names) if isinstance(node, c_ast.IdentifierType) else ()


def _or_operands_8616(node: c_ast.Node) -> list[c_ast.Node]:
    """Flatten one left-associative ``||`` chain into its ordered leaves."""
    if isinstance(node, c_ast.BinaryOp) and node.op == "||":
        return _or_operands_8616(node.left) + _or_operands_8616(node.right)
    return [node]


def _operand_param_index_8616(node: c_ast.Node, positions: dict[str, int]) -> int:
    """Bind one comparison operand to its parameter slot through signed casts."""
    while isinstance(node, c_ast.Cast):
        names = _type_name_tuple_8616(node.to_type.type)
        assert names in _SIGNED_WIDE_TYPE_NAMES_8616, f"unsigned or narrowing operand cast {names}"
        node = node.expr
    assert isinstance(node, c_ast.ID) and node.name in positions, "comparison operand is not a declared parameter"
    return positions[node.name]


def _return_constant_8616(node: c_ast.Return) -> int | None:
    """Return one literal return value, or None for non-literal expressions."""
    if isinstance(node.expr, c_ast.Constant):
        try:
            return int(node.expr.value, 0)
        except ValueError:
            return None
    return None


def assert_inbox_wide_condition_8616(generated_c: str) -> None:
    """Check _InBoxLng's guard by positional parameter binding, not names.

    Recovered argument identifiers are incidental; the contract is that six
    signed-wide parameters take part in four ordered signed comparisons
    (param0 < param2, param0 > param4, param1 < param3, param1 > param5)
    joined by ``||``, returning 0 out-of-box and 1 in-box.
    """
    tree = c_parser.CParser().parse(_PARSE_PRELUDE_8616 + _emitted_function_8616(generated_c, "_InBoxLng"))
    funcdef = next(node for node in tree.ext if isinstance(node, c_ast.FuncDef))
    params = funcdef.decl.type.args.params
    assert len(params) == 6
    assert all(isinstance(param, c_ast.Decl) and param.name for param in params)
    for param in params:
        assert _type_name_tuple_8616(param.type) in _SIGNED_WIDE_TYPE_NAMES_8616
    positions = {param.name: index for index, param in enumerate(params)}

    statements = funcdef.body.block_items
    branch = next((item for item in statements if isinstance(item, c_ast.If)), None)
    assert branch is not None, generated_c
    operands = _or_operands_8616(branch.cond)
    assert all(isinstance(operand, c_ast.BinaryOp) for operand in operands)
    assert [operand.op for operand in operands] == ["<", ">", "<", ">"]
    for operand, (lhs_index, rhs_index) in zip(operands, [(0, 2), (0, 4), (1, 3), (1, 5)], strict=True):
        assert _operand_param_index_8616(operand.left, positions) == lhs_index
        assert _operand_param_index_8616(operand.right, positions) == rhs_index

    then_items = branch.iftrue.block_items if isinstance(branch.iftrue, c_ast.Compound) else [branch.iftrue]
    then_values = [_return_constant_8616(item) for item in then_items if isinstance(item, c_ast.Return)]
    assert 0 in then_values, "out-of-box guard must return 0"
    tail_values = [
        _return_constant_8616(item)
        for item in statements[statements.index(branch) + 1 :]
        if isinstance(item, c_ast.Return)
    ]
    assert tail_values == [1], "in-box fall-through must return 1"


def _inbox_oracle_reference_c_8616(names: tuple[str, ...], cast: str) -> str:
    """Build small oracle controls with independently selected argument names."""
    x, z, xl, zl, xh, zh = names
    parameters = ", ".join(f"long {name}" for name in names)
    prefix = f"({cast})" if cast else ""
    return (
        f"unsigned short _InBoxLng({parameters})\n{{\n"
        f"    if ({prefix}{x} < {prefix}{xl} || {prefix}{x} > {prefix}{xh} || "
        f"{prefix}{z} < {prefix}{zl} || {prefix}{z} > {prefix}{zh})\n"
        "        return 0;\n    return 1;\n}\n"
    )


@pytest.mark.parametrize(
    ("names", "cast"),
    [
        (("arg_4", "arg_8", "arg_c", "arg_10", "arg_14", "arg_18"), "int32_t"),
        (("x", "z", "xl", "zl", "xh", "zh"), "int32_t"),
        (("a", "b", "c", "d", "e", "f"), "long"),
        (("a", "b", "c", "d", "e", "f"), ""),
    ],
)
def test_inbox_condition_oracle_accepts_incidental_names(
    names: tuple[str, ...],
    cast: str,
) -> None:
    """Keep positional comparisons independent of recovered/debug identifiers."""
    assert_inbox_wide_condition_8616(_inbox_oracle_reference_c_8616(names, cast))


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("(int32_t)x <", "(short)x <"),
        ("(int32_t)x <", "(uint32_t)x <"),
        ("(int32_t)x <", "(int)x <"),
        ("(int32_t)x < (int32_t)xl", "(int32_t)xl < (int32_t)x"),
        ("(int32_t)x < (int32_t)xl", "(int32_t)x <= (int32_t)xl"),
        ("(int32_t)z > (int32_t)zh", "(int32_t)z > (int32_t)(short)(zh >> 16)"),
        ("return 0;\n    return 1;", "return 1;\n    return 0;"),
        ("(int32_t)xl", "(int32_t)local_2"),
        (" || (int32_t)z > (int32_t)zh", ""),
        ("long x,", "short x,"),
        (" || ", " && "),
    ],
)
def test_inbox_condition_oracle_rejects_semantic_corruption(
    original: str,
    replacement: str,
) -> None:
    """Narrowing, unsignedness, wrong slots/branches and returns cannot pass."""
    source = _inbox_oracle_reference_c_8616(("x", "z", "xl", "zl", "xh", "zh"), "int32_t")
    assert original in source, "the deliberate corruption must actually apply"
    with pytest.raises(AssertionError):
        assert_inbox_wide_condition_8616(source.replace(original, replacement))


@pytest.mark.requires_kvm
def test_inbox_long_passes_validation_and_compiled_behavior(tmp_path: Path) -> None:
    """Require live tail equivalence, compiled behavior and signed-wide guards."""
    path = REPO_ROOT / "cod" / "f14" / "CARR.COD"
    assert path.exists(), "Required InBoxLng regression fixture is missing"
    result = _run_decompile_proc(
        path,
        "_InBoxLng",
        proc_kind="NEAR",
        analysis_timeout=10,
        subprocess_timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "validation=passed" in result.stderr
    assert_inbox_behavior(result.stdout, tmp_path)
    assert_inbox_wide_condition_8616(result.stdout)
    for token in ("function: 0x1000 _InBoxLng", "return 0;", "return 1;"):
        assert token in result.stdout, result.stdout
    for token in ("if (...)", "!(v4", "& &"):
        assert token not in result.stdout, result.stdout
