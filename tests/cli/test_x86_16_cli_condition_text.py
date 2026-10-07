from __future__ import annotations

from inertia.cli.cli import _format_known_helper_calls, _simplify_x86_16_conditions
from inertia.cli.cli_c_text_postprocess import _normalize_unary_not_shift_precedence_text


def test_cli_condition_text_refuses_to_invert_flag_formula_from_rendered_c():
    c_text = (
        "short f(void)\n"
        "{\n"
        "    unsigned short flags;\n"
        "    if (!(!(flags & 64) & (flags & 128) == (flags & 0x800)))\n"
        "        return 1;\n"
        "    return 0;\n"
        "}\n"
    )

    assert _simplify_x86_16_conditions(c_text) == c_text.rstrip("\n")


def test_cli_condition_text_preserves_unary_not_shift_precedence():
    c_text = "short f(void)\n{\n    if (!clPause >> 16)\n        return 1;\n}\n"

    normalized = _normalize_unary_not_shift_precedence_text(c_text)

    assert "if (((clPause >> 16) == 0))" in normalized


def test_format_known_helper_calls_preserves_flag_formula_text_when_no_helper_rewrite_applies():
    c_text = (
        "short f(void)\n"
        "{\n"
        "    unsigned short flags;\n"
        "    if (!(!(flags & 64) & (flags & 128) == (flags & 0x800)))\n"
        "        return 1;\n"
        "    return 0;\n"
        "}\n"
    )

    project = type("P", (), {"_sim_procedures": {}, "_inertia_interrupt_wrappers": None})()
    function = type("F", (), {"addr": 0x1000, "name": "f", "project": project})()

    formatted = _format_known_helper_calls(
        project=project,
        function=function,
        c_text=c_text,
        api_style="cdecl",
        binary_path=None,
        cod_metadata=None,
    )

    assert "if (!(!(flags & 64) & (flags & 128) == (flags & 0x800)))" in formatted
