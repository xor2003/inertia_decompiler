from __future__ import annotations

from inertia.cli.cli_c_text_postprocess import _normalize_function_signature_arg_names


def test_signature_arg_normalization_does_not_rewrite_return_call_literals() -> None:
    source = """unsigned short f(void)
{
    return sub_104f(0x7000, a & 255, b & 255);
}
"""

    assert _normalize_function_signature_arg_names(source) == source


def test_signature_arg_normalization_still_deduplicates_identifier_parameters() -> None:
    source = "unsigned short f(unsigned short value, unsigned short value);\n"

    assert _normalize_function_signature_arg_names(source) == (
        "unsigned short f(unsigned short value, unsigned short value_2);\n"
    )
