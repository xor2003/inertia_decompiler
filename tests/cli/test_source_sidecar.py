from __future__ import annotations

from pathlib import Path

import inertia.cli.cli as cli
from inertia.cli.cli_arg_parser import _build_cli_argument_parser
from inertia.cli.source_sidecar import (
    collect_local_source_sidecar_return_types,
    render_local_source_sidecar_function,
)


def test_render_local_source_sidecar_function_extracts_knr_body(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source = tmp_path / "sample.c"
    source.write_text("helper()\n{\n    return(1);\n}\n\npause_screen()\n{\n    return(0);\n}\n")

    rendered = render_local_source_sidecar_function(binary, "pause_screen")

    assert rendered is not None
    assert "pause_screen()" in rendered
    assert "return(0);" in rendered


def test_render_local_source_sidecar_function_uses_matching_stem_only(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    (tmp_path / "other.c").write_text("pause_screen(){return(1);}\n")

    rendered = render_local_source_sidecar_function(binary, "pause_screen")

    assert rendered is None


def test_render_local_source_sidecar_function_extracts_knr_with_arg_decls(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source = tmp_path / "sample.c"
    source.write_text("draw_box(attr)\nint attr;\n{\n    return;\n}\n")

    rendered = render_local_source_sidecar_function(binary, "draw_box")

    assert rendered is not None
    assert "draw_box(attr)" in rendered
    assert "int attr;" in rendered
    assert not rendered.startswith("\n")


def test_collect_local_source_sidecar_return_types_extracts_void_definitions(tmp_path: Path) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    source = tmp_path / "sample.c"
    source.write_text(
        "typedef struct BAR BAR;\n"
        "\n"
        "void Swaps( BAR *bar1, BAR *bar2 )\n"
        "{\n"
        "    return;\n"
        "}\n"
        "\n"
        "int value(void)\n"
        "{\n"
        "    return 1;\n"
        "}\n"
    )

    return_types = collect_local_source_sidecar_return_types(binary)

    assert return_types["Swaps"] == "void"
    assert return_types["value"] == "int"


def test_emit_optional_source_sidecar_c_block_emits_only_decompiled_c_when_alternate_enabled(
    tmp_path: Path, capsys
) -> None:
    cli._emit_optional_source_sidecar_c_block(
        tmp_path / "sample.exe",
        "source",
        "int decompiled(void) { return 0; }\n",
        alternate_source_c=True,
        c_header="/* -- c -- */",
    )

    out = capsys.readouterr().out
    assert "/* -- source c -- */" not in out
    assert out.count("/* -- c -- */") == 1
    assert "int decompiled(void) { return 0; }" in out


def test_emit_optional_source_sidecar_c_block_emits_only_decompiled_c_when_alternate_disabled(
    tmp_path: Path, capsys
) -> None:
    cli._emit_optional_source_sidecar_c_block(
        tmp_path / "sample.exe",
        "source",
        "int decompiled(void) { return 0; }\n",
        alternate_source_c=False,
        c_header="/* -- c -- */",
    )

    out = capsys.readouterr().out
    assert "/* -- source c -- */" not in out
    assert out.count("/* -- c -- */") == 1
    assert "int decompiled(void) { return 0; }" in out


def test_cli_prints_source_sidecar_by_default() -> None:
    parser = _build_cli_argument_parser()

    args = parser.parse_args(["sample.exe"])
    disabled_args = parser.parse_args(["--no-alternate-source-c", "sample.exe"])

    assert args.alternate_source_c is True
    assert disabled_args.alternate_source_c is False
