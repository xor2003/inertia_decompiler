from __future__ import annotations

from types import SimpleNamespace

from inertia.cli.cod_comment_emitter import format_cod_comment_block
from inertia.frontend.x86_16.cod_extract import CODProcMetadata
import inertia.cli.cli as cli


def test_annotate_cod_proc_output_keeps_cod_metadata_inert() -> None:
    metadata = CODProcMetadata(
        stack_aliases={4: "arg0", -2: "local0"},
        call_names=("DosBeep",),
        call_sources=(("DosBeep", "defined( OS2 )"),),
        global_names=("abarWork",),
        source_lines=("return speaker (with bits 0 and 1);",),
        source_line_set=frozenset({"return speaker (with bits 0 and 1);"}),
    )
    c_text = "short Beep(unsigned short a0)\n{\n    CallReturn();\n    DosBeep();\n    return ax;\n}\n"
    rendered = cli._annotate_cod_proc_output(c_text, SimpleNamespace(name="Beep"), metadata)
    assert rendered == c_text
    assert "defined( OS2 )" not in rendered
    assert "speaker (with bits 0 and 1)" not in rendered
    assert "DosBeep();" in rendered
    assert "[bp+0x4] = arg0" not in rendered


def test_format_cod_comment_block_escapes_trailing_macro_backslash_for_c_comments() -> None:
    rendered = format_cod_comment_block(
        func_name="main",
        proc_kind="NEAR",
        cod_path="SORTDEMO.COD",
        source_lines=(
            "#define _outtextxy( ach, x, y )   { _settextposition( y, x ); \\",
            "_outtext( ach ); }",
        ),
    )

    assert "<backslash>" in rendered
