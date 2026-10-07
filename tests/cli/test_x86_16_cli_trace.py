from __future__ import annotations

from types import SimpleNamespace

from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable

from inertia.lowering.codegen_metadata import (
    GlobalDeclarationArrayExtent8616,
)
from inertia.cli.cli_c_ast_rewrites import _attach_cod_global_declaration_types
from inertia.cli.cli_decompilation import (
    _emit_c_stage_trace,
    _get_layer_dump_state,
    _materialize_codegen_global_externs_text_8616,
)


def test_emit_c_stage_trace_prints_labeled_snapshot(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=True)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "post-helper-call-format", "int demo(void)\n{\n    return 0;\n}\n")

    captured = capsys.readouterr()
    assert "/* -- c trace: 0x1234 demo :: post-helper-call-format -- */" in captured.err
    assert "int demo(void)" not in captured.err


def test_emit_c_stage_trace_stays_silent_when_disabled(capsys):
    project = SimpleNamespace(_inertia_trace_c_stages=False)
    function = SimpleNamespace(addr=0x1234, name="demo")

    _emit_c_stage_trace(project, function, "final-emitted-c", "int demo(void) { return 0; }\n")

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_emit_c_stage_trace_writes_layer_dump(tmp_path):
    manifest_root = tmp_path / "decompilation_layers"
    project = SimpleNamespace(
        _inertia_dump_layers=True,
        _inertia_dump_layer_root=manifest_root,
        _inertia_dump_layer_filter="",
    )
    function = SimpleNamespace(addr=0x1234, name="demo")
    state = _get_layer_dump_state(project, function)
    assert state is not None

    _emit_c_stage_trace(
        project,
        function,
        "post-structured-codegen",
        "int demo(void)\n{\n    return 0;\n}\n",
        layer_dump_state=state,
    )

    manifest_path = manifest_root / "0x1234_demo_01" / "manifest.jsonl"
    assert manifest_path.exists()
    assert manifest_path.read_text().count("\n") >= 1
    manifest_line = manifest_path.read_text().splitlines()[-1]
    assert '"layer": "post-structured-codegen"' in manifest_line
    assert (manifest_root / "0x1234_demo_01" / "0001_post-structured-codegen.c").exists()


def test_materialize_codegen_global_externs_inserts_used_scalar():
    codegen = SimpleNamespace(_inertia_global_declaration_specs_8616=(("unsigned short", "cRow", None),))
    c_text = "void ReInitBars()\\n{\\n    for (; cRow > iRow; iRow += 1) {\\n    }\\n}\\n"

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    assert "extern unsigned short cRow;" in updated
    assert updated.index("extern unsigned short cRow;") < updated.index("void ReInitBars()")


def test_materialize_codegen_global_externs_preserves_unknown_array_extent():
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            (
                "unsigned char",
                "_S101_g_table",
                GlobalDeclarationArrayExtent8616.UNKNOWN,
            ),
        )
    )
    c_text = (
        "short sum(void)\n"
        "{\n"
        "    short total;\n"
        "    total = total + _S101_g_table[i];\n"
        "    return total;\n"
        "}\n"
    )

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    assert "extern unsigned char _S101_g_table[];" in updated


def test_materialize_codegen_global_externs_ignores_struct_member_name_specs():
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            ("unsigned short", "field_0", None),
            ("struct { unsigned char field_0; unsigned char field_1; }", "abarWork", 1),
        )
    )
    c_text = (
        "short BubbleSort(void)\\n"
        "{\\n"
        "    if (abarWork[1].field_0 < abarWork[0].field_0) {\\n"
        "        return 1;\\n"
        "    }\\n"
        "    return 0;\\n"
        "}\\n"
    )

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    assert "extern unsigned short field_0;" not in updated
    assert "extern struct { unsigned char field_0; unsigned char field_1; } abarWork[1];" in updated


def test_materialize_codegen_global_externs_ignores_prototype_type_and_parameter_names():
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            ("unsigned short", "abarWork_entry", None),
            ("unsigned short", "a0", None),
            ("unsigned short", "a1", None),
        )
    )
    c_text = (
        "int Swaps(struct abarWork_entry *a0, struct abarWork_entry *a1);\n\n"
        "void BubbleSort(void)\n"
        "{\n"
        "    return;\n"
        "}\n"
    )

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    assert updated == c_text


def test_materialize_codegen_global_externs_orders_struct_definition_before_dependent_prototype():
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            ("struct abarWork_entry { unsigned char field_0; unsigned char field_1; }", "abarWork", 1),
        )
    )
    c_text = (
        "int Swaps(struct abarWork_entry *a0, struct abarWork_entry *a1);\n\n"
        "void BubbleSort(void)\n"
        "{\n"
        "    Swaps(&abarWork[0], &abarWork[1]);\n"
        "}\n"
    )

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    struct_decl = (
        "extern struct abarWork_entry { unsigned char field_0; unsigned char field_1; } abarWork[1];"
    )
    assert updated.index(struct_decl) < updated.index("int Swaps(")


def test_materialize_codegen_global_externs_is_idempotent_for_named_types():
    regs_definition = "typedef union REGS { unsigned short ax; } REGS;"
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(("REGS", "rin", None),),
        _inertia_named_type_definitions_8616=(regs_definition,),
    )
    c_text = "void call_dos(void)\n{\n    rin.ax = 1;\n}\n"

    first = _materialize_codegen_global_externs_text_8616(c_text, codegen)
    second = _materialize_codegen_global_externs_text_8616(first, codegen)

    assert second == first
    assert second.count(regs_definition) == 1
    assert "extern REGS rin;" in second


def test_materialize_codegen_global_extern_follows_existing_named_type_definition():
    entry_definition = (
        "typedef struct g_08F0_entry {\n"
        "    char field_0;\n"
        "    char field_1;\n"
        "} g_08F0_entry;"
    )
    codegen = SimpleNamespace(
        _inertia_global_declaration_specs_8616=(
            ("g_08F0_entry", "g_0B4C", GlobalDeclarationArrayExtent8616.UNKNOWN),
        ),
        _inertia_named_type_definitions_8616=(entry_definition,),
    )
    c_text = (
        "void helper(void);\n\n"
        f"{entry_definition}\n\n"
        "void sort(void)\n{\n    g_0B4C[0].field_0 = 1;\n}\n"
    )

    updated = _materialize_codegen_global_externs_text_8616(c_text, codegen)

    extern = "extern g_08F0_entry g_0B4C[];"
    assert updated.index(entry_definition) < updated.index(extern) < updated.index("void sort(void)")


def test_cli_cod_global_typer_refuses_name_based_aggregate_recovery():
    variable = SimMemoryVariable(0x7000, 14)
    cvariable = SimpleNamespace(variable_type=None, unified_variable=None)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={variable: cvariable},
            unified_local_vars={},
        ),
        cexterns=(),
    )

    changed = _attach_cod_global_declaration_types(
        codegen,
        {0x7000: ("$S424_rin", 14)},
    )

    assert changed is True
    assert variable.size == 2
    assert isinstance(cvariable.variable_type, SimTypeShort)
    assert variable.name != "rin"


def test_dump_layer_state_uses_next_attempt_when_present(tmp_path):
    project = SimpleNamespace(
        _inertia_dump_layers=True,
        _inertia_dump_layer_root=tmp_path,
        _inertia_dump_layer_filter="",
    )
    function = SimpleNamespace(addr=0x1234, name="demo")

    first_state = _get_layer_dump_state(project, function)
    second_state = _get_layer_dump_state(project, function)

    assert first_state is not None
    assert second_state is not None
    assert first_state["root"] != second_state["root"]
