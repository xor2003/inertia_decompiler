from __future__ import annotations

from types import SimpleNamespace

import pytest
from angr.sim_type import SimTypeChar, SimTypeFunction, SimTypeShort

from inertia_decompiler.cli_c_text_postprocess import (
    _align_function_header_with_cod_source_decl_text,
    _align_unknown_call_names_from_cod_evidence_text,
    _annotate_cod_proc_output,
    _coalesce_redundant_split_global_incdec_text,
    _collapse_annotated_stack_aliases_text,
    _dedupe_duplicate_local_declarations_text,
    _materialize_annotated_cod_declarations_text,
    _materialize_missing_direct_call_prototypes_text,
    _materialize_missing_generic_local_declarations_text,
    _materialize_missing_synthetic_global_declarations_text,
    _normalize_boolean_conditions,
    _normalize_function_signature_arg_names,
    _normalize_integer_dereference_stores_text,
    _normalize_msc_signed_int_function_signature_text,
    _normalize_portable_flat_main_signature_text,
    _normalize_signed_char_function_signature_text,
    _prune_invalid_simple_function_prototypes_text,
    _prune_non_lvalue_arithmetic_assignments,
    _prune_parameter_shadow_declarations_text,
    _prune_standalone_memory_helper_reads_text,
    _prune_standalone_stack_probe_calls_text,
    _prune_trailing_generic_return_text,
    _prune_undefined_fragment_carrier_assignments_text,
    _prune_unused_local_declarations_text,
    _prune_unused_staging_assignments,
    _prune_void_call_assignments_text,
    _prune_void_function_return_values_text,
    _prune_weaker_conflicting_prototypes_text,
    _repair_missing_fallthrough_returns,
    _rewrite_known_helper_signature_text,
    _source_function_prototype_decls_from_cod_source_lines,
    _source_header_args_unmaterialized_8616,
)


def test_normalize_function_signature_arg_names_preserves_storage_local_arg_names():
    c_text = """\
unsigned short classify(short local_4)
{
    if (local_4 < 0)
        return -1;
    return 0;
}
"""

    assert _normalize_function_signature_arg_names(c_text) == c_text


def test_normalize_signed_char_function_signature_uses_typed_prototype():
    c_text = """\
char add_sc(char a, char b)
{
    return b + a;
}
"""
    prototype = SimTypeFunction([SimTypeChar(True), SimTypeChar(True)], SimTypeChar(True))
    codegen = SimpleNamespace(cfunc=SimpleNamespace(functy=prototype))
    function = SimpleNamespace(name="add_sc")

    rewritten = _normalize_signed_char_function_signature_text(c_text, function, codegen)

    assert "signed char add_sc(signed char a, signed char b)" in rewritten


def test_normalize_msc_signed_int_function_signature_requires_typed_return_evidence():
    c_text = """\
short switch_fold(short x)
{
    return x - 5;
}
"""
    prototype = SimTypeFunction([SimTypeShort(True)], SimTypeShort(True))
    function = SimpleNamespace(name="switch_fold")
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(functy=prototype),
        _inertia_typed_condition_signed_stack_arg_changed_fields_8616=("prototype_return",),
    )

    rewritten = _normalize_msc_signed_int_function_signature_text(c_text, function, codegen)

    assert "int switch_fold(int x)" in rewritten
    codegen._inertia_typed_condition_signed_stack_arg_changed_fields_8616 = ()
    assert _normalize_msc_signed_int_function_signature_text(c_text, function, codegen) == c_text


def test_normalize_function_signature_arg_names_renames_storage_local_arg_on_body_collision():
    c_text = """\
unsigned short select_and_apply(unsigned short local, unsigned long *local_2)
{
    unsigned short (*local_2)(unsigned short);
    return apply_twice(local_2, local);
}
"""

    rewritten = _normalize_function_signature_arg_names(c_text)

    assert "select_and_apply(unsigned short local, unsigned long *local_2_2)" in rewritten
    assert "unsigned short (*local_2)(unsigned short);" in rewritten


def test_dedupe_duplicate_local_declarations_prefers_function_pointer_decl():
    c_text = """\
int select_and_apply(int which, int value)
{
    unsigned short local_2;
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return apply_twice(local_2, value);
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert "unsigned short local_2;\n" not in rewritten
    assert "unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn" in rewritten


def test_repair_missing_fallthrough_returns_replaces_terminal_vvar_with_ax():
    c_text = """\
short InitMenu(void)
{
    unsigned short ax;  // ax
    unsigned short vvar_21;
    ax = local_2;
    return vvar_21;
}
"""

    rewritten = _repair_missing_fallthrough_returns(c_text)

    assert "return vvar_21;" not in rewritten
    assert rewritten.count("return ax;") == 1


def test_repair_missing_fallthrough_returns_keeps_terminal_call_return():
    c_text = """\
unsigned short main(void)
{
    unsigned short ax;  // ax
    ax = 7;
    return helper(ax);
}
"""

    rewritten = _repair_missing_fallthrough_returns(c_text)

    assert rewritten == c_text
    assert "return ax;" not in rewritten


def test_prune_trailing_generic_return_removes_unreachable_vvar_before_ax_return():
    c_text = """\
short InitMenu(void)
{
    return vvar_21;

    return ax;
}
"""

    rewritten = _prune_trailing_generic_return_text(c_text)

    assert "return vvar_21;" not in rewritten
    assert rewritten.count("return ax;") == 1


def test_prune_trailing_generic_return_keeps_distinct_fallthrough_return() -> None:
    c_text = """\
unsigned short choose_value(void)
{
    unsigned short v5;
    unsigned short v10;
    if (condition)
        return v10;
    return v5;
}
"""

    assert _prune_trailing_generic_return_text(c_text) == c_text


def test_prune_unused_staging_assignments_keeps_value_used_by_return() -> None:
    c_text = """\
unsigned short preserve_low_byte(void)
{
    unsigned short v10;
    v10 = source & 0xff00;
    return v10;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "v10 = source & 0xff00;" in rewritten
    assert "return v10;" in rewritten


def test_cod_annotation_keeps_stack_alias_source_rewrites_inert():
    c_text = """\
void *memset(void *dst, int ch, unsigned long count);
int outtext(const char *text);

unsigned short DrawBar(unsigned int arg_4)
{
    unsigned int achT;  // [bp-0x2c]
    unsigned int arg_4;  // [bp+0x4]

    memset(&achT, 223, abarWork[arg_4] & 255);
    return outtext(&achT);
}
"""
    metadata = SimpleNamespace(
        stack_aliases={-44: "achT", 4: "iRow"},
        call_names=("memset", "outtext"),
        global_names=(),
        source_lines=("void DrawBar( int iRow )",),
        source_line_set=frozenset({"void DrawBar( int iRow )"}),
    )

    rewritten = _annotate_cod_proc_output(c_text, SimpleNamespace(name="DrawBar"), metadata)

    assert rewritten == c_text


def test_cod_annotation_keeps_positive_arg_placeholder_source_rewrites_inert():
    c_text = """\
void settextposition(int row, int col);

void DrawFrame(int iTop, int iLeft, int iWidth, int iHeight)
{
    settextposition(arg_4, iLeft);
    settextposition(iHeight + arg_4, iLeft);
}
"""
    metadata = SimpleNamespace(
        stack_aliases={4: "iTop", 6: "iLeft", 8: "iWidth", 10: "iHeight"},
        call_names=("settextposition",),
        global_names=(),
        source_lines=("void DrawFrame( int iTop, int iLeft, int iWidth, int iHeight )",),
        source_line_set=frozenset({"void DrawFrame( int iTop, int iLeft, int iWidth, int iHeight )"}),
    )

    rewritten = _annotate_cod_proc_output(c_text, SimpleNamespace(name="DrawFrame"), metadata)

    assert rewritten == c_text


def test_cod_annotation_preserves_header_when_void_source_args_are_unmaterialized_next_line_brace():
    c_text = """\
int sortdemo_exchange_sort(short arg, char arg_6)

{
    unsigned int local_8;  // [bp-0x8]
    for (arg_6 = 0; local_8 < g_demo_rows; local_8 = local_8 + 1)
    {
        return arg_6;
    }
}
"""
    metadata = SimpleNamespace(
        stack_aliases={-8: "iRowCur"},
        call_names=(),
        global_names=("g_demo_rows",),
        source_lines=("int sortdemo_exchange_sort(void)",),
        source_line_set=frozenset({"int sortdemo_exchange_sort(void)"}),
    )

    rewritten = _annotate_cod_proc_output(c_text, SimpleNamespace(name="sortdemo_exchange_sort"), metadata)

    assert "int sortdemo_exchange_sort(short arg, char arg_6)" in rewritten
    assert "int sortdemo_exchange_sort(void)" not in rewritten
    assert "return arg_6;" in rewritten


def test_dedupe_duplicate_local_declarations_handles_pointer_declarator():
    c_text = """\
int sortdemo_single_pass_swap(void)
{
    unsigned short v24;
    unsigned short changed;
    char *v24;  // 4113

    changed = 0;
    return changed;
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert "unsigned short v24;\n" not in rewritten
    assert "char *v24;  // 4113" in rewritten
    assert "return changed;" in rewritten


def test_missing_generic_local_declarations_recognizes_function_pointer_decl():
    c_text = """\
int select_and_apply(int value)
{
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return local_2(value);
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short local_2;\n" not in rewritten
    assert "unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn" in rewritten


def test_missing_generic_local_declarations_recognizes_array_decl():
    c_text = """\
void DrawBar(void)
{
    char local_2c[44];  // [bp-0x2c]

    local_2c[0] = 0;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert rewritten == c_text
    assert "unsigned short local_2c;" not in rewritten


def test_missing_generic_local_declarations_scans_past_owned_struct_decl():
    c_text = """\
void sub_10554(void)
{
    inertia_stack_object stack_object_70;  // [bp-0x70]
    unsigned short local_5a[43];  // [bp-0x5a]
    unsigned short local_4;  // [bp-0x4]

    local_5a[local_4] = 1;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert rewritten == c_text
    assert "unsigned short local_5a;\n" not in rewritten


def test_dedupe_duplicate_local_declarations_parses_function_pointer_parameter():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    int local_2;  // [bp-0x2]
    int local_2;  // [bp+0x2] fn

    value = arg(value);
    return value;
}
"""

    rewritten = _dedupe_duplicate_local_declarations_text(c_text)

    assert rewritten.count("int local_2;") == 1
    assert "// [bp+0x2] fn" not in rewritten
    assert "value = arg(value);" in rewritten


def test_prune_unused_local_declarations_parses_function_pointer_parameter():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    unsigned short v6;  // ss

    value = arg(value);
    return value;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short v6;" not in rewritten
    assert "value = arg(value);" in rewritten


def test_coalesce_redundant_split_global_incdec_prunes_quicksort_high_byte_carrier():
    c_text = """\
extern unsigned short g_baa;
void QuickSort(void)
{
    unsigned short v12;
    unsigned short v13;
    char mem_0BAB;  // [0xbab]
    v12 = g_baa;
    v13 = mem_0BAB;
    g_baa = (v12 | v13 * 0x100) + 1;
    mem_0BAB = (v12 | v13 * 0x100) + 1 >> 8;
}
"""

    rewritten = _coalesce_redundant_split_global_incdec_text(c_text)
    rewritten = _prune_unused_staging_assignments(rewritten)
    rewritten = _prune_unused_local_declarations_text(rewritten)

    assert "g_baa += 1;" in rewritten
    assert "mem_0BAB" not in rewritten
    assert "v12" not in rewritten
    assert "v13" not in rewritten


def test_coalesce_redundant_split_global_incdec_prunes_for_initializer_high_byte_projection():
    c_text = """\
void QuickSort(void)
{
    unsigned short v19;
    g_baa += 1;
    for (SEG_U8(v19, 2987) = SEG_U16(v19, 2986) + 1 >> 8; i < j; i += 1)
    {
    }
}
"""

    rewritten = _coalesce_redundant_split_global_incdec_text(c_text)

    assert "SEG_U8" not in rewritten
    assert "SEG_U16" not in rewritten
    assert "for (; i < j; i += 1)" in rewritten


def test_missing_generic_local_declarations_materializes_tmp_temps():
    c_text = """\
int f(void)
{
    vvar_1 = tmp_35 + 1;
    return tmp_35;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short tmp_35;" in rewritten
    assert "unsigned short vvar_1;" in rewritten


def test_collapse_annotated_stack_aliases_keeps_function_pointer_decl_inert():
    c_text = """\
int select_and_apply(int value)
{
    unsigned short (*local_2)(unsigned short);  // [bp-0x2] fn

    return local_2(value);
}
"""

    rewritten = _collapse_annotated_stack_aliases_text(c_text)

    assert rewritten == c_text
    assert "unsigned short (*fn)(unsigned short);" not in rewritten
    assert "// [bp-0x2] fn" in rewritten
    assert "return local_2(value);" in rewritten


def test_cod_annotation_keeps_function_pointer_parameter_source_rewrites_inert():
    c_text = """\
short apply_twice(unsigned short (*arg)(unsigned short), unsigned short value)
{
    value = arg(value);
    value = arg(value);
    return value;
}
"""
    metadata = SimpleNamespace(
        stack_aliases={4: "fn", 6: "value"},
        call_names=(),
        global_names=(),
        source_lines=(
            "int apply_twice(int (*fn)(int), int value)",
            "{",
            "value = fn(value);",
            "value = fn(value);",
            "return value;",
            "}",
        ),
    )
    function = SimpleNamespace(name="apply_twice")

    rewritten = _annotate_cod_proc_output(c_text, function, metadata)

    assert rewritten == c_text


def test_text_cod_call_alignment_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("INERTIA_ENABLE_LEGACY_TEXT_CALL_NAME_ALIGNMENT", raising=False)
    c_text = """/* COD annotations:
 * calls = aNchkstk
 */
void f(void)
{
    sub_10079();
}
"""

    rewritten = _align_unknown_call_names_from_cod_evidence_text(c_text)

    assert rewritten == c_text
    assert "sub_10079();" in rewritten
    assert "aNchkstk();" not in rewritten


def test_prune_standalone_stack_probe_calls_removes_prototype_and_call():
    c_text = """\
/* COD annotations:
 * calls = aNchkstk, DrawBar
 */
void aNchkstk(void);
void DrawBar(unsigned short row);

int f(void)
{
    aNchkstk();
    DrawBar(1);
    return 0;
}
"""

    rewritten = _prune_standalone_stack_probe_calls_text(c_text)

    assert "void aNchkstk(void);" not in rewritten
    assert "    aNchkstk();" not in rewritten
    assert "calls = aNchkstk, DrawBar" in rewritten
    assert "DrawBar(1);" in rewritten


def test_source_header_args_unmaterialized_refuses_void_header_when_generated_arg_is_live():
    c_text = """\
void InsertionSort(char arg, char arg_6)
{
    arg_6 = 1;
    return;
}
"""

    blocked = _source_header_args_unmaterialized_8616(
        c_text,
        func_name="InsertionSort",
        source_decl="void InsertionSort(void)",
        source_arg_text=None,
    )

    assert blocked is True

    old_style_blocked = _source_header_args_unmaterialized_8616(
        c_text,
        func_name="InsertionSort",
        source_decl="void InsertionSort()",
        source_arg_text=None,
    )

    assert old_style_blocked is True


def test_materialize_annotated_cod_declarations_text_ignores_comment_pointer_false_positive():
    c_text = """
/* comment:
 * iRow2 is mentioned here but is not a pointer.
 */
int SwapBars(int iRow1, int iRow2)
{
    DrawBar(iRow1);
    DrawBar(iRow2);
    DrawTime(iRow1);
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "/* SwapBars - Calls DrawBar twice to switch the two bars in iRow1 and",
            " * iRow2, then calls DrawTime to update the time.",
            " */",
            "void SwapBars( int iRow1, int iRow2 )",
            "{",
            "DrawBar( iRow1 );",
            "DrawBar( iRow2 );",
            "DrawTime( iRow1 );",
            "}",
        ),
        global_names=(),
    )
    function = SimpleNamespace(name="SwapBars")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "int *iRow2" not in rewritten
    assert "SwapBars(int iRow1, int iRow2)" in rewritten or "SwapBars( int iRow1, int iRow2 )" in rewritten


def test_materialize_annotated_cod_declarations_does_not_promote_arg_from_source_pointer_decl():
    c_text = """\
void DrawThing(char arg)
{
    arg = 1;
}
"""
    metadata = SimpleNamespace(
        source_lines=("void DrawThing(char *arg)", "{", "    *arg = 1;", "}"),
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="DrawThing")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "void DrawThing(char arg)" in rewritten
    assert "void DrawThing(char *arg)" not in rewritten


def test_materialize_annotated_cod_declarations_preserves_authoritative_header():
    c_text = """\
void DrawThing(char arg)
{
    *arg = 1;
}
"""
    metadata = SimpleNamespace(
        source_lines=("void DrawThing(char arg)", "{", "    *arg = 1;", "}"),
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="DrawThing")

    rewritten = _materialize_annotated_cod_declarations_text(
        c_text,
        function,
        metadata,
        preserve_source_header=True,
    )

    assert "void DrawThing(char arg)" in rewritten
    assert "void DrawThing(char *arg)" not in rewritten


def test_materialize_annotated_cod_declarations_does_not_promote_multiply_operand_to_pointer():
    c_text = """\
short mul_us(unsigned short a, unsigned short b)
{
    return a * b;
}
"""
    metadata = SimpleNamespace(
        source_lines=("unsigned short mul_us(unsigned short a, unsigned short b)", "{", "    return a * b;", "}"),
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="mul_us")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "short mul_us(unsigned short a, unsigned short b)" in rewritten
    assert "unsigned short *b" not in rewritten


def test_materialize_annotated_cod_declarations_does_not_repair_callee_signature_from_source():
    c_text = """void Caller(void) {
    Swaps(1, 2);
}
"""
    metadata = SimpleNamespace(
        source_lines=("void Caller(void)", "{", "Swaps(1, 2);", "}"),
        call_names=("Swaps",),
        global_names=(),
    )
    function = SimpleNamespace(name="Caller")

    rewritten = _materialize_annotated_cod_declarations_text(
        c_text,
        function,
        metadata,
    )

    assert "int Swaps();" not in rewritten
    assert "void Swaps();" not in rewritten


def test_materialize_annotated_cod_declarations_ignores_local_source_void_return_for_header():
    c_text = """short Swaps(unsigned short *bar1, unsigned short *bar2)
{
    bar1[0] = bar2[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=("short Swaps(unsigned short *bar1, unsigned short *bar2)", "{", "bar1[0] = bar2[0];", "}"),
        source_return_lines=(),
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _materialize_annotated_cod_declarations_text(
        c_text,
        function,
        metadata,
    )

    assert "short Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" not in rewritten


def test_materialize_missing_direct_call_prototypes_does_not_repair_call_signature_from_source():
    c_text = """void Caller(void)
{
    Swaps(1, 2);
}
"""

    rewritten = _materialize_missing_direct_call_prototypes_text(c_text)

    assert "int Swaps();" not in rewritten
    assert "void Swaps();" not in rewritten


def test_helper_call_format_keeps_codegen_header_for_custom_source_pointer_type():
    c_text = """void Swaps(unsigned short *bar1, unsigned short *bar2)
{
    bar1[0] = bar2[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void Swaps( BAR *bar1, BAR *bar2 )",
            "{",
            "}",
        )
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _align_function_header_with_cod_source_decl_text(c_text, function, metadata)

    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "BAR *" not in rewritten


def test_helper_call_format_does_not_recover_header_from_source_decl_text():
    c_text = """void Swaps(unsigned short bar1, unsigned short bar2)
{
    bar1 = bar2;
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void Swaps( unsigned short *bar1, unsigned short *bar2 )",
            "{",
            "}",
        )
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _align_function_header_with_cod_source_decl_text(c_text, function, metadata)

    assert rewritten == c_text


def test_cod_annotation_keeps_codegen_header_for_custom_source_pointer_type():
    c_text = """void Swaps(unsigned short *bar1, unsigned short *bar2)
{
    unsigned short local_2;
    local_2 = bar1[0];
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void Swaps( BAR *bar1, BAR *bar2 )",
            "{",
            "}",
        ),
        stack_aliases={4: "bar1", 6: "bar2"},
        call_names=(),
        global_names=(),
    )
    function = SimpleNamespace(name="Swaps")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "void Swaps(unsigned short *bar1, unsigned short *bar2)" in rewritten
    assert "BAR *" not in rewritten


@pytest.mark.parametrize("authoritative", [False, True])
@pytest.mark.parametrize("name", ["_dos_getProcessId", "_dos_setProcessId", "_ERROR"])
def test_known_helper_signature_text_preserves_recovered_signature(authoritative, name):
    c_text = """void _dos_getProcessId(int pid)
{
    return;
}
"""
    c_text = c_text.replace("_dos_getProcessId", name)
    function = SimpleNamespace(name=name)
    codegen = SimpleNamespace(_inertia_codegen_signature_authoritative_8616=authoritative)

    rewritten = _rewrite_known_helper_signature_text(c_text, function, codegen=codegen)

    assert rewritten == c_text


def test_prune_void_function_return_values_text_preserves_call_side_effect():
    c_text = """void SwapBars(int iRow1)
{
    return DrawTime(iRow1);
}
"""

    rewritten = _prune_void_function_return_values_text(c_text)

    assert "return DrawTime" not in rewritten
    assert "DrawTime(iRow1);" in rewritten
    assert "return;" not in rewritten


def test_prune_void_function_return_values_text_preserves_address_qualified_call_side_effect():
    c_text = """void main(void)
{
    return ::0x1294f::setvideomode(65535);
}
"""

    rewritten = _prune_void_function_return_values_text(c_text)

    assert "return ::0x1294f::setvideomode" not in rewritten
    assert "::0x1294f::setvideomode(65535);" in rewritten
    assert "return;" not in rewritten


def test_prune_void_call_assignments_preserves_call_side_effect():
    c_text = """void DrawTime();
void f(void)
{
    ax_3 = DrawTime(2189);
}
"""

    rewritten = _prune_void_call_assignments_text(c_text)

    assert "ax_3 = DrawTime" not in rewritten
    assert "DrawTime(2189);" in rewritten


def test_missing_direct_call_prototypes_does_not_invent_known_helper_signature():
    c_text = """void f(void)
{
    ax_2 = aNldiv(3761);
}
"""

    rewritten = _materialize_missing_direct_call_prototypes_text(c_text)

    assert "long aNldiv();" not in rewritten
    assert "int aNldiv();" not in rewritten


def test_normalize_boolean_conditions_materializes_empty_label_statement():
    c_text = """void f(void)
{
    if (x)
    {
LABEL_114d:
    }
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "LABEL_114d:;" in rewritten
    assert "LABEL_114d:\n    }" not in rewritten


def test_normalize_boolean_conditions_materializes_empty_if_else_gap():
    c_text = """void f(void)
{
    if (x)
    else
    call();
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "if (x)\n    else" not in rewritten
    assert "if (x)\n    {\n    }\n    else\n    {\n    }\n    call();" in rewritten


def test_normalize_boolean_conditions_preserves_empty_true_branch_with_else_body():
    c_text = """void f(void)
{
    if (x)
    else
        call();
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "if (x);\n    else\n        call();" in rewritten


def test_normalize_boolean_conditions_simplifies_negated_zero_one_ternary_for_loop():
    c_text = """void f(void)
{
    for (i = 1; !((i < g_rows ? 0 : 1)); i = i + 1)
    {
        step(i);
    }
}
"""

    rewritten = _normalize_boolean_conditions(c_text)

    assert "for (i = 1; i < g_rows; i = i + 1)" in rewritten
    assert "? 0 : 1" not in rewritten


def test_normalize_integer_dereference_stores_text_refuses_fake_segment_zero_store():
    c_text = """\
void f(void)
{
    *(vvar_1398 + 1) = vvar_1401;
}
"""

    rewritten = _normalize_integer_dereference_stores_text(c_text)

    assert rewritten == c_text
    assert "SEG_U8(0," not in rewritten


def test_prune_unused_staging_assignments_drops_self_only_and_decorated_staging_lines():
    c_text = """
void SwapBars(int iRow1, int iRow2)
{
    unsigned short vvar_16;
    char s_2;
    unsigned int arg_1;

    s_2 = &s_2 + 2;
    arg_1 = ir_1;
    vvar_16{r8|2b} = &s_6;
    DrawBar(iRow1);
    DrawBar(iRow2);
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "s_2 = &s_2 + 2;" not in rewritten
    assert "arg_1 = ir_1;" not in rewritten
    assert "vvar_16{r8|2b} = &s_6;" not in rewritten
    assert "DrawBar(iRow1);" in rewritten


def test_prune_unused_local_declarations_text_removes_unused_arg_placeholder_locals():
    c_text = """
void SwapBars(int iRow1, int iRow2)
{
    unsigned int arg_1;  // [bp+0x0]

    DrawBar(iRow1);
    DrawBar(iRow2);
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned int arg_1;" not in rewritten
    assert "DrawBar(iRow2);" in rewritten


def test_prune_unused_local_declarations_text_removes_commented_generated_memory_and_segment_locals():
    c_text = """
int demo(int i)
{
    unsigned short ds;  // ds
    char mem_0042;  // [0x42]
    char tmp_2;  // [bp-0x4]
    unsigned short tmp; // [bp-0x2] tmp
    tmp = i;
    return tmp;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short ds;" not in rewritten
    assert "char mem_0042;" not in rewritten
    assert "char tmp_2;" not in rewritten
    assert "unsigned short tmp;" in rewritten
    assert "return tmp;" in rewritten


def test_prune_unused_local_declarations_text_removes_unused_suffixed_source_placeholder():
    c_text = """
int rel_i16(int a, int b)
{
    unsigned short mask_2;  // [bp-0x4]
    unsigned int mask;  // [bp-0x2]
    mask = 0;
    return mask;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short mask_2;" not in rewritten
    assert "unsigned int mask;" in rewritten
    assert "return mask;" in rewritten


def test_prune_unused_local_declarations_text_removes_unused_local_number_placeholders():
    c_text = """
int cmp_i16(int a, int b)
{
    unsigned short local_a;  // [bp-0xa]
    unsigned short local_2;  // [bp-0x2]

    if (b > a)
        return -1;
    return 0;
}
"""

    rewritten = _prune_unused_local_declarations_text(c_text)

    assert "unsigned short local_a;" not in rewritten
    assert "unsigned short local_2;" not in rewritten
    assert "return -1;" in rewritten


def test_prune_parameter_shadow_declarations_text_keeps_return_of_parameter_name():
    c_text = """
unsigned int clamp_u16(unsigned int value, unsigned int limit)
{
    unsigned short limit;  // [bp+0x6]

    return limit;
}
"""

    rewritten = _prune_parameter_shadow_declarations_text(c_text)

    assert "unsigned short limit;" not in rewritten
    assert "return limit;" in rewritten


def test_prune_parameter_shadow_declarations_text_removes_function_pointer_parameter_shadow():
    c_text = """
short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    unsigned short (*fn)(unsigned short);  // [bp+0x4]

    value = fn(value);
    value = fn(value);
    return value;
}
"""

    rewritten = _prune_parameter_shadow_declarations_text(c_text)

    assert "unsigned short (*fn)(unsigned short);" not in rewritten
    assert rewritten.count("value = fn(value);") == 2
    assert "return value;" in rewritten


def test_collapse_annotated_stack_aliases_text_keeps_same_slot_local_aliases_inert():
    c_text = """
int rel_i16(int a, int b)
{
    unsigned short mask_2;  // [bp-0x2] mask
    unsigned short mask_3;  // [bp-0x2] mask
    mask_2 = 0;
    if (b > a)
        mask_2 = mask_2 | 1;
    return mask_2;
}
"""

    rewritten = _collapse_annotated_stack_aliases_text(c_text)

    assert rewritten == c_text
    assert "mask_2" in rewritten
    assert "mask_3" in rewritten
    assert "return mask_2;" in rewritten


def test_collapse_annotated_stack_aliases_text_keeps_target_16bit_equivalent_types_inert():
    c_text = """
void InsertionSort()
{
    unsigned int local_6;  // [bp-0x6] iLength
    unsigned short iLength; // [bp-0x6] iLength
    local_6 = 3;
    if (iLength == 0)
        return;
}
"""

    rewritten = _collapse_annotated_stack_aliases_text(c_text)

    assert rewritten == c_text
    assert "unsigned int local_6;" in rewritten
    assert "unsigned short iLength; // [bp-0x6] iLength" in rewritten
    assert "local_6 = 3;" in rewritten
    assert "if (iLength == 0)" in rewritten


def test_normalize_portable_flat_main_signature_text_promotes_void_main_and_return_zero():
    c_text = """
void main(void)
{
    InitBars();
    return;
}
"""
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(void)" in rewritten
    assert "return 0;" in rewritten
    assert "void main(void)" not in rewritten


def test_normalize_portable_flat_main_signature_text_rejects_recovered_nonstandard_args():
    c_text = "int main(unsigned short arg)\n{\n    return 255;\n}\n"
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(void)" in rewritten
    assert "unsigned short arg" not in rewritten


def test_normalize_portable_flat_main_signature_text_normalizes_void_call_return():
    c_text = (
        "void setvideomode(int mode);\n"
        "unsigned short main(void)\n"
        "{\n"
        "    return setvideomode(65535);\n"
        "}\n"
    )
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(void)" in rewritten
    assert "setvideomode(65535);" in rewritten
    assert "return 0;" in rewritten
    assert "return setvideomode" not in rewritten


def test_normalize_portable_flat_main_signature_text_normalizes_non_int_call_return():
    c_text = (
        "int setvideomode(int mode);\n"
        "unsigned short main(void)\n"
        "{\n"
        "    return setvideomode(65535);\n"
        "}\n"
    )
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(void)" in rewritten
    assert "setvideomode(65535);" in rewritten
    assert "return 0;" in rewritten
    assert "return setvideomode" not in rewritten


def test_normalize_portable_flat_main_signature_text_keeps_standard_args():
    c_text = "int main(int argc, char **argv)\n{\n    return argc;\n}\n"
    function = SimpleNamespace(name="main")

    rewritten = _normalize_portable_flat_main_signature_text(
        c_text,
        function,
        c_target="portable-flat",
    )

    assert "int main(int argc, char **argv)" in rewritten


def test_materialize_annotated_cod_declarations_text_ignores_source_prototypes_for_called_functions():
    c_text = """
int main(void)
{
    InitBars();
    InitMenu();
    RunMenu();
    return 0;
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void main( void );",
            "void InitBars( void );",
            "void InitMenu( void );",
            "void RunMenu( void );",
        ),
        global_names=(),
        call_names=("InitBars", "InitMenu", "RunMenu"),
    )
    function = SimpleNamespace(name="main")

    rewritten = _materialize_annotated_cod_declarations_text(c_text, function, metadata)

    assert "int InitBars();" not in rewritten
    assert "int InitMenu();" not in rewritten
    assert "int RunMenu();" not in rewritten
    assert "void InitBars( void );" not in rewritten


def test_materialize_synthetic_globals_ignores_cod_function_designator_evidence_for_funcptr_targets():
    c_text = """
int select_and_apply(int which, int value)
{
    unsigned short (*fn)(unsigned short);

    if (which)
        fn = inc_one;
    else
        fn = dec_one;
    return apply_twice(fn, value);
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "int select_and_apply(int which, int value)",
            "{",
            "    int (*fn)(int);",
            "    if (which != 0) {",
            "        fn = inc_one;",
            "    } else {",
            "        fn = dec_one;",
            "    }",
            "    return apply_twice(fn, value);",
            "}",
        ),
        global_names=("inc_one", "dec_one"),
    )

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "int inc_one();" not in rewritten
    assert "int dec_one();" not in rewritten
    assert "extern unsigned short inc_one" not in rewritten
    assert "extern unsigned short dec_one" not in rewritten


def test_materialize_synthetic_globals_ignores_invalid_metadata_identifier_candidates():
    c_text = """
int DrawTime(void)
{
    sprintf();
}
"""
    metadata = SimpleNamespace(
        source_lines=("void (*fn)(void);", "fn = _sprintf;"),
        global_names=("_ sprintf",),
    )

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "int _ sprintf();" not in rewritten
    assert "extern unsigned short _ sprintf;" not in rewritten


def test_prune_invalid_simple_function_prototypes_removes_split_identifier_decls():
    c_text = """
int _sprintf(char *buf, const char *fmt, ...);
int _ sprintf();
int sprintf();

void f(void)
{
    sprintf();
    clFinish = clock();
}
"""

    rewritten = _prune_invalid_simple_function_prototypes_text(c_text)

    assert "int _ sprintf();" not in rewritten
    assert "int _sprintf(char *buf, const char *fmt, ...);" in rewritten
    assert "int sprintf();" in rewritten
    assert "    sprintf();" in rewritten
    assert "    clFinish = clock();" in rewritten


def test_prune_invalid_simple_function_prototypes_keeps_multiword_return_type() -> None:
    c_text = """\
unsigned short ReInitBars(void);

void InitBars(void)
{
    ReInitBars();
}
"""

    rewritten = _prune_invalid_simple_function_prototypes_text(c_text)

    assert "unsigned short ReInitBars(void);" in rewritten


def test_materialize_synthetic_globals_ignores_typedef_alias_and_prototype_parameter() -> None:
    c_text = """\
struct recovered_object;
unsigned short fill_object(struct recovered_object *a0);
int intdos(union REGS *in, union REGS *out);
typedef struct recovered_object {
    unsigned short field_0;
} recovered_object;

void run(void)
{
    recovered_object object;
    fill_object(&object);
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, synthetic_globals={0: ("REGS", 2)})

    assert "extern unsigned short a0;" not in rewritten
    assert "extern unsigned short REGS;" not in rewritten
    assert "extern unsigned short recovered_object;" not in rewritten


def test_materialize_synthetic_globals_declares_generated_scalar_hex_global_without_metadata():
    c_text = """
int f(void)
{
    return g_ba4 >> 8;
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short g_ba4;" in rewritten
    assert rewritten.index("extern unsigned short g_ba4;") < rewritten.index("int f(void)")


def test_materialize_synthetic_globals_declares_generic_word_byte_and_return_globals():
    c_text = """
short f(void)
{
    unsigned short local_2;
    local_2 = global_word_0042;
    local_2 += global_u8_0044[local_2];
    g_48 += 2;
    return g_0048;
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short global_word_0042;" in rewritten
    assert "extern unsigned char global_u8_0044[1];" in rewritten
    assert "extern unsigned short g_0048;" in rewritten
    assert "g_48" not in rewritten
    assert rewritten.index("extern unsigned short global_word_0042;") < rewritten.index("short f(void)")


def test_materialize_synthetic_globals_keeps_existing_aggregate_global_declaration():
    c_text = """
extern struct { unsigned char field_0; unsigned char field_1; } abarWork[1];

short f(void)
{
    return abarWork[0].field_0;
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert rewritten.count("extern struct { unsigned char field_0; unsigned char field_1; } abarWork[1];") == 1
    assert "_inertia_global_abarWork" not in rewritten


def test_materialize_synthetic_globals_does_not_promote_member_metadata_names():
    c_text = """
extern struct { unsigned char field_0; unsigned char field_1; } abarWork[1];

short f(void)
{
    return abarWork[0].field_0;
}
"""
    metadata = SimpleNamespace(source_lines=(), global_names=("field_0",))

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "extern unsigned short field_0;" not in rewritten
    assert rewritten.count("extern struct { unsigned char field_0; unsigned char field_1; } abarWork[1];") == 1


def test_materialize_synthetic_globals_declares_source_backed_scalar_condition_global():
    c_text = """
clock_t clock(void);

void ReInitBars()
{
    unsigned int iRow;
    for (iRow = 0; cRow > iRow; iRow += 1)
    {
    }
}
"""
    metadata = SimpleNamespace(
        source_lines=(
            "void ReInitBars( clock_t wait )",
            "{",
            "    clock_t goal;",
            "    int iRow;",
            "    for( iRow = 0; iRow < cRow; iRow++ )",
            "    {",
            "    }",
            "}",
        ),
        global_names=(),
    )

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "extern unsigned short cRow;" in rewritten
    assert "extern unsigned short iRow;" not in rewritten
    assert "extern unsigned short clock_t;" not in rewritten
    assert rewritten.index("extern unsigned short cRow;") < rewritten.index("void ReInitBars()")


def test_materialize_synthetic_globals_declares_plain_assignment_and_call_arg_globals_without_metadata():
    c_text = """
clock_t clock(void);
int sprintf(char *buf, const char *fmt, ...);

void DrawTime(int iCurrentRow)
{
    unsigned int achTiming;
    clFinish = clock();
    sprintf(&achTiming, fmt, iSwaps, iCompares);
    Sleep(clPause - 75);
    Beep(iCurrentRow, 75);
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short clFinish;" in rewritten
    assert "extern unsigned short iSwaps;" in rewritten
    assert "extern unsigned short iCompares;" in rewritten
    assert "extern unsigned short clPause;" in rewritten
    assert "extern unsigned short iCurrentRow;" not in rewritten
    assert "extern unsigned short achTiming;" not in rewritten
    assert "extern unsigned short Beep;" not in rewritten
    assert "extern unsigned short color;" not in rewritten
    assert "extern unsigned short char;" not in rewritten
    assert "extern unsigned short void;" not in rewritten
    assert rewritten.index("extern unsigned short clFinish;") < rewritten.index("void DrawTime")


def test_materialize_synthetic_globals_does_not_declare_function_call_parameters():
    c_text = """
short apply_twice(unsigned short (*fn)(unsigned short), unsigned short value)
{
    value = fn(value);
    value = fn(value);
    return value;
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short value;" not in rewritten
    assert "extern unsigned short fn;" not in rewritten
    assert rewritten.count("value = fn(value);") == 2


def test_materialize_synthetic_globals_does_not_declare_boolean_literals():
    c_text = """
clock_t clock(void);

void Sleep(clock_t wait)
{
    unsigned long goal;
    goal = clock() + wait;
    while (true)
    {
        if (false)
            break;
    }
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short true;" not in rewritten
    assert "extern unsigned short false;" not in rewritten
    assert "while (true)" in rewritten


def test_materialize_synthetic_globals_ignores_comment_only_field_mentions():
    c_text = """
/*/ if( abarWork[iChild + 1].len > abarWork[iChild].len ) */
void PercolateDown(void)
{
    if (abarWork[local_2] >= abarWork[local_4])
        return;
}
"""
    metadata = SimpleNamespace(source_lines=(), global_names=("abarWork",))

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "struct _inertia_global_abarWork" not in rewritten
    assert "extern unsigned short abarWork[1];" in rewritten


def test_materialize_synthetic_globals_keeps_executable_field_mentions_struct_backed():
    c_text = """
void PercolateDown(void)
{
    if (abarWork[local_2].len >= abarWork[local_4].len)
        return;
}
"""
    metadata = SimpleNamespace(source_lines=(), global_names=("abarWork",))

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text, metadata)

    assert "struct _inertia_global_abarWork" in rewritten
    assert "unsigned short len;" in rewritten
    assert "extern struct _inertia_global_abarWork abarWork[1];" in rewritten


def test_materialize_synthetic_globals_declares_scalar_condition_global_without_metadata():
    c_text = """
void ReInitBars()
{
    unsigned short local_2;
    for (local_2 = 0; cRow > local_2; local_2 += 1)
    {
    }
}
"""

    rewritten = _materialize_missing_synthetic_global_declarations_text(c_text)

    assert "extern unsigned short cRow;" in rewritten
    assert "extern unsigned short local_2;" not in rewritten
    assert rewritten.index("extern unsigned short cRow;") < rewritten.index("void ReInitBars()")


def test_source_function_prototype_decls_from_cod_source_lines_is_inert():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "void main( void );",
            "void InitBars( void );",
            "int helper(unsigned short x);",
            "{",
        )
    )

    assert prototypes == {}


def test_source_function_prototype_decls_from_cod_source_lines_ignores_comment_suffixed_prototypes():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "void InitMenu( void  );             // Menu Functions",
            "void InitBars( void  );             // Bar functions",
        )
    )

    assert prototypes == {}


def test_source_function_prototype_decls_from_cod_source_lines_refuses_return_call_statement():
    prototypes = _source_function_prototype_decls_from_cod_source_lines(
        (
            "int helper(int value);",
            "return apply_twice(fn, value);",
            "if (which) inc_one(value);",
        )
    )

    assert prototypes == {}


def test_prune_unused_staging_assignments_drops_transitively_dead_assignment_chains():
    c_text = """
int main(void)
{
    unsigned short vvar_20;
    unsigned short vvar_24;

    vvar_20 = &s_8;
    vvar_24 = vvar_20 - 2 + -2;
    return 0;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "vvar_20 = &s_8;" not in rewritten
    assert "vvar_24 = vvar_20 - 2 + -2;" not in rewritten


def test_prune_unused_staging_assignments_drops_dead_generated_v_memory_load_chain():
    c_text = """
void PercolateUp(int iMaxLevel)
{
    unsigned short v12;
    unsigned short v13;
    char v14;
    char v15;
    char mem_0B4C;
    unsigned short local_0;
    unsigned short local_2;

    v12 = local_2;
    v13 = local_0;
    v14 = local_0 & 0xff00 | *(&mem_0B4C + v13 * 2);
    v15 = *(&mem_0B4C + v12 * 2);
    if (abarWork[iMaxLevel] <= abarWork[local_2])
        return;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "v12 = local_2;" not in rewritten
    assert "v13 = local_0;" not in rewritten
    assert "v14 =" not in rewritten
    assert "v15 =" not in rewritten
    assert "mem_0B4C" in rewritten
    assert "abarWork[iMaxLevel] <= abarWork[local_2]" in rewritten


def test_prune_standalone_memory_helper_reads_drops_pure_generated_read():
    c_text = """
void ReInitBars(void)
{
    char mem_08F0;
    unsigned short local_0;

    MEM_U16(&mem_08F0 + local_0 * 2);
    abarWork[local_0] = MEM_U16(&mem_08F0 + local_0 * 2);
    DrawBar(local_0);
}
"""

    rewritten = _prune_standalone_memory_helper_reads_text(c_text)

    assert "    MEM_U16(&mem_08F0 + local_0 * 2);" not in rewritten
    assert "abarWork[local_0] = MEM_U16(&mem_08F0 + local_0 * 2);" in rewritten
    assert "DrawBar(local_0);" in rewritten


def test_prune_standalone_memory_helper_reads_keeps_nested_call_argument():
    c_text = """
void f(void)
{
    MEM_U16(next_ptr());
}
"""

    rewritten = _prune_standalone_memory_helper_reads_text(c_text)

    assert "MEM_U16(next_ptr());" in rewritten


def test_prune_undefined_fragment_carriers_drops_dead_arithmetic_chain_and_decls():
    c_text = """
void main(void)
{
    unsigned short vvar_31;
    unsigned short vvar_27;
    unsigned short vvar_40;
    unsigned short vvar_44;
    clearscreen(0);
    vvar_31 = vvar_27 - 4;
    displaycursor(0);
    vvar_40 = vvar_27 - 4 - 6;
    RunMenu();
    vvar_44 = vvar_27 - 4 - 6 - 4;
    return setvideomode(65535);
}
"""

    rewritten = _prune_undefined_fragment_carrier_assignments_text(c_text)

    assert "vvar_" not in rewritten
    assert "clearscreen(0);" in rewritten
    assert "displaycursor(0);" in rewritten
    assert "RunMenu();" in rewritten
    assert "return setvideomode(65535);" in rewritten


def test_prune_unused_staging_assignments_keeps_unused_call_result_side_effects():
    c_text = """
void QuickSort(int iLow, int iHigh)
{
    unsigned short vvar_97;
    unsigned short vvar_arg;

    vvar_arg = iLow;
    vvar_97 = Swaps(SEG_PTR(ds, (vvar_arg << 1) + 2892), SEG_PTR(ds, (iHigh << 1) + 2892));
    return;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "vvar_arg = iLow;" in rewritten
    assert "vvar_97 = Swaps" not in rewritten
    assert "    Swaps(SEG_PTR(ds, (vvar_arg << 1) + 2892), SEG_PTR(ds, (iHigh << 1) + 2892));" in rewritten


def test_prune_unused_staging_assignments_drops_unused_split_stack_suffix_names():
    c_text = """
int main(void)
{
    char s_2_2;

    s_2_2 = vvar_2;
    return 0;
}
"""

    rewritten = _prune_unused_staging_assignments(c_text)

    assert "s_2_2 = vvar_2;" not in rewritten


def test_prune_non_lvalue_arithmetic_assignments_keeps_compound_updates():
    c_text = """
int f(int x)
{
    x -= 1;
    x += 2;
    a + b = c;
    return x;
}
"""

    rewritten = _prune_non_lvalue_arithmetic_assignments(c_text)

    assert "x -= 1;" in rewritten
    assert "x += 2;" in rewritten
    # Invalid targets must remain visible to recompilation, not be deleted.
    assert "a + b = c;" in rewritten


def test_materialize_missing_generic_local_declarations_text_handles_mangled_function_names():
    c_text = """
void $_nfree(void)
{
    unsigned short ir_0;
    unsigned short ir_1;
    unsigned short ir_2;

    SEG_U8(ir_0, ir_1 + vvar_2) = SEG_U8(ir_0, ir_1 + vvar_2) + ir_2;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short vvar_2;" in rewritten


def test_materialize_missing_generic_local_declarations_text_does_not_declare_runtime_mem_helpers():
    c_text = """
void ReInitBars(void)
{
    char mem_08F0;
    unsigned short v15;

    v15 = MEM_U16(&mem_08F0);
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "int MEM_U16();" not in rewritten
    assert "MEM_U16(&mem_08F0)" in rewritten


def test_materialize_missing_generic_local_declarations_text_handles_generated_locals():
    c_text = """
int main(void)
{
    unsigned short ub;  // [bp-0x16]

    local_16 = ub;
    return local_18;
}
"""

    rewritten = _materialize_missing_generic_local_declarations_text(c_text)

    assert "unsigned short ub;" in rewritten
    assert "unsigned short local_16;" in rewritten
    assert "unsigned short local_18;" in rewritten


def test_prune_weaker_conflicting_prototypes_text_downgrades_typed_proto_on_lower_observed_arity():
    c_text = """\
void *memset(void *dst, int ch, unsigned long count);

void DrawBar(int iRow)
{
    memset();
    memset(iRow, 0);
}
"""
    rewritten = _prune_weaker_conflicting_prototypes_text(c_text)
    assert "int memset();" in rewritten
    assert "void *memset(void *dst, int ch, unsigned long count);" not in rewritten


def test_prune_weaker_conflicting_prototypes_text_keeps_return_call_statement():
    c_text = """\
int apply_twice();

int select_and_apply(int which, int value)
{
    unsigned int fn;
    if (which)
        fn = inc_one;
    else
        fn = dec_one;
    return apply_twice(fn, value);
}
"""
    rewritten = _prune_weaker_conflicting_prototypes_text(c_text)

    assert "int apply_twice();" in rewritten
    assert "return apply_twice(fn, value);" in rewritten
