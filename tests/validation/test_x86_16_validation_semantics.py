import pytest
from inertia.pipeline.errors import PipelineHardError

from inertia.validation.validation_semantics import assert_known_call_semantics_8616


def test_final_semantics_gate_allows_generic_vvar_temporaries():
    c_text = """
    void f(void)
    {
        unsigned short vvar_1;
        vvar_1 = 3;
        return;
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_allows_nonstack_ir_temporaries():
    c_text = """
    void f(void)
    {
        unsigned short ir_7;
        ir_7 = 3;
        return;
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_rejects_raw_stack_placeholders():
    c_text = """
    void f(void)
    {
        unsigned short s_0;
        s_0 = 3;
        return;
    }
    """

    with pytest.raises(PipelineHardError, match="unresolved stack locals"):
        assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_rejects_vvar_used_as_unresolved_ss_base():
    c_text = """
    void f(void)
    {
        unsigned short vvar_0;
        SEG_U16(ss, vvar_0 - 2) = 3;
        return;
    }
    """

    with pytest.raises(PipelineHardError, match="unresolved stack locals"):
        assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_allows_typed_stack_aggregate_name():
    c_text = """
    typedef struct inertia_stack_object_22_18w2 {
        unsigned short field_18;
    } inertia_stack_object_22_18w2;

    void f(void)
    {
        inertia_stack_object_22_18w2 stack_object_70;
        stack_object_70.field_18 = 1;
        return;
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_allows_lowered_hex_offset_argument_name():
    c_text = """
    void f(unsigned short arg_a)
    {
        consume(arg_a);
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_still_rejects_untyped_stack_prefix():
    c_text = """
    void f(void)
    {
        unsigned short stack_unknown;
        stack_unknown = 1;
        return;
    }
    """

    with pytest.raises(PipelineHardError, match="unresolved stack locals"):
        assert_known_call_semantics_8616(c_text, function_addr=0x1000)


def test_final_semantics_gate_ignores_forbidden_tokens_inside_comments():
    c_text = """
    void f(void)
    {
        /* previous bad output shape: ds << 4 and stack[0xfffc] */
        // previous bad output shape: es << 4
        return;
    }
    """

    assert_known_call_semantics_8616(c_text, function_addr=0x1000)
