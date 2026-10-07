import pytest

from tools.ada_script.idc_engine import IDCGrammar, IDCScript


@pytest.fixture
def grammar():
    """Provides an IDCGrammar instance for tests."""
    return IDCGrammar()

def test_simple_declaration(grammar):
    """Tests parsing of a simple static variable declaration."""
    script = "static byte my_var;"
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.variables) == 1
    variable = result.variables[0]
    assert variable['name'] == 'my_var'
    assert variable['modifier'] == 'static'
    assert variable['type'] == 'byte'

def test_failing_function_call_statement(grammar):
    """Tests parsing the complex function call that previously caused a syntax error."""
    script = "set_inf_attr(INF_GENFLAGS, ~INFFL_LOADIDC & get_inf_attr(INF_GENFLAGS));"
    # The main goal is to ensure this does not raise a SyntaxError.
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.operands) == 1
    call = result.operands[0]
    assert call['type'] == 'call'
    assert call['name'] == 'set_inf_attr'
    assert len(call['args']) == 2
    first_arg = call['args'][0]
    assert first_arg == 'INF_GENFLAGS'
    second_arg = call['args'][1]
    assert isinstance(second_arg, dict)
    assert second_arg['type'] == 'binary'
    assert second_arg['op'] == '&'

def test_function_definition_parsing(grammar):
    """Tests that a function definition with a body is parsed correctly."""
    script = """
    static GenInfo(void) {
        delete_all_segments();
 \t    set_processor_type("metapc", SETPROC_USER);
    }
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.functions) == 1
    func = result.functions[0]
    assert func['name'] == 'GenInfo'
    assert len(func['statements']) == 2
    first_stmt = func['statements'][0]
    assert first_stmt['type'] == 'call'
    assert first_stmt['name'] == 'delete_all_segments'
    second_stmt = func['statements'][1]
    assert second_stmt['type'] == 'call'
    assert second_stmt['name'] == 'set_processor_type'

def test_include_and_define(grammar):
    """Tests parsing of preprocessor directives."""
    script = """
    #include <idc.idc>
    #define UNLOADED_FILE 1
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.includes) == 1
    assert result.includes[0] == 'idc.idc'
    assert len(result.defines) == 1
    assert result.defines[0]['name'] == 'UNLOADED_FILE'
    assert result.defines[0]['value'].strip() == '1'

def test_syntax_error_on_invalid_script(grammar):
    """Tests that malformed IDC code raises a SyntaxError."""
    script = "static my_func(void) {"
    with pytest.raises(SyntaxError):
        grammar.parse(script)

def test_parse_egame_idc_snippet(grammar):
    """Tests a snippet from the problematic egame.idc file."""
    script = """
    static Segments(void) {
        add_segm_ex(0X10000,0X1F882,0X1000,0,1,2,ADDSEG_NOSREG);
        SegRename(0X10000,"seg000");
        SegClass (0X10000,"CODE");
    }
    """
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert len(result.functions) == 1
    func = result.functions[0]
    assert func['name'] == 'Segments'
    assert len(func['statements']) == 3
    first_stmt = func['statements'][0]
    assert first_stmt['type'] == 'call'
    assert first_stmt['name'] == 'add_segm_ex'
    assert len(first_stmt['args']) == 7
    second_stmt = func['statements'][1]
    assert second_stmt['type'] == 'call'
    assert second_stmt['name'] == 'SegRename'
    third_stmt = func['statements'][2]
    assert third_stmt['type'] == 'call'
    assert third_stmt['name'] == 'SegClass'


def test_function_def_with_return():
    """Test function_def handles return_stmt dict without .data error."""
    from tools.ada_script.idc_engine import parse_idc
    idc_content = """
    static test_func() {
        return id;
    }
    """
    result = parse_idc(idc_content)
    assert result is not None
    assert len(result.functions) == 1
    func = result.functions[0]
    assert 'statements' in func
    assert len(func['statements']) == 1
    stmt = func['statements'][0]
    assert isinstance(stmt, dict)
    assert stmt['type'] == 'return'

def test_multi_line_string_in_arg():
    """Test parsing multi-line strings with escapes in function args."""
    from tools.ada_script.idc_engine import parse_idc
    idc_content = '''
    static test_func() {
        set_cmt(0x100, "Multi\\nline\\nwith \\"quote\\"", 0);
    }
    '''
    result = parse_idc(idc_content)
    assert result is not None
    assert len(result.comments) == 1
    cmt = result.comments[0]
    assert cmt['type'] == 'call'
    assert cmt['name'] == 'set_cmt'
    assert cmt['args'][1] == 'Multi\nline\nwith "quote"'

def test_named_arg_in_call(grammar):
    """Tests parsing function call with named argument assignment."""
    script = 'create_insn(x=0x10013);'
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert hasattr(result, 'instructions') and len(result.instructions) == 1
    call = result.instructions[0]
    assert call['type'] == 'call'
    assert call['name'] == 'create_insn'
    assert len(call['args']) == 1
    arg = call['args'][0]
    assert isinstance(arg, dict)
    assert arg['type'] == 'assign'
    assert arg['left'] == 'x'
    assert arg['op'] == '='
    assert arg['right'] == 0x10013

def test_assignment_arg_parsing(grammar):
    """Tests standalone assignment in argument context."""
    script = 'op_hex(x=1, 1);'
    result = grammar.parse(script)
    assert isinstance(result, IDCScript)
    assert hasattr(result, 'operands') and len(result.operands) == 1
    call = result.operands[0]
    assert call['type'] == 'call'
    assert call['name'] == 'op_hex'
    assert len(call['args']) == 2
    first_arg = call['args'][0]
    assert first_arg['type'] == 'assign'
    assert first_arg['left'] == 'x'
    assert first_arg['right'] == 1
    second_arg = call['args'][1]
    assert second_arg == 1
