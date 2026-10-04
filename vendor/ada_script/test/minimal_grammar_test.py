import pytest

from idc_engine import IDCGrammar, IDCScript, parse_idc


def test_minimal_grammar_parses_simple_rules():
    """Test that the minimal grammar parses simple IDC rules."""
    grammar = IDCGrammar()
    
    # IDC with various simple rules
    simple_idc = """
    #include <idc.idc>
    #define SOME_CONSTANT 123
    static byte my_var;
    auto another_var = 0x1000;
    """
    
    result = grammar.parse(simple_idc)
    assert isinstance(result, IDCScript)
    assert len(result.includes) == 1
    assert len(result.defines) == 1
    assert len(result.variables) == 2

def test_parse_idc_function():
    """Test the main parse_idc function."""
    # Create a temporary IDC content
    simple_idc = """
    static main() {
        set_name("example", "Test");
    }
    """

    # Write to temp file for parse_idc
    result = parse_idc(simple_idc)
    assert result is not None
    assert len(result.functions) == 1
    assert result.functions[0]['name'] == 'main'
    # Check the statement
    assert len(result.functions[0]['statements']) == 1
    stmt = result.functions[0]['statements'][0]
    assert stmt['type'] == 'call'
    assert stmt['name'] == 'set_name'
    assert stmt['args'] == ['example', 'Test']

def test_keyword_handling():
    """Test parsing of known IDC keywords like 'static', 'include', etc."""
    grammar = IDCGrammar()
    keyword_test = """
    #include <header>
    static byte my_var;
    """

    result = grammar.parse(keyword_test)
    assert isinstance(result, IDCScript)
    assert len(result.includes) == 1
    assert result.includes[0] == 'header'
    assert len(result.variables) == 1
    assert result.variables[0]['modifier'] == 'static'

def test_syntax_error_on_incomplete_function():
    """Test that incomplete function definitions raise a syntax error."""
    grammar = IDCGrammar()
    invalid_idc = "static my_func( {"
    with pytest.raises(SyntaxError):
        grammar.parse(invalid_idc, strict=True)