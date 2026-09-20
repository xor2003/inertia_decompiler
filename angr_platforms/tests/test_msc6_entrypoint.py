"""Fixture entry wrappers require exact label and signature evidence."""

import pytest

from scripts.msc6_entrypoint import EntryBindingStatus, bind_msc6_fixture_entrypoint


def test_entry_wrapper_preserves_generated_source_and_calls_exact_entry():
    source = "unsigned short sub_1234(void) { return 255; }\n"
    result = bind_msc6_fixture_entrypoint(source, main_address=0x1234)
    assert result.status is EntryBindingStatus.BOUND
    assert result.source.startswith(source)
    assert "int main(void) { return (int)sub_1234(); }" in result.source
    again = bind_msc6_fixture_entrypoint(result.source, main_address=0x1234)
    assert again.status is EntryBindingStatus.EXISTING
    assert again.source == result.source


@pytest.mark.parametrize("address", [None, 0x4321, -1])
def test_entry_wrapper_refuses_missing_or_wrong_address(address):
    source = "unsigned short sub_1234(void) { return 255; }\n"
    result = bind_msc6_fixture_entrypoint(source, main_address=address)
    assert result.status is EntryBindingStatus.REFUSED
    assert result.source == source


@pytest.mark.parametrize("definition", [
    "int sub_1234(int argument) { return argument; }",
    "void sub_1234(void) {}",
    "int *sub_1234(void) { return 0; }",
    "int sub_1234(void) {return 0;} int sub_1234(void) {return 1;}",
])
def test_entry_wrapper_never_guesses_arguments_or_return_contract(definition):
    result = bind_msc6_fixture_entrypoint(definition, main_address=0x1234)
    assert result.status is EntryBindingStatus.REFUSED
    assert result.source == definition
