"""Entry documents preserve explicit state and reject lossy JSON coercions."""

from copy import deepcopy

import pytest

from inertia.frontend.x86_16.declared_entry_document import parse_declared_function_entry_spec_8616
from inertia.frontend.x86_16.declared_function_entry import DeclaredFunctionEntryRefusal8616
from tests.frontend.test_declared_function_entry import admit, make_spec


def test_document_roundtrip_retains_admission_identity():
    spec = make_spec(use_environment_memory=False)
    parsed = parse_declared_function_entry_spec_8616(spec.to_dict())
    assert parsed == spec
    assert admit(parsed) == admit(spec)


@pytest.mark.parametrize("field,value", [
    ("entry_offset", True), ("entry_segment", "4096"),
    ("version", 1.0), ("use_environment_memory", 0),
    ("registers", {"ss": 4096}), ("memory", {}),
])
def test_malformed_document_refuses_without_coercion(field, value):
    document = make_spec().to_dict()
    document[field] = value
    with pytest.raises(ValueError):
        parse_declared_function_entry_spec_8616(document)


@pytest.mark.parametrize("mutation", ["unknown", "missing", "span_extra", "bad_hex", "return_extra"])
def test_schema_and_byte_encoding_are_closed(mutation):
    document = deepcopy(make_spec().to_dict())
    if mutation == "unknown":
        document["guess_ds"] = True
    elif mutation == "missing":
        del document["use_environment_memory"]
    elif mutation == "span_extra":
        document["memory"][0]["observed"] = True
    elif mutation == "bad_hex":
        document["memory"][0]["data"] = "zz"
    else:
        document["return_boundary"]["extra"] = True
    with pytest.raises(ValueError):
        parse_declared_function_entry_spec_8616(document)


def test_duplicate_registers_survive_parsing_and_are_refused_by_admission():
    document = make_spec().to_dict()
    document["registers"].append(document["registers"][0])
    parsed = parse_declared_function_entry_spec_8616(document)
    assert len(parsed.registers) == 3
    assert isinstance(admit(parsed), DeclaredFunctionEntryRefusal8616)


def test_parsing_does_not_authenticate_foreign_source():
    document = make_spec().to_dict()
    document["source_sha256"] = "0" * 64
    parsed = parse_declared_function_entry_spec_8616(document)
    assert isinstance(admit(parsed), DeclaredFunctionEntryRefusal8616)
