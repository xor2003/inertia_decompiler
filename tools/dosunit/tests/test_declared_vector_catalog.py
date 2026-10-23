"""Catalog controls for explicit AH25/AH35 service declarations."""

import pytest

from tools.dosunit.tests import test_real16_declared_input as fixture


@pytest.mark.parametrize(("kind", "function"), [("vector_query", 0x35), ("vector_update", 0x25)])
def test_vector_kind_mints_explicit_bound_service(kind: str, function: int) -> None:
    source = fixture.mz(fixture.EXIT_PROGRAM)
    document = fixture._document(source, services=[fixture._service(kind=kind)])
    declaration = fixture._parse(document, source)
    (service,) = declaration.services
    assert service.function == function
    assert service.vector == 0x21
    assert service.caller_addr == fixture.DEFAULT_CALLER
    assert service.callsite_addr == fixture.DEFAULT_CALLSITE
    assert service.answer_ax is None
    assert service.answer_bx is None
    assert service.answer_cx is None
