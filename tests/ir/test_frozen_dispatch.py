"""Immutable dispatch retains handlers without exposing a mutable container."""

from collections.abc import Callable

import pytest

from inertia.ir.frozen_dispatch import FrozenDispatch, frozen_dispatch_lookup

pytestmark = pytest.mark.decompiler


def _first_handler():
    return 1


def _second_handler():
    return 2


def test_lookup_returns_exact_handler_and_absent_key():
    """String and type keys retain their ordinary static dispatch behavior."""
    handler = _first_handler
    string_entries: FrozenDispatch[str, Callable[[], int]] = (("MOV", handler),)
    type_entries: FrozenDispatch[type, Callable[[], int]] = ((int, handler),)
    assert frozen_dispatch_lookup(string_entries, "MOV") is handler
    assert frozen_dispatch_lookup(string_entries, "LOAD") is None
    assert frozen_dispatch_lookup(type_entries, int) is handler
    assert frozen_dispatch_lookup(type_entries, str) is None


def test_entry_containers_cannot_be_replaced():
    """Neither the entry inventory nor an individual pair supports assignment."""
    handler = _first_handler
    entries = (("MOV", handler),)
    with pytest.raises(TypeError):
        entries[0] = ("MOV", lambda: 2)
    with pytest.raises(TypeError):
        entries[0][1] = lambda: 2
    assert frozen_dispatch_lookup(entries, "MOV") is handler


@pytest.mark.parametrize("operation", ["equality", "union"])
def test_ordinary_operand_hooks_receive_only_immutable_tuple(operation):
    """Overloaded equality/union cannot expose a mappingproxy-style backing dict."""
    handler = _first_handler
    entries = (("MOV", handler),)
    received = []

    class Operand:
        def _observe(self, other):
            received.append(other)
            assert type(other) is tuple
            with pytest.raises(TypeError):
                other[0] = ("MOV", lambda: 2)
            with pytest.raises(TypeError):
                other[0][1] = lambda: 2

        def __eq__(self, other):
            self._observe(other)
            return False

        def __ror__(self, other):
            self._observe(other)
            return None

    if operation == "equality":
        assert (entries == Operand()) is False
    else:
        assert (entries | Operand()) is None
    assert len(received) == 1 and received[0] is entries
    assert frozen_dispatch_lookup(entries, "MOV") is handler


def test_lookup_reads_authoritative_entries_without_cache():
    """Distinct current tuples select their own exact handler on every lookup."""
    first = _first_handler
    second = _second_handler
    first_entries = (("MOV", first),)
    second_entries = (("MOV", second),)
    assert frozen_dispatch_lookup(first_entries, "MOV") is first
    assert frozen_dispatch_lookup(second_entries, "MOV") is second
    assert frozen_dispatch_lookup(first_entries, "MOV") is first
    assert type(first_entries) is tuple and type(first_entries[0]) is tuple


def test_exact_dict_replacement_preserves_ordinary_instrumentation():
    """Mutable foreign replacements remain callable without immutable admission."""
    replacement = {"MOV": _first_handler}
    assert frozen_dispatch_lookup(replacement, "MOV") is _first_handler
    replacement["MOV"] = _second_handler
    assert frozen_dispatch_lookup(replacement, "MOV") is _second_handler
    assert frozen_dispatch_lookup(replacement, "LOAD") is None


@pytest.mark.parametrize("entries", [[("MOV", object())],
                                    (["MOV", object()],), (("MOV",),)])
def test_malformed_container_is_a_loud_contract_defect(entries):
    """Foreign mutable containers and malformed entries cannot become authority."""
    with pytest.raises(TypeError):
        frozen_dispatch_lookup(entries, "MOV")
