"""Standard enum repr can be skipped without changing atom representation."""
import multiprocessing
from enum import StrEnum
from time import monotonic

import pytest

from inertia.frontend.x86_16.control_coordinates import ControlWidth
from inertia.ir.logical_memory_contracts import IRMemoryAccessKind8616
from inertia.ir.segment_state_transfer import SegmentValueKind8616
from inertia.semantics.caller_return_use_contracts import CallsiteReturnUseKind8616
from inertia.validation import tail_validation_generation_atoms as owner

pytestmark = pytest.mark.decompiler

ACTUAL = (ControlWidth.WORD, IRMemoryAccessKind8616.READ,
          SegmentValueKind8616.UNKNOWN, CallsiteReturnUseKind8616.VALUE)


def _large_enum_mapping() -> None:
    """Exercise the four observed native enums inside an exponentially shared DAG."""
    value = ACTUAL
    for _ in range(30):
        value = (value, value)
    start = monotonic()
    result = owner.build_validation_generation_atom_8616({'b': value, 'a': value})
    assert result[2][0][0] == 'a'
    assert result[2][0][1] is result[2][1][1]
    print('enum_shared30_seconds', monotonic() - start, flush=True)


def test_standard_enum_shared_mapping_is_bounded() -> None:
    """The actual native enum classes must not force value DAG repr expansion."""
    child = multiprocessing.get_context('fork').Process(target=_large_enum_mapping)
    child.start()
    child.join(2)
    if child.is_alive():
        child.kill()
        child.join()
    assert child.exitcode == 0


@pytest.mark.parametrize('value', ACTUAL)
def test_actual_enum_atoms_and_mapping_order_remain_exact(value: object) -> None:
    """Keep scalar enum identity and byte-for-byte native tuple repr order."""
    assert owner.build_validation_generation_atom_8616(value) is value
    result = owner.build_validation_generation_atom_8616({value: ('z', value), 'a': ('a', value)})
    assert result[2] == tuple(sorted(result[2], key=repr))


def test_custom_enum_repr_keeps_effects() -> None:
    """A user enum repr must execute exactly once per original value occurrence."""
    calls = []
    class Custom(StrEnum):
        """An intentionally observable enum formatter."""
        A = 'a'
        def __repr__(self) -> str:
            """Record formatting without changing normal enum syntax."""
            calls.append(self)
            return super().__repr__()
    result = owner.build_validation_generation_atom_8616({'b': Custom.A, 'a': Custom.A})
    assert calls == [Custom.A, Custom.A]
    assert result[2][0][0] == 'a'


def test_custom_attribute_and_descriptor_are_not_pure() -> None:
    """Purity inspection must refuse hooks without executing them."""
    class Custom(StrEnum):
        """Attribute-hook enum whose atom remains scalar."""
        A = 'a'
        def __getattribute__(self, name: str) -> object:
            """Use a custom method even though it currently delegates."""
            return super().__getattribute__(name)
    assert not owner._standard_enum_repr_8616(Custom.A)
    class Descriptor(StrEnum):
        """Descriptor corruption must be refused before attribute reads."""
        A = 'a'
    Descriptor._name_ = property(lambda self: (_ for _ in ()).throw(AssertionError('descriptor executed')))
    assert not owner._standard_enum_repr_8616(Descriptor.A)


def test_custom_value_repr_is_not_pure() -> None:
    """A class formatter override retains the full repr fallback."""
    class Custom(StrEnum):
        """Native enum syntax with custom scalar rendering."""
        A = 'a'
    Custom._value_repr_ = lambda value: 'custom'
    assert not owner._standard_enum_repr_8616(Custom.A)


def test_changed_enum_fields_recheck_purity_and_order() -> None:
    """No class/value purity decision is cached between mapping operations."""
    class Local(StrEnum):
        """Isolated mutable negative-control enum."""
        A = 'a'
        B = 'b'
    assert owner._standard_enum_repr_8616(Local.A)
    Local.A._name_ = 'Z'
    result = owner.build_validation_generation_atom_8616({Local.A: 1, Local.B: 2})
    assert result[2] == tuple(sorted(result[2], key=repr))
    assert result[2][0][0] is Local.B
    Local.A._name_ = 7
    assert not owner._standard_enum_repr_8616(Local.A)
    Local.A._name_ = 'A'
    Local.A._value_ = object()
    assert not owner._standard_enum_repr_8616(Local.A)


def test_mutated_value_metaclass_equality_is_never_called() -> None:
    """Reject a foreign value class without executing its metaclass equality."""
    class EqualityTrap(type):
        """A class identity is not authorized to run user comparison methods."""
        def __eq__(self, other: object) -> bool:
            """Fail loudly if purity checking invokes semantic equality."""
            raise AssertionError('metaclass equality executed')

    class Foreign(metaclass=EqualityTrap):
        """Non-scalar payload introduced by a mutation."""

    class Local(StrEnum):
        """Private enum prevents mutation of shared production evidence."""
        A = 'a'

    Local.A._value_ = Foreign()
    assert not owner._standard_enum_repr_8616(Local.A)
