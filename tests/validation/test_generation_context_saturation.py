"""A full contextual memo must not disable all reuse for later cyclic DAGs."""
import pytest

from tests.validation.test_generation_cycle_context import CountingBuilder, _diamond, _reference_atom

pytestmark = pytest.mark.decompiler


def test_late_cyclic_diamond_after_saturation() -> None:
    """Keep a fixed memo cap while bounding work after many cold cyclic roots."""
    roots = [_diamond(4) for _ in range(300)]
    late = _diamond(9)
    roots.append(late)
    builder = CountingBuilder()
    result = builder.atom(roots)
    assert result == _reference_atom(roots)
    assert builder._context_references <= 4096
    print('dispatches', builder.calls, 'refs', builder._context_references, flush=True)
    # Each cold diamond has ten compound objects; allow generous overhead.
    assert builder.calls < 4000
    late.payload = 99
    changed = builder.atom(roots)
    assert changed == _reference_atom(roots)
    assert changed != result
