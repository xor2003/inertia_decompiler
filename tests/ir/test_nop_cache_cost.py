"""Layer: Tests.

Responsibility: repeated coverage must reuse exact lift facts without trusting
stale bytes or mutable artifact provenance.
"""

import pytest
import inertia.ir.no_effect_instructions as effects
from tests.ir.test_nop_census_8616 import _BASE, _built


def test_repeated_native_coverage_does_not_relift_and_stale_bytes_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Warm proof queries reuse facts but still read the current native bytes."""
    built = _built(b"\x90" * 36 + b"\xc3", _BASE, _BASE + 37)
    assert built is not None
    project, _, _, coverage = built
    assert coverage.complete

    def unexpected_lift(*args: object, **kwargs: object) -> object:
        """Fail loudly if an unchanged bound proof repeats its native lifting."""
        raise AssertionError("unchanged coverage repeated native lifting")

    monkeypatch.setattr(effects.pyvex, "lift", unexpected_lift)
    for _ in range(100):
        assert coverage.complete
    project.loader.memory.store(_BASE, b"\xf4")
    assert not coverage.complete
