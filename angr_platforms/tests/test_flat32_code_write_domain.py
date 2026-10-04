"""A write touching any code byte must fail the explicit disjointness goal."""

from types import SimpleNamespace

import pytest
import z3

from tools.dosunit.recursive_proofs.flat32_image_bound_domain import (
    AccessKind,
    MemoryAccess,
    _access_goal,
)


@pytest.mark.parametrize('address,width,disjoint', [
    (0x1000, 4, False),
    (0x0fff, 2, False),
    (0x100f, 2, False),
    (0x0fff, 18, False),
    (0x0ffc, 4, True),
    (0x1010, 4, True),
    (0xfffffffe, 4, False),
])
def test_code_write_goal_uses_interval_disjointness(address: int, width: int, disjoint: bool) -> None:
    """Overlap is rejected even when independently checking broad writable regions."""
    run = SimpleNamespace(system=SimpleNamespace(component_ranges=((0x1000, 0x1010),)))
    access = MemoryAccess(AccessKind.STORE, {}, width)
    goal = _access_goal(run, access, z3.BitVecVal(address, 32), ((0, 1 << 32),))
    assert z3.is_true(z3.simplify(goal)) is disjoint
