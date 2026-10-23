"""Native instruction coverage, rather than function size, controls recovery.

Layer: CLI/frontend regression tests.
Responsibility: detect omitted continuations and retain complete short functions.
"""

import angr
import pytest

from inertia.cli.cli_function_discovery import _exact_region_recovery_looks_truncated
from inertia.frontend.x86_16.bootstrap import apply_x86_16_bootstrap
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from tests.cli.test_x86_16_cod_samples import _project_from_bytes

pytestmark = pytest.mark.decompiler


def _recover(code: bytes, region_size: int) -> tuple:
    """Recover native bytes with an independently restricted CFG scan region."""
    apply_x86_16_bootstrap()
    project = _project_from_bytes(code)
    cfg = project.analyses.CFGFast(
        kb=angr.KnowledgeBase(project),
        normalize=True,
        function_starts=[0x1000],
        regions=[(0x1000, 0x1000 + region_size)],
        force_smart_scan=False,
        force_complete_scan=False,
        function_prologues=False,
        symbols=False,
        resolve_indirect_jumps=False,
    )
    return project, cfg.functions[0x1000]


def test_small_function_with_missing_post_call_continuation_is_truncated() -> None:
    """A three-byte CALL cannot stand in for the reachable MOV/RET body."""
    code = bytes.fromhex("e80500b83412c390c3")
    project, function = _recover(code, 3)
    assert function.block_addrs_set == {0x1000}
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1007)
    assert boundary is not None
    assert boundary.block_addrs_set == {0x1000, 0x1003}
    assert _exact_region_recovery_looks_truncated(function, (0x1000, 0x1007))


def test_complete_return_before_large_padding_is_not_truncated() -> None:
    """Unreachable padding is not missing function behavior."""
    code = bytes.fromhex("b83412c3") + bytes(124)
    project, function = _recover(code, len(code))
    boundary = exact_function_range_boundary_8616(project, 0x1000, 0x1080)
    assert boundary is not None
    assert boundary.reachable_instruction_addrs == {0x1000, 0x1003}
    assert not _exact_region_recovery_looks_truncated(function, (0x1000, 0x1080))


def test_unresolved_indirect_terminal_does_not_authorize_reconstruction() -> None:
    """Incomplete native evidence cannot justify changing the recovered graph."""
    project, function = _recover(bytes.fromhex("ffe0"), 2)
    assert exact_function_range_boundary_8616(project, 0x1000, 0x1002) is None
    assert not _exact_region_recovery_looks_truncated(function, (0x1000, 0x1002))


def test_absent_region_does_not_authorize_reconstruction() -> None:
    """A function without independently supplied bounds keeps its CFG."""
    _, function = _recover(bytes.fromhex("b83412c3"), 4)
    assert not _exact_region_recovery_looks_truncated(function, None)
