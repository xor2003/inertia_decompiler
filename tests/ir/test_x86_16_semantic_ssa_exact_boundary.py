"""Semantic SSA construction from independently framed caller boundaries."""

from __future__ import annotations

import io
from types import SimpleNamespace

import angr
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.function_ssa_registry import (
    FunctionSSAArtifactFailure8616,
    FunctionSSAArtifactVerdict8616,
)
from inertia.ir.ssa_function import build_x86_16_function_ssa
from inertia.ir.vex_import import build_x86_16_ir_function_artifact
from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.lowering.condition_transfer import collect_typed_condition_artifacts_8616

from inertia.frontend.x86_16.frontend_function_boundary import (
    exact_function_range_boundary_8616,
)
from inertia.semantics.call_stack_effect_pipeline import (
    semantic_function_ssa_artifact_at_address_8616,
)


class _NoFunctions8616:
    """Function manager proving that no CFG boundary is registered."""

    def function(self, *, addr: int, create: bool = False) -> None:
        """Refuse every lookup without creating a guessed function."""
        return None


def _project_and_boundary() -> tuple[SimpleNamespace, SimpleNamespace]:
    """Build a real lifted project and one independently framed function."""
    lifted = angr.Project(
        io.BytesIO(b"\x55\x8b\xec\x5d\xc3"),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )
    project = SimpleNamespace(
        factory=lifted.factory,
        kb=SimpleNamespace(functions=_NoFunctions8616()),
    )
    boundary = SimpleNamespace(
        addr=0x1000,
        size=5,
        block_addrs_set={0x1000},
        info={},
    )
    return project, boundary


def test_exact_supplied_boundary_builds_without_cfg_function() -> None:
    """A binary-framed caller remains usable when the KB omitted its node."""
    project, boundary = _project_and_boundary()

    result = semantic_function_ssa_artifact_at_address_8616(
        project,
        0x1000,
        function=boundary,
    )

    assert result.verdict is FunctionSSAArtifactVerdict8616.PROVEN
    assert result.artifact is not None
    assert result.artifact.function_addr == 0x1000


def test_mismatched_supplied_boundary_refuses() -> None:
    """A retained boundary cannot be reused for a different caller address."""
    project, boundary = _project_and_boundary()

    result = semantic_function_ssa_artifact_at_address_8616(
        project,
        0x1002,
        function=boundary,
    )

    assert result.verdict is FunctionSSAArtifactVerdict8616.UNKNOWN_REFUSE
    assert result.failure is FunctionSSAArtifactFailure8616.FUNCTION_BOUNDARY_CONFLICT


def test_exact_range_boundary_keeps_call_fallthrough_block() -> None:
    """Bounded Frontend reachability retains code after an internal call."""
    lifted = angr.Project(
        io.BytesIO(b"\xe8\x00\x00\xb8\x01\x00\xc3"),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )

    boundary = exact_function_range_boundary_8616(lifted, 0x1000, 0x1007)

    assert boundary is not None
    assert boundary.block_addrs_set == frozenset({0x1000, 0x1003})
    assert 0x1003 in boundary.reachable_instruction_addrs
    assert boundary.successor_edges == ((0x1000, 0x1003),)

    artifact = build_x86_16_ir_function_artifact(lifted, boundary)
    assert artifact.blocks[0].successor_addrs == (0x1003,)
    assert build_x86_16_function_ssa(artifact).predecessor_map[0x1003] == (0x1000,)


def test_exact_range_boundary_keeps_typed_condition_blocks() -> None:
    """A census-owned caller boundary remains usable by typed Conditions."""
    lifted = angr.Project(
        io.BytesIO(b"\x3c\x0d\x75\x04\xb8\x01\x00\xc3\xb8\x02\x00\xc3"),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        auto_load_libs=False,
    )

    boundary = exact_function_range_boundary_8616(lifted, 0x1000, 0x100C)

    assert boundary is not None
    assert tuple(block.addr for block in boundary.blocks) == (0x1000, 0x1004, 0x1008)
    assert boundary.predecessors_by_block[0x1008] == frozenset({0x1000})
    conditions, _edges = collect_typed_condition_artifacts_8616(
        lifted,
        boundary.addr,
        function=boundary,
    )
    assert len(conditions) == 1
    assert conditions[0].op == "ne"
    assert conditions[0].producer_insn == 0x1000
