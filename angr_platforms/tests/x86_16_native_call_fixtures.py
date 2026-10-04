"""Native project and registered CALL evidence for focused lowering fixtures.

Layer: tests/fixtures.
Responsibility: preserve the actual symbolic CALL operand while providing the
source-backed decoded boundary and shared target proof its consumers require.
No target constant or segment state is substituted into the lifted IR.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import angr
from angr_platforms.X86_16.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DecodedDirectCallsiteIndex8616,
    build_boundary_direct_callsite_index_8616,
)
from angr_platforms.X86_16.frontend_function_boundary import exact_function_range_boundary_8616
from angr_platforms.X86_16.ir.function_ir_registry import publish_function_ir_artifact_8616
from angr_platforms.X86_16.ir.function_ssa_registry import (
    FunctionSSAArtifactStage8616,
    publish_function_ssa_artifact_8616,
)
from angr_platforms.X86_16.ir.ssa_function import SSAFunctionArtifact, build_x86_16_function_ssa
from angr_platforms.X86_16.ir.vex_import import build_x86_16_ir_function_artifact
from angr_platforms.X86_16.lowering.call_target_ssa_binder import bind_ssa_call_target_8616


@dataclass(frozen=True)
class NativeCallFixture8616:
    """Retain one real project together with its raw SSA and decoded index."""

    project: angr.Project
    ssa: SSAFunctionArtifact
    index: DecodedDirectCallsiteIndex8616

    def proven_target(self, callsite_addr: int) -> int:
        """Prove the decoded candidate against the unchanged symbolic SSA CALL."""
        # The index proposes coordinates; the shared binder supplies proof.
        proposals = tuple(sorted({
            entry.target_addr
            for entries in self.index._entries_by_normalized_target.values()
            for entry in entries
            if entry.callsite_addr == callsite_addr
        }))
        assert len(proposals) == 1
        proof = bind_ssa_call_target_8616(
            self.ssa, self.ssa.function_addr, callsite_addr, proposals,
            project=self.project, callsite_index=self.index,
        )
        assert proof.complete, proof
        assert proof.target_addr is not None
        return proof.target_addr


def lift_native_call_fixture_8616(code: bytes, *, base_addr: int = 0x1000) -> NativeCallFixture8616:
    """Close a supplied CALL-ending stream with one explicit fixture RET."""
    project = angr.Project(
        io.BytesIO(code + b"\xc3"),
        main_opts={"backend": "blob", "arch": Arch86_16(),
                   "base_addr": base_addr, "entry_point": base_addr},
        auto_load_libs=False,
    )
    boundary = exact_function_range_boundary_8616(project, base_addr, base_addr + len(code) + 1)
    assert boundary is not None
    index = build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    raw = build_x86_16_ir_function_artifact(project, boundary)
    assert not raw.refusals
    publish_function_ir_artifact_8616(project, raw)
    ssa = build_x86_16_function_ssa(raw)
    publish_function_ssa_artifact_8616(project, ssa, FunctionSSAArtifactStage8616.IR)
    return NativeCallFixture8616(project, ssa, index)


def retain_native_call_index_8616(
    project: angr.Project, start: int, end: int,
) -> DecodedDirectCallsiteIndex8616:
    """Retain a closed byte-derived census on its actual evidence project."""
    boundary = exact_function_range_boundary_8616(project, start, end)
    assert boundary is not None
    return build_boundary_direct_callsite_index_8616(
        boundary,
        direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
