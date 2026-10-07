"""Frame-carrier collection preserves its typed membership and refusal contract."""

import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CConstant, CDirtyExpression, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.frame_register_carriers import collect_frame_register_carriers_8616
from inertia.lowering.physical_registers import PhysicalRegisterView8616


@pytest.mark.parametrize("name,size,accepted", [("bp", 2, True), ("sp", 2, True), ("ax", 2, False),
                                               ("bp", 4, False), (None, 2, False)])
def test_frame_carriers_require_exact_bp_sp_views(name: str | None, size: int, accepted: bool) -> None:
    project = SimpleNamespace(arch=Arch86_16())
    codegen = SimpleNamespace(
        project=project, next_idx=lambda _: 1, next_node_idx=lambda: 1, next_ident=lambda name: name,
    )
    temporary = CDirtyExpression(
        VirtualVariable(1, 1, 16, VirtualVariableCategory.TMP, oident=1), codegen=codegen,
    )
    source = (
        CConstant(0, SimTypeShort(False), codegen=codegen) if name is None else
        CVariable(SimRegisterVariable(project.arch.registers[name][0], size), codegen=codegen)
    )
    assignment = CAssignment(temporary, source, codegen=codegen, tags={"ins_addr": 0x1000})
    resolution = collect_frame_register_carriers_8616(assignment, project, 0x1000)
    count = int(accepted)
    assert (resolution.raw_fact_count, resolution.normalized_fact_count,
            resolution.classified_fact_count, resolution.materialized_count,
            resolution.failure_count) == (count, count, count, 0, 0)
    if accepted:
        assert name is not None
        assert resolution.resolve(temporary) == PhysicalRegisterView8616(*project.arch.registers[name])
    else:
        assert resolution.resolve(temporary) is None
    assert assignment.rhs is source


def test_frame_carrier_owner_types_check_together(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    owner = "inertia/lowering/"
    result = subprocess.run(
        [sys.executable, "-m", "mypy", "--config-file", "pyproject.toml",
         "--no-pretty", "--no-error-summary", "--cache-dir", str(tmp_path / "mypy"),
         owner + "frame_register_carriers.py", owner + "physical_registers.py"],
        cwd=root, capture_output=True, text=True, check=False, timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
