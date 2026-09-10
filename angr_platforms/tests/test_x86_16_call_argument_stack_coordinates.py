"""Regress machine-BP call-argument source selection.

Tests the Types/Lowering coordinate consumer without relying on rendered C.
"""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_type import SimTypeChar, SimTypeFixedSizeArray, SimTypeShort
from angr.sim_variable import SimStackVariable
from angr_platforms.X86_16.alias.stack_memory_ssa import (
    build_x86_16_stack_memory_ssa_alias_artifact,
)
from angr_platforms.X86_16.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa
from angr_platforms.X86_16.lowering.call_argument_stack_sources import (
    call_argument_stack_variable_offset_8616,
    containing_stack_cvariable_8616,
    materialize_call_argument_stack_cvariable_8616,
    outgoing_call_stack_carrier_offset_8616,
)
from angr_platforms.X86_16.lowering.real_mode_linear import (
    RealModeLinearStackAccess8616,
    stack_cvar_for_stable_ss_linear_access_8616,
)
from angr_platforms.X86_16.lowering.stack_lowering_from_facts import (
    materialize_stack_cvar_at_offset_from_facts_8616,
)
from angr_platforms.X86_16.lowering.stack_variable_coordinates import (
    machine_bp_offset_for_stack_variable_8616,
    record_stack_variable_coordinate_projection_8616,
)
from archinfo import ArchX86


class _Codegen:
    """Minimal third-party codegen surface required by CVariable."""

    def __init__(self) -> None:
        self._next_index = 0
        self.project = SimpleNamespace(arch=ArchX86())

    def next_idx(self, _kind: str) -> int:
        """Allocate one stable test node index."""
        index = self._next_index
        self._next_index += 1
        return index

    def next_node_idx(self) -> int:
        """Allocate one stable test node index for current angr releases."""
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        """Keep deterministic C construct identities in the fixture."""
        return name


def test_call_argument_source_uses_machine_bp_coordinate_projection() -> None:
    """Select BP-2 even when angr represents it at entry-SP offset -4."""
    codegen = _Codegen()
    value_type = SimTypeShort(False)
    err = CVariable(
        SimStackVariable(-4, 2, base="bp", name="err"),
        variable_type=value_type,
        codegen=codegen,
    )
    raw_collision = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=value_type,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        arg_list=(),
        statements=None,
        variables_in_use={
            err.variable: err,
            raw_collision.variable: raw_collision,
        },
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=err.variable,
        cvar=err,
        bp_offset=-2,
        entry_sp_offset=-4,
        size=2,
        display_name="err",
    )

    selected = containing_stack_cvariable_8616(
        codegen,
        {},
        offset=-2,
        size_hint=2,
    )

    assert selected is err
    assert call_argument_stack_variable_offset_8616(codegen, selected) == -2


def test_byte_call_source_does_not_retype_wider_same_start_stack_view() -> None:
    """Keep an existing word intact when typed evidence requests its low byte."""
    codegen = _Codegen()
    word = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        statements=None,
        variables_in_use={word.variable: word},
        unified_local_vars={},
    )

    byte = materialize_stack_cvar_at_offset_from_facts_8616(
        codegen,
        -4,
        size=1,
        machine_bp_offset=-2,
        preferred_name="local_2",
    )

    assert isinstance(byte, CVariable)
    assert byte is not word
    assert byte.variable.size == 1
    assert word.variable.size == 2
    assert isinstance(word.variable_type, SimTypeShort)
    assert call_argument_stack_variable_offset_8616(codegen, byte) == -2


def test_call_address_preserves_proven_array_with_narrow_backing() -> None:
    """A word-sized address request must not overwrite a proven byte array."""
    codegen = _Codegen()
    array_type = SimTypeFixedSizeArray(SimTypeChar(False), 16)
    array = CVariable(
        SimStackVariable(-20, 1, base="bp", name="buffer", region=0x1000),
        variable_type=array_type, codegen=codegen,
    )
    original_type = array.variable_type
    codegen.cfunc = SimpleNamespace(
        addr=0x1000, arg_list=(), statements=None,
        variables_in_use={array.variable: array}, unified_local_vars={},
    )
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN, bp_entry_sp_delta=-2,
            detail="push bp; mov bp, sp", stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        ),
    )
    record_stack_variable_coordinate_projection_8616(
        codegen, variable=array.variable, cvar=array,
        bp_offset=-18, entry_sp_offset=-20, size=16,
    )

    selected = materialize_call_argument_stack_cvariable_8616(
        codegen, {}, machine_bp_offset=-18, size_hint=2,
    )

    assert selected is array
    assert array.variable_type is original_type
    assert array.variable.size == 1
    assert machine_bp_offset_for_stack_variable_8616(codegen, array.variable) == -18


def test_unprojected_call_argument_keeps_raw_machine_bp_coordinate() -> None:
    """Refuse to invent an entry-SP projection without typed evidence."""
    codegen = _Codegen()
    raw = CVariable(
        SimStackVariable(-4, 1, base="bp", name="local_4"),
        codegen=codegen,
    )

    assert call_argument_stack_variable_offset_8616(codegen, raw) == -4


def test_missing_call_source_cvar_uses_proven_entry_sp_projection() -> None:
    """Create machine BP-2 at entry-SP -4 instead of inventing raw BP identity."""
    codegen = _Codegen()
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        arg_list=(),
        statements=None,
        variables_in_use={},
        unified_local_vars={},
    )
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="push bp; mov bp, sp",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )

    selected = stack_cvar_for_stable_ss_linear_access_8616(
        codegen,
        RealModeLinearStackAccess8616(-2, 2),
    )

    assert isinstance(selected, CVariable)
    assert selected.variable.offset == -4
    assert machine_bp_offset_for_stack_variable_8616(codegen, selected.variable) == -2


def test_snapshot_clone_recovers_bp_coordinate_from_alias_and_frame() -> None:
    """Recover a lost registry projection only when Alias selects one domain."""
    slot = IRAddress(
        MemSpace.SS,
        base=("bp",),
        offset=-2,
        size=2,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )
    source_ssa = build_x86_16_function_ssa(
        IRFunctionArtifact(
            function_addr=0x1000,
            blocks=(
                IRBlock(
                    addr=0x1000,
                    instrs=(
                        IRInstr(
                            "STORE",
                            None,
                            (slot, IRValue(MemSpace.CONST, const=1, size=2)),
                            size=2,
                        ),
                    ),
                ),
            ),
        )
    )
    codegen = _Codegen()
    codegen._inertia_stack_memory_ssa_alias_artifact = (
        build_x86_16_stack_memory_ssa_alias_artifact(source_ssa)
    )
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="push bp; mov bp, sp",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )
    snapshot_clone = SimStackVariable(-4, 2, base="bp", name="local_2")

    assert machine_bp_offset_for_stack_variable_8616(codegen, snapshot_clone) == -2


def test_projected_function_argument_is_not_an_outgoing_call_carrier() -> None:
    """Do not mistake angr entry-SP +2 for the function's machine BP+4 argument."""
    codegen = _Codegen()
    argument = CVariable(
        SimStackVariable(2, 2, base="bp", name="arg_4"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    record_stack_variable_coordinate_projection_8616(
        codegen,
        variable=argument.variable,
        cvar=argument,
        bp_offset=4,
        entry_sp_offset=2,
        size=2,
        display_name="arg_4",
    )

    assert outgoing_call_stack_carrier_offset_8616(codegen, argument) is None


def test_legacy_machine_bp_two_slot_remains_an_outgoing_call_carrier() -> None:
    """Keep legacy unprojected BP+2 call-setup carriers classified."""
    codegen = _Codegen()
    carrier = CVariable(
        SimStackVariable(2, 2, base="bp", name="stack_bp_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )

    assert outgoing_call_stack_carrier_offset_8616(codegen, carrier) == 2
