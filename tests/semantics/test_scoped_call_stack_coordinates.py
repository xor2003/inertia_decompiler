"""Scoped call-stack coordinate carrier — native declared-context controls.

The carrier binds the universal physical coordinate record to the dual-scope
call effect. ``net_sp_delta_for(caller_scope, callee_scope)`` is the only
projection path: signed16(body_delta - return_frame_bytes), so AX=0 yields
net 0 and AX=4 yields net -4. Context-free fields keep universal meaning.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import angr
import pytest

from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.core import IRBlock, IRInstr
from inertia.ir.real16_invocation_domain import Real16InvocationDomain8616
from inertia.ir.scoped_call_stack_coordinates import (
    ScopedCallStackCoordinateFailure8616,
    prove_scoped_ir_call_stack_coordinates_8616,
)
from inertia.semantics.call_return_segment import ReturnSegmentFrame8616
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.semantics.scoped_call_stack_coordinates import (
    prove_scoped_call_stack_coordinates_8616,
)
from tests.support.scoped_stack_fixture import (
    CALLEE,
    CALLEE_LOOP,
    CALLSITE,
    RETURN_ADDR,
    build_scoped_stack_parts_8616,
)

pytestmark = pytest.mark.decompiler


def _call_site(artifact: object) -> tuple[IRInstr, IRBlock]:
    """Locate the exact decoded CALL instruction and its owning block."""
    for block in cast(object, artifact).blocks:  # type: ignore[attr-defined]
        for instruction in block.instrs:
            if instruction.op == "CALL":
                return instruction, block
    raise AssertionError("fixture caller must contain one CALL row")


def _summary() -> CallsiteSummary8616:
    """Build the exact callsite summary for the fixture's near CALL."""
    return CallsiteSummary8616(
        callsite_addr=CALLSITE, target_addr=CALLEE, return_addr=RETURN_ADDR,
        kind="near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )


def _carrier(ax_seed: int):
    """Produce the full scoped carrier for one declared world."""
    parts = build_scoped_stack_parts_8616(ax_seed, CALLEE_LOOP)
    instruction, block = _call_site(parts["caller_artifact"])
    carrier = prove_scoped_call_stack_coordinates_8616(
        parts["project"], _summary(),
        instruction=instruction, block=block,
        return_frame=ReturnSegmentFrame8616(callsite_addr=CALLSITE),
        caller_scope=cast(Real16InvocationDomain8616, parts["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts["callee_domain"]),
        coverage=cast(object, parts["coverage"]),  # type: ignore[arg-type]
    )
    return parts, carrier


def test_net_zero_under_ax0(tmp_path: Path) -> None:
    """AX=0 body delta +2 minus near frame 2 yields net 0."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.failure is None
    assert carrier.net_sp_delta_for(caller, callee) == 0
    assert carrier.has_proven_sp_delta_for(caller, callee) is True


def test_net_minus_four_under_ax4(tmp_path: Path) -> None:
    """AX=4 body delta -2 minus frame 2 yields net -4; no hardcode."""
    parts, carrier = _carrier(4)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.failure is None
    assert carrier.net_sp_delta_for(caller, callee) == -4


def test_absent_and_foreign_scopes_refuse(tmp_path: Path) -> None:
    """Missing or foreign scopes yield None, never a numeric fallback."""
    parts_a, carrier_a = _carrier(0)
    caller_a, callee_a = parts_a["caller_domain"], parts_a["callee_domain"]
    parts_b = build_scoped_stack_parts_8616(0, CALLEE_LOOP)
    assert carrier_a.net_sp_delta_for(None, callee_a) is None
    assert carrier_a.net_sp_delta_for(caller_a, None) is None
    assert carrier_a.net_sp_delta_for(None, None) is None
    assert carrier_a.net_sp_delta_for(
        parts_b["caller_domain"], callee_a) is None
    assert carrier_a.net_sp_delta_for(
        caller_a, parts_b["callee_domain"]) is None
    assert carrier_a.complete_for(parts_b["caller_domain"], callee_a) is False


def test_context_free_fields_never_inherit_scoped_value(tmp_path: Path) -> None:
    """The universal record must not gain a conditional net delta."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.net_sp_delta_for(caller, callee) == 0
    assert carrier.complete is False
    assert carrier.coordinates is not None
    assert carrier.coordinates.net_sp_delta is None
    assert carrier.coordinates.has_proven_sp_delta is False
    payload = carrier.to_dict()
    assert payload["kind"] == "scoped_call_stack_coordinates"


def test_conflicting_carrier_coordinates_refuse(tmp_path: Path) -> None:
    """A retained record disagreeing with the effect must refuse."""
    _parts, carrier = _carrier(0)
    assert carrier.failure is None and carrier.coordinates is not None
    effect = carrier.effect
    assert effect is not None
    shifted = replace(carrier.coordinates, callsite_addr=CALLSITE + 1)
    refused = prove_scoped_ir_call_stack_coordinates_8616(shifted, effect)
    assert refused.failure is ScopedCallStackCoordinateFailure8616.COORDINATE_CONFLICT
    wrong_frame = replace(carrier.coordinates, return_frame_bytes=4)
    refused2 = prove_scoped_ir_call_stack_coordinates_8616(wrong_frame, effect)
    assert refused2.failure is ScopedCallStackCoordinateFailure8616.COORDINATE_CONFLICT
    no_frame = replace(carrier.coordinates, return_frame_bytes=None)
    refused3 = prove_scoped_ir_call_stack_coordinates_8616(no_frame, effect)
    assert refused3.failure is ScopedCallStackCoordinateFailure8616.FRAME_UNPROVEN


def test_retained_byte_mutation_revokes_projection(tmp_path: Path) -> None:
    """Original-surface drift after proof revokes the scoped projection."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.net_sp_delta_for(caller, callee) == 0
    project = cast(angr.Project, parts["project"])
    project.loader.memory.store(0x1076, b"\x2b\xd9")
    assert bytes(project.loader.memory.load(0x1076, 2)) == b"\x2b\xd9"
    assert carrier.net_sp_delta_for(caller, callee) is None
    assert carrier.complete_for(caller, callee) is False

    parts_b, carrier_b = _carrier(0)
    caller_b, callee_b = parts_b["caller_domain"], parts_b["callee_domain"]
    assert carrier_b.net_sp_delta_for(caller_b, callee_b) == 0
    project_b = cast(angr.Project, parts_b["project"])
    project_b.loader.memory.store(0x1021, b"\x07\x00")
    assert carrier_b.net_sp_delta_for(caller_b, callee_b) is None



def test_replaced_physical_coordinates_revoke_accessor() -> None:
    """A frozen carrier replaced with conflicting coordinates must recheck them."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.net_sp_delta_for(caller, callee) == 0
    coordinates = carrier.coordinates
    assert coordinates is not None
    for changed in (
        replace(coordinates, return_frame_bytes=4),
        replace(coordinates, callsite_addr=CALLSITE + 1),
        replace(coordinates, return_addr=RETURN_ADDR + 1),
    ):
        forged = replace(carrier, coordinates=changed)
        assert forged.complete_for(caller, callee) is False
        assert forged.net_sp_delta_for(caller, callee) is None


def test_replaced_coordinate_source_revoke_accessor() -> None:
    """The source inputs must reproduce the retained physical record on access."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.net_sp_delta_for(caller, callee) == 0
    coordinates = carrier.coordinates
    assert coordinates is not None and coordinates.source is not None
    source = coordinates.source
    changed_source = replace(source, summary=replace(source.summary, return_addr=RETURN_ADDR + 1))
    forged = replace(carrier, coordinates=replace(coordinates, source=changed_source))
    assert forged.complete_for(caller, callee) is False
    assert forged.net_sp_delta_for(caller, callee) is None


def test_replaced_coordinate_census_revoke_accessor() -> None:
    """A retained physical record needs its own closed census as well as scope."""
    parts, carrier = _carrier(0)
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    assert carrier.net_sp_delta_for(caller, callee) == 0
    assert carrier.coordinates is not None
    changed = replace(carrier.coordinates, failure_count=999)
    forged = replace(carrier, coordinates=changed)
    assert forged.complete_for(caller, callee) is False
    assert forged.net_sp_delta_for(caller, callee) is None
