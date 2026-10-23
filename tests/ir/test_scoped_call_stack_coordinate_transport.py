"""Scoped call-effect transport — copy, SSA and serialization controls.

The scoped coordinate carrier rides inside ``IRCallStackEffect8616`` as an
optional field: native detach must preserve the carrier's live authority
identities verbatim, the SSA effect-site collection must carry it through,
and serialized surfaces may show presence only — never authorize a delta.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from inertia.frontend.x86_16.lift_86_16 import Lifter86_16  # noqa: F401
from inertia.ir.core import IRBlock, IRCallStackEffect8616
from inertia.ir.native_copy_memo import (
    _detach_native_instr_8616,
    seed_native_copy_memo_8616,
)
from inertia.ir.real16_invocation_domain import (
    Real16InvocationDomain8616,
    _native_call_effect_equal_8616,
)
from inertia.ir.ssa_memory import _call_effect_sites_8616
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


def _world(ax_seed: int = 0):
    """Build one fixture world, its carrier, and the CALL-site objects."""
    parts = build_scoped_stack_parts_8616(ax_seed, CALLEE_LOOP)
    artifact = parts["caller_artifact"]
    call_block = None
    call_instr = None
    for block in cast(object, artifact).blocks:  # type: ignore[attr-defined]
        for instruction in block.instrs:
            if instruction.op == "CALL":
                call_block, call_instr = block, instruction
    assert call_block is not None and call_instr is not None
    summary = CallsiteSummary8616(
        callsite_addr=CALLSITE, target_addr=CALLEE, return_addr=RETURN_ADDR,
        kind="near", arg_count=0, arg_widths=(), stack_cleanup=None,
        return_register=None, return_used=None,
    )
    carrier = prove_scoped_call_stack_coordinates_8616(
        parts["project"], summary,
        instruction=call_instr, block=call_block,
        return_frame=ReturnSegmentFrame8616(callsite_addr=CALLSITE),
        caller_scope=cast(Real16InvocationDomain8616, parts["caller_domain"]),
        callee_scope=cast(Real16InvocationDomain8616, parts["callee_domain"]),
        coverage=cast(object, parts["coverage"]),  # type: ignore[arg-type]
    )
    assert carrier.failure is None
    return parts, call_instr, call_block, carrier


def _call_effect(carrier: object) -> IRCallStackEffect8616:
    """Attach the carrier to one typed call effect (universal fields empty)."""
    assert cast(object, carrier).coordinates is not None  # type: ignore[attr-defined]
    return IRCallStackEffect8616(
        stack_coordinates=cast(object, carrier).coordinates,  # type: ignore[attr-defined]
        scoped_coordinates=cast(object, carrier),  # type: ignore[arg-type]
    )


def test_native_copy_preserves_carrier_identity(tmp_path: Path) -> None:
    """Detach must share the immutable carrier, keeping live authority bound."""
    parts, call_instr, _block, carrier = _world()
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    effect = _call_effect(carrier)
    detached_instr = replace(call_instr, call_stack_effect=effect)
    memo = seed_native_copy_memo_8616(cast(tuple[IRBlock, ...], ()))
    clone = _detach_native_instr_8616(detached_instr, memo)
    cloned_effect = clone.call_stack_effect
    assert cloned_effect is not None
    assert cloned_effect.scoped_coordinates is carrier
    assert _native_call_effect_equal_8616(effect, cloned_effect, 0)
    changed = replace(cloned_effect, scoped_coordinates=replace(carrier, failure_count=999))
    assert not _native_call_effect_equal_8616(effect, changed, 0)
    assert not _native_call_effect_equal_8616(
        effect, replace(cloned_effect, scoped_coordinates=None), 0,
    )
    assert cloned_effect.scoped_net_stack_delta_for(caller, callee) == 0
    assert effect.scoped_net_stack_delta_for(caller, callee) == 0


def test_ssa_effect_site_carries_scoped_sibling(tmp_path: Path) -> None:
    """The SSA collector transports the scoped carrier inside the effect."""
    parts, call_instr, call_block, carrier = _world()
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    block = replace(
        call_block,
        instrs=tuple(
            replace(instr, call_stack_effect=_call_effect(carrier))
            if instr is call_instr else instr
            for instr in call_block.instrs
        ),
    )
    sites = _call_effect_sites_8616(cast(tuple[object, ...], (block,)))
    assert len(sites) == 1
    site = sites[0]
    assert site.effect.scoped_coordinates is carrier
    assert site.effect.scoped_net_stack_delta_for(caller, callee) == 0
    assert site.effect.current_net_stack_delta is None


def test_serialized_surface_grants_no_authority(tmp_path: Path) -> None:
    """to_dict may show presence; the serialized payload never projects."""
    parts, _instr, _block, carrier = _world()
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    effect = _call_effect(carrier)
    payload = effect.to_dict()
    assert payload["scoped_coordinates"] is not None
    assert payload["stack_coordinates"] is not None
    assert payload["current_net_stack_delta"] is None
    assert payload["net_stack_delta"] is None
    assert carrier.observed_return_sp_delta == 2  # retained diagnostic
    assert carrier.net_sp_delta_for(caller, callee) == 0
    empty = IRCallStackEffect8616()
    assert empty.scoped_coordinates is None
    assert empty.scoped_net_stack_delta_for(caller, callee) is None


def test_universal_effect_projection_unchanged(tmp_path: Path) -> None:
    """Context-free accessors on the effect ignore the scoped carrier."""
    parts, _instr, _block, carrier = _world()
    caller, callee = parts["caller_domain"], parts["callee_domain"]
    effect = _call_effect(carrier)
    assert effect.current_net_stack_delta is None
    assert effect.complete is False
    universal = IRCallStackEffect8616(net_stack_delta=0, complete=True)
    assert universal.scoped_net_stack_delta_for(caller, callee) is None
