"""Declared semantic input keeps native CALLs and unproved effects explicit."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.ir.core import IRValue, MemSpace
from inertia.ir.declared_entry_pipeline import retain_declared_entry_pipeline_8616
from inertia.ir.entry_projection_mode import EntryProjectionMode8616
from inertia.semantics.call_stack_effect_contracts import CallStackEffectVerdict8616
from inertia.semantics.call_stack_effects import materialize_call_stack_effects_8616
from inertia.semantics.scoped_call_projection import ScopedCallSemanticInput8616, scoped_call_semantic_input_8616
from tests.frontend.test_declared_clinic_identity import _conversion


def _input() -> ScopedCallSemanticInput8616:
    """Build the production semantic request from a real declared entry."""
    clinic,entry=_conversion()
    consumer=SimpleNamespace()
    retain_declared_entry_pipeline_8616(consumer,entry)
    result=scoped_call_semantic_input_8616(clinic.project,consumer,entry.view.boundary,entry.bundle.artifact)
    assert result is not None
    return result


def test_declared_semantics_retains_raw_calls_and_unknown_effects() -> None:
    """Control transport supplies neither target rewrites nor stack proof."""
    result=_input()
    assert result.authenticate()
    assert result.projection_mode is EntryProjectionMode8616.CONTROL_ONLY
    assert all(a is b for a,b in zip(result.input_ir.blocks,result.source_ir.blocks,strict=True))
    effects=materialize_call_stack_effects_8616(result.input_ir,{},project=result.project)
    assert len(effects.facts)==2
    assert all(fact.verdict is CallStackEffectVerdict8616.UNKNOWN_REFUSE
               and not fact.effect.complete and not fact.effect.bp_preserved for fact in effects.facts)


@pytest.mark.parametrize("damage",["target","scope","native"])
def test_declared_semantic_input_reauthenticates_native_source(damage: str) -> None:
    """A retained declared projection cannot launder forged target or scope."""
    result=_input()
    assert result.authenticate()
    if damage=="target":
        blocks=[]
        for block in result.input_ir.blocks:
            rows=tuple(replace(row,args=(IRValue(MemSpace.CONST,const=0xdead,size=4),)) if row.op=="CALL" else row for row in block.instrs)
            blocks.append(replace(block,instrs=rows))
        result=replace(result,input_ir=replace(result.input_ir,blocks=tuple(blocks)))
    elif damage=="scope":
        result=replace(result,scope=replace(result.scope,project=object()))
    else:
        result.project.loader.memory.store(0x1043,b"\x90")
    assert not result.authenticate()


def test_projection_mode_cannot_be_forged_as_retained_state() -> None:
    """Mode is derived from typed authority, never a mutable caller assertion."""
    result=_input()
    with pytest.raises((AttributeError,TypeError)):
        object.__setattr__(result,"projection_mode",EntryProjectionMode8616.CALL_TARGETS)
    assert result.authenticate()
