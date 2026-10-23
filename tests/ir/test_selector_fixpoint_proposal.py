"""Fixpoint selector proposals need one fresh final native authentication."""
import sys
from types import SimpleNamespace

import pytest

from inertia.ir import entry_jump_domain as owner
from inertia.ir.declared_entry_pipeline import DeclaredEntryPipeline8616, prepare_declared_entry_pipeline_8616
from inertia.pipeline.errors import PipelineHardError
from tests.ir.test_forward_declared_call_scope import _forward_world

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize('damage', [None, 'record', 'native'])
def test_native_selector_proposal_is_sealed_after_transfer_callbacks(damage: str | None) -> None:
    world = _forward_world(helper_bytes=b'\x90', caller_bytes=bytes.fromhex('b83412e82a00') + b'\x90' * 20 + bytes.fromhex('ebe4'))
    project = world[0]
    batches = []
    changed = []

    def observe(code, offset, result):
        frame = sys._getframe(1)
        if code is owner._selector_call_batch_8616.__code__:
            batches.append(frame.f_back.f_code.co_name)
        elif not changed:
            run = frame.f_locals['self']
            assert run.call_preservations
            changed.append(True)
            if damage == 'record':
                object.__setattr__(run.call_preservations[0], 'failure_count', 1)
            elif damage == 'native':
                project.loader.memory.store(0x1070, b'\x90')

    codes = (owner._selector_call_batch_8616.__code__, owner._ProofRun8616._native_transfer_binding_8616.__code__)
    sys.monitoring.use_tool_id(4, 'selector-fixpoint-proposal')
    sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, observe)
    for code in codes:
        sys.monitoring.set_local_events(4, code, sys.monitoring.events.PY_RETURN)
    try:
        if damage is None:
            entry = prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), 0x1040)
            assert isinstance(entry, DeclaredEntryPipeline8616)
            assert entry.view.failure is None
        else:
            with pytest.raises(PipelineHardError, match='scoped CFG is unproved'):
                prepare_declared_entry_pipeline_8616(project, SimpleNamespace(), 0x1040)
    finally:
        for code in codes:
            sys.monitoring.set_local_events(4, code, 0)
        sys.monitoring.register_callback(4, sys.monitoring.events.PY_RETURN, None)
        sys.monitoring.free_tool_id(4)
    assert changed
    # Exactly one solver-view batch; other application consumers stay fresh.
    assert batches.count('_call_preservation_view_8616') == 1
