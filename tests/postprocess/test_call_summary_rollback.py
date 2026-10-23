"""Exact call occurrence provenance survives owned AST rollback."""

import pytest
from angr.analyses.decompiler.structured_codegen.c import CFunctionCall

from inertia.postprocess.decompiler_postprocess_stage import (
    _restore_codegen_cfunc,
    _restore_codegen_inertia_metadata_8616,
    _snapshot_codegen_cfunc,
    _snapshot_codegen_inertia_metadata_8616,
)
from tests.structuring.test_x86_16_call_return_conditions import _summary, _surface


class SharedCall(CFunctionCall):
    def __deepcopy__(self, memo):
        return self


@pytest.mark.parametrize("shared", [False, True])
@pytest.mark.parametrize("count", [1, 2])
def test_rollback_rekeys_exact_occurrences_repeatedly(shared, count):
    _, codegen, _ = _surface()
    codegen.cfunc.codegen = codegen
    summary = _summary()
    cls = SharedCall if shared else CFunctionCall
    calls = [cls("unresolved", None, [], codegen=codegen,
                 tags={"ins_addr": summary.callsite_addr}) for _ in range(count)]
    codegen.cfunc.statements.statements = calls
    stale = CFunctionCall("unresolved", None, [], codegen=codegen)
    codegen._inertia_callsite_summaries = {id(call): summary for call in calls}
    codegen._inertia_callsite_summaries[id(stale)] = summary
    snapshot = _snapshot_codegen_cfunc(codegen)
    metadata = _snapshot_codegen_inertia_metadata_8616(codegen)
    for _ in range(2):
        assert _restore_codegen_cfunc(codegen, snapshot)
        _restore_codegen_inertia_metadata_8616(codegen, metadata)
        restored = codegen.cfunc.statements.statements
        assert codegen._inertia_callsite_summaries == {id(call): summary for call in restored}
        assert all((left is right) == shared for left, right in zip(calls, restored, strict=True))
        assert not any("rollback_call" in key for key in codegen.cfunc.statements.tags)


def test_repeated_restore_does_not_admit_removed_clone():
    _, codegen, _ = _surface()
    codegen.cfunc.codegen = codegen
    call = CFunctionCall("unresolved", None, [], codegen=codegen)
    codegen.cfunc.statements.statements = [call]
    codegen._inertia_callsite_summaries = {id(call): _summary()}
    snapshot = _snapshot_codegen_cfunc(codegen)
    metadata = _snapshot_codegen_inertia_metadata_8616(codegen)
    assert _restore_codegen_cfunc(codegen, snapshot)
    _restore_codegen_inertia_metadata_8616(codegen, metadata)
    snapshot.statements.statements.clear()
    _restore_codegen_inertia_metadata_8616(codegen, metadata)
    assert codegen._inertia_callsite_summaries == {}


def test_wrong_root_does_not_rebind_old_metadata():
    _, codegen, _ = _surface()
    codegen.cfunc.codegen = codegen
    call = CFunctionCall("unresolved", None, [], codegen=codegen)
    codegen.cfunc.statements.statements = [call]
    codegen._inertia_callsite_summaries = {id(call): _summary()}
    snapshot = _snapshot_codegen_cfunc(codegen)
    metadata = _snapshot_codegen_inertia_metadata_8616(codegen)
    assert _restore_codegen_cfunc(codegen, snapshot)
    _restore_codegen_inertia_metadata_8616(codegen, metadata)
    second = _snapshot_codegen_cfunc(codegen)
    second_metadata = _snapshot_codegen_inertia_metadata_8616(codegen)
    assert _restore_codegen_cfunc(codegen, second)
    _restore_codegen_inertia_metadata_8616(codegen, second_metadata)
    live_call = second.statements.statements[0]
    assert codegen._inertia_callsite_summaries == {id(live_call): _summary()}
    assert not any("rollback_call" in key for key in second.statements.tags)
    _restore_codegen_inertia_metadata_8616(codegen, metadata)
    assert id(live_call) not in codegen._inertia_callsite_summaries
