from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from inertia_decompiler import cli_core
from inertia_decompiler.cli_semantic_rollback import (
    TrustedCoreSnapshot8616,
    rollback_final_semantic_drift_8616,
    snapshot_trusted_cfunc_8616,
)
from inertia_decompiler.sidecar_metadata import LSTMetadata


@pytest.mark.parametrize("before,after,named_guard,copies,expected", [
    ([], [], False, 0, []),
    ([], ["new"], False, 0, ["new"]),
    (["call"], [], False, 1, ["call"]),
    ([], [], True, 1, []),
    (["needed"], ["other"], True, 1, ["needed"]),
])
def test_rewrite_call_loss_snapshot_requires_calls_or_named_guard(
    monkeypatch, before, after, named_guard, copies, expected,
):
    """Skip zero-risk copies, but retain actual call-loss and named-call rollback."""
    from inertia_decompiler import cli_decompilation

    calls = list(before)
    snapshots = []

    def snapshot():
        saved = list(calls)
        snapshots.append(saved)
        return saved

    def restore(saved):
        calls[:] = saved
        return True

    def rewrite():
        calls[:] = after
        return True

    state = SimpleNamespace(
        current_func_addr=0x10000, function=SimpleNamespace(addr=0x10000, name="probe"),
        pass_name="test", call_loss_guard_active=True, expected_call_guard_active=named_guard,
        _codegen_call_expr_count=lambda: len(calls),
        _missing_expected_call_names_from_codegen_counts=lambda: [] if "needed" in calls else ["needed"],
        _snapshot_codegen_cfunc=snapshot, _restore_codegen_cfunc=restore,
        _run_stack_lowering_pass=object(), _stack_lowering_already_attempted=False,
        iter_changed=False, dec=SimpleNamespace(codegen=None),
    )
    state._rewrite_round_guarded_evidence_8616 = lambda index, changed: (
        cli_decompilation._DecompileRun8616._rewrite_round_guarded_evidence_8616(state, index, changed)
    )
    monkeypatch.setattr(cli_decompilation, "_debug_dump_rewrite_pass_lines_8616", lambda *a, **kw: None)
    monkeypatch.setattr(cli_decompilation, "function_original_addr", lambda function: function.addr)
    cli_decompilation._DecompileRun8616._rewrite_round_apply_8616(state, rewrite, 0, 0)
    assert len(snapshots) == copies
    assert calls == expected
    assert state.call_loss_guard_active is True


@dataclass(frozen=True)
class _Report:
    failures: dict[str, object]

    def semantic_failures(self) -> dict[str, object]:
        return self.failures


class _MutatingVariableManager:
    def __init__(self, manager: SimpleNamespace) -> None:
        self.manager = manager
        self.types = SimpleNamespace(_kb=manager._kb)

    def __getstate__(self) -> dict[str, object]:
        state = {"manager": None, "types": self.types}
        self.types._kb = None
        return state

    def __setstate__(self, state: dict[str, object]) -> None:
        self.__dict__.update(state)

    def set_manager(self, manager: SimpleNamespace) -> None:
        self.manager = manager
        self.types._kb = manager._kb


def test_trusted_snapshot_preserves_angr_variable_manager_bindings() -> None:
    kb = object()
    manager = SimpleNamespace(_kb=kb)
    live_manager = _MutatingVariableManager(manager)
    cfunc = SimpleNamespace(variable_manager=live_manager, statements=["trusted"])

    snapshot = snapshot_trusted_cfunc_8616(cfunc)

    assert snapshot is not None
    assert live_manager.types._kb is kb
    snapshot_manager = snapshot.variable_manager
    assert snapshot_manager is not live_manager
    assert snapshot_manager.manager is manager
    assert snapshot_manager.types._kb is kb


def test_semantic_rollback_restores_and_revalidates_trusted_core() -> None:
    project = SimpleNamespace(_inertia_last_tail_validation_snapshot={"postprocess": "failed"})
    codegen = SimpleNamespace(
        cfunc="mutated",
        _inertia_tail_validation_snapshot={"postprocess": "failed"},
    )
    trusted = TrustedCoreSnapshot8616(
        cfunc="trusted",
        tail_validation_snapshot={"postprocess": {"status": "stable"}},
    )
    reports = iter((_Report({"def_use": ("v9",)}), _Report({})))
    replayed: list[object] = []

    def refresh(_project: object, _codegen: object) -> _Report:
        return next(reports)

    def restore(cfunc: object) -> bool:
        codegen.cfunc = cfunc
        return True

    changed = rollback_final_semantic_drift_8616(
        project,
        codegen,
        trusted,
        refresh_validation=refresh,
        restore_cfunc=restore,
        replay_projections=lambda active_codegen: not replayed.append(active_codegen.cfunc),
        function_addr=0x10678,
    )

    assert changed is True
    assert codegen.cfunc == "trusted"
    assert codegen._inertia_tail_validation_snapshot == trusted.tail_validation_snapshot
    assert codegen._inertia_tail_validation_snapshot is not trusted.tail_validation_snapshot
    assert project._inertia_last_tail_validation_snapshot == trusted.tail_validation_snapshot
    assert codegen._inertia_codegen_decl_refresh_required_8616 is True
    assert codegen._inertia_force_codegen_regeneration_8616 is True
    assert replayed == ["trusted"]


def test_semantic_rollback_rejects_invalid_snapshot_transactionally() -> None:
    project = SimpleNamespace(_inertia_last_tail_validation_snapshot={"current": "passed"})
    codegen = SimpleNamespace(
        cfunc="current",
        _inertia_tail_validation_snapshot={"current": "passed"},
    )
    trusted = TrustedCoreSnapshot8616(
        cfunc="invalid-trusted",
        tail_validation_snapshot={"structuring": {"status": "stable"}},
    )
    reports = iter(
        (
            _Report({"required_memory_effects": ("lost-write",)}),
            _Report({"def_use": ("virtual-carrier:v324",)}),
        )
    )
    replayed: list[object] = []

    def restore(cfunc: object) -> bool:
        codegen.cfunc = cfunc
        return True

    changed = rollback_final_semantic_drift_8616(
        project,
        codegen,
        trusted,
        refresh_validation=lambda _project, _codegen: next(reports),
        restore_cfunc=restore,
        replay_projections=lambda active_codegen: not replayed.append(active_codegen.cfunc),
        function_addr=0x10678,
    )

    assert changed is False
    assert codegen.cfunc == "current"
    assert codegen._inertia_tail_validation_snapshot == {"current": "passed"}
    assert project._inertia_last_tail_validation_snapshot == {"current": "passed"}
    assert replayed == ["invalid-trusted", "current"]


def test_semantic_rollback_leaves_clean_ast_unchanged() -> None:
    project = SimpleNamespace()
    codegen = SimpleNamespace(cfunc="current")
    restore_calls: list[object] = []

    changed = rollback_final_semantic_drift_8616(
        project,
        codegen,
        None,
        refresh_validation=lambda _project, _codegen: _Report({}),
        restore_cfunc=lambda cfunc: not restore_calls.append(cfunc),
        function_addr=0x10678,
    )

    assert changed is False
    assert restore_calls == []
    assert codegen.cfunc == "current"


@pytest.mark.parametrize("metadata_available", (False, True))
def test_x86_retry_falls_back_to_pure_binary_clean_worker(
    monkeypatch,
    tmp_path,
    capsys,
    metadata_available: bool,
) -> None:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"), _inertia_c_target="portable-flat")
    function = SimpleNamespace(addr=0x10C18, name="ShellSort", project=project)
    item = cli_core.FunctionWorkItem(index=9, function_cfg=SimpleNamespace(), function=function)
    metadata = (
        LSTMetadata(data_labels={}, code_labels={}, absolute_addrs=True)
        if metadata_available
        else None
    )
    args = SimpleNamespace(
        binary=binary,
        timeout=60,
        api_style="default",
        alternate_source_c=True,
        output_c_dir=None,
    )
    failed_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "changed", "changed": True},
    }
    clean_snapshot = {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }
    clean_calls: list[tuple[object, cli_core.FunctionWorkItem, dict[str, object]]] = []

    monkeypatch.setattr(cli_core, "_direct_addr_use_fork_lane_8616", lambda **_kwargs: False)
    monkeypatch.setattr(cli_core, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())
    monkeypatch.setattr(cli_core, "_fresh_sidecar_retry_work_item_8616", lambda **_kwargs: item)
    monkeypatch.setattr(
        cli_core,
        "_run_function_work_item",
        lambda work_item, **_kwargs: cli_core.FunctionWorkResult(
            index=work_item.index,
            status="validation_failed",
            payload="sidecar candidate failed validation",
            partial_payload="short ShellSort(void) { return 0; }",
            debug_output="",
            function=work_item.function,
            function_cfg=work_item.function_cfg,
            tail_validation=failed_snapshot,
        ),
    )

    def _clean_worker(context, clean_item, **kwargs):
        clean_calls.append((context, clean_item, kwargs))
        return cli_core.FunctionWorkResult(
            index=clean_item.index,
            status="ok",
            payload="short sub_10c18(void) { return 0; }",
            debug_output="",
            function=clean_item.function,
            function_cfg=clean_item.function_cfg,
            tail_validation=clean_snapshot,
        )

    monkeypatch.setattr(cli_core, "_run_serial_clean_process_work_item_8616", _clean_worker)
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda payload: ([("portable-flat", payload)], None),
    )

    ok = cli_core._try_emit_retry_recovered_candidate_8616(
        item=item,
        function=function,
        project=project,
        args=args,
        lst_metadata=metadata,
        cod_metadata=None,
        synthetic_globals=None,
    )

    assert ok is True
    assert len(clean_calls) == 1
    assert clean_calls[0][1].recovery_addr == 0x10C18
    assert clean_calls[0][2]["timeout"] == 60
    assert "short sub_10c18(void)" in capsys.readouterr().out
