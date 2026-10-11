from __future__ import annotations

import inertia.cli.cli_core as cli_core


def _stable_snapshot() -> dict[str, dict[str, object]]:
    return {
        "structuring": {"status": "stable", "changed": False},
        "postprocess": {"status": "stable", "changed": False},
    }


def test_generated_c_acceptance_rejects_address_taken_unresolved_temporary(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=("int *escaped = &vvar_18;\n\nvoid SwapBars(void)\n{\n}\n"),
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "validation_failed"
    assert result.blocker == "Final quality guard rejected emitted C (unresolved-vvar)."


def test_generated_c_acceptance_rejects_unresolved_temporaries_with_stable_validation(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    payload = "unsigned short escaped = vvar_18;\n\nvoid unknown_binary_function(void)\n{\n}\n"
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=payload,
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "validation_failed"
    assert result.blocker == "Final quality guard rejected emitted C (unresolved-vvar)."


def test_generated_c_acceptance_allows_declared_virtual_temporary(monkeypatch):
    monkeypatch.setattr(
        cli_core,
        "_collect_recompilation_payloads_8616",
        lambda accepted_payload: ([("portable-flat", accepted_payload)], None),
    )

    payload = "unsigned short f(void)\n{\n    unsigned short vvar_18;\n    vvar_18 = 7;\n    return vvar_18;\n}\n"
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok",
        payload=payload,
        tail_validation_snapshot=_stable_snapshot(),
        tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )

    assert result.status == "ok"
    assert result.blocker is None


import pytest

from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
    x86_16_tail_validation_snapshot_passed,
)
from tests.ir.test_declared_entry_scoped_view import native_scope as native_scope
from tests.validation.test_declared_entry_tail import attached as attached


@pytest.fixture
def conditional_snapshot(attached):
    project, codegen = attached
    summary = collect_x86_16_tail_validation_summary(project, codegen)
    result = compare_x86_16_tail_validation_summaries(summary, summary)
    import copy
    return {"structuring": result, "postprocess": copy.deepcopy(result)}


def test_conditional_c_keeps_compiler_checks_without_global_pass(monkeypatch, conditional_snapshot):
    calls = []
    def compile_payload(payload):
        calls.append(payload)
        return [("portable-flat", payload)], None
    monkeypatch.setattr(cli_core, "_collect_recompilation_payloads_8616", compile_payload)
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok", payload="int f(void) { return 4660; }\n",
        tail_validation_snapshot=conditional_snapshot, tail_validation_enabled=True,
        expected_validation_stages=("structuring", "postprocess"), emit_failure_diagnostics=False,
    )
    assert result.status == "conditional"
    assert result.blocker is None
    assert calls == [result.validated_payload]
    assert result.validated_payload_hash == result.gcc_checked_payload_hash
    assert not x86_16_tail_validation_snapshot_passed(conditional_snapshot)


@pytest.mark.parametrize("mutation", ["missing", "digest", "different", "changed", "refused", "semantic_failure", "relabeled_stable"])
def test_conditional_acceptance_refuses_incomplete_or_changed_premises(monkeypatch, conditional_snapshot, mutation):
    import copy

    from inertia.validation.declared_entry_premise import valid_entry_premise_projection_8616
    snapshot = copy.deepcopy(conditional_snapshot)
    stage = snapshot["postprocess"]
    if mutation == "relabeled_stable":
        for entry in snapshot.values():
            entry["status"] = "stable"
    elif mutation == "missing":
        del stage["entry_premise"]
    elif mutation == "digest":
        stage["entry_premise"]["sha256"] = "0" * 64
    elif mutation == "different":
        # A different retained receipt must not become a same-premise pair.
        stage["entry_premise"]["payload"]["domain"]["entry_segment"] += 1
        import hashlib
        import json
        stage["entry_premise"]["sha256"] = hashlib.sha256(
            json.dumps(stage["entry_premise"]["payload"], sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        assert valid_entry_premise_projection_8616(stage["entry_premise"])
    elif mutation == "changed":
        stage["changed"] = True
    elif mutation == "refused":
        stage["status"] = "refused"
    else:
        stage["semantic_failures"] = ["retained failure"]
    monkeypatch.setattr(cli_core, "_collect_recompilation_payloads_8616", lambda _: pytest.fail("invalid premise compiled"))
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok", payload="int f(void) { return 1; }\n", tail_validation_snapshot=snapshot,
        tail_validation_enabled=True, expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )
    assert result.status == "validation_failed"


@pytest.mark.parametrize("compiler", ["failed", "hash_mismatch", "empty"])
def test_conditional_c_does_not_bypass_recompilation(monkeypatch, conditional_snapshot, compiler):
    def compile_payload(payload):
        if compiler == "failed":
            return [], "compiler rejected C"
        if compiler == "empty":
            return [], None
        return [("portable-flat", payload + "/* changed */")], None
    monkeypatch.setattr(cli_core, "_collect_recompilation_payloads_8616", compile_payload)
    result = cli_core._validated_generated_c_acceptance_8616(
        status="ok", payload="int f(void) { return 1; }\n", tail_validation_snapshot=conditional_snapshot,
        tail_validation_enabled=True, expected_validation_stages=("structuring", "postprocess"),
        emit_failure_diagnostics=False,
    )
    assert result.status == "validation_failed"


def test_conditional_artifacts_keep_exact_hash_premises_and_nonzero_terminal(tmp_path, monkeypatch, conditional_snapshot, capsys):
    import hashlib
    import json
    from types import SimpleNamespace

    from inertia.cli.work_items import FunctionWorkResult, WorkItemStatus
    payload = "int f(void) { return 4660; }\n"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    function = SimpleNamespace(addr=0x1020, name="f")
    result = FunctionWorkResult(index=1, status=WorkItemStatus.CONDITIONAL, payload=payload,
        debug_output="", function=function, function_cfg=None, tail_validation=conditional_snapshot,
        validated_payload_hash=digest, gcc_checked_payload_hash=digest)
    args = SimpleNamespace(output_c_dir=tmp_path)
    assert cli_core._emit_conditional_result_8616(result, args=args) == 5
    generated = tmp_path / "conditional" / "00001020-f.c"
    receipt = json.loads(generated.with_suffix(".json").read_text())
    assert generated.read_text() == payload
    assert receipt["payload_sha256"] == digest
    assert receipt["tail_validation"] == json.loads(json.dumps(conditional_snapshot))
    assert receipt["status"] == "conditional" and receipt["merge_gate"] == "hold"
    assert not (tmp_path / "00001020-f.c").exists()
    assert '"status": "conditional"' in capsys.readouterr().err
    # The direct terminal route must precede every fallback and cache path.
    owner = SimpleNamespace(direct_result=result, direct_project=object(), args=args)
    monkeypatch.delenv("INERTIA_SERIAL_CLEAN_WORKER_RESULT", raising=False)
    monkeypatch.setattr(cli_core, "_complete_serial_clean_worker_result_8616", lambda *a, **kw: False)
    assert cli_core._DirectAddrCliRun8616.run_8616_part5_8616_b1(owner) == 5


@pytest.mark.parametrize("mutation", ["payload", "compiler_hash", "premise"])
def test_conditional_artifact_writer_refuses_stale_evidence(tmp_path, conditional_snapshot, mutation):
    import copy
    import hashlib

    from inertia.cli.generated_c_artifacts import write_conditional_function_c_8616
    payload = "int f(void) { return 1; }\n"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    snapshot = copy.deepcopy(conditional_snapshot)
    compiler_hash = digest
    if mutation == "payload":
        payload += "/* stale */"
    elif mutation == "compiler_hash":
        compiler_hash = "0" * 64
    else:
        del snapshot["postprocess"]["entry_premise"]
    with pytest.raises(ValueError, match="intact premises"):
        write_conditional_function_c_8616(tmp_path, address=0x1020, name="f", payload=payload,
            snapshot=snapshot, validated_payload_hash=digest, gcc_checked_payload_hash=compiler_hash)
    assert not list(tmp_path.rglob("*.c"))


def test_conditional_display_and_legacy_rewrite_keep_status(conditional_snapshot):
    from inertia.cli.cli_decompilation import _tail_validation_snapshot_failed_for_cli_rewrite_8616
    from inertia.cli.tail_validation import tail_validation_display_status
    from inertia.cli.work_items import WorkItemStatus, _tail_validation_to_item_status
    assert tail_validation_display_status(conditional_snapshot) == "conditional"
    assert _tail_validation_to_item_status("conditional") is WorkItemStatus.CONDITIONAL
    assert not _tail_validation_snapshot_failed_for_cli_rewrite_8616(conditional_snapshot)


def test_conditional_artifact_serializes_receipt_before_writing_c(tmp_path, conditional_snapshot):
    import hashlib

    from inertia.cli.generated_c_artifacts import write_conditional_function_c_8616
    payload = "int f(void) { return 1; }\n"
    digest = hashlib.sha256(payload.encode()).hexdigest()
    conditional_snapshot["unserializable"] = object()
    with pytest.raises(TypeError):
        write_conditional_function_c_8616(tmp_path, address=0x1020, name="f", payload=payload,
            snapshot=conditional_snapshot, validated_payload_hash=digest, gcc_checked_payload_hash=digest)
    assert not list(tmp_path.rglob("*.c"))


@pytest.mark.parametrize("statuses", [("conditional",), ("ok", "conditional")])
def test_conditional_batch_terminal_is_nonzero_and_never_counts_as_accepted(monkeypatch, statuses):
    from pathlib import Path
    from types import SimpleNamespace

    from inertia.cli.work_items import FunctionWorkItem, FunctionWorkResult
    function = SimpleNamespace(addr=0x1020, name="f")
    tasks = [FunctionWorkItem(index=i, function=function, function_cfg=None) for i in range(len(statuses))]
    results = {i: FunctionWorkResult(index=i, function=function, function_cfg=None, status=status,
        payload=f"int f{i}(void) {{ return 1; }}", debug_output="") for i, status in enumerate(statuses)}
    args = SimpleNamespace(max_functions=0, addr=None, output_c_dir=None, binary=Path("sample.exe"))
    context = SimpleNamespace(args=args, project=object(), function_tasks=tasks, result_map=results,
        fallback_tail_validation_by_index={}, lst_metadata=None, shown_total=len(tasks), skipped_signature_labels=0)
    monkeypatch.setattr(cli_core, "_emit_pending_batch_results_8616", lambda *a: (0, 0))
    monkeypatch.setattr(cli_core, "attach_segment_program_layout_8616", lambda *a: None)
    monkeypatch.setattr(cli_core, "_source_region_catalog_evidence_8616", lambda *a: None)
    monkeypatch.setattr(cli_core, "_emit_tail_validation_console_summary", lambda *a, **kw: None)
    monkeypatch.setattr(cli_core, "emit_file_decompilation_summary", lambda *a, **kw: None)
    monkeypatch.setattr(cli_core, "_timing_output_enabled", lambda: False)
    observed = []
    real_build = cli_core.build_batch_c_output_8616
    def build(payloads, **kwargs):
        observed.extend(payloads)
        return real_build(payloads, **kwargs)
    monkeypatch.setattr(cli_core, "build_batch_c_output_8616", build)
    assert cli_core._finish_batch_cli_8616(context, decompiled=statuses.count("ok"), failed=0, emitted_indexes=set(results)) == 5
    assert observed == [results[i].payload for i, status in enumerate(statuses) if status == "ok"]
    assert len(results) == len(tasks)
