"""Final output-directory records preserve existing worker result semantics."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from inertia.cli import cli_core

pytestmark = pytest.mark.decompiler


@pytest.mark.parametrize("status", ["conditional", "validation_failed", "timeout"])
def test_final_output_record_retains_nonpassing_status(tmp_path, monkeypatch, status):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x1234, name="subject", project=project)
    item = cli_core.FunctionWorkItem(1, None, function)
    result = cli_core.FunctionWorkResult(1, status, "owned payload", "", function, None)
    args = SimpleNamespace(output_c_dir=tmp_path, show_asm=False)
    monkeypatch.setattr(cli_core, "_accept_function_work_result_for_emission_8616", lambda result, **kwargs: result)
    monkeypatch.setattr(cli_core, "_emit_conditional_result_8616", lambda *args, **kwargs: 5)
    monkeypatch.setattr(cli_core, "_emit_retry_gate_candidate_8616", lambda *args, **kwargs: False)
    def stdout_only_fallback(**kwargs):
        print("int unrelated_fallback(void) { return 0; }")
        return 1, 0
    monkeypatch.setattr(cli_core, "_emit_function_result_fallback_lanes_8616", stdout_only_fallback)
    cli_core._emit_function_result(
        item, result, project=project, args=args, lst_metadata=None, cod_metadata=None,
        synthetic_globals=None, precise_sidecar_regions=False, allow_heavy_fallbacks=False,
        interactive_stdout=False, use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )
    restored = cli_core._read_serial_clean_worker_result_8616(
        tmp_path / "00001234.result.json", item=item, debug_output="",
    )
    assert restored.status == status
    assert restored.payload == result.payload


def test_final_output_record_selects_retained_retry(tmp_path, monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(addr=0x1234, name="subject", project=project)
    item = cli_core.FunctionWorkItem(1, None, function)
    initial = cli_core.FunctionWorkResult(1, "timeout", "old attempt", "", function, None)
    retry = replace(initial, status="ok", payload="final owned retry")
    args = SimpleNamespace(output_c_dir=tmp_path, show_asm=False)
    monkeypatch.setattr(cli_core, "_accept_function_work_result_for_emission_8616", lambda result, **kwargs: result)
    def retain_retry(*args):
        args[-1][item.index] = retry
        return True
    monkeypatch.setattr(cli_core, "_emit_retry_gate_candidate_8616", retain_retry)
    cli_core._emit_function_result(
        item, initial, project=project, args=args, lst_metadata=None, cod_metadata=None,
        synthetic_globals=None, precise_sidecar_regions=False, allow_heavy_fallbacks=False,
        interactive_stdout=False, use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )
    restored = cli_core._read_serial_clean_worker_result_8616(
        tmp_path / "00001234.result.json", item=item, debug_output="",
    )
    assert restored.status == "ok" and restored.payload == retry.payload
