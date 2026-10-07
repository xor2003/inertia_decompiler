from __future__ import annotations

from types import SimpleNamespace

import pytest

import decompile


@pytest.mark.parametrize(
    ("direct_addr", "payload_is_emitted"),
    ((None, False), (0x10010, True)),
)
def test_accepted_function_payload_is_deferred_only_for_batch_output(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
    direct_addr: int | None,
    payload_is_emitted: bool,
) -> None:
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        _inertia_tail_validation_enabled=False,
    )
    function = SimpleNamespace(addr=0x10010, name="sub_10010", project=project)
    item = decompile.FunctionWorkItem(
        index=1,
        function_cfg=SimpleNamespace(),
        function=function,
    )
    payload = "int sub_10010(void) { return 0; }"
    result = decompile.FunctionWorkResult(
        index=item.index,
        status="ok",
        payload=payload,
        debug_output="",
        function=function,
        function_cfg=item.function_cfg,
        tail_validation={},
    )
    args = SimpleNamespace(
        addr=direct_addr,
        show_asm=False,
        binary=tmp_path / "sample.exe",
        alternate_source_c=False,
        output_c_dir=None,
    )
    monkeypatch.setattr(
        decompile,
        "_collect_recompilation_payloads_8616",
        lambda accepted: ([('portable-flat', accepted), ('msc-dos', accepted)], None),
    )

    decompiled, failed = decompile._emit_function_result(
        item,
        result,
        project=project,
        args=args,
        lst_metadata=None,
        cod_metadata=None,
        synthetic_globals=None,
        precise_sidecar_regions=False,
        allow_heavy_fallbacks=False,
        interactive_stdout=False,
        use_serial_fork_per_function=False,
        fallback_tail_validation_by_index={},
    )

    output = capsys.readouterr().out
    assert (decompiled, failed) == (1, 0)
    assert (payload in output) is payload_is_emitted
