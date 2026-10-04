from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli_core
from inertia_decompiler.sidecar_metadata import attach_lst_metadata_to_project
from inertia_decompiler.x86_16_exact_slice import mark_function_original_addr


def test_isolated_project_recovery_target_uses_original_addr_for_rebased_slice():
    function = SimpleNamespace(addr=0x1000, info={})
    mark_function_original_addr(function, 0x10010)
    isolated_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x13FFF))
    )

    candidate_addr, image_end = cli_core._isolated_project_recovery_target_8616(
        function,
        isolated_project,
        fallback_max_addr=0x104D,
    )

    assert candidate_addr == 0x10010
    assert image_end == 0x14000


def test_isolated_project_recovery_target_uses_absolute_inclusive_max_addr():
    function = SimpleNamespace(addr=0x1000, info={"inertia_original_addr": 0x10010})
    isolated_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0x14000))
    )

    candidate_addr, image_end = cli_core._isolated_project_recovery_target_8616(
        function,
        isolated_project,
        fallback_max_addr=0x104D,
    )

    assert candidate_addr == 0x10010
    assert image_end == 0x14001


def test_preserve_source_label_uses_original_addr_for_rebased_slice():
    source = SimpleNamespace(addr=0x1000, name="main", info={})
    recovered = SimpleNamespace(addr=0x10010, name="sub_10010", info={})
    mark_function_original_addr(source, 0x10010)

    assert cli_core._preserve_source_label_for_recovered_function_8616(source, recovered) is True
    assert recovered.name == "main"
    assert recovered.info["inertia_original_addr"] == 0x10010


def test_attach_lst_metadata_to_project_populates_fresh_project_labels():
    metadata = LSTMetadata(
        code_labels={0x10010: "main", 0x12A29: "settextrows"},
        data_labels={0x1BA2: "cRow"},
        absolute_addrs=True,
        source_format="cod_listing",
        cod_path="SORTDEMO.COD",
    )
    project = SimpleNamespace(kb=SimpleNamespace(labels={}))

    assert attach_lst_metadata_to_project(project, metadata) is True
    assert project._inertia_lst_metadata is metadata
    assert project.kb.labels[0x10010] == "main"
    assert project.kb.labels[0x12A29] == "settextrows"
    assert project.kb.labels[0x1BA2] == "cRow"


def test_sidecar_slice_tail_validation_summary_uses_slice_snapshot(monkeypatch):
    captured = {}

    def fake_emit(function_cfg, function, snapshot, *, binary_path):
        captured["function_cfg"] = function_cfg
        captured["function"] = function
        captured["snapshot"] = snapshot
        captured["binary_path"] = binary_path

    monkeypatch.setattr(cli_core, "_emit_tail_validation_snapshot_or_uncollected", fake_emit)
    cfg = SimpleNamespace(name="cfg")
    function = SimpleNamespace(name="BubbleSort")
    snapshot = {
        "structuring": {"status": "passed"},
        "postprocess": {"status": "passed"},
    }

    cli_core._emit_sidecar_slice_tail_validation_snapshot_8616(
        cfg,
        function,
        snapshot,
        binary_path=Path("SORTDEMO.EXE"),
    )

    assert captured == {
        "function_cfg": cfg,
        "function": function,
        "snapshot": snapshot,
        "binary_path": Path("SORTDEMO.EXE"),
    }


def test_parallel_clean_worker_timeout_model_covers_cold_start() -> None:
    default_model = cli_core.build_parallel_clean_worker_timeout_model(
        60,
        explicit_timeout=False,
    )
    explicit_model = cli_core.build_parallel_clean_worker_timeout_model(
        60,
        explicit_timeout=True,
    )

    assert default_model.timeout_for_byte_count(200) == 240
    assert explicit_model.timeout_for_byte_count(200) == 60


def test_retry_timeout_uses_observed_default_attempt_cost() -> None:
    assert cli_core.retry_timeout_after_failed_attempt(
        60,
        elapsed_seconds=307.33,
        timed_out=True,
        explicit_timeout=False,
    ) == 338


def test_retry_timeout_keeps_explicit_user_limit() -> None:
    assert cli_core.retry_timeout_after_failed_attempt(
        60,
        elapsed_seconds=307.33,
        timed_out=True,
        explicit_timeout=True,
    ) == 60
