import weakref
from types import SimpleNamespace

import pytest

from inertia.cli.lst_extract import LSTMetadata
import inertia.cli.cli_core as cli_core
from inertia.cli.work_items import (
    FunctionWorkExecutionOrigin8616,
    FunctionWorkItem,
    FunctionWorkResult,
)


class _WeakOwner:
    alive = True


def test_function_work_item_reads_attached_compiler_target() -> None:
    metadata = LSTMetadata(data_labels={}, code_labels={})
    project = SimpleNamespace(_inertia_c_target="msc-dos", _inertia_lst_metadata=metadata)
    item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(project=project),
    )

    assert item.c_target == "msc-dos"
    assert isinstance(item.sidecar_metadata_digest, str)


def test_function_work_item_digest_separates_sidecar_evidence_content() -> None:
    first_metadata = LSTMetadata(data_labels={}, code_labels={0x102E0: "RunMenu"})
    second_metadata = LSTMetadata(data_labels={}, code_labels={0x102E0: "OtherMenu"})
    first_item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(project=SimpleNamespace(_inertia_lst_metadata=first_metadata)),
    )
    second_item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(project=SimpleNamespace(_inertia_lst_metadata=second_metadata)),
    )

    assert first_item.sidecar_metadata_digest != second_item.sidecar_metadata_digest


def test_function_work_item_defaults_missing_compiler_target() -> None:
    item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(project=SimpleNamespace()),
    )

    assert item.c_target == "portable-flat"
    assert item.sidecar_metadata_digest is None


def test_function_work_item_preserves_original_and_active_addresses() -> None:
    item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(addr=0x1000, info={"inertia_original_addr": 0x11000}),
        recovery_addr=0x10FF0,
    )

    assert item.active_addr == 0x1000
    assert item.original_addr == 0x11000
    assert item.recovery_addr == 0x10FF0


def test_function_work_item_can_retain_weak_angr_owner() -> None:
    project = _WeakOwner()
    project.function_manager = _WeakOwner()
    manager_ref = weakref.ref(project.function_manager)
    function = SimpleNamespace(function_manager=weakref.proxy(project.function_manager))
    item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=function,
        retained_project=project,
    )

    del project

    assert manager_ref() is not None
    assert item.function.function_manager.alive is True


def test_clean_work_result_retries_only_with_distinct_sidecar_evidence() -> None:
    result = FunctionWorkResult(
        index=1,
        status="error",
        payload="failed",
        debug_output="",
        function=object(),
        function_cfg=object(),
        execution_origin=FunctionWorkExecutionOrigin8616.CLEAN_PROCESS,
    )

    assert not result.retry_may_change_evidence(sidecar_available=False)
    assert result.retry_may_change_evidence(sidecar_available=True)
    assert FunctionWorkResult(
        index=1,
        status="error",
        payload="failed",
        debug_output="",
        function=object(),
        function_cfg=object(),
    ).retry_may_change_evidence(sidecar_available=False)


def test_function_cache_lookup_forwards_complete_work_item_context(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}
    metadata = LSTMetadata(data_labels={}, code_labels={0x102E0: "RunMenu"})
    project = SimpleNamespace(_inertia_c_target="msc-dos", _inertia_lst_metadata=metadata)
    item = FunctionWorkItem(
        index=1,
        function_cfg=object(),
        function=SimpleNamespace(addr=0x102E0, name="RunMenu", project=project),
    )

    def record_key(_item: FunctionWorkItem, **kwargs: object) -> None:
        observed["item"] = _item
        observed.update(kwargs)
        return None

    monkeypatch.setattr(cli_core, "function_decompilation_cache_key_8616", record_key)
    monkeypatch.setattr(cli_core, "_tail_validation_runtime_enabled", lambda _project: False)

    result, _debug, _key, _tail_enabled, _expected_stages = cli_core._function_work_cache_lookup(
        item,
        binary_path=None,
        timeout=5,
        api_style="dos",
        enable_structured_simplify=True,
        enable_postprocess=True,
    )

    assert result is None
    assert observed["item"] is item
    assert observed["api_style"] == "dos"
    assert observed["cod_metadata"] is None
    assert observed["synthetic_globals"] is None
    assert observed["lst_metadata"] is None
