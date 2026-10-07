from __future__ import annotations

from importlib.util import find_spec

from inertia.cli.layer_module_status import (
    LAYER_MODULE_RECORDS,
    LayerModuleAdmission,
    LayerModuleRecord,
    layer_module_records_by_module,
)


def test_layer_module_admission_values_are_stable() -> None:
    assert {item.value for item in LayerModuleAdmission} == {
        "production_wired",
        "compatibility_wrapper",
        "test_only_prototype",
    }


def test_layer_module_records_are_complete_owned_contracts() -> None:
    assert LAYER_MODULE_RECORDS
    for record in LAYER_MODULE_RECORDS:
        assert isinstance(record, LayerModuleRecord)
        assert record.module
        assert isinstance(record.admission, LayerModuleAdmission)
        assert record.owner_layer
        assert record.note
        assert find_spec(record.module) is not None


def test_layer_module_records_are_unique_by_module() -> None:
    modules = [record.module for record in LAYER_MODULE_RECORDS]

    assert len(modules) == len(set(modules))


def test_layer_module_records_by_module_preserves_record_identity() -> None:
    by_module = layer_module_records_by_module()

    assert set(by_module) == {record.module for record in LAYER_MODULE_RECORDS}
    for record in LAYER_MODULE_RECORDS:
        assert by_module[record.module] is record
