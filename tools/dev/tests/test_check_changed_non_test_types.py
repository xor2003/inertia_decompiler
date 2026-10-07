from __future__ import annotations

from pathlib import Path

from tools.dev import check_changed_non_test_types


def _write_module(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_changed_new_function_without_annotations_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def new_helper(value):\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_functions_missing_annotations(module)

    assert diagnostics == [f"{module}:8: new_helper missing annotations: value, return"]


def test_changed_new_function_with_annotations_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def new_helper(value: int) -> int:\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_functions_missing_annotations(module)

    assert diagnostics == []


def test_changed_existing_function_body_without_annotations_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def existing_helper(value):\n"
        "    changed = value + 1\n"
        "    return changed\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {9})

    diagnostics = check_changed_non_test_types._changed_functions_missing_annotations(module)

    assert diagnostics == [f"{module}:8: existing_helper missing annotations: value, return"]


def test_changed_new_public_function_without_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def new_helper(value: int) -> int:\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == [f"{module}:8: new_helper missing docstring"]


def test_changed_new_public_class_without_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "class PublicContract:\n"
        "    pass\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == [f"{module}:8: PublicContract missing docstring"]


def test_changed_script_named_test_prefix_is_not_skipped(tmp_path):
    (tmp_path / "tools" / "dev").mkdir(parents=True)
    module = _write_module(
        tmp_path / "tools" / "dev" / "test_pipeline.py",
        '"""Curated pipeline."""\n\n'
        "from __future__ import annotations\n\n"
        "def main(argv: list[str] | None = None) -> int:\n"
        "    return 0\n",
    )

    assert check_changed_non_test_types._is_test_path(module) is False


def test_changed_local_helper_without_docstring_is_not_public_contract(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(value: int) -> int:\n"
        '    """Return the transformed value."""\n'
        "    def local_helper(inner: int) -> int:\n"
        "        return inner + 1\n"
        "    return local_helper(value)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {7})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == []


def test_changed_public_enum_without_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from enum import Enum\n\n"
        "class ContractStatus(Enum):\n"
        '    READY = "ready"\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {10})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == [f"{module}:10: ContractStatus missing docstring"]


def test_changed_existing_public_class_body_without_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "class PublicContract:\n"
        "    changed = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {9})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == [f"{module}:8: PublicContract missing docstring"]


def test_changed_dataclass_field_without_annotation_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    value = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {13})

    diagnostics = check_changed_non_test_types._changed_dataclass_fields_missing_annotations(module)

    assert diagnostics == [f"{module}:13: PublicContract.value missing annotation"]


def test_changed_dataclass_field_with_annotation_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True)\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    value: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {13})

    diagnostics = check_changed_non_test_types._changed_dataclass_fields_missing_annotations(module)

    assert diagnostics == []


def test_changed_private_dataclass_field_without_annotation_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    _cache = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {13})

    diagnostics = check_changed_non_test_types._changed_dataclass_fields_missing_annotations(module)

    assert diagnostics == []


def test_changed_new_private_definition_without_docstring_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def _new_helper(value: int) -> int:\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_definitions_missing_docstrings(module)

    assert diagnostics == []


def test_changed_module_without_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        "from __future__ import annotations\n\n"
        "VALUE = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {3})

    diagnostics = check_changed_non_test_types._changed_module_missing_docstring(module)

    assert diagnostics == [f"{module}:1: module missing docstring"]


def test_changed_module_with_docstring_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_module_missing_docstring(module)

    assert diagnostics == []


def test_changed_module_docstring_without_layer_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_module_docstring_missing_layer(module)

    assert diagnostics == [f"{module}:1: module docstring missing Layer: ownership"]


def test_changed_module_docstring_with_layer_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {7})

    diagnostics = check_changed_non_test_types._changed_module_docstring_missing_layer(module)

    assert diagnostics == []


def test_changed_module_docstring_without_responsibility_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {3})

    diagnostics = check_changed_non_test_types._changed_module_docstring_missing_responsibility(module)

    assert diagnostics == [f"{module}:1: module docstring missing Responsibility: ownership"]


def test_changed_module_body_without_responsibility_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {7})

    diagnostics = check_changed_non_test_types._changed_module_docstring_missing_responsibility(module)

    assert diagnostics == [f"{module}:1: module docstring missing Responsibility: ownership"]


def test_changed_module_docstring_with_responsibility_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {8})

    diagnostics = check_changed_non_test_types._changed_module_docstring_missing_responsibility(module)

    assert diagnostics == []


def test_changed_module_without_future_annotations_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_module_missing_future_annotations(module)

    assert diagnostics == [f"{module}:1: module missing 'from __future__ import annotations'"]


def test_changed_module_with_future_annotations_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {7})

    diagnostics = check_changed_non_test_types._changed_module_missing_future_annotations(module)

    assert diagnostics == []


def test_changed_public_module_assignment_without_annotation_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == [f"{module}:5: VALUE missing annotation"]


def test_changed_public_module_assignment_with_annotation_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == []


def test_changed_public_class_assignment_without_annotation_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    VALUE = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {7})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == [f"{module}:7: PublicContract.VALUE missing annotation"]


def test_changed_enum_member_without_annotation_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "from enum import Enum\n\n"
        "class ContractStatus(str, Enum):\n"
        '    """Typed terminal status."""\n'
        '    READY = "ready"\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {9})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == []


def test_changed_status_enum_auto_value_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from enum import Enum, auto\n\n"
        "class ContractStatus(Enum):\n"
        '    """Typed terminal status."""\n'
        "    READY = auto()\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_enum_members_missing_string_values(module)

    assert diagnostics == [f"{module}:12: ContractStatus.READY must use an explicit string value"]


def test_changed_status_enum_string_value_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from enum import Enum\n\n"
        "class ContractStatus(Enum):\n"
        '    """Typed terminal status."""\n'
        '    READY = "ready"\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_enum_members_missing_string_values(module)

    assert diagnostics == []


def test_changed_int_enum_value_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "from enum import IntEnum\n\n"
        "class RegisterIndex(IntEnum):\n"
        '    """Typed numeric register index."""\n'
        "    AX = 0\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_enum_members_missing_string_values(module)

    assert diagnostics == []


def test_changed_private_assignment_without_annotation_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "_CACHE = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == []


def test_changed_computed_dunder_all_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "_EXPORTS: tuple[str, ...] = ('public_helper',)\n"
        "__all__ = tuple(_EXPORTS)\n\n"
        "def public_helper() -> None:\n"
        '    """Public helper."""\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {9})

    diagnostics = check_changed_non_test_types._changed_computed_dunder_all(module)

    assert diagnostics == [f"{module}:9: __all__ must be a literal tuple/list of string exports"]


def test_changed_augmented_dunder_all_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "__all__ = ('public_helper',)\n"
        "__all__ += ('other_helper',)\n\n"
        "def public_helper() -> None:\n"
        '    """Public helper."""\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {9})

    diagnostics = check_changed_non_test_types._changed_computed_dunder_all(module)

    assert diagnostics == [f"{module}:9: __all__ must be a literal tuple/list of string exports"]


def test_changed_literal_dunder_all_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "__all__: tuple[str, ...] = ('public_helper',)\n\n"
        "def public_helper() -> None:\n"
        '    """Public helper."""\n',
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {6})

    diagnostics = check_changed_non_test_types._changed_computed_dunder_all(module)

    assert diagnostics == []


def test_changed_getattr_without_dynamic_boundary_reason_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(record: object) -> object:\n"
        '    """Return a value from a record."""\n'
        "    return getattr(record, 'value')\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:11: getattr requires nearby dynamic-boundary reason; use dot access for owned contracts"
    ]


def test_changed_getattr_with_dynamic_boundary_reason_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object, field_name: str) -> object:\n"
        '    """Return a plugin-provided value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    return getattr(plugin, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == []


def test_changed_getattr_with_dynamic_non_boundary_reason_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object, field_name: str) -> object:\n"
        '    """Return a plugin-provided value."""\n'
        "    # dynamic plugin field names come from a third-party registry.\n"
        "    return getattr(plugin, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:12: getattr requires nearby dynamic-boundary reason; use dot access for owned contracts"
    ]


def test_changed_getattr_with_enclosing_dynamic_boundary_docstring_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(codegen: object, field_name: str) -> object:\n"
        '    """Return a codegen field through a dynamic codegen compatibility boundary."""\n'
        "    return getattr(codegen, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == []


def test_changed_getattr_with_enclosing_dynamic_non_boundary_docstring_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(codegen: object, field_name: str) -> object:\n"
        '    """Return a dynamic codegen compatibility field."""\n'
        "    return getattr(codegen, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:11: getattr requires nearby dynamic-boundary reason; use dot access for owned contracts"
    ]


def test_changed_getattr_with_module_dynamic_boundary_docstring_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: test changed-file gates.\n"
        'Dynamic boundary: wraps angr codegen compatibility objects.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def _private_helper(codegen: object, field_name: str) -> object:\n"
        "    return getattr(codegen, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == []


def test_changed_getattr_with_detached_dynamic_boundary_reason_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object, field_name: str) -> object:\n"
        '    """Return a plugin-provided value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    value: object = plugin\n"
        "    return getattr(value, field_name)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {13})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:13: getattr requires nearby dynamic-boundary reason; use dot access for owned contracts"
    ]


def test_changed_setattr_without_dynamic_boundary_reason_is_rejected(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(record: object) -> None:\n"
        '    """Set a value on a record."""\n'
        "    setattr(record, 'value', 1)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:11: static setattr field 'value' must use dot access; "
        "dynamic-boundary exceptions require a runtime-computed field name"
    ]


def test_changed_setattr_with_dynamic_boundary_reason_is_allowed(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object, field_name: str) -> None:\n"
        '    """Set a plugin-provided value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    setattr(plugin, field_name, 1)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == []


def test_changed_static_setattr_is_rejected_even_with_dynamic_boundary_reason(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n'
        'Dynamic plugin boundary for runtime-provided fields.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object) -> None:\n"
        '    """Set a plugin-provided value."""\n'
        "    setattr(plugin, '_fixed_cache', 1)\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {12})

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == [
        f"{module}:12: static setattr field '_fixed_cache' must use dot access; "
        "dynamic-boundary exceptions require a runtime-computed field name"
    ]


def test_changed_static_setattr_allows_existing_head_debt(monkeypatch, tmp_path):
    source = (
        '"""Module contract.\n\nLayer: Tooling/gates.\nResponsibility: test changed-file gates.\n"""\n\n'
        "from __future__ import annotations\n\n"
        "def public_helper(plugin: object) -> None:\n"
        '    """Set a legacy plugin cache."""\n'
        "    setattr(plugin, '_fixed_cache', 1)\n"
    )
    module = _write_module(tmp_path / "module.py", source)
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {11})
    monkeypatch.setattr(check_changed_non_test_types, "_head_source", lambda _path: source)

    diagnostics = check_changed_non_test_types._changed_dynamic_attribute_access_missing_reason(module)

    assert diagnostics == []


def test_changed_dataclass_assignment_is_reported_by_dataclass_rule_only(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    value = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {10})

    diagnostics = check_changed_non_test_types._changed_public_assignments_missing_annotations(module)

    assert diagnostics == []


def test_main_reports_changed_new_untyped_function(monkeypatch, tmp_path, capsys):
    module = _write_module(
        tmp_path / "module.py",
        "from __future__ import annotations\n\n"
        "def new_helper(value):\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {3})

    rc = check_changed_non_test_types.main([str(module)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "changed non-test modules and definitions must be typed and documented" in captured.err
    assert "module missing docstring" in captured.err
    assert "new_helper missing annotations: value, return" in captured.err
    assert "new_helper missing docstring" in captured.err


def test_main_reports_changed_module_docstring_without_layer(monkeypatch, tmp_path, capsys):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "VALUE: int = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {5})

    rc = check_changed_non_test_types.main([str(module)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "module docstring missing Layer: ownership" in captured.err


def test_main_reports_changed_untyped_dataclass_field(monkeypatch, tmp_path, capsys):
    module = _write_module(
        tmp_path / "module.py",
        '"""Module contract."""\n\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class PublicContract:\n"
        '    """Owned contract."""\n'
        "    value = 1\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda _path: {10})

    rc = check_changed_non_test_types.main([str(module)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "PublicContract.value missing annotation" in captured.err


def test_main_checks_untracked_non_test_files_as_fully_changed(monkeypatch, tmp_path, capsys):
    module = _write_module(
        tmp_path / "module.py",
        "from __future__ import annotations\n\n"
        "def new_helper(value):\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: False)

    rc = check_changed_non_test_types.main([str(module)])

    captured = capsys.readouterr()
    assert rc == 1
    assert "module missing docstring" in captured.err
    assert "new_helper missing annotations: value, return" in captured.err
    assert "new_helper missing docstring" in captured.err


def test_main_skips_test_files(monkeypatch, tmp_path):
    module = _write_module(
        tmp_path / "test_module.py",
        "def test_helper(value):\n"
        "    return value\n",
    )
    monkeypatch.setattr(check_changed_non_test_types, "_tracked_by_git", lambda _path: True)

    rc = check_changed_non_test_types.main([str(module)])

    assert rc == 0


def test_gate_reads_changed_lines_once_per_file(monkeypatch, tmp_path):
    """All rules share one visit, but a later invocation sees new file contents."""
    path = tmp_path / "example.py"
    path.write_text('"""Layer: Tooling.\nResponsibility: test fixture."""\nfrom __future__ import annotations\n')
    original_changed = check_changed_non_test_types._changed_lines
    original_parse = check_changed_non_test_types.ast.parse
    counts = {"changed": 0, "parse": 0}

    def changed(selected):
        counts["changed"] += 1
        return original_changed(selected)

    def parse(source, filename="<unknown>", *args, **kwargs):
        if filename == str(path):
            counts["parse"] += 1
        return original_parse(source, filename, *args, **kwargs)

    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", changed)
    monkeypatch.setattr(check_changed_non_test_types.ast, "parse", parse)
    monkeypatch.setattr(check_changed_non_test_types, "_head_source", lambda selected: None)
    assert check_changed_non_test_types.main([str(path)]) == 0
    assert counts == {"changed": 1, "parse": 1}
    path.write_text(path.read_text() + "def broken(value):\n    return value\n")
    assert check_changed_non_test_types.main([str(path)]) == 1
    assert counts == {"changed": 2, "parse": 2}


def test_unchanged_module_is_not_parsed(monkeypatch, tmp_path):
    """Unchanged files retain the ratchet's skip contract without parsing."""
    path = tmp_path / "legacy.py"
    path.write_text("invalid syntax here !")
    monkeypatch.setattr(check_changed_non_test_types, "_changed_lines", lambda selected: set())
    assert check_changed_non_test_types.main([str(path)]) == 0
