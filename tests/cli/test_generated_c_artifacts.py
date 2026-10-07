from __future__ import annotations

from pathlib import Path

from inertia.cli.cli_arg_parser import parse_cli_arguments
from inertia.cli.generated_c_artifacts import (
    write_generated_function_c,
    write_generated_translation_unit_c,
)


def test_generated_function_artifact_preserves_validated_payload(tmp_path: Path) -> None:
    payload = "void sub_1234(void)\n{\n    return;\n}\n"

    destination = write_generated_function_c(
        tmp_path,
        address=0x1234,
        name="unsafe/name",
        payload=payload,
    )

    assert destination.name == "00001234-unsafe_name.c"
    assert destination.read_text(encoding="utf-8") == payload


def test_output_c_directory_can_be_selected_from_cli(tmp_path: Path) -> None:
    args = parse_cli_arguments(["sample.exe", "--output-c-dir", str(tmp_path)])

    assert args.output_c_dir == tmp_path


def test_generated_translation_unit_distinguishes_complete_and_partial_output(tmp_path: Path) -> None:
    complete = write_generated_translation_unit_c(
        tmp_path,
        payload="int first(void) { return 1; }\n",
        complete=True,
    )
    partial = write_generated_translation_unit_c(
        tmp_path,
        payload="int second(void) { return 2; }\n",
        complete=False,
    )

    assert partial.name == "partial-translation-unit.c"
    assert not complete.exists()
    assert partial.read_text(encoding="utf-8") == "int second(void) { return 2; }\n"

    complete = write_generated_translation_unit_c(
        tmp_path,
        payload="int first(void) { return 1; }\n",
        complete=True,
    )

    assert complete.name == "translation-unit.c"
    assert complete.read_text(encoding="utf-8") == "int first(void) { return 1; }\n"
    assert not partial.exists()
