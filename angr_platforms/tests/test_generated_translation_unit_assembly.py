from __future__ import annotations

import subprocess

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)

from inertia_decompiler.cli_batch_c_output import (
    BatchCOutputStatus8616,
    build_batch_c_output_8616,
)
from scripts.generated_translation_unit_assembly import (
    DeclarationContractKind,
    assemble_generated_translation_unit,
)


def test_assembler_preserves_portable_runtime_header_without_frozen_typedefs(tmp_path) -> None:
    header = coherent_gp_runtime_header_8616()
    result = assemble_generated_translation_unit((
        header + "void first(void) { inertia_si = 5; }\n",
        header + "unsigned long second(void) { return inertia_esi; }\n",
    ))
    assert result.conflicts == ()
    assert header in result.source
    assert result.source.count("typedef union inertia_gp_lane") == 1
    assert result.function_count == 2
    # A consumer may include the ABI header independently, as the MS C builder does.
    executable = tmp_path / "runtime_export"
    source = header + result.source + coherent_gp_runtime_definitions_8616() + """
int main(void) {
    inertia_esi = 0xabcd1234UL;
    first();
    return second() == 0xabcd0005UL ? 0 : 1;
}
"""
    compiled = subprocess.run(
        ["gcc", "-std=c89", "-pedantic-errors", "-Werror", "-x", "c", "-", "-o", str(executable)],
        input=source, text=True, capture_output=True, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    assert subprocess.run([str(executable)], check=False).returncode == 0


def test_assembler_retains_runtime_declaration_conflicts() -> None:
    header = coherent_gp_runtime_header_8616()
    result = assemble_generated_translation_unit((
        header + "void first(void) {}\n",
        "typedef unsigned short inertia_gp_dword;\nvoid second(void) {}\n",
    ))
    assert any(item.name == "inertia_gp_dword" for item in result.conflicts)


def test_assembler_deduplicates_types_and_uses_internal_definition_contract() -> None:
    first = """
typedef struct Row { unsigned short value; } Row;
int second(unsigned short value);
void first(void) { second(1); }
"""
    second = """
typedef struct Row { unsigned short value; } Row;
void second(unsigned short value) { (void)value; }
"""

    result = assemble_generated_translation_unit((first, second))

    assert result.source.count("typedef struct Row") == 1
    assert result.source.count("void second(unsigned short value)") == 2
    assert "int second(" not in result.source
    assert result.conflicts == ()


def test_assembler_drops_redundant_aggregate_forward_declaration() -> None:
    result = assemble_generated_translation_unit(
        (
            "struct Row;\nvoid first(void) {}\n",
            "typedef struct Row { int value; } Row;\nvoid second(void) {}\n",
        )
    )

    assert result.source.count("typedef struct Row") == 1
    assert "struct Row;" not in result.source
    assert result.conflicts == ()


def test_assembler_retains_and_reports_conflicting_global_contracts() -> None:
    first = "extern unsigned short shared[1];\nvoid first(void) {}\n"
    second = "extern unsigned char shared[1];\nvoid second(void) {}\n"

    result = assemble_generated_translation_unit((first, second))

    assert len(result.conflicts) == 1
    assert result.conflicts[0].kind is DeclarationContractKind.GLOBAL
    assert result.conflicts[0].name == "shared"
    assert "extern unsigned short shared[1];" in result.source
    assert "extern unsigned char shared[1];" in result.source


def test_assembler_joins_wide_external_return_and_discards_weaker_declaration() -> None:
    first = "int helper();\nvoid first(void) { helper(1, 2); }\n"
    second = "unsigned short helper(unsigned short a, unsigned short b);\nvoid second(void) {}\n"
    third = "unsigned long helper(unsigned short a, unsigned short b);\nvoid third(void) {}\n"

    result = assemble_generated_translation_unit((first, second, third))

    assert result.source.count("unsigned long helper(unsigned short a, unsigned short b)") == 1
    assert "int helper()" not in result.source
    assert "unsigned short helper(" not in result.source
    assert result.conflicts == ()


def test_assembler_joins_compatible_external_parameter_array_bounds() -> None:
    first = "int output();\nvoid first(void) {}\n"
    second = "int output(char text[80], unsigned short segment);\nvoid second(void) {}\n"
    third = "int output(char text[44], unsigned short segment);\nvoid third(void) {}\n"

    result = assemble_generated_translation_unit((first, second, third))

    assert result.source.count("int output(char text[80], unsigned short segment)") == 1
    assert "text[44]" not in result.source
    assert "int output()" not in result.source
    assert result.conflicts == ()


def test_assembler_joins_unprototyped_external_integer_returns() -> None:
    first = "unsigned short helper();\nvoid first(void) {}\n"
    second = "unsigned long helper();\nvoid second(void) {}\n"

    result = assemble_generated_translation_unit((first, second))

    assert result.source.count("unsigned long helper()") == 1
    assert "unsigned short helper()" not in result.source
    assert result.conflicts == ()


def test_assembler_refuses_unproven_void_external_return() -> None:
    first = "void helper(unsigned short value);\nvoid first(void) { helper(1); }\n"
    second = "int helper(unsigned short value);\nvoid second(void) { helper(2); }\n"

    result = assemble_generated_translation_unit((first, second))

    assert result.source.count("int helper(unsigned short value)") == 1
    assert "void helper(unsigned short value)" not in result.source
    assert result.conflicts == ()


def test_assembler_refuses_incompatible_external_parameter_contracts() -> None:
    first = "int helper(unsigned short value);\nvoid first(void) {}\n"
    second = "int helper(char *value);\nvoid second(void) {}\n"

    result = assemble_generated_translation_unit((first, second))

    assert len(result.conflicts) == 1
    assert result.conflicts[0].kind is DeclarationContractKind.EXTERNAL_FUNCTION
    assert result.conflicts[0].name == "helper"
    assert result.source.count("helper(") == 2


def test_batch_output_builds_one_canonical_complete_unit() -> None:
    result = build_batch_c_output_8616(
        (
            "typedef struct Row { int value; } Row;\nvoid first(void) {}\n",
            "typedef struct Row { int value; } Row;\nvoid second(void) {}\n",
        ),
        expected_function_count=2,
    )

    assert result.status is BatchCOutputStatus8616.READY
    assert result.function_count == 2
    assert result.source.count("typedef struct Row") == 1


def test_batch_output_retains_partial_c_without_claiming_complete_unit() -> None:
    result = build_batch_c_output_8616(
        ("void first(void) {}\n",),
        expected_function_count=2,
    )

    assert result.status is BatchCOutputStatus8616.INCOMPLETE
    assert result.source == "void first(void) {}\n"
    assert not result.failed


def test_batch_output_refuses_complete_conflicting_declarations() -> None:
    result = build_batch_c_output_8616(
        (
            "extern int shared;\nvoid first(void) {}\n",
            "extern char shared;\nvoid second(void) {}\n",
        ),
        expected_function_count=2,
    )

    assert result.status is BatchCOutputStatus8616.CONFLICT
    assert result.source == ""
    assert result.failed
