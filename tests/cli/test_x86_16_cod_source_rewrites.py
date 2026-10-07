from __future__ import annotations

from inertia.cli.cod_source_rewrites import (
    COD_SOURCE_REWRITE_REGISTRY,
    COD_SOURCE_REWRITE_SPECS,
    COD_SOURCE_REWRITE_SPECS_BY_NAME,
    CODSourceRewriteRegistry,
    CODSourceRewriteSpec,
    CODSourceRewriteStatus,
    CODSourceRewriteStatusKind,
    apply_cod_source_rewrites,
    cod_source_rewrite_description,
    cod_source_rewrite_names,
    cod_source_rewrite_summary,
    describe_x86_16_source_backed_rewrite_debt,
    describe_x86_16_source_backed_rewrite_status,
    get_cod_source_rewrite_spec,
)
from inertia.frontend.x86_16.cod_extract import CODProcMetadata

BUILTIN_SOURCE_REWRITE_NAMES = ()


def test_cod_source_rewrite_registry_is_keyed_and_unique():
    names = [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert names == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert names == []


def test_cod_source_rewrite_registry_lookup_matches_spec_objects():
    for spec in COD_SOURCE_REWRITE_SPECS:
        assert get_cod_source_rewrite_spec(spec.name) is spec


def test_cod_source_rewrite_registry_exposes_name_order():
    assert COD_SOURCE_REWRITE_REGISTRY.names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_summary_matches_registry_contents():
    summary = cod_source_rewrite_summary()
    assert summary["count"] == len(BUILTIN_SOURCE_REWRITE_NAMES) + len(COD_SOURCE_REWRITE_SPECS)
    assert summary["names"] == (*BUILTIN_SOURCE_REWRITE_NAMES, *tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME))
    assert summary["status_counts"] == {}
    assert summary["active_count"] == len(BUILTIN_SOURCE_REWRITE_NAMES)
    assert summary["oracle_count"] == 0
    assert summary["subsumed_count"] == 0


def test_cod_source_rewrite_status_rows_use_typed_statuses():
    status = CODSourceRewriteStatus(name="sample", rewrite_status="temporary_rescue")

    assert status.rewrite_status is CODSourceRewriteStatusKind.TEMPORARY_RESCUE
    assert status.rewrite_status.is_active


def test_cod_source_rewrite_registry_summarizes_typed_status_rows():
    registry = CODSourceRewriteRegistry(
        specs=(
            CODSourceRewriteSpec(
                name="oracle_case",
                header_regex="oracle",
                rewritten="",
                rewrite_status=CODSourceRewriteStatusKind.PERMANENT_GUARDED_ORACLE,
            ),
            CODSourceRewriteSpec(
                name="subsumed_case",
                header_regex="subsumed",
                rewritten="",
                rewrite_status=CODSourceRewriteStatusKind.ALREADY_SUBSUMED_BY_GENERAL_RECOVERY,
            ),
        ),
        by_name={},
    )

    summary = registry.summary()

    assert summary["oracle_count"] == 1
    assert summary["subsumed_count"] == 1
    assert summary["active_count"] == 1
    assert summary["status_counts"] == {
        "already_subsumed_by_general_recovery": 1,
        "permanent_guarded_oracle": 1,
    }


def test_cod_source_rewrite_description_matches_registry_contents():
    description = cod_source_rewrite_description()
    assert description["count"] == len(BUILTIN_SOURCE_REWRITE_NAMES) + len(COD_SOURCE_REWRITE_SPECS)
    assert description["names"] == (*BUILTIN_SOURCE_REWRITE_NAMES, *tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME))
    assert tuple(item["name"] for item in description["specs"][: len(BUILTIN_SOURCE_REWRITE_NAMES)]) == (
        BUILTIN_SOURCE_REWRITE_NAMES
    )
    assert all("rewrite_status" in item for item in description["specs"])
    assert all("owner" in item for item in description["specs"])


def test_cod_source_rewrite_status_matches_registry_contents():
    status = describe_x86_16_source_backed_rewrite_status()

    assert status["count"] == len(BUILTIN_SOURCE_REWRITE_NAMES) + len(COD_SOURCE_REWRITE_SPECS)
    assert status["names"] == (*BUILTIN_SOURCE_REWRITE_NAMES, *tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME))
    assert tuple(item["name"] for item in status["specs"][: len(BUILTIN_SOURCE_REWRITE_NAMES)]) == (
        BUILTIN_SOURCE_REWRITE_NAMES
    )
    assert status["status_counts"] == {}
    assert status["active_count"] == len(BUILTIN_SOURCE_REWRITE_NAMES)
    assert status["oracle_count"] == 0
    assert status["subsumed_count"] == 0


def test_cod_source_rewrite_debt_matches_registry_contents():
    debt = describe_x86_16_source_backed_rewrite_debt()

    assert debt["count"] == len(BUILTIN_SOURCE_REWRITE_NAMES) + len(COD_SOURCE_REWRITE_SPECS)
    assert debt["active_count"] == len(BUILTIN_SOURCE_REWRITE_NAMES)
    assert debt["oracle_count"] == 0
    assert debt["subsumed_count"] == 0
    assert debt["status_counts"] == {}
    assert debt["active_names"] == BUILTIN_SOURCE_REWRITE_NAMES
    assert debt["oracle_names"] == ()
    assert debt["subsumed_names"] == ()


def test_cod_source_rewrite_names_matches_registry_contents():
    assert cod_source_rewrite_names() == tuple(COD_SOURCE_REWRITE_SPECS_BY_NAME)


def test_cod_source_rewrite_registry_behaves_like_a_container():
    assert len(COD_SOURCE_REWRITE_REGISTRY) == len(COD_SOURCE_REWRITE_SPECS)
    assert [spec.name for spec in COD_SOURCE_REWRITE_REGISTRY] == [spec.name for spec in COD_SOURCE_REWRITE_SPECS]
    assert list(COD_SOURCE_REWRITE_REGISTRY) == []
    assert "missing" not in COD_SOURCE_REWRITE_REGISTRY


def test_cod_source_rewrite_registry_supports_mapping_access():
    assert list(COD_SOURCE_REWRITE_REGISTRY.keys()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME)
    assert list(COD_SOURCE_REWRITE_REGISTRY.values()) == list(COD_SOURCE_REWRITE_SPECS)
    assert list(COD_SOURCE_REWRITE_REGISTRY.items()) == list(COD_SOURCE_REWRITE_SPECS_BY_NAME.items())


def test_cod_source_rewrite_registry_lookup_is_read_only():
    sample = next(iter(COD_SOURCE_REWRITE_SPECS_BY_NAME.values()), None)
    try:
        COD_SOURCE_REWRITE_REGISTRY.by_name["missing"] = sample  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("registry lookup map should be read-only")


def test_cod_source_rewrite_spec_lookup_map_is_read_only():
    sample = next(iter(COD_SOURCE_REWRITE_SPECS_BY_NAME.values()), None)
    try:
        COD_SOURCE_REWRITE_SPECS_BY_NAME["missing"] = sample  # type: ignore[index]
    except TypeError:
        return
    raise AssertionError("spec lookup map should be read-only")


def test_apply_cod_source_rewrites_is_inert_for_source_backed_body_recovery():
    metadata = CODProcMetadata(
        stack_aliases={},
        call_names=("printf",),
        call_sources=(("printf", 'printf ("a = %d, b = %d\\n", a, b)'),),
        global_names=(),
        source_lines=(
            "#define TYPE unsigned char",
            "main()",
            "{ TYPE a, b;",
            "a = 255;",
            "b = 143;",
            "b = a + b;",
            "a = a - b;",
            'printf ("a = %d, b = %d\\n", a, b);',
            "}",
        ),
        source_line_set=frozenset(
            {
                "#define TYPE unsigned char",
                "main()",
                "{ TYPE a, b;",
                "a = 255;",
                "b = 143;",
                "b = a + b;",
                "a = a - b;",
                'printf ("a = %d, b = %d\\n", a, b);',
                "}",
            }
        ),
    )
    collapsed = """void _start(void)
{
    printf ("a = %d, b = %d
", a, b);
}"""

    rewritten = apply_cod_source_rewrites(collapsed, metadata)

    assert rewritten == collapsed
