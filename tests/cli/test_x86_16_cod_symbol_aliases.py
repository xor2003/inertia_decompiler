from __future__ import annotations

from pathlib import Path

from inertia.frontend.x86_16.cod_extract import extract_cod_proc_metadata


def test_cod_extract_preserves_static_identity_and_records_equ_alias(tmp_path: Path) -> None:
    cod_path = tmp_path / "ALIASED.COD"
    cod_path.write_text(
        "\n".join(
            (
                "; $S767_BadWeather EQU BadWeather",
                ";|*** static int BadWeather=0;",
                "_ChangeWeather\tPROC NEAR",
                "    *** 0000 83 3E 20 00 00 cmp WORD PTR $S767_BadWeather,0",
                "    *** 0005 C7 06 20 00 01 00 mov WORD PTR $S767_BadWeather,1",
                "_ChangeWeather\tENDP",
            )
        ),
        encoding="utf-8",
    )

    metadata = extract_cod_proc_metadata(cod_path, "_ChangeWeather")

    assert tuple(ref.name for ref in metadata.global_refs) == ("_S767_BadWeather", "_S767_BadWeather")
    assert tuple(ref.source_alias for ref in metadata.global_refs) == ("BadWeather", "BadWeather")


def test_cod_extract_preserves_generated_static_name_without_equ_alias(tmp_path: Path) -> None:
    cod_path = tmp_path / "UNALIASED.COD"
    cod_path.write_text(
        "\n".join(
            (
                ";|*** static int seen=0;",
                "_count\tPROC NEAR",
                "    *** 0000 FF 06 48 00 inc WORD PTR $S104_seen",
                "_count\tENDP",
            )
        ),
        encoding="utf-8",
    )

    metadata = extract_cod_proc_metadata(cod_path, "_count")

    assert tuple(ref.name for ref in metadata.global_refs) == ("_S104_seen",)
    assert tuple(ref.source_alias for ref in metadata.global_refs) == (None,)
