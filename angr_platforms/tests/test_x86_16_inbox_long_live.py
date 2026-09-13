"""Keep the recovered signed-wide bounds function in the non-skipping lane."""

from test_x86_16_cli import REPO_ROOT, _run_decompile_proc
from test_x86_16_wide_condition_provenance import assert_inbox_behavior


def test_inbox_long_passes_validation_and_compiled_behavior(tmp_path):
    path = REPO_ROOT / "cod" / "f14" / "CARR.COD"
    assert path.exists(), "Required InBoxLng regression fixture is missing"
    result = _run_decompile_proc(
        path, "_InBoxLng", proc_kind="NEAR", analysis_timeout=10, subprocess_timeout=30,
    )
    assert result.returncode == 0, result.stderr + result.stdout
    assert "validation=passed" in result.stderr
    assert_inbox_behavior(result.stdout, tmp_path)
    for token in (
        "function: 0x1000 _InBoxLng",
        "if ((int32_t)x < (int32_t)xl || (int32_t)x > (int32_t)xh || "
        "(int32_t)z < (int32_t)zl || (int32_t)z > (int32_t)zh)",
        "return 0;", "return 1;",
    ):
        assert token in result.stdout, result.stdout
    for token in ("if (...)", "!(v4", "& &"):
        assert token not in result.stdout, result.stdout
