"""Keep DrawTime's value contract independent of harmless identity casts."""

import pytest
from test_check_sortd_sidecar_free import _passing_transcript

from scripts.check_sortd_sidecar_free import evaluate_sortd_transcript


@pytest.mark.parametrize(("argument", "accepted"), [
    ("(unsigned short)arg * 60, 75", True),
    ("(short)arg * 60, 75", False),
    ("(unsigned short)arg, 75", False),
    ("(unsigned short)arg * 60, 76", False),
])
def test_drawtime_gate_accepts_only_identity_cast_and_exact_arguments(argument, accepted):
    transcript = _passing_transcript().replace("sub_10e70(arg * 60, 75)", f"sub_10e70({argument})")
    result = evaluate_sortd_transcript(
        transcript, decompiler_returncode=0, minimum_decompiled=20,
        maximum_empty=0, maximum_timeouts=0, maximum_tracebacks=0,
    )
    assert result.passed is accepted
