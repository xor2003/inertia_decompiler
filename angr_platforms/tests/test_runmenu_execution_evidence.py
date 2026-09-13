"""Bind whole-file acceptance to execution of its unchanged RunMenu body."""

from hashlib import sha256

import pytest
from test_check_sortd_sidecar_free import _passing_transcript

from scripts.check_sortd_sidecar_free import evaluate_sortd_transcript
from scripts.runmenu_behavior import RunMenuExecutionEvidence, collect_runmenu_execution_evidence


@pytest.mark.parametrize("fault", [None, "stale", "runtime", "scalar"])
def test_transcript_accepts_equivalent_exit_only_with_matching_execution(fault):
    body = "void sub_102e0(void) { while (1) { if (ax == 27) break; } }"
    digest = sha256(body.encode()).hexdigest()
    evidence = RunMenuExecutionEvidence(
        "stale" if fault == "stale" else digest,
        "execution failed" if fault == "runtime" else None,
    )
    if fault == "scalar":
        body = body.replace("void sub_", "short sub_")
        evidence = RunMenuExecutionEvidence(sha256(body.encode()).hexdigest(), None)
    transcript = _passing_transcript().replace(
        "void sub_102e0(void) { switch (ax) { case 27: return; } }", body,
    )
    result = evaluate_sortd_transcript(
        transcript, decompiler_returncode=0, minimum_decompiled=20,
        maximum_empty=0, maximum_timeouts=0, maximum_tracebacks=0,
        runmenu_execution=evidence,
    )
    assert result.passed is (fault is None)


def test_missing_export_is_an_explicit_execution_failure(tmp_path):
    result = collect_runmenu_execution_evidence(tmp_path, tmp_path)
    assert result.failure is not None
    assert "expected one generated artifact" in result.failure
    assert not result.accepts("")


@pytest.mark.parametrize("runtime_failure", [False, True])
def test_export_gets_runtime_header_without_changing_its_definition(tmp_path, monkeypatch, runtime_failure):
    from scripts import runmenu_behavior

    body = "void sub_102e0(void) { return; }"
    (tmp_path / "000102e0-sub_102e0.c").write_text(body)

    def execute(source, directory):
        assert directory == tmp_path
        assert "#include <stdint.h>" in source
        assert "#define SEG_U16" in source
        assert source.endswith(body)
        if runtime_failure:
            raise AssertionError("RunMenu execution failed: exit=20;")

    monkeypatch.setattr(runmenu_behavior, "assert_runmenu_behavior", execute)
    result = collect_runmenu_execution_evidence(tmp_path, tmp_path)
    assert result.accepts(body) is (not runtime_failure)
    if runtime_failure:
        assert "exit=20" in result.failure
