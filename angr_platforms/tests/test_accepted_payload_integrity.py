"""Regression tests for accepted generated-C payload identity."""

from __future__ import annotations

import ast
import hashlib
import inspect
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

import inertia_decompiler.cli_core as cli_core
from inertia_decompiler.accepted_payload_integrity import (
    AcceptedPayloadIntegrityVerdict8616,
    AcceptedPayloadWorkResult8616,
    verify_accepted_payload_integrity_8616,
    verify_function_work_result_payload_integrity_8616,
)
from inertia_decompiler.direct_addr_failure_family import build_failure_family_snapshot
from inertia_decompiler.work_items import FunctionWorkResult


def _accepted_result(payload: str) -> FunctionWorkResult:
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return FunctionWorkResult(
        index=1,
        status="ok",
        payload=payload,
        debug_output="",
        function=SimpleNamespace(addr=0x1000, name="sub_1000"),
        function_cfg=None,
        tail_validation={
            "structuring": {"status": "stable"},
            "postprocess": {"status": "stable"},
        },
        validated_payload_hash=digest,
        gcc_checked_payload_hash=digest,
        failure_family_snapshot=build_failure_family_snapshot(
            status="ok",
            failure_stage=None,
            fallback_kind="direct_addr",
            tail_validation_verdict="passed",
            artifact_path="0x1000:sub_1000",
        ),
    )


def test_accepted_payload_integrity_rejects_post_validation_replacement() -> None:
    accepted = "int sub_1000(void) { return 1; }\n"
    digest = hashlib.sha256(accepted.encode("utf-8")).hexdigest()

    report = verify_accepted_payload_integrity_8616(
        "int sub_1000(void) { return 0; }\n",
        validated_payload_hash=digest,
        gcc_checked_payload_hash=digest,
    )

    assert report.verdict is AcceptedPayloadIntegrityVerdict8616.VALIDATED_PAYLOAD_MISMATCH
    assert not report.passed


@pytest.mark.parametrize("acceptance_name", [
    "evidence_acceptance", "partial_acceptance", "robust_acceptance",
    "retry_acceptance", "checked_acceptance", "helper_acceptance",
])
def test_direct_recovery_replaces_payload_and_proofs_together(acceptance_name):
    """Exercise the actual nested promotion expression without constructing a DOS project."""
    tree = ast.parse(inspect.getsource(cli_core._DirectAddrCliRun8616))

    def _payload_base_name(value: ast.expr) -> str | None:
        if isinstance(value, ast.Name):
            return value.id
        if isinstance(value, ast.Attribute) and isinstance(value.value, ast.Name) and value.value.id == "self":
            return value.attr
        return None

    promotions = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "replace"
        and any(
            keyword.arg == "payload" and (
                (isinstance(keyword.value, ast.Attribute)
                and _payload_base_name(keyword.value.value) == acceptance_name)
                or (acceptance_name == "helper_acceptance"
                and _payload_base_name(keyword.value) == "helper_payload")
            )
            for keyword in node.keywords
        )
    ]
    assert len(promotions) == 1
    previous = _accepted_result("int sub_1000(void) { return 0; }\n")
    accepted = _accepted_result("int sub_1000(void) { return 1; }\n")
    acceptance = SimpleNamespace(
        gcc_checked_payload=accepted.payload,
        validated_payload_hash=accepted.validated_payload_hash,
        gcc_checked_payload_hash=accepted.gcc_checked_payload_hash,
    )
    state = SimpleNamespace(
        direct_result=previous,
        evidence_snapshot=accepted.tail_validation,
        robust_result=previous,
        retry_result=previous,
        robust_snapshot=accepted.tail_validation,
        func=previous.function,
        cfg=None,
        helper_status="ok",
        helper_payload=accepted.payload,
        helper_tail_validation_snapshot=accepted.tail_validation,
    )
    setattr(state, acceptance_name, acceptance)
    result = eval(compile(ast.Expression(promotions[0]), "<direct-promotion>", "eval"), {
        "replace": replace, "self": state, "direct_result": previous,
        acceptance_name: acceptance, "evidence_snapshot": accepted.tail_validation,
        "robust_result": previous, "retry_result": previous,
        "robust_snapshot": accepted.tail_validation, "func": previous.function, "cfg": None,
        "helper_status": "ok", "helper_payload": accepted.payload,
        "helper_tail_validation_snapshot": accepted.tail_validation,
    })
    assert result.payload == accepted.payload
    assert verify_function_work_result_payload_integrity_8616(result).passed
    assert previous.payload != result.payload


@pytest.mark.parametrize("missing_proof, expected", [
    (None, AcceptedPayloadIntegrityVerdict8616.PASSED),
    ("validation", AcceptedPayloadIntegrityVerdict8616.MISSING_VALIDATED_HASH),
    ("compiler", AcceptedPayloadIntegrityVerdict8616.MISSING_COMPILER_HASH),
])
def test_verifier_consumes_immutable_result_without_changing_proofs(
    missing_proof: str | None, expected: AcceptedPayloadIntegrityVerdict8616,
) -> None:
    result = _accepted_result("int sub_1000(void) { return 1; }\n")
    if missing_proof == "validation":
        result = replace(result, validated_payload_hash=None)
    elif missing_proof == "compiler":
        result = replace(result, gcc_checked_payload_hash=None)
    original = replace(result)
    contract: AcceptedPayloadWorkResult8616 = result

    report = verify_function_work_result_payload_integrity_8616(contract)

    assert report.verdict is expected
    assert result == original


def test_accepted_payload_integrity_import_stays_outside_work_item_graph() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; "
                "import inertia_decompiler.accepted_payload_integrity; "
                "raise SystemExit(int('inertia_decompiler.work_items' in sys.modules))"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


def test_direct_cache_artifact_refuses_post_validation_replacement() -> None:
    result = _accepted_result("int sub_1000(void) { return 1; }\n")
    replaced_result = replace(result, payload="int sub_1000(void) { return 0; }\n")
    context = SimpleNamespace(
        args=SimpleNamespace(
            ignore_local_sidecar_hints=False,
            binary=SimpleNamespace(),
            c_target="portable-flat",
        ),
        project=SimpleNamespace(arch=SimpleNamespace(name="86_16"), entry=0x1000),
        lst_metadata=object(),
    )

    artifact = cli_core._direct_request_cache_artifact_for_result_8616(
        context,
        replaced_result,
        function_addr=0x1000,
        function_name="sub_1000",
    )

    assert artifact is None


def test_direct_emitter_refuses_post_validation_replacement(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = _accepted_result("int sub_1000(void) { return 1; }\n")
    replaced_result = replace(result, payload="int sub_1000(void) { return 0; }\n")

    status = cli_core._emit_direct_cache_hit_8616(
        SimpleNamespace(args=SimpleNamespace()),
        replaced_result,
        function=result.function,
        function_cfg=None,
        emit_function_header=False,
        project_for_worker_result=None,
    )
    captured = capsys.readouterr()

    assert status == 4
    assert captured.out == ""
    assert "accepted generated-C payload integrity=validated_payload_mismatch" in captured.err


def test_direct_cli_contains_no_function_specific_result_substitution() -> None:
    source = inspect.getsource(cli_core._run_direct_addr_cli_8616).lower()

    assert "tidshowrange" not in source
    assert "drawradaralt" not in source
    assert "drawcockpit" not in source
    assert "cod annotations: calls" not in source
