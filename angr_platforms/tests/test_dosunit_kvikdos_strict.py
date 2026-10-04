"""Require explicit unsupported-service rejection at the native CLI boundary."""

from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from tools.dosunit import kvikdos_backend as backend
from tools.dosunit.runner import record_oracle


def test_cli_requests_strict_policy_and_preserves_failure(tmp_path: Path) -> None:
    """Keep the diagnostic and failure status while requesting strict mode."""
    executable = tmp_path / "kvikdos"
    executable.touch()
    diagnostic = b"unsupported service"
    with patch.object(backend.subprocess, "run", return_value=CompletedProcess(
        [], 252, stderr=diagnostic,
    )) as run, pytest.raises(backend.KvikdosBackendError, match="status 252: unsupported service"):
        backend._run_with_kvikdos_cli(
            tmp_path / "guest.com", tmp_path / "dump", kvikdos_path=executable,
        )
    assert run.call_args.args[0] == [
        str(executable), "--strict", "--tty-in=-3", str(tmp_path / "guest.com"),
    ]


def test_cli_failure_preserves_batch_accounting(tmp_path: Path) -> None:
    """A native failure retains its vector and does not discard later results."""
    executable = tmp_path / "kvikdos"
    executable.touch()
    vectors = [{"function": {"name": name}} for name in ("unsupported", "supported")]
    observation = {"status": "trapped", "regs": {"ax": "0x0001"}}

    def run_cli(argv: list[str], **kwargs: object) -> CompletedProcess[bytes]:
        """Simulate the process boundary, keeping real backend error handling."""
        assert "--strict" in argv
        env = kwargs["env"]
        assert isinstance(env, dict)
        dump = Path(env["KVIKDOS_MEM_DUMP"])
        if not seen:
            seen.append(True)
            return CompletedProcess(argv, 252, stderr=b"unsupported service")
        dump.write_bytes(b"observation")
        return CompletedProcess(argv, 0, stderr=b"")

    seen: list[bool] = []
    with (
        patch.object(backend, "build_harness", return_value=backend.Harness(b"guest", 0)),
        patch.object(backend, "_observation_from_dump", return_value=observation),
        patch.object(backend.subprocess, "run", side_effect=run_cli) as run,
    ):
        result = record_oracle(
            {"schema": "dosunit.vectors.v1", "vectors": vectors},
            backend="kvikdos", exe_path=tmp_path / "original.exe", kvikdos_path=executable,
        )
    assert run.call_count == 2
    assert len(result["vectors"]) == len(result["results"]) == 2
    failed, succeeded = result["results"]
    assert failed["status"] == "refused"
    assert failed["verdict"]["kind"] == "backend_failure"
    assert "unsupported service" in failed["diagnostics"][0]["message"]
    assert result["vectors"][0]["expected"] is None
    assert succeeded["status"] == "passed"
    assert result["vectors"][1]["expected"] == observation
