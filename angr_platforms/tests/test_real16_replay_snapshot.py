"""Executed MZ bytes and stability checks share one immutable input snapshot."""

import hashlib

import pytest
from test_real16_replay_cli import _mz, _run_cli, _vector

from tools.dosunit import real16_replay, real16_replay_cli
from tools.dosunit.model import DosUnitError


def test_transient_second_binary_read_refuses_before_report(monkeypatch, tmp_path):
    """A changed verification read must not be consumed as executable bytes."""
    reads = {}

    def transient_read(path, what):
        reads[path] = reads.get(path, 0) + 1
        return _mz(bytes.fromhex("b83512c3")) if reads[path] == 2 else path.read_bytes()

    monkeypatch.setattr(real16_replay_cli, "_read_bytes", transient_read)
    with pytest.raises(DosUnitError, match="binary changed during real16 replay"):
        _run_cli(real16_replay_cli, tmp_path, bytes.fromhex("b83412c3"), bytes.fromhex("b83412c3"),
                 [_vector()])
    assert not (tmp_path / "report.json").exists()


def test_snapshot_fingerprint_binds_executed_bytes(monkeypatch, tmp_path):
    """Each file is read once for execution and once for final verification."""
    reads, executed = {}, []
    original_replay = real16_replay.replay

    def count_read(path, what):
        reads[path] = reads.get(path, 0) + 1
        return path.read_bytes()

    def observe_image(image, *args, **kwargs):
        executed.append(image.file_sha256)
        return original_replay(image, *args, **kwargs)

    monkeypatch.setattr(real16_replay_cli, "_read_bytes", count_read)
    monkeypatch.setattr(real16_replay, "replay", observe_image)
    code = bytes.fromhex("b83412c3")
    status, report = _run_cli(real16_replay_cli, tmp_path, code, code, [_vector()])
    assert status == 0
    assert reads == {tmp_path / "oracle.exe": 2, tmp_path / "candidate.exe": 2}
    expected = hashlib.sha256(_mz(code)).hexdigest()
    assert executed == [expected, expected]
    assert [report["inputs"][side]["sha256"] for side in ("oracle", "candidate")] == executed


def test_persistent_binary_mutation_during_guest_run_refuses(monkeypatch, tmp_path):
    """A real mid-execution file rewrite invalidates the report."""
    original_replay = real16_replay.replay

    def mutate_image(image, *args, **kwargs):
        (tmp_path / "oracle.exe").write_bytes(_mz(bytes.fromhex("b83512c3")))
        return original_replay(image, *args, **kwargs)

    monkeypatch.setattr(real16_replay, "replay", mutate_image)
    with pytest.raises(DosUnitError, match="binary changed during real16 replay"):
        _run_cli(real16_replay_cli, tmp_path, bytes.fromhex("b83412c3"), bytes.fromhex("b83412c3"),
                 [_vector()])
    assert not (tmp_path / "report.json").exists()
