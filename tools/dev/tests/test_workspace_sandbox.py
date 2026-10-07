"""Focused unit tests for the repository-only Bubblewrap sandbox launcher.

Layer: Tests.
Responsibility: prove the pure argv contract, the exact KVM device/FD gate,
the 4 GiB limit ordering, and loud refusals; no real devices, bwrap, or exec.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tools.dev import workspace_sandbox as ws

REPO = Path(__file__).resolve().parents[3]
CHARDEV = stat.S_IFCHR | 0o666
REGFILE = stat.S_IFREG | 0o644
KVM_RDEV = os.makedev(ws.KVM_MAJOR, ws.KVM_MINOR)


def _stat_result(mode: int, rdev: int = 0) -> os.stat_result:
    """Build an os.stat_result carrying the requested mode and device id."""
    return os.stat_result((mode, 1, 2, 1, 0, 0, 0, 0, 0, 0), {"st_rdev": rdev})


def _patch_kvm(
    monkeypatch: pytest.MonkeyPatch,
    path_mode: int = CHARDEV,
    path_rdev: int = KVM_RDEV,
    fd_mode: int = CHARDEV,
    fd_rdev: int = KVM_RDEV,
    api: int = ws.KVM_API_VERSION,
) -> list[int]:
    """Point the module's device boundaries at fakes; return closed-fd log."""
    closed: list[int] = []
    monkeypatch.setattr(ws, "_stat_path", lambda path: _stat_result(path_mode, path_rdev))
    monkeypatch.setattr(ws, "_open_device", lambda path: 9)
    monkeypatch.setattr(ws, "_fstat_descriptor", lambda fd: _stat_result(fd_mode, fd_rdev))
    monkeypatch.setattr(ws, "_kvm_api_version", lambda fd: api)
    monkeypatch.setattr(ws, "_close_descriptor", closed.append)
    return closed


def test_default_argv_is_repository_only_with_no_host_devices() -> None:
    argv = ws.build_bwrap_argv(ws.SandboxSpec(repo_root=REPO, command=("echo", "hi")))
    assert argv[0] == "bwrap"
    for flag in ("--die-with-parent", "--unshare-pid", "--new-session", "--proc", "--dev", "--chdir"):
        assert flag in argv
    index = argv.index("--ro-bind")
    assert argv[index + 1 : index + 3] == ["/", "/"]
    index = argv.index("--bind")
    assert argv[index + 1 : index + 3] == [str(REPO), str(REPO)]
    assert "--dev-bind" not in argv
    assert "--bind-fd" not in argv
    assert "--sync-fd" not in argv
    assert argv[argv.index("--") + 1 :] == ["echo", "hi"]


def test_kvm_argv_transports_fd33_to_dev_kvm() -> None:
    argv = ws.build_bwrap_argv(ws.SandboxSpec(repo_root=REPO, command=("id",), with_kvm=True))
    fd = str(ws.KVM_TRANSPORT_DESCRIPTOR)
    sync = argv.index("--sync-fd")
    bind = argv.index("--dev-bind")
    assert argv[sync + 1] == fd
    assert argv[bind + 1 : bind + 3] == [f"/proc/self/fd/{fd}", "/dev/kvm"]
    assert argv.index("--dev") < bind  # private /dev exists before the bind


def test_command_tokens_pass_verbatim() -> None:
    command = ("python3", "-c", "print('a b')", "--not-an-option", "*")
    argv = ws.build_bwrap_argv(ws.SandboxSpec(repo_root=REPO, command=command))
    assert argv[argv.index("--") + 1 :] == list(command)


def test_root_filesystem_and_empty_command_are_refused() -> None:
    with pytest.raises(ValueError, match="root"):
        ws.build_bwrap_argv(ws.SandboxSpec(repo_root=Path("/"), command=("id",)))
    with pytest.raises(ValueError, match="command"):
        ws.build_bwrap_argv(ws.SandboxSpec(repo_root=REPO, command=()))


def test_repository_root_derives_from_this_file() -> None:
    assert ws.repository_root() == REPO


@pytest.mark.parametrize("root", [REPO.parent, REPO / "..", REPO / "../../.."])
def test_writable_bind_cannot_expand_outside_this_repository(root: Path) -> None:
    """Ancestor or normalized-root aliases cannot enlarge write authority."""
    with pytest.raises(ValueError):
        ws.build_bwrap_argv(ws.SandboxSpec(repo_root=root, command=("true",)))


def test_repository_alias_is_bound_at_the_canonical_exact_path() -> None:
    """Equivalent paths still produce exactly one canonical writable mount."""
    alias = REPO.parent / REPO.name / ".." / REPO.name
    argv = ws.build_bwrap_argv(ws.SandboxSpec(repo_root=alias, command=("true",)))
    bind = argv.index("--bind")
    assert argv[bind + 1:bind + 3] == [str(REPO), str(REPO)]


def test_empty_executable_is_refused() -> None:
    """Presence of argument tokens cannot disguise an empty executable."""
    with pytest.raises(ValueError):
        ws.build_bwrap_argv(ws.SandboxSpec(repo_root=REPO, command=("", "arg")))


def test_invalid_scope_has_no_device_or_resource_side_effects(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reject scope before opening KVM, changing limits or calling exec."""
    effects: list[str] = []
    monkeypatch.setattr(ws, "_find_bwrap", lambda: "/usr/bin/bwrap")
    monkeypatch.setattr(ws, "prepare_kvm_transport", lambda: effects.append("kvm"))
    monkeypatch.setattr(ws, "_set_address_limit", lambda: effects.append("limit"))
    monkeypatch.setattr(ws, "_exec", lambda _exe, _argv: effects.append("exec"))
    with pytest.raises(ValueError):
        ws.run(ws.SandboxSpec(repo_root=Path("/"), command=("true",), with_kvm=True))
    assert effects == []


def test_open_verified_kvm_accepts_exact_device_and_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_kvm(monkeypatch)
    assert ws.open_verified_kvm("/dev/kvm") == 9


def test_open_verified_kvm_rejects_regular_file_path() -> None:
    with pytest.MonkeyPatch.context() as mp:
        _patch_kvm(mp, path_mode=REGFILE)
        with pytest.raises(RuntimeError, match="10:232"):
            ws.open_verified_kvm("/dev/kvm")


def test_open_verified_kvm_rejects_wrong_device_numbers() -> None:
    with pytest.MonkeyPatch.context() as mp:
        _patch_kvm(mp, path_rdev=os.makedev(10, 233))
        with pytest.raises(RuntimeError, match="10:232"):
            ws.open_verified_kvm("/dev/kvm")


def test_open_verified_kvm_rejects_mismatched_descriptor_and_closes() -> None:
    with pytest.MonkeyPatch.context() as mp:
        closed = _patch_kvm(mp, fd_mode=REGFILE)
        with pytest.raises(RuntimeError, match="descriptor"):
            ws.open_verified_kvm("/dev/kvm")
        assert closed == [9]


def test_open_verified_kvm_rejects_wrong_api_and_closes() -> None:
    with pytest.MonkeyPatch.context() as mp:
        closed = _patch_kvm(mp, api=11)
        with pytest.raises(RuntimeError, match="API"):
            ws.open_verified_kvm("/dev/kvm")
        assert closed == [9]


def test_open_verified_kvm_propagates_missing_path_cause() -> None:
    with pytest.MonkeyPatch.context() as mp:
        def _missing(path: str) -> os.stat_result:
            raise FileNotFoundError(path)

        mp.setattr(ws, "_stat_path", _missing)
        with pytest.raises(FileNotFoundError):
            ws.open_verified_kvm("/dev/kvm")


def test_open_verified_kvm_propagates_ioctl_failure_and_closes() -> None:
    with pytest.MonkeyPatch.context() as mp:
        closed = _patch_kvm(mp)
        mp.setattr(ws, "_kvm_api_version", lambda fd: (_ for _ in ()).throw(OSError("ioctl")))
        with pytest.raises(OSError):
            ws.open_verified_kvm("/dev/kvm")
        assert closed == [9]


def test_prepare_kvm_transport_pins_and_releases_source_fd() -> None:
    with pytest.MonkeyPatch.context() as mp:
        duped: list[int] = []
        closed: list[int] = []
        mp.setattr(ws, "open_verified_kvm", lambda path: 9)
        mp.setattr(ws, "_dup_to_transport", duped.append)
        mp.setattr(ws, "_close_descriptor", closed.append)
        ws.prepare_kvm_transport()
        assert duped == [9]
        assert closed == [9]


def test_prepare_kvm_transport_does_not_close_transport_fd() -> None:
    with pytest.MonkeyPatch.context() as mp:
        closed: list[int] = []
        mp.setattr(ws, "open_verified_kvm", lambda path: ws.KVM_TRANSPORT_DESCRIPTOR)
        mp.setattr(ws, "_dup_to_transport", lambda fd: None)
        mp.setattr(ws, "_close_descriptor", closed.append)
        ws.prepare_kvm_transport()
        assert closed == []


def test_run_fails_loudly_when_bwrap_is_absent() -> None:
    with pytest.MonkeyPatch.context() as mp:
        executed: list[list[str]] = []
        mp.setattr(ws, "_find_bwrap", lambda: None)
        mp.setattr(ws, "_exec", lambda exe, argv: executed.append(argv))
        with pytest.raises(FileNotFoundError, match="bwrap"):
            ws.run(ws.SandboxSpec(repo_root=REPO, command=("id",)))
        assert executed == []


def test_run_applies_4gib_limit_and_execs_bwrap() -> None:
    with pytest.MonkeyPatch.context() as mp:
        limits: list[tuple[int, int]] = []
        executed: list[tuple[str, list[str]]] = []
        mp.setattr(ws, "_find_bwrap", lambda: "/usr/bin/bwrap")
        mp.setattr(ws, "_set_address_limit", lambda: limits.append(
            (ws.ADDRESS_LIMIT_BYTES, ws.ADDRESS_LIMIT_BYTES)
        ))
        mp.setattr(ws, "_exec", lambda exe, argv: executed.append((exe, argv)))
        spec = ws.SandboxSpec(repo_root=REPO, command=("echo", "ok"))
        ws.run(spec)
        assert limits == [(ws.ADDRESS_LIMIT_BYTES, ws.ADDRESS_LIMIT_BYTES)]
        assert executed == [("/usr/bin/bwrap", ws.build_bwrap_argv(spec))]


def test_run_verifies_kvm_before_limit_and_exec() -> None:
    with pytest.MonkeyPatch.context() as mp:
        order: list[str] = []
        mp.setattr(ws, "_find_bwrap", lambda: "/usr/bin/bwrap")
        mp.setattr(ws, "prepare_kvm_transport", lambda: order.append("kvm"))
        mp.setattr(ws, "_set_address_limit", lambda: order.append("limit"))
        mp.setattr(ws, "_exec", lambda exe, argv: order.append("exec"))
        ws.run(ws.SandboxSpec(repo_root=REPO, command=("id",), with_kvm=True))
        assert order == ["kvm", "limit", "exec"]


def test_run_without_kvm_never_touches_devices() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ws, "_find_bwrap", lambda: "/usr/bin/bwrap")
        mp.setattr(ws, "_set_address_limit", lambda: None)
        mp.setattr(ws, "_exec", lambda exe, argv: None)
        mp.setattr(ws, "open_verified_kvm", lambda path: pytest.fail("device opened"))
        ws.run(ws.SandboxSpec(repo_root=REPO, command=("id",), with_kvm=False))


def test_parse_requires_separator_and_command() -> None:
    with pytest.raises(SystemExit):
        ws._parse(["--with-kvm"])
    with pytest.raises(SystemExit):
        ws._parse(["--with-kvm", "--"])
    with pytest.raises(SystemExit):
        ws._parse(["--bogus", "--", "id"])


def test_parse_splits_options_from_verbatim_command() -> None:
    options = ws._parse(["--with-kvm", "--", "echo", "--flag", "a b"])
    assert options.with_kvm is True
    assert options.command == ("echo", "--flag", "a b")
    options = ws._parse(["--", "echo"])
    assert options.with_kvm is False
    assert options.command == ("echo",)
