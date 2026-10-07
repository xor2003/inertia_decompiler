#!/usr/bin/env python3
"""Execute one command inside the verified repository-only Bubblewrap sandbox.

Layer: Tooling/sandbox.
Responsibility: build and exec the exact read-only-host / writable-repository
boundary (private /proc and /dev, new session, private PID namespace,
die-with-parent, 4 GiB address-space limit) and optionally transport the
exact /dev/kvm character device through a descriptor opened and verified in
this process before exec. The launcher never falls back to a weaker sandbox,
never exposes host devices by default, and never creates host device nodes.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import resource
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn

ADDRESS_LIMIT_BYTES: Final[int] = 4 * 1024 * 1024 * 1024
BWRAP_EXECUTABLE: Final[str] = "bwrap"
KVM_DEVICE_PATH: Final[str] = "/dev/kvm"
KVM_TRANSPORT_DESCRIPTOR: Final[int] = 33
KVM_MAJOR: Final[int] = 10
KVM_MINOR: Final[int] = 232
KVM_API_VERSION: Final[int] = 12
KVM_GET_API_VERSION: Final[int] = 0xAE00
EXPECTED_KVM_IDENTITY: Final[tuple[bool, int, int]] = (True, KVM_MAJOR, KVM_MINOR)


@dataclass(frozen=True)
class SandboxSpec:
    """Immutable contract for one sandboxed launch.

    `repo_root` must resolve to `repository_root()` for every caller, not
    just the CLI. The boundary binds that exact canonical path writable
    and the rest of the host read-only.
    """

    repo_root: Path
    command: tuple[str, ...]
    with_kvm: bool = False


@dataclass(frozen=True)
class CliOptions:
    """Parsed CLI contract: flag state plus the verbatim command tail."""

    with_kvm: bool
    command: tuple[str, ...]


def repository_root() -> Path:
    """Return the repository root derived from this file's location."""
    return Path(__file__).resolve().parents[2]


def _stat_path(path: str) -> os.stat_result:
    """Stat a candidate device path; missing paths raise FileNotFoundError."""
    return os.stat(path)


def _open_device(path: str) -> int:
    """Open a candidate device read-write without descriptor inheritance."""
    return os.open(path, os.O_RDWR | os.O_CLOEXEC)


def _fstat_descriptor(descriptor: int) -> os.stat_result:
    """Stat an already-opened descriptor to check its real identity."""
    return os.fstat(descriptor)


def _kvm_api_version(descriptor: int) -> int:
    """Issue KVM_GET_API_VERSION against an opened descriptor."""
    return int(fcntl.ioctl(descriptor, KVM_GET_API_VERSION))


def _close_descriptor(descriptor: int) -> None:
    """Close one descriptor."""
    os.close(descriptor)


def _dup_to_transport(descriptor: int) -> None:
    """Pin a verified descriptor onto the known high transport FD."""
    os.dup2(descriptor, KVM_TRANSPORT_DESCRIPTOR, inheritable=True)


def _find_bwrap() -> str | None:
    """Resolve the bubblewrap executable, or None when absent."""
    return shutil.which(BWRAP_EXECUTABLE)


def _set_address_limit() -> None:
    """Apply the fixed 4 GiB address-space limit to this process."""
    resource.setrlimit(resource.RLIMIT_AS, (ADDRESS_LIMIT_BYTES, ADDRESS_LIMIT_BYTES))


def _exec(executable: str, argv: list[str]) -> NoReturn:
    """Replace this process image; exec errors propagate to the caller."""
    os.execvp(executable, argv)


def _device_identity(status: os.stat_result) -> tuple[bool, int, int]:
    """Return (is-char-device, major, minor) for one stat result."""
    rdev = status.st_rdev
    return (
        stat.S_ISCHR(status.st_mode),
        os.major(rdev) if rdev is not None else -1,
        os.minor(rdev) if rdev is not None else -1,
    )


def open_verified_kvm(path: str) -> int:
    """Open `path` only when path and descriptor are exact char 10:232 API12.

    Boundary errors (missing path, open or ioctl failure) propagate with
    their original cause; an identity or API mismatch raises RuntimeError
    after the opened descriptor is closed.
    """
    if _device_identity(_stat_path(path)) != EXPECTED_KVM_IDENTITY:
        raise RuntimeError(f"{path} is not the exact KVM character device {KVM_MAJOR}:{KVM_MINOR}")
    descriptor = _open_device(path)
    verified = False
    try:
        if _device_identity(_fstat_descriptor(descriptor)) != EXPECTED_KVM_IDENTITY:
            raise RuntimeError(
                f"opened descriptor for {path} is not the exact KVM character device "
                f"{KVM_MAJOR}:{KVM_MINOR}"
            )
        api = _kvm_api_version(descriptor)
        if api != KVM_API_VERSION:
            raise RuntimeError(f"{path} reports KVM API version {api}; expected {KVM_API_VERSION}")
        verified = True
        return descriptor
    finally:
        if not verified:
            _close_descriptor(descriptor)


def prepare_kvm_transport() -> None:
    """Verify host /dev/kvm and pin it to the well-known transport FD."""
    descriptor = open_verified_kvm(KVM_DEVICE_PATH)
    try:
        _dup_to_transport(descriptor)
    finally:
        if descriptor != KVM_TRANSPORT_DESCRIPTOR:
            _close_descriptor(descriptor)


def build_bwrap_argv(spec: SandboxSpec) -> list[str]:
    """Build the exact bubblewrap argv for `spec`; pure and side-effect free."""
    if spec.repo_root == Path("/"):
        raise ValueError("refusing a writable bind of the filesystem root")
    canonical_root = spec.repo_root.resolve()
    if canonical_root != repository_root():
        raise ValueError("the writable bind must be this exact repository root")
    if not spec.command or not spec.command[0]:
        raise ValueError("refusing an empty sandboxed command")
    root = str(canonical_root)
    argv = [
        BWRAP_EXECUTABLE, "--die-with-parent", "--unshare-pid", "--new-session",
        "--ro-bind", "/", "/", "--bind", root, root,
        "--proc", "/proc", "--dev", "/dev",
    ]
    if spec.with_kvm:
        transport = str(KVM_TRANSPORT_DESCRIPTOR)
        argv += ["--sync-fd", transport, "--dev-bind", f"/proc/self/fd/{transport}", KVM_DEVICE_PATH]
    argv += ["--chdir", root, "--", *spec.command]
    return argv


def run(spec: SandboxSpec) -> NoReturn:
    """Verify the boundary, apply the address limit, and exec the command."""
    argv = build_bwrap_argv(spec)
    executable = _find_bwrap()
    if executable is None:
        raise FileNotFoundError(f"{BWRAP_EXECUTABLE} executable not found on PATH")
    if spec.with_kvm:
        prepare_kvm_transport()
    _set_address_limit()
    _exec(executable, argv)


def _parse(argv: list[str]) -> CliOptions:
    """Split `--` so launcher options never consume command tokens."""
    parser = argparse.ArgumentParser(
        prog="workspace_sandbox",
        description="Run COMMAND inside the repository-only Bubblewrap sandbox.",
    )
    parser.add_argument("--with-kvm", action="store_true", help="transport verified /dev/kvm via FD 33")
    if "--" not in argv:
        parser.error("missing '--' separator before COMMAND")
    index = argv.index("--")
    command = argv[index + 1 :]
    if not command:
        parser.error("missing COMMAND after '--'")
    options = parser.parse_args(argv[:index])
    return CliOptions(with_kvm=options.with_kvm, command=tuple(command))


def main(argv: list[str] | None = None) -> NoReturn:
    """CLI entry: `workspace_sandbox.py [--with-kvm] -- COMMAND [ARG...]`."""
    options = _parse(list(sys.argv[1:]) if argv is None else argv)
    run(
        SandboxSpec(
            repo_root=repository_root(),
            command=options.command,
            with_kvm=options.with_kvm,
        )
    )


if __name__ == "__main__":
    main()
