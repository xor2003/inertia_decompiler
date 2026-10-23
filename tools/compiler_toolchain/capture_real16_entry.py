"""Capture and authenticate real16 executable entry state using explicit tools.

Layer: compiler tooling.
Responsibility: turn full-width live guest snapshots into the canonical initial
program manifest; execution evidence never invents DOS service contracts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
from enum import StrEnum
from pathlib import Path

from tools.compiler_toolchain.capture_real16_gdb import debugger_script
from tools.compiler_toolchain.compiler_profile import _run
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes


class CaptureStatus(StrEnum):
    """Capture authentication is separate from semantic validation."""

    CAPTURED = "captured"
    REFUSED = "refused"


def file_hash(path: Path) -> str:
    """Hash an explicit immutable input without path-based identity guesses."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identities(args: argparse.Namespace) -> dict[str, str]:
    """Authenticate every explicitly selected input and guest target."""
    identities = {name: file_hash(path) for name, path in
                  (("source", args.source), ("native_exe", args.native_exe),
                   ("gdb", args.gdb), ("config", args.config))}
    identities["target_stem"] = args.target_stem
    return identities


def _check_target(target: str) -> None:
    """Require an explicit DOS executable stem without path/control syntax."""
    punctuation = "_~!#$%&'()-@^`{}"
    if not 1 <= len(target) <= 8 or not target.isascii():
        raise ValueError("target must be a DOS executable stem")
    if any(not (character.isalnum() or character in punctuation) for character in target):
        raise ValueError("target must be a DOS executable stem")


def _object(value: object, label: str) -> dict[str, object]:
    """Require JSON objects with explicit string keys."""
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label}: expected object")
    return value


def _words(value: object, names: set[str], width: int, label: str) -> dict[str, int]:
    """Require every field exactly once and its architectural unsigned width."""
    fields = _object(value, label)
    if set(fields) != names:
        raise ValueError(f"{label}: missing or unexpected fields")
    result: dict[str, int] = {}
    for key, number in fields.items():
        if type(number) is not int or not 0 <= number < 1 << width:
            raise ValueError(f"{label}.{key}: invalid unsigned value")
        result[key] = number
    return result


def _extra_memory(memory: bytes, start: int, end: int) -> list[dict[str, object]]:
    """Declare exact captured conventional bytes outside the allocation."""
    result: list[dict[str, object]] = []
    for first, last in ((0, start), (end, 0xA0000)):
        for address in range(first, last, 0x10000):
            result.append({"segment": address >> 4, "offset": 0,
                           "data_hex": memory[address:min(address + 0x10000, last)].hex()})
    return result


def _authenticate_memory(capture: dict[str, object], memory: bytes) -> None:
    """Require the exact complete snapshot and fully materialized flags."""
    if len(memory) != 0x100000 or capture.get("memory_sha256") != hashlib.sha256(memory).hexdigest():
        raise ValueError("capture memory identity or size differs")
    if type(capture.get("lazy_flags_type")) is not int or capture["lazy_flags_type"] != 0:
        raise ValueError("pending or missing lazy flags")


def _authenticate_identity(capture: dict[str, object], source: bytes, identities: dict[str, str]) -> None:
    """Reject partial identities and changes to explicitly selected inputs."""
    if capture.get("schema") != "inertia.real16_entry_capture.v1":
        raise ValueError("unsupported capture schema")
    if set(identities) != {"source", "native_exe", "gdb", "config", "target_stem"}:
        raise ValueError("capture identities require every explicit input")
    if capture.get("identities") != identities or identities.get("source") != hashlib.sha256(source).hexdigest():
        raise ValueError("capture input identities changed")


def convert_capture(
    source: bytes, record: object, memory: bytes, identities: dict[str, str],
) -> dict[str, object]:
    """Authenticate complete captured state through canonical MZ boot owners.

    PSP arena limits are read from the captured PSP, not chosen by the tool.
    Lazy flags, mismatched image bytes and inconsistent entry state refuse.
    """
    capture = _object(record, "capture")
    _authenticate_identity(capture, source, identities)
    _authenticate_memory(capture, memory)
    registers = _words(capture.get("registers"),
                       {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eflags"}, 32, "registers")
    segments = _words(capture.get("segments"), {"cs", "ss", "ds", "es", "fs", "gs"}, 16, "segments")
    loader = _words(capture.get("loader"), {"load_segment", "cs", "ip", "ss", "sp"}, 16, "loader")
    eip = _words({"eip": capture.get("eip")}, {"eip"}, 32, "control")["eip"]
    psp = segments["ds"]
    if segments["es"] != psp or loader["load_segment"] != psp + 0x10:
        raise ValueError("captured PSP DS/ES disagree with loader")
    start = psp << 4
    end = int.from_bytes(memory[start + 2:start + 4], "little") << 4
    if not start + 256 <= end <= 0xA0000:
        raise ValueError("captured PSP allocation is invalid")
    document: dict[str, object] = {
        "schema": "dosunit.real16_program_environment.v1",
        "environment": {"psp_segment": psp, "allocation_hex": memory[start:end].hex(),
                        "registers": registers, "fs": segments["fs"], "gs": segments["gs"],
                        "extra_memory": _extra_memory(memory, start, end)},
        "observations": [],
    }
    manifest = parse_program_manifest(document)
    boot = program_from_mz_bytes(source, manifest.environment)
    expected = {"load_segment": psp + 0x10, "cs": boot.entry.segment, "ip": boot.entry.offset,
                "ss": boot.stack.segment, "sp": boot.stack.offset}
    if loader != expected or (segments["cs"], eip) != (boot.entry.segment, boot.entry.offset):
        raise ValueError("captured control coordinates differ from MZ header")
    if (segments["ss"], registers["esp"]) != (boot.stack.segment, boot.stack.offset):
        raise ValueError("captured stack coordinates differ from MZ header")
    for address, data in boot.image.chunks:
        if memory[address:address + len(data)] != data:
            raise ValueError("captured guest image differs from relocated source")
    return document


def main(argv: list[str] | None = None) -> int:
    """Capture or convert explicit inputs, retaining logs and typed refusals."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "convert"))
    for option in ("source", "native-exe", "gdb", "config", "out-dir"):
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--target-stem", required=True)
    parser.add_argument("--capture-json", type=Path)
    parser.add_argument("--memory", type=Path)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    output: Path = args.out_dir
    output.mkdir(parents=True, exist_ok=True)
    try:
        _check_target(args.target_stem)
        if not math.isfinite(args.timeout) or args.timeout <= 0:
            raise ValueError("positive timeout required")
        identities = _identities(args)
        capture_path = args.capture_json
        memory_path = args.memory
        if args.mode == "capture":
            capture_path, memory_path = output / "capture.json", output / "memory.bin"
            if capture_path.exists() or memory_path.exists():
                raise ValueError("capture output already exists; use a fresh directory")
            script = output / "capture.gdb"
            script.write_text(debugger_script(args.target_stem, output, identities))
            process = _run([str(args.gdb), "--batch", "-x", str(script), "--args",
                            str(args.native_exe), "-conf", str(args.config)],
                           timeout=args.timeout, cleanup_process_group=True)
            (output / "capture.log").write_text(process.stdout + process.stderr)
            if process.returncode != 0:
                raise ValueError(f"debugger exited {process.returncode}")
        if capture_path is None or memory_path is None:
            raise ValueError("conversion requires explicit capture JSON and memory")
        if _identities(args) != identities:
            raise ValueError("capture inputs changed during execution")
        document = convert_capture(args.source.read_bytes(), json.loads(capture_path.read_text()),
                                   memory_path.read_bytes(), identities)
        (output / "environment.json").write_text(json.dumps(document, indent=2) + "\n")
        report = {"status": CaptureStatus.CAPTURED, "identities": identities,
                  "proof_status": "not_established_by_execution"}
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        if isinstance(error, subprocess.TimeoutExpired):
            (output / "capture.log").write_text(str(error.output or "") + str(error.stderr or ""))
        report = {"status": CaptureStatus.REFUSED, "reason": str(error)}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0 if report["status"] == CaptureStatus.CAPTURED else 2


if __name__ == "__main__":
    raise SystemExit(main())
