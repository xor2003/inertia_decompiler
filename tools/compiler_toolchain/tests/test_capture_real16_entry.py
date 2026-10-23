"""Complete full-width initial-state conversion and corruption controls."""

import copy
import hashlib
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools.compiler_toolchain import capture_real16_entry as tool
from tools.compiler_toolchain.capture_real16_entry import convert_capture
from tools.compiler_toolchain.capture_real16_gdb import debugger_script
from tools.dosunit.reporting.real16_program_manifest import parse_program_manifest

pytestmark = pytest.mark.compiler_toolchain


def capture():
    header = bytearray(64)
    size = 65
    header[:2] = b"MZ"
    for offset, value in ((2, size), (4, 1), (8, 4), (12, 0x400), (16, 0x1000), (24, 0x1C)):
        header[offset:offset + 2] = value.to_bytes(2, "little")
    source = bytes(header) + b"\xC3"
    memory = bytearray(b"\xA5" * 0x100000)
    memory[0x10000:0x10004] = b"\xCD\x20\x00\x12"
    memory[0x10100] = 0xC3
    identities = {"source": hashlib.sha256(source).hexdigest(), "native_exe": "n", "gdb": "g", "config": "c",
                  "target_stem": "TEST"}
    registers = dict.fromkeys(("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"), 0x12340000)
    registers.update(esp=0x1000, eflags=0x202)
    record = {"schema": "inertia.real16_entry_capture.v1", "identities": identities,
              "memory_sha256": hashlib.sha256(memory).hexdigest(), "registers": registers,
              "segments": {"cs": 0x1010, "ss": 0x1010, "ds": 0x1000, "es": 0x1000, "fs": 0, "gs": 0},
              "eip": 0, "lazy_flags_type": 0,
              "loader": {"load_segment": 0x1010, "cs": 0x1010, "ip": 0, "ss": 0x1010, "sp": 0x1000}}
    return source, record, bytes(memory), identities


def test_full_width_state_and_exact_memory_survive_conversion():
    source, record, memory, identities = capture()
    manifest = parse_program_manifest(convert_capture(source, record, memory, identities))
    assert dict(manifest.environment.registers)["eax"] == 0x12340000
    assert manifest.environment.allocation == memory[0x10000:0x12000]
    assert manifest.environment.version_policy is None
    assert manifest.environment.vector_policy is None
    assert manifest.environment.memory_layout().contains(0, 0xA0000)


@pytest.mark.parametrize("field,value", [("lazy_flags_type", 1), ("lazy_flags_type", None),
                                        ("eip", 1), ("memory_sha256", "wrong"),
                                        ("identities", {}), ("schema", "other")])
def test_capture_corruption_refuses(field, value):
    source, record, memory, identities = capture()
    record[field] = value
    with pytest.raises(ValueError):
        convert_capture(source, record, memory, identities)


@pytest.mark.parametrize("group,field,value", [("segments", "es", 0x1001), ("segments", "cs", 0x1011),
                                              ("segments", "ss", 0x1011), ("registers", "esp", 0x12341000),
                                              ("loader", "ip", 1), ("registers", "eax", None)])
def test_inconsistent_or_partial_state_refuses(group, field, value):
    source, record, memory, identities = capture()
    record[group][field] = value
    with pytest.raises(ValueError):
        convert_capture(source, record, memory, identities)


def test_guest_image_mutation_refuses_even_with_rehashed_snapshot():
    source, record, memory, identities = capture()
    changed = bytearray(memory)
    changed[0x10100] = 0x90
    record["memory_sha256"] = hashlib.sha256(changed).hexdigest()
    with pytest.raises(ValueError, match="relocated source"):
        convert_capture(source, record, bytes(changed), identities)


def test_source_identity_and_missing_register_refuse():
    source, record, memory, identities = capture()
    with pytest.raises(ValueError, match="identities"):
        convert_capture(source + b"\x90", record, memory, identities)
    incomplete = copy.deepcopy(record)
    del incomplete["registers"]["edi"]
    with pytest.raises(ValueError, match="missing"):
        convert_capture(source, incomplete, memory, identities)


def test_debugger_commands_capture_full_width_before_first_instruction(tmp_path):
    script = debugger_script("TARGET", tmp_path, {"source": "sha"})
    assert "cpu_regs.regs[%d].dword[0]" in script
    assert "cpu_regs.ip.dword[0]" in script
    assert "lflags.type" in script
    assert "core.cseip ==" in script
    assert "gdb.selected_inferior().read_memory" in script
    assert "custom_init_entrypoint" in script
    embedded = script.split("python\n", 1)[1].rsplit("\nend\n", 1)[0]
    compile(embedded, "capture-gdb", "exec")


@pytest.mark.parametrize("changed,wrong", [("core.cseip", 0), ("Segs.val[1]", 0xF000),
                                         ("cpu_regs.ip.dword[0]", 0x14C6)])
def test_gdb_stop_rejects_wrong_entry_before_any_capture(tmp_path, monkeypatch, changed, wrong):
    source, record, memory, identities = capture()
    values = {"core.cseip": 0x10100, "MemBase": 0, "cpu_regs.ip.dword[0]": 0,
              "cpu_regs.flags": record["registers"]["eflags"], "lflags.type": 0}
    for index, name in enumerate(("es", "cs", "ss", "ds", "fs", "gs")):
        values[f"Segs.val[{index}]"] = record["segments"][name]
    for index, name in enumerate(("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")):
        values[f"cpu_regs.regs[{index}].dword[0]"] = record["registers"][name]
    actions = []

    class Breakpoint:
        def __init__(self, *args, **kwargs):
            pass

    def read_memory(address, size):
        actions.append("read_memory")
        assert address == 0 and size == 0x100000
        return memory

    fake = SimpleNamespace(Breakpoint=Breakpoint, parse_and_eval=lambda expression: values[expression],
                           selected_inferior=lambda: SimpleNamespace(read_memory=read_memory),
                           execute=lambda command: actions.append(command))
    monkeypatch.setitem(sys.modules, "gdb", fake)
    script = debugger_script("TEST", tmp_path, identities)
    embedded = script.split("python\n", 1)[1].rsplit("\nend\n", 1)[0]
    namespace = {}
    exec(compile(embedded, "capture-gdb", "exec"), namespace)
    entry = namespace["Entry"](record["loader"])
    original = values[changed]
    values[changed] = wrong
    assert entry.stop() is False
    assert actions == []
    assert not (tmp_path / "capture.json").exists()
    assert not (tmp_path / "memory.bin").exists()
    values[changed] = original
    assert entry.stop() is True
    assert actions == ["read_memory", "quit"]
    snapshot = json.loads((tmp_path / "capture.json").read_text())
    assert snapshot["eip"] == 0
    assert snapshot["segments"]["cs"] == 0x1010
    convert_capture(source, snapshot, (tmp_path / "memory.bin").read_bytes(), identities)


def test_cli_timeout_retains_logs_and_refuses_without_environment(tmp_path, monkeypatch):
    paths = []
    for name in ("source", "native-exe", "gdb", "config"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        paths.extend((f"--{name}", str(path)))
    output = tmp_path / "output"

    def timeout(command, *, timeout, cleanup_process_group):
        assert cleanup_process_group
        assert timeout == 0.1
        raise subprocess.TimeoutExpired(command, timeout, output="capturing", stderr="timed out")

    monkeypatch.setattr(tool, "_run", timeout)
    status = tool.main(["capture", *paths, "--out-dir", str(output), "--target-stem", "TEST", "--timeout", "0.1"])
    assert status == 2
    assert json.loads((output / "report.json").read_text())["status"] == "refused"
    assert "timed out" in (output / "capture.log").read_text()
    assert not (output / "environment.json").exists()


def test_missing_tool_identity_refuses():
    source, record, memory, identities = capture()
    del identities["gdb"]
    with pytest.raises(ValueError, match="every explicit"):
        convert_capture(source, record, memory, identities)


@pytest.mark.parametrize("target", ["", "../ABC", "ABC.EXE", "A\nB", "ABCDEFGHI", "é"])
def test_invalid_target_stem_refuses(target):
    with pytest.raises(ValueError, match="stem"):
        tool._check_target(target)


def test_cli_config_drift_is_detected_before_conversion(tmp_path, monkeypatch):
    arguments = []
    for name in ("source", "native-exe", "gdb", "config"):
        path = tmp_path / name
        path.write_bytes(name.encode())
        arguments.extend((f"--{name}", str(path)))

    def mutate(command, *, timeout, cleanup_process_group):
        (tmp_path / "config").write_bytes(b"changed")
        return subprocess.CompletedProcess(command, 0, "captured", "")

    monkeypatch.setattr(tool, "_run", mutate)
    output = tmp_path / "out"
    assert tool.main(["capture", *arguments, "--out-dir", str(output), "--target-stem", "TEST"]) == 2
    report = json.loads((output / "report.json").read_text())
    assert report["status"] == "refused"
    assert "changed during execution" in report["reason"]
