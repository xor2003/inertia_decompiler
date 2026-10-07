"""Compiler profiles must route verified toolchain settings, never MS C 6 guesses."""

import argparse
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import tools.compiler_toolchain.build_msc6_examples as harness
from tools.compiler_toolchain.compiler_coverage_manifest import load_manifest
from tools.compiler_toolchain.compiler_profile import (
    DEFAULT_PROFILE_REGISTRY,
    MANIFEST_COMPILER_NAMES,
    MSC6_AX_PROFILE_ID,
    CompileBackend,
    CompilerIdentity,
    UnsupportedCompilerProfile,
    compiler_toolchain_lock,
    load_compiler_profiles,
    msc6_ax_toolchain,
    resolve_case_toolchain,
    select_manifest_profile,
)
from tools.compiler_toolchain.msc6_memory_model import MSCMemoryModel


def _manifest(tmp_path, *, compiler="Microsoft C v5.1", flags=("/Od", "/AS"), model="small"):
    payload = {
        "schema": 1,
        "profile": {"id": "test", "compiler": compiler, "flags": list(flags), "memory_model": model},
        "scope": {"admitted": ["calls.direct"], "later": [], "excluded": [], "undecided": []},
        "cases": [{"id": "calls", "construct": "function_pointers", "obligations": ["calls.direct"]}],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_manifest(path)


def _pinned(root: Path, dos_path: str, payload: bytes) -> dict[str, str]:
    """Create the host file backing one e:-mounted tool and return its record."""
    host = root.joinpath(*dos_path[3:].split("\\"))
    host.parent.mkdir(parents=True, exist_ok=True)
    host.write_bytes(payload)
    return {"dos_path": dos_path, "sha256": hashlib.sha256(payload).hexdigest()}


def _runner_record(path: Path, payload: bytes, *, environment: dict | None = None) -> dict:
    """Write a fake runner binary and return its pinned runner record."""
    path.write_bytes(payload)
    record: dict[str, object] = {"path": str(path), "sha256": hashlib.sha256(payload).hexdigest()}
    if environment is not None:
        record["host_environment"] = environment
    return record


_DEP_FILES: dict[str, tuple[str, bytes]] = {
    "msc51": ("e:\\bin\\C1.EXE", b"fixture-c1"),
    "bcpp31": ("e:\\BIN\\DPMILOAD.EXE", b"fixture-dpmiload"),
}


def _dep_map(root: Path, group: str, extra: dict[str, bytes] | None = None) -> dict[str, str]:
    """Pin the spawned-tool files for one probe inventory group."""
    entries = [_DEP_FILES[group]]
    if extra is not None:
        entries.extend(sorted(extra.items()))
    pinned = {}
    for dos_path, payload in entries:
        pinned[dos_path] = _pinned(root, dos_path, payload)["sha256"]
    return pinned


def _borland_record(root: Path, **overrides) -> dict:
    """A bc31-style registry profile record backed by real fixture files."""
    record = {
        "id": "bc31-small",
        "probe_id": "bcpp31-small",
        "aliases": ["bcpp31-small"],
        "dependency_group": "bcpp31",
        "compiler": "Borland C++ 3.1",
        "memory_model": "small",
        "declared_flags": ["-Od", "-ms"],
        "compile_backend": "dosbox",
        "run_backend": "kvikdos",
        "toolchain_root": str(root),
        "tools": {
            "compiler": _pinned(root, "e:\\BIN\\BCC.EXE", b"bcc31"),
            "linker": _pinned(root, "e:\\BIN\\TLINK.EXE", b"tlink31"),
        },
        "libraries": [
            _pinned(root, "e:\\LIB\\C0S.OBJ", b"c0s"),
            _pinned(root, "e:\\LIB\\CS.LIB", b"cs-lib"),
            _pinned(root, "e:\\LIB\\EMU.LIB", b"emu"),
            _pinned(root, "e:\\LIB\\MATHS.LIB", b"maths"),
        ],
        "compiler_path_dos": ["e:\\BIN"],
        "linker_path_dos": ["e:\\BIN"],
        "compiler_environment": [["INCLUDE", "e:\\INCLUDE;c:\\"], ["LIB", "e:\\LIB"]],
        "linker_environment": [["INCLUDE", "e:\\INCLUDE;c:\\"], ["LIB", "e:\\LIB"]],
        "compile_arguments": ["-Od", "-ms", "-IE:\\INCLUDE", "-c", "-oc:\\{obj}", "c:\\{source}"],
        "cod_argument": None,
        "link_argument": (
            "/m /s e:\\LIB\\C0S+c:\\{obj}{extra_objs},c:\\{exe},c:\\{map},"
            "e:\\LIB\\CS e:\\LIB\\EMU e:\\LIB\\MATHS"
        ),
        "extra_object_format": "+c:\\{extra_obj}",
    }
    record.update(overrides)
    return record


def _msc51_record(root: Path, **overrides) -> dict:
    """An msc51-style registry profile record backed by real fixture files."""
    record = {
        "id": "msc51-small",
        "probe_id": "msc51-small",
        "aliases": [],
        "dependency_group": "msc51",
        "compiler": "Microsoft C v5.1",
        "memory_model": "small",
        "declared_flags": ["/Od", "/AS"],
        "compile_backend": "kvikdos",
        "run_backend": "kvikdos",
        "toolchain_root": str(root),
        "tools": {
            "compiler": _pinned(root, "e:\\bin\\CL.EXE", b"cl51"),
            "linker": _pinned(root, "e:\\bin\\LINK.EXE", b"link51"),
        },
        "libraries": [_pinned(root, "e:\\lib\\SLIBCE.LIB", b"slibce")],
        "compiler_path_dos": ["e:\\bin"],
        "linker_path_dos": [],
        "compiler_environment": [["INCLUDE", "E:\\INCLUDE;C:\\"], ["LIB", "E:\\LIB"], ["TMP", "C:\\"]],
        "linker_environment": [["LIB", "E:\\LIB"]],
        "compile_arguments": ["/AS", "/Od", "/W3", "/c", "/Foc:\\{obj}", "{cod_option}", "c:\\{source}"],
        "cod_argument": "/Fcc:\\{cod}",
        "link_argument": "c:\\{obj}{extra_objs},c:\\{exe},c:\\{map},e:\\lib\\SLIBCE.LIB;",
        "extra_object_format": "+c:\\{extra_obj}",
    }
    record.update(overrides)
    return record


def _probe_entry(record: dict, **overrides) -> dict:
    """The probe-evidence profile the registry record must trace back to."""
    product = {
        "Microsoft C v5.1": "Microsoft C 5.1",
        "Borland C++ 3.1": "Borland C++ 3.1",
    }[record["compiler"]]
    entry = {
        "id": record["probe_id"],
        "status": "verified",
        "compiler": {"product": product},
        "model": record["memory_model"],
        "model_flag": record["declared_flags"][-1],
        "compile_runner": record["compile_backend"],
        "run_runner": record["run_backend"],
    }
    entry.update(overrides)
    return entry


def _registry(
    tmp_path: Path,
    records: list[dict],
    probe_entries: list[dict] | None = None,
    *,
    with_dosbox: bool = True,
    with_kvikdos: bool = True,
    dep_overrides: dict[str, dict[str, bytes]] | None = None,
    children: dict[str, dict[str, str]] | None = None,
) -> Path:
    """Write a complete registry + probe-evidence pair for the given records.

    Each record's ``dependency_group`` gets real pinned dep files via
    ``_dep_map``; the probe inventory covers those deps plus the record's
    linker, mirroring the durable probe document's shape.
    """
    dependencies: dict[str, dict[str, str]] = {}
    toolchain_children: dict[str, dict[str, str]] = {}
    for record in records:
        group = record["dependency_group"]
        root = Path(record["toolchain_root"])
        if group in dependencies:
            continue
        if group not in _DEP_FILES:
            continue
        extra = None if dep_overrides is None else dep_overrides.get(group)
        dependencies[group] = _dep_map(root, group, extra)
        inventory = dict(dependencies[group])
        inventory[record["tools"]["linker"]["dos_path"]] = record["tools"]["linker"]["sha256"]
        toolchain_children[group] = inventory
    if children is not None:
        toolchain_children = children
    probe = tmp_path / "probe-evidence.json"
    if probe_entries is None:
        probe_entries = [_probe_entry(record) for record in records]
    probe.write_text(json.dumps(
        {"schema": 1, "profiles": probe_entries, "toolchain_children": toolchain_children},
    ), encoding="utf-8")
    runners: dict[str, object] = {}
    if with_kvikdos:
        runners["kvikdos"] = _runner_record(tmp_path / "kvikdos.bin", b"kvikdos")
    if with_dosbox:
        runners["dosbox"] = _runner_record(
            tmp_path / "dosbox.bin", b"dosbox",
            environment={"SDL_VIDEODRIVER": "dummy", "SDL_AUDIODRIVER": "dummy"},
        )
    registry = {
        "schema": 1,
        "profiles": records,
        "runners": runners,
        "probe_evidence": {
            "path": str(probe),
            "sha256": hashlib.sha256(probe.read_bytes()).hexdigest(),
        },
        "dependencies": dependencies,
    }
    path = tmp_path / "toolchains.json"
    path.write_text(json.dumps(registry), encoding="utf-8")
    return path


def _borland_registry(tmp_path: Path, **overrides) -> tuple[Path, Path]:
    """Return (registry path, toolchain root) for a canonical bc31-small profile."""
    root = tmp_path / "bcc31"
    return _registry(tmp_path, [_borland_record(root, **overrides)]), root


def test_pilot_manifest_resolves_the_builtin_msc6_profile():
    manifest = load_manifest(
        Path(__file__).resolve().parents[3] / "examples/compiler_coverage/pilot.json"
    )
    selection = select_manifest_profile(manifest)
    toolchain = selection.toolchain
    assert toolchain.profile_id == MSC6_AX_PROFILE_ID
    assert toolchain.identity is CompilerIdentity.MSC6_AX
    assert toolchain.memory_model is MSCMemoryModel.SMALL
    assert selection.evidence_path is None


def test_builtin_toolchain_renders_the_legacy_commands(tmp_path):
    toolchain = msc6_ax_toolchain(root=tmp_path / "msc6", memory_model=MSCMemoryModel.SMALL)
    assert toolchain.compile_argv(source_name="CASE.C", obj_name="CASE.OBJ", cod_name="CASE.COD") == [
        "/Ic:\\", "/nologo", "/Od", "/AS", "/c", "/Foc:\\CASE.OBJ", "/Fcc:\\CASE.COD", "c:\\CASE.C",
    ]
    assert toolchain.compile_argv(source_name="CASE.C", obj_name="CASE.OBJ") == [
        "/Ic:\\", "/nologo", "/Od", "/AS", "/c", "/Foc:\\CASE.OBJ", "c:\\CASE.C",
    ]
    assert toolchain.link_argv(
        obj_name="CASE.OBJ", exe_name="CASE.EXE", map_name="CASE.MAP",
    ) == ["c:\\CASE.OBJ,c:\\CASE.EXE,c:\\CASE.MAP,E:\\LIB\\SLIBCE.LIB;"]
    assert toolchain.link_argv(
        obj_name="CASE.OBJ", exe_name="CASE.EXE", map_name="CASE.MAP",
        extra_obj_names=("INERTIA.OBJ",),
    ) == ["c:\\CASE.OBJ+c:\\INERTIA.OBJ,c:\\CASE.EXE,c:\\CASE.MAP,E:\\LIB\\SLIBCE.LIB;"]


def test_builtin_large_model_uses_far_settings(tmp_path):
    toolchain = msc6_ax_toolchain(root=tmp_path / "msc6", memory_model=MSCMemoryModel.LARGE)
    assert toolchain.declared_flags == ("/Od", "/AL")
    assert "/AL" in toolchain.compile_argv(source_name="X.C", obj_name="X.OBJ")
    assert "LLIBCE.LIB" in toolchain.link_argv(obj_name="X.OBJ", exe_name="X.EXE", map_name="X.MAP")[0]


@pytest.mark.parametrize(
    "compiler,flags,model",
    [
        ("Other C 99", ("/Od", "/AS"), "small"),
        ("Microsoft C v6ax", ("/Os", "/AS"), "small"),
        ("Microsoft C v6ax", ("/Od", "/AS"), None),
        ("Microsoft C v5.1", ("/Od", "/AS"), None),
    ],
)
def test_unverified_manifest_profiles_refuse(tmp_path, compiler, flags, model):
    manifest = _manifest(tmp_path, compiler=compiler, flags=flags, model=model)
    with pytest.raises(UnsupportedCompilerProfile):
        select_manifest_profile(manifest)


def _default_profile_drift() -> str | None:
    """Name external probe or runner drift without chasing mutable worker artifacts."""
    registry = json.loads(DEFAULT_PROFILE_REGISTRY.read_text())
    probe = registry["probe_evidence"]
    probe_path = DEFAULT_PROFILE_REGISTRY.parents[2] / probe["path"]
    if hashlib.sha256(probe_path.read_bytes()).hexdigest() != probe["sha256"]:
        return "probe evidence sha256 mismatch"
    runner = registry["runners"]["kvikdos"]
    runner_path = Path(runner["path"])
    if hashlib.sha256(runner_path.read_bytes()).hexdigest() != runner["sha256"]:
        return "kvikdos executable sha256 mismatch"
    return None


def test_default_registry_resolves_verified_profiles():
    """The registry is durable; changed external runners refuse rather than re-pin."""
    drift = _default_profile_drift()
    if drift is not None:
        with pytest.raises(ValueError, match=re.escape(drift)):
            load_compiler_profiles(DEFAULT_PROFILE_REGISTRY)
        return
    profiles = {toolchain.profile_id: toolchain for toolchain in load_compiler_profiles(DEFAULT_PROFILE_REGISTRY)}
    assert {"msc51-small", "msc51-large", "bc31-small", "bc31-large"} <= set(profiles)
    msc51 = profiles["msc51-small"]
    assert msc51.identity is CompilerIdentity.MSC51
    assert msc51.compile_backend is CompileBackend.KVIKDOS
    assert len(msc51.dependency_tools) == 4
    bc31 = profiles["bc31-small"]
    assert bc31.identity is CompilerIdentity.BORLAND31
    assert bc31.compile_backend is CompileBackend.DOSBOX
    assert bc31.run_backend is CompileBackend.KVIKDOS
    assert "bcpp31-small" in bc31.aliases
    assert len(bc31.dependency_tools) == 6
    bc31.verify_tools()
    msc51.verify_tools()


def test_dosbox_runtime_profile_resolves_its_pinned_runner(tmp_path):
    root = tmp_path / "msc51"
    record = _msc51_record(root, run_backend="dosbox")
    registry = _registry(tmp_path, [record])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    assert toolchain.compile_backend is CompileBackend.KVIKDOS
    assert toolchain.run_backend is CompileBackend.DOSBOX
    assert toolchain.dosbox_executable == tmp_path / "dosbox.bin"
    assert toolchain.dosbox_sha256 == hashlib.sha256(b"dosbox").hexdigest()
    assert toolchain.to_dict()["dosbox_conf_sha256"] == hashlib.sha256(
        toolchain.dosbox_conf().encode("ascii")
    ).hexdigest()


def test_dosbox_runtime_profile_without_runner_refuses(tmp_path):
    root = tmp_path / "msc51"
    record = _msc51_record(root, run_backend="dosbox")
    registry = _registry(tmp_path, [record], with_dosbox=False)
    with pytest.raises(ValueError, match="DOSBox profiles require"):
        load_compiler_profiles(registry)


def test_dosbox_runtime_profile_with_stale_runner_pin_refuses(tmp_path):
    root = tmp_path / "msc51"
    registry = _registry(tmp_path, [_msc51_record(root, run_backend="dosbox")])
    payload = json.loads(registry.read_text())
    payload["runners"]["dosbox"]["sha256"] = "0" * 64
    registry.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="DOSBox executable sha256 mismatch"):
        load_compiler_profiles(registry)


def test_msc51_manifest_resolves_the_default_registry(tmp_path):
    manifest = _manifest(tmp_path, compiler="Microsoft C v5.1",
                         flags=("/Od", "/AS"), model="small")
    drift = _default_profile_drift()
    if drift is not None:
        with pytest.raises(UnsupportedCompilerProfile, match=re.escape(drift)):
            select_manifest_profile(manifest)
        return
    selection = select_manifest_profile(manifest)
    assert selection.toolchain.profile_id == "msc51-small"
    assert selection.evidence_path == DEFAULT_PROFILE_REGISTRY


def test_manifest_profile_uses_fixture_registry(tmp_path):
    manifest = _manifest(tmp_path, compiler="Borland C++ 3.1", flags=("-Od", "-ms"))
    registry, root = _borland_registry(tmp_path)
    selection = select_manifest_profile(manifest, evidence_path=registry)
    assert selection.evidence_path == registry
    toolchain = selection.toolchain
    assert toolchain.profile_id == "bc31-small"
    assert toolchain.identity is CompilerIdentity.BORLAND31
    assert toolchain.compile_backend is CompileBackend.DOSBOX
    assert toolchain.toolchain_root == root


def test_mismatched_declared_flags_refuse_even_with_evidence(tmp_path):
    manifest = _manifest(tmp_path, flags=("/Ox", "/AS"))
    registry, _root = _borland_registry(tmp_path)
    with pytest.raises(UnsupportedCompilerProfile, match="no verified profile"):
        select_manifest_profile(manifest, evidence_path=registry)


def test_alias_resolves_to_the_canonical_profile(tmp_path):
    registry, _root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bcpp31-small", evidence_path=registry)
    assert toolchain.profile_id == "bc31-small"


def test_unknown_profile_id_refuses(tmp_path):
    registry, _root = _borland_registry(tmp_path)
    with pytest.raises(UnsupportedCompilerProfile, match="exactly one"):
        resolve_case_toolchain("bc31-small-opt", evidence_path=registry)


def test_missing_registry_refuses(tmp_path):
    with pytest.raises(UnsupportedCompilerProfile, match="registry unusable"):
        resolve_case_toolchain("bc31-small", evidence_path=tmp_path / "absent.json")


def test_model_mismatch_refuses(tmp_path):
    registry, _root = _borland_registry(tmp_path)
    with pytest.raises(UnsupportedCompilerProfile, match="large"):
        resolve_case_toolchain("bc31-small", memory_model=MSCMemoryModel.LARGE, evidence_path=registry)


@pytest.mark.parametrize("fault", ["missing", "drifted"])
def test_pinned_tool_identity_refuses_stale_artifacts(tmp_path, fault):
    registry, root = _borland_registry(tmp_path)
    victim = root / "BIN" / "BCC.EXE"
    if fault == "missing":
        victim.unlink()
        match = "missing"
    else:
        victim.write_bytes(b"different bytes")
        match = "sha256 mismatch"
    with pytest.raises(UnsupportedCompilerProfile, match=match):
        resolve_case_toolchain("bc31-small", evidence_path=registry)


def test_pinned_spawned_dependency_identity_refuses_stale_artifacts(tmp_path):
    registry, root = _borland_registry(tmp_path)
    dependency = root / "BIN" / "DPMILOAD.EXE"
    dependency.write_bytes(b"changed dpmi loader")
    with pytest.raises(UnsupportedCompilerProfile, match=r"DPMILOAD.EXE sha256 mismatch"):
        resolve_case_toolchain("bc31-small", evidence_path=registry)


@pytest.mark.parametrize(
    "probe_override,match",
    [
        ({"compiler": {"product": "Microsoft C 6.0"}}, "does not match probe"),
        ({"model": "large"}, "does not match probe"),
        ({"compile_runner": "kvikdos"}, "does not match probe"),
        ({"id": "other-probe"}, "exactly one"),
    ],
)
def test_probe_identity_mismatch_refuses(tmp_path, probe_override, match):
    root = tmp_path / "bcc31"
    record = _borland_record(root)
    entry = _probe_entry(record, **probe_override)
    registry = _registry(tmp_path, [record], [entry])
    with pytest.raises(ValueError, match=match):
        load_compiler_profiles(registry)


@pytest.mark.parametrize("fault", ["missing_dep", "wrong_dep_hash", "extra_dep", "no_inventory"])
def test_dependency_inventory_mismatch_refuses(tmp_path, fault):
    root = tmp_path / "bcc31"
    record = _borland_record(root)
    children: dict[str, dict[str, str]] | None = None
    dep_overrides: dict[str, dict[str, bytes]] | None = None
    if fault == "missing_dep":
        children = {"bcpp31": {}}
    elif fault == "wrong_dep_hash":
        children = {"bcpp31": {"e:\\BIN\\DPMILOAD.EXE": "0" * 64,
                             "e:\\BIN\\TLINK.EXE": record["tools"]["linker"]["sha256"]}}
    elif fault == "extra_dep":
        dep_overrides = {"bcpp31": {"e:\\BIN\\UNMEASURED.EXE": b"extra"}}
    elif fault == "no_inventory":
        children = {}
    registry = _registry(
        tmp_path, [record], dep_overrides=dep_overrides, children=children,
    )
    if fault == "extra_dep":
        payload = json.loads(registry.read_text())
        payload["dependencies"]["bcpp31"]["e:\\BIN\\UNMEASURED.EXE"] = "0" * 64
        registry.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match=r"does not match probe|dependencies"):
        load_compiler_profiles(registry)


def test_dependency_group_must_exist(tmp_path):
    root = tmp_path / "bcc31"
    record = _borland_record(root, dependency_group="ghost")
    registry = _registry(tmp_path, [record])
    with pytest.raises(ValueError, match="no dependencies entry"):
        load_compiler_profiles(registry)


def test_probe_evidence_hash_drift_refuses(tmp_path):
    registry, _root = _borland_registry(tmp_path)
    payload = json.loads(registry.read_text())
    payload["probe_evidence"]["sha256"] = "0" * 64
    registry.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="sha256 mismatch"):
        load_compiler_profiles(registry)


@pytest.mark.parametrize("fault", ["schema", "fields", "duplicate", "reserved", "empty", "not_list",
                                   "unpinned_tool", "alias_conflict", "dosbox_missing"])
def test_malformed_registry_documents_refuse(tmp_path, fault):
    root = tmp_path / "bcc31"
    record = _borland_record(root)
    if fault == "unpinned_tool":
        record["tools"]["compiler"]["sha256"] = None
        path = _registry(tmp_path, [record])
    elif fault == "dosbox_missing":
        path = _registry(tmp_path, [record], with_dosbox=False)
    elif fault == "alias_conflict":
        second = _borland_record(tmp_path / "b2", id="bc31-large", probe_id="bcpp31-large",
                                 memory_model="large", declared_flags=["-Od", "-ml"],
                                 aliases=["bcpp31-small"])
        path = _registry(
            tmp_path, [record, second],
            [_probe_entry(record), _probe_entry(second)],
        )
    else:
        path = _registry(tmp_path, [record])
        payload = json.loads(path.read_text())
        if fault == "schema":
            payload["schema"] = 2
        elif fault == "fields":
            payload["profiles"][0]["extra_field"] = True
        elif fault == "duplicate":
            payload["profiles"].append(dict(payload["profiles"][0]))
        elif fault == "reserved":
            payload["profiles"][0]["id"] = MSC6_AX_PROFILE_ID
        elif fault == "empty":
            payload["profiles"] = []
        elif fault == "not_list":
            payload["profiles"] = "nope"
        path.write_text(json.dumps(payload))
    with pytest.raises(ValueError):
        load_compiler_profiles(path)


@pytest.mark.parametrize(
    "overrides",
    [
        {"toolchain_root": "relative/root"},
        {"compile_arguments": ["-c"]},
        {"link_argument": "c:\\{obj};"},
        {"extra_object_format": "{obj}"},
        {"compiler_environment": [["9BAD", "X"]]},
        {"compile_arguments": ["-c", "{typo}", "c:\\{source}", "-o{obj}"]},
    ],
)
def test_malformed_profile_records_refuse(tmp_path, overrides):
    root = tmp_path / "bcc31"
    record = _borland_record(root, **overrides)
    registry = _registry(tmp_path, [record])
    with pytest.raises(ValueError):
        load_compiler_profiles(registry)


def test_resolve_case_toolchain_keeps_the_builtin_default(tmp_path):
    toolchain = resolve_case_toolchain(msc6_root=tmp_path / "msc6")
    assert toolchain.identity is CompilerIdentity.MSC6_AX
    assert toolchain.toolchain_root == tmp_path / "msc6"
    assert toolchain.memory_model is MSCMemoryModel.SMALL


def test_compiler_host_path_maps_the_mount_and_lock_uses_it(tmp_path):
    registry, root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bc31-small", evidence_path=registry)
    assert toolchain.compiler_host_path == root / "BIN" / "BCC.EXE"
    with compiler_toolchain_lock(toolchain):
        pass
    (root / "BIN" / "BCC.EXE").unlink()
    with pytest.raises(FileNotFoundError), compiler_toolchain_lock(toolchain):
        pass


def test_dosbox_batch_writes_errorlevel_markers(tmp_path):
    registry, _root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bc31-small", evidence_path=registry)
    batch = toolchain.dosbox_batch(
        tag="CC",
        command_line=toolchain.compile_dos_command(source_name="CASE.C", obj_name="CASE.OBJ"),
        out_name="CC.OUT", ok_name="CCOK.OUT", fail_name="CCFL.OUT",
        path_dos=toolchain.compiler_path_dos,
        environment=toolchain.compiler_environment,
    )
    assert "set PATH=e:\\BIN" in batch
    assert "e:\\BIN\\BCC.EXE -Od -ms -IE:\\INCLUDE -c -oc:\\CASE.OBJ c:\\CASE.C > c:\\CC.OUT" in batch
    assert "if errorlevel 1 echo CC_FAIL > c:\\CCFL.OUT" in batch
    assert "if not errorlevel 1 echo CC_OK > c:\\CCOK.OUT" in batch
    assert toolchain.dosbox_ok_marker("CC") == "CC_OK"


def _dosbox_run(toolchain, tmp_path, marker_mode, *, artifact=True, artifact_payload=b"obj",
                rc=0, log=b""):
    """Fake a DOSBox run writing the same artifacts real DOSBox would."""
    def run(command, **kwargs):
        del kwargs
        bat = next(a.rsplit("\\", 1)[-1] for a in command if a.startswith("call c:\\"))
        tag = bat.split(".")[0]
        (tmp_path / f"{tag}.OUT").write_bytes(log)
        (tmp_path / f"{tag}FL.OUT").write_bytes(b"CC_FAIL\r\n" if marker_mode == "fail" else b"")
        if marker_mode == "ok":
            (tmp_path / f"{tag}OK.OUT").write_bytes(b"CC_OK\r\n")
        elif marker_mode == "empty":
            (tmp_path / f"{tag}OK.OUT").write_bytes(b"")
        elif marker_mode == "malformed":
            (tmp_path / f"{tag}OK.OUT").write_bytes(b"garbage\r\n")
        # "missing" writes no OK file at all.
        if artifact:
            (tmp_path / "CASE.OBJ").write_bytes(artifact_payload)
        return SimpleNamespace(returncode=rc, stdout="", stderr="")
    return run


@pytest.mark.parametrize(
    "marker_mode,artifact,artifact_payload,rc,log,expect_ok,match",
    [
        ("ok", True, b"obj", 0, b"", True, None),
        ("fail", True, b"obj", 0, b"", False, "ERRORLEVEL"),
        ("missing", True, b"obj", 0, b"", False, "missing"),
        ("empty", True, b"obj", 0, b"", False, "malformed"),
        ("malformed", True, b"obj", 0, b"", False, "malformed"),
        ("ok", False, b"obj", 0, b"", False, "missing artifact"),
        ("ok", True, b"", 0, b"", False, "stale or empty"),
        ("ok", True, b"obj", 1, b"", False, "launcher exit"),
        ("ok", True, b"obj", 0, b"fatal error x\r\n", False, "error"),
    ],
)
def test_dosbox_stage_marker_controls(
    tmp_path, monkeypatch, marker_mode, artifact, artifact_payload, rc, log, expect_ok, match,
):
    registry, _root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bc31-small", evidence_path=registry)
    monkeypatch.setattr(
        harness, "_run",
        _dosbox_run(toolchain, tmp_path, marker_mode, artifact=artifact,
                    artifact_payload=artifact_payload, rc=rc, log=log),
    )
    ok, stage_log = harness._run_dosbox_stage(
        toolchain,
        tmp_path,
        tag="CC",
        command_line=toolchain.compile_dos_command(source_name="CASE.C", obj_name="CASE.OBJ"),
        path_dos=toolchain.compiler_path_dos,
        environment=toolchain.compiler_environment,
        required=("CASE.OBJ",),
    )
    assert ok is expect_ok
    if match is not None:
        assert match in stage_log


def test_dosbox_stage_invokes_the_pinned_runner(tmp_path, monkeypatch):
    registry, _root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bc31-small", evidence_path=registry)
    commands: list[list[str]] = []
    fake = _dosbox_run(toolchain, tmp_path, "ok")

    def run(command, **kwargs):
        commands.append(command)
        return fake(command, **kwargs)

    monkeypatch.setattr(harness, "_run", run)
    ok, _log = harness._run_dosbox_stage(
        toolchain, tmp_path, tag="CC",
        command_line=toolchain.compile_dos_command(source_name="CASE.C", obj_name="CASE.OBJ"),
        path_dos=toolchain.compiler_path_dos,
        environment=toolchain.compiler_environment,
        required=("CASE.OBJ",),
    )
    assert ok
    command = commands[0]
    assert command[0] == str(toolchain.dosbox_executable)
    assert "-noconsole" in command
    assert "-conf" in command
    conf = Path(command[command.index("-conf") + 1])
    assert conf.read_text() == toolchain.dosbox_conf()
    assert 'mount e "' + str(toolchain.toolchain_root) + '"' in command
    assert "call c:\\CC.BAT" in command
    assert command[-2:] == ["-c", "exit"]


def _dosbox_runtime_case(tmp_path):
    root = tmp_path / "msc51"
    record = _msc51_record(root, run_backend="dosbox")
    registry = _registry(tmp_path, [record])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    executable = tmp_path / "CASE.EXE"
    image = bytearray(34)
    image[:2] = b"MZ"
    image[2:4] = (34).to_bytes(2, "little")
    image[4:6] = (1).to_bytes(2, "little")
    image[8:10] = (2).to_bytes(2, "little")
    image[32:] = b"\x90\xcb"
    executable.write_bytes(image)
    return toolchain, executable


def _write_dosbox_run_proof(out_dir, tag, guest_exit, *, fault=None):
    tag = tag.upper()
    if fault != "missing_stdout":
        (out_dir / f"{tag}.OUT").write_bytes(b"guest output\r\n")
    statuses = list(range(guest_exit + 1))
    if fault == "truncated":
        statuses = statuses[:-1]
    elif fault == "duplicate":
        statuses = [0, 1, 1]
    elif fault == "shuffled":
        statuses = [0, 2, 1]
    if fault != "missing_status":
        (out_dir / f"{tag}ST.OUT").write_text(
            "".join(f"{value}\r\n" for value in statuses), encoding="latin1",
        )
    if fault != "missing_exit":
        marker = "EXIT=256" if fault == "out_of_range" else f"EXIT={guest_exit}"
        (out_dir / f"{tag}EX.OUT").write_text(marker + "\r\n", encoding="latin1")
    if fault != "missing_done":
        done = "wrong marker" if fault == "malformed_done" else "END_OF_PROBE"
        (out_dir / f"{tag}DN.OUT").write_text(done + "\r\n", encoding="latin1")


@pytest.mark.parametrize("run_tag,guest_exit", [
    ("ORIG", 0), ("REBLD", 1), ("ORIG", 5), ("REBLD", 127), ("ORIG", 255),
])
def test_dosbox_runtime_routes_pinned_profile_and_returns_exact_guest_exit(
    tmp_path, monkeypatch, run_tag, guest_exit,
):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    commands = []

    def run(command, **kwargs):
        commands.append((command, kwargs))
        _write_dosbox_run_proof(tmp_path, run_tag, guest_exit)
        return SimpleNamespace(returncode=0, stdout="host out", stderr="host err")

    monkeypatch.setattr(harness, "_run", run)
    ran_ok, returned_exit, guest_stdout, diagnostics = harness._run_example(
        executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos",
        timeout=37, toolchain=toolchain, run_tag=run_tag,
    )
    assert ran_ok is (guest_exit == 0)
    assert returned_exit == guest_exit
    assert guest_stdout == "guest output\r\n"
    assert "DOSBox host stdout" in diagnostics and "host out" in diagnostics
    command, kwargs = commands[0]
    assert command[0] == str(toolchain.dosbox_executable)
    assert "-conf" in command and "call c:\\" + f"{run_tag}.BAT" in command
    conf_path = Path(command[command.index("-conf") + 1])
    assert conf_path.read_text() == toolchain.dosbox_conf()
    assert f'mount e "{toolchain.toolchain_root}"' in command
    assert f'mount c "{tmp_path}"' in command
    assert kwargs["env"] == dict(toolchain.dosbox_host_environment)
    assert kwargs["timeout"] == 37 and kwargs["cleanup_process_group"] is True
    batch = (tmp_path / f"{run_tag}.BAT").read_text(encoding="ascii")
    assert sum(line.startswith("if errorlevel ") and " echo " in line for line in batch.splitlines()) == 256
    assert "if errorlevel 255 goto EXIT255" in batch
    assert f"echo END_OF_PROBE > c:\\{run_tag}DN.OUT" in batch


def test_dosbox_runtime_accepts_lowercase_host_executable_from_mount(tmp_path, monkeypatch):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    lowercase_executable = executable.with_name("case.exe")
    executable.rename(lowercase_executable)

    def run(_command, **_kwargs):
        _write_dosbox_run_proof(tmp_path, "ORIG", 5)
        return SimpleNamespace(returncode=0, stdout="host output", stderr="")

    launch = Mock(side_effect=run)
    monkeypatch.setattr(harness, "_run", launch)
    result = harness._run_example(
        lowercase_executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos",
        timeout=37, toolchain=toolchain, run_tag="ORIG",
    )
    assert result[0] is False and result[1] == 5
    assert result[2] == "guest output\r\n"
    assert "c:\\CASE.EXE > c:\\ORIG.OUT" in (tmp_path / "ORIG.BAT").read_text(encoding="ascii")
    launch.assert_called_once()


@pytest.mark.parametrize("fault", [
    "truncated", "duplicate", "shuffled", "out_of_range", "missing_status",
    "missing_exit", "missing_done", "malformed_done", "missing_stdout",
    "host_failure", "stale", "timeout", "launch",
])
def test_dosbox_runtime_rejects_bad_or_incomplete_guest_proof(tmp_path, monkeypatch, fault):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    if fault == "stale":
        _write_dosbox_run_proof(tmp_path, "ORIG", 5)

    def run(_command, **kwargs):
        assert kwargs["timeout"] == 37
        assert kwargs["cleanup_process_group"] is True
        if fault == "launch":
            raise OSError("runner missing")
        if fault == "timeout":
            (tmp_path / "ORIG.OUT").write_bytes(b"partial guest")
            raise subprocess.TimeoutExpired("dosbox", kwargs["timeout"], output=b"host partial")
        if fault != "stale":
            _write_dosbox_run_proof(tmp_path, "ORIG", 5, fault=fault)
        code = 1 if fault == "host_failure" else 0
        return SimpleNamespace(returncode=code, stdout="host log", stderr="")

    monkeypatch.setattr(harness, "_run", run)
    result = harness._run_example(
        executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos",
        timeout=37, toolchain=toolchain, run_tag="ORIG",
    )
    assert result[0] is False
    assert result[1] is None
    if fault == "timeout":
        assert result[2] == "partial guest"
        assert "host partial" in result[3]
    if fault == "stale":
        assert not (tmp_path / "ORIGDN.OUT").exists()
    if fault == "malformed_done":
        assert (tmp_path / "ORIGDN.OUT").read_bytes() == b"wrong marker\r\n"
    if fault == "missing_done":
        assert not (tmp_path / "ORIGDN.OUT").exists()


def test_dosbox_runtime_rejects_invalid_executable_before_launch(tmp_path, monkeypatch):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    executable.write_bytes(b"not an MZ image")
    launch = Mock()
    monkeypatch.setattr(harness, "_run", launch)
    result = harness._run_example(
        executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos", toolchain=toolchain,
    )
    assert result[0] is False and result[1] is None
    assert "invalid or missing DOS MZ" in result[3]
    launch.assert_not_called()


@pytest.mark.parametrize("fault", ["empty_load", "entry_ip_outside_load", "entry_cs_outside_load"])
def test_dosbox_runtime_refuses_empty_or_out_of_image_mz_entry(tmp_path, monkeypatch, fault):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    image = bytearray(32 if fault == "empty_load" else 34)
    image[:2] = b"MZ"
    image[2:4] = len(image).to_bytes(2, "little")
    image[4:6] = (1).to_bytes(2, "little")
    image[8:10] = (2).to_bytes(2, "little")
    if fault == "entry_ip_outside_load":
        image[20:22] = (2).to_bytes(2, "little")
        image[32:] = b"\x90\xcb"
    elif fault == "entry_cs_outside_load":
        image[22:24] = (1).to_bytes(2, "little")
        image[32:] = b"\x90\xcb"
    executable.write_bytes(image)
    launch = Mock()
    monkeypatch.setattr(harness, "_run", launch)
    result = harness._run_example(
        executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos", toolchain=toolchain,
    )
    assert result[0] is False and result[1] is None
    assert "invalid or missing DOS MZ" in result[3]
    launch.assert_not_called()


def test_dosbox_runtime_refuses_valid_mz_outside_mount_with_colliding_basename(tmp_path, monkeypatch):
    toolchain, executable = _dosbox_runtime_case(tmp_path)
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    outside_executable = outside / executable.name
    outside_executable.write_bytes(executable.read_bytes())
    launch = Mock()
    monkeypatch.setattr(harness, "_run", launch)
    result = harness._run_example(
        outside_executable, tmp_path, kvikdos=tmp_path / "unused-kvikdos", toolchain=toolchain,
    )
    assert result[0] is False and result[1] is None
    assert "outside the mounted output file" in result[3]
    launch.assert_not_called()


def test_kvikdos_program_run_keeps_the_legacy_argv_without_a_profile(tmp_path, monkeypatch):
    commands = []
    monkeypatch.setattr(
        harness, "_run",
        lambda command, **kwargs: commands.append((command, kwargs))
        or SimpleNamespace(returncode=5, stdout="guest", stderr=""),
    )
    result = harness._run_example(tmp_path / "CASE.EXE", tmp_path, kvikdos=tmp_path / "kvikdos")
    assert result == (False, 5, "guest", "")
    command, kwargs = commands[0]
    assert command == [
        str(tmp_path / "kvikdos"), f"--mount=c:{tmp_path}/", "--drive=c",
        "--cwd-dos=c:\\", "--prog=c:\\CASE.EXE", "c:\\CASE.EXE",
    ]
    assert kwargs == {"timeout": 30}


def test_kvikdos_stage_dispatches_the_profile_command(tmp_path, monkeypatch):
    root = tmp_path / "msc51"
    registry = _registry(tmp_path, [_msc51_record(root)])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    commands = []
    monkeypatch.setattr(
        harness, "_run",
        lambda command, **kwargs: commands.append(command)
        or SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    ok, _stdout, _stderr = harness._run_tool_stage(
        toolchain, tmp_path, kvikdos=tmp_path / "kvikdos.bin", tag="CC",
        program=toolchain.compiler_program,
        argv=toolchain.compile_argv(source_name="CASE.C", obj_name="CASE.OBJ"),
        command_line=toolchain.compile_dos_command(source_name="CASE.C", obj_name="CASE.OBJ"),
        path_dos=toolchain.compiler_path_dos,
        environment=toolchain.compiler_environment,
        required=("CASE.OBJ",),
    )
    assert ok
    command = commands[0]
    assert command[0] == str(tmp_path / "kvikdos.bin")
    assert f"--mount=e:{root}/" in command
    assert "--prog=e:\\bin\\CL.EXE" in command
    assert "--env=INCLUDE=E:\\INCLUDE;C:\\" in command
    assert "/Foc:\\CASE.OBJ" in command


def _dosbox_pipeline_run(tmp_path, commands, built_artifacts):
    """Fake DOSBox honoring the staged batch files and their markers."""
    artifacts = {"CC": "CASE.OBJ", "RC": "INERTIA.OBJ", "LK": "CASE.EXE"}

    def run(command, **kwargs):
        del kwargs
        commands.append(command)
        bat = next(a.rsplit("\\", 1)[-1] for a in command if a.startswith("call c:\\"))
        tag = bat.split(".")[0]
        (tmp_path / f"{tag}FL.OUT").write_bytes(b"")
        (tmp_path / f"{tag}OK.OUT").write_bytes(f"{tag}_OK\r\n".encode())
        (tmp_path / f"{tag}.OUT").write_bytes(b"tool log\r\n")
        (tmp_path / artifacts[tag]).write_bytes(b"artifact")
        built_artifacts.append(artifacts[tag])
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    return run


def test_compile_and_link_uses_dosbox_for_every_stage(tmp_path, monkeypatch):
    registry, _root = _borland_registry(tmp_path)
    toolchain = resolve_case_toolchain("bc31-small", evidence_path=registry)
    kvikdos = tmp_path / "kvikdos.bin"
    commands: list[list[str]] = []
    built_artifacts: list[str] = []
    timeouts: list[int] = []
    pipeline_run = _dosbox_pipeline_run(tmp_path, commands, built_artifacts)

    def run(command, **kwargs):
        timeouts.append(kwargs["timeout"])
        return pipeline_run(command, **kwargs)

    monkeypatch.setattr(harness, "_run", run)
    built, *_ = harness._compile_and_link_unlocked(
        tmp_path / "CASE.C",
        tmp_path,
        kvikdos=kvikdos,
        msc6_root=toolchain.toolchain_root,
        obj_name="CASE.OBJ",
        exe_name="CASE.EXE",
        map_name="CASE.MAP",
        cod_name="CASE.COD",
        runtime_support=True,
        stage_timeout=37,
        toolchain=toolchain,
    )
    assert built
    assert timeouts == [37, 37, 37]
    assert built_artifacts == ["CASE.OBJ", "INERTIA.OBJ", "CASE.EXE"]
    assert len(commands) == 3
    for command in commands:
        assert command[0] == str(toolchain.dosbox_executable)
        assert "-conf" in command
        assert not any(arg.startswith("--mount=") for arg in command)
    assert "call c:\\RC.BAT" in commands[1]
    link_bat = (tmp_path / "LK.BAT").read_text()
    assert "e:\\LIB\\C0S+c:\\CASE.OBJ+c:\\INERTIA.OBJ,c:\\CASE.EXE" in link_bat


def test_compile_and_link_kvikdos_profile_keeps_one_pipeline(tmp_path, monkeypatch):
    root = tmp_path / "msc51"
    registry = _registry(tmp_path, [_msc51_record(root)])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    commands = []
    timeouts = []

    def run(command, **kwargs):
        commands.append(command)
        timeouts.append(kwargs["timeout"])
        for name in ("CASE.OBJ", "INERTIA.OBJ", "CASE.EXE"):
            (tmp_path / name).write_bytes(b"artifact")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(harness, "_run", run)
    built, *_ = harness._compile_and_link_unlocked(
        tmp_path / "CASE.C",
        tmp_path,
        kvikdos=tmp_path / "kvikdos.bin",
        msc6_root=toolchain.toolchain_root,
        obj_name="CASE.OBJ",
        exe_name="CASE.EXE",
        map_name="CASE.MAP",
        cod_name="CASE.COD",
        runtime_support=True,
        stage_timeout=37,
        toolchain=toolchain,
    )
    assert built
    assert len(commands) == 3
    assert timeouts == [37, 37, 37]
    for command in commands:
        assert command[0] == str(tmp_path / "kvikdos.bin")
        assert f"--mount=e:{root}/" in command
    assert "--prog=e:\\bin\\CL.EXE" in commands[0]
    assert "c:\\INERTIA.C" in commands[1]
    assert "--prog=e:\\bin\\LINK.EXE" in commands[2]
    assert "+c:\\INERTIA.OBJ" in commands[2][-1]


@pytest.mark.parametrize("fault", ["root", "model", "kvikdos"])
def test_conflicting_toolchain_arguments_refuse(tmp_path, fault):
    root = tmp_path / "msc51"
    registry = _registry(tmp_path, [_msc51_record(root)])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    kvikdos = tmp_path / "kvikdos.bin"
    kwargs = {
        "kvikdos": kvikdos if fault != "kvikdos" else tmp_path / "other-kvikdos",
        "obj_name": "CASE.OBJ",
        "exe_name": "CASE.EXE",
        "map_name": "CASE.MAP",
        "msc6_root": tmp_path / "other" if fault == "root" else toolchain.toolchain_root,
        "memory_model": MSCMemoryModel.LARGE if fault == "model" else toolchain.memory_model,
        "toolchain": toolchain,
    }
    with pytest.raises(ValueError):
        harness._compile_and_link_unlocked(tmp_path / "CASE.C", tmp_path, **kwargs)


def test_manifest_compiler_names_cover_the_plan_lanes():
    assert MANIFEST_COMPILER_NAMES[CompilerIdentity.MSC6_AX] == "Microsoft C v6ax"
    assert MANIFEST_COMPILER_NAMES[CompilerIdentity.MSC51] == "Microsoft C v5.1"
    assert MANIFEST_COMPILER_NAMES[CompilerIdentity.BORLAND31] == "Borland C++ 3.1"


@pytest.mark.parametrize("stem,dos_name", [
    ("compare16", "CMP16.C"),
    ("pointer_memory", "POINT.C"),
    ("simple_control", "SIMPLE.C"),
    ("function_pointers", "FPTR.C"),
    ("struct_value_abi", "STRVAL.C"),
    ("bitfield_neighbors", "BITNBR.C"),
    ("multidim_alias", "MDALIAS.C"),
    ("csmith", "CSMITH.C"),
])
def test_frozen_sources_stage_under_deterministic_dos_names(stem, dos_name):
    assert harness._dos_staged_source_name(Path(f"{stem}.c")) == dos_name


@pytest.mark.parametrize("names", [("CSMITH.C",), ("INERTIA.C",), ("RT.C", "rt.c"), ("RUNTIMESOURCE.C",)])
def test_runtime_source_collisions_and_invalid_dos_names_refuse(names):
    with pytest.raises(ValueError):
        harness._validate_runtime_stage_names("CSMITH.C", names)


def test_runtime_sources_cannot_alias_primary_or_generated_runtime():
    harness._validate_runtime_stage_names("CSMITH.C", ("CSMRT.C",))
    with pytest.raises(ValueError, match="reserved source names"):
        harness._validate_runtime_stage_names("MAIN.C", ("INERTIA.C",))


def test_stage_timeout_parser_enforces_the_frozen_ceiling():
    assert harness._build_arg_parser().parse_args([]).stage_timeout is None
    assert harness._stage_timeout_argument("120") == 120
    for value in ("0", "121", "-1"):
        with pytest.raises(argparse.ArgumentTypeError):
            harness._stage_timeout_argument(value)


@pytest.mark.parametrize(("count", "legacy_seconds"), [(1, 150), (8, 570)])
def test_candidate_process_deadline_caps_expanded_allowance_and_legacy_is_unchanged(
    monkeypatch, count, legacy_seconds,
):
    candidate = {"kind": "max-functions", "value": count}
    legacy = harness._decompile_candidate_run_timeout(
        candidate,
        decompile_mode="functions",
        decompile_run_timeout=120,
        decompile_timeout=60,
        decompile_max_functions=count,
    )
    assert legacy == legacy_seconds
    monkeypatch.setattr(harness.time, "monotonic", lambda: 100.0)
    bounded = harness._decompile_candidate_run_timeout(
        candidate,
        decompile_mode="functions",
        decompile_run_timeout=120,
        decompile_timeout=60,
        decompile_max_functions=count,
        stage_deadline=220.0,
    )
    assert bounded == 120.0


def test_candidate_retries_share_one_absolute_deadline(monkeypatch):
    candidate = {"kind": "max-functions", "value": 1}
    ticks = iter((100.0, 185.0))
    monkeypatch.setattr(harness.time, "monotonic", lambda: next(ticks))
    options = {
        "decompile_mode": "functions",
        "decompile_run_timeout": 120,
        "decompile_timeout": 60,
        "decompile_max_functions": 1,
        "stage_deadline": 220.0,
    }
    assert harness._decompile_candidate_run_timeout(candidate, **options) == 120.0
    assert harness._decompile_candidate_run_timeout(candidate, **options) == 35.0


def test_expired_candidate_deadline_does_not_start_another_process(monkeypatch):
    monkeypatch.setattr(harness.time, "monotonic", lambda: 221.0)
    with pytest.raises(subprocess.TimeoutExpired):
        harness._decompile_candidate_run_timeout(
            {"kind": "max-functions", "value": 1},
            decompile_mode="functions",
            decompile_run_timeout=120,
            decompile_timeout=60,
            decompile_max_functions=1,
            stage_deadline=220.0,
        )


def test_frozen_stage_timeout_writes_partial_decompile_reports(tmp_path, monkeypatch):
    executable = tmp_path / "CASE.EXE"

    def timed_out(command, **kwargs):
        assert kwargs["timeout"] <= 120
        raise subprocess.TimeoutExpired(
            command, kwargs["timeout"], output=b"int partial(void) { return 7; }",
            stderr=b"partial diagnostic",
        )

    monkeypatch.setattr(harness, "_run", timed_out)
    result = harness._decompile(
        executable,
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=120,
        decompile_mode="functions",
        decompile_cod_path=None,
        decompile_max_functions=0,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_ignore_local_sidecar_hints=True,
        frozen_stage_timeout=120,
    )
    assert result[0] is False
    assert result[4]["timeout"] is True
    assert "int partial(void) { return 7; }" in (tmp_path / "CASE.dec.txt").read_text()
    assert "partial diagnostic" in (tmp_path / "CASE.dec.err.txt").read_text()


def test_owned_process_group_success_preserves_returncode_and_streams():
    command = [
        sys.executable,
        "-c",
        "import sys; print('captured stdout'); print('captured stderr', file=sys.stderr); sys.exit(7)",
    ]
    result = harness._run(command, timeout=3, cleanup_process_group=True)
    assert result.returncode == 7
    assert result.stdout == "captured stdout\n"
    assert result.stderr == "captured stderr\n"


@pytest.mark.skipif(sys.platform != "linux", reason="Uses Linux process groups and procfs state")
def test_frozen_decompile_stage_timeout_kills_owned_parent_and_child(tmp_path):
    marker = tmp_path / "child-survived-timeout"
    ready_path = tmp_path / "child.ready"
    pid_path = tmp_path / "child.pid"
    child_program = (
        "import pathlib,sys,time; pathlib.Path(sys.argv[2]).write_text('ready'); "
        "time.sleep(1.1); pathlib.Path(sys.argv[1]).write_text('survived'); time.sleep(1.3)"
    )
    parent_program = (
        "import pathlib,subprocess,sys,time\n"
        f"child=subprocess.Popen([sys.executable, '-c', {child_program!r}, sys.argv[1], sys.argv[2]], "
        "start_new_session=True)\n"
        "pathlib.Path(sys.argv[3]).write_text(str(child.pid))\n"
        "deadline=time.monotonic()+2\n"
        "while not pathlib.Path(sys.argv[2]).exists() and time.monotonic()<deadline:\n"
        "    time.sleep(0.01)\n"
        "print('parent stdout', flush=True)\n"
        "print('parent stderr', file=sys.stderr, flush=True)\n"
        "time.sleep(60)\n"
    )
    command = [sys.executable, "-c", parent_program, str(marker), str(ready_path), str(pid_path)]
    start = time.monotonic()
    try:
        with pytest.raises(subprocess.TimeoutExpired) as failure:
            harness._run_decompile_candidate(
                command,
                {"kind": "proc", "name": "controlled-parent-child"},
                timeout=0.5,
                cleanup_process_group=True,
                trace_label="process-group-control",
                force_rizin=False,
            )
        elapsed = time.monotonic() - start
        assert elapsed < 0.5 + harness._STAGE_PROCESS_CLEANUP_GRACE_SECONDS + 0.5
        assert "parent stdout" in failure.value.stdout
        assert "parent stderr" in failure.value.stderr
        assert ready_path.read_text() == "ready"
        child_pid = int(pid_path.read_text(encoding="ascii"))
        time.sleep(1.3)
        assert not marker.exists()
        try:
            state = Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except FileNotFoundError:
            state = "X"
        assert state in {"Z", "X"}
    finally:
        if pid_path.exists():
            child_pid = int(pid_path.read_text(encoding="ascii"))
            try:
                argv = Path(f"/proc/{child_pid}/cmdline").read_bytes().decode(errors="replace")
                if str(marker) in argv:
                    os.kill(child_pid, signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError):
                pass


def test_validate_owner_threads_frozen_stage_cap_into_decompile(tmp_path, monkeypatch):
    sentinel = (False,)
    monkeypatch.setattr(harness, "_fallback_first_result", lambda _options: None)
    monkeypatch.setattr(harness, "_decompile_failure_result", lambda *_args: sentinel)
    observed = {}

    def decompile(_exe_path, _out_dir, **kwargs):
        observed.update(kwargs)
        return False, tmp_path / "dec.txt", tmp_path / "dec.err", 0.0, {}

    monkeypatch.setattr(harness, "_decompile", decompile)
    result = harness._decompile_and_validate(
        tmp_path / "CASE.EXE",
        tmp_path,
        kvikdos=tmp_path / "kvikdos",
        msc6_root=tmp_path / "compiler",
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=120,
        decompile_mode="functions",
        decompile_cod_path=None,
        decompile_max_functions=0,
        expected_exit_code=255,
        decompile_stage_timeout=37,
    )
    assert result is sentinel
    assert observed["frozen_stage_timeout"] == 37


def test_candidate_retries_through_decompile_owner_share_one_stage_deadline(tmp_path, monkeypatch):
    candidates = [
        {"kind": "proc", "name": "first"},
        {"kind": "proc", "name": "second"},
    ]
    ticks = iter((100.0, 100.0, 185.0))
    monkeypatch.setattr(harness.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(harness, "_main_mode_candidates", lambda *args, **kwargs: candidates)
    observed_timeouts = []

    def run_candidate(command, candidate, *, timeout, **kwargs):
        assert command[command.index("--timeout") + 1] == "60"
        observed_timeouts.append(timeout)
        if len(observed_timeouts) == 1:
            return SimpleNamespace(returncode=1, stdout="", stderr=""), {"timeout": True}, False
        raise subprocess.TimeoutExpired(command, timeout, output=b"partial", stderr=b"diagnostic")

    monkeypatch.setattr(harness, "_run_decompile_candidate", run_candidate)
    result = harness._decompile(
        tmp_path / "CASE.EXE",
        tmp_path,
        decompile_py=tmp_path / "decompile.py",
        decompile_timeout=60,
        decompile_run_timeout=120,
        frozen_stage_timeout=120,
        decompile_mode="main",
        decompile_cod_path=None,
        decompile_max_functions=0,
        decompile_function_discovery_backend="auto",
        decompile_seed_engine="auto",
        decompile_rizin_timeout=8,
        decompile_force_rizin_8616=False,
        decompile_ignore_local_sidecar_hints=True,
    )
    assert observed_timeouts == [120.0, 35.0]
    assert result[4]["timeout"] is True
    assert len(result[4]["commands_tried"]) == 2
    assert "partial" in (tmp_path / "CASE.dec.txt").read_text()


def test_unmapped_long_stems_refuse_ambiguous_staging(tmp_path):
    with pytest.raises(ValueError, match=re.escape("DOS 8.3")):
        harness._dos_staged_source_name(tmp_path / "unregistered_long_source.c")


def test_runtime_source_tus_compile_and_link_in_order(tmp_path, monkeypatch):
    """Frozen runtime TUs compile under the profile and join the link list."""
    root = tmp_path / "msc51"
    registry = _registry(tmp_path, [_msc51_record(root)])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    (tmp_path / "CSMRT.C").write_text("void rt(void) {}")
    commands = []

    def run(command, **kwargs):
        commands.append(command)
        for name in ("CASE.OBJ", "CSMRT.OBJ", "CASE.EXE"):
            (tmp_path / name).write_bytes(b"artifact")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(harness, "_run", run)
    built, *_ = harness._compile_and_link_unlocked(
        tmp_path / "CASE.C",
        tmp_path,
        kvikdos=tmp_path / "kvikdos.bin",
        msc6_root=toolchain.toolchain_root,
        obj_name="CASE.OBJ",
        exe_name="CASE.EXE",
        map_name="CASE.MAP",
        extra_source_names=("CSMRT.C",),
        toolchain=toolchain,
    )
    assert built
    assert len(commands) == 3
    assert "c:\\CSMRT.C" in commands[1]
    assert "/Foc:\\CSMRT.OBJ" in commands[1]
    assert "+c:\\CSMRT.OBJ" in commands[2][-1]


def test_unstaged_runtime_source_refuses_before_tools_run(tmp_path, monkeypatch):
    registry = _registry(tmp_path, [_msc51_record(tmp_path / "msc51")])
    toolchain = resolve_case_toolchain("msc51-small", evidence_path=registry)
    execute = Mock()
    monkeypatch.setattr(harness, "_run", execute)
    with pytest.raises(ValueError, match="not staged"):
        harness._compile_and_link_unlocked(
            tmp_path / "CASE.C",
            tmp_path,
            kvikdos=tmp_path / "kvikdos.bin",
            msc6_root=toolchain.toolchain_root,
            obj_name="CASE.OBJ",
            exe_name="CASE.EXE",
            map_name="CASE.MAP",
            extra_source_names=("CSMRT.C",),
            toolchain=toolchain,
        )


def test_expected_run_ok_requires_exit_code_and_stdout(tmp_path):
    options = SimpleNamespace(expected_exit_code=0, expected_stdout_contains="checksum = 637A4628")
    assert harness._expected_run_ok(options, 0, "checksum = 637A4628\n")
    assert not harness._expected_run_ok(options, 0, "checksum = 00000000\n")
    assert not harness._expected_run_ok(options, 1, "checksum = 637A4628\n")
    no_stdout = SimpleNamespace(expected_exit_code=255, expected_stdout_contains=None)
    assert harness._expected_run_ok(no_stdout, 255, "anything")
    assert not harness._expected_run_ok(no_stdout, 1, "anything")
