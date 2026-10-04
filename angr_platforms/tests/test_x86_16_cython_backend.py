"""Required compiled startup preserves explicit interpretation and rejects stale builds."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import sysconfig
from importlib.machinery import EXTENSION_SUFFIXES
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "angr_platforms/angr_platforms/X86_16/lifter_backend.py"
spec = importlib.util.spec_from_file_location("vex_backend_contract", SOURCE)
backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(backend)


def _manifest(root):
    source = root / backend.LIFTER_SOURCE
    source.parent.mkdir(parents=True)
    source.write_text("# pure Python lifter\n")
    cache = root / ".cache/cython-vex"
    cache.mkdir(parents=True)
    artifact = cache / ("lift_86_16" + EXTENSION_SUFFIXES[0])
    artifact.write_bytes(b"test extension identity")
    manifest = {
        "schema": backend.BUILD_SCHEMA, "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"), "source_sha256": backend.file_digest(source),
        "extension": artifact.name, "extension_sha256": backend.file_digest(artifact),
    }
    (cache / "active.json").write_text(json.dumps(manifest))
    return source, artifact, manifest


def _packaged_manifest(package_dir):
    """Create a verified bundle beside an isolated copied lifter source."""
    package_dir.mkdir(parents=True, exist_ok=True)
    source = package_dir / "lift_86_16.py"
    source.write_text("# pure Python lifter\n")
    bundle = package_dir / backend.PACKAGE_BUNDLE
    relative = Path("identity/lib/angr_platforms/X86_16") / ("lift_86_16" + EXTENSION_SUFFIXES[0])
    artifact = bundle / relative
    artifact.parent.mkdir(parents=True)
    artifact.write_bytes(b"test extension identity")
    manifest = {
        "schema": backend.BUILD_SCHEMA, "cache_tag": sys.implementation.cache_tag,
        "soabi": sysconfig.get_config_var("SOABI"), "source_sha256": backend.file_digest(source),
        "extension": relative.as_posix(), "extension_sha256": backend.file_digest(artifact),
    }
    (bundle / "active.json").write_text(json.dumps(manifest))
    return source, artifact, manifest


def _load_copied_backend(package_dir):
    """Load a copied lifter_backend module the way an isolated package would."""
    shutil.copyfile(SOURCE, package_dir / "lifter_backend.py")
    spec = importlib.util.spec_from_file_location("isolated_vex_backend", package_dir / "lifter_backend.py")
    isolated = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(isolated)
    return isolated


def test_default_backend_requires_verified_compilation(monkeypatch):
    """Normal startup must fail instead of silently interpreting a stale build."""
    monkeypatch.delenv("INERTIA_VEX_BACKEND", raising=False)
    monkeypatch.setattr(backend, "verified_extension_directory", lambda root: None)
    with pytest.raises(ImportError, match="missing or stale"):
        backend.activate_lifter_backend([])


def test_default_backend_selects_verified_cython(monkeypatch):
    """The default path activates the canonical extension before any import."""
    monkeypatch.delenv("INERTIA_VEX_BACKEND", raising=False)
    directory = Path("verified-extension")
    monkeypatch.setattr(backend, "verified_extension_directory", lambda root: directory)
    paths = ["source"]
    assert backend.activate_lifter_backend(paths) is backend.LifterBackend.CYTHON
    assert paths == [str(directory), "source"]


def test_python_mode_never_needs_a_build(monkeypatch):
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "python")
    monkeypatch.setattr(backend, "verified_extension_directory", lambda root: pytest.fail("Python must not consult the Cython cache"))
    paths = ["source"]
    assert backend.activate_lifter_backend(paths) is backend.LifterBackend.PYTHON
    assert paths == ["source"]


def test_required_build_refuses_and_auto_falls_back(monkeypatch):
    monkeypatch.setattr(backend, "verified_extension_directory", lambda root: None)
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "cython")
    with pytest.raises(ImportError, match="missing or stale"):
        backend.activate_lifter_backend([])
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "auto")
    assert backend.activate_lifter_backend([]) is backend.LifterBackend.PYTHON


def test_invalid_mode_names_the_configuration_error(monkeypatch):
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "typo")
    with pytest.raises(ValueError, match="INERTIA_VEX_BACKEND='typo'") as raised:
        backend.activate_lifter_backend([])
    assert isinstance(raised.value.__cause__, ValueError)


def test_verified_build_uses_canonical_extension_directory(tmp_path, monkeypatch):
    _, artifact, _ = _manifest(tmp_path)
    directory = backend.verified_extension_directory(tmp_path)
    assert directory == artifact.parent
    monkeypatch.setattr(backend, "verified_extension_directory", lambda root: directory)
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "cython")
    paths = ["source"]
    assert backend.activate_lifter_backend(paths) is backend.LifterBackend.CYTHON
    assert paths == [str(directory), "source"]


@pytest.mark.parametrize("damage", ["source", "artifact", "abi", "escape", "json", "shape"])
def test_stale_or_corrupt_build_is_rejected(tmp_path, damage):
    source, artifact, manifest = _manifest(tmp_path)
    if damage == "source":
        source.write_text("# changed semantics\n")
    elif damage == "artifact":
        artifact.write_bytes(b"corrupt")
    elif damage == "abi":
        manifest["soabi"] = "wrong-abi"
    elif damage == "escape":
        manifest["extension"] = str(tmp_path / artifact.name)
    cache = tmp_path / ".cache/cython-vex/active.json"
    cache.write_text(json.dumps(manifest))
    if damage == "json":
        cache.write_text("{")
    elif damage == "shape":
        cache.write_text("[]")
    assert backend.verified_extension_directory(tmp_path) is None


def test_verified_packaged_bundle_returns_extension_directory(tmp_path):
    """A staged bundle verifies against the copied source, not a repository."""
    package_dir = tmp_path / "lib" / "angr_platforms" / "X86_16"
    _, artifact, _ = _packaged_manifest(package_dir)
    assert backend.verified_packaged_extension_directory(package_dir) == artifact.parent.resolve()


@pytest.mark.parametrize("damage", ["source", "artifact", "abi", "escape", "json", "shape", "missing"])
def test_stale_or_corrupt_packaged_bundle_is_rejected(tmp_path, damage):
    """The packaged bundle applies the same fail-closed checks as the cache."""
    package_dir = tmp_path / "lib" / "angr_platforms" / "X86_16"
    source, artifact, manifest = _packaged_manifest(package_dir)
    bundle = package_dir / backend.PACKAGE_BUNDLE
    if damage == "source":
        source.write_text("# changed semantics\n")
    elif damage == "artifact":
        artifact.write_bytes(b"corrupt")
    elif damage == "abi":
        manifest["soabi"] = "wrong-abi"
    elif damage == "escape":
        manifest["extension"] = str(tmp_path / artifact.name)
    manifest_path = bundle / "active.json"
    manifest_path.write_text(json.dumps(manifest))
    if damage == "json":
        manifest_path.write_text("{")
    elif damage == "shape":
        manifest_path.write_text("[]")
    elif damage == "missing":
        manifest_path.unlink()
    assert backend.verified_packaged_extension_directory(package_dir) is None


def test_packaged_bundle_takes_precedence_over_repository_cache(monkeypatch):
    """A verified bundle beside the running file owns its artifact binding."""
    directory = Path("packaged-extension")
    monkeypatch.setattr(backend, "verified_packaged_extension_directory", lambda package_dir: directory)
    monkeypatch.setattr(
        backend,
        "verified_extension_directory",
        lambda root: pytest.fail("repository cache must not override a staged bundle"),
    )
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "cython")
    paths = ["source"]
    assert backend.activate_lifter_backend(paths) is backend.LifterBackend.CYTHON
    assert paths == [str(directory), "source"]


def test_copied_backend_activates_its_staged_bundle(tmp_path, monkeypatch):
    """A copied lifter_backend verifies the bundle against the copied source."""
    package_dir = tmp_path / "isolated" / "lib" / "angr_platforms" / "X86_16"
    package_dir.mkdir(parents=True)
    isolated = _load_copied_backend(package_dir)
    _, artifact, _ = _packaged_manifest(package_dir)
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "cython")
    paths = ["source"]
    assert isolated.activate_lifter_backend(paths) is isolated.LifterBackend.CYTHON
    assert paths == [str(artifact.parent.resolve()), "source"]


def test_copied_backend_refuses_a_corrupt_staged_bundle(tmp_path, monkeypatch):
    """A corrupt bundled artifact fails closed instead of interpreting."""
    package_dir = tmp_path / "isolated" / "lib" / "angr_platforms" / "X86_16"
    package_dir.mkdir(parents=True)
    isolated = _load_copied_backend(package_dir)
    _, artifact, _ = _packaged_manifest(package_dir)
    artifact.write_bytes(b"corrupt")
    monkeypatch.setenv("INERTIA_VEX_BACKEND", "cython")
    with pytest.raises(ImportError, match="missing or stale"):
        isolated.activate_lifter_backend([])


def test_interpreted_and_compiled_vex_are_identical():
    """Check calls, segments, flags, interrupts, and operand/address overrides."""
    assert backend.verified_extension_directory(ROOT) is not None, (
        "required Cython VEX build is absent or stale; run scripts/build_cython_vex.py"
    )
    code = """
import json
import pyvex
from types import SimpleNamespace
from angr_platforms.X86_16 import VEX_BACKEND, lift_86_16
from angr_platforms.X86_16.arch_86_16 import Arch86_16
instruction = SimpleNamespace(shared='instruction', nullable=None, get_type=lambda _: 'instruction type')
customizer = SimpleNamespace(shared='customizer', get_type=lambda _: 'customizer type', low_level=17)
facade = lift_86_16._LifterInstructionFacade(customizer, instruction)
assert facade._irsb_c is customizer
assert facade._instruction is instruction
facade.local_proof = ('direction evidence',)
assert facade.local_proof == ('direction evidence',)
assert facade.__dict__['local_proof'] == ('direction evidence',)
assert facade.shared == 'instruction'
assert facade.nullable is None
assert facade.get_type(None) == 'instruction type'
del instruction.get_type
assert facade.get_type(None) == 'customizer type'
customizer.get_type = lambda _: 'updated type'
assert facade.get_type(None) == 'updated type'
assert facade.low_level == 17
instruction.low_level = 23
assert facade.low_level == 23
try:
    facade.absent
except AttributeError:
    pass
else:
    raise AssertionError('missing facade attributes must remain missing')
class BrokenDescriptor:
    @property
    def low_level(self):
        raise AttributeError('descriptor has no value')
assert lift_86_16._LifterInstructionFacade(customizer, BrokenDescriptor()).low_level == 17
class ExplodingDescriptor:
    @property
    def low_level(self):
        raise RuntimeError('provider failure')
try:
    lift_86_16._LifterInstructionFacade(customizer, ExplodingDescriptor()).low_level
except RuntimeError as error:
    assert str(error) == 'provider failure'
else:
    raise AssertionError('provider errors must not be swallowed')
samples = [
    'b8ffff83c001c3', 'b8ffff89c1d1e819c0c3', '803e3e78317502c3c3',
    '5589e583ec048b46fe5dc3', '268b078b46028b04c3',
    '66b8785634126601c066c1e004c3', '678b448804c3',
    '9a00100020', 'e80000', 'c20800', 'cb', 'cd21',
    'f7f1c3', 'f7f9c3', 'f3a5c3', 'c8040000c9c3', '9c9dc3',
]
blocks = [str(pyvex.IRSB(bytes.fromhex(data), 0x1000, Arch86_16(), opt_level=0)) for data in samples]
print(json.dumps({'backend': VEX_BACKEND.value, 'module': lift_86_16.__file__, 'blocks': blocks}))
"""
    results = []
    without_cython = """
import builtins
original_import = builtins.__import__
def import_without_cython(name, *args, **kwargs):
    if name == 'cython':
        raise ModuleNotFoundError('Cython intentionally unavailable', name='cython')
    return original_import(name, *args, **kwargs)
builtins.__import__ = import_without_cython
"""
    for mode, prefix, legacy in (("python", "", False), ("cython", "", False), ("cython", without_cython, True)):
        env = dict(os.environ, INERTIA_VEX_BACKEND=mode, PYTHON_JIT="1", PYTHONPATH=str(ROOT / "angr_platforms") + os.pathsep + str(ROOT))
        script = code.replace("from angr_platforms.X86_16", "from angr_platforms.angr_platforms.X86_16") if legacy else code
        result = subprocess.run([sys.executable, "-c", prefix + script], cwd=ROOT, env=env, capture_output=True, text=True, check=True, timeout=180)
        results.append(json.loads(result.stdout))
    assert results[0]["backend"] == "python"
    assert results[1]["backend"] == "cython"
    assert results[1]["module"].endswith(tuple(EXTENSION_SUFFIXES))
    assert results[0]["blocks"] == results[1]["blocks"]
    assert results[2]["backend"] == "cython"
    assert results[0]["blocks"] == results[2]["blocks"]


def test_facade_forwarding_remains_live_without_a_compiled_build():
    """The default Python path must preserve dynamic precedence and null values."""
    from angr_platforms.X86_16.lift_86_16 import _LifterInstructionFacade

    instruction = SimpleNamespace(get_type=lambda _: "instruction", nullable=None)
    customizer = SimpleNamespace(get_type=lambda _: "customizer")
    facade = _LifterInstructionFacade(customizer, instruction)
    assert facade._irsb_c is customizer
    assert facade._instruction is instruction
    facade.local_proof = ("direction evidence",)
    assert facade.local_proof == ("direction evidence",)
    assert facade.__dict__["local_proof"] == ("direction evidence",)
    assert facade.get_type(None) == "instruction"
    assert facade.nullable is None
    del instruction.get_type
    assert facade.get_type(None) == "customizer"
    customizer.get_type = lambda _: "updated"
    assert facade.get_type(None) == "updated"
    with pytest.raises(AttributeError):
        _ = facade.missing
