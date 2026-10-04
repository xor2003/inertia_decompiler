"""Input fingerprints must change with content and toolchain file identity."""

import hashlib

import pytest

from scripts.compiler_coverage_provenance import (
    KVMAccessStatus,
    implementation_fingerprint,
    input_fingerprint,
    kvm_access_evidence,
    runtime_environment_snapshot,
)


def test_runtime_environment_records_dependencies_and_kvm_state(tmp_path, monkeypatch):
    """Replays must retain more than the Python executable hash."""
    import scripts.compiler_coverage_provenance as provenance

    class Distribution:
        """Minimal installed-distribution metadata boundary."""

        def __init__(self, name, version):
            self.metadata = {"Name": name}
            self.version = version

    monkeypatch.setattr(
        provenance.metadata,
        "distributions",
        lambda: (Distribution("Z3-Solver", "4.12"), Distribution("angr", "9.2")),
    )
    device = tmp_path / "kvm"
    device.write_bytes(b"")

    snapshot = runtime_environment_snapshot(kvm_device=device).to_dict()

    assert snapshot["installed_distributions"] == [["angr", "9.2"], ["z3-solver", "4.12"]]
    assert snapshot["kvm"]["status"] == KVMAccessStatus.READ_WRITE.value
    assert snapshot["python_version"]
    assert snapshot["machine"]


def test_kvm_absence_is_a_typed_nonresult(tmp_path):
    """A missing device must not be recorded as a semantic test failure."""
    evidence = kvm_access_evidence(tmp_path / "missing")
    assert evidence.status is KVMAccessStatus.MISSING
    assert evidence.error_number is not None


def test_missing_tool_is_explicit(tmp_path):
    assert input_fingerprint(tmp_path / "missing")["error"] == "missing"


def test_source_hash_is_standard_sha256(tmp_path):
    source = tmp_path / "case.c"
    source.write_bytes(b"int main(void) { return 0; }\n")
    assert input_fingerprint(source)["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()


def test_toolchain_hash_tracks_names_and_content(tmp_path):
    tool = tmp_path / "CL.EXE"
    tool.write_bytes(b"compiler")
    first = input_fingerprint(tmp_path)
    assert first == input_fingerprint(tmp_path)
    assert first["files"] == 1
    tool.write_bytes(b"updated")
    changed = input_fingerprint(tmp_path)
    assert changed["sha256"] != first["sha256"]
    tool.rename(tmp_path / "OTHER.EXE")
    assert input_fingerprint(tmp_path)["sha256"] != changed["sha256"]


@pytest.mark.parametrize("relative", [
    "decompile.py", "scripts/helper.py", "inertia_decompiler/owner.py",
    "angr_platforms/angr_platforms/X86_16/ir/owner.py",
])
def test_implementation_identity_tracks_add_edit_rename_delete(tmp_path, relative):
    before = implementation_fingerprint(tmp_path)
    source = tmp_path / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("# first\n")
    added = implementation_fingerprint(tmp_path)
    assert added["files"] == 1
    assert added != before
    source.write_text("# other\n")
    edited = implementation_fingerprint(tmp_path)
    assert edited != added
    renamed = source.rename(source.with_name("renamed.py"))
    assert implementation_fingerprint(tmp_path) != edited
    renamed.unlink()
    assert implementation_fingerprint(tmp_path) == before


def test_implementation_identity_ignores_runtime_artifacts_and_checkout_location(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    for root in (first, second):
        root.mkdir()
        (root / "decompile.py").write_text("# identical\n")
    expected = implementation_fingerprint(first)
    for relative in (".cache/generated.py", "scripts/__pycache__/generated.py", "scripts/.cache/generated.py"):
        artifact = first / relative
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_text("# runtime artifact\n")
    assert implementation_fingerprint(first) == implementation_fingerprint(second) == expected
