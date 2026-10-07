"""Merged disassembly must expose real shared-PAT naming evidence and conflicts."""

import json
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from tools.signatures.omf_pat import PatModule, PatPublicName, format_pat_module_line
from tools.ada_script.signatures import MatchStatus, apply_signatures

ROOT = Path(__file__).resolve().parents[2]
BODY = bytes.fromhex("55 8b ec b8 00 00 57 56 8b 46 04") + b"\x90" * 24 + bytes.fromhex("5e 5f 8b e5 5d c3")
BASE = 0x10000


def _catalog(path, name="_runtime", body=BODY):
    module = PatModule("msc.lib", "test MSC", name, tuple(body[:32]), len(body),
                       (PatPublicName(0, name),), (), tuple(body[32:]))
    path.write_text(format_pat_module_line(module) + "\n---\n")
    return path


def _database():
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE symbols(addr INTEGER PRIMARY KEY,name TEXT,auto INTEGER,kind TEXT);
        CREATE TABLE functions(start INTEGER PRIMARY KEY,end INTEGER,name TEXT,flags INTEGER);
        CREATE TABLE data_items(addr INTEGER,size INTEGER,count INTEGER);
        CREATE TABLE code_seeds(addr INTEGER PRIMARY KEY);
    """)
    return conn


def _match(conn, tmp_path, image=BODY, catalogs=None):
    catalogs = catalogs or (_catalog(tmp_path / "runtime.pat"),)
    return apply_signatures(conn, image=image, base=BASE, catalogs=catalogs, cache_dir=tmp_path / "cache")


def test_unique_library_match_names_symbol_and_seeds_without_inventing_extent(tmp_path):
    with _database() as conn:
        report = _match(conn, tmp_path)
        assert report.named_count == report.materialized_count == 1
        assert report.failure_count == 0
        assert conn.execute("SELECT name FROM symbols").fetchall() == [("runtime",)]
        assert conn.execute("SELECT start,end,name FROM functions").fetchall() == [(BASE, BASE, "runtime")]
        record = json.loads(conn.execute("SELECT evidence FROM signature_matches").fetchone()[0])
        assert record["candidates"][0]["source"] == "msc.lib"


@pytest.mark.parametrize("image", [BODY[:-1] + b"\xcb", BODY + b"\x90" + BODY])
def test_changed_or_repeated_body_does_not_claim_library_identity(tmp_path, image):
    with _database() as conn:
        report = _match(conn, tmp_path, image)
        assert report.named_count == 0
        assert conn.execute("SELECT * FROM symbols").fetchall() == []


def test_catalog_conflict_is_recorded_without_first_match_winning(tmp_path):
    catalogs = (_catalog(tmp_path / "a.pat", "_first"), _catalog(tmp_path / "b.pat", "_second"))
    with _database() as conn:
        report = _match(conn, tmp_path, catalogs=catalogs)
        assert report.matches[0].status == MatchStatus.AMBIGUOUS
        assert report.raw_fact_count == 2
        assert report.materialized_count == report.failure_count == 1
        assert conn.execute("SELECT * FROM symbols").fetchall() == []


def test_user_name_preserved_with_signature_provenance(tmp_path):
    with _database() as conn:
        conn.execute("INSERT INTO symbols VALUES(?, 'player_alloc', 0, 'name')", (BASE,))
        report = _match(conn, tmp_path)
        assert report.matches[0].status == MatchStatus.PRESERVED
        assert conn.execute("SELECT name FROM symbols").fetchone()[0] == "player_alloc"
        assert report.matches[0].names == ("runtime",)


def test_auto_name_replaced_and_function_projection_updated(tmp_path):
    with _database() as conn:
        conn.execute("INSERT INTO symbols VALUES(?, 'auto_label', 1, 'sub')", (BASE,))
        conn.execute("INSERT INTO functions VALUES(?,?, 'auto_label',0)", (BASE, BASE + len(BODY)))
        _match(conn, tmp_path)
        assert conn.execute("SELECT name,end FROM functions").fetchone() == ("runtime", BASE + len(BODY))


@pytest.mark.parametrize("conflict", ["name", "data"])
def test_conflicting_workspace_evidence_is_not_overwritten(tmp_path, conflict):
    with _database() as conn:
        if conflict == "name":
            conn.execute("INSERT INTO symbols VALUES(?, 'runtime',0,'name')", (BASE + 100,))
            expected = MatchStatus.COLLISION
        else:
            conn.execute("INSERT INTO data_items VALUES(?,?,1)", (BASE, len(BODY)))
            expected = MatchStatus.DATA_CONFLICT
        report = _match(conn, tmp_path)
        assert report.matches[0].status == expected
        assert report.named_count == 0


def test_signature_disable_policy_does_not_scan(tmp_path, monkeypatch):
    monkeypatch.setenv("INERTIA_DISABLE_SIGNATURES", "1")
    with _database() as conn:
        report = _match(conn, tmp_path, catalogs=(tmp_path / "absent.pat",))
        assert report.disabled
        assert report.raw_fact_count == 0


def test_auto_pat_backend_uses_shared_matcher_selection(tmp_path):
    with _database() as conn:
        report = apply_signatures(conn, image=BODY, base=BASE,
                                  catalogs=(_catalog(tmp_path / "auto.pat"),),
                                  cache_dir=tmp_path / "cache", backend="auto")
        assert report.named_count == 1


def _mz(path):
    image = b"\xe8\x0d\x00\xb8\x00\x4c\xcd\x21" + b"\x90" * 8 + BODY
    header = bytearray(32)
    header[:2] = b"MZ"
    struct.pack_into("<13H", header, 2, 32 + len(image), 1, 0, 2, 0, 0xffff, 0,
                     0xfffe, 0, 0, 0, 28, 0)
    path.write_bytes(header + image)
    return path


def test_merged_cli_names_library_in_asm_lst_and_database(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    catalog = _catalog(tmp_path / "runtime.pat")
    out = tmp_path / "result"
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                             "--full", "--work-dir", str(out), "--signature-catalog", str(catalog)],
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "runtime" in (out / "GAME.asm").read_text()
    assert "runtime" in (out / "GAME.lst").read_text()
    with sqlite3.connect(out / "analysis.db") as conn:
        assert conn.execute("SELECT name FROM functions WHERE start=?", (BASE + 16,)).fetchone() == ("runtime",)
        assert "runtime" in " ".join(row[0] or "" for row in conn.execute("SELECT asm_str FROM instructions"))
    assert json.loads((out / "signatures.json").read_text())["named_count"] == 1


def test_merged_cli_no_signatures_keeps_default_names(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    out = tmp_path / "result"
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                             "--full", "--work-dir", str(out), "--no-signatures"],
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "sub_10010" in (out / "GAME.asm").read_text()
    report = json.loads((out / "signatures.json").read_text())
    assert report["named_count"] == 0
    assert report["disabled"]


def test_asm_code_encoding_switch_preserves_bytes_or_shows_mnemonic(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    image = bytearray(binary.read_bytes())
    image[32:38] = bytes.fromhex("80 3e 3e 78 31 c3")
    binary.write_bytes(image)
    rendered = {}
    for mode in ("exact", "mnemonic"):
        out = tmp_path / mode
        result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                                 "--work-dir", str(out), "--no-signatures",
                                 "--asm-code-encoding", mode],
                                capture_output=True, text=True, timeout=40)
        assert result.returncode == 0, result.stdout + result.stderr
        rendered[mode] = (out / "GAME.asm").read_text()
    assert "db 80h,3Eh,3Eh,78h,31h ; cmp" in rendered["exact"]
    assert "cmp" in rendered["mnemonic"]
    assert "db 80h,3Eh,3Eh,78h,31h" not in rendered["mnemonic"]
    assert "Mnemonic view" in rendered["mnemonic"]


def test_missing_explicit_catalog_fails_loudly(tmp_path):
    with _database() as conn, pytest.raises(FileNotFoundError, match=r"absent\.pat"):
        _match(conn, tmp_path, catalogs=(tmp_path / "absent.pat",))


def test_idc_name_survives_cli_library_matching(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    catalog = _catalog(tmp_path / "runtime.pat")
    idc = tmp_path / "names.idc"
    idc.write_text('static main() { set_name(0x10010, "user_runtime", 0); }\n')
    out = tmp_path / "result"
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary), "--full",
                             "--work-dir", str(out), "--signature-catalog", str(catalog),
                             "--idc-script", str(idc)], capture_output=True, text=True, timeout=40)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "user_runtime" in (out / "GAME.asm").read_text()
    report = json.loads((out / "signatures.json").read_text())
    assert report["matches"][0]["status"] == "preserved_user_name"


def test_unsupported_idc_is_refused_instead_of_silently_discarded(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    idc = tmp_path / "names.idc"
    idc.write_text("extern ltf;\n")
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                             "--work-dir", str(tmp_path / "result"), "--idc-script", str(idc),
                             "--no-signatures"], capture_output=True, text=True, timeout=40)
    assert result.returncode == 1
    assert "IDC parse failed" in result.stderr


def test_runtime_trace_without_load_segment_refuses_instead_of_guessing(tmp_path):
    binary = _mz(tmp_path / "GAME.EXE")
    runtime = tmp_path / "trace.json"
    runtime.write_text(json.dumps({"Meta": {}, "Code": {"0x10000": {"ExecCount": 1}}}))
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                             "--work-dir", str(tmp_path / "result"), "--runtime", str(runtime),
                             "--no-signatures"], capture_output=True, text=True, timeout=40)
    assert result.returncode == 1
    assert "Meta.DosboxLoadSeg" in result.stderr


@pytest.mark.parametrize("signature", [b"PE\0\0", b"NE\0\0", b"LE\0\0", b"LX\0\0"])
def test_extended_executable_stub_is_refused(tmp_path, signature):
    binary = tmp_path / "EXTENDED.EXE"
    header = bytearray(128)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x80)
    binary.write_bytes(header + signature + b"\x90" * 16)
    result = subprocess.run([sys.executable, "-m", "tools.ada_script", str(binary),
                             "--work-dir", str(tmp_path / "result"), "--no-signatures"],
                            capture_output=True, text=True, timeout=40)
    assert result.returncode == 1
    assert "Unsupported extended executable" in result.stderr
    assert not (tmp_path / "result" / "analysis.db").exists()
