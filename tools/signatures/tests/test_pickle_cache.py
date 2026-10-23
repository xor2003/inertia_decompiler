"""Exercise compatibility at both production signature-cache readers."""

import pickle
import subprocess
import sys
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

from tools.compiler_id.report import _resolve_catalog_input
from tools.signatures import omf_pat


def _constructor_failure(error: type[Exception]) -> object:
    raise error("cache constructor defect")


class _BrokenConstructor:
    def __init__(self, error: type[Exception]) -> None:
        self.error = error

    def __reduce__(self) -> tuple[Callable[..., object], tuple[type[Exception]]]:
        return _constructor_failure, (self.error,)


def _reader(tmp_path: Path, kind: str, payload: bytes) -> Callable[[], tuple[object, ...]]:
    catalog = tmp_path / "catalog.pat"
    catalog.write_text("90" * 32 + " 00 0000 0001 :0000 function\n---\n")
    if kind == "bundle":
        bundle = tmp_path / "catalog.zip"
        with zipfile.ZipFile(bundle, "w") as archive:
            archive.write(catalog, "catalog.pat")
            archive.writestr("catalog_specs.pickle", payload)
        return lambda: _resolve_catalog_input(bundle)[2]
    cache_dir = tmp_path / "specs"
    omf_pat.load_cached_pat_regex_specs(catalog, cache_dir)
    cache_path, = cache_dir.glob("*.patrx.pickle")
    cache_path.write_bytes(payload)
    omf_pat.load_cached_pat_regex_specs.cache_clear()
    return lambda: omf_pat.load_cached_pat_regex_specs(catalog, cache_dir)


@pytest.mark.parametrize("kind", ["pat", "bundle"])
def test_legacy_specs_are_cache_hits(tmp_path, monkeypatch, kind):
    source = tmp_path / "source.pat"
    source.write_text("90" * 32 + " 00 0000 0001 :0000 function\n---\n")
    expected = omf_pat.load_cached_pat_regex_specs(source, tmp_path / "original")
    payload = pickle.dumps(expected, protocol=0)
    assert b"ctools.signatures.omf_pat\n" in payload
    legacy = payload.replace(b"ctools.signatures.omf_pat\n", b"comf_pat\n")
    read = _reader(tmp_path, kind, legacy)

    def forbid_rebuild(*_args):
        pytest.fail("supported legacy cache must not be discarded")

    monkeypatch.setattr(omf_pat, "parse_pat_file", forbid_rebuild)
    assert read() == expected


@pytest.mark.parametrize("kind", ["pat", "bundle"])
@pytest.mark.parametrize("error", [RuntimeError, OSError, TypeError, ValueError])
def test_constructor_defects_propagate(tmp_path, kind, error):
    read = _reader(tmp_path, kind, pickle.dumps(_BrokenConstructor(error)))
    with pytest.raises(error, match="cache constructor defect"):
        read()


@pytest.mark.parametrize("kind", ["pat", "bundle"])
@pytest.mark.parametrize("payload", [b"broken", b"", b"comf_pat\nMissingClass\n."])
def test_invalid_cache_is_recoverable(tmp_path, caplog, kind, payload):
    result = _reader(tmp_path, kind, payload)()
    if kind == "pat":
        assert len(result) == 1
        assert isinstance(result[0], omf_pat.CachedPatRegexSpec)
    else:
        assert result == ()
    assert "signature cache" in caplog.text.lower()


def test_legacy_decode_in_cold_interpreter():
    script = """
import sys
from tools.signatures.pickle_cache import loads_signature_pickle
assert 'omf_pat' not in sys.modules
symbol = loads_signature_pickle(b'comf_pat\\nPatPublicName\\n.')
from tools.signatures.omf_pat import PatPublicName
assert symbol is PatPublicName
assert 'omf_pat' not in sys.modules
"""
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_missing_class_preserves_lookup_cause():
    from tools.signatures.pickle_cache import SignatureCacheClassLookupError, loads_signature_pickle

    with pytest.raises(SignatureCacheClassLookupError) as captured:
        loads_signature_pickle(b"comf_pat\nMissingClass\n.")
    assert isinstance(captured.value.__cause__, AttributeError)
