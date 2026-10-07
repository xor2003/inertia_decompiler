"""Configuration ownership and compatibility controls."""

from pathlib import Path

from tools.signatures import flair_paths, signature_matching_policy


def test_legacy_modules_preserve_identity():
    import tools.signatures.flair_paths as legacy_paths
    import tools.signatures.signature_matching_policy as legacy_policy

    assert legacy_paths is flair_paths
    assert legacy_policy is signature_matching_policy


def test_default_assets_stay_at_repository_root(monkeypatch):
    monkeypatch.delenv("INERTIA_FLAIR_ROOT", raising=False)
    assert flair_paths.resolve_flair_root() == Path(__file__).resolve().parents[3] / "flair_startup"


def test_explicit_root_overrides_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("INERTIA_FLAIR_ROOT", str(tmp_path / "environment"))
    assert flair_paths.resolve_flair_root(tmp_path) == tmp_path


def test_legacy_parser_and_catalog_preserve_identity():
    import tools.signatures.omf_pat as legacy_parser
    import tools.signatures.pat_literal_filter as legacy_filter
    import tools.signatures.signature_catalog as legacy_catalog
    from tools.signatures import omf_pat, pat_literal_filter, signature_catalog

    assert legacy_parser is omf_pat
    assert legacy_catalog is signature_catalog
    assert legacy_filter is pat_literal_filter
    assert legacy_parser.PatModule is omf_pat.PatModule


def test_legacy_pickle_class_lookup():
    import pickle

    from tools.signatures.omf_pat import PatPublicName

    # Protocol-zero global lookup represents pickles produced before relocation.
    assert pickle.loads(b"comf_pat\nPatPublicName\n.") is PatPublicName
    symbol = PatPublicName(3, "example")
    assert pickle.loads(pickle.dumps(symbol)) == symbol
