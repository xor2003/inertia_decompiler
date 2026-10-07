"""Guarded GNU Make parity controls for the bounded inventory reader.

These external controls retain their unavailable-tool skips; the pipeline
accounts for all43 cases in its explicit makefile-gnu-oracle lane.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from tools.dev import makefile_inventory as staged
from tools.dev.tests.test_makefile_variable_expansion import MAKE_ORACLE_CASES, OVERRIDE_CASES, UNDEFINE_CASES


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
@pytest.mark.parametrize("source,variable,expected", MAKE_ORACLE_CASES)
def test_supported_cases_match_gnu_make(source: str, variable: str, expected: tuple[str, ...]) -> None:
    """Supported expansion cases agree with a GNU Make oracle."""
    oracle_source = source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(" + variable + ")'\n"
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=oracle_source,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert tuple(oracle.stdout.split()) == expected


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
@pytest.mark.parametrize("source,variable,expected", OVERRIDE_CASES + UNDEFINE_CASES)
def test_override_undefine_match_gnu_make(
    source: str, variable: str, expected: tuple[str, ...]
) -> None:
    """Override/undefine cases agree with a GNU Make oracle."""
    oracle_source = source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(" + variable + ")'\n"
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=oracle_source,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert tuple(oracle.stdout.split()) == expected


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
def test_skipped_include_override_oracle_proves_flag_needed(tmp_path: Path) -> None:
    """Oracle control: an included `override X` beats a later `X =`."""
    (tmp_path / "frag.mk").write_text("override X = evil.py\n", encoding="utf-8")
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "X = old.py\ninclude frag.mk\nX = new.py\n"
        "inspect:\n\t@printf '%s\\n' '$(X)'\n",
        encoding="utf-8",
    )
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-C", str(tmp_path), "inspect"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert oracle.stdout.split() == ["evil.py"]
    # The same shape with the include unresolvable must stay flagged.
    source = "X = old.py\ninclude missing.mk\nX = new.py\n"
    words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
    assert words == ("new.py", "$(X)")


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
def test_conditional_override_undefine_oracle(tmp_path: Path) -> None:
    """Oracle control: F=1 makes a guarded override live under plain undefine."""
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "ifdef F\noverride X = a.py\nendif\nundefine X\n"
        "inspect:\n\t@printf '%s\\n' '$(X)'\n",
        encoding="utf-8",
    )
    guarded = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", str(makefile), "F=1", "inspect"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    unguarded = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", str(makefile), "inspect"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert guarded.returncode == 0 and unguarded.returncode == 0
    # The outcome depends on the guard, so the staged reader must refuse.
    assert guarded.stdout.split() == ["a.py"]
    assert unguarded.stdout.split() == []
    source = "ifdef F\noverride X = a.py\nendif\nundefine X\n"
    assert staged.makefile_variable_words(source, "X") == ("$(X)",)


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
def test_include_cases_match_gnu_make(tmp_path: Path) -> None:
    """Literal includes agree with a GNU Make oracle run in tmp_path."""
    (tmp_path / "frag.mk").write_text("X += frag.py\nY = fragvar.py\n", encoding="utf-8")
    makefile = tmp_path / "Makefile"
    makefile.write_text(
        "X = top.py\ninclude frag.mk\n"
        "inspect:\n\t@printf '%s %s\\n' '$(X)' '$(Y)'\n",
        encoding="utf-8",
    )
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-C", str(tmp_path), "inspect"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    oracle_x, oracle_y = oracle.stdout.split()[:2], oracle.stdout.split()[2:]
    assert tuple(oracle_x + oracle_y) == ("top.py", "frag.py", "fragvar.py")
    words = staged.makefile_variable_words_from_file(makefile, "X")
    assert words == ("top.py", "frag.py")
    assert staged.makefile_variable_words_from_file(makefile, "Y") == ("fragvar.py",)


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
@pytest.mark.parametrize(
    "guard,expected",
    [("ifeq (a,a)", "hidden"), ("ifeq (a,b)", "second")],
)
def test_conditional_override_oracle_both_branches(guard: str, expected: str) -> None:
    """Oracle control: the branch outcome is guard-dependent, so flag it."""
    source = f"X=first\n{guard}\noverride X=hidden\nendif\nX=second\n"
    oracle_source = source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(X)'\n"
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=oracle_source,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert oracle.stdout.split() == [expected]
    assert staged.makefile_variable_words(source, "X") == ("second", "$(X)")


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
def test_conditional_override_undefine_oracle_both_branches() -> None:
    """Oracle control: guarded override survives a later plain undefine."""
    results = {}
    for guard in ("ifeq (a,a)", "ifeq (a,b)"):
        source = f"X=first\n{guard}\noverride X=hidden\nendif\nundefine X\n"
        oracle_source = source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(X)'\n"
        oracle = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
            input=oracle_source,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        assert oracle.returncode == 0, oracle.stderr
        results[guard] = oracle.stdout.split()
    assert results["ifeq (a,a)"] == ["hidden"]
    assert results["ifeq (a,b)"] == []
    for guard in ("ifeq (a,a)", "ifeq (a,b)"):
        source = f"X=first\n{guard}\noverride X=hidden\nendif\nundefine X\n"
        assert staged.makefile_variable_words(source, "X") == ("first", "$(X)")


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
@pytest.mark.parametrize(
    "source,expected",
    [
        ("override X=orig\ndefine X\nnewbody\nendef\nX=later\n", "orig"),
        ("X=a\noverride define X\nbody\nendef\nX=later\n", "body"),
    ],
)
def test_define_override_matches_gnu_make(source: str, expected: str) -> None:
    """define precedence cases agree with a GNU Make oracle."""
    oracle_source = source + ".PHONY: inspect\ninspect:\n\t@printf '%s\\n' '$(X)'\n"
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=oracle_source,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert oracle.stdout.split() == [expected]


@pytest.mark.skipif(shutil.which("make") is None, reason="make oracle unavailable")
@pytest.mark.parametrize("assignment,tail,expected", [
    ("private X=hidden", "", "hidden"),
    ("override private X=hidden", "X=later\n", "hidden"),
    ("private override X=hidden", "X=later\n", "hidden"),
    ("X$(EMPTY)=hidden", "", "hidden"),
    ("${NAME}=hidden", "", "hidden"),
    ("override ${NAME}=hidden", "X=later\n", "hidden"),
])
def test_unknown_global_assignment_gnu_oracle_proves_refusal_needed(assignment: str, tail: str, expected: str) -> None:
    """GNU changes the selected global value while the reader must refuse it."""
    source = f"NAME=X\nEMPTY=\nX=first\n{assignment}\n{tail}"
    oracle = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "inspect"],
        input=source + "$(info $(X))\n.PHONY: inspect\ninspect:\n",
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert oracle.returncode == 0, oracle.stderr
    assert oracle.stdout.split() == [expected]
    assert staged.makefile_variable_words(source, "X")[-1] == "$(X)"
    assert staged.makefile_inventory_diagnostics(source)

