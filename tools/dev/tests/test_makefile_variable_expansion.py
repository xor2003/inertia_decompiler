"""Bounded Makefile inventory variable-expansion regression tests.

Covers the bounded ``$(NAME)``/``${NAME}`` word-list extension: GNU Make
``=``/``:=``/``+=``/``?=`` timing, duplicates, continuations, and the
fail-closed refusals (unknown, cyclic, conditional, opaque, function and
shell references stay as explicit verbatim tokens).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.dev import makefile_inventory as staged

REPO_ROOT = Path(__file__).resolve().parents[3]


LITERAL_CASES = [
    ("QA := a.py\nQA += b.py\n", ("a.py", "b.py")),
    ("QA += a.py\nQA += a.py\n", ("a.py", "a.py")),
    ("QA := old.py\nQA := new.py\nQA += tail.py\n", ("new.py", "tail.py")),
    ("QA ?= a.py\nQA ?= ignored.py\nQA += b.py\n", ("a.py", "b.py")),
    ("QA = a.py # comment\nQA += b.py\n", ("a.py", "b.py")),
    ("QA := a.py \\\n\tb.py\nQA += \\\n\tc.py\n", ("a.py", "b.py", "c.py")),
    ("QA_OTHER := ignored.py\nQA:=a.py\n", ("a.py",)),
    ("QA :=\nQA ?= ignored.py\n", ()),
]


@pytest.mark.parametrize("source,expected", LITERAL_CASES)
def test_literal_semantics_preserved(source: str, expected: tuple[str, ...]) -> None:
    """Literal-only assignment behavior matches the pre-repair reader."""
    assert staged.makefile_variable_words(source, "QA") == expected


EXPANSION_CASES = [
    # forward reference through a recursive variable resolves at use time
    ("B = $(A)\nA = late.py\n", "B", ("late.py",)),
    # := binds the value current at definition time only
    ("A = one.py\nB := $(A)\nA = two.py\n", "B", ("one.py",)),
    # = defers: reassignment after the fact is visible
    ("A = one.py\nB = $(A)\nA = two.py\n", "B", ("two.py",)),
    # += on a simple variable expands the append immediately
    ("W = first.py\nV := a.py\nV += $(W)\nW = second.py\n", "V", ("a.py", "first.py")),
    # += on a recursive variable stores the append unexpanded
    ("W = first.py\nV = a.py\nV += $(W)\nW = second.py\n", "V", ("a.py", "second.py")),
    # += on an undefined variable behaves like =
    ("V += $(W)\nW = late.py\n", "V", ("late.py",)),
    # ?= after an empty := still sees the variable as defined
    ("V :=\nV ?= ignored.py\n", "V", ()),
    # ?= only applies while undefined
    ("V ?= a.py\nV ?= b.py\n", "V", ("a.py",)),
    # ?= contributes the recursive default when never defined
    ("V ?= $(W)\nW = late.py\n", "V", ("late.py",)),
    # duplicates introduced through expansion stay visible
    ("V := a.py\nW = a.py\nV += $(W) a.py\n", "V", ("a.py", "a.py", "a.py")),
    # ${NAME} brace form
    ("A = x.py\nB = ${A} y.py\n", "B", ("x.py", "y.py")),
    # nested named reference chains through both flavors
    ("A := a.py\nB := $(A) b.py\nC = $(B) c.py\nD += $(C)\n", "D", ("a.py", "b.py", "c.py")),
    # a := variable's previous value is visible while it is being rebound
    ("A = one.py\nA := $(A) two.py\n", "A", ("one.py", "two.py")),
    # references inside continued lines
    ("A = x.py \\\n\ty.py\nB = $(A)\n", "B", ("x.py", "y.py")),
    # $$ collapses to a literal dollar sign, not a reference
    ("A = price$$x.py\nB = $(A)\n", "B", ("price$x.py",)),
]


@pytest.mark.parametrize("source,variable,expected", EXPANSION_CASES)
def test_named_reference_expansion(source: str, variable: str, expected: tuple[str, ...]) -> None:
    """$(NAME)/${NAME} word-list references expand with Make timing."""
    assert staged.makefile_variable_words(source, variable) == expected


REFUSAL_CASES = [
    # unknown variable stays an explicit token (Make would emit empty)
    ("V := $(MISSING) ok.py\n", "V", ("$(MISSING)", "ok.py")),
    # := bound before the name existed stays unresolved
    ("B := $(A)\nA = late.py\n", "B", ("$(A)",)),
    # mutual recursion is left verbatim instead of looping
    ("A = $(B)\nB = $(A)\n", "A", ("$(A)",)),
    ("A = $(B)\nB = $(A)\n", "B", ("$(B)",)),
    # direct self-recursion keeps the token
    ("A = x.py $(A)\n", "A", ("x.py", "$(A)")),
    # function calls are never executed; verbatim tokens split on whitespace
    # but every fragment carrying '$( stays an explicit unresolved token
    ("V := $(shell echo hi)\n", "V", ("$(shell", "echo", "hi)")),
    ("V := $(filter a.py,$(B))\nB = a.py\n", "V", ("$(filter", "a.py,$(B))")),
    ("V := $(if x,$(A))\nA = a.py\n", "V", ("$(if", "x,$(A))")),
    # substitution references are not supported
    ("V := $(A:.c=.o)\nA = x.c\n", "V", ("$(A:.c=.o)",)),
    # computed names are not followed
    ("V = $(A$(B))\nB = _x\nA_x = got.py\n", "V", ("$(A$(B))",)),
    # != shell capture marks the variable opaque, never executes
    ("V != echo hi\n", "V", ("$(V)",)),
    ("S != echo hi\nV = $(S) ok.py\n", "V", ("$(S)", "ok.py")),
    # define bodies are opaque
    ("define V\nbody.py\nendef\n", "V", ("$(V)",)),
    ("define S\nbody.py\nendef\nV = $(S) ok.py\n", "V", ("$(S)", "ok.py")),
    # conditional assignments are not applied and are surfaced
    ("ifdef FLAG\nV = gated.py\nendif\n", "V", ("$(V)",)),
    ("V = base.py\nifdef FLAG\nV += gated.py\nendif\n", "V", ("base.py", "$(V)")),
    ("V = base.py\nifeq ($(FLAG),y)\nV = other.py\nendif\n", "V", ("base.py", "$(V)")),
    # references to a conditionally-defined variable stay unresolved
    ("ifdef F\nA = gated.py\nendif\nV = $(A) ok.py\n", "V", ("$(A)", "ok.py")),
    # a later unconditional reassignment clears the conditional mark
    ("ifdef F\nV = gated.py\nendif\nV = plain.py\n", "V", ("plain.py",)),
    # unterminated references keep the remainder verbatim
    ("V = ok.py $(BROKEN\n", "V", ("ok.py", "$(BROKEN")),
    # single-character $x references are not claimed
    ("V = $x.py\n", "V", ("$x.py",)),
]


@pytest.mark.parametrize("source,variable,expected", REFUSAL_CASES)
def test_unsupported_constructs_fail_closed(source: str, variable: str, expected: tuple[str, ...]) -> None:
    """Unsupported or unprovable constructs stay explicit tokens."""
    assert staged.makefile_variable_words(source, variable) == expected


def test_shell_reference_never_executes(tmp_path: Path) -> None:
    """A $(shell ...) token is retained verbatim without execution."""
    marker = tmp_path / "shell_executed"
    source = f"V := $(shell touch {marker})\n"
    words = staged.makefile_variable_words(source, "V")
    assert words[0] == "$(shell"
    assert any("$(" in word for word in words)
    assert not marker.exists()


def test_eval_and_wildcard_stay_verbatim() -> None:
    """$(eval)/$(wildcard) functions are never evaluated."""
    source = "V := $(eval HACKED := 1)$(wildcard *.py)\n"
    words = staged.makefile_variable_words(source, "V")
    assert any("$(" in word for word in words)
    assert staged.makefile_variable_words(source, "HACKED") == ()


def test_target_and_recipe_lines_are_not_assignments() -> None:
    """Rule and recipe lines cannot masquerade as assignments."""
    source = "V = real.py\nfake: dep\n\techo V = wrong.py\n"
    assert staged.makefile_variable_words(source, "V") == ("real.py",)
    source = "target: V = scoped.py\nV = global.py\n"
    assert staged.makefile_variable_words(source, "V") == ("global.py",)


SCOPED_IR_OWNERS = (
    "inertia/frontend/x86_16/frontend_local_call_evidence.py",
    "inertia/frontend/x86_16/mz_static_boot.py",
    "inertia/cli/mz_static_intake.py",
    "inertia/frontend/x86_16/frontend_near_return_continuation.py",
    "inertia/ir/near_return_continuation_view.py",
    "inertia/ir/scoped_control_obligations.py",
    "tools/dosunit/catalog/real16_scoped_invocation.py",
    "inertia/frontend/x86_16/frontend_invocation_inventory.py",
    "inertia/ir/entry_domain_call_preservation.py",
    "inertia/ir/scoped_function_ir_view.py",
)
SCOPED_IR_CONTRACT_TESTS = (
    "tests/ir/test_x86_16_premise_collection_budget.py",
    "tests/integration/test_x86_16_invocation_pending_inventory.py",
    "tests/integration/test_x86_16_near_call_frame_width.py",
    "tests/integration/test_x86_16_invocation_inventory_budgets.py",
    "tests/ir/test_x86_16_scoped_ir_view.py",
    "tests/ir/test_x86_16_scoped_ir_view_counters.py",
    "tests/ir/test_x86_16_scoped_ir_coverage.py",
    "tests/ir/test_x86_16_scoped_ir_function_refusals.py",
    "tests/ir/test_x86_16_scoped_segment_state.py",
    "tests/ir/test_x86_16_scoped_resolution_guard.py",
)
SCOPED_IR_NATIVE_TESTS = (
    "tests/ir/test_x86_16_invocation_edge_refinement.py",
    "tests/ir/test_x86_16_repeated_store_invocation.py",
    "tests/semantics/test_x86_16_declared_call_target_binding.py",
    "tests/ir/test_x86_16_invocation_path_load.py",
    "tests/frontend/test_x86_16_native_load_binding.py",
    "tests/ir/test_x86_16_invocation_feasible_joins.py",
    "tests/ir/test_x86_16_invocation_wide_multiply.py",
    "tests/ir/test_x86_16_invocation_internal_exit.py",
    "tests/ir/test_x86_16_declared_resize_boundary.py",
    "tests/ir/test_x86_16_resize_path_memory.py",
    "tests/frontend/test_x86_16_caller_native_intake.py",
    "tests/frontend/test_x86_16_encoded_entry_transport.py",
    "tests/frontend/test_x86_16_local_call_evidence.py",
    "tests/frontend/test_x86_16_local_evidence_epoch.py",
    "tests/integration/test_x86_16_scoped_invocation_source.py",
    "tests/integration/test_x86_16_declared_service_chain.py",
    "tests/frontend/test_x86_16_mz_static_invocation.py",
    "tests/cli/test_x86_16_mz_static_intake_guards.py",
    "tests/frontend/test_x86_16_mz_static_pending_callee.py",
    "tests/integration/test_x86_16_per_edge_frame_premise.py",
    "tests/integration/test_x86_16_near_return_continuation.py",
    "tests/integration/test_x86_16_scoped_control_obligations.py",
    "tests/integration/test_x86_16_scoped_control_refusal_ledger.py",
    "tests/integration/test_x86_16_near_return_scope_guards.py",
    "tests/frontend/test_x86_16_scoped_invocation_adapter.py",
    "tests/frontend/test_x86_16_scoped_ir_native_view.py",
    "tests/frontend/test_x86_16_scoped_ir_native_import.py",
    "tests/frontend/test_x86_16_scoped_ir_native_closure.py",
    "tests/frontend/test_x86_16_scoped_ir_native_resolution.py",
)
KVIKDOS_WORKER_TESTS = (
    "tools/dosunit/tests/test_dosunit_kvikdos_worker.py",
    "tools/dosunit/tests/test_dosunit_kvikdos_memory_range.py",
    "tools/dosunit/tests/test_dosunit_kvikdos_protocol_errors.py",
    "tools/dosunit/tests/test_dosunit_kvikdos_snapshot_registry.py",
)
NAMED_LISTS = {
    "SCOPED_IR_OWNERS": SCOPED_IR_OWNERS,
    "SCOPED_IR_CONTRACT_TESTS": SCOPED_IR_CONTRACT_TESTS,
    "SCOPED_IR_NATIVE_TESTS": SCOPED_IR_NATIVE_TESTS,
    "KVIKDOS_WORKER_TESTS": KVIKDOS_WORKER_TESTS,
}


def _makefile_text() -> str:
    return (REPO_ROOT / "Makefile").read_text(encoding="utf-8")


def _words(variable: str, text: str | None = None) -> tuple[str, ...]:
    """Read a variable with repo-local includes enabled for the real Makefile."""
    return staged.makefile_variable_words(
        _makefile_text() if text is None else text,
        variable,
        base_dir=REPO_ROOT,
    )


def test_real_makefile_named_lists_expand_to_literal_sublists() -> None:
    """Real Makefile named lists expand to their literal members."""
    for name, expected in NAMED_LISTS.items():
        assert _words(name) == expected
        for member in expected:
            assert (REPO_ROOT / member).exists(), member


def test_real_makefile_qa_lists_have_no_unresolved_tokens() -> None:
    """Expanded QA inventories contain no residual $( tokens."""
    for variable in ("QA_TYPED_FILES", "QA_RUFF_TARGETS", "QA_PYTEST_TARGETS"):
        words = _words(variable)
        assert words, variable
        assert not any("$" in word for word in words), (variable, [w for w in words if "$" in w])


def test_real_makefile_qa_lists_contain_expanded_members() -> None:
    """QA inventories contain the expanded member files that exist."""
    typed = _words("QA_TYPED_FILES")
    ruff = _words("QA_RUFF_TARGETS")
    pytest_targets = _words("QA_PYTEST_TARGETS")
    for member in SCOPED_IR_OWNERS:
        assert member in typed, member
        assert member in ruff, member
    for member in SCOPED_IR_CONTRACT_TESTS + SCOPED_IR_NATIVE_TESTS:
        assert member in ruff, member
    assert "tools/dosunit/tests/test_x86_16_scoped_native_inputs.py" in ruff
    for member in SCOPED_IR_CONTRACT_TESTS + KVIKDOS_WORKER_TESTS:
        assert member in pytest_targets, member
    for member in SCOPED_IR_OWNERS + SCOPED_IR_CONTRACT_TESTS + KVIKDOS_WORKER_TESTS:
        assert (REPO_ROOT / member).exists(), member


def test_real_makefile_included_file_contributes_to_qa_lists() -> None:
    """include tools/compiler_toolchain/coverage.mk appends reach the QA inventories.

    The pre-repair reader silently ignored the directive; these members are
    only assigned inside the included file, so their presence proves the
    include was applied.
    """
    fragment = (REPO_ROOT / "tools/compiler_toolchain/coverage.mk").read_text(encoding="utf-8")
    typed = _words("QA_TYPED_FILES")
    ruff = _words("QA_RUFF_TARGETS")
    pytest_targets = _words("QA_PYTEST_TARGETS")
    assert "tools/compiler_toolchain/msc6_memory_model.py" in _words("COMPILER_COVERAGE_TYPED_OWNERS")
    assert "tools/compiler_toolchain/msc6_memory_model.py" in typed
    assert "tools/compiler_toolchain/msc6_memory_model.py" in ruff
    assert "tools/compiler_toolchain/tests/test_msc6_memory_model.py" in pytest_targets
    assert "tools/signatures/tests/test_binary_signature_metadata.py" in pytest_targets
    for member in ("tools/compiler_toolchain/msc6_memory_model.py", "tools/compiler_toolchain/tests/test_msc6_memory_model.py"):
        assert member in fragment
        assert (REPO_ROOT / member).exists(), member


def test_real_makefile_inventory_diagnostics_are_empty() -> None:
    """The real Makefile resolves cleanly with repo-local include support."""
    diagnostics = staged.makefile_inventory_diagnostics(
        _makefile_text(), base_dir=REPO_ROOT
    )
    assert diagnostics == (), [f"{d.kind.value} {d.location}: {d.detail}" for d in diagnostics]


def test_production_expands_owned_inventory_references() -> None:
    """QA readers resolve owned groups instead of validating reference tokens as paths."""
    assert "$(SCOPED_IR_OWNERS)" not in _words("QA_TYPED_FILES")


MAKE_ORACLE_CASES = [
    (source, variable, expected)
    for (source, expected), variable in [
        (("B = $(A)\nA = late.py\n", ("late.py",)), "B"),
        (("A = one.py\nB := $(A)\nA = two.py\n", ("one.py",)), "B"),
        (("A = one.py\nB = $(A)\nA = two.py\n", ("two.py",)), "B"),
        (("W = first.py\nV := a.py\nV += $(W)\nW = second.py\n", ("a.py", "first.py")), "V"),
        (("W = first.py\nV = a.py\nV += $(W)\nW = second.py\n", ("a.py", "second.py")), "V"),
        (("V += $(W)\nW = late.py\n", ("late.py",)), "V"),
        (("V ?= $(W)\nW = late.py\n", ("late.py",)), "V"),
        (("A = x.py\nB = ${A} y.py\n", ("x.py", "y.py")), "B"),
        (("A := a.py\nB := $(A) b.py\nC = $(B) c.py\nD += $(C)\n", ("a.py", "b.py", "c.py")), "D"),
        (("A = price$$x.py\nB = $(A)\n", ("price$x.py",)), "B"),
    ]
]




# ---------------------------------------------------------------------------
# Literal repo-local includes
# ---------------------------------------------------------------------------


def test_include_inserts_file_text_in_place(tmp_path: Path) -> None:
    """A literal include contributes its assignments at the directive point."""
    (tmp_path / "frag.mk").write_text("X += after.py\nX2 = fragvar.py\n", encoding="utf-8")
    source = "X = before.py\ninclude frag.mk\nX += tail.py\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "before.py",
        "after.py",
        "tail.py",
    )
    assert staged.makefile_variable_words(source, "X2", base_dir=tmp_path) == ("fragvar.py",)


def test_include_resolves_against_base_dir_not_fragment_dir(tmp_path: Path) -> None:
    """Relative names resolve against base_dir, matching GNU Make CWD rules."""
    sub = tmp_path / "sub"
    sub.mkdir()
    (tmp_path / "inner.mk").write_text("X += inner.py\n", encoding="utf-8")
    (sub / "outer.mk").write_text("include inner.mk\nX += outer.py\n", encoding="utf-8")
    source = "X = top.py\ninclude sub/outer.mk\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "top.py",
        "inner.py",
        "outer.py",
    )


def test_reinclude_reapplies_assignments(tmp_path: Path) -> None:
    """GNU Make does not dedupe includes; re-inclusion re-applies appends."""
    (tmp_path / "frag.mk").write_text("X += frag.py\n", encoding="utf-8")
    source = "X = top.py\ninclude frag.mk frag.mk\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "top.py",
        "frag.py",
        "frag.py",
    )


def test_multiple_names_in_one_include(tmp_path: Path) -> None:
    """`include a.mk b.mk` processes each literal name in order."""
    (tmp_path / "a.mk").write_text("X = a.py\n", encoding="utf-8")
    (tmp_path / "b.mk").write_text("X += b.py\n", encoding="utf-8")
    source = "include a.mk b.mk\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == ("a.py", "b.py")


def test_include_cycle_fails_closed(tmp_path: Path) -> None:
    """Cyclic includes are refused with a diagnostic instead of looping."""
    (tmp_path / "a.mk").write_text("include b.mk\nX += a.py\n", encoding="utf-8")
    (tmp_path / "b.mk").write_text("include a.mk\nX += b.py\n", encoding="utf-8")
    source = "X = top.py\ninclude a.mk\n"
    words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
    assert words[-1] == "$(X)"
    kinds = {
        d.kind
        for d in staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
    }
    assert staged.MakefileInventoryDiagKind.INCLUDE_CYCLE in kinds


def test_include_missing_required_fails_closed(tmp_path: Path) -> None:
    """A missing required include taints every variable, including new ones."""
    source = "X = before.py\ninclude missing.mk\nY = later.py\n"
    words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
    assert words == ("before.py", "$(X)")
    # A variable assigned after the gap is NOT proven: the missing file
    # could have installed `override Y = ...`, which GNU Make honors over
    # the later non-override write.
    assert staged.makefile_variable_words(source, "Y", base_dir=tmp_path) == (
        "later.py",
        "$(Y)",
    )
    # A variable that may only exist inside the missing file stays explicit.
    assert staged.makefile_variable_words(source, "Z", base_dir=tmp_path) == ("$(Z)",)
    kinds = {
        d.kind
        for d in staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
    }
    assert staged.MakefileInventoryDiagKind.INCLUDE_MISSING in kinds


def test_optional_include_missing_is_proven_noop(tmp_path: Path) -> None:
    """`-include`/`sinclude` of an absent file is a real no-op, not a gap."""
    for directive in ("-include", "sinclude"):
        source = f"X = a.py\n{directive} missing.mk\nX += b.py\n"
        words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
        assert words == ("a.py", "b.py"), directive
        diagnostics = staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
        kinds = {d.kind for d in diagnostics}
        assert kinds == {staged.MakefileInventoryDiagKind.INCLUDE_SKIPPED_OPTIONAL}


def test_include_without_base_dir_fails_closed() -> None:
    """Text-only callers cannot resolve includes: loud gap, never silent."""
    source = "X = a.py\ninclude frag.mk\n"
    words = staged.makefile_variable_words(source, "X")
    assert words == ("a.py", "$(X)")
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.INCLUDE_NO_BASE_DIR in kinds


def test_include_outside_root_fails_closed(tmp_path: Path) -> None:
    """Includes escaping include_root are refused even when the file exists."""
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "escape.mk").write_text("X += escaped.py\n", encoding="utf-8")
    source = "X = a.py\ninclude ../escape.mk\n"
    words = staged.makefile_variable_words(
        source, "X", base_dir=root, include_root=root
    )
    assert words == ("a.py", "$(X)")
    kinds = {
        d.kind
        for d in staged.makefile_inventory_diagnostics(
            source, base_dir=root, include_root=root
        )
    }
    assert staged.MakefileInventoryDiagKind.INCLUDE_OUTSIDE_ROOT in kinds


def test_include_nonliteral_name_fails_closed(tmp_path: Path) -> None:
    """Computed or wildcard include names cannot be resolved statically."""
    for source in (
        "D = sub\nX = a.py\ninclude $(D)/frag.mk\n",
        "X = a.py\ninclude *.mk\n",
    ):
        words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
        assert words == ("a.py", "$(X)"), source
        kinds = {
            d.kind
            for d in staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
        }
        assert staged.MakefileInventoryDiagKind.INCLUDE_NONLITERAL_NAME in kinds


def test_conditional_include_fails_closed(tmp_path: Path) -> None:
    """An include inside an unevaluated conditional cannot be applied."""
    (tmp_path / "frag.mk").write_text("X += frag.py\n", encoding="utf-8")
    source = "X = a.py\nifdef FLAG\ninclude frag.mk\nendif\n"
    words = staged.makefile_variable_words(source, "X", base_dir=tmp_path)
    assert words == ("a.py", "$(X)")
    kinds = {
        d.kind
        for d in staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
    }
    assert staged.MakefileInventoryDiagKind.CONDITIONAL_INCLUDE in kinds


def test_undefine_inside_included_file_applies(tmp_path: Path) -> None:
    """Directives inside resolved includes affect the shared environment."""
    (tmp_path / "frag.mk").write_text("undefine X\nX ?= reset.py\n", encoding="utf-8")
    source = "X = keep.py\ninclude frag.mk\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == ("reset.py",)


def test_words_from_file_api(tmp_path: Path) -> None:
    """The file entry point resolves includes next to the Makefile itself."""
    (tmp_path / "frag.mk").write_text("X += frag.py\n", encoding="utf-8")
    makefile = tmp_path / "Makefile"
    makefile.write_text("X = top.py\ninclude frag.mk\n", encoding="utf-8")
    assert staged.makefile_variable_words_from_file(makefile, "X") == (
        "top.py",
        "frag.py",
    )


# ---------------------------------------------------------------------------
# override semantics
# ---------------------------------------------------------------------------


OVERRIDE_CASES = [
    # once marked, later non-override file assignments are ignored
    ("X = first.py\noverride X = second.py\nX = third.py\n", "X", ("second.py",)),
    ("X = first.py\noverride X = second.py\nX += third.py\n", "X", ("second.py",)),
    ("X = first.py\noverride X = second.py\nX ?= third.py\n", "X", ("second.py",)),
    # an override append applies and also marks the variable
    ("X = a.py\noverride X += b.py\nX += c.py\n", "X", ("a.py", "b.py")),
    # override ?= applies only while undefined, then freezes
    ("override X ?= a.py\nX += b.py\n", "X", ("a.py",)),
    # a second override assignment still applies
    ("X = a.py\noverride X = b.py\noverride X = c.py\nX = d.py\n", "X", ("c.py",)),
    # override on := freezes with immediate binding
    ("W = one.py\noverride X := $(W)\nW = two.py\nX += z.py\n", "X", ("one.py",)),
    # export prefix coexists with override
    ("X = a.py\nexport override X = b.py\nX = c.py\n", "X", ("b.py",)),
]


@pytest.mark.parametrize("source,variable,expected", OVERRIDE_CASES)
def test_override_freezes_against_file_assignments(
    source: str, variable: str, expected: tuple[str, ...]
) -> None:
    """GNU Make override precedence: non-override file writes are ignored."""
    assert staged.makefile_variable_words(source, variable) == expected


def test_bare_override_is_malformed_diagnostic() -> None:
    """Bare `override NAME` is invalid Make syntax -> fail-closed gap."""
    source = "X = a.py\noverride X\n"
    words = staged.makefile_variable_words(source, "X")
    assert words == ("a.py", "$(X)")
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.MALFORMED_DIRECTIVE in kinds


# ---------------------------------------------------------------------------
# undefine semantics
# ---------------------------------------------------------------------------


UNDEFINE_CASES = [
    # removal makes a later ?= default apply
    ("X = before.py\nundefine X\nX ?= after.py\n", "X", ("after.py",)),
    # removal makes a later += behave like = on an undefined variable
    ("X = before.py\nundefine X\nX += after.py\n", "X", ("after.py",)),
    # a never-redefined variable is simply gone
    ("X = before.py\nundefine X\n", "X", ()),
    ("X = before.py\nundefine X\n", "Y", ()),
    # plain undefine is ignored for override-origin variables
    ("override X = a.py\nundefine X\nX ?= b.py\n", "X", ("a.py",)),
    ("override X = a.py\nundefine X\nX += b.py\n", "X", ("a.py",)),
    # override undefine removes the variable and its override flag
    ("override X = a.py\noverride undefine X\nX ?= b.py\n", "X", ("b.py",)),
    ("X = a.py\noverride undefine X\nX ?= b.py\n", "X", ("b.py",)),
    ("override X = a.py\noverride undefine X\n", "X", ()),
    # undefine of a never-defined variable is a no-op
    ("X = a.py\nundefine Y\n", "X", ("a.py",)),
    # undefine wins even for variables defined through named references
    ("A = a.py\nX = $(A)\nundefine X\nX = $(A)\n", "X", ("a.py",)),
]


@pytest.mark.parametrize("source,variable,expected", UNDEFINE_CASES)
def test_undefine_respects_override_precedence(
    source: str, variable: str, expected: tuple[str, ...]
) -> None:
    """GNU Make undefine honors override origin precedence."""
    assert staged.makefile_variable_words(source, variable) == expected


def test_conditional_undefine_marks_variable_unproven() -> None:
    """A guarded undefine cannot be proven, so the value stays flagged."""
    source = "X = a.py\nifdef FLAG\nundefine X\nendif\n"
    assert staged.makefile_variable_words(source, "X") == ("a.py", "$(X)")


def test_nonliteral_undefine_fails_closed() -> None:
    """`undefine $(X)` removes an unknown name -> fail-closed gap."""
    source = "X = a.py\nundefine $(X)\n"
    words = staged.makefile_variable_words(source, "X")
    assert words == ("a.py", "$(X)")
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.UNDEFINE_NONLITERAL in kinds


def test_reassignment_after_gap_stays_flagged(tmp_path: Path) -> None:
    """A non-override `=` after an unapplied include cannot re-prove the value."""
    source = "X = old.py\ninclude missing.mk\nX = new.py\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "new.py",
        "$(X)",
    )


def test_override_assignment_reproves_after_gap(tmp_path: Path) -> None:
    """`override X =`/`override X :=` rewrite outright, erasing skipped effects."""
    source = (
        "X = old.py\ninclude missing.mk\n"
        "override X = new.py\nX += tail.py\noverride X += more.py\n"
    )
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "new.py",
        "more.py",
    )


def test_undefine_after_gap_stays_unproven(tmp_path: Path) -> None:
    """Skipped text may hold `override X`: plain undefine cannot prove removal."""
    source = "X = old.py\ninclude missing.mk\nundefine X\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "old.py",
        "$(X)",
    )
    # override undefine removes whatever the skipped text installed; the
    # later ?= then applies but the variable still carries gap evidence.
    source = "X = old.py\ninclude missing.mk\noverride undefine X\nX ?= v.py\n"
    assert staged.makefile_variable_words(source, "X", base_dir=tmp_path) == (
        "v.py",
        "$(X)",
    )


def test_conditional_state_blocks_plain_undefine() -> None:
    """A guarded `override X` may be live: plain undefine must not remove it."""
    source = "ifdef F\noverride X = a.py\nendif\nundefine X\n"
    assert staged.makefile_variable_words(source, "X") == ("$(X)",)


def test_bare_undefine_fails_closed() -> None:
    """Bare `undefine` has no provable name -> fail-closed gap."""
    source = "X = a.py\nundefine\n"
    words = staged.makefile_variable_words(source, "X")
    assert words == ("a.py", "$(X)")
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.UNDEFINE_NONLITERAL in kinds


# ---------------------------------------------------------------------------
# Expansion budget and deep chains
# ---------------------------------------------------------------------------


def test_deep_named_chain_still_resolves() -> None:
    """Regression: long reference chains resolve iteratively (parent probe)."""
    lines = ["A0 = x.py"]
    lines += [f"A{i} = $(A{i - 1})" for i in range(1, 699)]
    source = "\n".join(lines) + "\nX = $(A698)\n"
    assert staged.makefile_variable_words(source, "X") == ("x.py",)


def test_exponential_expansion_is_bounded() -> None:
    """A doubling chain hits the explicit budget instead of exploding."""
    lines = ["A0 = x.py"]
    lines += [f"A{i} = $(A{i - 1}) $(A{i - 1})" for i in range(1, 40)]
    # := expands at scan time so the diagnostic surface observes the budget.
    source = "\n".join(lines) + "\nX := $(A39)\n"
    words = staged.makefile_variable_words(source, "X")
    assert len(words) <= 2**24  # bounded, not the 2**39 make would produce
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.EXPANSION_BUDGET in kinds


def test_real_makefile_within_budget() -> None:
    """The valid existing inventory fits inside the modest budget."""
    diagnostics = staged.makefile_inventory_diagnostics(
        _makefile_text(), base_dir=REPO_ROOT
    )
    assert staged.MakefileInventoryDiagKind.EXPANSION_BUDGET not in {
        d.kind for d in diagnostics
    }


def test_scan_time_budget_does_not_taint_later_assignments() -> None:
    """Budget exhaustion is resource evidence, not skipped text.

    A ``:=`` expansion that exhausts the budget must not mark unrelated
    later assignments partial: nothing was skipped, so their values are
    still provable.
    """
    lines = ["A0 = x.py"]
    lines += [f"A{i} := $(A{i - 1}) $(A{i - 1})" for i in range(1, 26)]
    source = "\n".join(lines) + "\nW = w.py\n"
    assert staged.makefile_variable_words(source, "W") == ("w.py",)
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.EXPANSION_BUDGET in kinds


# ---------------------------------------------------------------------------
# Unsupported-statement diagnostics
# ---------------------------------------------------------------------------


def test_dollar_statement_line_fails_closed() -> None:
    """Top-level $(eval)/$(error) statements could alter or abort parsing."""
    source = "X = a.py\n$(eval HACKED := 1)\n"
    words = staged.makefile_variable_words(source, "X")
    assert words == ("a.py", "$(X)")
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.UNSUPPORTED_STATEMENT in kinds


def test_unterminated_conditional_fails_closed() -> None:
    """A missing endif is a GNU Make error -> diagnostic plus gap."""
    source = "X = a.py\nifdef FLAG\nX += b.py\n"
    words = staged.makefile_variable_words(source, "X")
    assert words[-1] == "$(X)"
    kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
    assert staged.MakefileInventoryDiagKind.UNTERMINATED_BLOCK in kinds


def test_diagnostics_are_typed_and_located(tmp_path: Path) -> None:
    """Diagnostics carry enum kinds and origin:line locations."""
    source = "X = a.py\ninclude missing.mk\n"
    diagnostics = staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
    assert len(diagnostics) == 1
    diagnostic = diagnostics[0]
    assert diagnostic.kind is staged.MakefileInventoryDiagKind.INCLUDE_MISSING
    assert diagnostic.location == "Makefile:2"
    assert "missing.mk" in diagnostic.detail


def test_diagnostic_location_names_included_file(tmp_path: Path) -> None:
    """Diagnostics from included files carry their repo-relative origin."""
    (tmp_path / "frag.mk").write_text("undefine $(X)\n", encoding="utf-8")
    source = "X = a.py\ninclude frag.mk\n"
    diagnostics = staged.makefile_inventory_diagnostics(source, base_dir=tmp_path)
    assert any(
        d.location == "frag.mk:1" and d.kind is staged.MakefileInventoryDiagKind.UNDEFINE_NONLITERAL
        for d in diagnostics
    )


# ---------------------------------------------------------------------------
# GNU Make oracle parity for the new constructs
# ---------------------------------------------------------------------------










# ---------------------------------------------------------------------------
# Conditional override uncertainty
# ---------------------------------------------------------------------------


CONDITIONAL_OVERRIDE_CASES = [
    # parent probe: the guarded override may be live, so the later plain
    # assignment cannot re-prove the value (GNU yields "hidden")
    ("X=first\nifeq (a,a)\noverride X=hidden\nendif\nX=second\n", "X", ("second", "$(X)")),
    # same static result when the guard would not fire (GNU yields "second")
    ("X=first\nifeq (a,b)\noverride X=hidden\nendif\nX=second\n", "X", ("second", "$(X)")),
    ("X=first\nifdef F\noverride X=hidden\nendif\nX=second\n", "X", ("second", "$(X)")),
    # a plain undefine cannot prove removal either (GNU keeps "hidden")
    ("X=first\nifeq (a,a)\noverride X=hidden\nendif\nundefine X\n", "X", ("first", "$(X)")),
    # conditional override += and override ?= mark the same uncertainty
    ("X=first\nifdef F\noverride X+=hidden\nendif\nX=second\n", "X", ("second", "$(X)")),
    ("X=first\nifdef F\noverride X?=hidden\nendif\nX=second\n", "X", ("second", "$(X)")),
    # conditional override define marks the variable unresolved too
    (
        "X=first\nifdef F\noverride define X\nhidden\nendef\nendif\nX=second\n",
        "X",
        ("second", "$(X)"),
    ),
    # an unconditional explicit override replacement re-proves outright
    ("X=first\nifeq (a,a)\noverride X=hidden\nendif\noverride X=final\nX=second\n", "X", ("final",)),
    ("X=first\nifdef F\noverride X=hidden\nendif\noverride X := final\n", "X", ("final",)),
]


@pytest.mark.parametrize("source,variable,expected", CONDITIONAL_OVERRIDE_CASES)
def test_conditional_override_stays_unresolved(
    source: str, variable: str, expected: tuple[str, ...]
) -> None:
    """A guarded override outranks later plain writes/undefine -> flagged."""
    assert staged.makefile_variable_words(source, variable) == expected






# ---------------------------------------------------------------------------
# else-if depth and define override precedence
# ---------------------------------------------------------------------------


def test_else_ifeq_shares_conditional_depth() -> None:
    """`else ifeq` does not nest deeper; one endif closes the chain."""
    source = "X=base\nifdef F\nX=a\nelse ifeq (b,b)\nX=b\nendif\nX=plain\n"
    assert staged.makefile_variable_words(source, "X") == ("plain",)
    diagnostics = staged.makefile_inventory_diagnostics(source)
    assert not any(
        d.kind is staged.MakefileInventoryDiagKind.UNTERMINATED_BLOCK
        for d in diagnostics
    )


def test_stray_else_and_endif_fail_closed() -> None:
    """else/endif without an open conditional is a GNU Make error -> gap."""
    for source in ("X=a\nelse\nX=b\n", "X=a\nelse ifeq (a,a)\nX=b\n", "X=a\nendif\nX=b\n"):
        words = staged.makefile_variable_words(source, "X")
        assert words[-1] == "$(X)", source
        kinds = {d.kind for d in staged.makefile_inventory_diagnostics(source)}
        assert staged.MakefileInventoryDiagKind.MALFORMED_DIRECTIVE in kinds


DEFINE_OVERRIDE_CASES = [
    # a non-override define is ignored on an override-origin variable
    ("override X=orig\ndefine X\nnewbody\nendef\nX=later\n", "X", ("orig",)),
    # override define applies and freezes the variable
    ("X=a\noverride define X\nbody\nendef\nX=later\n", "X", ("$(X)",)),
    # override define on an override variable still applies
    ("override X=orig\noverride define X\nbody\nendef\nX=later\n", "X", ("$(X)",)),
    # a plain define cannot clobber a possible conditional override
    ("X=first\nifdef F\noverride X=hidden\nendif\ndefine X\nbody\nendef\n", "X", ("first", "$(X)")),
    # override define discharges conditional-override uncertainty
    ("X=first\nifdef F\noverride X=hidden\nendif\noverride define X\nb\nendef\n", "X", ("$(X)",)),
]


@pytest.mark.parametrize("source,variable,expected", DEFINE_OVERRIDE_CASES)
def test_define_respects_override_precedence(
    source: str, variable: str, expected: tuple[str, ...]
) -> None:
    """define honors GNU override precedence instead of overwriting."""
    assert staged.makefile_variable_words(source, variable) == expected




@pytest.mark.parametrize("assignment", [
    "private X=hidden", "unexport X=hidden", "override private X=hidden",
    "private override X=hidden", "export private X:=hidden", "override unexport X=hidden",
    "private export override X+=hidden", "X$(EMPTY)=hidden", "X${EMPTY}=hidden",
    "${NAME}=hidden", "override ${NAME}=hidden", "export X$E=hidden",
])
def test_unknown_global_assignment_reports_gap_that_plain_write_cannot_erase(assignment: str) -> None:
    """Unsupported global names/prefixes may install override origin."""
    source = f"NAME=X\nEMPTY=\nE=\nX=first\n{assignment}\nX=later\n"
    assert staged.makefile_variable_words(source, "X")[-1] == "$(X)"
    diagnostics = staged.makefile_inventory_diagnostics(source)
    assert len(diagnostics) == 1
    assert diagnostics[0].kind is staged.MakefileInventoryDiagKind.UNSUPPORTED_GLOBAL_ASSIGNMENT


@pytest.mark.parametrize("source", [
    "X=first\ntarget: private X=local\n", "X=first\ntarget: unexport X=local\n",
    "X=first\ntarget: X$(EMPTY)=local\n", "X=first\ntarget:; echo private X=local\n",
    "X=first\ntarget:\n\tprivate X=recipe\n", "X=first\ntarget:\n\tX$(EMPTY)=recipe\n",
])
def test_unknown_assignment_detection_does_not_taint_literal_rules_or_recipes(source: str) -> None:
    """Out-of-scope target-local/recipe text cannot masquerade as global writes."""
    assert staged.makefile_variable_words(source, "X") == ("first",)
    assert staged.makefile_inventory_diagnostics(source) == ()
