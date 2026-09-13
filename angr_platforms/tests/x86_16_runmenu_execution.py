"""Mutation controls for the shared generated-C RunMenu execution oracle."""

from pathlib import Path

import pytest

from scripts.runmenu_behavior import assert_runmenu_behavior as assert_runmenu_behavior


def assert_runmenu_oracle_rejects_corruption(generated_c: str, tmp_path: Path) -> None:
    """Prove the execution oracle rejects call loss, lost ESC and wrong arguments."""
    mutations = (
        ("sub_10678();", ";"),
        ("break;", ";"),
        ("sub_10ce0(0,", "sub_10ce0(1,"),
    )
    for original, corrupted in mutations:
        assert original in generated_c, f"Refresh the deliberate mutation: {original}"
        with pytest.raises(AssertionError, match="RunMenu execution failed: exit=20;"):
            assert_runmenu_behavior(generated_c.replace(original, corrupted), tmp_path)
