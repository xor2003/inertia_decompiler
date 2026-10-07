"""Validate component declarations and maintain the legacy exported view.

Layer: Tooling/gates.
Responsibility: reject stale path exports and malformed ownership declarations.
"""

from __future__ import annotations

import argparse
import json

from .component_catalog import (
    ROOT,
    derive_test_catalog,
    load_components,
    make_quality_projection,
    validate_component_paths,
)


def main(argv: list[str] | None = None) -> int:
    """Check declarations, optionally regenerating the legacy JSON catalog."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate reference/test-components.json")
    args = parser.parse_args(argv)
    components = load_components()
    missing = validate_component_paths(components)
    if missing:
        print("\n".join(missing))
        return 1
    expected = derive_test_catalog(components)
    exported = ROOT / "reference" / "test-components.json"
    make_path = ROOT / "reference" / "components.mk"
    make_text = make_quality_projection(components)
    if args.write:
        exported.write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
        make_path.write_text(make_text, encoding="utf-8")
    actual = json.loads(exported.read_text(encoding="utf-8"))
    if actual != expected:
        print("Stale reference/test-components.json; run python -m tools.dev.component_catalog_cli --write")
        return 1
    if not make_path.is_file() or make_path.read_text(encoding="utf-8") != make_text:
        print("Stale reference/components.mk; run python -m tools.dev.component_catalog_cli --write")
        return 1
    print(f"Component catalog: {len(components)} owners, {len({path for paths in expected.values() for path in paths})} test modules")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
