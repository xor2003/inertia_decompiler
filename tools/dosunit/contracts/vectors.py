from __future__ import annotations  # noqa: D100

from typing import Any

from tools.dosunit.contracts.model import normalize_vector, stable_id, vectors_from_document


def select_vectors(  # noqa: D103
    vectors_document: dict[str, Any],
    *,
    names: list[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    selected: list[dict[str, Any]] = []
    wanted = set(names or [])
    for raw_vector in vectors_from_document(vectors_document):
        vector = normalize_vector(raw_vector)
        function = vector.get("function", {})
        function_id = function.get("id") if isinstance(function, dict) else None
        function_name = function.get("name") if isinstance(function, dict) else None
        if wanted and function_id not in wanted and function_name not in wanted:
            continue
        selected.append(vector)
        if limit is not None and len(selected) >= limit:
            break
    document_without_id = {
        "schema": "dosunit.vectors.v1",
        "vectors": selected,
        "selection": {
            "names": sorted(wanted),
            "limit": limit,
        },
    }
    document = dict(document_without_id)
    document["id"] = stable_id("vectors", document_without_id)
    return document
