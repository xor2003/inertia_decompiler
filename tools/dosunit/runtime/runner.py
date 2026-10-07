from __future__ import annotations  # noqa: D100

from contextlib import nullcontext
from pathlib import Path
from typing import Any

from tools.dosunit.catalog.mapping import MappingResolutionError, apply_candidate_mapping
from tools.dosunit.contracts.model import compare_observations, normalize_vector, stable_id, vectors_from_document
from tools.dosunit.runtime.kvikdos_backend import KvikdosBackendError, KvikdosSession, execute_vector


def _observed_from_fixture(vector: dict[str, Any], key: str) -> dict[str, Any] | None:
    fixture = vector.get("backend_fixture")
    if not isinstance(fixture, dict):
        return None
    observed = fixture.get(key)
    if not isinstance(observed, dict):
        return None
    return observed


def _backend_failure_result(vector: dict[str, Any], *, message: str) -> dict[str, Any]:
    return {
        "schema": "dosunit.result.v1",
        "vector_id": vector["id"],
        "module": vector.get("module"),
        "function": vector.get("function", {}).get("name"),
        "status": "refused",
        "verdict": {"kind": "backend_failure", "changed_fields": []},
        "diagnostics": [{"reason": "backend_error", "message": message}],
    }


def _mapping_failure_result(vector: dict[str, Any], *, reason: str, message: str) -> dict[str, Any]:
    return {
        "schema": "dosunit.result.v1",
        "vector_id": vector["id"],
        "module": vector.get("module"),
        "function": vector.get("function", {}).get("name"),
        "status": "refused",
        "verdict": {"kind": "mapping_unavailable", "changed_fields": []},
        "diagnostics": [{"reason": reason, "message": message}],
    }


def record_oracle(  # noqa: D103
    vectors_document: dict[str, Any],
    *,
    backend: str = "fixture",
    exe_path: Path | None = None,
    functions_catalog: dict[str, Any] | None = None,
    kvikdos_path: Path | None = None,
) -> dict[str, Any]:
    vectors: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    session_context = KvikdosSession(kvikdos_path=kvikdos_path) if backend == "libkvikdos" else nullcontext(None)
    with session_context as session:
        for raw_vector in vectors_from_document(vectors_document):
            vector = normalize_vector(raw_vector)
            observed: dict[str, Any] | None = None
            if backend == "fixture":
                observed = _observed_from_fixture(vector, "oracle")
            elif backend in {"libkvikdos", "kvikdos"}:
                if exe_path is None:
                    results.append(
                        _backend_failure_result(vector, message="--exe is required for kvikdos-backed oracle recording")
                    )
                    vectors.append(vector)
                    continue
                try:
                    observed = execute_vector(
                        vector,
                        exe_path=exe_path,
                        functions_catalog=functions_catalog,
                        backend=backend,
                        kvikdos_path=kvikdos_path,
                        session=session,
                    )
                except KvikdosBackendError as ex:
                    results.append(_backend_failure_result(vector, message=str(ex)))
                    vectors.append(vector)
                    continue
            if observed is None:
                result = {
                    "schema": "dosunit.result.v1",
                    "vector_id": vector["id"],
                    "module": vector.get("module"),
                    "function": vector.get("function", {}).get("name"),
                    "status": "refused",
                    "verdict": {"kind": "backend_failure", "changed_fields": []},
                    "diagnostics": [
                        {
                            "reason": "backend_error",
                            "message": "libkvikdos backend is not available; use --backend fixture for fixture vectors",
                        }
                    ],
                }
                results.append(result)
                vectors.append(vector)
                continue
            vector["expected"] = observed
            vectors.append(vector)
            results.append(
                {
                    "schema": "dosunit.result.v1",
                    "vector_id": vector["id"],
                    "module": vector.get("module"),
                    "function": vector.get("function", {}).get("name"),
                    "status": "passed",
                    "verdict": {"kind": "equivalent", "changed_fields": []},
                    "oracle": observed,
                    "candidate": None,
                    "diagnostics": [],
                }
            )
    document_without_id = {
        "schema": "dosunit.oracle_recording.v1",
        "backend": backend,
        "vectors": vectors,
        "results": results,
    }
    document = dict(document_without_id)
    document["id"] = stable_id("oracle-recording", document_without_id)
    return document


def compare_vectors(  # noqa: D103
    vectors_document: dict[str, Any],
    *,
    backend: str = "fixture",
    candidate_path: Path | None = None,
    functions_catalog: dict[str, Any] | None = None,
    mapping_document: dict[str, Any] | None = None,
    kvikdos_path: Path | None = None,
    ignore_fields: set[str] | None = None,
) -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    session_context = KvikdosSession(kvikdos_path=kvikdos_path) if backend == "libkvikdos" else nullcontext(None)
    with session_context as session:
        for raw_vector in vectors_from_document(vectors_document):
            vector = normalize_vector(raw_vector)
            expected = vector.get("expected")
            if not isinstance(expected, dict):
                results.append(
                    {
                        "schema": "dosunit.result.v1",
                        "vector_id": vector["id"],
                        "module": vector.get("module"),
                        "function": vector.get("function", {}).get("name"),
                        "status": "refused",
                        "verdict": {"kind": "oracle_unavailable", "changed_fields": []},
                        "diagnostics": [{"reason": "oracle_unavailable", "message": "vector has no expected output"}],
                    }
                )
                continue

            candidate: dict[str, Any] | None = None
            if backend == "fixture":
                candidate = _observed_from_fixture(vector, "candidate")
            elif backend in {"libkvikdos", "kvikdos"}:
                if candidate_path is None:
                    results.append(
                        _backend_failure_result(vector, message="--candidate is required for kvikdos-backed comparison")
                    )
                    continue
                try:
                    candidate_vector = apply_candidate_mapping(
                        vector,
                        mapping_document=mapping_document,
                        functions_catalog=functions_catalog,
                    )
                except MappingResolutionError as ex:
                    results.append(_mapping_failure_result(vector, reason=ex.reason, message=ex.message))
                    continue
                try:
                    candidate = execute_vector(
                        candidate_vector,
                        exe_path=candidate_path,
                        functions_catalog=functions_catalog,
                        backend=backend,
                        kvikdos_path=kvikdos_path,
                        session=session,
                    )
                except KvikdosBackendError as ex:
                    results.append(_backend_failure_result(vector, message=str(ex)))
                    continue
            if candidate is None:
                results.append(
                    {
                        "schema": "dosunit.result.v1",
                        "vector_id": vector["id"],
                        "module": vector.get("module"),
                        "function": vector.get("function", {}).get("name"),
                        "status": "refused",
                        "verdict": {"kind": "candidate_unavailable", "changed_fields": []},
                        "diagnostics": [
                            {
                                "reason": "backend_error",
                                "message": "candidate execution backend is not available",
                            }
                        ],
                    }
                )
                continue

            equivalent, changed_fields = compare_observations(expected, candidate, ignore_fields=ignore_fields)
            results.append(
                {
                    "schema": "dosunit.result.v1",
                    "vector_id": vector["id"],
                    "module": vector.get("module"),
                    "function": vector.get("function", {}).get("name"),
                    "status": "passed" if equivalent else "failed",
                    "verdict": {
                        "kind": "equivalent" if equivalent else "observable_mismatch",
                        "changed_fields": changed_fields,
                    },
                    "oracle": expected,
                    "candidate": candidate,
                    "diagnostics": [],
                }
            )
    document_without_id = {
        "schema": "dosunit.results.v1",
        "backend": backend,
        "ignore_fields": sorted(ignore_fields or set()),
        "results": results,
        "summary": summarize_results(results),
    }
    document = dict(document_without_id)
    document["id"] = stable_id("results", document_without_id)
    return document


def summarize_results(results: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: D103
    counts: dict[str, int] = {}
    changed_fields: dict[str, int] = {}
    refusals: dict[str, int] = {}
    for result in results:
        status = str(result.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
        verdict = result.get("verdict", {})
        if isinstance(verdict, dict):
            for field in verdict.get("changed_fields", []) or []:
                changed_fields[str(field)] = changed_fields.get(str(field), 0) + 1
        for diagnostic in result.get("diagnostics", []) or []:
            if isinstance(diagnostic, dict) and "reason" in diagnostic:
                reason = str(diagnostic["reason"])
                refusals[reason] = refusals.get(reason, 0) + 1
    return {
        "total": len(results),
        "status_counts": dict(sorted(counts.items())),
        "changed_fields": dict(sorted(changed_fields.items())),
        "refusal_reasons": dict(sorted(refusals.items())),
    }
