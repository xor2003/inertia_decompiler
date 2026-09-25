"""Persist accepted pytest memory measurements and conservative lower bounds.

Layer: Tooling/gates.
Responsibility: decode, validate, migrate, and retain worker RSS facts without
deriving shard semantics from display names or trusting failed runs to raise
concurrency.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

if __package__:
    from .pytest_partition_execution import WorkerSpec
else:
    from pytest_partition_execution import WorkerSpec

DEFAULT_CONTROLLER_RESERVE_KIB: int = 128 * 1024
DEFAULT_WORKER_HEADROOM_PERCENT: int = 10


@dataclass(frozen=True, slots=True)
class WorkerResourceContract:
    """Stable identity of one exact path and node-shard assignment."""

    paths: tuple[str, ...]
    shard_count: int
    shard_index: int

    @classmethod
    def from_spec(cls, spec: WorkerSpec) -> WorkerResourceContract:
        """Create a resource identity from an owned worker specification."""

        return cls(
            paths=tuple(spec.paths),
            shard_count=spec.shard_count,
            shard_index=spec.shard_index,
        )

    @classmethod
    def from_payload(cls, payload: object) -> WorkerResourceContract | None:
        """Decode a persisted contract, refusing malformed or partial facts."""

        if not isinstance(payload, dict):
            return None
        paths = payload.get("paths")
        shard_count = payload.get("shard_count")
        shard_index = payload.get("shard_index")
        if not isinstance(paths, list) or not paths:
            return None
        if not all(isinstance(path, str) for path in paths):
            return None
        if not isinstance(shard_count, int) or not isinstance(shard_index, int):
            return None
        if shard_count < 1 or shard_index < 0 or shard_index >= shard_count:
            return None
        return cls(tuple(paths), shard_count, shard_index)

    def as_dict(self) -> dict[str, object]:
        """Serialize the contract without encoding semantics in worker names."""

        return {
            "paths": list(self.paths),
            "shard_count": self.shard_count,
            "shard_index": self.shard_index,
        }


@dataclass(frozen=True, slots=True)
class WorkerResourceMeasurement:
    """Accepted peak RSS for one exact worker resource contract."""

    contract: WorkerResourceContract
    peak_rss_kib: int

    @classmethod
    def from_payload(cls, payload: object) -> WorkerResourceMeasurement | None:
        """Decode one accepted measurement from a summary record."""

        if not isinstance(payload, dict):
            return None
        contract = WorkerResourceContract.from_payload(payload.get("contract"))
        peak_rss_kib = payload.get("peak_rss_kib")
        if contract is None or not isinstance(peak_rss_kib, int) or peak_rss_kib <= 0:
            return None
        return cls(contract=contract, peak_rss_kib=peak_rss_kib)

    def as_dict(self) -> dict[str, object]:
        """Serialize one accepted resource measurement."""

        return {
            "contract": self.contract.as_dict(),
            "peak_rss_kib": self.peak_rss_kib,
        }


@dataclass(frozen=True, slots=True)
class WorkerResourceHistory:
    """Source-bound concurrency evidence plus conservative lower bounds."""

    accepted: tuple[WorkerResourceMeasurement, ...] = ()
    observed_lower_bounds: tuple[WorkerResourceMeasurement, ...] = ()
    accepted_source_sha256: str | None = None

    @classmethod
    def load(cls, path: Path | None) -> WorkerResourceHistory:
        """Load accepted memory facts, treating absent or invalid history as empty."""

        if path is None or not path.exists():
            return cls()
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return cls()
        if not isinstance(payload, dict):
            return cls()
        accepted_payload = payload.get("accepted_worker_resources")
        if isinstance(accepted_payload, list):
            return cls._from_accepted_payload(payload, accepted_payload)
        if payload.get("succeeded") is not True or payload.get("memory_exceeded") is True:
            return cls()
        return cls._from_legacy_worker_peaks(payload)

    @classmethod
    def _from_accepted_payload(
        cls,
        payload: dict[object, object],
        accepted_payload: list[object],
    ) -> WorkerResourceHistory:
        """Decode the typed accepted/lower-bound measurement lists."""
        raw_source_sha256 = payload.get("accepted_worker_resource_source_sha256")
        accepted_source_sha256 = (
            raw_source_sha256 if isinstance(raw_source_sha256, str) and raw_source_sha256 else None
        )
        accepted = tuple(
            measurement
            for record in accepted_payload
            if (measurement := WorkerResourceMeasurement.from_payload(record)) is not None
        )
        lower_bound_payload = payload.get("observed_worker_resource_lower_bounds")
        if isinstance(lower_bound_payload, list):
            lower_bounds = tuple(
                measurement
                for record in lower_bound_payload
                if (measurement := WorkerResourceMeasurement.from_payload(record)) is not None
            )
        else:
            lower_bounds = _typed_observed_measurements(payload)
        return cls(
            accepted=tuple(sorted(accepted, key=measurement_sort_key)),
            observed_lower_bounds=_maximum_measurements(lower_bounds),
            accepted_source_sha256=accepted_source_sha256,
        )

    @classmethod
    def _from_legacy_worker_peaks(
        cls,
        payload: dict[object, object],
    ) -> WorkerResourceHistory:
        """Migrate a legacy worker-paths/peak-RSS payload into measurements."""
        worker_paths = payload.get("worker_paths")
        worker_peaks = payload.get("worker_peak_rss_kib")
        if not isinstance(worker_paths, dict) or not isinstance(worker_peaks, dict):
            return cls()
        peaks_by_paths: dict[tuple[str, ...], list[int]] = {}
        for name, raw_paths in worker_paths.items():
            peak_rss_kib = worker_peaks.get(name)
            if not (
                isinstance(name, str)
                and isinstance(raw_paths, list)
                and raw_paths
            ):
                continue
            if not (
                all(isinstance(item, str) for item in raw_paths)
                and isinstance(peak_rss_kib, int)
                and peak_rss_kib > 0
            ):
                continue
            paths = tuple(raw_paths)
            peaks_by_paths.setdefault(paths, []).append(peak_rss_kib)
        migrated: list[WorkerResourceMeasurement] = []
        for paths, peaks in peaks_by_paths.items():
            shard_count = len(peaks)
            # An accepted exact run proves repeated path assignments were node shards.
            conservative_peak = max(peaks)
            migrated.extend(
                WorkerResourceMeasurement(
                    contract=WorkerResourceContract(
                        paths=paths,
                        shard_count=shard_count,
                        shard_index=shard_index,
                    ),
                    peak_rss_kib=conservative_peak,
                )
                for shard_index in range(shard_count)
            )
        accepted = tuple(sorted(migrated, key=measurement_sort_key))
        return cls(accepted=accepted)

    def accepted_for_source(self, source_sha256: str | None) -> WorkerResourceHistory:
        """Retain concurrency authority only for the exact accepted source tree."""

        if source_sha256 is not None and source_sha256 == self.accepted_source_sha256:
            return self
        return WorkerResourceHistory(observed_lower_bounds=self.observed_lower_bounds)

    def peak_for(self, spec: WorkerSpec) -> int | None:
        """Return a peak only when history proves the exact worker contract."""

        contract = WorkerResourceContract.from_spec(spec)
        for measurement in self.accepted:
            if measurement.contract == contract:
                return measurement.peak_rss_kib
        return None

    def conservative_peak_for(self, spec: WorkerSpec) -> int | None:
        """Return the largest exact peak without promoting failed-run evidence."""

        contract = WorkerResourceContract.from_spec(spec)
        peaks = (
            measurement.peak_rss_kib
            for measurement in (*self.accepted, *self.observed_lower_bounds)
            if measurement.contract == contract
        )
        return max(peaks, default=None)

    def retained_measurements(
        self,
        specs: Sequence[WorkerSpec],
        worker_peaks: dict[str, int],
        *,
        accepted: bool,
    ) -> tuple[WorkerResourceMeasurement, ...]:
        """Advance resource truth only after an exact successful full run."""

        if accepted:
            measurements = (
                WorkerResourceMeasurement(
                    contract=WorkerResourceContract.from_spec(spec),
                    peak_rss_kib=worker_peaks[spec.name],
                )
                for spec in specs
                if worker_peaks.get(spec.name, 0) > 0
            )
            return tuple(sorted(measurements, key=measurement_sort_key))
        return self.accepted

    def retained_lower_bounds(
        self,
        specs: Sequence[WorkerSpec],
        worker_peaks: dict[str, int],
    ) -> tuple[WorkerResourceMeasurement, ...]:
        """Retain exact observed peaks even when a run cannot authorize concurrency."""

        current = tuple(
            WorkerResourceMeasurement(
                contract=WorkerResourceContract.from_spec(spec),
                peak_rss_kib=worker_peaks[spec.name],
            )
            for spec in specs
            if worker_peaks.get(spec.name, 0) > 0
        )
        return _maximum_measurements((*self.observed_lower_bounds, *current))


def _typed_observed_measurements(payload: dict[str, object]) -> tuple[WorkerResourceMeasurement, ...]:
    """Decode exact current-run peaks without inferring contracts from worker names."""

    worker_contracts = payload.get("worker_contracts")
    worker_peaks = payload.get("worker_peak_rss_kib")
    if not isinstance(worker_contracts, dict) or not isinstance(worker_peaks, dict):
        return ()
    measurements: list[WorkerResourceMeasurement] = []
    for worker_name, contract_payload in worker_contracts.items():
        if not isinstance(worker_name, str):
            continue
        contract = WorkerResourceContract.from_payload(contract_payload)
        peak_rss_kib = worker_peaks.get(worker_name)
        if contract is not None and isinstance(peak_rss_kib, int) and peak_rss_kib > 0:
            measurements.append(WorkerResourceMeasurement(contract, peak_rss_kib))
    return tuple(measurements)


def _maximum_measurements(
    measurements: Sequence[WorkerResourceMeasurement],
) -> tuple[WorkerResourceMeasurement, ...]:
    """Keep one deterministic high-water mark for each exact worker contract."""

    peaks: dict[WorkerResourceContract, int] = {}
    for measurement in measurements:
        peaks[measurement.contract] = max(
            peaks.get(measurement.contract, 0),
            measurement.peak_rss_kib,
        )
    return tuple(
        sorted(
            (
                WorkerResourceMeasurement(contract=contract, peak_rss_kib=peak_rss_kib)
                for contract, peak_rss_kib in peaks.items()
            ),
            key=measurement_sort_key,
        )
    )


def worker_contract_sort_key(
    contract: WorkerResourceContract,
) -> tuple[tuple[str, ...], int, int]:
    """Return deterministic ordering for persisted worker contracts."""

    return contract.paths, contract.shard_count, contract.shard_index


def measurement_sort_key(
    measurement: WorkerResourceMeasurement,
) -> tuple[tuple[str, ...], int, int]:
    """Return deterministic ordering for accepted resource measurements."""

    return worker_contract_sort_key(measurement.contract)
