# Development infrastructure

Validate an existing inventory with `python -m tools.dev.pytest_inventory_check
FILE`. Make uses this command; the historical script still forwards to it.

Repository navigation, ownership and test-runner support lives here. It must
not introduce decompiler or proof semantics.

`pytest_test_record` owns the profiling record schema;
`pytest_profile_merge` merges xdist fragments, and `pytest_profile_rankings`
orders measured costs. Collection and profiling consumers import these owners
directly. Legacy script modules alias them, preserving old serialized class
lookups. Run their profiling integration with `PYTHONHASHSEED=0`, as Make does;
semantic-cache tests refuse nondeterministic processes.

`pytest_profile`, `pytest_cache_events`, and `pytest_test_inventory` collect
runtime costs, cache observations and static test facts. Invoke the profiler as
`python -m tools.dev.pytest_profile --profile-json FILE` followed by pytest
arguments. Its historical command remains supported. Observation does not
change test outcomes, and a source change during execution rejects the receipt.

`pytest_call_hints`, `pytest_inventory_review`, `pytest_assertion_facts`,
`pytest_source_index`, `pytest_source_structure`, and
`pytest_source_structure_cache` provide the existing inventory facts and source
index. Their historical imports alias these owners. Structure-cache paths and
freshness checks are preserved; private index tests are in this package.

`report_cython_vex` correlates existing Cython annotations with a measured
Python profile. Run `python -m tools.dev.report_cython_vex --annotation FILE
--profile FILE --out FILE`; `--source` defaults to the canonical frontend lifter.
The historical script forwards to this owner. Its private regression lives in
`tools/dev/tests/test_cython_vex_report.py`; annotations are diagnostics, not
instruction semantics or evidence of compiled execution speed.

The authoritative component declarations are `reference/components/*.json`.
They list reviewed source roots, public APIs, dependencies, guide paths,
component test modules, focused targets and known consumers. Tests can belong
to several components but have one physical home. Exact node/skip/resource
policies remain in the existing pipeline/ownership owners while they migrate.

```sh
nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.dev.component_catalog_cli
nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m tools.dev.component_catalog_cli --write
nice -n 10 env PYTHON_JIT=1 .venv/bin/python tools/dev/agent_test_focus.py --files tools/compiler_id/report.py --context --json --json-only --no-shared
nice -n 10 env PYTHON_JIT=1 .venv/bin/python -m pytest tools/dev/tests -q --tb=short
```

`reference/test-components.json` and `reference/components.mk` are derived compatibility exports. Edit the
per-component declaration and regenerate it; the catalog check rejects drift.
Pytest consumes the per-component declarations directly in this repository.
Migrated owners' `focus`, `routine_tests` and `quality_sources` also feed the
existing ownership selector, pipeline and Make quality lists. Legacy owners'
node/resource policies still live in their current declarations; migrate them
with equivalent selection evidence rather than inferring tests from directories.

`pytest_workspace` places default pytest temporary output in a fresh directory
under ignored `.cache/pytest/`, preserving explicit `--basetemp` supplied by
partition/xdist runners. Run roots remain available for failure investigation;
remove completed roots when their evidence is no longer needed.

Public contracts: `Component`, `load_components`, `validate_component_paths`.
Task context extends the existing selector; it is not a second test router.

`pytest_runtime` owns repository import roots and the `requires_kvm` collection
policy. Root conftest registers it once for platform, tool and integration tests.
Static tests never probe KVM; marked runtime tests retain device-evidence skips.
Policy controls remain `tools/dev/tests/test_kvm_marker_policy.py` during
infrastructure-test migration.

`pytest_live_failures` is the pipeline's pytest plugin for immediate failure
feedback. It forwards existing setup/call/teardown reports to the controller
terminal without changing outcomes. Its historical script import aliases the
same module. Private subprocess controls remain serial to avoid nested test
pools; the partitioned-runner integration keeps that resource policy.

`process_metrics`, `source_state`, and `decompile_process_budget` own process-tree
measurements, source snapshots and focused subprocess budgets. Existing script
imports alias these owners. They must retain process cleanup, cache freshness
and resource accounting; moving them is not permission to raise proof budgets.

`pytest_resource_history` owns accepted worker RSS evidence and conservative
lower bounds. `pytest_resource_scheduler` owns deterministic memory-bounded
worker waves. Measurements may raise concurrency only for matching accepted
source/worker contracts; missing or failed-run evidence retains conservative
limits. Private controls live in `tests/test_pytest_resource_scheduler.py`;
partition-controller integration remains in the shared partitioned-test module.
`pytest_worker_contract.WorkerSpec` is the shared immutable assignment contract;
resource analysis imports it directly without importing process-launch machinery.

`pytest_partitioned`, `pytest_partition_execution`, `pytest_partition_plugin`,
and `pytest_dynamic_schedule` own the controller, process lifecycle, shard
reporting and reservation-aware backfilling. Make invokes the controller with
`python -m tools.dev.pytest_partitioned`; the historical command and imports
forward to these owners. Their private tests live here. Aggregate RSS, worker
limits, exclusive lanes, source freshness and outcome accounting are unchanged.

`pytest_directory_cache` is the bounded collection plugin used by Make and both
pipeline pytest lanes. It reuses unchanged standard directory reports without
caching test execution, custom collectors or errors. Its historical
`scripts.pytest_directory_cache` import aliases the same owner. Private controls
verify identical selected node order and exits with neither plugin, the canonical
plugin and the historical entry; directory mutation and capacity limits retain
their bypass behavior.
