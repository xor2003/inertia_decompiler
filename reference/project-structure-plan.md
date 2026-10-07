# Project file reorganization

Status: file reorganization complete.

## Scope

Reorganize existing files so each tool or decompiler layer has a clear home,
with its private tests nearby. Shorten the project package to `inertia/`.
Preserve behavior. This plan does not change algorithms, proof rules, cache
policy, scheduling, or semantic recovery. It does not require model trials,
performance experiments, new gate infrastructure, or upstream contributions.

Implementation is limited to file moves and the import, command, build and
documentation updates those moves require. Keep unrelated defects outside
this plan; do not turn a file move into a subsystem refactor.

## Destinations

| Existing responsibility | Destination | Private tests |
| --- | --- | --- |
| Compiler identification | `tools/compiler_id/` | `tools/compiler_id/tests/` |
| Signature catalogs and OMF/PAT tooling | `tools/signatures/` | `tools/signatures/tests/` |
| Compiler building and coverage | `tools/compiler_toolchain/` | `tools/compiler_toolchain/tests/` |
| ADA disassembly | `tools/ada_script/` | `tools/ada_script/tests/` |
| Debugger | `tools/debugger/` | `tools/debugger/tests/` |
| Comparator drivers and target profiles | `tools/comparator/` | `tools/comparator/tests/` |
| Shared dosunit machinery | `tools/dosunit/` | `tools/dosunit/tests/` |
| Test runners, profiling, lint and build support | `tools/dev/` | `tools/dev/tests/` |
| Architecture, loading, lifting and SimOS | `inertia/frontend/x86_16/` | `tests/frontend/` |
| IR and semantic effects | `inertia/ir/`, `inertia/semantics/` | `tests/ir/`, `tests/semantics/` |
| Alias and widening | `inertia/alias/`, `inertia/widening/` | `tests/alias/`, `tests/widening/` |
| Types and lowering | `inertia/lowering/` | `tests/lowering/` |
| Structuring | `inertia/structuring/` | `tests/structuring/` |
| Cosmetic rewrite | `inertia/postprocess/` | `tests/postprocess/` |
| Validation | `inertia/validation/` | `tests/validation/` |
| Pipeline order and evidence contracts | `inertia/pipeline/` | `tests/integration/` |
| CLI orchestration, discovery, cache and reporting | `inertia/cli/` | `tests/cli/` |

Shared integration tests live in `tests/integration/`; shared small fixtures
live in `tests/fixtures/`. A test has one physical home. External compilers,
games and generated artifacts stay outside source packages.

Within dosunit, group existing modules under `contracts/`, `ssa/`, `compare/`,
`architectures/`, `catalog/`, `runtime/`, and `reporting/` by their current
responsibility. Move existing modules; do not redesign their interfaces or
split algorithms merely to satisfy this layout.

## Checklist

- [x] Exclude generated scratch from source navigation and the Git index.
- [x] Move compiler-identification implementation and private tests.
- [x] Move signature implementation and private tests.
- [x] Finish compiler-toolchain adapters and their test moves.
- [x] Finish ADA and debugger test ownership and consumer updates.
- [x] Finish comparator and dosunit file grouping.
- [x] Finish development infrastructure and private test moves.
- [x] Finish frontend helpers and their test moves.
- [x] Move the remaining core layers and their private tests.
- [x] Move CLI modules and their private tests.
- [x] Update concise project navigation and local tool instructions.
- [x] Verify final imports, entry points, packaging, native builds and relevant tests.

Implementations and private tests have moved to the destinations above.
Historical import and command shims are removed; callers use authoritative
owners. ADA implementation and private tests live only in `tools/ada_script/`.
Final review covers imports, lint/test enrollment, cache source inputs, installed
entry points and native builds. Full collection found 21,891 tests without
errors; installed-wheel source parity and native shared16 lowering passed.
The architecture scan's two stale documentation markers were corrected and
their focused checks passed. Comparator tests: 138 passed; dosunit/real16:
230 passed, 5 skipped, one shifted-callee control-proof budget failure in
unchanged proof code. That semantic limitation remains outside these file moves.
Detailed run output stays in `.cache/shim-removal/`.

## How to move files

1. Identify the existing owner, imports, entry points and relevant tests.
2. Move the implementation and its private tests together without semantic edits.
3. Update normal imports, commands, packaging/build inputs and existing test
   enrollment. Use the existing component declarations for their current purpose;
   do not add another location registry or redesign execution policy.
4. Remove historical aliases after updating callers, registration, build inputs
   and commands to their canonical owners. Do not leave forwarding files.
5. Run scoped lint and the relevant existing tests. For frontend/build changes,
   also verify the affected Cython build and installed import/lifting behavior.
6. Continue the checklist. Keep detailed logs in ignored cache output, not here.

Resolve source locations through ordinary imports and existing build constants.
Do not add dynamic directory discovery to compensate for stale imports. Tests
should check behavior, imports and entry points, rather than enforce arbitrary
physical filenames. Preserve the mandatory Cython lifter, cache freshness,
segmented-memory behavior, proof verdicts and current resource limits.

## Completion

All listed responsibilities and private tests have their intended homes;
imports, commands, builds and existing enrollment use the new owners. Relevant
checks pass on the final stable tree. Historical compatibility aliases and
duplicate implementation trees are removed. No unrelated semantic or
infrastructure project is a prerequisite for completing these file moves.
