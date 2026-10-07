# Comparator orchestration

The MS C tiny-example adapter is `compare_msc6_ssa_examples`. Run
`python -m tools.comparator.compare_msc6_ssa_examples --help` for its existing
report and comparison options. The historical script aliases this owner.
Compiler-header integration remains in `tests/integration/`.

`services.py` exposes typed `NativeProofOwners` through qualified imports.
It does not load backend modules until requested. Shared region, loop and
macro helpers use these owners without artifact modules or `sys.path` state.
`native.py` derives the model view from the existing SSA/architecture owners;
`abi.py` owns the unchanged shared default observation contract. Explicit
function output contracts remain caller-selected.

`profiles.py` owns target successor-admission policies. Both CLIs consume these
qualified policies and the native model view directly; compatibility adapters
retain aliases. Declared-bound and executable-section admission remain distinct.

`verified_pe.py` owns BC5's bounded, content-verified PE relocation cache and
uses the shared image loader. Certificates include loader implementation hashes;
the historical module aliases the exact owner, preserving cache-test injection.

`bc5_region.py` and `msc8_region.py` own the existing target region policies.
They share native model owners, retain distinct call-premise/trap behavior and
are imported by qualified name. Historical modules alias these exact owners.

`bc5_cfg.py` and `msc8_cfg.py` own target CFG comparison/report policies over
the shared `cfg.py` discovery/lowering owner. Their historical modules alias
the qualified owners; both CLIs use qualified imports.

`cfg.py` owns native CFG discovery, direct-edge admission, graph pairing and
full-state block lowering. Historical driver modules re-export these exact
owners and retain their target comparison policies. Noninteger control targets
refuse. Shared helper dispatch imports this backend owner only when needed.

`catalog.py` owns deterministic function coordinates and name-paired proof
obligations. Names select obligations; they never establish semantic equality.
Target listing, symbol and relocation policies live in separate qualified
catalog owners; they do not redefine proof semantics.

`msc8_catalog.py` owns MSC8 listing bounds, ELF symbols and verified PE LINK-map
data correspondence. Its historical artifact module aliases the exact owner;
the MSC8 CLI imports it by qualified name. `bc5_catalog.py` separately owns
BC5's broader listing forms, content-validated cache and symbol correspondence.
The BC5 CLI also uses qualified imports; its historical module aliases the owner.

`verdict.py` owns typed public verdicts and complete backend-result accounting.
It is independent of angr, VEX, Z3 and the SSA engine. Both historical target
verdict modules alias this exact owner, preserving identities and old pickles.

Proof-source seals include this package. Keep refusal, counterexample and
conditional proof distinct. A conditional result must name its assumptions.

Private tests are in `tests/`. Production drivers are `bc5_cli.py` and
`msc8_cli.py`, runnable with `python -m tools.comparator.bc5_cli` or
`python -m tools.comparator.msc8_cli`. Historical artifact commands remain
compatibility entry points and their module imports alias the exact owners.
CLI/package acceptance remains in progress; preserve resource limits and report
schemas without introducing a second semantic owner.
