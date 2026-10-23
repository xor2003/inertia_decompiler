# Catalog input verification

`pe32_link_map.py` binds MSVC linker-map evidence to a loaded PE candidate.
`flat32_catalog_admission.py` checks declared function extents against executable
sections. Their existing interfaces and proof-status rules are unchanged.

Linker-map consumers may explicitly request `include_statics=True`; private
symbols then use the same bounded parser and header binding as publics, while
remaining a separate catalog. Data relocation still consumes only publics.
Code-dependency consumers additionally validate segment coordinates against
the loaded executable sections before scanning any helper body.

The standalone linker-map tests live in `../tests/`. Admission tests that use
the shared comparator-driver fixtures remain with that integration cohort.
Historical imports from `tools.dosunit` alias these modules.

`real16_declared_input.py` authenticates an explicit conditional input for the
decompiler's DOS MZ lane. The JSON root requires four fields:

- `schema`: `inertia.real16_declared_input.v1`.
- `source_sha256`: SHA-256 of the exact original MZ file bytes.
- `program`: the entire canonical `dosunit.real16_program_environment.v1`
  manifest, with explicit memory/registers and optional DOS policies.
- `services`: a list of exact `kind`, `caller_addr`, `callsite_addr` objects.
  Kinds are `version` or `resize`; coordinates are integer linear addresses.

The optional `function_entries` list contains serialized
`DeclaredFunctionEntrySpec8616` records from
`inertia/frontend/x86_16/declared_function_entry.py`. Each record explicitly
binds the original file, relocated module, environment and native function
range, entry coordinates, register constraints, memory spans and return frame.
The canonical serializer is `spec.to_dict()`. Unknown fields, duplicate entry
addresses and foreign source/environment identities refuse. Omitted register
or memory values remain unknown; matching a library signature supplies none
of these constraints. Parsing admits a conditional premise and does not prove
that startup reaches the declared state. CLI pipeline transport of these
entries is being integrated; parser acceptance alone is not a decompilation
or round-trip result.

The wrapper adds source binding and site declarations; it does not duplicate
the environment parser or DOS semantics. Missing policies, foreign source,
malformed/duplicate declarations and replay-only code ranges refuse. Reading
retains the raw declaration-file digest separately from the source digest.
The native census must still prove the actual site, AH/AL, stack frame and IVT
before consuming a relation. A declaration is a premise, not a native-site proof.

```sh
rtk proxy nice -n 10 env PYTHON_JIT=1 PYTHONHASHSEED=0 \
  .venv/bin/python decompile.py PROGRAM.EXE \
  --real16-declared-input initialized-input.json --addr 0x10100 \
  --timeout 120 --no-alternate-source-c --ignore-local-sidecar-hints
```

The manifest owns load coordinates unless matching coordinates were explicitly
supplied. Conflicting coordinates, blob/COM and COD-linked `--proc` lanes refuse.
Declared loads use the authenticated MZ base and retain the same authority in
clean workers and isolated rebuilds. Live declaration loads/result lookups do
not reuse cached projects or positive result receipts. Runtime capture tooling
is described in `../../compiler_toolchain/README.md`; it creates initial input
only and does not invent service policies or prove a decompiler round trip.
