# Shared test fixtures

Small binary builders shared by frontend and comparator tests live here.
Import helpers by their package name instead of importing a whole test module.

`mz._mz_exe` retains the existing dosunit MZ header, relocation and allocation
defaults. Its legacy import in `test_dosunit_tool` remains available to existing
tests. This fixture does not define production loader or proof semantics.
