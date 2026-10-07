# Catalog input verification

`pe32_link_map.py` binds MSVC linker-map evidence to a loaded PE candidate.
`flat32_catalog_admission.py` checks declared function extents against executable
sections. Their existing interfaces and proof-status rules are unchanged.

The standalone linker-map tests live in `../tests/`. Admission tests that use
the shared comparator-driver fixtures remain with that integration cohort.
Historical imports from `tools.dosunit` alias these modules.
