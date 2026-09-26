# Third-party notices and license scope

The root [LICENSE](LICENSE) applies to original Inertia Decompiler source code
and documentation unless a file or directory carries a different notice. The
same original material is also available under a separately executed commercial
license as described in [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).

The repository also contains or references material that is not relicensed by
the Inertia Decompiler copyright holder. That material remains under its own
license or copyright terms. In particular, do not assume that the root license
grants rights to:

- code retained from or derived from `angr-platforms`;
- separately installed dependencies, including angr and the other packages
  listed in `pyproject.toml` and `requirements.txt`;
- content under `borrow/`;
- papers and extracted research text under `decompile/`;
- third-party games, executables, object files, listings, libraries, debug
  information, and corpus inputs under `cod/`, `deep/`, `examples/`,
  `signature_catalogs/`, or elsewhere in the repository; or
- any file carrying its own copyright or license notice.

## angr-platforms

Portions of the x86 platform history were derived from the `angr-platforms`
project and remain subject to its BSD 2-Clause License notice:

> BSD 2-Clause License
>
> Copyright (c) 2017,
> All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions are met:
>
> 1. Redistributions of source code must retain the above copyright notice,
>    this list of conditions and the following disclaimer.
> 2. Redistributions in binary form must reproduce the above copyright notice,
>    this list of conditions and the following disclaimer in the documentation
>    and/or other materials provided with the distribution.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
> AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
> IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
> ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
> LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
> CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
> SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
> INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
> CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
> POSSIBILITY OF SUCH DAMAGE.

The upstream project is available at <https://github.com/angr/angr-platforms>.

## Distribution review

### Imported ada_script snapshot

`vendor/ada_script/` contains tracked sources from
<https://github.com/xor2003/ada_script>, revision
`cf5ac66c2c82f51e78bc5e17802994d9c7d515a6`. Per-file hashes and import boundaries
are recorded in `vendor/ada_script/UPSTREAM.json` and `IMPORT.md`.
The imported checkout did not include a tracked LICENSE file; this notice
records provenance and does not assign a new license to the imported code.
The repository's blanket Inertia licensing must not be assumed to cover this
snapshot. Game binaries, local databases and generated artifacts were excluded.

### Review before redistribution

Before publishing a source archive, Python package, benchmark corpus, signature
bundle, or commercial build, review the included files and distribute only
material for which the required rights and notices are available. Inclusion in
the Git repository is not by itself evidence of permission for commercial
redistribution.
