#!/usr/bin/env python3

import sys

from inertia_decompiler import cli as _cli

sys.modules[__name__] = _cli


if __name__ == "__main__":
    raise SystemExit(_cli.main())
