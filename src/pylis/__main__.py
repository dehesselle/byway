# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Entry point for ``python -m pylis``."""

from __future__ import annotations

from pylis.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
