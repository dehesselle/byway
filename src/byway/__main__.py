# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Entry point for ``python -m byway``."""

from __future__ import annotations

from byway.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
