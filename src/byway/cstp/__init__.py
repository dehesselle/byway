# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""CSTP: AnyConnect authentication, tunnel handshake, and frame transport.

Knows nothing about TCP. Everything here deals in whole IP packets, which it
hands to (and takes from) the stack in :mod:`usernet.net`.
"""
