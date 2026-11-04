# SPDX-FileCopyrightText: 2026 René de Hesselle <dehesselle@web.de>
#
# SPDX-License-Identifier: 0BSD

"""Aggregate-auth: the XML form exchange that yields a ``webvpn`` cookie.

:mod:`~pylis.auth.xml_forms` is sans-IO -- it builds and parses XML and nothing
else -- so the whole gateway dialect surface can be tested against a corpus of
captured responses without a network.
"""
