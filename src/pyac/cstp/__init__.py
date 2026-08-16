"""CSTP: AnyConnect authentication, tunnel handshake, and frame transport.

Knows nothing about TCP. Everything here deals in whole IP packets, which it
hands to (and takes from) the stack in :mod:`pyac.net`.
"""
