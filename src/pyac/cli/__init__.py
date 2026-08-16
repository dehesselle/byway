"""Command-line interface.

``main.py`` is a thin dispatcher; each command lives in its own ``cmd_*``
module exposing ``register(subparsers)``. argparse is deliberate: a handful of
commands does not justify pulling in click (and, in practice, rich) for
``--help`` formatting. Revisit past roughly a dozen commands.
"""
