"""A fake AnyConnect gateway for end-to-end tests.

Grows with the milestones: it serves the auth XML exchange now, and gains
``CONNECT /CSCOSSLC/tunnel``, CSTP framing, DPD, and fault injection as the
tunnel layers land. The point is that the whole product can be exercised on
both Windows and Linux, in CI, in seconds, with no VPN anywhere in sight.
"""

from tests.fakegw.server import FakeGateway

__all__ = ["FakeGateway"]
