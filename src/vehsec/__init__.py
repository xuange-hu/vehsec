"""vehsec — Vehicle Security Toolkit.

Core library exposing CAN / UDS / Seed-Key / V2X / ICSim capabilities.
All modules degrade gracefully when optional dependencies are missing.
"""

__version__ = "0.1.0"

from . import can_bus
from . import uds
from . import seedkey
from . import v2x
from . import icsim
from . import doip
from . import dbc

__all__ = [
    "can_bus",
    "uds",
    "seedkey",
    "v2x",
    "icsim",
    "doip",
    "dbc",
    "__version__",
]
