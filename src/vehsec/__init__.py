"""vehsec — Vehicle Security Toolkit.

Core library exposing CAN / UDS / Seed-Key / V2X / ICSim / DoIP / DBC / J1939
capabilities. All modules degrade gracefully when optional dependencies are missing.
"""

__version__ = "0.2.0"

from . import can_bus
from . import uds
from . import seedkey
from . import v2x
from . import icsim
from . import doip
from . import dbc
from . import j1939
from . import iso_tp

__all__ = [
    "can_bus",
    "uds",
    "seedkey",
    "v2x",
    "icsim",
    "doip",
    "dbc",
    "j1939",
    "iso_tp",
    "__version__",
]
