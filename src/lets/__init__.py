"""Public package surface for Lineage Escrow Transition Systems, re-exporting the core
clock, error, and vector types consumed by src/lets/api.py and external integrators
such as AstralDeep's LETS driver.
"""

from lets.clock import Clock, ManualClock, SystemClock
from lets.errors import (
    ConflictError,
    ExpiredError,
    InvariantError,
    LETSError,
    NotFoundError,
    PolicyError,
    ReplayError,
    SignatureError,
)
from lets.vector import ResourceVector

__all__ = [
    "Clock",
    "ConflictError",
    "ExpiredError",
    "InvariantError",
    "LETSError",
    "ManualClock",
    "NotFoundError",
    "PolicyError",
    "ReplayError",
    "ResourceVector",
    "SignatureError",
    "SystemClock",
]

__version__ = "1.0.11"
