"""Dependency-free peer-request timeout constants (default, max, and minimum production
bounds) shared by cli.py's argument parsing and peer.py's dispatcher.
"""

DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS = 60
MAX_PEER_REQUEST_TIMEOUT_SECONDS = 60
MIN_PRODUCTION_PEER_REQUEST_TIMEOUT_SECONDS = 30

__all__ = [
    "DEFAULT_PEER_REQUEST_TIMEOUT_SECONDS",
    "MAX_PEER_REQUEST_TIMEOUT_SECONDS",
    "MIN_PRODUCTION_PEER_REQUEST_TIMEOUT_SECONDS",
]
