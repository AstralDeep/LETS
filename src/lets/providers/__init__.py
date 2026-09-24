"""Package of production runtime-provider profiles shipped with LETS; currently exposes
only the vendor-neutral provider in generic.py.
"""

from lets.providers.generic import open_runtime

__all__ = ["open_runtime"]
