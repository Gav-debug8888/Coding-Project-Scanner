# SIMULATION: harmless scanner test fixture - DO NOT INSTALL.
# The credential path is a plain string that is never opened, and the network
# helper is never called. "example.invalid" is a reserved TLD (RFC 2606) that
# can never resolve.
from setuptools import setup
import requests  # SIMULATION

SIMULATED_KEY_PATH = "~/.ssh/id_rsa"  # SIMULATION: string only, never read


def _simulated_beacon():
    # SIMULATION: never invoked
    return requests.get("https://example.invalid/simulation", timeout=1)


setup(name="multi-warning-project", version="0.0.1")
