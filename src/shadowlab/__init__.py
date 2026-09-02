"""shadowlab: a sandboxed defensive-security exercise runner.

Everything in this package is local and defensive: log analysis, config
auditing, and incident-response playbook scoring against bundled synthetic
fixtures. Nothing here reaches a network or touches a real target.
"""

from importlib import metadata

try:
    __version__ = metadata.version("shadowlab")
except metadata.PackageNotFoundError:  # pragma: no cover - editable/dev installs
    __version__ = "0.0.0+dev"

__all__ = ["__version__"]
