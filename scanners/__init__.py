"""Import scanner modules so BaseScanner registers every plugin."""

from scanners import active, passive

__all__ = ["active", "passive"]
