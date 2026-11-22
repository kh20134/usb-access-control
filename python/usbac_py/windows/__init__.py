"""Windows-only adapters. Importing this package does not load setupapi or cfgmgr32."""

from usbac_py.windows.elevation import is_elevated

__all__ = ["is_elevated"]
