"""Process elevation check. False on every non-Windows platform."""

from __future__ import annotations

import ctypes
import sys


def is_elevated() -> bool:
    """Return whether this process token is elevated.

    A filtered administrator token (a normal Windows terminal) returns False.
    HKLM policy and device-node changes require an elevated token.
    """
    if sys.platform != "win32":
        return False
    try:
        token = ctypes.c_void_p()
        if not ctypes.windll.advapi32.OpenProcessToken(
            ctypes.windll.kernel32.GetCurrentProcess(),
            0x0008,  # TOKEN_QUERY
            ctypes.byref(token),
        ):
            return False
        try:
            elevation = ctypes.c_uint32()
            returned = ctypes.c_uint32()
            # TokenElevation = 20. TokenIsElevated is a DWORD.
            if not ctypes.windll.advapi32.GetTokenInformation(
                token,
                20,
                ctypes.byref(elevation),
                ctypes.sizeof(elevation),
                ctypes.byref(returned),
            ):
                return False
            return bool(elevation.value)
        finally:
            ctypes.windll.kernel32.CloseHandle(token)
    except (AttributeError, OSError):
        return False
