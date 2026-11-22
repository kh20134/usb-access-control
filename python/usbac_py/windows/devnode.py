"""Enable or disable a USBSTOR device node.

cfgmgr32 is called only after the instance ID is checked to start with
``USBSTOR\\``. Other USB devices, including keyboards and mice, are refused
before any native call.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from usbac_py.exceptions import DeviceControlError, PlatformError
from usbac_py.identity import ensure_usbstor_instance

CR_SUCCESS = 0
CR_NO_SUCH_DEVNODE = 13
LOCATE_NORMAL = 0
LOCATE_PHANTOM = 1


class DevNodeController:
    def set_mass_storage_enabled(self, instance_id: str, enabled: bool) -> str:
        normalized = ensure_usbstor_instance(instance_id)
        if sys.platform != "win32":
            raise PlatformError("장치 노드 제어는 Windows 관리자 권한에서만 가능합니다.")
        cfgmgr = ctypes.WinDLL("cfgmgr32", use_last_error=True)
        cfgmgr.CM_Locate_DevNodeW.argtypes = [
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPCWSTR,
            wintypes.ULONG,
        ]
        cfgmgr.CM_Locate_DevNodeW.restype = wintypes.DWORD
        cfgmgr.CM_Enable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]
        cfgmgr.CM_Enable_DevNode.restype = wintypes.DWORD
        cfgmgr.CM_Disable_DevNode.argtypes = [wintypes.DWORD, wintypes.ULONG]
        cfgmgr.CM_Disable_DevNode.restype = wintypes.DWORD
        device = _locate(cfgmgr, normalized)
        if device is None:
            return "not_found"
        result = cfgmgr.CM_Enable_DevNode(device, 0) if enabled else cfgmgr.CM_Disable_DevNode(device, 0)
        if result == CR_SUCCESS:
            return "changed"
        if result == CR_NO_SUCH_DEVNODE:
            return "not_found"
        action = "활성화" if enabled else "비활성화"
        raise DeviceControlError(
            f"USBSTOR 장치 노드를 {action}하지 못했습니다 ({normalized}). CR={result}. 관리자 권한이 필요합니다."
        )


def _locate(cfgmgr, instance_id: str) -> int | None:
    for flags in (LOCATE_NORMAL, LOCATE_PHANTOM):
        device = wintypes.DWORD(0)
        if cfgmgr.CM_Locate_DevNodeW(ctypes.byref(device), instance_id, flags) == CR_SUCCESS:
            return int(device.value)
    return None
