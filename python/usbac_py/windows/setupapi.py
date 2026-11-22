"""Enumerate present USBSTOR disk devices with SetupAPI.

VID/PID often live on a parent USB node rather than the USBSTOR instance ID.
This module walks at most eight parents and never enables or disables a device.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from usbac_py.exceptions import DeviceControlError, PlatformError
from usbac_py.identity import is_usbstor_instance, parse_instance_id
from usbac_py.models import UsbStorageDevice

DIGCF_PRESENT = 0x00000002
SPDRP_DEVICEDESC = 0
SPDRP_FRIENDLYNAME = 12
ERROR_INSUFFICIENT_BUFFER = 122
INVALID_HANDLE = ctypes.c_void_p(-1).value
CR_SUCCESS = 0


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SP_DEVINFO_DATA(ctypes.Structure):
    """Matches SetupAPI's SP_DEVINFO_DATA, including pointer-width padding."""

    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("ClassGuid", GUID),
        ("DevInst", ctypes.c_uint32),
        ("Reserved", ctypes.c_size_t),
    ]


def disk_class_guid() -> GUID:
    guid = GUID()
    # GUID_DEVCLASS_DISK = {4d36e967-e325-11ce-bfc1-08002be10318}
    guid.Data1 = 0x4D36E967
    guid.Data2 = 0xE325
    guid.Data3 = 0x11CE
    guid.Data4 = (ctypes.c_ubyte * 8)(0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18)
    return guid


class SetupApiDeviceEnumerator:
    def list_mass_storage_devices(self) -> list[UsbStorageDevice]:
        if sys.platform != "win32":
            raise PlatformError("USB 저장장치 열거는 Windows에서만 가능합니다.")
        setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        cfgmgr = ctypes.WinDLL("cfgmgr32", use_last_error=True)
        _bind(setupapi, cfgmgr)
        guid = disk_class_guid()
        handle = setupapi.SetupDiGetClassDevsW(ctypes.byref(guid), "USBSTOR", None, DIGCF_PRESENT)
        if not handle or int(handle) == INVALID_HANDLE:
            raise DeviceControlError(
                "USBSTOR 장치 목록을 열지 못했습니다. Win32=" + str(ctypes.get_last_error())
            )
        devices: list[UsbStorageDevice] = []
        try:
            index = 0
            while True:
                info = SP_DEVINFO_DATA()
                info.cbSize = ctypes.sizeof(SP_DEVINFO_DATA)
                if not setupapi.SetupDiEnumDeviceInfo(handle, index, ctypes.byref(info)):
                    break
                index += 1
                instance_id = _read_instance_id(setupapi, handle, info)
                if not is_usbstor_instance(instance_id):
                    continue
                parsed = parse_instance_id(instance_id)
                vendor_id, product_id = _resolve_vid_pid(cfgmgr, info.DevInst, parsed.vendor_id, parsed.product_id)
                devices.append(
                    UsbStorageDevice(
                        instance_id=instance_id,
                        vendor_id=vendor_id,
                        product_id=product_id,
                        serial_number=parsed.serial_number,
                        friendly_name=_read_text(setupapi, handle, info, SPDRP_FRIENDLYNAME)
                        or _read_text(setupapi, handle, info, SPDRP_DEVICEDESC),
                        is_mass_storage=True,
                    )
                )
        finally:
            setupapi.SetupDiDestroyDeviceInfoList(handle)
        return devices


def _bind(setupapi, cfgmgr) -> None:
    setupapi.SetupDiGetClassDevsW.argtypes = [
        ctypes.POINTER(GUID),
        wintypes.LPCWSTR,
        wintypes.HWND,
        wintypes.DWORD,
    ]
    setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
    setupapi.SetupDiEnumDeviceInfo.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(SP_DEVINFO_DATA),
    ]
    setupapi.SetupDiEnumDeviceInfo.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceInstanceIdW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    setupapi.SetupDiGetDeviceInstanceIdW.restype = wintypes.BOOL
    setupapi.SetupDiGetDeviceRegistryPropertyW.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(SP_DEVINFO_DATA),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_byte),
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    setupapi.SetupDiGetDeviceRegistryPropertyW.restype = wintypes.BOOL
    setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
    setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL
    cfgmgr.CM_Get_Parent.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        wintypes.DWORD,
        wintypes.ULONG,
    ]
    cfgmgr.CM_Get_Parent.restype = wintypes.DWORD
    cfgmgr.CM_Get_Device_IDW.argtypes = [
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.ULONG,
        wintypes.ULONG,
    ]
    cfgmgr.CM_Get_Device_IDW.restype = wintypes.DWORD


def _read_instance_id(setupapi, handle, info: SP_DEVINFO_DATA) -> str:
    required = wintypes.DWORD(0)
    buffer = ctypes.create_unicode_buffer(512)
    ok = setupapi.SetupDiGetDeviceInstanceIdW(handle, ctypes.byref(info), buffer, len(buffer), ctypes.byref(required))
    if not ok and ctypes.get_last_error() == ERROR_INSUFFICIENT_BUFFER and 0 < required.value < 4096:
        buffer = ctypes.create_unicode_buffer(required.value)
        ok = setupapi.SetupDiGetDeviceInstanceIdW(
            handle, ctypes.byref(info), buffer, len(buffer), ctypes.byref(required)
        )
    if not ok:
        return ""
    return buffer.value


def _read_text(setupapi, handle, info: SP_DEVINFO_DATA, property_id: int) -> str | None:
    reg_type = wintypes.DWORD(0)
    required = wintypes.DWORD(0)
    buffer = (ctypes.c_byte * 1024)()
    ok = setupapi.SetupDiGetDeviceRegistryPropertyW(
        handle,
        ctypes.byref(info),
        property_id,
        ctypes.byref(reg_type),
        buffer,
        ctypes.sizeof(buffer),
        ctypes.byref(required),
    )
    if not ok:
        return None
    raw = bytes(buffer).split(b"\x00\x00", 1)[0]
    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", errors="ignore").strip("\x00").strip()
    return text or None


def _resolve_vid_pid(cfgmgr, dev_inst: int, vendor_id: str | None, product_id: str | None):
    if vendor_id and product_id:
        return vendor_id, product_id
    current = dev_inst
    for _depth in range(8):
        parent = wintypes.DWORD(0)
        if cfgmgr.CM_Get_Parent(ctypes.byref(parent), current, 0) != CR_SUCCESS:
            break
        parent_id = _device_id(cfgmgr, parent.value)
        parsed = parse_instance_id(parent_id)
        if parsed.vendor_id and parsed.product_id:
            return parsed.vendor_id, parsed.product_id
        current = parent.value
    return None, None


def _device_id(cfgmgr, dev_inst: int) -> str:
    buffer = ctypes.create_unicode_buffer(512)
    if cfgmgr.CM_Get_Device_IDW(dev_inst, buffer, len(buffer), 0) != CR_SUCCESS:
        return ""
    return buffer.value
