"""Normalize VID, PID, and serial numbers from Windows device instance IDs."""

from __future__ import annotations

import re
from dataclasses import dataclass

from usbac_py.exceptions import DeviceControlError

_HEX = re.compile(r"^[0-9A-Fa-f]+$")
_VID = re.compile(r"VID_([0-9A-Fa-f]{4})", re.IGNORECASE)
_PID = re.compile(r"PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


def normalize_vid_pid(raw: str | None) -> str | None:
    if raw is None:
        return None
    text = raw.strip()
    if not text:
        return None
    if text[:2].lower() == "0x":
        text = text[2:]
    upper = text.upper()
    if upper.startswith("VID_") or upper.startswith("PID_"):
        text = text[4:]
    if not 1 <= len(text) <= 4 or _HEX.fullmatch(text) is None:
        return None
    return text.upper().zfill(4)


def normalize_serial(serial: str | None) -> str | None:
    if serial is None:
        return None
    text = serial.strip()
    if not text:
        return None
    separator = text.rfind("&")
    if separator > 0 and text[separator + 1 :].isdigit():
        text = text[:separator]
    return text or None


@dataclass(frozen=True)
class ParsedDeviceId:
    vendor_id: str | None
    product_id: str | None
    serial_number: str | None


def parse_instance_id(instance_id: str | None) -> ParsedDeviceId:
    if instance_id is None or not instance_id.strip():
        return ParsedDeviceId(None, None, None)
    normalized = instance_id.strip().replace("/", "\\")
    vid_match = _VID.search(normalized)
    pid_match = _PID.search(normalized)
    vendor_id = vid_match.group(1).upper() if vid_match else None
    product_id = pid_match.group(1).upper() if pid_match else None
    parts = [part for part in normalized.split("\\") if part]
    serial = parts[-1] if len(parts) >= 3 else None
    if serial is not None and parts[0].upper() == "USBSTOR":
        serial = _strip_usbstor_suffix(serial)
    return ParsedDeviceId(vendor_id, product_id, normalize_serial(serial))


def is_usbstor_instance(instance_id: str | None) -> bool:
    if instance_id is None:
        return False
    return instance_id.strip().replace("/", "\\").upper().startswith("USBSTOR\\")


def ensure_usbstor_instance(instance_id: str) -> str:
    if not isinstance(instance_id, str):
        raise DeviceControlError("장치 인스턴스 ID가 올바르지 않습니다.")
    normalized = instance_id.strip().replace("/", "\\")
    if "\x00" in normalized or not normalized or len(normalized) > 512:
        raise DeviceControlError("장치 인스턴스 ID가 올바르지 않습니다.")
    if not is_usbstor_instance(normalized):
        raise DeviceControlError(
            "USBSTOR 대용량 저장장치만 활성화하거나 비활성화할 수 있습니다. "
            "키보드, 마우스 등 다른 USB 장치는 대상이 아닙니다."
        )
    return normalized


def _strip_usbstor_suffix(serial: str) -> str:
    separator = serial.rfind("&")
    if separator > 0 and serial[separator + 1 :].isdigit():
        return serial[:separator]
    return serial
