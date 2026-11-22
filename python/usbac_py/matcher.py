"""Whitelist rules and VID/PID/serial matching.

A specific serial wins over a same-product entry that omits the serial.
A storage device whose VID or PID cannot be read never matches.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from usbac_py.exceptions import ValidationError
from usbac_py.identity import normalize_serial, normalize_vid_pid
from usbac_py.models import UsbStorageDevice, WhitelistEntry

MAX_ENTRIES = 500
MAX_NAME_LENGTH = 80
MAX_NOTE_LENGTH = 200
MAX_SERIAL_LENGTH = 128


def create_entry(
    vendor_id: str,
    product_id: str,
    serial_number: str | None,
    display_name: str,
    note: str | None,
    created_at: datetime,
    entry_id: uuid.UUID | None = None,
) -> WhitelistEntry:
    vid = normalize_vid_pid(vendor_id)
    if vid is None:
        raise ValidationError("VID는 1~4자리 16진수여야 합니다. 예: 0781")
    pid = normalize_vid_pid(product_id)
    if pid is None:
        raise ValidationError("PID는 1~4자리 16진수여야 합니다. 예: 5581")
    serial = normalize_serial(serial_number)
    if serial is not None and len(serial) > MAX_SERIAL_LENGTH:
        raise ValidationError(f"일련번호는 {MAX_SERIAL_LENGTH}자 이하여야 합니다.")
    name = (display_name or "").strip()
    if not name:
        raise ValidationError("표시 이름을 입력하세요.")
    if len(name) > MAX_NAME_LENGTH:
        raise ValidationError(f"표시 이름은 {MAX_NAME_LENGTH}자 이하여야 합니다.")
    trimmed_note = None if note is None or not note.strip() else note.strip()
    if trimmed_note is not None and len(trimmed_note) > MAX_NOTE_LENGTH:
        raise ValidationError(f"메모는 {MAX_NOTE_LENGTH}자 이하여야 합니다.")
    return WhitelistEntry(
        id=entry_id or uuid.uuid4(),
        vendor_id=vid,
        product_id=pid,
        serial_number=serial,
        display_name=name,
        note=trimmed_note,
        created_at=created_at,
    )


def same_identity(left: WhitelistEntry, right: WhitelistEntry) -> bool:
    return (
        left.vendor_id.lower() == right.vendor_id.lower()
        and left.product_id.lower() == right.product_id.lower()
        and (left.serial_number or "").lower() == (right.serial_number or "").lower()
    )


def find_match(entries: list[WhitelistEntry], device: UsbStorageDevice) -> WhitelistEntry | None:
    vendor_id = normalize_vid_pid(device.vendor_id)
    product_id = normalize_vid_pid(device.product_id)
    if vendor_id is None or product_id is None:
        return None
    serial = normalize_serial(device.serial_number)
    wildcard: WhitelistEntry | None = None
    for entry in entries:
        if entry.vendor_id.lower() != vendor_id.lower() or entry.product_id.lower() != product_id.lower():
            continue
        entry_serial = normalize_serial(entry.serial_number)
        if entry_serial is None:
            if wildcard is None:
                wildcard = entry
            continue
        if serial is not None and entry_serial.lower() == serial.lower():
            return entry
    return wildcard
