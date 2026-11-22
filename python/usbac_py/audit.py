"""Append-only audit log (JSON Lines) and CSV export."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from usbac_py.models import AuditAction, format_timestamp, parse_audit_action, parse_timestamp
from usbac_py.store import FileProtector, PortableFileProtector, _atomic_write

_MAX_LINE = 1_000_000

CSV_HEADERS = (
    "timestamp",
    "user",
    "machine",
    "action",
    "actionKo",
    "vendorId",
    "productId",
    "serialNumber",
    "deviceName",
    "instanceId",
    "policyMode",
    "result",
    "detail",
)


@dataclass
class AuditEvent:
    timestamp: datetime
    user_name: str
    machine_name: str
    action: AuditAction
    instance_id: str | None = None
    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    device_name: str | None = None
    policy_mode: str | None = None
    result: str | None = None
    detail: str | None = None

    def to_json(self) -> dict[str, object]:
        return {
            "timestamp": format_timestamp(self.timestamp),
            "userName": self.user_name,
            "machineName": self.machine_name,
            "action": self.action.value,
            "instanceId": self.instance_id,
            "vendorId": self.vendor_id,
            "productId": self.product_id,
            "serialNumber": self.serial_number,
            "deviceName": self.device_name,
            "policyMode": self.policy_mode,
            "result": self.result,
            "detail": self.detail,
        }


class AuditLog:
    def __init__(self, directory: Path, protector: FileProtector | None = None) -> None:
        self.directory = Path(directory)
        self.path = self.directory / "audit.jsonl"
        self._protector = protector or PortableFileProtector()
        self._gate = threading.Lock()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._protector.protect_directory(self.directory)

    def append(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_json(), ensure_ascii=False, separators=(",", ":"))
        with self._gate:
            self.directory.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(line + "\n")
        self._protect()

    def read_all(self) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        with self._gate:
            text = self.path.read_text(encoding="utf-8")
        events: list[AuditEvent] = []
        for raw in text.split("\n"):
            line = raw.strip().rstrip("\r")
            if not line or len(line) > _MAX_LINE:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = _event_from_json(parsed)
            if event is not None:
                events.append(event)
        return events

    def _protect(self) -> None:
        try:
            self._protector.protect_file(self.path)
        except OSError:
            return


def export_csv(events: list[AuditEvent]) -> str:
    rows = ["\ufeff" + ",".join(CSV_HEADERS)]
    for event in events:
        cells = [
            event.timestamp.isoformat(),
            event.user_name,
            event.machine_name,
            _enum_name(event.action),
            event.action.korean,
            event.vendor_id,
            event.product_id,
            event.serial_number,
            event.device_name,
            event.instance_id,
            event.policy_mode,
            event.result,
            event.detail,
        ]
        rows.append(",".join(csv_cell(cell) for cell in cells))
    return "\n".join(rows) + "\n"


def _enum_name(action: AuditAction) -> str:
    text = action.value
    return text[:1].upper() + text[1:]


def csv_cell(value: str | None) -> str:
    text = "" if value is None else value
    if text and text[0] in "=+-@\t\r":
        text = "'" + text
    if any(character in text for character in '",\n\r'):
        return '"' + text.replace('"', '""') + '"'
    return text


def write_csv(path: Path, events: list[AuditEvent]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, export_csv(events))


def _event_from_json(data: object) -> AuditEvent | None:
    if not isinstance(data, dict):
        return None
    action_raw = data.get("action")
    if not isinstance(action_raw, str):
        return None
    action = parse_audit_action(action_raw)
    if action is None:
        return None
    try:
        timestamp = parse_timestamp(data.get("timestamp"))
    except Exception:
        return None
    return AuditEvent(
        timestamp=timestamp,
        user_name=_text(data.get("userName")),
        machine_name=_text(data.get("machineName")),
        action=action,
        instance_id=_optional(data.get("instanceId")),
        vendor_id=_optional(data.get("vendorId")),
        product_id=_optional(data.get("productId")),
        serial_number=_optional(data.get("serialNumber")),
        device_name=_optional(data.get("deviceName")),
        policy_mode=_optional(data.get("policyMode")),
        result=_optional(data.get("result")),
        detail=_optional(data.get("detail")),
    )


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _optional(value: object) -> str | None:
    return value if isinstance(value, str) else None
