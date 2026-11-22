"""Policy documents shared with the .NET tool's JSON shape."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from usbac_py.exceptions import ValidationError


class PolicyMode(Enum):
    BLOCK = "block"
    READ_ONLY = "readOnly"
    ALLOW = "allow"

    @property
    def korean(self) -> str:
        return _MODE_KO[self]

    @property
    def fingerprint_name(self) -> str:
        return _MODE_FINGERPRINT[self]


_MODE_KO = {
    PolicyMode.BLOCK: "차단",
    PolicyMode.READ_ONLY: "읽기 전용",
    PolicyMode.ALLOW: "허용",
}

_MODE_FINGERPRINT = {
    PolicyMode.BLOCK: "Block",
    PolicyMode.READ_ONLY: "ReadOnly",
    PolicyMode.ALLOW: "Allow",
}


def parse_mode(text: str | None) -> PolicyMode:
    if text is None or not str(text).strip():
        raise ValidationError("정책 모드가 비어 있습니다. block, readonly, allow 중 하나를 지정하세요.")
    value = str(text).strip()
    folded = value.casefold().replace("_", "").replace("-", "").replace(" ", "")
    if folded in {"block", "차단"}:
        return PolicyMode.BLOCK
    if folded in {"readonly", "읽기전용"}:
        return PolicyMode.READ_ONLY
    if folded in {"allow", "허용"}:
        return PolicyMode.ALLOW
    raise ValidationError("정책 모드는 block(차단), readonly(읽기 전용), allow(허용) 중 하나여야 합니다.")


class EffectiveAccess(Enum):
    ALLOW = "allow"
    READ_ONLY = "readOnly"
    BLOCK = "block"

    @property
    def korean(self) -> str:
        if self is EffectiveAccess.ALLOW:
            return "허용"
        if self is EffectiveAccess.READ_ONLY:
            return "읽기 전용"
        return "차단"


class AuditAction(Enum):
    POLICY_APPLIED = "policyApplied"
    POLICY_REJECTED = "policyRejected"
    WHITELIST_ADDED = "whitelistAdded"
    WHITELIST_REMOVED = "whitelistRemoved"
    DEVICE_INSERTED = "deviceInserted"
    DEVICE_REMOVED = "deviceRemoved"
    DEVICE_BLOCKED = "deviceBlocked"
    DEVICE_ALLOWED = "deviceAllowed"
    DEVICE_READ_ONLY = "deviceReadOnly"
    LOG_EXPORTED = "logExported"
    PASSWORD_SET = "passwordSet"
    PASSWORD_CLEARED = "passwordCleared"
    MONITOR_STARTED = "monitorStarted"
    MONITOR_STOPPED = "monitorStopped"

    @property
    def korean(self) -> str:
        return _AUDIT_KO[self]


_AUDIT_KO = {
    AuditAction.POLICY_APPLIED: "정책 적용",
    AuditAction.POLICY_REJECTED: "정책 거부",
    AuditAction.WHITELIST_ADDED: "화이트리스트 추가",
    AuditAction.WHITELIST_REMOVED: "화이트리스트 삭제",
    AuditAction.DEVICE_INSERTED: "장치 연결",
    AuditAction.DEVICE_REMOVED: "장치 분리",
    AuditAction.DEVICE_BLOCKED: "장치 차단",
    AuditAction.DEVICE_ALLOWED: "장치 허용",
    AuditAction.DEVICE_READ_ONLY: "장치 읽기 전용",
    AuditAction.LOG_EXPORTED: "로그 내보내기",
    AuditAction.PASSWORD_SET: "암호 설정",
    AuditAction.PASSWORD_CLEARED: "암호 해제",
    AuditAction.MONITOR_STARTED: "감시 시작",
    AuditAction.MONITOR_STOPPED: "감시 중지",
}


def parse_audit_action(text: str) -> AuditAction | None:
    for action in AuditAction:
        if text == action.value or text == action.name:
            return action
    return None


@dataclass
class PasswordRecord:
    algorithm: str
    iterations: int
    salt_base64: str
    hash_base64: str

    def to_json(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "iterations": self.iterations,
            "saltBase64": self.salt_base64,
            "hashBase64": self.hash_base64,
        }

    @classmethod
    def from_json(cls, data: object) -> PasswordRecord:
        if not isinstance(data, dict):
            raise ValidationError("관리자 암호 기록 형식이 올바르지 않습니다.")
        try:
            return cls(
                algorithm=str(data["algorithm"]),
                iterations=int(data["iterations"]),
                salt_base64=str(data["saltBase64"]),
                hash_base64=str(data["hashBase64"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValidationError("관리자 암호 기록을 읽지 못했습니다. 정책 파일은 바꾸지 않았습니다.") from exc


@dataclass
class WhitelistEntry:
    id: uuid.UUID
    vendor_id: str
    product_id: str
    serial_number: str | None
    display_name: str
    note: str | None
    created_at: datetime

    def to_json(self) -> dict[str, object]:
        return {
            "id": str(self.id),
            "vendorId": self.vendor_id,
            "productId": self.product_id,
            "serialNumber": self.serial_number,
            "displayName": self.display_name,
            "note": self.note,
            "createdAt": format_timestamp(self.created_at),
        }


@dataclass
class PolicyDocument:
    CURRENT_VERSION = 1

    version: int = CURRENT_VERSION
    mode: PolicyMode = PolicyMode.BLOCK
    whitelist: list[WhitelistEntry] = field(default_factory=list)
    admin_password: PasswordRecord | None = None
    updated_at: datetime = field(default_factory=lambda: datetime(1970, 1, 1, tzinfo=timezone.utc))
    updated_by: str | None = None
    applied_at: datetime | None = None
    applied_fingerprint: str | None = None

    def desired_fingerprint(self) -> str:
        ordered = sorted(
            self.whitelist,
            key=lambda entry: (
                entry.vendor_id.lower(),
                entry.product_id.lower(),
                (entry.serial_number or "").lower(),
                entry.id.hex,
            ),
        )
        body = ";".join(
            f"{entry.vendor_id}:{entry.product_id}:{entry.serial_number or '*'}:{entry.id.hex}"
            for entry in ordered
        )
        return f"{self.mode.fingerprint_name}|{body}"

    @property
    def is_applied(self) -> bool:
        return self.applied_fingerprint == self.desired_fingerprint()

    def to_json(self) -> dict[str, object]:
        return {
            "version": self.version,
            "mode": self.mode.value,
            "whitelist": [entry.to_json() for entry in self.whitelist],
            "adminPassword": None if self.admin_password is None else self.admin_password.to_json(),
            "updatedAt": format_timestamp(self.updated_at),
            "updatedBy": self.updated_by,
            "appliedAt": None if self.applied_at is None else format_timestamp(self.applied_at),
            "appliedFingerprint": self.applied_fingerprint,
        }


@dataclass(frozen=True)
class UsbStorageDevice:
    instance_id: str
    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    friendly_name: str | None = None
    is_mass_storage: bool = True


def format_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def parse_timestamp(value: object, *, fallback: datetime | None = None) -> datetime:
    if value is None or value == "":
        if fallback is not None:
            return fallback
        raise ValidationError("시각 값이 비어 있습니다.")
    if not isinstance(value, str):
        raise ValidationError("시각 값은 ISO-8601 문자열이어야 합니다.")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValidationError(f"시각 값을 읽지 못했습니다: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
