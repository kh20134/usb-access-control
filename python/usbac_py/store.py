"""Load and save policy.json and enforcement-state.json."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from usbac_py.exceptions import ValidationError
from usbac_py.matcher import MAX_ENTRIES, create_entry, same_identity
from usbac_py.models import PasswordRecord, PolicyDocument, WhitelistEntry, parse_mode, parse_timestamp

_MAX_POLICY_BYTES = 2_000_000
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


class FileProtector(Protocol):
    def protect_directory(self, directory: Path) -> None: ...

    def protect_file(self, path: Path) -> None: ...


class PortableFileProtector:
    """Best-effort owner-only permissions. Windows ACLs are a separate elevated step."""

    def protect_directory(self, directory: Path) -> None:
        if os.name != "nt" and directory.exists():
            try:
                os.chmod(directory, 0o700)
            except OSError:
                return

    def protect_file(self, path: Path) -> None:
        if os.name != "nt" and path.exists():
            try:
                os.chmod(path, 0o600)
            except OSError:
                return


@dataclass(frozen=True)
class PolicyLoadResult:
    document: PolicyDocument
    warnings: tuple[str, ...]


class PolicyStore:
    def __init__(self, directory: Path, protector: FileProtector | None = None) -> None:
        self.directory = Path(directory)
        self.path = self.directory / "policy.json"
        self._protector = protector or PortableFileProtector()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._protector.protect_directory(self.directory)

    def load_or_create(self) -> PolicyLoadResult:
        if not self.path.exists():
            return PolicyLoadResult(PolicyDocument(), ())
        size = self.path.stat().st_size
        if size > _MAX_POLICY_BYTES:
            raise ValidationError("정책 파일이 너무 큽니다. Windows 설정은 바꾸지 않았습니다.")
        try:
            raw = self.path.read_text(encoding="utf-8-sig")
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValidationError(
                "정책 파일을 읽지 못했습니다. Windows 설정은 바꾸지 않았습니다. " + str(exc)
            ) from exc
        except OSError as exc:
            raise ValidationError("정책 파일을 읽지 못했습니다. Windows 설정은 바꾸지 않았습니다.") from exc
        if not isinstance(data, dict):
            raise ValidationError("정책 파일이 비어 있거나 객체가 아닙니다. Windows 설정은 바꾸지 않았습니다.")
        return _document_from_json(data)

    def save(self, document: PolicyDocument) -> None:
        payload = json.dumps(document.to_json(), ensure_ascii=False, indent=2) + "\n"
        _atomic_write(self.path, payload)
        self._protector.protect_file(self.path)


@dataclass
class EnforcementState:
    disabled_instance_ids: list[str]

    def to_json(self) -> dict[str, object]:
        return {"disabledInstanceIds": list(self.disabled_instance_ids)}


class EnforcementStateStore:
    def __init__(self, directory: Path, protector: FileProtector | None = None) -> None:
        self.directory = Path(directory)
        self.path = self.directory / "enforcement-state.json"
        self._protector = protector or PortableFileProtector()
        self.directory.mkdir(parents=True, exist_ok=True)
        self._protector.protect_directory(self.directory)

    def load(self) -> EnforcementState:
        if not self.path.exists():
            return EnforcementState([])
        try:
            data = json.loads(self.path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            return EnforcementState([])
        if not isinstance(data, dict):
            return EnforcementState([])
        raw_ids = data.get("disabledInstanceIds", [])
        if not isinstance(raw_ids, list):
            return EnforcementState([])
        ids = [item for item in raw_ids if isinstance(item, str)]
        return EnforcementState(ids)

    def save(self, state: EnforcementState) -> None:
        payload = json.dumps(state.to_json(), ensure_ascii=False, indent=2) + "\n"
        _atomic_write(self.path, payload)
        self._protector.protect_file(self.path)


def default_data_directory() -> Path:
    if os.name == "nt":
        program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
        return Path(program_data) / "UsbAccessControlPy"
    xdg = os.environ.get("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / "UsbAccessControlPy"
    return Path.home() / ".local" / "share" / "UsbAccessControlPy"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def _document_from_json(data: dict[str, object]) -> PolicyLoadResult:
    version = data.get("version", PolicyDocument.CURRENT_VERSION)
    if not isinstance(version, int) or isinstance(version, bool):
        raise ValidationError("정책 파일 버전이 올바르지 않습니다. Windows 설정은 바꾸지 않았습니다.")
    if version > PolicyDocument.CURRENT_VERSION:
        raise ValidationError(
            f"정책 파일 버전 {version}은 이 프로그램({PolicyDocument.CURRENT_VERSION})에서 지원하지 않습니다. "
            "Windows 설정은 바꾸지 않았습니다."
        )
    mode = parse_mode(str(data.get("mode", "block")))
    warnings: list[str] = []
    whitelist = _load_whitelist(data.get("whitelist", []), warnings)
    password = _load_password(data.get("adminPassword", None))
    updated_at = parse_timestamp(data.get("updatedAt"), fallback=_EPOCH) if "updatedAt" in data else _EPOCH
    applied_at = None
    if data.get("appliedAt"):
        applied_at = parse_timestamp(data.get("appliedAt"))
    updated_by = data.get("updatedBy")
    fingerprint = data.get("appliedFingerprint")
    document = PolicyDocument(
        version=PolicyDocument.CURRENT_VERSION,
        mode=mode,
        whitelist=whitelist,
        admin_password=password,
        updated_at=updated_at,
        updated_by=updated_by if isinstance(updated_by, str) else None,
        applied_at=applied_at,
        applied_fingerprint=fingerprint if isinstance(fingerprint, str) else None,
    )
    return PolicyLoadResult(document, tuple(warnings))


def _load_password(raw: object) -> PasswordRecord | None:
    if raw is None:
        return None
    return PasswordRecord.from_json(raw)


def _load_whitelist(raw: object, warnings: list[str]) -> list[WhitelistEntry]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ValidationError("화이트리스트 형식이 올바르지 않습니다. Windows 설정은 바꾸지 않았습니다.")
    kept: list[WhitelistEntry] = []
    for item in raw:
        if len(kept) >= MAX_ENTRIES:
            warnings.append(f"화이트리스트는 {MAX_ENTRIES}개까지만 읽습니다. 나머지는 허용되지 않습니다.")
            break
        if not isinstance(item, dict):
            warnings.append("화이트리스트 항목을 무시했습니다. 해당 장치는 허용되지 않습니다.")
            continue
        try:
            entry_id = _parse_id(item.get("id"))
            created = parse_timestamp(item.get("createdAt"), fallback=_EPOCH)
            entry = create_entry(
                str(item.get("vendorId", "")),
                str(item.get("productId", "")),
                item.get("serialNumber") if isinstance(item.get("serialNumber"), str) else None,
                str(item.get("displayName", "")),
                item.get("note") if isinstance(item.get("note"), str) else None,
                created,
                entry_id,
            )
        except ValidationError as exc:
            warnings.append(f"화이트리스트 항목을 무시했습니다. 해당 장치는 허용되지 않습니다. {exc}")
            continue
        if any(same_identity(existing, entry) for existing in kept):
            warnings.append(
                f"중복된 화이트리스트 항목을 무시했습니다. {entry.vendor_id}:{entry.product_id}"
            )
            continue
        kept.append(entry)
    return kept


def _parse_id(raw: object) -> uuid.UUID:
    if not isinstance(raw, str) or not raw.strip():
        return uuid.uuid4()
    try:
        return uuid.UUID(raw)
    except ValueError:
        return uuid.uuid4()
